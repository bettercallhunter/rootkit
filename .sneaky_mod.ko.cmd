cmd_/home/zs149/rootkit/sneaky_mod.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000 -z noexecstack   --build-id  -T ./scripts/module-common.lds -o /home/zs149/rootkit/sneaky_mod.ko /home/zs149/rootkit/sneaky_mod.o /home/zs149/rootkit/sneaky_mod.mod.o;  true