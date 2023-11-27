
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"
#include "kernel/bpf.h"

int
main(int argc, char *argv[]) {
    printf("In netPFTest main\n");
    printf("argv[1] = %s\n", argv[1]);
    if (strcmp(argv[1], "enable_udp_checksum") == 0) {
        int fd = open("netPF.bpf.o", O_RDONLY);
        printf("Open netPF.bpf.o success\n");
        char elf[1024];
        int rb = read(fd, elf, 1024);
        printf("Read netPF.bpf.o success\n");
        int status = bpf(BPF_PROG_LOAD, elf, rb);
        printf("load network packet filter program status: %d\n", status);
        bpf(BPF_PROG_ATTACH, "enable_udp_checksum_filter", 40);
    } else {
        bpf(BPF_PROG_UNATTACH,"enable_udp_checksum_filter",40);
    }
    exit(0);
}