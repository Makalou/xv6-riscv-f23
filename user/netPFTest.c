#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"
#include "kernel/bpf_map.h"
#include "kernel/bpf.h"

int
main(int argc, char *argv[]) {
    printf("In netPFTest main\n");
    printf("argv[1] = %s\n", argv[1]);
    netPInfo net;
    unsigned char flag = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "enable_udp_checksum") == 0) {
            net.enableUdpCSum = 1;
            flag = 1;
        } else if (strcmp(argv[i], "filt_content") == 0 && i + 2 < argc) {
            printf("argv[i+1]: %d\n", argv[i+1]);
            net.filtConfig = atoi(argv[i+1]);
            net.filterCLen = strlen(argv[i+2]);
            for (int j = 0; j < net.filterCLen; j++) {
                net.netPContent[j] = *(argv[i+2] + j);
            }
            i += 2;
            flag = 1;
        }
    }
    printf("enableUdpCSum: %d, filtConfig: %d \n", net.enableUdpCSum, net.filtConfig);
    printf("filt content: %s\n", net.netPContent);
    if (flag == 1) {
        int fd = open("netPF.bpf.o", O_RDONLY);
        printf("Open netPF.bpf.o success\n");
        char elf[2048];
        int rb = read(fd, elf, 2048);
        printf("Read netPF.bpf.o success, rb = %d\n", rb);
        int status = bpf(BPF_PROG_LOAD, elf, rb);
        printf("load network packet filter program status: %d\n", status);
        bpf(BPF_PROG_ATTACH, "enable_udp_checksum_filter", 40);
        bpf(BPF_UPLOAD_NET_CONFIG, (char *)(&net), sizeof(netPInfo));
    } else {
        bpf(BPF_PROG_UNATTACH,"enable_udp_checksum_filter",40);
    }
    exit(0);
}