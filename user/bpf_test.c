#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"
#include "kernel/bpf.h"


int
main(int argc, char *argv[]) {
    //filter mkdir syscall
    if(strcmp(argv[1],"1")==0) {
        int fd = open("prog.bpf.o",O_RDONLY);
        char elf[1024];
        int rb = read(fd,elf,1024);
        bpf(BPF_PROG_LOAD, elf, rb);
        bpf(BPF_PROG_ATTACH, "syscall_pre_filter", 18);
    }else{
        bpf(BPF_PROG_UNATTACH,"",0);
    }
    exit(0);
}