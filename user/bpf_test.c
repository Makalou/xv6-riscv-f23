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
        bpf(BPF_PROG_LOAD, "prog.bpf.o", 11);
        bpf(BPF_PROG_ATTACH, "syscall_pre_filter", 18);
    }else{
        bpf(BPF_PROG_UNATTACH,"",0);
    }
    exit(0);
}