#include "kernel/syscall.h"
#include "kernel/bpf_args.h"

int counter[ ] = {0,0,0,0,0,0,0,0,0,
                   0,0,0,0,0,0,0,0,
                   0,0,0,0,0,0,0,0};

int bpf_entry(void* mem, int size)
{
    EXTRACT_ARG(mem,bpf_syscall_arg);

    if(arg->a7 == SYS_mkdir){
        counter[arg->a7]++;
        return -1;
    }

    return 0;
}