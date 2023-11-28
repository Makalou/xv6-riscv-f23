#include "kernel/syscall.h"
#include "kernel/bpf_args.h"

int bpf_entry(void* mem, int size)
{
    EXTRACT_ARG(mem,bpf_syscall_arg);

    if(arg->a7 == SYS_mkdir){
        return -1;
    }

    return 0;
}