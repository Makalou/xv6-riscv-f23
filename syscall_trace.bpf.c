#include "kernel/syscall.h"
#include "kernel/bpf_args.h"

int counter[25];

int bpf_entry(void* mem, int size)
{
    EXTRACT_ARG(mem,bpf_syscall_arg);
    counter[arg->a7]++;

    return 0;
}