#include "kernel/syscall.h"

int bpf_entry(void* mem, int size)
{
    int num = *(int*)mem;

    if(num == SYS_mkdir){
        return -1;
    }

    return 0;
}