#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/spinlock.h"
#include "kernel/riscv.h"
#include "kernel/proc.h"

int bpf_entry(void* mem, int size)
{
    int num = *(int*)mem;
    struct proc* p = (struct proc*) mem;
    int pid = p->pid;
    if(num == 20){
        return -1;
    }

    return 0;
}