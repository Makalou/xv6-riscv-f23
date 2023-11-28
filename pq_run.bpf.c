#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/spinlock.h"
#include "kernel/riscv.h"
#include "kernel/proc.h"

// first come prior queue run strategy
int bpf_entry(void* mem, int size)
{
    struct proc* all_proc = ((struct proc*)mem) + 1;
    int cp_idx = *((int*)mem);
    int n = *((int*)mem + 1);

    struct proc* cp = &all_proc[cp_idx];

    for(struct proc * p = all_proc;p<&all_proc[n];p++)
    {
        if(p->prior < cp->prior)
            return -1;
    }

    return 1;
}