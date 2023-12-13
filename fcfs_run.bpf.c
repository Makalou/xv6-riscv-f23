#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/spinlock.h"
#include "kernel/riscv.h"
#include "kernel/proc.h"

// first come first serve run strategy
int bpf_entry(void* mem, int size)
{
    struct proc* all_proc = ((struct proc*)mem) + 1;
    int cp_idx = *((int*)mem);
    int n = *((int*)mem + 1);

    struct proc* cp = &all_proc[cp_idx];

    int min_prority = cp->prior;
    int min_pid = cp->pid;

    for(struct proc * p = all_proc;p<&all_proc[n];p++)
    {
        if(p->prior < min_prority)
        {
            min_prority = p->prior;
            min_pid = p->pid;
        }
    }

    if(min_pid == cp->pid)
        return 1;

    return -1;
}