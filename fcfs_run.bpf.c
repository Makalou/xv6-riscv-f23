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

    //return cp->pid;
    int min_pid = cp->pid;

    for(struct proc * p = all_proc;p<&all_proc[n];p++)
    {
        if(p->pid < min_pid)
            min_pid = p->pid;
    }

    //return max_pid;

    *((int*)mem + 2) = min_pid;

    if(min_pid == cp->pid)
        return 1;

    return -1;
}