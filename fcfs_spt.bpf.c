#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/spinlock.h"
#include "kernel/riscv.h"
#include "kernel/proc.h"

// first come first serve preempt tick strategy
int bpf_entry(void* mem, int size)
{
    //struct proc* p = (struct proc*)mem;

    return -1;
}