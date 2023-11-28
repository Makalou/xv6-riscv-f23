//
// Created by 王泽远 on 2023/11/27.
//

#ifndef XV6_RISCV_F23_BPF_ARGS_H
#define XV6_RISCV_F23_BPF_ARGS_H

#include "types.h"
#include "param.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "riscv.h"
#include "proc.h"

struct
bpf_syscall_arg
{
    uint64 a0;
    uint64 a1;
    uint64 a2;
    uint64 a3;
    uint64 a4;
    uint64 a5;
    uint64 a6;
    uint64 a7;

    int pid;
    int prior;
    char name[16];
};

inline
void fill_bpf_syscall_arg(struct bpf_syscall_arg* arg, struct proc* p)
{
    struct trapframe* frame = p->trapframe;
    arg->a0 = frame->a0;
    arg->a1 = frame->a1;
    arg->a2 = frame->a2;
    arg->a3 = frame->a3;
    arg->a4 = frame->a4;
    arg->a5 = frame->a5;
    arg->a6 = frame->a6;
    arg->a7 = frame->a7;
    arg->pid = p->pid;
    arg->prior = p->prior;
    for(int i = 0;i<16;i++)
        arg->name[i] = p->name[i];
}

struct
bpf_sched_arg
{

};

#define EXTRACT_ARG(mem,bpf_arg_type) struct bpf_arg_type* arg = (struct bpf_arg_type*)mem;


#endif //XV6_RISCV_F23_BPF_ARGS_H
