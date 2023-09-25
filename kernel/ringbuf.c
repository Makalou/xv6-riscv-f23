//
// Created by 王泽远 on 2023/9/20.
//
#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"
#include "fs.h"
#include "sleeplock.h"
#include "ringbuf.h"
#include "memlayout.h"

struct spinlock ringbuf_lock;

struct ringbuf ringbufs[MAX_RINGBUFS];

struct book
{
    uint64 read_done, write_done;
};

int ringbufmap(pagetable_t pg, struct ringbuf* rb, void** va)
{
    uint64 base = PGROUNDDOWN(TRAPFRAME) - 2 * RINGBUF_SIZE * PGSIZE;
    uint64 cur = base;
    for(int i = 0;i < RINGBUF_SIZE;i++){
        mappages(pg,cur,PGSIZE,(uint64)rb->buf[i],PTE_W|PTE_R|PTE_U);
        cur += PGSIZE;
    }
    for(int i = 0;i < RINGBUF_SIZE;i++){
        mappages(pg,cur,PGSIZE,(uint64)rb->buf[i],PTE_W|PTE_R|PTE_U);
        cur += PGSIZE;
    }
    *va = (void*)cur;
    return 0;
}

void
ringbufalloc(struct ringbuf* rb)
{
    for(int i = 0;i<RINGBUF_SIZE;++i)
        rb->buf[i] = kalloc();
}

void
ringbuffree(struct ringbuf* rb)
{
    for(int i = 0;i<RINGBUF_SIZE;++i)
        kfree(rb->buf[i]);
}

int
ringbufopen(const char* name,void ** addr)
{
    //TODO: race condition caution
    struct proc* p = myproc();
    //Check if already exist
    for(int i = 0;i< NELEM(ringbufs);i++){
        if(strncmp(name,ringbufs[i].name,16) && ringbufs[i].refcount>0){
            if(ringbufmap(p->pagetable,&ringbufs[i],addr) == 0){
                ringbufs[i].refcount ++;
                return 0;
            }
        }
    }

    for(int i = 0;i< NELEM(ringbufs);i++){
        if(ringbufs[i].refcount == 0){
            ringbufalloc(&ringbufs[i]);
            if(ringbufmap(p->pagetable,&ringbufs[i],addr) == 0){
                strncpy(ringbufs[i].name,name,16);
                ringbufs[i].refcount ++;
                return 0;
            }
        }
    }
    panic("Failed to open ringbuf.");
}

int
ringbufclose(const char* name,void* addr)
{
    for(int i = 0;i< NELEM(ringbufs);i++){
        if(strncmp(name,ringbufs[i].name,16)){
           ringbufs[i].refcount --;
           //TODO: do we need to unmap ?
           if(ringbufs[i].refcount == 0){
               //TODO: grabage collect physical pages ...
               ringbuffree(&ringbufs[i]);
           }
        }
    }
    return 0;
}


