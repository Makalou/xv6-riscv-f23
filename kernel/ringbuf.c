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

int is_empty()
{
    return 0;
}

int ringbufmap(pagetable_t pg, struct ringbuf* rb, void** va)
{
    uint64 pages_need = 2 * RINGBUF_SIZE + 1;

    uint64 beg_addr = PGROUNDDOWN(TRAPFRAME) - PGSIZE;
    pte_t* pte;

    //TODO: More efficient way : own walk routine

    //use slide window to detect continuous pages for size of pages_need
    int pages_found = 0;
    while(pages_found != pages_need)
    {
        beg_addr -= PGSIZE;
        pages_found ++;
        pte = walk(pg, beg_addr,1);
        if(*pte & PTE_V)
        {
            pages_found = 0;
        }
    }

    //TODO: What if fail to find continuous address space?

    uint64 cur = beg_addr;
    for(int i = 0;i < RINGBUF_SIZE;i++){
        mappages(pg,cur,PGSIZE,(uint64)rb->buf[i],PTE_W|PTE_R|PTE_U);
        cur += PGSIZE;
    }
    for(int i = 0;i < RINGBUF_SIZE;i++){
        mappages(pg,cur,PGSIZE,(uint64)rb->buf[i],PTE_W|PTE_R|PTE_U);
        cur += PGSIZE;
    }
    mappages(pg,cur,PGSIZE,(uint64)rb->book,PTE_W|PTE_R|PTE_U); // map book
    *va = (void*)beg_addr;

    return 0;
}

void
ringbufalloc(struct ringbuf* rb)
{
    for(int i = 0;i<RINGBUF_SIZE;++i)
        rb->buf[i] = kalloc();
    //TODO: book
    rb->book = kalloc();
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
        if(strncmp(name,ringbufs[i].name,16) == 0 && ringbufs[i].refcount>0){
            if(ringbufmap(p->pagetable,&ringbufs[i],addr) == 0){
                ringbufs[i].refcount ++;
                return 0;
            }
        }
    }

    printf("No exits ringbuf found for %s\n",name);

    for(int i = 0;i< NELEM(ringbufs);i++){
        if(ringbufs[i].refcount == 0){
            ringbufalloc(&ringbufs[i]);
            if(ringbufmap(p->pagetable,&ringbufs[i],addr) == 0){
                strncpy(ringbufs[i].name,name, strlen(name));
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


