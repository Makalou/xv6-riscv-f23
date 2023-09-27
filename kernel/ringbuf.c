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

int
ringbufmap(pagetable_t pg, struct ringbuf* rb, void** va)
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

int
unmap_check(pagetable_t pg, uint64 va, uint64 pa)
{
    pte_t *pte;
    if((pte = walk(pg, va, 0)) == 0)
        return -1;
    if((*pte & PTE_V) == 0)
        return -1;
    if(PTE_FLAGS(*pte) == PTE_V)
        return -1;
    if(PTE2PA(*pte) != pa){
        return -1;
    }

    return 0;
}

int
ringbufunmap(pagetable_t pg, struct ringbuf* rb, void* va)
{

    uint64 a = (uint64)va;
    pte_t *pte;

    if(((uint64)va % PGSIZE) != 0)
        return -1;

    for(int i = 0; i < RINGBUF_SIZE; i++)
    {
        if(unmap_check(pg,a+PGSIZE*i,(uint64)rb->buf[i])!=0)
            return -1;
    }

    for(int i = 0; i < RINGBUF_SIZE; i++)
    {
        if(unmap_check(pg,a+PGSIZE*i,(uint64)rb->buf[i])!=0)
            return -1;
    }

    if(unmap_check(pg,a + PGSIZE * (2*RINGBUF_SIZE),(uint64)rb->book)!=0)
        return -1;

    //Do the actul unmap
    for(int i = 0; i < RINGBUF_SIZE; i++)
    {
        pte = walk(pg, a + PGSIZE * i, 0);
        *pte = 0;
    }

    for(int i = 0; i < RINGBUF_SIZE; i++)
    {
        pte = walk(pg, a + PGSIZE * (RINGBUF_SIZE + i), 0);
        *pte = 0;
    }

    pte = walk(pg, a + PGSIZE * (2*RINGBUF_SIZE),0);
    *pte = 0;

    return 0;
}

void
ringbufalloc(struct ringbuf* rb)
{
    for(int i = 0;i<RINGBUF_SIZE;++i)
        rb->buf[i] = kalloc();
    rb->book = kalloc();
}

void
ringbuffree(struct ringbuf* rb)
{
    for(int i = 0;i<RINGBUF_SIZE;++i)
        kfree(rb->buf[i]);
    kfree(rb->book);
}

int
ringbufopen(const char* name,void ** addr)
{
    acquire(&ringbuf_lock);
    struct proc* p = myproc();
    //Check if already exist
    for(int i = 0;i< NELEM(ringbufs);i++){
        if(strncmp(name,ringbufs[i].name,16) == 0 && ringbufs[i].refcount>0) //test refcount first. short circuit :)
        {
            if(ringbufmap(p->pagetable,&ringbufs[i],addr) == 0)
            {
                ringbufs[i].refcount ++;
                release(&ringbuf_lock);
                return 0;
            }
        }
    }

    for(int i = 0;i< NELEM(ringbufs);i++){
        if(ringbufs[i].refcount == 0){
            ringbufalloc(&ringbufs[i]);
            if(ringbufmap(p->pagetable,&ringbufs[i],addr) == 0)
            {
                strncpy(ringbufs[i].name,name, strlen(name));
                ringbufs[i].refcount ++;
                release(&ringbuf_lock);
                return 0;
            }
        }
    }
    release(&ringbuf_lock);
    return -1;
}

int
ringbufclose(const char* name,void* addr)
{
    //TODO : What if:
    //            1.The process try to close a buf it doesn't ref to ?
    //            2.The name is correct, but the address doesn't match ... ?
    acquire(&ringbuf_lock);
    struct proc* p = myproc();
    for(int i = 0;i< NELEM(ringbufs);i++){
        if(strncmp(name,ringbufs[i].name,16) == 0)
        {
            if(ringbufunmap(p->pagetable,&ringbufs[i],addr) != 0)
            {
                release(&ringbuf_lock);
                return -1;
            }
            if(--ringbufs[i].refcount == 0)
            {
                ringbuffree(&ringbufs[i]);
            }
            release(&ringbuf_lock);
            return 0;
        }
    }
    release(&ringbuf_lock);
    return -1;
}


