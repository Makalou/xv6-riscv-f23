#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_ringbuf(void)
{
    //TODO: check name validity(1-15 bytes)
    char buf_name[16];
    argstr(0,buf_name,16);
    int op;
    argint(1,&op);
    uint64 addr = 0;
    argaddr(2,&addr);

    printf(buf_name);
    printf("\n");

    void* ptr = (void*)0x12345;
    struct proc* p = myproc();
    copyout(p->pagetable,addr,(char*)&ptr,sizeof(void*));

    return 0;

    void** res_ptr;

    if(op == 1){
        ringbufopen(buf_name,res_ptr);
    }else if(op == 0){
        ringbufclose(buf_name,res_ptr);
    }else{
        panic("Unknown operation on ringbuf.");
    }

    copyout(p->pagetable,addr,(char*)res_ptr,sizeof(void*));

    return 0;
}
