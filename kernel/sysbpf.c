#include "types.h"
#include "riscv.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "bpf.h"
#include "ubpf.h"
#include "bpf_hooks.h"

int bpf_load_prog(const char* filename,int size)
{
    //todo: wait until current program finish
    int h = ubpf_load_elf_ex(&g_ubpf_vm,filename,size,"bpf_entry");
    if(h==0)
        current_attach_point = 0;//reset current attach point
    return h;
}

int bpf_attach_prog(char* attach_point,int nbytes)
{
    //todo: wait until current program finish
    if(strncmp(attach_point,"syscall_pre_trace",nbytes)==0){
        current_attach_point = 1;
        return 0;
    }
    if(strncmp(attach_point,"syscall_pre_filter",nbytes)==0){
        current_attach_point = 2;
        return 0;
    }
    if(strncmp(attach_point,"syscall_post_trace",nbytes)==0){
        current_attach_point = 3;
        return 0;
    }
    if(strncmp(attach_point,"syscall_post_filter",nbytes)==0){
        current_attach_point = 4;
        return 0;
    }
    if(strncmp(attach_point,"scheduler_preempt_tick",nbytes)==0){
        current_attach_point = 5;
        return 0;
    }
    if(strncmp(attach_point,"scheduler_preempt_wakeup",nbytes)==0){
        current_attach_point = 6;
        return 0;
    }
    if(strncmp(attach_point,"scheduler_wake_preempt_entity",nbytes)==0){
        current_attach_point = 7;
        return 0;
    }
    return -1;
}

int bpf_unattach_prog()
{
    current_attach_point = 0;
    return 0;
}

void bpf_syscall_pre_trace(int syscall_num,int pid)
{
    if(current_attach_point==1)
    {
        ubpf_exec(&g_ubpf_vm,&syscall_num,sizeof(int),NULL);
    }
}

int bpf_syscall_pre_filter(int syscall_num,int pid){
    if(current_attach_point==2)
    {
        uint64 ret = 0;
        //printf("bpf input %d\n",num);
        ubpf_exec(&g_ubpf_vm,&syscall_num,sizeof(int),&ret);
        //printf("bpf return value :%d\n",ret);
        return ret;
    }
    return 0;
}

void bpf_syscall_post_trace(int syscall_num,int pid,  int syscall_result){
    if(current_attach_point==3) {

    }
}

int bpf_syscall_post_filter(int syscall_num,int pid, int syscall_result){
    if(current_attach_point==4)
    {

    }
    return syscall_result;
}

int bpf_sch_check_preempt_tick(struct proc* p){
    return 0;
}

int bpf_sch_check_preempt_wakeup(struct proc* p){
    return 0;
}

int bpf_sch_wake_preempt_entity(struct proc* p){
    return 0;
}

uint64
sys_bpf(void)
{
    int ocmd,nbytes;
    argint(0,&ocmd);
    argint(2,&nbytes);
    uint64 addr = 0;
    argaddr(1,&addr);
    struct proc *p = myproc();
    char attr[1024];
    if(copyin(p->pagetable, attr, addr, nbytes) < 0)
        return -1;
    switch (ocmd) {
        case BPF_PROG_LOAD:
            return bpf_load_prog(attr,nbytes);
        case BPF_PROG_ATTACH:
            return bpf_attach_prog(attr,nbytes);
        case BPF_PROG_UNATTACH:
            return bpf_unattach_prog();
        case BPF_MAP_CREATE:
            break;
        case BPF_MAP_LOOKUP_ELEM:
            break;
        case BPF_MAP_UPDATE_ELEM:
            break;
        case BPF_MAP_DELETE_ELEM:
            break;
        default:
            return -1;
    }
    return -1;
}