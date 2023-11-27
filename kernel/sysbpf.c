#include "types.h"
#include "riscv.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "bpf.h"
#include "ubpf.h"
#include "bpf_hooks.h"

int current_vm_idx;
int loaded_elf_cnt;

int bpf_load_prog(const char* filename,int size)
{
    //todo: wait until current program finish
    int vm_idx = 0;
    ubpf_create(&vm_idx);
    if (vm_idx < 0) {
        return -1;
    }
    // Support adding multiple elf files.
    int h = ubpf_load_elf_ex(&g_ubpf_vm[loaded_elf_cnt], vm_idx, filename, size, "bpf_entry");
    if (h == 0) {
        loaded_elf_cnt++;
        current_vm_idx = vm_idx;//set current attach point

    }
    printf("current_vm_idx: %d h:%d\n", current_vm_idx, h);
    return h;
}

int attached_vm_list[9];

/*
 *  global variable will be initialized to 0 in C language
 *  so I think it's convienent to let 0 stands for vm "non-exist"
 *  therefore the valid vm idx stored in attached_vm_list starts from 1, instead of 0
 */

int bpf_attach_prog(char* attach_point,int nbytes)
{
    //todo: wait until current program finish
    if(strncmp(attach_point,"syscall_pre_trace",nbytes)==0){
        attached_vm_list[1] = current_vm_idx + 1;
        return 0;
    }
    if(strncmp(attach_point,"syscall_pre_filter",nbytes)==0){
        attached_vm_list[2] = current_vm_idx + 1;
        return 0;
    }
    if(strncmp(attach_point,"syscall_post_trace",nbytes)==0){
        attached_vm_list[3] = current_vm_idx + 1;
        return 0;
    }
    if(strncmp(attach_point,"syscall_post_filter",nbytes)==0){
        attached_vm_list[4] = current_vm_idx + 1;
        return 0;
    }
    if(strncmp(attach_point,"scheduler_preempt_tick",nbytes)==0){
        attached_vm_list[5] = current_vm_idx + 1;
        return 0;
    }
    if(strncmp(attach_point,"scheduler_preempt_wakeup",nbytes)==0){
        attached_vm_list[6] = current_vm_idx + 1;
        return 0;
    }
    if(strncmp(attach_point,"scheduler_wake_preempt_entity",nbytes)==0){
        attached_vm_list[7] = current_vm_idx + 1;
        return 0;
    }
    if (strncmp(attach_point, "enable_udp_checksum_filter", nbytes) == 0) {
        attached_vm_list[8] = current_vm_idx + 1;
        return 0;
    }
    return -1;
}

int bpf_unattach_prog(char* attach_point,int nbytes)
{
    if(strncmp(attach_point,"syscall_pre_trace",nbytes)==0){
        attached_vm_list[1] = -1;
        return 0;
    }
    if(strncmp(attach_point,"syscall_pre_filter",nbytes)==0){
        attached_vm_list[2] = -1;
        return 0;
    }
    if(strncmp(attach_point,"syscall_post_trace",nbytes)==0){
        attached_vm_list[3] = -1;
        return 0;
    }
    if(strncmp(attach_point,"syscall_post_filter",nbytes)==0){
        attached_vm_list[4] = -1;
        return 0;
    }
    if(strncmp(attach_point,"scheduler_preempt_tick",nbytes)==0){
        attached_vm_list[5] = -1;
        return 0;
    }
    if(strncmp(attach_point,"scheduler_preempt_wakeup",nbytes)==0){
        attached_vm_list[6] = -1;
        return 0;
    }
    if(strncmp(attach_point,"scheduler_wake_preempt_entity",nbytes)==0){
        attached_vm_list[7] = -1;
        return 0;
    }
    if (strncmp(attach_point, "enable_udp_checksum_filter", nbytes) == 0) {
        attached_vm_list[8] = -1;
        return 0;
    }
    return 0;
}

void bpf_syscall_pre_trace(int syscall_num,int pid)
{
    if (attached_vm_list[1] > 0) {
        ubpf_exec(&g_ubpf_vm[attached_vm_list[1] - 1], &syscall_num, sizeof(int), NULL);
    }
}

int bpf_syscall_pre_filter(int syscall_num,int pid){
    if(attached_vm_list[2]>0)
    {
        uint64 ret = 0;
        //printf("bpf input %d\n",num);
        ubpf_exec(&g_ubpf_vm[attached_vm_list[2]-1],&syscall_num,sizeof(int),&ret);
        //printf("bpf return value :%d\n",ret);
        return ret;
    }
    return 0;
}

void bpf_syscall_post_trace(int syscall_num,int pid,  int syscall_result){

}

int bpf_syscall_post_filter(int syscall_num,int pid, int syscall_result){
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

int bpf_enable_udp_checksum_filter() {
    if (attached_vm_list[8] > 0) {
        uint64 ret = 0;
        //printf("bpf input %d\n",num);
        char mem[16];
        int len = 16;
        ubpf_exec(&g_ubpf_vm[attached_vm_list[8]-1], mem, len, &ret);
        //printf("bpf return value :%d\n",ret);
        return ret;
    }
    return 0;
}

uint64
sys_bpf(void)
{
    int ocmd, nbytes;
    argint(0, &ocmd);
    argint(2, &nbytes);
    uint64 addr = 0;
    argaddr(1, &addr);
    struct proc *p = myproc();
    char attr[1024];
    if (copyin(p->pagetable, attr, addr, nbytes) < 0) {
        return -1;
    }
    switch (ocmd) {
        case BPF_PROG_LOAD:
            return bpf_load_prog(attr,nbytes);
        case BPF_PROG_ATTACH:
            return bpf_attach_prog(attr,nbytes);
        case BPF_PROG_UNATTACH:
            return bpf_unattach_prog(attr,nbytes);
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