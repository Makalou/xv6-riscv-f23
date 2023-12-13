#include "types.h"
#include "riscv.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "bpf.h"
#include "ubpf.h"
#include "bpf_hooks.h"
#include "bpf_args.h"
#include "bpf_map.h"
#include "bpf_helper_func.h"

int current_vm_idx;

int bpf_load_prog(char* filename,int size)
{
    //todo: wait until current program finish
    int vm_idx = 0;
    ubpf_create(&vm_idx);
    if (vm_idx < 0) {
        return -1;
    }
    // Support adding multiple elf files.
    struct ubpf_vm* vm = &bpf_vm_pool[vm_idx];

    register_all_helper_functions(vm);
    ubpf_register_data_relocation_default(vm);
    int h = ubpf_load_elf_ex(vm, vm_idx, filename, size, "bpf_entry");
    ubpf_register_data_bounds_check_default(vm);

    if (h == 0) {
        current_vm_idx = vm_idx;//set current attach point
    }
    //printf("current_vm_idx: %d h:%d\n", current_vm_idx, h);
    return h;
}

int attached_vm_list[10];

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
    if(strncmp(attach_point,"scheduler_preempt_run",nbytes)==0){
        attached_vm_list[8] = current_vm_idx + 1;
        return 0;
    }
    if (strncmp(attach_point, "enable_udp_checksum_filter", nbytes) == 0) {
        attached_vm_list[9] = current_vm_idx + 1;
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
    if(strncmp(attach_point,"scheduler_preempt_run",nbytes)==0){
        attached_vm_list[8] = -1;
        return 0;
    }
    if (strncmp(attach_point, "enable_udp_checksum_filter", nbytes) == 0) {
        attached_vm_list[9] = -1;
        return 0;
    }
    return 0;
}

void bpf_syscall_pre_trace(struct proc* p)
{
    if (attached_vm_list[1] > 0) {
        uint64 ret = 0;
        struct bpf_syscall_arg arg;
        fill_bpf_syscall_arg(&arg,p);
        ubpf_exec(&bpf_vm_pool[attached_vm_list[1] - 1], &arg, sizeof(struct bpf_syscall_arg), &ret);
    }
}

int bpf_syscall_pre_filter(struct proc* p){
    if(attached_vm_list[2]>0)
    {
        uint64 ret = 0;
        struct bpf_syscall_arg arg;
        fill_bpf_syscall_arg(&arg,p);
        ubpf_exec(&bpf_vm_pool[attached_vm_list[2]-1],&arg, sizeof(struct bpf_syscall_arg),&ret);
        //printf("bpf return value :%d\n",ret);
        return ret;
    }
    return 0;
}

void bpf_syscall_post_trace(struct proc* p){
    if(attached_vm_list[3]>0)
    {
        uint64 ret = 0;
        struct bpf_syscall_arg arg;
        fill_bpf_syscall_arg(&arg,p);
        ubpf_exec(&bpf_vm_pool[attached_vm_list[2]-1],&arg, sizeof(struct bpf_syscall_arg),&ret);
        //printf("bpf return value :%d\n",ret);
    }
}

int bpf_syscall_post_filter(struct proc* p) {
    if(attached_vm_list[4]>0)
    {
        uint64 ret = 0;
        struct bpf_syscall_arg arg;
        fill_bpf_syscall_arg(&arg,p);
        ubpf_exec(&bpf_vm_pool[attached_vm_list[2]-1],&arg, sizeof(struct bpf_syscall_arg),&ret);
        //printf("bpf return value :%d\n",ret);
        return ret;
    }
    return p->trapframe->a0;
}

int bpf_sch_check_preempt_tick(struct proc* p){
    if(attached_vm_list[5]>0)
    {
        uint64 ret = 0;
        ubpf_exec(&bpf_vm_pool[attached_vm_list[5]-1],p,sizeof (struct proc),&ret);
        return ret;
    }
    return 0;
}

int bpf_sch_check_preempt_wakeup(struct proc* p){
    if(attached_vm_list[6]>0)
    {

    }
    return 0;
}

int bpf_sch_wake_preempt_entity(struct proc* p){
    if(attached_vm_list[7]>0)
    {

    }
    return 0;
}

struct proc all_runnable_proc[NPROC+1];

int bpf_sch_check_run(struct proc* p, struct proc* all_proc, int n){
    if(attached_vm_list[8]>0)
    {
        uint64 ret = 0;
        int cp_idx = 0;
        int j = 1;
        //printf("should I run %d?\n",p->pid);
        //printf("current runnable process pid : [");

        for(int i = 0;i<NPROC;i++)
        {
            if(all_proc[i].state == RUNNABLE){
                //printf("%d, ",all_proc[i].pid);
                all_runnable_proc[j] = all_proc[i];
                if(all_proc[i].pid == p->pid)
                    cp_idx = j - 1;
                j++;
            }
        }

        //printf("]\n");

        *((int*)all_runnable_proc) = cp_idx;
        *((int*)all_runnable_proc + 1) = j - 1;
        *((int*)all_runnable_proc + 2) = 0;
        int stat = ubpf_exec(&bpf_vm_pool[attached_vm_list[8]-1], all_runnable_proc, j*sizeof(struct proc), &ret);

        //printf("min : %d\n",*((int*)all_runnable_proc + 2));
        //printf("ret : %d\n",ret);
        //printf("%d\n",ret);
        if(stat == 0)
            return ret;
    }
    return 0;
}

int bpf_enable_udp_checksum_filter() {
    if (attached_vm_list[9] > 0) {
        uint64 ret = 0;
        //printf("bpf input %d\n",num);
        char mem[16];
        int len = 16;
        ubpf_exec(&bpf_vm_pool[attached_vm_list[9]-1], mem, len, &ret);
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
    char* attr = (char*)kalloc();
    if (copyin(p->pagetable, attr, addr, nbytes) < 0) {
        return -1;
    }
    int result = -1;
    switch (ocmd) {
        case BPF_PROG_LOAD:
            result =  bpf_load_prog(attr,nbytes);
            break;
        case BPF_PROG_ATTACH:
            result = bpf_attach_prog(attr,nbytes);
            break;
        case BPF_PROG_UNATTACH:
            result = bpf_unattach_prog(attr,nbytes);
            break;
        case BPF_MAP_CREATE:
            result = bpf_create_map((struct bpf_map_create_attr*) attr);
            break;
        case BPF_MAP_LOOKUP_ELEM:
            result = bpf_map_lookup_elem((struct bpf_map_lookup_attr*) attr);
            break;
        case BPF_MAP_UPDATE_ELEM:
            result = bpf_map_update_elem((struct bpf_map_update_attr*) attr);
        case BPF_MAP_DELETE_ELEM:
            break;
        case BPF_MAP_ACQUIRE:
            result = bpf_map_acquire((struct bpf_map_lock_attr*)attr);
            break;
        case BPF_MAP_RELEASE:
            result = bpf_map_release((struct bpf_map_lock_attr*)attr);
            break;
        case BPF_MAP_GET_DESCRIPTOR:
            result = bpf_map_get_descriptor(attr,nbytes);
            break;
        default:
            break;
    }
    kfree(attr);
    return result;
}