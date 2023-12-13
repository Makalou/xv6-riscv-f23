#include "ebpf.h"
#include "riscv.h"
#include "defs.h"
#include "bpf_map.h"
#include "bpf_helper_func.h"
#include "ubpf.h"

int uptime()
{
    uint xticks;
    acquire(&tickslock);
    xticks = ticks;
    release(&tickslock);
    return xticks;
}

void register_all_helper_functions(struct ubpf_vm* vm)
{
    ubpf_register(vm,0,"bpf_map_lookup_elem", bpf_map_lookup_elem);
    ubpf_register(vm,1,"bpf_map_update_elem", bpf_map_update_elem);
    ubpf_register(vm,2,"bpf_map_acquire", bpf_map_acquire);
    ubpf_register(vm,3,"bpf_map_release", bpf_map_release);
    ubpf_register(vm,4,"bpf_map_get_descriptor", bpf_map_get_descriptor);
}