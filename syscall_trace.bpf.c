#include "kernel/syscall.h"
#include "kernel/bpf_args.h"
#include "kernel/bpf_helper_func.h"

int bpf_entry(void* mem, int size)
{
    EXTRACT_ARG(mem,bpf_syscall_arg);
    char name[8] = "counter";
    int md = bpf_map_get_descriptor(name,8);
    int val = 0;
    struct bpf_map_lock_attr l;
    l.md = md;
    struct bpf_map_lookup_attr attr1;
    attr1.md = md;
    attr1.idx = arg->a7;
    attr1.value = &val;
    attr1.bpf = 1;
    struct bpf_map_update_attr attr2;
    attr2.md = md;
    attr2.idx = arg->a7;
    attr2.bpf = 1;
    bpf_map_acquire(&l);
    bpf_map_lookup_elem(&attr1);
    val++;
    attr2.new_value = &val;
    bpf_map_update_elem(&attr2);
    bpf_map_release(&l);
    return 0;
}