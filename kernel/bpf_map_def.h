//
// Created by 王泽远 on 2023/11/29.
//

#ifndef XV6_RISCV_F23_BPF_MAP_DEF_H
#define XV6_RISCV_F23_BPF_MAP_DEF_H

enum bpf_map_type
{
    bpf_array
};

struct bpf_map_lookup_attr
{
    int md;
    union {
        void* key;
        int idx;
    };
    void* value;
    int bpf;
};

struct bpf_map_update_attr
{
    int md;
    union {
        void* key;
        int idx;
    };
    void* new_value;
    int bpf;
};

struct bpf_map_lock_attr
{
    int md;
};

int bpf_map_lookup_elem(struct bpf_map_lookup_attr* attr);

int bpf_map_update_elem(struct bpf_map_update_attr* attr);

int bpf_map_acquire(struct bpf_map_lock_attr* attr);

int bpf_map_release(struct bpf_map_lock_attr* attr);

int bpf_map_get_descriptor(char* name, int len);

#endif //XV6_RISCV_F23_BPF_MAP_DEF_H
