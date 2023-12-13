#ifndef BPF_MAP_H
#define BPF_MAP_H

#include "types.h"
#include "spinlock.h"
#include "bpf_map_def.h"

struct bpf_map_create_attr
{
    char name[10];
    enum bpf_map_type map_type;
    int value_size;
    int key_size;
    int max_eles;
};

int bpf_create_map(struct bpf_map_create_attr* attr);

struct bpf_map_def
{
    char name[10];
    enum bpf_map_type type;
    uint32 value_size;
    uint32 key_size;
    uint32 max_eles;
    void* data;
    uint32 size;
    struct spinlock rwlock;
};

uint64
bpf_map_relocator(
        void* user_context,
        const uint8_t* map_data,
        uint64 map_data_size,
        const char* symbol_name,
        uint64 symbol_offset,
        uint64 symbol_size);

bool
bpf_map_relocation_bounds_checker(void* user_context, uint64 addr, uint64 size);

#endif