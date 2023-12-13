
#include "bpf_map.h"
#include "riscv.h"
#include "defs.h"
#include "types.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"

#define MAX_BPF_MAP 32
struct bpf_map_def bpf_maps[MAX_BPF_MAP];

int find_empty_slot(struct bpf_map_def** bmd)
{
    int idx = 0;
    for(struct bpf_map_def* map_def = bpf_maps;
        map_def!=&bpf_maps[MAX_BPF_MAP];
        map_def++) {
        if (map_def->size == 0) {
            *bmd = map_def;
            return idx;
        }
        idx++;
    }
    return -1;
}

int bpf_create_map_array(struct bpf_map_create_attr* attr)
{
    //printf("create array %s\n",attr->name);
    int size = attr->value_size * attr->max_eles;
    if(size>PGSIZE)
        return -1;
    struct bpf_map_def* map_def = 0;
    int map_idx = find_empty_slot(&map_def);
    if(map_idx < 0)
        return -1;
    map_def->data = kalloc();
    memset(map_def->data,0,size);
    map_def->type = bpf_array;
    map_def->value_size = attr->value_size;
    map_def->key_size = 0;
    map_def->size = size;
    map_def->max_eles = attr->max_eles;
    safestrcpy(map_def->name,attr->name,10);
    return map_idx;
}

int bpf_create_map(struct bpf_map_create_attr* attr)
{
    if(attr->map_type == bpf_array)
        return bpf_create_map_array(attr);
    return -1;
}

int bpf_look_up_array(struct bpf_map_lookup_attr* attr,struct bpf_map_def* map)
{
    if(attr->idx < 0 || attr->idx >= map->max_eles)
        return -1;
    void* src = map->data + (map->value_size * attr->idx);
    if(attr->bpf){
        memmove(attr->value,src,map->value_size);
    }else{
        copyout(myproc()->pagetable,(uint64)attr->value,src,map->value_size);
    }
    return 0;
}

int bpf_map_lookup_elem(struct bpf_map_lookup_attr* attr)
{
    if(attr->md < 0 || attr->md>=MAX_BPF_MAP){
        return -1;
    }
    struct bpf_map_def* map = &bpf_maps[attr->md];
    int result = -1;
    if(map->size == 0)
        goto error;
    if(map->type == bpf_array)
        result =  bpf_look_up_array(attr,map);
    error:
    return result;
}

int bpf_update_array(struct bpf_map_update_attr* attr,struct bpf_map_def* map)
{
    if(attr->idx < 0 || attr->idx >= map->max_eles)
        return -1;
    void* dst = map->data + (map->value_size * attr->idx);
    if(attr->bpf){
        memmove(dst,attr->new_value,map->value_size);
    }else{
        copyin(myproc()->pagetable,dst,(uint64)attr->new_value,map->value_size);
    }

    return 0;
}

int bpf_map_update_elem(struct bpf_map_update_attr* attr)
{
    if(attr->md < 0 || attr->md>=MAX_BPF_MAP){
        return -1;
    }
    struct bpf_map_def* map = &bpf_maps[attr->md];
    int result = -1;
    if(map->size == 0)
        goto error;
    if(map->type == bpf_array)
        result =  bpf_update_array(attr,map);
    error:
    return result;
}

int bpf_map_acquire(struct bpf_map_lock_attr* attr)
{
    if(attr->md < 0 || attr->md>=MAX_BPF_MAP){
        return -1;
    }
    struct bpf_map_def* map = &bpf_maps[attr->md];
    acquire(&map->rwlock);
    return 0;
}

int bpf_map_release(struct bpf_map_lock_attr* attr)
{
    if(attr->md < 0 || attr->md>=MAX_BPF_MAP){
        return -1;
    }
    struct bpf_map_def* map = &bpf_maps[attr->md];
    release(&map->rwlock);
    return 0;
}

int bpf_map_get_descriptor(char* name,int len)
{
    int idx = 0;
    for(struct bpf_map_def* map_def = bpf_maps;
        map_def!=&bpf_maps[MAX_BPF_MAP];
        map_def++) {
        int min = len < 10 ? len : 10;
        if (map_def->size != 0 && strncmp(map_def->name,name,min)==0) {
            return idx;
        }
        idx++;
    }
    return -1;
}

uint64
bpf_map_relocator(
        void* user_context,
        const uint8_t* map_data,
        uint64 map_data_size,
        const char* symbol_name,
        uint64 symbol_offset,
        uint64 symbol_size)
{
    //(void)user_context; // unused

    for(struct bpf_map_def* bmd = bpf_maps;bmd!=&bpf_maps[MAX_BPF_MAP];bmd++)
    {
        if(strncmp(bmd->name,symbol_name,10)==0)
        {
            //found
            *(struct bpf_map_def**)user_context = bmd;
            if(symbol_size > bmd->size){
                return 0;
            }
            const uint64* target_address = (const uint64*)((uint64)bmd->data);
            return (uint64)target_address;
        }
    }

    return 0;
}

bool
bpf_map_relocation_bounds_checker(void* user_context, uint64 addr, uint64 size) {
    struct bpf_map_def* mapdef = (struct bpf_map_def*) user_context;
    if ((uint64) mapdef->data <= addr && (addr + size) <= ((uint64) mapdef->data + mapdef->size)) {
        return 1;
    }
    return 0;
}