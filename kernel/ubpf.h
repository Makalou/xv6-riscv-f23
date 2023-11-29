// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef UBPF_H
#define UBPF_H

#include "types.h"
#include "ebpf.h"
//#include "riscv.h"
//#include "defs.h"

#define MAX_VM_NUM 8
#define UBPF_STACK_SIZE 512
#define UBPF_MAX_CALL_DEPTH 10
#define MAX_EXT_FUNCS 64
#define NULL 0
#define true 1
#define false 0

#define UBPF_MAX_INSTS 65536

#define NUM_INSTS_MAX (UBPF_MAX_INSTS/8)

#define UNUSED(x) ((void)x)

#define ERR(fmt, ...) \
  printf("%d: error: " fmt "\n", __LINE__, ##__VA_ARGS__)

/**
 * @brief Opaque type for a uBPF JIT compiled function.
 */
typedef uint64 (*ubpf_jit_fn)(void* mem, size_t mem_len);


typedef struct {
    uint64 (*func)(uint64 arg0, uint64 arg1, uint64 arg2, uint64 arg3, uint64 arg4);
} ext_func;

/**
 * @brief Data relocation function that is called by the VM when it encounters a
 * R_BPF_64_64 relocation in the maps section of the ELF file.
 *
 * @param[in] user_context The user context that was passed to ubpf_register_data_relocation.
 * @param[in] data Pointer to start of the map section.
 * @param[in] data_size Size of the map section.
 * @param[in] symbol_name Name of the symbol that is referenced.
 * @param[in] symbol_offset Offset of the symbol relative to the start of the map section.
 * @param[in] symbol_size Size of the symbol.
 * @return uint64_t The value to insert into the BPF program.
 */
typedef uint64 (*ubpf_data_relocation)(
    void* user_context,
    const uint8_t* data,
    uint64 data_size,
    const char* symbol_name,
    uint64 symbol_offset,
    uint64 symbol_size);

typedef bool (*ubpf_bounds_check)(void* context, uint64 addr, uint64 size);

struct ubpf_vm
{
    struct ebpf_inst* insts;
    uint16_t num_insts;
    ubpf_jit_fn jitted;
    size_t jitted_size;
    ext_func** ext_funcs;
    bool* int_funcs;
    const char** ext_func_names;
    bool bounds_check_enabled;
    // The function should be different in xv6.
    //int (*error_printf)(FILE* stream, const char* format, ...);
    int (*translate)(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
    int unwind_stack_extension_index;
    uint64 pointer_secret;
    ubpf_data_relocation data_relocation_function;
    void* data_relocation_user_data;
    ubpf_bounds_check bounds_check_function;
    void* bounds_check_user_data;
#ifdef DEBUG
    uint64* regs;
#endif
};

struct ubpf_stack_frame
{
    uint16_t return_address;
    uint64 saved_registers[4];
};

typedef struct _ebpf_encoded_inst
{
    union
    {
        uint64 value;
        struct ebpf_inst inst;
    };
} ebpf_encoded_inst;

extern struct ubpf_vm bpf_vm_pool[MAX_VM_NUM];

unsigned int
ubpf_lookup_registered_function(struct ubpf_vm* vm, const char* name);

struct ubpf_vm* ubpf_create(int* vm_idx);

int
ubpf_register_data_relocation(struct ubpf_vm* vm, void* user_context, ubpf_data_relocation relocation);

//int
//ubpf_register_data_relocation_default(struct ubpf_vm* vm);

int
ubpf_register_data_bounds_check(struct ubpf_vm* vm, void* user_context, ubpf_bounds_check bounds_check);

//int
//ubpf_register_data_bounds_check_default(struct ubpf_vm* vm);

//Load code into a VM.
// This must be done before calling ubpf_exec and after registering all functions.
int ubpf_load(struct ubpf_vm*, int i,const void* ,uint32_t);

int ubpf_load_elf_ex(struct ubpf_vm* vm, int vm_idx,void* elf, size_t elf_len, const char* main_section_name);

int
ubpf_exec(const struct ubpf_vm* vm,void* mem, size_t mem_len, uint64* bpf_return_value);

#endif