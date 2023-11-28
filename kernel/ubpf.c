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

#include "ubpf.h"
#include "ebpf.h"
#include "riscv.h"
#include "defs.h"

// use global variables instead of using malloc
struct ubpf_vm g_ubpf_vm[MAX_VM_NUM];
ext_func g_ext_funcs[MAX_VM_NUM * MAX_EXT_FUNCS];
const char* g_ext_func_names[MAX_VM_NUM * MAX_EXT_FUNCS];
struct ebpf_inst g_ebpf_inst[MAX_VM_NUM * UBPF_MAX_INSTS];
bool g_int_funcs[MAX_VM_NUM * NUM_INSTS_MAX];

int
ubpf_translate_null(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg)
{
    /* NULL JIT target - just returns an error. */
    UNUSED(vm);
    UNUSED(buffer);
    UNUSED(size);
    ERR("Code can not be JITed on this target.\n");
    return -1;
}

void
ubpf_unload_code(struct ubpf_vm* vm)
{
    if (vm->jitted) {
        ERR("Error: vm->jitted != NULL");
    }
    if (vm->insts) {
        //free(vm->insts);
        vm->insts = NULL;
        vm->num_insts = 0;
    }
}

void
ubpf_destroy(struct ubpf_vm* vm)
{
    ubpf_unload_code(vm);

    //free(vm->int_funcs);
    vm->int_funcs = NULL;
    //free(vm->ext_funcs);
    //vm->ext_funcs = NULL;
    //free(vm->ext_func_names);
    vm->ext_func_names = NULL;
    //free(vm);
    vm = NULL;//???
}

struct ubpf_vm*
ubpf_create(int* vm_idx) {
    struct ubpf_vm* vm = NULL;
    int i = 0;
    for (vm = g_ubpf_vm; i != MAX_VM_NUM; vm++, i++){
        if(vm->ext_funcs == NULL)
            break;
    }

    if (i == MAX_VM_NUM) {
        *vm_idx = -1;
        return NULL;
    }

    vm->ext_funcs = (ext_func **)&g_ext_funcs[i * MAX_EXT_FUNCS];
    if (vm->ext_funcs == NULL) {
        ubpf_destroy(vm);
        *vm_idx = -1;
        return NULL;
    }
    vm->ext_func_names = &g_ext_func_names[i * MAX_EXT_FUNCS];
    if (vm->ext_func_names == NULL) {
        *vm_idx = -1;
        ubpf_destroy(vm);
        return NULL;
    }
    vm->bounds_check_enabled = true;
    //vm->error_printf = fprintf;

    vm->translate = ubpf_translate_null;
    vm->unwind_stack_extension_index = -1;
    vm->jitted = NULL;
    *vm_idx = i;
    return vm;
}

static bool
validate(const struct ubpf_vm* vm, const struct ebpf_inst* insts, uint32_t num_insts)
{
    if (num_insts >= UBPF_MAX_INSTS) {
        ERR("too many instructions (max %u)", UBPF_MAX_INSTS);
        return false;
    }
    int i;
    for (i = 0; i < num_insts; i++) {
        struct ebpf_inst inst = insts[i];
        bool store = false;
        
        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_NEG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ARSH_REG:
            break;

        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                ERR("invalid endian immediate at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_NEG64:
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_ARSH64_REG:
            break;

        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            break;

        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            store = true;
            break;

        case EBPF_OP_LDDW:
            if (inst.src != 0) {
                ERR("invalid source register for LDDW at PC %d", i);
                return false;
            }
            if (i + 1 >= num_insts || insts[i + 1].opcode != 0) {
                ERR("incomplete lddw at PC %d", i);
                return false;
            }
            i++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JEQ32_REG:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGT32_REG:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JGE32_REG:
        case EBPF_OP_JSET32_REG:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JNE32_REG:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGT32_REG:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JSGE32_REG:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLT32_REG:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JLE32_REG:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLT32_REG:
        case EBPF_OP_JSLE32_IMM:
        case EBPF_OP_JSLE32_REG:
            if (inst.offset == -1) {
                ERR("infinite loop at PC %d", i);
                return false;
            }
            int new_pc = i + 1 + inst.offset;
            if (new_pc < 0 || new_pc >= num_insts) {
                ERR("jump out of bounds at PC %d", i);
                return false;
            } else if (insts[new_pc].opcode == 0) {
                ERR("jump to middle of lddw at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_CALL:
            if (inst.src == 0) {
                if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
                    ERR("invalid call immediate at PC %d", i);
                    return false;
                }
                if (vm->ext_funcs[inst.imm]) {
                    ERR("call to nonexistent function %u at PC %d", inst.imm, i);
                    return false;
                }
            } else if (inst.src == 1) {
                int call_target = i + (inst.imm + 1);
                if (call_target < 0 || call_target > num_insts) {
                    ERR("call to local function (at PC %d) is out of bounds (target: %d)", i, call_target);
                    return false;
                }
            } else if (inst.src == 2) {
                ERR("call to external function by BTF ID (at PC %d) is not supported", i);
                return false;
            } else {
                ERR("call (at PC %d) contains invalid type value", i);
                return false;
            }
            break;

        case EBPF_OP_EXIT:
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            break;

        default:
            ERR("unknown opcode 0x%02x at PC %d", inst.opcode, i);
            return false;
        }

        if (inst.src > 10) {
            ERR("invalid source register at PC %d", i);
            return false;
        }

        if (inst.dst > 9 && !(store && inst.dst == 10)) {
            ERR("invalid destination register at PC %d", i);
            return false;
        }
    }

    return true;
}

void
ubpf_store_instruction(const struct ubpf_vm* vm, uint16_t pc, struct ebpf_inst inst)
{
    // XOR instruction with base address of vm.
    // This makes ROP attack more difficult.
    ebpf_encoded_inst encode_inst;
    encode_inst.inst = inst;
    encode_inst.value ^= (uint64)vm->insts;
    encode_inst.value ^= vm->pointer_secret;
    vm->insts[pc] = encode_inst.inst;
}

unsigned int
ubpf_lookup_registered_function(struct ubpf_vm* vm, const char* name)
{
    int i;
    for (i = 0; i < MAX_EXT_FUNCS; i++) {
        const char* other = vm->ext_func_names[i];
        if (other && !strncmp(other, name, strlen(name))) {
            return i;
        }
    }
    return -1;
}

int
ubpf_register_data_relocation(struct ubpf_vm* vm, void* user_context, ubpf_data_relocation relocation)
{
    if (vm->data_relocation_function != NULL) {
        return -1;
    }
    vm->data_relocation_function = relocation;
    vm->data_relocation_user_data = user_context;
    return 0;
}

void* _global_data;
uint64 _global_data_size;

static uint64
default_data_relocator(
        void* user_context,
        const uint8_t* map_data,
        uint64 map_data_size,
        const char* symbol_name,
        uint64 symbol_offset,
        uint64 symbol_size)
{
    (void)user_context; // unused
    (void)symbol_name;  // unused
    (void)symbol_size;  // unused

    if (_global_data == NULL) {
        _global_data = kalloc();
        _global_data_size = map_data_size;
        //memmove(_global_data, map_data, map_data_size);
        // I don't know why global variable in bpf program
        // are not automatically initialized to zero, wired...
        memset(_global_data,0,map_data_size);
    }
    const uint64* target_address = (const uint64*)((uint64)_global_data + symbol_offset);
    return (uint64)target_address;
}

int ubpf_register_data_relocation_default(struct ubpf_vm* vm)
{
    return ubpf_register_data_relocation(vm,NULL,default_data_relocator);
}

int
ubpf_register_data_bounds_check(struct ubpf_vm* vm, void* user_context, ubpf_bounds_check bounds_check)
{
    if (vm->bounds_check_function != NULL) {
        return -1;
    }
    vm->bounds_check_function = bounds_check;
    vm->bounds_check_user_data = user_context;
    return 0;
}

static bool
data_relocation_bounds_checker(void* user_context, uint64 addr, uint64 size)
{
    (void)user_context; // unused
    if ((uint64)_global_data <= addr && (addr + size) <= ((uint64)_global_data + _global_data_size)) {
        return true;
    }
    return false;
}

int
ubpf_register_data_bounds_check_default(struct ubpf_vm* vm)
{
    return ubpf_register_data_bounds_check(vm,NULL,data_relocation_bounds_checker);
}

int
ubpf_load(struct ubpf_vm* vm, int vm_idx,const void* code, uint32_t code_len)
{
    //const struct ebpf_inst* source_inst = code;
    if (UBPF_STACK_SIZE % sizeof(uint64) != 0) {
        ERR("UBPF_STACK_SIZE must be a multiple of 8");
        return -1;
    }
    if (vm->insts) {
        ERR("code has already been loaded into this VM. Use ubpf_unload_code() \
            if you need to reuse this VM");
        return -1;
    }

    if (code_len % 8 != 0) {
        ERR("code_len must be a multiple of 8");
        return -1;
    }

    if (!validate(vm, code, code_len / 8)) {
        return -1;
    }

    vm->insts = &g_ebpf_inst[vm_idx * UBPF_MAX_INSTS];
    if (vm->insts == NULL) {
        ERR("out of memory");
        return -1;
    }
    vm->num_insts = code_len / sizeof(vm->insts[0]);
    vm->int_funcs = &g_int_funcs[vm_idx * NUM_INSTS_MAX];
    if (!vm->int_funcs) {
        ERR("out of memory");
        return -1;
    }

    const struct ebpf_inst* source_inst = code;
    for (uint32_t i = 0; i < vm->num_insts; i++) {
        /* Mark targets of local call instructions. They
         * represent the beginning of local functions and
         * the jitter may need to do something special with
         * them.
         */
        if (source_inst[i].opcode == EBPF_OP_CALL && source_inst[i].src == 1) {
            uint32_t target = i + source_inst[i].imm + 1;
            vm->int_funcs[target] = true;
        }
        // Store instructions in the vm.
        ubpf_store_instruction(vm, i, source_inst[i]);
    }
    return 0;
}

/*
int
ubpf_exec(const struct ubpf_vm* vm, void* mem, size_t mem_len, uint64* bpf_return_value)
{
    uint16_t pc = 0;
    const struct ebpf_inst* insts = vm->insts;
    uint64* reg;
    uint64 _reg[16];
    uint64 ras_index = 0;
    int return_value = -1;

    uint64 stack[UBPF_STACK_SIZE / sizeof(uint64)];
    struct ubpf_stack_frame stack_frames[UBPF_MAX_CALL_DEPTH] = {
        0,
    };

    if (!insts) {
        // Code must be loaded before we can execute
        return -1;
    }
}
*/

struct ebpf_inst
ubpf_fetch_instruction(const struct ubpf_vm* vm, uint16_t pc)
{
    // XOR instruction with base address of vm.
    // This makes ROP attack more difficult.
    ebpf_encoded_inst encode_inst;
    encode_inst.inst = vm->insts[pc];
    encode_inst.value ^= (uint64)vm->insts;
    encode_inst.value ^= vm->pointer_secret;
    return encode_inst.inst;
}

#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)

#define htobe16(x) (x)
#define htobe32(x) (x)
#define htobe64(x) (x)

#define UINT32_MAX 4294967295U

#define SHIFT_MASK_32_BIT(X) ((X)&0x1f)
#define SHIFT_MASK_64_BIT(X) ((X)&0x3f)

typedef uint64 uintptr_t;

static uint32_t
u32(uint64 x)
{
    return x;
}

static int32_t
i32(uint64 x)
{
    return x;
}

#define IS_ALIGNED(x, a) (((uintptr_t)(x) & ((a)-1)) == 0)

inline static uint64
ubpf_mem_load(uint64 address, size_t size)
{
    if (!IS_ALIGNED(address, size)) {
        // Fill the result with 0 to avoid leaking uninitialized memory.
        uint64 value = 0;
        memmove(&value, (void*)address, size);
        return value;
    }

    switch (size) {
        case 1:
            return *(uint8_t*)address;
        case 2:
            return *(uint16_t*)address;
        case 4:
            return *(uint32_t*)address;
        case 8:
            return *(uint64*)address;
        default:
            panic("bpf mem load.\n");
    }
}

inline static void
ubpf_mem_store(uint64 address, uint64 value, size_t size)
{
    if (!IS_ALIGNED(address, size)) {
        memmove((void*)address, &value, size);
        return;
    }

    switch (size) {
        case 1:
            *(uint8_t*)address = value;
            break;
        case 2:
            *(uint16_t*)address = value;
            break;
        case 4:
            *(uint32_t*)address = value;
            break;
        case 8:
            *(uint64*)address = value;
            break;
        default:
            panic("bpf mem store.\n");
    }
}

static bool
bounds_check(
        const struct ubpf_vm* vm,
        void* addr,
        int size,
        const char* type,
        uint16_t cur_pc,
        void* mem,
        size_t mem_len,
        void* stack)
{
    if (!vm->bounds_check_enabled)
        return true;
    if (mem && (addr >= mem && ((char*)addr + size) <= ((char*)mem + mem_len))) {
        /* Context access */
        return true;
    } else if (addr >= stack && ((char*)addr + size) <= ((char*)stack + UBPF_STACK_SIZE)) {
        /* Stack access */
        return true;
    } else if (
            vm->bounds_check_function != NULL &&
            vm->bounds_check_function(vm->bounds_check_user_data, (uintptr_t)addr, size)) {
        /* Registered region */
        return true;
    } else {
        printf("uBPF error: out of bounds memory %s at PC %u, addr %p, size %d\nmem %p/%zd stack %p/%d\n",
               type,
               cur_pc,
               addr,
               size,
               mem,
               mem_len,
               stack,
               UBPF_STACK_SIZE);
        return false;
    }
}

int
ubpf_exec(const struct ubpf_vm* vm, void* mem, size_t mem_len, uint64* bpf_return_value)
{
    uint16_t pc = 0;
    const struct ebpf_inst* insts = vm->insts;
    uint64* reg;
    uint64 _reg[16];
    uint64 ras_index = 0;
    int return_value = -1;
    
    uint64 stack[UBPF_STACK_SIZE / sizeof(uint64)];
    struct ubpf_stack_frame stack_frames[UBPF_MAX_CALL_DEPTH] = {
            0,
    };

    if (!insts) {
        /* Code must be loaded before we can execute */
        return -1;
    }
    
    reg = _reg;

    reg[1] = (uintptr_t)mem;
    reg[1] = (uint64)mem;
    reg[2] = (uint64)mem_len;
    reg[10] = (uintptr_t)stack + UBPF_STACK_SIZE;

    while (1) {
        const uint16_t cur_pc = pc;
        struct ebpf_inst inst = ubpf_fetch_instruction(vm, pc++);

        switch (inst.opcode) {
            case EBPF_OP_ADD_IMM:
                reg[inst.dst] += inst.imm;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_ADD_REG:
                reg[inst.dst] += reg[inst.src];
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_SUB_IMM:
                reg[inst.dst] -= inst.imm;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_SUB_REG:
                reg[inst.dst] -= reg[inst.src];
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_MUL_IMM:
                reg[inst.dst] *= inst.imm;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_MUL_REG:
                reg[inst.dst] *= reg[inst.src];
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_DIV_IMM:
                reg[inst.dst] = u32(inst.imm) ? u32(reg[inst.dst]) / u32(inst.imm) : 0;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_DIV_REG:
                reg[inst.dst] = reg[inst.src] ? u32(reg[inst.dst]) / u32(reg[inst.src]) : 0;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_OR_IMM:
                reg[inst.dst] |= inst.imm;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_OR_REG:
                reg[inst.dst] |= reg[inst.src];
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_AND_IMM:
                reg[inst.dst] &= inst.imm;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_AND_REG:
                reg[inst.dst] &= reg[inst.src];
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_LSH_IMM:
                reg[inst.dst] = (u32(reg[inst.dst]) << SHIFT_MASK_32_BIT(inst.imm) & UINT32_MAX);
                break;
            case EBPF_OP_LSH_REG:
                reg[inst.dst] = (u32(reg[inst.dst]) << SHIFT_MASK_32_BIT(reg[inst.src]) & UINT32_MAX);
                break;
            case EBPF_OP_RSH_IMM:
                reg[inst.dst] = u32(reg[inst.dst]) >> SHIFT_MASK_32_BIT(inst.imm);
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_RSH_REG:
                reg[inst.dst] = u32(reg[inst.dst]) >> SHIFT_MASK_32_BIT(reg[inst.src]);
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_NEG:
                reg[inst.dst] = -(int64)reg[inst.dst];
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_MOD_IMM:
                reg[inst.dst] = u32(inst.imm) ? u32(reg[inst.dst]) % u32(inst.imm) : u32(reg[inst.dst]);
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_MOD_REG:
                reg[inst.dst] = u32(reg[inst.src]) ? u32(reg[inst.dst]) % u32(reg[inst.src]) : u32(reg[inst.dst]);
                break;
            case EBPF_OP_XOR_IMM:
                reg[inst.dst] ^= inst.imm;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_XOR_REG:
                reg[inst.dst] ^= reg[inst.src];
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_MOV_IMM:
                reg[inst.dst] = inst.imm;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_MOV_REG:
                reg[inst.dst] = reg[inst.src];
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_ARSH_IMM:
                reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
                reg[inst.dst] &= UINT32_MAX;
                break;
            case EBPF_OP_ARSH_REG:
                reg[inst.dst] = (int32_t)reg[inst.dst] >> u32(reg[inst.src]);
                reg[inst.dst] &= UINT32_MAX;
                break;

            case EBPF_OP_LE:
                if (inst.imm == 16) {
                    reg[inst.dst] = htole16(reg[inst.dst]);
                } else if (inst.imm == 32) {
                    reg[inst.dst] = htole32(reg[inst.dst]);
                } else if (inst.imm == 64) {
                    reg[inst.dst] = htole64(reg[inst.dst]);
                }
                break;
            case EBPF_OP_BE:
                if (inst.imm == 16) {
                    reg[inst.dst] = htobe16(reg[inst.dst]);
                } else if (inst.imm == 32) {
                    reg[inst.dst] = htobe32(reg[inst.dst]);
                } else if (inst.imm == 64) {
                    reg[inst.dst] = htobe64(reg[inst.dst]);
                }
                break;

            case EBPF_OP_ADD64_IMM:
                reg[inst.dst] += inst.imm;
                break;
            case EBPF_OP_ADD64_REG:
                reg[inst.dst] += reg[inst.src];
                break;
            case EBPF_OP_SUB64_IMM:
                reg[inst.dst] -= inst.imm;
                break;
            case EBPF_OP_SUB64_REG:
                reg[inst.dst] -= reg[inst.src];
                break;
            case EBPF_OP_MUL64_IMM:
                reg[inst.dst] *= inst.imm;
                break;
            case EBPF_OP_MUL64_REG:
                reg[inst.dst] *= reg[inst.src];
                break;
            case EBPF_OP_DIV64_IMM:
                reg[inst.dst] = inst.imm ? reg[inst.dst] / inst.imm : 0;
                break;
            case EBPF_OP_DIV64_REG:
                reg[inst.dst] = reg[inst.src] ? reg[inst.dst] / reg[inst.src] : 0;
                break;
            case EBPF_OP_OR64_IMM:
                reg[inst.dst] |= inst.imm;
                break;
            case EBPF_OP_OR64_REG:
                reg[inst.dst] |= reg[inst.src];
                break;
            case EBPF_OP_AND64_IMM:
                reg[inst.dst] &= inst.imm;
                break;
            case EBPF_OP_AND64_REG:
                reg[inst.dst] &= reg[inst.src];
                break;
            case EBPF_OP_LSH64_IMM:
                reg[inst.dst] <<= SHIFT_MASK_64_BIT(inst.imm);
                break;
            case EBPF_OP_LSH64_REG:
                reg[inst.dst] <<= SHIFT_MASK_64_BIT(reg[inst.src]);
                break;
            case EBPF_OP_RSH64_IMM:
                reg[inst.dst] >>= SHIFT_MASK_64_BIT(inst.imm);
                break;
            case EBPF_OP_RSH64_REG:
                reg[inst.dst] >>= SHIFT_MASK_64_BIT(reg[inst.src]);
                break;
            case EBPF_OP_NEG64:
                reg[inst.dst] = -reg[inst.dst];
                break;
            case EBPF_OP_MOD64_IMM:
                reg[inst.dst] = inst.imm ? reg[inst.dst] % inst.imm : reg[inst.dst];
                break;
            case EBPF_OP_MOD64_REG:
                reg[inst.dst] = reg[inst.src] ? reg[inst.dst] % reg[inst.src] : reg[inst.dst];
                break;
            case EBPF_OP_XOR64_IMM:
                reg[inst.dst] ^= inst.imm;
                break;
            case EBPF_OP_XOR64_REG:
                reg[inst.dst] ^= reg[inst.src];
                break;
            case EBPF_OP_MOV64_IMM:
                reg[inst.dst] = inst.imm;
                break;
            case EBPF_OP_MOV64_REG:
                reg[inst.dst] = reg[inst.src];
                break;
            case EBPF_OP_ARSH64_IMM:
                reg[inst.dst] = (int64)reg[inst.dst] >> inst.imm;
                break;
            case EBPF_OP_ARSH64_REG:
                reg[inst.dst] = (int64)reg[inst.dst] >> reg[inst.src];
                break;

                /*
                 * HACK runtime bounds check
                 *
                 * Needed since we don't have a verifier yet.
                 */
#define BOUNDS_CHECK_LOAD(size)                                                                                 \
    do {                                                                                                        \
        if (!bounds_check(vm, (char*)reg[inst.src] + inst.offset, size, "load", cur_pc, mem, mem_len, stack)) { \
            return_value = -1;                                                                                  \
            goto cleanup;                                                                                       \
        }                                                                                                       \
    } while (0)
#define BOUNDS_CHECK_STORE(size)                                                                                 \
    do {                                                                                                         \
        if (!bounds_check(vm, (char*)reg[inst.dst] + inst.offset, size, "store", cur_pc, mem, mem_len, stack)) { \
            return_value = -1;                                                                                   \
            goto cleanup;                                                                                        \
        }                                                                                                        \
    } while (0)

            case EBPF_OP_LDXW:
                BOUNDS_CHECK_LOAD(4);
                reg[inst.dst] = ubpf_mem_load(reg[inst.src] + inst.offset, 4);
                break;
            case EBPF_OP_LDXH:
                BOUNDS_CHECK_LOAD(2);
                reg[inst.dst] = ubpf_mem_load(reg[inst.src] + inst.offset, 2);
                break;
            case EBPF_OP_LDXB:
                BOUNDS_CHECK_LOAD(1);
                reg[inst.dst] = ubpf_mem_load(reg[inst.src] + inst.offset, 1);
                break;
            case EBPF_OP_LDXDW:
                BOUNDS_CHECK_LOAD(8);
                reg[inst.dst] = ubpf_mem_load(reg[inst.src] + inst.offset, 8);
                break;

            case EBPF_OP_STW:
                BOUNDS_CHECK_STORE(4);
                ubpf_mem_store(reg[inst.dst] + inst.offset, inst.imm, 4);
                break;
            case EBPF_OP_STH:
                BOUNDS_CHECK_STORE(2);
                ubpf_mem_store(reg[inst.dst] + inst.offset, inst.imm, 2);
                break;
            case EBPF_OP_STB:
                BOUNDS_CHECK_STORE(1);
                ubpf_mem_store(reg[inst.dst] + inst.offset, inst.imm, 1);
                break;
            case EBPF_OP_STDW:
                BOUNDS_CHECK_STORE(8);
                ubpf_mem_store(reg[inst.dst] + inst.offset, inst.imm, 8);
                break;

            case EBPF_OP_STXW:
                BOUNDS_CHECK_STORE(4);
                ubpf_mem_store(reg[inst.dst] + inst.offset, reg[inst.src], 4);
                break;
            case EBPF_OP_STXH:
                BOUNDS_CHECK_STORE(2);
                ubpf_mem_store(reg[inst.dst] + inst.offset, reg[inst.src], 2);
                break;
            case EBPF_OP_STXB:
                BOUNDS_CHECK_STORE(1);
                ubpf_mem_store(reg[inst.dst] + inst.offset, reg[inst.src], 1);
                break;
            case EBPF_OP_STXDW:
                BOUNDS_CHECK_STORE(8);
                ubpf_mem_store(reg[inst.dst] + inst.offset, reg[inst.src], 8);
                break;

            case EBPF_OP_LDDW:
                reg[inst.dst] = u32(inst.imm) | ((uint64)ubpf_fetch_instruction(vm, pc++).imm << 32);
                break;

            case EBPF_OP_JA:
                pc += inst.offset;
                break;
            case EBPF_OP_JEQ_IMM:
                if (reg[inst.dst] == inst.imm) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JEQ_REG:
                if (reg[inst.dst] == reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JEQ32_IMM:
                if (u32(reg[inst.dst]) == u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JEQ32_REG:
                if (u32(reg[inst.dst]) == reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JGT_IMM:
                if (reg[inst.dst] > u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JGT_REG:
                if (reg[inst.dst] > reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JGT32_IMM:
                if (u32(reg[inst.dst]) > u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JGT32_REG:
                if (u32(reg[inst.dst]) > u32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JGE_IMM:
                if (reg[inst.dst] >= u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JGE_REG:
                if (reg[inst.dst] >= reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JGE32_IMM:
                if (u32(reg[inst.dst]) >= u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JGE32_REG:
                if (u32(reg[inst.dst]) >= u32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JLT_IMM:
                if (reg[inst.dst] < u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JLT_REG:
                if (reg[inst.dst] < reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JLT32_IMM:
                if (u32(reg[inst.dst]) < u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JLT32_REG:
                if (u32(reg[inst.dst]) < u32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JLE_IMM:
                if (reg[inst.dst] <= u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JLE_REG:
                if (reg[inst.dst] <= reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JLE32_IMM:
                if (u32(reg[inst.dst]) <= u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JLE32_REG:
                if (u32(reg[inst.dst]) <= u32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSET_IMM:
                if (reg[inst.dst] & inst.imm) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSET_REG:
                if (reg[inst.dst] & reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSET32_IMM:
                if (u32(reg[inst.dst]) & u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSET32_REG:
                if (u32(reg[inst.dst]) & u32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JNE_IMM:
                if (reg[inst.dst] != inst.imm) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JNE_REG:
                if (reg[inst.dst] != reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JNE32_IMM:
                if (u32(reg[inst.dst]) != u32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JNE32_REG:
                if (u32(reg[inst.dst]) != u32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSGT_IMM:
                if ((int64)reg[inst.dst] > inst.imm) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSGT_REG:
                if ((int64)reg[inst.dst] > (int64)reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSGT32_IMM:
                if (i32(reg[inst.dst]) > i32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSGT32_REG:
                if (i32(reg[inst.dst]) > i32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSGE_IMM:
                if ((int64)reg[inst.dst] >= inst.imm) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSGE_REG:
                if ((int64)reg[inst.dst] >= (int64)reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSGE32_IMM:
                if (i32(reg[inst.dst]) >= i32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSGE32_REG:
                if (i32(reg[inst.dst]) >= i32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSLT_IMM:
                if ((int64)reg[inst.dst] < inst.imm) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSLT_REG:
                if ((int64)reg[inst.dst] < (int64)reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSLT32_IMM:
                if (i32(reg[inst.dst]) < i32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSLT32_REG:
                if (i32(reg[inst.dst]) < i32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSLE_IMM:
                if ((int64)reg[inst.dst] <= inst.imm) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSLE_REG:
                if ((int64)reg[inst.dst] <= (int64)reg[inst.src]) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSLE32_IMM:
                if (i32(reg[inst.dst]) <= i32(inst.imm)) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_JSLE32_REG:
                if (i32(reg[inst.dst]) <= i32(reg[inst.src])) {
                    pc += inst.offset;
                }
                break;
            case EBPF_OP_EXIT:
                if (ras_index > 0) {
                    ras_index--;
                    pc = stack_frames[ras_index].return_address;
                    reg[BPF_REG_6] = stack_frames[ras_index].saved_registers[0];
                    reg[BPF_REG_7] = stack_frames[ras_index].saved_registers[1];
                    reg[BPF_REG_8] = stack_frames[ras_index].saved_registers[2];
                    reg[BPF_REG_9] = stack_frames[ras_index].saved_registers[3];
                    break;
                }
                *bpf_return_value = reg[0];
                return_value = 0;
                goto cleanup;
            case EBPF_OP_CALL:
                // Differentiate between local and external calls -- assume that the
                // program was assembled with the same endianess as the host machine.
                if (inst.src == 0) {
                    // Handle call by address to external function.
                    reg[0] = vm->ext_funcs[inst.imm]->func(reg[1], reg[2], reg[3], reg[4], reg[5]);
                    // Unwind the stack if unwind extension returns success.
                    if (inst.imm == vm->unwind_stack_extension_index && reg[0] == 0) {
                        *bpf_return_value = reg[0];
                        return_value = 0;
                        goto cleanup;
                    }
                } else if (inst.src == 1) {
                    if (ras_index >= UBPF_MAX_CALL_DEPTH) {
                        /*vm->error_printf(
                                stderr,
                                "uBPF error: number of nested functions calls (%lu) exceeds max (%lu) at PC %u\n",
                                ras_index + 1,
                                UBPF_MAX_CALL_DEPTH,
                                cur_pc);*/
                        printf("uBPF error: number of nested functions calls (%lu) exceeds max (%lu) at PC %u\n",
                               ras_index + 1,
                               UBPF_MAX_CALL_DEPTH,
                               cur_pc);
                        return_value = -1;
                        goto cleanup;
                    }
                    stack_frames[ras_index].saved_registers[0] = reg[BPF_REG_6];
                    stack_frames[ras_index].saved_registers[1] = reg[BPF_REG_7];
                    stack_frames[ras_index].saved_registers[2] = reg[BPF_REG_8];
                    stack_frames[ras_index].saved_registers[3] = reg[BPF_REG_9];
                    stack_frames[ras_index].return_address = pc;
                    ras_index++;
                    pc += inst.imm;
                    break;
                } else if (inst.src == 2) {
                    // Calling external function by BTF ID is not yet supported.
                    return_value = -1;
                    goto cleanup;
                }
                // Because we have already validated, we can assume that the type code is
                // valid.
                break;
        }
    }

    cleanup:
    return return_value;
}