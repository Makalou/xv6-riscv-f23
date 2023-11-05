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

// use global variables instead of using malloc
struct ubpf_vm g_ubpf_vm;
ext_func g_ext_funcs[MAX_EXT_FUNCS];
const char* g_ext_func_names[MAX_EXT_FUNCS];
struct ebpf_inst g_ebpf_inst[UBPF_MAX_INSTS];
bool g_int_funcs[NUM_INSTS_MAX];

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
    vm = NULL;
}

struct ubpf_vm*
ubpf_create(void) {
    struct ubpf_vm* vm = &g_ubpf_vm;
    if (vm == NULL) {
        return NULL;
    }
    vm->ext_funcs = (ext_func **)&g_ext_funcs;
    if (vm->ext_funcs == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }
    vm->ext_func_names = g_ext_func_names;
    if (vm->ext_func_names == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }
    vm->bounds_check_enabled = true;
    //vm->error_printf = fprintf;

    vm->translate = ubpf_translate_null;
    vm->unwind_stack_extension_index = -1;
    vm->jitted = NULL;
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
    encode_inst.value ^= (uint64_t)vm->insts;
    encode_inst.value ^= vm->pointer_secret;
    vm->insts[pc] = encode_inst.inst;
}

int
ubpf_load(struct ubpf_vm* vm, const void* code, uint32_t code_len)
{
    //const struct ebpf_inst* source_inst = code;
    if (UBPF_STACK_SIZE % sizeof(uint64_t) != 0) {
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

    vm->insts = g_ebpf_inst;
    if (vm->insts == NULL) {
        ERR("out of memory");
        return -1;
    }
    vm->num_insts = code_len / sizeof(vm->insts[0]);
    vm->int_funcs = g_int_funcs;
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
ubpf_exec(const struct ubpf_vm* vm, void* mem, size_t mem_len, uint64_t* bpf_return_value)
{
    uint16_t pc = 0;
    const struct ebpf_inst* insts = vm->insts;
    uint64_t* reg;
    uint64_t _reg[16];
    uint64_t ras_index = 0;
    int return_value = -1;

    uint64_t stack[UBPF_STACK_SIZE / sizeof(uint64_t)];
    struct ubpf_stack_frame stack_frames[UBPF_MAX_CALL_DEPTH] = {
        0,
    };

    if (!insts) {
        // Code must be loaded before we can execute
        return -1;
    }
}
*/