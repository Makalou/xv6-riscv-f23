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

// use global variables instead of using malloc
struct ubpf_vm g_ubpf_vm;
ext_func g_ext_funcs[MAX_EXT_FUNCS];
const char* g_ext_func_names[MAX_EXT_FUNCS];

int
ubpf_translate_null(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg)
{
    /* NULL JIT target - just returns an error. */
    UNUSED(vm);
    UNUSED(buffer);
    UNUSED(size);
    printf("Code can not be JITed on this target.\n");
    return -1;
}

void
ubpf_unload_code(struct ubpf_vm* vm)
{
    if (vm->jitted) {
        printf("Error: vm->jitted != NULL");
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
    vm->ext_funcs = NULL;
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
    vm->ext_funcs = g_ext_funcs;
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