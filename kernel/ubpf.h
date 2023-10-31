typedef unsigned char uint8_t;
typedef unsigned char bool;
typedef unsigned short uint16_t;
typedef unsigned int  uint32_t;
typedef unsigned long uint64_t;
typedef unsigned long size_t;

/**
 * @brief Opaque type for a uBPF JIT compiled function.
 */
typedef uint64_t (*ubpf_jit_fn)(void* mem, size_t mem_len);

typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

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
typedef uint64_t (*ubpf_data_relocation)(
    void* user_context,
    const uint8_t* data,
    uint64_t data_size,
    const char* symbol_name,
    uint64_t symbol_offset,
    uint64_t symbol_size);

typedef bool (*ubpf_bounds_check)(void* context, uint64_t addr, uint64_t size);

struct ubpf_vm
{
    struct ebpf_inst* insts;
    uint16_t num_insts;
    ubpf_jit_fn jitted;
    size_t jitted_size;
    ext_func* ext_funcs;
    bool* int_funcs;
    const char** ext_func_names;
    bool bounds_check_enabled;
    // The function should be different in xv6.
    //int (*error_printf)(FILE* stream, const char* format, ...);
    int (*translate)(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
    int unwind_stack_extension_index;
    uint64_t pointer_secret;
    ubpf_data_relocation data_relocation_function;
    void* data_relocation_user_data;
    ubpf_bounds_check bounds_check_function;
    void* bounds_check_user_data;
#ifdef DEBUG
    uint64_t* regs;
#endif
};