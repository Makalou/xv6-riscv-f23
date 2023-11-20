
#include "ubpf.h"
#include "elfdefinitions.h"
#include "types.h"
#include "riscv.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

#define MAX_SECTIONS 32

#ifndef R_BPF_64_64
#define R_BPF_64_64 1
#endif

#ifndef R_BPF_64_32
#define R_BPF_64_32 2
#endif

typedef struct _bounds
{
    const void* base;
    uint64 size;
} bounds;

typedef struct _section
{
    const Elf64_Shdr* shdr;
    const void* data;
    uint64 size;
} section;

struct relocated_function
{
    const char* name;
    const Elf64_Shdr* shdr;
    const void* native_data;
    const void* linked_data;
    uint64 native_section_start;
    Elf64_Xword size;
    uint64 landed;
};

static const void*
bounds_check(bounds* bounds, uint64 offset, uint64 size)
{
    if (offset + size > bounds->size || offset + size < offset) {
        return NULL;
    }
    return bounds->base + offset;
}

void* calloc( size_t num, size_t size )
{
    //size_t total = num * size;
    void* mem = kalloc();
    //todo : how to solve
    return mem;
}

void free(void* mem)
{
    kfree(mem);
}

int ehdr_check(const Elf64_Ehdr* ehdr)
{
    if (!ehdr) {
        printf("not enough data for ELF header\n");
        return -1;
    }

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
        printf("wrong magic\n");
        return -1;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        printf("wrong class\n");
        return -1;
    }

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        printf("wrong byte order");
        return -1;
    }

    if (ehdr->e_ident[EI_VERSION] != 1) {
        printf("wrong version");
        return -1;
    }

    if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE) {
        printf("wrong OS ABI");
        return -1;
    }

    if (ehdr->e_type != ET_REL) {
        printf("wrong type, expected relocatable");
        return -1;
    }

    if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF) {
        printf("wrong machine, expected none or BPF, got %d",ehdr->e_machine);
        return -1;
    }

    if (ehdr->e_shnum > MAX_SECTIONS) {
        printf("too many sections");
        return -1;
    }

    return 0;
}

int
ubpf_load_elf_ex(struct ubpf_vm* vm, int vm_idx,const void* elf, size_t elf_size, const char* main_function_name)
{
    bounds b = {.base = elf, .size = elf_size};
    void* linked_program = NULL;
    int section_count = -1;
    int i;
    uint total_functions = 0;
    int load_success = -1;
    struct relocated_function** relocated_functions = NULL;

    const Elf64_Ehdr* ehdr = bounds_check(&b, 0, sizeof(*ehdr));

    if(ehdr_check(ehdr)!=0){
        goto error;
    }

    section_count = ehdr->e_shnum;

    //printf("section_count : %d\n",section_count);

    /* Parse section headers into an array */
    section sections[MAX_SECTIONS];
    uint64 current_section_header_offset = ehdr->e_shoff;
    for (i = 0; i < section_count; i++) {
        const Elf64_Shdr* shdr = bounds_check(&b, current_section_header_offset, sizeof(Elf64_Ehdr*));
        if (!shdr) {
            printf("bad section header offset or size");
            goto error;
        }
        current_section_header_offset += ehdr->e_shentsize;

        const void* data = bounds_check(&b, shdr->sh_offset, shdr->sh_size);
        if (!data) {
            printf("bad section offset or size");
            goto error;
        }

        sections[i].shdr = shdr;
        sections[i].data = data;
        sections[i].size = shdr->sh_size;
    }

    const char* strtab_data = NULL;
    int strtab_size = 0;
    for (i = 0; i < section_count; i++) {
        const Elf64_Shdr* shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_STRTAB) {
            strtab_data = sections[i].data;
            strtab_size = sections[i].size;
            break;
        }
    }

    if (!strtab_data) {
        printf("could not find the string table in the elf file");
        goto error;
    }

    Elf64_Sym* symbols = NULL;
    int symtab_size = 0;
    for (i = 0; i < section_count; i++) {
        const Elf64_Shdr* shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_SYMTAB) {
            symbols = (Elf64_Sym*)sections[i].data;
            symtab_size = sections[i].size;
            break;
        }
    }

    if (!symbols) {
        printf("could not find the symbol table in the elf file");
        goto error;
    }

    uint64 total_symbols = symtab_size / sizeof(Elf64_Sym);
    uint linked_program_size = 0;
    /*
     * Be conservative and assume that each of the symbols represents a function.
     */
    relocated_functions = (struct relocated_function**)calloc(total_symbols, sizeof(struct relocated_function*));

    if (relocated_functions == NULL) {
        printf("could not allocate memory for storing information about relocated functions");
        goto error;
    }

    total_functions = 1;
    for (uint64 i = 0; i < total_symbols; i++) {
        const Elf64_Sym* sym = symbols + i;
        //printf("%s\n",strtab_data+sym->st_name);
        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
            continue;
        }

        /*
         * Until that we are sure the symbol is valid, we use a stack-allocated relocated_function.
         */
        struct relocated_function rf = {};

        if (sym->st_name >= strtab_size) {
            printf("a function symbol contained a bad name");
            goto error;
        }
        rf.name = strtab_data + sym->st_name;

        if (sym->st_shndx > section_count) {
            printf("a function symbol contained a bad section index");
            goto error;
        }
        rf.shdr = sections[sym->st_shndx].shdr;

        if (rf.shdr->sh_type != SHT_PROGBITS || rf.shdr->sh_flags != (SHF_ALLOC | SHF_EXECINSTR)) {
            printf("function symbol %s points to a non-executable section");
            goto error;
        }

        rf.native_data = sections[sym->st_shndx].data + sym->st_value;

        rf.size = sym->st_size;
        rf.native_section_start = sym->st_value;

        linked_program_size += rf.size;

        bool is_main_function = (main_function_name && !strncmp(rf.name, main_function_name, strlen(main_function_name)));
        /*
         * When the user did not give us a main function, we assume that the function at the beginning
         * of the .text section is the main function.
         */
        bool is_default_main_function =
                (!main_function_name && !strncmp(strtab_data + rf.shdr->sh_name, ".text",5) && rf.native_section_start == 0);

        struct relocated_function* rfp = NULL;
        if (is_main_function || is_default_main_function) {
            rfp = relocated_functions[0] = (struct relocated_function*)calloc(1, sizeof(struct relocated_function));
        } else {
            rfp = relocated_functions[total_functions++] =
                    (struct relocated_function*)calloc(1, sizeof(struct relocated_function));
        }
        if (rfp == NULL) {
            printf("could not allocate space to store metadata about a relocated function");
            goto error;
        }
        memmove(rfp, &rf, sizeof(struct relocated_function));
    }

    if (!relocated_functions[0]) {
        printf("%s function not found.", main_function_name);
        goto error;
    }

    linked_program = (char*)calloc(linked_program_size, sizeof(char));
    if (!linked_program) {
        printf("failed to allocate memory for the linked program");
        goto error;
    }

    uint64 current_landing_spot = 0;
    for (uint i = 0; i < total_functions; i++) {
        memmove(linked_program + current_landing_spot, relocated_functions[i]->native_data, relocated_functions[i]->size);
        relocated_functions[i]->landed = current_landing_spot / 8;
        relocated_functions[i]->linked_data = linked_program + current_landing_spot;
        current_landing_spot += relocated_functions[i]->size;
    }

    /* Process each relocation section */
    for (i = 0; i < section_count; i++) {

        section* relo_section = &sections[i];
        if (relo_section->shdr->sh_type != SHT_REL) {
            continue;
        }

        /* the sh_info field is the index of the section to which these relocations apply. */
        int relo_applies_to_section = relo_section->shdr->sh_info;
        int relo_symtab_idx = relo_section->shdr->sh_link;

        /* Right now the loader only handles relocations that are applied to an executable section. */
        if (sections[relo_applies_to_section].shdr->sh_type != SHT_PROGBITS ||
            sections[relo_applies_to_section].shdr->sh_flags != (SHF_ALLOC | SHF_EXECINSTR)) {
            continue;
        }
        const Elf64_Rel* rs = relo_section->data;

        if (relo_symtab_idx >= section_count) {
            printf("bad symbol table section index");
            goto error;
        }

        section* relo_symtab = &sections[relo_symtab_idx];
        const Elf64_Sym* relo_syms = relo_symtab->data;
        uint32_t relo_symtab_num_syms = relo_symtab->size / sizeof(relo_syms[0]);

        int j;
        for (j = 0; j < relo_section->size / sizeof(Elf64_Rel); j++) {
            /* Copy rs[j] as it may not be appropriately aligned */
            Elf64_Rel relocation;
            memmove(&relocation, rs + j, sizeof(Elf64_Rel));

            if (ELF64_R_SYM(relocation.r_info) >= relo_symtab_num_syms) {
                printf("a relocation contained a bad symbol index");
                goto error;
            }

            /* No matter what the relocation type, the 4 MSBs are an index to a symbol
             * in the symbol table. So, we will set that up here for everyone's use.
             */
            Elf64_Sym relo_sym;
            memmove(&relo_sym, relo_syms + ELF64_R_SYM(relocation.r_info), sizeof(Elf64_Sym));
            if (relo_sym.st_name >= strtab_size) {
                printf("a relocation's symbol contained a bad name");
                goto error;
            }
            const char* relo_sym_name = strtab_data + relo_sym.st_name;
            /*
             * Let each relocation type handle the semantics of that symbol
             * table entry on its own.
             */

            struct relocated_function* source_function = NULL;

            for (uint i = 0; i < total_functions; i++) {
                if (sections[relo_applies_to_section].shdr == relocated_functions[i]->shdr &&
                    relocation.r_offset > relocated_functions[i]->native_section_start &&
                    relocation.r_offset < relocated_functions[i]->native_section_start + relocated_functions[i]->size) {
                    source_function = relocated_functions[i];
                    break;
                }
            }

            if (!source_function) {
                printf("a relocation's symbol contained a bad name");
                goto error;
            }

            struct ebpf_inst* applies_to_inst =
                    (struct
                            ebpf_inst*)(source_function->linked_data + (relocation.r_offset - source_function->native_section_start));
            uint64 applies_to_inst_index =
                    source_function->landed + ((relocation.r_offset - source_function->native_section_start) / 8);

            if (!source_function) {
                printf("an instruction with relocation is not in a function");
                goto error;
            }

            switch (ELF64_R_TYPE(relocation.r_info)) {
                case R_BPF_64_64: {
                    if (relocation.r_offset + 8 > sections[relo_applies_to_section].size) {
                        printf("bad R_BPF_64_64 relocation offset");
                        goto error;
                    }

                    if (relo_sym.st_shndx > section_count) {
                        printf("bad R_BPF_64_64 relocation section index");
                        goto error;
                    }
                    section* map = &sections[relo_sym.st_shndx];
                    if (map->shdr->sh_type != SHT_PROGBITS || map->shdr->sh_flags != (SHF_ALLOC | SHF_WRITE)) {
                        printf("bad R_BPF_64_64 relocation section");
                        goto error;
                    }

                    if (relo_sym.st_size + relo_sym.st_value > map->size) {
                        printf("bad R_BPF_64_64 size");
                        goto error;
                    }

                    struct ebpf_inst* applies_to_inst2 = applies_to_inst + 1;
                    if (applies_to_inst->opcode != EBPF_OP_LDDW) {
                        printf("bad R_BPF_64_64 relocation instruction");
                        goto error;
                    }
                    if (relocation.r_offset + sizeof(struct ebpf_inst) * 2 > sections[relo_applies_to_section].size) {
                        printf("bad R_BPF_64_64 relocation offset");
                        goto error;
                    }

                    if (!vm->data_relocation_function) {
                        printf("R_BPF_64_64 data relocation function not set");
                        goto error;
                    }

                    uint64 imm = vm->data_relocation_function(
                            vm->data_relocation_user_data,
                            map->data,
                            map->size,
                            relo_sym_name,
                            relo_sym.st_value,
                            relo_sym.st_size);
                    applies_to_inst->imm = (uint32_t)imm;
                    applies_to_inst2->imm = (uint32_t)(imm >> 32);
                    break;
                }
                case R_BPF_64_32: {
                    if (applies_to_inst->src == 1) {
                        // Perform local function call relocation.
                        int target_function_in_section_idx = relo_sym.st_shndx;

                        uint offset_in_target_section = (applies_to_inst->imm + 1) * 8;

                        struct relocated_function* target_function = NULL;
                        for (uint i = 0; i < total_functions; i++) {
                            if (sections[target_function_in_section_idx].shdr == relocated_functions[i]->shdr &&
                                offset_in_target_section == relocated_functions[i]->native_section_start) {
                                target_function = relocated_functions[i];
                                break;
                            }
                        }
                        if (!target_function) {
                            printf("relocated target of a function call does not point to a known function");
                            goto error;
                        }

                        applies_to_inst->imm = target_function->landed - (applies_to_inst_index + 1);
                    } else {
                        // Perform helper function relocation.
                        // Note: This is a uBPF specific relocation type and is not part of the ELF specification.
                        // It is used to perform resolution from helper function name to helper function id.
                        const char* section_name = strtab_data + relo_sym.st_name;
                        //printf("section_name : %s\n",section_name);
                        unsigned int imm = ubpf_lookup_registered_function(vm, section_name);
                        if (imm == -1) {
                            printf("function '%s' not found", section_name);
                            goto error;
                        }

                        applies_to_inst->imm = imm;
                    }
                    break;
                }
                default:
                    printf(
                            "Warning: bad relocation type %llu; skipping.\n",
                            (long long unsigned)ELF64_R_TYPE(relocation.r_info));
                    break;
            }
        }
    }

    /*
     * We got this far -- we'll set a provisional success value.
     */
    load_success = 1;

    error:
    for (uint i = 0; i < total_functions; i++) {
        if (relocated_functions[i] != NULL) {
            free(relocated_functions[i]);
        }
    }
    free(relocated_functions);

    if (load_success > 0) {
        //printf("load elf success\n");
        load_success = ubpf_load(vm,vm_idx, linked_program, linked_program_size);
    }
    free(linked_program);
    return load_success;
}
