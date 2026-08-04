#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

/* --- Structure Declarations --- */
typedef struct {
    char *filename;
    int fd;
    void *map_start;
    off_t file_size;
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr_table;
} elf_file_t;

struct fun_desc {
    char name;
    void (*fun)();
};

/* --- Global Variables --- */
int debug_mode = 0;
elf_file_t mapped_files[2] = {0};
int file_count = 0;

/* --- Helper Functions --- */
const char* get_section_type_name(Elf32_Word sh_type) {
    switch(sh_type) {
        case SHT_NULL:     return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB:   return "SYMTAB";
        case SHT_STRTAB:   return "STRTAB";
        case SHT_RELA:     return "RELA";
        case SHT_HASH:     return "HASH";
        case SHT_DYNAMIC:  return "DYNAMIC";
        case SHT_NOTE:     return "NOTE";
        case SHT_NOBITS:   return "NOBITS";
        case SHT_REL:      return "REL";
        case SHT_SHLIB:    return "SHLIB";
        case SHT_DYNSYM:   return "DYNSYM";
        default:           return "UNKNOWN";
    }
}

void clean_file_index(int idx) {
    if (mapped_files[idx].map_start && mapped_files[idx].map_start != MAP_FAILED) {
        munmap(mapped_files[idx].map_start, mapped_files[idx].file_size);
    }
    if (mapped_files[idx].fd > 0) {
        close(mapped_files[idx].fd);
    }
    if (mapped_files[idx].filename) {
        free(mapped_files[idx].filename);
    }
    memset(&mapped_files[idx], 0, sizeof(elf_file_t));
}

Elf32_Shdr* find_section_by_name(elf_file_t *file, const char *name) {
    if (!file || !file->ehdr || !file->shdr_table) return NULL;
    Elf32_Shdr *shstrtab_hdr = &file->shdr_table[file->ehdr->e_shstrndx];
    char *shstrtab = (char *)(file->map_start + shstrtab_hdr->sh_offset);
    
    for (int i = 0; i < file->ehdr->e_shnum; i++) {
        if (strcmp(shstrtab + file->shdr_table[i].sh_name, name) == 0) {
            return &file->shdr_table[i];
        }
    }
    return NULL;
}

/* --- Menu Actions --- */

void toggle_debug_mode() {
    debug_mode = !debug_mode;
    printf("Debug mode is now %s\n", debug_mode ? "ON" : "OFF");
}

void examine_elf_file() {
    if (file_count >= 2) {
        printf("Error: Already handling maximum limit of 2 ELF files.\n");
        return;
    }

    char filename[256];
    printf("Enter ELF file name: ");
    if (scanf("%255s", filename) != 1) return;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Error opening file");
        return;
    }

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        perror("Error stating file");
        close(fd);
        return;
    }

    void *map_start = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        perror("Error mapping file");
        close(fd);
        return;
    }

    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;

    // Validate ELF Magic Numbers
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        printf("Error: File '%s' is not a valid ELF file.\n", filename);
        munmap(map_start, sb.st_size);
        close(fd);
        return;
    }

    // Capture valid metadata into file structure
    mapped_files[file_count].filename = strdup(filename);
    mapped_files[file_count].fd = fd;
    mapped_files[file_count].map_start = map_start;
    mapped_files[file_count].file_size = sb.st_size;
    mapped_files[file_count].ehdr = ehdr;
    mapped_files[file_count].shdr_table = (Elf32_Shdr *)(map_start + ehdr->e_shoff);

    // Print Specifications
    printf("\nELF Header Specifications:\n");
    printf("  Magic bytes 1,2,3:         %c %c %c\n", ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
    printf("  Data encoding scheme:      %d (%s)\n", ehdr->e_ident[EI_DATA], 
           ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "2's complement, little endian" : "Big Endian");
    printf("  Entry point address:       0x%x\n", ehdr->e_entry);
    printf("  Section header table off:  %d (bytes)\n", ehdr->e_shoff);
    printf("  Number of section headers: %d\n", ehdr->e_shnum);
    printf("  Size of section header:    %d (bytes)\n", ehdr->e_shentsize);
    printf("  Program header table off:  %d (bytes)\n", ehdr->e_phoff);
    printf("  Number of program headers: %d\n", ehdr->e_phnum);
    printf("  Size of program header:    %d (bytes)\n", ehdr->e_phentsize);

    if (debug_mode) {
        printf("[DEBUG] Mapped starting address: %p\n", map_start);
        printf("[DEBUG] String table index (shstrndx): %d\n", ehdr->e_shstrndx);
    }

    file_count++;
}

void print_section_names() {
    if (file_count == 0) {
        printf("Error: No files currently mapped.\n");
        return;
    }

    for (int f = 0; f < file_count; f++) {
        elf_file_t *file = &mapped_files[f];
        Elf32_Shdr *shstrtab_hdr = &file->shdr_table[file->ehdr->e_shstrndx];
        char *shstrtab = (char *)(file->map_start + shstrtab_hdr->sh_offset);

        if (debug_mode) {
            printf("[DEBUG] File %s: shstrtab section offset: %d, size: %d\n", 
                   file->filename, shstrtab_hdr->sh_offset, shstrtab_hdr->sh_size);
        }

        printf("\nFile %s sections:\n", file->filename);
        printf("[index] section_name         section_address section_offset section_size  section_type\n");
        for (int i = 0; i < file->ehdr->e_shnum; i++) {
            Elf32_Shdr *shdr = &file->shdr_table[i];
            printf("[%2d]    %-20s 0x%08x      0x%06x         %d        %s\n",
                   i,
                   shstrtab + shdr->sh_name,
                   shdr->sh_addr,
                   shdr->sh_offset,
                   shdr->sh_size,
                   get_section_type_name(shdr->sh_type));
        }
    }
}

void print_symbols() {
    if (file_count == 0) {
        printf("Error: No files currently mapped.\n");
        return;
    }

    for (int f = 0; f < file_count; f++) {
        elf_file_t *file = &mapped_files[f];
        printf("\nFile %s symbols:\n", file->filename);

        int symtab_found = 0;
        for (int i = 0; i < file->ehdr->e_shnum; i++) {
            Elf32_Shdr *shdr = &file->shdr_table[i];
            if (shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM) {
                symtab_found = 1;
                Elf32_Sym *sym_table = (Elf32_Sym *)(file->map_start + shdr->sh_offset);
                int num_symbols = shdr->sh_size / shdr->sh_entsize;

                Elf32_Shdr *strtab_hdr = &file->shdr_table[shdr->sh_link];
                char *strtab = (char *)(file->map_start + strtab_hdr->sh_offset);

                Elf32_Shdr *shstrtab_hdr = &file->shdr_table[file->ehdr->e_shstrndx];
                char *shstrtab = (char *)(file->map_start + shstrtab_hdr->sh_offset);

                if (debug_mode) {
                    printf("[DEBUG] Found Symbol Table Section index: %d, Elements: %d\n", i, num_symbols);
                }

                printf("[index] value      section_index section_name         symbol_name\n");
                for (int j = 0; j < num_symbols; j++) {
                    Elf32_Sym *sym = &sym_table[j];
                    char sec_name_buf[32];

                    if (sym->st_shndx == SHN_UNDEF) {
                        strcpy(sec_name_buf, "UND");
                    } else if (sym->st_shndx == SHN_ABS) {
                        strcpy(sec_name_buf, "ABS");
                    } else if (sym->st_shndx == SHN_COMMON) {
                        strcpy(sec_name_buf, "COM");
                    } else if (sym->st_shndx < file->ehdr->e_shnum) {
                        strcpy(sec_name_buf, shstrtab + file->shdr_table[sym->st_shndx].sh_name);
                    } else {
                        sprintf(sec_name_buf, "%d", sym->st_shndx);
                    }

                    printf("[%2d]    0x%08x %-13d %-20s %s\n",
                           j, sym->st_value, sym->st_shndx, sec_name_buf, strtab + sym->st_name);
                }
            }
        }
        if (!symtab_found) {
            printf("Error: No symbol table found in this file.\n");
        }
    }
}

void print_relocations() {
    if (file_count == 0) {
        printf("Error: No files currently mapped.\n");
        return;
    }

    for (int f = 0; f < file_count; f++) {
        elf_file_t *file = &mapped_files[f];
        printf("\nFile %s relocations:\n", file->filename);

        int rel_found = 0;
        for (int i = 0; i < file->ehdr->e_shnum; i++) {
            Elf32_Shdr *shdr = &file->shdr_table[i];
            if (shdr->sh_type == SHT_REL) {
                rel_found = 1;
                Elf32_Rel *rel_table = (Elf32_Rel *)(file->map_start + shdr->sh_offset);
                int num_rel = shdr->sh_size / shdr->sh_entsize;

                // Find associated symbol table using sh_link
                Elf32_Shdr *symtab_hdr = &file->shdr_table[shdr->sh_link];
                Elf32_Sym *sym_table = (Elf32_Sym *)(file->map_start + symtab_hdr->sh_offset);

                // Find string table associated with symbol table
                Elf32_Shdr *strtab_hdr = &file->shdr_table[symtab_hdr->sh_link];
                char *strtab = (char *)(file->map_start + strtab_hdr->sh_offset);

                if (debug_mode) {
                    printf("[DEBUG] Relocation section: %d, entries: %d\n", i, num_rel);
                }

                printf("[index] location   related_symbol_name  type\n");
                for (int j = 0; j < num_rel; j++) {
                    Elf32_Rel *rel = &rel_table[j];
                    int sym_idx = ELF32_R_SYM(rel->r_info);
                    int rel_type = ELF32_R_TYPE(rel->r_info);
                    char *sym_name = strtab + sym_table[sym_idx].st_name;

                    printf("[%2d]    0x%08x %-20s %d\n", j, rel->r_offset, sym_name, rel_type);
                }
            }
        }
        if (!rel_found) {
            printf("No relocations\n");
        }
    }
}

void check_files_for_merge() {
    if (file_count < 2) {
        printf("Error: Two files must be opened and mapped first.\n");
        return;
    }

    elf_file_t *f1 = &mapped_files[0];
    elf_file_t *f2 = &mapped_files[1];

    Elf32_Shdr *symtab1_hdr = NULL, *symtab2_hdr = NULL;
    for (int i = 0; i < f1->ehdr->e_shnum; i++) 
        if (f1->shdr_table[i].sh_type == SHT_SYMTAB) symtab1_hdr = &f1->shdr_table[i];
    for (int i = 0; i < f2->ehdr->e_shnum; i++) 
        if (f2->shdr_table[i].sh_type == SHT_SYMTAB) symtab2_hdr = &f2->shdr_table[i];

    if (!symtab1_hdr || !symtab2_hdr) {
        printf("Feature not supported: Each file must contain exactly one symbol table.\n");
        return;
    }

    Elf32_Sym *symtab1 = (Elf32_Sym *)(f1->map_start + symtab1_hdr->sh_offset);
    int sym1_count = symtab1_hdr->sh_size / symtab1_hdr->sh_entsize;
    char *strtab1 = (char *)(f1->map_start + f1->shdr_table[symtab1_hdr->sh_link].sh_offset);

    Elf32_Sym *symtab2 = (Elf32_Sym *)(f2->map_start + symtab2_hdr->sh_offset);
    int sym2_count = symtab2_hdr->sh_size / symtab2_hdr->sh_entsize;
    char *strtab2 = (char *)(f2->map_start + f2->shdr_table[symtab2_hdr->sh_link].sh_offset);

    // Loop through SYMTAB1 elements (skipping dummy null symbol)
    for (int i = 1; i < sym1_count; i++) {
        char *name1 = strtab1 + symtab1[i].st_name;
        if (strlen(name1) == 0) continue;

        int found_in_2 = 0;
        int idx_in_2 = -1;
        for (int j = 1; j < sym2_count; j++) {
            if (strcmp(name1, strtab2 + symtab2[j].st_name) == 0) {
                found_in_2 = 1;
                idx_in_2 = j;
                break;
            }
        }

        if (symtab1[i].st_shndx == SHN_UNDEF) {
            if (!found_in_2 || symtab2[idx_in_2].st_shndx == SHN_UNDEF) {
                printf("Symbol %s undefined\n", name1);
            }
        } else {
            if (found_in_2 && symtab2[idx_in_2].st_shndx != SHN_UNDEF) {
                printf("Symbol %s multiply defined\n", name1);
            }
        }
    }
}

void merge_elf_files() {
    if (file_count < 2) {
        printf("Error: Two files must be mapped before executing merge.\n");
        return;
    }

    elf_file_t *f1 = &mapped_files[0];
    elf_file_t *f2 = &mapped_files[1];

    int out_fd = open("out.ro", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out_fd < 0) {
        perror("Error creating out.ro");
        return;
    }

    // Baseline configuration derived from File 1
    Elf32_Ehdr out_ehdr = *(f1->ehdr);
    
    // Allocate space dynamically in memory for the output Section Header table
    int shdr_table_size = out_ehdr.e_shnum * sizeof(Elf32_Shdr);
    Elf32_Shdr *out_shdr_table = malloc(shdr_table_size);
    memcpy(out_shdr_table, f1->shdr_table, shdr_table_size);

    // Write placeholder header to set starting file alignment
    write(out_fd, &out_ehdr, sizeof(Elf32_Ehdr));
    off_t current_offset = sizeof(Elf32_Ehdr);

    Elf32_Shdr *f1_shstrtab_hdr = &f1->shdr_table[f1->ehdr->e_shstrndx];
    char *f1_shstrtab = (char *)(f1->map_start + f1_shstrtab_hdr->sh_offset);

    // Process and append sections sequentially
    for (int i = 0; i < out_ehdr.e_shnum; i++) {
        char *sec_name = f1_shstrtab + f1->shdr_table[i].sh_name;
        
        if (f1->shdr_table[i].sh_type == SHT_NULL) {
            memset(&out_shdr_table[i], 0, sizeof(Elf32_Shdr));
            continue;
        }

        out_shdr_table[i].sh_offset = current_offset;

        if (strcmp(sec_name, ".text") == 0 || strcmp(sec_name, ".data") == 0 || strcmp(sec_name, ".rodata") == 0) {
            // Write payload data from File 1
            write(out_fd, f1->map_start + f1->shdr_table[i].sh_offset, f1->shdr_table[i].sh_size);
            current_offset += f1->shdr_table[i].sh_size;

            // Search and append relative payload tracking data from File 2
            Elf32_Shdr *f2_sec = find_section_by_name(f2, sec_name);
            if (f2_sec) {
                write(out_fd, f2->map_start + f2_sec->sh_offset, f2_sec->sh_size);
                out_shdr_table[i].sh_size = f1->shdr_table[i].sh_size + f2_sec->sh_size;
                current_offset += f2_sec->sh_size;
            } else {
                out_shdr_table[i].sh_size = f1->shdr_table[i].sh_size;
            }
        } 
        else if (f1->shdr_table[i].sh_type == SHT_SYMTAB) {
            /* Part 3.3 Bonus: Perform advanced symbol table analysis & modification */
            Elf32_Shdr *symtab1_hdr = &f1->shdr_table[i];
            int sym_count = symtab1_hdr->sh_size / symtab1_hdr->sh_entsize;
            Elf32_Sym *out_symtab = malloc(symtab1_hdr->sh_size);
            memcpy(out_symtab, f1->map_start + symtab1_hdr->sh_offset, symtab1_hdr->sh_size);

            char *strtab1 = (char *)(f1->map_start + f1->shdr_table[symtab1_hdr->sh_link].sh_offset);

            // Access File 2 Symbol Structures
            Elf32_Shdr *symtab2_hdr = NULL;
            for(int k=0; k<f2->ehdr->e_shnum; k++) 
                if(f2->shdr_table[k].sh_type == SHT_SYMTAB) symtab2_hdr = &f2->shdr_table[k];

            if (symtab2_hdr) {
                Elf32_Sym *symtab2 = (Elf32_Sym *)(f2->map_start + symtab2_hdr->sh_offset);
                int sym2_count = symtab2_hdr->sh_size / symtab2_hdr->sh_entsize;
                char *strtab2 = (char *)(f2->map_start + f2->shdr_table[symtab2_hdr->sh_link].sh_offset);
                char *f2_shstrtab = (char *)(f2->map_start + f2->shdr_table[f2->ehdr->e_shstrndx].sh_offset);

                for (int j = 1; j < sym_count; j++) {
                    if (out_symtab[j].st_shndx == SHN_UNDEF) {
                        char *name1 = strtab1 + out_symtab[j].st_name;
                        for (int m = 1; m < sym2_count; m++) {
                            if (strcmp(name1, strtab2 + symtab2[m].st_name) == 0 && symtab2[m].st_shndx != SHN_UNDEF) {
                                // Resolve properties
                                out_symtab[j].st_value = symtab2[m].st_value;
                                
                                // Remap section tracking parameters back to File 1 architecture indices
                                char *f2_sec_name = f2_shstrtab + f2->shdr_table[symtab2[m].st_shndx].sh_name;
                                for (int s = 0; s < out_ehdr.e_shnum; s++) {
                                    if (strcmp(f1_shstrtab + f1->shdr_table[s].sh_name, f2_sec_name) == 0) {
                                        out_symtab[j].st_shndx = s;
                                        // Update offset referencing bounds shifts
                                        out_symtab[j].st_value += f1->shdr_table[s].sh_size;
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            write(out_fd, out_symtab, symtab1_hdr->sh_size);
            free(out_symtab);
            current_offset += symtab1_hdr->sh_size;
        }
        else {
            // Transfer non-mergable sections safely
            write(out_fd, f1->map_start + f1->shdr_table[i].sh_offset, f1->shdr_table[i].sh_size);
            current_offset += f1->shdr_table[i].sh_size;
        }
    }

    // Finalize Section Header positioning tables
    out_ehdr.e_shoff = current_offset;
    write(out_fd, out_shdr_table, shdr_table_size);

    // Seek back to write structural corrections
    lseek(out_fd, 0, SEEK_SET);
    write(out_fd, &out_ehdr, sizeof(Elf32_Ehdr));

    free(out_shdr_table);
    close(out_fd);
    printf("Successfully completed partial merge. Resource saved as 'out.ro'\n");
}

void quit_program() {
    for (int i = 0; i < 2; i++) {
        clean_file_index(i);
    }
    printf("Exiting normally.\n");
    exit(0);
}

/* --- Core Application Interface Execution Loop --- */
int main(int argc, char **argv) {
    struct fun_desc menu[] = {
        {'D', toggle_debug_mode},
        {'F', examine_elf_file},
        {'N', print_section_names},
        {'S', print_symbols},
        {'R', print_relocations},
        {'C', check_files_for_merge},
        {'M', merge_elf_files},
        {'Q', quit_program},
        {0, NULL}
    };

    while (1) {
        printf("\nChoose action:\n");
        printf(" Toggle >D<ebug Mode\n");
        printf(" Examine ELF >F<ile\n");
        printf(" Print Section >N<ames\n");
        printf(" Print >S<ymbols\n");
        printf(" Print >R<elocations\n");
        printf(" >C<heck Files for Merge\n");
        printf(" >M<erge ELF Files\n");
        printf(" >Q<uit\n");
        printf("Option: ");

        char option[10];
        if (scanf("%9s", option) != 1) break;

        char choice = option[0];
        int handled = 0;
        for (int i = 0; menu[i].name != 0; i++) {
            if (menu[i].name == choice) {
                menu[i].fun();
                handled = 1;
                break;
            }
        }
        if (!handled) {
            printf("Unknown option sequence requested.\n");
        }
    }
    return 0;
}