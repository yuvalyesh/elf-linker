#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

/* --- Structure Declarations --- */
typedef struct {
    char *filename;
    char *map_start;
    off_t file_size;
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr_table;
} elf_file_t;

struct fun_desc {
    char name;
    void (*fun)(void);
};

/* --- Global Variables --- */
int debug_mode = 0;
elf_file_t mapped_files[2] = {0};
int file_count = 0;

/* --- Helper Functions --- */
const char* get_section_type_name(Elf32_Word sh_type) {
    switch(sh_type) {
        case SHT_NULL:       return "NULL";
        case SHT_PROGBITS:   return "PROGBITS";
        case SHT_SYMTAB:     return "SYMTAB";
        case SHT_STRTAB:     return "STRTAB";
        case SHT_RELA:       return "RELA";
        case SHT_HASH:       return "HASH";
        case SHT_DYNAMIC:    return "DYNAMIC";
        case SHT_NOTE:       return "NOTE";
        case SHT_NOBITS:     return "NOBITS";
        case SHT_REL:        return "REL";
        case SHT_SHLIB:      return "SHLIB";
        case SHT_DYNSYM:     return "DYNSYM";
        case SHT_INIT_ARRAY: return "INIT_ARRAY";
        case SHT_FINI_ARRAY: return "FINI_ARRAY";
        case SHT_GROUP:      return "GROUP";
        case SHT_GNU_HASH:   return "GNU_HASH";
        case SHT_GNU_versym: return "VERSYM";
        case SHT_GNU_verneed:return "VERNEED";
        default:             return "UNKNOWN";
    }
}

void clean_file_index(int idx) {
    if (mapped_files[idx].map_start) {
        munmap(mapped_files[idx].map_start, mapped_files[idx].file_size);
    }
    free(mapped_files[idx].filename);
    memset(&mapped_files[idx], 0, sizeof(elf_file_t));
}

/* True if [off, off+size) lies inside the mapped file. */
static int in_file(const elf_file_t *file, Elf32_Off off, Elf32_Word size) {
    return (off_t)off <= file->file_size && (off_t)size <= file->file_size - (off_t)off;
}

static Elf32_Shdr *get_shdr(const elf_file_t *file, Elf32_Word idx) {
    return idx < file->ehdr->e_shnum ? &file->shdr_table[idx] : NULL;
}

/* NUL-terminated string at `idx` inside string-table section `strtab`, or a placeholder. */
static const char *get_str(const elf_file_t *file, const Elf32_Shdr *strtab, Elf32_Word idx) {
    if (!strtab || strtab->sh_type != SHT_STRTAB || idx >= strtab->sh_size) return "<bad-name>";
    const char *start = file->map_start + strtab->sh_offset + idx;
    if (!memchr(start, '\0', strtab->sh_size - idx)) return "<bad-name>";
    return start;
}

static const char *section_name(const elf_file_t *file, Elf32_Word idx) {
    Elf32_Shdr *shdr = get_shdr(file, idx);
    if (!shdr) return "<bad-index>";
    return get_str(file, get_shdr(file, file->ehdr->e_shstrndx), shdr->sh_name);
}

/* Returns the (single) SHT_SYMTAB section, NULL if absent; *count = -1 if more than one. */
static Elf32_Shdr *find_symtab(const elf_file_t *file, int *count) {
    Elf32_Shdr *found = NULL;
    *count = 0;
    for (int i = 0; i < file->ehdr->e_shnum; i++) {
        if (file->shdr_table[i].sh_type == SHT_SYMTAB) {
            found = &file->shdr_table[i];
            (*count)++;
        }
    }
    return found;
}

static Elf32_Shdr *find_section_by_name(const elf_file_t *file, const char *name) {
    for (int i = 0; i < file->ehdr->e_shnum; i++) {
        if (strcmp(section_name(file, i), name) == 0) {
            return &file->shdr_table[i];
        }
    }
    return NULL;
}

/*
 * Structural validation done once at load time, so later code can index the
 * section table and dereference section data without re-checking bounds.
 * Returns NULL on success or a description of the problem.
 */
static const char *validate_elf32(elf_file_t *file) {
    const Elf32_Ehdr *ehdr = file->ehdr;
    if (file->file_size < (off_t)sizeof(Elf32_Ehdr)) return "file too small for an ELF header";
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return "bad ELF magic";
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) return "not an ELF32 file (compile with gcc -m32)";
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) return "only little-endian ELF is supported";
    if (ehdr->e_shnum == 0) return "no section header table";
    if (ehdr->e_shentsize != sizeof(Elf32_Shdr)) return "unexpected section header size";
    if (!in_file(file, ehdr->e_shoff, (Elf32_Word)ehdr->e_shnum * sizeof(Elf32_Shdr)))
        return "section header table lies outside the file";
    if (ehdr->e_shoff % 4 != 0) return "misaligned section header table";
    if (ehdr->e_shstrndx >= ehdr->e_shnum) return "invalid section-name string table index";
    file->shdr_table = (Elf32_Shdr *)(file->map_start + ehdr->e_shoff);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const Elf32_Shdr *shdr = &file->shdr_table[i];
        if (shdr->sh_type == SHT_NULL || shdr->sh_type == SHT_NOBITS) continue;
        if (!in_file(file, shdr->sh_offset, shdr->sh_size)) return "section data lies outside the file";
        if (shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM) {
            if (shdr->sh_entsize != sizeof(Elf32_Sym) || shdr->sh_offset % 4 != 0 ||
                shdr->sh_size % sizeof(Elf32_Sym) != 0)
                return "malformed symbol table";
            if (shdr->sh_link >= ehdr->e_shnum) return "symbol table links to an invalid string table";
        }
        if (shdr->sh_type == SHT_REL) {
            if (shdr->sh_entsize != sizeof(Elf32_Rel) || shdr->sh_offset % 4 != 0 ||
                shdr->sh_size % sizeof(Elf32_Rel) != 0)
                return "malformed relocation table";
            if (shdr->sh_link >= ehdr->e_shnum) return "relocation table links to an invalid symbol table";
            if (file->shdr_table[shdr->sh_link].sh_type != SHT_SYMTAB &&
                file->shdr_table[shdr->sh_link].sh_type != SHT_DYNSYM)
                return "relocation table links to a non-symbol-table section";
        }
    }
    return NULL;
}

/* Name for a symbol's st_shndx, written into `buf`. */
static const char *symbol_section_label(const elf_file_t *file, Elf32_Half shndx, char *buf, size_t len) {
    if (shndx == SHN_UNDEF) return "UND";
    if (shndx == SHN_ABS) return "ABS";
    if (shndx == SHN_COMMON) return "COM";
    if (shndx < file->ehdr->e_shnum) return section_name(file, shndx);
    snprintf(buf, len, "%u", (unsigned)shndx);
    return buf;
}

/* --- Menu Actions --- */

void toggle_debug_mode(void) {
    debug_mode = !debug_mode;
    printf("Debug mode is now %s\n", debug_mode ? "ON" : "OFF");
}

void examine_elf_file(void) {
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
    if (sb.st_size == 0) {
        printf("Error: File '%s' is empty.\n", filename);
        close(fd);
        return;
    }

    char *map_start = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd); /* the mapping stays valid after the descriptor is closed */
    if (map_start == MAP_FAILED) {
        perror("Error mapping file");
        return;
    }

    elf_file_t candidate = {0};
    candidate.map_start = map_start;
    candidate.file_size = sb.st_size;
    candidate.ehdr = (Elf32_Ehdr *)map_start;

    // Validate before trusting any offset in the file
    const char *problem = "file too small for an ELF header";
    if (sb.st_size >= (off_t)sizeof(Elf32_Ehdr)) {
        problem = validate_elf32(&candidate);
    }
    if (problem) {
        printf("Error: File '%s' is not a supported ELF32 file: %s.\n", filename, problem);
        munmap(map_start, sb.st_size);
        return;
    }

    candidate.filename = strdup(filename);
    if (!candidate.filename) {
        perror("strdup");
        munmap(map_start, sb.st_size);
        return;
    }
    mapped_files[file_count] = candidate;
    Elf32_Ehdr *ehdr = candidate.ehdr;

    // Print Specifications
    printf("\nELF Header Specifications:\n");
    printf("  Magic bytes 1,2,3:         %c %c %c\n", ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
    printf("  Data encoding scheme:      %d (%s)\n", ehdr->e_ident[EI_DATA], "2's complement, little endian");
    printf("  Entry point address:       0x%x\n", ehdr->e_entry);
    printf("  Section header table off:  %u (bytes)\n", ehdr->e_shoff);
    printf("  Number of section headers: %d\n", ehdr->e_shnum);
    printf("  Size of section header:    %d (bytes)\n", ehdr->e_shentsize);
    printf("  Program header table off:  %u (bytes)\n", ehdr->e_phoff);
    printf("  Number of program headers: %d\n", ehdr->e_phnum);
    printf("  Size of program header:    %d (bytes)\n", ehdr->e_phentsize);

    if (debug_mode) {
        printf("[DEBUG] Mapped starting address: %p\n", (void *)map_start);
        printf("[DEBUG] String table index (shstrndx): %d\n", ehdr->e_shstrndx);
    }

    file_count++;
}

void print_section_names(void) {
    if (file_count == 0) {
        printf("Error: No files currently mapped.\n");
        return;
    }

    for (int f = 0; f < file_count; f++) {
        elf_file_t *file = &mapped_files[f];
        Elf32_Shdr *shstrtab_hdr = &file->shdr_table[file->ehdr->e_shstrndx];

        if (debug_mode) {
            printf("[DEBUG] File %s: shstrtab section offset: %u, size: %u\n",
                   file->filename, shstrtab_hdr->sh_offset, shstrtab_hdr->sh_size);
        }

        printf("\nFile %s sections:\n", file->filename);
        printf("[index] section_name         section_address section_offset section_size  section_type\n");
        for (int i = 0; i < file->ehdr->e_shnum; i++) {
            Elf32_Shdr *shdr = &file->shdr_table[i];
            printf("[%2d]    %-20s 0x%08x      0x%06x         %u        %s\n",
                   i,
                   section_name(file, i),
                   shdr->sh_addr,
                   shdr->sh_offset,
                   shdr->sh_size,
                   get_section_type_name(shdr->sh_type));
        }
    }
}

void print_symbols(void) {
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
                int num_symbols = shdr->sh_size / sizeof(Elf32_Sym);
                Elf32_Shdr *strtab_hdr = get_shdr(file, shdr->sh_link);

                if (debug_mode) {
                    printf("[DEBUG] Found Symbol Table Section index: %d, Elements: %d\n", i, num_symbols);
                }

                printf("[index] value      section_index section_name         symbol_name\n");
                for (int j = 0; j < num_symbols; j++) {
                    Elf32_Sym *sym = &sym_table[j];
                    char shndx_buf[16];

                    printf("[%2d]    0x%08x %-13d %-20s %s\n",
                           j, sym->st_value, sym->st_shndx,
                           symbol_section_label(file, sym->st_shndx, shndx_buf, sizeof(shndx_buf)),
                           get_str(file, strtab_hdr, sym->st_name));
                }
            }
        }
        if (!symtab_found) {
            printf("Error: No symbol table found in this file.\n");
        }
    }
}

void print_relocations(void) {
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
                int num_rel = shdr->sh_size / sizeof(Elf32_Rel);

                // Find associated symbol table using sh_link (validated at load time)
                Elf32_Shdr *symtab_hdr = &file->shdr_table[shdr->sh_link];
                Elf32_Sym *sym_table = (Elf32_Sym *)(file->map_start + symtab_hdr->sh_offset);
                Elf32_Word sym_count = symtab_hdr->sh_size / sizeof(Elf32_Sym);

                // Find string table associated with symbol table
                Elf32_Shdr *strtab_hdr = get_shdr(file, symtab_hdr->sh_link);

                if (debug_mode) {
                    printf("[DEBUG] Relocation section: %d, entries: %d\n", i, num_rel);
                }

                printf("Relocation section '%s' applies to '%s':\n",
                       section_name(file, i), section_name(file, shdr->sh_info));
                printf("[index] location   related_symbol_name  type\n");
                for (int j = 0; j < num_rel; j++) {
                    Elf32_Rel *rel = &rel_table[j];
                    Elf32_Word sym_idx = ELF32_R_SYM(rel->r_info);
                    int rel_type = ELF32_R_TYPE(rel->r_info);
                    const char *sym_name = "<bad-symbol>";
                    if (sym_idx < sym_count) {
                        Elf32_Sym *sym = &sym_table[sym_idx];
                        // Section symbols have no name of their own; show the section instead
                        sym_name = ELF32_ST_TYPE(sym->st_info) == STT_SECTION
                                       ? section_name(file, sym->st_shndx)
                                       : get_str(file, strtab_hdr, sym->st_name);
                    }

                    printf("[%2d]    0x%08x %-20s %d\n", j, rel->r_offset, sym_name, rel_type);
                }
            }
        }
        if (!rel_found) {
            printf("No relocations\n");
        }
    }
}

/* Symbol table view of one file used by the merge-related commands. */
typedef struct {
    Elf32_Sym *syms;
    int count;
    Elf32_Shdr *strtab;
} symtab_view_t;

static int load_symtab_view(const elf_file_t *file, symtab_view_t *view) {
    int n;
    Elf32_Shdr *hdr = find_symtab(file, &n);
    if (n != 1) return 0;
    view->syms = (Elf32_Sym *)(file->map_start + hdr->sh_offset);
    view->count = hdr->sh_size / sizeof(Elf32_Sym);
    view->strtab = get_shdr(file, hdr->sh_link);
    return 1;
}

/* Global/weak, named symbol that participates in cross-file resolution. */
static int is_linkable(const Elf32_Sym *sym) {
    int bind = ELF32_ST_BIND(sym->st_info);
    int type = ELF32_ST_TYPE(sym->st_info);
    return (bind == STB_GLOBAL || bind == STB_WEAK) && type != STT_SECTION && type != STT_FILE &&
           sym->st_name != 0;
}

/* Index of a linkable symbol named `name` in `view`, or -1. */
static int find_linkable(const elf_file_t *file, const symtab_view_t *view, const char *name) {
    for (int j = 1; j < view->count; j++) {
        if (is_linkable(&view->syms[j]) && strcmp(name, get_str(file, view->strtab, view->syms[j].st_name)) == 0)
            return j;
    }
    return -1;
}

/* A "strong" definition: defined, not weak, not a tentative (COMMON) definition. */
static int is_strong_definition(const Elf32_Sym *sym) {
    return sym->st_shndx != SHN_UNDEF && sym->st_shndx != SHN_COMMON &&
           ELF32_ST_BIND(sym->st_info) != STB_WEAK;
}

/* Report symbols of `a` that are undefined in both files or strongly defined in both. */
static int report_conflicts(const elf_file_t *fa, const symtab_view_t *a,
                            const elf_file_t *fb, const symtab_view_t *b, int report_multiple) {
    int problems = 0;
    for (int i = 1; i < a->count; i++) {
        const Elf32_Sym *sym = &a->syms[i];
        if (!is_linkable(sym)) continue;
        const char *name = get_str(fa, a->strtab, sym->st_name);
        int j = find_linkable(fb, b, name);

        if (sym->st_shndx == SHN_UNDEF) {
            if (ELF32_ST_BIND(sym->st_info) != STB_WEAK && (j < 0 || b->syms[j].st_shndx == SHN_UNDEF)) {
                printf("Symbol %s undefined\n", name);
                problems++;
            }
        } else if (report_multiple && j >= 0 && is_strong_definition(sym) && is_strong_definition(&b->syms[j])) {
            printf("Symbol %s multiply defined\n", name);
            problems++;
        }
    }
    return problems;
}

void check_files_for_merge(void) {
    if (file_count < 2) {
        printf("Error: Two files must be opened and mapped first.\n");
        return;
    }

    elf_file_t *f1 = &mapped_files[0];
    elf_file_t *f2 = &mapped_files[1];
    symtab_view_t v1, v2;

    if (!load_symtab_view(f1, &v1) || !load_symtab_view(f2, &v2)) {
        printf("Feature not supported: Each file must contain exactly one symbol table.\n");
        return;
    }

    // Undefined symbols are checked in both directions; clashes only need one pass
    int problems = report_conflicts(f1, &v1, f2, &v2, 1);
    problems += report_conflicts(f2, &v2, f1, &v1, 0);
    if (problems == 0) {
        printf("No conflicts found: files can be merged.\n");
    }
}

/* Sections whose contents are concatenated (file 1 data, then file 2 data). */
static int is_mergeable_name(const char *name) {
    return strcmp(name, ".text") == 0 || strcmp(name, ".data") == 0 ||
           strcmp(name, ".rodata") == 0 || strcmp(name, ".bss") == 0;
}

static int write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Pad the output with zeros up to `align` (a power of two, or 0/1 for none). */
static int pad_to(int fd, off_t *offset, Elf32_Word align) {
    static const char zeros[16] = {0};
    if (align <= 1) return 0;
    off_t target = (*offset + align - 1) & ~((off_t)align - 1);
    while (*offset < target) {
        size_t chunk = target - *offset > (off_t)sizeof(zeros) ? sizeof(zeros) : (size_t)(target - *offset);
        if (write_all(fd, zeros, chunk) < 0) return -1;
        *offset += chunk;
    }
    return 0;
}

static Elf32_Word align_up(Elf32_Word value, Elf32_Word align) {
    return align <= 1 ? value : (value + align - 1) & ~(align - 1);
}

void merge_elf_files(void) {
    if (file_count < 2) {
        printf("Error: Two files must be mapped before executing merge.\n");
        return;
    }

    elf_file_t *f1 = &mapped_files[0];
    elf_file_t *f2 = &mapped_files[1];
    symtab_view_t v1, v2;

    if (f1->ehdr->e_type != ET_REL || f2->ehdr->e_type != ET_REL) {
        printf("Error: Both files must be relocatable objects (ET_REL, e.g. gcc -m32 -c).\n");
        return;
    }
    if (!load_symtab_view(f1, &v1) || !load_symtab_view(f2, &v2)) {
        printf("Feature not supported: Each file must contain exactly one symbol table.\n");
        return;
    }

    int shnum = f1->ehdr->e_shnum;
    size_t shdr_table_size = shnum * sizeof(Elf32_Shdr);
    Elf32_Shdr *out_shdr_table = malloc(shdr_table_size);
    Elf32_Shdr **f2_part = calloc(shnum, sizeof(*f2_part));     /* matching file-2 section */
    Elf32_Word *f2_offset = calloc(shnum, sizeof(*f2_offset));  /* where file-2 data starts */
    Elf32_Sym *out_symtab = malloc(v1.count * sizeof(Elf32_Sym));
    if (!out_shdr_table || !f2_part || !f2_offset || !out_symtab) {
        perror("malloc");
        goto out_free;
    }
    memcpy(out_shdr_table, f1->shdr_table, shdr_table_size);
    memcpy(out_symtab, v1.syms, v1.count * sizeof(Elf32_Sym));

    // Pass 1: lay out merged sections (file-2 part is placed at its own alignment)
    for (int i = 0; i < shnum; i++) {
        const char *name = section_name(f1, i);
        if (!is_mergeable_name(name)) continue;
        Elf32_Shdr *other = find_section_by_name(f2, name);
        if (!other || other->sh_type != f1->shdr_table[i].sh_type) continue;
        f2_part[i] = other;
        f2_offset[i] = align_up(f1->shdr_table[i].sh_size, other->sh_addralign);
        out_shdr_table[i].sh_size = f2_offset[i] + other->sh_size;
        if (other->sh_addralign > out_shdr_table[i].sh_addralign)
            out_shdr_table[i].sh_addralign = other->sh_addralign;
    }

    // Resolve file-1 UND symbols that file 2 defines in a merged section (or as ABS)
    int resolved = 0, unresolved = 0;
    for (int j = 1; j < v1.count; j++) {
        Elf32_Sym *sym = &out_symtab[j];
        if (sym->st_shndx != SHN_UNDEF || !is_linkable(sym)) continue;
        const char *name = get_str(f1, v1.strtab, sym->st_name);
        int m = find_linkable(f2, &v2, name);
        if (m < 0 || v2.syms[m].st_shndx == SHN_UNDEF) continue; /* undefined in both: left for ld */

        const Elf32_Sym *def = &v2.syms[m];
        int target = -1;
        if (def->st_shndx == SHN_ABS) {
            sym->st_shndx = SHN_ABS;
            sym->st_value = def->st_value;
            target = SHN_ABS;
        } else if (def->st_shndx < f2->ehdr->e_shnum) {
            for (int s = 0; s < shnum; s++) {
                if (f2_part[s] == &f2->shdr_table[def->st_shndx]) {
                    sym->st_shndx = s;
                    sym->st_value = def->st_value + f2_offset[s];
                    target = s;
                    break;
                }
            }
        }
        if (target < 0) {
            printf("Warning: %s is defined in file 2 outside .text/.data/.rodata/.bss; left undefined\n", name);
            unresolved++;
            continue;
        }
        sym->st_info = ELF32_ST_INFO(ELF32_ST_BIND(def->st_info), ELF32_ST_TYPE(def->st_info));
        sym->st_size = def->st_size;
        resolved++;
    }

    int out_fd = open("out.ro", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out_fd < 0) {
        perror("Error creating out.ro");
        goto out_free;
    }

    // Pass 2: write header placeholder, section contents, then the section header table
    Elf32_Ehdr out_ehdr = *(f1->ehdr);
    off_t current_offset = sizeof(Elf32_Ehdr);
    if (write_all(out_fd, &out_ehdr, sizeof(Elf32_Ehdr)) < 0) goto out_write_error;

    for (int i = 0; i < shnum; i++) {
        Elf32_Shdr *in = &f1->shdr_table[i];
        Elf32_Shdr *out = &out_shdr_table[i];
        if (in->sh_type == SHT_NULL) {
            memset(out, 0, sizeof(Elf32_Shdr));
            continue;
        }
        if (pad_to(out_fd, &current_offset, out->sh_addralign) < 0) goto out_write_error;
        out->sh_offset = current_offset;
        if (in->sh_type == SHT_NOBITS) continue; /* occupies no file space */

        const void *data = f1->map_start + in->sh_offset;
        if (in->sh_type == SHT_SYMTAB) data = out_symtab;
        if (write_all(out_fd, data, in->sh_size) < 0) goto out_write_error;
        current_offset += in->sh_size;

        if (f2_part[i]) {
            off_t part_start = out->sh_offset + f2_offset[i];
            while (current_offset < part_start) { /* zero padding between the two parts */
                if (write_all(out_fd, "", 1) < 0) goto out_write_error;
                current_offset++;
            }
            if (write_all(out_fd, f2->map_start + f2_part[i]->sh_offset, f2_part[i]->sh_size) < 0)
                goto out_write_error;
            current_offset += f2_part[i]->sh_size;
        }
    }

    if (pad_to(out_fd, &current_offset, 4) < 0) goto out_write_error;
    out_ehdr.e_shoff = current_offset;
    if (write_all(out_fd, out_shdr_table, shdr_table_size) < 0) goto out_write_error;

    // Seek back to write structural corrections
    if (lseek(out_fd, 0, SEEK_SET) < 0 || write_all(out_fd, &out_ehdr, sizeof(Elf32_Ehdr)) < 0)
        goto out_write_error;

    if (close(out_fd) < 0) {
        perror("Error closing out.ro");
        unlink("out.ro");
        goto out_free;
    }
    printf("Partial merge written to 'out.ro' (%d symbol(s) resolved from file 2, %d left undefined).\n",
           resolved, unresolved);
    goto out_free;

out_write_error:
    perror("Error writing out.ro");
    close(out_fd);
    unlink("out.ro");
out_free:
    free(out_shdr_table);
    free(f2_part);
    free(f2_offset);
    free(out_symtab);
}

void quit_program(void) {
    for (int i = 0; i < 2; i++) {
        clean_file_index(i);
    }
    printf("Exiting normally.\n");
    exit(0);
}

/* --- Core Application Interface Execution Loop --- */
int main(void) {
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

        char choice = toupper((unsigned char)option[0]);
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
    quit_program(); /* EOF on stdin: release mappings like 'Q' does */
    return 0;
}
