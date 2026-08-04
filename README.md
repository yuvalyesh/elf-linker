# ELF Linker

A userspace ELF object file analyzer and partial linker written in C. Implements core linker functionality from scratch: parsing ELF section headers, symbol table inspection, relocation entry decoding, merge-conflict detection, and binary section merging of two relocatable `.o` files into a single output object.

## Overview

The tool uses `mmap` to memory-map up to two ELF32 files simultaneously, then provides an interactive menu to inspect their internal structure and perform a partial link step analogous to what `ld` does during static linking.

```
myELF
├── Examine ELF file         → parse & validate ELF magic, map headers
├── Print Section Names      → walk SHT, resolve names via .shstrtab
├── Print Symbols            → traverse SYMTAB/DYNSYM, resolve via .strtab
├── Print Relocations        → decode REL entries, map to symbol names
├── Check Files for Merge    → detect undefined/multiply-defined symbols
└── Merge ELF Files          → produce out.ro with merged sections + resolved symtab
```

## Key Features

- **Zero-copy analysis** — entire files mapped via `mmap(MAP_PRIVATE)`, no intermediate buffers.
- **Section-header traversal** — resolves section names by walking `.shstrtab` using `sh_name` offsets.
- **Symbol table resolution** — handles `SHN_UNDEF`, `SHN_ABS`, `SHN_COMMON`, and normal section-indexed symbols.
- **Relocation decoding** — unpacks `r_info` using `ELF32_R_SYM` / `ELF32_R_TYPE`, resolves symbol names from the linked `.strtab`.
- **Partial linker** — merges `.text`, `.data`, `.rodata` from two object files; resolves `UND` symbols in file 1 that are defined in file 2 by patching `st_value` and `st_shndx`; produces a valid `out.ro`.
- **Debug mode** — verbose diagnostic output toggled at runtime.

## Tech Stack

| | |
|---|---|
| Language | C (C99) |
| Build | GNU Make |
| Binary format | ELF32 |
| OS interface | `mmap`, `open`, `fstat`, `lseek`, `write` |

## Project Structure

```
elf-linker/
├── myELF.c          # Full implementation (~517 lines)
├── Makefile
└── examples/        # Sample ELF object files for testing
    ├── F1a.o
    ├── F1b.o
    └── ...
```

## Build & Run

**Requirements:** gcc, GNU Make, Linux (ELF host)

```bash
make
./myELF
```

Interactive menu, single-key commands:

```
Choose action:
 Toggle >D<ebug Mode
 Examine ELF >F<ile
 Print Section >N<ames
 Print >S<ymbols
 Print >R<elocations
 >C<heck Files for Merge
 >M<erge ELF Files
 >Q<uit
```

## Example Workflow

```bash
# Start the analyzer
./myELF

Option: F
Enter ELF file name: examples/F1a.o

ELF Header Specifications:
  Magic bytes 1,2,3:         E L F
  Data encoding scheme:      1 (2's complement, little endian)
  Entry point address:       0x0
  Number of section headers: 12

Option: N
# Prints all section names with address, offset, size, type

Option: S
# Prints all symbol table entries

Option: F
Enter ELF file name: examples/F1b.o

Option: C
# Checks for undefined / multiply-defined symbols between the two files

Option: M
# Merges into out.ro
Successfully completed partial merge. Resource saved as 'out.ro'
```

## Concepts Demonstrated

- **ELF binary format** — direct manipulation of `Elf32_Ehdr`, `Elf32_Shdr`, `Elf32_Sym`, `Elf32_Rel` structs.
- **Memory-mapped I/O** — `mmap`/`munmap` for efficient binary file access.
- **Static linking mechanics** — section concatenation, symbol resolution across translation units, `st_value` offset adjustment.
- **Systems programming patterns** — function-pointer dispatch table, structured global state, careful resource cleanup.
