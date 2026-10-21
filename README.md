# ELF Linker

A userspace ELF object file analyzer and partial linker written in C. Implements core linker functionality from scratch: parsing ELF section headers, symbol table inspection, relocation entry decoding, merge-conflict detection, and section merging of two relocatable `.o` files into a single output object.

## Overview

The tool uses `mmap` to memory-map up to two ELF32 files simultaneously, then provides an interactive menu to inspect their internal structure and perform a partial link step similar to the first stage of what `ld -r` does.

```
myELF
├── Examine ELF file         → validate ELF32 header + section table, map file
├── Print Section Names      → walk SHT, resolve names via .shstrtab
├── Print Symbols            → traverse SYMTAB/DYNSYM, resolve via .strtab
├── Print Relocations        → decode REL entries, map to symbol / section names
├── Check Files for Merge    → detect undefined / multiply-defined global symbols
└── Merge ELF Files          → produce out.ro with merged sections + resolved symtab
```

## Key Features

- **Memory-mapped analysis** — files are mapped with `mmap(MAP_PRIVATE)` and inspected in place; no copies are made for the inspection commands.
- **Defensive parsing** — every file is validated once on load (ELF32 class, little-endian, section-table bounds, section data bounds, symbol/relocation table entry sizes and links), and every string or symbol index is range-checked, so malformed input produces an error message instead of a crash. Tested against 1,500 randomly corrupted objects under AddressSanitizer + UBSan.
- **Section-header traversal** — resolves section names by walking `.shstrtab` using `sh_name` offsets.
- **Symbol table resolution** — handles `SHN_UNDEF`, `SHN_ABS`, `SHN_COMMON`, and normal section-indexed symbols.
- **Relocation decoding** — unpacks `r_info` using `ELF32_R_SYM` / `ELF32_R_TYPE`, resolves symbol names from the linked `.strtab` (section symbols are shown by section name).
- **Merge check** — compares global/weak symbols only (locals such as two `static int x;` never clash), treats weak and `COMMON` definitions as non-conflicting, and checks undefined symbols in both directions.
- **Partial linker** — concatenates `.text`, `.data`, `.rodata` and `.bss` of two relocatable objects honouring `sh_addralign`, and resolves `UND` symbols of file 1 that file 2 defines by patching `st_shndx`, `st_value`, `st_size` and type. The output parses cleanly with `readelf -a`.
- **Debug mode** — verbose diagnostic output toggled at runtime.

## Tech Stack

| | |
|---|---|
| Language | C (GNU C, `-std=gnu17` default) |
| Build | GNU Make |
| Binary format | ELF32 little-endian (i386) |
| OS interface | `mmap`, `open`, `fstat`, `lseek`, `write` |

## Project Structure

```
elf-linker/
├── myELF.c                # Full implementation
├── Makefile
└── examples/              # Sources for sample objects (built with `make examples`)
    ├── main_part.c        # needs helper() and scale from helper_part.c
    ├── helper_part.c      # defines helper() and scale
    └── conflict.c         # clashes with helper_part.c and has an undefined symbol
```

## Build & Run

**Requirements:** Linux, gcc with 32-bit support (`sudo apt install gcc-multilib` on Debian/Ubuntu), GNU Make.

```bash
make             # builds ./myELF
make examples    # builds examples/*.o as ELF32 relocatable objects (gcc -m32 -c -fno-pie)
./myELF
```

Inputs must be **32-bit** objects. A default `gcc -c` on a 64-bit host produces ELF64, which the tool rejects with `not an ELF32 file (compile with gcc -m32)`.

Interactive menu, single-key commands (case-insensitive):

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
make && make examples
./myELF

Option: F
Enter ELF file name: examples/main_part.o

ELF Header Specifications:
  Magic bytes 1,2,3:         E L F
  Data encoding scheme:      1 (2's complement, little endian)
  Entry point address:       0x0
  Section header table off:  ... (bytes)
  Number of section headers: ...
  ...

Option: R
Relocation section '.rel.text' applies to '.text':
[index] location   related_symbol_name  type
[ 0]    0x00000007 shared_counter       1
[ 1]    0x00000010 helper               2
[ 2]    0x00000019 scale                1
...

Option: F
Enter ELF file name: examples/helper_part.o

Option: C
No conflicts found: files can be merged.

Option: M
Partial merge written to 'out.ro' (2 symbol(s) resolved from file 2, 0 left undefined).
```

Then `readelf -s out.ro` shows `helper` and `scale` defined in the merged `.text` / `.data` at their shifted offsets. Loading `examples/helper_part.o` together with `examples/conflict.o` and running `C` reports `Symbol helper multiply defined` and `Symbol missing_symbol undefined`.

## Limitations

This is a teaching-scale partial linker, not a replacement for `ld -r`:

- Only `.text`, `.data`, `.rodata` and `.bss` are merged; other file-2 sections (e.g. `.rodata.str1.1`, `.text.*`, `.eh_frame`) are dropped.
- File 2's relocation sections and its symbols other than those resolving file 1's `UND` entries are not carried into `out.ro`, so file-2 code inside the merged sections keeps unresolved references.
- File 1's section header layout is kept as the template; `REL`/`RELA` sections are copied from file 1 unchanged.
- At most two files can be loaded per session; ELF64 and big-endian files are not supported.

## Concepts Demonstrated

- **ELF binary format** — direct manipulation of `Elf32_Ehdr`, `Elf32_Shdr`, `Elf32_Sym`, `Elf32_Rel` structs.
- **Memory-mapped I/O** — `mmap`/`munmap` for efficient binary file access.
- **Static linking mechanics** — section concatenation with alignment, symbol resolution across translation units, `st_value` offset adjustment.
- **Robust systems code** — validation of untrusted binary input, checked I/O, sanitizer- and fuzz-tested.
