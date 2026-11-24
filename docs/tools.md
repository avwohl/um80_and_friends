# um80 Tools Reference

This document gives command summaries and reference notes for each tool of
the um80 toolchain. The man pages (`man um80` and the rest) have the full
option lists.

## Command Summary

### Assemble a source file

```bash
um80 program.mac                    # Creates program.rel
um80 -o output.rel program.mac      # Specify output name
um80 -l listing.prn program.mac     # Generate listing file
um80 -g program.mac                 # Export all symbols as PUBLIC (for debug)
um80 -t program.mac                 # Cut symbol names to 6 chars, as M80 does
um80 -e ".z80" program.mac          # Execute code before source (set Z80 mode)
um80 --pre macros.mac program.mac   # Include file before source
um80 --aseg program.asm             # Absolute, like DRI's MAC: ORG is an address
um80 --dri program.asm              # DRI source: MAC's names and labels
```

### Link object files

```bash
ul80 program.rel                    # Creates program.com
ul80 -o output.com a.rel b.rel      # Link multiple files
ul80 -s program.rel                 # Generate symbol file (.sym)
ul80 -S symbols.sym program.rel     # Specify symbol file name
ul80 -p E000 program.rel            # Set origin address (hex)
ul80 --prl program.rel              # MP/M .PRL transient (linked at 100H)
ul80 --prl --extra 1000 program.rel # ...asking MP/M for 1000H more memory
ul80 --spr program.rel              # MP/M .SPR/.RSP system page (linked at 0)
ul80 --allow-overlap a.rel patch.rel # Absolute code over other code: a warning
ul80 --fatal-mult-def a.rel b.rel   # A global defined twice fails the link
ul80 --bin -p 68 -d F800 --rom-data --rom-size 8000 crt0.rel a.rel  # ROM image (docs/ul80_rom.md)
```

### Disassemble a COM file

```bash
ud80 program.com                    # Creates program.mac
ud80 -z program.com                 # Z80 mode
ud80 -e 0200 program.com            # Add entry point at 0200h
ud80 -d 0500-05FF program.com       # Mark range as data
```

### Create/manage libraries

```bash
ulib80 -c mylib.lib a.rel b.rel     # Create library
ulib80 -l mylib.lib                 # List contents
ulib80 -p mylib.lib                 # Show public symbols
ulib80 -x mylib.lib module          # Extract module
ulib80 -a mylib.lib new.rel         # Add module
ulib80 -d mylib.lib module          # Delete module
```

### Generate cross-reference

```bash
ucref80 program.mac                 # Print to stdout
ucref80 -o xref.txt *.mac           # Output to file
```

### Translate 8080 to Z80 assembly

```bash
ux80 program.mac                    # Creates program_z80.mac
ux80 -o output.mac program.mac      # Specify output name
```

## Tools Reference

### um80 - Assembler

um80 is a Microsoft MACRO-80 (M80) compatible assembler. um80 has these functions:

- 8080 and Z80 instruction sets
- Macros with parameters (MACRO/ENDM)
- Repeat blocks (REPT, IRP, IRPC)
- Conditional assembly (IF/ELSE/ENDIF, IFDEF and others)
- Segments (CSEG, DSEG, ASEG, COMMON)
- PUBLIC and EXTRN, which connect modules
- Include files
- All standard directives (ORG, EQU, SET, DB, DW, DS and others)
- `--debug-info`: um80 also writes `NAME.dbm` in the same directory as the
  `.rel` file. The `.dbm` file has these data:
  - The source line of each instruction.
  - The active `;#` markers.
  - All labels.

  The `.rel` file does not change. See [debug_info.md](debug_info.md).

#### Command-Line Pre-Execution (`-e` and `--pre`)

The option `-e` (inline code) and the option `--pre` (include file) put code
before the main source file. You can repeat both options. um80 processes the
options in the order that you give them. Examples:

```bash
# Set Z80 mode from command line
um80 -e ".z80" program.mac

# Multiple statements using ! separator (DRI notation)
um80 -e ".z80!DEBUG equ 1!BUFSIZE equ 256" program.mac

# Include a file of macros before the main source
um80 --pre stdmacros.mac program.mac

# Combine both, processed left to right
um80 -e ".z80" --pre macros.mac -e "MYVAL equ 42" program.mac
```

These options are useful for these tasks:

- Switch the CPU mode (`.z80` or `.8080`) without a change to the source files.
- Define conditional assembly symbols (`DEBUG equ 1`).
- Include project-wide macro libraries.

For full documentation, read `man um80`, or read the original [Microsoft M80 Manual](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/m80.pdf).

### ul80 - Linker

ul80 is a LINK-80 (L80) compatible linker. ul80 has these functions:

- Links more than one REL file (.REL, relocatable)
- Resolves the references to external symbols
- Writes CP/M COM files (.COM)
- Accepts COMMON blocks
- Can write Intel HEX files
- Can write MP/M PRL files (.PRL, page relocatable)
- Defines the `__END__` symbol for dynamic memory allocation
- `--debug-info`: ul80 reads the `.dbm` file of each module. ul80 writes
  `NAME.dbg` in the same directory as the output file. The `.dbg` file has
  these data:
  - The addresses of the source lines.
  - The addresses of the routines.
  - The addresses of all labels.
  - The length of the output file.
  - The SHA-256 of the output file.

  `--debug-file FILE` names the `.dbg` file. The output file and the `.SYM`
  file do not change. See [debug_info.md](debug_info.md).

#### Predefined Symbols

ul80 has a predefined `__END__` symbol. The `__END__` symbol points to the
first free byte after all linked segments (code + data + common blocks). The
`__END__` symbol is useful for heap allocation:

```asm
        EXTRN   __END__         ; Import linker symbol

START:  LXI     H,__END__       ; Load end of program
        SHLD    HEAP            ; Initialize heap pointer
        ...

        DSEG
HEAP:   DW      0               ; Heap pointer
```

For full documentation, read `man ul80`, or read the original [Microsoft L80 Manual](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/l80.pdf).

### ulib80 - Library Manager

ulib80 is a LIB-80 compatible library manager. ulib80 does these tasks:

- Creates .LIB library files
- Lists the contents of a library file and the public symbols
- Adds, removes and extracts modules
- Stores the module with the `.dbm` file that is in the same directory as the
  `.rel` file. A library file with a `.dbm` file is a version 2 `ULIB` file.
  ul80 reads versions 1 and 2. See [debug_info.md](debug_info.md).

For full documentation, read `man ulib80`, or read the original [Microsoft CREF/LIB Manual](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/cref_lib.pdf).

### ucref80 - Cross-Reference

ucref80 writes cross-reference listings. A cross-reference listing has:

- Symbol definitions
- Symbol references by file and line
- PUBLIC and EXTRN declarations

For full documentation, read `man ucref80`.

### dbg2elf - ELF and DWARF file for GDB

dbg2elf reads `prog.dbg` (from `ul80 --debug-info`) and the program file.
dbg2elf writes an ELF file (ELF32). The ELF file has the code, the routine
symbols, DWARF line rows and inlined calls. With the ELF file, GDB with a z80
target can debug the program on `cpmemu --gdb`. See [gdb.md](gdb.md) and
`man dbg2elf`. dbg2elf is in package um80 0.4.0 and later.

### udb80 - Debugger

udb80 debugs a program that runs in `cpmemu --gdb` (cpmemu 4.11.0 and
later). udb80 works by source line. The commands are `break`, `step`, `next`,
`finish`, `bt` and `print` of variables. udb80 reads `prog.dbg` from
`ul80 --debug-info`. udb80 is in package um80 0.4.0 and later. See
[udb80.md](udb80.md) and `man udb80`.

### ud80 - Disassembler

ud80 is an 8080/Z80 disassembler. ud80 has these functions:

- Disassembles CP/M COM files (.COM) to .MAC source files
- Writes output that is compatible with um80
- Works with both the 8080 and the Z80 instruction sets
- Lets you mark data ranges and entry points
- Writes source code that you can assemble again

For full documentation, read `man ud80`. No Microsoft equivalent exists.

### ux80 - 8080 to Z80 Translator

ux80 is a source-to-source translator. ux80 translates Intel 8080 assembly
to Zilog Z80 assembly. ux80 has
these functions:

- Translates all 8080 instructions to equivalent Z80 mnemonics
- Keeps all comments, labels and the format of the text
- Writes output that is byte-identical when assembled
- Adds the `.Z80` directive to the output automatically
- Writes all assembler directives to the output unchanged

**Translation examples:**

| 8080 | Z80 |
|------|-----|
| `MOV A,B` | `LD A,B` |
| `MVI A,42H` | `LD A,42H` |
| `LXI H,1234H` | `LD HL,1234H` |
| `LDA addr` | `LD A,(addr)` |
| `LHLD addr` | `LD HL,(addr)` |
| `LDAX B` | `LD A,(BC)` |
| `INR A` | `INC A` |
| `INX H` | `INC HL` |
| `DAD D` | `ADD HL,DE` |
| `ADD B` | `ADD B` |
| `ADI 10` | `ADD 10` |
| `JMP addr` | `JP addr` |
| `JNZ addr` | `JP NZ,addr` |
| `CALL addr` | `CALL addr` |
| `CNZ addr` | `CALL NZ,addr` |
| `RET` / `RNZ` | `RET` / `RET NZ` |
| `RLC` | `RLCA` |
| `CMA` | `CPL` |
| `HLT` | `HALT` |
| `PCHL` | `JP (HL)` |
| `XCHG` | `EX DE,HL` |
| `IN port` | `IN A,(port)` |
| `OUT port` | `OUT (port),A` |
| `PSW` | `AF` |
| `M` (memory) | `(HL)` |

For full documentation, read `man ux80`.

## File Formats

| Extension | Description |
|-----------|-------------|
| .MAC | Assembly source (MACRO-80 format) |
| .REL | REL file (relocatable) |
| .COM | COM file (CP/M executable) |
| .PRL | PRL file (MP/M page relocatable executable) |
| .LIB | Library archive |
| .PRN | Assembly listing |
| .SYM | Symbol file |
| .DBM | Module debug information, JSON (`um80 --debug-info`) |
| .DBG | Linked debug information, JSON (`ul80 --debug-info`) |

## Installing Man Pages

From package um80 0.4.1, `pip install um80` installs the man pages. pip puts
the man pages in the `share/man/man1` directory, next to the `bin`
directory of the commands. The `share/man/man1` directory is in one of these
places:

- The `share/man/man1` directory of a virtual environment.
- The `share/man/man1` directory of the user base, when you use
  `pip install --user`.

The command `man` finds the man pages when that `bin` directory is on `PATH`:

```bash
man udb80
man -w udb80        # show where the page is
```

An older release has no man pages in the package. To install the man pages
from a checkout of this repository, run this command:

```bash
sudo cp docs/man/*.1 /usr/local/share/man/man1/
```

You can also read a man page directly. Run this command from the repository
root:

```bash
man docs/man/um80.1
```
