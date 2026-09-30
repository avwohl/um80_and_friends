# um80 Tools Reference

Command summaries and reference notes for each tool of the um80 toolchain.
The man pages (`man um80` and the rest) have the full option lists.

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

Microsoft MACRO-80 compatible assembler supporting:

- 8080 and Z80 instruction sets
- Macros with parameters (MACRO/ENDM)
- Repeat blocks (REPT, IRP, IRPC)
- Conditional assembly (IF/ELSE/ENDIF, IFDEF, etc.)
- Segments (CSEG, DSEG, ASEG, COMMON)
- PUBLIC/EXTRN for module linking
- Include files
- All standard directives (ORG, EQU, SET, DB, DW, DS, etc.)

#### Command-Line Pre-Execution (`-e` and `--pre`)

Code can be injected before the main source file using `-e` (inline code) and `--pre` (include file). Both options can be repeated and are processed in the order specified:

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

This is useful for:
- Switching CPU mode (`.z80` or `.8080`) without modifying source files
- Defining conditional assembly symbols (`DEBUG equ 1`)
- Including project-wide macro libraries

See `man um80` for full documentation, or refer to the original [Microsoft M80 Manual](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/m80.pdf).

### ul80 - Linker

LINK-80 compatible linker that:

- Links multiple .REL relocatable object files
- Resolves external references
- Produces CP/M .COM executables
- Supports COMMON blocks
- Can output Intel HEX format
- Can output MP/M .PRL (Page Relocatable) format
- Provides `__END__` symbol for dynamic memory allocation

#### Predefined Symbols

The linker provides a predefined `__END__` symbol that points to the first free byte after all linked segments (code + data + common blocks). This is useful for implementing heap allocation:

```asm
        EXTRN   __END__         ; Import linker symbol

START:  LXI     H,__END__       ; Load end of program
        SHLD    HEAP            ; Initialize heap pointer
        ...

        DSEG
HEAP:   DW      0               ; Heap pointer
```

See `man ul80` for full documentation, or refer to the original [Microsoft L80 Manual](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/l80.pdf).

### ulib80 - Library Manager

LIB-80 compatible library manager for:

- Creating .LIB library archives
- Listing library contents and public symbols
- Adding/removing/extracting modules

See `man ulib80` for full documentation, or refer to the original [Microsoft CREF/LIB Manual](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/cref_lib.pdf).

### ucref80 - Cross-Reference

Generates cross-reference listings showing:

- Symbol definitions
- Symbol references by file and line
- PUBLIC and EXTRN declarations

See `man ucref80` for full documentation.

### ud80 - Disassembler

8080/Z80 disassembler that:

- Disassembles CP/M .COM files to .MAC source
- Produces output compatible with um80
- Supports both 8080 and Z80 instruction sets
- Allows marking data ranges and entry points
- Generates re-assemblable source code

See `man ud80` for full documentation (no Microsoft equivalent exists).

### ux80 - 8080 to Z80 Translator

Source-to-source translator that converts Intel 8080 assembly to Zilog Z80 assembly:

- Translates all 8080 instructions to equivalent Z80 mnemonics
- Preserves all comments, labels, and formatting
- Produces byte-identical output when assembled
- Automatically adds `.Z80` directive to output
- Handles all assembler directives (passes them through unchanged)

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

See `man ux80` for full documentation.

## File Formats

| Extension | Description |
|-----------|-------------|
| .MAC | Assembly source (MACRO-80 format) |
| .REL | Relocatable object file |
| .COM | CP/M executable |
| .PRL | MP/M Page Relocatable executable |
| .LIB | Library archive |
| .PRN | Assembly listing |
| .SYM | Symbol file |

## Installing Man Pages

After pip installation, install the man pages manually:

```bash
# Find where the package is installed
PKGDIR=$(python3 -c "import um80; print(um80.__path__[0])")

# Copy man pages to system location (requires sudo)
sudo cp "$PKGDIR/../docs/man/"*.1 /usr/local/share/man/man1/
sudo mandb
```

Or view them directly, from the repository root:

```bash
man docs/man/um80.1
```
