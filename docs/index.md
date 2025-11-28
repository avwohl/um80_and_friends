# um80 Documentation

This documentation covers the um80 toolchain - a Microsoft MACRO-80 compatible
assembler suite for 8080/Z80 development on Linux.

## Overview

The um80 toolchain provides five command-line tools:

| Tool | Description | Microsoft Equivalent |
|------|-------------|---------------------|
| um80 | MACRO-80 assembler | M80 |
| ul80 | LINK-80 linker | L80 |
| ulib80 | LIB-80 library manager | LIB80 |
| ucref80 | Cross-reference utility | CREF80 |
| ud80 | Disassembler | (none) |
| ux80 | 8080 to Z80 translator | (none) |

## Quick Reference

### Assemble

```bash
um80 source.mac                 # Output: source.rel
um80 -o out.rel source.mac      # Specify output
um80 -l source.prn source.mac   # Generate listing
um80 -D DEBUG=1 source.mac      # Define symbol
um80 -I ./include source.mac    # Add include path
um80 -g source.mac              # Export all symbols as PUBLIC
um80 -v                         # Show version
```

### Link

```bash
ul80 program.rel                # Output: program.com
ul80 -o app.com a.rel b.rel     # Multiple inputs
ul80 -s program.rel             # Generate .sym file (auto name)
ul80 -S prog.sym program.rel    # Specify symbol file name
ul80 -x program.rel             # Intel HEX output
ul80 -p E000 program.rel        # Custom origin (hex)
ul80 -v                         # Show version
```

### Disassemble

```bash
ud80 program.com                # Output: program.mac
ud80 -z program.com             # Z80 mode
ud80 -e 0200 program.com        # Add entry point
ud80 -e 297a,ends program.com   # Entry point with label
ud80 -l 4406,buffer program.com # Add label without tracing
ud80 -d 0300-03FF program.com   # Mark data range
ud80 -t 0103-0120 program.com   # Mark address table (DW output)
ud80 -dc 0200-0210 program.com  # High-bit terminated strings
ud80 -da 0300-03FF program.com  # ASCII strings (null-terminated)
ud80 -da 0300-03FF,8 program.com # Fixed-length (8 char) strings
ud80 --org 0000 rom.bin         # Non-CP/M origin
```

### Library Management

```bash
ulib80 -c lib.lib a.rel b.rel   # Create library
ulib80 -l lib.lib               # List contents
ulib80 -p lib.lib               # Show symbols
ulib80 -x lib.lib               # Extract all
ulib80 -x lib.lib module        # Extract one
ulib80 -a lib.lib new.rel       # Add module
ulib80 -d lib.lib old           # Delete module
```

### Cross-Reference

```bash
ucref80 source.mac              # Output to stdout
ucref80 -o xref.txt *.mac       # Output to file
```

## Typical Workflow

```
                    +-----------+
                    | source.mac|
                    +-----+-----+
                          |
                          v
                    +-----+-----+
                    |   um80    |  Assembler
                    +-----+-----+
                          |
              +-----------+-----------+
              |           |           |
              v           v           v
        +-----+-----+ +---+---+ +-----+-----+
        | module.rel| |lib.lib| |source.prn |
        +-----+-----+ +---+---+ +-----------+
              |           |
              +-----------+
                    |
                    v
              +-----+-----+
              |   ul80    |  Linker
              +-----+-----+
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
  +-----+-----+ +---+---+ +-----+-----+
  |program.com| |.hex   | |program.sym|
  +-----------+ +-------+ +-----------+
```

## File Types

| Extension | Description | Tool |
|-----------|-------------|------|
| .mac | Assembly source | um80 input |
| .rel | Relocatable object | um80 output, ul80 input |
| .com | CP/M executable | ul80 output |
| .lib | Library archive | ulib80 |
| .prn | Assembly listing | um80 -l |
| .sym | Symbol file | ul80 -s |
| .hex | Intel HEX format | ul80 -x |

## Microsoft Manual References

The original Microsoft manuals are included in `docs/external/`:

- **m80.pdf** - MACRO-80 Assembler Manual
  - Complete directive reference
  - Macro programming guide
  - Expression syntax

- **l80.pdf** - LINK-80 Linker Manual
  - Linking process
  - Library searching
  - Memory layout

- **cref_lib.pdf** - CREF and LIB-80 Manual
  - Cross-reference listing format
  - Library management

- **8080asm.pdf** - 8080 Assembly Language Reference
  - Instruction set details
  - Programming techniques

These manuals document the original CP/M tools. The um80 tools are compatible
with the documented behavior except where noted.

## Man Pages

Detailed command-line documentation is available via man pages:

```bash
man um80      # Assembler
man ul80      # Linker
man ulib80    # Library manager
man ucref80   # Cross-reference
man ud80      # Disassembler
man ux80      # 8080 to Z80 translator
```

## Differences from Microsoft Tools

### um80 vs M80

- Unix line endings (LF) accepted in addition to DOS (CR/LF)
- File paths use Unix conventions
- Error messages are more verbose
- Same .REL output format

### ul80 vs L80

- Same .REL input format
- Same .COM output format
- Syntax matches original for compatibility

### ulib80 vs LIB80

- Uses custom ULIB library format (not bit-compatible with LIB80)
- Functionally equivalent
- Libraries can be rebuilt from .REL files

### ud80

New tool with no Microsoft equivalent. Designed to complement the toolchain
by enabling disassembly of existing CP/M programs.

## Examples

### Hello World

```asm
; hello.mac - Hello World for CP/M
        ORG     0100H

BDOS    EQU     0005H       ; BDOS entry point
PRINT   EQU     9           ; Print string function

START:  MVI     C,PRINT     ; BDOS function
        LXI     D,MSG       ; String address
        CALL    BDOS
        RET

MSG:    DB      'Hello, World!$'

        END     START
```

Build and run:

```bash
um80 hello.mac
ul80 hello.rel
cpm hello.com    # Using a CP/M emulator
```

### Multi-Module Project

main.mac:
```asm
        EXTRN   GETNUM, PUTNUM
        PUBLIC  START

        ORG     0100H

START:  CALL    GETNUM      ; Get number from user
        CALL    PUTNUM      ; Display it
        RET

        END     START
```

io.mac:
```asm
        PUBLIC  GETNUM, PUTNUM

GETNUM: ; ... implementation ...
        RET

PUTNUM: ; ... implementation ...
        RET

        END
```

Build:

```bash
um80 main.mac
um80 io.mac
ul80 -o program.com main.rel io.rel
```

### Using Libraries

```bash
# Build library modules
um80 math.mac
um80 string.mac
um80 io.mac

# Create library
ulib80 -c stdlib.lib math.rel string.rel io.rel

# Link with library
ul80 -o program.com main.rel stdlib.lib
```

## Troubleshooting

### "Undefined symbol" errors

- Check spelling (symbols are case-insensitive)
- Ensure PUBLIC declaration in defining module
- Ensure EXTRN declaration in referencing module
- Verify all needed .rel files are on link command

### "Phase error" warnings

- Label defined at different address in pass 1 vs pass 2
- Usually caused by forward reference in expression
- Try rearranging code or using explicit ORG

### Disassembly produces garbage

- Code might be data - use `-d` to mark data ranges
- Missing entry points - use `-e` to add them
- Wrong processor mode - try `-z` for Z80 code

## Support

For issues and feature requests, visit the project repository.
