# um80 - Microsoft MACRO-80 Compatible Toolchain for Linux

A complete Unix/Linux implementation of Microsoft's classic CP/M development tools from the 1980s:

- **um80** - MACRO-80 compatible assembler for 8080/Z80
- **ul80** - LINK-80 compatible linker
- **ulib80** - LIB-80 compatible library manager
- **ucref80** - Cross-reference utility
- **ud80** - 8080/Z80 disassembler for CP/M .COM files
- **ux80** - 8080 to Z80 assembly source translator

These tools can assemble, link, and manage 8080/Z80 assembly code to produce CP/M-compatible .COM executables on modern Linux systems.

## Installation

### From PyPI (recommended)

```bash
pip install um80
```

### From source

```bash
git clone https://github.com/um80/um80_and_friends.git
cd um80_and_friends
pip install -e .
```

## Quick Start

### Assemble a source file

```bash
um80 program.mac                    # Creates program.rel
um80 -o output.rel program.mac      # Specify output name
um80 -l listing.prn program.mac     # Generate listing file
um80 -g program.mac                 # Export all symbols as PUBLIC (for debug)
```

### Link object files

```bash
ul80 program.rel                    # Creates program.com
ul80 -o output.com a.rel b.rel      # Link multiple files
ul80 -s program.rel                 # Generate symbol file (.sym)
ul80 -S symbols.sym program.rel     # Specify symbol file name
ul80 -p E000 program.rel            # Set origin address (hex)
ul80 --prl program.rel              # Output MP/M .PRL format
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

See `man um80` for full documentation, or refer to the original [Microsoft M80 Manual](docs/external/m80.pdf).

### ul80 - Linker

LINK-80 compatible linker that:

- Links multiple .REL relocatable object files
- Resolves external references
- Produces CP/M .COM executables
- Supports COMMON blocks
- Can output Intel HEX format
- Can output MP/M .PRL (Page Relocatable) format

See `man ul80` for full documentation, or refer to the original [Microsoft L80 Manual](docs/external/l80.pdf).

### ulib80 - Library Manager

LIB-80 compatible library manager for:

- Creating .LIB library archives
- Listing library contents and public symbols
- Adding/removing/extracting modules

See `man ulib80` for full documentation, or refer to the original [Microsoft CREF/LIB Manual](docs/external/cref_lib.pdf).

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

## Compatibility Notes

These tools aim for compatibility with the original Microsoft tools while running on modern Unix/Linux systems:

- Source files use Unix line endings (LF), but CR/LF is also accepted
- File names are case-insensitive for symbols (converted to uppercase)
- Default origin is 0100h (standard CP/M load address)
- Output files are binary-compatible with original CP/M tools

## Documentation

- Man pages: `man um80`, `man ul80`, `man ulib80`, `man ucref80`, `man ud80`, `man ux80`
- Original Microsoft manuals in `docs/external/`:
  - `m80.pdf` - MACRO-80 assembler
  - `l80.pdf` - LINK-80 linker
  - `cref_lib.pdf` - CREF and LIB-80
  - `8080asm.pdf` - 8080 assembly reference

## Example Workflow

```bash
# Assemble source files
um80 -o main.rel main.mac
um80 -o util.rel util.mac

# Create a library
ulib80 -c mylib.lib helper.rel support.rel

# Link everything together
ul80 -o program.com main.rel util.rel mylib.lib

# Run in CP/M emulator
cpm program.com
```

## Installing Man Pages

After pip installation, install the man pages manually:

```bash
# Find where the package is installed
PKGDIR=$(python3 -c "import um80; print(um80.__path__[0])")

# Copy man pages to system location (requires sudo)
sudo cp "$PKGDIR/../docs/man/"*.1 /usr/local/share/man/man1/
sudo mandb
```

Or view them directly:

```bash
man docs/man/um80.1
```

## License

GNU General Public License v3.0 or later (GPLv3+). See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
