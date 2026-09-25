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
git clone https://github.com/avwohl/um80_and_friends.git
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
um80 -t program.mac                 # Cut symbol names to 6 chars, as M80 does
um80 -e ".z80" program.mac          # Execute code before source (set Z80 mode)
um80 --pre macros.mac program.mac   # Include file before source
um80 --aseg program.asm             # Absolute, like DRI's MAC: ORG is an address
um80 --dri program.asm              # DRI source: a $ inside a name is ignored
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

## Compatibility Notes

These tools aim for compatibility with the original Microsoft tools while running on modern Unix/Linux systems:

- Source files use Unix line endings (LF), but CR/LF is also accepted
- File names are case-insensitive for symbols (converted to uppercase)
- Default origin is 0100h (standard CP/M load address)
- Output files are binary-compatible with original CP/M tools

### 8080 is the default; Z80 mnemonics need `.Z80`

Like M80, um80 assembles 8080 mnemonics until a `.Z80` directive appears (use
`um80 -e .z80 file.mac` to set the mode from the command line without editing
the source). Where a Z80 instruction is spelled with an 8080 mnemonic — `RET
NZ`, `RLC B`, `RRC C` — um80 rejects it in 8080 mode instead of dropping the
operand:

```
$ um80 z80source.mac
Error at line 5: RET takes no operand, but was given 'NZ' RET NZ is Z80 syntax;
the 8080 spelling is RNZ. Add a .Z80 directive to assemble Z80 mnemonics.
```

Genuine M80 3.44 only flags these `Q` and emits the operand-less opcode, so
`RET NZ` assembles as an unconditional `RET` (C9) and the .REL is still
written. um80 makes it an error because that is a silent miscompile; this is a
deliberate divergence, recorded in CHANGELOG.md. Nothing is written and the
exit status is 1, as for any other assembly error.

## Extended Symbol Names

The original Microsoft REL format limits symbol names to 8 characters (and LINK-80 3.44 reads at most 7). um80/ul80 extend this to support symbols up to 255 characters, which is essential for:

- Long descriptive symbol names in modern code
- Compatibility with source code written for other assemblers

Use `-t` or `--truncate` to cut symbol names to 6 characters, as MACRO-80 does. An object that is to be linked with objects that M80 assembled needs it if a PUBLIC or EXTRN name is longer than 6 characters: M80 writes `FBUFP27` as `FBUFP2`. For objects that the original LINK-80 is to read, keep names to 7 characters (6 for an external used in a link-time expression), or use `-t`.

See [docs/EXTENSIONS.md](docs/EXTENSIONS.md) for technical details on the extended REL format.

## DRI Extensions

um80 supports several Digital Research (DRI) assembly syntax extensions commonly found in CP/M and MP/M source code. These extensions are compatible with DRI's ASM, MAC, and RMAC assemblers.

### Multi-Statement Lines (`!` separator)

Multiple instructions can be placed on a single line, separated by `!`:

```asm
        PUSH H! PUSH D! PUSH B      ; Save registers
        POP B! POP D! POP H         ; Restore registers
        MOV A,B! ORA A! RZ          ; Test and return if zero
```

### LOW and HIGH Operators

Extract the low or high byte of a 16-bit value using function-call syntax:

```asm
        MVI L,LOW(BUFFER)           ; Load low byte of address
        MVI H,HIGH(BUFFER)          ; Load high byte of address
        MVI A,LOW(1234H)            ; A = 34H
        MVI B,HIGH(1234H)           ; B = 12H
```

Both `LOW(expr)` and `HIGH(expr)` syntax (with parentheses) and `LOW expr` / `HIGH expr` syntax (with space) are supported.

When the operand is relocatable or external (`LOW(BUFFER)` above, with BUFFER
in CSEG or DSEG), the byte depends on where the linker puts the segment, so
um80 passes the expression to ul80 as REL extension link items — the same form
MACRO-80 3.44 writes for LINK-80 3.44. The same happens for any relocatable or
external value in a one-byte field (`MVI A,BUFFER`, `DB LABEL`). In MP/M
`.PRL`/`.SPR` output a `HIGH` byte is marked in the relocation bitmap and a
`LOW` byte is not. See [docs/EXTENSIONS.md](docs/EXTENSIONS.md#link-time-expressions-rel-extension-link-items).

### Digit Separators in Numbers (`$`)

The `$` character can be used as a visual separator within numeric literals for readability:

```asm
        MVI A,1111$0000B            ; Binary with separator
        LXI H,1$0000H               ; Hex: 10000H
        MVI B,1$000D                ; Decimal: 1000
```

The `$` characters are ignored during parsing and do not affect the numeric value.

### `$` Inside Names (`--dri`)

DRI's MAC and RMAC also ignore a `$` inside a name: `NMB$LST` and `NMBLST` are
one symbol. MACRO-80 keeps it, so by default um80 does too. `um80 --dri` reads
names as MAC and RMAC do; MP/M II's sources need it (`MPM.ASM` stores to
`nmb$lst`, which `DATAPG.ASM` defines as `nmblst`). See
[docs/EXTENSIONS.md](docs/EXTENSIONS.md#dri-sources---dri) for exactly what it
changes.

### Register Names as Values

In 8080 code um80 gives each register name a number and reads a register
operand as an expression, as MACRO-80 and DRI's MAC and RMAC do: B 0, C 1,
D 2, E 3, H 4, L 5, M 6, A 7, SP and PSW 6. A symbol equated to a register
name names that register:

```asm
UR      EQU     B                   ; 0: register B
MR      EQU     E                   ; 3: register E
RD      EQU     D                   ; 2: register D, or the pair DE
        MVI MR,0                    ; Same as MVI E,0
        MOV A,UR                    ; Same as MOV A,B
        DAD RD                      ; Same as DAD D
        PUSH RD                     ; Same as PUSH D
```

A register pair operand is the number of its first register: 0 B, 2 D, 4 H,
6 SP or PSW. An odd number (`DAD E`) is an error, as in M80 and MAC. An
address is its offset in its segment, as in M80 (`DAD LAB`, with `LAB` two
bytes into the code, is `DAD D`), with a warning. See
[docs/EXTENSIONS.md](docs/EXTENSIONS.md#register-names-as-values-equ-of-a-register).

### PUSH A / POP A

DRI assemblers allowed `PUSH A` and `POP A` as synonyms for `PUSH PSW` and `POP PSW`:

```asm
        PUSH A                      ; Same as PUSH PSW (push A and flags)
        POP A                       ; Same as POP PSW (pop A and flags)
```

### External Symbol Aliases (EQU external+offset)

Symbols can be defined as aliases to external symbols with an optional offset, then exported as PUBLIC:

```asm
; In library module - define entry points
        EXTRN   ADD10           ; External symbol from another module
        PUBLIC  ADD10_SKIP      ; Export the alias

; Define alias: ADD10_SKIP is ADD10+2 (skip first instruction)
ADD10_SKIP  EQU ADD10+2
```

This is useful for:
- Defining alternate entry points into routines (skipping initialization code)
- Creating symbolic offsets into data structures defined in other modules
- Porting code from assemblers that support this feature (like z88dk)

The alias is resolved at link time:

```asm
; In main module - use both symbols
        EXTRN   ADD10
        EXTRN   ADD10_SKIP

START:  CALL    ADD10           ; Call full routine
        CALL    ADD10_SKIP      ; Call at offset (skips first 2 bytes)
```

For more details on these extensions and compatibility notes, see [docs/EXTENSIONS.md](docs/EXTENSIONS.md).

## Documentation

- Man pages: `man um80`, `man ul80`, `man ulib80`, `man ucref80`, `man ud80`, `man ux80`
- [docs/mbasic2025.md](docs/mbasic2025.md): mbasic2025 built with um80/ul80 and with the genuine M80/L80
- Original Microsoft manuals in `docs/external/`:
  - `m80.pdf` - MACRO-80 assembler
  - `l80.pdf` - LINK-80 linker
  - `cref_lib.pdf` - CREF and LIB-80
  - `8080asm.pdf` - 8080 assembly reference

## Testing

The test suite (554 tests) runs under `pytest`:

```bash
pip install -e ".[dev]"
pytest                                    # run everything
pytest tests/test_expr_precedence.py -v   # one file, verbose
```

The MACRO-80 compatibility tests below were validated against the genuine
Microsoft MACRO-80 / LINK-80 3.44 binaries — each expected value was confirmed
by assembling the same source with the real assembler — so they pin um80/ul80
to documented M80 behavior. Those marked (DRI) were also checked against
Digital Research's MAC 2.0 and RMAC 1.1:

| File | Covers |
|------|--------|
| `test_expr_precedence.py` | Operator precedence (unary `-`/`NOT`/`HIGH`/`LOW`, relational, shifts) |
| `test_macro_bang_args.py` | DRI `!` separator vs. M80 argument-quote `!`, escaped commas |
| `test_macro_concat.py` | `&` concatenation: leading/trailing/shared, in-string `&param`, case folding |
| `test_macro_expansion.py` | EXITM in conditionals, macro shadowing built-ins, string-safe substitution, `NUL` |
| `test_repeat_blocks.py` | Nested REPT/IRP/IRPC, IRP sublists, EXITM |
| `test_radix_conditional.py` | Decimal `.RADIX` operand, unterminated / duplicate-`ELSE` diagnostics |
| `test_symbol_class.py` | SET vs. EQU/label redefinability classes |
| `test_z80_and_charconst.py` | `LD A,I`/`LD A,R` encoding, two-character constant byte order |
| `test_linker_segments.py` | Absolute ASEG placement, mixed CSEG+ASEG, COMMON-only modules |
| `test_linker_absolute_code.py` | A module's code placed above the absolute code loaded before it; absolute code overlapping anything is an error, or with `--allow-overlap` a warning and the byte loaded last in the image |
| `test_linker_dupglobal.py` | A global two modules define is L80's `%Mult. Def. Global` warning and the first definition is used; with `--fatal-mult-def` an error |
| `test_linker_loaded_over.py` | A byte loaded over a relocatable word or an item-12 chain word (an ORG back, a COMMON block declared again or shared) replaces that byte, as L80 relocates on loading |
| `test_irp_list_brackets.py` | An `IRP`/`IRPC` `<...>` list ends at its matching `>` (`IRPC C,<>>` is empty); `!` in an `IRP`/`IRPC` line |
| `test_module_name.py` | The module name from `NAME('X')` and, without it, from the last `TITLE` |
| `test_extrn_declared.py` | An `EXTRN` never used is written as an empty chain, and it pulls a library module; ul80 warns if nothing defines it |
| `test_truncate_m80.py` | `-t` cuts names to M80's 6 characters, so a um80 object links with an M80 object's `FBUFP2` |
| `test_parity_bit.py` | (DRI) A source byte's bit 7 is cleared: a line ending CR 8AH ends the line, C1H in a string is `A`, and an 8AH not after a CR is left out, as in M80 |
| `test_equ_name_column.py` | (DRI) The name of an `EQU`, `SET`, `DEFL`, `ASET` or `MACRO` may be indented |
| `test_register_values.py` | (DRI) A register operand is an expression and a register name its number: `RD EQU D` / `DAD RD` is `DAD D`; an odd register pair is an error; an address is its offset, as in M80 |
| `test_dri_names.py` | (DRI) `--dri` ignores a `$` inside a name, as MAC and RMAC do, but not in a macro call's arguments or an `IRP`/`IRPC` list; without it `$` is part of the name, as in M80 |

Further tests cover the toolchain more broadly: `test_ds_org.py` (DS/ORG and
segment placement), `test_defs_fill.py` (DEFS fill value), `test_end_symbol.py`
(`END` entry symbol and `__END__`), `test_ext_alias.py` (external aliases),
`test_jr_promotion.py` (JR/DJNZ out-of-range promotion),
`test_no_operand_strict.py` (an operand on a no-operand instruction is an
error, the one deliberate divergence from M80), and `test_case_sensitivity.py`.

### mbasic2025: historic binaries, byte for byte

`test_mbasic2025.py` builds the sources of
[mbasic2025](https://github.com/avwohl/mbasic2025) with each variant's own
build commands and this checkout's um80 and ul80. It compares the results,
byte for byte, with the historic Microsoft binaries: MBASIC 5.21 (14 modules,
and one Z80 file) and Altair 4K and 8K BASIC 4.0. It needs a mbasic2025
checkout, at `$MBASIC2025_DIR` or next to this repository. Without one, the
test is skipped:

```bash
git clone https://github.com/avwohl/mbasic2025 ../mbasic2025
pytest tests/test_mbasic2025.py -v -rw
```

CI (`.github/workflows/tests.yml`) checks out mbasic2025, at a pinned commit,
and runs the whole suite on every push and pull request. To test against a
newer mbasic2025, change the `ref:` there.

`tools/fourway_mbasic.py` builds the same sources with every mix of the genuine
MACRO-80/LINK-80 and um80/ul80. Each assembler builds all modules. Then one
module comes from the other assembler, for each module. Each of these is
linked with both linkers. The tool compares each image with the M80 + L80
build and with the historic binary. Microsoft's binaries are not in this
repository. Give their paths, and a [cpmemu](https://github.com/avwohl/cpmemu)
to run them:

```bash
python3 tools/fourway_mbasic.py --m80 path/M80.COM --l80 path/L80.COM \
    --cpmemu path/cpmemu [--variant mbasic_521] [--um80-flag=-t]
```

The exit status is 1 if any mix differs from the M80 + L80 build. Without
`--um80-flag=-t`, 8 of the 60 `mbasic_521` links fail because of a 7-character
name, which the tool names; use `-t` when the exit status is a pass/fail check.

[docs/mbasic2025.md](docs/mbasic2025.md) has the results and the changes that
mbasic2025's sources need.

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
## Related Projects

- [80un](https://github.com/avwohl/80un) - Unpacker for the CP/M archive and compression formats LBR, ARC, squeeze, crunch, and CrLZH.
- [cpmdroid](https://github.com/avwohl/cpmdroid) - Z80/CP/M emulator for Android phones and tablets. It emulates the RomWBW HBIOS interface and a VT100 terminal.
- [cpmemu](https://github.com/avwohl/cpmemu) - Z80/CP/M emulator for Linux and Windows, with Z80 and 8080 CPU cores. It translates the BDOS and BIOS calls of CP/M 2.2 programs to the host file system.
- [ioscpm](https://github.com/avwohl/ioscpm) - Z80/CP/M emulator for iOS and macOS. It emulates the RomWBW HBIOS interface and runs CP/M 2.2 and CP/M 3.
- [learn-ada-z80](https://github.com/avwohl/learn-ada-z80) - Collection of more than 90 Ada example programs for uada80, the Ada compiler for the Z80 processor and CP/M.
- [mbasic](https://github.com/avwohl/mbasic) - Python interpreter for MBASIC 5.21, the Microsoft BASIC-80 for CP/M. Two compiler backends compile the programs to CP/M .COM files or to JavaScript.
- [mbasic2025](https://github.com/avwohl/mbasic2025) - Reconstruction of the lost source code of MBASIC 5.21, the Microsoft BASIC-80 for CP/M. The MACRO-80 source code assembles to a binary that matches mbasic.com byte for byte.
- [mbasicc](https://github.com/avwohl/mbasicc) - C++17 interpreter for MBASIC 5.21, the Microsoft BASIC-80 for CP/M. It runs on Linux and macOS.
- [mbasicc_web](https://github.com/avwohl/mbasicc_web) - Web browser interpreter for MBASIC 5.21, the Microsoft BASIC-80 for CP/M. Emscripten compiles the mbasicc interpreter to WebAssembly.
- [mpm2](https://github.com/avwohl/mpm2) - Z80 emulator for MP/M II, the multi-user CP/M operating system. Users connect over SSH, and SFTP clients transfer files.
- [romwbw_emu](https://github.com/avwohl/romwbw_emu) - Hardware-level Z80/CP/M emulator for Linux and macOS. It emulates the RomWBW HBIOS interface and switches banks in 512 KB of ROM and 512 KB of RAM.
- [scelbal](https://github.com/avwohl/scelbal) - Floating-point BASIC interpreter for the 8080 processor and CP/M. A translator converts the original 8008 source code to 8080 source code.
- [uada80](https://github.com/avwohl/uada80) - Ada compiler for the Z80 processor and CP/M 2.2. It compiles a subset of Ada 2012 to CP/M .COM files.
- [uc80](https://github.com/avwohl/uc80) - C compiler for the Z80 processor and CP/M. It optimizes for small code size.
- [ucow](https://github.com/avwohl/ucow) - Cowgol compiler for the Z80 processor and CP/M. It runs on Linux in Python.
- [upeepz80](https://github.com/avwohl/upeepz80) - Peephole optimizer for Z80 compilers that write lowercase Z80 assembly language. It shortens jumps to jr, builds djnz loops, and removes dead stores.
- [uplm80](https://github.com/avwohl/uplm80) - PL/M-80 compiler for the Z80 processor and CP/M. It writes Intel 8080 and Zilog Z80 assembly language.
- [z80cpmw](https://github.com/avwohl/z80cpmw) - Z80/CP/M emulator for Windows. It emulates the RomWBW HBIOS interface and boots CP/M from disk images.

