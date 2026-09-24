# um80/ul80 Extensions Beyond M80/L80

This document describes extensions to the Microsoft MACRO-80 and LINK-80 compatible toolchain that go beyond the original Microsoft implementations.

## Extended REL Format: Long Symbol Names

### Background

The original Microsoft REL format encodes symbol names in a "B-field" using a 3-bit length (0-7, where 0 means 8 characters) followed by the ASCII characters. This limits symbol names to 8 characters maximum.

This limitation causes problems when assembling code that uses longer symbol names. (M80 itself keeps only the first 6 characters of every symbol.)

### Extended B-Field Format

um80/ul80 extend the REL B-field format to support symbols up to 255 characters:

**Standard format (1-8 characters):**
```
| 3-bit length | N bytes of ASCII characters |
```
- Length 1-7 means that many characters
- Length 0 means 8 characters

**Extended format (9-255 characters):**
```
| 3-bit length (0) | 0xFF marker | 1-byte actual length | N bytes of ASCII characters |
```
- 3-bit length field = 0
- First byte = 0xFF (extended mode marker)
- Second byte = actual length (9-255)
- Followed by the characters

### Backward Compatibility

The extended format is designed for backward compatibility:
- Standard 8-char symbols starting with 0xFF are extremely rare (non-printable)
- ul80 detects the 0xFF marker and reads the extended length

LINK-80 3.44 reads neither: it refuses a 3-bit count of 0 ("?Loading
Error"), so the longest name it accepts is **7** characters, and the longest
external an extension item `B` can name is 6 (the `B` is the first byte).
Checked against the genuine L80 under a CP/M emulator.

### Command-Line Control

Use `-t` or `--truncate` to disable extended format and truncate symbols to 8 characters (M80-compatible mode):

```bash
um80 -t program.mac          # Truncate symbols to 8 chars
um80 --truncate program.mac  # Same as above
um80 program.mac             # Default: allow long symbols
```

This is useful when:
- Debugging symbol resolution issues
- Comparing behavior with original tools

For objects the original Microsoft L80 is to read, keep symbols to 7
characters (6 for an external used in a link-time expression): `-t` still
allows 8, which L80 refuses.

---

## DRI Assembler Extensions

um80 supports several Digital Research (DRI) assembly syntax extensions commonly found in CP/M, MP/M, and CP/M-86 source code. These extensions are compatible with DRI's ASM, MAC, and RMAC assemblers.

### Multi-Statement Lines (`!` Separator)

Multiple instructions can be placed on a single line, separated by `!`:

```asm
        PUSH H! PUSH D! PUSH B      ; Save registers
        POP B! POP D! POP H         ; Restore registers
        MOV A,B! ORA A! RZ          ; Test and return if zero
        XRA A! RET                  ; Clear A and return
```

This is commonly used in DRI source code to group related operations. The comment applies to the entire line.

**Implementation notes:**
- The `!` separator is recognized outside of string literals
- Each statement after the first is processed as if it had no label
- Works with all instructions and most directives
- A macro-invocation line is **not** split on `!`. There, `!` retains its M80
  meaning of quoting the next character in the argument list (e.g.
  `head FOO,!!CF` passes the name `!CF`, and `!,` passes a literal comma), so
  the separator never interferes with macro arguments.

### HIGH and LOW Operators (Function Syntax)

Extract the low or high byte of a 16-bit value using function-call syntax:

```asm
        MVI L,LOW(BUFFER)           ; Load low byte of address
        MVI H,HIGH(BUFFER)          ; Load high byte of address
        MVI A,LOW(1234H)            ; A = 34H
        MVI B,HIGH(1234H)           ; B = 12H
        LXI H,HIGH(TABLE)*256+LOW(TABLE)  ; Verbose identity
```

Both syntaxes are supported:
- `LOW(expr)` and `HIGH(expr)` — DRI function-call style
- `LOW expr` and `HIGH expr` — Original M80 style with space

Of an absolute value the result is a constant. Of a relocatable or external
value it depends on where the linker puts things, so um80 passes the expression
to the linker — see [Link-time expressions](#link-time-expressions-rel-extension-link-items).

### Digit Separators in Numbers (`$`)

The `$` character can be used as a visual separator within numeric literals for readability:

```asm
        MVI A,1111$0000B            ; Binary: F0H
        MVI B,0001$0010B            ; Binary: 12H
        LXI H,1$0000H               ; Hex: 10000H (wraps to 0000H)
        MVI C,1$000D                ; Decimal: 1000
        DW  0ABCD$EF00H             ; Large hex constant
```

The `$` characters are stripped during parsing and do not affect the numeric value. This is particularly useful for binary constants where grouping bits improves readability.

### Register Aliases via EQU

Symbols can be defined with EQU to represent registers, then used in place of register names:

```asm
; Define register aliases using register names
UR      EQU     B                   ; UR is an alias for register B
LR      EQU     C                   ; LR is an alias for register C
MR      EQU     E                   ; MR is an alias for register E
KR      EQU     H                   ; KR maps to H (or HL for pairs)

; Use aliases in instructions
        MVI MR,0                    ; Same as MVI E,0
        MOV A,UR                    ; Same as MOV A,B
        INR LR                      ; Same as INR C
        DCR MR                      ; Same as DCR E
```

**Register pair promotion:**

For instructions that require register pairs (LXI, PUSH, POP, INX, DCX, DAD, etc.), single-register aliases are automatically promoted to their corresponding pair:

| Single Register | Promoted To |
|-----------------|-------------|
| B or C (0,1) | BC |
| D or E (2,3) | DE |
| H or L (4,5) | HL |

```asm
KR      EQU     H                   ; KR = 4 (H register)
        LXI KR,0                    ; Assembles as LXI H,0
        INX KR                      ; Assembles as INX H
        DAD KR                      ; Assembles as DAD H
```

**Numeric register values:**

EQU can also use numeric values (0-7 for registers, 0-3 for pairs):

```asm
REG_A   EQU     7                   ; A register
REG_BC  EQU     0                   ; BC pair
        MOV A,REG_A                 ; MOV A,A (unusual but valid)
        LXI REG_BC,100H             ; LXI B,100H
```

### PUSH A / POP A

DRI assemblers allowed `PUSH A` and `POP A` as synonyms for `PUSH PSW` and `POP PSW`:

```asm
        PUSH A                      ; Same as PUSH PSW
        POP A                       ; Same as POP PSW
```

This is shorthand recognized in MP/M and CP/M Plus source code.

### Conditional Directive Parsing

Conditional assembly directives at column 1 without a trailing colon are correctly recognized as directives, not labels:

```asm
IF DEBUG                            ; IF is a directive, not a label
        CALL TRACE
ENDIF                               ; ENDIF is a directive
```

This matches DRI assembler behavior where `IF`, `ELSE`, `ENDIF`, `IFDEF`, `IFNDEF`, etc. do not require indentation.

### External Symbol Aliases (EQU external+offset)

um80 supports defining symbols as aliases to external symbols with an optional offset:

```asm
        EXTRN   ROUTINE         ; External symbol
        PUBLIC  ROUTINE_ALT     ; Export the alias

; Define alias as external + offset
ROUTINE_ALT EQU ROUTINE+2       ; ROUTINE_ALT = ROUTINE + 2
```

**Use cases:**

1. **Alternate entry points:** Skip initialization code in a routine:
   ```asm
   ; Library module defines:
   ROUTINE:
           LD  A,10            ; 2 bytes - initialization
   ROUTINE_ENTRY:              ; Actual entry point
           ADD A,B
           RET

   ; Another module creates alias:
           EXTRN   ROUTINE
           PUBLIC  ROUTINE_ENTRY
   ROUTINE_ENTRY EQU ROUTINE+2
   ```

2. **Structure field offsets:** Access fields in structures defined elsewhere:
   ```asm
           EXTRN   BUFFER
           PUBLIC  BUF_LEN
           PUBLIC  BUF_DATA
   BUF_LEN  EQU BUFFER          ; Length at offset 0
   BUF_DATA EQU BUFFER+2        ; Data at offset 2
   ```

3. **z88dk compatibility:** The z88dk project uses this pattern extensively in its math libraries:
   ```asm
   ; z88dk pattern for alternate return points
           EXTRN   mm48__add10
           PUBLIC  am48_dpopret
   am48_dpopret EQU mm48__add10+1
   ```

**How it works:**

- When `EQU` is given an external symbol (with optional offset), um80 tracks it as an "external alias"
- When the alias is used in code, it emits an external reference with the combined offset
- When the alias is declared PUBLIC, it emits a special entry point format: `NEWNAME=EXTERNAL+N`
- The linker (ul80) detects this format and resolves the alias after loading all modules

**Limitations:**

- The base external symbol must be defined in another module being linked
- Aliases cannot be chained (ALIAS2 EQU ALIAS1+N where ALIAS1 is also an alias)
- The offset must be a constant expression

---

## ul80 Linker Extensions

### `__END__` Predefined Symbol

The linker automatically provides a `__END__` symbol that points to the first free byte after all linked segments:

```asm
        EXTRN   __END__             ; Import linker symbol

START:  LXI     H,__END__           ; Load end of program
        SHLD    HEAP                ; Initialize heap pointer
        ; ... allocate from HEAP upward ...

        DSEG
HEAP:   DW      0                   ; Heap pointer storage
```

This is useful for:
- Dynamic memory allocation (heap starts at `__END__`)
- Determining program size at runtime
- Initializing memory pools

### MP/M PRL Format Support

ul80 can output MP/M's two page-relocatable formats:

```bash
ul80 --prl program.rel                  # Transient .PRL, linked at 100H
ul80 --prl --extra 1000 -o pip.prl a.rel b.rel
ul80 --spr -o xdos.spr a.rel b.rel      # System page .SPR/.RSP, linked at 0
```

Both carry a 256-byte header, the image, and a relocation bitmap with one bit
per byte of the image; MP/M adds the load page to every byte the bitmap marks.

- **`--prl`** is a transient. MP/M loads it at `segment_bottom + 100H` but its
  relocator adds only the segment's base page, so the image is linked at 100H,
  exactly like a `.COM`.
- **`--spr`** is a system page (`.SPR`, `.RSP`, `.BRS`), loaded at the segment
  base itself and linked at 0.
- **`--extra HEX`** is the memory a `.PRL` asks for beyond its image, for
  storage a PL/M program places at `.MEMORY` — GENMOD's third argument
  (`genmod pip.hex pip.prl $1000`).

Page zero belongs to the process's memory segment under MP/M, so in either
format a resolved reference to an absolute symbol below 100H (the BDOS entry at
0005H, the default FCB at 005CH, the DMA buffer at 0080H) is marked for
relocation. An absolute symbol at or above 100H stays absolute.

A byte that is `HIGH` of an address, or a word that is an address, is marked
in the bitmap; a byte that is `LOW` of an address is not, since adding a page
never changes a low byte. A link-time expression whose value would not move by
exactly 0 or 1 page (`HIGH(A)+HIGH(B)`, `200H-LAB`, `LAB*2`) cannot be
expressed in the bitmap and is an error in either format.

### Link-time expressions (REL extension link items)

`MVI A,LOW(BUF+128)` with BUF in a relocatable segment needs a byte of an
address nobody knows until link time. MACRO-80 3.44 and LINK-80 3.44 handle it
with special link item 4, the "extension link item": its B-field starts with a
kind byte, and three kinds form a postfix program for the linker.

| Item | Bytes | Meaning |
|------|-------|---------|
| `A` | 41H, op | operator: 1 store as byte, 2 store as word, 3 HIGH, 4 LOW, 5 NOT, 6 unary minus, 7 minus, 8 plus, 9 multiply, 10 divide, 11 MOD |
| `B` | 42H, name | push the value of external symbol *name* |
| `C` | 43H, type, lo, hi | push a value; type 0 absolute, 1 program, 2 data, 3 common relative |

Operands are pushed in source order and a binary operator pops its right
operand first. Every expression ends in a store operator, which writes the
result at the current location counter; the field itself follows as zero
placeholder bytes, which load there and advance the counter. So
`MVI A,LOW(BUF+128)` becomes the absolute byte 3EH, then
`C(data, BUF+128) A(LOW) A(store byte)`, then the placeholder 00H.

The published Microsoft manual defines only the item 4 container (and a COBOL
overlay sentinel, 35H); the `A`/`B`/`C` kinds were established by assembling
test sources with the genuine M80 3.44 and linking them with L80 3.44 under a
CP/M emulator. Digital Research's LINK-80 lists item 4 as unused, and RMAC
rejects `LOW`/`HIGH` of a relocatable value with an `E` error.

um80 writes these items for:

- `HIGH`, `LOW`, `NOT`, unary minus, `*`, `/` and `MOD` applied to a
  relocatable or external value;
- any relocatable or external value in a one-byte field (`MVI A,BUF`,
  `DB LAB`, an `(IX+d)` displacement), as M80 does;
- a word that is not simply an address plus a constant (`-LAB`, `LAB+LAB2`,
  `DATALAB-CODELAB`, `n-EXT`, `EXT1+EXT2`, `HIGH(EXT)`).

`AND`, `OR`, `XOR`, `SHL`, `SHR` and the comparisons have no linker operator,
so applying one to a relocatable or external value in an instruction or
`DB`/`DW` operand is an error (M80: `R`). An `EQU` or `SET` to a link-time
expression stands for the expression wherever the symbol is used; such a symbol
cannot be `PUBLIC`.

ul80 evaluates the expressions once every module is placed and writes the
results over the placeholders, for every output format, and reads objects
written by the real M80 the same way.

### Objects LINK-80 reads, and objects MACRO-80 writes

um80's `.REL` files follow the Microsoft format where earlier releases did
not, so the genuine LINK-80 3.44 loads them, and ul80 links what MACRO-80 3.44
writes (each checked by linking the same program four ways: M80+L80,
M80+ul80, um80+L80, um80+ul80):

- special item 14 (end program) carries its A-field, the start address
  (absolute 0 if none), and item 13 (program size) is typed program relative;
  the segment and COMMON sizes come first in the module, as M80 writes them
  (L80 needs a COMMON block's size before anything refers to it);
- `JMP EXT+3` is item 9 (External plus offset, `A` = 3; `EXT-1` is FFFFH)
  just before the word, which is a reference in EXT's chain. um80 used to put
  the constant in the chain's name (`EXT+3`), which L80 takes for an undefined
  symbol; ul80 still reads that. ul80 applies items 9 and 8, and follows
  MACRO-80's chains through every reference, each link typed by its
  relocation;
- a chain head of absolute 0 is an empty chain (M80 writes one for an
  external used only in an expression), so a reference *at* absolute 0 is
  written as an extension item `B(EXT) A(store word)`;
- each named COMMON block is placed on its own; a COMMON-relative word,
  extension value, public, chain head or set-location is preceded by
  special item 1 when it refers to another block than the one selected last;
  bytes assembled into a COMMON block load there (DB, FORTRAN's BLOCK DATA);
- a `.REL` holding several modules (a LIB-80 library such as FORTRAN-80's
  FORLIB.REL) loads every one of them, and `ulib80 -c` stores each as a
  module of its own.

### Absolute assembly (`--aseg`)

M80 starts a file in CSEG, so an `ORG` is an offset within a relocatable
segment. DRI's MAC has no relocatable segments: its sources are absolute and an
`ORG` is an absolute address. `um80 --aseg` starts the file in ASEG, which
assembles MAC sources the way MAC does.

---

## Compatibility Matrix

| Feature | M80/L80 | um80/ul80 | ASM/MAC/RMAC | z88dk |
|---------|---------|-----------|--------------|-------|
| 8-char symbols | ✓ | ✓ | ✓ | ✓ |
| Extended symbols (>8) | ✗ | ✓ | ✗ | ✓ |
| `!` separator | ✗ | ✓ | ✓ | ✗ |
| `HIGH(expr)` syntax | ✗ | ✓ | ✓ | ✓ |
| `HIGH expr` syntax | ✓ | ✓ | ✓ | ✓ |
| `$` digit separator | ✗ | ✓ | ✓ | ✗ |
| Register EQU aliases | ✗ | ✓ | ✓ | ✗ |
| PUSH A / POP A | ✗ | ✓ | ✓ | ✗ |
| EQU external+offset | ✗ | ✓ | ✗ | ✓ |
| `__END__` symbol | ✗ | ✓ | ✗ | ✗ |
| PRL / SPR output | ✗ | ✓ | (RMAC) | ✗ |
| HIGH/LOW of a relocatable value | ✓ (3.44) | ✓ | ✗ | ? |

---

## Version History

- **Unreleased** — link-time expressions (REL extension link items): HIGH/LOW of relocatable and external values; `.REL` objects the genuine LINK-80 reads (item 14's A-field, item 9 for EXT+n, COMMON block selection)
- **0.3.48** — `--spr`, `--extra` and `--aseg`; `--prl` links a transient at 100H
- **0.3.33** — External symbol aliases (EQU external+offset) for z88dk compatibility
- **0.3.21** — Extended REL format for long symbols, `-t/--truncate` switch
- **0.3.20** — DRI extensions (!, HIGH(), $, register aliases, PUSH A)
- Earlier versions focused on M80/L80 compatibility
