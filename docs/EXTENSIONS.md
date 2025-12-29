# um80/ul80 Extensions Beyond M80/L80

This document describes extensions to the Microsoft MACRO-80 and LINK-80 compatible toolchain that go beyond the original Microsoft implementations.

## Extended REL Format: Long Symbol Names

### Background

The original Microsoft REL format encodes symbol names in a "B-field" using a 3-bit length (0-7, where 0 means 8 characters) followed by the ASCII characters. This limits symbol names to 8 characters maximum.

This limitation causes problems when assembling code that uses longer symbol names, especially when external references include offsets like `MEMSEGTBL+2`. The original M80 would truncate this to `MEMSEGTB` (8 chars), losing the `+2` offset information.

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
- Legacy L80 would see 0xFF as the first character of an 8-char symbol
- ul80 detects the 0xFF marker and reads the extended length

### Command-Line Control

Use `-t` or `--truncate` to disable extended format and truncate symbols to 8 characters (M80-compatible mode):

```bash
um80 -t program.mac          # Truncate symbols to 8 chars
um80 --truncate program.mac  # Same as above
um80 program.mac             # Default: allow long symbols
```

This is useful when:
- Producing REL files for use with original Microsoft L80
- Debugging symbol resolution issues
- Comparing behavior with original tools

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

ul80 can output MP/M Page Relocatable (.PRL) format:

```bash
ul80 --prl program.rel              # Output program.prl
ul80 --prl -o output.prl a.rel b.rel
```

PRL files contain:
- A relocation bitmap for page-aligned loading
- Offset header for MP/M loader
- Position-independent code support

---

## Compatibility Matrix

| Feature | M80/L80 | um80/ul80 | ASM/MAC/RMAC |
|---------|---------|-----------|--------------|
| 8-char symbols | ✓ | ✓ | ✓ |
| Extended symbols (>8) | ✗ | ✓ | ✗ |
| `!` separator | ✗ | ✓ | ✓ |
| `HIGH(expr)` syntax | ✗ | ✓ | ✓ |
| `HIGH expr` syntax | ✓ | ✓ | ✓ |
| `$` digit separator | ✗ | ✓ | ✓ |
| Register EQU aliases | ✗ | ✓ | ✓ |
| PUSH A / POP A | ✗ | ✓ | ✓ |
| `__END__` symbol | ✗ | ✓ | ✗ |
| PRL output | ✗ | ✓ | (RMAC) |

---

## Version History

- **0.3.21** — Extended REL format for long symbols, `-t/--truncate` switch
- **0.3.20** — DRI extensions (!, HIGH(), $, register aliases, PUSH A)
- Earlier versions focused on M80/L80 compatibility
