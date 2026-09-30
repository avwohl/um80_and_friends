# Compatibility and Syntax Extensions

Where um80 matches or differs from Microsoft MACRO-80, and a summary of the
syntax extensions. [EXTENSIONS.md](EXTENSIONS.md) has the full details.

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

### A label needs a colon

As in M80, the first word of a statement is its operation, in column 1 or not
(`NOP` in column 1 is a NOP), and a label is a name with a colon after it; the
name in front of an `EQU`, `SET` or `MACRO` needs none. A statement whose
first word is no instruction, directive or macro is a list of values M80
assembles as `DB` (after `FOO EQU 5`, `FOO` alone is 05), so `LAB DS 1` is an
error there, and in um80. DRI's MAC and RMAC take such a word for a label, in
any column: `um80 --dri` reads it as they do.

## Extended Symbol Names

The original Microsoft REL format limits symbol names to 8 characters (and LINK-80 3.44 reads at most 7). um80/ul80 extend this to support symbols up to 255 characters, which is essential for:

- Long descriptive symbol names in modern code
- Compatibility with source code written for other assemblers

Use `-t` or `--truncate` to cut symbol names to 6 characters, as MACRO-80 does. An object that is to be linked with objects that M80 assembled needs it if a PUBLIC or EXTRN name is longer than 6 characters: M80 writes `FBUFP27` as `FBUFP2`. For objects that the original LINK-80 is to read, keep names to 7 characters (6 for an external used in a link-time expression), or use `-t`.

See [EXTENSIONS.md](EXTENSIONS.md) for technical details on the extended REL format.

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
M80 applies them to the term after them (`HIGH(X)+1` is `HIGH(X)` plus 1), and
so does um80; MAC and RMAC to all that follows (`HIGH(X+1)`), and so does
`um80 --dri`, which also takes MAC's `=`, `<`, `<=`, `>`, `>=` and `<>`.

When the operand is relocatable or external (`LOW(BUFFER)` above, with BUFFER
in CSEG or DSEG), the byte depends on where the linker puts the segment, so
um80 passes the expression to ul80 as REL extension link items — the same form
MACRO-80 3.44 writes for LINK-80 3.44. The same happens for any relocatable or
external value in a one-byte field (`MVI A,BUFFER`, `DB LABEL`). In MP/M
`.PRL`/`.SPR` output a `HIGH` byte is marked in the relocation bitmap and a
`LOW` byte is not. See [EXTENSIONS.md](EXTENSIONS.md#link-time-expressions-rel-extension-link-items).

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
`nmb$lst`, which `DATAPG.ASM` defines as `nmblst`). It also takes a word with no
colon for a label, as MAC does, and ignores a line number, a `*` comment line
and MAC's `$-MACRO` controls. See
[EXTENSIONS.md](EXTENSIONS.md#dri-sources---dri) for exactly what it
changes.

### Register Names as Values

In 8080 code um80 gives each register name a number, in any expression, and
reads a register operand as an expression, as MACRO-80 and DRI's MAC and RMAC
do: B 0, C 1, D 2, E 3, H 4, L 5, M 6, A 7, SP and PSW 6 (`DB B` is 00, `X EQU
D+1` is 3). A symbol equated to a register name names that register:

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
[EXTENSIONS.md](EXTENSIONS.md#register-names-as-values-equ-of-a-register).

### PUSH A / POP A

DRI's MAC and RMAC take `PUSH A` and `POP A` for `PUSH PSW` and `POP PSW`, and
so does `um80 --dri`; M80 flags them, and without `--dri` they are an error:

```asm
        PUSH A                      ; PUSH PSW (push A and flags), with --dri
        POP A                       ; POP PSW (pop A and flags), with --dri
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

For more details on these extensions and compatibility notes, see [EXTENSIONS.md](EXTENSIONS.md).
