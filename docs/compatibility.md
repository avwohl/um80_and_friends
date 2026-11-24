# Compatibility and Syntax Extensions

This document shows where um80 matches or differs from Microsoft MACRO-80
(M80). This document also summarizes the syntax extensions.
[EXTENSIONS.md](EXTENSIONS.md) has the full details.

## Compatibility Notes

These tools aim to be compatible with the original Microsoft tools. The tools run on
modern Unix and Linux systems:

- Source files use Unix line endings (LF). um80 also accepts CR/LF
- Symbol names are case-insensitive (um80 converts them to uppercase)
- Default origin is 0100h (standard CP/M load address)
- Output files are binary-compatible with the original CP/M tools

### 8080 is the default; Z80 mnemonics need `.Z80`

Like M80, um80 assembles 8080 mnemonics until a `.Z80` directive appears. To
set the mode from the command line without a change to the source, use
`um80 -e .z80 file.mac`.

Some Z80 instructions have the spelling of an 8080 mnemonic: `RET NZ`,
`RLC B` and `RRC C`. In 8080 mode, um80 rejects these instructions. um80 does
not ignore the operand:

```
$ um80 z80source.mac
Error at line 5: RET takes no operand, but was given 'NZ' RET NZ is Z80 syntax;
the 8080 spelling is RNZ. Add a .Z80 directive to assemble Z80 mnemonics.
```

Genuine M80 3.44 only flags these statements `Q` and writes the operand-less opcode.
As a result, `RET NZ` assembles as an unconditional `RET` (C9). M80 still
writes the REL file.

um80 makes these statements an error, because the code that M80 writes is
wrong and the assembly does not stop. The difference from M80 is deliberate.
CHANGELOG.md records the difference. um80 writes nothing, and the exit status
is 1, as for any other assembly error.

### A label needs a colon

As in M80:

- The first word of a statement is its operation, in column 1 or in any other column. `NOP` in
  column 1 is a NOP.
- A label is a name with a colon after it. The name in front of an `EQU`,
  `SET` or `MACRO` needs no colon.
- A statement whose first word is not an instruction, a directive or a macro is a
  list of values. M80 assembles the list as `DB`. After `FOO EQU 5`, `FOO` alone is
  05.
- `LAB DS 1` is an error in M80, and in um80.

MAC and RMAC read such a word as a label, in any column. `um80 --dri` reads
such a word as MAC and RMAC read it.

### A name may begin with a dot

As in M80, a name has letters, digits and the characters `$ . ? @ _`. A digit
does not start a name. A `.` may begin a name or be inside a name. These are
names: `.FOO`, `..BAR`, `.XC.0`, `.201B`, `.1H` and `X.1`. `.201B` is never a
number.

A name that begins with a dot works in every place where a name without the dot
works:

- a label (`.FOO:` and `.FOO::`)
- the name of an `EQU`, `SET`, `DEFL`, `ASET` or `MACRO`
- a `PUBLIC` or `EXTRN` name
- an operand or an operator operand

The `.` alone is a name too. The `.` alone is not the location counter. The
location counter is `$`. M80 has no `.AND.` operator. `.AND.` is an undefined
name.

These directives start with a dot:

- `.Z80`, `.8080`, `.PHASE`, `.DEPHASE` and `.RADIX`
- `.LIST`, `.XLIST`, `.PRINTX`, `.REQUEST` and `.COMMENT`
- the other directives that start with a `.`

Such a word is the directive when it is the first word of a statement and no
`:` immediately follows the word.

A `:` or `::` immediately after the word makes the word a label, in column 1
or in any other column. The mode, the listing and the phase do not change. `.Z80:` defines the
label `.Z80`, and um80 assembles a `NOP` after the label. Before issue #7,
um80 read `.Z80:` as the directive. um80 then ignored the rest of the line and
gave no error.

A word that starts with a dot and has no colon is an operation, as any other name is.
The rule applies when the word is not a directive and not a macro. The
statement is then a list of values. The statement is an error if the name has no definition. `.Z80 EQU 5` defines
a symbol `.Z80`, as in M80.

## Extended Symbol Names

The original Microsoft REL format limits symbol names to 8 characters.
LINK-80 (L80) 3.44 reads at most 7 characters of a name. um80 and ul80 extend
this limit. um80 and ul80 accept symbols of up to 255 characters. This
extension is essential for:

- Long descriptive symbol names in modern code
- Compatibility with source code written for other assemblers

To cut symbol names to 6 characters, as M80 does, use `-t` or `--truncate`.
Use `-t` when both of these conditions are true:

- You link the REL file with REL files that M80 assembled.
- A PUBLIC, EXTRN or `##` name is longer than 6 characters.

For example, M80 writes `FBUFP27` as `FBUFP2`. `X##` makes a name external by
its whole name, as `EXTRN` and `PUBLIC` do. `-t` cuts the name in the REL file
only.

If L80 must read the REL file, do one of these:

- Keep each name to 7 characters, or to 6 characters for an external used in a
  link-time expression.
- Use `-t`.

For technical details of the extended REL format, see
[EXTENSIONS.md](EXTENSIONS.md).

## DRI Extensions

um80 reads several syntax extensions of Digital Research (DRI). The source
code of CP/M and MP/M often has these extensions. The extensions are
compatible with the DRI assemblers ASM, MAC and RMAC.

### Multi-Statement Lines (`!` separator)

Write more than one instruction on a line, with `!` between the instructions:

```asm
        PUSH H! PUSH D! PUSH B      ; Save registers
        POP B! POP D! POP H         ; Restore registers
        MOV A,B! ORA A! RZ          ; Test and return if zero
```

### LOW and HIGH Operators

To extract the low byte or the high byte of a 16-bit value, use the syntax of
a function call:

```asm
        MVI L,LOW(BUFFER)           ; Load low byte of address
        MVI H,HIGH(BUFFER)          ; Load high byte of address
        MVI A,LOW(1234H)            ; A = 34H
        MVI B,HIGH(1234H)           ; B = 12H
```

um80 accepts both of these syntaxes:

- `LOW(expr)` and `HIGH(expr)`, with parentheses
- `LOW expr` and `HIGH expr`, with a space

The assemblers differ in the part of the expression that `LOW` and `HIGH`
take:

- M80 applies `LOW` and `HIGH` to the term after the operator. `HIGH(X)+1` is
  `HIGH(X)` plus 1. um80 without `--dri` does the same.
- MAC and RMAC apply `LOW` and `HIGH` to the whole expression that follows
  (`HIGH(X+1)`). `um80 --dri` does the same.
- `um80 --dri` also takes the operators `=`, `<`, `<=`, `>`, `>=` and `<>` of
  MAC.

The operand can be relocatable or external. For example, `LOW(BUFFER)` above
can have BUFFER in CSEG or DSEG. In that case, the byte depends on where
the linker puts the segment. um80 passes the expression to ul80 as REL extension link items.
M80 3.44 writes the same form for L80 3.44.

um80 also passes any relocatable or external value in a one-byte field to
ul80 as link items (`MVI A,BUFFER`, `DB LABEL`). In MP/M `.PRL` and `.SPR` output, a `HIGH`
byte is marked in the relocation bitmap, and a `LOW` byte is not. See
[EXTENSIONS.md](EXTENSIONS.md#link-time-expressions-rel-extension-link-items).

### Digit Separators in Numbers (`$`)

You can use the `$` character as a visual separator in a numeric literal. The
separator makes the literal easier to read:

```asm
        MVI A,1111$0000B            ; Binary with separator
        LXI H,1$0000H               ; Hex: 10000H
        MVI B,1$000D                ; Decimal: 1000
```

The parser ignores the `$` characters. The `$` characters do not affect the
numeric value.

### `$` Inside Names (`--dri`)

MAC and RMAC also ignore a `$` inside a name. `NMB$LST` and `NMBLST` are one
symbol. M80 keeps the `$`, so by default um80 keeps the `$` too.

`um80 --dri` reads names as MAC and RMAC read them. The sources of MP/M II need
`um80 --dri`. For example, `MPM.ASM` stores to `nmb$lst`, and `DATAPG.ASM`
defines the same name as `nmblst`.

`um80 --dri` also does these things:

- Reads a word with no colon as a label, as MAC does.
- Ignores a line number.
- Ignores a `*` comment line.
- Ignores the `$-MACRO` controls of MAC.

For the exact changes, see
[EXTENSIONS.md](EXTENSIONS.md#dri-sources---dri).

### Register Names as Values

In 8080 code, um80 gives each register name a number in any expression. um80
also reads a register operand as an expression. M80, MAC and RMAC do the same.
These are the numbers:

Register | Number
--- | ---
B | 0
C | 1
D | 2
E | 3
H | 4
L | 5
M | 6
A | 7
SP | 6
PSW | 6

Two examples: `DB B` is 00, and `X EQU D+1` is 3. If an EQU gives a register
name to a symbol, the symbol names that register:

```asm
UR      EQU     B                   ; 0: register B
MR      EQU     E                   ; 3: register E
RD      EQU     D                   ; 2: register D, or the pair DE
        MVI MR,0                    ; Same as MVI E,0
        MOV A,UR                    ; Same as MOV A,B
        DAD RD                      ; Same as DAD D
        PUSH RD                     ; Same as PUSH D
```

A register pair operand has the number of its first register:

- B pair: 0
- D pair: 2
- H pair: 4
- SP or PSW: 6

An odd number (`DAD E`) is an error, as in M80 and MAC.

An address is its offset in its segment, as in M80. For example, `DAD LAB`,
with `LAB` two bytes into the code, is `DAD D`. um80 gives a warning in this
case. See
[EXTENSIONS.md](EXTENSIONS.md#register-names-as-values-equ-of-a-register).

### PUSH A / POP A

MAC and RMAC read `PUSH A` and `POP A` as `PUSH PSW` and `POP PSW`. `um80 --dri`
does the same. M80 flags `PUSH A` and `POP A`. Without `--dri`, `PUSH A` and
`POP A` are errors in um80:

```asm
        PUSH A                      ; PUSH PSW (push A and flags), with --dri
        POP A                       ; POP PSW (pop A and flags), with --dri
```

### External Symbol Aliases (EQU external+offset)

You can define a symbol as an alias of an external symbol, with an optional
offset. You can then declare the alias PUBLIC:

```asm
; In library module - define entry points
        EXTRN   ADD10           ; External symbol from another module
        PUBLIC  ADD10_SKIP      ; Export the alias

; Define alias: ADD10_SKIP is ADD10+2 (skip first instruction)
ADD10_SKIP  EQU ADD10+2
```

An alias is useful for:

- Alternate entry points into routines, which skip the initialization code
- Symbolic offsets into data structures that other modules define
- Code from other assemblers that have this feature (like z88dk)

The linker resolves the alias at link time:

```asm
; In main module - use both symbols
        EXTRN   ADD10
        EXTRN   ADD10_SKIP

START:  CALL    ADD10           ; Call full routine
        CALL    ADD10_SKIP      ; Call at offset (skips first 2 bytes)
```

For more details of these extensions and compatibility notes, see
[EXTENSIONS.md](EXTENSIONS.md).
