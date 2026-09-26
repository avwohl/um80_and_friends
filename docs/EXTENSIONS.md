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

Use `-t` or `--truncate` to disable extended format and cut every name in the
.REL - PUBLIC, EXTRN, module name - to 6 characters, as MACRO-80 3.44 does:

```bash
um80 -t program.mac          # Names cut to 6 chars, as M80
um80 --truncate program.mac  # Same as above
um80 program.mac             # Default: allow long symbols
```

This is useful when:
- Linking with objects that the genuine M80 assembled: M80 writes the PUBLIC
  `FBUFP27` as `FBUFP2`, and a module that um80 assembled without `-t` asks
  for `FBUFP27`, which neither LINK-80 nor ul80 then finds
- Comparing behavior with original tools

For objects the original Microsoft L80 is to read, keep symbols to 7
characters (6 for an external used in a link-time expression), or use `-t`.
(Up to 0.3.49, `-t` cut names to 8 characters, which neither M80 nor L80
does: L80 refuses an 8-character name.)

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

This is commonly used in DRI source code to group related operations.
Without `--dri` a comment runs to the end of the line, so a `!` in it is
text. With `--dri` a `!` ends a comment too, as in MAC and RMAC, and the next
statement starts after it: `NOP ;save! INX H` is two statements (see
[DRI sources](#dri-sources---dri)).

**Implementation notes:**
- The `!` separator is recognized outside of string literals
- Each statement after the first is processed as if it had no label
- Works with all instructions and most directives. (MAC and RMAC flag `D`
  a line on which a `DB` or a `DW` has a `!` after it, and assemble what
  follows it wrong: `DB 1! DB 2` is 01 00 there, and 01 02 here.) An `EXITM` after a `!`
  ends the macro expansion or the repetition there, as one at the start of
  a line does (`NOP! EXITM! DB 5` assembles the `NOP` only). A `LOCAL` in a
  macro body is a statement wherever it is on the line, as in MAC and RMAC:
  `NOP! LOCAL QQ`, `LOCAL QQ! NOP` and `NOP! LOCAL QQ! NOP` (and with
  `--dri`, where a `!` ends a comment, `LOCAL QQ ;c! NOP` and `MM ;c! LOCAL
  QQ`) declare `QQ`. As in MAC and RMAC it declares its names for what
  follows it, the statements after it on the line and the lines after it: a
  statement before it on the line reads the name as it was. With `QQ EQU 7`
  outside the macro, `MVI A,QQ! LOCAL QQ! LXI H,QQ` is 3E 07 and the local
  `QQ`'s address; `LXI H,QQ! LOCAL QQ` with no `QQ` outside is an undefined
  symbol (MAC: U), and `QQ: NOP! LOCAL QQ` defines the `QQ` outside, so a
  second expansion defines it twice (MAC: P). With `--dri` a `LOCAL` that
  MAC and RMAC leave out after a macro call (see *What follows a macro call
  on its line*) declares nothing, as in MAC: in `NN! LOCAL QQ`, with `NN` a
  macro of no parameters, the `!` is text of the call, and um80 warns that
  the `LOCAL` is left out. M80 reads `LOCAL QQ! NOP` as `LOCAL QQ` and
  nothing more, and flags `NOP! LOCAL QQ`, where `QQ` is not local.
- A macro-invocation line is **not** split on `!`. There, `!` retains its M80
  meaning of quoting the next character in the argument list (e.g.
  `head FOO,!!CF` passes the name `!CF`, and `!,` passes a literal comma), so
  the separator never interferes with macro arguments. Without `--dri` it
  quotes a `;` too, as in M80: `MM A!;B` passes `A;B`, and `MM A!"B;C` `A"B`.
  With `--dri` a `!` after the arguments is read as MAC reads it: see *What
  follows a macro call on its line* under [DRI sources](#dri-sources---dri).

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

What follows the operand differs between the two assemblers: M80 applies
`HIGH` to the term after it, so `HIGH(BUF)+1` is `HIGH(BUF)` plus 1, and MAC
and RMAC to all that follows, `HIGH(BUF+1)`. um80 reads it as M80 does, and
as MAC does with `--dri` ([DRI sources](#dri-sources---dri)).

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

### DRI sources (`--dri`)

`um80 --dri` reads a source the way DRI's MAC and RMAC read it where they
differ from MACRO-80, in the ways listed here. It changes these things:

**A `$` inside a name is ignored.** DRI's manuals: "All characters are
significant in an identifier, except for the embedded dollar sign ($) which
can be used to improve readability of the name." `NMB$LST`, `NMBLST` and
`N$M$B$LST` are one symbol, and so are `AB$` and `AB`. This holds wherever a
name is read - labels, `EQU`/`SET` names, operands, macro names and their
parameters, `IF` operands - and for `PUBLIC` and `EXTRN` names: `PUBLIC
A$BC` writes `ABC`, as RMAC does. Kept as they are:

- a `$` that starts a word: `$` alone is the location counter (`JMP $+3`),
  and a name may start with `$`;
- everything inside a quoted string (`DB 'Hello$'`, `NAME('M$OD')`) and after
  a `;`;
- the arguments of a macro call and the list of an `IRP` or `IRPC`, which MAC
  and RMAC read as text, not as names. `PRINT HELLO$` passes `HELLO$`, so a
  body of `DB '&MSG'` keeps its BDOS terminator, and `IRPC C,12$3` iterates
  four times. Where an argument becomes a name in the body it loses the `$`
  there: `MM NMB$LST`, with a body of `LDA P`, loads `NMBLST`. The macro's
  name, a label, and the parameter of an `IRP` or `IRPC` are names and lose
  theirs. A `%` argument's expression is read as names: `GEN %N$C` passes
  the value of `NC`.

um80 drops each such `$` from a statement as it reads it, so the listing shows
the statement without them. A `$` in a number (`0001$1111B`) is ignored with
or without `--dri`.

Without `--dri`, a `$` is part of the name, as in MACRO-80 3.44: there
`NMBLST EQU 5` then `LDA NMB$LST` is an undefined symbol, and `AB EQU 1` with
`A$B EQU 2` defines two symbols, where MAC reports `AB` defined twice.

**A macro body is read as MAC reads it.** A line of a `MACRO`, `REPT`, `IRP`
or `IRPC` body is kept as written, and read when it is expanded, because MAC
finds a formal parameter in the body as written, and a `$` ends the name it
looks for. With the formal `A`, `DB A$B` is `DB X$B` after `MM X`; `DB P$1` is
not the formal `P$1` (MAC reports it undefined), and `LOCAL L$1` declares
`L1`. So do a `_` and a `.`: in MAC a name is letters, digits, `?` and `@`,
where in M80 it is also `$`, `.` and `_`, so with the formal `X` MAC reads
`'&X_'` as the argument and `_`, and M80 as the text `&X_`. In a quoted
string MAC and RMAC drop every `&` next to a parameter, and a name before an
`&` is one too (`'X&B'` is the argument and `B`); M80 reads only `&X`,
drops its `&`, and reads the rest of the line as if outside a string, until
a quote starts another (`'&X &X'` is `K &K` there, `K K` in RMAC; `'&X''&Y'`
is `K'L` in both). RMAC folds case in a string, as um80 does; MAC 2.0 does
not. An empty argument in a string is nothing in MAC (`'Z&P'` is `Z`), where
M80 passes it as a 00 byte (5A 00). A `>` with no `<` before it in a macro
call's arguments is text, as in MAC, and a later comma still ends the
argument: `MM 1>2,3` passes `1>2` and 3. M80 ends the argument at such a `>`,
as at a comma, and flags it `Q` (there `MM 1>2,3` passes 1, 2 and 3); without
`--dri` um80 does the same, and warns. A blank or a tab ends a macro
argument outside a quoted string and a `<...>` group, in MAC, RMAC and M80,
and MAC and RMAC end the arguments there: a comma after the blanks starts the
next argument (`MM A ,B` passes A and B), a `;` or a `!` ends the call's
statement (see *What follows a macro call on its line* below), and anything
else is an error, as MAC and RMAC flag it `S` and leave it out (`MM A B`
passes A there). M80
reads the blanks after an argument as a separator, as a comma, so without
`--dri` `MM A B` passes A and B, `MM 5 GT 2,4` 5, GT, 2 and 4, and `MM A ,B`
A, an empty argument and B. A `"` in a macro call's arguments or an `IRP`
list is text, as MAC and RMAC quote a string with `'` only: `MM "A,B",C`
passes `"A`, `B"` and C, and `MM "A;B",C` `"A`, the rest a comment (M80
reads `"A,B"` and `"A;B"` as strings). In an `IRPC` string a `"` is text in
M80 as well.
Only an argument that starts with `%` is a value, as in MAC; M80 also reads
`A%E` as `A` and E's value, and `<A>%E` as `A` and the value, and evaluates a
`%` in an `IRP` list, which MAC reads as text. A `%` expression runs to its
comma, blanks and all, in all three (`MM %1 + 1,5` passes 2 and 5), and a `<`
or a `>` in it is MAC's relational operator, not a bracket (`MM %1<2,3`
passes 65535 and 3; M80 flags the `<`), and `<>` is RMAC's `NE`: `MM %1<>2`
passes 65535, as RMAC does, where MAC 2.0 flags `<>` `E`, as it does
everywhere (and passes 0). A `%` with no expression after it
is 0 in M80 (`MM %` passes 0), and MAC and RMAC flag it `E`: with `--dri` it
is an error. An item of
an `IRP` list ends at a comma, as in MAC, and a `;` in the list, outside a
nested `<...>`, is an error, as MAC and RMAC flag it `B`. MAC and RMAC skip a
blank or a tab at the start of an item, before its first character (`<A, B>`
is A and B), and read any other blank outside a nested `<...>` otherwise,
and not in a way um80 follows: `<A ,B ,C>` is A, B and an empty item in MAC,
`<A ,B,C>` A and C, `<A, ,B>` A and `,`, and `< ,A>` the one item `,` in MAC
and RMAC; RMAC stops at `<A ,B>` and writes nothing, without a word; MAC
flags `<A B>` and `<A >` (RMAC stops), and both flag `<%1 + 1,5>`. So with
`--dri` such a blank is an error. M80 ends an item at a `,`, a `;`, a blank or a tab, so there `<A;B>`
and `<A B>` are A and B, and `<A ,B>` is A, an empty item and B. MAC and
RMAC read the list of an `IRP`, and the string of an `IRPC`, as a macro
call's argument: the `<` that opens a group and the `>` that closes it go,
wherever they are, what is outside them is text of the list too, to a blank,
a tab, a comma or a `!` outside any group, and a comma inside the outer
group separates items. So `IRP X,<1,2>3<4,5>` goes round 1, 234 and 5, `IRP
X,A<1,2>` A1 and 2, `IRP X,<1>>2` `1>2`, `IRP X,<"A>B">` the one item
`"AB">`, and `IRPC X,A<B>C` A, B and C. M80 ends the list at the `>` that
matches its `<` and ignores the rest of the line (1 and 2; A; 1; `"A>B"`, a
string there; and A, `<`, B, `>`, C), and so does um80 without `--dri`, with
a warning. Text after the blank or the comma that ends the list, but for a
`!` statement, is an error with `--dri`, as MAC and RMAC flag it `S` (`IRP
X,<1,2>,3`, `IRP X,1,2`, `IRPC X,AB CD`); M80 ignores it, and um80 warns. A
`!` inside the list is M80's quote here, with `--dri` too (`IRP X,<1!,2,3>`
goes round `1,2` and 3), where MAC and RMAC end the statement at it and flag
it `V` and `S`. MAC and RMAC honour a `LOCAL` in a `REPT`, `IRP` or `IRPC`
body; um80 reads one in a `MACRO` only, as M80 does, and a label it names
is defined again each time round. An `IRPC` with an
empty string goes round once, with its parameter empty, as in MAC; M80 does so
only where a macro's empty argument made the string empty. A label on the
`ENDM` that ends a body is defined where the body ends, each time, as in MAC
(DRI's `STACK.LIB` ends `SIZ` with `STACK: ENDM`); M80 ignores it.

**An `IF` a macro body leaves open ends with it.** MAC and RMAC end the `IF`s
that a macro expansion, or one repetition of a `REPT`, `IRP` or `IRPC`, opened
and did not end, true or false, when it ends. DRI's own libraries rely on it:
`CONTROL/COMPARE.LIB`'s `TEST?` ends inside an `ELSE`, and `SEQIO.LIB`'s
`FILLFCB` opens an `IF` in each repetition of an `IRPC`. M80 carries them on
past the `ENDM` - a false one skips the rest of the file - and reports
"Unterminated Conditional", and so does um80 without `--dri`. (An `EXITM`
ends the `IF`s it is in with or without `--dri`, as all three do.)

**A word with no colon may be a label.** The first word of a statement that
is not an instruction, a directive or a macro is a label, in any column, as
in MAC and RMAC ("the ':' following the identifier in a label is optional"):
`OBP DS 1` (`UTIL3/GENHEX.ASM`), `<TAB>LAB<TAB>NOP`, and `HALT LXI H,1` in
8080 code, where `HALT` is no instruction. Without `--dri` it is not, as in
M80 (see [The first word of a statement](#the-first-word-of-a-statement)).
um80's own directives stay directives: MAC would take `ENTRY JMP START` for a
label `ENTRY`, which is no MAC directive; um80 reads the `ENTRY` directive.

**A line number, a `*` comment line and a MAC control are ignored.** A word
that starts with a digit in front of a statement is a line number (`00010
LAB: NOP`); a line whose first character, after any blanks, is `*` is a
comment (a `!` in it still ends the comment, as in MAC, whatever is before
it: `* TEXT ! NOP` and `* it's! NOP` are a NOP); and MAC's assembly controls
(`$-MACRO`, `$+PRINT`, `$*MACRO`) are left out. M80 flags each (`O` or `U`),
and so does um80 without `--dri`.

**A `!` ends a comment.** MAC and RMAC read a `;` comment to the end of the
line or to a `!`, and the `!` then starts the next statement, as it does
outside a comment: `NOP ;c! DB 1` is 00 01, and `; text! DB 1` is 01. DRI's
own sources rely on it - CP/M 2.0's CCP has `nosub: ;no submit file! call
del$sub`, and MP/M II's `disk2_files/ldrbios.asm` `;<TAB>in 0f5h ! ani 2 !
rz` - and both assemble to MAC's bytes with `--dri --aseg`. A quote in a
comment starts no string (`NOP ;it's! DB 1` is 00 01). A `;;` comment in a
macro body is left out of the body only up to its `!` (`NOP ;;c! DB 7` is
stored as `NOP! DB 7`). What follows the `!` is a statement like any other:
an `IF` or an `ENDIF`, a statement of the body of the `REPT`, `IRP` or `IRPC`
on that line (`IRPC X,AB ;c! DB '&X'` puts `DB '&X'` in the body), or an
`ENDM`. In a line of a body being defined, each statement is read for the
`MACRO`, `REPT`, `IRP`, `IRPC` and `ENDM` that nest in the body, with a `!` in
a comment or not: `NOP! ENDM` ends the body after the `NOP`, and what follows
the `ENDM` is assembled where the body ends (`NOP! ENDM! DB 5` is 05 there).
M80 has no `!` separator, and without `--dri` a comment runs to the end of
the line (`NOP ;c! DB 1` is 00). So a line of `!` statements commented out
with one `;` in front (`;<TAB>pop h! lxi h,7! jmp err`) is assembled from its
first `!` on with `--dri`, as in MAC and RMAC: put a `;` in front of each
statement.

**What follows a macro call on its line.** MAC and RMAC read what follows a
macro call's arguments as text, to the first `!` there that follows a
character other than a blank or a tab, and go on with the statement after
that `!`. Up to it a `;` starts a comment that ends at its `!`, which counts
as such a character, and a `!` after a blank is text; when the call has no
arguments, the first character after the macro's name is text whatever it
is. With `--dri` um80 does the same, and warns where it leaves out a
statement:

```asm
        MM      ;c! DB 1            ; MM, then DB 1: the comment ends at its !
        NOP! MM ;c! DB 1            ; 00, MM, DB 1
        MM      A;c! DB 1           ; MM A: DB 1 is left out
        MM      A ! DB 1            ; MM A: DB 1 is left out
        MM      A;c!! DB 1          ; MM A, DB 1: the statement left out is empty
        MM      A ;c! DB 1! DB 2    ; MM A, DB 2
        MM      ;c ! DB 1           ; MM: a ! after a blank is text
        MM      ;;c! DB 1           ; MM: the second ; starts a comment
        MM      ! DB 1              ; MM: the first character is text
```

A call reads as many arguments as the macro has parameters, and the rest as
text: `MM A! DB 1` and `NOP! MM A! DB 1` assemble DB 1 where MM has no
parameter, and `NOP! MM A! DB 1` leaves it out where MM has one. A `!` right
after an argument of a line's first statement is still M80's quote where the
macro has parameters (see
[Multi-Statement Lines](#multi-statement-lines--separator)): MAC ends the
arguments there, so `MM A!B` passes A in MAC and AB in um80, and `MM A! DB 1`
is an error in um80. Where MAC defines a body, it reads a line that starts
with a macro call for its statements as any other (`MM ;c! ENDM` ends the
body), and in a false `IF` too (`MM ;c ! ENDIF` ends the `IF`), and so does
um80.

**`MOV M,M` is 76H,** HLT's opcode, as MAC and RMAC assemble it without a
flag; M80 flags it `A` (and assembles 76H), and without `--dri` it is an
error.

**`PUSH A` is `PUSH PSW`, and an expression may have two register names in
it,** as in MAC and RMAC (M80 flags both); see
[PUSH A / POP A](#push-a--pop-a) and
[Register Names as Values](#register-names-as-values-equ-of-a-register).

**MAC's relational operators, and its precedence for `HIGH` and `LOW`.** `=`,
`<`, `<=`, `>`, `>=` and `<>` are `EQ`, `LT`, `LE`, `GT`, `GE` and `NE`, at
their level, unsigned, true 0FFFFH, as in MAC's manual and in RMAC 1.1 (MAC
2.0 itself flags `<>`): `IF @Y = 1` (`CONTROL/DEBLOCK.ASM`), `DW 1<2,3` (a `<`
or `>` in a list of values is an operator, not a bracket). M80 has none of
them (`O`), and without `--dri` they are an error. MAC's manual puts `HIGH`
and `LOW` below every other operator, and MAC and RMAC apply them to all that
follows: `HIGH 1234H OR 0F00H` is `HIGH(1F34H)`, 1FH; `HIGH(100H)+1` is
`HIGH(101H)`, 1; `LOW 1234H SHR 4` is 23H. M80 applies them to the term after
them (12H OR 0F00H, 2, 03H), and so does um80 without `--dri`. MAC's order,
highest first: `* / MOD SHL SHR`, `+ -`, `EQ LT LE GT GE NE` (and `= < <= >
>= <>`), `NOT`, `AND`, `OR XOR`, `HIGH LOW`.

**An `IF` is true when bit 0 of its value is set,** as in MAC and RMAC:
`IF 2`, `IF 100H`, `IF 0FFFEH` and `IF NOT 1` are false, and `IF 1`, `IF 3`
and `IF -1` true. (An `IF` with no operand is false in all three; MAC and
RMAC flag it `E`, and um80 takes it without a word.) M80 takes any value but 0 as true, and so does um80
without `--dri`. A relation is 0 or 0FFFFH in all three, so `IF X EQ 2` means
the same everywhere; `IF X AND 2` does not. MAC has no `IFT`, `IFE`, `IFF`,
`COND`, `IF1`, `IF2`, `IFDEF`, `IFNDEF`, `IFB`, `IFNB`, `IFIDN` or `IFDIF` (it
reads `IFT 2` as a label, and flags the `ELSE` and `ENDIF` after it `B`); um80
keeps them with `--dri`, with M80's meaning (`IFT 2` is true).

**A unary sign applies to all that `*`, `/`, `MOD`, `SHL` and `SHR` make of
it, and division is unsigned,** as in MAC and RMAC: `-1 SHR 8` is -(1 SHR 8),
0, `-2 SHR 1` 0FFFFH, 8000H/2 4000H and 0FFFEH/2 7FFFH, and `x/0` is 0FFFFH,
which MAC flags nothing for (um80 warns). M80 applies a sign to the term
after it (00FFH, 7FFFH), divides signed, rounding toward 0 (0C000H, 0FFFFH),
gives the remainder of `MOD` the sign of the quotient (4 MOD -3 and -4 MOD 3
are 0FFFFH), and flags `x/0` `O`; so does um80 without `--dri` (`x/0` is an
error there). `x MOD 0` is `x` in all three. MAC also flags a sign after
another operator (`2+-1`, `7/-2`: `E`), which um80 takes.

**A string is quoted with `'` only,** as in MAC and RMAC: `DB "A"`, `DW "A"`
and `MVI A,"A"` are an error, as MAC and RMAC flag them `E` (and assemble
00). M80 reads `"A"` as a string, and so does um80 without `--dri`. A `"`
in a macro call's arguments or an `IRP` list is text (see *A macro body is
read as MAC reads it*), and `DB '"'` is 22 in all three.

**An empty operand in a `DB` or a `DW` is an error,** as MAC and RMAC flag
it `E`: `DB` or `DW` with none, `DB 1,` and `DB 1,,2` (they assemble 00 for
each, and `DB 1,,2` is 01 00 00 there). M80 assembles 0 for each - `DB` is
00, `DB 1,` 01 00, `DW` 00 00 - and flags the `DB`s `Q`, and so does um80
without `--dri`, with a warning. An empty string (`DB ''`) is nothing in all
three. M80's `DEFB` and `DEFW`, which um80 reads with `--dri` too, are not
MAC's: MAC and RMAC take the word for a label and assemble nothing on the
line, flagging nothing (`DEFB`, `DEFW`, and `DEFB 1` too); an empty operand
in one is an error with `--dri`, which says so.

**A two-character string used as a value has its first character in the
low byte,** as in MAC and RMAC: `'AB'` is 4241H, so `DW 'AB'` is 41 42, `LXI
H,'AB'` 21 41 42, `X EQU 'AB'` then `DW X` 41 42, `DB ('AB') SHR 8` 42, and
`IF 'AB' EQ 4241H` is true. M80 makes the first character the high byte,
`'AB'` = 4142H (42 41, 21 42 41, 41), and so does um80 without `--dri`. A
string in a `DB` is its characters, in order, in all three (`DB 'AB'` is 41
42). An expression in a `DB` that starts with a two-character string is
not read as MAC reads it: MAC and RMAC flag it `D` and assemble the string
(`DB 'AB'+0`, `DB 'AB' SHR 8`: 41 42), where um80 assembles the one byte of
its value (41, 42), without a word.

**An 8AH or an 8DH inside a line is read as MAC reads it.** MAC and RMAC clear
a byte's bit 7 and then read it, so an 8AH is a line feed and an 8DH a
carriage return, where M80 leaves out an 8AH that does not follow a CR and
reads an 8DH as the end of the line. An 8AH that does not follow a CR is a
character of the line: in a string it is the byte 0AH (`DB 'A<8AH>B'` is 41
0A 42; M80 41 42), in a comment nothing, in the arguments of a macro call
and the list of an `IRP` or `IRPC` text, which MAC passes on (`MM A<8AH>B`
with a body of `DB '&P'` is 41 0A 42), and anywhere else an error (MAC:
`E`). An 8DH ends the statement, in a comment too, and MAC then takes the next
item, after any blanks - a word or a number, a string, one other character,
or a comment to the next CR - for the line feed that should follow a CR; the
rest of the line is the next statement. `DB 1 ;X<8DH><TAB>DB 2` is 01 (`DB`
goes, and `2` is a line number), and with `X<TAB>DB 2` after the 8DH, 01 02;
M80 gives 01 02 for both. An 8DH 8AH or CR 8AH is a line end in all three. A
line whose CR MAC takes for that line feed makes the next line start with a
line feed, which MAC flags (`S`), and so does um80.

**`MACLIB NAME` reads `NAME.LIB`,** as in MAC and RMAC, and then
`NAME.MAC`, where um80 --dri looked before: DRI's `maclib diskdef`
(`CONTROL/RESXIOS.ASM` in MP/M II, `os4bios.asm` in CP/M 2.0) reads
`DISKDEF.LIB`. MAC reads `NAME.LIB` whatever extension follows the name, and
flags `MACLIB NAME.MAC` `S`; um80 reads the file named. M80 reads a `MACLIB`
file as an `INCLUDE` file, `NAME.MAC`, and so does um80 without `--dri`. In
either mode a file is looked for by its name as written, and then in upper
and in lower case, as a CP/M file name has no case: `maclib diskdef` finds
`DISKDEF.LIB`, and `include inc` finds `INC.MAC`, on a file system where
case matters. With `--dri -t`, MP/M II's `CONTROL/RESXIOS.ASM` assembles to
RMAC 1.1's object, and with `--dri --aseg` CP/M 2.0's `os4bios.asm`, with
MP/M II's `DISKDEF.LIB`, to MAC 2.0's bytes.

**A `MACLIB` library is read in pass 1 only,** as in MAC and RMAC, for its
macros and the symbols it defines: none of its code or data is assembled,
an `ORG` or a macro call in it assembles nothing, and a symbol it defines
keeps the value pass 1 gave it. With a library of `DB 1`, `DB 2` after the
`MACLIB` is 02 at the location the `MACLIB` left; with `LL: DB 1`, `DW LL` is
the address pass 1 gave `LL`, the `DW`'s own; a `SET` in a library gives the
symbol the value it has at the end of pass 1 (`X SET 1` there, then `DB X / X
SET 2 / DB X` in the source, is 02 02). The size of the program, and of the
data and each `COMMON` block, is the most pass 1 reached in it, which counts
the library's code and data wherever the library leaves the location
counter: with a library of `DB 1`, a `DB 2` after the `MACLIB` makes the
program 2 bytes long, one of them loaded, as in RMAC, and with `DSEG / BUF:
DS 10 / CSEG` the data is 10 bytes long, as in RMAC, so that another
module's data is linked after `BUF`. (RMAC writes a segment's location
counter at the end of pass 1, at the first `END` it reads, a library's too,
where um80 writes the most reached, as M80 does: after an `ORG` back RMAC's
size is less - `ORG 180H / DB 9 / ORG 100H / DB 2` is 101H long in RMAC
and 181H here - and with a library that ends in `END` RMAC leaves the
program after the `MACLIB` out of it.) A label or an `EQU $` after a `MACLIB`
whose code moved it is where pass 1 put it in MAC and RMAC, which flag it
`P`; um80 reports a phase error. DRI's libraries hold macros and `EQU`s
only, which are read alike in all three. M80 reads a `MACLIB` file as an
`INCLUDE` file, in both passes, and so does um80 without `--dri`. Two things
um80 reads otherwise: an `EQU` in a library of a symbol the source defines
further down is its value here, and 0 in MAC, which reads the library once;
and um80 reads a `MACLIB` inside a library, which MAC and RMAC do not (a
symbol it defines is `U`; M80 flags the `MACLIB` `O`).

**A label on an `ORG` is the location the `ORG` sets,** as in MAC and RMAC:
`DB 1 / LAB ORG 300H / DW LAB` puts 0300H at 0300H, and `LAB ORG $+4` is the
location after the gap. M80 gives such a label the location before the
`ORG` (0101H), and so does um80 without `--dri`. A label on a `DS` is where
the `DS` starts in all three. A label on an `ORG` whose operand reads a
symbol defined further down is an error: MAC and RMAC give it the location
before the `ORG`, which their pass 1 gave it, and flag it `P` (`DB 1 / LAB
ORG X / DW LAB / X EQU 200H` is 01 01 01). um80 reads pass 1 again until
such a read has the symbol's final value, and would give it 0200H. An `ORG`
of such a symbol with no label is no error in MAC, nor here. Other forward
reads MAC and RMAC flag `P`, and um80 resolves without a word, are under
Known issues in the CHANGELOG: `X EQU Y` with `Y` further down (MAC: X is
0), and a label after a `DS` of a symbol further down (M80 flags it `P`
too).

**`END` of a symbol that is not defined takes no start address.** MAC and
RMAC read nothing after an `END`, so in `END START` with `START` below it
the symbol is not defined, and they take no start address and flag nothing,
as for any operand that reads a symbol not defined (`END FOO`, `END
START+1`): RMAC's REL has no start address. M80 flags it `U`, and so does
um80 without `--dri` (an error).

**An `END` in a `MACLIB` library ends the library.** MAC and RMAC stop
reading a library at its `END` and go on with the source after the `MACLIB`,
and the address on that `END` is not the start address. M80 reads a `MACLIB`
file as an `INCLUDE` file, so its `END` ends the source, and so does um80
without `--dri`, with a warning.

Where MAC, RMAC and M80 agree, um80 behaves that way with or without `--dri`:
a source byte's bit 7 is cleared (a line ending CR 8AH is a line end), the name
of an `EQU`, `SET` or `MACRO` may be indented, in 8080 code a register name
is a number in any expression (`RD EQU D` then `DAD RD` is `DAD D`, `DB B` is
00), a `<...>` group inside a macro argument or an `IRP` item loses its
brackets wherever it is (`MM 1<2>3` passes `123`, not `1<2>3`, which MAC's
relational operators would read), and a parenthesis in a macro call's
arguments is text, so a comma inside one ends the argument (`MM (A,B),C`
passes `(A`, `B)` and C, and `MM A),B,C` `A)`, B and C).

MP/M II's sources need `--dri`: `NUCLEUS/MPM.ASM` stores to `nmb$lst`, which
`DATAPG.ASM` defines as `nmblst`; `RESBDOS1.ASM` calls both `SET$DMABUFA` and
`SET$DMA$BUFA`; `CLI.ASM` defines `cli$slct$user` and uses `cli$slctuser`;
`BNKBDOS.ASM` defines `getmemseg` and calls `GET$MEM$SEG`. With `um80 --dri -t`
the unmodified `MPM.ASM`, `CLI.ASM`, `MEMMGR.ASM`, `RESBDOS1.ASM` (with
`CONBDOS.ASM`) and `BNKBDOS/BNKBDOS.ASM` assemble to the objects that copies
with the names spelled one way give. Built with `--dri -t` from DRI's
`NUCLEUS` sources, changed only where `VER.ASM` and `RESBDOS1.ASM` carry the
serial number placeholder `'654321'`, the V2.0 XDOS.SPR, BNKXDOS.SPR,
RESBDOS.SPR and TMP.SPR are DRI's byte for byte, and BNKBDOS.SPR from the
unmodified `BNKBDOS.ASM` is DRI's V2.1 file. `um80 --dri --aseg` assembles
`MPMLDR/LDRBDOS.ASM` to exactly the bytes at 0D00H-164CH of MPMLDR.COM (V2.0
and V2.1) that it loads. Every other assembler source in DRI's MP/M II release
that um80 assembles without `--dri` assembles to the same object with it -
but for `UTIL1/DDT2MON.ASM` assembled relocatable, whose `LOW(DEMON)-1` is
`LOW(DEMON-1)` for the linker with `--dri`, as MAC reads it (the same byte);
with `--aseg`, as a MAC source, its object is the same too. Since `PUSH A`,
a label with no colon and a `*` comment line need `--dri`, `BNKBDOS.ASM`,
`BDOS30.ASM`, `RESBDOS1.ASM` and `UTIL3/GENHEX.ASM` assemble only with it.

`--dri` does not imply the other options a DRI source may need:

- `--aseg`, for MAC's sources: MAC has no relocatable segments, so its `ORG`
  is an absolute address. RMAC's sources are relocatable, like M80's.
- `-t`, for RMAC's objects: RMAC, like M80, writes the first six characters of
  a `PUBLIC` or `EXTRN` name. MP/M II's nucleus depends on it (`DSPTCH.ASM`'s
  `extrn userprocess` is `MEMMGR.ASM`'s `userpr`).

Another difference between MAC/RMAC and M80 that `--dri` does not cover (none
of MP/M II's sources needs it): MAC stops reading at a 9AH byte (1AH with bit
7), where M80 reads on.

### Register Names as Values (EQU of a register)

In 8080 code, MACRO-80 and DRI's MAC and RMAC give each register name a
number, in any expression, and read a register operand as an expression, and
so does um80:

| Name | B | C | D | E | H | L | M | A | SP | PSW |
|------|---|---|---|---|---|---|---|---|----|-----|
| Value | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 6 | 6 |

A symbol equated to a register name then names that register:

```asm
UR      EQU     B                   ; 0
MR      EQU     E                   ; 3
RD      EQU     D                   ; 2
        MVI MR,0                    ; MVI E,0
        MOV A,UR                    ; MOV A,B
        DAD RD                      ; DAD D   (19H)
        PUSH RD                     ; PUSH D  (D5H)
```

A register pair operand is the number of the pair's first register: 0 is B
(BC), 2 D (DE), 4 H (HL), and 6 SP or PSW, whichever the instruction takes.
So `DAD 2` is `DAD D`, `PUSH 6` is `PUSH PSW`, `LXI SP-2,0` is `LXI H,0`,
and `MOV A,2` is `MOV A,D` - any expression with an absolute value will do,
including a name defined further down, one named like an instruction too:
`DAD RP` with `RP EQU H` below it is `DAD H` (29H), as in M80 (MAC and RMAC
take no instruction's name for a symbol: they flag `RP EQU H` `S`, and read
`RP` in `DAD RP` as its opcode, `V`; with `--dri` it is an error). An odd
number for a pair (`DAD E`,
`DAD 1`), `LDAX`/`STAX` of anything but B or D, and a number above 7 for a
register are errors, as in M80 (`A`) and MAC (`R` or `V`). um80 also takes
`BC`, `DE` and `HL` for B, D and H.

An address is a number too, as M80 reads it: a label's offset in its segment,
or an external's constant (`Y+2` is 2). With `LAB` two bytes into the code,
`DAD LAB` is `DAD D`, and with `Y` EXTRN, `MOV A,Y` is `MOV A,B`. M80 flags
nothing; RMAC flags `V`, and um80 warns. (In MAC, which has no relocatable
values, a label is its address, so `DAD LAB` is an error only when that is
not a register's number.) Anything else computed from an address -
`HIGH LAB`, `LAB-Y` - is an error in um80, as it was in 0.3.50.

Up to 0.3.50 um80 took a value for a pair's own encoding (0 BC, 1 DE, 2 HL,
3 SP), so `RD EQU D` then `DAD RD` was `DAD H`, and an odd value was quietly
taken for the pair of the register below it.

The number is the name's value in any expression, not only in a register
operand: `X EQU D+1` is 3 (`MOV A,X` is 7BH), `DB B` is 00, `MVI A,B` is 3E
00, `JMP B` is C3 00 00, `OUT A` is D3 07 and `IF B EQ 0` is true, in M80 and
MAC alike. Up to 0.3.50 um80 stopped at each with "Register 'B' used as
value". M80 also reads `BC`, `DE` and `HL` as 0, 2 and 4 (MAC: undefined),
and so does um80. Where they differ:

- M80 flags an expression with two register names in it (`A*256+B`, `C-B`,
  `A EQ B`) `O`, though it computes it; MAC does not. um80 reports it without
  `--dri`, and takes it with. Through symbols (`X EQU A`, `Y EQU B`, `X-Y`)
  neither flags anything.
- A program may define a symbol named like a register (MAC flags it `S`).
  M80 then reads the name as that symbol everywhere, in a register operand
  too, and so does um80: after `C EQU 2`, `MOV A,C` is `MOV A,D` and `DB C`
  is 02; after `A: NOP`, `DW A` is the label.
- M80 gives its internal numbers to the Z80 names in 8080 code (`IX` 44H,
  `IY` 64H, `AF` 6, `I` 8, `R` 9) and to the conditions (`Z` 1, `PE` 5); MAC
  reports them undefined, and so does um80.
- In Z80 code (`.Z80`) M80 gives every register name the value 0 in an
  expression (`X EQU B` then `LD A,X` is `LD A,0`); um80 reports it. A
  symbol of the name is the symbol there too (after `C: NOP`, `JP C` jumps to
  it); but a register operand is still the register (`B EQU 9` then `LD A,B`
  is `LD A,B`, where M80 loads 9).

### PUSH A / POP A

DRI's MAC and RMAC take `PUSH A` and `POP A` - `PUSH 7`, any register pair
operand whose value is A's 7 - for `PUSH PSW` and `POP PSW`, and so does
`um80 --dri`:

```asm
        PUSH A                      ; Same as PUSH PSW, with --dri
        POP A                       ; Same as POP PSW, with --dri
```

MP/M II's `BNKBDOS.ASM`, `RESBDOS1.ASM` and `BDOS30.ASM` use them. M80 flags them `A` (and
pushes PSW), and without `--dri` they are an error in um80, as they are in
M80. Up to 0.3.50 um80 took `PUSH A` for `PUSH PSW` without `--dri` and
rejected `PUSH 7`. The other odd numbers (`PUSH 1`, `DAD 7`, `DAD A`) are
errors in all three.

### The first word of a statement

A label is a name with a colon after it (`::` also makes it `PUBLIC`), in any
column. The first word of a statement is otherwise its operation, in column 1
or not, as in MACRO-80 3.44 - but for the name of an `EQU`, `SET`, `DEFL`,
`ASET` or `MACRO` in front of its directive (`NOP EQU 5` defines `NOP`, as in
M80):

```asm
IF DEBUG                            ; IF, in column 1
        CALL TRACE
ENDIF
NOP                                 ; 00
DB      7                           ; 07
END
```

Up to 0.3.50 um80 took any word in column 1 for a label, so `NOP`, `RET`,
`END` or `DB 7` there assembled nothing, without a word, and an `ENDM` or a
`LOCAL` in column 1 was never seen.

M80 reads a line of a `MACRO`, `IRP` or `IRPC` body it defines for the
`ENDM` that ends it, the `MACRO`, `REPT`, `IRP` and `IRPC` that nest in it,
and its `LOCAL` names, after a word that is no instruction or directive too
(a label with no colon, in any column, a macro's name, a word made with
`&`), and so does um80: `LAB ENDM`, `<TAB>LAB<TAB>ENDM` and `L&P ENDM` end the
body, and the word is not defined; `LAB REPT 2` opens a block the next `ENDM`
ends (and is an error where the body is expanded, as M80 flags it `U`); `LAB
LOCAL QQ` declares `QQ`. After an instruction or a directive the word is its
operand (`NOP ENDM` ends nothing), and a third word is not read (`LAB FOO
ENDM`). M80 reads a `REPT` body for its first word only: `LAB ENDM` does not
end one. With `--dri` a word made with `&` is a label as any other, as in MAC
and RMAC, which define it where the body ends (`L&P ENDM`).

A statement whose first word is no instruction, directive or macro is, in
M80, a list of values it assembles as `DB`, and so it is in um80, which also
warns: after `FOO EQU 5`, `FOO` alone is the byte 05, `FOO+1,'AB'` is 06 41 42,
and `LAB: 5,6` (a statement that starts with a value) is 05 06. Up to 0.3.50
um80 left out a statement that started with a value, without a word. So M80
has no label without a colon: `OBP DS 1` is an error, an undefined `OBP` (M80:
`U`), and so is `<TAB>FOO<TAB>NOP`, with a hint to add the colon or read the
source with `--dri`, where it is a label, as in MAC and RMAC
([DRI sources](#dri-sources---dri)). A line that starts with `*` is not a
comment either, as in M80 - but for M80's `*EJECT` in column 1 - and nor is a
line number. M80's `$TITLE('text')` (a subtitle) and `$EJECT` are directives.

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

The linker automatically provides a `__END__` symbol that points to the first free byte after all linked segments (and after any absolute code loaded above them):

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
relocation. It is the symbol that decides, not symbol plus offset: `TBUF+80H`
(0100H) is marked with TBUF. An absolute symbol at or above 100H stays
absolute. The linker cannot tell a page-zero address from a small constant:
a `PUBLIC` constant below 100H used from another module (`NFILES EQU 10`) is
relocated too, so give such a constant to each module that needs it.

`__END__`, `__BSS_START` and `__BSS_END` are absolute values the linker
computes, but they are addresses in the program and move with it, so a
reference to one - or to a `PUBLIC` alias of one, such as PL/M's `.MEMORY`
(`HT EQU __END__`) - is marked like any program address.

A byte that is `HIGH` of an address, or a word that is an address, is marked
in the bitmap; a byte that is `LOW` of an address is not, since adding a page
never changes a low byte. `(BUF+255)/256` is `HIGH(BUF+255)` and `BUF MOD 256`
is `LOW(BUF)`. A link-time expression whose value would not move by exactly 0
or 1 page (`HIGH(A)+HIGH(B)`, `200H-LAB`, `LAB*2`) cannot be expressed in the
bitmap and is an error in either format.

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
`C(data, BUF) C(abs, 128) A(plus) A(LOW) A(store byte)`, then the
placeholder 00H.

An address and a constant added to it are separate operands, as M80 writes
them (`HIGH(5+C1)` is `C(abs, 5) C(common, C1) A(plus) A(HIGH)`). This is
more than form: LINK-80 3.44 miscomputes a COMMON-relative `C` value that
lies past the end of its block, so `HIGH(C1+400H)` with C1 at the start of a
300H-byte block links right only as `C(common, C1) C(abs, 400H) A(plus)`.
A symbol is one value, as in M80: after `X EQU C1+400H`, `HIGH X` is
`C(common, C1+400H) A(HIGH)`, and a word is folded too (`DW C1+400H` is one
COMMON-relative word) - L80 gets both wrong for M80's objects and um80's
alike, and ul80 gets them right. um80 folds constant subexpressions (`2*3`
is `C(abs, 6)`; M80 writes `C C A(*)`), which changes the `.REL` but not the
linked value. In a CSEG or DSEG value L80 handles an offset of any size.

The listing (`um80 -l`) shows such a field as the placeholder the `.REL`
carries, marked after its last byte the way MACRO-80's listing marks a value
the linker finishes: `'` program relative, `"` data relative, `!` COMMON,
`*` external (an expression is marked `*` if it uses an external, else by
its first relocatable operand). With BUF at DSEG 0300H, `MVI A,HIGH(BUF)`
lists `3E 00"` (M80 lists `3E 03"`, a byte in neither the `.REL` nor the
program) and `DW EXT+2` lists `00 00*` (M80: `0002*`, the constant of its
item 9). A relocatable word shows its offset, as in M80: `DW BUF` lists
`00 03"`.

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
  bytes assembled into a COMMON block load there (DB, FORTRAN's BLOCK DATA).
  Bytes load into the block that was selected at the last set-location, in
  ul80 as in L80: M80 selects another block for an operand inside a COMMON
  block and does not select back, and what follows still loads into the
  first;
- a `.REL` holding several modules (a LIB-80 library such as FORTRAN-80's
  FORLIB.REL) loads every one of them, and `ulib80 -c` stores each as a
  module of its own;
- every module carries item 10 (data size), 0 when it has no DSEG, as M80
  writes it: without it L80 drops the constant of an item 9 in ASEG
  (`DW EXT+1` there links to EXT);
- an `ASEG` directive's set-location item is held back until something is
  loaded or reserved in the segment, as M80 does, and an `ORG` or another
  segment directive before then replaces it. L80 takes a set-location to
  ASEG 0000H for code loaded there, so `ASEG` / `ORG 100H` made it write a
  `.COM` starting at 0000H;
- a chain link typed absolute is an address in ASEG (M80 and DRI's RMAC chain
  a CSEG reference to one in ASEG that way) — except in an object from um80
  0.3.48 or earlier (item 14 without an A-field), where it is read as an
  offset in the segment of the word holding it. um80 0.2.0 to 0.3.34
  chained all the references to an external through such untyped links,
  each the offset of the previous reference in whichever segment that one
  was in; the link does not say which, so an old object whose references
  to one external are in more than one segment does not link right
  (assemble it again). 0.3.35 to 0.3.48 wrote a chain of one per
  reference, whose link is 0 however it is read;
- special item 12 (chain address) fills every word of the chain it heads with
  the address of the location where it appears: FORTRAN-80 writes every
  forward reference (a jump to a label further down, a FORMAT string, a
  constant after the code) that way;
- a byte loaded over a word the linker has yet to finish is handled as L80
  handles it. L80 relocates a word as it loads it and fills an item-12
  chain when it reads the item, so a byte loaded there afterwards - an `ORG`
  back, a `COMMON` block declared again (every `COMMON` statement starts at
  the beginning of its block), another module loading the same COMMON
  bytes - replaces that byte, and the other byte of the word keeps its
  finished value. An external's chain is filled once the module and the
  one defining the external are both loaded, so what a later module loads
  over it stays. Items 8 and 9 and link-time expressions are applied at the
  end of the link, to whatever is there then;
- if a module defines the global `$MEMRY`, the word there gets the address
  of the first free byte after the data area, as L80 stores it (FORTRAN-80's
  FORLIB allocates its file buffers from it). L80 overwrites the word
  whatever the module loaded there, and uses the end of the data area even
  when `/D` puts that below the program; in ul80's layout, data and COMMON
  after the code, that is `__END__`.

An F80 program linked against FORLIB with `ul80 -x t.rel forlib.lib` gives
the same image as `L80 /P:100/D:19D3,T,FORLIB/S` (`/D` where ul80 puts the
data), 0100H through 1BCDH; so does a second one with a subroutine, a
function and `STOP`. (`forlib.lib` is FORLIB.REL under another name: ul80
searches a file named `.lib` and loads every module of a `.rel`.)

#### What still differs

The four-way comparison (M80+L80, M80+ul80, um80+L80, um80+ul80) of 52 test
links gives the same bytes all four ways in 40, and differs only in these
cases, each checked with the genuine M80 and L80 3.44:

- **M80 3.44 miscompiles, um80 does not.** `DW -LAB`, `DW LAB*2`,
  `DW EXT*2`, `DB HIGH(BUF)*2` and the like, and the distance between two
  COMMON blocks, which M80 assembles as a constant. um80's objects link to
  the arithmetically right value in L80 and ul80 alike; M80's do not, in
  either linker.
- **M80 3.44 undercounts a segment after an `ORG` back.** Its segment size
  is the most of the locations set and the one at the end, which leaves
  out bytes loaded past the highest `ORG` (`ORG 20H` / `DB 1` / `ORG 10H`
  / `DB 2` is 20H bytes, so L80 links the next module over the 1). um80
  writes the most the segment reached, 21H. Where each byte goes matches
  M80, including a segment directive going on at the highest location set
  (not where the segment was left) and every `COMMON` statement starting
  at the beginning of its block.
- **A forward read of a `SET` symbol.** Above the `SET`s of X, um80 reads
  the value the last one gives X, with every symbol at its final value;
  M80 3.44 reads, without a message, the value X had at the end of its
  pass 1, computed while the symbols defined further down had none yet
  (0). `DW X` / `X SET Y+1` / `DW X` / `Y EQU 5` is 01 00 06 00 in M80
  (and um80 0.3.48) and 06 00 06 00 in um80. They agree unless that value
  depends on a symbol defined below the `SET` (`DW X` / `X SET 1` /
  `X SET 2` is 02 00 in both). Of 173 random programs of forward `EQU`s,
  `SET`s, `DS` and `IF` that M80 assembles without an error, 19 differ,
  each through such a read (0.3.48 matched M80 in 17 of them). A forward
  `EQU` chain is not silent in M80: `MVI A,X` / `X EQU FWD+1` /
  `FWD EQU 5` is flagged `U` and assembles to 01, where um80 assembles 6.
- **L80 3.44 miscomputes a COMMON-relative value past the end of its block**
  (an `EQU` of one, a `DW` of one) — M80's objects and um80's give the same
  wrong bytes in L80; ul80 computes them right.
- **The linkers lay the program out differently** (the same for M80's
  objects as for um80's, in each linker):
  - L80 puts COMMON at the start of the data area, before the modules' data,
    with `/D` or without, and without `/D` it loads each module's data just
    before its code; ul80 puts all code, then all data, then COMMON (as L80
    does with `/D` set to the end of the code, except for COMMON);
  - with `/D` given, L80 does not start a module's program area above the
    absolute code loaded before it, as it does without `/D` (and ul80
    does, see below): it loads the code over the absolute code, without a
    message. And it refuses a link in which absolute code lies above the
    program or data area it meets ("?Intersecting Program area",
    "?Intersecting Data area"). The links with absolute code are compared
    with L80 run without `/D`, on modules with no data, where the two
    layouts are the same;
  - L80 writes a `.COM` from 0100H whatever `/P` says (with `/P:200` the
    program starts 100H bytes into the file); ul80 writes it from `-p`, so
    that `-p` gives a raw image for another address, such as a ROM at
    E000H;
  - L80 takes a set-location item to ASEG 0000H for code loaded there, and
    ul80 does not: `ASEG` / `ORG 0` / `DS 103H` and a CSEG module after it
    put the module at 0103H in both, but L80 writes the `.COM` from 0000H
    (384 bytes, the module 103H bytes in) and ul80 from 0100H. (um80 writes
    that item, as M80 does, only when something is loaded or reserved in
    ASEG before an `ORG` replaces it.)

- **Library search.** ul80 searches the libraries, each in turn and its
  modules in library order, until nothing more loads; LINK-80's `/S` makes
  one pass, so a reference to a module earlier in the library than the one
  that makes it stays undefined in L80 ("Undefined Global") and is loaded
  by ul80. Of 150 random library links, the 127 L80 links cleanly are
  byte-identical, and the 18 differences are all such backward references.
- **A COMMON block declared larger the second time.** L80 keeps the first
  declaration's size ("%2nd COMMON Larger"), ul80 the largest.

ul80 has no counterpart of `/D`; to compare with L80, give L80 `/D:` the
address where ul80 puts the data (the end of the code).

To repeat these checks under `cpmemu`, run M80, L80 and F80 from a
configuration file that sets `default_mode = binary` and
`eol_convert = false`. By default cpmemu writes a file the CP/M program
creates as text: it stops at the first 1AH and drops the CR of a CR LF, so a
`.COM` or `.REL` holding those bytes comes out cut short or altered (L80
seemed to write a 1-byte `.COM` for a program starting `21 1A 01`).

### Absolute assembly (`--aseg`)

M80 starts a file in CSEG, so an `ORG` is an offset within a relocatable
segment. DRI's MAC has no relocatable segments: its sources are absolute and an
`ORG` is an absolute address. `um80 --aseg` starts the file in ASEG, which
assembles MAC sources the way MAC does.

### Absolute code in a link

ul80 places each module's code after the previous module's, unless the
modules before it loaded absolute (`ASEG`) code reaching higher: then the
module's code starts above the highest absolute location they reached - a
byte loaded, or a location an `ORG` or `DS` set with nothing loaded after
it. This is LINK-80 3.44's rule without `/D` (ul80 has no `/D`), probed
under cpmemu: it holds with `/P` and without, and when there is free space
below the absolute code (`ASEG` / `ORG 200H` in one module, then a CSEG
module, linked `/P:100`: the CSEG starts at 0204H). Absolute code below the
origin moves nothing. A module's own absolute code does not move its own
code, because L80 allocates a module's program area before it loads anything
in it. The data and COMMON follow all the code, as always in ul80.
`__END__`, and so `$MEMRY` and PL/M's `.MEMORY`, is past absolute code
loaded above the program, as L80 stores `$MEMRY`. Only the bytes a module
loads go into the image: the gap an `ORG` or `DS` leaves in its absolute
code does not overwrite another module's code there.

Absolute code that lands on something else is an error, and ul80 writes no
output: on a module's program area (its own, or an earlier module's), on the
data or COMMON that follow all the code, or on absolute code another module
loaded. For example `ASEG` / `ORG 100H` / `JMP START`
followed by a CSEG in the same module, linked at ul80's default origin,
0100H, gives

```
Error: Module X: absolute code at 0100H-0102H overlaps its own program area (0100H-0115H)
```

L80 warns "%Overlaying Program area" (or "Data area") there and writes a
mixture of the two. L80's default origin is 0103H, which leaves room for
exactly such a jump; link the program with `-p 103`. An `ORG` back over a
module's own absolute bytes is not an overlap: the later bytes load, as they
do in the assembler.

For a module that loads over code on purpose - a patch module linked after
the program, an overlay - `ul80 --allow-overlap` makes each of these a
warning and writes the image, with the byte loaded last in it: a later
module's byte over an earlier one's, and in one module the byte it loaded
later, whether absolute or not. That is what L80 writes when given `/D`
(without `/D` it keeps some of the earlier bytes). A relocatable word that
something is loaded over keeps the relocated byte nothing replaced, as in
L80, which relocates a word as it loads it.

### A global defined twice (`--fatal-mult-def`)

When a second module defines a global that one loaded before it defines,
LINK-80 3.44 prints `%Mult. Def. Global FOO`, binds every reference to the
first definition and writes the program. ul80 does the same, and says which
modules and which definition:

```
Warning: %Mult. Def. Global FOO: defined in A and in B; A's definition is used
```

The exit status is 0, as the program is linked: link lines depend on it (MP/M
II's GENSYS link overrides ten names of its runtime with `X0100.ASM`'s, linked
first). For a link where that is a mistake - it once sent four calls to
`PRINTB` in MP/M II's CLI and ATTACH to the wrong routine - `ul80
--fatal-mult-def` makes it an error: ul80
writes no output and exits 1. Up to 0.3.50 ul80 printed "Error: Multiply
defined global" but wrote the output and exited 0.

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
| `$` ignored inside names | ✗ | `--dri` | ✓ | ✗ |
| Register EQU aliases | ✓ | ✓ | ✓ | ✗ |
| Register name in any expression (`DB B`) | ✓ | ✓ | ✓ | ✗ |
| PUSH A / POP A | ✗ | `--dri` | ✓ | ✗ |
| Label with no colon | ✗ | `--dri` | ✓ | ✗ |
| `=` `<` `<=` `>` `>=` `<>` relational operators | ✗ | `--dri` | ✓ | ✗ |
| `HIGH`/`LOW` of all that follows (`HIGH(X)+1` is `HIGH(X+1)`) | ✗ | `--dri` | ✓ | ✗ |
| `'AB'` is 4241H (first character in the low byte) | ✗ | `--dri` | ✓ | ? |
| `IF` true only when bit 0 is set (`IF 2` false) | ✗ | `--dri` | ✓ | ? |
| `MACLIB` reads `NAME.LIB`, in pass 1 only | ✗ | `--dri` | ✓ | ✗ |
| Signed `/` and `MOD`, a unary sign before `* / MOD SHL SHR` | ✓ | ✓ (not `--dri`) | ✗ | ? |
| Statement of values (`LAB: 5,6` is `DB`) | ✓ | ✓ | ✗ | ✗ |
| EQU external+offset | ✗ | ✓ | ✗ | ✓ |
| `__END__` symbol | ✗ | ✓ | ✗ | ✗ |
| PRL / SPR output | ✗ | ✓ | (RMAC) | ✗ |
| HIGH/LOW of a relocatable value | ✓ (3.44) | ✓ | ✗ | ? |

---

## Version History

- **Unreleased** — `--dri`: `'AB'` is 4241H, `IF` is true when bit 0 is set, `MACLIB NAME` reads `NAME.LIB` in pass 1 only, a label on an `ORG` is the location it sets, `END` of a symbol not defined takes no start address, `IRP`/`IRPC` lists and division as MAC reads them, `MOV M,M` is 76H, and `"` quotes nothing; M80's unary sign and signed `/` and `MOD`, an empty `DB`/`DW` operand is 0, `.CREF`/`.XCREF`; a label that moves between the passes is a phase error; `LOCAL` after a `!`; a label on `IF`, `ELSE`, `ENDIF` and `EXITM`
- **0.3.51** — `--dri` (a `$` inside a name is ignored, a word with no colon may be a label, `PUSH A` is `PUSH PSW`, `=` is `EQ` and `HIGH` binds loosest, as in MAC and RMAC); an instruction or directive in column 1 is one, and a statement of values is a `DB`, as in M80; in 8080 code a register name is its number in any expression, as in M80 and MAC; ul80 `--fatal-mult-def`
- **0.3.50** — MACRO-80 IRP/IRPC lists, 6-character `-t`, mbasic2025 in the test suite
- **0.3.49** — link-time expressions (REL extension link items), LINK-80 interchange, absolute code in a link
- **0.3.48** — `--spr`, `--extra` and `--aseg`; `--prl` links a transient at 100H
- **0.3.33** — External symbol aliases (EQU external+offset) for z88dk compatibility
- **0.3.21** — Extended REL format for long symbols, `-t/--truncate` switch
- **0.3.20** — DRI extensions (!, HIGH(), $, register aliases, PUSH A)
- Earlier versions focused on M80/L80 compatibility
