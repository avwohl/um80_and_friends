# um80/ul80 Extensions Beyond M80/L80

This document describes the extensions of um80 and ul80.
The toolchain follows Microsoft MACRO-80 (M80) and LINK-80 (L80).
The extensions go beyond the original Microsoft programs.

## Extended REL Format: Long Symbol Names

### Background

The original Microsoft REL format encodes the name of a symbol in a "B-field".
The B-field has a 3-bit length (0-7, where 0 means 8 characters).
The ASCII characters of the name follow the length.
The format limits a symbol name to 8 characters maximum.

The limit causes problems when you assemble code that uses longer symbol
names. (M80 3.44 keeps 16 characters of a name in its symbol table. M80 3.44
writes only the first 6 characters of a PUBLIC or external name in the .REL.)

### Extended B-Field Format

um80/ul80 extend the REL B-field format to support symbols up to 255
characters.

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

The design of the extended format gives backward compatibility:
- A standard symbol of 8 characters that starts with 0xFF is extremely rare
  (0xFF is not printable)
- ul80 detects the 0xFF marker and reads the extended length

L80 3.44 reads neither an 8-character name in the standard format nor a name
in the extended format. Both use a 3-bit count of 0, and L80 3.44 refuses a
3-bit count of 0 ("?Loading Error").
The longest name that L80 3.44 accepts is **7** characters.
The longest external that an extension item `B` can name is 6
(the `B` is the first byte).
The check used the Microsoft L80 under cpmemu, the CP/M emulator.

### Command-Line Control

Use the option `-t` or `--truncate` to disable the extended format.
The option cuts every name in the REL file to 6 characters, as M80 3.44
does. The names are the PUBLIC names, the EXTRN names, the `##` external
names and the module name.

```bash
um80 -t program.mac          # Names cut to 6 chars, as M80
um80 --truncate program.mac  # Same as above
um80 program.mac             # Default: allow long symbols
```

The option is useful in these cases:
- You link with REL files that M80 assembled.
  M80 writes the PUBLIC `FBUFP27` as `FBUFP2`.
  A module that um80 assembled without `-t` asks for `FBUFP27`.
  Neither L80 nor ul80 then finds `FBUFP27`.
- You compare the behavior of um80 with the behavior of the original tools.

If L80 must read the REL files, keep each symbol to 7 characters.
Keep an external that a link-time expression uses to 6 characters.
Alternatively, use `-t`.

In versions up to 0.3.49, the option `-t` cut names to 8 characters.
Neither M80 nor L80 cuts a name to 8 characters.
L80 refuses a name of 8 characters.

---

## DRI Assembler Extensions

um80 reads several syntax extensions of Digital Research (DRI) assemblers.
These extensions are commonly found in CP/M, MP/M, and CP/M-86 source code.
The extensions are compatible with the DRI assemblers ASM, MAC, and RMAC.

### Multi-Statement Lines (`!` Separator)

You can put more than one instruction on a single line. Separate the
instructions with `!`:

```asm
        PUSH H! PUSH D! PUSH B      ; Save registers
        POP B! POP D! POP H         ; Restore registers
        MOV A,B! ORA A! RZ          ; Test and return if zero
        XRA A! RET                  ; Clear A and return
```

DRI source code commonly uses the `!` separator to group related operations.

Without `--dri`, a comment runs to the end of the line. A `!` in the comment
is text.

With `--dri`, a `!` ends a comment too, as in MAC and RMAC. The next
statement starts after the `!`. For example, `NOP ;save! INX H` is two
statements (see [DRI sources](#dri-sources---dri)).

#### Implementation notes

- um80 recognizes the `!` separator outside of string literals.
- um80 processes each statement after the first as if the statement had no
  label.
- The `!` separator works with all instructions and most directives. The
  details follow.

##### DB and DW before a separator

MAC and RMAC flag `D` a line on which a `DB` or a `DW` has a `!` after it.
MAC and RMAC assemble what follows the `!` incorrectly.

Source text | MAC and RMAC | um80
--- | --- | ---
`DB 1! DB 2` | 01 00 | 01 02

##### EXITM after a separator

An `EXITM` after a `!` ends the macro expansion or the repetition at that
place. An `EXITM` at the start of a line does the same. For example,
`NOP! EXITM! DB 5` assembles the `NOP` only.

##### LOCAL after a separator

A `LOCAL` in a macro body is a statement wherever the `LOCAL` is on the
line, as in MAC and RMAC. These lines declare `QQ`:

- `NOP! LOCAL QQ`
- `LOCAL QQ! NOP`
- `NOP! LOCAL QQ! NOP`
- With `--dri`, a `!` ends a comment. Two more lines declare `QQ`:
  `LOCAL QQ ;c! NOP` and `MM ;c! LOCAL QQ`.

As in MAC and RMAC, a `LOCAL` declares its names for what follows the
`LOCAL`. The names are for the statements after the `LOCAL` on the line and
for the lines after the `LOCAL`. A statement before the `LOCAL` on the line
uses the meaning that the name had before the `LOCAL`.

Examples:

- With `QQ EQU 7` outside the macro, `MVI A,QQ! LOCAL QQ! LXI H,QQ` is
  3E 07 and the address of the local `QQ`.
- `LXI H,QQ! LOCAL QQ` with no `QQ` outside the macro is an undefined
  symbol (MAC: U).
- `QQ: NOP! LOCAL QQ` defines the `QQ` outside the macro, so a second
  expansion defines `QQ` twice (MAC: P).

With `--dri`, a `LOCAL` that MAC and RMAC leave out after a macro call (see
[What follows a macro call on its line](#what-follows-a-macro-call-on-its-line)) declares nothing, as in MAC. In
`NN! LOCAL QQ`, with `NN` a macro of no parameters, the `!` is text of the
call. um80 warns that the `LOCAL` is left out.

M80 reads `LOCAL QQ! NOP` as `LOCAL QQ` and nothing more. M80 flags
`NOP! LOCAL QQ`, where `QQ` is not local.

##### A macro call line

um80 does **not** split a macro call line on `!`. In a macro call line, the
`!` keeps its M80 meaning. The `!` quotes the next character in the argument
list. Because of this rule, the statement separator never interferes with
macro arguments. Examples:

- `head FOO,!!CF` passes the name `!CF`.
- `!,` passes a literal comma.

Without `--dri`, the quote character `!` quotes a `;` too, as in M80:

- `MM A!;B` passes `A;B`.
- `MM A!"B;C` passes `A"B`.

With `--dri`, um80 reads a `!` after the arguments as MAC reads the `!`. See
[What follows a macro call on its line](#what-follows-a-macro-call-on-its-line) under
[DRI sources](#dri-sources---dri).

### HIGH and LOW Operators (Function Syntax)

To get the low byte or the high byte of a 16-bit value, use the
function-call syntax:

```asm
        MVI L,LOW(BUFFER)           ; Load low byte of address
        MVI H,HIGH(BUFFER)          ; Load high byte of address
        MVI A,LOW(1234H)            ; A = 34H
        MVI B,HIGH(1234H)           ; B = 12H
        LXI H,HIGH(TABLE)*256+LOW(TABLE)  ; Verbose identity
```

um80 accepts both syntaxes:
- `LOW(expr)` and `HIGH(expr)` - the function-call style of DRI
- `LOW expr` and `HIGH expr` - the style of M80, with a space

M80 and MAC read the operand of `HIGH` in different ways. M80 applies `HIGH`
to the term after `HIGH`. MAC and RMAC apply `HIGH` to all that follows.
um80 without `--dri` reads the operand as M80 does. um80 with `--dri` reads
the operand as MAC does (see [DRI sources](#dri-sources---dri)).

Source text | M80 | MAC and RMAC | um80 without `--dri` | um80 with `--dri`
--- | --- | --- | --- | ---
`HIGH(BUF)+1` | `HIGH(BUF)` plus 1 | `HIGH(BUF+1)` | `HIGH(BUF)` plus 1 | `HIGH(BUF+1)`

If the value is absolute, the result is a constant. If the value is
relocatable or external, the result depends on where the linker puts things.
For a relocatable or external value, um80 passes the expression to the linker. See
[Link-time expressions](#link-time-expressions-rel-extension-link-items).

### Digit Separators in Numbers (`$`)

Use the `$` character as a visual separator in numeric literals, to make the
numbers easier to read:

```asm
        MVI A,1111$0000B            ; Binary: F0H
        MVI B,0001$0010B            ; Binary: 12H
        LXI H,1$0000H               ; Hex: 10000H (wraps to 0000H)
        MVI C,1$000D                ; Decimal: 1000
        DW  0ABCD$EF00H             ; Large hex constant
```

When um80 parses a number, um80 deletes the `$` characters. The `$`
characters do not change the numeric value. The separator is particularly
useful in binary constants, where groups of bits are easier to read.

### DRI sources (`--dri`)

`um80 --dri` reads a source the way MAC and RMAC read it where they differ
from M80. The topics below list the differences.

#### A `$` inside a name is ignored

With `--dri`, um80 ignores a `$` inside a name. The manuals of DRI say: "All
characters are significant in an identifier, except for the embedded dollar
sign ($) which can be used to improve readability of the name."

`NMB$LST`, `NMBLST` and `N$M$B$LST` are one symbol. `AB$` and `AB` are one
symbol too. The rule holds wherever um80 reads a name:

- labels
- the names of `EQU` and `SET`
- operands
- macro names and their parameters
- `IF` operands
- `PUBLIC` and `EXTRN` names: `PUBLIC A$BC` writes `ABC`, as RMAC does

um80 deletes each such `$` from a statement as it reads the statement. Thus the
listing shows the statement without the `$` characters. A `$` in a number
(`0001$1111B`) is ignored with or without `--dri`.

##### Where um80 keeps a `$`

With `--dri`, um80 keeps a `$` in these places:

- A `$` that starts a word. A `$` alone is the location counter (`JMP $+3`).
  A name can start with `$`.
- Everything inside a quoted string (`DB 'Hello$'`, `NAME('M$OD')`) and
  everything after a `;`.
- The arguments of a macro call and the list of an `IRP` or `IRPC`.

##### A `$` in a macro argument or an IRP list

MAC and RMAC read the arguments of a macro call and the list of an `IRP` or
`IRPC` as text, not as names. um80 does the same with `--dri`.

- `PRINT HELLO$` passes `HELLO$`. Thus a body of `DB '&MSG'` keeps its BDOS
  terminator.
- `IRPC C,12$3` repeats four times.

Where an argument becomes a name in the body, the argument loses the `$` there.
`MM NMB$LST`, with a body of `LDA P`, loads `NMBLST`.

The name of the macro, a label, and the parameter of an `IRP` or `IRPC` are
names. These names lose their `$`. The expression of a `%` argument is read as
names. `GEN %N$C` passes the value of `NC`.

##### A `.` in a name

MAC does not read a `.` in a name. With `--dri`, um80 keeps this rule for a
word with no colon. `.BAR NOP` is an error. Thus a mistyped directive that
starts with a dot is not a label.

A label with a colon can start with a dot (`.FOO:`) with and without `--dri`.
The option `--dri` adds this extension to MAC. um80 assembles M80 sources that
have such labels. The parameter of a macro keeps the rule of MAC: a `.` ends the
name of the parameter.

##### A `$` in a name without `--dri`

Without `--dri`, a `$` is part of the name, as in M80 3.44. There are two
examples:

- `NMBLST EQU 5` then `LDA NMB$LST`: the name `NMB$LST` is an undefined
  symbol.
- `AB EQU 1` with `A$B EQU 2`: um80 defines two symbols. MAC reports `AB`
  defined twice.

#### A macro body is read as MAC reads it

A line of a `MACRO`, `REPT`, `IRP` or `IRPC` body is kept as written. um80
reads the line when um80 expands the body. The reason is that MAC finds a
parameter in the body as the body is written. A `$` ends the name that MAC
searches for.

##### Where the name of a parameter ends

These examples show the rule that a `$` ends the name:

- With the parameter `A`, `DB A$B` is `DB X$B` after `MM X`.
- `DB P$1` is not the parameter `P$1`. MAC reports the name undefined.
- `LOCAL L$1` declares `L1`.

A `_` and a `.` also end the name. In MAC, a name has letters, digits, `?` and
`@`. In M80, a name also has `$`, `.` and `_`. With the parameter `X`, MAC reads
`'&X_'` as the argument and `_`. M80 reads `'&X_'` as the text `&X_`.

##### A parameter in a quoted string

In a quoted string, MAC and RMAC delete every `&` next to a parameter. A name
before an `&` is a parameter too (`'X&B'` is the argument and `B`).

M80 reads only `&X` and deletes the `&` of `&X`. M80 reads the remaining text of
the line as if the text is outside a string, until a quote starts another
string.

Source text | M80 | RMAC
--- | --- | ---
`'&X &X'` | `K &K` | `K K`
`'&X''&Y'` | `K'L` | `K'L`

RMAC folds case in a string, as um80 does. MAC 2.0 does not fold case.

An empty argument in a string is nothing in MAC (`'Z&P'` is `Z`). M80 passes
the empty argument as a 00 byte (5A 00).

##### A `>` with no `<` before it

In the arguments of a macro call, a `>` with no `<` before the `>` is text, as in
MAC. A later comma still ends the argument. M80 ends the argument at such a
`>`, as at a comma, and flags the `>` with the error code `Q`. um80 without
`--dri` does the same as M80, and writes a warning.

Source text | M80 | MAC | um80 without `--dri`
--- | --- | --- | ---
`MM 1>2,3` | passes 1, 2 and 3, flags `Q` | passes `1>2` and 3 | passes 1, 2 and 3, writes a warning

##### A blank or a tab in the arguments of a macro call

In MAC, RMAC and M80, a blank or a tab ends a macro argument. The rule holds
outside a quoted string and outside a `<...>` group. MAC and RMAC end the
arguments at the blanks. The text after the blanks has these meanings:

- A comma starts the next argument.
- A `;` or a `!` ends the statement of the call (see *What follows a macro call
  on its line* below).
- Anything else is an error. MAC and RMAC flag the text `S` and ignore the
  text.

M80 reads the blanks after an argument as a separator, as a comma. um80
without `--dri` does the same. In the table, "not stated" means that this
document gives no result.

Source text | M80 | MAC and RMAC | um80 without `--dri`
--- | --- | --- | ---
`MM A ,B` | A, an empty argument and B | A and B | A, an empty argument and B
`MM A B` | A and B | passes A, flags `S` | A and B
`MM 5 GT 2,4` | 5, GT, 2 and 4 | not stated | 5, GT, 2 and 4

##### A `"` in the arguments of a macro call

MAC and RMAC quote a string with `'` only. Thus a `"` in the arguments of a
macro call or in an `IRP` list is text. In an `IRPC` string, a `"` is text in
M80 as well.

Source text | M80 | MAC and RMAC
--- | --- | ---
`MM "A,B",C` | reads `"A,B"` as a string | passes `"A`, `B"` and C
`MM "A;B",C` | reads `"A;B"` as a string | passes `"A`, the remaining text is a comment

##### A `%` argument

Only an argument that starts with `%` is a value, as in MAC. M80 also reads
these forms as values:

- `A%E` is `A` and the value of E.
- `<A>%E` is `A` and the value.
- A `%` in an `IRP` list: M80 evaluates the `%`, and MAC reads the `%` as text.

In MAC, RMAC and M80, a `%` expression runs to the next comma. The expression
includes blanks.
`MM %1 + 1,5` passes 2 and 5.

In a `%` expression, a `<` or a `>` is the relational operator of MAC, not a
bracket. `MM %1<2,3` passes 65535 and 3. M80 flags the `<`.

`<>` is the `NE` of RMAC. `MM %1<>2` passes 65535, as RMAC does. MAC 2.0 flags
`<>` with the error code `E`, as MAC 2.0 does everywhere, and passes 0.

M80 reads a `%` with no expression after the `%` as 0 (`MM %` passes 0). MAC and
RMAC flag the `%` with the error code `E`. With `--dri`, a `%` with no expression is an error.

##### An item of an `IRP` list

An item of an `IRP` list ends at a comma, as in MAC. A `;` in the list, outside
a nested `<...>`, is an error. MAC and RMAC flag the `;` with the error code `B`.

MAC and RMAC skip a blank or a tab at the start of an item, before the first
character of the item. `<A, B>` is A and B.

##### A blank in an `IRP` list

MAC and RMAC read any other blank outside a nested `<...>` in several
different ways, as the table shows. um80 does not copy any of these ways. With `--dri`, such a blank is an error.

Source text | MAC | RMAC
--- | --- | ---
`<A ,B ,C>` | A, B and an empty item | not stated
`<A ,B,C>` | A and C | not stated
`<A, ,B>` | A and `,` | not stated
`< ,A>` | the one item `,` | the one item `,`
`<A ,B>` | not stated | stops and writes nothing, with no message
`<A B>` | flags | stops
`<A >` | flags | stops
`<%1 + 1,5>` | flags | flags

M80 ends an item at a `,`, a `;`, a blank or a tab. In M80, `<A;B>` and `<A B>`
are A and B. In M80, `<A ,B>` is A, an empty item and B.

##### The list of an `IRP` and the string of an `IRPC`

MAC and RMAC read the list of an `IRP`, and the string of an `IRPC`, as the
argument of a macro call:

- The `<` that opens a group and the `>` that closes the group are removed,
  wherever they are.
- The text outside the groups is text of the list too. The text runs to a
  blank, a tab, a comma or a `!` outside any group.
- A comma inside the outer group separates items.

M80 ends the list at the `>` that matches the `<`. M80 ignores the remaining
text of the line. um80 without `--dri` does the same, and writes a warning.

Source text | M80 | MAC and RMAC | um80 without `--dri`
--- | --- | --- | ---
`IRP X,<1,2>3<4,5>` | 1 and 2 | 1, 234 and 5 | as M80, with a warning
`IRP X,A<1,2>` | A | A1 and 2 | as M80, with a warning
`IRP X,<1>>2` | 1 | `1>2` | as M80, with a warning
`IRP X,<"A>B">` | `"A>B"`, a string | the one item `"AB">` | as M80, with a warning
`IRPC X,A<B>C` | A, `<`, B, `>`, C | A, B and C | as M80, with a warning

##### Text after the end of an `IRP` list

With `--dri`, text after the blank or the comma that ends the list is an error.
A `!` statement is the exception. MAC and RMAC flag the text `S`. These
examples are errors:

- `IRP X,<1,2>,3`
- `IRP X,1,2`
- `IRPC X,AB CD`

M80 ignores the text. um80 without `--dri` writes a warning.

A `!` inside the list is the quote character of M80, with `--dri` too.
`IRP X,<1!,2,3>` repeats `1,2` and 3. MAC and RMAC end the statement at the
`!` and flag the `!` with the error codes `V` and `S`.

##### A `LOCAL` in a `REPT`, `IRP` or `IRPC` body

MAC and RMAC obey a `LOCAL` in the body of a `REPT`, `IRP` or `IRPC`. um80
reads a `LOCAL` in the body of a `MACRO` only, as M80 does. In a `REPT`, `IRP`
or `IRPC` body, a label that the `LOCAL` names is defined again in each
repetition.

##### An `IRPC` with an empty string

An `IRPC` with an empty string repeats once, with an empty parameter, as in
MAC. M80 does the same only where an empty argument of a macro made the string
empty.

##### A label on an `ENDM`

A label on the `ENDM` that ends a body is defined where the body ends, each
time, as in MAC. For example, `STACK.LIB` of DRI ends `SIZ` with
`STACK: ENDM`. M80 ignores the label.

#### An `IF` a macro body leaves open ends with it

An expansion, or one repetition of a `REPT`, `IRP` or `IRPC`, can open an `IF`
and not end the `IF`. MAC and RMAC end each such `IF`, true or false, when the
expansion or the repetition ends.

The libraries of DRI rely on this behavior:

- `TEST?` of `CONTROL/COMPARE.LIB` ends inside an `ELSE`.
- `FILLFCB` of `SEQIO.LIB` opens an `IF` in each repetition of an `IRPC`.

M80 continues each open `IF` past the `ENDM`. A false `IF` skips the remaining
text of the file. M80 reports "Unterminated Conditional". um80 without `--dri`
does the same.

An `EXITM` ends the `IF`s that the `EXITM` is in, with or without `--dri`.
M80, MAC and RMAC do the same.

#### A word with no colon may be a label

With `--dri`, the first word of a statement is a label when the word is not an
instruction, a directive or a macro. The label can be in any column. MAC and
RMAC do the same ("the ':' following the identifier in a label is optional").
These are examples:

- `OBP DS 1` (`UTIL3/GENHEX.ASM`)
- `<TAB>LAB<TAB>NOP`
- `HALT LXI H,1` in 8080 code, where `HALT` is not an instruction

Without `--dri`, such a word is not a label, as in M80 (see
[The first word of a statement](#the-first-word-of-a-statement)).

The directives of um80 stay directives. MAC would read `ENTRY JMP START` as a
label `ENTRY`, which is not a directive of MAC. um80 reads the `ENTRY`
directive.

#### A line number, a `*` comment line and a MAC control are ignored

With `--dri`, um80 ignores these three items:

- A line number: a word that starts with a digit before a statement
  (`00010 LAB: NOP`).
- A `*` comment line: a line whose first character, after any blanks, is `*`.
  The line is a comment. A `!` in the line still ends the comment, as in MAC,
  whatever is before the `!`. Each of `* TEXT ! NOP` and `* it's! NOP` is a NOP.
- A MAC assembly control (`$-MACRO`, `$+PRINT`, `$*MACRO`).

M80 flags each of these items (`O` or `U`). um80 without `--dri` does the same.

#### A `!` ends a comment

MAC and RMAC read a `;` comment to the end of the line or to a `!`. The `!`
then starts the next statement, as the `!` does outside a comment.

Examples:

- `NOP ;c! DB 1` is 00 01.
- `; text! DB 1` is 01.
- A quote in a comment starts no string: `NOP ;it's! DB 1` is 00 01.

DRI's own sources rely on this rule. Two examples:

- The CCP of CP/M 2.0 has `nosub: ;no submit file! call del$sub`.
- The file `disk2_files/ldrbios.asm` of MP/M II has
  `;<TAB>in 0f5h ! ani 2 ! rz`.

With `--dri --aseg`, um80 assembles both of these DRI sources to the bytes of
MAC.

A `;;` comment in a macro body is a special case. The macro body leaves
out the comment only up to its `!`. For example, `NOP ;;c! DB 7` is
stored as `NOP! DB 7`.

The text after the `!` is a statement like any other. The statement can be
one of these:

- an `IF` or an `ENDIF`
- a statement of the body of the `REPT`, `IRP` or `IRPC` on that line:
  `IRPC X,AB ;c! DB '&X'` puts `DB '&X'` in the body
- an `ENDM`

In a line of a body being defined, each statement is read for these
directives that nest in the body:

- `MACRO`
- `REPT`
- `IRP`
- `IRPC`
- `ENDM`

The rule is the same where the `!` is in a comment and where the `!` is not
in a comment. Examples:

- `NOP! ENDM` ends the body after the `NOP`.
- The text after the `ENDM` is assembled at the place where the body ends.
  For example, `NOP! ENDM! DB 5` is 05.

M80 has no `!` separator. Without `--dri`, a comment runs to the end of the
line: `NOP ;c! DB 1` is 00. Thus, without `--dri`, the whole line is a
comment when it has one `;` in front. An example is
`;<TAB>pop h! lxi h,7! jmp err`.

With `--dri`, um80 assembles that line from its first `!` on, as MAC and RMAC
do. To comment out such a line, put a `;` in front of each statement.

#### What follows a macro call on its line

MAC and RMAC read the text after the arguments of a macro call as text. The
text ends at the first `!` that follows a character other than a blank or a
tab. MAC and RMAC then continue with the statement after that `!`.

Up to that `!`, these rules apply:

- A `;` starts a comment that ends at its `!`. The `!` of the comment counts
  as a character other than a blank or a tab.
- A `!` after a blank is text.
- When the call has no arguments, the first character after the name of the
  macro is text, whatever the character is.

With `--dri`, um80 does the same. um80 writes a warning where it ignores a
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

A macro call reads as many arguments as the macro has parameters. The rest
of the line is text. Two examples:

- Where MM has no parameter, `MM A! DB 1` and `NOP! MM A! DB 1` assemble
  DB 1.
- Where MM has one parameter, `NOP! MM A! DB 1` does not assemble DB 1.

Where the macro has parameters, a `!` can follow an argument of the first
statement of a line. um80 still reads that `!` as the quote character of M80 (see
[Multi-Statement Lines](#multi-statement-lines--separator)). MAC ends the
arguments at the `!`. Thus `MM A!B` passes A in MAC and AB in um80. `MM A! DB
1` is an error in um80.

MAC reads the statements of a line that starts with a macro call in the same
way as the statements of any other line. The rule is the same where MAC
defines a body:
`MM ;c! ENDM` ends the body. The rule is the same in a false `IF`:
`MM ;c ! ENDIF` ends the `IF`. um80 does the same.

#### `MOV M,M` is 76H

76H is the opcode of HLT. The table shows the result for each program.

Source text | M80 | MAC and RMAC | um80 without `--dri` | um80 with `--dri`
--- | --- | --- | --- | ---
`MOV M,M` | 76H, error code `A` | 76H, no error code | error | 76H

#### `PUSH A` is `PUSH PSW`, and an expression may have two register names in it

As in MAC and RMAC, `PUSH A` is `PUSH PSW`. As in MAC and RMAC, an
expression can have two register names in it. M80 flags both.

For more information, see [PUSH A / POP A](#push-a--pop-a) and
[Register Names as Values](#register-names-as-values-equ-of-a-register).

#### MAC's relational operators, and its precedence for `HIGH` and `LOW`

In MAC and RMAC, the operators `=`, `<`, `<=`, `>`, `>=` and `<>` are `EQ`,
`LT`, `LE`, `GT`, `GE` and `NE`. Each symbol has the level of its word. The
operators are unsigned, and a true result is 0FFFFH, as in the manual of MAC
and in RMAC 1.1. MAC 2.0 flags `<>`.

Examples:

- `IF @Y = 1` (`CONTROL/DEBLOCK.ASM`)
- `DW 1<2,3`: a `<` or `>` in a list of values is an operator, not a
  bracket.

M80 has none of these operators and flags them with error code `O`. Without `--dri`, the
operators are an error in um80.

The manual of MAC puts `HIGH` and `LOW` below every other operator. MAC and
RMAC apply `HIGH` and `LOW` to all that follows. M80 applies `HIGH` and `LOW`
to the term after them, and so does um80 without `--dri`.

Source text | M80 | MAC and RMAC | um80 without `--dri` | um80 with `--dri`
--- | --- | --- | --- | ---
`HIGH 1234H OR 0F00H` | 12H OR 0F00H | `HIGH(1F34H)`, 1FH | 12H OR 0F00H | `HIGH(1F34H)`, 1FH
`HIGH(100H)+1` | 2 | `HIGH(101H)`, 1 | 2 | `HIGH(101H)`, 1
`LOW 1234H SHR 4` | 03H | 23H | 03H | 23H

The order of MAC, highest first:

1. `* / MOD SHL SHR`
2. `+ -`
3. `EQ LT LE GT GE NE` (and `= < <= > >= <>`)
4. `NOT`
5. `AND`
6. `OR XOR`
7. `HIGH LOW`

#### An `IF` is true when bit 0 of its value is set

An `IF` is true when bit 0 of its value is set, as in MAC and RMAC. M80
takes any value but 0 as true, and so does um80 without `--dri`.

Source text | M80 | MAC and RMAC | um80 without `--dri` | um80 with `--dri`
--- | --- | --- | --- | ---
`IF 2`, `IF 100H`, `IF 0FFFEH` and `IF NOT 1` | true | false | true | false
`IF 1`, `IF 3` and `IF -1` | true | true | true | true

An `IF` with no operand is false in M80, MAC, RMAC and um80. MAC and RMAC
flag the `IF` with error code `E`. um80 accepts the `IF` with no message.

A relation is 0 or 0FFFFH in M80, MAC, RMAC and um80. Thus `IF X EQ 2` means the same
everywhere, but `IF X AND 2` does not.

MAC has none of these directives: `IFT`, `IFE`, `IFF`, `COND`, `IF1`, `IF2`,
`IFDEF`, `IFNDEF`, `IFB`, `IFNB`, `IFIDN` and `IFDIF`. MAC reads `IFT 2` as a
label. MAC flags the `ELSE` and the `ENDIF` after that label with error
code `B`. With `--dri`, um80 keeps the directives, with the meaning that M80 gives. For
example, `IFT 2` is true.

#### A unary sign applies to all that `*`, `/`, `MOD`, `SHL` and `SHR` make of it, and division is unsigned

In MAC and RMAC, a unary sign applies to the result of the operators `*`,
`/`, `MOD`, `SHL` and `SHR` on the next term. Division is unsigned. The table
shows the results.

Source text | M80 | MAC and RMAC | um80 without `--dri` | um80 with `--dri`
--- | --- | --- | --- | ---
`-1 SHR 8` | 00FFH | -(1 SHR 8), 0 | 00FFH | -(1 SHR 8), 0
`-2 SHR 1` | 7FFFH | 0FFFFH | 7FFFH | 0FFFFH
`8000H/2` | 0C000H | 4000H | 0C000H | 4000H
`0FFFEH/2` | 0FFFFH | 7FFFH | 0FFFFH | 7FFFH
`x/0` | error code `O` | 0FFFFH, no error code | error | 0FFFFH, warning

M80 does these things, and so does um80 without `--dri`:

- M80 applies a sign to the term after the sign.
- M80 divides signed, and rounds toward 0.
- M80 gives the remainder of `MOD` the sign of the quotient: 4 MOD -3 and
  -4 MOD 3 are 0FFFFH.
- M80 flags `x/0` with error code `O`. The `x/0` is an error in um80 without `--dri`.

`x MOD 0` is `x` in M80, MAC, RMAC and um80.

MAC also flags a sign after another operator with error code `E`: `2+-1` and `7/-2`.
um80 accepts such a sign.

#### A string is quoted with `'` only

As in MAC and RMAC, a string has the quote `'` only. MAC and RMAC flag
`DB "A"`, `DW "A"` and `MVI A,"A"` with error code `E`, and assemble 00. M80 reads `"A"`
as a string, and so does um80 without `--dri`.

Source text | M80 | MAC and RMAC | um80 without `--dri` | um80 with `--dri`
--- | --- | --- | --- | ---
`DB "A"`, `DW "A"` and `MVI A,"A"` | string | error code `E`, 00 | string | error

A `"` in the arguments of a macro call or in an `IRP` list is text (see
[A macro body is read as MAC reads it](#a-macro-body-is-read-as-mac-reads-it)). `DB '"'` is 22 in M80, MAC, RMAC and um80.

#### An empty operand in a `DB` or a `DW` is an error

MAC and RMAC flag an empty operand with error code `E`. The cases are `DB` or `DW` with no
operand, `DB 1,` and `DB 1,,2`. MAC and RMAC assemble 00 for each case, and
`DB 1,,2` is 01 00 00 in MAC and RMAC.

M80 assembles 0 for each empty operand. Examples:

- `DB` is 00.
- `DB 1,` is 01 00.
- `DW` is 00 00.

M80 flags the `DB` statements with error code `Q`. um80 without `--dri` does the same, with a
warning. With `--dri`, an empty operand in a `DB` or a `DW` is an error.

An empty string (`DB ''`) is nothing in M80, MAC, RMAC and um80.

The directives `DEFB` and `DEFW` of M80 are not directives of MAC. um80 reads
`DEFB` and `DEFW` also with `--dri`. MAC and RMAC read the word as a label and
assemble nothing on the line. MAC and RMAC flag nothing for `DEFB`, `DEFW`
and `DEFB 1`. With `--dri`, an empty operand in `DEFB` or `DEFW` is an error,
and the error message says so.

#### A two-character string used as a value has its first character in the low byte

As in MAC and RMAC, `'AB'` is 4241H. M80 makes the first character the high
byte, so `'AB'` is 4142H in M80. um80 without `--dri` does the same.

Source text | M80 and um80 without `--dri` | MAC, RMAC and um80 with `--dri`
--- | --- | ---
`DW 'AB'` | 42 41 | 41 42
`LXI H,'AB'` | 21 42 41 | 21 41 42
`DB ('AB') SHR 8` | 41 | 42

In MAC, RMAC and um80 with `--dri`, `X EQU 'AB'` then `DW X` is 41 42, and
`IF 'AB' EQ 4241H` is true.

A string in a `DB` is its characters, in order, in M80, MAC, RMAC and um80: `DB 'AB'` is
41 42.

An expression in a `DB` that starts with a two-character string is not read
as MAC reads the expression. MAC and RMAC flag the expression with error code `D` and
assemble the string. um80 assembles the one byte of the value, with no
message.

Source text | MAC and RMAC | um80 with `--dri`
--- | --- | ---
`DB 'AB'+0` | error code `D`, 41 42 | 41
`DB 'AB' SHR 8` | error code `D`, 41 42 | 42

#### An 8AH or an 8DH inside a line is read as MAC reads it

MAC and RMAC clear bit 7 of a byte and then read the byte. Thus an 8AH is a
line feed, and an 8DH is a carriage return. M80 does not read the bytes in
this way. M80 ignores an 8AH that does not follow a CR. M80 reads an 8DH as
the end of the line.

An 8AH that does not follow a CR is a character of the line. The result
depends on the place of the 8AH:

- In a string, the 8AH is the byte 0AH. `DB 'A<8AH>B'` is 41 0A 42. M80
  gives 41 42.
- In a comment, the 8AH is ignored.
- In the arguments of a macro call, and in the list of an `IRP` or `IRPC`,
  the 8AH is text, and MAC passes the text to the macro. `MM A<8AH>B` with a body of
  `DB '&P'` is 41 0A 42.
- Anywhere else, the 8AH is an error. MAC flags the 8AH with error code `E`.

An 8DH ends the statement, in a comment too. After the 8DH, MAC reads the
next item, after any blanks, as the line feed that should follow a CR. The
next item is one of these:

- a word or a number
- a string
- one other character
- a comment to the next CR

The rest of the line is the next statement. Examples:

- `DB 1 ;X<8DH><TAB>DB 2` is 01. MAC treats `DB` as the line feed, and `2` is
  a line number.
- With `X<TAB>DB 2` after the 8DH, the result is 01 02.
- M80 gives 01 02 for both.

An 8DH 8AH or CR 8AH is a line end in M80, MAC, RMAC and um80.

When MAC treats the CR of a line as that line feed, the next line starts with
a line feed. MAC flags the line feed with error code `S`, and so does um80.

#### `MACLIB NAME` reads `NAME.LIB`

In um80 with `--dri`, `MACLIB NAME` reads `NAME.LIB`, as in MAC and RMAC, and
then `NAME.MAC`. Before, um80 with `--dri` looked at `NAME.MAC`.

Example: the statement `maclib diskdef` of DRI reads `DISKDEF.LIB`. The
statement `maclib diskdef` is in `CONTROL/RESXIOS.ASM` in MP/M II and in
`os4bios.asm` in CP/M 2.0.

The programs read the file as follows:

- MAC reads `NAME.LIB` whatever extension follows the name. MAC flags
  `MACLIB NAME.MAC` `S`.
- um80 with `--dri` reads the file named.
- M80 reads a `MACLIB` file as an `INCLUDE` file, `NAME.MAC`. um80 without
  `--dri` does the same.

In either mode, um80 searches for a file by its name as written, and then in
upper case and in lower case, because a CP/M file name has no case. On a file
system where case matters:

- `maclib diskdef` finds `DISKDEF.LIB`.
- `include inc` finds `INC.MAC`.

Two sources of DRI assemble to known output:

- With `--dri -t`, um80 assembles `CONTROL/RESXIOS.ASM` of MP/M II to the REL
  file that RMAC 1.1 writes.
- With `--dri --aseg`, um80 assembles `os4bios.asm` of CP/M 2.0, with the
  `DISKDEF.LIB` of MP/M II, to the bytes that MAC 2.0 writes.

#### A `MACLIB` library is read in pass 1 only

um80 with `--dri` reads a macro library in pass 1 only, as MAC and RMAC do.
The library supplies its macros and the symbols that the library defines.
um80 assembles none of the code or data of the library. An `ORG` or a macro
call in the library assembles nothing. A symbol that the library defines keeps
the value that pass 1 gave to the symbol.

##### Values that pass 1 gives

- With a library of `DB 1`, a `DB 2` after the `MACLIB` is 02, at the location
  that the `MACLIB` left.
- With `LL: DB 1` in the library, `DW LL` is the address that pass 1 gave
  `LL`. That address is the address of the `DW` itself.
- A `SET` in a library gives the symbol the value that the symbol has at the
  end of pass 1. With `X SET 1` in the library, then `DB X / X SET 2 / DB X`
  in the source, the result is 02 02.

##### Size of a segment

The size of the program, of the data and of each `COMMON` block is the most
that pass 1 reached in the segment. The size counts the code and the data of
the library, wherever the library leaves the location counter. Two examples,
as in RMAC:

- With a library of `DB 1`, a `DB 2` after the `MACLIB` makes the program 2
  bytes long, one of them loaded.
- With `DSEG / BUF: DS 10 / CSEG`, the data is 10 bytes long, so that the linker
  puts the data of another module after `BUF`.

##### How RMAC and um80 differ in the size

RMAC writes the location counter of a
segment at the end of pass 1, at the first `END` that RMAC reads. The `END` of
a library counts too. um80 writes the most that pass 1 reached, as M80 does.
The difference has two results:

- After an `ORG` to a lower address, the size of RMAC is smaller.
  `ORG 180H / DB 9 / ORG 100H / DB 2` is 101H long in RMAC and 181H in um80.
- With a library that ends in `END`, RMAC does not count the program after the
  `MACLIB` in the size.

##### Other cases of a library

- The code of a `MACLIB` can move a label or an `EQU $` that follows the
  `MACLIB`. Then MAC and RMAC put the label where pass 1 put the label, and
  flag the label `P`. um80 reports a phase error.
- DRI's libraries hold macros and `EQU`s only. MAC, RMAC and um80 read these
  libraries alike.
- M80 reads a `MACLIB` file as an `INCLUDE` file, in both passes. um80 without
  `--dri` does the same.

##### Two differences of um80

- A library has an `EQU` for a symbol that the source defines further down. In
  um80, the `EQU` has the value of that symbol. In MAC the value is 0, because
  MAC reads the library once.
- um80 reads a `MACLIB` inside a library. MAC and RMAC do not read the inner
  `MACLIB`, and a symbol that the inner `MACLIB` defines is `U`. M80 flags the
  `MACLIB` `O`.

#### A label on an `ORG` is the location the `ORG` sets

In MAC, RMAC and um80 with `--dri`, a label on an `ORG` is the location that
the `ORG` sets. M80 gives such a label the location before the `ORG`, and so
does um80 without `--dri`.

Source text | M80 | MAC and RMAC | um80 without `--dri` | um80 with `--dri`
--- | --- | --- | --- | ---
`DB 1 / LAB ORG 300H / DW LAB` | `LAB` is 0101H | `LAB` is 0300H, and `DW LAB` puts 0300H at 0300H | `LAB` is 0101H | `LAB` is 0300H
`LAB ORG $+4` | the location before the `ORG` | the location after the gap | the location before the `ORG` | the location after the gap

A label on a `DS` is where the `DS` starts in all three.

A label on an `ORG` whose operand reads a symbol that is defined further down
is an error. The results:

- MAC and RMAC give the label the location before the `ORG`, which their pass
  1 gave to the label. MAC and RMAC flag the label `P`. `DB 1 / LAB ORG X / DW
  LAB / X EQU 200H` is 01 01 01.
- um80 reads pass 1 again until such a read has the final value of the symbol.
  um80 would give the label 0200H.

An `ORG` of such a symbol with no label is no error in MAC, and no error in
um80.

MAC and RMAC flag other forward reads `P`, and um80 resolves the forward
reads with no message. The section Known issues in the CHANGELOG lists these two cases:

- `X EQU Y` with `Y` further down. In MAC, X is 0.
- A label after a `DS` of a symbol further down. M80 flags the label `P` too.

#### `END` of a symbol that is not defined takes no start address

MAC and RMAC read nothing after an `END`. In `END START` with `START` below
the `END`, the symbol is not defined, so MAC and RMAC take no start address
and flag nothing. The same is true for any operand that reads a symbol that is
not defined (`END FOO`, `END START+1`). The REL file of RMAC has no start
address.

Source text | M80 | MAC and RMAC | um80 without `--dri`
--- | --- | --- | ---
`END START` with `START` below the `END` | flags `U` | no start address, nothing flagged | flags `U` (an error)

#### An `END` in a `MACLIB` library ends the library

MAC and RMAC end the read of a library at the `END` of the library. MAC and
RMAC continue with the source after the `MACLIB`. The address on that `END` is
not the start address. M80 reads a `MACLIB` file as an `INCLUDE` file, so the `END` of the
file ends the source.

Program | What an `END` in a macro library does
--- | ---
M80 | ends the source
MAC and RMAC | ends the library, and the address on the `END` is not the start address
um80 without `--dri` | ends the source, with a warning
um80 with `--dri` | ends the library

#### Where MAC, RMAC and M80 agree

Where MAC, RMAC and M80 agree, um80 behaves that way with or without
`--dri`:

- um80 clears bit 7 of each source byte. A line that ends with CR 8AH is a
  line end.
- um80 accepts an indented name on an `EQU`, `SET` or `MACRO`.
- In 8080 code, a register name is a number in any expression. `RD EQU D` then
  `DAD RD` is `DAD D`. `DB B` is 00.
- A `<...>` group inside a macro argument or an `IRP` item loses its brackets
  wherever the group is. `MM 1<2>3` passes `123`. The macro call does not pass
  `1<2>3`, which the relational operators of MAC would read.
- A parenthesis in the arguments of a macro call is text, so a comma inside a
  parenthesis ends the argument. `MM (A,B),C` passes `(A`, `B)` and C. `MM
  A),B,C` passes `A)`, B and C.

#### MP/M II sources need `--dri`

The sources of MP/M II need `--dri`. These four sources show the reason:

File | What the source does
--- | ---
`NUCLEUS/MPM.ASM` | stores to `nmb$lst`, which `DATAPG.ASM` defines as `nmblst`
`RESBDOS1.ASM` | calls both `SET$DMABUFA` and `SET$DMA$BUFA`
`CLI.ASM` | defines `cli$slct$user` and uses `cli$slctuser`
`BNKBDOS.ASM` | defines `getmemseg` and calls `GET$MEM$SEG`

The results with `--dri`:

- Copies of the sources, with the names spelled one way, give REL files.
  With `um80 --dri -t`, the unmodified `MPM.ASM`, `CLI.ASM`, `MEMMGR.ASM`,
  `RESBDOS1.ASM` (with `CONBDOS.ASM`) and `BNKBDOS/BNKBDOS.ASM` assemble to
  the same REL files as the copies give.
- The build with `--dri -t` uses the `NUCLEUS` sources of DRI. The sources are
  changed only where `VER.ASM` and `RESBDOS1.ASM` carry the serial number
  placeholder `'654321'`. Then the V2.0 files XDOS.SPR, BNKXDOS.SPR,
  RESBDOS.SPR and TMP.SPR are the files of DRI byte for byte.
- Built with `--dri -t`, BNKBDOS.SPR from the unmodified `BNKBDOS.ASM` is
  the V2.1 file of DRI.
- `um80 --dri --aseg` assembles `MPMLDR/LDRBDOS.ASM` to exactly the bytes at
  0D00H-164CH of MPMLDR.COM (V2.0 and V2.1) that MPMLDR.COM loads.
- Every other assembler source in the MP/M II release of DRI that um80
  assembles without `--dri` assembles to the same REL file with `--dri`.
  One source is an exception to the same REL file:
  - `UTIL1/DDT2MON.ASM`, assembled relocatable, has `LOW(DEMON)-1`. With
    `--dri`, `LOW(DEMON)-1` is `LOW(DEMON-1)` for the linker, as MAC reads it.
    The byte is the same.
  - With `--aseg`, as a MAC source, the REL file of `UTIL1/DDT2MON.ASM` is
    the same too.
- `PUSH A`, a label with no colon and a `*` comment line need `--dri`. For
  this reason, `BNKBDOS.ASM`, `BDOS30.ASM`, `RESBDOS1.ASM` and
  `UTIL3/GENHEX.ASM` assemble only with `--dri`.

#### `--dri` does not imply the other options

`--dri` does not imply the other options that a DRI source may need:

- `--aseg`, for the sources of MAC. MAC has no relocatable segments, so the
  `ORG` of MAC is an absolute address. The sources of RMAC are relocatable,
  like the sources of M80.
- `-t`, for the REL files of RMAC. RMAC, like M80, writes the first six
  characters of a `PUBLIC` or `EXTRN` name (and an external made with `##`).
  The nucleus of MP/M II depends on the six-character names: the `extrn
  userprocess` of `DSPTCH.ASM` is the `userpr` of `MEMMGR.ASM`.

#### A difference that `--dri` does not cover

MAC and RMAC have one more difference from M80 that `--dri` does not cover.
None of the sources of MP/M II needs the difference. MAC stops the read at a 9AH
byte (1AH with bit 7). M80 continues to read.

### Register Names as Values (EQU of a register)

In 8080 code, M80, MAC, RMAC and um80 do two things:

- Each register name has a number in any expression.
- A register operand is read as an expression.

The numbers are:

| Name | B | C | D | E | H | L | M | A | SP | PSW |
|------|---|---|---|---|---|---|---|---|----|-----|
| Value | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 6 | 6 |

When an `EQU` gives a register name to a symbol, the symbol then names that
register:

```asm
UR      EQU     B                   ; 0
MR      EQU     E                   ; 3
RD      EQU     D                   ; 2
        MVI MR,0                    ; MVI E,0
        MOV A,UR                    ; MOV A,B
        DAD RD                      ; DAD D   (19H)
        PUSH RD                     ; PUSH D  (D5H)
```

#### Register pair operands

A register pair operand is the number of the first register of the pair. The
numbers are:

- 0 is B (BC).
- 2 is D (DE).
- 4 is H (HL).
- 6 is SP or PSW, whichever the instruction takes.

Any expression with an absolute value is correct. Examples:

- `DAD 2` is `DAD D`.
- `PUSH 6` is `PUSH PSW`.
- `LXI SP-2,0` is `LXI H,0`.
- `MOV A,2` is `MOV A,D`.

A name that is defined further down in the source is correct too. The name
can also be the name of an instruction. In the example below, `RP EQU H` is
below `DAD RP`:

| Source text | M80 | MAC and RMAC | um80 without `--dri` | um80 with `--dri` |
|-------------|-----|--------------|----------------------|-------------------|
| `DAD RP` | `DAD H` (29H) | `S` and `V` (see the list below) | `DAD H` (29H), as in M80 | error |

For `DAD RP`, MAC and RMAC act as follows:

- MAC and RMAC take no instruction name for a symbol.
- MAC and RMAC flag `RP EQU H` `S`.
- MAC and RMAC read `RP` in `DAD RP` as the opcode of `RP` and flag `V`.

um80 reports these cases as errors, as M80 (error code `A`) and MAC (error
code `R` or `V`) do:

- An odd number for a pair (`DAD E`, `DAD 1`).
- `LDAX`/`STAX` of anything but B or D.
- A number above 7 for a register.

um80 also reads `BC`, `DE` and `HL` as B, D and H.

#### Addresses as numbers

As in M80, an address is a number too. The number is one of two values:

- For a label, the offset of the label in its segment.
- For an external symbol, the constant of the external symbol (`Y+2` is 2).

Examples:

- With `LAB` two bytes into the code, `DAD LAB` is `DAD D`.
- With `Y` EXTRN, `MOV A,Y` is `MOV A,B`.

| Source text | M80 | RMAC | um80 |
|-------------|-----|------|------|
| `DAD LAB` | no flag | `V` | warning |
| `MOV A,Y` | no flag | `V` | warning |

MAC has no relocatable values. In MAC, a label is its address. So `DAD LAB`
is an error in MAC only when the address is not the number of a register.

Anything else that is calculated from an address is an error in um80, as it
was in 0.3.50. Examples are `HIGH LAB` and `LAB-Y`.

#### Register pair values up to 0.3.50

Up to 0.3.50, um80 read the value for a register pair as the encoding of
the pair itself (0 BC, 1 DE, 2 HL, 3 SP). So `RD EQU D` then `DAD RD` was `DAD H`.
um80 read an odd value, with no message, as the pair of the register below
the odd value.

#### A register name as a value in any expression

The number is the value of the name in any expression, not only in a
register operand. M80 and MAC give these results alike:

- `X EQU D+1` is 3 (`MOV A,X` is 7BH).
- `DB B` is 00.
- `MVI A,B` is 3E 00.
- `JMP B` is C3 00 00.
- `OUT A` is D3 07.
- `IF B EQ 0` is true.

Up to 0.3.50, um80 stopped at each of these statements with "Register 'B'
used as value".

M80 also reads `BC`, `DE` and `HL` as 0, 2 and 4. In MAC, these names are
undefined. um80 reads the names as M80 does.

#### Where the programs differ for register names

Two register names in one expression (`A*256+B`, `C-B`, `A EQ B`):

| Source text | M80 | MAC | um80 without `--dri` | um80 with `--dri` |
|-------------|-----|-----|----------------------|-------------------|
| `A*256+B`, `C-B`, `A EQ B` | error code `O`, though M80 evaluates the expression | no error code | reports the expression | accepts the expression |

Through symbols (`X EQU A`, `Y EQU B`, `X-Y`), neither M80 nor MAC flags
anything.

A program can define a symbol that has the name of a register. MAC flags the
symbol `S`. M80 then reads the name as the symbol everywhere, in a register
operand too. um80 does the same. Examples:

- After `C EQU 2`, `MOV A,C` is `MOV A,D` and `DB C` is 02.
- After `A: NOP`, `DW A` is the label.

In 8080 code, M80 gives its internal numbers to the Z80 names and to the
conditions:

- The Z80 names: `IX` 44H, `IY` 64H, `AF` 6, `I` 8, `R` 9.
- The conditions: `Z` 1, `PE` 5.

MAC reports these names undefined. um80 does the same.

In Z80 code (`.Z80`), M80 gives every register name the value 0 in an
expression.

Example: `X EQU B` then `LD A,X` is `LD A,0`. um80 reports such an
expression. Two more rules apply in Z80 code:

- A symbol with the name of a register is the symbol there too. After
  `C: NOP`, `JP C` jumps to the symbol.
- A register operand is still the register. After `B EQU 9`, `LD A,B` is
  `LD A,B`, where M80 loads 9.

### PUSH A / POP A

MAC and RMAC read `PUSH A` and `POP A` as `PUSH PSW` and `POP PSW`.
`um80 --dri` does the same. The same rule applies to `PUSH 7`, and to any
register pair operand whose value is the 7 of A.

The example below is for `um80 --dri`:

```asm
        PUSH A                      ; Same as PUSH PSW, with --dri
        POP A                       ; Same as POP PSW, with --dri
```

MP/M II uses these statements in `BNKBDOS.ASM`, `RESBDOS1.ASM` and
`BDOS30.ASM`. The results of `PUSH A` and `POP A` are:

| Source text | M80 | MAC and RMAC | um80 without `--dri` | um80 with `--dri` |
|-------------|-----|--------------|----------------------|-------------------|
| `PUSH A`, `POP A` | error code `A` (M80 pushes PSW) | `PUSH PSW`, `POP PSW` | error | `PUSH PSW`, `POP PSW` |

Up to 0.3.50, um80 without `--dri` read `PUSH A` as `PUSH PSW` and rejected
`PUSH 7`. The other odd numbers (`PUSH 1`, `DAD 7`, `DAD A`) are errors in
all three.

### The first word of a statement

A label is a name with a colon after the name, in any column. A `::` after
the name also makes the label `PUBLIC`.

Otherwise, the first word of a statement is its operation, in column 1 or
not, as in M80 3.44. The exception is the name of
an `EQU`, `SET`, `DEFL`, `ASET` or `MACRO` directive. The name is before the
directive. For example, `NOP EQU 5` defines `NOP`, as in M80.

Example with the first word in column 1:

```asm
IF DEBUG                            ; IF, in column 1
        CALL TRACE
ENDIF
NOP                                 ; 00
DB      7                           ; 07
END
```

Up to 0.3.50, um80 read any word in column 1 as a label. So `NOP`, `RET`,
`END` or `DB 7` in column 1 assembled nothing, with no message. An `ENDM` or
a `LOCAL` in column 1 was never seen.

#### Words before a directive in a macro body

M80 reads the lines of the body of a `MACRO`, `IRP` or `IRPC` that M80
defines. In each line, M80 finds these items:

- The `ENDM` that ends the body.
- The `MACRO`, `REPT`, `IRP` and `IRPC` that nest in the body.
- The `LOCAL` names.

M80 also finds these items after a word that is not an instruction or a
directive. Such a word is a label with no colon (in any column), the name of a
macro, or a word made with `&`. um80 does the same. Examples:

- `LAB ENDM`, `<TAB>LAB<TAB>ENDM` and `L&P ENDM` end the body. The word is
  not defined.
- `LAB REPT 2` opens a block that the next `ENDM` ends. The statement is an
  error where the body expands, as M80 flags the statement `U`.
- `LAB LOCAL QQ` declares `QQ`.

After an instruction or a directive, the word is the operand of the
instruction or directive. `NOP ENDM` ends nothing. A third word is not read
(`LAB FOO ENDM`).

M80 reads the body of a `REPT` for the first word only. So `LAB ENDM` does
not end the body of a `REPT`.

With `--dri`, um80 reads a word made with `&` as a label like any other
label, as MAC and RMAC do. MAC and RMAC define the label where the body ends
(`L&P ENDM`).

#### A statement of values

A statement can have a first word that is not an instruction, a directive or
a macro. In M80, the statement is a list of values that M80 assembles as
`DB`. um80 does the same and also writes a warning. Examples:

- After `FOO EQU 5`, `FOO` alone is the byte 05.
- `FOO+1,'AB'` is 06 41 42.
- `LAB: 5,6` (a statement that starts with a value) is 05 06.

Up to 0.3.50, um80 did not assemble a statement that started with a value,
with no message.

#### A label with no colon

M80 has no label without a colon. So `OBP DS 1` is an error: `OBP` is
undefined (M80: `U`). `<TAB>FOO<TAB>NOP` is an error too.

For `<TAB>FOO<TAB>NOP`, um80 gives a hint. The hint tells you to add the
colon or to read the source with `--dri`. With `--dri`, the word is a label,
as in MAC and RMAC ([DRI sources](#dri-sources---dri)).

#### Comments, line numbers and directives of M80

In um80, a line that starts with `*` is not a comment, as in M80. The
exception is `*EJECT` of M80 in column 1. A line number is not a comment
either.

`$TITLE('text')` (a subtitle) and `$EJECT` are directives of M80.

### External Symbol Aliases (EQU external+offset)

um80 accepts the definition of a symbol as an alias of an external symbol,
with an optional offset:

```asm
        EXTRN   ROUTINE         ; External symbol
        PUBLIC  ROUTINE_ALT     ; Export the alias

; Define alias as external + offset
ROUTINE_ALT EQU ROUTINE+2       ; ROUTINE_ALT = ROUTINE + 2
```

**Use cases:**

1. **Alternate entry points:** Skip the initialization code in a routine:
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

2. **Structure field offsets:** Access fields in structures that are defined
   elsewhere:
   ```asm
           EXTRN   BUFFER
           PUBLIC  BUF_LEN
           PUBLIC  BUF_DATA
   BUF_LEN  EQU BUFFER          ; Length at offset 0
   BUF_DATA EQU BUFFER+2        ; Data at offset 2
   ```

3. **z88dk compatibility:** The z88dk project uses this pattern in many
   places in its math libraries:
   ```asm
   ; z88dk pattern for alternate return points
           EXTRN   mm48__add10
           PUBLIC  am48_dpopret
   am48_dpopret EQU mm48__add10+1
   ```

**How it works:**

- When an `EQU` has an external symbol (with an optional offset), um80
  records the symbol as an "external alias".
- When the code uses the alias, um80 writes an external reference with the
  combined offset.
- When the program declares the alias PUBLIC, um80 writes the public symbol in
  a special entry point format: `NEWNAME=EXTERNAL+N`.
- ul80 detects this format. ul80 resolves the alias after ul80 loads all the
  modules.

**Limitations:**

- Another module in the same link must define the base external symbol.
- Aliases cannot be chained (ALIAS2 EQU ALIAS1+N, where ALIAS1 is also an
  alias).
- The offset must be a constant expression.

---

## ul80 Linker Extensions

### `__END__` Predefined Symbol

ul80 automatically provides a `__END__` symbol. The symbol points to the first
free byte after all linked segments, and after any absolute code that is
loaded above the segments:

```asm
        EXTRN   __END__             ; Import linker symbol

START:  LXI     H,__END__           ; Load end of program
        SHLD    HEAP                ; Initialize heap pointer
        ; ... allocate from HEAP upward ...

        DSEG
HEAP:   DW      0                   ; Heap pointer storage
```

The symbol `__END__` is useful for these tasks:
- To allocate memory (the heap starts at `__END__`)
- To find the program size at runtime
- To initialize memory pools

### MP/M PRL Format Support

ul80 can write the two page-relocatable formats of MP/M:

```bash
ul80 --prl program.rel                  # Transient .PRL, linked at 100H
ul80 --prl --extra 1000 -o pip.prl a.rel b.rel
ul80 --spr -o xdos.spr a.rel b.rel      # System page .SPR/.RSP, linked at 0
```

Each format has three parts:

- a 256-byte header
- the image
- a relocation bitmap, with one bit for each byte of the image

MP/M adds the load page to each byte that the relocation bitmap marks.

The options are:

- **`--prl`** is for a transient. MP/M loads a PRL file at
  `segment_bottom + 100H`. But the relocator of MP/M adds only the base page
  of the segment. Therefore ul80 links the image at 100H, exactly like a
  `.COM`.
- **`--spr`** is for a system page (`.SPR`, `.RSP`, `.BRS`). MP/M loads a
  system page at the segment base itself. ul80 links the image at 0.
- **`--extra HEX`** gives the memory that a `.PRL` asks for beyond its image.
  The memory is for storage that a PL/M program places at `.MEMORY`. The value
  is the third argument of GENMOD (`genmod pip.hex pip.prl $1000`).

#### Page-zero symbols in PRL files and SPR files

Under MP/M, page zero belongs to the memory segment of the process.
Therefore, in either format, ul80 marks for relocation a resolved reference to
an absolute symbol below 100H. Examples of such a symbol:

- the BDOS entry at 0005H
- the default FCB at 005CH
- the DMA buffer at 0080H

The symbol decides, not the symbol plus an offset. For example, ul80
marks `TBUF+80H` (0100H) with TBUF. An absolute symbol at or above 100H stays
absolute.

ul80 cannot tell a page-zero address from a small constant. A `PUBLIC`
constant below 100H that another module uses (`NFILES EQU 10`) is relocated
too. Therefore put a definition of such a constant in each module that needs
the constant.

#### Symbols that move with the program in PRL files and SPR files

ul80 calculates `__END__`, `__BSS_START` and `__BSS_END` as absolute values.
But the three symbols are addresses in the program, and the symbols move with
the program. Therefore ul80 marks a reference to one of the symbols like any
program address. The same is true for a reference to a `PUBLIC` alias of one
of the symbols. An example is the `.MEMORY` of PL/M (`HT EQU __END__`).

#### HIGH and LOW in the relocation bitmap

The relocation bitmap has a mark for:

- a byte that is `HIGH` of an address
- a word that is an address

The relocation bitmap has no mark for a byte that is `LOW` of an address.
Adding a page never changes a low byte.

`(BUF+255)/256` is the same as `HIGH(BUF+255)`. `BUF MOD 256` is the same as
`LOW(BUF)`.

A link-time expression can have a value that would not move by exactly 0 or 1
page. Examples are `HIGH(A)+HIGH(B)`, `200H-LAB` and `LAB*2`. The relocation
bitmap cannot express such an expression. In either format, such an
expression is an error.

### Link-time expressions (REL extension link items)

Take `MVI A,LOW(BUF+128)` with BUF in a relocatable segment. The instruction
needs a byte of an address that nobody knows until link time. MACRO-80 3.44
and LINK-80 3.44 handle this case with special link item 4, the "extension
link item". The B-field of the item starts with a kind byte. Three kinds form
a postfix program for the linker.

| Item | Bytes | Meaning |
|------|-------|---------|
| `A` | 41H, op | operator (see the table of operator numbers below) |
| `B` | 42H, name | push the value of external symbol *name* |
| `C` | 43H, type, lo, hi | push a value. Type 0 absolute, 1 program, 2 data, 3 common relative |

The operator numbers of the kind `A` are:

| op | Operator |
|----|----------|
| 1 | store as byte |
| 2 | store as word |
| 3 | HIGH |
| 4 | LOW |
| 5 | NOT |
| 6 | unary minus |
| 7 | minus |
| 8 | plus |
| 9 | multiply |
| 10 | divide |
| 11 | MOD |

#### Evaluation of the postfix program

Operands are pushed in source order. A binary operator pops the right operand
first.

Every expression ends in a store operator. The store operator writes the
result at the current location counter. The field itself follows as
placeholder bytes with the value zero. The placeholder bytes load at that
location and advance the counter.

So `MVI A,LOW(BUF+128)` becomes these items, in this order:

1. the absolute byte 3EH
2. `C(data, BUF) C(abs, 128) A(plus) A(LOW) A(store byte)`
3. the placeholder 00H

#### An address and a constant are separate operands

An address and a constant that is added to the address are separate operands,
as M80 writes them. For example, `HIGH(5+C1)` is
`C(abs, 5) C(common, C1) A(plus) A(HIGH)`.

The separate operands are not only a matter of form. LINK-80 3.44 gives a wrong value
for a COMMON-relative `C` value that is past the end of its block. For
example, C1 is at the start of a 300H-byte block. Then `HIGH(C1+400H)` links
correctly only as `C(common, C1) C(abs, 400H) A(plus)`.
In a CSEG or DSEG value, L80 handles an offset of any size.

#### A symbol is one value

A symbol is one value, as in M80. After `X EQU C1+400H`, `HIGH X` is
`C(common, C1+400H) A(HIGH)`. A word is folded too: `DW C1+400H` is one
COMMON-relative word.

L80 gives a wrong value in both cases. The wrong value is the same for the
REL files of M80 and for the REL files of um80. ul80 gives the correct value
in both cases.

#### Constant folding in um80

um80 folds constant subexpressions. `2*3` is `C(abs, 6)`. M80 writes
`C C A(*)`. When um80 folds a subexpression, the `.REL` changes but the linked value
does not.

#### Listing of a link-time field

The listing (`um80 -l`) shows such a field as the placeholder that the `.REL`
carries. The listing marks the field after its last byte, in the way that the
listing of MACRO-80 marks a value that the linker finishes. The marks are:

- `'` program relative
- `"` data relative
- `!` COMMON
- `*` external

The listing marks an expression `*` if the expression uses an external.
Otherwise the listing marks the expression with the mark of its first
relocatable operand.

With BUF at DSEG 0300H, the listing shows these fields:

| Source text | M80 lists | um80 lists |
|-------------|-----------|------------|
| `MVI A,HIGH(BUF)` | `3E 03"` | `3E 00"` |
| `DW EXT+2` | `0002*` | `00 00*` |

In the listing of M80, the byte 03H in `3E 03"` is in neither the `.REL` nor
the program. In the listing of M80, `0002*` is the constant of item 9 of M80.

A relocatable word shows its offset, as in M80. For example, `DW BUF` lists
`00 03"`.

#### How the extension kinds were found

The published Microsoft manual defines only the item 4 container and a COBOL
overlay sentinel, 35H. Test sources that the genuine M80 3.44
assembled established the kinds `A`, `B` and `C`. The REL files of these
sources were then linked with L80 3.44 under a CP/M emulator.

The LINK-80 of Digital Research lists item 4 as unused. RMAC rejects
`LOW`/`HIGH` of a relocatable value with an `E` error.

#### Where um80 writes extension items

um80 writes these items for:

- `HIGH`, `LOW`, `NOT`, unary minus, `*`, `/` and `MOD` applied to a
  relocatable or external value
- any relocatable or external value in a one-byte field (`MVI A,BUF`,
  `DB LAB`, an `(IX+d)` displacement), as M80 does
- a word that is not simply an address plus a constant (`-LAB`, `LAB+LAB2`,
  `DATALAB-CODELAB`, `n-EXT`, `EXT1+EXT2`, `HIGH(EXT)`)

#### Operators that have no linker operator

The linker has no operator for `AND`, `OR`, `XOR`, `SHL`, `SHR` and the
comparisons. Therefore the operand of such an operator cannot be a
relocatable or external value in an instruction operand or in a `DB`/`DW`
operand. If the operand is such a value, the statement is an error. In M80,
the error code is `R`.

An `EQU` or `SET` to a link-time expression stands for the expression
wherever the symbol is used. Such a symbol cannot be `PUBLIC`.

#### Evaluation of link-time expressions by ul80

ul80 evaluates the expressions after ul80 places every module. ul80 writes the
results over the placeholders, for every output format. ul80 also reads
objects that the real M80 wrote. ul80 evaluates the link-time expressions of
these objects in the same way.

### Objects LINK-80 reads, and objects MACRO-80 writes

In the points below, the `.REL` files of um80 now follow the Microsoft format.
Earlier releases did not follow the format in these points.
As a result, the genuine LINK-80 3.44 (L80) loads the `.REL` files of um80.
Also, ul80 links what M80 3.44 writes.

A four-way link test checked each point.
The test links the same program four ways: M80+L80, M80+ul80, um80+L80,
um80+ul80.

#### End program and program size items

- Special item 14 (end program) carries its A-field, the start address
  (absolute 0 if none).
- Item 13 (program size) is typed program relative.
- The segment and COMMON sizes come first in the module, as M80 writes them.
- L80 needs the size of a COMMON block before anything refers to the block.

#### External plus offset

`JMP EXT+3` is item 9 (External plus offset) with `A` = 3.
For `EXT-1`, `A` is FFFFH.
Item 9 is immediately before the word.
The word is a reference in the chain of EXT.

- um80 used to put the constant in the name of the chain (`EXT+3`).
  L80 treats that name as an undefined symbol.
  ul80 still reads the old form.
- ul80 applies items 9 and 8.
- ul80 follows the chains of M80 through every reference.
  Each chain entry is typed by its relocation.

#### A chain head of absolute 0

A chain head of absolute 0 is an empty chain.
M80 writes one for an external symbol that an expression alone uses.
Because a chain head of absolute 0 is an empty chain, a reference *at*
absolute 0 is written as an extension item `B(EXT) A(store word)`.

#### Named COMMON blocks

Each named COMMON block is placed on its own.

- Special item 1 comes before a COMMON-relative word, extension value,
  public, chain head or set-location.
  The item 1 is there when the word, extension value, public, chain
  head or set-location refers to another block than the one selected last.
- Bytes assembled into a COMMON block load there (DB, FORTRAN's BLOCK DATA).
- Bytes load into the block that was selected at the last set-location, in
  ul80 as in L80.
- M80 selects another block for an operand inside a COMMON block.
  M80 does not select back.
  What follows still loads into the first block.

#### A REL file with several modules

A `.REL` that holds several modules loads every one of the modules.
An example is a LIB-80 library such as FORLIB.REL of FORTRAN-80.
`ulib80 -c` stores each of the modules as a module of its own.

#### Data size item 10

Every module carries item 10 (data size).
The data size is 0 when the module has no DSEG, as M80 writes it.

Without item 10, L80 drops the constant of an item 9 in ASEG.
In that case, `DW EXT+1` in ASEG links to EXT.

#### Set-location item of an ASEG directive

The set-location item of an `ASEG` directive is held back until something is
loaded or reserved in the segment, as M80 does.
An `ORG` or another segment directive before then replaces the item.

L80 takes a set-location to ASEG 0000H for code loaded there.
So `ASEG` / `ORG 100H` made L80 write a `.COM` that starts at 0000H.

#### A chain entry typed absolute

A chain entry typed absolute is an address in ASEG.
M80 and RMAC of DRI chain a CSEG reference to a reference in ASEG that way.

- Exception: a REL file from um80 0.3.48 or earlier has item 14 without an
  A-field.
  In such a REL file, the chain entry is an offset in the segment of the word
  that holds the chain entry.
- um80 0.2.0 to 0.3.34 chained all the references to an external through
  such untyped chain entries.
  Each chain entry was the offset of the previous reference in whichever
  segment that reference was in.
  The chain entry does not say which segment.
  An old REL file whose references to one external are in more than one
  segment does not link right.
  Assemble the source of the old REL file again.
- um80 0.3.35 to 0.3.48 wrote a chain of one for each reference.
  The chain entry of such a chain is 0 however one reads the chain entry.

#### Chain address item 12

Special item 12 (chain address) fills every word of the chain that the item
heads.
The item fills each word with the address of the location where the item
appears.

FORTRAN-80 writes every forward reference that way.
The forward references are:

- a jump to a label further down
- a FORMAT string
- a constant after the code

#### A byte loaded over a word that is not finished

The linker handles a byte loaded over a word that it has yet to finish as
L80 handles the byte.

- L80 relocates a word as L80 loads the word.
- L80 fills an item-12 chain when L80 reads the item.
- A byte that loads over the word later replaces the byte that was there
  before.
  The other byte of the word keeps its finished value.
- Examples of a byte that loads over the word later:
  - an `ORG` back
  - a `COMMON` block declared again (every `COMMON` statement starts at the
    beginning of its block)
  - another module that loads the same COMMON bytes
- L80 fills the chain of an external after L80 loads both the module and the
  module that defines the external.
  What a later module loads over the chain stays.
- Items 8 and 9 and link-time expressions are applied at the end of the
  link, to whatever is there then.

#### The public symbol `$MEMRY`

If a module defines the public symbol `$MEMRY`, the word at `$MEMRY` gets
an address.
The address is the first free byte after the data area, as L80 stores the
address.
FORLIB of FORTRAN-80 allocates its file buffers from the word.

- L80 overwrites the word, whatever the module loaded in the word.
- L80 uses the end of the data area even when `/D` puts the data area below
  the program.
- In the layout of ul80, data and COMMON after the code, the end of the data
  area is `__END__`.

#### Check with FORLIB

An F80 program linked against FORLIB with `ul80 -x t.rel forlib.lib` gives
the same image as `L80 /P:100/D:19D3,T,FORLIB/S`.
In the L80 command, `/D` is where ul80 puts the data.
The image is 0100H through 1BCDH.
A second F80 program, with a subroutine, a function and `STOP`, does the
same.

`forlib.lib` is FORLIB.REL under another name.
ul80 searches a file named `.lib` and loads every module of a `.rel`.

#### What still differs

The four-way link test did 52 test links.
In 40 of the links, all four ways (M80+L80, M80+ul80, um80+L80, um80+ul80)
give the same bytes.
The links that differ do so only in the cases below.
The genuine Microsoft M80 and L80 3.44 were used to check each case.

##### M80 3.44 miscompiles, um80 does not

M80 assembles these expressions with a wrong value:

- `DW -LAB`
- `DW LAB*2`
- `DW EXT*2`
- `DB HIGH(BUF)*2`
- other expressions of the same kind
- the distance between two COMMON blocks, which M80 assembles as a constant

The REL files of um80 link to the arithmetically right value in L80 and ul80
alike.
The REL files of M80 do not, in either linker.

##### M80 3.44 undercounts a segment after an `ORG` back

The segment size of M80 is the largest of the locations set and the location
at the end.
The size ignores bytes loaded past the highest `ORG`.

- `ORG 20H` / `DB 1` / `ORG 10H` / `DB 2` is 20H bytes in M80.
  L80 links the next module over the 1.
- um80 writes the largest size that the segment reached, 21H.

um80 puts each byte where M80 puts the byte.
The rule that um80 puts each byte where M80 puts the byte includes two cases:

- A segment directive continues at the highest location set, not where the
  segment was left.
- Every `COMMON` statement starts at the beginning of its block.

##### A forward read of a `SET` symbol

Consider a read of the symbol X that comes before the `SET`s of X.
The two assemblers give different values:

- um80 reads the value that the last `SET` gives X.
  Every symbol has its final value.
- M80 3.44 reads the value that X had at the end of its pass 1, with no
  message.
  M80 calculates the value while the symbols defined further down had none
  yet (0).

M80 and um80 agree unless that value depends on a symbol defined below the
`SET`.
The table gives two examples.

| Source text | M80 | um80 |
|---|---|---|
| `DW X` / `X SET Y+1` / `DW X` / `Y EQU 5` | 01 00 06 00 | 06 00 06 00 |
| `DW X` / `X SET 1` / `X SET 2` | 02 00 | 02 00 |

For the first example, um80 0.3.48 also gives 01 00 06 00.

Of 173 random programs of forward `EQU`s, `SET`s, `DS` and `IF` that M80
assembles without an error, 19 differ.
Each difference comes from such a read.
um80 0.3.48 matched M80 in 17 of the 19.

A forward `EQU` chain is not silent in M80.
`MVI A,X` / `X EQU FWD+1` / `FWD EQU 5` is flagged `U` and assembles to 01
in M80.
um80 assembles 6.

##### L80 3.44 gives a wrong value for a COMMON-relative value past the end of its block

The cases are an `EQU` of such a value and a `DW` of such a value.
L80 gives the same wrong bytes for the REL files of M80 and for the REL files
of um80.
ul80 calculates the values right.

##### The linkers place the program differently

The difference is the same for the REL files of M80 as for the REL files of
um80, in each linker.

| Item | L80 | ul80 |
|---|---|---|
| COMMON and data | L80 puts COMMON at the start of the data area, before the data of the modules, with `/D` or without. Without `/D`, L80 loads the data of each module immediately before the code of the module. With `/D` set to the end of the code, L80 puts all code, then all data, but still puts COMMON first. | ul80 puts all the code, then all the data, then COMMON. |
| Absolute code, without `/D` | L80 starts the program area of a module above the absolute code that loaded before the module. | ul80 also starts the program area of a module above the absolute code that loaded before the module. |
| Absolute code, with `/D` given | L80 does not start the program area of a module above the absolute code that loaded before the module. L80 loads the code over the absolute code, with no message. L80 also refuses some links: the links that have absolute code above the program or data area that L80 meets ("?Intersecting Program area", "?Intersecting Data area"). | ul80 has no counterpart of `/D`. |
| Start address of the `.COM` | L80 writes a `.COM` from 0100H whatever `/P` says. With `/P:200`, the program starts 100H bytes into the file. | ul80 writes the `.COM` from `-p`. Because ul80 writes the `.COM` from `-p`, `-p` gives a raw image for another address, such as a ROM at E000H. |
| A set-location item to ASEG 0000H | L80 treats the item as code loaded there. | ul80 does not treat the item as code loaded there. |

The links with absolute code are compared with L80 run without `/D`, on
modules with no data.
There the two layouts are the same.

`ASEG` / `ORG 0` / `DS 103H` and a CSEG module after the `DS 103H` put the
module at 0103H in both linkers.
L80 writes the `.COM` from 0000H (384 bytes, the module 103H bytes in).
ul80 writes the `.COM` from 0100H.

um80 writes the set-location item, as M80 does, only when something is loaded
or reserved in ASEG before an `ORG` replaces the item.

##### Library search

ul80 searches the libraries, each in turn and its modules in library order,
until nothing more loads.
The `/S` of LINK-80 makes one pass.
A reference to a module earlier in the library than the module that makes
the reference stays undefined in L80 ("Undefined Global").
ul80 loads the module.

Of 150 random library links, L80 links 127 cleanly.
The 127 links are byte-identical.
The 18 differences are all such backward references.

##### A COMMON block declared larger the second time

L80 keeps the size of the first declaration ("%2nd COMMON Larger").
ul80 keeps the largest size.

#### The option `/D` in a comparison with L80

ul80 has no counterpart of `/D`.
To compare with L80, give L80 the option `/D:` with the address where ul80
puts the data (the end of the code).

#### Repeat the checks under `cpmemu`

To repeat these checks under `cpmemu`, run M80, L80 and F80 from a
configuration file that sets `default_mode = binary` and
`eol_convert = false`.

By default, cpmemu writes a file that the CP/M program creates as text.
cpmemu stops at the first 1AH and deletes the CR of a CR LF.
A `.COM` or `.REL` that holds those bytes comes out cut short or altered.
L80 seemed to write a 1-byte `.COM` for a program that starts with `21 1A 01`.

### Absolute assembly (`--aseg`)

M80 starts a file in CSEG, so an `ORG` is an offset within a relocatable
segment.

MAC has no relocatable segments. The sources of MAC are absolute. In MAC, an
`ORG` is an absolute address.

`um80 --aseg` starts the file in ASEG. With this option, um80 assembles MAC
sources the way MAC does.

### Absolute code in a link

#### Where ul80 places the code of a module

ul80 places the code of each module after the code of the previous module.
The exception is the following case: the modules before the module loaded absolute
(`ASEG`) code that reaches higher. Then the code of the module starts above
the highest absolute location that the earlier modules reached. That location
is one of these:

- a byte that a module loaded
- a location that an `ORG` or `DS` set, with nothing loaded after the `ORG`
  or `DS`.

L80 3.44 has the same rule when you do not give the L80 option `/D`. ul80
has no `/D`. L80 3.44 was probed under cpmemu. The probes show that the rule
holds in these cases:

- The rule holds with `/P` and without `/P`.
- The rule holds when there is free space below the absolute code. Example:
  `ASEG` / `ORG 200H` in one module, then a CSEG module, linked `/P:100`. The
  CSEG starts at 0204H.

These statements also apply:

- Absolute code below the origin moves nothing.
- The absolute code of a module does not move the code of the same module.
  The reason is that L80 allocates the program area of a module before L80
  loads anything in the program area.
- In ul80, the data and the COMMON blocks follow all the code, as always.
- `__END__` is past absolute code that a module loads above the program, as L80
  stores `$MEMRY`. Therefore `$MEMRY` and the `.MEMORY` of PL/M are past this
  code too.
- Only the bytes that a module loads go into the image. The gap that an `ORG`
  or `DS` leaves in absolute code does not overwrite the code of another
  module in that gap.

#### Absolute code that overlaps other code

Absolute code that lands on something else is an error. ul80 writes no
output. The error occurs when the absolute code lands on one of these:

- the program area of a module (its own, or the program area of an earlier
  module)
- the data or COMMON that follow all the code
- absolute code that another module loaded.

Example: a module has `ASEG` / `ORG 100H` / `JMP START`, then a CSEG in the
same module. ul80 links the module at the default origin of ul80, 0100H. ul80
gives this error:

```
Error: Module X: absolute code at 0100H-0102H overlaps its own program area (0100H-0115H)
```

In the same case, L80 writes the warning "%Overlaying Program area" (or "Data
area") and writes a mixture of the two. The default origin of L80 is 0103H.
This origin leaves room for exactly such a jump. Link the program with
`-p 103`.

An `ORG` that returns to the absolute bytes of the same module is not an
overlap. The
later bytes load, as they do in the assembler.

#### Overlap on purpose (`--allow-overlap`)

Some modules load over code on purpose. Two examples are a patch module that
is linked after the program, and an overlay. For such a link,
`ul80 --allow-overlap` makes each of these errors a warning and writes the
image. In the image, the byte that was loaded last is at each address:

- a byte of a later module over a byte of an earlier module
- in one module, the byte that the module loaded later, whether absolute or
  not.

L80 writes this image when you give L80 the option `/D`. Without `/D`, L80
keeps some of the earlier bytes.

When something is loaded over a relocatable word, the word keeps the
relocated byte that nothing replaced, as in L80. L80 relocates a word as L80
loads the word.

### A global defined twice (`--fatal-mult-def`)

When a second module defines a global that a module loaded before it defines,
L80 3.44 does three things:

- L80 3.44 writes `%Mult. Def. Global FOO`.
- L80 3.44 binds every reference to the first definition.
- L80 3.44 writes the program.

ul80 does the same. ul80 also says which modules define the global and which
definition ul80 uses:

```
Warning: %Mult. Def. Global FOO: defined in A and in B; A's definition is used
```

The exit status is 0, as the program is linked. Link lines depend on this
exit status. Example: the GENSYS link of MP/M II overrides ten names of its
runtime with the names of `X0100.ASM`, which is linked first.

Some links need a different result. For a link where a global defined twice is
a mistake, `ul80 --fatal-mult-def` makes the global defined twice an error.
Such a mistake once sent four calls to `PRINTB` in CLI and ATTACH of MP/M II
to the wrong routine. With `--fatal-mult-def`, ul80 writes no output and exits
1.

Up to 0.3.50, ul80 printed "Error: Multiply defined global" but wrote the
output and exited 0.

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

- **Unreleased**
  - `--dri`:
    - `'AB'` is 4241H
    - `IF` is true when bit 0 is set
    - `MACLIB NAME` reads `NAME.LIB` in pass 1 only
    - a label on an `ORG` is the location it sets
    - `END` of a symbol not defined takes no start address
    - `IRP`/`IRPC` lists and division as MAC reads them
    - `MOV M,M` is 76H
    - `"` quotes nothing
  - M80's unary sign and signed `/` and `MOD`
  - an empty `DB`/`DW` operand is 0
  - `.CREF`/`.XCREF`
  - a label that moves between the passes is a phase error
  - `LOCAL` after a `!`
  - a label on `IF`, `ELSE`, `ENDIF` and `EXITM`
- **0.3.51**
  - `--dri`, as in MAC and RMAC:
    - a `$` inside a name is ignored
    - a word with no colon may be a label
    - `PUSH A` is `PUSH PSW`
    - `=` is `EQ`
    - `HIGH` binds loosest
  - as in M80:
    - an instruction or directive in column 1 is one
    - a statement of values is a `DB`
  - as in M80 and MAC: in 8080 code a register name is its number in any
    expression
  - ul80 `--fatal-mult-def`
- **0.3.50** — MACRO-80 IRP/IRPC lists, 6-character `-t`, mbasic2025 in the test suite
- **0.3.49** — link-time expressions (REL extension link items), LINK-80 interchange, absolute code in a link
- **0.3.48** — `--spr`, `--extra` and `--aseg`, and `--prl` links a transient at 100H
- **0.3.33** — External symbol aliases (EQU external+offset) for z88dk compatibility
- **0.3.21** — Extended REL format for long symbols, `-t/--truncate` switch
- **0.3.20** — DRI extensions (!, HIGH(), $, register aliases, PUSH A)
- Earlier versions focused on M80/L80 compatibility
