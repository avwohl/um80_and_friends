# Changelog

All notable changes to the um80 toolchain are documented here.

## [Unreleased]

The 0.3.51 release gate found the differences below between um80 and the
genuine MACRO-80 3.44, DRI's MAC 2.0 and RMAC 1.1, three of them the
`--dri` Known issues of 0.3.51. Each expected result was confirmed with the
genuine tools under cpmemu, and each has a regression test that fails on
0.3.51.

### Fixed
- um80 assembler: with `--dri`, a two-character string used as a value has
  its first character in the low byte, as in MAC and RMAC: `DW 'AB'` is 41
  42, `LXI H,'AB'` 21 41 42, `DB ('AB') SHR 8` 42, and `IF 'AB' EQ 4241H`
  is true. um80 --dri gave M80's order (42 41, 21 42 41, 41), without a
  word. Without `--dri` it is still M80's, `'AB'` = 4142H.
- um80 assembler: with `--dri`, an `IF` is true only when bit 0 of its
  value is set, as in MAC and RMAC: `IF 2`, `IF 100H`, `IF 0FFFEH` and `IF
  NOT 1` are false. um80 --dri took any value but 0 as true, as M80 does,
  without a word. `IFT`, `IFE`, `IF1`, `IFDEF` and the other `IF`s MAC does
  not have (MAC reads `IFT 2` as a label) keep M80's meaning with `--dri`.
- um80 assembler: with `--dri`, `MACLIB NAME` reads `NAME.LIB`, as MAC and
  RMAC do, and then `NAME.MAC`, which um80 --dri read before: DRI's
  `maclib diskdef` (MP/M II's `CONTROL/RESXIOS.ASM`, CP/M 2.0's
  `os4bios.asm`) was "Cannot find include file". Without `--dri` it is
  `NAME.MAC`, as in M80, and the error says MAC reads `NAME.LIB`. A file
  that `INCLUDE`, `MACLIB` or `--pre` names is looked for as written, and
  then in upper and in lower case, as a CP/M file name has no case; the
  error names the files looked for. `RESXIOS.ASM` with `--dri -t` now
  assembles to RMAC 1.1's object.
- um80 assembler: a label whose address in pass 2 is not the one pass 1
  gave it, or an EQU whose value changed, is an error, a phase error, where
  nothing read it before: M80 flags such a label P and keeps its address from
  pass 1 (an EQU M), and so do MAC and RMAC (P). um80 took the address of
  pass 2, without a word: `IF2 / DB 1 / ENDIF / LAB: NOP / DW LAB` was 01 00
  01 01, where M80 assembles 01 00 00 01. `IFDEF` of a symbol defined further
  down, which is false in pass 1 and true in pass 2, moved labels so too. (A
  symbol read before it moved was already a phase error.)
- um80 assembler: with `--dri`, a `MACLIB` library is read in pass 1 only,
  as MAC and RMAC read it: its macros and the symbols it defines are there,
  but none of its code or data is assembled, an `ORG` or a macro call in it
  assembles nothing, and a symbol it defines keeps its value of pass 1.
  With a library of `DB 1`, `DB 2` after the `MACLIB` is now 02, and with
  `LL: DB 1`, `DW LL` is 00 01 at 0100H, as in MAC; um80 --dri assembled
  the library as an `INCLUDE` file (01 02, 01 00 01), without a word. A
  `SET` in a library gives the symbol its value at the end of pass 1. The
  program's size is the most pass 1 reached, as RMAC writes it, and a label
  a library's code moved is a phase error, as MAC and RMAC flag it (P).
  DRI's libraries hold macros and `EQU`s only, which are read as before.
- um80 assembler: a `LOCAL` after a `!` in a macro body declares its names,
  as in MAC and RMAC: `NOP! LOCAL QQ`, `LOCAL QQ! NOP`, `LOCAL QQ,RR! NOP`
  and `NOP! LOCAL QQ! NOP`, and with `--dri` `LOCAL QQ ;c! NOP`, `NOP ;c!
  LOCAL QQ` and `MM ;c! LOCAL QQ`. um80 read a body line for its first
  statement only, so a second expansion said "QQ multiply defined", and
  `LOCAL QQ! NOP` declared `QQ! NOP` and left out the `NOP`. (M80 has no `!`
  separator: it reads `LOCAL QQ! NOP` as `LOCAL QQ` alone.)
- um80 assembler: with `--dri`, `END START` with `START` defined after the
  `END` takes no start address and is no error, as in MAC and RMAC, which
  read nothing after an `END`; so does any operand that reads a symbol not
  defined (`END FOO`, `END START+1`). um80 --dri reported it undefined. M80
  flags it U, and so does um80 without `--dri`.
- um80 assembler: with `--dri`, a label on an `ORG` is the location the
  `ORG` sets, as in MAC and RMAC: `DB 1 / LAB ORG 300H / DW LAB` is 01 at
  0100H and 00 03 at 0300H. um80 --dri gave it the location before the
  `ORG`, as M80 does (01 01 at 0300H), without a word; without `--dri` it
  still does. (MP/M II's `tools/genmod.py` refused a label on an `ORG`
  line for that.)
- um80 assembler: a label on an `IF`, `ELSE`, `ENDIF` or `EXITM` line is
  defined, where the line before it was assembled, as in M80, MAC and RMAC:
  `LAB: IF 0`, `LAB: ELSE` and `LAB: ENDIF` after a true `IF`, and `LAB:
  EXITM` in a macro, a `REPT`, an `IRP` or an `IRPC`, are the location there.
  um80 defined none of them (a use of one was "Undefined symbol"). A label
  on an `ELSE` or `ENDIF` after a false `IF`, or on any line inside one, is
  still not defined, as in all three.
- um80 assembler: a unary minus or plus applies to the term after it,
  before `*`, `/`, `MOD`, `SHL` and `SHR`, as in M80 3.44: `-1 SHR 8` is
  00FFH and `-2 SHR 1` 7FFFH (um80: 0 and 0FFFFH, MAC's reading, without a
  word). `/` and `MOD` divide signed, as in M80: 8000H/2 is 0C000H, 0FFFEH/2
  0FFFFH, 7/-2 0FFFDH (the quotient rounds toward 0), and the remainder has
  the sign of the quotient, so 4 MOD -3 and -4 MOD 3 are 0FFFFH and -4 MOD -3
  is 1 (um80: 4000H, 7FFFH, 0, 4, 0FFFFH, 0FFFCH). With `--dri` both are
  MAC's and RMAC's: the sign applies to all that follows it, and division is
  unsigned. `x MOD 0` is `x`, as in all three, where um80 reported a
  division by zero; with `--dri` `x/0` is 0FFFFH, as in MAC and RMAC, which
  flag neither (um80 warns); without it `x/0` is still an error (M80: O).
- um80 assembler: M80's `.CREF` and `.XCREF` (cross-reference listing on
  and off) are accepted and assemble nothing, as in M80; um80 reported
  them as "Unknown instruction or directive".
- um80 assembler: with `--dri`, `MOV M,M` (and `MOV 6,M`) is 76H, HLT's
  opcode, as MAC and RMAC assemble it without a flag. um80 reported it in
  either mode; M80 flags it A, and without `--dri` it is still an error.
- um80 assembler: with `--dri`, a string in double quotes is an error, as
  MAC and RMAC quote a string with `'` only and flag `DB "A"`, `DW "A"` and
  `MVI A,"A"` E (they assemble 00). um80 --dri read it as a string, as M80
  does, without a word; without `--dri` it still does.
- um80 assembler: an empty operand in a `DB` or a `DW` is 0, as in M80: `DB`
  with none is 00, `DB 1,` 01 00 and `DB 1,,2` 01 00 02 (M80 flags them Q),
  and `DW` is 00 00 and `DW 1,` 01 00 00 00; `DW ''` is 00 00. um80
  assembled nothing for `DB`, `DW` or a comma at the end, so every address
  after it moved, without a word, and `DW ''` was an error. um80 warns. With
  `--dri` each is an error, as MAC and RMAC flag it E.
- um80 assembler: with `--dri`, an 8AH in the arguments of a macro call, or
  the list of an `IRP` or `IRPC`, is a LF there, which MAC and RMAC pass on
  as text: `MM A`, 8AH, `B` with a body of `DB '&P'` is 41 0A 42, and so is
  `IRPC X,A`, 8AH, `B`. um80 --dri reported a line feed outside a string, and
  took a LF right after the macro's name, or in an `IRPC` string, for a
  blank. Without `--dri` an 8AH there is left out, as in M80 (41 42).
- um80 assembler: with `--dri`, the list of an `IRP` and the string of an
  `IRPC` are read as MAC and RMAC read them, as a macro call's argument: a
  group's brackets go wherever they are, what is outside them is text of the
  list too, and a comma inside the outer group separates items. `IRP
  X,<"A>B">` is the one item `"AB">`, `IRP X,<1,2>3` goes round 1 and 23,
  `IRP X,A<1,2>` A1 and 2, and `IRPC X,A<B>C` A, B and C. um80 --dri ended
  the list at the `>` that matches its `<`, as M80 does, and warned about
  the rest (`"A`; 1 and 2; A; A, `<`, B, `>`, C). Text after the list, but
  for a `!` statement, is an error, as MAC and RMAC flag it S (`IRP
  X,<1,2>,3`, `IRPC X,AB CD`; `IRP X,1,2`, which went round 1 and 2).

## [0.3.51] - 2026-09-26

Building MP/M II (https://github.com/avwohl/mpm2) from Digital Research's
unmodified sources found the defects below, and so did assembling DRI's
`CONTROL` macro libraries (`SELECT`, `STACK`, `SEQIO`, `COMPARE`, `DISKDEF`,
...) and dropping the workarounds uplm80 carries for um80. Each expected
result was confirmed with the genuine MACRO-80 3.44, DRI's MAC 2.0 and RMAC
1.1, and LINK-80 3.44 under cpmemu, and each has a regression test that fails
on 0.3.50.

### Added
- um80 assembler: `--dri` reads a source as DRI's MAC and RMAC read it where
  they differ from MACRO-80, in the ways this section and
  `docs/EXTENSIONS.md` list; three it does not follow yet are under Known
  issues. It ignores a `$` inside a name, as MAC and RMAC
  do: `NMB$LST` and `NMBLST` are one symbol, and `PUBLIC A$BC` writes `ABC`. A
  `$` that starts a word (the location counter), and one in a quoted string or
  a comment, are kept, and so is one in the arguments of a macro call or the
  list of an `IRP` or `IRPC`, which MAC and RMAC read as text: `PRINT HELLO$`
  passes `HELLO$`, so `DB '&MSG'` keeps its BDOS terminator, and `IRPC C,12$3`
  iterates four times. A macro body is matched to its formal parameters as
  written, with MAC's names and RMAC's rules for an `&` in a string, and an
  `IF` a macro body leaves open ends with it (see Fixed). Without `--dri` a
  `$` is part of the name, as in M80, where `LDA NMB$LST` after `NMBLST EQU 5`
  is an undefined symbol and `AB EQU 1` with `A$B EQU 2` defines two symbols.
  MP/M II's sources spell names both ways (`MPM.ASM` stores to `nmb$lst`,
  which `DATAPG.ASM` defines as `nmblst`). With `--dri -t`, DRI's unmodified
  `MPM.ASM`, `CLI.ASM`, `MEMMGR.ASM`, `RESBDOS1.ASM` and `BNKBDOS.ASM`
  assemble to the objects the copies mpm2 edits to one spelling give. The V2.0
  nucleus - XDOS, BNKXDOS, RESBDOS and TMP - built with `--dri -t` from DRI's
  `NUCLEUS` sources, changed only to carry DRI's serial number, is DRI's byte
  for byte, and BNKBDOS.SPR from the unmodified `BNKBDOS.ASM` is DRI's V2.1
  file. `--dri --aseg` assembles `MPMLDR/LDRBDOS.ASM` to the bytes at
  0D00H-164CH of MPMLDR.COM (V2.0 and V2.1). `--dri` does not imply `--aseg`
  or `-t`; `docs/EXTENSIONS.md` says exactly what it changes.
- um80 assembler: with `--dri`, the first word of a statement that is no
  instruction, directive or macro is a label, colon or not, in any column, as
  in MAC and RMAC: `OBP DS 1` (MP/M II's `UTIL3/GENHEX.ASM`), `<TAB>LAB NOP`,
  and `HALT LXI H,1` in 8080 code. A line number in front of a statement
  (`00010 LAB: NOP`), a line that starts with `*` (a `!` still ends it, as in
  MAC) and MAC's assembly controls (`$-MACRO`) are ignored, as in MAC.
- um80 assembler: with `--dri`, `PUSH A`, `POP A` and `PUSH 7` are `PUSH PSW`
  and `POP PSW`, and an expression may have two register names in it
  (`A*256+B`), as in MAC and RMAC (see Changed).
- um80 assembler: with `--dri`, MAC's relational operators `=`, `<`, `<=`,
  `>`, `>=` and `<>` are `EQ`, `LT`, `LE`, `GT`, `GE` and `NE`, as in MAC's
  manual and RMAC (`IF @Y = 1`, in DRI's `CONTROL/DEBLOCK.ASM`), and a `<` or
  `>` in a list of values is an operator, not a bracket (`DW 1<2,3` is two
  words). And `HIGH` and `LOW` apply to all that follows them, as MAC's
  manual has them and MAC and RMAC read them: `HIGH(100H)+1` is `HIGH(101H)`,
  1, and `HIGH 1234H OR 0F00H` 1FH. M80 has no such operators (`O`), and
  applies `HIGH` and `LOW` to the term after them (2 and 0F12H), and so does
  um80 without `--dri`.
- um80 assembler: M80's `$TITLE('text')` (a subtitle) and `$EJECT`. um80 took
  `$TITLE` in column 1 for a label.
- ul80 linker: `--fatal-mult-def` makes a global that more than one module
  defines an error: ul80 writes no output and exits 1 (see Changed).

### Changed
- um80 assembler: a label needs a colon without `--dri`, as in MACRO-80 3.44,
  which has no label without one. um80 took a word in column 1 for a label
  (see Fixed); `OBP DS 1` is now an error, an undefined `OBP` (M80: `U`), with
  a hint to add the colon or read the source with `--dri`. So is a line that
  starts with `*` (M80: `U`, but for its `*EJECT` in column 1) or with a line
  number (M80: `O`); um80 left both out, without a word. DRI sources that
  have them - `CPM22.ASM`, `GENHEX.ASM`, MP/M II's `BNKBDOS.ASM` - need
  `--dri`. In a `MACRO`, `IRP` or `IRPC` body being defined a word
  with no colon in front of its `ENDM` is still read as M80 reads it (see
  Fixed).
- um80 assembler: `PUSH A` and `POP A` are an error without `--dri`, as M80
  flags them (`A`); with `--dri` they are `PUSH PSW` and `POP PSW`, as in MAC
  and RMAC, which also take `PUSH 7`. um80 took `PUSH A` for `PUSH PSW` in
  either mode (and rejected `PUSH 7`). MP/M II's `BNKBDOS.ASM`,
  `RESBDOS1.ASM` and `BDOS30.ASM` need `--dri`.
- ul80 linker: a global that a second module defines is now LINK-80's
  warning, with its message, `%Mult. Def. Global FOO`, and ul80 says which
  modules define it and whose definition every reference uses: the first one
  loaded, as in LINK-80. ul80 0.3.50 printed "Error: Multiply defined global"
  but wrote the output and exited 0, so a build script could not tell; that
  is how, once mpm2 cut names to six characters, four calls to `PRINTB` in
  MP/M II's CLI and ATTACH went to the wrong routine (a patch-area
  `PRINTBrlsfile` had become a second `PRINTB`). The exit status is still 0,
  as in LINK-80, which links the program, and link lines rely on it (uc80's
  `__sret_buf` link does); a script
  that must not link such a program passes `--fatal-mult-def`.

### Fixed
- um80 assembler: an instruction, a directive or a macro in column 1 is that,
  as in MACRO-80, MAC and RMAC. um80 took any word in column 1 without a colon
  for a label, so `NOP`, `RET`, `XCHG`, `END` or `DB 7` there assembled
  nothing, without a word, and `MVI A,5` there was "Unknown instruction or
  directive: A". An `ENDM` in column 1 did not end a `REPT` or a macro, so
  every line after it became its body, and a `LOCAL` in column 1 was a label
  in the expansion. The name in front of an `EQU`, `SET`, `DEFL`, `ASET` or
  `MACRO` is still a name, in any column (`NOP EQU 5` defines `NOP`, as in
  M80).
- um80 assembler: in a `MACRO`, `IRP` or `IRPC` body being defined, a word
  with no colon that is no instruction or directive - a label, in any column,
  a macro's name, or a word made with `&` - in front of an `ENDM`, `MACRO`,
  `REPT`, `IRP`, `IRPC` or `LOCAL` does not hide it, as in MACRO-80 3.44:
  `LAB ENDM`, `<TAB>LAB<TAB>ENDM` and `L&P ENDM` end the body (the word is not
  defined), `LAB REPT 2` opens a block the next `ENDM` ends, and `LAB LOCAL
  QQ` declares `QQ`. Once a label needed its colon, um80 took `LAB` for the
  operation and never saw the `ENDM`: `IRP X,<1,2> / DB X / LAB ENDM / DB 9`
  stored the rest of the file as the body, warned only "Unterminated IRP ...
  nothing after it was assembled", and exited 0 with an object without that
  code, where M80 and 0.3.50 assemble 01 02 09; `LAB LOCAL QQ` was an unknown
  instruction. 0.3.50 read neither `<TAB>LAB<TAB>ENDM` nor `L&P ENDM`. After
  an instruction or a directive the word is its operand, as in M80 (`NOP
  ENDM` and `DB ENDM` end nothing), and so is a third word (`LAB FOO ENDM`);
  M80 reads a `REPT` body for its first word only, and `LAB ENDM` does not end
  one, in M80 or um80. With `--dri` a word made with `&` is a label, as in MAC
  and RMAC: `L&P ENDM` ends the body and defines `L3` where it ends (after `MM
  3`), `L&P REPT 2` opens a `REPT`, and `L&P LOCAL QQ` declares `QQ`, where
  um80 --dri did not see them.
- um80 assembler: a name is read whole where it ends in the letters of a
  word operator (MOD, SHL, SHR, AND, OR, XOR, NOT, EQ, NE, LT, LE, GT, GE,
  HIGH, LOW, NUL, TYPE) and a `+` or `-` follows: `X1EQ+2`, `@P$NUL-1` and
  `X1LOW+1` are the symbol plus or minus the number, as in M80 and MAC. um80
  took the letters for the operator and the sign for its operand's, so each
  was "Cannot parse expression", and uplm80 renamed such names or wrote the
  offset first (`2+X1EQ`).
- um80 assembler: a symbol named like an operator is that symbol wherever
  the name occurs, as in M80, even when it is defined further down or
  EXTRN: after `EQ: NOP`, `DW EQ` is the label (um80: 0FFFFH, `0 EQ 0`, so
  `CALL EQ` called 0FFFFH, without a word); after `TYPE EQU 5`, `DB TYPE+2`
  is 07 (um80: TYPE of +2, 00); `NUL EQU 5` then `DB NUL` is 05. It is not
  the operator there, as in M80: `DB 1 EQ 1` is then an error (M80: `O`).
  MAC and RMAC do not let a program define such a name. An operator with
  nothing on one side - `DW EQ` or `DW SHL` with no such symbol, `DW 1 EQ` -
  is an error, as in M80 (`O`); um80 took the missing value for 0.
- um80 assembler: in 8080 code a register name is its number in any
  expression, as in M80 and MAC: `X EQU D+1` is 3 (`MOV A,X` is 7BH), `DB B`
  00, `MVI A,B` 3E 00, `LXI H,SP` 21 06 00, `JMP B` C3 00 00, `IF B EQ 0`
  true, `DB BC,DE,HL` (M80) 00 02 04. um80 stopped at each with "Register
  'B' used as value" - the number was a register operand's only. An
  expression with two register names in it (`A*256+B`) is an error without
  `--dri`, as M80 flags it (`O`); MAC takes it. A symbol named like a
  register is that symbol, as in M80, in a register operand too: after `C
  EQU 2`, `MOV A,C` is `MOV A,D` and `DB C` 02 (um80: `MOV A,C`, and an
  error). In Z80 code, where M80 makes every register name 0, a register
  name in an expression is still an error.
- um80 assembler: in Z80 code, `JP P` after a label `P` jumps to it, as in
  M80, and so do `JP Z`, `JP NZ`, `JP PE` and the rest after labels of those
  names, defined before or after the jump. um80 stopped with "JP with
  condition requires address", so uplm80 wrote `JP 0+P` for a jump to its
  procedure `P`. (M80 3.44 gets one defined further down wrong: its pass 1
  takes `JP P` for one byte, and it reports a phase error.)
- um80 assembler: `TYPE` of an expression that is not a name is its mode
  with the defined bit, as in M80: `TYPE 5`, `TYPE 'A'` and `TYPE +2` are
  20H, `TYPE (LAB)` with LAB in CSEG 21H. um80 gave 0 for all of them.
- um80 assembler: `END` ends the source, as in MACRO-80, MAC and RMAC,
  which read nothing after it - not the rest of the file, nor the rest of a
  macro, a `REPT` or an `INCLUDE` file that has one. um80 went on and
  assembled what followed (`DB 1 / END / DB 2` was 01 02), and a label
  after the `END` was defined, where all three report it undefined. An `END`
  in a false `IF` is still skipped. An `END` in a `MACLIB` file ends the
  source too, as in M80, which reads one as an `INCLUDE` file, and um80 says
  so in a warning; with `--dri` it ends only the library, as in MAC and RMAC,
  which go on after the `MACLIB` and take no start address from it.
- um80 assembler: a statement whose first word is no instruction, directive
  or macro is a list of values assembled as `DB`, as in M80: after `FOO EQU
  5`, `FOO` is the byte 05, `FOO+1,'AB'` is 06 41 42 and `LAB: 5,6` is 05 06.
  um80 left out a statement that started with a value (`LAB: 5,6`, `'AB'`),
  without a word. um80 warns, as M80 does not.
- um80 assembler: a source byte with bit 7 set is now read with bit 7
  clear, as MACRO-80, MAC and RMAC all read it. um80 read it as a character
  that no name or operator starts with, so a line that began with one was
  dropped without a word, and in a string it became FDH. MP/M II's
  `NUCLEUS/MEMMGR.ASM` ends six lines with CR and 8AH, a line feed with its
  parity bit set: the line after each was lost, one of them an `INX B`.
  A string of the bytes `a`, C1H and `b` is now 41H in the middle, as in
  M80, not FDH. CR 8AH and 8DH 8AH are a CR LF, and an 8DH is a CR, as in
  M80. Without `--dri` (see below for MAC's reading), an 8AH that does not
  follow a CR is left out, as M80 leaves it out:
  it ends no line in M80, MAC or RMAC, so `NOP ; ABC`, 8AH, `INX B` is still
  00 (the `INX B` is comment), as is a UTF-8 comment with an 8AH byte in it,
  and a string of `a`, 8AH and `b` is 61 62, as in M80 (0.3.50: 61 FD 62).
  A lone LF still ends a line, for files from Unix. This applies to the
  source, to `INCLUDE`/`MACLIB` files and to `--pre` files.
- um80 assembler: the name of an `EQU`, `SET`, `DEFL`, `ASET` or `MACRO` no
  longer has to be in column 1. M80, MAC and RMAC all take
  `<TAB>FOO<TAB>EQU 5`, even when FOO is also an instruction or a macro;
  um80 stopped with "Unknown instruction or directive: FOO". MP/M II's
  `MPMLDR/LDRBDOS.ASM` has `<TAB>arech  equ b! arecl  equ c`. A macro
  defined inside a macro with its name indented was not seen as nested, so
  its `ENDM` ended the outer macro; it is now nested, as in M80.
- um80 assembler: `RD EQU D` then `DAD RD` assembled `DAD H` (29H), and
  `PUSH RD` `PUSH H`. In 8080 code M80, MAC and RMAC give each register name
  a number - B 0, C 1, D 2, E 3, H 4, L 5, M 6, A 7, SP and PSW 6 - and read
  a register operand as an expression. um80 took the 2 of `RD EQU D` for a
  register pair's encoding, which is H. A register pair operand is now the
  number of its first register (0 B, 2 D, 4 H, 6 SP or PSW), so `DAD RD` is
  19H and `PUSH RD` D5H, as in M80. `X EQU SP` and `X EQU PSW` are 6 (they
  were 3). A register operand may be any expression, as in M80 and MAC:
  `DAD 2`, `MOV A,2`, `PUSH PSW+0` and a register name defined further down
  now assemble, as in M80 one named like an instruction too (`DAD RP` with
  `RP EQU H` below is 29H, `PUSH RP` with `RP EQU D` D5H, `MOV A,RZ` with `RZ
  EQU E` 7BH): on pass 1 such a name read as the instruction's opcode, and
  um80 stopped with "Invalid register pair for DAD: RP". MAC and RMAC take
  no instruction's name for a symbol (`S`), and read it as the opcode (`V`):
  with `--dri` it is still an error. An odd number for a register pair
  (`DAD E`, `PUSH 3`), which um80 took for the pair of the register below
  it, is an error, as in M80 and MAC. An address is read as M80 reads it,
  without a flag: a label's offset in its segment, or an external's
  constant, is the number, so with `LAB` two bytes into the code `DAD LAB`
  is `DAD D` (19H), and with `Y` EXTRN `MOV A,Y` is `MOV A,B`; um80 warns,
  and RMAC flags it V. 0.3.50 took the offset too, as the pair's encoding
  (`DAD H`), and rejected an external.
- um80 assembler: a macro argument written `%expression` is now the
  expression's value when the macro is called, as in MACRO-80, MAC and RMAC.
  um80 left the `%` in the argument and evaluated each `%` in a body line as
  that line was expanded, so a call in a `REPT` body inside a macro got the
  same value on every repetition: DRI's `CONTROL/SELECT.LIB` builds its case
  table so, and um80 gave `10 01 10 01 10 01` for M80's and MAC's `10 01 15
  01 1A 01` (and `LXI H,011FH` for `LXI H,013AH`). A body that changed the
  symbol before it used the argument read the new value; the value was not
  text, so `LB&N:` was a parse error and `DB '&N'` gave `%E`; and with
  `--dri`, where the argument keeps its `$`, `GEN %N$C` looked up `N$C` as
  written, an undefined name, and passed 0 without a word (MAC: the value of
  `NC`). The argument is now the value's digits in the current radix, as M80
  writes them (with `.RADIX 16`, 26 is `1A` and 160 `0A0`), and with `--dri`
  a name in the expression loses its `$`. M80 also evaluates a `%` after
  other text (`A%E` is `A7`); with `--dri` only an argument that starts with
  `%` is a value, as in MAC. A `%` in a body line that is not an argument is
  an error, as in M80 (O) and MAC (E); um80 evaluated it.
- um80 assembler: an undefined name in the expression of a `%` macro
  argument is now an error, as MACRO-80 (U, fatal) and MAC (U) report it.
  um80 passed 0 without a word, so a misspelt name, or without `--dri` a
  name written with a `$` that is defined without one, assembled wrong
  bytes. A forward reference is still its value.
- um80 assembler: without `--dri`, a `%` in an item of an `IRP` list is
  evaluated when the `IRP` is read, as MACRO-80 reads an item like a macro
  argument: `IRP X,<%E,2>` iterates over E's value and 2. um80 passed `%E`
  on as text, which was a parse error where the body used it. M80 flags a
  `%` in the last item O and passes 0; um80 takes the value and warns. MAC
  and RMAC read the list as text, and so does `--dri`.
- um80 assembler: a macro body is matched to its parameters name by name,
  as MACRO-80, MAC and RMAC read it. A parameter whose name starts with `?`
  or `@` was never replaced: DRI's `CONTROL/COMPARE.LIB` (`TDIG? SET
  '&?Y'-'0'`), `STACK.LIB` (`LHLD ADC&?C`), `NCOMPARE.LIB` and `Z80.LIB`
  (`?N`, `?DD`) could not be used. A parameter was replaced inside a longer
  name that has a `?`, `@`, `$` or `.` in it: with the parameter `FC`,
  `SEQIO.LIB`'s `IRPC ?FC,FC` became `IRPC ?X,X`, and with `X`, `?X`, `X?`,
  `@X`, `X@`, `X$1` and `A.X` were all changed. And `1X` was left alone, where
  M80 and MAC read 1 and then the parameter X. In M80 a name is letters,
  digits and `$ . ? @ _`; with `--dri` it is MAC's, letters, digits, `?`
  and `@`, and a `$`, `_` or `.` ends it (`X$1` is the parameter X, then
  `$1`).
- um80 assembler: in a quoted string in a macro body, the `&` next to a
  parameter now goes as it goes in MACRO-80, and with `--dri` as in RMAC. M80
  3.44 reads only `&X` in a string, and drops its `&` and one right after it
  (`'&X&Z'` is `KZ`; um80 gave `K&Z`). It then reads the rest of the line as
  if outside a string - its string loop keeps the quote in a register that
  reading the parameter's name overwrites - until a quote starts what it takes
  for another string. So `'&X''&Y'` is `K'L` and `'&X','&Y'` `K` and `L`, as
  written, but `'&X &X'` is `K &K` (um80: `K K`), `'&X ','&Y'` `K` and `&L`,
  `'&X"&Y'` `K"&L`, `'&X(X'` `K(K`, and in `'&X(',Z` the `Z` is inside a
  string to M80, so the symbol, not the argument. MAC and RMAC drop every `&`
  next to a parameter, and read a name before an `&` as one too: `'X&B'` is
  `KB` (M80: `X&B`). MAC 2.0 also matches a string's text as written, so
  `'&abc'` is not its parameter `ABC`; RMAC 1.1, M80 and um80 fold case.
- um80 assembler: the parameter of an `IRP` or `IRPC` is now replaced in its
  body as a macro's parameter is, as in MACRO-80, MAC and RMAC. um80 replaced
  it inside quoted strings without an `&` (`IRP X,<K>` with `DB 'X'` gave
  `K`; M80 and MAC `X`), inside longer names (`'A&XB'` gave `AKB`, `?X`
  `?K`), and left the `&` of `X&B`, a parse error.
- um80 assembler: a `LOCAL` name is now read as MACRO-80, MAC and RMAC read
  it, as a parameter of the macro. A local name with a `?` in it (`LOCAL
  L?,?L`, as DRI's `SEQIO.LIB` has `EOB?`) was not renamed, so the second
  expansion defined it again. The text of an argument was renamed as if
  the macro had written it: `MM LL`, with `LOCAL LL` and `DB P` in the body,
  read the local `LL`, not the `LL` outside (M80 and MAC: 33H there, um80
  the local's address). And `'&L'` in a string is now the unique name, as
  in M80 (`..0000`) and MAC (`??0001`); um80's is `L?0001`.
- um80 assembler: an `EXITM` inside a true `IF` now ends that `IF` with the
  expansion, as MACRO-80, MAC and RMAC end it. The `IF`'s `ENDIF` is never
  read, so um80 left it open to the end of the file and warned
  "Unterminated conditional (missing ENDIF)" where they report nothing:
  DRI's `CONTROL/INTER.LIB` `SETLITE` with `DEBUG` true, or `IF NUL P /
  EXITM / ENDIF` inside another `IF`. The same holds for an `EXITM` in a
  `REPT`, `IRP` or `IRPC` body.
- um80 assembler: with `--dri`, an `IF` that a macro expansion, or one
  repetition of a `REPT`, `IRP` or `IRPC`, leaves open now ends with it, as
  in MAC and RMAC. DRI's `CONTROL/COMPARE.LIB` ends its `TEST?` macro inside
  an `ELSE`, and `SEQIO.LIB`'s `FILLFCB` opens an `IF` in each repetition of
  an `IRPC`; um80 carried them on, so after a false one nothing more was
  assembled, and it warned "Unterminated conditional". Without `--dri` um80
  still carries them on, as M80 does.
- um80 assembler: a `;` inside `<...>` in the arguments of a macro call, or
  in the list of an `IRPC` or in a nested `<...>` in the list of an `IRP`,
  is now text, not the start of a comment, as in MACRO-80, MAC and RMAC.
  DRI's `CONTROL/DISKDEF.LIB` passes `<;sec per track>` to a macro whose
  body is `dw data comment`; um80 cut the line at the `;`, so the argument
  was `<` ("Cannot parse expression"). In the list of an `IRP` a `;` ends an
  item (see below).
- um80 assembler: an `IRPC` with an empty string (`IRPC C,`) is no longer
  an error. um80 stopped with "IRPC requires parameter and string", and the
  body's `ENDM` was then "ENDM without MACRO". MAC and RMAC go round once
  with the parameter empty, and so does `--dri`: DRI's `SEQIO.LIB` fills a
  file name with `IRPC ?FC,FC` and tests `NUL ?FC`, and `FILE` passes an
  empty type. MACRO-80 goes round once only where a macro's empty argument
  made the string empty (`IRPC C,P` with P empty), and not for `IRPC C,` or
  `IRPC C,<>` as written; without `--dri` um80 does the same.
- um80 assembler: with `--dri`, a label on the `ENDM` that ends a macro,
  `REPT`, `IRP` or `IRPC` body is defined where the body ends, each time it
  is expanded, as in MAC and RMAC. DRI's `CONTROL/STACK.LIB` ends `SIZ` with
  `STACK: ENDM` (a `LOCAL` name, the top of the stack it reserves),
  `COMPARE.LIB`'s `GTR` ends with `FL: ENDM` and `SEQIO.LIB`'s `FILLFCB`
  with `PFCB: ENDM`; um80 dropped the label, so each reference to it was
  undefined. MACRO-80 ignores such a label (a reference to it is U), and so
  does um80 without `--dri`. A label made with `&` on an `ENDM` (`L&X: ENDM`)
  now ends the body, as in M80, MAC and RMAC; um80 took every line after it
  into the body ("Unterminated IRP").
- um80 assembler: a `<...>` group inside a macro argument or an `IRP` item
  now loses its brackets wherever it is, and keeps its text, as in
  MACRO-80, MAC and RMAC: `MM 1<2>3` passes `123`, `MM 5<>5` `55`, `MM
  <1,2>3` `1,23`, and `IRP P,<1<2>3,4>` iterates over `123` and `4`. Only
  the outer brackets go (`1<2<3>4>5` is `12<3>45`). um80 dropped them only
  when they were the whole argument, so without `--dri` each was "Cannot
  parse expression", and with `--dri` MAC's relational operators read `DB
  P` as `(1<2)>3`, 0FFH, without a word. A `<` with no `>` is left out
  too, and um80 warns (M80 flags it `X`, MAC and RMAC `V`).
- um80 assembler: an item of an `IRP` list now ends where MACRO-80 ends it,
  at a `,`, a `;`, a blank or a tab: `IRP P,<A;B;C>` goes round three times,
  and `<A;;B>` and `<1,;2>` have an empty item in the middle. um80 had
  made a `;` in the list text, so `<A;B;C>` was one item, `A;B;C`, without
  a word (0.3.50 cut the line there, took `A`, and warned), and a macro's
  `IRP P,<Q>` called with `<1;2>` went round once. A blank ends an item too:
  `<A B>` is A and B, and `<A ,B>` and `<A >` have an empty item after A,
  as in M80; um80 took `A B` for one item. MAC and RMAC end an item at a
  comma, and flag a `;` in the list `B`: with `--dri` so does um80, and a
  `;` is an error. They skip a blank or a tab at the start of an item,
  before its first character (`<A, B>` and `< A,<TAB>B>` are A and B), and
  read any other blank otherwise: `<A ,B ,C>` is A, B and an empty item in
  MAC, `<A ,B,C>` A and C, `<A, ,B>` A and `,`, and `< ,A>` the one item
  `,` in MAC and RMAC, while RMAC stops at `<A ,B>` and writes nothing,
  without a word; MAC flags `<A B>` and `<A >`, where RMAC stops too. With
  `--dri` such a blank is an error; um80 took each list for the items
  between its commas, without a word. A blank inside a nested `<...>` is
  text in all three (`<A,<B C>>` is A and `B C`). A comma at the end of the
  list is an empty item, in M80, MAC and RMAC: `<A,>` is A and an empty
  item, and `<,>` two empty items; um80 dropped the last one. A `%` item is
  an expression to its `,` or `;` in M80 (`<%1 + 1,5>` is 2 and 5); MAC
  flags that list, and with `--dri` its blanks are an error.
- um80 assembler: with `--dri`, an 8AH or an 8DH inside a line is read as
  MAC and RMAC read it, not as M80 does. An 8AH that does not follow a CR
  is a line feed, a character of the line: in a string the byte 0AH (`DB
  'A`, 8AH, `B'` is 41 0A 42; M80 and um80 gave 41 42), in a comment
  nothing, and anywhere else an error, as MAC flags it (`E`). An 8DH ends
  the statement, in a comment too, and MAC then takes the next word or
  character, after any blanks, for the line feed that should follow a CR;
  the rest of the line is the next statement. So `DB 1 ;X`, 8DH, TAB `DB
  2` is 01 in MAC and RMAC, as in 0.3.50 - `DB` goes for the line feed,
  and `2` is a line number - where um80 `--dri` ended the line at the 8DH
  and assembled 01 02 without a word; `LAB: MVI A,1 ;LOAD`, 8DH, TAB `MVI
  B,2` is an error (MAC: `S`, 3E 01), not 3E 01 06 02. Where MAC takes the
  line's own CR for that line feed, the next line starts with a line feed,
  which MAC flags `S`, and so does um80. Without `--dri` nothing changes.
- um80 assembler: an empty macro argument, `IRP` item or `IRPC` character
  that a quoted string in the body takes (`'Z&P'`) is now a 00 byte there,
  as in MACRO-80, which passes an empty argument as a 00: `'Z&P'` is 5A 00,
  and `IRP P,<A;;B>` with `DB '&P'` is 41 00 42 (um80: 5A, and 41 42). MAC
  and RMAC pass nothing (5A), and so does um80 with `--dri`.
- um80 assembler: a `>` with no `<` open before it in a macro call's
  arguments no longer stops every later comma from ending an argument. um80
  took it for a closing bracket, so the bracket depth went below zero: `MM
  1>2,3` passed one argument, `1>2,3`. With `--dri` that was wrong bytes
  without a word - `DB P` and `DB Q` gave 00 03 and nothing, where MAC and
  RMAC read the `>` as text and pass `1>2` and 3 (00, 03); `MM A>B,C` with
  `DB 'Z&P'` and `DB 'Y&Q'` gave `ZA>B,C` and `Y` for MAC's `ZA>B` and `YC`.
  Now `--dri` reads it as MAC does. MACRO-80 ends the argument at such a
  `>`, as at a comma, and flags the line `Q`: `MM 1>2,3` passes 1, 2 and 3,
  `MM A>,B` A, an empty argument and B, and `MM <A>>B` A and B. Without
  `--dri` um80 now does the same, and warns; it had passed `1>2,3`, an
  error, or `A>B` (`MM <A>>B`) without a word.
- um80 assembler: a comma inside parentheses in a macro call's arguments now
  ends the argument, as in MACRO-80, MAC and RMAC, to which a parenthesis
  there is text: `MM (A,B),C` passes `(A`, `B)` and C. um80 kept the comma
  in the argument (`(A,B)` and C), and a `)` with no `(` or a `(` with no
  `)` stopped every later comma from ending an argument: `MM A),B,C` passed
  the one argument `A),B,C`, and `MM A(B,C` `A(B,C`, where the three tools
  pass `A)`, B and C, and `A(B` and C - with or without `--dri`, without a
  word. The operands of every other statement keep their parentheses.
- um80 assembler: a blank or a tab now ends a macro argument outside a
  quoted string and a `<...>` group, as in MACRO-80, MAC and RMAC. um80 kept
  it in the argument: `MM A B` passed `A B`, and `MM 1 + 1,5` `1 + 1` and 5,
  without a word. MACRO-80 reads the blanks after an argument as a
  separator, as a comma: `MM A B` passes A and B, `MM 5 GT 2,4` 5, GT, 2 and
  4, and `MM 1 + 1,5` 1, +, 1 and 5; a comma after the blanks is one more, so
  `MM A ,B` passes A, an empty argument and B (um80: A and B). Without
  `--dri` um80 now does the same. MAC and RMAC end the arguments at the
  blanks: a comma after them starts the next argument (`MM A ,B` is A and B,
  as before), a `;` or a `!` there ends the call's statement (see the `!`
  item below), and anything else they flag `S` and leave out (`MM A B` passes
  A); with `--dri` that is now an error. A `%` expression still runs to its
  comma, blanks and all (`MM %1 + 1,5` passes 2 and 5), and without `--dri`
  a `%` after a `<...>` group is now a value, as in M80: `MM <A>%1+1` passes
  A2, where um80 passed `A%1+1`.
- um80 assembler: without `--dri`, a `!` in a macro call's arguments or an
  `IRP` list now quotes a `;` after it, as in MACRO-80, which passes `MM
  A!;B` as the one argument `A;B`. um80 cut the line at its first `;`
  outside a string before it read the arguments, so it passed `A!`, and a
  `!`-quoted quote started a string that hid the comment: `MM A!"B;C` passed
  `A"B;C`, where M80 passes `A"B`. A quoted bracket there opens or closes no
  group either (`MM <A!>;B>` passes `A>;B`; um80 `A>`), and a quoted blank
  at the end of the arguments is kept (`MM A! ;B` passes `A `; um80 `A!`) -
  all without a word. With `--dri` the comment starts where it did; MAC and
  RMAC end the statement at the `!`.
- um80 assembler: with `--dri`, a `"` in a macro call's arguments or an `IRP`
  list is now text, as in MAC and RMAC, which quote a string with `'` only:
  `MM "A,B",C` passes `"A`, `B"` and C, `MM "A;B",C` passes `"A` (the rest
  is comment), and `IRP X,<"A,B">` goes round `"A` and `B"`. um80 read
  `"A,B"` and `"A;B"` as strings, as M80 does, and passed them and C,
  without a word. In the string of an `IRPC` a `"` is text in M80 too:
  `IRPC X,"A;B"` goes round `"` and A in all three, where um80 went round
  `"`, A, `;`, B and `"`, with or without `--dri`.
- um80 assembler: with `--dri`, a `<` or a `>` in a macro argument that
  starts with `%` is now MAC's relational operator, not a bracket: `MM
  %1<2,3` passes 65535 (1<2 is true) and 3, as in MAC and RMAC (FF 03 from
  `DB P` and `DB Q`). um80 read `<2,3` as a `<...>` group that ran to the
  end of the line, and reported "Cannot parse expression", and a `;` after
  such a `<` was not a comment (`MM %1<2;X`).
- um80 assembler: a `%` with no expression after it in a macro argument is
  now 0, as in MACRO-80, which passes `MM %` as 0 and `MM A%` as A0, and
  goes round 0 and A for `IRP X,<%,A>`, without a flag; um80 passed `%`,
  without a word. MAC and RMAC pass 0 and flag it `E`; with `--dri` it is
  now an error.
- um80 assembler: with `--dri`, a `!` inside a `;` comment now ends the
  comment and starts the next statement, as in MAC and RMAC: `NOP ;c! DB 1`
  is 00 01, and `; text! DB 1` is 01. DRI's sources rely on it: CP/M 2.0's
  CCP has `nosub: ;no submit file! call del$sub` and `mov d,a ;save value!
  mov a,b ;mult by 10`, and MP/M II's `disk2_files/ldrbios.asm` `;<TAB>in
  0f5h ! ani 2 ! rz`. um80 `--dri` read the comment to the end of the line
  and left those statements out, without a word: 1523 of the 1887 bytes MAC
  assembles from the CCP differed, and 298 of LDRBIOS's 414; both are now
  MAC's byte for byte. A quote in the comment starts no string (`NOP ;it's!
  DB 1`), a `*` comment line ends at a `!` whatever is in it (`* it's! DB 1`,
  `* a;b! DB 1`), and a `;;` comment in a macro body is left out only up to
  its `!` (`NOP ;;c! DB 7` is stored as `NOP! DB 7`). What follows the `!` is
  a statement like any other: an `IF` or an `ENDIF`, the first statement of
  the body of a `REPT`, `IRP` or `IRPC` on that line (`IRPC X,AB ;c! DB
  '&X'`), or, in a line of a body being defined, the `MACRO`, `REPT`,
  `IRP`, `IRPC` or `ENDM` that nests in it: `NOP! ENDM` and `NOP ;c! ENDM`
  end the body after the `NOP`, as in MAC, where um80 went on to the end of
  the file ("Unterminated MACRO"). With `--dri` what follows a macro call on
  its line is read as MAC and RMAC read it: they go on with the statement
  after the first `!` after the call's arguments that follows a character
  other than a blank or a tab, where a `;` starts a comment that ends at its
  `!`, which counts as such a character, and a `!` after a blank is text;
  when the call has no arguments, the first character after the macro's name
  is text whatever it is. So a call with no arguments ends at the `!` of its
  `;` comment, as another statement does: `MM ;c! DB 1` and `NOP! MM ;c! DB
  1` assemble the `DB`. `MM A;c! DB 1`, `MM A ! DB 1`, `MM ! DB 1`, `MM ;c !
  DB 1`, `MM ;;c! DB 1` and `NOP! MM 1! DB 1` leave it out (MM with a
  parameter), and `MM A;c!! DB 1` does not (the statement left out is empty).
  A call reads as many arguments as the macro has parameters and the rest as
  text, so `MM A! DB 1` and `NOP! MM A! DB 1` assemble the `DB` where MM has
  no parameter. um80 `--dri` left out all that followed a call's arguments -
  `MM ;c! DB 1` was MM's bytes only, without a word, and `NOP! MM ;c! DB 1`
  warned that MAC leaves the `DB` out, which it does not - and took `MM A !
  DB 1` and `MM ! DB 1` for arguments it reported; it now does as MAC does,
  and warns where it leaves out a statement. A `!` right after an argument of
  a line's first statement is still M80's quote where the macro has
  parameters, as `docs/EXTENSIONS.md` says. A line of a body being defined
  that starts with a macro call, an `IRP` or an `IRPC` is read for its
  statements too (`MM ;c! ENDM`, `IRPC C,AB ! NOP ! ENDM` in a macro), and so
  is a macro call's line in a false `IF` (`MM ;c ! ENDIF`): um80 went on to
  the end of the file, or past the `ENDIF`. With or without `--dri`, an
  `EXITM` after a `!` now ends the macro expansion or the repetition, as one
  at the start of a line does (`NOP! EXITM! DB 5`, and `IF 1! EXITM! ENDIF`):
  um80 read on after it, without a word, where MAC ends there. Without
  `--dri` a comment runs to the end of the line, as in M80 (`NOP ;c! DB 1` is
  00). A `!` at the end of a line, or of a comment there, no longer adds an
  empty line to the listing. A line of `!` statements commented out with one
  `;` in front - `;<TAB>pop h! lxi h,0007! jmp shell$err` - is now assembled
  from its first `!` on with `--dri`, as MAC and RMAC assemble it; comment
  out each statement instead. mpm2's V2.1 changes to `NUCLEUS/RESBDOS1.ASM`
  and `CONBDOS.ASM` (`src/overrides`) keep the code they replace in two such
  lines, and RESBDOS.SPR for V2.1 comes out 10 bytes longer, 0D00H, until
  they are rewritten; with them rewritten every file of the V2.0 and V2.1
  builds is what it was.

### Known issues
- um80 assembler: three things MAC and RMAC do that `--dri` does not do yet.
  Each gives different bytes without a word; none is in any DRI source in
  the tests, all 38 of which assemble to MAC's bytes.
  - A two-character string used as a value has its first character in the
    low byte in MAC and RMAC (`DW 'AB'` is 41 42, `LXI H,'AB'` is 21 41 42);
    `--dri` values it as M80 does (42 41).
  - MAC and RMAC take an `IF` as true only when bit 0 of its value is set
    (`IF 2` and `IF NOT 1` are false); `--dri` takes any value but 0 as
    true, as M80 does.
  - MAC and RMAC read a `MACLIB` library in pass 1 only, so its code and
    data are not assembled and its labels keep their pass-1 values; `--dri`
    assembles it as an `INCLUDE` file (library `DB 1` then `DB 2` is 02 in
    MAC and 01 02 here).
- um80 assembler: with `--dri`, `MACLIB NAME` looks for `NAME.MAC`, where
  MAC and RMAC read `NAME.LIB`; `LOCAL` after a `!` on the line is not
  honoured (`NOP! LOCAL QQ`); and `END START` with START defined after the
  `END` is reported undefined, where MAC takes no start address. Each stops
  with an error.

## [0.3.50] - 2026-09-25

mbasic2025 (https://github.com/avwohl/mbasic2025) rebuilds historic Microsoft
BASIC binaries - MBASIC 5.21, as 14 modules and as one Z80 file, and Altair
4K and 8K BASIC 4.0 - from MACRO-80 sources, and is now part of the test
suite. The same sources were also built with the genuine MACRO-80 and
LINK-80 3.44 under a CP/M emulator, and with every mix of them and
um80/ul80: each assembler for all modules, one module from the other
assembler, and both linkers for each. That found the defects below. Each
has a regression test that fails on 0.3.49. `docs/mbasic2025.md` has the
results.

### Added
- tests: `tests/test_mbasic2025.py` builds every variant of mbasic2025 that has
  a historic binary with each variant's own build commands and this checkout's
  um80 and ul80, and compares the result with the binary byte for byte. The
  historic binaries are pinned by SHA-256. The MBASIC 5.2 sources, which have
  no historic binary, are pinned to the image M80 and L80 build from them. It
  runs when the sources are at `$MBASIC2025_DIR` or in a `mbasic2025` checkout
  next to this repository; otherwise it is skipped. It needs mbasic2025
  2d19520 or later, the first revision whose sources build every variant
  byte for byte with this release (see Fixed).
- CI: `.github/workflows/tests.yml` runs the test suite on every push and
  pull request, with avwohl/mbasic2025 checked out at a pinned commit (change
  its `ref:` to take a newer one). Before this, CI ran only pylint.
- tools: `tools/fourway_mbasic.py` builds mbasic2025 with every mix of the
  genuine M80.COM/L80.COM (supplied by path; they are not in this
  repository) and this checkout's um80/ul80. It compares each module's two
  .REL files and each image with the all-Microsoft build and the historic
  binary. The exit status is 1 when a tool mix differs from M80 + L80. Without
  `--um80-flag=-t`, that includes 8 links of `mbasic_521` that a 7-character
  name breaks (see Changed); the tool names the symbol and says to use `-t`.

### Changed
- um80 assembler: `-t` cuts every PUBLIC, EXTRN and module name to 6
  characters, as MACRO-80 does. Before, it cut names to 8 characters, which
  neither M80 (6) nor LINK-80 (reads 7) does. MBASIC 5.21's `BINTRP.MAC`
  declares `PUBLIC FBUFP27`, which M80 writes as `FBUFP2`. A `F4.REL` from um80
  asked for `FBUFP27`, so a link of `BINTRP.REL` from one assembler and `F4.REL`
  from the other failed: L80 reported an undefined global and left 4 bytes
  unset, and ul80 stopped. With `-t`, all 60 links of mbasic_521 (30 .REL
  sets, two linkers) build the historic binary.

### Fixed
- um80 assembler: the `<...>` list of an `IRPC` or `IRP` now ends at the `>`
  that matches its `<`, and um80 ignores the rest of the line, as MACRO-80
  3.44 does. Before, um80 dropped the first and last characters of the
  operand. The difference shows when a macro wraps its argument in brackets
  (`IRPC CH,<STR>`) and the argument is `!>`: M80 reads `IRPC CH,<>>`, an
  empty list. mbasic2025's 4K and 8K BASIC sources build their keyword tables
  with such a macro (`rdc <!>>`). um80 built the historic 8K BASIC from them,
  but the genuine M80 left out the `>` keyword byte, so every address after
  it moved (6645 bytes of 8192). um80 now assembles what M80 assembles, and
  warns about the `>` it ignores. The sources need `db '>'+80h`, as the 8K
  source already has for `<`. mbasic2025 2d19520 made that change (and the
  others `docs/mbasic2025.md` lists) alongside this release; **with an older
  mbasic2025 its `4k8k/8k/build_8k.sh` fails with this um80** (6645 bytes
  differ; it passed with 0.3.49). A list
  with no closing `>` runs to the end of the line, with a warning (M80 flags
  it `Q`). `IRPC C,<A>B` is `A`; `IRP X,<1,2>,3` is 1 and 2. In an `IRP`
  list, a `>`, `<`, `,` or `!` inside a quoted string is text, as in M80
  (`IRP X,<'A>B','<',2>` is `'A>B'`, `'<'` and 2); in an `IRPC` list a quote
  is an ordinary character.
- um80 assembler: a `!` in an `IRP` or `IRPC` list was taken as DRI's
  statement separator, so `IRPC C,<!>` became `IRPC C,<` and a stray `>`
  line. In an `IRPC` list a `!` is an ordinary character. In an `IRP` list it
  quotes the next character, as in a macro argument (`IRP X,<1!,2,3>` is `1,2`
  and `3`). An unbracketed `IRPC` string ends at a blank (`IRPC C,A B` is `A`),
  and um80 warns about the text after it, which M80 ignores. After the list, a
  `!` is still DRI's separator, so a whole block on one line,
  `IRPC C,AB ! DB '&C' ! ENDM`, assembles as before.
- ud80 disassembler: the output ended with `END` and no newline, and
  MACRO-80 reads a line only once it ends, so it never saw the `END` and
  warned "%No END statement". mbasic2025's `4kbas40_new.mac`, written by
  ud80, did exactly that. The output now ends with a newline.
- um80 assembler: a `MACRO`, `REPT`, `IRP` or `IRPC` with no `ENDM` takes
  every line after it as its body, so nothing after it is assembled, and um80
  said nothing. It now warns, as MACRO-80 does ("Unterminated
  REPT/IRP/IRPC/MACRO"). Worse, the block was still open when pass 2 began,
  so pass 2 took the lines before it as its body too, and the module came
  out empty. `DB 1` followed by an unterminated `IRPC` is now 01, as in M80.
- um80 assembler: an `EXITM` in a `REPT`, `IRP` or `IRPC` inside a macro ended
  the macro while the repeat's body was still being collected, so the repeat
  never got its `ENDM` (`REPT 8 / IF @Y EQ 1 / EXITM / ENDIF / ... / ENDM`, the
  log2 macro of CP/M 2.0's `DEBLOCK.ASM`). It now ends the repeat, as in M80.
- um80 assembler: a `!` inside a quoted string in a macro argument was
  dropped: `MSG <'Hi!'>` and `MSG 'Hi!'` passed `'Hi'`. MACRO-80 keeps it, and
  now um80 does too, in a macro call and in an `IRP` list
  (`IRP M,<'Error!','Ok'>`). Outside a string, `!` still quotes the next
  character.
- um80 assembler: `NAME('XYZ')` wrote the module name `'XYZ'`, with the quotes.
  It is now `XYZ`, cut to 6 characters as M80 does.
- um80 assembler: `TITLE` now names a module that has no `NAME`, as MACRO-80
  does. The name is the first 6 characters of the text of the last `TITLE`, up
  to a blank. mbasic2025's `BINTRP.MAC` is the module `BASIC` from both
  assemblers. Before, um80 used the file name `BINTRP`.
- um80 assembler: an `EXTRN` that no instruction uses, and an external that is
  used only in a link-time expression, now go into the .REL as an empty chain,
  as MACRO-80 writes them. The chain tells the linker that the module needs
  the symbol. LINK-80 and ul80 then search a library for it, so that `EXTRN X`
  alone links the module that defines X, and LINK-80 lists the symbol as an
  undefined global if no module defines it. um80 wrote nothing, so the
  library module was not linked.
- ul80 linker: an external that a module only declares, and that no module
  defines, is now a warning and the program is written, as LINK-80 does. There
  is nothing in the program to fill in. Before, ul80 stopped with
  "Undefined symbol", also on objects from the genuine M80. An external that
  something refers to is still an error.

### Removed
- `tests/mbasic.com`, the MBASIC 5.21 binary, which no test used. It came
  from the mbasic2025 project this repository split from. That project has
  the same file (`mbasic_521/com/mbasic.com`), and `tests/test_mbasic2025.py`
  pins it by SHA-256. It is not part of the package, and this repository does
  not otherwise ship Microsoft's binaries.

## [0.3.49] - 2026-09-24

`LOW`/`HIGH` of a relocatable or external value, and any such value in a
one-byte field, are now computed by the linker. MACRO-80 3.44 and LINK-80 3.44
pass them as REL "extension link items"; um80 writes the same items and ul80
evaluates them. The format was established by running the genuine M80 and L80
3.44 under a CP/M emulator and is described in `um80/relformat.py` and
`docs/EXTENSIONS.md`.

### Fixed
- um80 assembler: `LOW(expr)` and `HIGH(expr)` (and M80's `LOW expr` /
  `HIGH expr`) of a relocatable or external value assembled the byte of the
  value's *offset within its segment* as an absolute byte, so no relocation
  reached the linker. MP/M II's `MPMLDR/LDRLWR.ASM`, a CSEG module that GENSYS
  links after `GENSYS.PLM`, does `mvi a,low(bitmap+128)`: in the linked
  `GENSYS.COM` bitmap+128 is at 256CH, but the instruction came out
  `MVI A,0A6H` — the low byte of its offset, 01A6H — so GENSYS read its
  relocation bitmap record at the wrong time and generated a wrong `MPM.SYS`.
  It only worked by accident in a one-module `.COM` whose CSEG starts at 0100H,
  where `LOW` happens to agree (`HIGH` does not). The expression now goes to the
  linker as a postfix program ending in a store operator, written just before
  the placeholder byte it fills — `C(prog,0126H) C(abs,0080H) + LOW
  store-byte` (bitmap, then 128), then `0` — and the linked byte is 6CH.
  Rebuilding all of MP/M II (41 targets) with this change alone changes
  exactly that byte of `GENSYS.COM`; every `.SPR`,
  `.PRL`, `.RSP` and other `.COM` is byte-identical. (The forward-`EQU` and
  `.MEMORY` fixes below also change the relocation bitmaps of `ED`, `PIP`,
  `SDIR`, `STAT`, `SPOOL` and `SUBMIT.PRL`, and the forward-`EQU` fix changes
  the `SUBMIT` that uplm80 0.3.6 compiles from DRI's unaltered `SUB.PLM`.) (DRI built LDRLWR with Intel's
  ASM80 and ISIS LINK/LOCATE — see `MPMLDR/GENSYS.SUB` — whose object format
  carries byte relocations; DRI's own RMAC rejects the line with an `E`.)
- um80 assembler: any other relocatable or external value in a one-byte field
  — `MVI A,BUF`, `DB LAB`, `CPI LOW(EXT+1)`, `LD (IX+OFF),HIGH BUF` — has the
  same cure, which is what M80 does. An external there was an error
  ("Cannot use external in immediate byte"): DRI's own `LDRLWR.ASM` could not
  be assembled at all because of `sui low(sctbfr)`, which is why the MP/M tree
  carries a rewritten copy. The Z80 `LD r,n` form silently assembled 0 for an
  external.
- um80 assembler: a word whose value is not `address + constant` — `-LAB`,
  `LAB*2`, `LAB+LAB2`, the distance between a DSEG and a CSEG label,
  `HIGH(EXT)`, `EXT+LAB` — assembled a value computed from segment offsets,
  which is wrong wherever the linker puts the segment. It goes to the linker
  too. (M80 3.44 gets several of these wrong — in word fields, `DW -LAB`,
  `DW BUF*2`, `DW HIGH(BUF)`, and in byte fields, `MVI A,BUF*2`,
  `MVI A,HIGH(BUF*2)`, `DB HIGH(BUF)*2` — and 0.3.48 matched M80 byte for
  byte there. um80 does not copy that: its values are the arithmetically
  correct ones, so a binary rebuilt with um80 can differ from an M80-built
  reference in those fields.)
- um80 assembler: in a link-time expression a constant added to an address
  was folded into it: `MVI A,HIGH(C1+100H)`, C1 at offset 0 of COMMON
  `/BLK1/`, went out as the one extension item C(common, 0100H). MACRO-80
  writes the address and the constant as items of their own,
  C(common, 0) C(abs, 0100H) A(+), and LINK-80 miscomputes a
  COMMON-relative value that lies past the end of its block: with BLK1 300H
  bytes long, `HIGH(C1+400H)` linked in L80 to A0H instead of 05H. um80 now
  writes M80's form, the operands in source order, in every segment. (L80
  gets the folded form wrong for M80's own objects too, which fold an `EQU`
  such as `X EQU C1+400H` and a word such as `DW C1+400H`; ul80 computes
  all of them right.)
- um80 assembler: `X EQU HIGH BUF` now stands for the expression, so `MVI A,X`
  is linked like `MVI A,HIGH BUF`. It was the constant high byte of BUF's
  offset. (M80 3.44 gets this one wrong too: it keeps BUF's segment, with the
  high byte of BUF's offset as the value.)
- um80 assembler: a constant added to an external that already carries one
  was lost — `EXT+2+3` linked to `EXT+3`, `(EXT+2)-1` to `EXT-1`,
  `1+EXT+1` to `EXT+1`, and after `EQX EQU EXT+2`, `DW EQX+1` to `EXT+1`.
  Only the newest constant was kept. (Present in 0.3.48 for words; with the
  byte fields above it reached `MVI A,EQX+1` too.) `1 SHR (EXT-1)` also
  stopped with a Python traceback ("negative shift count") instead of the
  error for SHR on an external.
- um80 assembler: a symbol used above the `EQU` that defines it, when that
  `EQU` itself uses a symbol defined further down, silently assembled a
  wrong value: `MVI A,X` / `X EQU FWD+1` / `FWD EQU 5` gave `MVI A,01H`.
  Pass 1 computed X with FWD still 0, and pass 2 read that value above the
  line that recomputes it. The same froze a forward `X EQU HIGH BUF` as the
  absolute byte 0, and an alias `RBUF EQU LABEL` of a later label as
  absolute 0: MP/M II's SUB utility, compiled from `SUB.PLM`
  (`declare rbuff(1) byte at (.minimum$buffer)`), stored its command buffer
  at address 0000H. Pass 1 is now repeated until the symbol table stops
  changing, and a forward reference reads what the symbol's definition will
  give: after each time through, the `EQU`s and `SET`s are evaluated again
  in the order they read each other, and the next time through checks that
  guess, reading the whole source again. Pass 1 is over when the values it
  computes are the ones the forward references read, which is what pass 2
  reads there too — so X is 6. (MACRO-80 3.44 flags that forward use of X
  `U` and assembles the 01 its pass 1 computed.) A chain of 500 forward
  `EQU`s is read twice,
  in 0.6 s; settled one link per time through, it took 92 s. (After three
  wrong guesses a forward reference reads the value from the end of the
  time before, one link per time through, and the limit on repeats grows
  with the longest chain in the source, plus 64 for labels moved by forward
  sizes and JR promotion.) EQUs and SETs defined in
  terms of each other are an error naming the cycle — "Cannot resolve the
  value of 'X': it is defined in terms of itself (X EQU Y, Y SET X)" —
  whether or not some value satisfies them, and so is a symbol whose value
  still changes when the limit is reached (through a label its own value
  moves) or differs between the passes after it was used (a phase error,
  e.g. after `IFDEF` of a later symbol). A forward reference to a `SET`
  symbol reads its last value — what its last `SET` gives, with every
  symbol at its final value — and `X SET X+1` reads the X of the line
  before, so each `SET` is a definition of its own: a chain may run
  through `SET`s, and a `SET` that reads a later symbol whose value comes
  from an earlier `SET` of the same name is no cycle. That differs from
  MACRO-80 3.44 when the last value depends on a symbol defined further
  down: M80 does not flag a forward read of a `SET` symbol, and silently
  uses the value the symbol had at the end of its pass 1, computed while
  the symbols below still had none (0). `DW X` / `X SET Y+1` / `DW X` /
  `Y EQU 5` is 01 00 06 00 in M80 and in 0.3.48, 06 00 06 00 in um80 now
  (`DW X` / `X SET 1` / `X SET 2` is 02 00 in all three). See "What still
  differs" in `docs/EXTENSIONS.md`.
- um80 assembler: `/` or `MOD` by a symbol defined further down, or by an
  external, was reported as "Division by zero" (its pass-1 value is 0).
  Only a constant 0 divisor is an error now; `MOD EXT` goes to the linker,
  as in M80.
- um80 assembler: an `EQU` redefined with the same offset in another
  segment (`X EQU PC0` then `X EQU PD0`), or a link-time `EQU` redefined as
  a different expression, or an external alias as another offset, was
  accepted; the second silently replaced the first. It is "multiply
  defined", as in M80.
- um80 assembler: an `EQU` whose value uses `AND`/`OR`/... on a relocatable
  value was reported at every line that used it, without naming it — on
  CP/M 2.0's `ASM.COM` sources, at `LXI SP,ENDMOD`, which has no `AND` in
  it. It is reported once, at the `EQU` (where M80 flags it), naming the
  first line that used it. A `DS n,fill` with such a fill repeated the error
  once per byte; `PUBLIC` of a link-time `EQU` was reported at a line past
  `END` and is now reported at the `PUBLIC`.
- um80 assembler: `JR`/`DJNZ` to an external, to a link-time expression,
  to an address in another segment, or between absolute and relocatable
  code assembled a meaningless displacement with no error: `JR EXT` came
  out `18 FE`, a jump to itself, with the external missing from the
  `.REL`, and far enough from the segment start it was promoted to
  `JP 0000H`. LINK-80 has no PC-relative operator; these are errors now, as
  in M80 (`E`/`R`).
- um80 assembler: the listing showed a field the linker computes as the
  value worked out from segment offsets — `MVI A,HIGH(BUF)`, BUF at DSEG
  0300H, listed `3E 03`, a byte that is in neither the `.REL` nor the
  program. It lists the placeholder the `.REL` carries, and every field
  the linker has yet to finish is marked after its last byte as MACRO-80
  marks it: `'` program relative, `"` data relative, `!` COMMON, `*`
  external (`3E 00"`, `00 00*`, `00 03"` for `DW BUF`, `01 00'02`). The
  byte column is one character wider for the marks. And `JR EXT` far from
  the start of its segment reported its error together with "Note: 1
  JR/DJNZ instruction(s) promoted to JP": pass 1 promoted it for being far
  from the 0 it read for the target. A target the jump cannot reach is no
  longer promoted.
- um80 assembler: expressions MACRO-80 accepts that um80 rejected or
  evaluated differently (each checked against M80 3.44): a word operator
  next to a tab or a parenthesis — `HIGH<TAB>X`, `X<TAB>AND<TAB>0FH`,
  `NOT(X)`, `X AND(0FH)`, `(X)SHR(4)`, `LOW(X)OR 1` — was "Cannot parse
  expression"; `OR` and `XOR` are one precedence level, left to right, so
  `1 OR 1 XOR 1` is 0 (as in DRI's MAC too), not 1; `''''` is 27H, not
  2727H; `DB 'A'+'B'` is the byte 83H, not the five bytes of the text;
  `X##` of a local alias of an external or of a link-time `EQU` stands for
  what `X` does; `EXT EQ EXT` (offsets from one external) is a constant.
  Division stays unsigned and a leading minus still applies after `SHR`
  (`-4 SHR 1` is FFFEH): that is what DRI's MAC computes, and um80
  assembles MAC sources too (M80 3.44 divides signed and gives 7FFEH).
- um80 assembler: in `.Z80` mode a labelled `SET` instruction —
  `X1: SET 7,(IX+1)` — was taken for the `SET` directive ("SET requires
  one operand"). With two operands it is the instruction.
- um80 assembler: `.PHASE addr` / `.DEPHASE` were ignored, so the labels
  and `$` of a block meant to run at `addr` got their load addresses
  (`X: JP X` after `.PHASE 0F000H` assembled `C3 0001'`). They are the
  absolute addresses the block runs at, as in M80; its bytes still load at
  the current location.
- relformat: special link item 4 was returned as `UNKNOWN_SPECIAL` without
  consuming its B-field, so everything after it in the module was misread:
  ulib80 indexed four garbage "public symbols" from an M80 module that uses
  one. Item 8 (External − offset) has an A-field only, per the Microsoft
  manual, but was read as if it had a B-field as well.
- ul80 linker: a chain-external record whose head is absolute 0 is an empty
  chain, as in LINK-80 — M80 writes one to declare an external used only
  inside an expression, or not used at all. It was followed as if a reference
  sat at absolute 0, writing the external's address over the first word of a
  module with ASEG code there (a reset vector). um80 now writes a reference
  at absolute 0 as an extension link item; only in an object from um80 0.3.48
  or earlier, recognised by its item 14, is such a head still a reference.
- relformat, um80: the genuine LINK-80 3.44 could not load any object um80
  wrote ("?Loading Error", or a hang). Special item 14 (end program) has an
  A-field — the start address, absolute 0 if none — which um80 left out,
  writing the start address as a set-location item instead; item 13
  (program size) has to be typed program relative, as M80 writes it (L80
  writes no output when it is absolute); and a COMMON block's size has to
  come before anything refers to the block. um80 now writes all three the
  way M80 does, with the segment and COMMON sizes at the start of the
  module. (LINK-80 still refuses a symbol of 8 or more characters, and an
  external of 7 or more inside a link-time expression; see
  `docs/EXTENSIONS.md`.) Linked four ways — M80+L80, M80+ul80, um80+L80,
  um80+ul80 — 26 of 41 test links give the same bytes all four ways. Of
  the other 15, 3 differ where M80 3.44 miscompiles an expression (um80's
  objects link to the right value in both linkers), 2 where L80 3.44
  miscomputes a COMMON-relative value past the end of its block (for M80's
  objects as for um80's), 8 where L80 lays the program out differently from
  ul80 (COMMON before the data, data before the code without `/D`, code
  above absolute code), and 2 that L80 refuses for M80's objects and um80's
  alike ("?Intersecting Program area" / "Data area"). In every one um80's
  objects link in L80 as M80's do, or to the right value where M80's do
  not. `docs/EXTENSIONS.md` lists them.
- um80 assembler: a module with no DSEG had no item 10 (data size), which
  MACRO-80 writes in every module, 0 if need be. Without it LINK-80 drops
  the constant of an external plus offset in ASEG: `ASEG` / `ORG 4000H` /
  `DW EXT+1` linked in L80 to EXT. It is always written now.
- relformat: the reader read item 14 without its A-field, so every object
  MACRO-80 or LINK-80 wrote fell out of step after its first module:
  `ulib80 -c` on FORTRAN-80's FORLIB.REL crashed (UnicodeEncodeError) and
  found 43 garbage "publics" instead of 418. It reads both layouts (um80's
  earlier objects have no A-field).
- ul80 linker: MACRO-80 writes `JMP EXT+3` as special item 9 (External plus
  offset) before a word that is a link in EXT's chain, and chains every
  reference to an external through the words. ul80 ignored items 9 and 8,
  and fixed up only the head of each chain, so the relocation pass then
  added the segment base to the other links: in an M80 object `JMP EXT+3`
  linked to EXT, and of three `CALL X` the second called X+100H. It applies
  the constants and follows each chain link by its relocation type.
- ul80 linker: a chain link typed absolute is an address in ASEG, as in
  LINK-80. ul80 read it as an offset in the segment of the word holding it,
  so where MACRO-80 chains a CSEG or DSEG reference to one in ASEG (`ASEG` /
  `ORG 4000H` / `DW EXT` / `CSEG` / `CALL EXT`) the ASEG word was never
  found and stayed 0000H. And a word in a chain was marked in a `.PRL`/`.SPR`
  bitmap by the type of the link it held (program relative, for a link to
  another reference) rather than by the value filled in: two `CALL X` of an
  absolute X marked the second. An object from um80 0.3.48 or earlier,
  recognised by its item 14 (no A-field), is still read the old way, an
  absolute link being an offset in the segment of the word holding it.
  That matters only for um80 0.2.0 to 0.3.34, which chained all the
  references to an external through untyped words, each the offset of the
  previous reference; 0.3.35 to 0.3.48 wrote a chain of one per reference,
  whose link is 0 however it is read. (Where the references are in more
  than one segment, a link does not say which segment it is in; see Known
  issues.)
- ul80 linker: special item 12 (chain address) was read and never applied.
  FORTRAN-80 writes every forward reference — a jump to a label further
  down, a FORMAT string, a constant after the code — as a chain through the
  words that need the address and then item 12 where the address is, and
  the words kept their chain links. And LINK-80 stores the address of the
  first free byte after the program's data in the word at `$MEMRY` when a
  module defines that global (FORLIB's DSKDRV allocates its file buffers
  from it); ul80 left it 0000H. A 10-line DO/WRITE/FORMAT program compiled
  with F80 and linked with FORLIB differed from L80's
  `/P:100/D:19D3,T,FORLIB/S` in 10 bytes and stopped with `**DZ**`; its
  image is now byte-identical and it prints `385 128.333`. So is that of a
  program with a subroutine, a function, an array argument, `IF`/`GOTO`
  and `STOP` (0100H–1CF9H).
- ul80 linker, ulib80: a `.REL` holding several modules — a LIB-80 library
  such as FORTRAN-80's FORLIB.REL, 106 modules — loaded only the first, and
  `ulib80 -c` stored it as one module. Every module is loaded, and ulib80
  keeps each as a module of its own, named by its program name.
- um80 assembler, ul80 linker: two or more named COMMON blocks were placed at
  one address, on top of each other. ul80 ignored special item 1 (select
  COMMON block), which a COMMON-relative value is relative to, and um80 wrote
  it only at the `COMMON` directive, so every COMMON-relative word, extension
  value and public referred to whichever block came last. Each block now gets
  its own place, the size of its largest declaration, in the order blocks are
  first declared, and um80 selects the right block before each reference (a
  reference to another block from inside one goes out as an extension item,
  with the block being loaded selected again before the store). The distance
  between two different COMMON blocks is a link-time expression, not a
  constant (M80 3.44 assembles it as one). Bytes assembled into a COMMON
  block (`DB`, FORTRAN's BLOCK DATA) went into the segment before the
  `COMMON` directive — overwriting the code after it — and ul80 dropped
  initialized COMMON data; both now land in the block, and the bytes a module
  loads there are in the image. ul80 loads into the block selected at the
  last set-location item, as LINK-80 does, not the one selected last: M80
  selects another block for an operand inside a COMMON block and does not
  select back (`COMMON /BLK1/` / `DW C2` / `DB 7`, C2 in BLK2), and ul80
  loaded the rest of BLK1 into BLK2. A `.PRL` header now reserves memory for
  COMMON, which lies past the image: MP/M allocated none.
- um80 assembler: with `--aseg`, code before the first `ORG` was loaded by
  the linker into CSEG, at the program base, although its labels are
  absolute from 0; an external referenced there was never filled in. The
  module now starts in ASEG.
- um80 assembler: every `ASEG` directive wrote a set-location item to ASEG
  0000H, even when nothing was assembled there. LINK-80 takes that item as
  code loaded at 0000H: `ASEG` / `ORG 100H` / ... linked with L80 into a
  .COM starting at 0000H (384 bytes, "Data 0000 010C" where M80's object
  gives "Data 0100 010C"). As in MACRO-80, the item is now written only
  when something is loaded or reserved in the segment before an `ORG` or
  another segment directive replaces it; `--aseg` starts the same way.
- um80 assembler: where a segment or `COMMON` directive goes on, as in
  MACRO-80 3.44. Every `COMMON` statement starts at the beginning of its
  block (the MACRO-80 manual gives FORTRAN's rule: a block declared again
  lays its contents over the same storage); um80 went on where the block was
  left. And MACRO-80 keeps for each of CSEG, DSEG and ASEG the most of the
  locations set in it (`ORG`, the end of a `DS`) and of those it was left
  at, and `CSEG`/`DSEG`/`ASEG` goes on from there: after `ASEG` / `ORG 200H`
  / `DB 1,2,3` / `ORG 180H` / `DB 4`, a later `ASEG` goes on at 0200H, over
  the 1, and after `DS 10H` / `ORG 4` / `DB 1`, a later `CSEG` at 10H, past
  the `DS`. um80 went on where the segment was left (0181H, 5), so a source
  that does this assembled into another layout than M80's.
- ul80 linker: a byte loaded over a relocatable word was relocated as if it
  were the word. ul80 relocated after loading everything, adding the
  segment base to whatever bytes had been loaded over the word since: an
  `ORG` back (`CSEG` / `NOP` / `X: DW X` / `ORG 1` / `DB 5,6` linked to
  00 05 07, and `ORG 1` / `DW X` to 00 01 02, the base added twice),
  another module loading the same bytes of a COMMON block, and — once um80
  started every `COMMON` statement at the beginning of its block, as
  MACRO-80 does (above) — a block declared again: `COMMON /C/` /
  `C1: DW C1` / `DB 7` / `COMMON /C/` / `DB 9,9` linked to 0C 0A 07, where
  L80 gives 09 09 07. LINK-80 relocates a word as it loads it, so a byte
  loaded there later just replaces that byte, and the other byte keeps its
  relocated value (`ORG 1` / `DB 5` gives 00 05 01); ul80 now does the
  same, and a `.PRL`/`.SPR` bitmap no longer marks a byte something was
  loaded over. The chain of special item 12 is filled when the item is
  read, as L80 fills it, so bytes loaded over one of its words afterwards
  stay; ul80 followed it at the end, through whatever had been loaded over
  it. An external's chain is filled when L80 fills it, once the module and
  the one defining the external are both loaded, so bytes a later module
  loads over it in a shared COMMON block stay too. Items 8 and 9 (external
  plus or minus a constant) and link-time expressions are still applied
  last, to whatever is there then, as L80 applies them. Every case was
  checked against the genuine M80 and L80 3.44, with M80's objects and
  um80's; in 406 random single-module programs of `CSEG`, `DSEG`, `ASEG`,
  `COMMON`, `ORG`, `DS`, `DB` and `DW` that L80 links, ul80 now links
  um80's object to L80's bytes in every one (two of the first 120 differed
  before). No source in the corpus of 1363 changes.
- um80 assembler: a segment's size (items 13 and 10) was its location at
  the end, which after an `ORG` back undercounts it: `CSEG` / `ORG 20H` /
  `DB 1` / `ORG 10H` / `DB 2` said 11H bytes, and the next module was
  linked over the 1. It is the most the segment reached, 21H. (MACRO-80
  says 20H: its size is the most of the locations set and the one at the
  end, which leaves out the bytes loaded past the highest `ORG`, and L80
  then links the next module over the last of them.)
- ul80 linker: absolute code `ORG`ed below the first byte a module loaded in
  ASEG was dropped without a message: `ASEG` / `ORG 200H` / `DB 1` /
  `ORG 180H` / `DB 4` came out with only the 1 (ul80 took the first address
  loaded for the start of the module's ASEG). The 4 is at 0180H now, as in
  LINK-80. And a `.COM` whose only code is absolute and above the origin
  (`-p`, 0100H by default) started at its lowest byte, which CP/M then
  loads at 0100H; it starts at the origin. At the default origin that is
  what LINK-80 writes (the same 384 bytes as L80's for the example); L80
  starts a `.COM` at 0100H whatever `/P` says, and ul80 at `-p`, so that
  `-p` gives a raw image that starts elsewhere, e.g. a ROM at E000H (see
  "What still differs" in `docs/EXTENSIONS.md`).
- ul80 linker: the gap an `ORG` or `DS` leaves in a module's absolute code
  was written into the image as zeros, over whatever another module had
  loaded there: a CSEG module at 0100H, then a module loading absolute
  bytes at 0080H and 0300H, came out with the CSEG zeroed, without a
  message. Only the bytes a module loads go into the image, as in LINK-80.
- ul80 linker: each module's code went straight after the previous
  module's, even where a module before it had loaded absolute code:
  `ASEG` / `ORG 100H` in one module and a CSEG in the next linked the CSEG
  on top of the absolute code, without a message. LINK-80 3.44 (probed
  under cpmemu) starts the next module above the highest absolute location
  loaded so far - a byte, or a location an `ORG` or `DS` set - with `/P`
  or without, and even with free space below it (absolute code at 0200H,
  `/P:100`: the next module at 0204H); absolute code below the origin
  moves nothing, and a module's own absolute code does not move its own
  code. ul80 now does the same. `__END__` (and so `$MEMRY` and PL/M's
  `.MEMORY`) is past absolute code loaded above the program, as L80's
  `$MEMRY` is; it was the end of the relocatable areas, below it.
  Absolute code that still lands on something - a module's program area
  (its own, or an earlier module's), the data or COMMON after all the code,
  or another module's absolute code - is an error and no output is
  written; L80 warns "%Overlaying Program area" and writes a mixture of
  the two (`--allow-overlap`, under Added, links it as L80 does with
  `/D`). `ASEG` / `ORG 100H` / `JMP START` and a CSEG in one module is
  such a case at ul80's default origin, 0100H; L80's, 0103H, leaves room
  for the jump, and so does `-p 103`. A full MP/M II source build (2.0 and
  2.1) gives the same bytes in 42 of its 44 targets; `DDT.COM` and
  `RDT.PRL`, which it links from DRI's absolute `DDT0MOV`, `DDT1ASM` and
  `DDT2MON`, now fail with "Module DDT1AS: absolute code at 0100H,
  0103H-019AH overlaps absolute code of module DDT0MO". `DDT1ASM` is
  assembled at 0000H, and its code went over `DDT0MOV`'s relocator: the
  `.COM` started at 0000H with a `JMP 0683H` of `DDT1ASM`'s. DRI put the
  three together with `GENHEX` and `GENMOD` (`DDT.SUB`), not a linker
  (see Known issues).
- ul80 linker: in a `.PRL`/`.SPR` bitmap, a reference to `__END__`,
  `__BSS_START` or `__BSS_END`, or to a `PUBLIC` alias of one, was never
  marked: the linker computes them as absolute values, but they are program
  addresses. PL/M's `.MEMORY` compiles to exactly that, so in a `.PRL` it
  pointed at the linked address, not the loaded one: MP/M II's SDIR
  (UTIL7/DSE.PLM puts its hash table `AT(.MEMORY)`) wrote outside its memory
  segment whenever MP/M loaded it anywhere but the link base. A full MP/M II
  build now marks 17 more words in ED.PRL, 9 in PIP, 4 in SDIR and 3 in
  STAT, every one a reference to the program's end.
- ul80 linker: whether a reference was to page zero was judged on symbol
  plus offset for a chained word and on the symbol for a link-time
  expression, so `LXI H,TBUF+80H` (0100H) escaped the bitmap while
  `MVI A,HIGH(TBUF+80H)` was marked, and `DW KHI-1200H` (0034H) of a
  constant 1234H was marked. It is the symbol, in both.
- ul80 linker: the modules a library search loaded, and so the image, came
  out in an order that changed from run to run (the search went through a
  Python set of undefined names). The order is now LINK-80's: each library
  in turn, its modules in library order. ul80 goes on searching until
  nothing more loads, where LINK-80's `/S` makes one pass and leaves a
  reference to a module earlier in the library undefined, so the two lay
  such a link out differently (see `docs/EXTENSIONS.md`).
- ul80 linker: an external chain whose head, or a link, leads outside the
  bytes the module loaded was followed that far and dropped without a word,
  leaving the references after it unfilled. No correct object holds one; the
  objects um80 0.3.48 assembled with `--aseg` from relocatable sources do
  (their code went to CSEG, their chain heads stayed absolute). ul80 now
  warns, naming the module and the symbol. **Reassemble any object 0.3.48
  made with `--aseg`.**
- um80 assembler: an empty COMMON block (`COMMON /X/` with nothing in it)
  got no size item (special item 5). MACRO-80 writes it with size 0, and
  LINK-80 stops with "?Loading Error" at the select of a block it was never
  given a size for, so such an object could not be loaded by L80.
- ul80 linker: "link-time expression has no store operator" was printed as
  an error, but the image was written with the field left 0 and ul80
  exited 0. The link fails.
- ul80 linker: `(BUF+255)/256` and `BUF MOD 256` of a relocatable BUF are
  `HIGH(BUF+255)` and `LOW(BUF)`, which a page bitmap can express; they were
  refused for `.PRL`/`.SPR` output.
- ul80 linker, ulib80: a LIB-80 library (`.LIB` made by Microsoft's LIB-80:
  `.REL` modules one after another, like FORTRAN-80's FORLIB) was refused
  ("bad magic"). It is searched like a ulib80 library, and `ulib80 -l`/`-p`
  list it. A program calling FORLIB's `$AA` links to the same code as
  LINK-80's `/S` search.

### Changed
- um80 assembler: `n-SYM` and an expression naming two externals, errors since
  0.3.48 because the `.REL` format "cannot carry them", are computed by the
  linker the way M80 3.44 writes them. In `.PRL`/`.SPR` output they are
  errors when the result would not move by exactly 0 or 1 page (see below).
- um80 assembler: `AND`, `OR`, `XOR`, `SHL`, `SHR` or a comparison applied to a
  relocatable or external value is an error when the result is assembled into
  an instruction or `DB`/`DW` (M80 flags these `R`, except a comparison of
  two externals, which it evaluates with both as 0; DRI's RMAC flags `E`).
  LINK-80 has no such operators, and the offset-based value was silently
  wrong. Two addresses in one segment, or two offsets from one external,
  compare as constants. Absolute code (`ASEG`, `--aseg`) is unaffected: HIGH/LOW of an absolute
  value is a constant and no extension item is written.
- um80 assembler: a directive that uses its operand while assembling — `ORG`,
  `DS`, `IF`/`IFE`/`COND`, `REPT`, `RST`, `IM`, `BIT`, `END`, `.RADIX` and
  the macro `%` operator — refuses a value only the linker knows: an
  external, `HIGH`/`LOW` or another link-time expression of a relocatable
  value, or `AND`/`OR`/... of one (M80 flags all of these `R`). The value
  it used was computed from segment offsets: `DS 100H-LOW($)` in a CSEG
  aligned to the start of the segment rather than to a page, and
  `X EQU LOW(LAB+5)` / `DS X` reserved the low byte of an offset. `IF 5-EXT`
  and `REPT EXT+EXT`, errors in 0.3.48, would otherwise have become 0. A
  relocatable address used as a number is still its offset (M80 flags
  `IF LAB` and `DS LAB` too; um80 keeps accepting them), and `ORG $+10`
  still moves within the segment; `ORG` to an address in another segment is
  an error.
- um80 assembler: a `PUBLIC` symbol equated to a link-time expression is an
  error — a `.REL` public carries an address or a constant.
- um80 assembler: a word that is an external plus a constant goes out as
  M80 writes it — special item 9 with the constant, then a reference in the
  external's chain — instead of a chain named `EXT+3`, which LINK-80 took for
  an undefined symbol. ul80 still reads the old form.

### Added
- ul80 linker: `--allow-overlap` links absolute code that loads over other
  code — a patch or overlay module — with a warning, as LINK-80 does
  ("%Overlaying Program area"), where it is otherwise an error (see Fixed).
  The image has the byte loaded last: a later module's over an earlier
  one's, and in one module the byte it loaded later, absolute or not, as
  L80 writes it given `/D`; a relocated word keeps the relocated byte
  nothing replaced. Without it, the error now says the switch exists. Where
  a patch loads over a word of an external's chain, ul80 still fills every
  reference by following each module's own links, where L80 follows the
  patched bytes as a link: 191 of 199 random patch links are byte-identical
  to L80 `/D`, 7 differ that way and 1 by the `/D` layout.
- ul80 linker: evaluates extension link items (`+ - * / MOD NOT HIGH LOW`,
  unary minus, externals, program/data/common-relative values) once every
  segment is placed, for `.COM`, `.HEX`, `.PRL` and `.SPR` output alike. An
  object written by the real MACRO-80 3.44 links to the values LINK-80 3.44
  computes for it, and one um80 writes links in LINK-80 to the values ul80
  computes — except where L80 miscomputes a COMMON-relative value past the
  end of its block, and where the two linkers place things differently
  (see `docs/EXTENSIONS.md`).
- ul80 linker: in `.PRL`/`.SPR` output a stored byte that is `HIGH` of an
  address is marked in the relocation bitmap and one that is `LOW` of an
  address is not (a page move never changes a low byte); a stored word that is
  an address is marked on its high byte. A value that would not move by
  exactly 0 or 1 page when MP/M relocates the program — `HIGH(A)+HIGH(B)`,
  `200H-LAB`, `LAB*2` — cannot be expressed in the bitmap and is an error for
  `--prl`/`--spr`; it is linked normally for `.COM` and `.HEX`.

### Known issues
- MP/M II's source build (`tools/build.py` in the mpm2 repository, V2.0
  and `--version 2.1`) stops with "Build complete: 42 succeeded, 2
  failed": `DDT.COM` and `RDT.PRL`, which it links from DRI's absolute
  `DDT0MOV`, `DDT1ASM` and `DDT2MON` with ul80, fail with "Module DDT1AS:
  absolute code at 0100H, 0103H-019AH overlaps absolute code of module
  DDT0MO". The error is right: the `DDT.COM` that recipe linked (mpm2's
  committed `bin/src/DDT.COM`) starts `C3 83 06`, DRI's `01 94 11 C3 47 01`.
  DRI made the two with `GENHEX` and `GENMOD` (`UTIL1/DDT.SUB`), not a
  linker, and the mpm2 recipe (`UTIL1_TARGETS`) has to do the same before
  this release is used for that build; mpm2's branch `fix/ddt-genmod`
  (commit 0386288, merged for mpm2's next release) does, and builds all 44
  targets for V2.0 and V2.1 with this ul80, its `DDT.COM` and `RDT.PRL`
  byte-identical to DRI's. Linking the old way with
  `--allow-overlap` gives exactly the old, wrong `DDT.COM`.
- ul80 linker: an object from um80 0.2.0 to 0.3.34 that refers to one
  external from more than one segment does not link right, with this ul80
  or any earlier one. Those releases chained all the references to an
  external through untyped words, each holding the offset of the previous
  reference in whichever segment that one was in, and the link does not
  say which; ul80 follows each link in the segment of the word holding
  it, so the chain goes astray at the first link that crosses to another
  segment and the references before it keep their link values.
  `EXTRN EXT` / `CSEG` / `CALL EXT` / `DSEG` / `DW EXT` assembled by um80
  0.3.34 links to `CD 00 00` for the `CALL` (the `DW` gets EXT). (0.2.0 to
  0.3.20 also put a module's DSEG bytes in its CSEG stream; ul80 0.3.48
  and this one fill different wrong words there.) Assemble such a source
  again with a current um80.
- ul80 linker: a `.PRL`/`.SPR` relocation bitmap can disagree with the image
  where an external's chain word, a `HIGH`/`LOW` field or an item-9 word is
  loaded over (an `ORG` back over it, or a later module loading the same
  COMMON bytes and defining the external): a mark set when the chain is
  filled can outlive the byte. Every such program is garbage in for L80 too,
  which follows the corrupted chain elsewhere or hangs. 938 random programs
  without such an overwrite all satisfy the page-shift property (the bitmap
  moved by k pages equals the image linked k pages higher).
- um80 assembler (as in every earlier release): a symbol named like a
  register (`E`, `A`, `B`) cannot be used in an expression ("Register 'e'
  used as value"), and a directive written in column 1 (`public fcb`) is
  taken for a label. MACRO-80 accepts both.

## [0.3.48] - 2026-09-24

Five defects found by building all of MP/M II V2.0 and V2.1 from Digital
Research's sources and comparing the result against DRI's binaries. Each has a
regression test that fails with its fix reverted.

### Changed
- ul80 linker: `--prl` now links a transient at 100H. MP/M loads a `.PRL` at
  `segment_bottom + 100H` but its relocator (NUCLEUS/CLI.ASM, `relocate`) adds
  only the segment's base *page* to the bytes the bitmap marks, so the extra
  page has to come from the link, exactly as for a `.COM`. It was linked at 0,
  which put every relocated address a page below the code: source-built MP/M
  utilities loaded, printed nothing and dropped the session. DRI's binaries
  state the convention — the highest relocatable word in `STAT.PRL` is its
  program length plus 100H. **A `.PRL` linked with `--prl` by an earlier
  release was wrong; relink it.**
- ul80 linker: system pages (`.SPR`, `.RSP`, `.BRS`), which MP/M loads at the
  segment base and which really are linked at 0, have their own switch,
  `--spr`.
- ul80 linker: in page-relocatable output a resolved reference to an absolute
  symbol below 100H — the BDOS entry at 0005H, the default FCB at 005CH, the
  DMA buffer at 0080H — is now marked for relocation, because under MP/M page
  zero belongs to the process's memory segment. DRI got the same effect by
  linking twice at different offsets (PLM_WORK/X0100.ASM and X0200.ASM) and
  letting GENMOD diff the results; DRI's `DIR.PRL` marks twelve `CALL 5`
  sites. An absolute symbol at or above 100H stays absolute.

### Added
- ul80 linker: `--extra HEX`, the memory a `.PRL` asks MP/M for beyond its
  image, for storage a PL/M program places at `.MEMORY`. Nothing in the object
  files says how much, so DRI named it at build time as GENMOD's third
  argument; its ASM, ED, PIP and SDIR reserve 1000H and RDT 1500H.
- um80 assembler: `--aseg` assembles a source written for DRI's MAC the way MAC
  does — absolute, so an `ORG` is an address rather than an offset in CSEG.
  MP/M II's assembler is seven such modules, each with its own `ORG`, which DRI
  assembled separately and concatenated as HEX; assembled as relocatable they
  were stacked end to end and `ASM.PRL` came out at 36971 bytes against DRI's
  8171. With `--aseg` it is 8176 bytes, and the `BOOT.HEX` it produces from
  `BOOT.ASM` is byte-identical to the one DRI's own `ASM.PRL` produces.

### Fixed
- um80 assembler: an offset subtracted from an external symbol kept its sign.
  `LXI H,PDTBL-34H` assembled to `PDTBL+34H` — the two branches that separate
  the constant from the symbol were swapped, so the constant to the right of a
  `-` was added and the one to the left negated. `SYM+n` and `n+SYM` were
  right, which is why it survived. `n-SYM` (a negated symbol) and an expression
  naming two externals cannot be carried in a `.REL` file and are now errors
  rather than wrong code. In MP/M II's CLI this put every process descriptor
  reference 68H bytes past the table, so a source-built system warm-booted
  instead of running any transient.
- um80 assembler: a label named after a mnemonic assembled to the opcode byte.
  An opcode name stands for its own byte (`DB MOV` is 40H), and um80 applied
  that before looking in the symbol table, so `CALL ADD` assembled to
  `CALL 0080H` (80H is `ADD A,B`) even where `ADD` was a defined procedure. A
  defined or external symbol now wins; the opcode byte remains for names that
  are not symbols. MP/M II's `STAT.PLM` declares `add: procedure`, and STAT
  executed its own command tail at 0080H and restarted, printing its drive
  line 1837 times.
- ul80 linker: `__END__` exported to another module was zero. A PL/M
  `AT (.MEMORY)` compiles to a public alias of `__END__`, which has to be
  registered before externals are resolved but has no value until every
  segment is placed; it is now recomputed once the bases are known. SDIR's
  hash table is declared that way in one module and used from another, and it
  cleared 256 bytes from address 0, BDOS vector included.

## [0.3.47] - 2026-09-23

### Documentation
- Backfilled the missing CHANGELOG entries for 0.3.25 through 0.3.36. The file
  ran from 0.3.37 straight back to 0.3.24, so twelve releases had no record at
  all — including 0.3.32, which carried the DSEG placement fix. That one had
  silently corrupted every multi-module link whose modules carry initialized
  data, and it is the sort of thing that needs to be findable afterwards: it
  surfaced months later as an MP/M II system image that was 1152 bytes short
  and would not boot. No code changes in this release.

## [0.3.46] - 2026-08-04

### Fixed
- ul80 linker: An error recorded during an otherwise successful link is now
  reported. `main()` printed `linker.errors` only when `link()` returned false,
  but L80 keeps the first definition of a multiply-defined global and links on,
  so `link()` succeeds and every error recorded along the way was silently
  thrown away: exit 0, output written, nothing on stderr. This swallowed the
  multiply-defined PUBLIC error added in 0.3.42 on the command-line path, which
  went unnoticed because the test for it drives the `Linker` API rather than
  the entry point — the check worked, only the reporting did not. On the
  command line the diagnostic had been missing for two releases: through 0.3.41
  ul80 printed `Warning: Multiple definition of 'X'`, 0.3.42 made it an error
  that `main()` never reached, and 0.3.43 shipped that way. It now prints
  `Error: Multiply defined global 'X'`. Both CLI paths are covered now. The
  exit status stays 0 when the link still succeeded, matching L80, which
  accepts such link lines and produces output.

## [0.3.45] - 2026-08-04

### Fixed
- um80 assembler: The two-operand Z80 ALU forms `SUB/AND/XOR/OR/CP A,<operand>`
  no longer drop the operand. ADD, ADC and SBC each collapse a leading `A,` to
  the one-operand encoding; these five had no such branch, so `A` was taken as
  the operand and the real one was discarded — `CP A,5` assembled as `CP A`
  (BF, which always sets Z) rather than FE 05, `SUB A,5` as 97 rather than
  D6 05, `AND A,0FH` as A7 rather than E6 0F, and `CP A,(IX+3)` as BF rather
  than DD BE 03. Exit 0 and no diagnostic, on ordinary Zilog syntax that people
  write. The upper bound added in 0.3.44 only rejected three or more operands,
  which is why it did not reach this. A destination that is not the accumulator
  is now an error rather than a silent drop — for these five and for ADD/ADC/SBC
  too, since `ADD B,C` fell through to `ADD B` and dropped the C the same way.
  That last part breaks source that used to assemble: `ADD B,C` and `CP B,5`
  exited 0 under 0.3.43 and now stop the assembly.
- um80 assembler: `.Z80`/`.8080` mode no longer leaks across passes. The mode
  was set once in `__init__` and never reset, so the mode pass 1 ended in became
  pass 2's starting mode, and a `.Z80` anywhere in a file assembled the lines
  ABOVE it as Z80 on the second pass: `JP addr` silently became C3 instead of
  the 8080 F2 (jump if positive), and `CP n` a two-byte FE instead of the
  three-byte F4 (call if plus), which moves every label after it. Exit 0, no
  diagnostic. The mode now resets each pass exactly as the radix does, since a
  `.Z80`/`.8080` re-applies on every pass. This undercut the advice in 0.3.44's
  own error message: a user told to add a `.Z80` directive who put it at the
  bottom of the file silently changed the meaning of everything above it.
- Documentation: the three Microsoft manual links in README.md, the manual list
  in docs/index.md and the pointer in docs/project.txt all named
  `docs/external/m80.pdf` and its neighbours. Those PDFs have never been
  tracked in this repository or shipped in the sdist, so every one of those
  links was dead for anyone who did not already have a private copy of that
  directory; they now point at the retro_docs archive. The "From source"
  instructions in README.md also cloned `github.com/um80/um80_and_friends.git`,
  an organization that does not exist, so that copy-and-paste clone failed
  outright; it now names `avwohl`. No code changed for either.

## [0.3.44] - 2026-08-03

### Added
- README.md documents that 8080 is the default mode and that Z80 mnemonics need
  a `.Z80` directive, quotes the text of the new error below, and notes that
  `um80 -e .z80 file.mac` sets the mode from the command line without editing
  the source. The change below turns a silent operand drop into a hard error,
  and someone who hits that error otherwise has no way to learn that the mode
  is positional or that there is a route that does not involve editing every
  file. (The Related Projects list in the same file was separately rewritten in
  Simplified Technical English: wording only, same projects, same links.)
- docs/ISSUES.md #4 records a ulib80 defect found while measuring the blast
  radius of that change and NOT fixed here: `ulib80 -c lib.lib` writes a
  different byte stream on every run over the same unchanged `.rel` inputs,
  because the library writer iterates a `set` or `dict`; pinning
  `PYTHONHASHSEED` makes the output reproducible. The archive still links
  correctly, so nothing built from it is wrong, but a byte comparison cannot be
  used to tell whether a toolchain change altered a library — across the 0.3.44
  change every uc80 `.rel` module came out byte-identical while `libc.lib` and
  `runtime.lib` differed on every rebuild.

### Changed (deliberate divergence from MACRO-80 3.44)
- um80 assembler: An operand given to an instruction that takes none is now an
  ERROR, so nothing is written and the exit status is 1. It used to be a
  warning (or, for the conditional returns, no diagnostic at all) and the
  operand was thrown away, which silently assembled a different program:

  - `RET NZ` assembled as `C9`, an unconditional RET (Z80: `C0`).
  - `RLC B` assembled as `07`, RLC A (Z80: `CB 00`).
  - `RRC C` assembled as `0F`, RRC A (Z80: `CB 09`).
  - `RZ FOO` assembled as `C8` with no diagnostic at all.
  - `NOP 5` assembled as `00`.

  All 17 8080 no-operand mnemonics (NOP RLC RRC RAL RAR DAA CMA STC CMC HLT RET
  PCHL SPHL XCHG XTHL DI EI), all 8 conditional returns (RNZ RZ RNC RC RPO RPE
  RP RM), and the Z80-mode no-operand and ED-prefix no-operand mnemonics are
  covered. When the mnemonic and its operand spell a valid Z80 instruction
  (`RET cc`, `RLC r`, `RRC r`), the message names the `.Z80` directive, which is
  what makes um80 assemble Z80 mnemonics; for `RET cc` it also gives the 8080
  spelling (`RET NZ` is `RNZ`), and for `RLC r` and `RRC r`, which have no
  8080 spelling, it says that the 8080 rotate applies to A only.

  Genuine MACRO-80 3.44 instead flags these `Q` (questionable), emits the
  operand-less opcode and still writes the .REL; this is therefore a knowing
  break with M80 bit-compatibility, made because turning `RET NZ` into an
  unconditional `RET` is a silent miscompile. Measured blast radius is zero:
  the 14 original Microsoft MBASIC 8080 sources, the 98 uc80 library modules
  and every other `*.mac` outside `external/` assemble to byte-identical
  objects with no new diagnostics.

  8080 mode remains the default (M80 behavior), and the legitimate 8080
  readings of `JP`/`CP` (jump-if-positive, call-if-plus) are unchanged.

### Fixed
- um80 assembler: A Z80 ALU mnemonic with three or more operands is now an
  error. `ADD A,B,C` assembled as `ADD A` and dropped the rest.

## [0.3.43] - 2026-07-21

### Fixed
- um80 assembler: The two-operand Z80 ALU forms `ADD/ADC/SBC A,<expr>` no
  longer uppercase the immediate expression. Both operands are uppercased to
  match register names (`ADD HL,DE`, `ADC A,B`, ...), and the uppercased COPY
  of the immediate was fed back into expression evaluation, so `ADD A,'a'`
  assembled as `ADD A,'A'` (C6 41) and `ADD A,'a'-'A'` as `ADD A,0` (C6 00) -
  a tolower routine built on it was silently a no-op. Single-operand forms
  (`SUB 'a'`, `CP 'a'`) and all other mnemonics were unaffected, which is why
  the wrong bytes assembled without any diagnostic. Register matching remains
  case-insensitive. Found via a broken lowercase-filename export in the
  romwbw_emu W8 utility.

## [0.3.42] - 2026-06-13

A broad M80-compatibility audit. Every fix below was verified against the
genuine MACRO-80 / LINK-80 3.44 binaries running under cpmemu.

### Fixed
- um80 assembler: Expression operator precedence now matches M80. The unary
  operators (NOT, unary minus/plus, HIGH/LOW) were evaluated first, giving them
  the lowest precedence; they are now at their correct levels, so `-2+3`=1,
  `NOT 1 AND 2`=2, `3*-2 AND 0FFH`=0FAH, `HIGH 1234H + 1`=13H, `-1 GT 1`=0FFFFH,
  and `HIGH(1234H)+LOW(5678H)` parses correctly.
- um80 assembler: A two-character constant places the first character in the
  high byte (`'AB'`=0x4142), so `DW 'AB'` emits bytes `42 41`.
- um80 assembler: `LD A,I` / `LD A,R` now encode `ED 57` / `ED 5F` (were emitted
  as `LD A,0`).
- um80 assembler: Macro fixes — EXITM is ignored inside a false conditional
  branch (the IF/EXITM/ENDIF idiom); a user macro shadows a built-in
  instruction/pseudo-op of the same name; parameter, LOCAL and `%` substitution
  no longer corrupt quoted string literals; `IF NUL <param>` works with an
  omitted argument.
- um80 assembler: REPT/IRP/IRPC fixes — a directly nested repeat block is no
  longer dropped; `IRP X,<<1,2>,<3,4>>` iterates twice (not four times) and
  strips one bracket level per item; EXITM terminates a repeat expansion.
- um80 assembler: `.RADIX` evaluates its operand in decimal regardless of the
  current radix (so `.RADIX 16` works), and the radix resets each pass.
- um80 assembler: An unterminated conditional (missing ENDIF) is reported, and
  a duplicate ELSE for one conditional level is an error.
- um80 assembler: Cross-class symbol redefinition is rejected — a SET/DEFL/ASET
  symbol and an EQU/label symbol cannot redefine each other (multiply defined).
- ul80 linker: A multiply-defined PUBLIC global is now an error (was a warning),
  matching L80's `%Mult. Def. Global`.
- ul80 linker: Reworked segment placement so absolute (ASEG) code is emitted at
  its absolute address instead of being rebased to the relocatable load address
  (resolves docs/ISSUES.md #1). A module mixing CSEG and ASEG now keeps the CSEG
  relocatable while emitting the ASEG block at its ORG (previously the CSEG was
  silently dropped), and a module contributing only a COMMON block no longer
  has its bytes miscounted as program code. Verified against LINK-80 3.44.

## [0.3.41] - 2026-06-13

### Fixed
- um80 assembler: Fixed the DRI `!` multi-statement separator corrupting macro
  invocations. On a macro-call line, `!` is the M80 argument-quote operator
  (e.g. `head FOO,!!CF` passes the name `!CF`, and `!,` passes a literal comma),
  not a statement separator, so such lines are no longer split on `!`. Escaped
  commas in a macro argument list are also kept within their argument (issue #3).
- um80 assembler: Fixed `&`-concatenation of a macro parameter being
  case-sensitive, so a lowercase `&name` referencing parameter `name` left a
  stray `&` in the output instead of substituting the argument (issue #3).

### Removed
- Removed the stale standalone scripts under `src/` (um80, ul80, ulib80,
  ucref80, ud80, and the `um80_*opcodes`/`um80_relformat` helpers). They were a
  pre-package copy that had drifted months out of sync; the installed tools all
  run from the `um80/` package (see `pyproject.toml` entry points).

## [0.3.40] - 2026-04-09

### Fixed
- um80 assembler: Fixed `DEFS count,fill` ignoring the fill-value operand and
  emitting zero bytes instead of `count` bytes of the fill value (issue #2).

## [0.3.39] - 2026-04-09

### Fixed
- ul80 linker: Fixed ASEG `.COM` output including 256 leading null bytes when
  the source had `ASEG` followed by `ORG 0100H` (issue #2).

## [0.3.38] - 2026-04-08

### Added
- um80 assembler: Added `ASET` directive (M80-compatible alias for `SET`/`DEFL`).

### Fixed
- um80 assembler: Fixed `EQU` with forward references incorrectly triggering "multiply defined"
  error on pass 2 when the symbol value changed due to forward reference resolution.

## [0.3.37] - 2026-03-29

### Fixed
- ud80 disassembler: Fixed incorrect bit pattern comments for DCX and LDAX opcodes.
- ux80 translator: Fixed ALU mapping comments that incorrectly described output format.
- ucref80, ux80: Removed unreachable dead code (try/except around decode with errors='replace').

## [0.3.36] - 2026-03-12

### Added
- ul80 linker: Predefined `__BSS_START` and `__BSS_END` symbols giving the
  bounds of the COMMON region, alongside the `__END__` symbol added in 0.3.16.
  A crt0 that zeroes uninitialized data before entering `main` needs both ends
  of that region and previously had no way to ask the linker for either.

### Fixed
- um80 assembler: An unnamed COMMON block (`COMMON //`, whose name is the empty
  string) was not recognized as a COMMON block at all. The location-counter
  getter and setter and the `seg_type` property all tested
  `if self.current_common:`, and Python treats `''` as false, so a blank COMMON
  — the form every C compiler's BSS uses — was assembled as though the block
  had never been opened: the bytes were counted against the enclosing segment
  and labeled with its segment type. The tests are now `is not None`.
- ul80 linker: With `--no-ds-zeros`, the DSEG output size still counted
  reserved (DS) bytes, so space merely reserved at the end of the data segment
  was written out as zero padding in the binary — exactly the bytes that option
  exists to leave out. Only initialized bytes (DB/DW) are counted now.

## [0.3.35] - 2026-03-11

### Fixed
- um80 assembler: External references are no longer threaded through a linked
  list embedded in the emitted code. Each reference stored the offset of the
  previous one in its own two bytes, with 0 as the end-of-chain marker, which
  is indistinguishable from a reference at offset 0 of a segment — a perfectly
  ordinary place for the first instruction of a module to be. The linker
  stopped walking there, so every earlier reference in that chain kept the raw
  chain link instead of the resolved address. The assembler now emits one
  CHAIN_EXTERNAL record per reference. Chains are also keyed by segment type,
  so a chain started in one segment can no longer run into another and patch
  bytes that belong to it.
- ul80 linker: A location fixed up while resolving an external reference could
  be relocated a second time in Phase 2, adding the segment base twice. The
  linker now records the locations it resolved externally and skips them.

## [0.3.34] - 2026-01-25

### Fixed
- ul80 linker: A reference from DSEG to a CSEG symbol — an initialized function
  pointer, `int (*f)(int) = &some_function;` — was placed using the code base
  rather than the data base. The relocation records carried only the target's
  segment type, not the referencing segment's, so the output offset was
  computed from `code_base` for a location that lives at `data_base`: the
  patched address was written into the wrong bytes of the image, and external
  chains anchored in DSEG were followed from the wrong buffer offset as well.
  Relocation records are now 3-tuples carrying the referencing segment type.

## [0.3.33] - 2026-01-24

### Added
- um80 assembler, ul80 linker: `EQU` accepts an external symbol plus an
  optional offset, and such an alias can itself be declared PUBLIC:

      EXTRN   ROUTINE
      PUBLIC  ROUTINE_ALT
      ROUTINE_ALT EQU ROUTINE+2

  The assembler emits uses of the alias as external-plus-offset references and
  writes an exported alias as `NEWNAME=EXTERNAL+N`; the linker defers those
  publics and resolves them before linking. z88dk libraries use this to publish
  alternate entry points a few bytes into an existing routine. Documented in
  README.md and docs/EXTENSIONS.md, with tests in `tests/test_ext_alias.py`.

## [0.3.32] - 2026-01-08

### Fixed
- ul80 linker: Initialized DSEG data is placed at the module's data base
  address instead of immediately after that module's own code. The linker had
  treated each module's CSEG and DSEG as one contiguous block and copied the
  whole buffer to `code_base`, so a module's initialized data landed directly
  on top of whatever was linked next — which, in a multi-module link, is the
  next module's code. Nothing reported it: the link succeeded, the file was
  written, and the image was wrong. Any link of more than one module where the
  modules carry initialized data was silently corrupted, and the corruption was
  worse the more modules there were.

  It was finally identified by size. MP/M II's XDOS.SPR is built from 19
  modules, nearly all of which use DSEG; ul80 produced an 8960-byte XDOS.SPR
  where DRI's own XDOS.SPR is 10112 bytes. The 1152 missing bytes were the
  overlap — data written over code that the output was then never sized to
  hold. CSEG bytes now go to `code_base`, initialized DSEG bytes to
  `data_base`, and the output buffer is sized to cover both regions.
- tests: `tests/test_case_sensitivity.py` expected symbols to be truncated to
  eight characters, but `RELWriter` defaults to `truncate_symbols=False` and
  keeps the full name. The expectations were wrong, not the writer; no
  behavior changed.

## [0.3.31] - 2026-01-07

### Fixed
- um80 assembler: `EX AF,AF'` no longer swallows the rest of the line. The
  trailing apostrophe was read as the start of a string literal, both when
  stripping comments and when splitting operands, so everything after it —
  including the comment and any following statement — was absorbed into an
  unterminated string. An apostrophe directly after an alphanumeric character
  is now part of the register name, not a quote.
- um80 assembler: The LOCAL symbol counter was not reset between passes, so the
  generated `??NNNN` names drifted: a symbol defined as `??0000` during pass 1
  was referenced under a different number in pass 2. The counter is now reset
  at the start of each pass-1 iteration and again for pass 2, so a LOCAL symbol
  keeps one name throughout.

## [0.3.30] - 2026-01-07

### Fixed
- um80 assembler: The `-e`/`--execute` and `--pre` options added in 0.3.29
  reached the installed tool. That release had added them only to `src/um80`, a
  standalone copy of the assembler that nothing runs — the `um80` entry point
  in pyproject.toml names `um80.um80:main` — so an installed 0.3.29 still
  rejected both options as unrecognized arguments. The same code is now in
  `um80/um80.py`. (The stale `src/` copies were removed outright in 0.3.41.)

## [0.3.29] - 2026-01-07

### Added
- um80 assembler: `-e`/`--execute CODE` assembles a line of inline source ahead
  of the main file, and `--pre FILE` includes a whole file ahead of it. Both
  may be repeated and are processed in the order given, and `-e` accepts the
  DRI `!` statement separator. This is how a source file's CPU mode or a
  conditional-assembly symbol can be set from the command line without editing
  the file — `um80 -e .z80 file.mac`. Note that in this release the options
  existed only in the unused `src/um80` script; see 0.3.30.

## [0.3.28] - 2026-01-06

### Fixed
- ul80 linker: External references resolved to DSEG and COMMON symbols are now
  recorded in the PRL relocation bitmap as well. 0.3.27 marked only targets in
  CSEG, so a cross-module pointer into another module's data segment or a
  COMMON block stayed at its link-time address when MP/M loaded the .PRL or
  .SPR anywhere else.

## [0.3.27] - 2026-01-06

### Fixed
- ul80 linker: Addresses patched in while resolving an external reference are
  included in the PRL relocation bitmap. The bitmap was built only from the
  relocations the linker applied from a module's own relocation records, so an
  EXTRN resolved to a symbol in another module — every cross-module call or
  jump — was written as a link-time address and never relocated when the image
  was loaded at its real page. A single-module .PRL was correct, which is why
  this survived as long as it did.

## [0.3.26] - 2026-01-06

### Fixed
- `__version__` is read from the installed package metadata instead of being a
  hardcoded literal in `um80/__init__.py`. It had to be edited by hand in step
  with pyproject.toml and regularly was not: 0.3.12 and 0.3.14 were both yanked
  for exactly this, and every tool in 0.3.25 reported itself as 0.3.24. There
  is now one place to change.

## [0.3.25] - 2026-01-05

### Fixed
- um80 assembler: `$` evaluated one byte too high in the 8080 instructions that
  take an address operand (JMP, the conditional jumps, CALL, the conditional
  calls, LXI, LDA and their kin). The opcode byte was emitted before the
  operand expression was parsed, so `$` saw the location counter already
  advanced past it: `JNZ $-5H` assembled a target one byte beyond the one
  written. The expression is now parsed first and the opcode emitted after.
- um80 assembler: A CSEG/DSEG/ASEG directive now emits a SET_LOC record, so the
  linker switches output buffers where the source does. Without it the bytes
  after a segment switch were accumulated into the previous segment's buffer.
- ul80 linker: DS zero fill was applied only when the location counter advanced
  within the current segment, so space reserved immediately after a switch to
  another segment was not filled.

### Changed
- ul80 linker: DS directives now emit zeros by default; `--no-ds-zeros`
  restores the old behavior of treating reserved space as BSS. PRL and SPR
  images must be contiguous, and space reserved at the end of a segment was
  simply absent from the file — which is what prevented MPM.SYS from being
  built with these tools.

## [0.3.24] - 2025-12-31

### Fixed
- um80 assembler: Fixed ORG tracking to only apply to ASEG (absolute segment).
  ORG in CSEG/DSEG now correctly just sets the location counter without affecting
  segment origin. Fixes `org $-1` patterns in relocatable code that broke in 0.3.5.

## [0.3.20] - 2025-12-28

### Changed
- Added GitHub Actions workflow for automated PyPI publishing via trusted publishers.

## [0.3.19] - 2025-12-28

### Fixed
- ul80 linker: PRL/SPR output now defaults to origin 0 instead of 0x100.
  Previously, --prl incorrectly used the CP/M COM default origin, causing
  all addresses to be 0x100 too high in SPR files.

## [0.3.18] - 2025-12-28

### Fixed
- ul80 linker: Binary output files (.COM and .PRL) now padded to 128-byte
  CP/M record boundary. Fixes MP/M 2 .SPR file loading issues.

## [0.3.17] - 2025-12-21

### Fixed
- ul80 linker: Fixed segment buffer management when switching between segments
  (e.g., CSEG -> DSEG -> CSEG). Previously, returning to a segment could overwrite
  data from other segments. Now uses separate buffers per segment type.

### Added
- Test suite for DS and ORG directive combinations (`tests/test_ds_org.py`)
  covering segment switching, RST vector layouts, and external references.

## [0.3.16] - 2025-12-18

### Added
- ul80 linker: Predefined `__END__` symbol pointing to the first free byte after
  all linked segments (code + data + common blocks). Useful for dynamic memory
  allocation in CP/M programs.
- Test suite for `__END__` symbol (`tests/test_end_symbol.py`)

### Fixed
- ul80 linker: Fixed segment buffer offset calculation for external references
  in absolute-origin code (ORG directive with absolute address).

## [0.3.15] - 2024-12-16

### Fixed
- ul80 linker: Fixed segment buffer management to prevent SET_LOC to new segments
  from overwriting bytes from earlier segments. Chain following now correctly uses
  buffer offsets instead of segment-relative addresses.

## [0.3.14] - 2024-12-16 [YANKED]

Yanked due to missing `__version__` update. Use 0.3.15 instead.

## [0.3.13] - 2024-12-14

### Fixed
- Symbol case sensitivity: REL file reader now uppercases all symbols when
  reading, matching original Microsoft L80 behavior. The linker is now fully
  case-insensitive regardless of the source assembler.

### Added
- Test suite for case sensitivity handling (`tests/test_case_sensitivity.py`)

## [0.3.12] - 2024-12-14 [YANKED]

Yanked due to missing `__version__` update. Use 0.3.13 instead.

## [0.3.11] - 2024-11-26

### Added
- Library (.lib) file support in ul80 linker

## [0.3.10] - 2024-11-26

### Added
- MP/M .PRL (Page Relocatable) output format support in ul80

## [0.3.9] - 2024-11-26

### Fixed
- .SYM file output format for SID.COM/ZSID.COM debugger compatibility

## [0.3.8] - 2024-11-26

### Fixed
- REPT/IRP/IRPC directives inside macros
- `&` substitution operator in macros
- Angle bracket stripping in macro arguments

## [0.3.7] - 2024-11-26

### Fixed
- DC pseudo-op handling

## [0.3.6] - 2024-11-26

### Fixed
- Relocatable address emission with ORG directive

## [0.3.5] - 2024-11-26

### Fixed
- ORG to high addresses no longer outputs spurious zeros

## [0.3.4] - 2024-11-26

### Fixed
- LD indirect addressing with external references and segments
- LD SP parsing improvements

## [0.3.0] - 2024-11-26

### Added
- ux80: 8080 to Z80 assembly translator

## [0.2.4] - 2024-11-26

### Added
- Named labels in ud80 disassembler
- DC/DA string directives support
- Jump table detection and support

## [0.2.1] - 2024-11-26

### Fixed
- GitHub URLs in package metadata

## [0.2.0] - 2024-11-26

### Added
- ud80: 8080/Z80 disassembler for CP/M .COM files
- Z80 instruction set support in um80

## [0.1.0] - 2024-11-26

### Added
- Initial release
- um80: MACRO-80 compatible assembler
- ul80: LINK-80 compatible linker
- ulib80: LIB-80 compatible library manager
- ucref80: Cross-reference utility
