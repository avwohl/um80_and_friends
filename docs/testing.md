# Testing

The test suite (1750 tests) runs under `pytest`:

```bash
pip install -e ".[dev]"
pytest                                    # run everything
pytest tests/test_expr_precedence.py -v   # one file, verbose
```

## Compatibility tests

The compatibility tests in the table below were validated against the
genuine Microsoft MACRO-80 (M80) 3.44 and LINK-80 (L80) 3.44 binaries.
Each expected value was confirmed when the same source was assembled with the
real assembler M80.
Thus the tests keep um80 and ul80 at the documented behavior of M80.
The tests that are marked (DRI) were also checked against the Digital
Research (DRI) assemblers MAC 2.0 and RMAC 1.1.

Where a row says "notes below", the section "Notes on the compatibility
tests" has the full text for the row.

| File | Covers |
|------|--------|
| `test_expr_precedence.py` | Operator precedence (unary `-`/`NOT`/`HIGH`/`LOW`, relational, shifts) |
| `test_macro_bang_args.py` | The statement separator `!` of DRI and the quote character `!` of M80 in macro arguments, escaped commas |
| `test_macro_concat.py` | `&` concatenation: leading/trailing/shared, in-string `&param`, case folding |
| `test_macro_expansion.py` | EXITM in conditionals, macro shadowing built-ins, string-safe substitution, `NUL` |
| `test_macro_arguments.py` | (DRI) How macro call arguments and `IRP` lists read `;`, `<...>`, `>`, commas, blanks, `!`, `"` and `%` (notes below) |
| `test_macro_conditionals.py` | (DRI) `EXITM` and an `IF` that a macro body leaves open (notes below) |
| `test_macro_endm_label.py` | (DRI) A label on the `ENDM` of a body (notes below) |
| `test_macro_names.py` | (DRI) A macro body is matched to its parameters name by name (notes below) |
| `test_macro_percent.py` | (DRI) A `%` argument is its value at the call (notes below) |
| `test_repeat_blocks.py` | Nested REPT/IRP/IRPC, IRP sublists, EXITM |
| `test_radix_conditional.py` | Decimal `.RADIX` operand, unterminated and duplicate-`ELSE` messages |
| `test_symbol_class.py` | Redefinability classes: SET compared with EQU and labels |
| `test_debug_info.py` | `um80 --debug-info`, ulib80 container version 2 and `ul80 --debug-info` (docs/debug_info.md) (notes below) |
| `test_dbg2elf.py` | `dbg2elf` (docs/gdb.md): the ELF file of `sumto.mac`. No GDB needed (notes below) |
| `test_gdb.py` | Live GDB 18.1 with the z80 target against `cpmemu --gdb` (notes below) |
| `test_source_position.py` | The physical line of the source file in messages and in the .PRN listing file (notes below) |
| `test_z80_and_charconst.py` | `LD A,I`/`LD A,R` encoding, two-character constant byte order |
| `test_linker_segments.py` | Absolute ASEG placement, mixed CSEG+ASEG, COMMON-only modules |
| `test_linker_absolute_code.py` | The code of a module above absolute code, and absolute code that overlaps (notes below) |
| `test_ul80_rom.py` | ul80 ROM options, and a full crt0 ROM link (notes below) |
| `test_linker_dupglobal.py` | A public symbol that two modules define (notes below) |
| `test_linker_loaded_over.py` | A byte written to the same address as a relocatable word or an item-12 chain word (notes below) |
| `test_irp_list_brackets.py` | (DRI) The `<...>` list of an `IRP` or `IRPC` (notes below) |
| `test_module_name.py` | The module name from `NAME('X')` and, without it, from the last `TITLE` |
| `test_extrn_declared.py` | An `EXTRN` that is never used (notes below) |
| `test_hash_external.py` | `X##` and `-t` (issue #6) (notes below) |
| `test_dot_names.py` | A name that begins with `.`, as in M80 (issue #7) (notes below) |
| `test_ucref80.py` | ucref80 reads `.FOO`, `..BAR` and `X.1` as names, and reads no symbol in a number, a string or a comment |
| `test_truncate_m80.py` | `-t` cuts names to the 6 characters of M80, so a REL file of um80 links with `FBUFP2` in a REL file of M80 |
| `test_parity_bit.py` | (DRI) Bit 7 of a source byte (notes below) |
| `test_equ_name_column.py` | (DRI) The name of an `EQU`, `SET`, `DEFL`, `ASET` or `MACRO` may be indented |
| `test_register_values.py` | (DRI) A register operand is an expression, and a register name is its number (notes below) |
| `test_dri_names.py` | (DRI) A `$` inside a name (notes below) |
| `test_operator_names.py` | Names that look like operators (notes below) |
| `test_condition_names.py` | In Z80 code, a label that has the name of a condition (`P:`, `NZ:`) is the address of `JP`, as in M80 |
| `test_register_expressions.py` | (DRI) A register name in an 8080 expression (notes below) |
| `test_dri_relations.py` | (DRI) The relational operators of MAC, and `HIGH`/`LOW` (notes below) |
| `test_dri_comment_bang.py` | (DRI) A `!` that ends a `;` comment (notes below) |
| `test_dri_after_macro_call.py` | (DRI) The text after a macro call on the same line (notes below) |
| `test_end_directive.py` | (DRI) The text after `END` (notes below) |
| `test_column_one.py` | (DRI) An instruction, a directive or a macro in column 1 (notes below) |
| `test_body_word_before_endm.py` | A word with no colon before the `ENDM`, `MACRO`, `REPT`, `IRP`, `IRPC` or `LOCAL` of a body (notes below) |
| `test_dri_string_value.py` | (DRI) A two-character string used as a value (notes below) |
| `test_dri_if_value.py` | (DRI) The value that makes an `IF` true (notes below) |
| `test_maclib.py` | (DRI) `MACLIB NAME` (notes below) |
| `test_macro_local_bang.py` | (DRI) A `LOCAL` after a `!` in a macro body (notes below) |
| `test_directive_labels.py` | (DRI) A label on an `ORG`, `IF`, `ELSE`, `ENDIF` or `EXITM` line (notes below) |
| `test_m80_arithmetic.py` | (DRI) A unary sign, `/` and `MOD` (notes below) |
| `test_listing_controls.py` | The listing controls of M80 (`.CREF`, `.XCREF`, `.LALL`, `.SFCOND`, `PAGE`, `$EJECT` and others) assemble nothing |
| `test_data_empty_operands.py` | (DRI) An empty operand in a `DB` or a `DW` (notes below) |

## Notes on the compatibility tests

Each subsection below belongs to one row of the table.
A heading that ends with (DRI) belongs to a test that the table marks (DRI).

### `test_macro_arguments.py` (DRI)

The test checks these rules for macro call arguments and `IRP` lists:

- A `;` inside `<...>` in the arguments of a macro call or in an `IRP` list is
  text. The file `DISKDEF.LIB` of DRI is an example.
- A `<...>` group anywhere in an argument or in an `IRP` item loses its
  brackets. Example: `MM 1<2>3` is 123.
- Without `--dri`, an `IRP` item ends at a `;` or at a blank, as in M80.
- With `--dri`, an `IRP` item ends at a comma, as in MAC.
  um80 skips a blank at the start of the item only.
  A `;` or any other blank is an error.
- An `IRPC` with an empty string, as M80 and as MAC go round it.
- With `--dri`, a `>` with no `<` in the arguments of a macro call is text, as
  in MAC.
  Without `--dri`, such a `>` ends the argument, as in M80.
- A comma inside parentheses in a macro call ends the argument, as in M80, MAC
  and RMAC.
- In the same place, a blank ends an argument too.
  Without `--dri`, the blank also separates the next argument, as in M80.
  With `--dri`, the blank ends the arguments, and text after the blank is an
  error, as in MAC.
- A `!` quotes a `;` in the arguments of a macro call or in an `IRP` list, as
  in M80.
- With `--dri`, a `"` in the same place is text, as in MAC.
  A `"` in an `IRPC` string is text in M80, MAC and RMAC.
- With `--dri`, a `<` or `>` in a `%` argument is the operator of MAC.

### `test_macro_conditionals.py` (DRI)

The test checks these rules:

- `EXITM` ends the `IF`s that the `EXITM` is in, without a message.
- With `--dri`, an `IF` that a macro body leaves open ends with the macro body,
  as in MAC.
- Without `--dri`, an `IF` that a macro body leaves open goes on, as in M80.

### `test_macro_endm_label.py` (DRI)

The test covers a label on the `ENDM` of a macro body.

- With `--dri`, the label is defined where the body ends, as in MAC.
  The file `STACK.LIB` of DRI is an example.
- Without `--dri`, the label is ignored, as in M80.
- `L&X: ENDM` ends an `IRP`.

### `test_macro_names.py` (DRI)

A macro body is matched to its parameters name by name.

- `?Y` and `@N` are parameters. The files `COMPARE.LIB` and `STACK.LIB` of DRI
  are examples.
- `?X` and `X?` are not `X`.
- `1X` is 1 then `X`.
- The test uses the name characters of M80 and the name characters of MAC.
- The test checks which `&` goes in a string, in M80 and in RMAC.
- An `IRP` body or an `IRPC` body is matched in the same way.
- A `LOCAL` name works as a parameter.
- An empty argument in a string is a 00 byte in M80 and nothing in MAC.

### `test_macro_percent.py` (DRI)

The test checks these rules:

- A `%` argument is its value at the call, as digits in the current radix.
- An undefined name in a `%` argument is an error.
- M80 evaluates a `%` argument in an `IRP` list.
- In a `REPT` body in a macro, M80 evaluates a `%` argument on each
  repetition.
  The file `SELECT.LIB` of DRI is an example.
- With `--dri`, `%N$C` is the value of `NC`.
- A `%` with no expression is 0, as in M80.
- With `--dri`, a `%` with no expression is an error, as MAC flags the `%` `E`.

### `test_debug_info.py`

The test covers `um80 --debug-info`, ulib80 container version 2 and
`ul80 --debug-info` (docs/debug_info.md).
The test checks these statements:

- The `.rel`, `.com`, `.SYM` and `.PRN` files are the same with and without the
  options.
- The label addresses of `prog.dbg` are the `.SYM` addresses.
- Each instruction row has the line of the `.PRN`.
- A macro row has the body line.
- A row that a later module overwrote is deleted.
- The line rows of `tools/dbg2elf_proto/sumto.mac` equal the rows of the
  prototype.

The test also covers these cases and items:

- A JR promotion, a `.PHASE` block, a DS with no fill and a library module.
- The D4 merge rule and `nostmt`.
- The marker grammar and its warnings.
- `--rom-data` load addresses.
- The SHA-256 of the output file.
- A `.dbm` that is out of date.
- A version 1 library.

### `test_dbg2elf.py`

The test covers `dbg2elf` (docs/gdb.md).

- The test reads the ELF file of `sumto.mac` with `tests/elfread.py`.
  The test checks these parts:
  - the ELF header
  - the sections
  - the symbol table
  - the `.debug_line` rows (rule D4)
  - the `.debug_info` (routines, inlined calls, static variables)
- A program file that is out of date or longer is refused.
- The test does not need GDB.

### `test_gdb.py`

The test checks these rules:

- The test runs GDB 18.1 with the z80 target against `cpmemu --gdb`.
- The programs are `sumto.mac`, an inlined call (hand-written and `uc80 -g`),
  and a recursive program with the Python unwinder.
- The test skips, with a reason, when GDB, cpmemu or uc80 is missing.
- `UDB80_REQUIRE_GDB=1`, `UDB80_REQUIRE_CPMEMU=1` and `UDB80_REQUIRE_UC80=1`
  make a skip a failure.
- `UDB80_GDB` names the GDB program.

### `test_source_position.py`

Messages and the .PRN listing file give the physical line of the source file
in these cases:

- after a macro or `REPT`
- in an `INCLUDE` file
- with `-e`
- with `--pre` text

### `test_ul80_rom.py`

The test covers a full crt0 ROM link and these ul80 ROM options:

- `--data-origin`
- `--rom-data` and its `__DATA_*` symbols
- `--bin`
- `--fill`
- `--rom-size`
- `--ram-end`
- `--ram-size`
- `--min-stack`
- hex load addresses
- ASEG vectors with a CSEG

### `test_extrn_declared.py`

- An `EXTRN` that is never used is written as an empty chain and pulls a
  library module.
- ul80 writes a warning if nothing defines the external symbol.

### `test_hash_external.py`

- `X##` names an external symbol by its whole name, as `EXTRN` does.
- `-t` cuts the name to 6 characters in the .REL file only (issue #6).

### `test_linker_absolute_code.py`

The test checks these rules:

- The code of a module is placed above the absolute code that is loaded before
  the code of the module.
- Absolute code that overlaps anything is an error.
- With `--allow-overlap`, absolute code that overlaps anything is a warning.
  The image has the byte that was loaded last.

### `test_linker_dupglobal.py`

The test checks these rules:

- A public symbol that two modules define gives the L80 warning
  `%Mult. Def. Global`.
- The first definition is used.
- With `--fatal-mult-def`, the warning is an error.

### `test_linker_loaded_over.py`

The test checks these rules:

- A byte that is written to the same address as a relocatable word or an
  item-12 chain word replaces the byte of the word.
  L80 does the same, because L80 relocates when L80 loads the bytes.
- The cases are an ORG that goes back, a COMMON block that is declared again,
  and a COMMON block that is shared.

### `test_irp_list_brackets.py` (DRI)

The test checks these rules:

- Without `--dri`, the `<...>` list of an `IRP` or `IRPC` ends at its matching
  `>`, as in M80. Example: `IRPC C,<>>` is empty.
- With `--dri`, the `<...>` list is read as a macro argument, as in MAC and
  RMAC. Example: `IRP X,<1,2>3` is 1 and 23.
- The test also covers the `!` in an `IRP` line or `IRPC` line.

### `test_dot_names.py`

The test checks these rules:

- A name may begin with `.`, as in M80 (issue #7).
- The test covers labels, `EQU`/`SET`/`DEFL`, operands and macros.
- `.Z80:` is a label.
  The other directives that start with a dot are labels too, when they have a
  colon.
- A link of two modules gives the same result as L80.
- The expected bytes were read from M80 3.44 and L80 3.44.

### `test_parity_bit.py` (DRI)

Bit 7 of a source byte is cleared.

Without `--dri`, the rules are the rules of M80:

- A line that ends with CR 8AH ends the line.
- C1H in a string is `A`.
- An 8AH that is not after a CR is ignored.

With `--dri`, the rules are the rules that MAC and RMAC use to read the bytes:

- An 8AH is a LF.
  In a string, the LF is 0AH.
  In the arguments of a macro call, the LF is text.
- An 8DH is a CR whose LF is the next item.

### `test_register_values.py` (DRI)

The test checks these rules:

- A register operand is an expression, and a register name is its number.
- `RD EQU D` and `DAD RD` give `DAD D`.
- `DAD RP`, with `RP EQU H` later in the source, is `DAD H`.
- An odd register pair is an error.
- An address is its offset, as in M80.

### `test_dri_names.py` (DRI)

The test checks these rules:

- With `--dri`, a `$` inside a name is ignored, as MAC and RMAC do.
  The `$` is not ignored in the arguments of a macro call or in an `IRP` list
  or `IRPC` list.
- Without `--dri`, the `$` is part of the name, as in M80.

### `test_operator_names.py`

The test checks these rules:

- A name that ends in the letters of an operator is read as a whole.
  Example: `X1EQ+2`.
- A symbol that has the name of an operator is that symbol, as in M80.
  Examples: `EQ:`, `TYPE EQU 5`.
- An operator with nothing on one side is an error.
- The test also covers `TYPE` of an expression.

### `test_register_expressions.py` (DRI)

The test checks these rules:

- A register name is its number in any 8080 expression.
  Examples: `DB B`, `X EQU D+1`.
- M80 flags two of these in one expression: `PUSH A` and `MOV M,M`.
- With `--dri`, `PUSH A` and `MOV M,M` are accepted, as in MAC.
- A symbol that has the name of a register is that symbol, as in M80.

### `test_dri_relations.py` (DRI)

The test checks these rules:

- With `--dri`, um80 accepts the operators of MAC: `=`, `<`, `<=`, `>`, `>=`,
  `<>`.
- With `--dri`, `HIGH` and `LOW` apply to all that follows, as in MAC and RMAC.
- Without `--dri`, um80 works as M80 does.

### `test_dri_comment_bang.py` (DRI)

The test checks these rules:

- With `--dri`, a `!` ends a `;` comment and starts the next statement, as in
  MAC and RMAC.
  Example, from the Console Command Processor (CCP) of CP/M 2.0:
  `nosub: ;no submit file! call del$sub`.
- The `!` does this in a `*` line, in a macro body, in a `REPT`, `IRP` or
  `IRPC` line, and before an `ENDM` or `EXITM`.
- Without `--dri`, a comment runs to the end of the line, as in M80.

### `test_dri_after_macro_call.py` (DRI)

With `--dri`, the text after a macro call on the same line is read as MAC and
RMAC read the text.

- `MM ;c! DB 1` assembles the `DB`.
- `MM A;c! DB 1`, `MM A ! DB 1` and `MM ;c ! DB 1` do not assemble the `DB`.
  um80 writes a warning.
- A macro call reads as many arguments as the macro has parameters.
- A body line or a false `IF` line that starts with a macro call is read for
  its `ENDM` or `ENDIF`.

### `test_end_directive.py` (DRI)

The test checks these rules:

- Nothing after `END` is assembled, as in M80, MAC and RMAC.
  The assembler assembles nothing after `END` in these places:
  - the rest of the file
  - a macro
  - a `REPT`
  - an `INCLUDE` file
- Without `--dri`, an `END` in a `MACLIB` file ends the source, as in M80.
  With `--dri`, the `END` ends only the library, as in MAC and RMAC.
- With `--dri`, the statement `END START` can name a `START` that the source
  defines after the `END`.
  In this case, um80 takes no start address, as MAC and RMAC do.
  M80 gives `U`.

### `test_column_one.py` (DRI)

The test checks these rules:

- An instruction, a directive or a macro in column 1 is read as an
  instruction, a directive or a macro.
- Without `--dri`, as in M80, a statement of values is a `DB`, and a label
  needs a colon.
- With `--dri`, as in MAC, a word with no colon is a label.
  A line number is ignored.
  A `*` line is ignored.

### `test_body_word_before_endm.py`

The test covers a word that has no colon and is not an instruction or a
directive.
The word is before the `ENDM`, `MACRO`, `REPT`, `IRP`, `IRPC` or `LOCAL` of a
`MACRO`, `IRP` or `IRPC` body that the source defines.

- Examples: `LAB ENDM`, `<TAB>LAB<TAB>ENDM`, `L&P ENDM`, `LAB LOCAL QQ`.
- The word is read as M80 reads the word.
- The rule does not apply in a `REPT` body.
- The rule does not apply after an instruction.
- With `--dri`, a word made with `&` is a label, as in MAC.

### `test_dri_string_value.py` (DRI)

The test checks these rules:

- With `--dri`, a two-character string that is used as a value has the first
  character in the low byte, as in MAC and RMAC.
  `DW 'AB'` is 41 42.
- Without `--dri`, the first character is in the high byte, as in M80.
  `DW 'AB'` is 42 41.
- With `--dri`, `DB "A"` is an error, as MAC and RMAC accept only `'` around a
  string.

### `test_dri_if_value.py` (DRI)

The test checks these rules:

- With `--dri`, an `IF` is true when bit 0 of its value is set, as in MAC and
  RMAC.
  `IF 2` and `IF NOT 1` are false.
- Without `--dri`, an `IF` is true when the value is not 0, as in M80.
- `IFT`, `IFE`, `COND` and the other `IF`s that MAC does not have keep the
  meaning that they have in M80.

### `test_maclib.py` (DRI)

The test checks these rules:

- Without `--dri`, `MACLIB NAME` reads `NAME.MAC`, as in M80.
- With `--dri`, `MACLIB NAME` reads `NAME.LIB`, as in MAC and RMAC, and then
  `NAME.MAC`.
- um80 searches for a file name as written, then in upper case and in lower
  case.

With `--dri`, a library is read in pass 1 only, as in MAC and RMAC:

- The code and the data of the library are not assembled.
- The symbols of the library keep their values of pass 1.
- A label that the code of the library moved is a phase error.
- The sizes are the most that pass 1 reached in each segment and `COMMON`
  block.
  The rule for the sizes covers a library that reserves data or `COMMON`
  space and goes back to the code segment too.

### `test_macro_local_bang.py` (DRI)

A `LOCAL` after a `!` in a macro body declares its names, as in MAC and RMAC.

- Examples: `NOP! LOCAL QQ` and `LOCAL QQ! NOP`.
  With `--dri`, `NOP ;c! LOCAL QQ` is also an example.
- The declaration applies to the statements after the `LOCAL` on the line and
  to the lines after the line.
- A statement before the `LOCAL` reads the name as the name was before the
  `LOCAL`.
  Example: `LXI H,QQ! LOCAL QQ`.
- With `--dri`, a `LOCAL` that MAC ignores after a macro call (`NN! LOCAL QQ`)
  declares nothing.

### `test_directive_labels.py` (DRI)

The test checks these rules:

- Without `--dri`, a label on an `ORG` is the location before the `ORG`, as in
  M80.
- With `--dri`, a label on an `ORG` is the location that the `ORG` sets, as in
  MAC and RMAC.
- With `--dri`, a label on an `ORG` is an error when the `ORG` operand is a
  symbol that is defined further down.
  MAC and RMAC flag the error `P`.
- A label on an `IF`, `ELSE`, `ENDIF` or `EXITM` line is defined where the previous
  line was assembled.
  The rule is the same in M80, MAC and RMAC.

### `test_m80_arithmetic.py` (DRI)


Without `--dri`, the rules are the rules of M80:

- A unary sign applies to the term after the sign, before `* / MOD SHL SHR`.
- `/` and `MOD` use signed division.
- Examples: `-1 SHR 8` is 00FFH, and 8000H/2 is 0C000H.

With `--dri`, the rules are the rules of MAC and RMAC:

- The sign applies to all of these operators.
- Division is unsigned.

In all cases, `x MOD 0` is `x`.

### `test_data_empty_operands.py` (DRI)

The test checks these rules:

- An empty operand in a `DB` or a `DW` is 0, with a warning, as in M80.
  Examples: `DB`, `DB 1,`, `DW 1,,2`.
- With `--dri`, an empty operand in a `DB` or a `DW` is an error, as MAC and
  RMAC flag the operand.
- With `--dri`, an empty operand in a `DEFB` or `DEFW` is an error.
  MAC and RMAC treat `DEFB` and `DEFW` as a label.
  The error message says so.

## Further tests

Further tests cover the toolchain more broadly:

- `test_ds_org.py`: DS/ORG and segment placement.
- `test_defs_fill.py`: DEFS fill value.
- `test_end_symbol.py`: `END` entry symbol and `__END__`.
- `test_ext_alias.py`: external aliases.
- `test_jr_promotion.py`: JR/DJNZ out-of-range promotion.
- `test_no_operand_strict.py`: an operand on a no-operand instruction is an
  error, the one deliberate divergence from M80.
- `test_case_sensitivity.py`.
- `test_packaging.py`: the files that `MANIFEST.in` and `pyproject.toml` name
  exist, and the source distribution carries `CHANGELOG.md`.

## mbasic2025: historic binaries, byte for byte

The test `test_mbasic2025.py` builds the sources of
[mbasic2025](https://github.com/avwohl/mbasic2025) with the build commands of
each variant.
The test uses um80 and ul80 from this checkout.
The test compares the results, byte for byte, with the historic Microsoft
binaries.
The binaries are:

- MBASIC 5.21 (14 modules, and one Z80 file)
- Altair 4K and 8K BASIC 4.0

The test needs a checkout of mbasic2025, at `$MBASIC2025_DIR` or in the same
directory as this repository.
Without a checkout, the test is skipped.
To do the test, clone mbasic2025 and run the test:

```bash
git clone https://github.com/avwohl/mbasic2025 ../mbasic2025
pytest tests/test_mbasic2025.py -v -rw
```

CI (`.github/workflows/tests.yml`) gets a copy of mbasic2025 at a pinned
commit.
CI runs the whole suite on every push and on every pull request.
To test with a newer mbasic2025, change the `ref:` in
`.github/workflows/tests.yml`.

### The four-way link test

The tool `tools/fourway_mbasic.py` builds the same sources with every mix of
M80 and L80 and of um80 and ul80.

1. Each assembler builds all modules.
2. Then, for each module in turn, make a set in which that one module comes
   from the other assembler.
3. Both linkers link each of these sets of modules.
4. The tool compares each image with the M80 + L80 build and with the historic
   binary.

The Microsoft binaries are not in this repository.
Give the path of each Microsoft binary and a
[cpmemu](https://github.com/avwohl/cpmemu) to run the binaries:

```bash
python3 tools/fourway_mbasic.py --m80 path/M80.COM --l80 path/L80.COM \
    --cpmemu path/cpmemu [--variant mbasic_521] [--um80-flag=-t]
```

The exit status is 1 if any mix differs from the M80 + L80 build.
Without `--um80-flag=-t`, 8 of the 60 `mbasic_521` links fail.
The reason is a 7-character name.
The tool prints the name.
Use `-t` when you use the exit status as a pass/fail check.

The file [mbasic2025.md](mbasic2025.md) has the results and the changes that
the sources of mbasic2025 need.
