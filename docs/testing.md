# Testing

The test suite (1319 tests) runs under `pytest`:

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
| `test_macro_arguments.py` | (DRI) A `;` inside `<...>` in a macro call's arguments or an `IRP` list is text (DRI's `DISKDEF.LIB`); a `<...>` group anywhere in an argument or `IRP` item loses its brackets (`MM 1<2>3` is 123); an `IRP` item ends at a `;` or a blank, as in M80, or at a comma, with a blank skipped at its start only, and a `;` or any other blank is an error, as in MAC (`--dri`); an `IRPC` with an empty string, as M80 and as MAC go round it; a `>` with no `<` in a macro call's arguments is text, as in MAC (`--dri`), or ends the argument, as in M80; a comma inside parentheses in a macro call ends the argument, as in all three; a blank ends one too, and separates the next, as in M80, or ends the arguments, and text after it is an error, as in MAC (`--dri`); a `!` quotes a `;` in a macro call's arguments or an `IRP` list, as in M80; a `"` there is text, as in MAC (`--dri`), and in an `IRPC` string in all three; with `--dri` a `<` or `>` in a `%` argument is MAC's operator |
| `test_macro_conditionals.py` | (DRI) `EXITM` ends the `IF`s it is in without a message; with `--dri` an `IF` a macro body leaves open ends with it, as in MAC, and without it goes on, as in M80 |
| `test_macro_endm_label.py` | (DRI) A label on the `ENDM` of a body: defined where the body ends with `--dri`, as in MAC (DRI's `STACK.LIB`); ignored without, as in M80; `L&X: ENDM` ends an `IRP` |
| `test_macro_names.py` | (DRI) A macro body is matched to its parameters name by name: `?Y` and `@N` are parameters (DRI's `COMPARE.LIB`, `STACK.LIB`), `?X` and `X?` are not `X`, `1X` is 1 then `X`; M80's and MAC's name characters; which `&` goes in a string, in M80 and in RMAC; an `IRP`/`IRPC` body the same way; a `LOCAL` name as a parameter; an empty argument in a string is a 00 byte in M80, nothing in MAC |
| `test_macro_percent.py` | (DRI) A `%` argument is its value at the call, as digits in the current radix, and an undefined name in it an error; M80 evaluates one in an `IRP` list; in a `REPT` body in a macro, on each repetition (DRI's `SELECT.LIB`); with `--dri`, `%N$C` is the value of `NC`; a `%` with no expression is 0, as in M80, and an error with `--dri`, as MAC flags it `E` |
| `test_repeat_blocks.py` | Nested REPT/IRP/IRPC, IRP sublists, EXITM |
| `test_radix_conditional.py` | Decimal `.RADIX` operand, unterminated / duplicate-`ELSE` diagnostics |
| `test_symbol_class.py` | SET vs. EQU/label redefinability classes |
| `test_z80_and_charconst.py` | `LD A,I`/`LD A,R` encoding, two-character constant byte order |
| `test_linker_segments.py` | Absolute ASEG placement, mixed CSEG+ASEG, COMMON-only modules |
| `test_linker_absolute_code.py` | A module's code placed above the absolute code loaded before it; absolute code overlapping anything is an error, or with `--allow-overlap` a warning and the byte loaded last in the image |
| `test_linker_dupglobal.py` | A global two modules define is L80's `%Mult. Def. Global` warning and the first definition is used; with `--fatal-mult-def` an error |
| `test_linker_loaded_over.py` | A byte loaded over a relocatable word or an item-12 chain word (an ORG back, a COMMON block declared again or shared) replaces that byte, as L80 relocates on loading |
| `test_irp_list_brackets.py` | (DRI) An `IRP`/`IRPC` `<...>` list ends at its matching `>` (`IRPC C,<>>` is empty), as in M80; with `--dri` it is read as a macro argument, as in MAC and RMAC (`IRP X,<1,2>3` is 1 and 23); `!` in an `IRP`/`IRPC` line |
| `test_module_name.py` | The module name from `NAME('X')` and, without it, from the last `TITLE` |
| `test_extrn_declared.py` | An `EXTRN` never used is written as an empty chain, and it pulls a library module; ul80 warns if nothing defines it |
| `test_truncate_m80.py` | `-t` cuts names to M80's 6 characters, so a um80 object links with an M80 object's `FBUFP2` |
| `test_parity_bit.py` | (DRI) A source byte's bit 7 is cleared: a line ending CR 8AH ends the line, C1H in a string is `A`, and an 8AH not after a CR is left out, as in M80; with `--dri` it is a LF (0AH in a string, text in a macro call's arguments) and an 8DH a CR whose LF is the next item, as MAC and RMAC read them |
| `test_equ_name_column.py` | (DRI) The name of an `EQU`, `SET`, `DEFL`, `ASET` or `MACRO` may be indented |
| `test_register_values.py` | (DRI) A register operand is an expression and a register name its number: `RD EQU D` / `DAD RD` is `DAD D`, and `DAD RP` with `RP EQU H` further down `DAD H`; an odd register pair is an error; an address is its offset, as in M80 |
| `test_dri_names.py` | (DRI) `--dri` ignores a `$` inside a name, as MAC and RMAC do, but not in a macro call's arguments or an `IRP`/`IRPC` list; without it `$` is part of the name, as in M80 |
| `test_operator_names.py` | A name that ends in an operator's letters (`X1EQ+2`) is read whole; a symbol named like an operator (`EQ:`, `TYPE EQU 5`) is that symbol, as in M80; an operator with nothing on one side is an error; `TYPE` of an expression |
| `test_condition_names.py` | In Z80 code a label named like a condition (`P:`, `NZ:`) is `JP`'s address, as in M80 |
| `test_register_expressions.py` | (DRI) A register name is its number in any 8080 expression (`DB B`, `X EQU D+1`); M80 flags two in one expression, `PUSH A` and `MOV M,M`, MAC takes them (`--dri`); a symbol named like a register is that symbol, as in M80 |
| `test_dri_relations.py` | (DRI) `--dri` takes MAC's `=`, `<`, `<=`, `>`, `>=`, `<>`, and applies `HIGH`/`LOW` to all that follows, as MAC and RMAC do; without it, as M80 does |
| `test_dri_comment_bang.py` | (DRI) With `--dri` a `!` ends a `;` comment and starts the next statement, as in MAC and RMAC (CP/M 2.0's CCP: `nosub: ;no submit file! call del$sub`), in a `*` line, a macro body, a `REPT`/`IRP`/`IRPC` line and before an `ENDM` or `EXITM`; without it a comment runs to the end of the line, as in M80 |
| `test_dri_after_macro_call.py` | (DRI) With `--dri` what follows a macro call on its line is read as MAC and RMAC read it: `MM ;c! DB 1` assembles the `DB`, `MM A;c! DB 1`, `MM A ! DB 1` and `MM ;c ! DB 1` leave it out (with a warning), and a call reads as many arguments as the macro has parameters; a body line or a false `IF` line that starts with a macro call is read for its `ENDM` or `ENDIF` |
| `test_end_directive.py` | (DRI) Nothing after `END` is assembled - the rest of the file, a macro, a `REPT`, an `INCLUDE` file - as in M80, MAC and RMAC; an `END` in a `MACLIB` file ends the source as in M80, or with `--dri` only the library, as in MAC and RMAC; with `--dri` `END START`, `START` defined after it, takes no start address, as in MAC and RMAC (M80: U) |
| `test_column_one.py` | (DRI) An instruction, directive or macro in column 1 is one; a statement of values is a `DB` and a label needs a colon, as in M80; with `--dri` a word with no colon is a label and a line number or a `*` line is ignored, as in MAC |
| `test_body_word_before_endm.py` | A word with no colon that is no instruction or directive in front of the `ENDM`, `MACRO`, `REPT`, `IRP`, `IRPC` or `LOCAL` of a `MACRO`, `IRP` or `IRPC` body being defined (`LAB ENDM`, `<TAB>LAB<TAB>ENDM`, `L&P ENDM`, `LAB LOCAL QQ`) is read as M80 reads it; not in a `REPT` body, nor after an instruction; with `--dri` a word made with `&` is a label, as in MAC |
| `test_dri_string_value.py` | (DRI) A two-character string used as a value has its first character in the low byte with `--dri`, as in MAC and RMAC (`DW 'AB'` is 41 42), and in the high byte without, as in M80 (42 41); with `--dri` `DB "A"` is an error, as MAC and RMAC quote with `'` only |
| `test_dri_if_value.py` | (DRI) With `--dri` an `IF` is true when bit 0 of its value is set, as in MAC and RMAC (`IF 2` and `IF NOT 1` are false), and without when it is not 0, as in M80; `IFT`, `IFE`, `COND` and the other `IF`s MAC does not have keep M80's meaning |
| `test_maclib.py` | (DRI) `MACLIB NAME` reads `NAME.MAC`, as in M80, or with `--dri` `NAME.LIB`, as in MAC and RMAC, and then `NAME.MAC`; a file name is looked for as written, then in upper and in lower case; with `--dri` a library is read in pass 1 only, as in MAC and RMAC: its code and data are not assembled, its symbols keep their values of pass 1, a label its code moved is a phase error, and the sizes are the most pass 1 reached in each segment and `COMMON` block, those of a library that reserves data or `COMMON` space and goes back to the code segment too |
| `test_macro_local_bang.py` | (DRI) A `LOCAL` after a `!` in a macro body (`NOP! LOCAL QQ`, `LOCAL QQ! NOP`, with `--dri` `NOP ;c! LOCAL QQ`) declares its names, as in MAC and RMAC, for the statements after it on the line and the lines after it: a statement before it reads the name as it was (`LXI H,QQ! LOCAL QQ`); with `--dri` one MAC leaves out after a macro call (`NN! LOCAL QQ`) declares nothing |
| `test_directive_labels.py` | (DRI) A label on an `ORG` is the location before it, as in M80, or with `--dri` the location the `ORG` sets, as in MAC and RMAC, and an error on an `ORG` of a symbol defined further down, as MAC and RMAC flag it P; a label on an `IF`, `ELSE`, `ENDIF` or `EXITM` line is defined where the line before it was assembled, as in all three |
| `test_m80_arithmetic.py` | (DRI) A unary sign applies to the term after it, before `* / MOD SHL SHR`, and `/` and `MOD` divide signed, as in M80 (`-1 SHR 8` is 00FFH, 8000H/2 0C000H); with `--dri` the sign applies to all of them and division is unsigned, as in MAC and RMAC; `x MOD 0` is `x` |
| `test_listing_controls.py` | M80's listing controls (`.CREF`, `.XCREF`, `.LALL`, `.SFCOND`, `PAGE`, `$EJECT`, ...) assemble nothing |
| `test_data_empty_operands.py` | (DRI) An empty operand in a `DB` or a `DW` (`DB`, `DB 1,`, `DW 1,,2`) is 0, as in M80, with a warning; with `--dri` an error, as MAC and RMAC flag it, and in a `DEFB` or `DEFW`, which MAC and RMAC take for a label, an error that says so |

Further tests cover the toolchain more broadly: `test_ds_org.py` (DS/ORG and
segment placement), `test_defs_fill.py` (DEFS fill value), `test_end_symbol.py`
(`END` entry symbol and `__END__`), `test_ext_alias.py` (external aliases),
`test_jr_promotion.py` (JR/DJNZ out-of-range promotion),
`test_no_operand_strict.py` (an operand on a no-operand instruction is an
error, the one deliberate divergence from M80), `test_case_sensitivity.py`,
and `test_packaging.py` (the files `MANIFEST.in` and `pyproject.toml` name
exist, and the source distribution carries `CHANGELOG.md`).

## mbasic2025: historic binaries, byte for byte

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

[mbasic2025.md](mbasic2025.md) has the results and the changes that
mbasic2025's sources need.
