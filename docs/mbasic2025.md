# mbasic2025: historic Microsoft BASIC, byte for byte

[mbasic2025](https://github.com/avwohl/mbasic2025) has MACRO-80 (M80)
sources for historic Microsoft BASIC binaries. um80 and ul80 build the
binaries from these sources, byte for byte. mbasic2025 is a good
test of the toolchain. The sources have:

- about 66,000 lines of real Microsoft assembly language
- macros
- 14-module links
- 8080 code and Z80 code
- ROM images at address 0

This page describes how mbasic2025 is part of the test suite. The page also
records what happened when MACRO-80 3.44 and LINK-80 3.44 from Microsoft
built the same sources. They built the sources alone and in every mix with
um80 and ul80.

| Variant | Build (in mbasic2025) | Reference | Bytes |
|---|---|---|---|
| `mbasic_521` | `mbasic_521/build.sh`: 14 modules | `mbasic_521/com/mbasic.com`, MBASIC 5.21 | 24320 |
| `mbasicz` | `mbasicz/build.sh`: one `.Z80` file | `mbasicz/com/mbasic.com`, the same binary | 24320 |
| `4k` | `4k8k/4k/build_4k.sh`: `4kbas40_new.mac`, linked at 0 | `4k8k/4k/4kbas40.bin`, Altair 4K BASIC 4.0 | 3833 |
| `4k-annotated` | the same, from the annotated `4kbas40.mac` (ASEG) | the same | 3833 |
| `8k` | `4k8k/8k/build_8k.sh`, linked at 0 | `4k8k/8k/8kbas.bin`, Altair 8K BASIC 4.0 | 8192 |
| `mbasic_52` | `mbasic_52/makefile`: 14 modules | none: see below | 24338 |

`mbasic_52` has the MBASIC 5.2 sources of an OEM build ("BASIC 5.2 / MAGIC
Operating System / Copyright 1982"). mbasic2025 has no binary of that build.
The test checks the image that the Microsoft M80 and L80 build from
the sources against a fixed value.

`mystery_8k` is an OCR of a 1978 assembly
listing. The work to clean `mystery_8k` has only started, and
`mystery_8k` has no binary. `mystery_8k` does not assemble with any um80.
um80 reports about 150 errors, all in the OCR text.

## The test

The test `tests/test_mbasic2025.py` copies each variant. Then the test runs
the build commands of the variant with the `um80` and `ul80` of this
checkout. The test starts the tools the way the build scripts do, as
`python -m um80.um80`. Last, the test compares the result with the
reference, byte for byte.

The test records the SHA-256 hash of each reference. If a reference changes,
the test notices the change and does not trust the new reference. The test
also checks the image of `mbasic_52` against a fixed value. Therefore the
test notices any change in how um80 assembles those sources.

### Where the sources come from

- The sources come from `$MBASIC2025_DIR`, or from a `mbasic2025` checkout
  in the same directory as this repository.
- If the sources are not present, the test skips.
- If `$MBASIC2025_REQUIRED` is set, the test fails instead of a skip.

### CI

CI runs the whole test suite on every push and
pull request. The workflow `.github/workflows/tests.yml` checks out
`avwohl/mbasic2025` at a fixed commit. Therefore a commit to mbasic2025
alone cannot make the CI of um80 fail.

The CI job stops after 15 minutes. Each time that the test starts um80 or
ul80, the tool stops after 5 minutes.

To take a newer mbasic2025, do these steps:

1. Change the `ref:` in the workflow.
2. Run the test.
3. Update the test in the same commit.

### Padding of the output file

ul80 pads the output file to a whole 128-byte CP/M record. L80 writes whole
records too. If a reference is not a whole number of records, the test
compares the output with the reference up to the length of the reference.
The padding after that length must be zeros.

For example, 4K BASIC is 3833 bytes. The file from ul80 is 3840 bytes.

### Changed lines in the copy

Three sources have a defect that the historic binary does not have (see
below). The test changes those lines in its copy. The test writes a warning
for each change. When mbasic2025 changes a line, the test does not change
that line any more.

## Byte for byte with um80 and ul80

The build of each variant used the commands of its own build script.

| Variant | 0.3.48 | 0.3.49 | this branch |
|---|---|---|---|
| `mbasic_521` | identical | identical | identical |
| `mbasicz` | 12 bytes differ | 12 bytes differ | 12 bytes differ (identical with the source change) |
| `4k` | identical (+7 bytes of padding) | identical (+7) | identical (+7) |
| `4k-annotated` | identical (+7) | identical (+7) | 3 bytes differ (identical with the source change) |
| `8k` | identical | identical | 6645 bytes differ (identical with the source change) |
| `mbasic_52` | 1 byte differs from M80 + L80 | = M80 + L80 | = M80 + L80 |

Version 0.3.49 has no regressions. The differences are:

- `mbasicz`: twelve message strings are `dc`.
  - The `dc` directive sets the high bit of the last character.
  - The historic binary has no high bits in these strings (for example `Ok`
    at 0C46H).
  - Before version 0.3.7, um80 treated `DC` as `DB`.
  - Version 0.3.7 (2025-11-29) of um80 made `DC` work as the `DC` of M80
    works.
  - mbasic2025 changed the same strings in `mbasic_521` to `db` (its commit
    1ba49ad), but it did not change `mbasicz`.
- `4k`: the image is identical.
  - The file is 7 bytes longer. Since version 0.3.18, ul80 pads the output
    to a 128-byte record.
  - `build_4k.sh` compares the whole file with `cmp`, so
    `build_4k.sh` has reported a failure since version 0.3.18.
- `4k-annotated` and `8k`: see "`rdc <!>>`" below.
  - um80 now assembles these lines as M80 does. The result is not the
    historic binary.
  - Therefore mbasic2025 had to change these lines for the present um80.
    mbasic2025 changed them in the same release cycle (see "What mbasic2025 changed").
  - With mbasic2025 2d19520 or later, every variant builds byte for byte.
    CI checks that revision.
- `mbasic_52` in version 0.3.48:
  - `DCPM.MAC` has `lxi h,filnam+9-0-0-2*0`. `FILNAM` is external.
  - Version 0.3.48 kept only the last constant, so the result was `FILNAM`.
  - Version 0.3.49 fixed the defect (see the CHANGELOG entry for 0.3.49).
    The result is now `FILNAM+9`, as M80 assembles the expression.
  - The instruction is at 3BF2H. The low byte of the operand of the
    instruction is at 3BF3H.
  - The low byte is 2AH in the output of M80 and of version 0.3.49. The low
    byte is 21H in the output of version 0.3.48.

## Every mix with the genuine MACRO-80 and LINK-80

The tool `tools/fourway_mbasic.py` does the four-way link test. The tool
assembles every module with M80.COM from Microsoft and with um80. The tool
compares the two REL files of each module. Then the tool links each set of
REL files with L80.COM from Microsoft and with ul80.

A variant of one module has four builds. A variant of several modules has
these builds:

- all-M80
- all-um80
- each "one module from M80, the rest from um80"
- each "one module from um80, the rest from M80"

For 14 modules, the result is 30 sets of REL files and 60 links. The tool
compares each image with the all-Microsoft build and with the historic
binary.

The Microsoft binaries are not in this repository. The command line of the
tool is:

```bash
python3 tools/fourway_mbasic.py --m80 path/M80.COM --l80 path/L80.COM \
    --cpmemu path/cpmemu [--mbasic2025 DIR] [--variant NAME] [--um80-flag=-t]
```

The tool gives one of these exit statuses:

- 1: any image built with um80 or ul80 differs from the M80 + L80 build.
- 2: a setup error.
- 0: all other cases.

Without `--um80-flag=-t`, 8 links of `mbasic_521` fail. These links mix
`BINTRP.REL` and `F4.REL` from different assemblers (see "`FBUFP27`" below).
Therefore the exit status is 1. The tool then writes the cause and says to
use `-t`. If you use the exit status as a pass or fail check, use `-t`.

### Setup of the Microsoft programs

The tool uses MACRO-80 3.44 and LINK-80 3.44 (09-Dec-81). The tool runs the
two programs under [cpmemu](https://github.com/avwohl/cpmemu). cpmemu must
use `default_mode = binary` and `eol_convert = false`. Otherwise cpmemu
converts every file that the program writes, as if the file were text. The tool writes these
settings.

The tool does these steps too:

- The tool gives the source files to M80 with CR LF line endings.
- The tool links with `/P:100` for MBASIC and with `/P:0` for the Altair
  ROMs.
- At `/P:0`, L80 asks "Origin below loader memory, move anyway (Y or N)?".
  The tool answers Y.
- No variant has a data segment, so `/D` is not needed.

### Results on this branch

| Variant | All M80 | All um80 | Mixed modules | Notes |
|---|---|---|---|---|
| `mbasic_521` | historic, both linkers | historic, both linkers | 48 of 56 historic (all 56 with `um80 -t`) | `FBUFP27` (below) |
| `mbasic_52` | = M80 + L80 | = M80 + L80, both linkers | all 56 = M80 + L80 | no historic binary |
| `mbasicz` | M80 cannot assemble it | 12 bytes (`dc`) | (one module) | with 3 source changes, all four historic |
| `4k` | historic, both linkers | historic, both linkers | (one module) | M80: "%No END statement" |
| `4k-annotated` | 3 bytes differ, both linkers | the same as M80 | (one module) | `rdc <!>>` (all four historic with the change) |
| `8k` | 6645 bytes differ, both linkers | the same as M80 | (one module) | `rdc <!>>` (all four historic with the change) |

For an L80 link, "Historic, both linkers" means all the bytes that the REL
files load. The comparison leaves out the bytes that no REL item loads,
because L80 does not clear them. These bytes are the DS space: 1234 bytes of
`mbasic_521`. In every L80 link of `mbasic_521`, 5 of these bytes were not
zero (see "LINK-80 does not clear DS space").

### What the mismatches were, and whose they were

#### `rdc <!>>`: um80 read an `IRPC` list differently from M80 (um80 defect, fixed)

The 4K sources and the 8K sources make the BASIC keyword tables with a
macro:

```
rdc     macro   str
        irpc    ch,<str>
        ...
        rdc     <!>>            ; the keyword '>'
```

In the argument, `!>` is a `>`. Therefore the body becomes `irpc ch,<>>`.
M80 ends the list at the `>` that matches the `<`. Therefore the list `<>`
is empty, and M80 ignores the remaining text.

In the output of M80, the byte for the keyword `>` is missing. In 8K BASIC,
every address after the BASIC keyword table moves by one byte, and 6645 of
the 8192 bytes differ.

The call `rdc <!<>` gives `irpc ch,<<>`. M80 reads the list as `<` and `>`,
and flags the line `Q`.

um80 deleted the first character and the last character of the list
operand. The result was `>` and `<`. The author meant that result, but M80
does not give that result.

Now um80 reads the list as M80 does. um80 also writes a warning about the
`>` that it ignores. The sources need `db '>'+80h` and `db '<'+80h`. The
file `8kbas_src.mac` already has this form for `<`. With that change, all
four builds of each file are historic.

#### `FBUFP27`: 6-character names (not a defect, `um80 -t`)

`BINTRP.MAC` declares `public fbufp27`, and `F4.MAC` uses the symbol. M80
writes the first 6 characters of a PUBLIC or external name in the REL file:
`FBUFP2`. um80 writes the whole name (a documented extension).

If the modules come from the same assembler, the link is correct. If
`BINTRP.REL` and `F4.REL` come from different assemblers, the names do not
match. That case occurs in 4 of the 28 mixed sets of REL files. In that
case:

- L80 reports "1 Undefined Global(s)" and leaves the two references at 2CF2H
  and 2E89H as zero.
- ul80 stops.

`um80 -t` now cuts names to 6 characters, as M80 does. Before, `-t` cut
names to 8 characters. With `-t`, all 60 links of `mbasic_521` are
historic.

mbasic2025 renamed `fbufp33`, `fbufp34` and `filnm12` for the same reason
(its commit 6cbfb25). mbasic2025 could rename `fbufp27` too.

#### LINK-80 does not clear DS space (L80 limitation)

No REL item loads the bytes that `DS` reserves. In `mbasic_521`, these
bytes are 1234 bytes in 14 ranges. The last range is the `ds 7` at the end
of `INIT.MAC` (5FF9H-5FFFH). The historic binary and ul80 have zeros in all
of these bytes. L80 writes whatever was in its memory.

In every L80 link of `mbasic_521`, 5 of the 1234 bytes were not zero. In
the all-M80 link, these 5 bytes were 5FFBH-5FFFH, `21 FF FF 22 98`. In
`mbasic_52`, 64 such bytes were not zero.

When the tool compares an L80 image, the tool leaves out these bytes. The
tool counts the bytes that are not zero.

#### `mbasicz` is not M80 source (a source dialect: um80 accepts more)

M80 stops with 1263 errors. The source has two groups of lines that M80 does
not accept:

- 550 lines of the form `name set value`. In `.Z80` mode, `SET` is the Z80
  bit instruction. These lines need the `ASET` of M80.
- 151 lines that use one-operand forms (`ADD A`, `SBC B`, `ADC (HL)`). M80
  requires the corresponding forms `ADD A,A`, `SBC A,B` and `ADC A,(HL)`.

um80 accepts both forms.

A scratch copy builds the historic binary with all four tool combinations.
The scratch copy has the two changes above and the 12 changes from `dc` to
`db`.

### What else differed in the .REL files (um80 defects, fixed)

- An `EXTRN` that no instruction uses:
  - M80 writes the `EXTRN` as an empty chain. um80 wrote nothing.
  - `BINTRP.MAC` declares about 40 such external symbols.
  - The chain tells the linker that the module needs the symbol. Therefore
    `EXTRN X` alone links the module of X from a library.
  - If no module defined such an external symbol, ul80 stopped with
    "Undefined symbol". ul80 did this even for the REL files of M80.
  - L80 lists the symbol and writes the program. Now ul80 writes a warning
    and writes the program.
- The module name:
  - M80 names a module from the last `TITLE` of the module. The module name
    of `BINTRP.MAC` is `BASIC`.
  - um80 used the file name.
  - um80 also wrote `NAME('X')` as `'X'`, with the quotes.

Now, with `um80 -t`, um80 writes a REL file for each of the 14 modules of
`mbasic_521`. Each REL file has the same items as the REL file of M80:

- the module name
- the sizes
- the PUBLIC names and EXTRN names
- the entry point
- the loaded bytes

Without `-t`, 12 of the 14 modules are the same. The other two differ only
in `FBUFP27`.

The REL files of all 14 modules of `mbasic_52` are the same as the REL files
of M80, with or without `-t`. The REL files of 4K BASIC, annotated 4K BASIC
and 8K BASIC are also the same as those of M80, with or without `-t`.

### M80 and um80 differences that were seen but not changed

- A `;` in an `IRP` or `IRPC` `<...>` list:
  - M80 keeps the `;` (`IRPC C,<A;B>` gives A, `;` and B).
  - um80 reads the `;` as the start of a comment.
- `.PRINTX /text/`: M80 prints the delimiters too.
- um80 accepts some lines that M80 rejects:
  - `NAME 'X'`
  - `IRP X,1,2` without brackets
  - the `SET` directive in `.Z80` mode
  - one-operand `ADD A`
- When a whole DRI repeat block is on one line
  (`IRPC C,AB ! DB '&C' ! ENDM`), the programs differ:
  - M80 ignores the text after the list. M80 takes the remaining text of the
    file as the body of the block. M80 writes the warning "Unterminated
    REPT/IRP/IRPC/MACRO".
  - um80 assembles the DRI statements, as version 0.3.49 did.
  - Inside the list, um80 reads a `!` as M80 reads the `!`.

## What mbasic2025 changed

The mbasic2025 commit 2d19520 (2026-09-24) made these changes. Each change
is byte-neutral against the historic binaries. The changes make every
variant build byte for byte with this um80 and ul80. The changes also make
every variant except `mbasicz` build byte for byte with MACRO-80 and LINK-80
from Microsoft. The changes make the build identical in every combination.
For the links of `mbasic_521` with mixed modules, the changes make the
build identical without `-t`.

1. In `mbasicz/mbasicz.mac`, the 12 message strings are `db`, not `dc`, as
   in `mbasic_521` (9911ac3).
2. In `4k8k/4k/4kbas40.mac` and `4k8k/8k/8kbas_src.mac`, `rdc <!>>` and
   `rdc <!<>` became `db '>'+80h` and `db '<'+80h` (a20d008).
3. `4k8k/4k/build_4k.sh` and `build_4k_hack.sh` compare only the 3833 bytes
   of the reference (d2a9387). `cmp -n` does not work on macOS when the
   lengths differ. Therefore the scripts compare `head -c` of the output.
4. In `mbasic_521`, `fbufp27` is `fbup27`, like `fbup33`. Therefore REL files
   from M80 and from um80 mix without `-t` (a4af9d1).
5. `4kbas40_new.mac` and `4kbas40.mac` end with a newline. Therefore M80
   reads the `END` of each file (ba573d2). ud80 wrote `4kbas40_new.mac`.
   ud80 now ends the output with a newline too.
6. mbasic2025 updated the notes that were out of date, and the READMEs
   (2d19520). The notes and the READMEs now say:
   - MACRO-80 and LINK-80 from Microsoft build these variants as well.
   - M80 needs CR LF line endings.
   - L80 leaves a trailing `ds` as whatever was in its memory.

The owner of mbasic2025 chose not to change `mbasicz.mac`. `mbasicz.mac` is
still in the um80 dialect (`set` in `.Z80` mode, one-operand
`ADD`/`ADC`/`SBC`). Therefore the M80 from Microsoft does not assemble
`mbasicz.mac`.
