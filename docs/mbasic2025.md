# mbasic2025: historic Microsoft BASIC, byte for byte

[mbasic2025](https://github.com/avwohl/mbasic2025) has MACRO-80 sources for
historic Microsoft BASIC binaries. um80 and ul80 build the binaries from
these sources, byte for byte. This makes mbasic2025 a good test of the
toolchain: about 66,000 lines of real Microsoft assembly language, macros,
14-module links, 8080 and Z80 code, and ROM images at address 0. This page
describes how mbasic2025 is part of the test suite. It also records what
happened when the same sources were built with the genuine MACRO-80 and
LINK-80 3.44, alone and in every mix with um80 and ul80.

| Variant | Build (in mbasic2025) | Reference | Bytes |
|---|---|---|---|
| `mbasic_521` | `mbasic_521/build.sh`: 14 modules | `mbasic_521/com/mbasic.com`, MBASIC 5.21 | 24320 |
| `mbasicz` | `mbasicz/build.sh`: one `.Z80` file | `mbasicz/com/mbasic.com`, the same binary | 24320 |
| `4k` | `4k8k/4k/build_4k.sh`: `4kbas40_new.mac`, linked at 0 | `4k8k/4k/4kbas40.bin`, Altair 4K BASIC 4.0 | 3833 |
| `4k-annotated` | the same, from the annotated `4kbas40.mac` (ASEG) | the same | 3833 |
| `8k` | `4k8k/8k/build_8k.sh`, linked at 0 | `4k8k/8k/8kbas.bin`, Altair 8K BASIC 4.0 | 8192 |
| `mbasic_52` | `mbasic_52/makefile`: 14 modules | none: see below | 24338 |

`mbasic_52` holds the MBASIC 5.2 sources of an OEM build ("BASIC 5.2 / MAGIC
Operating System / Copyright 1982"). mbasic2025 has no binary of that build,
so the test pins the image that the genuine M80 and L80 build from it. `mystery_8k` is an OCR of a 1978 assembly
listing. The work to clean it up has only started, and it has no binary; it
does not assemble with any um80 (about 150 errors, all in the OCR text).

## The test

`tests/test_mbasic2025.py` copies each variant, runs its build commands with
this checkout's `um80` and `ul80` (as `python -m um80.um80`, the way the build
scripts do), and compares the result with the reference byte for byte. The
references are pinned by SHA-256, so the test notices a changed reference and
does not trust it. The test also pins the image of `mbasic_52`, so it notices
any change in how um80 assembles those sources.

- The sources come from `$MBASIC2025_DIR`, or from a `mbasic2025` checkout
  next to this repository. Without them, the test is skipped. If
  `$MBASIC2025_REQUIRED` is set, the test fails instead.
- CI (`.github/workflows/tests.yml`) checks out `avwohl/mbasic2025` and runs
  the whole test suite on every push and pull request.
- ul80 pads its output to a whole 128-byte CP/M record, as LINK-80 writes whole
  records. A reference that is not a whole number of records is compared up to
  its length, and the padding after it must be zeros. (4K BASIC is 3833 bytes,
  and its file from ul80 is 3840 bytes.)
- Three sources have a defect that the historic binary does not have (see
  below). The test changes those lines in its copy, and it gives a warning
  for each change. When mbasic2025 changes a line, the test stops changing it.

## Byte for byte with um80 and ul80

Each variant was built with the commands of its own build script:

| Variant | 0.3.48 | 0.3.49 | this branch |
|---|---|---|---|
| `mbasic_521` | identical | identical | identical |
| `mbasicz` | 12 bytes differ | 12 bytes differ | 12 bytes differ; identical with the source change |
| `4k` | identical (+7 bytes of padding) | identical (+7) | identical (+7) |
| `4k-annotated` | identical (+7) | identical (+7) | 3 bytes differ; identical with the source change |
| `8k` | identical | identical | 6645 bytes differ; identical with the source change |
| `mbasic_52` | 1 byte differs from M80 + L80 | = M80 + L80 | = M80 + L80 |

0.3.49 has no regressions. The differences are:

- `mbasicz`: twelve message strings are `dc`, which sets the high bit of the
  last character. The historic binary has no high bits in them (for example
  `Ok` at 0C46H). um80 up to 0.3.6 treated `DC` as `DB`. 0.3.7 (2025-11-29)
  made `DC` work as M80's does. mbasic2025 changed the same strings in
  `mbasic_521` to `db` (its commit 1ba49ad) but did not change `mbasicz`.
- `4k`: the image is identical. The file is 7 bytes longer because ul80 has
  padded to a 128-byte record since 0.3.18. `build_4k.sh` compares the whole
  file with `cmp`, so it has reported a failure since then.
- `4k-annotated` and `8k` on this branch: see "`rdc <!>>`" below. On this
  branch um80 assembles these lines as the genuine M80 does, which is not
  the historic binary.
- `mbasic_52` in 0.3.48: `DCPM.MAC` has `lxi h,filnam+9-0-0-2*0`, where
  `FILNAM` is external. 0.3.48 kept only the last constant, so the result
  was `FILNAM`. 0.3.49 fixed this (see its CHANGELOG), and the result is
  `FILNAM+9`, as M80 assembles it (at 3BF4H: 2AH, not 21H).

## Every mix with the genuine MACRO-80 and LINK-80

`tools/fourway_mbasic.py` assembles every module with the genuine M80.COM and
with um80. It compares each module's two .REL files. Then it links each .REL
set with the genuine L80.COM and with ul80. A variant of one module has four
builds. A variant of several modules has all-M80 and all-um80, plus each
"one module from M80, the rest from um80" and each "one module from um80, the
rest from M80". For 14 modules, this is 30 .REL sets and 60 links. Each image
is compared with the all-Microsoft build and with the historic binary.
Microsoft's binaries are not in this repository:

```bash
python3 tools/fourway_mbasic.py --m80 path/M80.COM --l80 path/L80.COM \
    --cpmemu path/cpmemu [--mbasic2025 DIR] [--variant NAME] [--um80-flag=-t]
```

The M80 and L80 used are MACRO-80 3.44 and LINK-80 3.44 (09-Dec-81), run
under [cpmemu](https://github.com/avwohl/cpmemu). cpmemu must use
`default_mode = binary` and `eol_convert = false`, because otherwise it
converts every file the program writes as text. The tool writes these
settings. The tool gives the sources to M80 with CR LF line endings, and
links with `/P:100` for MBASIC and `/P:0` for the Altair ROMs. At `/P:0`, L80
asks "Origin below loader memory, move anyway (Y or N)?", and the tool
answers Y. No variant has a data segment, so `/D` is not needed.

Results on this branch:

| Variant | All M80 | All um80 | Mixed modules | Notes |
|---|---|---|---|---|
| `mbasic_521` | historic, both linkers | historic, both linkers | 48 of 56 historic; all 56 with `um80 -t` | `FBUFP27` (below) |
| `mbasic_52` | = M80 + L80 | = M80 + L80, both linkers | all 56 = M80 + L80 | no historic binary |
| `mbasicz` | M80 cannot assemble it | 12 bytes (`dc`) | (one module) | with 3 source changes, all four historic |
| `4k` | historic, both linkers | historic, both linkers | (one module) | M80: "%No END statement" |
| `4k-annotated` | 3 bytes differ, both linkers | the same as M80 | (one module) | `rdc <!>>`; all four historic with the change |
| `8k` | 6645 bytes differ, both linkers | the same as M80 | (one module) | `rdc <!>>`; all four historic with the change |

"Historic, both linkers" for an L80 link means all the bytes that the .REL
files load. Five bytes are not loaded (see "LINK-80 does not clear DS
space").

### What the mismatches were, and whose they were

**`rdc <!>>`: um80 read an `IRPC` list differently from M80 (um80 defect,
fixed).** The 4K and 8K sources make their keyword tables with a macro:

```
rdc     macro   str
        irpc    ch,<str>
        ...
        rdc     <!>>            ; the keyword '>'
```

The argument `!>` is a `>`, so the body becomes `irpc ch,<>>`. M80 ends the
list at the `>` that matches the `<`, so the list `<>` is empty, and it ignores
the rest. The `>` keyword byte is missing. In 8K BASIC, every address after
the keyword table moves by one byte, and 6645 of the 8192 bytes differ.
`rdc <!<>` gives `irpc ch,<<>`, which M80 reads as `<` and `>` and flags `Q`.
um80 dropped the first and last characters of the list operand, which gave
`>` and `<`: what the author meant, but not what M80 does. um80 now reads the
list as M80 does, and it warns about the `>` that it ignores. The sources need
`db '>'+80h` and `db '<'+80h`, as `8kbas_src.mac` already has for `<`. With
that change, all four builds of each file are historic.

**`FBUFP27`: 6-character names (not a defect; `um80 -t`).** `BINTRP.MAC`
declares `public fbufp27`, and `F4.MAC` uses it. M80 keeps 6 characters and
writes `FBUFP2`. um80 writes the whole name (a documented extension). If the
modules come from the same assembler, the link is correct. If `BINTRP.REL`
and `F4.REL` come from different assemblers, the names do not match. This is
true of 4 of the 28 mixed .REL sets. L80 reports "1 Undefined Global(s)" and
leaves the two references at 2CF2H and 2E89H as zero. ul80 stops. `um80 -t` now cuts names to 6 characters, as M80
does (before, `-t` cut to 8 characters). With `-t`, all 60 links of
`mbasic_521` are historic. In mbasic2025, `fbufp33`, `fbufp34` and `filnm12`
were renamed for the same reason (its commit 6cbfb25), and `fbufp27` could be
renamed too.

**LINK-80 does not clear DS space (L80 limitation).** `INIT.MAC` ends with
`ds 7`. No .REL item loads those bytes. The historic binary and ul80 have
zeros there. L80 writes whatever was in its memory. In a link of M80's
objects, the bytes at 5FFBH-5FFFH were `21 FF FF 22 98`. In a link of um80's
objects, other bytes had other values. In `mbasic_52`, 64 such bytes differ. The tool leaves out these "hole" bytes
when it compares an L80 image, and it counts them.

**`mbasicz` is not M80 source (a source dialect; um80 accepts more).** M80
stops with 1263 errors. In `.Z80` mode, `SET` is the Z80 bit instruction, so
the 550 `name set value` lines need M80's `ASET`. 151 lines use one-operand
forms (`ADD A`, `SBC B`, `ADC (HL)`) that M80 requires as `ADD A,A`,
`SBC A,B`, `ADC A,(HL)`. um80 accepts both forms. A scratch copy with these
two changes and the 12 `dc` to `db` changes builds the historic binary with
all four tool combinations.

### What else differed in the .REL files (um80 defects, fixed)

- An `EXTRN` that no instruction uses: M80 writes it as an empty chain, and
  um80 wrote nothing. `BINTRP.MAC` declares about 40 such externals. The chain
  tells the linker that the module needs the symbol, so `EXTRN X` alone links
  X's module out of a library. Also, ul80 stopped with "Undefined symbol" on
  such an external if no module defined it, even for M80's objects. L80
  lists it and writes the program, and ul80 now warns and writes the program.
- The module name: M80 names a module from its last `TITLE` (`BINTRP.MAC` is
  `BASIC`). um80 used the file name. um80 also wrote `NAME('X')` as `'X'`,
  with the quotes.

Now, with `um80 -t`, each of the 14 modules of `mbasic_521` gives a .REL with
the same module name, sizes, PUBLIC and EXTRN names, entry point and loaded
bytes as M80's. Without `-t`, 12 of the 14 modules are the same, and the
other two differ only in `FBUFP27`. The .REL files of all 14 modules of
`mbasic_52`, and of 4K, annotated 4K and 8K BASIC, are the same as M80's
with or without `-t`.

### M80 and um80 differences that were seen but not changed

- A `;` in an `IRP` or `IRPC` `<...>` list: M80 keeps it (`IRPC C,<A;B>` is
  A, ;, B). um80 reads it as the start of a comment.
- `.PRINTX /text/`: M80 prints the delimiters too.
- um80 accepts some lines that M80 rejects: `NAME 'X'`, `IRP X,1,2` without
  brackets, the `SET` directive in `.Z80` mode, and one-operand `ADD A`.

## Changes that mbasic2025 could make

mbasic2025 is not changed here. These are suggestions for its owner:

1. `mbasicz/mbasicz.mac`: change the 12 message strings from `dc` to `db`, as
   in `mbasic_521`. Without this, mbasicz has not been byte-exact since um80
   0.3.7.
2. `4k8k/4k/4kbas40.mac` lines 186 and 188, and `4k8k/8k/8kbas_src.mac` line
   198: change `rdc <!>>` to `db '>'+80h` and `rdc <!<>` to `db '<'+80h`.
3. `4k8k/4k/build_4k.sh` and `build_4k_hack.sh`: compare only the reference's
   length (`cmp -n 3833`), or accept zero padding. `build_8k.sh` works because
   8192 bytes is a whole number of records.
4. `mbasic_521`: rename `fbufp27` (for example to `fbup27`, like `fbup33`), so
   that objects from M80 and um80 mix without `-t`.
5. `mbasicz.mac`: if the file must also assemble with M80, change `set` to
   `aset` and use the two-operand `ADD`/`ADC`/`SBC` forms.
6. `4kbas40_new.mac` and `4kbas40.mac` do not end with a newline, so M80 does
   not read their `END` line and warns "%No END statement". The warning does
   not change the output.
7. Documentation: `4k8k/4k/WORK_IN_PROGRESS.txt` says that `4kbas40.mac` does
   not match, but it does now. `4k8k/4k/.claude/CLAUDE.md` says that
   `build_4k.sh` builds `4kbas40.mac`, but it builds `4kbas40_new.mac`. In the
   top-level README, the `4k8k/` tree lists `mbasic_521`'s files.
