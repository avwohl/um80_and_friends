# Changelog

This file lists all notable changes to the um80 toolchain.

## [0.4.3] - 2026-11-20

### X## names an external by its whole name (issue #6)

um80 cut the name of a `##` reference to 6 characters before the symbol
lookup. These faults followed:

- `STAYTOP##` made an external `STAYTO`.
- A `STAYTOP::` in another module did not match that external, and ul80 said
  "Undefined symbol: STAYTO".
- `STAYTOP##` followed by a plain `STAYTOP` in one module gave "Undefined
  symbol".

`##` now uses the whole name, as `EXTRN`, `PUBLIC` and `::` do. The option
`-t` cuts the name to 6 characters in the REL file only.

Measured with MACRO-80 3.44 and LINK-80 3.44 on 2026-11-20:

- M80 keeps 16 characters of a name in its symbol table.
- In the REL file, M80 writes the first 6 characters of a PUBLIC or external
  name.
- `LONGNAME1##` and `LONGNAME2##` are two externals, both written `LONGNA`.
- With `-t`, um80 now writes the same items in the REL file.

These places said that M80 keeps 6 characters of every symbol:

- `docs/EXTENSIONS.md`
- `docs/mbasic2025.md`
- the um80 man page
- two comments in `relformat.py`

The statement was wrong. The text now gives the measured rule. `um80 --help`
now says that `-t` cuts `##` external names too.

Two changes for old sources:

- After `STAYTOP##`, a plain `STAYTO` now gives "Undefined symbol", as M80
  flags U.
- When you link a REL file of um80 with a REL file that M80 assembled,
  use `-t` for long `##` names, as for long `EXTRN` names.

`tests/test_hash_external.py` has 8 tests. 7 of the tests fail with the old
code.

### A name may begin with a dot (issue #7)

um80 read a word that began with `.` as a directive that starts with a dot.
These faults followed:

- A label such as `.FOO:` gave "Unknown instruction or directive: .FOO".
- `JP .FOO` gave "Cannot parse expression".
- `.PHASE:` and `.RADIX:` gave a parse error.
- A `.Z80:` label was worse. um80 parsed the label as the `.Z80` directive
  and defined no label. um80 did not assemble the rest of the line (a `NOP`
  after the label), and wrote no error.

A name may begin with `.` now. Names such as `.FOO`, `..BAR`, `.XC.0`,
`.201B`, `.HJ001`, `.0` and `.1H` work in all places that take a name:

- a label (`:` and `::`)
- the name of an `EQU`, `SET`, `DEFL`, `ASET` or `MACRO`
- a macro parameter, `LOCAL`, and a name made with `&`
- every operand and expression.

A directive that starts with a dot is a label when a `:` follows directly
after the directive. The mode, the listing and the phase do not change. With
`--dri`, um80 takes `.FOO:`. A word that starts with a dot and has
no colon is still an error.

Measured with MACRO-80 3.44 and LINK-80 3.44 on 2026-11-20:

- A name starts with one of `A-Za-z$.?@_` and continues with those
  characters and digits.
- A name with a leading dot acts like the same name without the dot.
- `.` alone is a name, not the location counter.
- `.AND.` is an undefined name, not an operator.

`tests/test_dot_names.py` has 101 tests with expected bytes read from M80 and
L80. 87 of the tests fail with the old code.

ucref80 read the source with a name pattern that had no `.`. ucref80 listed
`.FOO` as `FOO` and `X.1` as `X`. ucref80 now reads names as M80 does.
ucref80 no longer lists a number such as `0FFH` as the symbol `FFH`.
`tests/test_ucref80.py` has 4 tests. ux80 is not changed.

## [0.4.2] - 2026-11-05

### udb80 --wait-program takes the rule's stop as T05

The wait-program rule of the stub (romwbw_emu, ioscpm, z80cpmw, cpmdroid)
stopped with `T05swbreak`. GDB set no breakpoint at 0100H, so GDB continued
past that stop with no message. `monitor wait-program` could not stop a GDB
session (measured with GDB 18.1 on romwbw_emu).

The stub of cpmemu now sends a plain `T05` for the stop of the rule. udb80
0.4.1 read `T05` as a step and stopped with "the program ended before it
started".

udb80 now takes `T05` or `T05swbreak` with signal 5. udb80 takes the stop
only when PC is the load address of the program in `prog.dbg`. A stop at any
other address is an error.

`tests/test_udb80.py` has a fake stub that answers both ways (3 tests). Two of
the 3 tests fail with the old code (measured).

Use udb80 0.4.2 or later with a stub newer than 2026-11-05.

## [0.4.1] - 2026-11-05

### The wheel installs the man pages

`pip install um80` installed no man page. The pages were in the sdist only.
`docs/tools.md` told the reader to copy the pages from `$PKGDIR/../docs/man`,
and a wheel install does not have that directory.

`[tool.setuptools.data-files]` now puts `docs/man/*.1` into the wheel. pip
installs the pages in `share/man/man1`, beside the `bin` of the commands.

Measured on 2026-11-05 (macOS 27 arm64):

- From the 0.4.1 wheel, a Python 3.12 venv and a `--user` install both have
  the eight pages.
- `man -w udb80` finds the page with only the `bin` directory on `PATH`.

`docs/tools.md` says so.
`tests/test_packaging.py` checks that the data-files line is there and that
each console script has a page.

### Man pages for udb80 and dbg2elf

New man pages: `docs/man/udb80.1` and `docs/man/dbg2elf.1`. The pages have:

- the options
- the commands of udb80 and its three other forms (`addr2line`, `sizes`,
  `bt-dump`)
- the exit statuses
- examples
- the releases that have the tools and `--gdb`.

Both pages pass `mandoc -T lint`. The one warning is the date form, which the
six other pages share.

The examples were run on 2026-11-05 with um80 0.4.0 and uc80 0.8.0 from PyPI
and the cpmemu 4.11.0 release. These examples were run:

- `udb80 --batch` with `break sum`
- `udb80 addr2line -r`
- the GDB command line of `dbg2elf.1`, which stopped at `break rs.c:4` with a
  6-frame `bt`.

The README, `docs/index.md` and `docs/tools.md` list the two pages. The
`MANIFEST.in` line `recursive-include docs *.md *.1` already puts the pages
in the sdist.

### Docs: udb80 and dbg2elf are in 0.4.0

The README tool list and the table in `docs/index.md` now name udb80 and
dbg2elf, with "0.4.0 and later". The table in `docs/index.md` said "five
command-line tools" over a table of six.

`docs/udb80.md`, `docs/gdb.md`, `docs/debug_info.md` and `docs/tools.md` say
which um80 release has udb80, dbg2elf, the GDB scripts and `--debug-info`.
The same files say which cpmemu (4.11.0) and romwbw_emu (1.50) have `--gdb`.
`docs/tools.md` also gains a udb80 entry next to the entry of dbg2elf.

### Docs: Homebrew's `gdb` has the Z80 target

`docs/gdb.md` said that Homebrew has no formula and that GDB must be built
from source. The Homebrew formula `gdb` (18.1) configures with
`--enable-targets=all`, which includes z80.

A GDB 18.1 that was built with the configure options of the formula
(2026-11-05, macOS 27 arm64) listed z80 in `set architecture`. With
`udb80_unwind.py` from a PyPI install of um80 0.4.0, the GDB 18.1 build
debugged a uc80 0.8.0 `-g` program on cpmemu. The commands that were run:

- `break`
- `continue`
- a 6-frame `bt`
- `up`

`docs/gdb.md` also says that the codesign step of Homebrew is for native
programs only. The bottle itself was not installed.

## [0.4.0] - 2026-11-04

### Added
- Variables (phase 8 of the cpmemu debugger plan) and the `outer=` level (rule
  D8). The format is in docs/debug_info.md (Variables). The debugger is in
  docs/udb80.md. The text about GDB is in docs/gdb.md.
  - **Format.** Two new markers:
    - `;#type NAME size=.. members=.. | values=.. |
      target=..` for a struct, union, enum or typedef.
    - `;#var NAME TYPE
      [kind=..] [at=LABEL+N | ix=N | reg=R | none] [range=LABEL:LABEL ...]
      [scope=F:A-B] [decl=F:L] [why=..]`.

    A type is a text with no blanks (`*struct:node`, `[4]int:2`,
    `typedef:byte`).

    The DBM file (`.dbm`) and `prog.dbg` get the keys `revision` (2), `types`
    and `vars` **only when a module has a marker**. The key `version` stays 1.

    Measured with the installed ul80 and udb80 (main, `da44ce5`):

    - Both read a DBM file (`.dbm`) and a DBG file (`.dbg`) of revision 2 and
      ignore the new keys.
    - The COM file (`.com`) is the same, byte for byte.
    - A module with no `;#var` or `;#type` marker gives a DBM file (`.dbm`)
      and a DBG file (`.dbg`) with the same keys as before
      (`test_a_module_without_variables_gets_no_new_keys`).

    The REL file (`.rel`) has the same bytes with the markers
    (`test_the_object_file_is_the_same...`).

    um80 resolves `at=` and `range=` labels to segment offsets. um80 also
    resolves the labels in COMMON blocks. In uc80 output, `??AUTO` is
    `COMMON:AUTO`.

    If the module does not define an `at=` label, the variable has no
    location and um80 writes no warning. The reason is that uc80 removes the
    data of a global that nothing uses.
  - **ul80** does three things with the variable records:
    - ul80 relocates the locations and the ranges.
    - ul80 gives the routine as a start address.
    - ul80 merges the types of all modules by name.

    Two modules can have the same `struct pt` with different members. Then
    the types get `struct:pt` and `struct:pt~1`. The variables of the second
    module use `~1`.
  - **udb80** reads the tables through the new `um80/vardata.py`. The file
    uses the standard library only. The GDB commands share the file.

    New in udb80:

    - `print` of variables. The forms are `g`, `*p`, `p->m`, `s.m`, `a[i]`,
      `&x`, `+ - * / %`, strings, enums, bit fields, and pointers as hex with
      the target `<g>` or `"text"`.
    - `info locals`
    - `info args`
    - `ptype`
    - `whatis`
    - `frame [N]` (`f`)
    - `up`
    - `down`
    - `x` with a variable

    The selected frame decides the scope. The scope is the routine, and the
    line for blocks and declarations. The selected frame also decides the
    frame base.

    For the frame base, the frame scanner of `um80/frames.py` now keeps the
    stack slot of each return address (`Walker.slots`). The base of an IX
    frame is the slot minus 2.

    A register variable shows only in frame 0 and inside its PC ranges. In
    every other case, a variable that has no place shows `<not available>`.
  - **Outer level (D8).**
    - `info line` adds `Outer level: line M of "FILE".`.
    - `set level outer` (or `c`) shows the outer position in stops, `frame`,
      `bt` and `list`.
    - `set level both` shows both positions.
    - `addr2line` adds `[outer F:L]` and has `--outer`.

    Nothing that relied on the old form changed. A program with no `outer=`
    prints the same text as before.
  - **dbg2elf** writes these DWARF records:
    - Types: `DW_TAG_base_type`, `pointer_type`, `array_type`,
      `structure_type`, `union_type`, `member`, `enumeration_type`,
      `enumerator`, `typedef`, `subroutine_type`.
    - `DW_TAG_variable` and `DW_TAG_formal_parameter`.

    The records are inside the `DW_TAG_subprogram` of the routine. An inner
    block gets a `DW_TAG_lexical_block` with the address range of the lines.
    A fixed address is `DW_OP_addr`.

    **Measured with GDB 18.1 (z80 target):**

    - `DW_OP_addr` works.
    - `DW_OP_fbreg N-4-pops` with the frame base `DW_OP_call_frame_cfa` works
      for IX variables **when `udb80_unwind.py` is loaded**. The frame id of
      the Python unwinder is the stack address after the return, IX+4.
    - With the Python unwinder, `info locals`, `info args`, `print *p` and
      `up` show the right values at 3 levels of recursion.
    - Without the Python unwinder, GDB shows garbage frames (`bt` 20 frames) and
      `{0, 0}`.

    A register has no DWARF register number in the z80 port. Therefore
    `dbg2elf` writes no record for a register variable. With `--ix-locals
    off`, dbg2elf writes no record for IX variables.

    New: the GDB commands in `um80/gdb/udb80_vars.py` (`zlocals`, `zargs`,
    `zprint`, `zptype`, `udb80-vars-dbg` and `dbg2elf --vars-path`). The GDB
    commands read `prog.dbg` with `vardata.py`. The GDB commands show
    register variables and IX variables in any frame.

    The label variables of the older `dbg2elf` stay for a `prog.dbg` with no
    `vars`.
  - **Tests.** `tests/test_variables.py` has 85 tests. The tests cover:
    - the markers through um80 and ul80
    - merge and rename of types
    - a library module
    - malformed markers
    - the expression code on a fake memory (27 expressions, scope, ranges,
      errors)
    - live `udb80` sessions against `cpmemu --gdb` with `uc80 -g`, for:
      - a global, a file static, a local static and a `??AUTO` local
      - an IX local, and an IX parameter under `--optnone`
      - an array element and a struct member
      - `frame 1` and `frame 3` locals
      - a register variable that is not available in a caller
    - the DWARF tree
    - GDB sessions: static, `??AUTO`, IX with the unwinder, and the helper
      commands in frames 0 and 1
    - the outer level, with a hand-written `.mac` and with a `#line` C file
      from uc80

    The suite went from 1546 passed, 1 skipped to 1629 passed, 1 skipped (GDB
    18.1, cpmemu `39b0f4f`, uc80 from the checkout next to this one).

    Mutation checks:

    - The base of an upper IX frame, changed by 2 bytes: 2 tests fail.
    - The CFA offset of `DW_OP_fbreg`: 4 tests fail.
    - The ul80 ranges: 6 tests fail.
    - The scope test, removed: 3 tests fail.
  - **Review fixes.**
    1. Before the fix, five commands on a variable with no address ended the
       session with a `TypeError`: `print m2[1]`, `print buf[0]`,
       `print &m2[1]`, `print buf+1` and `x/s buf`. uc80
       removes the data of an unused global, so the variable has no address.
       Now an element of an unavailable array is `<not available>`. A sum or
       `x` operand made from such an element gives the same message. The
       command `print` turns any internal error into a message.
    2. Two files can define `static int cnt` or `struct s` differently.
       Before the fix, `print cnt` and `ptype struct s` did not find the name
       (the records had `cnt__s0`, `s__t0`). Now these names work:
       - uc80 writes the source name in `;#var`. The `at=` label keeps the
         unique name.
       - The command `lookup` prefers the variable of the file of the frame.
       - The command `ptype` and type names accept the source tag. When the
         source tag is ambiguous, `ptype` and type names list `s__t0, s__t1`.
       - Two new tests are in `tests/test_variables.py` (85 tests).
  - **Not done.**
    - Only uc80 writes `;#var` so far. uplm80 and ucow write no variable
      records. uada80 is out of scope.
    - A register variable has the PC range from the first to the last
      statement marker, cut at the `push`/`pop` of its pair. A write that
      reuses the register after the last use without a `pop` is not seen.
    - There is no float conversion.
    - There is no assignment or cast.
    - There is no `info scope`.
    - A DWARF location list for register variables is not done.
    - `break` on an outer-level file is not done.

- `udb80 --wait-program`, for a stub that does not load the program itself
  (romwbw_emu, phase 9 of the cpmemu debugger plan).
  - udb80 sends `monitor wait-program sha256 LENGTH SHA` with the image of
    prog.dbg. Then udb80 continues. When the stub stops at 0100H in bank 8EH
    with those bytes, udb80 starts the session.
  - Without the option, udb80 compares the emulated memory at 0100H before
    CP/M loads the program. Then udb80 refuses prog.dbg as out of date.
  - Measured with romwbw_emu ab42bd2 and the 3.6.0 ROM: a program that
    starts from a disk image stops at 0100H. `break`, `bt` and the exit work.
  - `tests/test_udb80.py::test_live_wait_program_under_romwbw` fails without
    the option. The test skips with the reason when romwbw_emu, the ROM or
    the disk is missing. `UDB80_REQUIRE_ROMWBW=1` turns the skip into a
    failure.

- Backtrace from the frame records of prog.dbg (phase 6 of the cpmemu debugger
  plan, rule D7 source 2). `um80/frames.py` (standard library only) finds the
  chain of return addresses from PC, SP, IX, the memory and the `;#func`
  records.
  - Between `ixbegin` and `ixend` of an IX frame, the return address is at
    IX+2. The word must follow a CALL, because a routine can lend IX to its
    code as a pointer.
  - Elsewhere, the return address is at SP+d. The value d is the stack depth
    that a walk over the code of the routine finds. The walk counts push,
    pop, `inc sp`, `dec sp` and the `pops` of the called routine.
    - The value d is not known in these cases:
      - two paths with two different depths
      - `ld sp,hl`
      - `ld sp,(nn)`

      In these cases, the frame is a `guess`.
    - `ld sp,nn` and the routine at the load address end the chain.
  - A record with `frame=ix` and no range gets one from the code.
  - Instruction lengths come from the `asm` rows. For library code, which has
    no rows, the lengths come from a length table.
  - `udb80 bt` uses the shadow call stack when the stub has one. Otherwise
    `udb80 bt` uses the frame records. `udb80 bt` tags each frame `[shadow]`,
    `[frame]` or `[guess]`.
  - New: `bt shadow` and `bt frame` choose the unwind method. The command
    `udb80 bt-dump [--ix IX] prog.dbg memory.bin SP PC` reads a memory dump
    file from `cpmemu --save-memory`.
  - The Python unwinder `udb80_unwind.py` uses the same file,
    `um80/frames.py`. As a result, the Python unwinder now uses `ixbegin` and
    `ixend`. Before, the Python unwinder used only a fixed prologue of 8 bytes
    and the `ret` byte.
  - docs/frame_records.md has the rules, the commands and the limits.
  - Measured with `cpmemu --gdb`:
    - `bt frame` equals `bt shadow`, frame by frame, at each stop of `stepi`,
      `step` and `next`. The programs are a recursive assembler program, a
      program with an IX frame, a recursive `uc80 -g` program and eight more
      `uc80 -g` programs.
    - The measurement had 11,727 `stepi` stops with the `printf` library and
      0 differences. 835 stops have a `guess` frame. All 835 frames are equal
      to the shadow call stack.
    - A `setjmp`/`longjmp` program differs at 657 of 3000 stops. At 653 stops,
      the shadow call stack keeps a frame that `longjmp` skipped, and the
      frame records are right. At 4 stops, SP changes inside `longjmp`.
    - `bt-dump` gives the same frames as `bt` for a program that ends with
      `jp 0` at depth 3.
  - Fixed on the way: the Python unwinder read an out-of-date page of the
    stack. The reason is that GDB steps in `finish` out of an inline frame
    with no event between the stops. Now the Python unwinder reads fresh
    memory for each frame.
  - Tests:
    - tests/test_frames.py has 17 tests (new).
    - tests/test_gdb.py has 3 new tests. The tests use a `uc80 -g` program
      with 3 cases, and two assembler routines with an IX
      range that only the frame record of the routine gives: `push hl / pop ix` for a prologue,
      and a load of IX after `ixend`.
    - The tests of `bt-dump` use PC in an IX range, with and without `--ix`.
    - The expected tags of `test_live_without_a_shadow_stack` are `[frame]`
      now. Before, the tags were `[guess]`. The old scan found the same
      addresses.
  - Mutation checks:
    - With the old `udb80_unwind.py`, the `ixend` test fails.
    - With the `rec.get('ix')` lines removed from `Walker.ix_range`, 5 tests
      fail. Before, the full suite still passed.
  - The suite went from 1523 passed, 1 skipped to 1540 passed, 1 skipped
    (with GDB 18.1).
  - Not done:
    - A measurement with a program from uplm80 or ucow. Only `uc80 -g` and
      hand-written programs were measured. uada80 is out of the plan.
    - A shadow call stack that follows `longjmp`.
    - The stack of a second task.

- `dbg2elf` (`um80/dbg2elf.py`, console script `dbg2elf`), the Python
  unwinder `um80/gdb/udb80_unwind.py` and docs/gdb.md (phase 7 of the cpmemu
  debugger plan).
  - `dbg2elf prog.dbg` reads the program that prog.dbg names. dbg2elf checks
    the length and the SHA-256 of the program. dbg2elf refuses a prog.dbg that
    is out of date.
  - dbg2elf writes an ELF32 EM_Z80 file (`e_flags` 1). The ELF file has:
    - `.text` at the load address
    - a symbol table with routine sizes
    - DWARF 4 `.debug_line` (rule D4):
      - Each line of a line group is a statement row in source order.
      - The last line is primary.
      - `nostmt` rows have `is_stmt` off.
    - `.debug_info` with one compile unit. The compile unit has:
      - a subprogram for each routine
      - a `DW_TAG_inlined_subroutine` for each record of the inline stack
        (nested, with call file and call line)
      - a `DW_OP_addr` variable for each data label
  - Measured with GDB 18.1 against `cpmemu --gdb`: `break FILE:LINE`,
    `continue`, `step`, `next`, `finish`, `bt` and `print` of a static
    variable work for two programs:
    - tools/dbg2elf_proto/sumto.mac (ELF file 1153 bytes)
    - a `uc80 -g` program (crc.c, 190 lines: COM file 1536 bytes, prog.dbg
      21495 bytes, ELF file 3974 bytes, 0.14 s)
  - With a `uc80 -g` program that has an inlined call, GDB steps into the
    inlined body and out, and `bt` shows the inline frame. Before, GDB showed
    the inlined line at the call and had no inline frame.
  - `;#endinline` puts the call line back as the position. Therefore
    `dbg2elf` deletes that line from a line group that has more lines.
  - The Python unwinder unwinds from the `monitor bt` shadow call stack. The
    Python unwinder finds the stack address of each return address by a
    search upward from the frame below. Otherwise, the Python unwinder uses
    the `;#func` frame records. The frame records cover the IX frame, the
    prologue and `ret` cases, and a frameless routine with pushes.
  - For a recursive C program, the Python unwinder shows 5 `sum` frames and 4
    `fill` frames (IX frame). These frames are equal to the entries of
    `monitor bt`. Both sources give the same `bt` at each instruction of the
    prologue and the epilogue.
  - Tests:
    - The 22 tests of tests/test_dbg2elf.py need no GDB. The tests use the
      reader tests/elfread.py.
    - The 14 tests of tests/test_gdb.py use live GDB. A test skips with a
      reason when GDB or cpmemu is missing. `UDB80_REQUIRE_GDB=1` makes the
      skip a failure.
  - The suite went from 1487 passed, 1 skipped to 1523 passed, 1 skipped.
  - `dbg2elf` refuses a program file whose length is not the `length` of
    prog.dbg. Measured: before, one appended byte gave an ELF file 1 byte
    longer. Now the result is exit 1 and "stale".
  - Not done:
    - local variables (phase 8)
    - a compile unit for each file
    - the `moved` table
    - `hex`, `prl` and `spr` images

- ul80 ROM options (details in docs/ul80_rom.md):
  - `-d/--data-origin` (LINK-80 `/D:`)
  - `--common-origin`
  - `--rom-data`:
    - ul80 stores the initial bytes of DSEG after the code.
    - The DSEG symbols stay at the RAM address.
    - ul80 defines `__DATA_ROM`, `__DATA_RAM`, `__DATA_LEN` and
      `__DATA_END`.
  - `--bin` with `--fill` and `--rom-size` (raw image, no 128-byte padding)
  - `--ram-end`, `--ram-size` and `--min-stack` (RAM overflow check)
  - `--verbose` (ROM and RAM usage line)

  With `--rom-data` or `-d`, the Intel HEX output uses load addresses and
  skips gaps. Without these options, the output is the same as before.
- ul80 `--equ-file FILE` and the symbol `__RAM_END`:
  - `--equ-file FILE` writes all public symbols as EQU lines for a bank to
    INCLUDE.
  - The symbol `__RAM_END` comes from `--ram-end` or `--ram-size`.
  - These cases are now errors:
    - `--rom-data` with COM, PRL or SPR output
    - `--fill` above FF
    - `--bin --rom-size` without `-p`
    - data past 10000H with `-d`

- Fixes in the same feature, before release:
  - A COMMON block with a name in lower case (`COMMON /blk/`) lost its rows in
    prog.dbg. The reason is that um80 wrote the segment as `COMMON:blk`, and
    the REL file stores `BLK`. Measured: `dropped_rows` was 1 for one row and
    2 for two modules that share a block. Now the row of the later module is
    kept and the row of the earlier module is deleted: `dropped_rows` is 1.
  - The block name is now in upper case in the DBM file and in ul80.
  - A DS in DSEG with `--rom-data` is now in `moved`.
  - The DBM file and the DBG file are written with LF line ends on Windows.
  - Without `--debug-info`, um80 no longer records the position of macro body
    lines.

- `um80 --debug-info`, `ulib80` container version 2 and `ul80 --debug-info`
  (specification: docs/debug_info.md, phase 2 of the cpmemu debugger plan).
  - um80 writes `NAME.dbm` in the same directory as the REL file. For each
    instruction and data statement, the DBM file has:
    - its segment, load offset and length
    - the run address (.PHASE)
    - the physical source line: the call line for a macro or REPT, and the
      body line too for a macro
    - the state of the whole-line `;#` markers (`;#file`, `;#line`,
      `;#inline`, `;#endinline`, `;#func`, `;#endfunc`, `;#noopt`)
  - A DS with no fill is a row with no bytes.
  - All labels are in the file, with no PUBLIC needed.
  - Lines that come together with no byte between them are a line group, in
    source order. The last line is primary. Only `nostmt` is not a step point.
  - ulib80 stores the DBM file of a module with the module. ulib80 writes
    version 2 of the container only when a DBM file exists. ul80 reads
    versions 1 and 2.
  - ul80 relocates each row. ul80 deletes the rows of bytes that a later
    module loaded over. ul80 writes `NAME.dbg` with the line,
    assembler line, label, routine and moved-address tables, and the length
    and SHA-256 of the output file as written.
  - The REL file, the output file, the symbol file and the listing file are
    the same with and without the options. 747 sources give byte-identical
    REL files and the same messages before and after the change, and with
    `--debug-info`. The sources are all of tests/, the lib of uc80, the
    runtime of uada80 and the tests/*.asm of cpmemu.
  - Tests are in tests/test_debug_info.py (47 tests). The suite went from
    1415 to 1462 passed.

- `udb80`, a source-level debugger for cpmemu (phase 3 of the cpmemu
  debugger plan). The user view is in docs/udb80.md. The console script is
  `udb80`. The module is `um80/udb80.py`.
  - udb80 reads the `prog.dbg` that `ul80 --debug-info` writes. udb80 refuses
    a file that does not match the program. This is the D9 check. The D9 check
    compares the length and the SHA-256 of the COM file, and of the emulated
    memory at 0100H.
  - udb80 speaks the GDB remote protocol to `cpmemu --gdb`. udb80 starts
    cpmemu itself with `--run 'cpmemu ARGS'` (port 0 and a port file), or
    udb80 connects with `--connect HOST:PORT`.
  - Commands:
    - `break`/`tbreak`: the argument is FILE:LINE, a routine or label, or
      `*ADDR`. A line with many addresses gets a breakpoint at each address.
    - `delete`
    - `continue`
    - `step`: the D4 range rule, with one `vCont;r` packet for a line.
    - `next` and `finish`: a temporary breakpoint at the return address. The
      breakpoint counts only when the shadow call stack is back to its depth.
      The fallback is SP, when the stub has no shadow call stack.
    - `stepi`
    - `bt`: the shadow call stack from `monitor bt`, each frame marked
      `[shadow]`, or `[guess]` from a stack scan.
    - `list`
    - `disassemble` (the `ud80` decoder)
    - `info registers`
    - `info symbols`
    - `info line`
    - `x`
    - `print`
    - `sizes`
    - a batch mode (`-ex`, `-x FILE`, `--batch`)
  - `udb80 addr2line [-r] prog.dbg ADDR...` gives the routine and line of
    each address (for the `--backtrace` output of cpmemu). `udb80 sizes
    prog.dbg` gives the bytes of each routine.
  - `next` and `finish` also stop when the frame unwinds past the return
    address (a longjmp, or POP POP RET). The temporary breakpoint goes on the
    return address of every caller. A return to one of these addresses counts
    when the shadow call stack depth is below the starting depth.
  - Without this change, `next` over such a call ran the program to its exit.
    Measured with two live tests. The two tests fail without the change and
    pass with the change.
  - Tests are in tests/test_udb80.py (23 tests). The suite went from 1464
    passed, 1 skipped to 1487 passed, 1 skipped.
  - Fifteen of the 23 tests run a real `cpmemu --gdb` on
    `tools/dbg2elf_proto/sumto.mac` and on a recursive assembler program.
    Each of the 15 tests skips with the reason when no cpmemu is found.
    `UDB80_REQUIRE_CPMEMU=1` makes that skip a failure.

### Fixed
- `udb80 bt frame` and the Python unwinder listed a uplm80 static procedure
  twice when the procedure had a third, stacked argument.
  - The procedure pops its own return address. The procedure puts the return
    address back with `ex (sp),hl` in the slot of the argument.
  - The frame scanner counted only the stack depth. The frame scanner read 2
    bytes below SP, where an out-of-date copy of the return address from the
    next CALL was.
  - `um80/frames.py` now follows the return address into a register pair
    (`pop rr`, `ex (sp),hl`, `ex de,hl`) and back onto the stack (`push rr`,
    `ex (sp),hl`). `um80/frames.py` keeps the old slot only while no write
    can have changed the slot.
  - Measured on a uplm80 `-g` program at `-O0` and `-O2`: before, `bt frame`
    gave LEAF, MID, MID, P. Now `bt frame` gives LEAF, MID, P, as `bt shadow`
    does.
  - Two new tests in `tests/test_frames.py` fail on the old frame scanner.
    The suite went from 1631 to 1633 passed, 1 skipped.

- Messages and the listing file (.PRN) now give the physical line of the
  source file. Before, um80 counted the lines of each macro or REPT
  expansion.
  - A file of 9 lines (a 3-line macro called twice, then a wrong line 9) said
    "Error at line 15". It now says line 9.
  - An expansion line has the line number of the macro call or of the REPT,
    IRP or IRPC line.
  - A message for a line in an INCLUDE file gives the file ("Error at line 7
    of inc.mac"). The same form is in warnings and in the line numbers inside
    messages ("used at line ...", "Unterminated MACRO M2 (line 3 of
    inc.mac)").
  - Lines from -e text or a --pre file do not move the numbers of the source
    file. Before, 3 lines of -e text moved every number by 3. The names of
    these lines are "-e" and the name of the --pre file. um80 numbers the lines of all -e
    options in one sequence from 1.
  - um80 does not change the count that the promotion of JR/DJNZ uses.
  - um80 does not change the assembled REL files. 1554 REL files from 1139 sources
    are byte-identical before and after. The sources are uc80, uada80,
    cpmemu, klaatutv and others, each with and without --dri.
  - Tests are in tests/test_source_position.py.
- In a listing file (.PRN), the line of a macro call came after its
  expansion and repeated the last byte of the expansion (`7 0003 D1 swap
  bc,de` after `pop de`). Now the line of the macro call comes first and has
  no bytes.
- um80 no longer reports a false "Phase error" in a CSEG or DSEG that is
  longer than 64K.
  - A JR or DJNZ near the 64K mark was too far in one pass. In the next pass,
    the same JR was near. um80 cut the target address to 16 bits but did not
    cut the location counter.
  - The distance now uses the true offsets of the segment. In a .PHASE block,
    where addresses are 16-bit, the distance wraps at 64K. um80 still
    reports a real phase error in the source.
  - Tests are in tests/test_jr_64k.py.
- The REL file can change for code that crosses the 64K mark. um80 now makes
  the choice between JR and JP near the mark with the true distance. In ASEG
  code and in .PHASE blocks, the distance wraps at 64K. A JR over the mark
  can stay a JR where um80 made a JP before. Both encodings are correct.
  Code that does not cross 64K gives the same REL file as before.
- A program can cross 64K and have a size that depends on a label. The size
  moves the label (for example, IF (L2-L1) LT 45 around a DS). Such a
  program has no fixed point. um80 now reports "Cannot resolve the value" for such a
  program. The old wrap error hid the missing fixed point. M80 reports a
  phase error for the same program.

## [0.3.52] - 2026-09-26

The release test of 0.3.51 found the differences below between um80 and
M80 3.44, MAC 2.0 and RMAC 1.1. Three of the differences were the `--dri`
Known issues of 0.3.51. The release test confirmed each expected result
with M80, MAC and RMAC under cpmemu. Each difference has a regression test
that fails on 0.3.51.

### Fixed
- um80 assembler: with `--dri`, a two-character string used as a value has
  its first character in the low byte, as in MAC and RMAC.
  - `DW 'AB'` is 41 42.
  - `LXI H,'AB'` is 21 41 42.
  - `DB ('AB') SHR 8` is 42.
  - `IF 'AB' EQ 4241H` is true.
  - Before, um80 with `--dri` gave the order of M80 (42 41, 21 42 41, 41)
    with no message.
  - Without `--dri`, the order is still the order of M80: `'AB'` = 4142H.
- um80 assembler: with `--dri`, an `IF` is true only when bit 0 of the value
  of the `IF` is set, as in MAC and RMAC.
  - `IF 2`, `IF 100H`, `IF 0FFFEH` and `IF NOT 1` are false.
  - Before, um80 with `--dri` read any value but 0 as true, as M80 does,
    with no message.
  - `IFT`, `IFE`, `IF1`, `IFDEF` and the other `IF` directives that MAC does
    not have keep the meaning of M80 with `--dri`. MAC reads `IFT 2` as a
    label.
- um80 assembler: with `--dri`, `MACLIB NAME` reads `NAME.LIB`, as MAC and
  RMAC do, and then `NAME.MAC`. Before, um80 with `--dri` read `NAME.MAC`.
  - The `maclib diskdef` of DRI was "Cannot find include file". The files
    that use `maclib diskdef` include the file `CONTROL/RESXIOS.ASM` of
    MP/M II and the file `os4bios.asm` of CP/M 2.0.
  - Without `--dri`, `MACLIB NAME` reads `NAME.MAC`, as in M80. The error
    message says that MAC reads `NAME.LIB`.
  - um80 first searches for the file that `INCLUDE`, `MACLIB` or `--pre`
    names, with the name exactly as the source has the name. Then um80
    searches for the name in upper case and in lower case. A CP/M file name
    has no letter case. The error message names the files that um80 searched for.
  - `RESXIOS.ASM` with `--dri -t` now assembles to the REL file of
    RMAC 1.1.
- um80 assembler: um80 now writes an error, a phase error, in two cases.
  The first case is a label whose address in pass 2 is not the address that
  pass 1 gave to the label. The second case is an EQU whose value changed.
  Before, um80 wrote no message.
  - M80 flags such a label P and keeps the address from pass 1. M80 flags
    such an EQU M. MAC and RMAC do the same (P).
  - um80 took the address of pass 2, with no message.
  - Example: `IF2 / DB 1 / ENDIF / LAB: NOP / DW LAB` was 01 00 01 01 in
    um80. M80 assembles 01 00 00 01.
  - `IFDEF` of a symbol that the source defines further down is false in
    pass 1 and true in pass 2. This `IFDEF` moved labels in the same way.
  - A symbol that um80 read before the symbol moved was already a phase
    error.
- um80 assembler: with `--dri`, um80 reads a `MACLIB` library in pass 1
  only, as MAC and RMAC read the library.
  - The macros of the library and the symbols that the library defines are
    there.
  - None of the code or data of the library is assembled.
  - An `ORG` or a macro call in the library assembles nothing.
  - A symbol that the library defines keeps its value of pass 1.
  - A `SET` in a library gives the symbol its value at the end of pass 1.
  - With a library of `DB 1`, `DB 2` after the `MACLIB` is now 02.
  - With a library of `LL: DB 1`, `DW LL` is 00 01 at 0100H, as in MAC.
  - Before, um80 with `--dri` assembled the library as an `INCLUDE` file
    (01 02, 01 00 01) with no message.
  - A label that the code of a library moved is a phase error, as MAC and
    RMAC flag it (P).
  - The libraries of DRI hold macros and `EQU`s only. um80 reads these as before.
  - The size of each segment and `COMMON` block is the most that pass 1
    reached in it. The size counts the code and data of the library
    wherever the library leaves the location counter.
  - With a library of `DSEG / BUF: DS 10 / CSEG`, the data is 10 bytes long,
    as in RMAC and 0.3.51. The data of another module is linked after `BUF`.
    See Known issues for the way that RMAC counts the size.
- um80 assembler: a `LOCAL` after a `!` in a macro body declares its names,
  as in MAC and RMAC.
  - These cases work: `NOP! LOCAL QQ`, `LOCAL QQ! NOP`,
    `LOCAL QQ,RR! NOP` and `NOP! LOCAL QQ! NOP`.
  - With `--dri`, these cases also work: `LOCAL QQ ;c! NOP`,
    `NOP ;c! LOCAL QQ` and `MM ;c! LOCAL QQ`.
  - Before, um80 read a body line for its first statement only. A second
    expansion said "QQ multiply defined".
  - `LOCAL QQ! NOP` declared `QQ! NOP` and did not assemble the `NOP`.
  - As in MAC and RMAC, the names are declared for what follows the `LOCAL`.
    The names apply to the statements after the `LOCAL` on the line and to
    the lines after the `LOCAL`.
  - In `LXI H,QQ! LOCAL QQ`, the `LXI` reads the `QQ` outside the macro.
  - `QQ: NOP! LOCAL QQ` defines the `QQ` outside the macro. A second
    expansion is "QQ multiply defined" (the P of MAC).
  - With `--dri`, MAC and RMAC ignore a `LOCAL` after a macro call, and the
    `LOCAL` declares nothing. um80 with `--dri` does the same.
  - Example: in `NN! LOCAL QQ` and `NOP! NN! LOCAL QQ`, with `NN` a macro of
    no parameters, `QQ` is the label outside the macro. A second expansion
    is "QQ multiply defined" (the P of MAC).
  - M80 has no `!` separator. M80 reads `LOCAL QQ! NOP` as `LOCAL QQ` alone.
- um80 assembler: with `--dri`, `END START` with `START` defined after the
  `END` takes no start address and is no error, as in MAC and RMAC.
  - MAC and RMAC read nothing after an `END`.
  - Any operand that reads a symbol that is not defined has the same
    result: `END FOO`, `END START+1`.
  - Before, um80 with `--dri` reported the symbol undefined.
  - M80 flags the symbol U, and so does um80 without `--dri`.
- um80 assembler: with `--dri`, a label on an `ORG` is the location that the
  `ORG` sets, as in MAC and RMAC.
  - `DB 1 / LAB ORG 300H / DW LAB` is 01 at 0100H and 00 03 at 0300H.
  - Before, um80 with `--dri` gave the label the location before the `ORG`,
    as M80 does (01 01 at 0300H), with no message. Without `--dri`, um80
    still does.
  - For that reason, MP/M II's `tools/genmod.py` refused a label on an `ORG`
    line.
  - A label on an `ORG` is an error when the operand of the `ORG` reads a
    symbol that the source defines further down.
  - MAC and RMAC flag such a label P. They give the label the location
    before the `ORG`, which their pass 1 gave to the label.
  - Example: `DB 1 / LAB ORG X / DW LAB / X EQU 200H` is 01 01 01.
  - In um80, pass 1 reads the value of the symbol there as pass 2 does.
- um80 assembler: a label on an `IF`, `ELSE`, `ENDIF` or `EXITM` line is
  defined when the line before it was assembled, as in M80, MAC and RMAC.
  - In each of these cases, the label is the location there:
    - `LAB: IF 0`
    - `LAB: ELSE` after a true `IF`
    - `LAB: ENDIF` after a true `IF`
    - `LAB: EXITM` in a macro, a `REPT`, an `IRP` or an `IRPC`
  - Before, um80 defined none of these labels. A use of one of them was
    "Undefined symbol".
  - A label on an `ELSE` or `ENDIF` after a false `IF` is still not defined.
    A label on any line inside a false `IF` is also still not defined. M80,
    MAC and RMAC do the same.
- um80 assembler: a unary minus or plus applies to the term after the sign,
  before `*`, `/`, `MOD`, `SHL` and `SHR`, as in M80 3.44. Also, `/` and
  `MOD` divide signed, as in M80.
  - `-1 SHR 8` is 00FFH and `-2 SHR 1` is 7FFFH.
  - Before, um80 gave 0 and 0FFFFH with no message. MAC reads the
    expressions in this way.
  - 8000H/2 is 0C000H, 0FFFEH/2 is 0FFFFH and 7/-2 is 0FFFDH. The quotient
    rounds toward 0.
  - The remainder has the sign of the quotient. 4 MOD -3 and -4 MOD 3 are
    0FFFFH. -4 MOD -3 is 1.
  - For the six division cases, in the same order, um80 gave 4000H, 7FFFH,
    0, 4, 0FFFFH and 0FFFCH.
  - With `--dri`, the sign and the division are the rules of MAC and RMAC.
    The sign applies to all that follows the sign. Division is unsigned.
  - `x MOD 0` is `x`, as in M80, MAC and RMAC. Before, um80 reported a
    division by zero.
  - With `--dri`, `x/0` is 0FFFFH, as in MAC and RMAC. MAC and RMAC flag
    neither case. um80 writes a warning.
  - Without `--dri`, `x/0` is still an error (M80: O).
- um80 assembler: um80 accepts the directives `.CREF` and `.XCREF` of M80
  (cross-reference listing on and off) and assembles nothing for them, as
  M80 does. Before, um80 reported them as "Unknown instruction or
  directive".
- um80 assembler: with `--dri`, `MOV M,M` (and `MOV 6,M`) is 76H, the opcode
  of HLT. MAC and RMAC assemble the instruction with no error code.
  - Before, um80 reported the instruction in either mode.
  - M80 flags the instruction A. Without `--dri`, the instruction is still
    an error.
- um80 assembler: with `--dri`, a string in double quotes is an error. MAC
  and RMAC quote a string with `'` only.
  - MAC and RMAC flag `DB "A"`, `DW "A"` and `MVI A,"A"` E. They assemble
    00.
  - Before, um80 with `--dri` read the double-quoted text as a string, as
    M80 does, with no message. Without `--dri`, um80 still does.
- um80 assembler: an empty operand in a `DB` or a `DW` is 0, as in M80.
  - `DB` with no operand is 00. `DB 1,` is 01 00. `DB 1,,2` is 01 00 02.
    M80 flags these three `DB` statements Q.
  - `DW` with no operand is 00 00. `DW 1,` is 01 00 00 00. `DW ''` is 00 00.
  - Before, um80 assembled nothing for `DB`, `DW` or a comma at the end.
    Every address after the statement moved, with no message. `DW ''` was
    an error.
  - Now um80 writes a warning.
  - With `--dri`, each of these cases is an error, as MAC and RMAC flag each
    case E.
  - `DEFB` and `DEFW` are directives of M80. MAC and RMAC read `DEFB` and
    `DEFW` as a label. They assemble nothing on the line and flag nothing.
    In um80 with `--dri`, an empty operand there is an error, and the error
    message says so.
- um80 assembler: with `--dri`, an 8AH in the arguments of a macro call, or
  in the list of an `IRP` or `IRPC`, is a LF there. MAC and RMAC keep the LF
  as text.
  - `MM A`, 8AH, `B` with a body of `DB '&P'` is 41 0A 42. `IRPC X,A`, 8AH,
    `B` gives the same bytes.
  - Before, um80 with `--dri` reported a line feed outside a string.
  - Before, um80 with `--dri` also read a LF right after the name of the
    macro, or in an `IRPC` string, as a blank.
  - Without `--dri`, um80 ignores an 8AH there, as M80 does (41 42).
- um80 assembler: with `--dri`, um80 reads the list of an `IRP` and the
  string of an `IRPC` as MAC and RMAC read them. MAC and RMAC read them as
  the argument of a macro call.
  - A group of brackets can start at any place in the list, not only at
    the start of an item.
  - The text outside the brackets is text of the list too.
  - A comma inside the outer group separates items.
  - `IRP X,<"A>B">` is the one item `"AB">`.
  - `IRP X,<1,2>3` repeats with the items 1 and 23.
  - `IRP X,A<1,2>` repeats with the items A1 and 2.
  - `IRPC X,A<B>C` repeats with A, B and C.
  - Before, um80 with `--dri` ended the list at the `>` that matches its
    `<`, as M80 does. um80 warned about the remaining text.
  - The items in um80 with `--dri` were these:
    - `IRP X,<"A>B">`: `"A`.
    - `IRP X,<1,2>3`: 1 and 2.
    - `IRP X,A<1,2>`: A.
    - `IRPC X,A<B>C`: A, `<`, B, `>` and C.
  - Text after the list is an error, as MAC and RMAC flag it S. A `!`
    statement is the exception.
  - Examples of the error: `IRP X,<1,2>,3`, `IRPC X,AB CD` and `IRP X,1,2`.
    Before, `IRP X,1,2` repeated with the items 1 and 2.
- packaging: the source distribution now includes `CHANGELOG.md`. The
  README and the man pages refer to `CHANGELOG.md`.
  - `MANIFEST.in` named PDFs in a `docs/external` that does not exist.
    `python -m build` warned about this four times.
  - `pyproject.toml` named a package file, `um80/py.typed`, that does not
    exist. No wheel had the file, and nothing warned about the name.
  - Both names are deleted.
  - The man pages and the list of manuals in the README still named
    `docs/external/m80.pdf` and its neighbors. These files moved to the
    retro_docs archive in 0.3.46. The man pages and the README now point
    there.

### Known issues
- um80 assembler: M80, MAC or RMAC flag the statements below, and um80 takes
  them with no message. Each case names the tool that flags the statement,
  with the bytes that the tool assembles or the result that MAC gives.
  - MAC and RMAC flag a sign right after another operator (`2+-1`, `7/-2`,
    `--1`: E).
  - MAC and RMAC flag a shift by more than 16 (`1 SHL 17`: E).
  - M80 flags a sign before `HIGH`, `LOW`, `NOT` or `TYPE` (`-HIGH 100H`:
    O).
  - M80 flags a byte that is not 00H-0FFH or 0FF00H-0FFFFH (`MVI A,300H`,
    `DB 300H`: A). um80 assembles the low byte.
  - MAC flags a byte that is not -128 to 255 (`DB 0FF00H`, `DB -129`: V).
    um80 assembles the low byte.
- um80 assembler: um80 differs from M80 in three places.
  - um80 does not read the `.COMMENT` of M80 when the `.COMMENT` has more
    than one line. The lines after the first line are errors.
  - `DS` with no operand is an error. M80 assembles `DS` with no operand as
    `DS 0`.
  - M80 assembles `DB 1,'',2` as 01 and flags the statement Q. um80
    assembles 01 02, as MAC does.
- um80 assembler: with `--dri`, MAC and RMAC flag the statements below, and
  um80 takes them with no message.
  - A bare `IF`. MAC and RMAC flag the `IF` E. The `IF` is false in M80, MAC
    and RMAC.
  - A two-character string in an expression in a `DB`: `DB 'AB'+0`,
    `DB 'AB' SHR 8`, `DB 'AB' AND 0FFH` and `DB 'BA' EQ 4142H`.
    - MAC and RMAC flag these statements D and assemble the string, 41 42
      or 42 41.
    - um80 assembles the one byte, 41, 42, 41 and FF.
    - 0.3.51 gave 42, 41, 42 and 00.
  - A `DB` or a `DW` with a `!` after the statement on the line.
    - MAC and RMAC flag these statements D. They assemble what follows in a
      wrong way.
    - `DB 1! DB 2` is 01 00.
    - `DB 1! MVI A,5` is 01 06 00.
    - `MVI A,1! DB 2! DB 3` is 3E 01 02 00.
    - The last item of an inline repetition is 00. `IRP X,<1,2>! DB X! ENDM`
      is 01 00. `IRPC X,AB! DB '&X'! ENDM` is 41 00.
    - um80 assembles each statement as written. The results, in the order
      of the examples above, are 01 02, 01 3E 05, 3E 01 02 03, 01 02 and
      41 42.
    - 0.3.51 did not assemble the `IRPC` and wrote a warning.
  - A `!` inside an `IRP` list.
    - In MAC and RMAC, the `!` ends the statement. `IRP X,<1!,2,3>` is V
      and S, and the one item is 1.
    - In um80, the `!` is the quote of M80. The items are `1,2` and 3.
- um80 assembler: with `--dri`, a `LOCAL` in a `REPT`, `IRP` or `IRPC` body
  is "QQ multiply defined", as in 0.3.51.
  - MAC and RMAC honor a `LOCAL` at the start of a line and after a `!`.
  - Example: `REPT 2 / LOCAL QQ / QQ: DB 1 / DW QQ / ENDM` is
    01 00 01 01 03 01.
  - M80 has `LOCAL` in a `MACRO` only, and flags it O there.
- um80 assembler: with `--dri`, um80 reads a `MACLIB` inside a library. MAC
  and RMAC do not read it. A symbol that the `MACLIB` defines is U there.
  - An `EQU` in a library of a symbol that the source defines further down
    is the value of that symbol. MAC reads the library once, and gives 0.
  - See `docs/EXTENSIONS.md`.
- um80 assembler: with `--dri`, the size of a segment or a `COMMON` block is
  the most reached in it, as M80 writes the size.
  - RMAC writes its location counter at the end of pass 1, at the first
    `END` that RMAC reads. The `END` of a library counts too.
  - `ORG 180H / DB 9 / ORG 100H / DB 2` is 101H long in RMAC and 181H in
    um80.
  - `DSEG / DS 10 / ORG 2 / DB 1` gives a data size of 3 in RMAC and 10 in
    um80.
  - With a library that ends in `END`, the program after the library is
    ignored in the size of RMAC. `ORG 100H / MACLIB INC / DB 2,3,4,5` is
    100H long in RMAC and 104H in um80.
  - The result is the same as in 0.3.51.
- um80 assembler: um80 reads pass 1 again until every symbol that um80 reads
  above the line that defines the symbol has its final value.
  - M80, MAC and RMAC read their pass 1 once. They flag a value that
    changed in pass 2 (P).
  - MAC and RMAC flag `X EQU Y / DW X / Y EQU 5` P. MAC and RMAC also flag
    `X EQU LL` of a label further down P. They assemble the value of X from
    pass 1 (00 00). M80 assembles 05 00 and does not flag the statement.
  - M80, MAC and RMAC flag the label after `DS N` with `N` defined further down.
    Example: `DS N / L1: DW L1 / N EQU 4`. M80 gives 00 01. MAC gives 00 00.
  - M80, MAC and RMAC flag the label after `IF FW` with `FW` defined further down.
    The `IF FW` is false in their pass 1. Example:
    `IF FW / DB 1 / ENDIF / LAB: NOP / DW LAB / FW EQU 1` is 01 00 00 01 in
    M80, MAC and RMAC.
  - um80 assembles 05 00, 04 01 and 01 00 01 01 with no message, in either
    mode.
  - At an `ORG` of a symbol that their pass 1 has not read yet, M80, MAC and RMAC
    leave the location where the location counter is. For example,
    `DB 1 / ORG LL / LL: DB 2` puts the 02 at 0101H, and M80, MAC and RMAC
    flag nothing.
  - um80 puts the 02 at 0000H. The value of `LL` after um80 reads pass 1
    again is 0000H.
  - With `--dri`, a label on such an `ORG` is an error, as MAC flags it. See
    Fixed.
  - The result is the same as in 0.3.51.
- um80 assembler: with `--dri`, the summary that um80 prints gives the data
  size that pass 2 reached.
  - A `MACLIB` library that reserves data (`DSEG / BUF: DS 10 / CSEG`) shows
    "Data segment: 0 bytes", although the data size in the REL file is 10,
    as the data size of RMAC is.
  - Only the printed line is wrong.
- um80 assembler: with `--dri`, MAC and RMAC flag S where a `!` is followed
  directly by a keyword (`NOP!INX H`) or has a blank before it
  (`NOP !INX H`). MAC and RMAC ignore the remaining text of the line.
  - um80 assembles both statements, as 0.3.51 did.
  - `NOP ! INX H` is clean in M80, MAC and RMAC.
- um80 assembler: a `LOCAL` at the start of a line in a macro that is defined
  inside another macro is taken by the outer macro
  (`QQ?0001 multiply defined`).
  - M80, MAC and RMAC give the `LOCAL` to the inner macro.
  - um80 stops with an error.
- um80 assembler: MAC and RMAC flag `HIGH`, `LOW` (E) and `NOT` (U) inside a
  macro body and assemble 00.
  - um80 applies these operators as at the top level, as 0.3.51 did.
  - The sources of DRI never use `HIGH`, `LOW` or `NOT` inside a macro body.

## [0.3.51] - 2026-09-26

Three activities found the defects below:

- The build of MP/M II (https://github.com/avwohl/mpm2) from Digital
  Research's unmodified sources.
- The assembly of DRI's `CONTROL` macro libraries (`SELECT`, `STACK`,
  `SEQIO`, `COMPARE`, `DISKDEF`, ...).
- The removal of the workarounds that uplm80 carries for um80.

The genuine MACRO-80 3.44, DRI's MAC 2.0 and RMAC 1.1, and LINK-80 3.44
confirmed each expected result under cpmemu. Each defect has a
regression test that fails on 0.3.50.

### Added
- um80 assembler: `--dri` reads a source as DRI's MAC and RMAC read it where
  they differ from MACRO-80. This section and `docs/EXTENSIONS.md` list the
  differences. Three differences that um80 does not follow yet are under
  Known issues.

  With `--dri`, um80 ignores a `$` inside a name, as MAC and RMAC do.
  `NMB$LST` and `NMBLST` are one symbol, and `PUBLIC A$BC` writes `ABC`.
  um80 keeps a `$` in these places:

  - A `$` that starts a word (the location counter).
  - A `$` in a quoted string or a comment.
  - A `$` in the arguments of a macro call, or in the list of an `IRP` or
    `IRPC`. MAC and RMAC read these as text. `PRINT HELLO$` passes
    `HELLO$`, so `DB '&MSG'` keeps its BDOS terminator.
    `IRPC C,12$3` repeats four times.

  With `--dri`, um80 matches a macro body to its formal parameters as written.
  um80 uses the names of MAC and the rules of RMAC for an `&` in a string.
  An `IF` that a macro body leaves open ends with the macro body (see Fixed).

  Without `--dri` a `$` is part of the name, as in M80. In M80, `LDA NMB$LST`
  after `NMBLST EQU 5` is an undefined symbol. In M80, `AB EQU 1` with
  `A$B EQU 2` defines two symbols.

  MP/M II's sources spell names both ways. `MPM.ASM` stores to `nmb$lst`,
  which `DATAPG.ASM` defines as `nmblst`. With `--dri -t`, um80 assembles
  DRI's unmodified `MPM.ASM`, `CLI.ASM`, `MEMMGR.ASM`, `RESBDOS1.ASM` and
  `BNKBDOS.ASM` to the same REL files that the copies give. mpm2 edits the
  copies to one spelling.

  Two results are DRI's:

  - The V2.0 nucleus (XDOS, BNKXDOS, RESBDOS and TMP), built with
    `--dri -t` from DRI's `NUCLEUS` sources, is DRI's nucleus byte for byte.
    The sources have one change: they carry DRI's serial number.
  - BNKBDOS.SPR from the unmodified `BNKBDOS.ASM` is DRI's V2.1 file.

  With `--dri --aseg`, um80 assembles `MPMLDR/LDRBDOS.ASM` to the bytes at
  0D00H-164CH of MPMLDR.COM (V2.0 and V2.1). `--dri` does not imply `--aseg`
  or `-t`. `docs/EXTENSIONS.md` says exactly what `--dri` changes.
- um80 assembler: with `--dri`, the first word of a statement is a label when
  the word is not an instruction, a directive or a macro. The label can have
  a colon or not, and can be in any column, as in MAC and RMAC. Examples:

  - `OBP DS 1` (MP/M II's `UTIL3/GENHEX.ASM`)
  - `<TAB>LAB NOP`
  - `HALT LXI H,1` in 8080 code

  With `--dri`, um80 ignores these items, as MAC does:

  - A line number before a statement (`00010 LAB: NOP`).
  - A line that starts with `*`. A `!` still ends the line, as in MAC.
  - The assembly controls of MAC (`$-MACRO`).
- um80 assembler: with `--dri`, `PUSH A`, `POP A` and `PUSH 7` are `PUSH PSW`
  and `POP PSW`. An expression can have two register names in it
  (`A*256+B`). The two rules follow MAC and RMAC (see Changed).
- um80 assembler: with `--dri`, the relational operators `=`, `<`, `<=`, `>`,
  `>=` and `<>` of MAC are `EQ`, `LT`, `LE`, `GT`, `GE` and `NE`. The manual
  of MAC has the same rule, and RMAC follows the rule. An example is `IF @Y = 1` in DRI's
  `CONTROL/DEBLOCK.ASM`. A `<` or `>` in a list of values is an operator, not
  a bracket. `DW 1<2,3` is two words. M80 has no such operators (`O`).

  With `--dri`, `HIGH` and `LOW` apply to all that follows them. The manual
  of MAC describes `HIGH` and `LOW` with this rule. MAC and RMAC read `HIGH`
  and `LOW` with the same rule. M80 applies `HIGH` and `LOW` to the term after them. um80 without
  `--dri` does the same as M80. The results:

  Expression | MAC, RMAC and um80 with `--dri` | M80 and um80 without `--dri`
  --- | --- | ---
  `HIGH(100H)+1` | `HIGH(101H)`, 1 | 2
  `HIGH 1234H OR 0F00H` | 1FH | 0F12H
- um80 assembler: um80 now reads `$TITLE('text')` (a subtitle) and `$EJECT`
  of M80. Before, um80 read `$TITLE` in column 1 as a label.
- ul80 linker: a public symbol that more than one module defines is an error
  with `--fatal-mult-def`. ul80 writes no output and the exit status is 1
  (see Changed).

### Changed
- um80 assembler: a label needs a colon without `--dri`, as in MACRO-80 3.44,
  which has no label without a colon.

  Before, um80 read a word in column 1 as a label (see Fixed). Now `OBP DS 1`
  is an error: an undefined `OBP` (M80: `U`). The message has a hint to add
  the colon or to read the source with `--dri`.

  Two more kinds of line are errors without `--dri`:

  - A line that starts with `*` (M80: `U`, but for its `*EJECT` in column 1).
  - A line that starts with a line number (M80: `O`).

  Before, um80 ignored both kinds of line, with no message.

  DRI sources that have a label without a colon, a line that starts with `*`
  or a line number need `--dri`. These sources are `CPM22.ASM`, `GENHEX.ASM`
  and MP/M II's `BNKBDOS.ASM`.

  In a `MACRO`, `IRP` or `IRPC` body being defined, a word with no colon in
  front of its `ENDM` is still read as M80 reads the word (see Fixed).
- um80 assembler: `PUSH A` and `POP A` are an error without `--dri`, as M80
  flags them (`A`). With `--dri`, `PUSH A` and `POP A` are `PUSH PSW` and
  `POP PSW`, as in MAC and RMAC. MAC and RMAC also accept `PUSH 7`. Before,
  um80 read `PUSH A` as `PUSH PSW` in either mode (and rejected `PUSH 7`).
  MP/M II's `BNKBDOS.ASM`, `RESBDOS1.ASM` and `BDOS30.ASM` need `--dri`.
- ul80 linker: a public symbol that a second module defines is now a warning
  of LINK-80, with its message `%Mult. Def. Global FOO`. ul80 says which
  modules define the symbol. ul80 also says whose definition every reference
  uses: the first definition loaded, as in LINK-80.

  ul80 0.3.50 wrote the message "Error: Multiply defined global" but wrote
  the output and exited 0, so a build script could not tell. The exit status 0
  is how four calls to `PRINTB` in MP/M II's CLI and ATTACH went to the wrong
  routine, once mpm2 cut names to six characters. A patch-area
  `PRINTBrlsfile` had become a second `PRINTB`.

  The exit status is still 0, as in LINK-80. LINK-80 links the program. Link
  lines rely on the exit status 0. The `__sret_buf` link of uc80 relies on
  the exit status 0. If
  a script must not link such a program, pass `--fatal-mult-def` to ul80.

### Fixed
- um80 assembler: um80 now reads a word in column 1 that is an instruction, a
  directive or a macro as that, as in MACRO-80, MAC and RMAC.
  - Before the change, um80 read any word in column 1 without a colon as a
    label.
  - `NOP`, `RET`, `XCHG`, `END` or `DB 7` in column 1 assembled nothing, with
    no message.
  - `MVI A,5` in column 1 gave "Unknown instruction or directive: A".
  - An `ENDM` in column 1 did not end a `REPT` or a macro. Every line after
    the `ENDM` became the body.
  - A `LOCAL` in column 1 was a label in the expansion.
  - The name before an `EQU`, `SET`, `DEFL`, `ASET` or `MACRO` is still a
    name, in any column. `NOP EQU 5` defines `NOP`, as in M80.
- um80 assembler: a word with no colon that is not an instruction or a
  directive no longer hides a following `ENDM`, `MACRO`, `REPT`, `IRP`,
  `IRPC` or `LOCAL`. MACRO-80 3.44 does the same. The same rule holds in the
  body of a `MACRO`, `IRP` or `IRPC` that um80 reads as a definition.
  - The word can be a label in any column, the name of a macro, or a word
    made with `&`.
  - `LAB ENDM`, `<TAB>LAB<TAB>ENDM` and `L&P ENDM` end the body. um80 does
    not define the word.
  - `LAB REPT 2` opens a block that the next `ENDM` ends.
  - `LAB LOCAL QQ` declares `QQ`.
  - When a label needed its colon, um80 read `LAB` as the operation and never
    saw the `ENDM`.
    - `IRP X,<1,2> / DB X / LAB ENDM / DB 9` stored the rest of the file as
      the body.
    - um80 warned only "Unterminated IRP ... nothing after it was
      assembled".
    - um80 ended with exit status 0 and a REL file without the code after the
      `ENDM`. M80 and 0.3.50 assemble 01 02 09.
    - `LAB LOCAL QQ` was an unknown instruction.
    - 0.3.50 read neither `<TAB>LAB<TAB>ENDM` nor `L&P ENDM`.
  - After an instruction or a directive, the word is an operand, as in M80.
    `NOP ENDM` and `DB ENDM` end nothing.
  - A third word is also an operand (`LAB FOO ENDM`).
  - M80 reads a `REPT` body for its first word only. `LAB ENDM` does not end
    a `REPT` body, in M80 or um80.
  - With `--dri`, a word made with `&` is a label, as in MAC and RMAC.
    - `L&P ENDM` ends the body and defines `L3` where the body ends (after
      `MM 3`).
    - `L&P REPT 2` opens a `REPT`.
    - `L&P LOCAL QQ` declares `QQ`.
    - um80 with `--dri` did not see these statements.
- um80 assembler: um80 now reads a name that ends in the letters of a word
  operator whole when a `+` or `-` follows. M80 and MAC do the same.
  - The word operators are MOD, SHL, SHR, AND, OR, XOR, NOT, EQ, NE, LT, LE,
    GT, GE, HIGH, LOW, NUL and TYPE.
  - `X1EQ+2`, `@P$NUL-1` and `X1LOW+1` are the symbol plus or minus the
    number.
  - um80 read the letters as the operator and the sign as the sign of the
    operand of the operator. Each name was "Cannot parse expression".
  - uplm80 renamed such names or wrote the offset first (`2+X1EQ`).
- um80 assembler: a symbol that has the name of an operator is now that
  symbol wherever the name occurs, as in M80. The same holds when the
  program defines the symbol further down or declares the symbol EXTRN.
  - After `EQ: NOP`, `DW EQ` is the label. um80 gave 0FFFFH (`0 EQ 0`), so
    `CALL EQ` called 0FFFFH, with no message.
  - After `TYPE EQU 5`, `DB TYPE+2` is 07. um80 gave 00 (TYPE of +2).
  - `NUL EQU 5` then `DB NUL` is 05.
  - When the program defines the symbol, the name is not the operator, as in
    M80. `DB 1 EQ 1` is then an error (M80: `O`).
  - MAC and RMAC do not let a program define such a name.
  - An operator with nothing on one side is an error, as in M80 (`O`).
    Examples are `DW EQ` or `DW SHL` with no such symbol, and `DW 1 EQ`.
    um80 read the missing value as 0.
- um80 assembler: in 8080 code, a register name is now its number in any
  expression, as in M80 and MAC.
  - `X EQU D+1` is 3 (`MOV A,X` is 7BH).
  - `DB B` is 00.
  - `MVI A,B` is 3E 00.
  - `LXI H,SP` is 21 06 00.
  - `JMP B` is C3 00 00.
  - `IF B EQ 0` is true.
  - `DB BC,DE,HL` (M80) is 00 02 04.
  - um80 stopped at each of these with "Register 'B' used as value". um80
    gave the number of a register only in a register operand.
  - An expression with two register names in it (`A*256+B`) is an error
    without `--dri`, as M80 flags it (`O`). MAC accepts the expression.
  - A symbol with the name of a register is that symbol, as in M80, in a
    register operand too. After `C EQU 2`, `MOV A,C` is `MOV A,D` and `DB C`
    is 02. Before the change, um80 gave `MOV A,C` and an error.
  - In Z80 code, M80 makes every register name 0. um80 still reports a
    register name in an expression as an error in Z80 code.
- um80 assembler: in Z80 code, `JP P` after a label `P` now jumps to the
  label, as in M80.
  - `JP Z`, `JP NZ`, `JP PE` and the rest do the same after labels of those
    names, defined before or after the jump.
  - um80 stopped with "JP with condition requires address", so uplm80 wrote
    `JP 0+P` for a jump to its procedure `P`.
  - M80 3.44 gives a wrong result for a label that the program defines
    further down. Pass 1 of M80 3.44 reads `JP P` as one byte, and M80 3.44
    reports a phase error.
- um80 assembler: `TYPE` of an expression that is not a name is now its mode
  with the defined bit, as in M80.
  - `TYPE 5`, `TYPE 'A'` and `TYPE +2` are 20H.
  - `TYPE (LAB)` with LAB in CSEG is 21H.
  - um80 gave 0 for all of them.
- um80 assembler: `END` now ends the source, as in MACRO-80, MAC and RMAC.
  - M80, MAC and RMAC read nothing after `END`. M80, MAC and RMAC do not
    read the rest of the file. They do not read the rest of a macro, a
    `REPT` or an `INCLUDE` file that has the `END`.
  - um80 continued and assembled the text after `END` (`DB 1 / END / DB 2`
    was 01 02).
  - um80 defined a label after the `END`, but M80, MAC and RMAC all report
    the label as undefined.
  - An `END` in a false `IF` is still skipped.
  - An `END` in a `MACLIB` file ends the source too, as in M80, which reads a
    `MACLIB` file as an `INCLUDE` file. um80 writes a warning.
  - With `--dri`, an `END` in a `MACLIB` file ends only the library, as in
    MAC and RMAC. MAC and RMAC continue after the `MACLIB` and take no start
    address from the library.
- um80 assembler: a statement whose first word is not an instruction, a
  directive or a macro is now a list of values, as in M80. um80 assembles the
  list as `DB`.
  - After `FOO EQU 5`, `FOO` is the byte 05.
  - `FOO+1,'AB'` is 06 41 42.
  - `LAB: 5,6` is 05 06.
  - um80 ignored a statement that started with a value (`LAB: 5,6`, `'AB'`),
    with no message.
  - um80 writes a warning. M80 does not.
- um80 assembler: um80 now reads a source byte with bit 7 set with bit 7
  clear, as MACRO-80, MAC and RMAC all read the byte.
  - um80 read the byte as a character that no name or operator starts with.
    A line that began with the byte was ignored with no message. In a
    string, the byte became FDH.
  - The file `NUCLEUS/MEMMGR.ASM` of MP/M II ends six lines with CR and 8AH,
    a line feed with its parity bit set. The line after each was lost. One of the
    lost lines was an `INX B`.
  - A string of the bytes `a`, C1H and `b` is now 41H in the middle, as in
    M80, not FDH.
  - CR 8AH and 8DH 8AH are a CR LF, and an 8DH is a CR, as in M80.
  - Without `--dri`, um80 ignores an 8AH that does not follow a CR, as M80
    ignores the 8AH. See below for how MAC reads the byte.
    - An 8AH that does not follow a CR ends no line in M80, MAC or RMAC.
    - `NOP ; ABC`, 8AH, `INX B` is still 00. The `INX B` is a comment.
    - The same holds for a UTF-8 comment with an 8AH byte in it.
    - A string of `a`, 8AH and `b` is 61 62, as in M80 (0.3.50: 61 FD 62).
  - A lone LF still ends a line, for files from Unix.
  - The change applies to the source, to `INCLUDE`/`MACLIB` files and to
    `--pre` files.
- um80 assembler: the name of an `EQU`, `SET`, `DEFL`, `ASET` or `MACRO` no
  longer has to be in column 1.
  - M80, MAC and RMAC all accept `<TAB>FOO<TAB>EQU 5`, also when FOO is an
    instruction or a macro.
  - um80 stopped with "Unknown instruction or directive: FOO".
  - The file `MPMLDR/LDRBDOS.ASM` of MP/M II has `<TAB>arech  equ b! arecl  equ c`.
  - um80 did not see a macro that the program defines inside a macro, with
    its name indented, as nested. The `ENDM` of the inner macro ended the outer macro.
    um80 now sees the inner macro as nested, as in M80.
- um80 assembler: `RD EQU D` then `DAD RD` assembled `DAD H` (29H), and
  `PUSH RD` assembled `PUSH H`. um80 now assembles `DAD RD` as 19H and
  `PUSH RD` as D5H, as in M80.
  - In 8080 code, M80, MAC and RMAC give each register name a number: B 0,
    C 1, D 2, E 3, H 4, L 5, M 6, A 7, SP and PSW 6. M80, MAC and RMAC read
    a register operand as an expression.
  - um80 read the 2 of `RD EQU D` as the encoding of a register pair. The
    pair with that encoding is H.
  - A register pair operand is now the number of its first register (0 B,
    2 D, 4 H, 6 SP or PSW).
  - `X EQU SP` and `X EQU PSW` are 6. They were 3.
  - A register operand may be any expression, as in M80 and MAC. `DAD 2`,
    `MOV A,2`, `PUSH PSW+0` and a register name that is defined further down
    now assemble.
  - These operands also assemble, as in M80, when the register name has the
    name of an instruction. `DAD RP` with `RP EQU H` below is 29H. `PUSH RP` with
    `RP EQU D` is D5H. `MOV A,RZ` with `RZ EQU E` is 7BH.
    - On pass 1, such a name was read as the opcode of the instruction.
    - um80 stopped with "Invalid register pair for DAD: RP".
    - MAC and RMAC do not read the name of an instruction as a symbol (`S`).
      They read the name as the opcode (`V`).
    - With `--dri`, such a name is still an error.
  - An odd number for a register pair (`DAD E`, `PUSH 3`) is an error, as in
    M80 and MAC. um80 read the number as the pair of the register below it.
  - um80 reads an address as M80 reads it. M80 does not flag the address.
    - The offset of a label in its segment, or the constant of an external
      symbol, is the number.
    - With `LAB` two bytes into the code, `DAD LAB` is `DAD D` (19H).
    - With `Y` EXTRN, `MOV A,Y` is `MOV A,B`.
    - um80 warns, and RMAC flags the address V.
    - 0.3.50 also read the offset, as the encoding of the pair (`DAD H`),
      and rejected an external symbol.
- um80 assembler: a macro argument written `%expression` is now the value of
  the expression when the macro is called, as in MACRO-80, MAC and RMAC.
  - Before the change, um80 left the `%` in the argument. um80 evaluated each
    `%` in a body line when um80 expanded the line.
  - A call in a `REPT` body inside a macro got the same value on every
    repetition. The DRI file `CONTROL/SELECT.LIB` builds its case table in
    this way.
    - M80 and MAC give `10 01 15 01 1A 01`. um80 gave `10 01 10 01 10 01`.
    - M80 and MAC give `LXI H,013AH`. um80 gave `LXI H,011FH`.
  - A body that changed the symbol before the body used the argument read the
    new value.
  - um80 did not substitute the value as text. Therefore `LB&N:` was a parse
    error, and `DB '&N'` gave `%E`.
  - With `--dri`, the argument keeps its `$`. `GEN %N$C` searched for `N$C` as
    written, an undefined name, and passed 0 with no message (MAC: the value
    of `NC`).
  - The argument is now the digits of the value in the current radix, as M80
    writes them. With `.RADIX 16`, 26 is `1A` and 160 is `0A0`.
  - With `--dri`, a name in the expression loses its `$`.
  - M80 also evaluates a `%` after other text (`A%E` is `A7`). With `--dri`,
    only an argument that starts with `%` is a value, as in MAC.
  - A `%` in a body line that is not an argument is an error, as in M80 (O)
    and MAC (E). um80 evaluated the `%`.
- um80 assembler: an undefined name in the expression of a `%` macro argument
  is now an error, as MACRO-80 (U, fatal) and MAC (U) report it.
  - um80 passed 0 with no message. A misspelled name assembled wrong bytes.
  - Without `--dri`, a name written with a `$` that is defined without one
    also assembled wrong bytes.
  - A forward reference still gives the value of the name.
- um80 assembler: without `--dri`, um80 now evaluates a `%` in an item of an
  `IRP` list when um80 reads the `IRP`. MACRO-80 reads an item like a macro
  argument.
  - `IRP X,<%E,2>` repeats with the value of E and then with 2.
  - um80 passed `%E` as text. The text was a parse error where the body
    used the text.
  - M80 flags a `%` in the last item O and passes 0. um80 takes the value and
    warns.
  - MAC and RMAC read the list as text. um80 with `--dri` does the same.
- um80 assembler: a macro body is now matched to its parameters name by name,
  as MACRO-80, MAC and RMAC read the body.
  - A parameter whose name starts with `?` or `@` was never replaced. These
    DRI files could not be used: `CONTROL/COMPARE.LIB`
    (`TDIG? SET '&?Y'-'0'`), `STACK.LIB` (`LHLD ADC&?C`), `NCOMPARE.LIB` and
    `Z80.LIB` (`?N`, `?DD`).
  - um80 replaced a parameter inside a longer name that has a `?`, `@`, `$`
    or `.` in it.
    - With the parameter `FC`, `IRPC ?FC,FC` of `SEQIO.LIB` became
      `IRPC ?X,X`.
    - With `X`, `?X`, `X?`, `@X`, `X@`, `X$1` and `A.X` were all changed.
  - um80 did not change `1X`, but M80 and MAC read 1 and then the
    parameter X.
  - In M80, a name is letters, digits and `$ . ? @ _`.
  - With `--dri`, a name is as in MAC: letters, digits, `?` and `@`. A `$`,
    `_` or `.` ends the name (`X$1` is the parameter X, then `$1`).
- um80 assembler: um80 now treats the `&` next to a parameter in a quoted
  string in a macro body as MACRO-80 treats the `&`. With `--dri`, um80
  treats the `&` as RMAC does.
  - M80 3.44 reads only `&X` in a string. M80 deletes the `&` of the `&X` and
    an `&` right after the `&X`. `'&X&Z'` is `KZ` (um80 gave `K&Z`).
  - M80 then reads the rest of the line as if the line were outside a
    string, until a quote starts what M80 reads as another string.
    - The reason is that the string loop of M80 keeps the quote in a
      register. Reading the name of the parameter overwrites the register.
    - `'&X''&Y'` is `K'L`, and `'&X','&Y'` is `K` and `L`, as written.
    - `'&X &X'` is `K &K` (um80: `K K`).
    - `'&X ','&Y'` is `K` and `&L`.
    - `'&X"&Y'` is `K"&L`.
    - `'&X(X'` is `K(K`.
    - In `'&X(',Z`, the `Z` is inside a string to M80. So M80 reads the
      symbol `Z`, not the argument.
  - MAC and RMAC delete every `&` next to a parameter. MAC and RMAC also read
    a name before an `&` as a parameter. `'X&B'` is `KB` (M80: `X&B`).
  - MAC 2.0 also matches the text of a string as written, so `'&abc'` is not
    the parameter `ABC`. RMAC 1.1, M80 and um80 ignore the letter case.
- um80 assembler: um80 now replaces the parameter of an `IRP` or `IRPC` in
  the body as it replaces the parameter of a macro. MACRO-80, MAC and RMAC do
  the same. Before the change, um80 replaced the parameter in these places:
  - Inside quoted strings without an `&`. `IRP X,<K>` with `DB 'X'` gave `K`.
    M80 and MAC give `X`.
  - Inside longer names. `'A&XB'` gave `AKB`, and `?X` gave `?K`.
  - um80 also left the `&` of `X&B`, which was a parse error.
- um80 assembler: um80 now reads a `LOCAL` name as MACRO-80, MAC and RMAC
  read the name, as a parameter of the macro.
  - A local name with a `?` in it was not renamed, so the second expansion
    defined the name again. An example is `LOCAL L?,?L`, as the DRI file
    `SEQIO.LIB` has `EOB?`.
  - um80 renamed the text of an argument as if the macro had written the
    text. `MM LL`, with `LOCAL LL` and `DB P` in the body, read the local
    `LL`, not the `LL` outside. In that case M80 and MAC give 33H, and um80
    gave the address of the local.
  - `'&L'` in a string is now the unique name, as in M80 (`..0000`) and MAC
    (`??0001`). The unique name of um80 is `L?0001`.
- um80 assembler: an `EXITM` inside a true `IF` now ends that `IF` with the
  expansion, as MACRO-80, MAC and RMAC end the `IF`.
  - The program never reads the `ENDIF` of the `IF`.
  - um80 kept the `IF` open to the end of the file and warned
    "Unterminated conditional (missing ENDIF)". M80, MAC and RMAC report
    nothing.
  - Two examples are `SETLITE` of the DRI file `CONTROL/INTER.LIB` with
    `DEBUG` true, and `IF NUL P / EXITM / ENDIF` inside another `IF`.
  - The same holds for an `EXITM` in a `REPT`, `IRP` or `IRPC` body.
- um80 assembler: with `--dri`, an `IF` that a macro expansion does not close
  now ends with the expansion, as in MAC and RMAC. The same holds for an `IF`
  that one repetition of a `REPT`, `IRP` or `IRPC` does not close.
  - The DRI file `CONTROL/COMPARE.LIB` ends its `TEST?` macro inside an
    `ELSE`.
  - `FILLFCB` of `SEQIO.LIB` opens an `IF` in each repetition of an `IRPC`.
  - um80 kept such an `IF` open after the expansion. After a false `IF`,
    nothing more was assembled, and um80 warned "Unterminated conditional".
  - Without `--dri`, um80 still keeps such an `IF` open after the expansion,
    as M80 does.
- um80 assembler: a `;` inside `<...>` is now text, not the start of a
  comment, as in MACRO-80, MAC and RMAC. The rule holds in three places:
  - in the arguments of a macro call
  - in the list of an `IRPC`
  - in a nested `<...>` in the list of an `IRP`

  The DRI file `CONTROL/DISKDEF.LIB` passes `<;sec per track>` to a macro whose body
  is `dw data comment`. um80 cut the line at the `;`, so the argument was `<`
  ("Cannot parse expression"). In the list of an `IRP`, a `;` ends an item
  (see below).
- um80 assembler: an `IRPC` with an empty string (`IRPC C,`) is no longer an
  error.
  - um80 stopped with "IRPC requires parameter and string". The `ENDM` of the
    body was then "ENDM without MACRO".
  - MAC and RMAC repeat the body once with the parameter empty. um80 with
    `--dri` does the same.
  - The DRI file `SEQIO.LIB` fills a file name with `IRPC ?FC,FC` and tests
    `NUL ?FC`. `FILE` passes an empty type.
  - MACRO-80 repeats the body once only where the empty argument of a macro
    made the string empty (`IRPC C,P` with P empty). MACRO-80 does not repeat
    the body for `IRPC C,` or `IRPC C,<>` as written. Without `--dri`, um80
    does the same.
- um80 assembler: with `--dri`, um80 now defines a label on the `ENDM` that
  ends the body of a macro, `REPT`, `IRP` or `IRPC`. MAC and RMAC do the
  same. Each time um80 expands the body, the label is at the place where the
  body ends.
  - The DRI file `CONTROL/STACK.LIB` ends `SIZ` with `STACK: ENDM` (a
    `LOCAL` name, the top of the stack that `SIZ` reserves).
  - `GTR` of `COMPARE.LIB` ends with `FL: ENDM`.
  - `FILLFCB` of `SEQIO.LIB` ends with `PFCB: ENDM`.
  - um80 ignored the label, so each reference to the label was undefined.
  - MACRO-80 ignores such a label (a reference to the label is U), and so
    does um80 without `--dri`.
  - A label made with `&` on an `ENDM` (`L&X: ENDM`) now ends the body, as in
    M80, MAC and RMAC. um80 read every line after the label into the body
    ("Unterminated IRP").
- um80 assembler: a `<...>` group inside a macro argument or an `IRP` item
  now loses its brackets wherever the group is. The group keeps its text.
  MACRO-80, MAC and RMAC do the same.
  - `MM 1<2>3` passes `123`.
  - `MM 5<>5` passes `55`.
  - `MM <1,2>3` passes `1,23`.
  - `IRP P,<1<2>3,4>` repeats with `123` and `4`.
  - um80 deletes only the outer brackets (`1<2<3>4>5` is `12<3>45`).
  - um80 deleted the brackets only when they were the whole argument.
    Without `--dri`, each was "Cannot parse expression". With `--dri`, the
    relational operators of MAC read `DB P` as `(1<2)>3`, 0FFH, with no
    message.
  - um80 also deletes a `<` with no `>`, and um80 warns. M80 flags it `X`.
    MAC and RMAC flag it `V`.
- um80 assembler: an item of an `IRP` list now ends where M80 ends the item,
  at a `,`, a `;`, a blank or a tab.
  - `IRP P,<A;B;C>` repeats three times. `<A;;B>` and `<1,;2>` have an
    empty item in the middle.
  - Before, um80 did not end an item at a `;` in the list text. `<A;B;C>`
    was one item, `A;B;C`, with no message. When a macro that has
    `IRP P,<Q>` was called with `<1;2>`, the `IRP` repeated once.
  - Version 0.3.50 cut the line at the `;`, used `A`, and wrote a warning.
  - A blank ends an item too, as in M80. `<A B>` is A and B. `<A ,B>` and
    `<A >` have an empty item after A. Before, um80 read `A B` as one item.
  - MAC and RMAC end an item at a comma. They flag a `;` in the list `B`.
    With `--dri`, um80 does the same, and a `;` is an error.
  - MAC and RMAC skip a blank or a tab at the start of an item, before the
    first character of the item. `<A, B>` and `< A,<TAB>B>` are A and B.
  - MAC and RMAC read any other blank in a different way:
    - In MAC, `<A ,B ,C>` is A, B and an empty item.
    - In MAC, `<A ,B,C>` is A and C.
    - In MAC, `<A, ,B>` is A and `,`.
    - In MAC and RMAC, `< ,A>` is the one item `,`.
    - RMAC stops at `<A ,B>` and writes nothing, with no message.
    - MAC flags `<A B>` and `<A >`. RMAC stops at these two lists too.
  - With `--dri`, such a blank is an error. Before, um80 read each list as
    the items between its commas, with no message.
  - A blank inside a nested `<...>` is text in M80, MAC and RMAC.
    `<A,<B C>>` is A and `B C`.
  - A comma at the end of the list is an empty item, in M80, MAC and RMAC.
    `<A,>` is A and an empty item. `<,>` is two empty items. um80 deleted
    the last empty item.
  - In M80, a `%` item is an expression that runs to its `,` or `;`.
    `<%1 + 1,5>` is 2 and 5. MAC flags that list. With `--dri`, the blanks
    of that list are an error.
- um80 assembler: with `--dri`, um80 now reads an 8AH or an 8DH inside a
  line as MAC and RMAC read the byte, not as M80 does.
  - An 8AH that does not follow a CR is a line feed, a character of the
    line.
    - In a string, the 8AH is the byte 0AH. `DB 'A`, 8AH, `B'` is 41 0A 42.
      M80 and um80 gave 41 42.
    - In a comment, the 8AH is nothing.
    - Anywhere else, the 8AH is an error, as MAC flags the 8AH (`E`).
  - An 8DH ends the statement, in a comment too. MAC then reads the next
    word or character, after any blanks, as the line feed that should
    follow a CR. The remaining text of the line is the next statement.
  - `DB 1 ;X`, 8DH, TAB `DB 2` is 01 in MAC and RMAC, as in 0.3.50.
    `DB` is the line feed, and `2` is a line number. um80 `--dri` ended
    the line at the 8DH and assembled 01 02 with no message.
  - `LAB: MVI A,1 ;LOAD`, 8DH, TAB `MVI B,2` is an error (MAC: `S`,
    3E 01), not 3E 01 06 02.
  - Where MAC reads the CR of the line as that line feed, the next line
    starts with a line feed. MAC flags that line feed `S`, and um80 does
    the same.
  - Without `--dri`, nothing changes.
- um80 assembler: um80 now writes a 00 byte for an empty macro argument,
  `IRP` item or `IRPC` character in a quoted string of the body (`'Z&P'`).
  M80 does the same.
  - M80 passes an empty argument as a 00. `'Z&P'` is 5A 00. `IRP P,<A;;B>`
    with `DB '&P'` is 41 00 42. um80 gave 5A, and 41 42.
  - MAC and RMAC pass nothing (5A). um80 with `--dri` does the same.
- um80 assembler: a `>` with no `<` open before the `>` in the arguments of
  a macro call no longer changes the later commas. Every later comma ends
  an argument.
  - Before, um80 read the `>` as a closing bracket, so the bracket depth
    went below zero. `MM 1>2,3` passed one argument, `1>2,3`.
  - With `--dri`, that gave wrong bytes with no message. `DB P` and `DB Q`
    gave 00 03 and nothing. MAC and RMAC read the `>` as text and pass
    `1>2` and 3 (00, 03).
  - With `--dri`, `MM A>B,C` with `DB 'Z&P'` and `DB 'Y&Q'` gave `ZA>B,C`
    and `Y`. MAC gives `ZA>B` and `YC`. Now `--dri` reads the arguments as
    MAC does.
  - M80 ends the argument at such a `>`, as at a comma, and flags the line
    `Q`. `MM 1>2,3` passes 1, 2 and 3. `MM A>,B` passes A, an empty
    argument and B. `MM <A>>B` passes A and B.
  - Without `--dri`, um80 now does the same as M80, and writes a warning.
    Before, um80 had passed `1>2,3`, an error, or `A>B` (`MM <A>>B`), with
    no message.
- um80 assembler: a comma inside parentheses in the arguments of a macro
  call now ends the argument, as in M80, MAC and RMAC.
  - In M80, MAC and RMAC, a parenthesis there is text. `MM (A,B),C` passes
    `(A`, `B)` and C.
  - Before, um80 kept the comma in the argument (`(A,B)` and C).
  - Before, a `)` with no `(` or a `(` with no `)` stopped every later comma
    from ending an argument. `MM A),B,C` passed the one argument `A),B,C`.
    `MM A(B,C` passed `A(B,C`.
  - The three tools pass `A)`, B and C, and `A(B` and C. um80 gave the
    wrong result with or without `--dri`, with no message.
  - The operands of every other statement keep their parentheses.
- um80 assembler: a blank or a tab now ends a macro argument outside a
  quoted string and a `<...>` group, as in M80, MAC and RMAC.
  - Before, um80 kept the blank in the argument. `MM A B` passed `A B`.
    `MM 1 + 1,5` passed `1 + 1` and 5. um80 wrote no message.
  - M80 reads the blanks after an argument as a separator, as a comma.
    - `MM A B` passes A and B.
    - `MM 5 GT 2,4` passes 5, GT, 2 and 4.
    - `MM 1 + 1,5` passes 1, +, 1 and 5.
    - A comma after the blanks is one more separator, so `MM A ,B` passes
      A, an empty argument and B (um80: A and B).
  - Without `--dri`, um80 now does the same as M80.
  - MAC and RMAC end the arguments at the blanks:
    - A comma after the blanks starts the next argument (`MM A ,B` is A and
      B, as before).
    - A `;` or a `!` after the blanks ends the statement of the call (see
      the `!` item below).
    - MAC and RMAC flag anything else `S` and ignore the text (`MM A B`
      passes A). With `--dri`, that is now an error.
  - A `%` expression still runs to its comma, blanks and all (`MM %1 + 1,5`
    passes 2 and 5).
  - Without `--dri`, a `%` after a `<...>` group is now a value, as in M80.
    `MM <A>%1+1` passes A2. um80 passed `A%1+1`.
- um80 assembler: without `--dri`, a `!` in the arguments of a macro call
  or in an `IRP` list now quotes a `;` after the `!`. M80 does the same.
  - M80 passes `MM A!;B` as the one argument `A;B`.
  - Before, um80 cut the line at its first `;` outside a string before um80
    read the arguments, so um80 passed `A!`.
  - Before, a `!`-quoted quote started a string that hid the comment. `MM
    A!"B;C` passed `A"B;C`. M80 passes `A"B`.
  - Before, a quoted bracket there opened or closed a group. `MM <A!>;B>`
    passes `A>;B` in M80. um80 passed `A>`.
  - Before, um80 did not keep a quoted blank at the end of the arguments.
    `MM A! ;B` passes `A ` in M80. um80 passed `A!`.
  - um80 gave all these results with no message.
  - With `--dri`, the comment starts where the comment did. MAC and RMAC
    end the statement at the `!`.
- um80 assembler: with `--dri`, a `"` in the arguments of a macro call or in
  an `IRP` list is now text, as in MAC and RMAC. MAC and RMAC quote a
  string with `'` only.
  - `MM "A,B",C` passes `"A`, `B"` and C.
  - `MM "A;B",C` passes `"A` (the remaining text is a comment).
  - `IRP X,<"A,B">` repeats for `"A` and `B"`.
  - Before, um80 read `"A,B"` and `"A;B"` as strings, as M80 does, and
    passed the strings and C, with no message.
  - In the string of an `IRPC`, a `"` is text in M80 too. `IRPC X,"A;B"`
    repeats for `"` and A in M80, MAC and RMAC. um80 repeated for `"`, A,
    `;`, B and `"`, with or without `--dri`.
- um80 assembler: with `--dri`, a `<` or a `>` in a macro argument that
  starts with `%` is now the relational operator of MAC, not a bracket.
  - `MM %1<2,3` passes 65535 (1<2 is true) and 3, as in MAC and RMAC (FF 03
    from `DB P` and `DB Q`).
  - Before, um80 read `<2,3` as a `<...>` group that ran to the end of the
    line, and reported "Cannot parse expression".
  - Before, a `;` after such a `<` was not a comment (`MM %1<2;X`).
- um80 assembler: a `%` with no expression after the `%` in a macro
  argument is now 0, as in M80.
  - M80 passes `MM %` as 0 and `MM A%` as A0. For `IRP X,<%,A>`, M80
    repeats for 0 and A. M80 flags none of these cases.
  - Before, um80 passed `%`, with no message.
  - MAC and RMAC pass 0 and flag the `%` `E`. With `--dri`, the `%` is now
    an error.
- um80 assembler: with `--dri`, a `!` inside a `;` comment now ends the
  comment and starts the next statement, as in MAC and RMAC.
  `NOP ;c! DB 1` is 00 01, and `; text! DB 1` is 01.
  - DRI sources use this rule. The CCP of CP/M 2.0 has
    `nosub: ;no submit file! call del$sub` and `mov d,a ;save value!
    mov a,b ;mult by 10`. `disk2_files/ldrbios.asm` of MP/M II has
    `;<TAB>in 0f5h ! ani 2 ! rz`.
  - Before, um80 `--dri` read the comment to the end of the line. um80
    ignored those statements, with no message.
    - 1523 of the 1887 bytes that MAC assembles from the CCP differed.
    - 298 of the 414 bytes of LDRBIOS differed.
    - Both now match the output of MAC byte for byte.
  - Special cases:
    - A quote in the comment starts no string (`NOP ;it's! DB 1`).
    - A `*` comment line ends at a `!` whatever is in the line
      (`* it's! DB 1`, `* a;b! DB 1`).
    - um80 ignores a `;;` comment in a macro body only up to its `!`.
      `NOP ;;c! DB 7` is stored as `NOP! DB 7`.
  - What follows the `!` is a statement like any other. The statement can
    be:
    - an `IF` or an `ENDIF`,
    - the first statement of the body of a `REPT`, `IRP` or `IRPC` on that
      line (`IRPC X,AB ;c! DB '&X'`), or
    - in a line of a body being defined, the `MACRO`, `REPT`, `IRP`, `IRPC`
      or `ENDM` that nests in it.
  - `NOP! ENDM` and `NOP ;c! ENDM` end the body after the `NOP`, as in MAC.
    Before, um80 continued to the end of the file ("Unterminated MACRO").
  - With `--dri`, um80 reads what follows a macro call on its line as MAC
    and RMAC read the text:
    - MAC and RMAC continue with the statement after the first `!` that is
      after the arguments of the call and that follows a character other
      than a blank or a tab.
    - A `;` starts a comment that ends at its `!`. That `!` counts as a
      character other than a blank or a tab.
    - A `!` after a blank is text.
    - When the call has no arguments, the first character after the name of
      the macro is text, whatever the character is.
  - A call with no arguments ends at the `!` of its `;` comment, as another
    statement does. `MM ;c! DB 1` and `NOP! MM ;c! DB 1` assemble the `DB`.
  - These lines do not assemble the `DB` (MM has a parameter):
    `MM A;c! DB 1`, `MM A ! DB 1`, `MM ! DB 1`, `MM ;c ! DB 1`,
    `MM ;;c! DB 1` and `NOP! MM 1! DB 1`.
  - `MM A;c!! DB 1` does assemble the `DB`. The statement that MAC leaves
    out is empty.
  - A call reads as many arguments as the macro has parameters. A call
    reads the remaining text as text. `MM A! DB 1` and `NOP! MM A! DB 1`
    assemble the `DB` where MM has no parameter.
  - Before, um80 `--dri` ignored all text that followed the arguments of a
    call:
    - `MM ;c! DB 1` gave the bytes of MM only, with no message.
    - `NOP! MM ;c! DB 1` gave a warning that MAC leaves out the `DB`. MAC
      does not leave out the `DB`.
    - um80 read `MM A ! DB 1` and `MM ! DB 1` as arguments, and reported
      them.
  - Now um80 `--dri` does what MAC does. um80 writes a warning where it
    ignores a statement.
  - A `!` right after an argument of the first statement of a line is still
    the quote character `!` of M80 where the macro has parameters, as
    `docs/EXTENSIONS.md` says.
  - um80 now also reads the statements of two more kinds of line:
    - A line of a macro definition that starts with a macro
      call, an `IRP` or an `IRPC` (`MM ;c! ENDM`, `IRPC C,AB ! NOP ! ENDM`
      in a macro).
    - A macro call line in a false `IF` (`MM ;c ! ENDIF`).
  - Before, um80 continued to the end of the file, or past the `ENDIF`, in
    these two kinds of line.
  - With or without `--dri`, an `EXITM` after a `!` now ends the macro
    expansion or the repetition, as an `EXITM` at the start of a line does
    (`NOP! EXITM! DB 5`, and `IF 1! EXITM! ENDIF`). Before, um80 continued
    to read after the `EXITM`, with no message. MAC ends there.
  - Without `--dri`, a comment runs to the end of the line, as in M80
    (`NOP ;c! DB 1` is 00).
  - um80 no longer adds an empty line to the listing for a `!` at the end of
    a line, or at the end of a comment there.
  - A line of `!` statements is commented out with one `;` in front, for example
    `;<TAB>pop h! lxi h,0007! jmp shell$err`. With `--dri`, um80 now
    assembles such a line from its first `!`, as MAC and RMAC assemble the
    line. Comment out each statement instead.
  - The V2.1 changes of mpm2 to `NUCLEUS/RESBDOS1.ASM` and `CONBDOS.ASM`
    (`src/overrides`) keep the code that they replace in two such lines.
    - Until the two lines are rewritten, RESBDOS.SPR for V2.1 is 10 bytes
      longer, 0D00H.
    - When the two lines are rewritten, every file of the V2.0 and V2.1
      builds is as it was before.

### Known issues
- um80 assembler: MAC and RMAC do three things that `--dri` does not do yet.
  Each gives different bytes with no message. None of the three is in any
  DRI source in the tests. All 38 DRI sources in the tests assemble to the
  bytes of MAC.
  - A two-character string used as a value has its first character in the
    low byte in MAC and RMAC (`DW 'AB'` is 41 42, `LXI H,'AB'` is 21 41 42).
    `--dri` gives the value as M80 does (42 41).
  - MAC and RMAC treat an `IF` as true only when bit 0 of the value is set
    (`IF 2` and `IF NOT 1` are false). `--dri` treats any value but 0 as
    true, as M80 does.
  - MAC and RMAC read a `MACLIB` library in pass 1 only. The code and data
    of the library are not assembled, and the labels of the library keep
    their values of pass 1. `--dri` assembles the library as an `INCLUDE`
    file (library `DB 1` then `DB 2` is 02 in MAC and 01 02 here).
- um80 assembler: with `--dri`, each of these cases stops with an error:
  - `MACLIB NAME` searches for `NAME.MAC`. MAC and RMAC read `NAME.LIB`.
  - um80 does not obey a `LOCAL` after a `!` on the line (`NOP! LOCAL QQ`).
  - `END START` with START defined after the `END`: um80 reports START as
    undefined. MAC takes no start address.

## [0.3.50] - 2026-09-25

mbasic2025 (https://github.com/avwohl/mbasic2025) rebuilds historic Microsoft
BASIC binaries from MACRO-80 sources. The binaries are MBASIC 5.21 (as 14
modules and as one Z80 file) and Altair 4K and 8K BASIC 4.0. mbasic2025 is now
part of the test suite.

The project also built the same sources with the genuine MACRO-80 and
LINK-80 3.44 under a CP/M emulator. The project also built the sources with
every mix of M80, L80, um80 and ul80. The mixes are:

- each assembler for all modules
- one module from the other assembler
- both linkers for each of these

The mixes found the defects below. Each defect has a regression test that
fails on 0.3.49. The file `docs/mbasic2025.md` has the results.

### Added
- tests: `tests/test_mbasic2025.py` builds every variant of mbasic2025 that has
  a historic binary.
  - The test uses the build commands of each variant and the um80 and ul80 of
    this checkout. The test compares the result with the historic binary byte
    for byte.
  - The test checks the historic binaries against their SHA-256 values. The
    MBASIC 5.2 sources have no historic binary. For these sources, the test
    checks the result against a fixed value: the image that M80 and L80 build
    from the sources.
  - The test runs when the sources are at `$MBASIC2025_DIR` or in a
    `mbasic2025` checkout in the same directory as this repository.
    Otherwise, the test is skipped.
  - The test needs mbasic2025 2d19520 or later. The revision 2d19520 is the
    first revision whose sources build every variant byte for byte with this
    release (see Fixed).
- CI: `.github/workflows/tests.yml` runs the test suite on every push and
  pull request. The workflow checks out avwohl/mbasic2025 at a fixed commit.
  To take a newer commit, change the `ref:` of the checkout. Before this
  change, CI ran only pylint.
- tools: `tools/fourway_mbasic.py` builds mbasic2025 with every mix of
  M80.COM/L80.COM and the um80/ul80 of this checkout.
  - You supply the genuine M80.COM and L80.COM by path. M80.COM and L80.COM
    are not in this repository.
  - The tool compares the two .REL files of each module and each image with
    the all-Microsoft build and the historic binary.
  - The exit status is 1 when a tool mix differs from M80 + L80.
  - Without `--um80-flag=-t`, the exit status 1 also covers 8 links of
    `mbasic_521`. A name of 7 characters breaks these links (see Changed). For
    these links, the tool names the symbol and says to use `-t`.

### Changed
- um80 assembler: `-t` cuts every PUBLIC, EXTRN and module name to 6
  characters, as M80 does. Before, `-t` cut names to 8 characters. M80 writes
  6 characters, and L80 reads 7 characters. Neither uses 8.
  - MBASIC 5.21 has `BINTRP.MAC`. The file declares `PUBLIC FBUFP27`. M80
    writes this name as `FBUFP2`.
  - The `F4.REL` that um80 wrote requested `FBUFP27`.
  - When one assembler wrote `BINTRP.REL` and the other assembler wrote
    `F4.REL`, the link step failed. L80 reported an undefined global and did
    not set 4 bytes. ul80 stopped.
  - With `-t`, all 60 links of mbasic_521 build the historic binary. The 60
    links are 30 sets of .REL files, each with two linkers.

### Fixed
- um80 assembler: the `<...>` list of an `IRPC` or `IRP` now ends at the `>`
  that matches its `<`. um80 ignores the rest of the line, as M80 3.44 does.
  Before, um80 deleted the first and last characters of the operand.
  - The difference shows when a macro wraps its argument in brackets
    (`IRPC CH,<STR>`) and the argument is `!>`. M80 then reads
    `IRPC CH,<>>`, an empty list.
  - The 4K and 8K BASIC sources of mbasic2025 write their keyword tables with
    such a macro (`rdc <!>>`). um80 built the historic 8K BASIC from them, but
    the genuine M80 did not write the `>` keyword byte. Every address after
    the byte moved (6645 bytes of 8192).
  - um80 now assembles what M80 assembles, and warns about the `>` that um80
    ignores.
  - The sources need `db '>'+80h`, as the 8K source already has for `<`.
    mbasic2025 2d19520 made this change, and the other changes that
    `docs/mbasic2025.md` lists, together with this release.
  - **The script `4k8k/8k/build_8k.sh` of an older mbasic2025 fails with this
    um80.** 6645 bytes differ. The script passed with 0.3.49.
  - These cases follow the same rule:
    - A list that has no `>` to end it runs to the end of the line, with a warning.
      M80 flags the line `Q`.
    - `IRPC C,<A>B` is `A`.
    - `IRP X,<1,2>,3` is 1 and 2.
    - In an `IRP` list, a `>`, `<`, `,` or `!` inside a quoted string is
      text, as in M80. `IRP X,<'A>B','<',2>` is `'A>B'`, `'<'` and 2.
    - In an `IRPC` list, a quote is an ordinary character.
- um80 assembler: um80 read a `!` in an `IRP` or `IRPC` list as the statement
  separator `!` of DRI. As a result, `IRPC C,<!>` became `IRPC C,<` and a stray
  `>` line. The rules now are:
  - In an `IRPC` list, a `!` is an ordinary character.
  - In an `IRP` list, a `!` quotes the next character, as in a macro
    argument. `IRP X,<1!,2,3>` is `1,2` and `3`.
  - An unbracketed `IRPC` string ends at a blank. `IRPC C,A B` is `A`. um80
    warns about the text after the blank. M80 ignores that text.
  - After the list, a `!` is still the statement separator of DRI. Therefore a
    whole block on one line assembles as before:
    `IRPC C,AB ! DB '&C' ! ENDM`.
- ud80 disassembler: the output ended with `END` and no newline. M80 reads a
  line only after the line ends. M80 therefore never saw the `END`, and M80
  warned "%No END statement". The file `4kbas40_new.mac` of mbasic2025,
  which ud80 wrote, did exactly that. The output now ends with a newline.
- um80 assembler: um80 now warns about a `MACRO`, `REPT`, `IRP` or `IRPC`
  block that has no `ENDM`, as M80 does ("Unterminated REPT/IRP/IRPC/MACRO").
  - Before, um80 read every line after the `MACRO`, `REPT`, `IRP` or `IRPC`
    as the body of the block. um80 did not assemble the lines after the
    directive, and wrote no message.
  - The effect was worse in pass 2. The block was still open when pass 2
    began. Pass 2 therefore read the lines before the block as the body too,
    and the module was empty.
  - `DB 1` followed by an unterminated `IRPC` is now 01, as in M80.
- um80 assembler: an `EXITM` in a `REPT`, `IRP` or `IRPC` inside a macro now
  ends the repeat, as in M80. Before, the `EXITM` ended the macro while um80
  still collected the body of the repeat. The repeat then never got its
  `ENDM`. The log2 macro in the `DEBLOCK.ASM` of CP/M 2.0 is an example:
  `REPT 8 / IF @Y EQ 1 / EXITM / ENDIF / ... / ENDM`.
- um80 assembler: a `!` inside a quoted string in a macro argument now stays
  in the argument, as in M80. The rule applies in a macro call and in an `IRP`
  list (`IRP M,<'Error!','Ok'>`). Before, um80 deleted the `!`:
  `MSG <'Hi!'>` and `MSG 'Hi!'` passed `'Hi'`. Outside a string, the `!` still
  quotes the next character.
- um80 assembler: `NAME('XYZ')` wrote the module name `'XYZ'`, with the quotes.
  The module name is now `XYZ`, cut to 6 characters as M80 does.
- um80 assembler: `TITLE` now names a module that has no `NAME`, as M80
  does. The name is the first 6 characters of the text of the last `TITLE`, up
  to a blank. For `BINTRP.MAC` of mbasic2025, the module is `BASIC` from both
  assemblers. Before, um80 used the file name `BINTRP`.
- um80 assembler: um80 now writes two kinds of external into the .REL as an
  empty chain, as M80 does:
  - an `EXTRN` that no instruction uses
  - an external that only a link-time expression uses

  The chain tells the linker that the module needs the symbol. L80 and ul80
  then search a library for the symbol. As a result, `EXTRN X` alone links the
  module that defines X. L80 lists the symbol as an undefined global if no
  module defines the symbol. Before, um80 wrote nothing, so the linker did not
  link the library module.
- ul80 linker: ul80 now writes a warning for an external that a module only
  declares and that no module defines. ul80 writes the program, as L80 does.
  The program has nothing to fill in for this external. Before, ul80 stopped
  with "Undefined symbol". ul80 also stopped on REL files from M80. An external
  that something refers to is still an error.

### Removed
- `tests/mbasic.com`, the MBASIC 5.21 binary, which no test used.
  - The file came from the mbasic2025 project that this repository split from.
  - The mbasic2025 project has the same file (`mbasic_521/com/mbasic.com`).
    `tests/test_mbasic2025.py` checks that file against its SHA-256 value.
  - The file `tests/mbasic.com` was not part of the package. This repository
    does not otherwise contain Microsoft's binaries.

## [0.3.49] - 2026-09-24

The linker now computes `LOW`/`HIGH` of a relocatable or external value. The
linker also computes any such value in a one-byte field. MACRO-80 3.44 and
LINK-80 3.44 pass these values as REL "extension link items". um80 writes the
same items, and ul80 evaluates them. Running the genuine M80 and
L80 3.44 under a CP/M emulator established the format. `um80/relformat.py` and
`docs/EXTENSIONS.md` describe the format.

### Fixed
- um80 assembler: `LOW(expr)` and `HIGH(expr)` (and `LOW expr` / `HIGH expr`
  of M80) of a relocatable or external value assembled a wrong byte. um80
  assembled the *offset of the value within its segment* as an absolute byte.
  As a result, no relocation reached the linker.

  Example from MP/M II:
  - `MPMLDR/LDRLWR.ASM` is a CSEG module that GENSYS links after
    `GENSYS.PLM`. The module does `mvi a,low(bitmap+128)`.
  - In the linked `GENSYS.COM`, bitmap+128 is at 256CH. But the instruction
    came out `MVI A,0A6H`. The byte 0A6H is the low byte of the offset of
    bitmap+128, 01A6H.
  - As a result, GENSYS read its relocation bitmap record at the wrong time
    and generated a wrong `MPM.SYS`.
  - The wrong code worked only by accident in a one-module `.COM` whose CSEG
    starts at 0100H. There, `LOW` happens to agree. `HIGH` does not agree.

  Correction:
  - The expression now goes to the linker as a postfix program that ends in
    a store operator. um80 writes the program just before the placeholder
    byte that the program fills.
  - The program for the example (bitmap, then 128) is
    `C(prog,0126H) C(abs,0080H) + LOW store-byte`. The placeholder byte `0`
    follows the program.
  - The linked byte is 6CH.

  Test:
  - A rebuild of all of MP/M II (41 targets) with this change alone changes
    exactly that byte of `GENSYS.COM`.
  - Every `.SPR`, `.PRL`, `.RSP` and other `.COM` is byte-identical.
  - The forward-`EQU` and `.MEMORY` fixes below also change the relocation
    bitmaps of `ED`, `PIP`, `SDIR`, `STAT`, `SPOOL` and `SUBMIT.PRL`.
  - The forward-`EQU` fix changes the `SUBMIT` that uplm80 0.3.6 compiles from
    the unaltered `SUB.PLM` of DRI.

  Background: DRI built LDRLWR with ASM80 of Intel and with ISIS
  LINK/LOCATE (see `MPMLDR/GENSYS.SUB`). The object format of these programs
  carries byte relocations. RMAC of DRI rejects the line with an `E`.
- um80 assembler: any other relocatable or external value in a one-byte field
  has the same cure. M80 does the same. Examples: `MVI A,BUF`, `DB LAB`,
  `CPI LOW(EXT+1)`, `LD (IX+OFF),HIGH BUF`.
  - An external in such a field was an error ("Cannot use external in
    immediate byte").
  - DRI's own `LDRLWR.ASM` could not be assembled at all because of
    `sui low(sctbfr)`. For this reason the MP/M tree carries a rewritten
    copy.
  - The Z80 `LD r,n` form assembled 0 for an external, with no message.
- um80 assembler: a word whose value is not `address + constant` assembled a
  value that um80 computed from segment offsets. Examples: `-LAB`, `LAB*2`,
  `LAB+LAB2`, the distance between a DSEG and a CSEG label, `HIGH(EXT)`,
  `EXT+LAB`. The value is wrong wherever the linker puts the segment. Such a
  word now goes to the linker too.
  - M80 3.44 gets several of these wrong. In word fields: `DW -LAB`,
    `DW BUF*2`, `DW HIGH(BUF)`. In byte fields: `MVI A,BUF*2`,
    `MVI A,HIGH(BUF*2)`, `DB HIGH(BUF)*2`.
  - Version 0.3.48 matched M80 byte for byte there. um80 does not copy
    the result of M80 there. The values of um80 are the arithmetically correct ones.
  - As a result, a binary rebuilt with um80 can differ from a reference built
    with M80 in those fields.
- um80 assembler: in a link-time expression, um80 folded a constant that the
  expression adds to an address into the address.
  - Example: `MVI A,HIGH(C1+100H)`, C1 at offset 0 of COMMON `/BLK1/`, went
    out as the one extension item C(common, 0100H).
  - MACRO-80 writes the address and the constant as items of their own,
    C(common, 0) C(abs, 0100H) A(+).
  - LINK-80 gives a wrong value for a COMMON-relative value that lies past
    the end of its block. With BLK1 300H bytes long, `HIGH(C1+400H)` linked
    in L80 to A0H instead of 05H.
  - um80 now writes the form of M80, with the operands in source order, in
    every segment.
  - L80 gets the folded form wrong for M80's own objects too. M80 folds an
    `EQU` such as `X EQU C1+400H` and a word such as `DW C1+400H` in these
    objects. ul80 computes all of them right.
- um80 assembler: `X EQU HIGH BUF` now stands for the expression. So
  the linker links `MVI A,X` like `MVI A,HIGH BUF`. Before, `X` was the
  constant high byte of the offset of BUF. M80 3.44 gets this one wrong too: it keeps the
  segment of BUF, with the high byte of the offset of BUF as the value.
- um80 assembler: um80 lost a constant that the expression adds to an
  external that already carries one. Only the newest constant was kept.
  - `EXT+2+3` linked to `EXT+3`.
  - `(EXT+2)-1` linked to `EXT-1`.
  - `1+EXT+1` linked to `EXT+1`.
  - After `EQX EQU EXT+2`, `DW EQX+1` linked to `EXT+1`.

  Version 0.3.48 has this fault for words. With the byte fields above, the
  fault reached `MVI A,EQX+1` too. Also, `1 SHR (EXT-1)` stopped with a
  Python traceback ("negative shift count") instead of the error for SHR on
  an external.
- um80 assembler: um80 used a symbol above the `EQU` that defines the symbol,
  and that `EQU` itself uses a symbol that the source defines further down. In this
  case um80 assembled a wrong value with no message.

  The fault:
  - `MVI A,X` / `X EQU FWD+1` / `FWD EQU 5` gave `MVI A,01H`. Pass 1
    computed X with FWD still 0. Pass 2 read that value above the line that
    recomputes the value.
  - The same fault froze a forward `X EQU HIGH BUF` as the absolute byte 0.
  - The same fault froze an alias `RBUF EQU LABEL` of a later label as
    absolute 0.
  - Result in MP/M II: the SUB utility, compiled from `SUB.PLM`
    (`declare rbuff(1) byte at (.minimum$buffer)`), stored its command
    buffer at address 0000H.

  The correction:
  - um80 now repeats pass 1 until no value in the symbol table changes.
    A forward reference reads what the definition of the symbol will give.
  - After each repeat, um80 evaluates the `EQU`s and `SET`s again in
    the order in which they read each other.
  - The next repeat checks that guess, and reads the whole source
    again.
  - Pass 1 is over when the values that pass 1 computes are the values that
    the forward references read. Pass 2 reads the same values there too. So
    X is 6.
  - MACRO-80 3.44 flags that forward use of X `U`, and assembles the 01 that
    its pass 1 computed.

  Measurement:
  - A chain of 500 forward `EQU`s is read twice, in 0.6 s.
  - When each repeat settled one `EQU` of the chain, the chain took 92 s.
  - After three wrong guesses, a forward reference reads the value from the
    end of the repeat before. Each repeat then settles one `EQU` of the
    chain.
  - The limit on repeats grows with the longest chain in the source. The
    limit adds 64 for labels that forward sizes and JR promotion move.

  Cycles:
  - `EQU`s and `SET`s that are defined in terms of each other are an error
    that names the cycle: "Cannot resolve the value of 'X': it is defined in
    terms of itself (X EQU Y, Y SET X)". The error applies whether or not
    some value satisfies the definitions.
  - The same error applies to a symbol whose value still changes when the
    limit is reached (through a label whose own value moves).
  - The same error applies to a symbol whose value differs between the passes
    after the symbol was used (a phase error, for example after `IFDEF` of a
    later symbol).

  The `SET` directive:
  - A forward reference to a `SET` symbol reads the last value of the symbol.
    This value is what the last `SET` gives, with every symbol at its final
    value.
  - `X SET X+1` reads the X of the line before. So each `SET` is a
    definition of its own.
  - A chain may run through `SET`s.
  - A `SET` that reads a later symbol whose value comes from an earlier `SET`
    of the same name is no cycle.

  The difference from MACRO-80 3.44:
  - The difference exists when the last value depends on a symbol defined
    further down.
  - M80 does not flag a forward read of a `SET` symbol. M80 uses the value
    that the symbol had at the end of its pass 1, with no message. M80
    computed this value while the symbols below still had none (0).
  - Example: `DW X` / `X SET Y+1` / `DW X` / `Y EQU 5` is 01 00 06 00 in M80
    and in 0.3.48. The result is 06 00 06 00 in um80 now.
  - `DW X` / `X SET 1` / `X SET 2` is 02 00 in M80, in 0.3.48 and in um80
    now.
  - See "What still differs" in `docs/EXTENSIONS.md`.
- um80 assembler: um80 reported `/` or `MOD` by a symbol defined further
  down, or by an external, as "Division by zero" (the pass-1 value of the
  symbol is 0). Now only a constant 0 divisor is an error. `MOD EXT` goes to
  the linker, as in M80.
- um80 assembler: um80 accepted these redefinitions, and the second
  definition replaced the first with no message:
  - an `EQU` that is redefined with the same offset in another segment
    (`X EQU PC0` then `X EQU PD0`)
  - a link-time `EQU` that is redefined as a different expression
  - an external alias that is redefined as another offset

  Now each of these is "multiply defined", as in M80.
- um80 assembler: um80 reported an `EQU` whose value uses `AND`/`OR`/... on a
  relocatable value. um80 reported the error at every line that used the
  `EQU`, and the report did not name the `EQU`. On the sources of `ASM.COM` of CP/M 2.0, the report was at
  `LXI SP,ENDMOD`, which has no `AND` in it.
  - Now um80 reports the error once, at the `EQU` (where M80 flags it). The
    report names the first line that used the `EQU`.
  - A `DS n,fill` with such a fill repeated the error once per byte.
  - um80 reported the error for `PUBLIC` of a link-time `EQU` at a line past
    `END`. um80 now reports the error at the `PUBLIC`.
- um80 assembler: um80 assembled a meaningless displacement with no error for
  `JR`/`DJNZ` in these cases:
  - to an external
  - to a link-time expression
  - to an address in another segment
  - between absolute and relocatable code

  Details:
  - `JR EXT` came out `18 FE`, a jump to itself, with the external missing
    from the `.REL`.
  - Far enough from the segment start, um80 promoted the jump to `JP 0000H`.
  - LINK-80 has no PC-relative operator. These cases are errors now, as in
    M80 (`E`/`R`).
- um80 assembler: the listing showed the value that um80 computed from segment
  offsets, for a field that the linker computes. Example: `MVI A,HIGH(BUF)`,
  BUF at DSEG 0300H, listed `3E 03`. This byte is in neither the `.REL` nor the
  program.
  - Now the listing shows the placeholder that the `.REL` carries.
  - um80 marks every field that the linker has yet to finish after its last
    byte, as MACRO-80 marks the field:
    - `'` program relative
    - `"` data relative
    - `!` COMMON
    - `*` external

  Examples: `3E 00"`, `00 00*`, `00 03"` for `DW BUF`, `01 00'02`.
  The byte column is one character wider for the marks.

  A second fault in the listing: `JR EXT` far from the start of its segment
  reported its error together with "Note: 1 JR/DJNZ instruction(s) promoted
  to JP". Pass 1 promoted the jump because the jump was far from the 0 that pass 1
  read for the target. A target that the jump cannot reach is no longer
  promoted.
- um80 assembler: um80 rejected or evaluated differently some expressions
  that MACRO-80 accepts. Each fix was checked against M80 3.44.
  - A word operator next to a tab or a parenthesis was "Cannot parse
    expression". Examples: `HIGH<TAB>X`, `X<TAB>AND<TAB>0FH`, `NOT(X)`,
    `X AND(0FH)`, `(X)SHR(4)`, `LOW(X)OR 1`.
  - `OR` and `XOR` are one precedence level, left to right. So `1 OR 1 XOR 1`
    is 0, not 1. MAC does the same.
  - `''''` is 27H, not 2727H.
  - `DB 'A'+'B'` is the byte 83H, not the five bytes of the text.
  - `X##` of a local alias of an external or of a link-time `EQU` stands for
    what `X` does.
  - `EXT EQ EXT` (offsets from one external) is a constant.

  Division stays unsigned and a leading minus still applies after `SHR`
  (`-4 SHR 1` is FFFEH). MAC of DRI computes this value, and um80 assembles
  MAC sources too. M80 3.44 divides signed and gives 7FFEH.
- um80 assembler: in `.Z80` mode, um80 read a labeled `SET` instruction,
  `X1: SET 7,(IX+1)`, as the `SET` directive ("SET requires one operand").
  With two operands, the line is the instruction.
- um80 assembler: um80 ignored `.PHASE addr` and `.DEPHASE`. So the labels
  and `$` of a block meant to run at `addr` got their load addresses (`X: JP X`
  after `.PHASE 0F000H` assembled `C3 0001'`). Now the labels and `$` are the
  absolute addresses at which the block runs, as in M80. The bytes of the
  block still load at the current location.
- relformat: relformat returned special link item 4 as `UNKNOWN_SPECIAL`, and
  did not consume the B-field of the item. So relformat misread everything
  after the item in the module. ulib80 indexed four wrong "public symbols"
  from an M80 module that uses one such item. Item 8 (External − offset) has
  an A-field only, per the Microsoft manual. But relformat read item 8 as if
  the item had a B-field as well.
- ul80 linker: a chain-external record whose head is absolute 0 is an empty
  chain, as in LINK-80. M80 writes such a record to declare an external that
  is used only inside an expression, or not used at all.
  - ul80 followed the record as if a reference sat at absolute 0.
  - As a result, ul80 wrote the address of the external over the first word
    of a module with ASEG code there (a reset vector).
  - um80 now writes a reference at absolute 0 as an extension link item.
  - Such a head is still a reference only in an object from um80 0.3.48 or
    earlier. ul80 recognizes such an object by its item 14.
- relformat, um80: the genuine LINK-80 3.44 could not load any object that um80
  wrote. LINK-80 gave "?Loading Error", or LINK-80 did not end. There were three causes:
  - Special item 14 (end program) has an A-field, the start address
    (absolute 0 if none). um80 omitted the A-field, and wrote the start
    address as a set-location item instead.
  - Item 13 (program size) must have the type program relative, as M80
    writes it. L80 writes no output when the item is absolute.
  - The size of a COMMON block has to come before anything refers to the
    block.

  um80 now writes all three the way M80 does, with the segment and COMMON
  sizes at the start of the module. LINK-80 still refuses a symbol of 8 or
  more characters, and an external of 7 or more inside a link-time
  expression. See `docs/EXTENSIONS.md`.

  Four-way link test (M80+L80, M80+ul80, um80+L80, um80+ul80): 26 of 41 test
  links give the same bytes all four ways. The other 15 are as follows:
  - 3 differ where M80 3.44 gives a wrong value for an expression. The
    objects of um80 link to the right value in both linkers.
  - 2 differ where L80 3.44 gives a wrong value for a COMMON-relative value
    past the end of its block. The same is true for the objects of M80 and the
    objects of um80.
  - 8 differ where L80 places the program differently from ul80. The
    differences are: COMMON before the data, data before the code without
    `/D`, code above absolute code.
  - L80 refuses 2 for the objects of M80 and the objects of um80
    alike ("?Intersecting Program area" / "Data area").

  In every one of the 15, the objects of um80 link in L80 as the objects of
  M80 do. Where the objects of M80 give a wrong value, the objects of um80
  link to the right value.
  `docs/EXTENSIONS.md` lists the 15 test links.
- um80 assembler: a module with no DSEG had no item 10 (data size). MACRO-80
  writes item 10 in every module, 0 if need be. Without item 10, LINK-80
  drops the constant of an external plus offset in ASEG. Example: `ASEG` /
  `ORG 4000H` / `DW EXT+1` linked in L80 to EXT. um80 now always writes
  item 10.
- relformat: the reader read item 14 without its A-field. So the reader
  misread every object that MACRO-80 or LINK-80 wrote after the first module
  of the object.
  Example: `ulib80 -c` on FORLIB.REL of FORTRAN-80 crashed
  (UnicodeEncodeError) and found 43 wrong "publics" instead of 418. The
  reader now reads both layouts (the earlier objects of um80 have no
  A-field).
- ul80 linker: MACRO-80 writes `JMP EXT+3` as special item 9 (External plus
  offset). The item comes before a word that is an entry of the chain of EXT.
  MACRO-80 chains every reference to an external through the words.
  - ul80 ignored items 9 and 8, and changed only the head of each chain.
  - As a result, the relocation pass added the segment base to the other
    chain entries.
  - In an M80 object, `JMP EXT+3` linked to EXT, and of three `CALL X` the
    second called X+100H.
  - ul80 now applies the constants and follows each chain entry by its
    relocation type.
- ul80 linker: a chain entry that has the type absolute is an address in
  ASEG, as in LINK-80.
  - Before, ul80 read the entry as an offset in the segment of the word that
    holds the entry. MACRO-80 chains a CSEG or DSEG reference to a reference
    in ASEG (`ASEG` / `ORG 4000H` / `DW EXT` / `CSEG` / `CALL EXT`). In this
    case ul80 never found the ASEG word, and the word stayed 0000H.
  - Also, ul80 marked a word in a chain in the relocation bitmap of a `.PRL`
    file or `.SPR` file by the type of the link that the word held. The type is
    program relative for a link to another reference. ul80 did not mark the
    word by the value that was filled in. Example: two `CALL X` of an
    absolute X marked the second.
  - For a REL file from package um80 0.3.48 or earlier, ul80 still uses the
    old way. ul80 recognizes such a file by its special link item 14 (no
    A-field). In the old way, an absolute link is an offset in the segment of
    the word that holds the link.
  - The old way matters only for package um80 0.2.0 to 0.3.34. These
    versions chained all the references to an external through untyped
    words. Each word holds the offset of the previous reference.
  - Package um80 0.3.35 to 0.3.48 wrote each reference as a chain of one
    entry. The link in that entry is 0 in either way that ul80 reads the
    link.
  - Where the references are in more than one segment, a link does not say
    which segment the link is in (see Known issues).
- ul80 linker: ul80 read special link item 12 (chain address) and never
  applied the item.
  - FORTRAN-80 writes every forward reference as a chain through the words
    that need the address, and then item 12 where the address is. A forward
    reference is a jump to a label further down, a FORMAT string, or a
    constant after the code. The words kept their chain links.
  - When a module defines the global `$MEMRY`, LINK-80 stores an address in
    the word at `$MEMRY`. The address is the first free byte after the data
    of the program. DSKDRV of FORLIB allocates its file buffers from that
    word. ul80 left the word 0000H.
  - Test: a 10-line DO/WRITE/FORMAT program was compiled with F80 and linked
    with FORLIB. The image differed in 10 bytes from the image that L80
    writes with `/P:100/D:19D3,T,FORLIB/S`. The program stopped with
    `**DZ**`. Now the image is byte-identical, and the program prints
    `385 128.333`.
  - The image of a program with a subroutine, a function, an array argument,
    `IF`/`GOTO` and `STOP` is byte-identical too (0100H-1CF9H).
- ul80 linker, ulib80: ul80 loaded only the first module of a `.REL` that
  holds several modules. An example is a LIB-80 library such as FORLIB.REL of
  FORTRAN-80, which has 106 modules. Also, `ulib80 -c` stored the file as one
  module. Now ul80 loads every module. ulib80 keeps each module as a module
  of its own, named by the program name of the module.
- um80 assembler, ul80 linker: two or more named COMMON blocks were placed at
  one address, on top of each other.
  - Cause: ul80 ignored special link item 1 (select COMMON block). A
    COMMON-relative value is relative to this item. um80 wrote the item only
    at the `COMMON` directive. So every COMMON-relative word, every value of
    an extension link item and every public symbol referred to the block that
    came last.
  - Now each block gets its own place. The size of the place is the size of
    the largest declaration of the block. The blocks are placed in the order
    in which the blocks are first declared.
  - um80 selects the right block before each reference. um80 writes a
    reference to another block from inside a block as an extension item.
    Before the store, um80 selects again the block that is being loaded.
  - The distance between two different COMMON blocks is a link-time
    expression, not a constant. M80 3.44 assembles the distance as a
    constant.
  - um80 put bytes that it assembled into a COMMON block (`DB`, BLOCK DATA
    of FORTRAN) into the segment before the `COMMON` directive. The bytes
    overwrote the code after the directive. Also, ul80 ignored initialized
    COMMON data. Now both land in the block, and the bytes that a module
    loads there are in the image.
  - ul80 loads into the block that the last set-location item selected, as
    LINK-80 does. ul80 does not load into the block that was selected last.
    M80 selects another block for an operand inside a COMMON block, and M80
    does not select the first block again. Example: `COMMON /BLK1/` /
    `DW C2` / `DB 7`, with C2 in BLK2. ul80 loaded the rest of BLK1 into
    BLK2.
  - A `.PRL` header now reserves memory for COMMON, which lies past the
    image. Before, MP/M allocated no memory for COMMON.
- um80 assembler: with `--aseg`, the linker loaded code before the first
  `ORG` into CSEG, at the program base. The labels of the code are absolute
  from 0. An external that was referenced there was never filled in. The
  module now starts in ASEG.
- um80 assembler: every `ASEG` directive wrote a set-location item to ASEG
  0000H, even when nothing was assembled there.
  - LINK-80 takes that item as code that is loaded at 0000H. Example:
    `ASEG` / `ORG 100H` / ... linked with L80 into a COM file that starts at
    0000H. The COM file has 384 bytes and "Data 0000 010C". The REL file of
    M80 gives "Data 0100 010C".
  - As in MACRO-80, um80 now writes the item only when something is loaded
    or reserved in the segment. An `ORG` or another segment directive can
    replace the item before then, and um80 writes no item in that case.
    `--aseg` starts the same way.
- um80 assembler: um80 now continues a segment or a `COMMON` block at the
  same place as MACRO-80 3.44.
  - Every `COMMON` statement starts at the beginning of its block. The
    MACRO-80 manual gives the rule of FORTRAN: a block that is declared again
    lays its contents over the same storage. um80 continued where the block
    was left.
  - MACRO-80 keeps a location for each of CSEG, DSEG and ASEG. The location
    is the highest of these:
    - the locations that were set in the segment (`ORG`, the end of a `DS`)
    - the locations at which the segment was left
  - `CSEG`/`DSEG`/`ASEG` continues from that location.
  - Example 1: after `ASEG` / `ORG 200H` / `DB 1,2,3` / `ORG 180H` / `DB 4`,
    a later `ASEG` continues at 0200H, over the 1.
  - Example 2: after `DS 10H` / `ORG 4` / `DB 1`, a later `CSEG` continues
    at 10H, past the `DS`.
  - um80 continued where the segment was left (0181H in example 1, 5 in
    example 2). So um80 and M80 gave different layouts for such a source.
- ul80 linker: ul80 relocated a byte that was loaded over a relocatable word
  as if the byte were the word.
  - ul80 relocated after it loaded everything. It added the segment base to
    whatever bytes had been loaded over the word since then. These cases
    were wrong:
    - A module with an `ORG` back. `CSEG` / `NOP` / `X: DW X` / `ORG 1` /
      `DB 5,6` linked to 00 05 07, and `ORG 1` / `DW X` to 00 01 02, with
      the base added twice.
    - A second module that loads the same bytes of a COMMON block.
    - A block that the source declares again. This case came after um80 started
      every `COMMON` statement at the beginning of its block, as MACRO-80
      does (above). Example: `COMMON /C/` / `C1: DW C1` / `DB 7` /
      `COMMON /C/` / `DB 9,9` linked to 0C 0A 07, where L80 gives 09 09 07.
  - LINK-80 relocates a word as it loads the word. A byte that is loaded
    there later just replaces that byte, and the other byte keeps its
    relocated value (`ORG 1` / `DB 5` gives 00 05 01). ul80 now does the
    same.
  - The relocation bitmap of a `.PRL` file or `.SPR` file no longer marks a
    byte that something was loaded over.
  - ul80 now fills the chain of special link item 12 when ul80 reads the
    item, as L80 does. So bytes that are loaded over a word of the chain
    afterwards stay. Before, ul80 followed the chain at the end, through
    whatever had been loaded over the chain.
  - ul80 fills the chain of an external when L80 fills the chain. L80 fills
    the chain after both the module and the module that defines the external
    are loaded. So bytes that a later module loads over the chain in a shared
    COMMON block stay too.
  - ul80 still applies items 8 and 9 (external plus or minus a constant) and
    link-time expressions last, to whatever is there then, as L80 applies
    them.
  - Tests: every case was checked against the genuine M80 and L80 3.44, with
    the REL files of M80 and of um80.
    - The test used 406 random single-module programs that L80 links. The
      programs use `CSEG`, `DSEG`, `ASEG`, `COMMON`, `ORG`, `DS`, `DB` and
      `DW`.
    - In every program, ul80 now links the REL file of um80 to the bytes of
      L80. Before, two of the first 120 programs differed.
    - The output for no source in the corpus of 1363 changes.
- um80 assembler: um80 gave the size of a segment (items 13 and 10) as the
  location at the end of the segment. After an `ORG` back, this size gives a
  wrong count.
  - Example: `CSEG` / `ORG 20H` / `DB 1` / `ORG 10H` / `DB 2` gave 11H
    bytes, and the next module was linked over the 1.
  - The size is now the highest location that the segment reached, 21H.
  - MACRO-80 says 20H. The size in MACRO-80 is the highest of the locations
    that were set and the location at the end. This size ignores the bytes
    that are loaded past the highest `ORG`. L80 then links the next module over the
    last of these bytes.
- ul80 linker: ul80 ignored absolute code that an `ORG` placed below the
  first byte that a module loaded in ASEG. ul80 wrote no message.
  - Example: `ASEG` / `ORG 200H` / `DB 1` / `ORG 180H` / `DB 4` gave an
    image with only the 1. ul80 took the first address that was loaded as
    the start of the ASEG of the module. Now the 4 is at 0180H, as in
    LINK-80.
  - Also, a COM file whose only code is absolute and above the origin (`-p`,
    0100H by default) started at its lowest byte. CP/M then loads the file
    at 0100H. Now the file starts at the origin.
  - At the default origin, LINK-80 also writes a COM file that starts at the
    origin (the same 384 bytes that L80 writes for the example).
  - L80 starts a COM file at 0100H whatever `/P` says. ul80 starts the file
    at `-p`. So `-p` gives an image that starts at another address, for
    example a ROM at E000H (see "What still differs" in
    `docs/EXTENSIONS.md`).
- ul80 linker: ul80 wrote the gap that an `ORG` or `DS` leaves in the
  absolute code of a module into the image as zeros. The zeros went over
  whatever another module had loaded there, with no message.
  - Example: a CSEG module at 0100H, then a module that loads absolute bytes
    at 0080H and 0300H. The image had the CSEG zeroed.
  - Now ul80 writes only the bytes that a module loads into the image, as
    LINK-80 does.
- ul80 linker: ul80 put the code of each module straight after the code of
  the previous module, even where an earlier module had loaded absolute
  code.
  - Example: `ASEG` / `ORG 100H` in one module and a CSEG in the next module.
    ul80 linked the CSEG on top of the absolute code, with no message.
  - LINK-80 3.44 (probed under cpmemu) starts the next module above the
    highest absolute location that was loaded so far. The location is a
    byte, or a location that an `ORG` or `DS` set. LINK-80 starts the next
    module there with `/P` and without `/P`. LINK-80 starts the next module
    there even when free space is below the location. Example: absolute
    code at 0200H and `/P:100` put the next module at 0204H.
  - Absolute code below the origin moves nothing. The absolute code of a
    module does not move the code of the same module. ul80 now does the same
    as LINK-80.
  - `__END__` (and so `$MEMRY` and `.MEMORY` of PL/M) is now past the
    absolute code that is loaded above the program, as `$MEMRY` of L80 is.
    Before, `__END__` was the end of the relocatable areas, below the
    absolute code.
  - Absolute code that still lands on something is an error, and ul80
    writes no output. The cases are:
    - the program area of a module (its own, or of an earlier module)
    - the data or COMMON after all the code
    - the absolute code of another module
  - L80 warns "%Overlaying Program area" and writes a mixture of the two.
    `--allow-overlap` (under Added) links as L80 does with `/D`.
  - Example of such an error: `ASEG` / `ORG 100H` / `JMP START` and a CSEG in
    one module, at the default origin of ul80, 0100H. The origin of L80,
    0103H, leaves room for the jump. `-p 103` also leaves room for the jump.
  - Test: a full MP/M II source build (2.0 and 2.1) gives the same bytes in
    42 of its 44 targets. The build links `DDT.COM` and `RDT.PRL` from the
    absolute `DDT0MOV`, `DDT1ASM` and `DDT2MON` of DRI. Both targets now
    fail with "Module DDT1AS: absolute code at 0100H, 0103H-019AH overlaps
    absolute code of module DDT0MO".
  - Reason for the failure: `DDT1ASM` is assembled at 0000H. Its code went
    over the relocator of `DDT0MOV`. The `.COM` started at 0000H with a
    `JMP 0683H` of `DDT1ASM`. DRI joined the three files with `GENHEX` and
    `GENMOD` (`DDT.SUB`), not with a linker (see Known issues).
- ul80 linker: in the relocation bitmap of a `.PRL` file or `.SPR` file, ul80
  never marked a reference to `__END__`, `__BSS_START` or `__BSS_END`. ul80
  also never marked a reference to a `PUBLIC` alias of one of these.
  - The linker calculates these symbols as absolute values, but they are
    program addresses.
  - `.MEMORY` of PL/M compiles to exactly such a reference. So in a `.PRL` file
    the reference pointed at the linked address, not at the loaded address.
  - Example: SDIR of MP/M II (UTIL7/DSE.PLM puts its hash table
    `AT(.MEMORY)`) wrote outside its memory segment whenever MP/M loaded
    SDIR anywhere but the link base.
  - A full MP/M II build now marks 17 more words in ED.PRL, 9 in PIP, 4 in
    SDIR and 3 in STAT. Every one is a reference to the end of the program.
- ul80 linker: for a chained word, ul80 used the symbol plus the offset to
  decide whether a reference was to page zero. For a link-time expression,
  ul80 used only the symbol.
  - So `LXI H,TBUF+80H` (0100H) escaped the bitmap, while
    `MVI A,HIGH(TBUF+80H)` was marked.
  - Also, ul80 marked `DW KHI-1200H` (0034H) of a constant 1234H.
  - Now ul80 uses only the symbol in both cases.
- ul80 linker: the modules that a library search loaded, and so the image,
  had a different order each time that you started ul80. The search used
  a Python set of undefined names.
  - The order is now the order of LINK-80: each library in turn, and its
    modules in library order.
  - ul80 continues to search until no more modules load. The option `/S` of
    LINK-80 makes one pass. The option `/S` leaves a reference to a module
    earlier in the library undefined. So the two programs place the modules of such a link
    differently (see `docs/EXTENSIONS.md`).
- ul80 linker: ul80 followed an external chain whose head, or a link, leads
  outside the bytes that the module loaded. ul80 followed the chain that far
  and then ignored the rest of the chain, with no message. The references
  after that point stayed unfilled.
  - No correct REL file holds such a chain. The REL files that package um80
    0.3.48 assembled with `--aseg` from relocatable sources do hold such a
    chain. The code of these files went to CSEG, and the chain heads stayed
    absolute.
  - ul80 now writes a warning that names the module and the symbol.
  - **Reassemble any REL file that package um80 0.3.48 made with
    `--aseg`.**
- um80 assembler: an empty COMMON block (`COMMON /X/` with nothing in it) got
  no size item (special link item 5).
  - MACRO-80 writes the block with size 0.
  - LINK-80 stops with "?Loading Error" when it selects a block that has no
    size. So L80 could not load such a REL file.
- ul80 linker: ul80 printed "link-time expression has no store operator" as
  an error, but ul80 wrote the image with the field 0, and ul80 exited with
  status 0. Now the link step fails.
- ul80 linker: ul80 refused `(BUF+255)/256` and `BUF MOD 256` of a
  relocatable BUF for `.PRL` output or `.SPR` output. The two expressions are
  `HIGH(BUF+255)` and `LOW(BUF)`, which a relocation bitmap can express. ul80
  now accepts them.
- ul80 linker, ulib80: ul80 refused a LIB-80 library with the message "bad
  magic". The library is a `.LIB` made by LIB-80 of Microsoft: `.REL`
  modules one after another, like FORLIB of FORTRAN-80.
  - ul80 now searches the library like a library file of ulib80.
  - `ulib80 -l`/`-p` list the library.
  - A program that calls `$AA` of FORLIB links to the same code as the `/S`
    search of LINK-80.

### Changed
- um80 assembler: the linker now calculates `n-SYM` and an expression that
  names two externals. Since 0.3.48 these were errors, because the `.REL`
  format "cannot carry them". Now um80 writes them in the form that M80 3.44
  uses. In `.PRL`/`.SPR` output they are errors when the result would not move
  by exactly 0 or 1 page (see below).
- um80 assembler: um80 reports an error when a program applies `AND`, `OR`,
  `XOR`, `SHL`, `SHR` or a comparison to a relocatable or external value. The
  error occurs when um80 assembles the result into an instruction or
  `DB`/`DW`.
  - M80 flags these `R`. The exception is a comparison of two externals.
    M80 evaluates that comparison with both externals as 0.
  - RMAC of DRI flags these `E`.
  - LINK-80 has no such operators, and the value that was based on the
    offset was wrong, with no message.
  - Two addresses in one segment, or two offsets from one external, compare
    as constants.
  - Absolute code (`ASEG`, `--aseg`) is not affected: HIGH/LOW of an absolute
    value is a constant and um80 writes no extension item.
- um80 assembler: a directive that uses its operand while it assembles
  refuses a value that only the linker knows. These directives are `ORG`,
  `DS`, `IF`/`IFE`/`COND`, `REPT`, `RST`, `IM`, `BIT`, `END`, `.RADIX` and
  the macro `%` operator.
  - A value that only the linker knows is an external, `HIGH`/`LOW` or
    another link-time expression of a relocatable value, or `AND`/`OR`/... of
    one. M80 flags all of these `R`.
  - Before, the directive used a value that um80 calculated from segment
    offsets. `DS 100H-LOW($)` in a CSEG aligned to the start of the segment
    and not to a page. `X EQU LOW(LAB+5)` / `DS X` reserved the low byte of
    an offset.
  - `IF 5-EXT` and `REPT EXT+EXT` were errors in 0.3.48. Without the change,
    these two statements would become 0.
  - A relocatable address that is used as a number is still its offset. M80
    flags `IF LAB` and `DS LAB` too, but um80 continues to accept them.
  - `ORG $+10` still moves within the segment. `ORG` to an address in
    another segment is an error.
- um80 assembler: a `PUBLIC` symbol that is equated to a link-time expression
  is an error, because a `.REL` public carries an address or a constant.
- um80 assembler: a word that is an external plus a constant is now written
  as M80 writes it: special item 9 with the constant, then a reference in the
  chain of the external. Before, um80 wrote a chain with the name `EXT+3`,
  and LINK-80 treated that name as an undefined symbol. ul80 still reads the
  old form.

### Added
- ul80 linker: `--allow-overlap` links absolute code that loads over other
  code, for example a patch module or an overlay module. ul80 writes a
  warning, as LINK-80 does ("%Overlaying Program area"). Without the option,
  the overlap is an error (see Fixed). The error message now says that the
  option exists.
  - The image has the byte that ul80 loaded last. A byte of a later module is
    over a byte of an earlier module.
  - In one module, the byte that ul80 loaded later wins, absolute or not.
    L80 writes the same image when it is given `/D`.
  - A relocated word keeps the relocated byte that no other byte replaced.
  - Where a patch loads over a word of the chain of an external, ul80 still
    fills every reference. ul80 follows the links that each module has. L80
    follows the patched bytes as a link.
  - Of 199 random patch links, 191 are byte-identical to L80 `/D`. Seven differ
    in the way that the previous item describes. One differs by the `/D`
    layout.
- ul80 linker: ul80 evaluates extension link items (`+ - * / MOD NOT HIGH
  LOW`, unary minus, externals, program/data/common-relative values) once it
  has placed every segment. ul80 does this for `.COM`, `.HEX`, `.PRL` and
  `.SPR` output alike.
  - ul80 links an object that the real MACRO-80 3.44 wrote to the values that
    LINK-80 3.44 calculates for the object.
  - L80 links an object that um80 wrote to the values that ul80 calculates.
  - Two exceptions: L80 gives a wrong value for a COMMON-relative value past
    the end of its block, and the two linkers place things in a different
    way (see `docs/EXTENSIONS.md`).
- ul80 linker: in `.PRL`/`.SPR` output, ul80 marks bytes and words in the
  relocation bitmap.
  - ul80 marks a stored byte that is `HIGH` of an address in the relocation
    bitmap.
  - ul80 does not mark a stored byte that is `LOW` of an address, because a
    page move never changes a low byte.
  - ul80 marks a stored word that is an address on its high byte.
  - The bitmap cannot express a value that would not move by exactly 0 or 1
    page when MP/M relocates the program. Examples are `HIGH(A)+HIGH(B)`,
    `200H-LAB` and `LAB*2`. Such a value is an error for `--prl`/`--spr`.
    ul80 links the value normally for `.COM` and `.HEX`.

### Known issues
- MP/M II's source build (`tools/build.py` in the mpm2 repository, V2.0
  and `--version 2.1`) stops with "Build complete: 42 succeeded, 2
  failed". `DDT.COM` and `RDT.PRL` fail with "Module DDT1AS: absolute code at
  0100H, 0103H-019AH overlaps absolute code of module DDT0MO". The build
  links them with ul80 from the absolute modules `DDT0MOV`, `DDT1ASM` and
  `DDT2MON` of DRI.
  - The error is right. The `DDT.COM` that the recipe linked (committed in
    mpm2 as `bin/src/DDT.COM`) starts `C3 83 06`. The `DDT.COM` of DRI starts
    `01 94 11 C3 47 01`.
  - DRI made the two files with `GENHEX` and `GENMOD` (`UTIL1/DDT.SUB`), not
    with a linker. The recipe of mpm2 (`UTIL1_TARGETS`) has to do the same
    before this release is used for that build.
  - The branch `fix/ddt-genmod` of mpm2 (commit 0386288, merged for the next
    release of mpm2) does this. It builds all 44 targets for V2.0 and V2.1
    with this ul80. Its `DDT.COM` and `RDT.PRL` are byte-identical to the
    files of DRI.
  - If you link the old way with `--allow-overlap`, the result is exactly the
    old, wrong `DDT.COM`.
- ul80 linker: an object from um80 0.2.0 to 0.3.34 that refers to one
  external from more than one segment does not link correctly. The problem
  exists with this ul80 and with any earlier ul80.
  - Those releases chained all the references to an external through untyped
    words. Each word holds the offset of the previous reference, in the
    segment where that reference was. The link does not say which segment.
  - ul80 follows each link in the segment of the word that holds the link.
    The chain goes wrong at the first link that crosses to another segment.
    The references before that link keep their link values.
  - Example: `EXTRN EXT` / `CSEG` / `CALL EXT` / `DSEG` / `DW EXT`, assembled
    by um80 0.3.34, links to `CD 00 00` for the `CALL`. The `DW` gets EXT.
  - Also, um80 0.2.0 to 0.3.20 put the DSEG bytes of a module in the CSEG
    stream of the module. ul80 0.3.48 and this ul80 fill different wrong
    words there.
  - To correct the problem, assemble such a source again with a current um80.
- ul80 linker: a `.PRL`/`.SPR` relocation bitmap can disagree with the image
  where a later write replaces one of these:
  - the chain word of an external
  - a `HIGH`/`LOW` field
  - an item-9 word

  A later write is one of two things: an `ORG` back over the word, or a later
  module that loads the same COMMON bytes and defines the external. A mark that
  ul80 set when the chain was filled can stay after the byte is replaced.
  - Every such program is wrong input for L80 too. L80 follows the wrong
    chain to other bytes, or does not end.
  - 938 random programs without such an overwrite all satisfy the page-shift
    property. The bitmap moved by k pages equals the image linked k pages
    higher.
- um80 assembler (as in every earlier release): two things do not work as in
  MACRO-80.
  - um80 does not accept a symbol that has the name of a register (`E`, `A`,
    `B`) in an expression ("Register 'e' used as value").
  - um80 treats a directive that the programmer writes in column 1
    (`public fcb`) as a label.

  MACRO-80 accepts both.

## [0.3.48] - 2026-09-24

A build of all of MP/M II V2.0 and V2.1 from the sources of Digital
Research found five defects. The build result was compared with the binaries
of DRI. Each defect has a regression test. The test fails when a person
reverts the fix.

### Changed
- ul80 linker: `--prl` now links a transient at 100H. MP/M loads a `.PRL` at
  `segment_bottom + 100H`, but its relocator (NUCLEUS/CLI.ASM, `relocate`)
  adds only the base *page* of the segment to the bytes that the bitmap
  marks. For this reason the extra page has to come from the link, exactly as
  for a `.COM`.
  - Before, ul80 linked at 0. Every relocated address was then a page below
    the code. Source-built MP/M utilities loaded, printed nothing and dropped
    the session.
  - The binaries of DRI state the convention: the highest relocatable word in
    `STAT.PRL` is its program length plus 100H.
  - **An earlier release linked a `.PRL` with `--prl` in the wrong way. Link
    the `.PRL` again.**
- ul80 linker: system pages (`.SPR`, `.RSP`, `.BRS`) have their own option,
  `--spr`. MP/M loads system pages at the segment base, and they are linked
  at 0.
- ul80 linker: in page-relocatable output, ul80 now marks for relocation a
  resolved reference to an absolute symbol below 100H. Examples are the BDOS
  entry at 0005H, the default FCB at 005CH and the DMA buffer at 0080H. The
  reason is that under MP/M page zero belongs to the memory segment of the
  process.
  - DRI got the same effect with two links at different offsets
    (PLM_WORK/X0100.ASM and X0200.ASM). GENMOD then compared the results.
  - `DIR.PRL` of DRI marks twelve `CALL 5` sites.
  - An absolute symbol at or above 100H stays absolute.

### Added
- ul80 linker: `--extra HEX` gives the memory that a `.PRL` asks MP/M for
  beyond its image, for storage that a PL/M program places at `.MEMORY`.
  Nothing in the REL files says how much memory. DRI named the amount at build
  time, as the third argument of GENMOD. ASM, ED, PIP and SDIR of DRI reserve
  1000H, and RDT reserves 1500H.
- um80 assembler: `--aseg` assembles a source that was written for MAC of
  DRI the way MAC assembles it: absolute, so an `ORG` is an address and not an
  offset in CSEG.
  - The assembler of MP/M II is seven such modules, each with its own `ORG`.
    DRI assembled them separately and concatenated them as HEX.
  - Assembled as relocatable, the modules were stacked end to end, and
    `ASM.PRL` was 36971 bytes against 8171 bytes for DRI.
  - With `--aseg`, `ASM.PRL` is 8176 bytes. The `BOOT.HEX` that um80 writes
    from `BOOT.ASM` is byte-identical to the `BOOT.HEX` that the
    `ASM.PRL` of DRI writes.

### Fixed
- um80 assembler: an offset that um80 subtracted from an external symbol kept
  its sign. `LXI H,PDTBL-34H` assembled to `PDTBL+34H`.
  - The two branches that separate the constant from the symbol were
    swapped. um80 added the constant to the right of a `-` and negated the
    constant to the left.
  - `SYM+n` and `n+SYM` were right, and for this reason the defect stayed.
  - `n-SYM` (a negated symbol) and an expression that names two externals
    cannot be carried in a `.REL` file. They are now errors and no longer
    wrong code.
  - In the CLI of MP/M II, the defect put every reference to a process
    descriptor 68H bytes past the table. A source-built system warm-booted
    and did not run any transient.
- um80 assembler: a label that has the name of a mnemonic assembled to the
  opcode byte. An opcode name stands for its own byte (`DB MOV` is 40H).
  um80 applied that rule before it searched the symbol table.
  - For this reason `CALL ADD` assembled to `CALL 0080H` (80H is `ADD A,B`),
    also where `ADD` was a defined procedure.
  - A defined or external symbol now wins. The opcode byte remains for names
    that are not symbols.
  - `STAT.PLM` of MP/M II declares `add: procedure`. STAT executed its own
    command tail at 0080H and restarted. It printed its drive line 1837
    times.
- ul80 linker: `__END__` that ul80 exported to another module was zero.
  - A PL/M `AT (.MEMORY)` compiles to a public alias of `__END__`. ul80 has
    to register the alias before it resolves externals, but the alias has no
    value until ul80 has placed every segment. ul80 now calculates the value
    again when the bases are known.
  - SDIR declares its hash table in this way in one module and uses the hash
    table from another module. SDIR cleared 256 bytes from address 0, the
    BDOS vector included.

## [0.3.47] - 2026-09-23

### Documentation
- Backfilled the missing CHANGELOG entries for 0.3.25 through 0.3.36. No
  code changes in this release.
  - The file ran from 0.3.37 straight back to 0.3.24. Twelve releases had no
    record at all.
  - One of the twelve is 0.3.32, which carried the DSEG placement fix. The
    defect that the fix removed had corrupted every multi-module link whose
    modules carry initialized data, with no message.
  - A record of that fix needs to be easy to find afterward. The defect
    appeared months later as an MP/M II system image that was 1152 bytes
    short and did not boot.

## [0.3.46] - 2026-08-04

### Fixed
- ul80 linker: ul80 now reports an error that it recorded during an otherwise
  successful link. `main()` printed `linker.errors` only when `link()`
  returned false.
  - L80 keeps the first definition of a multiply-defined global and links
    on. Then `link()` succeeds, and ul80 threw away every error that was
    recorded along the way, with no message: exit 0, output written, nothing
    on stderr.
  - This hid the multiply-defined PUBLIC error that 0.3.42 added, on the
    command-line path. Nobody noticed, because the test for the error drives
    the `Linker` API and not the entry point. The check worked, and only the
    reporting did not.
  - On the command line the message was missing for two releases. Through
    0.3.41, ul80 printed `Warning: Multiple definition of 'X'`. 0.3.42 made
    the message an error that `main()` never reached. 0.3.43 shipped in that
    state.
  - ul80 now prints `Error: Multiply defined global 'X'`. Tests now cover
    both CLI paths.
  - The exit status stays 0 when the link still succeeded. L80 does the same:
    L80 accepts such link lines and writes output.

## [0.3.45] - 2026-08-04

### Fixed
- um80 assembler: The two-operand Z80 ALU forms `SUB/AND/XOR/OR/CP A,<operand>`
  no longer delete the operand.
  - ADD, ADC and SBC each reduce a leading `A,` to the one-operand encoding.
    These five forms had no such branch. um80 read `A` as the operand and
    deleted the real operand.
  - Examples: `CP A,5` assembled as `CP A` (BF, which always sets Z) and not
    as FE 05. `SUB A,5` assembled as 97 and not as D6 05. `AND A,0FH`
    assembled as A7 and not as E6 0F. `CP A,(IX+3)` assembled as BF and not
    as DD BE 03.
  - The exit status was 0 and um80 wrote no message, on ordinary Zilog syntax
    that people write.
  - The upper bound that 0.3.44 added only rejected three or more operands.
    For this reason the bound did not reach this defect.
  - A destination that is not the accumulator is now an error. Before, um80
    deleted the destination with no message. This is true for these five
    forms and for ADD/ADC/SBC too, because `ADD B,C` went to `ADD B` and
    deleted the C in the same way.
  - The last change breaks source that assembled before. `ADD B,C` and `CP B,5`
    gave exit status 0 under 0.3.43. Now they stop the assembly.
- um80 assembler: `.Z80`/`.8080` mode no longer leaks across passes. um80
  set the mode once in `__init__` and never reset the mode. The mode at the
  end of pass 1 became the first mode of pass 2.
  - A `.Z80` anywhere in a file made pass 2 assemble the lines ABOVE the
    `.Z80` as Z80 code.
  - `JP addr` silently became C3 and not the 8080 F2 (jump if positive).
  - `CP n` became the two bytes FE and not the three bytes F4 (call if plus).
    This moves every label after the `CP n`.
  - The exit status was 0, and um80 wrote no message.
  - The mode now resets in each pass, exactly as the radix does, because a
    `.Z80`/`.8080` applies again in every pass.
  - The defect weakened the advice in the error message of 0.3.44 itself. The
    message told a user to add a `.Z80` directive. A user who put the
    directive at the bottom of the file silently changed the meaning of
    everything above the directive.
- Documentation: the three Microsoft manual links in README.md, the manual
  list in docs/index.md and the pointer in docs/project.txt all named
  `docs/external/m80.pdf` and its neighbors.
  - The repository has never tracked those PDF files, and the sdist did not
    ship them. Every one of those links was dead for anyone who did not
    already have a private copy of that directory.
  - The links now point to the retro_docs archive.
  - The "From source" instructions in README.md also cloned
    `github.com/um80/um80_and_friends.git`. That organization does not
    exist, so the copy-and-paste clone failed outright. The instructions now
    name `avwohl`.
  - No code changed for either correction.

## [0.3.44] - 2026-08-03

### Added
- README.md documents three things.
  - 8080 is the default mode, and Z80 mnemonics need a `.Z80` directive.
  - The text of the new error below.
  - `um80 -e .z80 file.mac` sets the mode from the command line, with no edit
    of the source.

  The change below turns a silent operand drop into a hard error. Without
  these notes, a user who gets that error has no way to learn that the mode
  is positional. The user also has no way to learn that a route exists that
  does not need an edit of every file.

  The Related Projects list in the same file was separately rewritten in
  Simplified Technical English: wording only, same projects, same links.
- docs/ISSUES.md #4 records a ulib80 defect. The defect was found
  while the set of files that the change affects was measured. The defect
  was NOT fixed in this release.
  - `ulib80 -c lib.lib` writes a different byte stream each time that it runs
    over the same unchanged `.rel` inputs. The reason is that the library
    writer iterates a `set` or `dict`. A fixed `PYTHONHASHSEED` makes the
    output reproducible.
  - The archive still links correctly, so nothing that was built from the
    archive is wrong. But a byte comparison cannot show whether a change of
    the toolchain altered a library.
  - Across the 0.3.44 change, every uc80 `.rel` module was byte-identical.
    `libc.lib` and `runtime.lib` differed on every rebuild.

### Changed (deliberate divergence from MACRO-80 3.44)
- um80 assembler: An operand that a program gives to an instruction that takes
  none is now an ERROR. um80 writes nothing and the exit status is 1.
  - Before, um80 wrote a warning, or no message at all for the conditional
    returns. um80 deleted the operand. This silently assembled a different
    program:

    - `RET NZ` assembled as `C9`, an unconditional RET (Z80: `C0`).
    - `RLC B` assembled as `07`, RLC A (Z80: `CB 00`).
    - `RRC C` assembled as `0F`, RRC A (Z80: `CB 09`).
    - `RZ FOO` assembled as `C8` with no message at all.
    - `NOP 5` assembled as `00`.

  - The error covers these mnemonics:
    - All 17 8080 no-operand mnemonics (NOP RLC RRC RAL RAR DAA CMA STC CMC
      HLT RET PCHL SPHL XCHG XTHL DI EI).
    - All 8 conditional returns (RNZ RZ RNC RC RPO RPE RP RM).
    - The Z80-mode no-operand mnemonics and the ED-prefix no-operand
      mnemonics.
  - Some mnemonics with an operand spell a valid Z80 instruction (`RET cc`,
    `RLC r`, `RRC r`). For these, the message names the `.Z80` directive,
    which makes um80 assemble Z80 mnemonics.
    - For `RET cc`, the message also gives the 8080 spelling (`RET NZ` is
      `RNZ`).
    - For `RLC r` and `RRC r`, which have no 8080 spelling, the message says
      that the 8080 rotate applies to A only.
  - M80 3.44 flags these statements `Q` (questionable). M80 writes the opcode
    with no operand and still writes the .REL. The change is therefore a
    deliberate break with the bit-compatibility with M80. The reason is that
    um80 would change `RET NZ` to an unconditional `RET`, which is a silent
    wrong assembly.
  - The set of files that the change affects is empty (measured). The 14
    original Microsoft MBASIC 8080 sources, the 98 uc80 library modules and
    every other `*.mac` outside `external/` assemble to byte-identical
    objects with no new messages.
  - 8080 mode remains the default (M80 behavior). The legitimate 8080
    readings of `JP`/`CP` (jump-if-positive, call-if-plus) do not change.

### Fixed
- um80 assembler: A Z80 ALU mnemonic with three or more operands is now an
  error. `ADD A,B,C` assembled as `ADD A` and deleted the remaining operands.

## [0.3.43] - 2026-07-21

### Fixed
- um80 assembler: The two-operand Z80 ALU forms `ADD/ADC/SBC A,<expr>` no
  longer uppercase the immediate expression.
  - um80 uppercased both operands to match register names (`ADD HL,DE`,
    `ADC A,B` and other forms).
  - um80 then used the uppercased copy of the immediate in the expression
    evaluation.
  - Result: `ADD A,'a'` assembled as `ADD A,'A'` (C6 41), and `ADD A,'a'-'A'`
    assembled as `ADD A,0` (C6 00).
  - A tolower routine built on these forms was a no-op, and um80 gave no
    message.
  - Single-operand forms (`SUB 'a'`, `CP 'a'`) and all other mnemonics were
    not affected. For this reason the wrong bytes assembled without any
    message.
  - Register matching remains case-insensitive.
  - A broken lowercase-filename export in the romwbw_emu W8 utility showed
    the fault.

## [0.3.42] - 2026-06-13

A broad M80-compatibility audit. Every fix below was verified against the
genuine MACRO-80 and LINK-80 3.44 binaries that run under cpmemu.

### Fixed
- um80 assembler: Expression operator precedence now matches M80.
  - um80 evaluated the unary operators (NOT, unary minus/plus, HIGH/LOW)
    first. The order gave the unary operators the lowest precedence.
  - The unary operators are now at their correct levels. The expressions
    below now give these values:
    - `-2+3`=1
    - `NOT 1 AND 2`=2
    - `3*-2 AND 0FFH`=0FAH
    - `HIGH 1234H + 1`=13H
    - `-1 GT 1`=0FFFFH
  - um80 also parses `HIGH(1234H)+LOW(5678H)` correctly.
- um80 assembler: A two-character constant places the first character in the
  high byte (`'AB'`=0x4142). Thus `DW 'AB'` writes the bytes `42 41`.
- um80 assembler: `LD A,I` / `LD A,R` now encode `ED 57` / `ED 5F`. Before
  this fix, um80 wrote `LD A,0` in their place.
- um80 assembler: Macro fixes.
  - um80 ignores EXITM inside a false conditional branch (the IF/EXITM/ENDIF
    idiom).
  - A user macro hides a built-in instruction or directive of the same name.
  - um80 no longer corrupts quoted string literals when it substitutes a
    parameter, a LOCAL name or `%`.
  - `IF NUL <param>` works with an omitted argument.
- um80 assembler: REPT/IRP/IRPC fixes.
  - um80 no longer drops a directly nested repeat block.
  - `IRP X,<<1,2>,<3,4>>` repeats twice (not four times). um80 strips one
    bracket level per item.
  - EXITM ends a repeat expansion.
- um80 assembler: `.RADIX` evaluates its operand in decimal regardless of the
  current radix (so `.RADIX 16` works). The radix resets in each pass.
- um80 assembler: um80 reports an unterminated conditional (missing ENDIF). A
  duplicate ELSE for one conditional level is an error.
- um80 assembler: um80 rejects a cross-class redefinition of a symbol. A
  SET/DEFL/ASET symbol and an EQU/label symbol cannot redefine each other
  (multiply defined).
- ul80 linker: A multiply-defined PUBLIC global is now an error. Before, it
  was a warning. The error matches `%Mult. Def. Global` of L80.
- ul80 linker: Reworked segment placement (resolves docs/ISSUES.md #1).
  - ul80 now writes absolute (ASEG) code at its absolute address. Before,
    ul80 rebased the code to the relocatable load address.
  - A module can mix CSEG and ASEG. ul80 now keeps the CSEG relocatable and
    writes the ASEG block at its ORG. Before, ul80 dropped the CSEG with no
    message.
  - A module can contribute only a COMMON block. ul80 no longer counts the
    bytes of that block as program code.
  - The result was verified against LINK-80 3.44.

## [0.3.41] - 2026-06-13

### Fixed
- um80 assembler: um80 no longer corrupts macro calls with the DRI `!`
  multi-statement separator (issue #3).
  - On a macro-call line, `!` is the M80 argument-quote operator, not a
    statement separator. For example, `head FOO,!!CF` passes the name `!CF`, and `!,`
    passes a literal comma.
  - um80 no longer splits such lines on `!`.
  - um80 also keeps escaped commas in a macro argument list within their
    argument (issue #3).
- um80 assembler: `&`-concatenation of a macro parameter is no longer
  case-sensitive (issue #3). Before, a lowercase `&name` that referenced
  parameter `name` left a stray `&` in the output. um80 did not substitute the
  argument.

### Removed
- Removed the out-of-date standalone scripts under `src/` (um80, ul80, ulib80,
  ucref80, ud80, and the `um80_*opcodes`/`um80_relformat` helpers).
  - The scripts were a copy from before the package existed.
  - The copy had drifted months out of sync.
  - The installed tools all run from the `um80/` package (see `pyproject.toml`
    entry points).

## [0.3.40] - 2026-04-09

### Fixed
- um80 assembler: um80 now uses the fill-value operand of `DEFS count,fill`.
  Before, um80 ignored the operand and wrote zero bytes in place of `count`
  bytes of the fill value (issue #2).

## [0.3.39] - 2026-04-09

### Fixed
- ul80 linker: ul80 no longer writes 256 leading null bytes in the ASEG `.COM`
  output when the source has `ASEG` followed by `ORG 0100H` (issue #2).

## [0.3.38] - 2026-04-08

### Added
- um80 assembler: Added the `ASET` directive (an M80-compatible alias for
  `SET`/`DEFL`).

### Fixed
- um80 assembler: An `EQU` with a forward reference incorrectly caused a
  "multiply defined" error in pass 2. The error occurred when the value of the
  symbol changed because um80 resolved the forward reference.

## [0.3.37] - 2026-03-29

### Fixed
- ud80 disassembler: Fixed incorrect bit pattern comments for the DCX and LDAX
  opcodes.
- ux80 translator: Fixed ALU mapping comments that incorrectly described the
  output format.
- ucref80, ux80: Removed the unreachable dead code (try/except around decode
  with errors='replace').

## [0.3.36] - 2026-03-12

### Added
- ul80 linker: Predefined `__BSS_START` and `__BSS_END` symbols.
  - The symbols give the bounds of the COMMON block. The two symbols come in addition
    to the `__END__` symbol that 0.3.16 added.
  - A crt0 that zeroes uninitialized data before it enters `main` needs both
    ends of that block.
  - Before this change, such a crt0 had no way to ask the linker for either
    end.

### Fixed
- um80 assembler: um80 did not recognize an unnamed COMMON block (`COMMON //`,
  whose name is the empty string) as a COMMON block at all.
  - The location-counter getter and setter and the `seg_type` property all
    tested `if self.current_common:`. Python treats `''` as false.
  - Thus um80 assembled a blank COMMON, the form that the BSS of every C
    compiler uses, as though the block had never been opened.
  - um80 counted the bytes against the enclosing segment and labeled the
    bytes with its segment type.
  - The tests are now `is not None`.
- ul80 linker: With `--no-ds-zeros`, ul80 still counted the reserved (DS)
  bytes in the DSEG output size.
  - Thus ul80 wrote space that was only reserved at the end of the data
    segment as zero padding in the output file.
  - The option `--no-ds-zeros` exists to leave out exactly these bytes.
  - ul80 now counts only the initialized bytes (DB/DW).

## [0.3.35] - 2026-03-11

### Fixed
- um80 assembler: um80 no longer threads external references through a linked
  list (a reference chain) that is embedded in the code it writes.
  - Each reference stored the offset of the previous reference in its own two
    bytes. The value 0 was the end-of-chain marker.
  - Such a reference cannot be told apart from a reference at offset 0 of
    a segment. Offset 0 of a segment is an ordinary place for the first
    instruction of a module.
  - The linker stopped at that reference. Every earlier reference in that
    chain kept the raw chain link in place of the resolved address.
  - um80 now writes one CHAIN_EXTERNAL record for each reference.
  - Chains are also keyed by segment type. A chain that starts in one segment
    can no longer run into another segment and patch bytes that belong to the
    other segment.
- ul80 linker: ul80 could relocate a location a second time in Phase 2. This
  happened to a location that ul80 fixed up when it resolved an external
  reference. Then ul80 added the segment base twice. ul80 now records the
  locations that it resolved externally, and ul80 skips these locations.

## [0.3.34] - 2026-01-25

### Fixed
- ul80 linker: ul80 placed a reference from DSEG to a CSEG symbol with the code
  base in place of the data base. An example is an initialized function
  pointer, `int (*f)(int) = &some_function;`.
  - The relocation records carried only the segment type of the target. They
    did not carry the segment type of the referencing segment.
  - Thus ul80 computed the output offset from `code_base` for a location that
    lives at `data_base`.
  - ul80 wrote the patched address into the wrong bytes of the image.
  - ul80 also followed external chains that start in DSEG from the
    wrong buffer offset.
  - Relocation records are now 3-tuples that carry the segment type of the
    referencing segment.

## [0.3.33] - 2026-01-24

### Added
- um80 assembler, ul80 linker: `EQU` accepts an external symbol plus an
  optional offset. A PUBLIC directive can also declare such an alias PUBLIC:

      EXTRN   ROUTINE
      PUBLIC  ROUTINE_ALT
      ROUTINE_ALT EQU ROUTINE+2

  - The assembler writes the uses of the alias as external-plus-offset
    references.
  - The assembler writes an exported alias as `NEWNAME=EXTERNAL+N`.
  - The linker defers these public symbols and resolves them before it links.
  - z88dk libraries use this feature to publish alternate entry points a
    few bytes into an existing routine.
  - README.md and docs/EXTENSIONS.md document the feature. The tests are in
    `tests/test_ext_alias.py`.

## [0.3.32] - 2026-01-08

### Fixed
- ul80 linker: ul80 now places initialized DSEG data at the data base address
  of the module, and not immediately after the code of that module.

  The linker had treated the CSEG and DSEG of each module as one contiguous
  block. The linker copied the whole buffer to `code_base`. As a result, the
  initialized data of a module landed directly on top of whatever the linker
  linked next. In a multi-module link, that is the code of the next module.

  Nothing reported the fault. The link succeeded, ul80 wrote the file, and
  the image was wrong. ul80 corrupted any link of more than one module where
  the modules carry initialized data, with no message. The corruption was
  worse the more modules there were.

  A size difference finally identified the fault. XDOS.SPR of MP/M II is built
  from 19 modules, and nearly all of the modules use DSEG. ul80 produced an
  8960-byte XDOS.SPR, but the XDOS.SPR of DRI is 10112 bytes. The 1152 missing
  bytes were the overlap: data written over code. ul80 never sized the output to
  hold that code.

  Now ul80 writes CSEG bytes to `code_base` and initialized DSEG bytes to
  `data_base`. ul80 sizes the output buffer to cover both segments.
- tests: `tests/test_case_sensitivity.py` expected that symbols are cut to
  eight characters. But `RELWriter` defaults to `truncate_symbols=False` and
  keeps the full name. The expectations were wrong, and the writer was not. No
  behavior changed.

## [0.3.31] - 2026-01-07

### Fixed
- um80 assembler: `EX AF,AF'` no longer absorbs the rest of the line.
  - um80 read the trailing apostrophe as the start of a string literal. This
    happened both when um80 stripped comments and when um80 split operands.
  - Everything after the apostrophe, including the comment and any following
    statement, was absorbed into an unterminated string.
  - An apostrophe directly after an alphanumeric character is now part of the
    register name, and not a quote.
- um80 assembler: um80 did not reset the LOCAL symbol counter between passes.
  - The generated `??NNNN` names then changed from one pass to the next. For
    example, a symbol defined as `??0000` in pass 1 was referenced under a
    different number in pass 2.
  - um80 now resets the counter at the start of each pass-1 iteration and
    again for pass 2. A LOCAL symbol thus keeps one name throughout.

## [0.3.30] - 2026-01-07

### Fixed
- um80 assembler: The `-e`/`--execute` and `--pre` options added in 0.3.29 now
  reach the installed tool.
  - 0.3.29 had added the options only to `src/um80`. `src/um80` is a
    standalone copy of the assembler that nothing runs.
  - The `um80` entry point in pyproject.toml names `um80.um80:main`. Thus an
    installed 0.3.29 still rejected both options as unrecognized arguments.
  - The same code is now in `um80/um80.py`.
  - 0.3.41 removed the out-of-date `src/` copies completely.

## [0.3.29] - 2026-01-07

### Added
- um80 assembler: Two new options.
  - `-e`/`--execute CODE` assembles a line of inline source before the main
    file.
  - `--pre FILE` includes a whole file before the main file.
  - You can repeat both options. um80 processes the options in the order
    given. The option `-e` accepts the DRI `!` statement separator.
  - Use these options to set the CPU mode of a source file, or a
    conditional-assembly symbol, from the command line without a change to
    the file. Example: `um80 -e .z80 file.mac`.
  - Note that in this release the options existed only in the unused
    `src/um80` script (see 0.3.30).

## [0.3.28] - 2026-01-06

### Fixed
- ul80 linker: ul80 now also records the external references that it resolves
  to DSEG and COMMON symbols in the PRL relocation bitmap.
  - 0.3.27 marked only targets in CSEG.
  - As a result, a cross-module pointer into the data segment of another
    module, or into a COMMON block, stayed at its link-time address.
  - The fault occurred when MP/M loaded the .PRL file or .SPR file at any
    other address.

## [0.3.27] - 2026-01-06

### Fixed
- ul80 linker: ul80 now includes in the PRL relocation bitmap the addresses that it
  patches when it resolves an external reference.
  - Before, ul80 built the bitmap only from the relocations that it applied
    from the relocation records of each module.
  - Thus ul80 wrote an EXTRN that resolved to a symbol in another module as a
    link-time address. Every cross-module call or jump is such an EXTRN.
  - MP/M never relocated the address when it loaded the image at its real
    page.
  - A single-module .PRL file was correct. For this reason the fault survived
    as long as it did.

## [0.3.26] - 2026-01-06

### Fixed
- `__version__` now comes from the metadata of the installed package. Before,
  `__version__` was a hardcoded literal in `um80/__init__.py`.
  - Someone had to edit the literal by hand, together with pyproject.toml. The
    edit regularly did not happen.
  - The project yanked both 0.3.12 and 0.3.14 for exactly this reason.
  - Every tool in 0.3.25 reported itself as 0.3.24.
  - There is now one place to change the version.

## [0.3.25] - 2026-01-05

### Fixed
- um80 assembler: `$` evaluated one byte too high in the 8080 instructions
  that take an address operand. These are JMP, the conditional jumps, CALL,
  the conditional calls, LXI, LDA and similar instructions.
  - um80 wrote the opcode byte before it parsed the operand expression.
  - `$` then saw the location counter after the advance past the opcode byte.
    For example, `JNZ $-5H` assembled a target one byte beyond the target that
    the source wrote.
  - um80 now parses the expression first and writes the opcode after.
- um80 assembler: um80 now writes a SET_LOC record for a CSEG/DSEG/ASEG
  directive. The linker thus switches output buffers at the same place as the
  source. Without the record, the linker accumulated the bytes after a segment
  switch into the buffer of the previous segment.
- ul80 linker: ul80 applied the DS zero fill only when the location counter
  advanced within the current segment. Thus ul80 did not fill space that a DS
  directive reserved immediately after a switch to another segment.

### Changed
- ul80 linker: DS directives now write zeros by default. The option
  `--no-ds-zeros` restores the old behavior, which treated reserved space as
  BSS.
  - PRL and SPR images must be contiguous.
  - Space reserved at the end of a segment was absent from the file.
  - The missing space was the reason that these tools could not build MPM.SYS.

## [0.3.24] - 2025-12-31

### Fixed
- um80 assembler: ORG tracking now applies only to ASEG (absolute segment).
  ORG in CSEG/DSEG now correctly only sets the location counter. ORG does not
  affect the segment origin there. The fix repairs `org $-1` patterns in
  relocatable code that broke in 0.3.5.

## [0.3.20] - 2025-12-28

### Changed
- Added a GitHub Actions workflow for automated PyPI publishing with trusted
  publishers.

## [0.3.19] - 2025-12-28

### Fixed
- ul80 linker: PRL/SPR output now defaults to origin 0 and not 0x100. Before,
  the option --prl incorrectly used the CP/M COM default origin. As a result,
  all addresses in SPR files were 0x100 too high.

## [0.3.18] - 2025-12-28

### Fixed
- ul80 linker: ul80 now pads binary output files (.COM and .PRL) to a 128-byte
  CP/M record boundary. The change fixes the problems when MP/M 2 loads .SPR
  files.

## [0.3.17] - 2025-12-21

### Fixed
- ul80 linker: ul80 now manages the segment buffers correctly when the source
  switches between segments (for example, CSEG -> DSEG -> CSEG). Before, a
  return to a segment could overwrite data from other segments. ul80 now uses
  a separate buffer for each segment type.

### Added
- Test suite for DS and ORG directive combinations (`tests/test_ds_org.py`).
  The tests cover segment switches, RST vector layouts, and external
  references.

## [0.3.16] - 2025-12-18

### Added
- ul80 linker: Predefined `__END__` symbol. The symbol points to the first free
  byte after all linked segments (code + data + COMMON blocks). The symbol is
  useful for dynamic memory allocation in CP/M programs.
- Test suite for `__END__` symbol (`tests/test_end_symbol.py`)

### Fixed
- ul80 linker: ul80 now calculates the segment buffer offset correctly for
  external references in absolute-origin code (ORG directive with absolute
  address).

## [0.3.15] - 2024-12-16

### Fixed
- ul80 linker: ul80 now manages the segment buffers so that a SET_LOC to a new
  segment cannot overwrite bytes from earlier segments. When ul80 follows a
  chain, it now correctly uses buffer offsets and not segment-relative
  addresses.

## [0.3.14] - 2024-12-16 [YANKED]

Yanked because the `__version__` update was missing. Use 0.3.15 instead.

## [0.3.13] - 2024-12-14

### Fixed
- Symbol case sensitivity: The REL file reader now uppercases all symbols when
  it reads them. The change matches the behavior of the Microsoft L80. The
  linker is now fully case-insensitive regardless of the source assembler.

### Added
- Test suite for case sensitivity handling (`tests/test_case_sensitivity.py`)

## [0.3.12] - 2024-12-14 [YANKED]

Yanked because the `__version__` update was missing. Use 0.3.13 instead.

## [0.3.11] - 2024-11-26

### Added
- Library (.lib) file support in the ul80 linker

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
- ucref80: Cross-reference program
