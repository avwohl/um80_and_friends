# GDB for Z80 programs

GDB can debug a Z80 program at the source level. GDB shows C lines, sets breakpoints on lines, steps by line, steps into inlined calls and shows a backtrace. The work is phase 7 of the [debugger plan](https://github.com/avwohl/cpmemu/blob/main/docs/debugger_plan.md) of the cpmemu project.

Four parts work together:

- `ul80 --debug-info` writes `prog.dbg`. The format is in [debug_info.md](debug_info.md).
- `dbg2elf` reads `prog.dbg` and the program. `dbg2elf` writes `prog.elf`, an ELF file with DWARF line and routine data.
- `cpmemu --gdb` runs the program and speaks the GDB remote protocol. The cpmemu file `docs/gdb_stub.md` describes the stub.
- A GDB Python script, `udb80_unwind.py`, unwinds the Z80 stack for `bt`, `up`, `finish` and `next`.

The program keeps all of its 64K. GDB keeps the symbols and the source files on the host.

## Build GDB 18.1 for the Z80

GDB has had a Z80 target since GDB 11.1. Most packages do not build the target. Homebrew has no formula. Build GDB from source.

The commands below built GDB 18.1 on macOS 27 (arm64) in about one minute. GDB 18.1 needs GMP and MPFR. The build used Homebrew packages for both.

```
curl -O https://ftp.gnu.org/gnu/gdb/gdb-18.1.tar.xz
curl -O https://ftp.gnu.org/gnu/gdb/gdb-18.1.tar.xz.sig
gpg --verify gdb-18.1.tar.xz.sig gdb-18.1.tar.xz
tar xf gdb-18.1.tar.xz
mkdir build && cd build
../gdb-18.1/configure --target=z80-unknown-elf --disable-nls --disable-werror \
    --with-python=/opt/homebrew/bin/python3.14 --with-gmp=/opt/homebrew \
    --with-mpfr=/opt/homebrew --without-guile --disable-sim
make -j10 all-gdb
```

The build on Linux was not measured. Keep `--with-python`, because the unwinder needs the Python support of GDB.

Run `build/gdb/gdb`. Give GDB its data directory when you run GDB from the build folder:

```
build/gdb/gdb --data-directory=build/gdb/data-directory
```

The tests in `tests/test_gdb.py` do this by themselves: they pass `--data-directory` when a folder `data-directory` stands next to the GDB program. Set `UDB80_GDB` to the path of the GDB program.

Check the build. The command `set architecture` lists z80, z80-strict, z80-full, r800, gbz80, z180, z80n, ez80-z80 and ez80-adl. The command `python print(1)` prints 1.

## Make the ELF file

Build the program with `--debug-info` in both tools. Then run `dbg2elf`:

```
um80 --debug-info -o prog.rel prog.mac
ul80 --debug-info -o prog.com prog.rel
dbg2elf prog.dbg
```

`dbg2elf` writes `prog.elf` beside `prog.dbg`. The program file is the file that `prog.dbg` names. `dbg2elf` checks the length and the SHA-256 of the program file, as udb80 does. A stale `prog.dbg` gives an error and no ELF file.

```
dbg2elf prog.dbg [prog.com] [-o prog.elf] [--comp-dir DIR] [--asm-lines MODE]
        [--keep-underscore] [--keep-case] [--no-variables] [--ix-locals fbreg|off]
        [--language c|asm]
dbg2elf --unwinder-path
dbg2elf --vars-path
```

- `--comp-dir DIR`: the folder that relative source paths start from. The default is the folder of `prog.dbg`. The compilers write paths relative to the folder where you ran them.
- `--asm-lines auto|always|never`: write the lines of the `.mac` files. `auto` writes the lines only when `prog.dbg` has no source lines, so an assembler program has lines. `always` adds the lines of the `.mac` files for bytes with no source line. A step then goes into the runtime. `never` writes none.
- `--keep-underscore`: keep the leading underscore of a C name. Without the option, `dbg2elf` removes the underscore, and GDB sees `main` for `_main`.
- `--keep-case`: um80 writes every label in upper case. Without the option, `dbg2elf` writes a label with no lower case letter in lower case. A name from a `;#func` marker keeps its case.
- `--no-variables`: write no variables and no types.
- `--ix-locals fbreg|off`: `fbreg` (the default) writes the variables at IX+N with `DW_OP_fbreg`. `off` writes no record for them. See [Variables](#variables).
- `--vars-path`: print the path of `udb80_vars.py`, the GDB commands for the variables.
- `--unwinder-path`: print the path of `udb80_unwind.py`.

### What the ELF file holds

The ELF file is ELFCLASS32, little endian, `e_machine` 220 (EM_Z80) and `e_flags` 1 (EF_Z80_MACH_Z80). GDB sets the z80 architecture from the file.

- `.text` and one `PT_LOAD` segment hold the program at its load address (0100H for a `.COM` file).
- `.symtab` has a `STT_FUNC` symbol with a size for each routine and a `STT_OBJECT` symbol for each data label. The other labels have the type `STT_NOTYPE`. A label in a routine that has a `;#func` marker is not a symbol, except a PUBLIC label.
- `.debug_line` is DWARF 4 with address size 2. Rule D4 of the plan decides the rows. Each line of a merged group is a row at the same address, in source order. The last line is primary. Only a `nostmt` row has `is_stmt` off. A gap between two entries of `prog.dbg` ends the sequence.
- `.debug_info` has one compile unit. The unit has these records:
  - one `DW_TAG_subprogram` with `low_pc` and `high_pc` for each routine
  - one `DW_TAG_inlined_subroutine` for each inline record
  - the types, variables and parameters of the `vars` and `types` tables, if `prog.dbg` has them: see [Variables](#variables)
  - one `DW_TAG_variable` with `DW_OP_addr` for each data label, if `prog.dbg` has no `vars` table
- `.debug_abbrev` and `.debug_str` complete the DWARF data.

The program has one compile unit. The name of the unit is the file of the first routine.

### Routines

A routine is a `;#func` record of `prog.dbg`. A program without `;#func` markers has no records. In that case `dbg2elf` takes each label that starts with an underscore (`_name`, not `__name`) or is PUBLIC and has an instruction. The routine ends at the next routine or at the first data row.

### Variables

A `prog.dbg` from a compiler that writes `;#var` markers (`uc80 -g`) has the tables `types` and `vars`: see [debug_info.md](debug_info.md#variables). `dbg2elf` writes them as DWARF:

- A type becomes `DW_TAG_base_type`, `DW_TAG_pointer_type`, `DW_TAG_array_type` with `DW_TAG_subrange_type`, `DW_TAG_structure_type` or `DW_TAG_union_type` with `DW_TAG_member` (a bit field has `DW_AT_bit_size` and `DW_AT_data_bit_offset`), `DW_TAG_enumeration_type` with `DW_TAG_enumerator`, `DW_TAG_typedef` or `DW_TAG_subroutine_type`.
- A variable with a fixed address (a global, a static, a local in the shared area `??AUTO`) becomes a `DW_TAG_variable` with `DW_OP_addr`. A local goes inside its `DW_TAG_subprogram`. A local in an inner block goes inside a `DW_TAG_lexical_block` with the address range of the lines of the block. A parameter becomes a `DW_TAG_formal_parameter`.
- A variable at IX+N becomes a `DW_TAG_variable` or `DW_TAG_formal_parameter` with `DW_OP_fbreg`, and the routine gets `DW_AT_frame_base` `DW_OP_call_frame_cfa`. The offset is N - 4 - pops. The unwinder gives each frame the stack address after the return address as its id, and GDB uses this address as the call frame address. The address is IX+4.
- A variable in a register, and a variable with no place, get no record.

What GDB 18.1 does with the z80 target, measured (`tests/test_variables.py`):

- `DW_OP_addr` works. `print g`, `print gp.y`, `print ga[2]`, `ptype struct pt`, `whatis` and `print leaf::cnt` give the right values.
- `DW_OP_fbreg` with `DW_OP_call_frame_cfa` works **when `udb80_unwind.py` is loaded**. `info locals`, `info args`, `print *p` and `up` then show the values of IX variables, also in the callers. Without the unwinder, the z80 unwinder of GDB makes the frames. In a measured session `bt` then showed 20 frames, most of them garbage, and `print arr` gave `{0, 0}`.
- A register does not work: the z80 port has no DWARF register numbers, and a register holds a local in part of the routine only. `dbg2elf` writes no record, and GDB does not know the name.

The GDB commands in `um80/gdb/udb80_vars.py` fill the gap. The commands read `prog.dbg` (the same lookup as the unwinder) and use the code of `udb80` (`um80/vardata.py`):

```
(gdb) source /path/to/um80/gdb/udb80_unwind.py
(gdb) source /path/to/um80/gdb/udb80_vars.py
(gdb) zlocals          # the locals of the selected frame, with the register locals
(gdb) zargs            # the arguments
(gdb) zprint arr[1]    # name, *p, p->m, s.m, a[i], &x, + and -
(gdb) zptype p         # the type of an expression, or struct TAG
```

A register local shows only in frame 0 and only inside its PC ranges. Elsewhere the commands show `<not available>`. `udb80-vars-dbg FILE` chooses the `prog.dbg` file. The IX base of a frame is the stack pointer of the next outer frame minus 4 minus `pops`.

The values of a routine that the optimizer changed can be stale: see [udb80.md](udb80.md#which-variables-a-frame-has). Use `--optnone` for the routine that you debug.

### Inlined calls

A line entry of `prog.dbg` with an inline stack gives one `DW_TAG_inlined_subroutine` for each name on the stack. Neighbour entries with the same call site give one record. Each name also gets an abstract `DW_TAG_subprogram`, so GDB shows the name. The record has `call_file` and `call_line` of the call site.

The marker `;#endinline` puts the call line back as the position. When more lines follow at the same address, `dbg2elf` does not write the call line as a row. Without the rule, `break` on the call line also stops after the inlined body.

## Start a session

Start cpmemu in one terminal and GDB in another:

```
cpmemu --gdb prog.com
gdb prog.elf
(gdb) source /path/to/um80/gdb/udb80_unwind.py
(gdb) target remote :1234
(gdb) break prog.c:14
(gdb) continue
```

GDB reads the architecture from `prog.elf`. The stub answers `Z0`. GDB therefore does not write into guest memory and needs no `_break_handler` symbol. GDB still prints a warning about `_break_handler` when GDB connects. Ignore the warning.

A session on the `sumto` test program (`tools/dbg2elf_proto/sumto.mac`), measured with GDB 18.1:

```
Breakpoint 1 at 0x108: file sumto.c, line 14.
Breakpoint 1, main () at sumto.c:14
add () at sumto.c:6
#0  add () at sumto.c:6
#1  0x00000111 in main () at sumto.c:14
Breakpoint 2, main () at sumto.c:16
$1 = 10
[Inferior 1 (Remote target) exited normally]
```

`Breakpoint 2` was set on line 15. Lines 15 and 16 have the same code, and the last line of the group is the line that GDB shows.

The stub does not report a breakpoint on the first instruction (0100H) at the first `continue`. GDB stops there at the start. Use `step` or `next` from the start.

### Inlined calls in GDB

This C program has an inlined call on line 13. `uc80 -g` inlined `sq`:

```
13    r = sq(r);
```

A session with GDB 18.1, measured:

```
Breakpoint 1, main () at inl2.c:12
13	    r = sq(r);
#0  main () at inl2.c:13
sq () at inl2.c:3
#0  sq () at inl2.c:3
#1  main () at inl2.c:13
main () at inl2.c:14
```

- `step` from line 12 stops on line 13 in `main`. GDB hides the inline frame at the first address of the inlined code.
- The second `step` goes into `sq`. `bt` shows the inline frame `sq` above `main`.
- `finish` leaves the inline frame and stops in `main` on line 14.
- `break inl2.c:13` stops in `sq` and `bt` shows both frames. The first address of line 13 belongs to the inlined body. GDB shows the innermost frame at a breakpoint set by line.

## The Python unwinder

GDB has a Z80 unwinder for SDCC prologues only. The script `um80/gdb/udb80_unwind.py` adds an unwinder for the programs of this tool family. Load the script with a `source` line, or put the line in `.gdbinit`:

```
source /path/to/um80/gdb/udb80_unwind.py
```

`dbg2elf --unwinder-path` prints the path. For each frame the unwinder uses the first source of these two that works:

1. **The shadow call stack of the stub.** The unwinder runs `monitor bt` once after each resume. The stub lists the return address of each call that has not returned. The stub does not give the address of the return address on the stack. The unwinder looks for each return address in memory, from the stack address of the frame below, upward.
2. **The frame records of `prog.dbg`.** The unwinder uses `um80/frames.py`, as `udb80` does. [frame_records.md](frame_records.md) has the rules. Between `ixbegin` and `ixend` of a routine with `frame=ix`, the saved IX is at IX+0 and the return address is at IX+2. Elsewhere the return address is at SP plus the bytes that the routine has pushed. The unwinder finds that number by a walk over the code of the routine. The unwinder checks that the word follows a CALL instruction. If the check fails, or if the number is not known, the unwinder searches the stack for a word that follows a CALL. The unwinder marks such a frame as `guess`.

When neither source works, GDB uses its own unwinder.

GDB asks its inline unwinder before the Python unwinders. Thus the Python unwinder gets real frames only. An inlined call is an inline frame of GDB, with the call site of `DW_TAG_inlined_subroutine`.

The frame id of a frame is the stack address after the return and the first address of the routine. Both stay the same while the routine runs, so `finish`, `next` and `up` work.

### Where the unwinder finds `prog.dbg`

1. The command `udb80-dbg FILE`.
2. The environment variable `UDB80_DBG`.
3. The program file of GDB with the extension `.dbg` (`prog.elf` gives `prog.dbg`).

The unwinder works without `prog.dbg` when the stub has a shadow call stack.

### Commands

- `udb80-unwind-info`: show the last 50 frames the unwinder handled, each with the source `shadow`, `frame` or `guess`.
- `udb80-unwind-mode auto|records`: `auto` uses the shadow call stack first. `records` uses only the frame records of `prog.dbg`. Use `records` with a target that has no shadow call stack, and to compare the two sources.
- `udb80-dbg FILE`: choose the `prog.dbg` file.

### Measured behavior

A test stops a recursive C program (5 calls of `sum`, 4 calls of `fill` with an IX frame) at the base case. The `bt` of GDB shows 5 `sum` frames and `main`, and 4 `fill` frames and `main`. The return address of each frame equals the entry of `monitor bt` with the same number. The two sources give the same `bt` at each instruction of the prologue of `fill`, of the epilogue of `fill` and of `sum`. The same test runs for a `uc80 -g` program, where `uc80` writes `ixbegin` and `ixend`.

## The tests

`tests/test_dbg2elf.py` parses the ELF file with a reader written for the tests (`tests/elfread.py`) and checks the structure, the line rows and the DIE tree. These tests need no GDB.

`tests/test_variables.py` has the format tests (no tools), the tests of the expression code on a fake memory, the live tests of `udb80` (`uc80 -g`, `cpmemu --gdb`), the DWARF tests and the GDB tests for the variables.

`tests/test_gdb.py` runs GDB against `cpmemu --gdb`. The tests find GDB in the environment variable `UDB80_GDB`, then `z80-unknown-elf-gdb` and `gdb` on the PATH. The tests find cpmemu as `tests/test_udb80.py` does. A test skips with a reason when a tool is missing. These variables turn the skip into a failure:

- `UDB80_REQUIRE_GDB=1`
- `UDB80_REQUIRE_CPMEMU=1`
- `UDB80_REQUIRE_UC80=1` (the tests that compile a C program with `uc80 -g`)

CI cannot build GDB in each run. Set `UDB80_REQUIRE_GDB=1` on a job that has a Z80 GDB, so that a missing GDB fails the job.

## Limits

- The ELF file has one compile unit. A function from a header file has the right lines and file, and the same unit.
- Two inlined calls of the same name at the same call line, next to each other, give one inlined record. `prog.dbg` does not keep the end of the first call.
- `print` of a variable in a register needs the helper commands (`zprint`). `print` of an IX variable needs `udb80_unwind.py`.
- A `bool` or a float has a base type with the right size, and GDB cannot decode the float formats of uc80.
- `dbg2elf` reads `com` and `bin` images. A `hex`, `prl` or `spr` image gives an error. The `moved` table of `prog.dbg` (`--rom-data`) is not used.
- The unwinder reads the stack from the stack address of the innermost frame. The unwinder looks at most 16K upward for a return address.
- The shadow call stack hides a frame for a tail call (`jp`), as the stub documentation says.
- `catch syscall` does not work on a Z80 in GDB 18.1.
