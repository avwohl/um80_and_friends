# Debug information

This file is the specification of the debug information of the um80 tools.
Each program that writes or reads the information follows this file.
The programs are um80, ulib80, ul80, the compilers that write markers, and
the debuggers.

The debug information does not change the code. The `.rel` file and the
output file of ul80 are the same, byte for byte, with and without the
options in this file. The tests in `tests/test_debug_info.py` check the byte match.

## How the information goes through the tools

```
source.mac  (with ;# marker lines)
    |  um80 --debug-info
    v
source.rel  +  source.dbm      (module debug file, JSON)
    |  ulib80 -c stores source.dbm with the module
    v
ul80 --debug-info reads each .dbm, and relocates it
    v
prog.com  +  prog.dbg          (linked debug file, JSON)
```

The `.rel` file has no debug data. LINK-80 3.44 refuses each new kind of
extension item in a `.rel` file. The debug data is therefore in a separate
file.

## Options

- `um80 --debug-info`: write `NAME.dbm` beside the `.rel` file.
- `ulib80 -c` and `ulib80 -a`: store `NAME.dbm` with a module, when the file
  is beside `NAME.rel`. No option is necessary.
- `ul80 --debug-info`: read the `.dbm` files and write `NAME.dbg` beside the
  output file. `--debug-file FILE` gives another name, and also turns
  `--debug-info` on.
- `.SYM` files do not change.

The option name `-g` of um80 is in use: `-g` makes all labels PUBLIC.

## Markers

A marker is a whole-line comment. The line has these parts, in this order:

1. optional blanks and tabs
2. `;`
3. optional blanks and tabs
4. `#`
5. the kind of the marker, in letters
6. the fields, with blanks between them

A real MACRO-80 assembler reads a marker as a comment. A marker is never
a trailing comment, because the text optimizers can remove a trailing
comment. A marker is not a label, because a label stops the optimizers.

um80 reads a marker only with `--debug-info`, and only in pass 2. um80
does not read a marker in a false conditional. um80 does not read a marker
while um80 collects the body of a macro or of a REPT. A marker in a macro
body takes effect when the macro runs.

The kind and the words `nostmt`, `begin` and `end` can be in upper or
lower case. Paths and names keep their case. A number is decimal digits.

| Marker | Meaning |
|---|---|
| `;#file N "PATH"` | File table entry. `N` is 1 or more. `PATH` is in double quotes. Write `\"` for a quote and `\\` for a backslash. |
| `;#line F L [nostmt] [outer=G:M]` | The bytes that follow come from file `F`, line `L`. |
| `;#inline F L NAME` | The code that follows is `NAME`, inlined at file `F`, line `L`. |
| `;#endinline` | Go back to the position that was current at the last `;#inline`. |
| `;#func NAME F L [key=value ...]` | A routine starts at the next byte. |
| `;#endfunc [NAME]` | The routine ends at the next byte. |
| `;#noopt begin` | The start of a region that no optimizer changes. |
| `;#noopt end` | The end of the region. |

### Fields

`F` is a file number from a `;#file` marker. `F` = 0 means no file. `L` is a line number in the file.

- `;#line`: `F` = 0 clears the position. The next bytes have no source
  line until the next `;#line`.
- `nostmt`: the line is not a step point. Use `nostmt` for code that the
  optimizer moved, for example code that moved out of a loop.
- `outer=G:M`: the position at the next level up. See [Levels](#levels).
  `G` is a file number, and `M` is a line. Readers that do not use levels
  keep the value and do not use it.
- `;#inline`: `NAME` has no blanks. The markers `;#line` that follow
  give the positions inside `NAME`. The call site is the position `F`, `L`.
  Inline calls can contain inline calls.
- `;#func`: `NAME` is the name of the routine. `F` and `L` are the
  declaration. Each `key=value` is one of these:
  - `frame=none`, `frame=ix` or `frame=static`. The default is `none`.
    `ix` means that the routine keeps its frame in IX. `static` means that
    the routine keeps its locals at fixed addresses.
  - `pops=N`. The number of bytes of stack that the routine removes from the
    caller's stack. The default is 0.
  - `ixbegin=LABEL` and `ixend=LABEL`. The two labels give the range of
    addresses where IX holds the frame. Give both or none.
  - um80 ignores other keys.
- `;#endfunc`: `NAME`, when present, must be the name of the open routine.
  The bytes after `;#endfunc` have no source line until the next `;#line`.
- `;#noopt`: the word `begin` or `end`. Regions can contain regions. um80
  only records the region. The optimizers do the work.

A reader ignores the words after the defined fields. A later version
can add words. A line that starts like a marker but has an unknown kind is
a plain comment.

A marker with wrong fields gives a warning, and um80 ignores the marker. A
marker with a file number that no `;#file` defined also gives a warning.
Assembly goes on.

### The merge rule

A marker sets a state, as the GNU assembler `.loc` does. Each byte that
follows has the position of the state, up to the next marker.

Two or more `;#line` markers with no byte between them all belong to the
next instruction or data statement. The row for that statement lists all
the lines, in source order. The last line is the primary line. The next
statement, if no marker comes before it, has only the primary line.

Each line of a group is a statement (a step point), in source order. Only
`nostmt` makes a line not a step point. A debugger that sets a breakpoint
on a line uses each address whose group has that line.

Example, from `tools/dbg2elf_proto/sumto.mac`:

```
;#line 1 15
;#line 1 16
        ld      hl,0
        jp      0
```

`ld hl,0` has the group lines 15 and 16, and line 16 is primary. `jp 0`
has line 16.

## The .dbm file

A `.dbm` file is JSON. The top level is one object. Each row of the tables
`rows` and `labels` is on one line, in the file. The tables use arrays and not
objects, because a big program gives a small file.

| Key | Value |
|---|---|
| `format` | The text `um80-dbm`. |
| `version` | The number 1. A reader that does not know the version ignores the file. |
| `module` | The module name that the `.rel` file has. |
| `source` | The path of the main source file, as given on the command line. |
| `rel` | `{"length": N, "sha256": "HEX"}` for the `.rel` file. ul80 refuses a `.dbm` that does not match the `.rel`. |
| `files` | List of paths. All file indexes in the file are indexes into this list, from 0. |
| `rows` | See below. |
| `labels` | List of `[name, segment, offset, file, line]`. |
| `funcs` | List of routine objects, see below. |
| `noopt` | List of `[start, end]`. Each is a position `[segment, offset, run]`. |

The list `files` has the main source file, the INCLUDE files, and the
files of the `;#file` markers. A `;#file` path that is the same as an
earlier path has the same index.

### Segment names

- `ASEG`, `CSEG`, `DSEG`: the segments. The offset in `ASEG` is the absolute
  address.
- `COMMON:NAME`: a COMMON block. A block with no name has a blank as its
  name.
- `ABS`: used for labels only. The value is an absolute address. The label
  of an ASEG location or of a `.PHASE` block has this segment.

### Rows

um80 writes one row for each instruction and for each data statement, in
pass 2 only, in source order. A row is an array. A row can end early: the
columns that are missing are null.

| Column | Name | Meaning |
|---|---|---|
| 0 | segment | Segment name. |
| 1 | offset | The load offset in the segment. |
| 2 | length | The number of bytes, or the size of the space for kind `s`. |
| 3 | run | The run address, or null. um80 gives a value only inside a `.PHASE` block. Without `.PHASE` the run address is the load address. |
| 4 | file | Index of the `.mac` file in `files`. |
| 5 | line | The physical line in that file. |
| 6 | kind | `i` for an instruction, `d` for data (`DB`, `DW`, `DS` with a fill), `s` for a `DS` with no fill. |
| 7 | src | The position group. See below. |
| 8 | inline | The inline stack. See below. |
| 9 | body file | Index of the file of the macro body line, or null. |
| 10 | body line | The line of the macro body, or null. |

A line in a macro expansion, a REPT, an IRP or an IRPC has the line of the
call or of the REPT as `line`. A line from a macro also has the macro
body line in columns 9 and 10. A REPT body has no body line.

A DS with no fill makes no bytes. Its row has kind `s`, and the length is
the size of the space. A line with a label only has no row.

Column 7, `src`, has three states:

- null: no marker came since the previous row. The position is the primary
  line of the previous row.
- `[]`: no source position. A `;#line 0 0` marker or a `;#endfunc` marker
  came before the row.
- a list of groups. Each group is `[file, line, nostmt]`. `file` is an index
  into `files`, and `nostmt` is 0 or 1. A group with an outer position has
  two more values, `[file, line, nostmt, outer file, outer line]`. The
  groups are in source order, and the last group is the primary line.

Column 8, `inline`, is null when the stack did not change since the
previous row. Otherwise the column is the stack, outermost first. Each
entry is `[name, file, line]`, with the call site. An empty list means
no inline call.

### Labels

A label is every name that a label definition makes, global or local. A
label does not need PUBLIC. A symbol that is an EQU or a SET is not a
label. The `offset` and the `segment` are the ones of the label, as
defined in pass 2.

### Routines

Each object in `funcs` has these keys:

- `name`, `file` (an index or null), `line`, `frame` and `pops`
- `start` and `end`, each `[segment, offset, run]`. `end` is null when the
  routine has no `;#endfunc`.
- `ix`: null, or two positions `[segment, offset]`

## The ulib80 container, version 2

The `ULIB` header has a version. Version 1 has no debug data. Version 2
adds one field to each module entry: the size of the `.dbm`, in 4 bytes. A
size of 0 means that the module has no `.dbm`. The bytes of the `.dbm`
follow the bytes of its module in the data area.

ulib80 writes version 2 only when a module has a `.dbm`. A library with no
`.dbm` is a version 1 file, the same as before. ul80 reads both versions.

The `.dbm` belongs to the stored module name, not to the name of the `.rel`
file. A `.rel` file of one module takes the `.dbm` beside the file. A
`.rel` file of several modules gives the `.dbm` to the module that has the
name in the `module` key. ulib80 refuses a `.dbm` that does not match its
`.rel` file, and says so.

`ulib80 -x` writes `NAME.dbm` beside `NAME.rel`, and `ulib80 -l` shows the
size of the debug data. A library in LINK-80 form has no debug data. The
modules that ul80 takes from such a library get labels only.

## The prog.dbg file

ul80 writes `prog.dbg` beside the output file, or in the file of
`--debug-file`. The file is JSON. The tables `lines`, `asm`, `labels`,
`moved` and `noopt` have one row on each line.

| Key | Value |
|---|---|
| `format` | The text `um80-dbg`. |
| `version` | The number 1. |
| `producer` | The name and the version of the program that wrote the file. |
| `image` | The output file. See [The image check](#the-image-check). |
| `files` | List of paths, for all modules. All file indexes in the file are indexes into this list, from 0. |
| `modules` | List of `{"name", "source", "debug"}`, in link order. `debug` is false for a module with no `.dbm`. |
| `lines` | The source line table. |
| `asm` | The assembler line table. |
| `labels` | List of `[name, address, module, global]`. `module` is an index into `modules`. `global` is 1 for a PUBLIC name. With `-t` the linker compares the name with the shortened PUBLIC names, so a PUBLIC name longer than 6 characters has `global` 0. |
| `funcs` | List of routine objects. |
| `noopt` | List of `[start, end]` addresses. |
| `moved` | List of `[run, load, length]`. See below. |
| `dropped_rows` | The number of rows that ul80 dropped. |

All addresses are run addresses, as the program sees the addresses. Each
table is in address order. A range `[start, end]` includes `start` and does
not include `end`.

A label has the address that ul80 gives the same name in the `.SYM`
file. The `.SYM` file has only the PUBLIC names, and the `labels` table
has all labels.

### The source line table

`lines` has the rows `[start, end, groups]` or `[start, end, groups, inline]`.
`groups` is a list of `[file, line, nostmt]` in source order, or
`[file, line, nostmt, outer file, outer line]`. The last group is the
primary line. `inline` is a list of `[name, file, line]`, outermost first,
and is absent when no inline call is open.

An entry starts at an instruction (or data statement) that has markers
before it. The entry goes on over the next instructions that have no
marker before them. A DS, or a data statement with no marker, ends the entry
and starts none. Bytes with no position have no entry.

The groups of an entry are the groups of its first instruction, by the
merge rule above. Each group is a step point, unless `nostmt` is 1.

### The assembler line table

`asm` has one row for each instruction and each data statement:
`[start, end, kind, file, line]` and, for a macro line, two more values:
the file and the line of the macro body. `kind` is `i`, `d` or `s`.
Every instruction of every module that has a `.dbm` has a row, with the
`.mac` line, even when the module has no markers.

### Routines and regions

A routine has `name`, `module`, `file`, `line`, `frame`, `pops`, `start`,
`end` (null when unknown) and `ix` (null, or `[begin, end]` as addresses).

### Rows that ul80 drops

When two modules write the same byte (`--allow-overlap`, or a shared COMMON
block), the later module owns the byte, as in the image. ul80 drops a row
of the earlier module when a later module owns one of its bytes. The
number of such rows is in `dropped_rows`. A row for a DS with no fill is
never dropped.

### Run address and load address

With `.PHASE`, the code has one load address and a different run address.
With `--rom-data`, the initial bytes of DSEG are in the image after the
code, and run in RAM. The debugger uses the run address.

The `moved` table
has `[run, load, length]` for each range where the load address in the
image is not the run address. The table has no entry for a range
that is not moved. A DS range in DSEG is in the table: the image holds its
zero bytes after the code.

### Levels

Each byte has an assembler position (the `.mac` file and line) from the
`asm` table. A byte that has markers also has a source position, from the
`lines` table. A debugger shows the source by default, and can show the
assembler.

The format has room for a third level. A `;#line` marker can have `outer=G:M`: the
position in a language above the source, for example the BASIC line that
made a C line. The value is in the groups as the two last values. The
compilers do not write this field now.

### The image check

`image` is an object that describes the output file, as ul80 wrote the
file. ul80 reads the file back after it writes the file.

| Key | Value |
|---|---|
| `file` | The file name, with no directory. |
| `kind` | `com`, `bin`, `hex`, `prl` or `spr`. |
| `length` | The length of the file in bytes, with the padding that CP/M needs (a multiple of 128 bytes for `com`). |
| `sha256` | The SHA-256 of the file, in 64 hex digits. |
| `load` | The address of the first byte of the image, or null for `hex`. |
| `offset` | The place of that byte in the file, or null for `hex`. |
| `model` | `cpm` for `com`, and `flat` for the other kinds. |

A debugger checks `length` and `sha256` against the program it debugs. It
compares the first `length` bytes of memory from `load`. A `.dbg` file that does
not match is stale: the debugger refuses it. The check is for the build. The
debugger does not look at memory again after the program starts.
