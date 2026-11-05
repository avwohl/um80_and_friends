# Debug information

This file is the specification of the debug information of the um80 tools.
Each program that writes or reads the information follows this file.
The programs are um80, ulib80, ul80, the compilers that write markers, and
the debuggers.

The debug information does not change the code. The `.rel` file and the
output file of ul80 are the same, byte for byte, with and without the
options in this file. The tests in `tests/test_debug_info.py` check the byte match.

The `--debug-info` options of um80 and ul80, the `.dbm` files in a ulib80
library, udb80 and dbg2elf are in um80 0.4.0 and later.

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

The kind and the words `nostmt`, `begin`, `end` and `none` can be in upper or
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
| `;#type NAME [key=value ...]` | The definition of a named type (struct, union, enum or typedef). See [Variables](#variables). |
| `;#var NAME TYPE [key=value ...]` | A variable: its type, where it lives and where its name is valid. See [Variables](#variables). |

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
    addresses where IX holds the frame. Give both or none. The range
    includes both addresses. `ixbegin` is the address after `add ix,sp`.
    `ixend` is the address of the last `pop ix` in front of a `ret`. In the
    range, the saved IX is at IX+0 and the return address is at IX+2. Outside
    the range, or with no range, a debugger uses the stack depth at the
    address ([frame_records.md](frame_records.md)). A compiler writes the two
    labels after its last text pass, because a label stops the optimizers.
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

## Variables

A `;#var` marker describes one variable. A `;#type` marker describes one
named type. The compiler writes both after its last text pass, because only
the final text tells where a variable lives.

### Types

A type is a text with no blanks. The grammar:

| Text | Meaning |
|---|---|
| `void` | no value |
| `NAME:SIZE` | a base type with its size in bytes, for example `int:2`, `uchar:1`, `long:4` |
| `*T` | pointer to `T` (2 bytes) |
| `[N]T` | array of `N` elements of `T`. `[]T` has no known size. |
| `func(T)` | function that returns `T` |
| `struct:TAG`, `union:TAG`, `enum:TAG` | a named aggregate or enumeration. An anonymous one has the tag `.N`. |
| `typedef:NAME` | a typedef name |
| `raw:N` | `N` bytes of unknown type |

The base names are `char`, `schar`, `uchar`, `short`, `ushort`, `int`, `uint`,
`long`, `ulong`, `llong`, `ullong`, `bool`, `float`, `double` and `ldouble`. A
name that starts with `u` is unsigned (`bool` too). `char` is signed. The size
comes from the compiler, because the size of `int` depends on its options.
Qualifiers (`const`, `volatile`) are not recorded.

`;#type` has these forms. A tag and a name use letters, digits and `_ . $ ~`.

```
;#type struct:pt size=4 members=x:int:2@0,y:int:2@2
;#type union:u size=2 members=i:int:2@0,c:[2]char:1@0
;#type enum:color size=2 values=RED=0,GREEN=5
;#type typedef:byte target=uchar:1
;#type struct:bits size=2 members=a:uint:2@0#3.0,b:uint:2@0#5.3
```

A member is `NAME:TYPE@OFFSET`. A bit field adds `#WIDTH.SHIFT`: the width in
bits, and the bit of the storage unit at `OFFSET` where the field starts (0 is
the least significant bit). An unknown key is ignored. A second `;#type` with
the same name and a different content gives a warning, and the first one stays.

### The variable marker

```
;#var NAME TYPE [kind=KIND] [LOCATION] [range=LABEL:LABEL ...] [scope=F:A-B] [decl=F:L] [why=TEXT]
```

`NAME` and `TYPE` come first. The other words can be in any order.

- `kind=` is `global`, `static`, `local` or `param`. The default is `global`
  outside a routine, and `local` inside one. A `static` is a file-scope
  `static` object or a `static` local.
- A `;#var` marker between `;#func` and `;#endfunc` belongs to that routine.
  A marker outside a routine belongs to the program.
- `LOCATION` is one of these words. With no location word, or with `none`, the
  value is *not available*.
  - `at=LABEL`, `at=LABEL+N` or `at=LABEL-N`: the variable is at the address of
    a label. A local in the shared automatic area is `at=??AUTO+N`. The
    address is correct while the routine is active, and the compiler shares
    the area only between routines that are never active together.
  - `ix=N`: the variable is at IX+N (N can be negative) in the IX frame of the
    routine. A debugger takes the frame base from the frame records
    ([frame_records.md](frame_records.md)): the base of an IX frame is the stack
    address of the return address minus 2.
  - `reg=R`: the variable is in the register `R` (`A B C D E H L BC DE HL IX IY`
    and the halves of IX and IY).
  - `none`: the variable has no place. `why=TEXT` can say why (no blanks).
- `range=A:B` (repeatable): the variable is valid when `A <= PC < B`. Two
  labels give the addresses. A variable in a register needs the ranges, because a
  register holds the local in part of the routine only. A variable with no
  `range=` is valid in the whole routine.
- `scope=F:A-B`: the name is visible on the lines `A` to `B` of file `F`. A
  local is visible from its declaration to the end of its block.
- `decl=F:L`: the line of the declaration.

The routine, the lines and the ranges together decide when a name stands for
a variable. A debugger looks up a name in the routine that holds the PC and
in the blocks that hold the line. Names in an inner block hide names in an
outer block. The static and global names come last.

The compiler writes `none` and not a guess when it does not know the place. The
reasons that uc80 gives are `no-storage` (no instruction uses the slot: the
optimizer removed the variable), `no-frame` (the IX frame was removed) and
`save-not-paired` (the pushes and pops of the register do not show where the
register holds the variable).

um80 resolves each label of `at=` and `range=` to a segment and an offset. An
`at=` label that the module does not define gives a variable with no location.
um80 writes no warning, because the compiler removes the data of a global that
nothing uses. A `range=` label that is not defined gives a warning.

### Rows in the files

A row of the `vars` table of a `.dbm` file is
`[name, type, kind, location, routine, scope, ranges, decl]` and, when the
variable has a reason, a ninth value `why`.

- `location` is `["at", segment, offset]`, `["ix", N]`, `["reg", "BC"]` or null.
- `routine` is the name of the routine, or null.
- `scope` is `[file, first, last]` or null. `decl` is `[file, line]` or null.
  Both use indexes into `files`.
- `ranges` is null or a list of `[start, end]` positions `[segment, offset]`.

A row of `vars` in `prog.dbg` is
`[name, type, kind, location, routine start, scope, ranges, decl, module]` and
an optional `why`. The location of `at` is `["at", address]`, the routine is
the start address of the routine, and `ranges` are `[start, end]` addresses.
The rows are in the order of the routines, and the order of the compiler
inside a routine.

`types` maps a name to a definition: `{"size": N, "members": [[name, type,
offset] or [name, type, offset, width, shift], ...]}` for a struct or union,
`{"size": N, "values": [[name, value], ...]}` for an enum, and
`{"target": type}` for a typedef.

ul80 merges the types of all modules by name. Two modules that define the
same name with the same content share one definition. Another module can define the
same name with other content. That module gets the name `NAME~1` (then `~2`)
for its own variables and for the types in its own definitions. Two modules
can thus use `struct node` for two different structures.

A link of modules with no `;#var` marker gives a `prog.dbg` with none of the
new keys.

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
| `revision` | The number 2. Present only when the module has `types` or `vars`. |
| `types` | Object: type name to definition. Present only with `revision`. See [Variables](#variables). |
| `vars` | List of variable rows. Present only with `revision`. See [Variables](#variables). |

The `version` stays 1 when a file gets the keys `revision`, `types` and `vars`.
A reader of the first revision checks `format` and `version`, and ignores the
keys that it does not know. A module with no `;#type` and no `;#var` marker
gets none of the three keys, so its file is the same as before.

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
| `revision` | The number 2. Present only when a module has `types` or `vars`. |
| `vars` | List of variable rows, with addresses. Present only with `revision`. |
| `types` | Object: type name to definition, for all modules. Present only with `revision`. |

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

The format has a third level. A `;#line` marker can have `outer=G:M`: the
position at the level below the source, for example the C line under a BASIC
line. The value is in the groups as the two last values. uc80 writes the field
when a `#line` directive is in effect: the position of the marker is the BASIC
line that the directive names, and `outer=` is the line of the C file. The
`.dbm` file and `prog.dbg` carry the value. `udb80` shows the level: see
[udb80.md](udb80.md#the-outer-level).

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
