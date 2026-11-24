# udb80: the debugger

udb80 is a debugger for 8080 and Z80 programs that run in `cpmemu`. udb80
shows source lines, sets breakpoints on source lines, steps by line and shows
the backtrace. udb80 is phase 3 of the debugger plan in the
[cpmemu project](https://github.com/avwohl/cpmemu/blob/main/docs/debugger_plan.md).

udb80 is in package um80 0.4.0 and later. An older release has no udb80.
Install um80 from PyPI:

```
pip install "um80>=0.4.0"
```

udb80 needs two things:

- A `prog.dbg` file. Link the program with `ul80 --debug-info`. The format
  is in [debug_info.md](debug_info.md).
- A cpmemu that has the `--gdb` option: cpmemu 4.11.0 or later, or
  romwbw_emu 1.50 or later with `--wait-program`. udb80 uses the GDB remote
  protocol to talk to the GDB stub in cpmemu. The program keeps all of its
  64K, because udb80 keeps the symbols and the source files on the host.

## Build a program for udb80

```
um80 --debug-info -o prog.rel prog.mac
ul80 --debug-info -o prog.com prog.rel
```

Then `prog.dbg` is in the same directory as `prog.com`. A program with no
`;#line` markers has assembler lines only. udb80 then uses the lines of the
`.mac` file.

## Start

```
udb80 prog.dbg --run 'cpmemu prog.com'
udb80 prog.dbg --connect 127.0.0.1:1234
```

`--run` starts cpmemu. udb80 adds `--gdb=0` and `--gdb-port-file` to the
command, and reads the port that cpmemu chooses. `--connect` uses a cpmemu
that already runs (`cpmemu --gdb prog.com`). The program stops before the
instruction at 0100H.

Options:

- `-ex COMMAND`: run a command. You can give the option more than once.
- `-x FILE`, `--command FILE`: run the commands in FILE. A line that
  starts with `#` is a comment.
- `--batch`: run the commands, end the program and quit. Without
  `--batch`, udb80 reads more commands from the keyboard.
- `--program FILE`: the program file for the image check.
- `--wait-program`: for romwbw_emu, where CP/M and not the stub starts the
  program. udb80 asks the stub to stop when the program image of prog.dbg is
  at 0100H in bank 8EH. Then udb80 starts the session. udb80 0.4.2 and later
  accept the stop as `T05` or as `T05swbreak`, at the load address only.
  udb80 0.4.1 refuses the stop `T05`, which a stub from after 2026-11-05
  sends. Use udb80 0.4.2 or later with a newer stub.
- `-d DIR`, `--directory DIR`: a directory that holds source files.
- `--asm`: start at the assembler level. `--8080`: disassemble as 8080.

In `--batch` mode the exit status is 1 if a command gave an error.

## The image check

`prog.dbg` holds the length and the SHA-256 of `prog.com`. udb80 refuses a
`prog.dbg` that does not match the program, because a `prog.dbg` from an
older build shows wrong lines. udb80 does two checks:

- The `.com` file in the same directory as `prog.dbg`.
- The first `length` bytes of emulated memory at 0100H.

udb80 does not check memory again after the program starts.

## Commands

You can use a short form of a command name when only one command has
that start (`b`, `c`, `s`, `n`, `bt`, `p`, `l`).

A location has one of three forms:

- `FILE:LINE`. `FILE` can be the base name of the file.
- A routine name or a label.
- `*ADDRESS`.

A line can have more than one address, for example when the compiler copied a
loop test. `break` sets a breakpoint at each address. A `nostmt` line takes no
breakpoint. When a line has no code, `break` uses the next line that has code
and says so.

- `break LOCATION`, `tbreak LOCATION`: set a breakpoint, or a breakpoint
  that is removed after the first stop. `break` with no argument uses the
  current address.
- `delete [N...]`: delete breakpoints. `info breakpoints` lists the
  breakpoints.
- `continue`: run until a breakpoint, the end of the program, or ^C.
- `step [N]`: run to the next source line and enter a call.
- `next [N]`: the same as `step`, but run over a call.
- `stepi [N]`: run one instruction.
- `finish`: run until the current routine returns.
- `backtrace [shadow|frame] [N]` (`bt`): show the frames.
- `list [LOCATION]`, `list FIRST,LAST`: show source lines.
- `disassemble [START,END | START,+LENGTH | LOCATION]`: show instructions.
  The default is the routine that holds the current address. A `=>`
  marks the current address.
- `info registers [NAME...]`: show the registers and the flags.
- `info symbols [PATTERN | ADDRESS]`: list the labels, or name the label
  of an address.
- `info line [LOCATION]`: show the address range of a line.
- `x/NFU ADDRESS`: show memory. N is a count. F is `x`, `d`, `u`, `c`,
  `s` or `i`. U is `b` (1 byte, the default), `h` (2 bytes) or `w` (4 bytes).
- `print[/F] EXPRESSION`: show a value. See [Print](#print) and
  [Variables](#variables).
- `info locals`, `info args`: show the variables of the selected frame. See
  [Variables](#variables).
- `frame [N]` (`f`), `up [N]`, `down [N]`: select a frame. See
  [Variables](#variables).
- `ptype`, `whatis`: show a type. See [Variables](#variables).
- `sizes`: show the bytes of each routine.
- `monitor COMMAND`: send a command to the stub (`monitor bt`).
- `set level auto|src|asm|outer|both`: set the level. See
  [The outer level](#the-outer-level).
- `set cpu z80|8080`.
- `set shadow on|off`.
- `kill`, `quit`, `echo TEXT`, `help`.

A breakpoint at 0100H stops the program at the first `continue`. The stub
does not report a breakpoint at the address where the program waits, and
udb80 reports the breakpoint itself.

### How step works

A source line is a range of addresses in the `lines` table of
`prog.dbg`. `step` runs the range with one range-step packet (`vCont;r`).
The stub does the work, so one round trip covers the line.

When the program leaves the range, `step` stops if the new address is the
start of a line that is a step point. A `nostmt` line is not a step point.
`step` continues to run through the `nostmt` line. When the new address is in
the middle of a line, `step` runs to the end of that line. The test uses
address ranges and not line numbers, so a loop on one line stops after one
pass.

When a program has no `;#line` markers, `step` uses the assembler lines
(`set level asm` forces the assembler lines). When a program has markers,
`step` does not enter code that has no source line, for example a library.
`step` runs over a call to such code.

### How next and finish work

When the range step leaves through a CALL, `next` puts a temporary
breakpoint at the return address and runs. The breakpoint counts only when
the shadow call stack is as short as it was before the call. A deeper
return to the same address does not count, so recursion works. A user
breakpoint in the called routine stops `next` first.

`next` and `finish` also put a temporary breakpoint on the return address
of each caller above. A routine can remove its return addresses (a longjmp,
or POP POP RET) and return to a caller. Then the shadow call stack is
shorter than at the start, and `next` or `finish` stops in that caller.

`finish` does the same with the return address of the current frame.

When the stub has no shadow call stack (`set shadow off` gives the same
behavior), `next` uses the stack pointer. An instruction is a call when the
word on top of the stack is the address after the instruction. The return
counts when SP is at least 2 above SP at the call. `finish` needs the shadow
stack.

### Backtrace

`backtrace` has two unwind methods. The first method is the shadow call stack
of the stub (`monitor bt`). The list has the current address and the return
addresses, innermost first. The second method is the frame records of
`prog.dbg`. The second method needs only the registers and the memory, so the
method works with a stub that has no shadow call stack.
[frame_records.md](frame_records.md) has the rules.

`backtrace` uses the shadow call stack when the stub has one. Otherwise
`backtrace` uses the frame records. The line of a return address is the line
of the CALL before it. Each frame has a tag:

- `[shadow]`: the frame comes from the shadow call stack.
- `[frame]`: the frame comes from the frame records. The IX range or the stack
  depth of the routine gave the return address.
- `[guess]`: udb80 could not find the return address from the records.
  udb80 scanned the stack for a word that follows a CALL instruction in
  the program. The frame can be wrong.

You can choose the method: `backtrace shadow` and `backtrace frame`. A count
can follow (`backtrace frame 3`). `set shadow off` makes `backtrace`, `next`
and `finish` act as with a stub that has no shadow call stack.

```
#0  BOTTOM () at rec.mac:9  [shadow]
#1  0x010e in REC () at rec.mac:7  [shadow]
#2  0x010e in REC () at rec.mac:7  [shadow]
#3  0x0105 in START () at rec.mac:3  [shadow]
```

A routine name comes from a `;#func` record. Without records, the name is
the nearest label below the address. When the program has global labels,
udb80 uses only the global labels.

### Print

`print` takes these items:

- Numbers (`10`, `0x0A`, `0AH`).
- Registers (`$pc`, `$sp`, `$hl`, `$a`).
- Labels.
- The operators `+`, `-`, `&` (address of a label) and `*` (the word at an
  address).

A label of static data gives the value. The size of the value comes from the
`DB` or `DW` statement. The size is 1 byte or 2 bytes. A bigger area gives its
address, and `x` shows the bytes. A label of code gives its address. `print/x`
shows hexadecimal.

A name that is a variable of the program gets a C value: see
[Variables](#variables). A name that is a label only gets the old rules.

## Variables

A `prog.dbg` that has the `vars` table gives udb80 the C variables. A program
that `uc80 -g` made has the table, when `um80` and `ul80` ran with
`--debug-info`. The
table format is in [debug_info.md](debug_info.md#variables).

```
(udb80) break deep.c:27
(udb80) continue
(udb80) info args
n = 1
p = (struct pt *) 0x03a8 <q>
(udb80) print *p
$1 = {x = 5, y = 6}
(udb80) frame 1
#1  0x01b5 in _deep () at deep.c:28
(udb80) info locals
arr = {4, 2}
local = 4
```

### Expressions

An expression has these items:

- Names and numbers.
- Character constants (`'a'`).
- `*p`, `&x`, `a[i]`, `s.m` and `p->m`.
- A unary minus and parentheses.

An expression can also have `+ - * / %` on integers, and a pointer plus or
minus an integer. There is no cast, no comparison and no assignment.

A name is a variable first. When the name is not a variable, `print` tries
the labels and the registers, as before (`$pc`, `*0x100`).

A value has the form of the type:

- an integer: a decimal number. `char` types show the character, for
  example `97 'a'`. `bool` shows `true` or `false`.
- an enumeration: the name of the constant, or the number.
- a pointer: `(int *) 0x02cd <g>`. The text in angle brackets is the variable
  or the routine at the address. A `char` pointer shows the string:
  `0x02e2 "hi"`.
- an array: `{10, 20, 30}`. A `char` array shows the string. A run of 10 or
  more equal elements shows as `0 <repeats 12 times>`. udb80 shows 200
  elements at most.
- a struct or union: `{x = 3, y = 4}`.
- a float: the bytes in hex. udb80 does not convert the float formats.

`print/x`, `/d`, `/u`, `/o`, `/t` and `/c` change an integer, an enumeration
or a pointer.

`x/4dh ARRAY` takes the address of an array, struct or function
and the value of an integer or pointer variable. `ptype EXPRESSION` and
`ptype struct TAG` show the full type. `whatis` shows the name of the type.

### Which variables a frame has

`frame N` (`up`, `down`) selects a frame of the backtrace. `print`, `info
locals`, `info args` and `x` use the selected frame. Each resume (`continue`,
`step`, `next`, `finish`, `stepi`) selects frame 0 again. udb80 takes the
frames from the frame records, with each unwind method of `bt`.

A name stands for a variable when both conditions are true:

- The routine of the frame holds the variable.
- The line of the frame is in the scope of the variable.

A line above the declaration does not see the variable. A name in an inner
block hides a name in an outer block. The global variables and the static
variables of the file come last. `info locals` lists the innermost block
first.

Two files can each have a `static` variable of one name, and a struct tag or
typedef of one name with different content. The record keeps the source name
of the variable. The variable in the file of the frame wins. If no variable
is in that file, the first variable wins.

The compiler gives the name `TAG__tN` to a tag that conflicts with another
tag. `ptype struct TAG` finds the tag when one file defines it, and
shows the choices `TAG__t0`, `TAG__t1` when two files do.

The compiler removes the data of a global that nothing uses. The variable
then has no address. `print` shows `<not available>` for the variable and for
each element of the variable. An `x` command or a sum that needs the
address gives the same message. udb80 keeps the session open.

The place of a variable decides what udb80 can show:

- *Fixed address* (a global variable, a static variable, a local variable in
  the shared area `??AUTO`): udb80 reads the address in any frame of the
  routine. The routine must be active, and the compiler shares `??AUTO` only
  between routines that are never active together.
- *IX frame*: the frame base is the stack address of the return address minus
  2. In frame 0 between `add ix,sp` and `pop ix`, the base is the register IX.
  Before the prologue ends and after the epilogue, the arguments (IX+4 and up)
  are valid and the locals are not available. A frame with a `[guess]` tag has
  no frame base.
- *Register*: udb80 shows the variable only in frame 0, and only when the PC
  is in a range of the variable. The registers of the other frames are
  not saved. The value of a register that is not live shows
  `<not available>`.
- *No place*: the optimizer removed the variable, or the compiler did not
  know where the variable lives. udb80 shows `<not available>`.

With `uc80`, the values are exact at the start of a statement for a routine
under `--optnone`. In an optimized routine, the optimizer can keep a value in
a register, delete a store, or fold a constant. udb80 then shows the value of
the slot, or `<not available>`. Use `--optnone=NAME` for the routine that you
debug.

## The outer level

A line can have an outer level: the position below the source level, for
example the C line under a BASIC line (`outer=` in
[debug_info.md](debug_info.md#levels)). uc80 writes the field when a `#line`
directive is active, as in the C code that mbasic makes.

- `info line` adds the line `Outer level: line 7 of "p.c".`
- `set level outer` (or `set level c`) shows the outer position in place of
  the source position, in the stop message, in `frame`, `bt` and `list`.
  `set level both` shows the source line and the outer line. `set level src`,
  `auto` and `asm` disable the outer level.
- `addr2line` adds `[outer FILE:LINE]`. With `--outer`, `addr2line` shows the
  outer position in place of the source position.

`step`, `next` and `break` work on the source level in all cases.

## addr2line

```
udb80 addr2line [-r] [--asm] prog.dbg ADDRESS...
```

The command shows the routine and the line for each address. An address is
`0x0108`, `0108H` or a decimal number. With `-r`, each address is a return
address, and the command reads the byte before the address (use `-r` for the
addresses of `cpmemu --backtrace`). With `--asm`, the command shows the
assembler line. Example:

```
$ udb80 addr2line sumto.dbg 0x108 0x121
0x0108  LOOP  sumto.c:14  [asm sumto.mac:11]
0x0121  _ADD+1  sumto.c:7  [asm sumto.mac:30]
```

The exit status is 1 if an address has no line. The command checks `prog.dbg`
against `prog.com` when `prog.com` is in the same directory as `prog.dbg`.

## sizes

```
udb80 sizes prog.dbg
```

The command shows the bytes of each routine, the biggest first, and the
total. Use the list to choose the routines for `--optnone`:

```
    24  0108  LOOP
     8  0100  _MAIN
     2  0120  _ADD
    34  total in 3 routines
```

A routine runs from its `;#func` record to its end. For a program with no
records, the command uses the labels. A routine then runs from a label to the
next label or to the first data.

## bt-dump

```
udb80 bt-dump [--ix IX] [-n COUNT] prog.dbg memory.bin SP PC
```

The command shows the backtrace of a program that has stopped, from a memory
dump file and three register values. The command uses the frame records only.

Make the memory dump file with `cpmemu --save-memory=memory.bin prog.com`. The
memory dump file has 65536 bytes, from address 0. SP and PC are the values at
the stop. When PC is in the IX range of a routine, give `--ix`. The command
checks the program in the memory dump file against `prog.dbg`, as `udb80`
does at the start of a session.

## Limits

- udb80 runs one program on one stub.
- udb80 has no `watch`, `ignore`, conditions, `call` or `set` of memory yet.
- An expression has no cast, assignment, comparison, `sizeof` or function
  call.
- udb80 has no `info scope`, `info variables` or `watch` of a variable.
- udb80 does not convert a float.
- With `--run` and no `--batch`, the program and udb80 both read the
  terminal. For a program that reads the keyboard, start cpmemu in a second
  terminal and use `--connect`.
- The disassembler is `ud80`. `ud80` shows some Z80 jumps with the 8080
  names (`JMP`).

## Tests

`tests/test_frames.py` compares `bt shadow` with `bt frame` at each stop of a
step-through. The live tests of `tests/test_frames.py` have the same skip
rule. The file also tests `bt-dump`.

`tests/test_udb80.py` always runs the static tests. `tests/test_udb80.py`
runs the live tests when a cpmemu with `--gdb` is present, in one of these
places:

- `$CPMEMU`
- `../cpmemu/src/cpmemu`
- `~/src/cpmemu/src/cpmemu`
- `cpmemu` on PATH

When no cpmemu is present, the live
tests skip and give the reason. Set `UDB80_REQUIRE_CPMEMU=1` to make the
skip a failure.
