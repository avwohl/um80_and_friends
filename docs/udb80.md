# udb80: the debugger

udb80 is a debugger for Z80 and 8080 programs that run in `cpmemu`. udb80
shows source lines, sets breakpoints on source lines, steps by line and
shows the chain of calls. udb80 is phase 3 of the debugger plan in the
[cpmemu project](https://github.com/avwohl/cpmemu/blob/main/docs/debugger_plan.md).

udb80 needs two things:

- A `prog.dbg` file. Link the program with `ul80 --debug-info`. The format
  is in [debug_info.md](debug_info.md).
- A cpmemu that has the `--gdb` option. udb80 speaks the GDB remote
  protocol to the stub in cpmemu. The program keeps all of its 64K,
  because udb80 keeps the symbols and the source files on the host.

## Build a program for udb80

```
um80 --debug-info -o prog.rel prog.mac
ul80 --debug-info -o prog.com prog.rel
```

Then `prog.dbg` is beside `prog.com`. A program that has no `;#line` markers
has only assembler lines. udb80 then uses the lines of the `.mac` file.

## Start

```
udb80 prog.dbg --run 'cpmemu prog.com'
udb80 prog.dbg --connect 127.0.0.1:1234
```

`--run` starts cpmemu. udb80 adds `--gdb=0` and `--gdb-port-file` to the
command, and reads the port that cpmemu chooses. `--connect` uses a cpmemu
that runs already (`cpmemu --gdb prog.com`). The program stops before the
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
  at 0100H in bank 8EH, then starts the session.
- `-d DIR`, `--directory DIR`: a directory that holds source files.
- `--asm`: start at the assembler level. `--8080`: disassemble as 8080.

In `--batch` mode the exit status is 1 if a command gave an error.

## The image check

`prog.dbg` holds the length and the SHA-256 of `prog.com`. udb80 refuses a
`prog.dbg` that does not match the program, because a `prog.dbg` from an
older build shows wrong lines. udb80 does two checks: the `.com` file
beside `prog.dbg`, and the first `length` bytes of guest memory at 0100H.
udb80 does not check memory again after the program starts.

## Commands

You can use a short form of a command name when only one command has
that start (`b`, `c`, `s`, `n`, `bt`, `p`, `l`).

A location is `FILE:LINE`, a routine name or a label, or `*ADDRESS`.
`FILE` can be the base name of the file. A line can have more than one
address, for example when the compiler copied a loop test. `break` sets a
breakpoint at each address. A `nostmt` line takes no breakpoint. When a
line has no code, `break` uses the next line that has code and says so.

- `break LOCATION`, `tbreak LOCATION`: set a breakpoint, or a breakpoint
  that goes after the first stop. `break` with no argument uses the
  current address.
- `delete [N...]`: delete breakpoints. `info breakpoints` lists them.
- `continue`: run until a breakpoint, the end of the program, or ^C.
- `step [N]`: run to the next source line and go into a call.
- `next [N]`: the same, but run over a call.
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
- `print[/F] EXPRESSION`: show a value. See [Print](#print).
- `sizes`: show the bytes of each routine.
- `monitor COMMAND`: send a command to the stub (`monitor bt`).
- `set level auto|src|asm`, `set cpu z80|8080`, `set shadow on|off`.
- `kill`, `quit`, `echo TEXT`, `help`.

A breakpoint at 0100H stops the program at the first `continue`. The stub
does not report a breakpoint at the address where the program waits, and
udb80 reports it by itself.

### How step works

A source line is a range of addresses in the `lines` table of
`prog.dbg`. `step` runs the range with one range-step packet (`vCont;r`),
so the stub does the work and one round trip covers the line. When the
program leaves the range, `step` stops if the new address is the start of
a line that is a step point. A line that is `nostmt` is not a step point,
and `step` runs on through it. When the new address is in the middle of a
line, `step` runs to the end of that line. The test uses address ranges
and not line numbers, so a loop on one line stops after one pass.

When a program has no `;#line` markers, `step` uses the assembler lines
(`set level asm` forces this). When a program has markers, `step` does not
go into code that has no source line, for example a library. `step` runs
over such a call.

### How next and finish work

When the range step leaves through a CALL, `next` puts a temporary
breakpoint at the return address and runs. The breakpoint counts only when
the shadow call stack is as short as it was before the call. A deeper
return to the same address does not count, so recursion works. A user
breakpoint in the called routine stops `next` first.

`next` and `finish` also put a temporary breakpoint on the return address
of each caller above. A routine can drop its return addresses (a longjmp,
or POP POP RET) and return to a caller. Then the shadow call stack is
shorter than at the start, and `next` or `finish` stops in that caller.

`finish` does the same with the return address of the current frame.

When the stub has no shadow call stack (`set shadow off` acts like such a
stub), `next` uses the stack pointer. The call is a call when the word on
top of the stack is the address after the instruction. The return counts
when SP is at least 2 above SP at the call. `finish` needs the shadow stack.

### Backtrace

`backtrace` has two sources. The first is the shadow call stack of the stub
(`monitor bt`). The list has the current address and the return addresses,
innermost first. The second source is the frame records of `prog.dbg`. The
second source needs only the registers and the memory, so it works with a stub
that has no shadow call stack. [frame_records.md](frame_records.md) has the
rules.

`backtrace` uses the shadow call stack when the stub has one. Otherwise
`backtrace` uses the frame records. The line of a return address is the line of
the CALL before it. Each frame has a tag:

- `[shadow]`: the frame comes from the shadow call stack.
- `[frame]`: the frame comes from the frame records. The IX range or the stack
  depth of the routine gave the return address.
- `[guess]`: the debugger could not find the return address from the records.
  The debugger scanned the stack for a word that follows a CALL instruction in
  the program. The frame can be wrong.

You can choose the source: `backtrace shadow` and `backtrace frame`. A count
can follow (`backtrace frame 3`). `set shadow off` makes `backtrace`, `next` and
`finish` act as with a stub that has no shadow call stack.

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

`print` takes numbers (`10`, `0x0A`, `0AH`), registers (`$pc`, `$sp`,
`$hl`, `$a`), labels, and the operators `+`, `-`, `&` (address of a
label) and `*` (the word at an address). A label of static data gives the
value, and the size of the value comes from the `DB` or `DW` statement:
1 byte or 2 bytes. A bigger area gives its address, and `x` shows the bytes.
A label of code gives its address. `print/x` shows hex.

`prog.dbg` has no types, so `print total` shows a number and not a C
value. Types are phase 8 of the plan.

## addr2line

```
udb80 addr2line [-r] [--asm] prog.dbg ADDRESS...
```

The command shows the routine and the line for each address. An address is
`0x0108`, `0108H` or a decimal number. With `-r`, each address is a return
address, and the command looks at the byte before it (use `-r` for the
addresses of `cpmemu --backtrace`). With `--asm`, the command shows the
assembler line. Example:

```
$ udb80 addr2line sumto.dbg 0x108 0x121
0x0108  LOOP  sumto.c:14  [asm sumto.mac:11]
0x0121  _ADD+1  sumto.c:7  [asm sumto.mac:30]
```

The exit status is 1 if an address has no line. The command checks
`prog.dbg` against `prog.com` when `prog.com` is beside the file.

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

A routine runs from its `;#func` record to its end. A program with no
records uses its labels: a routine runs from a label to the next label or
to the first data.

## bt-dump

```
udb80 bt-dump [--ix IX] [-n COUNT] prog.dbg memory.bin SP PC
```

The command shows the backtrace of a program that has stopped, from a memory
image and three register values. It uses the frame records only.

Make the image
with `cpmemu --save-memory=memory.bin prog.com`. The image has 65536 bytes,
from address 0. SP and PC are the values at the stop. Give `--ix` when PC is
in the IX range of a routine. The command checks the program in the image
against `prog.dbg`, as `udb80` does at the start of a session.

## Limits

- udb80 runs one program on one stub.
- No `watch`, `ignore`, conditions, `call` or `set` of memory yet.
- Variables with types are a later phase.
- With `--run` and no `--batch`, the program and udb80 both read the
  terminal. Start cpmemu in a second terminal and use `--connect` for a
  program that reads the keyboard.
- The disassembler is `ud80`. `ud80` shows some Z80 jumps with the 8080
  names (`JMP`).

## Tests

`tests/test_frames.py` compares `bt shadow` with `bt frame` at each stop of a step-through (live tests with the same skip rule), and tests `bt-dump`.

`tests/test_udb80.py` runs the static tests always and the live tests when
a cpmemu with `--gdb` is present: `$CPMEMU`, `../cpmemu/src/cpmemu`,
`~/src/cpmemu/src/cpmemu` or `cpmemu` on PATH. Without cpmemu, the live
tests skip and give the reason. Set `UDB80_REQUIRE_CPMEMU=1` to make the
skip a failure.
