# Backtrace from frame records

A debugger can find the chain of calls of a program in two ways. The stub of
the emulator can keep a shadow call stack (`monitor bt`). Or the debugger can
use the registers PC, SP and IX, the memory of the program and the frame
records of `prog.dbg`. This file describes the second way. The plan calls the second way
source 2 of rule D7 in the
[cpmemu project](https://github.com/avwohl/cpmemu/blob/main/docs/debugger_plan.md).

The frame records are the only source when the stub has no shadow call stack.
GDB stubs, z80fpga and a memory dump after a crash are such cases.

The code is `um80/frames.py`. `udb80` and the GDB unwinder
([gdb.md](gdb.md)) use the same file, so both give the same frames.

## What the compiler writes

Each `;#func` marker can carry these fields (see [debug_info.md](debug_info.md)):

- `frame=none`, `frame=ix` or `frame=static`. `ix` means that the routine
  keeps a frame in IX. `static` means that the locals are at fixed addresses
  and the routine has no frame.
- `pops=N`. The routine removes N bytes of arguments from the stack of the
  caller when the routine returns.
- `ixbegin=LABEL ixend=LABEL`. IX holds the frame from `ixbegin` to `ixend`,
  and both addresses belong to the range. `ixbegin` is the address after
  `add ix,sp`. `ixend` is the address of the last `pop ix` in front of a `ret`.

`uc80 -g` writes all of these. `uc80` writes the labels of the range after its
last text pass, so the labels do not change the code. uplm80 writes
the same range fields (`add_ix_range_labels` in its `compiler.py`). A routine with `frame=ix` and no range gets a range from the
code: the debugger looks for `push ix / ld ix,0 / add ix,sp` at the start and
for the last `pop ix` in front of a `ret`.

## How the debugger finds the return address

For each frame the debugger knows PC, SP and IX. For the first frame the values are
the registers. For the other frames the values come from the frame below. The
debugger looks for the stack address of the return address of the frame in
this order:

1. **The IX range.** PC is between `ixbegin` and `ixend`. The saved IX is at
   IX+0 and the return address is at IX+2. The routine can use IX as a pointer
   for a few instructions. The debugger therefore accepts the word at IX+2 only
   when the word is the address after a CALL instruction.
2. **The stack depth.** The debugger follows the code of the routine from the
   first instruction and counts the bytes that the routine has pushed. The
   result is the depth d for each instruction. The return address is at SP+d.
   - `push` adds 2. `pop` subtracts 2. `inc sp` and `dec sp` change d by 1.
   - A `call` subtracts the `pops` value of the routine that the `call`
     names. A routine without a record has `pops` 0.
   - A jump or a conditional jump goes to its target. A `ret` and a
     `jp (hl)` end the path.
   - If two paths reach one instruction with two depths, d is not known
     there. A loop that pushes in each pass has this result.
   - `ld sp,hl` and `ld sp,(nn)` make d not known. `ld sp,nn` starts a new
     stack: the routine is the start-up code and no routine called the
     routine.
   - The instruction lengths come from the `asm` rows of `prog.dbg`. Library
     code has no rows, so the debugger uses a table of the Z80 lengths.
3. **A guess.** When d is not known, the debugger searches upward from SP for
   the first word that is the address after a CALL. The frame has the tag
   `guess`.

At a `ret` instruction the return address is at SP when the routine has an IX
frame, or when d is not known. This rule handles an early `pop ix` and `ret`
inside the IX range. A `push de` and `ret` pair is a computed jump. In such a
case d gives the right address.

The chain ends at the start-up code, which has no caller. The start-up code is
the routine at the load address. In another routine, a word that is not the
address after a CALL means that the depth was wrong. The frame is then a
`guess`.

The debugger marks each frame with the source that found the frame:
`[shadow]`, `[frame]` or `[guess]`.

## Commands

```
(udb80) bt              the shadow call stack, else the frame records
(udb80) bt shadow       the shadow call stack only
(udb80) bt frame        the frame records only
(udb80) set shadow off  act as a stub that has no shadow call stack
```

`bt shadow` and `bt frame` at one stop give two lists that you can compare.

### After a crash

```
cpmemu --save-memory=mem.bin prog.com
udb80 bt-dump [--ix IX] prog.dbg mem.bin SP PC
```

`mem.bin` is the 64K memory image that `cpmemu --save-memory` writes. SP and
PC are the values at the crash. Give `--ix IX` when PC is in the IX range of a
routine.

Without `--ix`, the command uses the stack depth of the routine. If the depth
is known at PC, the frames are the same and have the tag `[frame]`. If the
routine loads SP with a computed value, the command scans the stack, finds the
same return address, and tags the frame `[guess]`.

The command checks the program in the image against `prog.dbg`, then
prints the frames as `bt` does.

## Measured

On 2026-11-04, with cpmemu `--gdb` on macOS arm64. The test compares `bt shadow`
and `bt frame` at each stop, frame by frame (address, routine and source line).

- `tests/test_frames.py`: a recursive assembler program, a program with an IX
  frame and a frameless recursive routine with pushes, and a recursive
  `uc80 -g` program (`sum` with 5 calls, `fill` with 4 calls and an IX frame).
  The two lists are equal at each stop of `stepi`, `step` and `next`, from the
  first instruction to the end of the program.
- Eight more `uc80 -g` programs (`qsort`, `fib` and `hanoi` with recursion and
  IX frames, `long` arithmetic, `printf`, `switch`, structures and strings), at
  most 3000 `stepi` stops each: 11,727 stops, 0 differences. The stops include
  the library code of `printf`. At 835 of these stops one frame or more has the
  tag `guess`, in library routines whose stack depth is not known. All of those
  guesses are equal to the shadow stack.
- A `uc80 -g` program with `setjmp` and `longjmp`, 3000 `stepi` stops: 657
  stops differ. At 653 of them the shadow stack keeps one frame that `longjmp`
  skipped, and the frame records are right. The other 4 stops are inside
  `longjmp`, where SP changes (`guess`).
- GDB 18.1 with the unwinder in the mode `records`: `bt` equals `bt` of the
  mode `auto` at each instruction of the prologue and of the epilogue of an IX
  frame (`tests/test_gdb.py`).

## Limits

- A tail call (`jp`) hides a frame, as in each debugger.
- `longjmp`, a task switch and any routine that changes SP with `ld sp,hl`
  give `guess` frames. The frames can be wrong.
- A routine that uses IX and has no record can change IX. The debugger then
  does not know IX of the caller, and an IX range further up is read from the
  stack depth.
- A routine that gets its arguments from the code after the `call`
  (`pop hl` and `jp (hl)`) can hide its frame.
- Library code has no `;#func` records. The debugger splits the code into
  routines at the global labels and assumes depth 0 at the start of each
  routine. A jump from one routine into the middle of another routine can
  give a wrong depth. The check of the return address then gives a `guess`.
- A dump after a crash has no registers. SP, PC and IX come from the user.
