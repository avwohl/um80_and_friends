"""Backtrace from the frame records of prog.dbg (D7 source 2 of the debugger plan).

The shadow call stack of the emulator needs no help from the compiler, but a
stub that has no shadow stack (GDB's own stubs, z80fpga), and a memory dump
after a crash, have only the registers and the memory.  This module finds
the chain of return addresses from those and from prog.dbg.  The same file
serves udb80 and the GDB unwinder (um80/gdb/udb80_unwind.py), so it uses
only the standard library.

For each frame the walker knows the registers PC, SP and IX of the frame.
It finds the slot that holds the return address of the frame in one of two
ways:

1. IX range.  A routine whose ;#func record has frame=ix and the labels
   ixbegin and ixend keeps its frame in IX between `add ix,sp` and `pop ix`.
   There the saved IX is at IX+0 and the return address at IX+2.
2. Stack depth.  Everywhere else the slot is SP+d.  d is the number of
   bytes that the routine has pushed since the entry.  The walker finds d
   at each instruction of the routine by a walk over the code: PUSH adds 2,
   POP subtracts 2, and a CALL subtracts the `pops` count of the called
   routine (a callee that removes its arguments from the stack).  Where two
   paths reach an instruction with different d, or the routine loads SP
   (`ld sp,hl`), d is not known for that instruction.

A frame found by 1 or 2 is exact ('frame').  When d is not known, the walker
looks for the first word above SP that follows a CALL instruction.  That
frame is a guess ('guess').

The decoder knows only what changes SP and the flow of control; the length of
each instruction comes from the `asm` rows of prog.dbg.
"""

import bisect

MAX_SCAN = 0x4000       # how far above SP a guess looks
MAX_FRAMES = 4096

CALLS = (0xCD, 0xC4, 0xCC, 0xD4, 0xDC, 0xE4, 0xEC, 0xF4, 0xFC)
PUSHES = (0xC5, 0xD5, 0xE5, 0xF5)
POPS = (0xC1, 0xD1, 0xE1, 0xF1)
JP_CC = (0xC2, 0xCA, 0xD2, 0xDA, 0xE2, 0xEA, 0xF2, 0xFA)
JR_CC = (0x20, 0x28, 0x30, 0x38)
RET_CC = (0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8)

CONFLICT = 'conflict'
BASE = 'base'      # SP was loaded with a constant: the stack starts here


class Step(object):
    """One unwound frame: the caller's PC, SP and IX, and how it was found."""

    def __init__(self, ret, sp, ix, tag, slot):
        self.ret = ret      # return address
        self.sp = sp        # SP of the caller, after the return
        self.ix = ix        # IX of the caller, or None when not known
        self.tag = tag      # 'frame' or 'guess'
        self.slot = slot    # stack address of the return address

    def __repr__(self):
        return 'Step(ret=%04x sp=%04x ix=%s %s)' % (
            self.ret, self.sp, '?' if self.ix is None else '%04x' % self.ix,
            self.tag)


class Program(object):
    """The parts of prog.dbg that a backtrace needs."""

    def __init__(self, data):
        self.funcs = sorted((f for f in data.get('funcs') or []
                             if f.get('start') is not None),
                            key=lambda f: f['start'])
        self.starts = [f['start'] for f in self.funcs]
        self.asm = sorted((r for r in data.get('asm') or [] if r[2] == 'i'),
                          key=lambda r: r[0])
        self.asm_starts = [r[0] for r in self.asm]
        self.asm_end = {r[0]: r[1] for r in self.asm}
        self.row_by_end = {}
        for r in self.asm:
            self.row_by_end.setdefault(r[1], r[0])
        labels = data.get('labels') or []
        has_global = any(len(l) > 3 and l[3] for l in labels)
        self.labels = sorted({l[1] for l in labels
                              if (len(l) > 3 and l[3]) or not has_global})
        image = data.get('image') or {}
        self.load = image.get('load') or 0x100
        ends = [r[1] for r in self.asm] + [0]
        self.code_end = max(ends)
        # The library modules have no rows, so the end of the program is the
        # end of the image when prog.dbg says it.
        self.image_end = (self.load + image['length']
                          if image.get('length') else self.code_end)
        self.code_end = max(self.code_end, self.image_end)
        self.by_start = {f['start']: f for f in self.funcs}

    # -- routines ------------------------------------------------------------

    def func_at(self, addr):
        """The ;#func record that holds addr, or None."""
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return None
        f = self.funcs[i]
        end = f.get('end')
        if end is None:
            end = self.starts[i + 1] if i + 1 < len(self.starts) else self.code_end
        return f if f['start'] <= addr < end else None

    def routine(self, addr):
        """(start, end, record) of the routine that holds addr.  Without a
        record, the routine runs from the label at or below addr to the next
        label."""
        if addr >= self.image_end:
            return None         # the BDOS entry, the BIOS: not the program
        f = self.func_at(addr)
        if f is not None:
            end = f.get('end')
            if end is None:
                i = self.starts.index(f['start'])
                end = self.starts[i + 1] if i + 1 < len(self.starts) else self.code_end
            return f['start'], end, f
        i = bisect.bisect_right(self.labels, addr) - 1
        if i < 0:
            return None
        end = self.labels[i + 1] if i + 1 < len(self.labels) else self.code_end
        return self.labels[i], max(end, addr + 1), None

    def pops_of(self, target):
        f = self.by_start.get(target)
        return (f.get('pops') or 0) if f else 0

    def row_containing(self, addr):
        """(start, end) of the instruction row that holds addr, or None."""
        i = bisect.bisect_right(self.asm_starts, addr) - 1
        if i >= 0 and self.asm[i][0] <= addr < self.asm[i][1]:
            return self.asm[i][0], self.asm[i][1]
        return None

    def is_call_return(self, read_byte, addr):
        """True if addr follows a CALL or RST instruction.  The rows of
        prog.dbg decide where they cover the address; library code has no
        rows (the library modules have no .dbm), and there the bytes in
        front of addr decide."""
        if addr is None or addr < 3 or addr > 0xFFFF:
            return False
        row = self.row_containing(addr - 1)
        if row is not None:
            if row[1] != addr:
                return False
            op = read_byte(row[0])
            return op is not None and (op in CALLS or (op & 0xC7) == 0xC7)
        op = read_byte(addr - 3)
        return op in CALLS


# Instruction lengths for code that has no rows in prog.dbg.
_LEN2 = set((0x06, 0x0E, 0x16, 0x1E, 0x26, 0x2E, 0x36, 0x3E, 0x10, 0x18, 0x20,
             0x28, 0x30, 0x38, 0xC6, 0xCE, 0xD6, 0xDE, 0xE6, 0xEE, 0xF6, 0xFE,
             0xD3, 0xDB, 0xCB))
_LEN3 = set((0x01, 0x11, 0x21, 0x31, 0x22, 0x2A, 0x32, 0x3A, 0xC3, 0xCD)
            + JP_CC + CALLS)
_ED_LEN4 = set((0x43, 0x4B, 0x53, 0x5B, 0x63, 0x6B, 0x73, 0x7B))
_IDX_D = set([0x34, 0x35, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x77]
             + [0x46 + 8 * i for i in range(8) if i != 6]
             + [0x86 + 8 * i for i in range(8)])


def insn_length(read_byte, a):
    """The length of the Z80 or 8080 instruction at a, or None."""
    op = read_byte(a)
    if op is None:
        return None
    if op in (0xDD, 0xFD):
        op2 = read_byte(a + 1)
        if op2 is None:
            return None
        if op2 in (0x21, 0x22, 0x2A):
            return 4
        if op2 == 0x36 or op2 == 0xCB:
            return 4
        if op2 in _IDX_D:
            return 3
        if op2 in (0x26, 0x2E):
            return 3
        return 2
    if op == 0xED:
        op2 = read_byte(a + 1)
        if op2 is None:
            return None
        return 4 if op2 in _ED_LEN4 else 2
    if op in _LEN3:
        return 3
    if op in _LEN2:
        return 2
    return 1


class Walker(object):
    """Unwinds frames from registers, memory and prog.dbg.

    `read_byte(addr)` returns a byte or None.  It is the memory of the
    program, so that the walker reads the real code.
    """

    def __init__(self, program, read_byte):
        self.prog = program
        self.read_byte = read_byte
        self._depth = {}        # routine start -> (map addr -> d, touches ix)
        self.bottom = False     # the last step found the end of the stack
        self.slots = []         # see walk()

    def word(self, addr):
        if addr is None or not 0 <= addr < 0xFFFF:
            return None
        lo, hi = self.read_byte(addr), self.read_byte(addr + 1)
        if lo is None or hi is None:
            return None
        return lo | (hi << 8)

    # -- the walk over one routine ------------------------------------------

    def depths(self, start, end):
        """({address: d}, touches_ix) for the routine start..end.  d is an
        int, None (not known) or CONFLICT."""
        key = (start, end)
        if key in self._depth:
            return self._depth[key]
        prog = self.prog
        state = {}
        touches = [False]
        work = [(start, 0)]
        while work:
            a, d = work.pop()
            while start <= a < end:
                if a in state:
                    if state[a] == d or state[a] == CONFLICT:
                        break
                    d = CONFLICT        # two paths, two depths: not known
                state[a] = d
                nxt = prog.asm_end.get(a)
                op = self.read_byte(a)
                if op is None:
                    break
                if nxt is None:
                    size = insn_length(self.read_byte, a)
                    if size is None:
                        break
                    nxt = a + size
                size = nxt - a
                follow, d2 = self._effect(op, a, size, d, work, touches)
                if not follow:
                    break
                a, d = nxt, d2
        self._depth[key] = (state, touches[0])
        return self._depth[key]

    def _effect(self, op, a, size, d, work, touches):
        """Apply the instruction at a.  Returns (continue to the next
        instruction?, d after it) and queues the jump targets."""
        rb = self.read_byte

        def add(n):
            return d if d in (None, BASE, CONFLICT) else d + n

        def target_abs():
            lo, hi = rb(a + 1), rb(a + 2)
            return None if lo is None or hi is None else lo | (hi << 8)

        def target_rel(at=1):
            v = rb(a + at)
            if v is None:
                return None
            return (a + at + 1 + (v - 256 if v >= 128 else v)) & 0xFFFF

        if op in PUSHES:
            return True, add(2)
        if op in POPS:
            return True, add(-2)
        if op == 0x33:
            return True, add(-1)            # inc sp
        if op == 0x3B:
            return True, add(1)             # dec sp
        if op == 0x31:
            return True, BASE               # ld sp,nn
        if op == 0xF9:
            return True, None               # ld sp,hl
        if op == 0xCD or op in CALLS:
            t = target_abs()
            pops = self.prog.pops_of(t) if t is not None else 0
            return True, add(-pops)
        if op == 0xC9:
            return False, d
        if op in RET_CC:
            return True, d
        if op == 0xC3:
            t = target_abs()
            if t is not None:
                work.append((t, d))
            return False, d
        if op in JP_CC:
            t = target_abs()
            if t is not None:
                work.append((t, d))
            return True, d
        if op == 0xE9:
            return False, d                 # jp (hl)
        if op == 0x18:
            t = target_rel()
            if t is not None:
                work.append((t, d))
            return False, d
        if op in JR_CC or op == 0x10:
            t = target_rel()
            if t is not None:
                work.append((t, d))
            return True, d
        if op in (0xDD, 0xFD):
            op2 = self.read_byte(a + 1)
            if op2 == 0xE5:
                return True, add(2)
            if op2 == 0xE1:
                if op == 0xDD:
                    touches[0] = True
                return True, add(-2)
            if op2 == 0xE9:
                return False, d
            if op2 == 0xF9:
                return True, None           # ld sp,ix / ld sp,iy
            if op == 0xDD:
                touches[0] = True
            return True, d
        if op == 0xED:
            op2 = self.read_byte(a + 1)
            if op2 in (0x4D, 0x45):
                return False, d             # reti, retn
            if op2 == 0x7B:
                return True, None           # ld sp,(nn)
            return True, d
        return True, d

    # -- one frame -----------------------------------------------------------

    PROLOGUE = (0xDD, 0xE5, 0xDD, 0x21, 0x00, 0x00, 0xDD, 0x39)

    def ix_range(self, start, end, rec):
        """[begin, end] where IX holds the frame of a frame=ix routine, or
        None.  The record gives the range (ixbegin, ixend).  A record with
        no range (older compilers) gets one from the code: after the
        prologue `push ix / ld ix,0 / add ix,sp` up to the last `pop ix`
        in front of a `ret`."""
        if rec is None or rec.get('frame') != 'ix':
            return None
        if rec.get('ix'):
            return rec['ix']
        key = ('ix', start, end)
        if key in self._depth:
            return self._depth[key]
        rng = None
        code = tuple(self.read_byte(start + i) for i in range(len(self.PROLOGUE)))
        if code == self.PROLOGUE:
            last = None
            a = start + len(self.PROLOGUE)
            while a < end:
                size = self.prog.asm_end.get(a)
                size = size - a if size else insn_length(self.read_byte, a)
                if not size:
                    break
                if (self.read_byte(a) == 0xDD and self.read_byte(a + 1) == 0xE1
                        and self.read_byte(a + 2) == 0xC9):
                    last = a
                a += size
            if last is not None:
                rng = [start + len(self.PROLOGUE), last]
        self._depth[key] = rng
        return rng

    def step(self, pc, sp, ix, innermost):
        """Unwind the frame whose PC is pc.  For a frame above the innermost
        one, pc is a return address.  Returns a Step or None.  None with
        `self.bottom` set means that the frame is the first one of the stack."""
        prog = self.prog
        look = pc if innermost else pc - 1
        r = prog.routine(look)
        if r is None:
            return self.guess(sp, None, ix)
        start, end, rec = r
        pops = (rec.get('pops') or 0) if rec else 0

        def finish(slot, caller_ix):
            """The step for a return address at slot.  The word must be the
            address after a CALL.  In the start-up code (the routine at the
            load address) another word is the end of the stack: CP/M leaves
            0000H there.  In any other routine it means that the stack depth
            was wrong, and the answer is a guess."""
            ret = self.word(slot)
            if ret is None:
                return None
            if prog.is_call_return(self.read_byte, ret):
                return Step(ret, slot + 2 + pops, caller_ix, 'frame', slot)
            if start == prog.load:
                self.bottom = True
                return None
            return self.guess(sp, rec, ix)

        rng = self.ix_range(start, end, rec)
        at_ret = innermost and self.read_byte(pc) == 0xC9
        # In a routine with an IX frame, an early `pop ix` is in front of a
        # RET that is inside the range.  At the RET, SP is exact.  (A RET can
        # also be a computed jump, `push de / ret`; the stack depth tells.)
        if at_ret and rng:
            return finish(sp, ix)
        if rng:
            b, e = rng
            inside = (b <= pc <= e) if innermost else (b < pc <= e)
            if inside and ix is not None:
                # A routine can lend IX to its code as a pointer for a few
                # instructions, so the word must look like a return address.
                saved = self.word(ix)
                if saved is not None and prog.is_call_return(
                        self.read_byte, self.word(ix + 2)):
                    return finish(ix + 2, saved)
        states, touches = self.depths(start, end)
        d = states.get(pc)
        if at_ret and not isinstance(d, int):
            return finish(sp, ix)
        if d == BASE:
            # The routine loaded SP with a constant (the start-up code): the
            # stack is empty here and nothing called the routine.
            self.bottom = True
            return None
        if (d is None or d == CONFLICT) and start == prog.load:
            # The start-up code sets SP itself (`ld sp,hl`), and nothing
            # called the routine.
            self.bottom = True
            return None
        if d is None or d == CONFLICT:
            return self.guess(sp, rec, ix)
        caller_ix = ix
        if rng:
            if pc < rng[0]:
                # In the prologue.  After `push ix` the caller's IX is on
                # the stack, below the return address; `ld ix,0` and
                # `add ix,sp` have changed IX itself.
                caller_ix = ix if pc == start else self.word(sp + d - 2)
        elif touches:
            caller_ix = None
        return finish(sp + d, caller_ix)

    def guess(self, sp, rec, ix):
        """The first word above SP that follows a CALL."""
        a = sp
        pops = (rec.get('pops') or 0) if rec else 0
        lim = min(sp + MAX_SCAN, 0xFFFF)
        while a < lim:
            w = self.word(a)
            if self.prog.is_call_return(self.read_byte, w):
                return Step(w, a + 2 + pops, None, 'guess', a)
            a += 1
        return None

    # -- the chain -------------------------------------------------------------

    def walk(self, pc, sp, ix, limit=MAX_FRAMES):
        """The frames, innermost first: a list of (pc, sp, tag).  Frame 0 is
        the PC itself.  A frame has the tag of the step that found it; frame 0
        has the tag of the step that leaves it."""
        frames = [(pc, sp, None)]
        # slots[i]: the stack address of the return address of frame i (the
        # frame base of an IX frame is slot - 2), or None
        self.slots = []
        cur_pc, cur_sp, cur_ix = pc, sp, ix
        innermost = True
        self.bottom = False
        while len(frames) < limit:
            self.bottom = False
            st = self.step(cur_pc, cur_sp, cur_ix, innermost)
            if st is None:
                break
            # The chain ends where the word is not the address after a call:
            # the word that the loader put below the program (0000H).
            if not self.prog.is_call_return(self.read_byte, st.ret):
                break
            if st.sp <= cur_sp and not innermost:
                break
            if frames[0][2] is None:
                frames[0] = (frames[0][0], frames[0][1], st.tag)
            frames.append((st.ret, st.sp, st.tag))
            self.slots.append(st.slot if st.tag == 'frame' else None)
            cur_pc, cur_sp, cur_ix = st.ret, st.sp, st.ix
            innermost = False
            if st.sp > 0xFFFF:
                break
        if frames[0][2] is None and self.bottom:
            frames[0] = (frames[0][0], frames[0][1], 'frame')
        return frames
