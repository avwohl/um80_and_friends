"""A GDB Python unwinder for Z80 frames.

Load the file in GDB with a `source` line:

    (gdb) source /path/to/um80/gdb/udb80_unwind.py

`python3 -m um80.dbg2elf --unwinder-path` prints the path.  docs/gdb.md has
the user view.  The unwinder takes frames from two places, best first:

1. The shadow call stack of the cpmemu stub (`monitor bt`).  The stub lists
   the return address of each call that has not returned.  The stub does not
   give the stack address of a return address, so the unwinder looks for
   each return address in memory, upward from the stack address of the
   frame below.
2. The frame records of prog.dbg (`;#func ... frame=ix`).  An IX frame has
   the saved IX at IX+0 and the return address at IX+2.  A routine without a
   frame record is read as: the return address is at SP, or else the first
   word above SP that follows a CALL instruction (a guess).

A frame that neither source can unwind goes to the unwinder of GDB.  GDB
asks the unwinders in this order: the dummy, tail call and inline unwinders
of GDB, then Python unwinders, then the z80 unwinder of GDB.  An inlined
call is therefore an inline frame of GDB, and this unwinder only sees the
real frame under it.

prog.dbg is found as follows: the command `udb80-dbg FILE`, the environment
variable UDB80_DBG, or the program file of GDB with the extension .dbg.  The
unwinder works without prog.dbg when the stub has a shadow call stack.

The command `udb80-unwind-info` prints what the unwinder knows.
"""

import bisect
import json
import os

import gdb
from gdb.unwinder import Unwinder

MAX_STACK_SCAN = 0x4000
Z80_ARCHS = ('z80', 'ez80', 'z180', 'r800', 'gbz80')


class FrameId(object):
    def __init__(self, sp, pc):
        self.sp = sp
        self.pc = pc


class Mem(object):
    """Guest memory, read in pages of 256 bytes, forgotten at each stop."""

    def __init__(self):
        self.pages = {}

    def byte(self, addr):
        if not 0 <= addr < 0x10000:
            return None
        page = addr >> 8
        if page not in self.pages:
            try:
                data = bytes(gdb.selected_inferior().read_memory(page << 8, 256))
            except gdb.MemoryError:
                data = None
            self.pages[page] = data
        data = self.pages[page]
        return None if data is None else data[addr & 255]

    def word(self, addr):
        lo, hi = self.byte(addr), self.byte(addr + 1)
        if lo is None or hi is None:
            return None
        return lo | (hi << 8)


class DbgFile(object):
    """The parts of prog.dbg that unwinding needs."""

    def __init__(self, path):
        self.path = path
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        if data.get('format') != 'um80-dbg':
            raise ValueError('%s is not a um80-dbg file' % path)
        self.funcs = sorted((f for f in data.get('funcs') or []
                             if f.get('start') is not None),
                            key=lambda f: f['start'])
        self.starts = [f['start'] for f in self.funcs]
        labels = sorted((l[1], l[0]) for l in data.get('labels') or [])
        self.label_addrs = [a for a, _n in labels]
        self.labels = labels
        self.code_end = max([r[1] for r in data.get('asm') or []] + [0])
        self.asm = sorted(data.get('asm') or [], key=lambda r: r[0])
        self.asm_starts = [r[0] for r in self.asm]

    def func_at(self, addr):
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return None
        f = self.funcs[i]
        end = f.get('end')
        if end is None:
            end = self.starts[i + 1] if i + 1 < len(self.starts) else self.code_end
        return f if f['start'] <= addr < end else None

    def routine_start(self, addr):
        f = self.func_at(addr)
        if f is not None:
            return f['start']
        i = bisect.bisect_right(self.label_addrs, addr) - 1
        return self.label_addrs[i] if i >= 0 else None

    def is_instruction(self, addr):
        i = bisect.bisect_right(self.asm_starts, addr) - 1
        return i >= 0 and self.asm[i][0] <= addr < self.asm[i][1] and self.asm[i][2] == 'i'


class State(object):
    """What the unwinder learned since the last stop."""

    def __init__(self):
        self.reset()
        self.dbg = None
        self.dbg_path = None
        self.dbg_tried = False
        self.shadow_works = True
        self.use_shadow = True      # false: use only the frame records
        self.log = []

    def reset(self):
        self.mem = Mem()
        self.shadow = None          # list of return addresses, or None
        self.shadow_done = False
        self.out_of_step = False
        self.sps = None             # stack address of each real frame
        self.slots = None

    def set_dbg(self, path):
        self.dbg_path = path
        self.dbg_tried = True
        self.dbg = None
        if path:
            try:
                self.dbg = DbgFile(path)
            except (OSError, ValueError) as e:
                gdb.write('udb80_unwind: cannot read %s: %s\n' % (path, e), gdb.STDERR)

    def find_dbg(self):
        if self.dbg_tried:
            return self.dbg
        path = os.environ.get('UDB80_DBG')
        if not path:
            prog = gdb.current_progspace().filename
            if prog:
                path = os.path.splitext(prog)[0] + '.dbg'
        if path and os.path.exists(path):
            self.set_dbg(path)
        else:
            self.dbg_tried = True
        return self.dbg


STATE = State()


def shadow_stack(sp0):
    """The return addresses of the shadow call stack, innermost first, and the
    stack address of each.  None when the stub has no shadow call stack."""
    st = STATE
    if st.shadow_done:
        return st.shadow
    st.shadow_done = True
    if not st.shadow_works or not st.use_shadow:
        return None
    try:
        text = gdb.execute('monitor bt', False, True)
    except gdb.error:
        st.shadow_works = False
        return None
    rets = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('(the shadow stack is out of step'):
            st.out_of_step = True
        if line.startswith('#'):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith('0x'):
                rets.append(int(parts[1], 16))
    if not rets:
        st.shadow_works = False
        return None
    rets = rets[1:]                 # frame 0 is the pc
    # find the slot of each return address, going up the stack
    slots = []
    start = sp0
    for r in rets:
        found = None
        for parity in (0, 1):
            a = start + parity
            while a < min(start + MAX_STACK_SCAN, 0xffff):
                if st.mem.word(a) == r:
                    found = a
                    break
                a += 2
            if found is not None:
                break
        if found is None:
            break
        slots.append(found)
        start = found + 2
    st.shadow = rets[:len(slots)]
    st.slots = slots
    st.sps = [sp0] + [s + 2 for s in slots]
    return st.shadow


def func_start(pending, pc, level):
    """The start of the real routine that holds the frame: a part of the frame
    id that stays the same while the routine runs."""
    try:
        b = pending.block()
    except RuntimeError:
        b = None
    start = None
    while b is not None:
        if b.function is not None:
            start = b.start
        sup = b.superblock
        if sup is None or sup.is_static or sup.is_global:
            break
        b = sup
    if start is not None:
        return start
    dbg = STATE.find_dbg()
    if dbg is not None:
        s = dbg.routine_start(pc - 1 if level else pc)
        if s is not None:
            return s
    return pc


def looks_like_return(mem, dbg, addr):
    """True if addr follows a CALL or RST instruction."""
    if addr is None or addr < 3:
        return False
    if dbg is not None and dbg.asm:
        # the instruction before addr is a call when the row that ends at addr
        # starts with a call opcode
        i = bisect.bisect_left(dbg.asm_starts, addr) - 1
        while i >= 0 and dbg.asm[i][1] > addr:
            i -= 1
        if i >= 0 and dbg.asm[i][1] == addr and dbg.asm[i][2] == 'i':
            op = mem.byte(dbg.asm[i][0])
            return op == 0xCD or (op is not None and (op & 0xC7) in (0xC4, 0xC7))
        return False
    op = mem.byte(addr - 3)
    return op == 0xCD or (op is not None and (op & 0xC7) == 0xC4)


PROLOGUE = (0xDD, 0xE5, 0xDD, 0x21, 0x00, 0x00, 0xDD, 0x39)    # push ix, ld ix,0, add ix,sp


def record_unwind(pending, pc, sp, level, dbg):
    """Frame record of prog.dbg.  Returns (caller pc, caller sp, saved ix or
    None, how) or None."""
    mem = STATE.mem
    f = dbg.func_at(pc - 1 if level else pc)
    if f is None:
        return None
    start = f['start']
    try:
        ix = int(pending.read_register('ix'))
    except gdb.error:
        ix = None
    pops = f.get('pops') or 0
    if f.get('frame') == 'ix' and ix is not None:
        # the routine keeps its frame in IX between `add ix,sp` and `ld sp,ix`
        code = [mem.byte(start + i) for i in range(len(PROLOGUE))]
        has_prologue = tuple(code) == PROLOGUE
        off = pc - start
        op = mem.byte(pc)
        if level == 0 and has_prologue and off < 8:
            # before the frame is set up: IX is still the caller's
            extra = 2 if off >= 2 else 0       # push ix done
            ret_at = sp + extra
            return mem.word(ret_at), ret_at + 2 + pops, ix, 'frame'
        if level == 0 and op == 0xC9:
            # at the RET: IX and SP are the caller's already
            return mem.word(sp), sp + 2 + pops, ix, 'frame'
        saved = mem.word(ix)
        ret = mem.word(ix + 2)
        if ret is not None:
            return ret, ix + 4 + pops, saved, 'frame'
        return None
    # frame=none or static: the return address is at SP, with the pushes of
    # the routine added.  A straight scan from the start to PC counts PUSH
    # and POP; a jump makes the count a guess, so the word is checked.
    depth = 0
    a = start
    guess = False
    while a < pc:
        op = mem.byte(a)
        if op is None:
            break
        if op & 0xCF == 0xC5:
            depth += 2
            a += 1
        elif op & 0xCF == 0xC1:
            depth -= 2
            a += 1
        elif op in (0xDD, 0xFD):
            op2 = mem.byte(a + 1)
            if op2 == 0xE5:
                depth += 2
            elif op2 == 0xE1:
                depth -= 2
            a += 2 if op2 in (0xE5, 0xE1) else 1
            if op2 not in (0xE5, 0xE1):
                guess = True
                break
        else:
            # any other instruction: its length is unknown here; use the
            # assembler row of prog.dbg
            i = bisect.bisect_right(dbg.asm_starts, a) - 1
            if i < 0 or dbg.asm[i][0] != a:
                guess = True
                break
            a = dbg.asm[i][1]
    cands = [] if guess else [sp + depth]
    for c in cands:
        w = mem.word(c)
        if looks_like_return(mem, dbg, w):
            return w, c + 2 + pops, None, 'frame'
    # a guess: the first word above SP that follows a CALL
    a = sp
    while a < min(sp + MAX_STACK_SCAN, 0xffff):
        w = mem.word(a)
        if looks_like_return(mem, dbg, w):
            return w, a + 2 + pops, None, 'guess'
        a += 1
    return None


class Z80Unwinder(Unwinder):
    def __init__(self):
        super(Z80Unwinder, self).__init__('udb80-z80')

    def __call__(self, pending):
        try:
            name = pending.architecture().name()
        except gdb.error:
            return None
        if not name.startswith(Z80_ARCHS):
            return None
        st = STATE
        pc = int(pending.read_register('pc'))
        sp = int(pending.read_register('sp'))
        level = pending.level()
        # The shadow call stack is read once after each resume, at the first
        # real frame that GDB asks about: that is the innermost real frame,
        # and inline frames above it have the same stack address.  The
        # unwinder must not ask GDB for frame 0 here: GDB computes the id of
        # an inline frame from the id of the real frame under it.
        result = None
        if not st.shadow_done and st.shadow_works and st.use_shadow:
            shadow_stack(sp)
        if st.sps is not None and sp in st.sps:
            k = st.sps.index(sp)
            if k < len(st.slots):
                result = (st.shadow[k], st.slots[k] + 2, None, 'shadow')
        if result is None:
            dbg = st.find_dbg()
            if dbg is not None:
                result = record_unwind(pending, pc, sp, level, dbg)
        if result is None or result[0] is None:
            return None
        ret, csp, saved_ix, how = result
        ptr = pending.read_register('pc').type
        sptype = pending.read_register('sp').type
        uinfo = pending.create_unwind_info(FrameId(csp, func_start(pending, pc, level)))
        uinfo.add_saved_register('pc', gdb.Value(ret).cast(ptr))
        uinfo.add_saved_register('sp', gdb.Value(csp).cast(sptype))
        for reg in ('ix', 'iy'):
            try:
                if reg == 'ix' and saved_ix is not None:
                    uinfo.add_saved_register(reg, gdb.Value(saved_ix).cast(
                        pending.read_register(reg).type))
                else:
                    uinfo.add_saved_register(reg, pending.read_register(reg))
            except gdb.error:
                pass
        st.log.append((level, pc, sp, how))
        del st.log[:-200]
        return uinfo


def _reset(_event=None):
    STATE.reset()


def _forget_memory(_event=None):
    STATE.mem = Mem()


class DbgCommand(gdb.Command):
    """udb80-dbg FILE: the prog.dbg that the Z80 unwinder reads."""

    def __init__(self):
        super(DbgCommand, self).__init__('udb80-dbg', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        STATE.set_dbg(arg.strip() or None)
        gdb.write('udb80-dbg: %s\n' % (STATE.dbg_path or 'none'))


class ModeCommand(gdb.Command):
    """udb80-unwind-mode auto|records: auto uses the shadow call stack of the
    stub when there is one; records uses only the frame records of prog.dbg."""

    def __init__(self):
        super(ModeCommand, self).__init__('udb80-unwind-mode', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        word = arg.strip()
        if word not in ('auto', 'records'):
            raise gdb.GdbError('udb80-unwind-mode: say auto or records')
        STATE.use_shadow = word == 'auto'
        STATE.reset()
        gdb.execute('maintenance flush register-cache', False, True)
        gdb.write('udb80-unwind-mode: %s\n' % word)


class InfoCommand(gdb.Command):
    """udb80-unwind-info: show what the Z80 unwinder used."""

    def __init__(self):
        super(InfoCommand, self).__init__('udb80-unwind-info', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        st = STATE
        gdb.write('prog.dbg: %s\n' % (st.dbg_path or 'none'))
        gdb.write('shadow call stack: %s\n' % ('works' if st.shadow_works else 'not available'))
        if st.out_of_step:
            gdb.write('the shadow stack is out of step\n')
        for lvl, pc, sp, how in st.log[-50:]:
            gdb.write('level %d pc %04x sp %04x [%s]\n' % (lvl, pc, sp, how))


def install():
    from gdb.unwinder import register_unwinder
    register_unwinder(None, Z80Unwinder(), replace=True)
    # The cache is valid from one resume to the next one.  GDB makes the
    # frames of a stop before it sends the stop event, so the cache is not
    # cleared at the stop.
    gdb.events.cont.connect(_reset)
    gdb.events.exited.connect(_reset)
    gdb.events.new_objfile.connect(_reset)
    gdb.events.register_changed.connect(_reset)
    gdb.events.memory_changed.connect(_forget_memory)
    DbgCommand()
    ModeCommand()
    InfoCommand()


install()
