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
2. The frame records of prog.dbg (`;#func ... frame=ix ixbegin=.. ixend=..`),
   read by um80/frames.py, the code that udb80 uses too.  Between ixbegin
   and ixend the frame is in IX: the saved IX is at IX+0 and the return
   address at IX+2.  Everywhere else the return address is at SP+d, where d
   is the stack depth that a walk over the code of the routine finds.  When
   d is not known, the unwinder takes the first word above SP that follows a
   CALL instruction (a guess).

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
import importlib.util
import json
import os

import gdb
from gdb.unwinder import Unwinder


def _load_frames():
    """um80/frames.py, the frame-record walker that udb80 shares.  It is
    loaded by its path, so that GDB needs no installed um80."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(os.path.dirname(here), 'frames.py')
    spec = importlib.util.spec_from_file_location('udb80_frames', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


frames = _load_frames()

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
        self.program = frames.Program(data)
        self.walker = frames.Walker(self.program, lambda a: None)
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


def record_unwind(pending, pc, sp, level, dbg):
    """Frame record of prog.dbg (um80/frames.py).  Returns (caller pc, caller
    sp, caller ix or None, how) or None.  `how` is 'frame' for an exact
    answer and 'guess' for a scan of the stack."""
    try:
        ix = int(pending.read_register('ix'))
    except gdb.error:
        ix = None
    # A new Mem for each frame.  GDB steps and asks for frames at many
    # stops with no event between them (`finish` out of an inline frame), so
    # the pages that an earlier stop read can be stale.  Measured: the page
    # at FC00H read as zeros one stop after a CALL had written to it, and the
    # walker took a word of the wrong frame.  Only the depth maps of the
    # routines (the code does not change) stay from call to call.
    mem = Mem()
    walker = dbg.walker
    walker.read_byte = mem.byte
    st = walker.step(pc, sp, ix, level == 0)
    if st is None:
        return None
    return st.ret, st.sp, st.ix, st.tag


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
