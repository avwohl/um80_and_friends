"""Backtrace from the frame records of prog.dbg (D7 source 2, phase 6).

The static tests build small programs with um80 and ul80, put the program in a
memory image by hand and ask um80/frames.py for the frames.  The live tests run
`cpmemu --gdb` and compare, at every stop of a step-through, the frames of the
shadow call stack (`bt shadow`) with the frames of the frame records
(`bt frame`).  Live tests skip with a reason when cpmemu is missing; the test
with a uc80 program also skips when uc80 is missing (as in test_gdb.py).
"""

# pytest fixtures are parameters with the name of the fixture function.
# pylint: disable=redefined-outer-name
# The test names say what each test checks.
# pylint: disable=missing-function-docstring
import json
import os
import re
import subprocess
import sys

import pytest

from um80 import frames, udb80
from um80.ud80 import Disassembler

from test_udb80 import ROOT, _build, _run, cpmemu, in_order, live, udb  # noqa: F401
from test_gdb import ODD_MAC, REC_C, uc80_programs  # noqa: F401


# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------

# An IX frame with a range, a frameless routine with pushes and a branch whose
# two paths have the same depth, and a recursion in each.  The labels are the
# ones that uc80 writes after its text passes.
MIX = """\
\t.z80
;#file 1 "mix.c"
;#func _main 1 1 frame=none pops=0
_main:
\tld\thl,3
\tcall\t_ixrec
\tld\thl,3
\tcall\t_flat
\tjp\t0
;#endfunc _main
;#func _ixrec 1 5 frame=ix pops=0 ixbegin=??IXB1 ixend=??IXE1
_ixrec:
\tpush\tix
\tld\tix,0
\tadd\tix,sp
??IXB1:
\tpush\thl
\tld\ta,h
\tor\tl
\tjr\tz,ixrec_ret
\tdec\thl
\tcall\t_ixrec
ixrec_ret:
\tld\tsp,ix
??IXE1:
\tpop\tix
\tret
;#endfunc _ixrec
;#func _flat 1 20 frame=none pops=0
_flat:
\tpush\tbc
\tld\ta,h
\tor\tl
\tjr\tz,flat_out
\tpush\tde
\tdec\thl
\tcall\t_flat
\tpop\tde
flat_out:
\tpop\tbc
\tret
;#endfunc _flat
"""

# Ends at depth three with `jp 0`, so the stack stays as it was.
DEAD = """\
\t.z80
start:\tld\tb,3
\tcall\trec
\tjp\t0
rec:\tdec\tb
\tjr\tz,bottom
\tcall\trec
\tret
bottom:\tjp\t0
"""

# A routine that moves SP by a number: the depth is not known there.
GUESS = """\
\t.z80
;#func _main 1 1 frame=none pops=0
_main:
\tcall\t_g
\tjp\t0
;#endfunc _main
;#func _g 1 5 frame=none pops=0
_g:
\tld\thl,-6
\tadd\thl,sp
\tld\tsp,hl
\tnop
\tld\thl,6
\tadd\thl,sp
\tld\tsp,hl
\tret
;#endfunc _g
"""

POPS = """\
\t.z80
;#func _main 1 1 frame=none pops=0
_main:
\tld\tde,1234h
\tpush\tde
\tcall\t_pa
back:\tjp\t0
;#endfunc _main
;#func _pa 1 5 frame=none pops=2
_pa:
\tpop\thl
\tinc\tsp
\tinc\tsp
\tjp\t(hl)
;#endfunc _pa
"""

JOIN = """\
\t.z80
;#func _main 1 1 frame=none pops=0
_main:
\tcall\t_c
\tjp\t0
;#endfunc _main
;#func _c 1 5 frame=none pops=0
_c:
\tpush\tbc
\tor\ta
\tjr\tz,join
\tpush\tde
join:
\tnop
\tpop\tbc
\tret
;#endfunc _c
"""


def build_dir(tmp_path_factory, name, text):
    d = tmp_path_factory.mktemp(name)
    (d / (name + '.mac')).write_text(text)
    _build(d, name)
    return d


@pytest.fixture(scope='module')
def mix(tmp_path_factory):
    return build_dir(tmp_path_factory, 'mix', MIX)


@pytest.fixture(scope='module')
def dead(tmp_path_factory):
    return build_dir(tmp_path_factory, 'dead', DEAD)


@pytest.fixture(scope='module')
def guess(tmp_path_factory):
    return build_dir(tmp_path_factory, 'guess', GUESS)


class Image:
    """A program in memory, with a stack that the test fills by hand."""

    def __init__(self, d, name):
        self.dbg = json.load(open(os.path.join(str(d), name + '.dbg')))
        com = open(os.path.join(str(d), name + '.com'), 'rb').read()
        self.mem = bytearray(0x10000)
        self.mem[0x100:0x100 + len(com)] = com
        self.prog = frames.Program(self.dbg)
        self.walker = frames.Walker(self.prog, lambda a: self.mem[a])
        self.labels = {l[0]: l[1] for l in self.dbg['labels']}

    def put(self, addr, word):
        self.mem[addr] = word & 255
        self.mem[addr + 1] = word >> 8

    def addr(self, name):
        return self.labels[name.upper()]


# ---------------------------------------------------------------------------
# Static
# ---------------------------------------------------------------------------

def test_instruction_lengths_agree_with_ud80():
    # insn_length is for library code that has no rows in prog.dbg.
    bad = []
    prefixes = [(), (0xDD,), (0xFD,), (0xED,), (0xCB,)]
    for prefix in prefixes:
        for op in range(256):
            code = bytes(prefix) + bytes([op, 0x12, 0x34, 0x56, 0, 0, 0, 0])
            dis = Disassembler(code, org=0, z80_mode=True)
            d = dis.decode_instruction(0)
            if d is None or d[0] in ('DB', '???') or (prefix and d[1] == 1):
                continue
            if prefix == (0xDD,) or prefix == (0xFD,):
                if code[1] in (0xDD, 0xFD, 0xED):
                    continue
            got = frames.insn_length(lambda a: code[a] if a < len(code) else None, 0)
            if got != d[1]:
                bad.append((prefix, hex(op), d[0], d[1], got))
    assert not bad, bad[:20]


def test_depth_of_a_branch_with_equal_paths(mix):
    img = Image(mix, 'mix')
    s = img.addr('_flat')
    r = img.prog.routine(s)
    states, touches = img.walker.depths(r[0], r[1])
    assert not touches
    assert states[s] == 0
    out = img.addr('flat_out')
    assert states[out] == 2           # push bc was done on both paths
    assert states[out + 1] == 0       # the ret


def test_depth_conflict_and_guess(tmp_path_factory):
    d = build_dir(tmp_path_factory, 'join', JOIN)
    img = Image(d, 'join')
    r = img.prog.routine(img.addr('_c'))
    states, _ = img.walker.depths(r[0], r[1])
    assert states[img.addr('join')] == frames.CONFLICT
    # a stop at the nop has no exact answer: the scan finds the return
    # address, the walker says guess
    img.put(0xFF00, img.addr('_main') + 3)       # the CALL _c is at _main
    pc = img.addr('join')
    st = img.walker.step(pc, 0xFEF8, 0, True)
    assert st.tag == 'guess' and st.ret == img.addr('_main') + 3


def test_callee_pops_are_counted(tmp_path_factory):
    d = build_dir(tmp_path_factory, 'pops', POPS)
    img = Image(d, 'pops')
    back = img.addr('back')
    main = img.addr('_main')
    # SP is FF00 at the start of main; push de; call _pa
    img.put(0xFEFE, 0x1234)
    img.put(0xFEFC, back)
    pa = img.addr('_pa')
    # at each instruction of _pa (pop hl, inc sp, inc sp, jp (hl)) the frames
    # are _pa and _main
    for pc, sp in ((pa, 0xFEFC), (pa + 1, 0xFEFE), (pa + 2, 0xFEFF),
                   (pa + 3, 0xFF00)):
        chain = img.walker.walk(pc, sp, None)
        assert [f[0] for f in chain][:2] == [pc, back], (hex(pc), chain)
        assert chain[0][2] == 'frame'
    # in main after the call the argument is gone: d is 2 (push) - 2 (pops)
    states, _ = img.walker.depths(main, pa)
    assert states[back] == 0


def test_a_load_of_sp_gives_a_guess(guess):
    img = Image(guess, 'guess')
    g = img.addr('_g')
    ret = img.addr('_main') + 3
    # _main: call _g (3 bytes) at _main; the return address is _main+3
    img.put(0xFEFC, ret)
    pc = g + 5                       # at the nop, after `ld sp,hl`
    r = img.prog.routine(pc)
    states, _ = img.walker.depths(r[0], r[1])
    assert states[pc] is None
    chain = img.walker.walk(pc, 0xFEFC - 6, None)
    assert [hex(f[0]) for f in chain[:2]] == [hex(pc), hex(ret)]
    assert chain[0][2] == 'guess'


def test_an_ix_record_without_a_range_gets_one_from_the_code(mix):
    img = Image(mix, 'mix')
    rec = dict(next(f for f in img.dbg['funcs'] if f['name'] == '_ixrec'))
    r = img.prog.routine(rec['start'])
    assert rec['ix'] and rec['frame'] == 'ix'
    want = rec['ix']
    rec['ix'] = None
    assert img.walker.ix_range(r[0], r[1], rec) == want


def test_dbg_records_the_labels_of_the_ix_range(mix):
    d = json.load(open(os.path.join(str(mix), 'mix.dbg')))
    f = next(f for f in d['funcs'] if f['name'] == '_ixrec')
    labels = {l[0]: l[1] for l in d['labels']}
    assert f['ix'] == [labels['??IXB1'], labels['??IXE1']]


@pytest.fixture(scope='module')
def odd(tmp_path_factory):
    return build_dir(tmp_path_factory, 'odd', ODD_MAC)


def odd_stack(img, pc_label):
    """Memory for a stop in _odd: _main called it from odd_back.  The return
    address is at FF00, the caller's IX (5555) below it."""
    img.put(0xFF00, img.addr('odd_back'))
    img.put(0xFEFE, 0x5555)
    return 0xFEFE, 0xFEF8        # IX, SP at odd_stop


def test_the_record_range_decides_when_the_code_cannot(odd):
    """_odd has `push hl / pop ix` for a prologue and `ld sp,hl` in the
    body.  The code gives no range and no stack depth, so without the record
    the answer is a guess.  With the record it is exact.  (Mutation check:
    without the `rec.get('ix')` line of Walker.ix_range the first assertion
    fails.)"""
    img = Image(odd, 'odd')
    rec = next(f for f in img.dbg['funcs'] if f['name'] == '_odd')
    assert rec['ix'] and rec['frame'] == 'ix'
    pc = img.addr('odd_stop')
    ix, sp = odd_stack(img, 'odd_stop')
    chain = img.walker.walk(pc, sp, ix)
    assert [hex(f[0]) for f in chain[:2]] == [hex(pc), hex(img.addr('odd_back'))]
    assert chain[0][2] == 'frame' and chain[1][2] == 'frame', chain
    # the same stop with the range taken from the record: guess
    img2 = Image(odd, 'odd')
    r2 = next(f for f in img2.dbg['funcs'] if f['name'] == '_odd')
    r2['ix'] = None
    img2.prog = frames.Program(img2.dbg)
    img2.walker = frames.Walker(img2.prog, lambda a: img2.mem[a])
    odd_stack(img2, 'odd_stop')
    chain2 = img2.walker.walk(pc, sp, ix)
    assert chain2[0][2] == 'guess', chain2
    assert chain2[1][0] == img.addr('odd_back')


def test_the_record_ends_the_ix_range_before_the_last_pop(odd):
    """_clob loads IX with 8000H after the label ixend, and the last
    `pop ix / ret` is further down.  A range inferred from the code would run
    to that `pop ix` and read the return address from IX+2, which is a
    return address of another frame here.  The range of the record stops
    where the code changes IX."""
    img = Image(odd, 'odd')
    rec = next(f for f in img.dbg['funcs'] if f['name'] == '_clob')
    pc = img.addr('clob_out')
    r = img.prog.routine(pc)
    inferred = frames.Walker(img.prog, lambda a: img.mem[a])
    dummy = dict(rec, ix=None)
    assert inferred.ix_range(r[0], r[1], dummy)[1] >= pc      # the code alone
    assert rec['ix'][1] < pc                                  # the record
    # _clob was called from clob_back's caller: return address at FF00.
    # push ix, push hl: the stop at `pop hl` has SP = FF00 - 4.
    img.put(0xFF00, img.addr('clob_back'))
    img.put(0xFEFE, 0x5555)
    img.put(0x8002, img.addr('odd_back'))       # IX+2 of the wrong IX
    img.put(0x8000, 0x4444)
    chain = img.walker.walk(pc, 0xFEFC, 0x8000)
    assert chain[1][0] == img.addr('clob_back'), chain
    assert [f[2] for f in chain[:2]] == ['frame', 'frame']


def put_stack_and_dump(img, d):
    """Write the image to mem.bin in d."""
    with open(os.path.join(str(d), 'mem.bin'), 'wb') as f:
        f.write(bytes(img.mem))


def test_bt_dump_with_pc_inside_an_ix_range(odd):
    img = Image(odd, 'odd')
    pc = img.addr('odd_stop')
    ix, sp = odd_stack(img, 'odd_stop')
    put_stack_and_dump(img, odd)
    back = f"{img.addr('odd_back'):04x}"
    # with --ix: exact frames
    run = udb('bt-dump', '--ix', hex(ix), 'odd.dbg', 'mem.bin', hex(sp), hex(pc),
              cwd=str(odd))
    g = bt_groups(run.stdout)[0]
    assert [f[3] for f in g[:2]] == ['frame', 'frame'], run.stdout
    assert g[1][0] == back and g[0][1] == '_odd' and g[1][1] == '_main'
    # without --ix the walker has no IX: the stack depth is not known in
    # _odd, so the same return address is found by the scan and tagged guess
    run = udb('bt-dump', 'odd.dbg', 'mem.bin', hex(sp), hex(pc), cwd=str(odd))
    g = bt_groups(run.stdout)[0]
    assert g[1][0] == back and g[1][3] == 'guess', run.stdout
    # a stop in a range where the depth is known needs no IX
    img.put(0xFF00, img.addr('clob_back'))
    img.put(0xFEFE, 0x5555)
    put_stack_and_dump(img, odd)
    run = udb('bt-dump', 'odd.dbg', 'mem.bin', hex(0xFEFC), hex(img.addr('clob_in')),
              cwd=str(odd))
    g = bt_groups(run.stdout)[0]
    assert g[1][0] == f"{img.addr('clob_back'):04x}" and g[1][3] == 'frame', run.stdout


# ---------------------------------------------------------------------------
# Live: the frame records against the shadow stack
# ---------------------------------------------------------------------------

BT_LINE = re.compile(r'^#(\d+)\s+(?:0x([0-9a-f]+) in )?(\S+) \(\)(?: at (\S+))?\s+\[(\w+)\]')


def bt_groups(text):
    """The frames of each bt in the output: a list of lists of
    (address or None, routine, position, tag)."""
    groups = []
    for line in text.splitlines():
        m = BT_LINE.match(line)
        if not m:
            continue
        if m.group(1) == '0':
            groups.append([])
        groups[-1].append((m.group(2), m.group(3), m.group(4), m.group(5)))
    return groups


def compare_sources(cpmemu, d, prog, start, motion, count, **kw):
    """Break at start, then do `motion` count times; at each stop run
    `bt shadow` and `bt frame`.  Returns (number of stops, the tags that the
    frame records gave).  Every pair must agree frame by frame."""
    cmds = ['break ' + start, 'continue', 'delete']
    for _ in range(count):
        cmds += [motion, 'bt shadow', 'bt frame']
    args = ['--batch', prog + '.dbg', '--run', f'{cpmemu} {prog}.com']
    for c in cmds:
        args += ['-ex', c]
    out = udb(*args, cwd=str(d), check=False).stdout
    groups = bt_groups(out)
    assert len(groups) % 2 == 0 and groups, out
    tags = set()
    stops = 0
    for shadow, record in zip(groups[0::2], groups[1::2]):
        if shadow[0][0] == '0000':      # the program has ended (jp 0)
            continue
        stops += 1
        assert [f[:3] for f in shadow] == [f[:3] for f in record], (
            'stop %d\nshadow: %s\nframe:  %s' % (stops, shadow, record))
        assert {f[3] for f in shadow} == {'shadow'}
        tags |= {f[3] for f in record}
    return stops, tags


def test_live_recursive_assembler_frames_equal_shadow(cpmemu, tmp_path_factory):
    d = build_dir(tmp_path_factory, 'rec', """\
\t.z80
start:\tld\tb,3
\tcall\trec
\tjp\t0
rec:\tdec\tb
\tjr\tz,bottom
\tcall\trec
\tret
bottom:\tret
""")
    stops, tags = compare_sources(cpmemu, d, 'rec', '*0x100', 'stepi', 12)
    assert stops >= 8
    assert tags <= {'frame', 'guess'}
    for motion in ('step', 'next'):
        compare_sources(cpmemu, d, 'rec', 'rec.mac:4', motion, 6)


def test_live_ix_frames_frames_equal_shadow_at_every_instruction(cpmemu, mix):
    # _ixrec has the prologue, the epilogue, the range and a recursion
    stops, tags = compare_sources(cpmemu, mix, 'mix', '*0x100', 'stepi', 120)
    assert stops >= 80
    assert tags == {'frame'}, tags


def test_live_mixed_step_and_next(cpmemu, mix):
    compare_sources(cpmemu, mix, 'mix', '_ixrec', 'step', 10)
    compare_sources(cpmemu, mix, 'mix', '_ixrec', 'next', 3)


def test_live_uc80_program_frames_equal_shadow(cpmemu, uc80_programs):
    d = uc80_programs
    text = open(os.path.join(d, 'rec.mac')).read()
    assert re.search(r';#func _fill .*frame=ix .*ixbegin=\S+ ixend=\S+', text), text
    dbg = json.load(open(os.path.join(d, 'rec.dbg')))
    assert any(f['frame'] == 'ix' and f['ix'] for f in dbg['funcs'])
    # every instruction, from the start of the program to its end
    stops, tags = compare_sources(cpmemu, d, 'rec', '*0x100', 'stepi', 2500)
    assert stops > 150
    assert 'frame' in tags
    for motion, n in (('step', 80), ('next', 20)):
        compare_sources(cpmemu, d, 'rec', 'main', motion, n)


def test_live_bt_uses_the_frame_records_without_a_shadow_stack(cpmemu, mix):
    out = live(cpmemu, mix, 'mix', 'set shadow off', 'break _flat', 'continue',
               'continue', 'bt').stdout
    groups = bt_groups(out)
    assert groups
    assert {f[3] for f in groups[-1]} == {'frame'}, out
    assert [f[1] for f in groups[-1]][:3] == ['_flat', '_flat', '_main']


def test_live_a_load_of_sp_is_a_guess(cpmemu, guess):
    out = live(cpmemu, guess, 'guess', 'break *_g+5', 'continue', 'bt frame', 'bt shadow').stdout
    groups = bt_groups(out)
    assert groups[0][0][3] == 'guess' and groups[0][1][3] == 'guess', out
    assert [f[:2] for f in groups[0]] == [f[:2] for f in groups[1]]


def test_bt_dump_of_a_crashed_program(cpmemu, dead):
    # The program ends with `jp 0` at depth three, so cpmemu --save-memory
    # keeps the stack.  A session with the same run says what SP and PC were.
    d = str(dead)
    out = live(cpmemu, dead, 'dead', 'break bottom', 'continue', 'bt shadow',
               'info registers sp').stdout
    shadow = bt_groups(out)[0]
    m = re.search(r'\bsp\s+0x([0-9a-f]+)', out)
    assert m, out
    sp = m.group(1)
    pc = re.search(r'Breakpoint 1 at 0x([0-9a-f]+)', out).group(1)
    run = subprocess.run([cpmemu, '--save-memory=' + os.path.join(d, 'mem.bin'),
                          os.path.join(d, 'dead.com')], cwd=d, capture_output=True,
                         text=True, stdin=subprocess.DEVNULL, timeout=60)
    assert os.path.getsize(os.path.join(d, 'mem.bin')) == 65536, run.stderr
    run = udb('bt-dump', 'dead.dbg', 'mem.bin', '0x' + sp, '0x' + pc, cwd=d)
    dump = bt_groups(run.stdout)[0]
    assert [f[:3] for f in dump] == [f[:3] for f in shadow], run.stdout
    assert {f[3] for f in dump} == {'frame'}
    assert len(dump) == 4


# uplm80's static procedure with a third, stacked argument pops its own
# return address and puts it back with `ex (sp),hl` in the slot of the
# argument.  A walk that counts only the depth looked 2 bytes below SP,
# where the CALL to _leaf had left a stale copy of lback, and listed _mid
# twice.
CALLEE_POPS = """\
\t.z80
;#func _main 1 1 frame=none pops=0
_main:\tld\thl,7
\tpush\thl
\tld\tbc,1
\tld\tde,2
\tcall\t_mid
mback:\tjp\t0
;#endfunc _main
;#func _mid 1 5 frame=static pops=2
_mid:\tpop\thl
\tex\t(sp),hl
\tld\t(arg),hl
\tcall\t_leaf
lback:\tinc\thl
\tret
;#endfunc _mid
;#func _leaf 1 9 frame=none pops=0
_leaf:\tld\thl,(arg)
\tret
;#endfunc _leaf
arg:\tdw\t0
"""


def test_a_return_address_moved_by_ex_sp_hl(tmp_path_factory):
    d = build_dir(tmp_path_factory, 'cpop', CALLEE_POPS)
    img = Image(d, 'cpop')
    mid, leaf = img.addr('_mid'), img.addr('_leaf')
    states, _ = img.walker.depths(mid, leaf)
    # pop hl takes the return address (in HL, the old slot 2 below SP);
    # ex (sp),hl puts it back at the top of the stack
    assert states[mid + 1] == ('HL', -2)
    assert states[mid + 2] == 0
    # In _leaf, called from _mid: SP = FEFE holds lback, FF00 holds mback
    # (the argument's slot), and FEFC still holds a stale copy of lback.
    img.put(0xFEFC, img.addr('lback'))
    img.put(0xFEFE, img.addr('lback'))
    img.put(0xFF00, img.addr('mback'))
    chain = img.walker.walk(leaf, 0xFEFE, None)
    assert [f[0] for f in chain][:3] == [leaf, img.addr('lback'), img.addr('mback')], chain
    assert [f[2] for f in chain[:3]] == ['frame', 'frame', 'frame']


def test_live_callee_pops_frames_equal_shadow(cpmemu, tmp_path_factory):
    d = build_dir(tmp_path_factory, 'cpop_live', CALLEE_POPS)
    stops, tags = compare_sources(cpmemu, d, 'cpop_live', '*0x100', 'stepi', 14)
    assert stops >= 10
    assert tags == {'frame'}
