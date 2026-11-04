"""dbg2elf and the GDB Python unwinder, against a real GDB and cpmemu.

Each test builds a program with um80 and ul80 (--debug-info), turns prog.dbg
into prog.elf with dbg2elf, starts `cpmemu --gdb` and runs GDB in batch mode
against the stub.  The programs:

  a. tools/dbg2elf_proto/sumto.mac: break, continue, step, next, finish, bt,
     print of a static variable and a run to the end
  b. a program with an inlined call: break on the call line, step into the
     inlined body, bt with the inline frame, step out.  A hand-written .mac
     with the markers that uc80 writes, and (when uc80 is installed) a C
     program that `uc80 -g` compiles
  c. a recursive program: bt through the Python unwinder shows the depth
     that `monitor bt` shows, from the shadow stack and from the frame
     records of prog.dbg

GDB must have the z80 target (docs/gdb.md has the build).  It comes from
$UDB80_GDB, then z80-unknown-elf-gdb and gdb on PATH.  cpmemu comes from $CPMEMU as in test_udb80.py.  A
missing GDB or cpmemu skips the live tests with the reason.
UDB80_REQUIRE_GDB=1 (and UDB80_REQUIRE_CPMEMU=1, UDB80_REQUIRE_UC80=1) turn
the skip into a failure, so that a CI job that must have the tool cannot
pass without it.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMTO = os.path.join(ROOT, 'tools', 'dbg2elf_proto')
UNWINDER = os.path.join(ROOT, 'um80', 'gdb', 'udb80_unwind.py')


def _skip(reason, require_var):
    if os.environ.get(require_var) == '1':
        pytest.fail('%s (%s=1 turns the skip into a failure)' % (reason, require_var))
    pytest.skip(reason)


def _has_z80(path):
    """True when GDB accepts `set architecture z80` and has Python."""
    try:
        run = subprocess.run([path, '-batch', '-nx', '-ex', 'set architecture z80',
                              '-ex', 'python print("py-ok")'],
                             capture_output=True, text=True, timeout=60,
                             stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    out = run.stdout + run.stderr
    return 'Undefined' not in out and 'py-ok' in out


@pytest.fixture(scope='session')
def gdb_path():
    cands = [os.environ.get('UDB80_GDB'), shutil.which('z80-unknown-elf-gdb'),
             shutil.which('gdb')]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK) and _has_z80(c):
            return c
    _skip('no GDB with the z80 target: set UDB80_GDB, or build GDB 18.1 as '
          'docs/gdb.md says', 'UDB80_REQUIRE_GDB')


def _find_cpmemu():
    cands = [os.environ.get('CPMEMU'),
             os.path.join(os.path.dirname(ROOT), 'cpmemu', 'src', 'cpmemu'),
             os.path.expanduser('~/src/cpmemu/src/cpmemu'),
             shutil.which('cpmemu')]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


@pytest.fixture(scope='session')
def cpmemu():
    path = _find_cpmemu()
    if path is None:
        _skip('no cpmemu binary: set CPMEMU, build ~/src/cpmemu/src/cpmemu '
              '(make -C src), or put cpmemu on PATH', 'UDB80_REQUIRE_CPMEMU')
    try:
        run = subprocess.run([path], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL, timeout=20)
        has = '--gdb' in run.stdout + run.stderr
    except (OSError, subprocess.SubprocessError):
        has = False
    if not has:
        _skip('%s has no --gdb option; build a cpmemu from 2026-11-04 or later' % path,
              'UDB80_REQUIRE_CPMEMU')
    return path


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

def run_tool(module, *args, cwd):
    env = dict(os.environ, PYTHONPATH=ROOT)
    run = subprocess.run([sys.executable, '-m', module, *args], cwd=cwd, env=env,
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    return run


def build(d, name, libs=()):
    run_tool('um80.um80', '--debug-info', '-o', name + '.rel', name + '.mac', cwd=d)
    run_tool('um80.ul80', '--debug-info', '-o', name + '.com', name + '.rel',
             *libs, cwd=d)
    run_tool('um80.dbg2elf', name + '.dbg', '-o', name + '.elf', cwd=d)


@pytest.fixture(scope='module')
def sumto(tmp_path_factory):
    d = tmp_path_factory.mktemp('sumto')
    for f in ('sumto.mac', 'sumto.c'):
        shutil.copy(os.path.join(SUMTO, f), d / f)
    build(str(d), 'sumto')
    return str(d)


INL_C = """\
static int sq(int x)
{
    return x + x;
}

int g = 5;
int total;

int main(void)
{
    int r;
    r = g + 1;
    r = sq(r);
    total = r + 1;
    return 0;
}
"""

# What uc80 -g writes for INL_C, with the multiply replaced by an add so that
# no runtime library is needed.
INL_MAC = """\
\t.z80
;#file 1 "inl.c"
;#func _main 1 9 frame=none pops=0
_main:
;#line 1 9
;#line 1 12
\tld\thl,(_g)
\tinc\thl
;#line 1 13
;#inline 1 13 sq
;#line 1 3
\tld\td,h
\tld\te,l
\tadd\thl,de
;#endinline
;#line 1 14
\tinc\thl
\tld\t(_total),hl
;#line 1 15
\tld\thl,0
;#line 1 16
\tjp\t0
;#endfunc _main
_g:\tdw\t5
_total:\tdw\t0
"""

# Recursion with a frame in IX, as uc80 writes it, and one without a frame.
REC_C = """\
int total;

int fill(int n)
{
    int buf[2];
    buf[0] = n;
    buf[1] = n + 1;
    if (n == 0)
        return buf[0];
    return buf[1] + fill(n - 1);
}

int sum(int n)
{
    if (n == 0)
        return 0;
    return n + sum(n - 1);
}

int main(void)
{
    total = sum(4);
    total = fill(3);
    return 0;
}
"""

REC_MAC = """\
\t.z80
;#file 1 "rec.c"
start:\tcall\t_main
\tjp\t0
;#func _fill 1 3 frame=ix pops=0
_fill:
;#line 1 3
\tpush\tix
\tld\tix,0
\tadd\tix,sp
\tpush\thl
\tld\tc,l
\tld\tb,h
\tld\thl,-4
\tadd\thl,sp
\tld\tsp,hl
;#line 1 8
\tld\ta,c
\tor\tb
\tjr\tnz,fill_more
;#line 1 9
\tld\thl,0
\tjr\tfill_ret
fill_more:
;#line 1 10
\tpush\thl
\tld\tl,c
\tld\th,b
\tdec\thl
\tcall\t_fill
\tpop\tde
\tadd\thl,de
fill_ret:
;#line 1 11
\tld\tsp,ix
\tpop\tix
\tret
;#endfunc _fill
;#func _sum 1 13 frame=none pops=0
_sum:
;#line 1 13
;#line 1 15
\tld\ta,l
\tor\th
\tjr\tnz,sum_more
;#line 1 16
\tld\thl,0
\tret
sum_more:
;#line 1 17
\tpush\thl
\tdec\thl
\tcall\t_sum
\tpop\tde
\tadd\thl,de
;#line 1 18
\tret
;#endfunc _sum
;#func _main 1 20 frame=none pops=0
_main:
;#line 1 20
;#line 1 22
\tld\thl,4
\tcall\t_sum
\tld\t(_total),hl
;#line 1 23
\tld\thl,3
\tcall\t_fill
\tld\t(_total),hl
;#line 1 24
\tld\thl,0
;#line 1 25
\tret
;#endfunc _main
_total:\tdw\t0
"""


def _write_rec(d):
    # The sum recursion is called from main; REC_C lines are the markers' lines.
    with open(os.path.join(d, 'rec.c'), 'w') as f:
        f.write(REC_C)
    with open(os.path.join(d, 'rec.mac'), 'w') as f:
        f.write(REC_MAC)


@pytest.fixture(scope='module')
def inl(tmp_path_factory):
    d = tmp_path_factory.mktemp('inl')
    (d / 'inl.c').write_text(INL_C)
    (d / 'inl.mac').write_text(INL_MAC)
    build(str(d), 'inl')
    return str(d)


@pytest.fixture(scope='module')
def rec(tmp_path_factory):
    d = tmp_path_factory.mktemp('rec')
    _write_rec(str(d))
    build(str(d), 'rec')
    return str(d)


def _uc80_libs():
    try:
        import uc80
    except ImportError:
        return None
    lib = os.path.join(os.path.dirname(uc80.__file__), 'lib')
    libs = [os.path.join(lib, 'libc.lib'), os.path.join(lib, 'runtime.lib')]
    return libs if all(os.path.exists(p) for p in libs) else None


@pytest.fixture(scope='module')
def uc80_programs(tmp_path_factory):
    """The C programs, compiled by `uc80 -g`.  Skips when uc80 is missing."""
    libs = _uc80_libs()
    if libs is None:
        _skip('uc80 is not installed (pip install uc80, or a checkout on '
              'PYTHONPATH) or its libraries are not built', 'UDB80_REQUIRE_UC80')
    d = str(tmp_path_factory.mktemp('uc80'))
    for name, text in (('inl', INL_C.replace('x + x', 'x * x')), ('rec', REC_C)):
        with open(os.path.join(d, name + '.c'), 'w') as f:
            f.write(text)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(
            [ROOT] + ([os.environ['PYTHONPATH']] if os.environ.get('PYTHONPATH') else [])))
        run = subprocess.run([sys.executable, '-m', 'uc80.main', name + '.c', '-g',
                              '-o', name + '.mac'], cwd=d, env=env,
                             capture_output=True, text=True)
        if run.returncode != 0:
            _skip('uc80 failed: ' + (run.stdout + run.stderr)[-300:], 'UDB80_REQUIRE_UC80')
        build(d, name, libs)
    return d


# ---------------------------------------------------------------------------
# Running GDB against cpmemu --gdb
# ---------------------------------------------------------------------------

def gdb_session(gdb_path, cpmemu, d, prog, commands, unwinder=True, timeout=120):
    """Run the commands in GDB against `cpmemu --gdb prog.com`.  Returns the
    output of GDB (warnings of GDB about the breakpoint type removed)."""
    port_file = os.path.join(d, prog + '.port')
    if os.path.exists(port_file):
        os.remove(port_file)
    emu = subprocess.Popen([cpmemu, '--gdb=0', '--gdb-port-file=' + port_file, prog + '.com'],
                           cwd=d, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            if os.path.exists(port_file) and os.path.getsize(port_file) > 0:
                break
            if emu.poll() is not None:
                raise AssertionError('cpmemu ended: ' + emu.stdout.read().decode())
            time.sleep(0.05)
        else:
            raise AssertionError('cpmemu wrote no port file')
        time.sleep(0.05)
        port = open(port_file).read().strip()
        data = os.path.join(os.path.dirname(gdb_path), 'data-directory')
        args = [gdb_path, '-batch', '-nx']
        if os.path.isdir(data):
            args.append('--data-directory=' + data)
        args += [prog + '.elf']
        if unwinder:
            args += ['-ex', 'source ' + UNWINDER]
        args += ['-ex', 'target remote :' + port]
        for c in commands:
            args += ['-ex', c]
        run = subprocess.run(args, cwd=d, capture_output=True, text=True, timeout=timeout,
                             stdin=subprocess.DEVNULL)
    finally:
        emu.kill()
        emu.wait()
        emu.stdout.close()
    out = run.stdout + run.stderr
    assert 'internal-error' not in out, out
    return '\n'.join(l for l in out.splitlines() if not l.startswith('warning:'))


def in_order(text, parts):
    pos = 0
    for p in parts:
        i = text.find(p, pos)
        assert i >= 0, 'missing or out of order: %r\n%s' % (p, text)
        pos = i + len(p)


def frames(text):
    """The lines '#N ...' of a bt, as (N, address or None, function)."""
    out = []
    for m in re.finditer(r'^#(\d+)\s+(?:0x([0-9a-f]+) in )?(\S+) \(', text, re.M):
        out.append((int(m.group(1)), int(m.group(2), 16) if m.group(2) else None, m.group(3)))
    return out


# ---------------------------------------------------------------------------
# a. sumto
# ---------------------------------------------------------------------------

def test_sumto_session(gdb_path, cpmemu, sumto):
    out = gdb_session(gdb_path, cpmemu, sumto, 'sumto', [
        'break sumto.c:14', 'continue', 'delete', 'step', 'bt', 'finish', 'bt',
        'break sumto.c:15', 'continue', 'print total', 'info line sumto.c:14',
        'continue'])
    in_order(out, [
        'Breakpoint 1 at 0x108: file sumto.c, line 14.',
        'Breakpoint 1, main () at sumto.c:14',
        'add () at sumto.c:6',
        '#0  add () at sumto.c:6',
        '#1  0x00000111 in main () at sumto.c:14',
        '0x00000111 in main () at sumto.c:14',
        '#0  0x00000111 in main () at sumto.c:14',
        'Breakpoint 2 at 0x11a: file sumto.c, line 15.',
        # the last marker of a merged group is the line GDB shows (rule D4)
        'Breakpoint 2, main () at sumto.c:16',
        '$1 = 10',
        'Line 14 of "sumto.c" starts at address 0x108 <main+8> and ends at 0x114 <main+20>.',
        '[Inferior 1 (Remote target) exited normally]'])


def test_sumto_next_steps_over_the_call(gdb_path, cpmemu, sumto):
    out = gdb_session(gdb_path, cpmemu, sumto, 'sumto', ['next', 'next', 'next', 'bt'])
    # Line 14 is the loop body.  The row of the loop increment (line 13) is
    # nostmt, so the loop back to line 14 is no new line for GDB and the third
    # next runs the loop to the end.  No stop is inside add.
    in_order(out, ['13\t    for', '14\t        total = add', '16\t}', '#0  main () at sumto.c:16'])
    assert 'add ()' not in out, out
    assert frames(out)[-1][2] == 'main', out


# ---------------------------------------------------------------------------
# b. an inlined call
# ---------------------------------------------------------------------------

def _inline_session(gdb_path, cpmemu, d, prog, start):
    # start: the commands that bring the program to line 12 (the line before
    # the call).  The stub does not report a breakpoint at the first
    # instruction, so the hand-written program starts there with no command.
    return gdb_session(gdb_path, cpmemu, d, prog, start + [
        'step',                      # to the call line: GDB hides the inline frame
        'bt',
        'step',                      # into the inlined body
        'bt',
        'info frame',
        'finish',                    # out of the inline frame
        'bt',
        'print total', 'continue'])


def _check_inline_session(out):
    in_order(out, [
        'inl.c:12',
        '13\t    r = sq(r);',
        '#0  main () at inl.c:13',
        'sq () at inl.c:3',
        '#0  sq () at inl.c:3',
        '#1  main () at inl.c:13',
        'inlined into frame 1',
        'main () at inl.c:14',
        '#0  main () at inl.c:14',
        '[Inferior 1 (Remote target) exited normally]'])


def test_inlined_call_hand_written(gdb_path, cpmemu, inl):
    out = _inline_session(gdb_path, cpmemu, inl, 'inl', [])
    _check_inline_session(out)


def test_inlined_call_breakpoint_on_the_call_line(gdb_path, cpmemu, inl):
    out = gdb_session(gdb_path, cpmemu, inl, 'inl', [
        'break inl.c:13', 'continue', 'bt', 'step', 'bt'])
    # the code of the call line starts with the inlined body, so GDB stops in
    # the inline frame and bt shows both frames
    in_order(out, ['Breakpoint 1 at 0x', 'inl.c, line 13', 'Breakpoint 1, sq () at inl.c:3',
                   '#0  sq () at inl.c:3', '#1  main () at inl.c:13',
                   'main () at inl.c:14'])


def test_inlined_call_uc80(gdb_path, cpmemu, uc80_programs):
    out = _inline_session(gdb_path, cpmemu, uc80_programs, 'inl',
                          ['break inl.c:12', 'continue', 'delete'])
    _check_inline_session(out)


# ---------------------------------------------------------------------------
# c. recursion
# ---------------------------------------------------------------------------

def _monitor_bt(text):
    """The return addresses that `monitor bt` printed, frame 0 first.  The
    stub writes 4 hex digits; bt of GDB writes 8."""
    return [int(m.group(1), 16) for m in
            re.finditer(r'^#\d+\s+0x([0-9A-Fa-f]{4})(?:\s|$)', text, re.M)]


def _first_bt(text):
    """The frames of the first bt: the run of '#N' lines that starts at '#0'
    with a function name."""
    lines = text.splitlines()
    for i, l in enumerate(lines):
        if re.match(r'#0  \S+ \(', l):
            j = i
            while j < len(lines) and re.match(r'#\d+ ', lines[j]):
                j += 1
            return frames('\n'.join(lines[i:j]))
    raise AssertionError('no bt in the output:\n' + text)


def _recursion(gdb_path, cpmemu, d, prog, line, func, depth, mode):
    out = gdb_session(gdb_path, cpmemu, d, prog, [
        'udb80-unwind-mode ' + mode,
        'break rec.c:%d' % line, 'continue', 'bt', 'monitor bt', 'udb80-unwind-info',
        'up', 'finish'])
    bt = _first_bt(out)
    assert [f for _n, _a, f in bt].count(func) == depth, out
    assert bt[-1][2] == 'main', out
    assert [n for n, _a, _f in bt] == list(range(len(bt))), out
    mon = _monitor_bt(out)
    # each caller frame of bt has the return address of the stub
    for n, addr, _f in bt[1:]:
        assert addr == mon[n], (n, hex(addr), [hex(m) for m in mon], out)
    # the stub has one more entry: the call of main by the start-up code
    assert len(mon) == len(bt) + 1, out
    info = out[out.index('prog.dbg:'):]
    how = re.findall(r'^level \d+ pc [0-9a-f]+ sp [0-9a-f]+ \[(\w+)\]', info, re.M)
    assert len(how) >= len(bt), out
    return out, how[-len(bt):]


@pytest.mark.parametrize('mode,source', [('auto', 'shadow'), ('records', 'frame')])
def test_recursion_without_frame(gdb_path, cpmemu, rec, mode, source):
    # rec.c:16 is the base case of sum; sum is called 5 times
    out, how = _recursion(gdb_path, cpmemu, rec, 'rec', 16, 'sum', 5, mode)
    assert set(how) == {source}, how


@pytest.mark.parametrize('mode,source', [('auto', 'shadow'), ('records', 'frame')])
def test_recursion_with_ix_frame(gdb_path, cpmemu, rec, mode, source):
    # rec.c:9 is the base case of fill; fill is called 4 times
    out, how = _recursion(gdb_path, cpmemu, rec, 'rec', 9, 'fill', 4, mode)
    assert set(how) == {source}, how


def test_python_unwinder_claims_the_frames(gdb_path, cpmemu, rec):
    """With the unwinder loaded, `udb80-unwind-info` lists the caller frame as
    made from the shadow call stack: the Python unwinder produced the frame."""
    cmds = ['break rec.c:16', 'continue', 'info frame 2']
    with_u = gdb_session(gdb_path, cpmemu, rec, 'rec', cmds + ['udb80-unwind-info'])
    assert re.search(r'^level 2 pc [0-9a-f]+ sp [0-9a-f]+ \[shadow\]', with_u, re.M), with_u


def test_recursion_uc80(gdb_path, cpmemu, uc80_programs):
    out = gdb_session(gdb_path, cpmemu, uc80_programs, 'rec', [
        'break rec.c:16', 'continue', 'bt', 'monitor bt', 'udb80-unwind-info'])
    bt = _first_bt(out)
    assert [f for _n, _a, f in bt].count('sum') == 5, out
    assert bt[-1][2] == 'main', out
    mon = _monitor_bt(out)
    for n, addr, _f in bt[1:]:
        assert addr == mon[n], out
    assert re.findall(r'\[(\w+)\]', out[out.index('prog.dbg:'):]).count('shadow') == len(bt), out


@pytest.mark.parametrize('stop,steps', [('*fill', 11), ('rec.c:11', 4), ('rec.c:17', 5)])
def test_frame_records_agree_with_the_shadow_stack_at_every_instruction(
        gdb_path, cpmemu, rec, stop, steps):
    """The IX frame is not set up in the prologue and is gone at the RET; the
    records path decodes both.  bt from the frame records equals bt from the
    shadow call stack at each instruction of the prologue, of the epilogue and
    of a frameless routine with pushes."""
    cmds = ['break ' + stop, 'continue', 'delete'] + ['bt', 'stepi'] * steps + [
        'bt', 'udb80-unwind-info']
    runs = {}
    for mode in ('auto', 'records'):
        out = gdb_session(gdb_path, cpmemu, rec, 'rec', ['udb80-unwind-mode ' + mode] + cmds)
        runs[mode] = frames(out)
        assert len(runs[mode]) > steps, out
        how = re.findall(r'^level \d+ pc [0-9a-f]+ sp [0-9a-f]+ \[(\w+)\]', out, re.M)
        # every frame came from the source that the mode names (the log keeps
        # the last 50 frames)
        assert set(how) == {'shadow' if mode == 'auto' else 'frame'}, (mode, how, out)
    assert runs['auto'] == runs['records'], runs
