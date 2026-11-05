"""udb80: the prog.dbg reader, addr2line, sizes and the live commands.

The static tests build a prog.dbg with um80 --debug-info and ul80
--debug-info from tools/dbg2elf_proto/sumto.mac, and check the output of
`udb80 addr2line` and `udb80 sizes` against text written by hand.

The live tests run a real `cpmemu --gdb` and drive it with udb80 in batch
mode.  cpmemu comes from $CPMEMU, then ../cpmemu/src/cpmemu next to this
repository, then PATH.  When no cpmemu is found the live tests skip with the
reason.  UDB80_REQUIRE_CPMEMU=1 turns that skip into a failure, so that a CI
job that must have cpmemu cannot pass without one.
"""

# pytest fixtures are parameters with the name of the fixture function.
# pylint: disable=redefined-outer-name
# The test names say what each test checks.
# pylint: disable=missing-function-docstring
import os
import shutil
import subprocess
import time
import sys

import pytest

from um80 import udb80

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMTO = os.path.join(ROOT, 'tools', 'dbg2elf_proto')

# Assembler only: no ;# markers, so the debugger works on the .mac lines.
RECURSE = """\
\t.z80
start:\tld\tb,3
\tcall\trec
\tjp\t0
rec:\tdec\tb
\tjr\tz,bottom
\tcall\trec
\tret
bottom:\tret
"""


def _run(module, *args, cwd):
    env = dict(os.environ, PYTHONPATH=ROOT)
    run = subprocess.run([sys.executable, '-m', module, *args], cwd=cwd,
                         env=env, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    return run


def _build(d, name):
    _run('um80.um80', '--debug-info', '-o', name + '.rel', name + '.mac', cwd=d)
    _run('um80.ul80', '--debug-info', '-o', name + '.com', name + '.rel', cwd=d)


# Routine records from ;#func markers.
FUNCS = """\
\t.z80
;#file 1 "t.c"
;#func _main 1 1 frame=none
;#line 1 2
_main:\tcall\t_f
\tjp\t0
;#endfunc _main
;#func _f 1 5
;#line 1 6
_f:\tnop
\tnop
\tret
;#endfunc _f
"""


@pytest.fixture(scope='module')
def sumto(tmp_path_factory):
    d = tmp_path_factory.mktemp('sumto')
    for f in ('sumto.mac', 'sumto.c'):
        shutil.copy(os.path.join(SUMTO, f), d / f)
    _build(d, 'sumto')
    return d


@pytest.fixture(scope='module')
def funcs(tmp_path_factory):
    d = tmp_path_factory.mktemp('funcs')
    (d / 'fn.mac').write_text(FUNCS)
    _build(d, 'fn')
    return d


@pytest.fixture(scope='module')
def recurse(tmp_path_factory):
    d = tmp_path_factory.mktemp('recurse')
    (d / 'rec.mac').write_text(RECURSE)
    _build(d, 'rec')
    return d


def udb(*args, cwd=None, check=True):
    env = dict(os.environ, PYTHONPATH=ROOT)
    run = subprocess.run([sys.executable, '-m', 'um80.udb80', *args], cwd=cwd,
                         env=env, capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, timeout=120)
    if check:
        assert run.returncode == 0, run.stdout + run.stderr
    return run


# ---------------------------------------------------------------------------
# Static: addr2line, sizes, the D9 check
# ---------------------------------------------------------------------------

def test_addr2line_golden(sumto):
    out = udb('addr2line', 'sumto.dbg', '0x100', '0x108', '0x10e', '0x120',
              '0x121', '288', cwd=sumto).stdout
    assert out == (
        '0x0100  _MAIN  sumto.c:12  [asm sumto.mac:5]\n'
        '0x0108  LOOP  sumto.c:14  [asm sumto.mac:11]\n'
        '0x010e  LOOP+6  sumto.c:14  [asm sumto.mac:14]\n'
        '0x0120  _ADD  sumto.c:6  [asm sumto.mac:28]\n'
        '0x0121  _ADD+1  sumto.c:7  [asm sumto.mac:30]\n'
        '0x0120  _ADD  sumto.c:6  [asm sumto.mac:28]\n')
    # An address with no label and no line: ??, and exit status 1.
    run = udb('addr2line', 'sumto.dbg', '0x50', cwd=sumto, check=False)
    assert (run.returncode, run.stdout) == (1, '0x0050  ??  ??:0\n')


def test_addr2line_return_address_and_asm(sumto):
    # A return address points after the CALL: -r looks at the CALL itself.
    out = udb('addr2line', '-r', 'sumto.dbg', '0x111', cwd=sumto).stdout
    assert out == '0x0111  LOOP+8  sumto.c:14  [asm sumto.mac:14]\n'
    out = udb('addr2line', '--asm', 'sumto.dbg', '0x108', cwd=sumto).stdout
    assert out == '0x0108  LOOP  sumto.mac:11  [asm]\n'


def test_addr2line_merged_group_primary_line(sumto):
    # The group 15, 16 at 0x11a has line 16 as its primary line (D4).
    out = udb('addr2line', 'sumto.dbg', '0x11a', cwd=sumto).stdout
    assert out.split()[2] == 'sumto.c:16'


def test_sizes_golden(sumto):
    out = udb('sizes', 'sumto.dbg', cwd=sumto).stdout
    assert out == ('    24  0108  LOOP\n'
                   '     8  0100  _MAIN\n'
                   '     2  0120  _ADD\n'
                   '    34  total in 3 routines\n')


def test_func_records_name_the_routines(funcs):
    assert udb('sizes', 'fn.dbg', cwd=funcs).stdout == (
        '     6  0100  _main\n     3  0106  _f\n     9  total in 2 routines\n')
    out = udb('addr2line', 'fn.dbg', '0x100', '0x108', cwd=funcs).stdout
    assert out == ('0x0100  _main  t.c:2  [asm fn.mac:5]\n'
                   '0x0108  _f+2  t.c:6  [asm fn.mac:12]\n')


def test_refuses_a_stale_dbg(sumto, tmp_path):
    for f in ('sumto.dbg', 'sumto.com'):
        shutil.copy(sumto / f, tmp_path / f)
    data = bytearray((tmp_path / 'sumto.com').read_bytes())
    data[40] ^= 0xFF
    (tmp_path / 'sumto.com').write_bytes(bytes(data))
    run = udb('sizes', 'sumto.dbg', cwd=tmp_path, check=False)
    assert run.returncode == 2
    assert 'does not match' in run.stderr and 'stale' in run.stderr


def test_break_on_a_line_without_code_says_so(cpmemu, sumto):
    out = live(cpmemu, sumto, 'sumto', 'break sumto.c:9').stdout
    assert 'Line 9 has no code; using line 12.' in out


def test_line_addrs_rules(sumto):
    dbg = udb80.DebugInfo(str(sumto / 'sumto.dbg'))
    assert dbg.line_addrs('sumto.c', 14) == ([0x108], 14)
    # Line 15 and 16 are one group at one address.
    assert dbg.line_addrs('sumto.c', 15) == ([0x11a], 15)
    assert dbg.line_addrs('sumto.c', 16) == ([0x11a], 16)
    # Line 13 has a step point (0x106) and a nostmt copy (0x114): only the
    # step point takes a breakpoint (D4).
    assert dbg.line_addrs('sumto.c', 13) == ([0x106], 13)
    # Line 9 has no code: the next line with code is used.
    assert dbg.line_addrs('sumto.c', 9) == ([0x100], 12)
    with pytest.raises(udb80.UdbError):
        dbg.line_addrs('nosuch.c', 1)


def test_parse_stop():
    assert udb80.parse_stop('T05swbreak:;').kind == 'break'
    assert udb80.parse_stop('T05').kind == 'step'
    assert udb80.parse_stop('T02').kind == 'int'
    e = udb80.parse_stop('W01')
    assert (e.kind, e.code) == ('exit', 1)
    assert udb80.parse_stop('X0f').kind == 'signal'


# ---------------------------------------------------------------------------
# Live: cpmemu --gdb
# ---------------------------------------------------------------------------

def _find_cpmemu():
    cands = [os.environ.get('CPMEMU'),
             os.path.join(os.path.dirname(ROOT), 'cpmemu', 'src', 'cpmemu'),
             os.path.expanduser('~/src/cpmemu/src/cpmemu'),
             shutil.which('cpmemu')]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


@pytest.fixture(scope='module')
def cpmemu():
    path = _find_cpmemu()
    if path is None:
        reason = ('no cpmemu binary: set CPMEMU, build ~/src/cpmemu/src/cpmemu '
                  '(make -C src), or put cpmemu on PATH')
        if os.environ.get('UDB80_REQUIRE_CPMEMU') == '1':
            pytest.fail(reason + ' (UDB80_REQUIRE_CPMEMU=1 turns the skip into a failure)')
        pytest.skip(reason)
    try:
        help_text = subprocess.run([path], capture_output=True, text=True,
                                   stdin=subprocess.DEVNULL, timeout=20)
        has_gdb = '--gdb' in help_text.stdout + help_text.stderr
    except (OSError, subprocess.SubprocessError):
        has_gdb = False
    if not has_gdb:
        reason = f'{path} has no --gdb option; build a cpmemu from 2026-11-04 or later'
        if os.environ.get('UDB80_REQUIRE_CPMEMU') == '1':
            pytest.fail(reason)
        pytest.skip(reason)
    return path


def live(cpmemu, d, prog, *commands):
    args = ['--batch', prog + '.dbg', '--run', f'{cpmemu} {prog}.com']
    for c in commands:
        args += ['-ex', c]
    return udb(*args, cwd=d)


def in_order(text, parts):
    pos = 0
    for p in parts:
        i = text.find(p, pos)
        assert i >= 0, f'missing or out of order: {p!r}\n{text}'
        pos = i + len(p)


def test_live_sumto_session(cpmemu, sumto):
    out = live(cpmemu, sumto, 'sumto',
               'break sumto.c:14', 'continue', 'step', 'next', 'finish', 'bt',
               'print total', 'delete', 'continue').stdout
    in_order(out, [
        'Breakpoint 1 at 0x0108: file sumto.c, line 14.',
        'Breakpoint 1, LOOP () at sumto.c:14',
        '14\t        total = add(total, i);',
        '_ADD () at sumto.c:6',                      # step enters the call
        '6\t    return a + b;',
        '7\t}',                                       # next
        'Run till exit from #0  _ADD () at sumto.c:7',
        '0x0111 in LOOP () at sumto.c:14',            # finish
        '#0  0x0111 in LOOP () at sumto.c:14  [shadow]',
        '$1 = 0',                                     # total, before the store
        '[Program exited normally]'])
    assert '#1' not in out.split('Run till exit')[1].split('$1')[0]


def test_live_next_steps_over_the_call(cpmemu, sumto):
    out = live(cpmemu, sumto, 'sumto',
               'break sumto.c:14', 'continue', 'next', 'print total', 'bt',
               'next', 'next', 'print total', 'info registers pc').stdout
    in_order(out, [
        'Breakpoint 1, LOOP () at sumto.c:14',
        '14\t        total = add(total, i);',          # next: the nostmt line is
        '$1 = 1',                                       # skipped, the loop comes back
        '#0  LOOP () at sumto.c:14  [shadow]',
        '$2 = 6'])
    assert 'sumto.c:6' not in out        # next never showed the callee


def test_live_other_commands(cpmemu, sumto):
    out = live(cpmemu, sumto, 'sumto',
               'tbreak sumto.c:15', 'continue', 'info breakpoints', 'stepi',
               'list sumto.c:15', 'x/2xb &total', 'print &total',
               'info symbols _add', 'disassemble 0x11a,0x120',
               'continue').stdout
    in_order(out, [
        'Temporary breakpoint 1 at 0x011a: file sumto.c, line 15.',
        'Temporary breakpoint 1, LOOP () at sumto.c:16',   # primary line of 15,16
        'No breakpoints or watchpoints.',
        '0x011d in LOOP () at sumto.c:16',
        '10\t{', '15\t    return 0;', '16\t}',
        '0x0122 <_TOTAL>:\t0x0a\t0x00',
        '$1 = 0x0122 <_TOTAL>',
        '_ADD in the program',
        '0x011a <LOOP+18>:\tLD HL,0000H',
        '[Program exited normally]'])


def test_live_connect_mode(cpmemu, sumto):
    port = sumto / 'port.txt'
    if port.exists():
        port.unlink()
    proc = subprocess.Popen([cpmemu, '--gdb=0', f'--gdb-port-file={port}',
                             'sumto.com'], cwd=sumto, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        import time
        for _ in range(500):
            if port.exists() and port.read_text().strip():
                break
            time.sleep(0.02)
        out = udb('--batch', 'sumto.dbg', '--connect',
                  f'127.0.0.1:{port.read_text().strip()}',
                  '-ex', 'break _add', '-ex', 'continue', '-ex', 'bt',
                  '-ex', 'continue', cwd=sumto).stdout
        in_order(out, ['Breakpoint 1, _ADD () at sumto.c:6',
                       '#1  0x0111 in LOOP () at sumto.c:14  [shadow]',
                       'Breakpoint 1, _ADD () at sumto.c:6'])
    finally:
        proc.kill()
        proc.wait()


def test_live_command_file(cpmemu, sumto):
    (sumto / 'cmds.txt').write_text('# a comment\nbreak _add\ncontinue\nbt\n')
    out = udb('--batch', 'sumto.dbg', '--run', f'{cpmemu} sumto.com',
              '-x', 'cmds.txt', cwd=sumto).stdout
    in_order(out, ['Breakpoint 1 at 0x0120', 'Breakpoint 1, _ADD ()', '#1  0x0111'])


def test_live_recursive_assembler(cpmemu, recurse):
    out = live(cpmemu, recurse, 'rec',
               'break rec.mac:9', 'continue', 'bt').stdout
    in_order(out, [
        'Breakpoint 1 at 0x0',
        'Breakpoint 1, BOTTOM () at rec.mac:9',
        '#0  BOTTOM () at rec.mac:9  [shadow]',
        '#1  0x', 'in REC () at rec.mac:7  [shadow]',
        '#2  0x', 'in REC () at rec.mac:7  [shadow]',
        '#3  0x', 'in START () at rec.mac:3  [shadow]'])
    assert '#4' not in out


def test_live_recursive_step_and_next(cpmemu, recurse):
    out = live(cpmemu, recurse, 'rec',
               'break rec.mac:5', 'continue', 'step', 'step', 'step', 'bt',
               'delete', 'break rec.mac:7', 'continue').stdout
    in_order(out, [
        'Breakpoint 1, REC () at rec.mac:5',
        '6\t', '7\t',                     # step goes line by line
        '5\trec:',                        # and into the recursive call
        '#0  REC () at rec.mac:5  [shadow]',
        '#1  0x', 'in REC () at rec.mac:7  [shadow]',
        '#2  0x', 'in START () at rec.mac:3  [shadow]'])


def test_live_recursive_next_counts_only_its_own_depth(cpmemu, recurse):
    # next at line 7 runs over a call that recurses two deeper.  The return
    # address is reached by the deeper returns first; only the return at the
    # original depth counts.
    out = live(cpmemu, recurse, 'rec',
               'break rec.mac:7', 'continue', 'delete', 'next', 'bt').stdout
    in_order(out, [
        'Breakpoint 1, REC () at rec.mac:7',
        '8\t\tret',
        '#0  REC () at rec.mac:8  [shadow]',
        '#1  0x', 'in START () at rec.mac:3  [shadow]'])
    assert '#2' not in out


LONGJMP = """\
\t.z80
start:\tcall\touter
\tnop
\tjp\t0
outer:\tcall\tfa
\tnop
\tret
fa:\tcall\tfb
\tret
fb:\tpop\thl
\tpop\thl
\tret
"""


@pytest.fixture(scope='module')
def longjmp(tmp_path_factory):
    d = tmp_path_factory.mktemp('longjmp')
    (d / 'lj.mac').write_text(LONGJMP)
    _build(d, 'lj')
    return d


def test_live_next_stops_when_the_frame_unwinds_early(cpmemu, longjmp):
    # fb drops two return addresses and returns straight into start, so the
    # return address of "call fa" is never reached.  next must stop in start.
    out = live(cpmemu, longjmp, 'lj',
               'break lj.mac:5', 'continue', 'next', 'bt').stdout
    assert 'exited' not in out, out
    in_order(out, ['Breakpoint 1, OUTER () at lj.mac:5',
                   '#0  START () at lj.mac:3  [shadow]'])
    assert '#1' not in out


def test_live_finish_stops_when_the_frame_unwinds_early(cpmemu, longjmp):
    out = live(cpmemu, longjmp, 'lj',
               'break lj.mac:11', 'continue', 'finish', 'bt').stdout
    assert 'exited' not in out, out
    assert '#0  START () at lj.mac:3  [shadow]' in out


def test_live_refuses_a_different_program_in_memory(cpmemu, sumto, tmp_path):
    (tmp_path / 'other.mac').write_text('\t.z80\n\tnop\n\tjp\t0\n')
    _build(tmp_path, 'other')
    run = udb('--batch', 'sumto.dbg', '--run', f"{cpmemu} {tmp_path / 'other.com'}",
              '-ex', 'continue', cwd=sumto, check=False)
    assert run.returncode == 2, run.stdout + run.stderr
    assert 'guest memory at 0x0100 does not match' in run.stderr


def test_live_user_breakpoint_stops_next(cpmemu, recurse):
    out = live(cpmemu, recurse, 'rec',
               'break rec.mac:7', 'continue', 'next', 'bt').stdout
    in_order(out, [
        'Breakpoint 1, REC () at rec.mac:7',
        'Breakpoint 1, REC () at rec.mac:7',     # the callee hit the breakpoint
        '#0  REC () at rec.mac:7  [shadow]',
        '#1  0x', '#2  0x'])
    assert '#3' not in out


def test_live_routine_names_from_func_records(cpmemu, funcs):
    out = live(cpmemu, funcs, 'fn', 'break _f', 'continue', 'bt',
               'disassemble').stdout
    in_order(out, ['Breakpoint 1, _f () at t.c:6',
                   '#1  0x0103 in _main () at t.c:2  [shadow]',
                   '=> 0x0106 <_f>:\tNOP', '0x0108 <_f+2>:\tRET'])


def test_live_without_a_shadow_stack(cpmemu, sumto, recurse):
    # "set shadow off" acts as a stub with no shadow stack, as GDB's
    # stubs and z80fpga are: next uses SP, bt uses the frame records ([frame]).
    out = live(cpmemu, sumto, 'sumto', 'set shadow off', 'break sumto.c:14',
               'continue', 'next', 'print total', 'step', 'bt').stdout
    in_order(out, ['Breakpoint 1, LOOP () at sumto.c:14',
                   '14\t        total = add(total, i);', '$1 = 1',
                   '_ADD () at sumto.c:6',
                   '#0  _ADD () at sumto.c:6  [frame]',
                   '#1  0x0111 in LOOP () at sumto.c:14  [frame]'])
    out = live(cpmemu, recurse, 'rec', 'set shadow off', 'break rec.mac:7',
               'continue', 'delete', 'next').stdout
    in_order(out, ['Breakpoint 1, REC () at rec.mac:7', '8\t\tret'])


# --- romwbw_emu: a program that CP/M starts from a disk image ---------------
#
# romwbw_emu does not load the program; CP/M does.  udb80 --wait-program
# asks the stub to stop at 0100H in bank 8EH when the bytes there have the
# length and SHA-256 of the image in prog.dbg.  Needs romwbw_emu built with
# its stub (~/src/romwbw_emu or ROMWBW_EMU), the cached 3.6.0 ROM and
# hd1k_cpm22 disk, and cpmemu's util/cpm_disk.py.  Skips with the reason;
# UDB80_REQUIRE_ROMWBW=1 turns the skip into a failure.

ROMWBW_PROG = """\
\t.z80
start:\tld\tc,9
\tld\tde,msg
\tcall\t5
\tcall\touter
\tjp\t0
outer:\tcall\tinner
\tret
inner:\tld\ta,5
\tinc\ta
\tret
msg:\tdb\t'WAITED',13,10,'$'
"""


@pytest.fixture(scope='module')
def romwbw():
    home = os.path.expanduser('~')
    emu = os.environ.get('ROMWBW_EMU') or os.path.join(home, 'src', 'romwbw_emu', 'src', 'romwbw_emu')
    assets = os.path.join(home, '.cache', 'romwbw_emu', 'v0', '3.6.0', 'assets')
    rom = os.path.join(assets, 'emu_avw-v0-3.6.0.rom')
    disk = os.path.join(assets, 'hd1k_cpm22-v0-3.6.0.img')
    cpm_disk = os.environ.get('CPM_DISK') or os.path.join(home, 'src', 'cpmemu', 'util', 'cpm_disk.py')
    for path, what in ((emu, 'romwbw_emu'), (rom, 'the 3.6.0 ROM'), (disk, 'the hd1k_cpm22 disk'),
                       (cpm_disk, 'cpm_disk.py')):
        if not os.path.isfile(path):
            reason = f'no {what} at {path}'
            if os.environ.get('UDB80_REQUIRE_ROMWBW') == '1':
                pytest.fail(reason + ' (UDB80_REQUIRE_ROMWBW=1)')
            pytest.skip(reason)
    return emu, rom, disk, cpm_disk


class _FakeStub:
    """A stub on 127.0.0.1 that answers the packets of a --wait-program
    session: qSupported, ?, qRcmd, c (with the reply under test), g, m, k.
    Guest memory is the program at 0100H and zeros elsewhere."""

    def __init__(self, com_bytes, stop_reply, stop_pc=0x100):
        import socket
        import threading
        self.mem = bytearray(65536)
        self.mem[0x100:0x100 + len(com_bytes)] = com_bytes
        self.stop_reply = stop_reply
        self.pc = 0
        self.stop_pc = stop_pc
        self.packets = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _answer(self, pkt):
        self.packets.append(pkt)
        if pkt.startswith('qSupported'):
            return 'PacketSize=1000;swbreak+'
        if pkt == '?':
            return 'S05'
        if pkt.startswith('qRcmd,'):
            text = bytes.fromhex(pkt[6:]).decode()
            if text.startswith('wait-program'):
                return 'wait-program: armed\n'.encode().hex()
            return ''
        if pkt == 'c':
            self.pc = self.stop_pc
            return self.stop_reply
        if pkt == 'g':
            regs = [0, 0, 0, 0, 0xFFF0, self.pc] + [0] * 7
            return ''.join('%02x%02x' % (r & 255, r >> 8) for r in regs)
        if pkt.startswith('p'):
            n = int(pkt[1:], 16)
            v = self.pc if n == 5 else 0
            return '%02x%02x' % (v & 255, v >> 8)
        if pkt.startswith('m'):
            addr, n = (int(x, 16) for x in pkt[1:].split(','))
            return bytes(self.mem[addr:addr + n]).hex()
        if pkt in ('k', 'D'):
            return None
        return ''

    def _serve(self):
        conn, _ = self.listener.accept()
        buf = b''
        with conn:
            while True:
                while b'#' not in buf or len(buf) < buf.index(b'#') + 3:
                    data = conn.recv(4096)
                    if not data:
                        return
                    buf += data
                start = buf.index(b'$')
                end = buf.index(b'#', start)
                pkt = buf[start + 1:end].decode('latin-1')
                buf = buf[end + 3:]
                conn.sendall(b'+')
                reply = self._answer(pkt)
                if reply is None:
                    conn.sendall(b'$OK#9a')
                    return
                body = reply.encode('latin-1')
                conn.sendall(b'$' + body + b'#%02x' % (sum(body) & 255))


@pytest.mark.parametrize('stop_reply', ['T05swbreak:;', 'T05'])
def test_wait_program_takes_either_stop_reply(tmp_path, stop_reply):
    # cpmemu's stub before 2026-11-05 sent T05swbreak for the rule's stop.
    # The stub after sends T05, because GDB set no breakpoint there and
    # continues past a swbreak it did not ask for.  udb80 takes both.
    d = str(tmp_path)
    with open(os.path.join(d, 'wp.mac'), 'w') as f:
        f.write(ROMWBW_PROG)
    _build(d, 'wp')
    com = open(os.path.join(d, 'wp.com'), 'rb').read()
    stub = _FakeStub(com, stop_reply)
    out = udb('--batch', 'wp.dbg', '--connect', '127.0.0.1:%d' % stub.port, '--wait-program',
              cwd=d).stdout
    assert 'The program has started at 0x0100.' in out
    assert any(p.startswith('qRcmd,') and bytes.fromhex(p[6:]).startswith(b'wait-program sha256 ')
               for p in stub.packets)


def test_wait_program_refuses_a_stop_elsewhere(tmp_path):
    d = str(tmp_path)
    with open(os.path.join(d, 'wp.mac'), 'w') as f:
        f.write(ROMWBW_PROG)
    _build(d, 'wp')
    com = open(os.path.join(d, 'wp.com'), 'rb').read()
    stub = _FakeStub(com, 'T05', stop_pc=0x0234)
    r = udb('--batch', 'wp.dbg', '--connect', '127.0.0.1:%d' % stub.port, '--wait-program',
            cwd=d, check=False)
    assert r.returncode != 0
    assert 'not at the start of the program' in r.stdout + r.stderr


def test_live_wait_program_under_romwbw(romwbw, tmp_path):
    emu, rom, disk, cpm_disk = romwbw
    d = str(tmp_path)
    with open(os.path.join(d, 'wp.mac'), 'w') as f:
        f.write(ROMWBW_PROG)
    _build(d, 'wp')
    img = os.path.join(d, 'disk.img')
    shutil.copyfile(disk, img)
    subprocess.run([sys.executable, cpm_disk, 'add', '--slice', '0', img,
                    os.path.join(d, 'wp.com')], check=True, stdout=subprocess.DEVNULL)
    portfile = os.path.join(d, 'port')
    proc = subprocess.Popen([emu, '--romwbw=' + rom, '--disk0=' + img, '--boot=2',
                             '--no-config', '--max-instructions=0', '--gdb=0',
                             '--gdb-port-file=' + portfile],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    try:
        for _ in range(600):
            if os.path.exists(portfile) and open(portfile).read().endswith('\n'):
                break
            time.sleep(0.05)
        port = open(portfile).read().strip()
        if not port:
            reason = f'{emu} gave no port: built without its GDB stub?'
            if os.environ.get('UDB80_REQUIRE_ROMWBW') == '1':
                pytest.fail(reason)
            pytest.skip(reason)
        proc.stdin.write(b'WP\r')
        proc.stdin.close()
        out = udb('--batch', 'wp.dbg', '--connect', '127.0.0.1:' + port, '--wait-program',
                  '-ex', 'break inner', '-ex', 'continue', '-ex', 'bt', '-ex', 'continue',
                  cwd=d).stdout
        in_order(out, [
            'Waiting for the program (',
            'The program has started at 0x0100.',
            'Breakpoint 1, INNER () at wp.mac:9',
            '#1  0x', 'in OUTER () at wp.mac:7  [shadow]',
            '#2  0x', 'in START () at wp.mac:5  [shadow]',
            '[Program exited normally]',
        ])
        proc.wait(timeout=30)
        assert b'WAITED' in proc.stdout.read()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
