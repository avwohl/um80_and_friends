#!/usr/bin/env python3
"""udb80 - source-level debugger for Z80 and 8080 programs.

udb80 reads the prog.dbg file that `ul80 --debug-info` writes (format:
docs/debug_info.md) and talks the GDB remote serial protocol to a stub, for
example `cpmemu --gdb` (the stub: docs/gdb_stub.md in the cpmemu project).
The user view is docs/udb80.md.  The design is phase 3 of
docs/debugger_plan.md in the cpmemu project.

    udb80 [options] PROG.dbg (--run 'cpmemu ARGS' | --connect HOST:PORT)
    udb80 addr2line [-r] [--asm] PROG.dbg ADDR...
    udb80 sizes PROG.dbg
    udb80 bt-dump [--ix IX] PROG.dbg MEMORY.BIN SP PC
"""

import argparse
import bisect
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time

from um80 import frames
from um80.ud80 import Disassembler

REG_NAMES = ['af', 'bc', 'de', 'hl', 'sp', 'pc', 'ix', 'iy',
             "af'", "bc'", "de'", "hl'", 'ir']
FLAG_BITS = [(7, 'S'), (6, 'Z'), (4, 'H'), (2, 'P'), (1, 'N'), (0, 'C')]
CALL_OPCODES = (0xCD, 0xC4, 0xCC, 0xD4, 0xDC, 0xE4, 0xEC, 0xF4, 0xFC)


class UdbError(Exception):
    """An error that the user sees as one line."""


def h4(value):
    return '0x%04x' % (value & 0xFFFF)


def parse_int(text):
    """A number in C form (0x1F, 31) or in assembler form (1FH, 0100H)."""
    t = text.strip()
    try:
        if re.fullmatch(r'0[xX][0-9a-fA-F]+', t):
            return int(t, 16)
        if re.fullmatch(r'[0-9][0-9a-fA-F]*[hH]', t):
            return int(t[:-1], 16)
        if re.fullmatch(r'[0-9]+', t):
            return int(t, 10)
    except ValueError:
        pass
    raise ValueError(text)


# ---------------------------------------------------------------------------
# prog.dbg
# ---------------------------------------------------------------------------

class DebugInfo:
    """The linked debug file, with the lookups the commands need."""

    def __init__(self, path):
        self.path = path
        self.dir = os.path.dirname(os.path.abspath(path))
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            raise UdbError('cannot read %s: %s' % (path, e))
        if data.get('format') != 'um80-dbg':
            raise UdbError('%s is not a um80-dbg file' % path)
        if data.get('version') != 1:
            raise UdbError('%s has format version %r; udb80 reads version 1'
                           % (path, data.get('version')))
        self.data = data
        self.image = data.get('image') or {}
        self.files = data.get('files') or []
        self.lines = sorted(data.get('lines') or [], key=lambda r: r[0])
        self.asm = sorted(data.get('asm') or [], key=lambda r: r[0])
        self.labels = data.get('labels') or []
        self.modules = data.get('modules') or []
        self.funcs = sorted(data.get('funcs') or [],
                            key=lambda f: f.get('start') or 0)
        self._line_starts = [r[0] for r in self.lines]
        self._asm_starts = [r[0] for r in self.asm]
        # Labels by address.  The routine labels are the ones that name a
        # routine: the global labels when there are any, else all labels.
        self.sorted_labels = sorted(
            ((l[1], l[0], l[3] if len(l) > 3 else 0) for l in self.labels),
            key=lambda t: (t[0], t[1]))
        has_global = any(g for _a, _n, g in self.sorted_labels)
        self.routine_labels = [(a, n) for a, n, g in self.sorted_labels
                               if g or not has_global]
        self._rl_addrs = [a for a, _n in self.routine_labels]
        self._by_name = {}
        for a, n, _g in self.sorted_labels:
            self._by_name.setdefault(n.upper(), a)
        for f in self.funcs:
            if f.get('start') is not None:
                self._by_name[f['name'].upper()] = f['start']
        self.code_end = max([r[1] for r in self.asm] +
                            [r[1] for r in self.lines] + [0])
        self._frame_program = None

    def frame_program(self):
        """The frame records and instruction rows, for um80.frames."""
        if self._frame_program is None:
            self._frame_program = frames.Program(self.data)
        return self._frame_program

    # -- the D9 check -----------------------------------------------------

    def program_path(self, override=None):
        if override:
            return override
        name = self.image.get('file')
        return os.path.join(self.dir, name) if name else None

    def check_program_file(self, override=None):
        """Refuse a prog.dbg that does not match its image file.

        Returns the path that matched, or None when the file is not there."""
        path = self.program_path(override)
        if not path or not os.path.exists(path):
            if override:
                raise UdbError('program file %s does not exist' % override)
            return None
        with open(path, 'rb') as f:
            blob = f.read()
        self._compare(blob, 'the file %s' % path)
        return path

    def check_memory(self, blob):
        """The D9 check against the first `length` bytes of guest memory."""
        self._compare(blob, 'guest memory at %s' % h4(self.image.get('load') or 0))

    def _compare(self, blob, what):
        length = self.image.get('length')
        want = self.image.get('sha256')
        if length is None or want is None:
            return
        if len(blob) < length or hashlib.sha256(blob[:length]).hexdigest() != want:
            raise UdbError(
                '%s does not match %s (the image check of the build: '
                'length %d, SHA-256 %s...).  The debug file is stale; '
                'build the program again.' % (what, self.path, length, want[:12]))

    # -- lookups ----------------------------------------------------------

    @staticmethod
    def _find(table, starts, addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and table[i][0] <= addr < table[i][1]:
            return table[i]
        return None

    def line_entry(self, addr):
        return self._find(self.lines, self._line_starts, addr)

    def asm_row(self, addr):
        return self._find(self.asm, self._asm_starts, addr)

    def file_name(self, index):
        if index is None or not 0 <= index < len(self.files):
            return '?'
        return self.files[index]

    def label_at_or_before(self, addr):
        """(name, offset) of the routine label at or below addr, or None."""
        i = bisect.bisect_right(self._rl_addrs, addr) - 1
        if i < 0:
            return None
        a, n = self.routine_labels[i]
        return n, addr - a

    def func_at(self, addr):
        """(name, offset): a ;#func routine if one holds addr, else a label."""
        for k, f in enumerate(self.funcs):
            s = f.get('start')
            if s is None:
                continue
            e = f.get('end')
            if e is None:
                e = self.funcs[k + 1]['start'] if k + 1 < len(self.funcs) \
                    else self.code_end
            if s <= addr < e:
                return f['name'], addr - s
        return self.label_at_or_before(addr)

    def symbolize(self, addr):
        """'<NAME+off>' for an address, or ''."""
        r = self.func_at(addr)
        if r is None:
            return ''
        return '<%s>' % r[0] if r[1] == 0 else '<%s+%d>' % r

    def resolve(self, name):
        key = name.upper()
        for k in (key, '_' + key, key.lstrip('_')):
            if k in self._by_name:
                return self._by_name[k]
        return None

    def match_file(self, name):
        """Indexes of the files that a user's file name can mean."""
        want = name.replace('\\', '/')
        out = []
        for i, f in enumerate(self.files):
            p = f.replace('\\', '/')
            if p == want or p.endswith('/' + want) or os.path.basename(p) == want:
                out.append(i)
        return out

    def src_primary(self, entry):
        g = entry[2][-1]
        return g[0], g[1]

    def line_addrs(self, name, line):
        """Addresses to stop at for file:line, from the source table first,
        then the assembler table.  Returns (addresses, line used)."""
        files = set(self.match_file(name))
        if not files:
            raise UdbError('No source file named %s.' % name)
        best = None
        for use in (line, None):
            addrs = []
            cand = None
            for e in self.lines:
                for g in e[2]:
                    if g[0] in files and not g[2]:
                        if use is None:
                            if g[1] > line and (cand is None or g[1] < cand):
                                cand = g[1]
                        elif g[1] == use:
                            addrs.append(e[0])
            for r in self.asm:
                if r[2] == 's':
                    continue
                if (r[3] in files and r[4] is not None and
                        (r[4] == use if use is not None else r[4] > line)):
                    if use is None:
                        if cand is None or r[4] < cand:
                            cand = r[4]
                    else:
                        addrs.append(r[0])
                elif (len(r) > 6 and r[5] in files and use is not None and r[6] == use):
                    addrs.append(r[0])
            if use is not None and addrs:
                return sorted(set(addrs)), use
            if use is None:
                best = cand
        if best is None:
            raise UdbError('No code at or after %s:%d.' % (name, line))
        return self.line_addrs(name, best)

    def addr2line(self, addr, want_asm=False):
        """A dict for one address: func, src (file, line, inline), asm."""
        out = {'addr': addr}
        fn = self.func_at(addr)
        out['func'] = fn[0] if fn else None
        out['offset'] = fn[1] if fn else None
        e = self.line_entry(addr)
        out['src'] = None
        if e is not None and not want_asm:
            f, l = self.src_primary(e)
            out['src'] = (self.file_name(f), l, e[3] if len(e) > 3 else None)
        r = self.asm_row(addr)
        out['asm'] = (self.file_name(r[3]), r[4]) if r else None
        return out

    def sizes(self):
        """List of (size, start, name): bytes per routine."""
        rows = []
        if any(f.get('start') is not None for f in self.funcs):
            for k, f in enumerate(self.funcs):
                s = f.get('start')
                if s is None:
                    continue
                e = f.get('end')
                if e is None:
                    e = self.funcs[k + 1]['start'] if k + 1 < len(self.funcs) \
                        else self.code_end
                rows.append((e - s, s, f['name']))
        else:
            labs = []
            for a, n in self.routine_labels:
                r = self.asm_row(a)
                if r is not None and r[2] == 'i':
                    labs.append((a, n))
            for k, (a, n) in enumerate(labs):
                nxt = labs[k + 1][0] if k + 1 < len(labs) else self.code_end
                # a data label or a gap ends the routine early
                for dr in self.asm:
                    if dr[0] > a and dr[2] != 'i' and dr[0] < nxt:
                        nxt = dr[0]
                        break
                rows.append((nxt - a, a, n))
        rows.sort(key=lambda t: (-t[0], t[1]))
        return rows


# ---------------------------------------------------------------------------
# The RSP client
# ---------------------------------------------------------------------------

class Rsp:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b''
        self.packet_size = 0x800

    @staticmethod
    def _sum(data):
        return sum(data) & 0xFF

    def send(self, payload):
        data = payload.encode('latin-1')
        self.sock.sendall(b'$' + data + b'#' + ('%02x' % self._sum(data)).encode())

    def recv(self):
        """One packet payload (a str).  Blocks until one arrives.  A
        KeyboardInterrupt while waiting sends 03H, the debugger's ^C."""
        interrupted = False
        while True:
            while self.buf[:1] in (b'+', b'-'):
                self.buf = self.buf[1:]
            s = self.buf.find(b'$')
            if s >= 0:
                e = self.buf.find(b'#', s)
                if e >= 0 and len(self.buf) >= e + 3:
                    body = self.buf[s + 1:e]
                    want = int(self.buf[e + 1:e + 3], 16)
                    self.buf = self.buf[e + 3:]
                    if self._sum(body) != want:
                        raise UdbError('bad checksum in a packet from the stub')
                    self.sock.sendall(b'+')
                    return body.decode('latin-1')
            try:
                data = self.sock.recv(65536)
            except KeyboardInterrupt:
                if interrupted:
                    raise
                interrupted = True
                self.sock.sendall(b'\x03')
                continue
            if not data:
                raise EOFError('the stub closed the connection')
            self.buf += data

    def cmd(self, payload):
        self.send(payload)
        return self.recv()


class Event:
    """A stop reply."""

    def __init__(self, kind, code=0, raw=''):
        self.kind = kind      # break step int exit signal watch syscall
        self.code = code
        self.raw = raw


def parse_stop(reply):
    c = reply[:1]
    if c == 'W':
        return Event('exit', int(reply[1:3], 16), reply)
    if c == 'X':
        return Event('signal', int(reply[1:3], 16), reply)
    if c in 'TS':
        sig = int(reply[1:3], 16)
        if sig == 2:
            return Event('int', sig, reply)
        if 'swbreak' in reply:
            return Event('break', sig, reply)
        if 'watch' in reply:
            return Event('watch', sig, reply)
        if 'syscall' in reply:
            return Event('syscall', sig, reply)
        return Event('step', sig, reply)
    raise UdbError('unexpected stop reply %r' % reply)


# ---------------------------------------------------------------------------
# The debugger
# ---------------------------------------------------------------------------

class Breakpoint:
    def __init__(self, num, spec, addrs, temp):
        self.num = num
        self.spec = spec
        self.addrs = addrs
        self.temp = temp
        self.hits = 0


class Debugger:
    def __init__(self, dbg, rsp, out=None):
        self.dbg = dbg
        self.rsp = rsp
        self.out = out or sys.stdout
        self.alive = True
        self.breakpoints = []
        self.next_bp = 1
        self.z_refs = {}          # address -> count of Z0 packets in force
        self.level = 'auto'       # auto, src or asm
        self.cpu_z80 = True
        self.shadow = None        # True once monitor bt has answered
        self.no_shadow = False    # set shadow off: act as with a stub without one
        self.list_file = None
        self.list_next = None
        self.src_cache = {}
        self.dis_cache = None
        self.hist = 0
        self.started = False
        self._regs = None
        self._pages = {}
        self.errors = 0
        self._handshake()

    # -- plumbing ---------------------------------------------------------

    def say(self, text=''):
        self.out.write(text + '\n')
        self.out.flush()

    def _handshake(self):
        reply = self.rsp.cmd('qSupported:swbreak+;vContSupported+')
        m = re.search(r'PacketSize=([0-9a-fA-F]+)', reply)
        if m:
            self.rsp.packet_size = max(0x100, int(m.group(1), 16))
        self.rsp.cmd('?')

    def need_alive(self):
        if not self.alive:
            raise UdbError('The program is not being run.')

    def regs(self, fresh=False):
        self.need_alive()
        if self._regs is None or fresh:
            reply = self.rsp.cmd('g')
            raw = bytes.fromhex(reply)
            if len(raw) < 2 * len(REG_NAMES):
                raise UdbError('short register reply from the stub')
            self._regs = {n: raw[2 * i] | (raw[2 * i + 1] << 8)
                          for i, n in enumerate(REG_NAMES)}
        return self._regs

    def pc(self):
        return self.regs()['pc']

    def read_mem(self, addr, length):
        self.need_alive()
        out = b''
        step = max(16, (self.rsp.packet_size - 16) // 2)
        while length > 0:
            n = min(length, step, 0x10000 - addr)
            if n <= 0:
                break
            reply = self.rsp.cmd('m%x,%x' % (addr, n))
            if reply.startswith('E'):
                if out:
                    break
                raise UdbError('Cannot access memory at address %s' % h4(addr))
            out += bytes.fromhex(reply)
            addr += n
            length -= n
        return out

    def read_word(self, addr):
        b = self.read_mem(addr, 2)
        if len(b) < 2:
            raise UdbError('Cannot access memory at address %s' % h4(addr))
        return b[0] | (b[1] << 8)

    def check_memory(self):
        img = self.dbg.image
        if img.get('kind') != 'com' or img.get('load') is None:
            return
        blob = self.read_mem(img['load'], img.get('length') or 0)
        self.dbg.check_memory(blob)

    # -- the shadow stack ---------------------------------------------------

    def shadow_frames(self):
        """Return addresses, innermost first, from monitor bt, or None."""
        self.need_alive()
        if self.no_shadow:
            self.shadow = False
            return None
        reply = self.rsp.cmd('qRcmd,' + b'bt'.hex())
        try:
            text = bytes.fromhex(reply).decode('latin-1')
        except ValueError:
            self.shadow = False
            return None
        addrs = [int(m.group(1), 16) for m in
                 re.finditer(r'^#\d+\s+0x([0-9A-Fa-f]+)', text, re.M)]
        if not addrs:
            self.shadow = False
            return None
        self.shadow = True
        self.out_of_step = 'out of step' in text
        return addrs

    def depth(self):
        f = self.shadow_frames()
        return None if f is None else len(f) - 1

    # -- running ------------------------------------------------------------

    def _resume(self, packet):
        self.need_alive()
        self._regs = None
        self._pages = {}
        self.started = True
        self.rsp.send(packet)
        try:
            reply = self.rsp.recv()
        except EOFError:
            self.alive = False
            return Event('exit', 0, 'closed')
        ev = parse_stop(reply)
        if ev.kind in ('exit', 'signal'):
            self.alive = False
        return ev

    def _set_z(self, addr, on):
        n = self.z_refs.get(addr, 0)
        if on:
            if n == 0:
                reply = self.rsp.cmd('Z0,%x,1' % addr)
                if reply != 'OK':
                    raise UdbError('the stub refused a breakpoint at %s' % h4(addr))
            self.z_refs[addr] = n + 1
        else:
            if n <= 1:
                self.rsp.cmd('z0,%x,1' % addr)
                self.z_refs.pop(addr, None)
            else:
                self.z_refs[addr] = n - 1

    def user_addrs(self):
        return {a for b in self.breakpoints for a in b.addrs}

    def run_temp(self, addr, ok, extra=()):
        """Continue to a temporary breakpoint at addr.  A user breakpoint,
        an exit and ^C stop earlier.  ok() is called at each arrival and
        says if the arrival counts.  extra is a list of more return
        addresses (the callers above addr): a return to one of them that
        passes ok() also ends the run, so a frame that unwinds past addr
        (a longjmp, or a POP POP RET) still stops.  Returns the Event, with
        kind 'temp' when a temporary breakpoint stopped the program."""
        addrs = [addr] + [a for a in dict.fromkeys(extra) if a != addr]
        for a in addrs:
            self._set_z(a, True)
        try:
            while True:
                ev = self._resume('c')
                if not self.alive or ev.kind != 'break':
                    return ev
                pc = self.pc()
                if pc in addrs and ok():
                    return Event('temp', 0, ev.raw)
                if pc in self.user_addrs():
                    return ev
        finally:
            if self.alive:
                for a in addrs:
                    self._set_z(a, False)

    def effective_entry(self, addr):
        """(start, end, groups, is_src) for the stepping range at addr."""
        d = self.dbg
        mode = self.level
        if mode == 'auto':
            mode = 'src' if d.lines else 'asm'
        if mode == 'src':
            e = d.line_entry(addr)
            if e is not None:
                return e[0], e[1], e[2], True
            return None
        r = d.asm_row(addr)
        if r is not None and r[2] != 's':
            return r[0], r[1], [[r[3], r[4], 0]], False
        return None

    @staticmethod
    def is_step_point(entry):
        return any(not g[2] for g in entry[2])

    def do_step(self, over):
        self.need_alive()
        pc0 = self.pc()
        func0 = self.frame_key()
        ent = self.effective_entry(pc0)
        if ent is None:
            ev = self._resume('s')
            return self._finish_stop(ev, func0)
        d0 = self.depth()
        for _guard in range(100000):
            lo, hi = ent[0], ent[1]
            sp0 = self.regs()['sp']
            ev = self._resume('vCont;r%x,%x' % (lo, hi))
            if ev.kind != 'step':
                return self._finish_stop(ev, func0)
            regs = self.regs()
            pc = regs['pc']
            # Did the range step leave through a CALL?
            ret = None
            outer = ()
            if self.shadow is not False:
                frames = self.shadow_frames()
            else:
                frames = None
            if frames is not None:
                d = len(frames) - 1
                if d0 is not None and d > d0:
                    ret = frames[1]
                    outer = frames[2:]
                    entered_depth = d
                    def ok(entered_depth=entered_depth):
                        dd = self.depth()
                        return dd is None or dd < entered_depth
                elif d0 is not None and d < d0:
                    d0 = d
            else:
                # No shadow stack: a CALL left the range when the word on
                # top of the stack is an address just after the range start
                # and no more than 3 bytes below the range end.
                sp = regs['sp']
                try:
                    w = self.read_word(sp)
                except UdbError:
                    w = None
                if (w is not None and lo < w <= hi and hi - w < 4
                        and not (lo <= pc < hi) and sp < sp0):
                    ret = w
                    sp_entry = sp

                    def ok(sp_entry=sp_entry):
                        return self.regs(True)['sp'] >= sp_entry + 2
            if ret is not None:
                new = self.effective_entry(pc)
                into = (not over) and new is not None and pc == new[0] \
                    and self.is_step_point(new)
                if not into:
                    ev = self.run_temp(ret, ok, outer)
                    if ev.kind != 'temp':
                        return self._finish_stop(ev, func0)
                    pc = self.pc()
                    # back in the caller
                else:
                    return self._finish_stop(Event('step'), func0)
            new = self.effective_entry(pc)
            if new is None:
                return self._finish_stop(Event('step'), func0)
            if pc == new[0] and self.is_step_point(new):
                return self._finish_stop(Event('step'), func0)
            ent = new
            pc0 = pc
        raise UdbError('step did not end')

    def frame_key(self):
        """(routine name, shadow depth): what "the same frame" means."""
        f = self.dbg.func_at(self.pc())
        return (f[0] if f else None, self.depth() if self.shadow is not False else None)

    def _finish_stop(self, ev, func0=None):
        self.report_stop(ev, func0)
        return ev

    def do_finish(self):
        self.need_alive()
        frames = self.shadow_frames()
        if frames is None:
            raise UdbError('finish needs the shadow call stack of the stub.')
        if len(frames) < 2:
            raise UdbError('"finish" not meaningful in the outermost frame.')
        d = len(frames) - 1
        ret = frames[1]
        self.say('Run till exit from #0  %s' % self.frame_text(frames[0], 0, True))
        func0 = self.frame_key()
        ev = self.run_temp(ret, lambda: (self.depth() or 0) < d, frames[2:])
        if ev.kind == 'temp':
            ev = Event('finish', 0, ev.raw)
        self.report_stop(ev, func0)
        return ev

    def do_continue(self):
        if not self.started and self.pc() in self.user_addrs():
            # The stub always runs the first instruction, so a breakpoint
            # at the start address would be missed.  Report it here.
            self.started = True
            ev = Event('break', 5, 'T05swbreak:;')
        else:
            ev = self._resume('c')
        self.report_stop(ev, None)
        return ev

    def do_stepi(self):
        func0 = self.frame_key()
        ev = self._resume('s')
        self.report_stop(ev, func0, instr=True)
        return ev

    # -- reporting ------------------------------------------------------------

    def report_stop(self, ev, func0, instr=False):
        k = ev.kind
        if k == 'exit':
            if ev.code == 0:
                self.say('[Program exited normally]')
            else:
                self.say('[Program exited with code %02x]' % ev.code)
            return
        if k == 'signal':
            self.say('[Program terminated by signal %d]' % ev.code)
            return
        pc = self.pc()
        head = None
        if k == 'break':
            hit = [b for b in self.breakpoints if pc in b.addrs]
            for b in hit:
                b.hits += 1
            if hit:
                head = ('Temporary breakpoint %d, ' if hit[0].temp else 'Breakpoint %d, ') % hit[0].num
                for b in hit:
                    if b.temp:
                        self.delete_bp(b)
            else:
                head = 'Breakpoint, '
        elif k == 'int':
            head = 'Program received signal SIGINT, Interrupt.\n'
        elif k == 'watch':
            head = 'Watchpoint, '
        elif k == 'finish':
            head = ''
        self.print_location(pc, head, func0, instr)

    def location_text(self, addr, want_pc=None):
        """'FUNC () at FILE:LINE' for an address."""
        info = self.dbg.addr2line(addr, self.level == 'asm')
        name = info['func'] or '??'
        if info['src'] is not None:
            where = ' at %s:%d' % (info['src'][0], info['src'][1])
        elif info['asm'] is not None:
            where = ' at %s:%d' % info['asm']
        else:
            where = ''
        return '%s ()%s' % (name, where), info

    def print_location(self, pc, head, func0, instr=False):
        text, info = self.location_text(pc)
        ent = self.effective_entry(pc)
        at_start = ent is not None and ent[0] == pc
        func_now = info['func']
        show_frame = (head is not None or instr or func0 is None
                      or func0 != self.frame_key())
        lead = '' if at_start else '%s in ' % h4(pc)
        if head and head.endswith('\n'):
            self.say(head.rstrip('\n'))
            head = ''
        if show_frame:
            self.say((head or '') + lead + text)
        line = None
        if info['src'] is not None:
            line = (info['src'][0], info['src'][1])
        elif info['asm'] is not None:
            line = info['asm']
        if line is not None:
            self.show_source_line(line[0], line[1])
            self.list_file, self.list_next = line[0], max(1, line[1] - 4)
            self._center = line[1]
        elif not show_frame:
            self.say('%s in %s' % (h4(pc), text))

    def source_lines(self, fname):
        if fname in self.src_cache:
            return self.src_cache[fname]
        cands = [fname, os.path.join(self.dbg.dir, fname),
                 os.path.join(self.dbg.dir, os.path.basename(fname))]
        for extra in getattr(self, 'src_dirs', []):
            cands.append(os.path.join(extra, os.path.basename(fname)))
        text = None
        for c in cands:
            if os.path.isfile(c):
                with open(c, encoding='latin-1') as f:
                    text = f.read().split('\n')
                if text and text[-1] == '':
                    text.pop()
                break
        self.src_cache[fname] = text
        return text

    def show_source_line(self, fname, line):
        lines = self.source_lines(fname)
        if lines is None or not 1 <= line <= len(lines):
            self.say('%d\tin %s' % (line, fname))
        else:
            self.say('%d\t%s' % (line, lines[line - 1]))

    def frame_text(self, addr, index, is_pc):
        # A return address points after the CALL; its line is the call line.
        probe = addr if is_pc else max(0, addr - 1)
        text, info = self.location_text(probe)
        pre = '' if (is_pc and self.effective_entry(addr) and
                     self.effective_entry(addr)[0] == addr) else h4(addr) + ' in '
        return pre + text

    # -- breakpoints ----------------------------------------------------------

    def add_bp(self, spec, temp=False):
        spec = spec.strip()
        if not spec:
            self.need_alive()
            addrs, note = [self.pc()], None
        else:
            addrs, note = self.resolve_location(spec)
        bp = Breakpoint(self.next_bp, spec, addrs, temp)
        self.next_bp += 1
        for a in addrs:
            self._set_z(a, True)
        self.breakpoints.append(bp)
        if note:
            self.say(note)
        kind = 'Temporary breakpoint' if temp else 'Breakpoint'
        a0 = addrs[0]
        text, _ = self.location_text(a0)
        more = ' (%d locations)' % len(addrs) if len(addrs) > 1 else ''
        info = self.dbg.addr2line(a0, self.level == 'asm')
        where = ''
        m = re.fullmatch(r'(.+):(\d+)', spec)
        if m and note is None:
            idx = self.dbg.match_file(m.group(1))
            where = ': file %s, line %s.' % (self.dbg.file_name(idx[0]), m.group(2))
        elif info['src'] is not None:
            where = ': file %s, line %d.' % (info['src'][0], info['src'][1])
        elif info['asm'] is not None:
            where = ': file %s, line %d.' % info['asm']
        self.say('%s %d at %s%s%s' % (kind, bp.num, h4(a0), where, more))
        return bp

    def resolve_location(self, spec):
        m = re.fullmatch(r'\*\s*(.+)', spec)
        if m:
            return [self.eval_addr(m.group(1))], None
        m = re.fullmatch(r'(.+):(\d+)', spec)
        if m:
            addrs, used = self.dbg.line_addrs(m.group(1), int(m.group(2)))
            note = None
            if used != int(m.group(2)):
                note = 'Line %s has no code; using line %d.' % (m.group(2), used)
            return addrs, note
        if re.fullmatch(r'\d+', spec):
            fname = self.list_file
            if fname is None:
                raise UdbError('No default source file; use FILE:LINE.')
            addrs, used = self.dbg.line_addrs(fname, int(spec))
            return addrs, None
        a = self.dbg.resolve(spec)
        if a is None:
            raise UdbError('Function "%s" not defined.' % spec)
        return [a], None

    def delete_bp(self, bp):
        for a in bp.addrs:
            if self.alive:
                self._set_z(a, False)
        if bp in self.breakpoints:
            self.breakpoints.remove(bp)

    # -- expressions ------------------------------------------------------------

    TOKEN = re.compile(r'\s*(\$\w+|0[xX][0-9a-fA-F]+|[0-9][0-9a-fA-F]*[hH]\b|\d+|'
                       r"[A-Za-z_.?@][\w.?@$]*|[-+*&()])")

    def tokenize(self, text):
        pos, out = 0, []
        text = text.strip()
        while pos < len(text):
            m = self.TOKEN.match(text, pos)
            if not m:
                raise UdbError('Invalid expression at "%s"' % text[pos:])
            out.append(m.group(1))
            pos = m.end()
            while pos < len(text) and text[pos].isspace():
                pos += 1
        return out

    def eval_expr(self, text):
        """(value, address-of-symbol or None)."""
        toks = self.tokenize(text)
        if not toks:
            raise UdbError('Argument required (an expression).')
        pos = [0]

        def peek():
            return toks[pos[0]] if pos[0] < len(toks) else None

        def take():
            t = peek()
            pos[0] += 1
            return t

        def primary():
            t = take()
            if t is None:
                raise UdbError('Invalid expression: it ends too early.')
            if t == '(':
                v = expr()
                if take() != ')':
                    raise UdbError('A ")" is missing.')
                return v
            if t.startswith('$'):
                name = t[1:].lower()
                if name == 'ixh' or name == 'ixl':
                    pass
                regs = self.regs()
                if name in regs:
                    return regs[name], None
                if len(name) == 1 and name in 'abcdehl':
                    pair = {'a': 'af', 'b': 'bc', 'c': 'bc', 'd': 'de',
                            'e': 'de', 'h': 'hl', 'l': 'hl'}[name]
                    v = regs[pair]
                    return ((v >> 8) if name in 'adbh' else (v & 0xFF)) & 0xFF, None
                if name == 'f':
                    return regs['af'] & 0xFF, None
                raise UdbError('Unknown register or variable "%s".' % t)
            try:
                return parse_int(t), None
            except ValueError:
                pass
            a = self.dbg.resolve(t)
            if a is None:
                raise UdbError('No symbol "%s" in the current context.' % t)
            return self.symbol_value(a), a

        def unary():
            t = peek()
            if t == '-':
                take()
                return (-unary()[0]) & 0xFFFF, None
            if t == '&':
                take()
                v, a = unary()
                if a is None:
                    raise UdbError('Attempt to take the address of a value not in memory.')
                return a, None
            if t == '*':
                take()
                v, a = unary()
                return self.read_word(v & 0xFFFF), None
            return primary()

        def expr():
            v, a = unary()
            while peek() in ('+', '-'):
                op = take()
                w, _ = unary()
                v = (v + w) if op == '+' else (v - w)
                a = None
            return v, a

        result = expr()
        if pos[0] != len(toks):
            raise UdbError('Invalid expression near "%s".' % toks[pos[0]])
        return result

    def symbol_value(self, addr):
        """The value of a symbol: static data by its size, else its address."""
        r = self.dbg.asm_row(addr)
        if r is not None and r[0] == addr and r[2] == 'd':
            n = r[1] - r[0]
            if self.alive:
                data = self.read_mem(addr, n)
                if n == 1:
                    return data[0]
                if n == 2:
                    return data[0] | (data[1] << 8)
        return addr

    def eval_addr(self, text):
        v, a = self.eval_expr(text)
        return (a if a is not None else v) & 0xFFFF

    # -- disassembly ------------------------------------------------------------

    def instr_text(self, dis, addr):
        d = dis.decode_instruction(addr)
        if d is None:
            return 1, 'DB ??'
        mnem, size, ops, target = d
        text = mnem + ((' ' + ','.join(ops)) if ops else '')
        if target is not None and 0 <= target < 0x10000:
            sym = self.dbg.symbolize(target)
            if sym:
                text += '    ; ' + sym
        return max(1, size), text

    def disassemble_range(self, lo, hi, mark=None):
        data = self.read_mem(lo, hi - lo + 4)
        dis = Disassembler(data, org=lo, z80_mode=self.cpu_z80)
        a = lo
        while a < hi:
            size, text = self.instr_text(dis, a)
            sym = self.dbg.symbolize(a)
            self.say('%s %s %s:\t%s' % ('=>' if a == mark else '  ', h4(a),
                                         sym, text))
            a += size

    # -- listing ------------------------------------------------------------------

    def list_lines(self, fname, first, last):
        lines = self.source_lines(fname)
        if lines is None:
            raise UdbError('%s: No such file or directory.' % fname)
        if first > len(lines):
            raise UdbError('Line number %d out of range; "%s" has %d lines.'
                           % (first, fname, len(lines)))
        last = min(last, len(lines))
        for n in range(max(1, first), last + 1):
            self.say('%d\t%s' % (n, lines[n - 1]))
        self.list_file, self.list_next = fname, last + 1

    # -- commands --------------------------------------------------------------------

    def execute(self, line):
        line = line.strip()
        if not line or line.startswith('#'):
            return True
        m = re.match(r'([A-Za-z_]+|[a-z]+/?)(.*)', line)
        word, rest = m.group(1), m.group(2)
        fmt = ''
        if rest.startswith('/'):
            m2 = re.match(r'/(\S*)\s*(.*)', rest)
            fmt, rest = m2.group(1), m2.group(2)
        rest = rest.strip()
        name = self.canonical(word)
        try:
            getattr(self, 'cmd_' + name)(rest, fmt)
        except UdbError as e:
            sys.stdout.flush()
            sys.stderr.write('%s\n' % e)
            sys.stderr.flush()
            self.errors += 1
        except EOFError:
            self.alive = False
            self.say('The connection to the stub closed.')
        return name != 'quit'

    COMMANDS = ['break', 'tbreak', 'delete', 'continue', 'step', 'next', 'stepi',
                'finish', 'backtrace', 'list', 'disassemble', 'info', 'x',
                'print', 'sizes', 'set', 'monitor', 'echo', 'kill', 'quit', 'help']
    ALIASES = {'b': 'break', 'br': 'break', 'tb': 'tbreak', 'd': 'delete',
               'c': 'continue', 'cont': 'continue', 'r': 'continue',
               's': 'step', 'n': 'next', 'si': 'stepi', 'fin': 'finish',
               'bt': 'backtrace', 'where': 'backtrace', 'l': 'list',
               'disas': 'disassemble', 'i': 'info', 'p': 'print',
               'inspect': 'print', 'q': 'quit', 'exit': 'quit', 'h': 'help'}

    def canonical(self, word):
        if word in self.ALIASES:
            return self.ALIASES[word]
        hits = [c for c in self.COMMANDS if c.startswith(word)]
        if word in self.COMMANDS:
            return word
        if len(hits) == 1:
            return hits[0]
        raise_name = word
        self.errors += 1
        sys.stderr.write('Undefined command: "%s".  Try "help".\n' % raise_name)
        return 'noop'

    def cmd_noop(self, rest, fmt):
        pass

    def cmd_break(self, rest, fmt):
        self.add_bp(rest, False)

    def cmd_tbreak(self, rest, fmt):
        self.add_bp(rest, True)

    def cmd_delete(self, rest, fmt):
        if not rest or rest.split()[0] == 'breakpoints':
            for b in list(self.breakpoints):
                self.delete_bp(b)
            return
        for tok in rest.split():
            try:
                n = int(tok)
            except ValueError:
                raise UdbError('Bad breakpoint argument: "%s"' % tok)
            hit = [b for b in self.breakpoints if b.num == n]
            if not hit:
                raise UdbError('No breakpoint number %d.' % n)
            self.delete_bp(hit[0])

    def repeat_count(self, rest):
        if not rest:
            return 1
        try:
            return max(1, int(rest))
        except ValueError:
            raise UdbError('Bad count: "%s"' % rest)

    def cmd_continue(self, rest, fmt):
        self.need_alive()
        self.do_continue()

    def cmd_step(self, rest, fmt):
        for _ in range(self.repeat_count(rest)):
            self.need_alive()
            ev = self.do_step(False)
            if ev.kind != 'step':
                break

    def cmd_next(self, rest, fmt):
        for _ in range(self.repeat_count(rest)):
            self.need_alive()
            ev = self.do_step(True)
            if ev.kind != 'step':
                break

    def cmd_stepi(self, rest, fmt):
        for _ in range(self.repeat_count(rest)):
            self.need_alive()
            ev = self.do_stepi()
            if ev.kind != 'step':
                break

    def cmd_finish(self, rest, fmt):
        self.do_finish()

    def page_byte(self, addr):
        """One byte of guest memory, read in pages of 256 bytes that are
        forgotten when the program runs.  None when the stub refuses."""
        if not 0 <= addr < 0x10000:
            return None
        page = addr >> 8
        if page not in self._pages:
            try:
                data = self.read_mem(page << 8, 256)
            except UdbError:
                data = b''
            self._pages[page] = data if len(data) == 256 else None
        data = self._pages[page]
        return None if data is None else data[addr & 255]

    def frame_chain(self):
        """D7 source 2: the frames from the frame records of prog.dbg and
        the registers.  A list of (address, SP, tag), innermost first."""
        regs = self.regs()
        walker = frames.Walker(self.dbg.frame_program(), self.page_byte)
        chain = walker.walk(regs['pc'], regs['sp'], regs['ix'])
        # One frame is a whole answer only when the walker reached the
        # bottom of the stack; else the walker could not unwind the frame.
        return chain if len(chain) > 1 or walker.bottom else None

    def cmd_backtrace(self, rest, fmt):
        self.need_alive()
        source = 'auto'
        limit = None
        for word in rest.split():
            if word in ('shadow', 'frame', 'frames'):
                source = 'shadow' if word == 'shadow' else 'frame'
                continue
            try:
                limit = int(word)
            except ValueError:
                raise UdbError('Bad count: "%s"' % word)
        pc = self.pc()
        chain = None
        extra = ''
        shadow = self.shadow_frames() if source != 'frame' else None
        if shadow is not None:
            entries = [(a, 'shadow') for a in shadow]
            if getattr(self, 'out_of_step', False):
                extra = '(the shadow stack is out of step: some frames can be wrong)'
        elif source == 'shadow':
            raise UdbError('The stub has no shadow call stack.')
        else:
            chain = self.frame_chain()
            if chain is not None:
                entries = [(a, tag) for a, _sp, tag in chain]
            else:
                entries = [(a, 'guess') for a in [pc] + self.guess_frames()]
        self.print_frames(entries, limit)
        if extra:
            self.say(extra)

    def print_frames(self, entries, limit=None):
        for i, (a, tag) in enumerate(entries):
            if limit is not None and i >= limit:
                self.say('(More stack frames follow...)')
                break
            self.say('#%-2d %s  [%s]' % (i, self.frame_text(a, i, i == 0), tag))

    def guess_frames(self):
        """D7 source 3: stack words that point after a CALL in the program."""
        regs = self.regs()
        sp = regs['sp']
        lo = self.dbg.image.get('load') or 0x100
        hi = self.dbg.code_end
        data = self.read_mem(sp, 512)
        out = []
        for i in range(0, len(data) - 1, 2):
            w = data[i] | (data[i + 1] << 8)
            if lo + 3 <= w <= hi:
                b = self.read_mem(w - 3, 1)
                if b and b[0] in CALL_OPCODES:
                    out.append(w)
        return out

    def cmd_list(self, rest, fmt):
        if rest and ',' in rest:
            a, b = rest.split(',', 1)
            fname = self.list_file
            first = self.list_arg(a)
            last = self.list_arg(b)
            self.list_lines(first[0] or fname, first[1], last[1])
            return
        if rest:
            fname, line = self.list_arg(rest)
            fname = fname or self.list_file
            if fname is None:
                raise UdbError('No default source file; use FILE:LINE.')
            first = max(1, line - 5)
            self.list_lines(fname, first, first + 9)
            return
        if self.list_file is None:
            if self.alive:
                info = self.dbg.addr2line(self.pc(), self.level == 'asm')
                src = info['src'] and info['src'][:2] or info['asm']
                if src:
                    self.list_file, self.list_next = src[0], max(1, src[1] - 4)
            if self.list_file is None:
                raise UdbError('No default source file; use "list FILE:LINE".')
        self.list_lines(self.list_file, self.list_next, self.list_next + 9)

    def list_arg(self, text):
        text = text.strip()
        m = re.fullmatch(r'(.+):(\d+)', text)
        if m:
            idx = self.dbg.match_file(m.group(1))
            if not idx:
                raise UdbError('No source file named %s.' % m.group(1))
            return self.dbg.file_name(idx[0]), int(m.group(2))
        if re.fullmatch(r'\d+', text):
            return None, int(text)
        a = self.dbg.resolve(text)
        if a is None:
            raise UdbError('Function "%s" not defined.' % text)
        info = self.dbg.addr2line(a, self.level == 'asm')
        src = info['src'] and info['src'][:2] or info['asm']
        if not src:
            raise UdbError('"%s" has no source line.' % text)
        return src

    def cmd_disassemble(self, rest, fmt):
        mark = self.pc() if self.alive else None
        count = None
        if rest:
            parts = rest.split(',')
            lo = self.eval_addr(parts[0])
            if len(parts) > 1:
                p1 = parts[1].strip()
                if p1.startswith('+'):
                    hi = lo + self.eval_addr(p1[1:])
                else:
                    hi = self.eval_addr(p1)
            else:
                hi = self.routine_end(lo)
        else:
            self.need_alive()
            lo = mark
            lo = self.routine_start(lo)
            hi = self.routine_end(lo)
        if hi <= lo:
            raise UdbError('Empty address range.')
        self.disassemble_range(lo, hi, mark)

    def routine_start(self, addr):
        f = self.dbg.func_at(addr)
        return addr - f[1] if f else addr

    def routine_end(self, addr):
        d = self.dbg
        for k, f in enumerate(d.funcs):
            s = f.get('start')
            if s is not None and s <= addr and (f.get('end') or 0) > addr:
                return f['end']
        i = bisect.bisect_right(d._rl_addrs, addr)
        if i < len(d._rl_addrs):
            return d._rl_addrs[i]
        return max(addr + 1, d.code_end)

    def cmd_info(self, rest, fmt):
        parts = rest.split(None, 1)
        if not parts:
            raise UdbError('List of info subcommands: registers, breakpoints, '
                           'symbols, line, source, frame.')
        sub, arg = parts[0], (parts[1] if len(parts) > 1 else '')
        for full in ('registers', 'breakpoints', 'symbols', 'symbol', 'line',
                     'source', 'all-registers'):
            if full.startswith(sub):
                break
        else:
            raise UdbError('Undefined info command: "%s".' % sub)
        if full in ('registers', 'all-registers'):
            self.info_registers(arg)
        elif full == 'breakpoints':
            self.info_breakpoints()
        elif full in ('symbols', 'symbol'):
            self.info_symbols(arg)
        elif full == 'line':
            self.info_line(arg)
        elif full == 'source':
            self.say('Debug file: %s' % self.dbg.path)
            self.say('Files: %s' % ', '.join(self.dbg.files))

    def info_registers(self, arg):
        regs = self.regs(True)
        names = [n.lstrip('$').lower() for n in arg.split()] or REG_NAMES
        for n in names:
            if n not in regs:
                raise UdbError('Invalid register `%s\'' % n)
            v = regs[n]
            extra = ''
            if n == 'pc':
                extra = '    ' + self.dbg.symbolize(v)
            self.say('%-4s 0x%04x    %d%s' % (n, v, v, extra))
        if arg == '' or 'af' in names:
            f = regs['af'] & 0xFF
            flags = [c for bit, c in FLAG_BITS if f & (1 << bit)]
            self.say('flags [ %s ]' % ' '.join(flags))

    def info_breakpoints(self):
        if not self.breakpoints:
            self.say('No breakpoints or watchpoints.')
            return
        self.say('Num  Type        Disp  Address  What')
        for b in self.breakpoints:
            for a in b.addrs:
                text, _ = self.location_text(a)
                self.say('%-4d breakpoint  %-4s  %s   %s' % (
                    b.num, 'del' if b.temp else 'keep', h4(a), text))
            if b.hits:
                self.say('     breakpoint already hit %d time%s' % (
                    b.hits, '' if b.hits == 1 else 's'))

    def info_symbols(self, arg):
        d = self.dbg
        if arg:
            try:
                addr = parse_int(arg)
            except ValueError:
                addr = d.resolve(arg)
                if addr is None:
                    rx = re.compile(arg, re.I)
                    for a, n, g in d.sorted_labels:
                        if rx.search(n):
                            self.say('%s  %s' % (h4(a), n))
                    return
            r = d.label_at_or_before(addr)
            if r is None:
                self.say('No symbol matches %s.' % arg)
            elif r[1] == 0:
                self.say('%s in the program' % r[0])
            else:
                self.say('%s + %d in the program' % r)
            return
        for a, n, g in d.sorted_labels:
            self.say('%s  %s%s' % (h4(a), n, '' if g or not any(
                x[2] for x in d.sorted_labels) else ''))

    def info_line(self, arg):
        if not arg:
            self.need_alive()
            addr = self.pc()
        else:
            addrs, _ = self.resolve_location(arg)
            addr = addrs[0]
        info = self.dbg.addr2line(addr, self.level == 'asm')
        e = self.dbg.line_entry(addr)
        if e is None:
            r = self.dbg.asm_row(addr)
            if r is None:
                self.say('No line number information available for address %s'
                         % h4(addr))
                return
            self.say('Assembler line %d of "%s" starts at address %s and ends at %s.'
                     % (r[4], self.dbg.file_name(r[3]), h4(r[0]), h4(r[1])))
            return
        f, l = self.dbg.src_primary(e)
        self.say('Line %d of "%s" starts at address %s and ends at %s.'
                 % (l, self.dbg.file_name(f), h4(e[0]), h4(e[1])))

    def cmd_x(self, rest, fmt):
        m = re.fullmatch(r'(\d*)([a-z]*)', fmt)
        count = int(m.group(1)) if m and m.group(1) else 1
        letters = m.group(2) if m else ''
        kind = 'x'
        unit = 1
        for c in letters:
            if c in 'xduci s':
                kind = c
            elif c == 'b':
                unit = 1
            elif c == 'h':
                unit = 2
            elif c == 'w':
                unit = 4
            elif c == 'g':
                unit = 8
        if kind == 'c':
            unit = 1
        if not rest:
            raise UdbError('Argument required (starting display address).')
        addr = self.eval_addr(rest)
        if kind == 'i':
            data = self.read_mem(addr, count * 4 + 4)
            dis = Disassembler(data, org=addr, z80_mode=self.cpu_z80)
            a = addr
            mark = self.pc() if self.alive else None
            for _ in range(count):
                size, text = self.instr_text(dis, a)
                self.say('%s %s %s:\t%s' % ('=>' if a == mark else '  ', h4(a),
                                             self.dbg.symbolize(a), text))
                a += size
            return
        if kind == 's':
            for _ in range(count):
                data = self.read_mem(addr, 256)
                end = data.find(b'\0')
                s = data[:end if end >= 0 else len(data)]
                self.say('%s %s:\t"%s"' % (h4(addr), self.dbg.symbolize(addr),
                                            s.decode('latin-1')))
                addr += len(s) + 1
            return
        per_line = 8 if unit == 1 else 8 // unit if unit <= 8 else 1
        per_line = max(1, per_line)
        data = self.read_mem(addr, count * unit)
        if len(data) < count * unit:
            raise UdbError('Cannot access memory at address %s'
                           % h4(addr + len(data)))
        items = []
        for i in range(count):
            chunk = data[i * unit:(i + 1) * unit]
            v = int.from_bytes(chunk, 'little')
            if kind == 'x':
                items.append('0x%0*x' % (unit * 2, v))
            elif kind == 'd':
                if v >= 1 << (unit * 8 - 1):
                    v -= 1 << (unit * 8)
                items.append(str(v))
            elif kind == 'u':
                items.append(str(v))
            elif kind == 'c':
                ch = chr(v) if 32 <= v < 127 else '\\%03o' % v
                items.append("%d '%s'" % (v, ch))
            else:
                items.append('0x%0*x' % (unit * 2, v))
        for i in range(0, len(items), per_line):
            a = addr + i * unit
            sym = self.dbg.symbolize(a)
            self.say('%s%s:\t%s' % (h4(a), (' ' + sym) if sym else '',
                                     '\t'.join(items[i:i + per_line])))

    def cmd_print(self, rest, fmt):
        if not rest:
            raise UdbError('Argument required (an expression).')
        v, a = self.eval_expr(rest)
        self.hist += 1
        self.say('$%d = %s' % (self.hist, self.format_value(rest, v, a, fmt)))

    def format_value(self, text, v, a, fmt):
        if fmt == 'x':
            return '0x%04x' % (v & 0xFFFF)
        if fmt == 'c':
            return "%d '%s'" % (v & 0xFF, chr(v & 0xFF) if 32 <= v & 0xFF < 127 else '?')
        if fmt == 'o':
            return '0%o' % v
        if fmt == 't':
            return bin(v & 0xFFFF)[2:]
        t = text.strip()
        if (a is not None and v == a) or t.lower() == '$pc' or t.startswith('&'):
            return '%s %s' % (h4(v), self.dbg.symbolize(v))
        return str(v)

    def cmd_sizes(self, rest, fmt):
        print_sizes(self.dbg, self.out)

    def cmd_set(self, rest, fmt):
        parts = rest.split()
        if len(parts) == 2 and parts[0] == 'level' and parts[1] in ('auto', 'src', 'asm'):
            self.level = parts[1]
        elif len(parts) == 2 and parts[0] == 'cpu' and parts[1] in ('z80', '8080'):
            self.cpu_z80 = parts[1] == 'z80'
        elif len(parts) == 2 and parts[0] == 'shadow' and parts[1] in ('on', 'off'):
            self.no_shadow = parts[1] == 'off'
            self.shadow = None
        elif len(parts) >= 1 and parts[0] in ('confirm', 'pagination', 'width', 'height'):
            pass
        else:
            raise UdbError('set: use "set level auto|src|asm", "set cpu z80|8080" or "set shadow on|off".')

    def cmd_monitor(self, rest, fmt):
        self.need_alive()
        reply = self.rsp.cmd('qRcmd,' + rest.encode().hex())
        try:
            self.out.write(bytes.fromhex(reply).decode('latin-1'))
        except ValueError:
            self.say(reply)
        self.out.flush()

    def cmd_echo(self, rest, fmt):
        self.out.write(rest.replace('\\n', '\n'))
        self.out.flush()

    def cmd_kill(self, rest, fmt):
        self.kill()

    def cmd_quit(self, rest, fmt):
        pass

    def cmd_help(self, rest, fmt):
        self.say('Commands: break tbreak delete continue step next stepi finish '
                 'backtrace list disassemble info x print sizes set monitor '
                 'echo kill quit.')
        self.say('Locations: FILE:LINE, FUNCTION or LABEL, *ADDRESS.')
        self.say('See docs/udb80.md.')

    def kill(self):
        if self.alive:
            try:
                self.rsp.send('k')
            except OSError:
                pass
            self.alive = False


# ---------------------------------------------------------------------------
# Static commands
# ---------------------------------------------------------------------------

def print_sizes(dbg, out):
    rows = dbg.sizes()
    total = 0
    for size, start, name in rows:
        out.write('%6d  %04X  %s\n' % (size, start, name))
        total += size
    out.write('%6d  total in %d routine%s\n' % (total, len(rows),
                                                 '' if len(rows) == 1 else 's'))


def parse_addr(text):
    try:
        v = parse_int(text)
    except ValueError:
        try:
            v = int(text, 16)
        except ValueError:
            raise UdbError('"%s" is not an address' % text)
    if not 0 <= v <= 0xFFFF:
        raise UdbError('address %s is out of range' % text)
    return v


def cmd_addr2line(argv):
    ap = argparse.ArgumentParser(prog='udb80 addr2line')
    ap.add_argument('dbg')
    ap.add_argument('addr', nargs='+')
    ap.add_argument('-r', '--return-address', action='store_true',
                    help='each ADDR is a return address; look up ADDR-1')
    ap.add_argument('--asm', action='store_true',
                    help='show the assembler line, not the source line')
    ap.add_argument('--program', help='the program file for the image check')
    args = ap.parse_intermixed_args(argv)
    dbg = DebugInfo(args.dbg)
    dbg.check_program_file(args.program)
    status = 0
    for text in args.addr:
        addr = parse_addr(text)
        probe = addr - 1 if args.return_address else addr
        info = dbg.addr2line(probe, args.asm)
        name = info['func'] or '??'
        if info['func'] and info['offset']:
            name = '%s+%d' % (info['func'], info['offset'])
        if info['src'] is not None:
            f, l, inl = info['src']
            line = '%s  %s  %s:%d' % (h4(addr), name, f, l)
            if inl:
                line += '  (inlined: %s)' % ', '.join(
                    '%s at %s:%d' % (n, dbg.file_name(ff), ll) for n, ff, ll in inl)
            if info['asm']:
                line += '  [asm %s:%d]' % info['asm']
        elif info['asm'] is not None:
            line = '%s  %s  %s:%d  [asm]' % ((h4(addr), name) + info['asm'])
        else:
            line = '%s  %s  ??:0' % (h4(addr), name)
            status = 1
        print(line)
    return status


def cmd_sizes(argv):
    ap = argparse.ArgumentParser(prog='udb80 sizes')
    ap.add_argument('dbg')
    ap.add_argument('--program', help='the program file for the image check')
    args = ap.parse_args(argv)
    dbg = DebugInfo(args.dbg)
    dbg.check_program_file(args.program)
    print_sizes(dbg, sys.stdout)
    return 0


class DumpView(Debugger):
    """A memory dump and three registers instead of a running program: the
    part of Debugger that bt-dump needs."""

    def __init__(self, dbg, memory, regs, out=None):
        self.dbg = dbg
        self.out = out or sys.stdout
        self.memory = memory
        self._regs = regs
        self.level = 'auto'
        self.cpu_z80 = True
        self.alive = True
        self.src_cache = {}
        self._pages = {}
        self.errors = 0
        self.src_dirs = []

    def read_mem(self, addr, length):
        return bytes(self.memory[addr:addr + length])

    def page_byte(self, addr):
        return self.memory[addr] if 0 <= addr < len(self.memory) else None


def cmd_bt_dump(argv):
    ap = argparse.ArgumentParser(
        prog='udb80 bt-dump',
        description='Show the backtrace of a memory dump from the frame '
                    'records of PROG.dbg.  The dump is the file that '
                    'cpmemu --save-memory=FILE writes.')
    ap.add_argument('dbg')
    ap.add_argument('memory', help='64K memory image, from address 0')
    ap.add_argument('sp', help='the value of SP')
    ap.add_argument('pc', help='the value of PC')
    ap.add_argument('--ix', help='the value of IX (needed when PC is in the '
                                 'IX range of a routine)')
    ap.add_argument('--program', help='the program file for the image check')
    ap.add_argument('-n', '--count', type=int, help='show only N frames')
    args = ap.parse_args(argv)
    dbg = DebugInfo(args.dbg)
    dbg.check_program_file(args.program)
    try:
        with open(args.memory, 'rb') as f:
            memory = f.read()
    except OSError as e:
        raise UdbError('cannot read %s: %s' % (args.memory, e))
    if len(memory) != 0x10000:
        raise UdbError('%s has %d bytes; a dump from cpmemu --save-memory '
                       'has 65536' % (args.memory, len(memory)))
    img = dbg.image
    if img.get('kind') == 'com' and img.get('load') is not None:
        dbg.check_memory(memory[img['load']:img['load'] + (img.get('length') or 0)])
    sp, pc = parse_addr(args.sp), parse_addr(args.pc)
    ix = parse_addr(args.ix) if args.ix else None
    view = DumpView(dbg, memory, {'sp': sp, 'pc': pc, 'ix': ix})
    walker = frames.Walker(dbg.frame_program(), view.page_byte)
    chain = walker.walk(pc, sp, ix)
    if len(chain) > 1 or walker.bottom:
        entries = [(a, tag) for a, _sp, tag in chain]
    else:
        entries = [(a, 'guess') for a in [pc] + view.guess_frames()]
    view.print_frames(entries, args.count)
    return 0


# ---------------------------------------------------------------------------
# Starting and connecting
# ---------------------------------------------------------------------------

def start_cpmemu(run, stdin):
    """Start `cpmemu ARGS` with --gdb=0, wait for the port file."""
    argv = shlex.split(run)
    if not argv:
        raise UdbError('--run needs a command')
    fd, portfile = tempfile.mkstemp(prefix='udb80-port-')
    os.close(fd)
    os.remove(portfile)
    argv[1:1] = ['--gdb=0', '--gdb-port-file=' + portfile]
    try:
        proc = subprocess.Popen(argv, stdin=stdin)
    except OSError as e:
        raise UdbError('cannot start %s: %s' % (argv[0], e))
    deadline = time.time() + 30
    port = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise UdbError('%s ended with status %d before it listened'
                           % (argv[0], proc.returncode))
        try:
            with open(portfile) as f:
                text = f.read().strip()
            if text:
                port = int(text)
                break
        except (OSError, ValueError):
            pass
        time.sleep(0.02)
    try:
        os.remove(portfile)
    except OSError:
        pass
    if port is None:
        proc.kill()
        raise UdbError('%s did not write its port in 30 seconds' % argv[0])
    return proc, port


def connect(host, port):
    deadline = time.time() + 10
    while True:
        try:
            return socket.create_connection((host, port), timeout=10)
        except OSError as e:
            if time.time() > deadline:
                raise UdbError('cannot connect to %s:%d: %s' % (host, port, e))
            time.sleep(0.05)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if argv and argv[0] == 'addr2line':
            return cmd_addr2line(argv[1:])
        if argv and argv[0] == 'sizes':
            return cmd_sizes(argv[1:])
        if argv and argv[0] == 'bt-dump':
            return cmd_bt_dump(argv[1:])
        return debug_main(argv)
    except UdbError as e:
        sys.stderr.write('udb80: %s\n' % e)
        return 2


def debug_main(argv):
    ap = argparse.ArgumentParser(
        prog='udb80',
        description='Source-level debugger for Z80 and 8080 programs. '
                    'Other forms: udb80 addr2line PROG.dbg ADDR..., '
                    'udb80 sizes PROG.dbg, udb80 bt-dump PROG.dbg MEMORY.BIN SP PC.')
    ap.add_argument('dbg', help='the prog.dbg file that ul80 --debug-info wrote')
    ap.add_argument('--run', metavar='CMD',
                    help="start cpmemu: --run 'cpmemu prog.com'; udb80 adds "
                         "--gdb=0 and --gdb-port-file")
    ap.add_argument('--connect', metavar='HOST:PORT',
                    help='connect to a stub that already runs')
    ap.add_argument('-ex', dest='ex', action='append', default=[], metavar='CMD',
                    help='run a command (repeatable)')
    ap.add_argument('-x', '--command', dest='cmdfile', metavar='FILE',
                    help='run the commands in FILE')
    ap.add_argument('--batch', action='store_true',
                    help='run the commands, then quit')
    ap.add_argument('--program', help='the program file for the image check')
    ap.add_argument('-d', '--directory', action='append', default=[],
                    help='a directory to look for source files')
    ap.add_argument('--asm', action='store_true', help='start in assembler level')
    ap.add_argument('--8080', dest='cpu8080', action='store_true',
                    help='disassemble as 8080')
    args = ap.parse_args(argv)
    if bool(args.run) == bool(args.connect):
        raise UdbError('give one of --run and --connect')
    dbg = DebugInfo(args.dbg)
    dbg.check_program_file(args.program)
    commands = []
    if args.cmdfile:
        try:
            with open(args.cmdfile, encoding='utf-8') as f:
                commands += [l.rstrip('\n') for l in f]
        except OSError as e:
            raise UdbError('cannot read %s: %s' % (args.cmdfile, e))
    commands = list(args.ex) + commands if not args.cmdfile else commands + list(args.ex)
    proc = None
    sock = None
    try:
        if args.run:
            interactive = not args.batch and sys.stdin.isatty()
            proc, port = start_cpmemu(args.run, subprocess.DEVNULL if interactive else None)
            host = '127.0.0.1'
        else:
            host, _, p = args.connect.rpartition(':')
            host = host or '127.0.0.1'
            try:
                port = int(p)
            except ValueError:
                raise UdbError('--connect wants HOST:PORT')
        sock = connect(host, port)
        dbr = Debugger(dbg, Rsp(sock))
        dbr.src_dirs = args.directory
        if args.asm:
            dbr.level = 'asm'
        if args.cpu8080:
            dbr.cpu_z80 = False
        dbr.check_memory()
        dbr.say('Connected; the program is stopped before %s.' % h4(dbr.pc()))
        for c in commands:
            if not dbr.execute(c):
                break
        else:
            if not args.batch:
                while True:
                    try:
                        sys.stdout.write('(udb80) ')
                        sys.stdout.flush()
                        line = sys.stdin.readline()
                    except KeyboardInterrupt:
                        sys.stdout.write('\n')
                        continue
                    if not line:
                        break
                    if not dbr.execute(line):
                        break
        dbr.kill()
        return 1 if (args.batch and dbr.errors) else 0
    finally:
        if sock is not None:
            try:
                if proc is not None:
                    sock.sendall(b'$k#6b')     # end cpmemu if it still runs
                sock.close()
            except OSError:
                pass
        if proc is not None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == '__main__':
    sys.exit(main())
