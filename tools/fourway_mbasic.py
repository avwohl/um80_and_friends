#!/usr/bin/env python3
"""Build mbasic2025 with every mix of Microsoft's MACRO-80/LINK-80 and um80/ul80.

mbasic2025 (https://github.com/avwohl/mbasic2025) holds MACRO-80 sources that
rebuild historic Microsoft BASIC binaries byte for byte.  tests/test_mbasic2025.py
checks that this checkout's um80 and ul80 still do.  This script asks the other
question: are um80/ul80 and the genuine tools interchangeable?  For each variant it

  1. assembles every module with the genuine M80.COM (under the cpmemu CP/M
     emulator) and with this checkout's um80;
  2. compares each module's two .REL files: segment sizes, PUBLIC and EXTRN
     names, entry point, and which bytes each loads;
  3. links, with the genuine L80.COM and with this checkout's ul80, the .REL
     sets "every module from M80", "every module from um80", and - for a
     variant of several modules - each "one module from M80, the rest from
     um80" and "one module from um80, the rest from M80";
  4. compares every image with the all-Microsoft build (M80 + L80) and with the
     historic binary.

Microsoft's binaries are not part of this repository: pass them by path.

    python3 tools/fourway_mbasic.py --m80 M80.COM --l80 L80.COM \\
        [--mbasic2025 DIR] [--cpmemu PATH] [--variant NAME ...] [--work DIR]
        [--um80-flag=-t] [--um80 TREE]

--um80-flag passes an option to um80: -t, to cut names to the six
characters M80 keeps, is what makes a module that declares a longer PUBLIC
link with M80's objects.  --um80 runs another um80 source tree's um80 and
ul80 (a release, to compare with).

The paths also come from the environment: M80_COM, L80_COM, CPMEMU, and
MBASIC2025_DIR (default: a mbasic2025 checkout next to this repository).
Tested with MACRO-80 3.44 and LINK-80 3.44 (09-Dec-81) and cpmemu
(https://github.com/avwohl/cpmemu).

What is compared, and why:

  * LINK-80 does not clear memory it reserves with DS: a DS at the end of the
    program comes out as whatever LINK-80 had in that memory.  ul80 writes
    zeros there, as do the historic binaries.  So bytes no .REL item loads -
    the "holes" - are left out of an L80 image's comparison and counted
    instead ("N hole bytes as L80 left them").  An image from ul80 is
    compared in full: its holes must be zero.
  * A variant with no historic binary (mbasic_52) is compared with the
    all-Microsoft build, its holes taken as zero.
  * L80 writes whole 128-byte records, ul80 pads its output to one: only the
    reference's length (or the program's) is compared.

The exit status is 1 when any image built with um80 or ul80 differs from the
all-Microsoft one (an interchangeability failure), 2 on a setup error, else 0.
Without --um80-flag=-t that includes the mixes a name longer than six
characters breaks - mbasic_521's FBUFP27, which M80 writes as FBUFP2: 8 of
its 60 links.  The tool names such a symbol and says to use -t; as a
pass/fail check, run it with --um80-flag=-t.
A difference from the historic binary that the all-Microsoft build shares is
reported, not failed: it is the source, not the tools.  A module M80 cannot
assemble is reported, and the mixes that need its M80 .REL are left out.
docs/mbasic2025.md has the results.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from um80.relformat import RELReader  # noqa: E402  pylint: disable=wrong-import-position

MBASIC_521 = ['bintrp', 'f4', 'biptrg', 'biedit', 'biprtu', 'bio', 'bimisc',
              'bistrs', 'binlin', 'fiveo', 'dskcom', 'dcpm', 'fivdsk', 'init']
# mbasic_52/makefile's order: bintrp, then alphabetical.
MBASIC_52 = ['bintrp', 'biedit', 'bimisc', 'binlin', 'bio', 'biprtu', 'biptrg',
             'bistrs', 'dcpm', 'dskcom', 'f4', 'fivdsk', 'fiveo', 'init']

# name: (source directory, [(source file stem, CP/M name)], reference, origin)
VARIANTS = {
    'mbasic_521': ('mbasic_521/mbasic_src', [(m, m.upper()) for m in MBASIC_521],
                   'mbasic_521/com/mbasic.com', 0x100),
    'mbasic_52': ('mbasic_52', [(m, m.upper()) for m in MBASIC_52], None, 0x100),
    'mbasicz': ('mbasicz', [('mbasicz', 'MBASICZ')], 'mbasicz/com/mbasic.com', 0x100),
    '4k': ('4k8k/4k', [('4kbas40_new', 'BAS4K')], '4k8k/4k/4kbas40.bin', 0),
    '4k-annotated': ('4k8k/4k', [('4kbas40', 'BAS4KA')], '4k8k/4k/4kbas40.bin', 0),
    '8k': ('4k8k/8k', [('8kbas_src', 'BAS8K')], '4k8k/8k/8kbas.bin', 0),
}


class SetupError(Exception):
    """Something needed to run is missing or did not work."""


def find_file(d, name):
    """`name' in directory `d', in either case (cpmemu writes lower case)."""
    for cand in (name, name.lower(), name.upper()):
        p = os.path.join(d, cand)
        if os.path.exists(p):
            return p
    return None


class Tools:
    """The genuine tools under cpmemu, and this checkout's um80/ul80."""

    def __init__(self, m80, l80, cpmemu, python, um80_root, um80_flags=()):
        self.m80, self.l80, self.cpmemu, self.python = m80, l80, cpmemu, python
        self.um80_root = um80_root
        self.um80_flags = list(um80_flags)

    def cpm(self, prog, d, tail=None, stdin=b''):
        """Run a CP/M program in directory `d'; return its console output."""
        name = os.path.basename(prog).upper()
        if not os.path.exists(os.path.join(d, name)):
            shutil.copy(prog, os.path.join(d, name))
        # cpmemu otherwise converts files the program writes as text: it
        # stops at the first 1AH and drops the CR of a CR LF.
        with open(os.path.join(d, 'run.cfg'), 'w', encoding='ascii') as f:
            f.write(f'program = {name}\ndefault_mode = binary\neol_convert = false\n')
        args = [self.cpmemu, 'run.cfg'] + ([tail] if tail else [])
        try:
            r = subprocess.run(args, cwd=d, input=stdin, capture_output=True,
                               timeout=600, check=False)
        except subprocess.TimeoutExpired as e:
            raise SetupError(f'{name} {tail or ""} timed out in {d}') from e
        return (r.stdout + r.stderr).decode('latin1').replace('\r', '')

    def um(self, module, d, *args):
        """Run um80.<module> (um80 or ul80); return (status, output)."""
        env = dict(os.environ, PYTHONPATH=self.um80_root, PYTHONDONTWRITEBYTECODE='1')
        try:
            r = subprocess.run([self.python, '-m', 'um80.' + module, *args], cwd=d,
                               capture_output=True, text=True, env=env, timeout=600,
                               check=False)
        except subprocess.TimeoutExpired as e:
            raise SetupError(f'{module} {" ".join(args)} timed out in {d}') from e
        return r.returncode, r.stdout + r.stderr


def m80_flags(prn):
    """The flagged lines of an M80 listing: an error letter in column 1."""
    out = []
    with open(prn, 'rb') as f:
        text = f.read().decode('latin1').replace('\r', '')
    for line in text.split('\n'):
        if re.match(r'[A-Z%] ', line) and not line.startswith(('Macros', 'Symbols')):
            out.append(line.rstrip())
    return out


def rel_summary(path, base):
    """What a .REL defines and loads, with its program area at `base'.

    Returns a dict: 'loaded' (the addresses it loads a byte at), 'size'
    (program area), 'publics' {name: (type, value)}, 'externs' (external
    names it refers to), 'declared' (EXTRN names with an empty chain: declared
    and never used), 'name', 'start' (END's address).  Only program-relative
    and absolute code is modelled: every mbasic2025 variant is that.
    """
    with open(path, 'rb') as f:
        items = RELReader(f.read()).read_all()
    s = {'loaded': set(), 'size': 0, 'publics': {}, 'externs': set(),
         'declared': set(), 'name': None, 'start': None}
    seg, loc = 1, 0
    for it in items:
        kind = it[0]
        if kind == 'SET_LOC':
            seg, loc = it[1]
        elif kind in ('ABSOLUTE_BYTE', 'PROGRAM_REL', 'DATA_REL', 'COMMON_REL'):
            n = 1 if kind == 'ABSOLUTE_BYTE' else 2
            if seg not in (0, 1):
                raise SetupError(f'{path}: data or COMMON segment: not modelled')
            for i in range(n):
                s['loaded'].add((base if seg == 1 else 0) + loc + i)
            loc += n
        elif kind == 'DEFINE_PROG_SIZE':
            s['size'] = it[1][1]
        elif kind == 'DEFINE_DATA_SIZE' and it[1][1]:
            raise SetupError(f'{path}: data segment: not modelled')
        elif kind == 'DEFINE_ENTRY':
            s['publics'][it[2]] = it[1]
        elif kind == 'CHAIN_EXTERNAL':
            s['declared' if it[1] == (0, 0) else 'externs'].add(it[2])
        elif kind == 'EXT_SYMBOL':
            s['externs'].add(it[1])
        elif kind == 'PROGRAM_NAME':
            s['name'] = it[1]
        elif kind == 'END_PROGRAM':
            s['start'] = it[1]
    s['declared'] -= s['externs']
    return s


def compare_rels(m, u):
    """Differences between the M80 and um80 .REL summaries of one module."""
    out = []
    if m['name'] != u['name']:
        out.append(f"module name M80 {m['name']} um80 {u['name']}")
    if m['size'] != u['size']:
        out.append(f"program size M80 {m['size']:04X}H um80 {u['size']:04X}H")
    only_m = sorted(set(m['publics']) - set(u['publics']))
    only_u = sorted(set(u['publics']) - set(m['publics']))
    if only_m:
        out.append('PUBLIC only from M80: ' + ' '.join(only_m))
    if only_u:
        out.append('PUBLIC only from um80: ' + ' '.join(only_u))
    val = sorted(n for n in set(m['publics']) & set(u['publics'])
                 if m['publics'][n] != u['publics'][n])
    if val:
        out.append('PUBLIC values differ: ' + ' '.join(
            f"{n}={m['publics'][n][1]:04X}/{u['publics'][n][1]:04X}" for n in val[:8]))
    if m['externs'] != u['externs']:
        out.append('EXTRN used, only from M80: ' + ' '.join(sorted(m['externs'] - u['externs']))
                   + '; only from um80: ' + ' '.join(sorted(u['externs'] - m['externs'])))
    if m['declared'] != u['declared']:
        out.append(f"EXTRN declared and not used: M80 writes {len(m['declared'])},"
                   f" um80 {len(u['declared'])}")
    if m['start'] != u['start']:
        out.append(f"END address M80 {m['start']} um80 {u['start']}")
    if m['loaded'] != u['loaded']:
        a = sorted(m['loaded'] - u['loaded'])
        b = sorted(u['loaded'] - m['loaded'])
        out.append(f'loaded bytes differ: {len(a)} only M80 (first {a[:1]}),'
                   f' {len(b)} only um80 (first {b[:1]})')
    return out


def long_names(m, u):
    """{um80 name: M80 name} for the names um80 keeps longer than M80's 6.

    M80 cuts a PUBLIC or EXTRN name to 6 characters; um80 keeps it whole
    unless -t is given.  Such a module's .REL from one assembler does not
    link with the modules from the other that define or use the name.
    """
    out = {}
    for key in ('publics', 'externs'):
        only_m = set(m[key]) - set(u[key])
        for name in set(u[key]) - set(m[key]):
            if len(name) > 6 and name[:6] in only_m:
                out[name] = name[:6]
    return out


def ranges(addrs):
    """'0C44-0C45 5E99' from a sorted address list."""
    out, start, prev = [], None, None
    for a in addrs:
        if start is None:
            start = prev = a
        elif a == prev + 1:
            prev = a
        else:
            out.append((start, prev))
            start = prev = a
    if start is not None:
        out.append((start, prev))
    return ' '.join(f'{a:04X}' if a == b else f'{a:04X}-{b:04X}' for a, b in out)


class Variant:
    """One mbasic2025 variant: assemble both ways, link every mix, compare."""

    def __init__(self, name, spec, src_root, tools, work):
        self.name = name
        self.src_dir, self.mods, ref, self.origin = spec
        self.src_dir = os.path.join(src_root, self.src_dir)
        self.ref = None
        if ref:
            with open(os.path.join(src_root, ref), 'rb') as f:
                self.ref = f.read()
        self.tools = tools
        self.work = os.path.join(work, name)
        self.summaries = {}
        self.notes = []
        self.m80_failed = set()   # modules M80 has fatal errors in
        self.long_names = {}      # um80 name: the 6 characters M80 keeps
        self.bad = False

    def assemble(self):
        """Assemble every module with M80 and with um80."""
        for tag in ('m80', 'um80'):
            os.makedirs(os.path.join(self.work, tag), exist_ok=True)
        for stem, cpm in self.mods:
            src = os.path.join(self.src_dir, stem + '.mac')
            with open(src, 'rb') as f:
                text = f.read()
            d = os.path.join(self.work, 'm80')
            with open(os.path.join(d, cpm + '.MAC'), 'wb') as f:
                f.write(text.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
            out = self.tools.cpm(self.tools.m80, d, f'{cpm},{cpm}={cpm}')
            m = re.search(r'(No|\d+) Fatal error\(s\)(?:,(\d+) Warning\(s\))?', out)
            if not m or not find_file(d, cpm + '.REL'):
                raise SetupError(f'M80 did not run on {stem}: {out[-400:]}')
            if m.group(1) != 'No':
                self.m80_failed.add(stem)
            if m.group(1) != 'No' or m.group(2):
                flags = m80_flags(find_file(d, cpm + '.PRN'))
                self.notes.append(f'M80 {stem}.mac: {m.group(0)}: ' + ' | '.join(flags[:3]))
            if 'No END statement' in out:
                self.notes.append(f'M80 {stem}.mac: %No END statement (the last line has no'
                                  ' line terminator, so M80 never reads its END)')
            # um80 gets the same file name M80 does, so that a module without
            # NAME or TITLE gets the same module name from both.
            d = os.path.join(self.work, 'um80')
            shutil.copy(src, os.path.join(d, cpm + '.MAC'))
            rc, msg = self.tools.um('um80', d, *self.tools.um80_flags, cpm + '.MAC',
                                    '-o', cpm + '.REL')
            if rc:
                raise SetupError(f'um80 did not assemble {stem}: {msg[-400:]}')
            warn = [ln for ln in msg.splitlines() if 'arning' in ln]
            if warn:
                self.notes.append(f'um80 {stem}.mac: ' + ' | '.join(warn[:3]))

    def rel_path(self, tag, cpm):
        """The .REL of module `cpm' from assembler `tag'."""
        return find_file(os.path.join(self.work, tag), cpm + '.REL')

    def combos(self):
        """[(label, [tag per module])], leaving out an M80 .REL with errors."""
        n = len(self.mods)
        out = [('all M80', ['m80'] * n), ('all um80', ['um80'] * n)]
        if n > 1:
            for i, (stem, _) in enumerate(self.mods):
                tags = ['um80'] * n
                tags[i] = 'm80'
                out.append((f'M80 {stem}, um80 rest', tags))
            for i, (stem, _) in enumerate(self.mods):
                tags = ['m80'] * n
                tags[i] = 'um80'
                out.append((f'um80 {stem}, M80 rest', tags))
        return [(label, tags) for label, tags in out
                if not any(t == 'm80' and stem in self.m80_failed
                           for t, (stem, _) in zip(tags, self.mods))]

    def loaded(self, tags):
        """Addresses the .REL set loads a byte at, and the program's end."""
        base, top, loaded = self.origin, self.origin, set()
        for (_, cpm), tag in zip(self.mods, tags):
            key = (tag, cpm, base)
            if key not in self.summaries:
                self.summaries[key] = rel_summary(self.rel_path(tag, cpm), base)
            s = self.summaries[key]
            loaded |= s['loaded']
            base += s['size']
            top = max(top, base)
        return loaded, max(top, max(loaded) + 1 if loaded else top)

    def link(self, label, tags, linker):
        """Link one .REL set with `linker'; return (image, messages)."""
        d = os.path.join(self.work, 'link', re.sub(r'\W+', '_', label) + '_' + linker)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        names = []
        for (_, cpm), tag in zip(self.mods, tags):
            shutil.copy(self.rel_path(tag, cpm), os.path.join(d, cpm + '.REL'))
            names.append(cpm)
        if linker == 'L80':
            words = [f'/P:{self.origin:X}'] + names
            lines, cur = [], ''
            for w in words:
                if cur and len(cur) + len(w) > 60:
                    lines.append(cur)
                    cur = ''
                cur += (',' if cur else '') + w
            lines += [cur, 'OUT/N/E', 'Y']   # Y: "Origin below loader memory, move anyway?"
            out = self.tools.cpm(self.tools.l80, d, stdin=('\r\n'.join(lines) + '\r\n').encode())
            # Undefined globals are listed after each command line until the
            # module that defines them is loaded: only the last list counts.
            final = out.split('OUT/N/E')[-1]
            msgs = [ln.strip() for ln in final.split('\n')
                    if ln.strip().startswith(('?', '%')) or 'Undefined' in ln]
        else:
            rc, out = self.tools.um('ul80', d, '-p', f'{self.origin:X}', '-o', 'OUT.COM',
                                    *[n + '.REL' for n in names])
            msgs = [ln.strip() for ln in out.splitlines()
                    if rc or 'rror' in ln or 'arning' in ln]
        p = find_file(d, 'OUT.COM')
        if p is None:
            return None, msgs or [out.strip()[-200:]]
        with open(p, 'rb') as f:
            return f.read(), msgs

    def run(self):
        """Assemble, compare .RELs, link every mix; print the results."""
        print(f'== {self.name}: {len(self.mods)} module(s) from {self.src_dir}')
        self.assemble()
        n_same = 0
        for stem, cpm in self.mods:
            m, u = (rel_summary(self.rel_path(tag, cpm), 0) for tag in ('m80', 'um80'))
            diffs = compare_rels(m, u)
            self.long_names.update(long_names(m, u))
            if diffs:
                print(f'   {stem}.rel M80 vs um80: ' + '; '.join(diffs))
            else:
                n_same += 1
        print(f'   .REL M80 vs um80: {n_same}/{len(self.mods)} modules alike')
        for note in self.notes:
            print('   note:', note)

        combos = self.combos()
        results = {}
        for label, tags in combos:
            for linker in ('L80', 'ul80'):
                results[label, linker] = self.link(label, tags, linker)

        # The all-Microsoft build, its holes taken as zero.
        ms_img = results.get(('all M80', 'L80'), (None, ['M80 has errors']))
        loaded, top = self.loaded(['m80' if ms_img[0] else 'um80'] * len(self.mods))
        length = len(self.ref) if self.ref is not None else top - self.origin
        ms = None
        if ms_img[0] is not None:
            ms = bytes(ms_img[0][i] if self.origin + i in loaded else 0 for i in range(length))
        if self.ref is not None:
            print(f'   historic binary: {length} bytes')
        elif ms is not None:
            print(f'   no historic binary: the reference is M80 + L80 ({length} bytes)')
        else:
            print('   no historic binary, and no M80 + L80 build to compare with')
        if ms is None:
            print('   M80 + L80 did not build it: ' + ' | '.join(ms_img[1][:3]))

        width = max(len(label) for label, _ in combos)
        print(f'   {"assembled with":{width}s}  {"linked with L80":40s}  linked with ul80')
        for label, tags in combos:
            loaded, _ = self.loaded(tags)
            cells = []
            for linker in ('L80', 'ul80'):
                img, msgs = results[label, linker]
                cells.append(self.verdict(img, loaded, length, ms, linker))
            print(f'   {label:{width}s}  {cells[0]:40s}  {cells[1]}')
            for linker in ('L80', 'ul80'):
                img, msgs = results[label, linker]
                if msgs:
                    print(f'   {"":{width}s}    {linker} said: ' + ' | '.join(msgs[:4]))
        if self.ref is not None and ms is not None:
            self.explain(ms, self.loaded(['m80'] * len(self.mods))[0], length)
        if self.long_names and self.bad:
            print('   cause: ' + ', '.join(f'{u} (M80: {m})' for u, m in
                                         sorted(self.long_names.items()))
                  + ': M80 keeps 6 characters of a name and um80 all of them, so a'
                  ' module that defines it and one that uses it do not link when'
                  ' they come from different assemblers; um80 -t keeps 6'
                  ' (--um80-flag=-t)')

    def verdict(self, img, loaded, length, ms, linker):
        """One cell of the matrix, e.g. '= historic (5 hole bytes as L80 left them)'."""
        if img is None:
            self.bad = True
            return 'NO IMAGE'
        img = img[:length].ljust(length, b'\0')

        def differ(ref):
            return [i for i in range(length) if img[i] != ref[i]
                    and (self.origin + i in loaded or linker == 'ul80')]

        def where(diff):
            return f'{len(diff)} bytes at {ranges([self.origin + i for i in diff])[:19]}'
        vs_ms = differ(ms) if ms is not None else None
        vs_ref = differ(self.ref) if self.ref is not None else None
        if vs_ms:
            self.bad = True
            text = 'DIFFERS from M80+L80: ' + ('= historic' if vs_ref == [] else where(vs_ms))
        elif vs_ms == [] and vs_ref is None:
            text = '= M80+L80'
        elif vs_ref == []:
            text = '= historic'
        elif vs_ms == []:
            text = '= M80+L80, not historic'
        elif vs_ref:
            text = 'not historic: ' + where(vs_ref)
        else:
            text = '(nothing to compare with)'
        holes = [i for i in range(length) if self.origin + i not in loaded and img[i]]
        if holes and linker == 'L80':
            text += f' ({len(holes)} hole bytes as L80 left them)'
        return text

    def explain(self, ms, loaded, length):
        """Where the all-Microsoft build differs from the historic binary."""
        diff = [self.origin + i for i in range(length) if ms[i] != self.ref[i]]
        if not diff:
            return
        print(f'   M80 + L80 differs from the historic binary in {len(diff)} bytes'
              f' at {ranges(diff)[:100]}')
        for a in diff[:4]:
            i = a - self.origin
            print(f'     {a:04X}: historic {self.ref[i]:02X} M80+L80 {ms[i]:02X}'
                  f'{"" if a in loaded else " (hole)"}')


def main(argv=None):
    """Command line entry point."""
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n', maxsplit=1)[0])
    ap.add_argument('--m80', default=os.environ.get('M80_COM'), help='genuine M80.COM')
    ap.add_argument('--l80', default=os.environ.get('L80_COM'), help='genuine L80.COM')
    ap.add_argument('--cpmemu', default=os.environ.get('CPMEMU') or shutil.which('cpmemu'),
                    help='cpmemu binary (default: $CPMEMU, or cpmemu on PATH)')
    ap.add_argument('--mbasic2025', default=os.environ.get('MBASIC2025_DIR')
                    or os.path.join(os.path.dirname(REPO), 'mbasic2025'),
                    help='mbasic2025 checkout (default: $MBASIC2025_DIR, or ../mbasic2025)')
    ap.add_argument('--variant', action='append', choices=list(VARIANTS),
                    help='variant to build (repeatable; default: all)')
    ap.add_argument('--work', help='work directory, kept (default: a temporary one)')
    ap.add_argument('--um80', default=REPO,
                    help='um80 source tree whose um80/ul80 to run (default: this checkout)')
    ap.add_argument('--um80-flag', action='append', default=[], metavar='FLAG',
                    help='pass FLAG to um80 (repeatable), e.g. --um80-flag=-t')
    ap.add_argument('--python', default=sys.executable,
                    help='Python that runs um80/ul80 (default: this one)')
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(line_buffering=True)
    for what in ('m80', 'l80', 'cpmemu'):
        if not getattr(args, what) or not os.path.exists(getattr(args, what)):
            print(f'fourway_mbasic: --{what} not given or not found', file=sys.stderr)
            return 2
    if not os.path.isdir(os.path.join(args.mbasic2025, 'mbasic_521')):
        print(f'fourway_mbasic: no mbasic2025 checkout at {args.mbasic2025}', file=sys.stderr)
        return 2
    tools = Tools(os.path.abspath(args.m80), os.path.abspath(args.l80),
                  os.path.abspath(args.cpmemu), args.python, os.path.abspath(args.um80),
                  args.um80_flag)
    work = args.work or tempfile.mkdtemp(prefix='fourway_')
    bad = too_long = False
    try:
        for name in args.variant or list(VARIANTS):
            v = Variant(name, VARIANTS[name], args.mbasic2025, tools, os.path.abspath(work))
            v.run()
            bad = bad or v.bad
            too_long = too_long or (v.bad and bool(v.long_names))
    except SetupError as e:
        print(f'fourway_mbasic: {e}', file=sys.stderr)
        return 2
    finally:
        if not args.work:
            shutil.rmtree(work, ignore_errors=True)
    print('RESULT:', 'some image built with um80 or ul80 differs from M80 + L80' if bad
          else 'every mix of M80/um80 and L80/ul80 that M80 can assemble'
          ' builds the M80 + L80 image')
    if too_long:
        print('        names longer than 6 characters (see "cause:" above) break some'
              ' mixes; rerun with --um80-flag=-t to check the rest')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
