#!/usr/bin/env python3
"""Prototype of dbg2elf for docs/debugger_plan.md phase 0.

Reads an um80 .mac with ;#file/;#line markers and its .PRN listing, and the
.COM ul80 made from it (CSEG at 0100H).  Writes an ELF32 EM_Z80 file with
the image, a symbol table, and DWARF 4 .debug_abbrev/.debug_info/.debug_line.

Rule D4 of the plan: a marker is a state; markers with no byte between them
all belong to the next instruction; the first is primary.  In DWARF the
lines that are not primary go first at the address with is_stmt off, and
the primary row comes last with is_stmt on.
"""
import re, struct, sys

mac, prn, com, out = sys.argv[1:5]
BASE = 0x100

src = open(mac).read().split('\n')
files = {}
rows = []           # (addr, [(file, line, stmt)...])
pending = []        # markers since the last byte
state = None
for ln in open(prn):
    ln = ln.rstrip('\n')
    m = re.match(r'\s*(\d+)\s+([0-9A-F]{4})\s+((?:[0-9A-F]{2}[\'"*]?\s)+)', ln)
    num = int(ln[:5]) if ln[:5].strip().isdigit() else None
    if num is None:
        continue
    text = src[num - 1]
    mk = re.match(r';\s*#(\w+)\s*(.*)', text)
    if mk:
        kind, rest = mk.groups()
        if kind == 'file':
            n, name = rest.split(None, 1)
            files[int(n)] = name.strip('"')
        elif kind == 'line':
            p = rest.split()
            pending.append((int(p[0]), int(p[1]), 'nostmt' not in p[2:]))
        continue
    if m and not text.lstrip().startswith(('dw', 'db')) and '\tdw\t' not in text:
        addr = BASE + int(m.group(2), 16)
        if pending:                       # a row starts where a marker group lands
            rows.append((addr, pending))
            pending = []

code_end = rows[-1][0] + 1
image = open(com, 'rb').read()

labels = {}
for i, text in enumerate(src):
    lm = re.match(r'(\w+):', text)
    if lm:
        labels[lm.group(1)] = i + 1
# label addresses from the listing: the next line with an address
prn_addr = {}
for ln in open(prn):
    if ln[:5].strip().isdigit():
        m = re.match(r'\s*(\d+)\s+([0-9A-F]{4})\s', ln)
        if m:
            prn_addr[int(m.group(1))] = BASE + int(m.group(2), 16)
def label_addr(name):
    n = labels[name]
    while n not in prn_addr:
        n += 1
    return prn_addr[n]
main_lo, add_lo, total = label_addr('_main'), label_addr('_add'), label_addr('_total')
add_hi = total

def uleb(v):
    b = bytearray()
    while True:
        x = v & 0x7f; v >>= 7
        b.append(x | (0x80 if v else 0))
        if not v:
            return bytes(b)
def sleb(v):
    b = bytearray()
    while True:
        x = v & 0x7f; v >>= 7
        done = (v == 0 and not x & 0x40) or (v == -1 and x & 0x40)
        b.append(x | (0 if done else 0x80))
        if done:
            return bytes(b)
cstr = lambda s: s.encode() + b'\0'

# .debug_line, DWARF 4
prog = bytearray()
prog += b'\0' + uleb(3) + b'\x02' + struct.pack('<H', rows[0][0])
cur_addr, cur_line, cur_stmt = rows[0][0], 1, True
emitted = []
for addr, poss in rows:
    import os
    if os.environ.get('VARIANT') == 'B':     # every line a statement, the last marker primary
        order = poss
        stmts = [s for (_, _, s) in poss]
    else:                                     # plan D4: the first primary, the others not statements
        order = poss[1:] + poss[:1]
        stmts = [False] * (len(order) - 1) + [order[-1][2]]
    for i, (f, line, stmt) in enumerate(order):
        is_stmt = stmts[i]
        if addr != cur_addr:
            prog += b'\x02' + uleb(addr - cur_addr); cur_addr = addr
        if line != cur_line:
            prog += b'\x03' + sleb(line - cur_line); cur_line = line
        if is_stmt != cur_stmt:
            prog += b'\x06'; cur_stmt = is_stmt
        prog += b'\x01'
        emitted.append((addr, line, is_stmt))
prog += b'\x02' + uleb(add_hi - cur_addr)
prog += b'\0' + uleb(1) + b'\x01'
hdr = bytearray()
hdr += bytes([1, 1, 1, (-5) & 0xff, 14, 13]) + bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
hdr += b'\0'                                   # no include directories
for n in sorted(files):
    hdr += cstr(files[n]) + uleb(0) + uleb(0) + uleb(0)
hdr += b'\0'
body = struct.pack('<H', 4) + struct.pack('<I', len(hdr)) + hdr + prog
debug_line = struct.pack('<I', len(body)) + body

# .debug_abbrev
def abbrev(code, tag, children, attrs):
    b = uleb(code) + uleb(tag) + bytes([1 if children else 0])
    for a, f in attrs:
        b += uleb(a) + uleb(f)
    return b + b'\0\0'
debug_abbrev = (
    abbrev(1, 0x11, True, [(0x25, 0x08), (0x13, 0x05), (0x03, 0x08), (0x1b, 0x08),
                           (0x11, 0x01), (0x12, 0x05), (0x10, 0x17)]) +
    abbrev(2, 0x2e, False, [(0x3f, 0x19), (0x03, 0x08), (0x3a, 0x0b), (0x3b, 0x0b),
                            (0x49, 0x13), (0x11, 0x01), (0x12, 0x05)]) +
    abbrev(3, 0x24, False, [(0x0b, 0x0b), (0x3e, 0x0b), (0x03, 0x08)]) +
    abbrev(4, 0x34, False, [(0x03, 0x08), (0x3a, 0x0b), (0x3b, 0x0b), (0x49, 0x13),
                            (0x3f, 0x19), (0x02, 0x18)]) + b'\0')

# .debug_info, DWARF 4, address size 2
die = bytearray()
die += uleb(1) + cstr('dbg2elf prototype') + struct.pack('<H', 0x0c) + cstr(files[1]) + \
       cstr(sys.argv[5] if len(sys.argv) > 5 else '.') + struct.pack('<HH', main_lo, add_hi - main_lo) + \
       struct.pack('<I', 0)
cu_hdr_len = 4 + 2 + 4 + 1
int_off = None
subs = bytearray()
# base type placed after the subprograms; compute its offset first
# layout: CU die, sub main, sub add, var total, base int, 0
def sub(name, line, lo, hi, tref):
    return uleb(2) + cstr(name) + bytes([1, line]) + struct.pack('<IHH', tref, lo, hi - lo)
tmp = sub('main', 9, 0, 0, 0)
size_sub_main = len(tmp); size_sub_add = len(sub('add', 4, 0, 0, 0))
var_len = len(uleb(4) + cstr('total') + bytes([1, 2]) + struct.pack('<I', 0) + uleb(3) + b'\x03\0\0')
int_off = cu_hdr_len + len(die) + size_sub_main + size_sub_add + var_len
die += sub('main', 9, main_lo, add_lo, int_off)
die += sub('add', 4, add_lo, add_hi, int_off)
die += uleb(4) + cstr('total') + bytes([1, 2]) + struct.pack('<I', int_off) + uleb(3) + b'\x03' + struct.pack('<H', total)
assert cu_hdr_len + len(die) == int_off
die += uleb(3) + bytes([2, 5]) + cstr('int')
die += b'\0'
cu = struct.pack('<H', 4) + struct.pack('<I', 0) + bytes([2]) + die
debug_info = struct.pack('<I', len(cu)) + cu

# symbols
strtab = bytearray(b'\0')
def sname(s):
    off = len(strtab); strtab.extend(cstr(s)); return off
syms = [struct.pack('<IIIBBH', 0, 0, 0, 0, 0, 0)]
for name, val, size, typ in (('_main', main_lo, add_lo - main_lo, 2), ('_add', add_lo, add_hi - add_lo, 2),
                             ('loop', label_addr('loop'), 0, 0), ('_total', total, 2, 1)):
    syms.append(struct.pack('<IIIBBH', sname(name), val, size, (1 << 4) | typ, 0, 1))
symtab = b''.join(syms)

text = image[:total + 2 - BASE]
names = ['', '.text', '.debug_abbrev', '.debug_info', '.debug_line', '.symtab', '.strtab', '.shstrtab']
shstr = bytearray(b'\0'); noff = {}
for n in names[1:]:
    noff[n] = len(shstr); shstr.extend(cstr(n))
datas = [b'', text, debug_abbrev, debug_info, debug_line, symtab, bytes(strtab), bytes(shstr)]
off = 52 + 32
offs = []
for d in datas:
    offs.append(off); off += len(d)
shoff = off
eh = b'\x7fELF' + bytes([1, 1, 1, 0]) + b'\0' * 8
eh += struct.pack('<HHIIIIIHHHHHH', 2, 220, 1, main_lo, 52, shoff, 0x01, 52, 32, 1, 40, len(names), 7)
ph = struct.pack('<IIIIIIII', 1, offs[1], BASE, BASE, len(text), len(text), 5, 1)
sh = b''
for i, n in enumerate(names):
    if i == 0:
        sh += b'\0' * 40; continue
    typ, flags, addr, link, info, ent = 1, 0, 0, 0, 0, 0
    if n == '.text': flags, addr = 6, BASE
    if n == '.symtab': typ, link, info, ent = 2, 6, 1, 16
    if n in ('.strtab', '.shstrtab'): typ = 3
    sh += struct.pack('<IIIIIIIIII', noff[n], typ, flags, addr, offs[i], len(datas[i]), link, info, 1, ent)
open(out, 'wb').write(eh + ph + b''.join(datas) + sh)
for a, l, s in emitted:
    print(f"row {a:04X} line {l} {'stmt' if s else '-'}")
