#!/usr/bin/env python3
"""dbg2elf: write an ELF32 file with DWARF 4 line and routine information
from a prog.dbg file, so that GDB (z80 target) can show source lines.

Input: prog.dbg (written by `ul80 --debug-info`, format in docs/debug_info.md)
and the program image that the file names (prog.com).  Output: an ELF32
little-endian EM_Z80 file with e_flags 1 (EF_Z80_MACH_Z80).  The file has
these sections:

  .text           the image, at its load address (0100H for a .COM file)
  .symtab .strtab routine symbols with sizes, data and code labels
  .debug_line     DWARF 4 line table (rule D4 of the debugger plan)
  .debug_info     one compile unit: a subprogram for each routine, an
                  inlined subroutine for each inline record, a variable for
                  each data label
  .debug_abbrev .debug_str

The address size is 2.  docs/gdb.md has the user view.
"""

import argparse
import bisect
import hashlib
import json
import os
import re
import struct
import sys

from um80 import vardata

# --- ELF constants ----------------------------------------------------------
EM_Z80 = 220
EF_Z80_MACH_Z80 = 1
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 1, 2, 3
SHF_ALLOC, SHF_EXECINSTR = 2, 4
STB_LOCAL, STB_GLOBAL = 0, 1
STT_NOTYPE, STT_OBJECT, STT_FUNC = 0, 1, 2
SHN_ABS = 0xfff1

# --- DWARF constants --------------------------------------------------------
DW_TAG_array_type = 0x01
DW_TAG_enumeration_type = 0x04
DW_TAG_formal_parameter = 0x05
DW_TAG_lexical_block = 0x0b
DW_TAG_member = 0x0d
DW_TAG_pointer_type = 0x0f
DW_TAG_compile_unit = 0x11
DW_TAG_structure_type = 0x13
DW_TAG_subroutine_type = 0x15
DW_TAG_typedef = 0x16
DW_TAG_union_type = 0x17
DW_TAG_enumerator = 0x28
DW_TAG_inlined_subroutine = 0x1d
DW_TAG_subrange_type = 0x21
DW_TAG_base_type = 0x24
DW_TAG_subprogram = 0x2e
DW_TAG_variable = 0x34

DW_AT_location = 0x02
DW_AT_name = 0x03
DW_AT_byte_size = 0x0b
DW_AT_bit_size = 0x0d
DW_AT_const_value = 0x1c
DW_AT_prototyped = 0x27
DW_AT_data_member_location = 0x38
DW_AT_frame_base = 0x40
DW_AT_data_bit_offset = 0x6b
DW_AT_stmt_list = 0x10
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_language = 0x13
DW_AT_comp_dir = 0x1b
DW_AT_inline = 0x20
DW_AT_producer = 0x25
DW_AT_upper_bound = 0x2f
DW_AT_abstract_origin = 0x31
DW_AT_decl_file = 0x3a
DW_AT_decl_line = 0x3b
DW_AT_encoding = 0x3e
DW_AT_external = 0x3f
DW_AT_type = 0x49
DW_AT_call_file = 0x58
DW_AT_call_line = 0x59

DW_FORM_addr = 0x01
DW_FORM_data1 = 0x0b
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_udata = 0x0f
DW_FORM_sdata = 0x0d
DW_FORM_strp = 0x0e
DW_FORM_ref4 = 0x13
DW_FORM_sec_offset = 0x17
DW_FORM_exprloc = 0x18
DW_FORM_flag_present = 0x19

DW_ATE_boolean = 2
DW_ATE_float = 4
DW_ATE_signed = 5
DW_ATE_signed_char = 6
DW_ATE_unsigned = 7
DW_ATE_unsigned_char = 8
DW_OP_fbreg = 0x91
DW_OP_call_frame_cfa = 0x9c
DW_INL_inlined = 1
DW_OP_addr = 0x03
DW_LANG_C99 = 0x0c
DW_LANG_Mips_Assembler = 0x8001

DW_LNS_copy, DW_LNS_advance_pc, DW_LNS_advance_line, DW_LNS_set_file = 1, 2, 3, 4
DW_LNS_negate_stmt = 6
DW_LNE_end_sequence, DW_LNE_set_address = 1, 2

LINE_BASE, LINE_RANGE, OPCODE_BASE = -5, 14, 13


class Dbg2ElfError(Exception):
    pass


# --- encoding helpers -------------------------------------------------------

def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def sleb(v):
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        done = (v == 0 and not b & 0x40) or (v == -1 and b & 0x40)
        out.append(b | (0 if done else 0x80))
        if done:
            return bytes(out)


def cstr(s):
    return s.encode('utf-8') + b'\0'


class StrTab:
    """A string table with one copy of each string (.strtab, .debug_str)."""

    def __init__(self):
        self.data = bytearray(b'\0')
        self.index = {'': 0}

    def add(self, s):
        if s not in self.index:
            self.index[s] = len(self.data)
            self.data += cstr(s)
        return self.index[s]


# --- names ------------------------------------------------------------------

def fold_label(name, keep_case):
    """um80 writes every label in upper case.  A name with no lower case
    letter is written in lower case, as the compilers wrote it."""
    if keep_case:
        return name
    return name.lower() if name == name.upper() else name


def c_name(name, keep_underscore):
    """The C name of an assembler name: uc80 writes `_main` for `main`."""
    if not keep_underscore and len(name) > 1 and name[0] == '_' and name[1] != '_':
        return name[1:]
    return name


# --- the model of the program -----------------------------------------------

class Routine:
    def __init__(self, name, lo, hi, file=None, line=None, has_record=False):
        self.name = name            # name as the symbol table has it
        self.lo = lo
        self.hi = hi
        self.file = file            # index into files, or None
        self.line = line
        self.has_record = has_record
        self.inlines = []           # top-level InlineNode objects


class InlineNode:
    def __init__(self, key, lo, hi):
        self.key = key              # (name, file, line): the call site
        self.lo = lo
        self.hi = hi
        self.children = []


class Variable:
    def __init__(self, name, addr, size, is_global):
        self.name = name
        self.addr = addr
        self.size = size
        self.is_global = is_global


class Model:
    """What dbg2elf takes from prog.dbg."""

    def __init__(self, dbg, opts):
        self.dbg = dbg
        self.opts = opts
        self.files = [f.replace('\\', '/') for f in dbg.get('files') or []]
        self.lines = sorted(dbg.get('lines') or [], key=lambda r: r[0])
        self.asm = sorted(dbg.get('asm') or [], key=lambda r: r[0])
        self._asm_starts = [r[0] for r in self.asm]
        self.labels = dbg.get('labels') or []
        self.modules = dbg.get('modules') or []
        image = dbg.get('image') or {}
        self.load = image.get('load') or 0
        self.code_end = max([r[1] for r in self.asm] + [r[1] for r in self.lines] + [0])
        self.routines = self._routines()
        self._attach_inlines()
        self.variables = self._variables()

    # routines -------------------------------------------------------------

    def _asm_row(self, addr):
        i = bisect.bisect_right(self._asm_starts, addr) - 1
        if i >= 0 and self.asm[i][0] <= addr < self.asm[i][1]:
            return self.asm[i]
        return None

    def _first_data_after(self, addr):
        for r in self.asm:
            if r[0] > addr and r[2] != 'i':
                return r[0]
        return None

    def _routines(self):
        o = self.opts
        funcs = [f for f in self.dbg.get('funcs') or [] if f.get('start') is not None]
        funcs.sort(key=lambda f: f['start'])
        out = []
        if funcs:
            for k, f in enumerate(funcs):
                hi = f.get('end')
                if hi is None:
                    hi = funcs[k + 1]['start'] if k + 1 < len(funcs) else self.code_end
                out.append(Routine(f['name'], f['start'], hi, f.get('file'),
                                   f.get('line'), True))
            return out
        # No ;#func record: a routine is a label with an instruction row that
        # starts with an underscore (the C naming) or is PUBLIC.
        cands = []
        for lab in self.labels:
            name, addr = lab[0], lab[1]
            row = self._asm_row(addr)
            if row is None or row[2] != 'i' or row[0] != addr:
                continue
            is_global = len(lab) > 3 and lab[3]
            if is_global or re.match(r'_[A-Za-z0-9]', name) and not name.startswith('__'):
                cands.append((addr, fold_label(name, o.keep_case)))
        cands.sort()
        seen = set()
        uniq = []
        for a, n in cands:
            if a not in seen:
                seen.add(a)
                uniq.append((a, n))
        for k, (a, n) in enumerate(uniq):
            hi = uniq[k + 1][0] if k + 1 < len(uniq) else self.code_end
            d = self._first_data_after(a)
            if d is not None and d < hi:
                hi = d
            out.append(Routine(n, a, hi))
        return out

    def routine_at(self, addr):
        for r in self.routines:
            if r.lo <= addr < r.hi:
                return r
        return None

    # inline records -------------------------------------------------------

    def _attach_inlines(self):
        """Turn the inline stack of each line entry into a tree of nodes under
        the routine that holds the entry.  A node covers a run of entries
        that are next to each other and have the same call site."""
        open_nodes = []
        last_end = None
        cur = None
        for e in self.lines:
            start, end = e[0], e[1]
            stack = [tuple(s) for s in e[3]] if len(e) > 3 and e[3] else []
            r = self.routine_at(start)
            if r is None or r is not cur or start != last_end:
                open_nodes = []
            cur = r
            last_end = end
            if r is None:
                continue
            k = 0
            while k < len(open_nodes) and k < len(stack) and open_nodes[k].key == stack[k]:
                k += 1
            del open_nodes[k:]
            for i in range(k, len(stack)):
                node = InlineNode(stack[i], start, end)
                (open_nodes[i - 1].children if i else r.inlines).append(node)
                open_nodes.append(node)
            for node in open_nodes:
                node.hi = end

    # variables ------------------------------------------------------------

    def _variables(self):
        """A data label is a static variable.  prog.dbg has no types, so the
        size is the run of data bytes from the label to the next label, and
        the type comes from the size (phase 8 of the plan adds real types)."""
        o = self.opts
        if o.no_variables:
            return []
        addrs = sorted(set(l[1] for l in self.labels))
        out = []
        seen = set()
        for lab in self.labels:
            name, addr = lab[0], lab[1]
            if name.startswith(('@', '?', '__')) or addr in seen:
                continue
            mi = lab[2] if len(lab) > 2 else None
            if (mi is not None and 0 <= mi < len(self.modules)
                    and not self.modules[mi].get('debug', True)):
                continue
            row = self._asm_row(addr)
            if row is None or row[2] not in ('d', 's') or row[0] != addr:
                continue
            if self.routine_at(addr) is not None:
                continue
            nxt = [a for a in addrs if a > addr]
            limit = nxt[0] if nxt else self.code_end
            size = 0
            a = addr
            while a < limit:
                r = self._asm_row(a)
                if r is None or r[2] not in ('d', 's') or r[0] != a:
                    break
                size += r[1] - r[0]
                a = r[1]
            if size <= 0:
                continue
            seen.add(addr)
            is_global = bool(len(lab) > 3 and lab[3])
            out.append(Variable(fold_label(name, o.keep_case), addr, size, is_global))
        out.sort(key=lambda v: v.addr)
        return out

    # line rows ------------------------------------------------------------

    def line_sequences(self):
        """Sequences of rows: [(start, end, [(addr, file, line, is_stmt)])].
        Rule D4: each line of a merged group is a row at the address of the
        entry, in source order, and the last line is primary.  Only a nostmt
        group has is_stmt off.  File numbers are 1 based (DWARF)."""
        mode = self.opts.asm_lines
        spans = []      # (start, end, [(file, line, stmt)])
        prev = None
        for e in self.lines:
            groups = [(g[0] + 1, g[1], not g[2]) for g in e[2]]
            stack = [tuple(s) for s in e[3]] if len(e) > 3 and e[3] else []
            if prev is not None and prev[1] == e[0]:
                # ;#endinline puts the call line back as the position.  When
                # more lines follow it at the same address, the call line is
                # no statement of its own: drop it.
                pstack = [tuple(s) for s in prev[3]] if len(prev) > 3 and prev[3] else []
                if (len(stack) < len(pstack) and pstack[:len(stack)] == stack
                        and len(groups) > 1):
                    closed = pstack[len(stack)]
                    if groups[0][:2] == ((closed[1] or 0) + 1, closed[2]):
                        groups = groups[1:]
            prev = e
            spans.append((e[0], e[1], groups))
        if mode == 'always' or (mode == 'auto' and not self.lines):
            covered = [(s, t) for s, t, _g in spans]
            starts = [s for s, _t in covered]
            prev_key = None
            add = []
            for r in self.asm:
                if r[2] == 's' or r[3] is None or r[4] is None:
                    continue
                i = bisect.bisect_right(starts, r[0]) - 1
                if i >= 0 and covered[i][0] <= r[0] < covered[i][1]:
                    continue
                groups = []
                if len(r) > 6 and r[5] is not None and r[6] is not None:
                    groups.append((r[5] + 1, r[6], True))
                groups.append((r[3] + 1, r[4], True))
                key = (groups[-1][0], groups[-1][1], len(groups))
                if add and add[-1][1] == r[0] and prev_key == key and len(groups) == 1:
                    add[-1] = (add[-1][0], r[1], add[-1][2])
                else:
                    add.append((r[0], r[1], groups))
                prev_key = key
            spans = sorted(spans + add, key=lambda t: t[0])
        seqs = []
        for s, t, groups in spans:
            if seqs and seqs[-1][1] == s:
                seqs[-1][1] = t
                seqs[-1][2].append((s, groups))
            else:
                seqs.append([s, t, [(s, groups)]])
        return [(a, b, [(addr, g) for addr, g in rows]) for a, b, rows in seqs]


# --- .debug_line ------------------------------------------------------------

def debug_line(model, comp_dir):
    files = model.files
    hdr = bytearray()
    hdr += bytes([1, 1, 1, LINE_BASE & 0xff, LINE_RANGE, OPCODE_BASE])
    hdr += bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
    hdr += b'\0'                                    # no include directories
    for f in files:
        hdr += cstr(f) + uleb(0) + uleb(0) + uleb(0)
    hdr += b'\0'
    prog = bytearray()
    for lo, hi, rows in model.line_sequences():
        addr, file_, line, stmt = lo, 1, 1, True
        prog += b'\0' + uleb(3) + bytes([DW_LNE_set_address]) + struct.pack('<H', lo)
        for raddr, groups in rows:
            for f, ln, st in groups:
                if f != file_:
                    prog += bytes([DW_LNS_set_file]) + uleb(f)
                    file_ = f
                if st != stmt:
                    prog += bytes([DW_LNS_negate_stmt])
                    stmt = st
                da, dl = raddr - addr, ln - line
                special = None
                if LINE_BASE <= dl < LINE_BASE + LINE_RANGE:
                    op = (dl - LINE_BASE) + LINE_RANGE * da + OPCODE_BASE
                    if 0 <= da and op <= 255:
                        special = op
                if special is not None:
                    prog.append(special)
                else:
                    if da:
                        prog += bytes([DW_LNS_advance_pc]) + uleb(da)
                    if dl:
                        prog += bytes([DW_LNS_advance_line]) + sleb(dl)
                    prog.append(DW_LNS_copy)
                addr, line = raddr, ln
        if hi != addr:
            prog += bytes([DW_LNS_advance_pc]) + uleb(hi - addr)
        prog += b'\0' + uleb(1) + bytes([DW_LNE_end_sequence])
    body = struct.pack('<H', 4) + struct.pack('<I', len(hdr)) + bytes(hdr) + bytes(prog)
    return struct.pack('<I', len(body)) + body


# --- .debug_info ------------------------------------------------------------

class Die:
    def __init__(self, tag, attrs, children=None):
        self.tag = tag
        self.attrs = attrs              # list of (attr, form, value)
        self.children = children or []
        self.offset = None


class Ref:
    def __init__(self, die):
        self.die = die


class TypeBuilder:
    """DWARF type DIEs for the type expressions of prog.dbg (docs/debug_info.md,
    Variables).  `die(text)` returns the DIE of a type, or None for void."""

    ENCODING = {'char': DW_ATE_signed_char, 'schar': DW_ATE_signed_char,
                'uchar': DW_ATE_unsigned_char, 'bool': DW_ATE_boolean,
                'float': DW_ATE_float, 'double': DW_ATE_float,
                'ldouble': DW_ATE_float}

    def __init__(self, program):
        self.program = program
        self.cache = {}
        self.dies = []              # every type DIE, in creation order

    def _add(self, die):
        self.dies.append(die)
        return die

    def die(self, text):
        t = self.program.type(text)
        return self.of(t, text)

    def of(self, t, key=None):
        key = key or repr(t)
        if key in self.cache:
            return self.cache[key]
        prog = self.program
        k = t[0]
        if k == 'void':
            return None
        if k == 'base':
            enc = self.ENCODING.get(t[1])
            if enc is None:
                enc = DW_ATE_unsigned if t[1] in vardata.UNSIGNED else DW_ATE_signed
            die = self._add(Die(DW_TAG_base_type, [
                (DW_AT_byte_size, DW_FORM_data1, t[2]),
                (DW_AT_encoding, DW_FORM_data1, enc),
                (DW_AT_name, DW_FORM_strp, vardata.BASE_C_NAMES.get(t[1], t[1]))]))
            self.cache[key] = die
            return die
        if k == 'ptr':
            die = Die(DW_TAG_pointer_type, [(DW_AT_byte_size, DW_FORM_data1, 2)])
            self.cache[key] = self._add(die)
            target = self.of(t[1])
            if target is not None:
                die.attrs.append((DW_AT_type, DW_FORM_ref4, Ref(target)))
            return die
        if k == 'arr':
            die = Die(DW_TAG_array_type, [])
            self.cache[key] = self._add(die)
            elem = self.of(t[2])
            if elem is not None:
                die.attrs.append((DW_AT_type, DW_FORM_ref4, Ref(elem)))
            sub = [(DW_AT_upper_bound, DW_FORM_udata, t[1] - 1)] if t[1] else []
            die.children.append(Die(DW_TAG_subrange_type, sub))
            return die
        if k == 'func':
            die = Die(DW_TAG_subroutine_type, [])
            self.cache[key] = self._add(die)
            ret = self.of(t[1])
            if ret is not None:
                die.attrs.append((DW_AT_type, DW_FORM_ref4, Ref(ret)))
            return die
        if k == 'typedef':
            d = prog.types.get(t[1])
            die = Die(DW_TAG_typedef, [(DW_AT_name, DW_FORM_strp, t[1].split(':', 1)[1])])
            self.cache[key] = self._add(die)
            target = self.of(prog.type(d['target'])) if d else None
            if target is not None:
                die.attrs.append((DW_AT_type, DW_FORM_ref4, Ref(target)))
            return die
        if k in ('struct', 'union'):
            d = prog.types.get(t[1])
            tag = t[1].split(':', 1)[1]
            attrs = []
            if not tag.startswith('.'):
                attrs.append((DW_AT_name, DW_FORM_strp, tag.split('~')[0]))
            if d is None:
                attrs.append((DW_AT_byte_size, DW_FORM_data1, 0))
            else:
                attrs.append((DW_AT_byte_size, DW_FORM_data2, d.get('size') or 0))
            die = Die(DW_TAG_structure_type if k == 'struct' else DW_TAG_union_type,
                      attrs)
            self.cache[key] = self._add(die)
            for m in (d or {}).get('members', ()):
                mt = self.of(prog.type(m[1]))
                a = [(DW_AT_name, DW_FORM_strp, m[0])]
                if mt is not None:
                    a.append((DW_AT_type, DW_FORM_ref4, Ref(mt)))
                if len(m) > 3:
                    a.append((DW_AT_bit_size, DW_FORM_data1, m[3]))
                    a.append((DW_AT_data_bit_offset, DW_FORM_udata, m[2] * 8 + m[4]))
                else:
                    a.append((DW_AT_data_member_location, DW_FORM_udata, m[2]))
                die.children.append(Die(DW_TAG_member, a))
            return die
        if k == 'enum':
            d = prog.types.get(t[1])
            tag = t[1].split(':', 1)[1]
            attrs = []
            if not tag.startswith('.'):
                attrs.append((DW_AT_name, DW_FORM_strp, tag.split('~')[0]))
            size = (d or {}).get('size') or 2
            attrs.append((DW_AT_byte_size, DW_FORM_data1, size))
            attrs.append((DW_AT_encoding, DW_FORM_data1, DW_ATE_signed))
            die = Die(DW_TAG_enumeration_type, attrs)
            self.cache[key] = self._add(die)
            for name, value in (d or {}).get('values', ()):
                die.children.append(Die(DW_TAG_enumerator, [
                    (DW_AT_name, DW_FORM_strp, name),
                    (DW_AT_const_value, DW_FORM_sdata, value)]))
            return die
        # raw bytes
        die = Die(DW_TAG_array_type, [])
        self.cache[key] = self._add(die)
        die.attrs.append((DW_AT_type, DW_FORM_ref4, Ref(self.of(('base', 'uchar', 1)))))
        die.children.append(Die(DW_TAG_subrange_type,
                                [(DW_AT_upper_bound, DW_FORM_udata, max(t[1] - 1, 0))]))
        return die


def typed_variables(model, builder):
    """(file-scope DIEs, {routine start: DIEs}) for the `vars` table of
    prog.dbg.  A variable with a fixed address gets DW_OP_addr.  A variable
    at an IX offset gets DW_OP_fbreg when --ix-locals is fbreg (the default),
    else no DIE (docs/gdb.md: the helper command zlocals reads it).  A variable in a
    register gets no DIE.  A name that is in an inner block goes into a
    DW_TAG_lexical_block with the address range of the block."""
    opts = model.opts
    prog = builder.program
    top, inner = [], {}
    by_scope = {}
    pops = {f['start']: f.get('pops') or 0
            for f in model.dbg.get('funcs') or [] if f.get('start') is not None}
    for v in prog.vars:
        loc = v.loc
        if loc is None or (loc[0] == 'ix' and getattr(opts, 'ix_locals', 'fbreg') != 'fbreg') \
                or loc[0] == 'reg':
            continue
        t = builder.of(v.type, v.type_text)
        attrs = [(DW_AT_name, DW_FORM_strp, v.name)]
        if v.decl:
            attrs.append((DW_AT_decl_file, DW_FORM_udata, v.decl[0] + 1))
            attrs.append((DW_AT_decl_line, DW_FORM_udata, v.decl[1]))
        if v.kind == 'global':
            attrs.append((DW_AT_external, DW_FORM_flag_present, True))
        if t is not None:
            attrs.append((DW_AT_type, DW_FORM_ref4, Ref(t)))
        if loc[0] == 'at':
            expr = bytes([DW_OP_addr]) + struct.pack('<H', loc[1])
        else:
            # The frame base is the CFA that the unwinder gives: the stack
            # address after the return, which is IX + 4 + pops.
            expr = bytes([DW_OP_fbreg]) + sleb(loc[1] - 4 - pops.get(v.func, 0))
        attrs.append((DW_AT_location, DW_FORM_exprloc, expr))
        die = Die(DW_TAG_formal_parameter if v.kind == 'param'
                  else DW_TAG_variable, attrs)
        if v.func is None:
            top.append(die)
            continue
        rng = None
        if v.scope is not None and v.kind != 'param':
            rng = _scope_range(model, v)
            if rng is not None and rng == _scope_range(model, v, True):
                rng = None            # the block of the whole routine
        by_scope.setdefault((v.func, rng), []).append(die)
    for (func, rng), dies in by_scope.items():
        r = next((r for r in model.routines if r.lo == func), None)
        if rng is not None and r is not None and rng != (r.lo, r.hi):
            block = Die(DW_TAG_lexical_block, [
                (DW_AT_low_pc, DW_FORM_addr, rng[0]),
                (DW_AT_high_pc, DW_FORM_data4, rng[1] - rng[0])], dies)
            inner.setdefault(func, []).append(block)
        else:
            inner.setdefault(func, []).extend(dies)
    return top, inner


def _scope_range(model, v, whole=False):
    """(low, high) addresses of the lines of the scope of v within its
    routine, or None.  With `whole`: of all the lines of the routine."""
    f, a, b = v.scope
    r = next((r for r in model.routines if r.lo == v.func), None)
    if r is None:
        return None
    if whole:
        # every line after the declaration line of the routine
        a, b = (r.line or 0) + 1, 1 << 30
    lo = hi = None
    for e in model.lines:
        if e[0] < r.lo or e[1] > r.hi:
            continue
        if any(g[0] == f and a <= g[1] <= b and not g[2] for g in e[2]):
            lo = e[0] if lo is None else min(lo, e[0])
            hi = e[1] if hi is None else max(hi, e[1])
    return None if lo is None else (lo, hi)


def build_debug_info(model, comp_dir, producer, language):
    """Returns (debug_info, debug_abbrev, debug_str)."""
    strs = StrTab()
    opts = model.opts
    cu_files = model.files
    # the name of the compile unit: the source file of the first routine
    cu_name = None
    for r in model.routines:
        if r.file is not None and r.file < len(cu_files):
            cu_name = cu_files[r.file]
            break
    if cu_name is None:
        for e in model.lines:
            cu_name = cu_files[e[2][-1][0]]
            break
    if cu_name is None:
        cu_name = cu_files[0] if cu_files else 'prog'
    int_t = Die(DW_TAG_base_type, [(DW_AT_byte_size, DW_FORM_data1, 2),
                                   (DW_AT_encoding, DW_FORM_data1, DW_ATE_signed),
                                   (DW_AT_name, DW_FORM_strp, 'int')])
    char_t = Die(DW_TAG_base_type, [(DW_AT_byte_size, DW_FORM_data1, 1),
                                    (DW_AT_encoding, DW_FORM_data1, DW_ATE_unsigned_char),
                                    (DW_AT_name, DW_FORM_strp, 'unsigned char')])
    type_dies = [int_t, char_t]
    var_dies = []
    typed_top, typed_inner, builder = [], {}, None
    if model.dbg.get('vars') and not opts.no_variables:
        builder = TypeBuilder(vardata.Program(model.dbg))
        typed_top, typed_inner = typed_variables(model, builder)
    typed_addrs = set()
    for v in (builder.program.vars if builder else ()):
        if v.func is None and v.loc and v.loc[0] == 'at':
            typed_addrs.add(v.loc[1])
    for v in model.variables:
        if v.addr in typed_addrs:
            continue
        if v.size == 1:
            t = char_t
        elif v.size == 2:
            t = int_t
        else:
            sub = Die(DW_TAG_subrange_type, [(DW_AT_type, DW_FORM_ref4, Ref(int_t)),
                                             (DW_AT_upper_bound, DW_FORM_udata, v.size - 1)])
            t = Die(DW_TAG_array_type, [(DW_AT_type, DW_FORM_ref4, Ref(char_t))], [sub])
            type_dies.append(t)
        attrs = [(DW_AT_name, DW_FORM_strp, c_name(v.name, opts.keep_underscore))]
        if v.is_global:
            attrs.append((DW_AT_external, DW_FORM_flag_present, True))
        attrs.append((DW_AT_type, DW_FORM_ref4, Ref(t)))
        attrs.append((DW_AT_location, DW_FORM_exprloc,
                      bytes([DW_OP_addr]) + struct.pack('<H', v.addr)))
        var_dies.append(Die(DW_TAG_variable, attrs))
    # abstract subprograms for the inlined routines, one for each name
    abstract = {}

    def abstract_die(name):
        if name not in abstract:
            abstract[name] = Die(DW_TAG_subprogram, [
                (DW_AT_name, DW_FORM_strp, c_name(name, opts.keep_underscore)),
                (DW_AT_inline, DW_FORM_data1, DW_INL_inlined)])
        return abstract[name]

    def inline_die(node):
        name, f, line = node.key
        attrs = [(DW_AT_abstract_origin, DW_FORM_ref4, Ref(abstract_die(name))),
                 (DW_AT_low_pc, DW_FORM_addr, node.lo),
                 (DW_AT_high_pc, DW_FORM_data4, node.hi - node.lo)]
        if f is not None:
            attrs.append((DW_AT_call_file, DW_FORM_udata, f + 1))
        attrs.append((DW_AT_call_line, DW_FORM_udata, line))
        return Die(DW_TAG_inlined_subroutine, attrs, [inline_die(c) for c in node.children])

    sub_dies = []
    for r in model.routines:
        attrs = [(DW_AT_external, DW_FORM_flag_present, True),
                 (DW_AT_name, DW_FORM_strp, c_name(r.name, opts.keep_underscore))]
        if r.file is not None and r.line is not None:
            attrs.append((DW_AT_decl_file, DW_FORM_udata, r.file + 1))
            attrs.append((DW_AT_decl_line, DW_FORM_udata, r.line))
        attrs.append((DW_AT_low_pc, DW_FORM_addr, r.lo))
        attrs.append((DW_AT_high_pc, DW_FORM_data4, r.hi - r.lo))
        if getattr(opts, 'ix_locals', 'fbreg') == 'fbreg':
            attrs.append((DW_AT_frame_base, DW_FORM_exprloc,
                          bytes([DW_OP_call_frame_cfa])))
        sub_dies.append(Die(DW_TAG_subprogram, attrs,
                            [inline_die(n) for n in r.inlines]
                            + typed_inner.get(r.lo, [])))
    lo = model.load
    hi = max([model.code_end] + [r.hi for r in model.routines] + [lo])
    cu = Die(DW_TAG_compile_unit, [
        (DW_AT_producer, DW_FORM_strp, producer),
        (DW_AT_language, DW_FORM_data2, language),
        (DW_AT_name, DW_FORM_strp, cu_name),
        (DW_AT_comp_dir, DW_FORM_strp, comp_dir),
        (DW_AT_low_pc, DW_FORM_addr, lo),
        (DW_AT_high_pc, DW_FORM_data4, hi - lo),
        (DW_AT_stmt_list, DW_FORM_sec_offset, 0)],
        type_dies + (builder.dies if builder else []) + list(abstract.values())
        + sub_dies + var_dies + typed_top)

    # abbreviations
    abbrevs = {}
    abbrev_bytes = bytearray()

    def abbrev_code(die):
        key = (die.tag, bool(die.children), tuple((a, f) for a, f, _v in die.attrs))
        if key not in abbrevs:
            abbrevs[key] = len(abbrevs) + 1
            abbrev_bytes.extend(uleb(abbrevs[key]) + uleb(die.tag) +
                                bytes([1 if die.children else 0]))
            for a, f, _v in die.attrs:
                abbrev_bytes.extend(uleb(a) + uleb(f))
            abbrev_bytes.extend(b'\0\0')
        return abbrevs[key]

    # Two passes: the first gives each DIE its offset, the second writes the
    # references (they are 4 bytes in both passes, so the sizes do not change).
    CU_HDR = 11

    def emit(die, out):
        die.offset = CU_HDR + len(out)
        out += uleb(abbrev_code(die))
        for a, f, v in die.attrs:
            if f == DW_FORM_strp:
                out += struct.pack('<I', strs.add(v))
            elif f == DW_FORM_addr:
                out += struct.pack('<H', v)
            elif f == DW_FORM_data1:
                out += struct.pack('<B', v)
            elif f == DW_FORM_data2:
                out += struct.pack('<H', v)
            elif f in (DW_FORM_data4, DW_FORM_sec_offset):
                out += struct.pack('<I', v)
            elif f == DW_FORM_udata:
                out += uleb(v)
            elif f == DW_FORM_sdata:
                out += sleb(v)
            elif f == DW_FORM_ref4:
                out += struct.pack('<I', v.die.offset if v.die.offset is not None else 0)
            elif f == DW_FORM_exprloc:
                out += uleb(len(v)) + v
            elif f == DW_FORM_flag_present:
                pass
            else:
                raise Dbg2ElfError('internal: form %#x' % f)
        for c in die.children:
            emit(c, out)
        if die.children:
            out += b'\0'

    out = bytearray()
    emit(cu, out)
    out = bytearray()
    emit(cu, out)
    abbrev_bytes += b'\0'
    cu_body = struct.pack('<H', 4) + struct.pack('<I', 0) + bytes([2]) + bytes(out)
    info = struct.pack('<I', len(cu_body)) + cu_body
    return info, bytes(abbrev_bytes), bytes(strs.data)


# --- the ELF file -----------------------------------------------------------

def symbols(model, image_lo, image_hi):
    """The symbol table rows: (name, value, size, bind, type, shndx)."""
    o = model.opts
    rows = []
    routine_at = {}
    for r in model.routines:
        routine_at[r.lo] = r
        rows.append((r.name, r.lo, r.hi - r.lo, STB_GLOBAL, STT_FUNC, 1))
    var_at = {v.addr: v for v in model.variables}
    for v in model.variables:
        rows.append((v.name, v.addr, v.size,
                     STB_GLOBAL, STT_OBJECT,
                     1 if image_lo <= v.addr < image_hi else SHN_ABS))
    seen = set((n, a) for n, a, *_ in rows)
    for lab in model.labels:
        name = fold_label(lab[0], o.keep_case)
        addr = lab[1]
        if (name, addr) in seen or addr in routine_at or addr in var_at:
            continue
        if name.startswith(('@', '?')):
            continue
        r = model.routine_at(addr)
        is_global = bool(len(lab) > 3 and lab[3])
        if r is not None and r.has_record and not is_global:
            continue
        seen.add((name, addr))
        rows.append((name, addr, 0, STB_GLOBAL if is_global else STB_LOCAL,
                     STT_NOTYPE, 1 if image_lo <= addr < image_hi else SHN_ABS))
    rows.sort(key=lambda t: (t[3] != STB_LOCAL, t[1], t[0]))
    return rows


def build_elf(dbg, image, opts, comp_dir):
    model = Model(dbg, opts)
    load = model.load
    img_lo, img_hi = load, load + len(image)
    language = DW_LANG_Mips_Assembler if opts.language == 'asm' else DW_LANG_C99
    producer = 'dbg2elf (um80) from %s' % (dbg.get('producer') or 'prog.dbg')
    info, abbrev, dstr = build_debug_info(model, comp_dir, producer, language)
    # comp_dir and file names are in .debug_str through build_debug_info
    line = debug_line(model, comp_dir)
    strtab = StrTab()
    syms = [struct.pack('<IIIBBH', 0, 0, 0, 0, 0, 0)]
    rows = symbols(model, img_lo, img_hi)
    first_global = 1
    for i, (name, val, size, bind, typ, shndx) in enumerate(rows):
        syms.append(struct.pack('<IIIBBH', strtab.add(name), val, size,
                                (bind << 4) | typ, 0, shndx))
        if bind == STB_LOCAL:
            first_global = i + 2
    symtab = b''.join(syms)

    sections = [
        ('.text', SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, load, bytes(image), 0, 0, 0),
        ('.debug_abbrev', SHT_PROGBITS, 0, 0, abbrev, 0, 0, 0),
        ('.debug_info', SHT_PROGBITS, 0, 0, info, 0, 0, 0),
        ('.debug_line', SHT_PROGBITS, 0, 0, line, 0, 0, 0),
        ('.debug_str', SHT_PROGBITS, 0, 0, dstr, 0, 0, 0),
        ('.symtab', SHT_SYMTAB, 0, 0, symtab, 7, first_global, 16),
        ('.strtab', SHT_STRTAB, 0, 0, bytes(strtab.data), 0, 0, 0),
    ]
    shstr = StrTab()
    names = [shstr.add(s[0]) for s in sections]
    shstr_name = shstr.add('.shstrtab')
    shstr_data = bytes(shstr.data)

    off = 52 + 32
    offs = []
    for s in sections:
        offs.append(off)
        off += len(s[4])
    shstr_off = off
    off += len(shstr_data)
    shoff = off
    nsec = len(sections) + 2
    shstrndx = nsec - 1
    eh = b'\x7fELF' + bytes([1, 1, 1, 0]) + b'\0' * 8
    eh += struct.pack('<HHIIIIIHHHHHH', 2, EM_Z80, 1, load, 52, shoff, EF_Z80_MACH_Z80,
                      52, 32, 1, 40, nsec, shstrndx)
    ph = struct.pack('<IIIIIIII', 1, offs[0], load, load, len(image), len(image), 5, 1)
    sh = bytearray(b'\0' * 40)
    for i, s in enumerate(sections):
        _n, typ, flags, addr, data, link, info_, ent = s
        sh += struct.pack('<IIIIIIIIII', names[i], typ, flags, addr, offs[i], len(data),
                          link, info_, 1, ent)
    sh += struct.pack('<IIIIIIIIII', shstr_name, SHT_STRTAB, 0, 0, shstr_off,
                      len(shstr_data), 0, 0, 1, 0)
    return eh + ph + b''.join(s[4] for s in sections) + shstr_data + bytes(sh)


# --- command line -----------------------------------------------------------

def load_dbg(path):
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise Dbg2ElfError('cannot read %s: %s' % (path, e))
    if data.get('format') != 'um80-dbg':
        raise Dbg2ElfError('%s is not a um80-dbg file' % path)
    if data.get('version') != 1:
        raise Dbg2ElfError('%s has format version %r; dbg2elf reads version 1'
                           % (path, data.get('version')))
    return data


def read_image(dbg, dbg_path, com_path):
    """The program bytes at the load address, after the D9 image check."""
    image = dbg.get('image') or {}
    kind = image.get('kind')
    if kind not in ('com', 'bin'):
        raise Dbg2ElfError('the image kind %r has no flat image; dbg2elf reads '
                           'com and bin' % (kind,))
    path = com_path
    if path is None:
        name = image.get('file')
        if not name:
            raise Dbg2ElfError('prog.dbg names no image file; give the program file')
        path = os.path.join(os.path.dirname(os.path.abspath(dbg_path)), name)
    try:
        with open(path, 'rb') as f:
            blob = f.read()
    except OSError as e:
        raise Dbg2ElfError('cannot read the program file: %s' % e)
    length, want = image.get('length'), image.get('sha256')
    if length is not None and want is not None:
        if len(blob) != length or hashlib.sha256(blob[:length]).hexdigest() != want:
            raise Dbg2ElfError(
                '%s does not match %s (the image check of the build: length %d, '
                'SHA-256 %s...).  The debug file is stale; build the program again.'
                % (path, dbg_path, length, (want or '')[:12]))
    offset = image.get('offset') or 0
    blob = blob[offset:]
    load = image.get('load')
    if load is None:
        raise Dbg2ElfError('prog.dbg has no load address')
    if load + len(blob) > 0x10000:
        raise Dbg2ElfError('the image does not fit in 64K at %04XH' % load)
    return blob


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='dbg2elf',
        description='Write an ELF file with DWARF line and routine data from '
                    'a prog.dbg file, for GDB with a z80 target.')
    ap.add_argument('dbg', nargs='?', help='prog.dbg, written by ul80 --debug-info')
    ap.add_argument('program', nargs='?',
                    help='the program file (default: the file that prog.dbg names)')
    ap.add_argument('-o', '--output', help='ELF file (default: prog.elf beside prog.dbg)')
    ap.add_argument('--comp-dir', help='directory that relative source paths '
                    'start from (default: the directory of prog.dbg)')
    ap.add_argument('--asm-lines', choices=('auto', 'always', 'never'), default='auto',
                    help='write the lines of the .mac files: auto (only when '
                    'prog.dbg has no source lines), always (for the bytes that '
                    'have no source line), never')
    ap.add_argument('--keep-underscore', action='store_true',
                    help='keep the leading underscore of C names')
    ap.add_argument('--keep-case', action='store_true',
                    help='keep the case of labels (um80 writes them in upper case)')
    ap.add_argument('--no-variables', action='store_true',
                    help='write no static variables')
    ap.add_argument('--ix-locals', choices=('off', 'fbreg'), default='fbreg',
                    help='variables at IX+N: fbreg (the default: DW_OP_fbreg '
                    'with the call frame CFA that udb80_unwind.py gives as '
                    'the frame base) or off (no DWARF record; the GDB helper '
                    'udb80_vars.py still reads them)')
    ap.add_argument('--language', choices=('c', 'asm'), default='c')
    ap.add_argument('--unwinder-path', action='store_true',
                    help='print the path of the GDB Python unwinder and stop')
    ap.add_argument('--vars-path', action='store_true',
                    help='print the path of the GDB Python variable commands '
                    '(zlocals, zargs, zprint, zptype) and stop')
    opts = ap.parse_args(argv)
    if opts.unwinder_path:
        print(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gdb',
                           'udb80_unwind.py'))
        return 0
    if opts.vars_path:
        print(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gdb',
                           'udb80_vars.py'))
        return 0
    if not opts.dbg:
        ap.error('the following arguments are required: dbg')
    try:
        dbg = load_dbg(opts.dbg)
        blob = read_image(dbg, opts.dbg, opts.program)
        comp_dir = opts.comp_dir or os.path.dirname(os.path.abspath(opts.dbg))
        out = opts.output or os.path.splitext(opts.dbg)[0] + '.elf'
        elf = build_elf(dbg, blob, opts, comp_dir)
        with open(out, 'wb') as f:
            f.write(elf)
    except Dbg2ElfError as e:
        print('dbg2elf: %s' % e, file=sys.stderr)
        return 1
    print('dbg2elf: wrote %s (%d bytes)' % (out, len(elf)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
