#!/usr/bin/env python3
"""
um80 - Microsoft MACRO-80 compatible assembler for Linux.

Usage: um80 [-o output.rel] [-l listing.prn] input.mac
"""

import sys
import os
import re
import argparse
from collections import deque
from pathlib import Path

from um80 import __version__
from um80.opcodes_8080 import *
from um80.opcodes_z80 import *
from um80.relformat import *


class AssemblerError(Exception):
    """Assembler error with line information."""
    def __init__(self, message, line_num=None, line_text=None):
        self.message = message
        self.line_num = line_num
        self.line_text = line_text
        super().__init__(self.format_message())

    def format_message(self):
        if self.line_num:
            return f"Error at line {self.line_num}: {self.message}"
        return f"Error: {self.message}"


# Characters that continue a symbol name (see the name pattern in
# eval_operand()): a word operator next to one of these is part of a name.
IDENT_CHARS = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                        '0123456789_@?$.')

# The characters of a name, where a macro body is matched to the names of
# its parameters (Assembler.substitute_macro_params()).  In MACRO-80 a name
# is letters, digits and $ . ? @ _, and a digit does not start one: with the
# parameter X, `?X', `X?', `@X', `X$1', `X.1' and `_X' are other names, and
# `1X' is 1 then X.  In MAC and RMAC it is letters, digits, ? and @: a `$',
# `_' or `.' ends it.
M80_NAME_START = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                           '$.?@_')
M80_NAME_CHARS = M80_NAME_START | frozenset('0123456789')
DRI_NAME_START = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                           '?@')
DRI_NAME_CHARS = DRI_NAME_START | frozenset('0123456789')

# The operations of a statement: every directive assemble_pseudo_op() takes,
# and the instructions of each processor (assemble_instruction() and
# assemble_z80_instruction()).  See Assembler.is_operation().
DIRECTIVES = frozenset({
    'ORG', 'EQU', 'SET', 'DEFL', 'ASET', 'DB', 'DEFB', 'DEFM', 'DC', 'DW', 'DEFW',
    'DS', 'DEFS', 'CSEG', 'DSEG', 'ASEG', 'COMMON', 'PUBLIC', 'ENTRY', 'GLOBAL',
    'EXTRN', 'EXT', 'EXTERNAL', 'NAME', 'TITLE', 'SUBTTL', '$TITLE', 'PAGE',
    '$EJECT', '*EJECT', '.LIST', '.XLIST', '.RADIX', '.8080', '.Z80', '.SALL',
    '.LALL', '.XALL', '.SFCOND', '.LFCOND', '.TFCOND', '.PRINTX', '.COMMENT',
    '.REQUEST', '.PHASE', '.DEPHASE', 'END', 'IF', 'IFT', 'IFE', 'IFF', 'IFDEF',
    'IFNDEF', 'IF1', 'IF2', 'IFB', 'IFNB', 'IFIDN', 'IFDIF', 'ELSE', 'ENDIF',
    'ENDC', 'COND', 'INCLUDE', '$INCLUDE', 'MACLIB', 'MACRO', 'ENDM', 'EXITM',
    'LOCAL', 'REPT', 'IRP', 'IRPC'})
INSTRUCTIONS_8080 = frozenset(
    set(NO_OPERAND) | COND_RETS | COND_JUMPS | COND_CALLS | set(ALU_REG)
    | set(ALU_IMM) | {'MOV', 'MVI', 'LXI', 'INR', 'DCR', 'INX', 'DCX', 'DAD',
                      'LDAX', 'STAX', 'PUSH', 'POP', 'JMP', 'CALL', 'RST', 'LDA',
                      'STA', 'LHLD', 'SHLD', 'IN', 'OUT'})
INSTRUCTIONS_Z80 = frozenset(
    set(Z80_NO_OPERAND) | set(Z80_ED_NO_OPERAND) | Z80_ALU_MNEMONICS
    | Z80_ROT_MNEMONICS | Z80_BIT_MNEMONICS
    | {'EX', 'LD', 'PUSH', 'POP', 'INC', 'DEC', 'JP', 'JR', 'DJNZ', 'CALL',
       'RET', 'RST', 'IN', 'OUT', 'IM'})

# A name that begins a statement, and the name of an EQU, SET, DEFL, ASET or
# MACRO in front of its directive (see Assembler.parse_line()).
NAME_WORD = re.compile(r'([$A-Za-z_@?][A-Za-z0-9_@?$.]*)\s*')
NAME_DEFINITION = re.compile(r'([$A-Za-z_@?][A-Za-z0-9_@?$.]*)\s+'
                             r'(?:EQU|SET|DEFL|ASET|MACRO)(?![A-Za-z0-9_@?$.])',
                             re.IGNORECASE)
# MAC's line number in front of a statement, and its assembly controls
# ($-MACRO, $+PRINT, ...): see Assembler.parse_line().
LINE_NUMBER = re.compile(r'\d[0-9A-Za-z$]*(?:\s+|$)')
DRI_CONTROL = re.compile(r'\$[-+*][A-Za-z]')

# Every byte of a source file with its bit 7 cleared (see source_lines()).
STRIP_PARITY = bytes(b & 0x7F for b in range(256))
# An 8AH that does not follow a CR or an 8DH (see source_lines()).
LONE_8AH = re.compile(rb'(?<![\r\x8d])\x8a')


def source_lines(data):
    """The lines of a source file, read from its bytes as CP/M's assemblers
    read them.

    A 1AH (^Z) ends the file: CP/M pads a file's last 128-byte record with
    them.  Each line ends at a CR, a LF or a CR LF.

    Every byte loses bit 7, the parity bit some CP/M editors and serial
    links left set: MACRO-80 3.44, and DRI's MAC and RMAC, all read 8DH as
    a CR, E9H as `i' and C1H in a string as `A', and CR 8AH as CR LF.  um80
    read such a byte as a character no name or operator starts with, so a
    line ending CR 8AH made the next line one it dropped without a word.
    Six lines of MP/M II's NUCLEUS/MEMMGR.ASM end so - one of those dropped
    was an INX B.  A 9AH byte (1AH with bit 7) does not end the file, as in
    M80; MAC and RMAC stop at it.

    An 8AH that does not follow a CR or an 8DH is left out, as M80 leaves
    out every LF: it does not end the line in M80, MAC or RMAC, and um80
    ends one only at a lone LF, which a file from Unix ends its lines
    with.  `NOP ; ABC', 8AH, `INX B' is 00 in all three - the INX B is
    comment - and UTF-8 text in a comment has 8AH bytes (U+4E0A is E4 B8
    8A).  In a string M80 gives `A', 8AH, `B' as 61 62.
    """
    eof = data.find(0x1A)
    if eof >= 0:
        data = data[:eof]
    data = LONE_8AH.sub(b'', data)
    text = data.translate(STRIP_PARITY).decode('ascii')
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    text = text.rstrip('\x00')  # padding nulls
    return text.split('\n')


def drop_name_dollars(line):
    """`line' with every `$' inside a name or a number left out.

    DRI's MAC and RMAC ignore a `$' embedded in a name, to make it easier
    to read: NMB$LST, NMBLST and NMB$L$ST are one symbol, and `public
    a$bc' writes ABC.  MACRO-80 keeps it: there they are three.  um80
    already ignores one in a number (`0001$1111B'), which M80 does not
    accept.  With --dri (Assembler(dri=True)) each statement is read
    through this first, except where MAC reads text and not a name
    (Assembler._dri_statement()).  A `$' that starts a word - the location
    counter, `$+3' - is kept, and so is everything in a quoted string and
    after a `;'.
    """
    if '$' not in line:
        return line
    out = []
    i, n = 0, len(line)
    in_word = False
    while i < n:
        c = line[i]
        if c == ';':
            out.append(line[i:])
            break
        # A quoted string, as parse_line() finds one: a ' after a letter
        # or digit does not start one (Z80's AF').  A doubled quote stays in.
        if c in '\'"' and not (c == "'" and i > 0 and line[i - 1].isalnum()):
            j = i + 1
            while j < n:
                if line[j] == c:
                    if j + 1 < n and line[j + 1] == c:
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            out.append(line[i:j])
            i = j
            in_word = False
            continue
        if c == '$' and in_word:
            i += 1
            continue
        in_word = c.isalnum() or c in '_@?.'
        out.append(c)
        i += 1
    return ''.join(out)


def is_string_literal(text):
    """True if `text' is one quoted string, like 'it''s' - not 'A'+'B'.

    Inside, the quote character stands for itself only when doubled.
    """
    if len(text) < 2 or text[0] not in "'\"" or text[-1] != text[0]:
        return False
    q = text[0]
    return q not in text[1:-1].replace(q * 2, '')


def prefix_operand(expr, word):
    """The operand of a prefix word operator (NOT, HIGH, ...), or None.

    `word' must start `expr' and be followed by something that does not
    continue a name: a blank, a tab or a parenthesis (M80 takes `NOT(X)'
    and `HIGH<TAB>X').
    """
    n = len(word)
    if expr[:n].upper() != word or len(expr) == n or expr[n] in IDENT_CHARS:
        return None
    return expr[n:]


class Symbol:
    """Symbol table entry."""
    def __init__(self, name, value=0, seg_type=ADDR_ABSOLUTE,
                 defined=False, public=False, external=False,
                 ext_alias_base=None, ext_alias_offset=0):
        self.name = name.upper()
        self.value = value
        self.seg_type = seg_type  # ADDR_ABSOLUTE, ADDR_PROGRAM_REL, etc.
        self.defined = defined
        self.defined_pass = 0  # Track which pass defined this symbol
        self.redefinable = False  # True if defined via SET/DEFL/ASET
        self.public = public
        self.external = external
        self.references = []  # Line numbers where referenced
        # For symbols defined as EQU external+offset
        self.ext_alias_base = ext_alias_base  # Name of external symbol, or None
        self.ext_alias_offset = ext_alias_offset  # Offset to add
        # For an EQU/SET whose value only the linker can compute (e.g.
        # `X EQU HIGH BUF' with BUF relocatable): the ExprValue it stands for.
        self.link_expr = None
        self.common_block = None  # COMMON block name of a COMMON-relative symbol
        self.line = 0  # Source line of the (latest) definition
        self.public_line = 0  # Source line of the PUBLIC that named it
        # Pass 2 read the value pass 1 left before this pass redefined it
        # (a forward reference): it must not change when it is redefined.
        self.read_early = False


class ExprValue:
    """An evaluated operand.

    value, seg, ext and name are the assembly-time view parse_expression()
    returns: for a relocatable value, its offset in segment `seg'; for an
    external, `name' plus the constant `value'.

    kind says what the value is once the program is linked:
      'abs'   known now; value is the answer.
      'rel'   the address `value' in segment `seg': a relocatable word.
              When it is an address plus or minus a constant, `rpn' holds
              the two as separate extension link items, the form a
              link-time expression that uses it is written in.
      'ext'   external `name' plus the constant `value'.
      'expr'  anything else computed from relocatable or external values
              with operators LINK-80 can evaluate - HIGH(BUF+128), LOW EXT,
              LAB-EXT - for which `rpn' holds the postfix extension link
              items (see relformat.py).
      'bad'   uses an operator LINK-80 cannot evaluate (AND, OR, XOR, SHL,
              SHR or a comparison) on a relocatable or external value;
              `why' names it, and `origin' the (symbol, line) of the EQU
              or SET that did so when the value came through a symbol.

    A COMMON-relative value ('rel' with seg ADDR_COMMON_REL) also names its
    COMMON block in `block': each named block is placed on its own.
    """

    __slots__ = ('value', 'seg', 'ext', 'name', 'kind', 'rpn', 'why', 'origin',
                 'block')

    def __init__(self, value, seg=ADDR_ABSOLUTE, ext=False, name=None,
                 kind=None, rpn=None, why=None, origin=None, block=None):
        self.value = value
        self.seg = seg
        self.ext = ext
        self.name = name
        if kind is None:
            if ext:
                kind = 'ext'
            else:
                kind = 'abs' if seg == ADDR_ABSOLUTE else 'rel'
        self.kind = kind
        self.rpn = rpn
        self.why = why
        self.origin = origin
        self.block = block if seg == ADDR_COMMON_REL else None

    def as_tuple(self):
        """(value, seg_type, is_external, ext_name), as parse_expression()."""
        return (self.value, self.seg, self.ext, self.name)


class Segment:
    """Code/data segment."""
    def __init__(self, name, seg_type):
        self.name = name
        self.seg_type = seg_type
        self.loc = 0  # Location counter
        self.org = 0  # Starting origin (first ORG or 0)
        self.org_set = False  # Whether org has been set
        self.size = 0  # High water mark
        # Where a CSEG, DSEG or ASEG directive goes on in the segment: the
        # most of the locations set in it and those it was left at (see
        # Assembler.enter_segment()).
        self.mark = 0
        self.data = bytearray()

    def extent(self):
        """The segment's size: the most of the locations reached in it."""
        top = max(self.size, self.loc)
        return top - self.org if self.org_set else top


class Macro:
    """Macro definition."""
    def __init__(self, name, params, body):
        self.name = name.upper()
        self.params = params  # List of parameter names
        self.body = body  # List of source lines


class Assembler:
    """MACRO-80 compatible assembler."""

    def __init__(self, predefined=None, export_all_symbols=False, truncate_symbols=False,
                 strict_jr=False, dri=False):
        self.symbols = {}  # Symbol table
        # --dri: read the source as DRI's MAC and RMAC do where they differ
        # from MACRO-80 - a `$' inside a name is left out (_dri_statement()),
        # a macro body is read with MAC's names (substitute_macro_params(),
        # percent_argument()), and an IF a body leaves open ends with it
        # (end_conditionals()).
        self.dri = dri
        self.export_all_symbols = export_all_symbols  # -g flag: export all as PUBLIC
        self.truncate_symbols = truncate_symbols  # -t flag: names cut to 6 chars, as M80
        self.strict_jr = strict_jr  # --strict flag: error on out-of-range JR instead of promoting to JP
        self.promoted_jr = set()  # Line numbers where JR/DJNZ was promoted to JP
        self.macros = {}   # Macro definitions
        self.segments = {
            'ASEG': Segment('ASEG', ADDR_ABSOLUTE),
            'CSEG': Segment('CSEG', ADDR_PROGRAM_REL),
            'DSEG': Segment('DSEG', ADDR_DATA_REL),
        }
        self.common_blocks = {}  # COMMON blocks
        # Which segment a file starts in.  M80 starts in CSEG; Digital
        # Research's MAC has no relocatable segments at all, so a source
        # written for it is absolute and its ORG means an absolute address.
        # MP/M II's assembler, DDT, GENHEX and GENMOD are all MAC sources.
        self.default_seg = 'CSEG'
        self.current_seg = 'CSEG'  # Default is code segment
        self.current_common = None  # Current COMMON block if any

        self.pass_num = 1
        self.line_num = 0
        self.errors = []
        self.warnings = []

        self.radix = 10  # Default numeric radix
        self.list_on = True
        self.cond_stack = []  # Conditional assembly stack
        self.cond_false_depth = 0  # Depth of false conditionals
        self.cond_else_levels = set()  # Conditional depths that have seen an ELSE

        self.local_counter = 0  # For LOCAL symbols in macros
        self.irpc_from_argument = False  # see expand_macro()
        self.expanding_macro = False
        self.macro_level = 0

        # Macro definition collection state
        self.collecting_macro = None  # Name of macro being defined
        self.macro_params = []  # Parameters of macro being defined
        self.macro_body = []  # Lines of macro being defined
        self.macro_nest_depth = 0  # For nested MACRO/ENDM

        # REPT/IRP/IRPC state
        self.repeat_stack = []  # Stack of (type, count/list, body, iter_var)
        self.repeat_nest_depth = 0  # Nesting depth while collecting a repeat body
        self.repeat_line_tail = None  # DRI '!' statements after an IRP/IRPC list
        self.block_open_line = 0  # Line of the MACRO/REPT/IRP/IRPC still open

        self.entry_point = None  # END address if specified
        self.ended = False  # an END was assembled: the source ends there
        self.module_name = None   # from NAME('...')
        self.title_name = None    # from TITLE, which NAME overrides

        # Save predefined symbols for pass iterations
        self.predefined = predefined or {}

        # Add predefined symbols from command line
        for name, value in self.predefined.items():
            sym = Symbol(name, value, ADDR_ABSOLUTE, defined=True)
            self.symbols[name] = sym

        # External reference chains
        self.ext_chains = {}  # name -> list of (seg, offset, common block) references

        # Forward reference chains (for labels within module)
        self.fwd_chains = {}  # name -> list of (seg, offset) references

        self.output = RELWriter(truncate_symbols=truncate_symbols)
        self.listing_lines = []
        self.source_lines = []

        # Listing generation
        self.generate_listing = False
        self.current_line_bytes = []
        # Index in current_line_bytes -> the mark listed after that byte:
        # the field ending there is not final until the program is linked.
        self.current_line_marks = {}
        self.current_line_start_loc = 0
        self.current_line_start_seg = 'CSEG'

        # Include file handling
        self.include_stack = []  # Stack of (filename, line_num) for nested includes
        self.base_path = None  # Base path for resolving relative includes
        self.include_paths = []  # Additional search paths for includes

        # Processor mode
        self.z80_mode = False  # False = 8080 mode, True = Z80 mode

        # Pass 1 is repeated until the symbol table stops changing.  From
        # the second time on, a symbol used before the line that defines it
        # reads its value at the end of the time before (forward_value()).
        self.pass1_iteration = 0
        self.prev_symbols = {}  # name -> (value, seg_type), for JR/DJNZ
        self.prev_defs = {}  # name -> ExprValue
        self.defining = None  # the symbol a SET is defining, while it does
        # What each EQU and SET read in this time through pass 1, for
        # definition_graph().  A definition is a node (name, k): k is 0 for
        # an EQU, and for a SET its number among the SETs of that name so
        # far (a SET symbol's value depends on where it is read).
        # def_deps: node -> {node read: True if it was a forward reference,
        # to a symbol not defined yet, which reads its last definition};
        # def_text and def_line say where it is, for messages; `reading'
        # collects the reads while an operand is evaluated (note_read()).
        self.def_deps = {}
        self.def_text = {}
        self.def_line = {}
        self.set_count = {}  # name -> SETs of it so far in this pass
        self.reading = None
        # For predict_forward_values(): node -> (operator, operand, radix)
        # of a definition that can be evaluated again away from its line
        # (None if it cannot: it read $, TYPE or X##, or was made twice),
        # and node -> the value it gave.  reading_pure is cleared while an
        # operand is read if it reads something that depends on its line.
        self.def_replay = {}
        self.def_value = {}
        self.reading_pure = True
        # While an 8080 register operand is read (register_value()), a
        # register name in it is its number.
        self.register_operand = False
        # Register names read as values in the expression being evaluated
        # (eval_operand()), and how deep in it the evaluation is.
        self.registers_read = 0
        self.eval_depth = 0
        self.register_number = None  # what register_value() last read
        self.phase = None  # (run address, location counter) after .PHASE
        self.rel_common = None  # COMMON block last selected in the .REL
        self.reported_unlinkable = set()  # symbols report_unlinkable() named

    @property
    def loc(self):
        """Current location counter."""
        if self.current_common is not None:
            return self.common_blocks[self.current_common].loc
        return self.segments[self.current_seg].loc

    @loc.setter
    def loc(self, value):
        if self.current_common is not None:
            com = self.common_blocks[self.current_common]
            com.loc = value
            com.size = max(com.size, value)  # a COMMON block's size
        else:
            seg = self.segments[self.current_seg]
            seg.loc = value
            # A segment's size is also the most it reached: after an ORG
            # back, the location at the end undercounts it (`ORG 20H / DB 1
            # / ORG 10H / DB 2' is 21H bytes, where um80 said 11H and so
            # the next module was linked over the 1).
            if value > seg.size:
                seg.size = value

    def mark_location(self, value=None):
        """Note a location set in the current segment (ORG, DS) or the one
        it is left at: a later CSEG, DSEG or ASEG goes on from the most of
        them."""
        if self.current_common is None:
            seg = self.segments[self.current_seg]
            seg.mark = max(seg.mark, seg.loc if value is None else value)

    def leave_segment(self):
        """Before a segment or COMMON directive."""
        self.mark_location()

    def enter_segment(self, name):
        """CSEG, DSEG or ASEG: go on in segment `name' where MACRO-80 does.

        MACRO-80 3.44 keeps for each segment the most of the locations set
        in it (ORG, the end of a DS) and of those it was left at, and a
        segment directive goes on from there - not from where the segment
        was left, if an ORG went back below an earlier one.  `ASEG / ORG
        200H / DB 1,2,3 / ORG 180H / DB 4 / CSEG / DB 5 / ASEG / DB 6' puts
        the 6 at 0200H, over the 1; so does ASEG alone in place of `CSEG /
        DB 5 / ASEG'.  After `DS 10H / ORG 4 / DB 1', CSEG goes on at 10H,
        past the DS.  um80 went on where the segment was left (0181H, 5).
        """
        self.leave_segment()
        moved = self.current_seg != name or self.current_common is not None
        self.current_seg = name
        self.current_common = None
        seg = self.segments[name]
        if seg.loc != seg.mark:
            seg.loc = seg.mark
            moved = True
        if moved and self.pass_num == 2:
            if name == 'ASEG':
                # The linker has to load into ASEG from here on, but the
                # item saying so is held back until something is loaded or
                # reserved here, as MACRO-80 does: an ORG or another segment
                # directive first replaces it.  LINK-80 takes a set-location
                # item to ASEG 0000H for code loaded at 0000H, so `ASEG /
                # ORG 100H' made it write a .COM from 0000H.
                self.output.defer_set_location(self.seg_type, self.loc)
            else:
                # So the linker loads into this segment again (leaving a
                # COMMON block too, which did not set one).
                self.output.drop_deferred_location()
                self.output.write_set_location(self.seg_type, self.loc)

    @property
    def pc(self):
        """The address the current instruction runs at: $, a label's value.

        The location counter, except inside .PHASE addr ... .DEPHASE, where
        code loaded here runs at `addr': the block's labels and $ are the
        absolute addresses it runs at (M80 manual; checked against M80 3.44).
        """
        if self.phase is not None:
            base, start = self.phase
            return (base + self.loc - start) & 0xFFFF
        return self.loc

    @property
    def pc_seg(self):
        """The segment type of pc: absolute inside a .PHASE block."""
        return ADDR_ABSOLUTE if self.phase is not None else self.seg_type

    def here(self):
        """The ExprValue of $: pc, in its segment (and COMMON block)."""
        return ExprValue(self.pc, self.pc_seg, block=self.current_common)

    @property
    def seg_type(self):
        """Current segment type."""
        if self.current_common is not None:
            return ADDR_COMMON_REL
        return self.segments[self.current_seg].seg_type

    def error(self, msg):
        """Record an error."""
        self.errors.append(AssemblerError(msg, self.line_num))

    def warning(self, msg):
        """Record a warning."""
        self.warnings.append(f"Warning at line {self.line_num}: {msg}")

    def z80_form_hint(self, operator, ops):
        """Hint for a Z80 instruction whose mnemonic is an 8080 mnemonic.

        In 8080 mode the operand of 'RET cc', 'RLC r' or 'RRC r' used to be
        thrown away, which assembled Z80 source into a different program.
        Returns '' when there is nothing useful to say.
        """
        if self.z80_mode or len(ops) != 1:
            return ''
        add_z80 = " Add a .Z80 directive to assemble Z80 mnemonics."
        first = ops[0].strip().upper()
        if operator == 'RET' and first in CONDITIONS:
            return (f" RET {first} is Z80 syntax; the 8080 spelling is"
                    f" R{first}.{add_z80}")
        if operator in ('RLC', 'RRC') and first in Z80_REGS_M:
            return (f" {operator} {first} is Z80 syntax; the 8080 {operator}"
                    f" rotates A only.{add_z80}")
        return ''

    def error_no_operand(self, operator, ops):
        """Reject operands given to an instruction that takes none.

        Real MACRO-80 3.44 only flags these 'Q' and assembles the instruction
        without its operand, so 'RET NZ' becomes an unconditional RET (C9) and
        'RLC B' becomes RLC A (07).  Dropping an operand changes what the
        program does, so um80 makes it an error.  This is a deliberate
        divergence from M80; see CHANGELOG.md.
        """
        text = ','.join(op.strip() for op in ops)
        self.error(f"{operator} takes no operand, but was given '{text}'"
                   + self.z80_form_hint(operator, ops))

    def _start_listing_line(self):
        """Prepare for listing capture at start of line processing."""
        if self.pass_num == 2 and self.generate_listing:
            self.current_line_start_loc = self.pc
            self.current_line_start_seg = self.current_seg
            self.current_line_bytes = []
            self.current_line_marks = {}

    def _save_listing_entry(self, line):
        """Save a listing entry for the current line."""
        if self.pass_num == 2 and self.generate_listing:
            self.listing_lines.append({
                'line_num': self.line_num,
                'addr': self.current_line_start_loc,
                'seg': self.current_line_start_seg,
                'bytes': self.current_line_bytes[:],
                'marks': dict(self.current_line_marks),
                'source': line
            })

    def define_symbol(self, name, value, seg_type=None, public=False):
        """Define or update a symbol (a label, or EQU of an assembly-time value)."""
        if seg_type is None:
            seg_type = self.seg_type
        self.define_value(name, ExprValue(value, seg_type,
                                          block=self.current_common), public)

    def define_value(self, name, ev, public=False):
        """Define a label or EQU symbol as the ExprValue `ev'.

        `ev' may be an address or constant, an external plus a constant (the
        symbol is an alias of the external), or a value only the linker can
        compute, which the symbol then stands for wherever it is used.
        """
        name = name.upper()
        if ev.kind == 'rel' and ev.rpn:
            # A symbol is one address (its operands are not kept).
            ev = ExprValue(ev.value, ev.seg, block=ev.block)
        sym = self.symbols.get(name)
        if sym is None:
            sym = Symbol(name)
            self.symbols[name] = sym
        elif sym.defined and sym.defined_pass == self.pass_num and not sym.external:
            # Multiply defined if the value changed - its segment, the
            # expression it stands for, not just the number - or if the
            # symbol was made redefinable by SET/DEFL/ASET (EQU/label cannot
            # redefine a SET symbol -- the definition class is fixed by the
            # first definition).
            if sym.redefinable or (self.value_key(self.symbol_value(sym))
                                   != self.value_key(ev)):
                self.error(f"Symbol '{name}' multiply defined")
                return
        self.check_phase(sym, ev)
        sym.value = ev.value
        sym.seg_type = ADDR_ABSOLUTE if ev.kind == 'ext' else ev.seg
        sym.ext_alias_base = ev.name if ev.kind == 'ext' else None
        sym.ext_alias_offset = ev.value if ev.kind == 'ext' else 0
        sym.link_expr = ev if ev.kind in ('expr', 'bad') else None
        sym.common_block = ev.block
        sym.defined = True
        sym.defined_pass = self.pass_num
        sym.redefinable = False  # EQU / label is non-redefinable
        sym.line = self.line_num
        if public:
            sym.public = True

    @staticmethod
    def symbol_value(sym):
        """The ExprValue a defined or external symbol stands for."""
        if sym.external:
            return ExprValue(0, ext=True, name=sym.name)
        if sym.ext_alias_base:
            return ExprValue(sym.ext_alias_offset, ext=True,
                             name=sym.ext_alias_base)
        ev = sym.link_expr
        if ev is not None:
            if ev.kind == 'bad' and ev.origin is None:
                # Name the definition in the error a use of it gets.
                ev = ExprValue(ev.value, ev.seg, ev.ext, ev.name, kind='bad',
                               why=ev.why, origin=(sym.name, sym.line))
            return ev
        return ExprValue(sym.value, sym.seg_type, block=sym.common_block)

    def forward_value(self, name):
        """The value of a symbol used before the line that defines it, or None.

        On a repeat of pass 1 that is its value at the end of the previous
        repeat, which is what pass 2 will read there too; so a chain like
        `MVI A,X / X EQU FWD+1 / FWD EQU 5' settles on X = 6 instead of
        freezing the 1 the first time through computed with FWD still 0.
        A SET symbol read by its own SET (`X SET X+1') is left undefined.
        """
        if self.pass_num != 1 or name == self.defining:
            return None
        return self.prev_defs.get(name)

    @staticmethod
    def value_key(ev):
        """A comparable summary of everything an ExprValue says."""
        return (ev.kind, ev.value & 0xFFFF, ev.seg, ev.ext, ev.name,
                tuple(ev.rpn) if ev.rpn else None, ev.why, ev.block)

    def check_phase(self, sym, new):
        """Refuse a pass-2 redefinition that differs from pass 1's value.

        Pass 2 reads a forward-referenced symbol's pass-1 value; if the line
        that defines it then computes something else, every earlier use was
        assembled with the wrong value.  Pass 1 is iterated until the table
        stops changing (assemble()), so this should not happen - it is the
        net under that, for whatever makes the two passes differ (an IFDEF
        of a later symbol, IF1/IF2).
        """
        if (self.pass_num == 2 and sym.defined and sym.defined_pass == 1
                and sym.read_early and not sym.redefinable
                and not sym.external
                and self.value_key(self.symbol_value(sym))
                != self.value_key(new)):
            self.error(f"Phase error: '{sym.name}' is used before it is "
                       f"defined, and its value is not the same in both "
                       f"passes ({sym.value & 0xFFFF:04X}H before this "
                       f"line, {new.value & 0xFFFF:04X}H here)")

    def note_read(self, sym):
        """Record in `reading' which definition of `sym' is read.

        A symbol not defined yet is a forward reference: it reads the
        symbol's value at the end of the previous time through, its last
        definition, which is (name, -1) until the pass is over.  A SET
        symbol read by its own SET reads the SET before (there may be
        none: `X SET X+1' with no X yet reads nothing).
        """
        name = sym.name
        if name in OPCODE_VALUES:
            # Read as the symbol here, as the opcode's byte away from here.
            self.reading_pure = False
        if name == self.defining:
            k = self.set_count.get(name, 0)
            if k:
                self.reading.setdefault((name, k), False)
        elif sym.defined or sym.external:
            k = self.set_count.get(name, 0) if sym.redefinable else 0
            self.reading.setdefault((name, k), False)
        else:
            self.reading[(name, -1)] = True

    def note_definition(self, node, operator, text, reads):
        """Record what the EQU or SET `node' read (note_read())."""
        self.def_replay[node] = None if node in self.def_deps or \
            not self.reading_pure else (operator, text, self.radix)
        deps = self.def_deps.setdefault(node, {})
        for dep, forward in reads.items():
            deps[dep] = deps.get(dep) or forward
        self.def_text.setdefault(node, f"{node[0]} {operator} {text.strip()}")
        self.def_line.setdefault(node, self.line_num)

    def predict_forward_values(self, order, defs):
        """What forward references should read next time through pass 1,
        or None if that is `defs'.

        `defs' holds every symbol's value at the end of this time through,
        which is what a forward reference reads next time; so a chain of N
        EQUs, each defined in terms of the next one down, settles one link
        per time through and the source is read N times (500 deep: 92 s).
        Instead each EQU and SET is evaluated again here, in `order' (each
        after the definitions it reads), with what it reads standing for
        the values just worked out, which settles the chain in one go.  It
        is only a guess - a label may yet move - so the next time through
        still computes every value, and pass 1 is over only when those are
        what the forward references read.  A definition that cannot be
        evaluated away from its line (def_replay) keeps the value it gave.
        """
        values, affected = {}, set()
        for node in order:
            value = None
            # Only a definition that reads a forward reference, or one
            # that such a definition decides, can come out another way.
            reads = self.def_deps[node]
            if any(forward or self.resolve_node(dep) in affected
                   for dep, forward in reads.items()):
                affected.add(node)
            else:
                values[node] = self.def_value.get(node)
                continue
            replay = self.def_replay.get(node)
            if replay is not None:
                env = {}
                for dep in reads:
                    used = self.resolve_node(dep)
                    known = values.get(used, self.def_value.get(used))
                    if known is None:
                        known = defs.get(dep[0])
                    if known is not None:
                        env[dep[0]] = known
                value = self.evaluate_away(replay, env)
            values[node] = value if value is not None \
                else self.def_value.get(node)
        guessed = None
        for (name, k), value in values.items():
            if (value is not None and name in defs
                    and k == self.set_count.get(name, 0)
                    and self.value_key(value) != self.value_key(defs[name])):
                guessed = guessed or dict(defs)
                guessed[name] = value
        return guessed

    def evaluate_away(self, replay, env):
        """The value of an EQU or SET operand, `replay' = (operator,
        operand, radix), with each symbol it reads standing for its value
        in `env' - or None if that reports an error."""
        operator, text, radix = replay
        saved = (self.symbols, self.prev_defs, self.pass_num, self.defining,
                 self.reading, self.errors, self.radix)
        # With no symbol defined, every one read is looked up in prev_defs.
        self.symbols, self.prev_defs, self.pass_num = {}, env, 1
        self.defining = self.reading = None
        self.errors, self.radix = [], radix
        try:
            ev = self.eval_operand(text, allow_undefined=True)
            failed = bool(self.errors)
        finally:
            (self.symbols, self.prev_defs, self.pass_num, self.defining,
             self.reading, self.errors, self.radix) = saved
        # What the symbol then stands for, as define_value() and SET store
        # it (symbol_value()).
        if failed or ev.kind == 'bad':
            return None
        if ev.kind == 'expr':
            return ev
        if operator != 'EQU':
            return None if ev.kind == 'ext' else ExprValue(ev.value, ev.seg)
        if ev.kind == 'ext':
            return ExprValue(ev.value, ext=True, name=ev.name)
        return ExprValue(ev.value, ev.seg, block=ev.block)

    def resolve_node(self, node):
        """The definition a read recorded as `node' reads, now that the
        pass is over: a forward reference, (name, -1), reads the last."""
        name, k = node
        return (name, self.set_count.get(name, 0)) if k < 0 else node

    def definition_graph(self):
        """(cycle, depth, order) of the EQUs and SETs of the last pass 1.

        `cycle' is a list of definitions each defined in terms of the next
        and the last in terms of the first, with at least one of those
        uses a forward reference (reading an earlier definition is not
        circular: `X EQU 5 / Y EQU X / X EQU Y' is fine), or None.  `depth'
        is the most forward references along any chain of definitions,
        the number of repeats of pass 1 the chain needs to settle.  `order'
        lists every definition after those it reads (a cycle's members
        together).

        Each strongly connected set of definitions (Tarjan's algorithm,
        iterative, so a long chain does not hit Python's recursion limit)
        is circular if a forward reference joins two of its members: there
        is then a way back from the one read to the one reading it.
        """
        deps = self.def_deps
        edges = {}
        for node, reads in deps.items():
            out = {}
            for dep, forward in reads.items():
                dep = self.resolve_node(dep)
                if dep in deps:  # not a label, an external, ...
                    out[dep] = out.get(dep, False) or forward
            edges[node] = sorted(out.items())

        roots = sorted(deps, key=lambda n: (self.def_line.get(n, 0), n))
        components = self._strong_components(roots, edges)

        # Components come out after every component they read.
        cycle, depth, order = None, {}, []
        for component in components:
            members = set(component)
            most = 0
            for node in component:
                for used, forward in edges[node]:
                    if used not in members:
                        most = max(most, depth[used] + (1 if forward else 0))
                    elif forward and cycle is None:
                        cycle = self._cycle_through(node, used, members, edges)
            for node in component:
                depth[node] = most
            order.extend(component)
        return cycle, max(depth.values(), default=0), order

    @staticmethod
    def _strong_components(roots, edges):
        """The strongly connected components of the graph `edges' (node ->
        [(node, anything)]), each listed after every component it reaches:
        Tarjan's algorithm, iterative."""
        index, low, on_stack, stack, components = {}, {}, set(), [], []

        def visit(node):
            index[node] = low[node] = len(index)
            stack.append(node)
            on_stack.add(node)
            return (node, iter(edges[node]))

        for root in roots:
            if root in index:
                continue
            work = [visit(root)]
            while work:
                node, uses = work[-1]
                for used, _ in uses:
                    if used not in index:
                        work.append(visit(used))
                        break
                    if used in on_stack:
                        low[node] = min(low[node], index[used])
                else:
                    work.pop()
                    if work:
                        parent = work[-1][0]
                        low[parent] = min(low[parent], low[node])
                    if low[node] == index[node]:
                        component = [stack.pop()]
                        while component[-1] != node:
                            component.append(stack.pop())
                        on_stack.difference_update(component)
                        components.append(component)
        return components

    @staticmethod
    def _cycle_through(node, used, members, edges):
        """The cycle `node' -> `used' -> ... -> `node' within `members'."""
        came_from = {used: None}
        queue = deque([used])
        while queue:
            here = queue.popleft()
            if here == node:
                break
            for nxt, _ in edges[here]:
                if nxt in members and nxt not in came_from:
                    came_from[nxt] = here
                    queue.append(nxt)
        path = []
        here = node
        while here is not None:
            path.append(here)
            here = came_from[here]
        path.reverse()  # used ... node
        return [node] + path[:-1]

    def report_circular(self, cycle):
        """Error for definitions made in terms of each other (`cycle')."""
        first = min(range(len(cycle)),
                    key=lambda i: (self.def_line.get(cycle[i], 0), i))
        cycle = cycle[first:] + cycle[:first]
        chain = ', '.join(self.def_text.get(node, f"{node[0]} EQU ?")
                          for node in cycle)
        self.errors.append(AssemblerError(
            f"Cannot resolve the value of '{cycle[0][0]}': it is defined in "
            f"terms of itself ({chain})", self.def_line.get(cycle[0])))

    def lookup_symbol(self, name):
        """Look up a symbol, creating undefined entry if needed."""
        name = name.upper()
        if name not in self.symbols:
            self.symbols[name] = Symbol(name)
        return self.symbols[name]

    def parse_number(self, s):
        """Parse a numeric constant, return (value, success)."""
        s = s.strip().upper()
        if not s:
            return (0, False)

        # DRI extension: strip $ digit separators (e.g., 010$0000B)
        s = s.replace('$', '')

        # Check for suffix notation
        if s.endswith('H'):
            try:
                return (int(s[:-1], 16), True)
            except ValueError:
                return (0, False)
        elif s.endswith('O') or s.endswith('Q'):
            try:
                return (int(s[:-1], 8), True)
            except ValueError:
                return (0, False)
        elif s.endswith('B'):
            try:
                return (int(s[:-1], 2), True)
            except ValueError:
                return (0, False)
        elif s.endswith('D'):
            try:
                return (int(s[:-1], 10), True)
            except ValueError:
                return (0, False)

        # Check for X'nn' hex notation
        if s.startswith("X'") and s.endswith("'"):
            try:
                return (int(s[2:-1], 16), True)
            except ValueError:
                return (0, False)

        # Check for leading 0 prefix for hex that starts with letter
        if s and s[0].isdigit():
            try:
                return (int(s, self.radix), True)
            except ValueError:
                # Try hex if it looks like hex
                try:
                    return (int(s, 16), True)
                except ValueError:
                    return (0, False)

        return (0, False)

    def parse_char_const(self, s):
        """Parse character constant like 'A' or 'AB'.

        A doubled quote inside stands for one: '''' is 27H, as in M80.
        """
        if is_string_literal(s):
            chars = s[1:-1].replace(s[0] * 2, s[0])
            if len(chars) == 1:
                return (ord(chars), True)
            elif len(chars) == 2:
                # M80: first char is the high-order byte ('AB' = 0x4142).
                return ((ord(chars[0]) << 8) | ord(chars[1]), True)
        return (0, False)

    def find_op_at_level0(self, expr, ops):
        """
        Find the rightmost occurrence of any operator in ops at parenthesis level 0.
        Returns (index, op_len) or (-1, 0) if not found.
        Properly skips over string/character constants.
        """
        # First, mark positions that are inside strings
        in_string = [False] * len(expr)
        i = 0
        while i < len(expr):
            if expr[i] in "'\"":
                quote_char = expr[i]
                start = i
                i += 1
                while i < len(expr) and expr[i] != quote_char:
                    i += 1
                if i < len(expr):
                    # Mark all chars from start to i (inclusive) as in string
                    for j in range(start, i + 1):
                        in_string[j] = True
                i += 1
            else:
                i += 1

        level = 0
        i = len(expr) - 1
        while i >= 0:
            if in_string[i]:
                i -= 1
                continue
            ch = expr[i]
            if ch == ')':
                level += 1
            elif ch == '(':
                level -= 1
            elif level == 0:
                for op in ops:
                    if i >= len(op) - 1:
                        # Check if op matches at position i-len(op)+1
                        start = i - len(op) + 1
                        # Make sure none of the op chars are in a string
                        if any(in_string[j] for j in range(start, i + 1)):
                            continue
                        if expr[start:i+1].upper() == op.upper():
                            # Make sure it's not part of a larger token
                            if op[0].isalpha():
                                # Word operator - needs boundaries: not part
                                # of a longer name (MY_OR, XOR, ORG.1), but
                                # a tab or a parenthesis will do (M80 takes
                                # `X<TAB>AND<TAB>0FH' and `(X)SHR(4)').
                                before_ok = (start == 0 or expr[start-1] not in IDENT_CHARS)
                                after_ok = (i+1 >= len(expr) or expr[i+1] not in IDENT_CHARS)
                                if (before_ok and after_ok
                                        and not self.names_symbol(op)):
                                    return (start, len(op))
                            else:
                                # Symbol operator
                                return (start, len(op))
            i -= 1
        return (-1, 0)

    # Word operators that may directly precede a '+'/'-' that is therefore a
    # unary sign on the following term, not a binary add/subtract.
    _PRECEDING_WORD_OPS = frozenset({
        'MOD', 'SHL', 'SHR', 'AND', 'OR', 'XOR', 'NOT',
        'EQ', 'NE', 'LT', 'LE', 'GT', 'GE', 'HIGH', 'LOW', 'NUL', 'TYPE',
    })

    def names_symbol(self, name):
        """True if `name' is a symbol of the program: defined, EXTRN, or
        defined further down (the time through pass 1 before defined it).

        MACRO-80 3.44 reads such a name as the symbol wherever it could also
        be an operator or a register: after `EQ: NOP', `DW EQ' is the label
        and `DW 1 EQ 1' is an error (O); after `TYPE EQU 5', `DB TYPE+2' is
        07; after `B EQU 9', `DB B' is 09.  MAC and RMAC do not let a
        program define such a name (S).
        """
        name = name.upper()
        sym = self.symbols.get(name)
        if sym is not None and (sym.defined or sym.external):
            return True
        return self.pass_num == 1 and name in self.prev_defs

    def prefix_word(self, expr, word):
        """prefix_operand(), for an operator the program has not made a
        symbol (names_symbol())."""
        rest = prefix_operand(expr, word)
        return None if rest is None or self.names_symbol(word) else rest

    def find_binary_addsub(self, expr):
        """Rightmost binary '+'/'-' at paren level 0, skipping unary signs.

        A '+'/'-' is unary (and skipped) when it begins the expression or
        immediately follows another operator or a word operator (e.g. the '-'
        in 3*-2, 5--3, 2 SHL -1). Returns (index, op_char) or (-1, '').
        """
        in_string = [False] * len(expr)
        i = 0
        while i < len(expr):
            if expr[i] in "'\"":
                quote_char = expr[i]
                start = i
                i += 1
                while i < len(expr) and expr[i] != quote_char:
                    i += 1
                if i < len(expr):
                    for j in range(start, i + 1):
                        in_string[j] = True
                i += 1
            else:
                i += 1

        level = 0
        i = len(expr) - 1
        while i >= 0:
            if in_string[i]:
                i -= 1
                continue
            ch = expr[i]
            if ch == ')':
                level += 1
            elif ch == '(':
                level -= 1
            elif level == 0 and ch in '+-':
                left = expr[:i].rstrip()
                if left and left[-1] not in '+-*/(<,':
                    # The word before the sign, whole: X1EQ, @P$NUL and
                    # ALOW end in letters that make an operator, but are
                    # names (`X1EQ+2' is X1EQ plus 2, as in M80; um80 read
                    # it as X1 EQ +2, which did not parse).
                    m = re.search(r'[A-Za-z0-9_@?$.]+$', left)
                    word = m.group(0) if m else ''
                    if not (word.upper() in self._PRECEDING_WORD_OPS
                            and not self.names_symbol(word)):
                        return (i, ch)
            i -= 1
        return (-1, '')

    def parse_expression(self, expr, allow_undefined=False):
        """
        Parse an expression, return (value, seg_type, is_external, ext_name).
        Uses recursive descent with proper precedence and parenthesis handling.

        This is the assembly-time view of the value, and what every directive
        that needs a number now (ORG, DS, IF, EQU ...) uses.  An instruction
        or DB/DW operand is evaluated with eval_operand() instead, which also
        knows when the value only exists at link time.
        """
        return self.eval_operand(expr, allow_undefined).as_tuple()

    def eval_operand(self, expr, allow_undefined=False):
        """Evaluate an expression to an ExprValue.

        The value/seg/ext/name fields are exactly what parse_expression() has
        always returned; `kind' and the postfix form say what the linker has
        to be told when the value depends on segment placement or externals.

        In 8080 code a register name is its number (REG_VALUES), as in M80
        and MAC: `X EQU D+1' is 3, `DB B' 00, `MVI A,B' 3E 00.  M80 flags an
        expression with two register names in it (`A*256+B', `C-B') O,
        though it computes it; MAC does not, and neither does um80 with
        --dri.
        """
        top = self.eval_depth == 0
        if top:
            self.registers_read = 0
        self.eval_depth += 1
        try:
            ev = self._evaluate(expr, allow_undefined)
        finally:
            self.eval_depth -= 1
        if (top and self.registers_read > 1 and not self.dri
                and self.pass_num == 2):
            self.error(f"'{expr.strip()}' has {self.registers_read} register names"
                       f" in it (M80: O; MAC takes it: --dri)")
        return ev

    def _evaluate(self, expr, allow_undefined=False):
        """eval_operand() of `expr', which may be part of the expression."""
        expr = expr.strip()
        if not expr:
            return ExprValue(0)

        # Handle special symbols
        if expr == '$':
            self.reading_pure = False
            return self.here()

        # Operators are split lowest-precedence-first (recursive descent) in
        # M80 precedence order. Unary operators (NOT; unary +/-; HIGH/LOW/NUL/
        # TYPE) are handled at their own precedence level further down, NOT at
        # the top, so e.g. -2+3 = (-2)+3 and NOT 1 AND 2 = (NOT 1) AND 2.
        upper = expr.upper()

        # Handle parenthesized expression - check if balanced outer parens
        if expr.startswith('('):
            level = 0
            for i, ch in enumerate(expr):
                if ch == '(':
                    level += 1
                elif ch == ')':
                    level -= 1
                    if level == 0:
                        if i == len(expr) - 1:
                            # Entire expr is wrapped in parens
                            return self.eval_operand(expr[1:-1], allow_undefined)
                        else:
                            # Parens close before end, not fully wrapped
                            break

        # --dri: HIGH and LOW bind loosest of all, as MAC's manual has them
        # and MAC and RMAC read them: `HIGH 1234H OR 0F00H' is HIGH(1F34H),
        # 1FH, `HIGH(100H)+1' is HIGH(101H), 1, and `LOW 1234H SHR 4' is
        # 23H.  M80 applies them to the term that follows (12H OR 0F00H;
        # 2; 03H), and so does um80 without --dri (further down).
        if self.dri:
            for word, code in (('HIGH', EXT_OP_HIGH), ('LOW', EXT_OP_LOW)):
                inner = self.prefix_word(expr, word)
                if inner is not None:
                    return self._high_low(code, inner, allow_undefined)

        # Lowest precedence: OR and XOR, one level, left to right (M80 and
        # DRI's MAC both: `1 OR 1 XOR 1' is 0), then AND.  LINK-80 has no
        # operator for any of the three, so on a relocatable or external
        # operand the result cannot reach the linker (M80 flags these 'R').
        for words in (('OR', 'XOR'), ('AND',)):
            idx, oplen = self.find_op_at_level0(expr, list(words))
            if idx >= 0:
                word = expr[idx:idx+oplen].upper()
                if self.missing_operand(expr, expr[:idx], expr[idx+oplen:], word):
                    return ExprValue(0)
                left = self.eval_operand(expr[:idx], allow_undefined)
                right = self.eval_operand(expr[idx+oplen:], allow_undefined)
                a, b = left.value & 0xFFFF, right.value & 0xFFFF
                value = a | b if word == 'OR' else a ^ b if word == 'XOR' \
                    else a & b
                return self._link_binary(word, left, right, value)

        # NOT (unary): binds tighter than AND/OR/XOR, looser than relational.
        rest = self.prefix_word(expr, 'NOT')
        if rest is not None:
            operand = self.eval_operand(rest, allow_undefined)
            return self._link_unary(EXT_OP_NOT, operand,
                                    (~operand.value) & 0xFFFF)

        # Comparison operators: EQ, NE, LT, LE, GT, GE, and with --dri MAC's
        # =, <>, <, <=, >, >= for them (M80 has no such operator: `IF @Y =
        # 1', in DRI's CONTROL/DEBLOCK.ASM, is O there).
        idx, oplen = self.find_op_at_level0(
            expr, ['EQ', 'NE', 'LT', 'LE', 'GT', 'GE']
            + (list(self._DRI_RELATIONS) if self.dri else []))
        if idx >= 0:
            op = expr[idx:idx+oplen].strip().upper()
            op = self._DRI_RELATIONS.get(op, op)
            if self.missing_operand(expr, expr[:idx], expr[idx+oplen:], op):
                return ExprValue(0)
            left = self.eval_operand(expr[:idx], allow_undefined)
            right = self.eval_operand(expr[idx+oplen:], allow_undefined)
            left_val, right_val = left.value & 0xFFFF, right.value & 0xFFFF
            if op == 'EQ':
                result = 0xFFFF if left_val == right_val else 0
            elif op == 'NE':
                result = 0xFFFF if left_val != right_val else 0
            elif op == 'LT':
                result = 0xFFFF if left_val < right_val else 0
            elif op == 'LE':
                result = 0xFFFF if left_val <= right_val else 0
            elif op == 'GT':
                result = 0xFFFF if left_val > right_val else 0
            elif op == 'GE':
                result = 0xFFFF if left_val >= right_val else 0
            else:
                result = 0
            # Two addresses in the same segment compare the same wherever the
            # linker puts it; so do two offsets from the same external
            # (`EXT EQ EXT', which M80 also accepts).
            if ((left.kind == 'rel' and right.kind == 'rel'
                 and left.seg == right.seg and left.block == right.block)
                    or (left.kind == 'ext' and right.kind == 'ext'
                        and left.name == right.name)):
                return ExprValue(result)
            return self._link_binary(op, left, right, result)

        # Binary addition and subtraction (left-associative). Only split at a
        # '+'/'-' in binary context; a unary sign (e.g. in 3*-2 or 5--3) is
        # left for the unary handler / higher-precedence operand parsing.
        idx, op = self.find_binary_addsub(expr)
        if idx >= 0:
            left_text = expr[:idx].strip()
            right_text = expr[idx+1:].strip()

            if left_text:
                left = self.eval_operand(left_text, allow_undefined)
                right = self.eval_operand(right_text, allow_undefined)
                return self._add_sub(op, left, right)

        # Unary minus / plus: binds tighter than binary +/- but looser than
        # the multiplicative operators (so 3*-2 = 3*(-2), -2*3 = -(2*3)).
        if expr.startswith('-') and len(expr) > 1:
            operand = self.eval_operand(expr[1:], allow_undefined)
            return self._link_unary(EXT_OP_NEG, operand, (-operand.value) & 0xFFFF,
                                    operand.seg, operand.ext, operand.name)
        if expr.startswith('+') and len(expr) > 1:
            return self.eval_operand(expr[1:], allow_undefined)

        # Multiplication, division, MOD, SHL, SHR
        idx, oplen = self.find_op_at_level0(expr, ['*', '/', 'MOD', 'SHL', 'SHR'])
        if idx >= 0:
            op = expr[idx:idx+oplen].strip().upper()
            if self.missing_operand(expr, expr[:idx], expr[idx+oplen:], op):
                return ExprValue(0)
            left = self.eval_operand(expr[:idx], allow_undefined)
            right = self.eval_operand(expr[idx+oplen:], allow_undefined)
            # The offset beside an external may be negative (EXT-1).
            left_val, right_val = left.value & 0xFFFF, right.value & 0xFFFF
            if op == '*':
                result = (left_val * right_val) & 0xFFFF
            elif op in ('/', 'MOD'):
                if right_val == 0:
                    # Only a constant 0 is a division by zero.  A divisor
                    # read before its definition is 0 the first time pass 1
                    # sees it, and an external or relocatable divisor is 0
                    # at assembly time whatever the linker makes of it.
                    if right.kind == 'abs' and self.pass_num == 2:
                        self.error("Division by zero")
                        return ExprValue(0)
                    return self._link_binary(op, left, right, 0)
                if op == '/':
                    result = (left_val // right_val) & 0xFFFF
                else:
                    result = (left_val % right_val) & 0xFFFF
            elif right_val > 15:
                result = 0  # every bit shifted out
            elif op == 'SHL':
                result = (left_val << right_val) & 0xFFFF
            else:
                result = (left_val >> right_val) & 0xFFFF
            return self._link_binary(op, left, right, result)

        # Highest-precedence operators (bind tightest, just below parentheses):
        # HIGH/LOW, the DRI HIGH(...)/LOW(...) function form, NUL and TYPE.
        # DRI HIGH(expr)/LOW(expr): only the function form when the matching
        # close paren is at end-of-expression (otherwise a binary operator
        # above would already have split, e.g. HIGH(1234H)+1).
        #
        # The value is the byte of the assembly-time value, which for a
        # relocatable operand is its offset in the segment - not the byte of
        # the address the linker gives it (in MP/M II's LDRLWR.ASM,
        # `mvi a,low(bitmap+128)' came out as the low byte of the offset).
        # So a relocatable or external operand makes this an expression for
        # the linker to finish; see _link_unary().
        for word, code in (('HIGH', EXT_OP_HIGH), ('LOW', EXT_OP_LOW)):
            inner = self.prefix_word(expr, word)
            if inner is not None:
                # HIGH X, HIGH(X), HIGH<TAB>X.  A binary operator after the
                # operand - HIGH(1234H)+1 - has already been split above.
                return self._high_low(code, inner, allow_undefined)

        # NUL operator - true (0FFFFh) if its argument is null/empty. The empty
        # case (a macro arg omitted, leaving a bare 'NUL') is its primary use.
        if (upper == 'NUL' and not self.names_symbol('NUL')
                or self.prefix_word(expr, 'NUL') is not None):
            arg = expr[3:].strip()
            if not arg or arg == '<>' or arg == "''":
                return ExprValue(0xFFFF)
            return ExprValue(0)

        # TYPE operator - returns byte describing expression characteristics
        # Lower 2 bits: mode (0=abs, 1=prog rel, 2=data rel, 3=common rel)
        # Bit 5 (20H): defined; Bit 7 (80H): external
        if self.prefix_word(expr, 'TYPE') is not None:
            self.reading_pure = False
            arg = expr[4:].strip()
            if re.match(r'^[A-Za-z_@?][A-Za-z0-9_@?$.]*$', arg):
                if (arg.upper() in REG_VALUES and not self.z80_mode
                        and not self.names_symbol(arg)):
                    return ExprValue(0x20)  # a number, as M80 has it
                sym = self.symbols.get(arg.upper())
                if sym:
                    result = sym.seg_type & 0x03
                    if sym.defined:
                        result |= 0x20
                    if sym.external:
                        result |= 0x80
                    return ExprValue(result)
                return ExprValue(0)
            return ExprValue(self.type_of(arg))

        # Handle ## suffix (6-character truncation operator, implies external)
        if expr.endswith('##'):
            self.reading_pure = False
            # Truncate symbol to 6 chars and look it up
            sym_name = expr[:-2][:6]
            sym = self.lookup_symbol(sym_name)
            if sym.external:
                return ExprValue(0, ext=True, name=sym.name)
            if not sym.defined:
                # ## implies external if not defined locally
                sym.external = True
                return ExprValue(0, ext=True, name=sym.name)
            # A local definition: an alias of an external or a link-time
            # expression stands for what it stands for without the ## too.
            return self.symbol_value(sym)

        # Try as simple symbol
        if re.match(r'^[$A-Za-z_@?][A-Za-z0-9_@?$.]*$', expr):
            upper = expr.upper()

            # A register name, but for a symbol of that name (M80 reads
            # `B EQU 9' / `DB B' as 09): in 8080 code, its number, as in
            # M80 and MAC.  um80 made it "Register 'B' used as value" but in
            # a register operand, so `X EQU D+1', `DB B', `MVI A,B' and `IF
            # B EQ 0' did not assemble.  In Z80 code M80 gives every
            # register name 0; um80 keeps the error.
            if ((upper in REGS or upper in REGPAIRS or upper in REGPAIRS_PUSHPOP)
                    and not self.names_symbol(upper)):
                if self.register_operand or not self.z80_mode:
                    self.registers_read += 1
                    return ExprValue(REG_VALUES[upper])
                self.error(f"Register '{expr}' used as value")
                return ExprValue(0)

            # An opcode name stands for its own byte (M80 manual p.2-4, so
            # `DB MOV' works), but only where the name is not a symbol: a
            # definition has to win, or a program cannot have a label called
            # ADD.  MP/M II's STAT.PLM does - it declares a PROCEDURE named
            # `add' - and `call ADD' resolving to the byte 80H turned the call
            # into `call 0080H', a call into the DMA buffer.
            #
            # On pass 1 a forward-referenced label is not in the table yet and
            # still reads as the opcode.  That is harmless: the operand is the
            # same width either way, so only the value is wrong, and pass 2
            # fixes it.  The worst case is a JR promoted to JP that need not
            # have been, which the promotion set then keeps stable.
            defined_sym = self.symbols.get(upper)
            if upper in OPCODE_VALUES and not (
                    defined_sym is not None
                    and (defined_sym.defined or defined_sym.external)):
                return ExprValue(OPCODE_VALUES[upper])

            sym = self.lookup_symbol(expr)
            if self.reading is not None:
                self.note_read(sym)
            if not (sym.defined or sym.external):
                ev = self.forward_value(sym.name)
                if ev is not None:
                    return ev
                if not allow_undefined and self.pass_num == 2:
                    self.error(f"Undefined symbol '{expr}'")
                return ExprValue(0)
            if self.pass_num == 2 and sym.defined_pass != 2:
                sym.read_early = True
            # An external, an alias of one (X EQU EXT+n), an EQU/SET whose
            # value only the linker can compute, or an address or constant.
            return self.symbol_value(sym)

        # Try as number
        val, ok = self.parse_number(expr)
        if ok:
            return ExprValue(val & 0xFFFF)

        # Try as character constant
        val, ok = self.parse_char_const(expr)
        if ok:
            return ExprValue(val & 0xFFFF)

        self.error(f"Cannot parse expression: '{expr}'")
        return ExprValue(0)

    # MAC's relational operators (--dri), longest first: at the end of `<=',
    # `<=' is found before `='.
    _DRI_RELATIONS = {'<=': 'LE', '>=': 'GE', '<>': 'NE', '=': 'EQ', '<': 'LT',
                      '>': 'GT'}

    def _high_low(self, code, inner, allow_undefined):
        """HIGH or LOW (`code') of the expression `inner'."""
        operand = self.eval_operand(inner, allow_undefined)
        value = (operand.value >> 8) & 0xFF if code == EXT_OP_HIGH \
            else operand.value & 0xFF
        return self._link_unary(code, operand, value,
                                ext=operand.ext, name=operand.name)

    def type_of(self, text):
        """TYPE of an expression that is not a name: 20H (defined) with its
        mode in the low two bits, 80H for an external, 0 if it does not
        evaluate.  M80: `TYPE 5', `TYPE 'A'' and `TYPE +2' are 20H, `TYPE
        (LAB)' 21H with LAB in CSEG; um80 gave 0 for all of them.  (TYPE
        binds tighter than + and -: `TYPE LAB+1' is (TYPE LAB)+1.)
        """
        errors = len(self.errors)
        ev = self.eval_operand(text)
        if len(self.errors) > errors:
            del self.errors[errors:]
            return 0
        if ev.kind == 'abs':
            return 0x20
        if ev.kind == 'rel':
            return 0x20 | (ev.seg & 0x03)
        if ev.kind == 'ext':
            return 0x80
        return 0

    def missing_operand(self, expr, left, right, word):
        """True, and an error in pass 2, if a binary operator has nothing on
        one side: `DW EQ' or `DW SHL', with no symbol EQ or SHL, and `* TEXT'
        (M80: O).  um80 took the missing value for 0, so `DW EQ' was 0FFFFH
        (0 EQ 0), without a word.  Pass 1 does not report it: a name defined
        further down (`DW EQ / EQ: NOP') is only a symbol from the second
        time through (names_symbol()).
        """
        if left.strip() and right.strip():
            return False
        if self.pass_num == 2:
            self.error(f"'{expr}': {word} needs a value on each side")
        return True

    @staticmethod
    def _ext_offset(value):
        """The constant beside an external, as a signed 16-bit number.

        `EXT-1' and `EXT+0FFFFH' are the same address; keeping the offset in
        -8000H..7FFFH gives them one spelling and keeps `EXT-n' negative,
        the form its external chain has always been written in.
        """
        return ((value + 0x8000) & 0xFFFF) - 0x8000

    def _add_sub(self, op, left, right):
        """left + right or left - right, as parse_expression() evaluates it."""
        if left.ext or right.ext:
            # External reference with offset.  A plain `symbol + constant'
            # travels as an external reference with the constant beside it;
            # that constant is the one the external already carries (EXT+2
            # in EXT+2+3) plus or minus the one added now.
            if left.kind == 'ext' and right.kind == 'abs':
                # SYM+n or SYM-n.
                if op == '-':
                    offset = left.value - right.value
                else:
                    offset = left.value + right.value
                return ExprValue(self._ext_offset(offset), ext=True,
                                 name=left.name)
            if op == '+' and left.kind == 'abs' and right.kind == 'ext':
                # n+SYM.
                return ExprValue(self._ext_offset(left.value + right.value),
                                 ext=True, name=right.name)
            # Anything else - n-SYM, SYM+SYM, SYM+label, HIGH(SYM)+1 - is an
            # expression for the linker (MACRO-80 writes the same ones as
            # extension link items).  The assembly-time tuple is what um80
            # has always produced: the external and the offset it could see.
            if left.ext and right.ext:
                name, offset = left.name, 0
            elif left.ext:
                name = left.name
                offset = left.value - right.value if op == '-' \
                    else left.value + right.value
            elif op == '-':
                name, offset = right.name, 0
            else:
                name, offset = right.name, left.value + right.value
            return self._link_binary(op, left, right,
                                     self._ext_offset(offset),
                                     ext=True, name=name)

        if op == '+':
            result = left.value + right.value
        else:
            result = left.value - right.value
        result &= 0xFFFF

        # Determine result segment type
        left_seg, right_seg = left.seg, right.seg
        if left_seg == right_seg and op == '-':
            result_seg = ADDR_ABSOLUTE
        elif right_seg == ADDR_ABSOLUTE:
            result_seg = left_seg
        elif left_seg == ADDR_ABSOLUTE:
            result_seg = right_seg
        else:
            result_seg = left_seg

        # The combinations a relocatable word can carry: address +/- constant,
        # constant + address, and the (absolute) distance between two
        # addresses in one segment.  Everything else - constant - address,
        # the sum of two addresses, the distance between two segments, or a
        # term that is already an expression - goes to the linker.
        # (Two COMMON blocks are placed apart, so the distance between them
        # is not a constant; M80 3.44 assembles it as one.)
        simple = (left.kind == 'abs' and right.kind == 'abs') \
            or (left.kind == 'rel' and right.kind == 'abs') \
            or (op == '+' and left.kind == 'abs' and right.kind == 'rel') \
            or (op == '-' and left.kind == 'rel' and right.kind == 'rel'
                and left_seg == right_seg and left.block == right.block)
        block = left.block if left.kind == 'rel' else right.block
        if simple:
            ev = ExprValue(result, result_seg, block=block)
            if ev.kind == 'rel':
                # An address plus or minus a constant: one relocatable word,
                # but in a link-time expression the operands as the source
                # has them (see _link_items()).
                ev.rpn = self._link_items(left) + self._link_items(right) \
                    + [(EXT_ITEM_OPERATOR, self._LINK_BINARY_OPS[op])]
            return ev
        return self._link_binary(op, left, right, result, result_seg)

    def _link_items(self, ev):
        """The postfix extension link items that compute `ev' at link time.

        An address plus or minus a constant is written as MACRO-80 3.44
        writes it, the address and the constant each an item of its own:
        `HIGH(C1+100H)' is C(common, C1) C(abs, 100H) A(+) A(HIGH).  um80
        folded the constant into the address, C(common, C1+100H), and
        LINK-80 3.44 gets a COMMON-relative value past the end of its block
        wrong.  (A symbol is one value, EQU C1+100H included, as in M80.)
        """
        if ev.kind == 'abs':
            return [(EXT_ITEM_VALUE, ADDR_ABSOLUTE, ev.value & 0xFFFF)]
        if ev.kind == 'rel':
            if ev.rpn:
                return list(ev.rpn)
            if ev.seg == ADDR_COMMON_REL:
                return [(EXT_ITEM_VALUE, ev.seg, ev.value & 0xFFFF, ev.block)]
            return [(EXT_ITEM_VALUE, ev.seg,
                     self._reloc_value(ev.value, ev.seg) & 0xFFFF)]
        if ev.kind == 'ext':
            items = [(EXT_ITEM_SYMBOL, ev.name)]
            if ev.value & 0xFFFF:
                items += [(EXT_ITEM_VALUE, ADDR_ABSOLUTE, ev.value & 0xFFFF),
                          (EXT_ITEM_OPERATOR, EXT_OP_PLUS)]
            return items
        return list(ev.rpn)

    # Binary operators LINK-80 can evaluate, by the source spelling.
    _LINK_BINARY_OPS = {'+': EXT_OP_PLUS, '-': EXT_OP_MINUS, '*': EXT_OP_MUL,
                        '/': EXT_OP_DIV, 'MOD': EXT_OP_MOD}

    def _link_binary(self, op, left, right, value, seg=ADDR_ABSOLUTE,
                     ext=False, name=None):
        """ExprValue of `left op right' whose assembly-time value is given."""
        if left.kind == 'abs' and right.kind == 'abs':
            return ExprValue(value, seg, ext, name, kind='abs')
        for side in (left, right):
            if side.kind == 'bad':
                return ExprValue(value, seg, ext, name, kind='bad',
                                 why=side.why, origin=side.origin)
        code = self._LINK_BINARY_OPS.get(op)
        if code is None:
            return ExprValue(value, seg, ext, name, kind='bad', why=op)
        return ExprValue(value, seg, ext, name, kind='expr',
                         rpn=self._link_items(left) + self._link_items(right)
                         + [(EXT_ITEM_OPERATOR, code)])

    def _link_unary(self, code, operand, value, seg=ADDR_ABSOLUTE,
                    ext=False, name=None):
        """ExprValue of a unary operator (HIGH, LOW, NOT, unary minus)."""
        if operand.kind == 'abs':
            return ExprValue(value, seg, ext, name, kind='abs')
        if operand.kind == 'bad':
            return ExprValue(value, seg, ext, name, kind='bad',
                             why=operand.why, origin=operand.origin)
        return ExprValue(value, seg, ext, name, kind='expr',
                         rpn=self._link_items(operand)
                         + [(EXT_ITEM_OPERATOR, code)])

    def _reloc_value(self, value, seg_type):
        """A relocatable value as the .REL file carries it (see emit_word)."""
        if seg_type == ADDR_PROGRAM_REL and self.segments['CSEG'].org_set:
            return value - self.segments['CSEG'].org
        if seg_type == ADDR_DATA_REL and self.segments['DSEG'].org_set:
            return value - self.segments['DSEG'].org
        return value

    def is_operation(self, word):
        """True if `word' is a macro, a directive or an instruction of the
        processor being assembled for (so `HALT' is one after .Z80 only)."""
        word = word.upper()
        return (word in self.macros or word in DIRECTIVES
                or word in (INSTRUCTIONS_Z80 if self.z80_mode
                            else INSTRUCTIONS_8080))

    def parse_line(self, line, brackets=False):
        """Parse a source line, return (label, operator, operands, comment).

        In the arguments of a macro call and the list of an IRP or IRPC a
        `;' inside <...> is text, not a comment, as in MACRO-80, MAC and
        RMAC: DRI's CONTROL/DISKDEF.LIB passes `<;sec per track>' to a
        macro that puts it after a DW.  Such a line is read again with
        `brackets'.
        """
        whole = line
        # Remove comment
        comment = ''
        in_string = False
        string_char = None
        depth = 0
        for i, ch in enumerate(line):
            if in_string:
                if ch == string_char:
                    in_string = False
            elif ch in "'\"":
                # Don't treat ' as string start if preceded by alphanumeric
                # (handles Z80 AF' register)
                if ch == "'" and i > 0 and line[i-1].isalnum():
                    pass  # Not a string start
                else:
                    in_string = True
                    string_char = ch
            elif brackets and ch in '<>':
                depth = depth + 1 if ch == '<' else max(depth - 1, 0)
            elif ch == ';' and not depth:
                comment = line[i+1:]
                line = line[:i]
                break

        line = line.rstrip()
        if not line:
            return (None, None, None, comment)

        # The label, if any.  A name with a colon after it is one, in any
        # column.  So is the name of an EQU, SET, DEFL, ASET or MACRO in
        # front of its directive: MACRO-80, MAC and RMAC all take
        # `<TAB>FOO<TAB>EQU 5', even where FOO is also an instruction or a
        # macro (MP/M II's MPMLDR/LDRBDOS.ASM has `<TAB>arech  equ b!
        # arecl  equ c').
        #
        # A name with no colon is not a label in MACRO-80 3.44, in column 1
        # or not: the first word of a statement is its operation, and a word
        # that is no instruction, directive or macro starts a list of values
        # M80 assembles as DB (`FOO NOP' is U, `FOO' after `FOO EQU 5' is the
        # byte 05; see _process_single_statement()).  um80 took a word in
        # column 1 for a label even when it was an instruction or a
        # directive, so `NOP', `RET', `END' and `DB 7' there assembled
        # nothing, without a word.  MAC and RMAC (--dri) take a word that
        # is not an instruction, directive or macro for a label, colon or
        # not, in any column; they ignore a line number in front of a
        # statement, a line whose first character is `*', and MAC's
        # assembly controls ($-MACRO, $+PRINT).
        label = None
        stripped = line.lstrip()
        if self.dri:
            if stripped.startswith('*') or DRI_CONTROL.match(stripped):
                return (None, None, None, comment)
            number = LINE_NUMBER.match(stripped)
            if number:
                stripped = line = stripped[number.end():]
                if not line:
                    return (None, None, None, comment)
        elif line[:6].upper() == '*EJECT':
            # MACRO-80's page eject, in column 1 only.
            return (None, '*EJECT', line[6:].strip(), comment)
        match = re.match(r'^([$A-Za-z_@?][A-Za-z0-9_@?$.]*)(::|:)\s*', stripped)
        if match:
            label = match.group(1)
            colons = match.group(2)
            stripped = stripped[match.end():]
            line = stripped  # Continue with remainder
            if colons == '::':
                sym = self.lookup_symbol(label)
                sym.public = True
                sym.public_line = sym.public_line or self.line_num
        else:
            match = NAME_DEFINITION.match(stripped)
            if match:
                label = match.group(1)
                line = stripped[match.end(1):]
            elif self.dri:
                match = NAME_WORD.match(stripped)
                if (match and match.group(1) != '$'
                        and not self.is_operation(match.group(1))):
                    label = match.group(1)
                    line = stripped[match.end():]

        if not line.strip():
            return (label, None, None, comment)

        # Parse operator
        line = line.strip()
        match = re.match(r'^([$A-Za-z_@?.][A-Za-z0-9_@?$.]*)\s*', line)
        if not match:
            return (label, None, line, comment)

        operator = match.group(1).upper()
        operands = line[match.end():].strip()

        if (comment and not brackets and '<' in operands
                and (operator in self.macros or operator in ('IRP', 'IRPC'))):
            return self.parse_line(whole, brackets=True)
        return (label, operator, operands, comment)

    def split_operands(self, operands, escape_bang=False, angles=True):
        """Split operands by comma, respecting strings, parentheses, and angle brackets.

        With `angles' false a < or > is not a bracket but an operator, as
        MAC's relational ones are with --dri: `DW 1<2,3' is two values.

        When escape_bang is True (macro argument lists), '!' quotes the
        following character so an escaped comma/bracket is not treated as a
        delimiter (M80 macro syntax). The '!' is retained in the returned
        argument for process_macro_argument() to consume (issue #3).
        """
        if not operands:
            return []

        result = []
        current = ''
        paren_depth = 0
        angle_depth = 0
        in_string = False
        string_char = None

        i = 0
        n = len(operands)
        while i < n:
            ch = operands[i]
            if escape_bang and ch == '!' and not in_string and i + 1 < n:
                # '!' quotes the next character in a macro argument list
                current += ch + operands[i + 1]
                i += 2
                continue
            if in_string:
                current += ch
                if ch == string_char:
                    in_string = False
            elif ch in "'\"":
                # Don't treat ' as string start if preceded by alphanumeric
                # (handles Z80 AF' register)
                if ch == "'" and current and current[-1].isalnum():
                    current += ch  # Just add it, not a string start
                else:
                    in_string = True
                    string_char = ch
                    current += ch
            elif ch == '(':
                paren_depth += 1
                current += ch
            elif ch == ')':
                paren_depth -= 1
                current += ch
            elif ch == '<' and angles:
                angle_depth += 1
                current += ch
            elif ch == '>' and angles:
                angle_depth -= 1
                current += ch
            elif ch == ',' and paren_depth == 0 and angle_depth == 0:
                result.append(current.strip())
                current = ''
            else:
                current += ch
            i += 1

        if current.strip():
            result.append(current.strip())

        return result

    def split_on_exclamation(self, line):
        """
        DRI extension: Split a line on '!' separator, respecting strings.
        Returns list of statement strings. Each statement after the first
        should be treated as having no label.
        Example: "PUSH H! PUSH D! PUSH B" -> ["PUSH H", " PUSH D", " PUSH B"]
        """
        # First, find the comment (if any) and separate it
        comment = ''
        in_string = False
        string_char = None
        comment_pos = -1
        for i, ch in enumerate(line):
            if in_string:
                if ch == string_char:
                    in_string = False
            elif ch in "'\"":
                in_string = True
                string_char = ch
            elif ch == ';':
                comment = line[i:]  # Include the semicolon
                comment_pos = i
                break

        if comment_pos >= 0:
            line = line[:comment_pos]

        # Now split on '!' while respecting strings
        result = []
        current = ''
        in_string = False
        string_char = None

        for ch in line:
            if in_string:
                current += ch
                if ch == string_char:
                    in_string = False
            elif ch in "'\"":
                in_string = True
                string_char = ch
                current += ch
            elif ch == '!':
                result.append(current)
                current = ''
            else:
                current += ch

        # Add the last segment
        result.append(current)

        # Append comment to the last segment
        if comment and result:
            result[-1] = result[-1] + comment

        return result

    def select_common(self, block):
        """Make `block' the COMMON block the .REL's COMMON items refer to.

        A COMMON-relative word, extension value, set-location, public or
        chain head is relative to the block selected last (special item 1),
        as MACRO-80 writes them.  um80 selected a block only at the COMMON
        directive, so every COMMON-relative value was relative to whichever
        block came last.
        """
        if self.pass_num == 2 and block is not None and block != self.rel_common:
            self.output.write_select_common(block if block else ' ')
            self.rel_common = block

    def select_for_load(self):
        """Before loading into a COMMON block, make it the selected one again.

        A reference to another block selects that one.  LINK-80 goes on
        loading into the block selected at the last set-location, so this
        is not needed for the load (M80 does not select back), but it
        keeps the selection and the load in step.
        """
        if (self.pass_num == 2 and self.current_common is not None
                and self.rel_common != self.current_common):
            self.select_common(self.current_common)
            self.output.write_set_location(ADDR_COMMON_REL, self.loc)

    # How the listing marks a field the linker has yet to finish, as
    # MACRO-80's listing does: after the field, the kind of value in it.
    LIST_MARKS = {ADDR_PROGRAM_REL: "'", ADDR_DATA_REL: '"',
                  ADDR_COMMON_REL: '!'}
    LIST_MARK_EXTERNAL = '*'

    def list_field(self, values, mark=None):
        """Add the bytes of one field to the listing line, then its mark."""
        if self.pass_num == 2 and self.generate_listing:
            self.current_line_bytes.extend(v & 0xFF for v in values)
            if mark:
                self.current_line_marks[len(self.current_line_bytes) - 1] = mark

    def link_mark(self, ev):
        """The listing mark of a field the linker computes from `ev'.

        `*' if it uses an external, as M80 marks one; otherwise the mark of
        the segment of the first relocatable value in it.
        """
        items = self._link_items(ev)
        if any(item[0] == EXT_ITEM_SYMBOL for item in items):
            return self.LIST_MARK_EXTERNAL
        for item in items:
            if item[0] == EXT_ITEM_VALUE and item[1] != ADDR_ABSOLUTE:
                return self.LIST_MARKS[item[1]]
        return None

    def emit_byte(self, value):
        """Emit a byte to current segment."""
        if self.pass_num == 2:
            self.select_for_load()
            self.output.write_absolute_byte(value & 0xFF)
            self.list_field([value])
        self.loc += 1

    def emit_word(self, value, seg_type=ADDR_ABSOLUTE, block=None, ev=None,
                  mark=None):
        """Emit a 16-bit word to current segment (`ev': the operand it is).

        The listing shows it with `mark', or the mark of its segment.
        """
        if (seg_type == ADDR_COMMON_REL and self.current_common is not None
                and block is not None and block != self.current_common):
            # An address in another COMMON block, from inside this one:
            # selecting that block would also move the loading there, so it
            # is a link-time expression with this block selected again
            # before the store.
            self.emit_link_expr(ev if ev is not None
                                else ExprValue(value, seg_type, block=block), 2)
            return
        if self.pass_num == 2:
            self.select_for_load()
            if seg_type == ADDR_ABSOLUTE:
                self.output.write_absolute_byte(value & 0xFF)
                self.output.write_absolute_byte((value >> 8) & 0xFF)
            elif seg_type == ADDR_PROGRAM_REL:
                # Subtract segment ORG so linker can relocate properly
                rel_value = value
                if self.segments['CSEG'].org_set:
                    rel_value -= self.segments['CSEG'].org
                self.output.write_program_relative(rel_value)
            elif seg_type == ADDR_DATA_REL:
                # Subtract segment ORG so linker can relocate properly
                rel_value = value
                if self.segments['DSEG'].org_set:
                    rel_value -= self.segments['DSEG'].org
                self.output.write_data_relative(rel_value)
            elif seg_type == ADDR_COMMON_REL:
                self.select_common(block)
                self.output.write_common_relative(value)
            self.list_field([value, value >> 8],
                            mark or self.LIST_MARKS.get(seg_type))
        self.loc += 2

    def emit_link_expr(self, ev, size):
        """Emit a 1- or 2-byte field whose value the linker computes.

        The expression goes out as extension link items ending in a store
        operator, followed by the field itself as zero placeholder bytes -
        the order MACRO-80 3.44 uses and LINK-80 3.44 expects: the store
        writes at the location counter it finds, which is where the
        placeholder then loads.  See relformat.py.
        """
        if self.pass_num == 2:
            out = self.output
            for item in self._link_items(ev):
                if item[0] == EXT_ITEM_VALUE:
                    if item[1] == ADDR_COMMON_REL:
                        self.select_common(item[3])
                    out.write_ext_value(item[1], item[2])
                elif item[0] == EXT_ITEM_SYMBOL:
                    out.write_ext_symbol(item[1])
                else:
                    out.write_ext_operator(item[1])
            # The store writes where the loader is, in this block.
            self.select_for_load()
            out.write_ext_operator(EXT_OP_STORE_BYTE if size == 1
                                   else EXT_OP_STORE_WORD)
            for _ in range(size):
                out.write_absolute_byte(0)
            # The listing shows the placeholder, as the .REL has it: the
            # value computed from segment offsets (`MVI A,HIGH(BUF)' listed
            # 3E 03 for BUF at DSEG 0300H) is not in the program.
            self.list_field([0] * size, self.link_mark(ev))
        self.loc += size

    def report_unlinkable(self, ev):
        """Error for an operand that uses an operator LINK-80 does not have.

        M80 flags the same operands 'R' (relocation error).  Assembling the
        operator's assembly-time result instead would bake the value's
        offset within its segment into the program, which is right only if
        the linker happens to put the segment at 0.  When the value came
        through an EQU or SET, the error is reported once, at that
        definition (where M80 flags it), naming the line that used it.
        """
        if self.pass_num != 2 or not ev.why:
            return
        why = (f"{ev.why} cannot be applied to a relocatable or external "
               f"value: LINK-80 has no {ev.why} operator, so the linker could "
               f"not compute the result")
        if ev.origin is None:
            self.error(why)
            return
        name, line = ev.origin
        if name in self.reported_unlinkable:
            return
        self.reported_unlinkable.add(name)
        self.errors.append(AssemblerError(
            f"{name}, used at line {self.line_num}: {why}", line))

    def number_operand(self, text, directive, allow_undefined=False):
        """Evaluate the operand of a directive that needs a number now.

        ORG, DS, IF, REPT, RST, ... use the value while assembling, so it
        cannot be one only the linker knows: an external, HIGH/LOW or any
        other link-time expression of a relocatable value, or AND/OR/... of
        one.  The assembly-time value of those is computed from segment
        offsets and was silently used (`DS 100H-LOW($)' aligned to the
        segment, not to the address); M80 flags them 'R'.  A relocatable
        address is still taken as its offset, as before.  Reported in pass
        2; the ExprValue is returned either way.
        """
        ev = self.eval_operand(text, allow_undefined)
        if ev.kind not in ('abs', 'rel') and self.pass_num == 2:
            self.error(f"{directive} needs a value the assembler knows, but "
                       f"'{text.strip()}' {self.link_time_reason(ev)}")
        return ev

    @staticmethod
    def link_time_reason(ev):
        """Why `ev' has no value at assembly time, for a message."""
        if ev.kind == 'ext':
            return f"is the external symbol {ev.name}" + (
                f"{ev.value:+d}" if ev.value else '')
        if ev.kind == 'bad':
            how = f"applies {ev.why} to a relocatable or external value"
            if ev.origin:
                how += f" (in {ev.origin[0]}, line {ev.origin[1]})"
            return how
        if any(item[0] == EXT_ITEM_SYMBOL for item in ev.rpn or ()):
            return "depends on an external symbol"
        return "depends on where the linker puts a segment"

    def emit_word_operand(self, ev):
        """Emit a 16-bit operand (address of JMP/CALL/LXI, DW, ...)."""
        if ev.kind in ('abs', 'rel'):
            self.emit_word(ev.value, ev.seg, ev.block, ev)
        elif ev.kind == 'ext':
            self.emit_external_ref(ev.name, ev.value)
        elif ev.kind == 'expr':
            self.emit_link_expr(ev, 2)
        else:
            self.report_unlinkable(ev)
            self.emit_word(ev.value)

    def emit_code(self, code, fields=None):
        """Emit instruction bytes.

        `fields' maps the index of a byte in `code' to the ExprValue that
        byte holds (an immediate or an index displacement).  An absolute
        value is emitted as the encoder produced it; any other value is a
        one-byte field for the linker to fill, as MACRO-80 does - the
        encoder's byte would be the low byte of an offset, not of the
        address.
        """
        for i, b in enumerate(code):
            ev = fields.get(i) if fields else None
            if ev is None or ev.kind == 'abs':
                self.emit_byte(b)
            elif ev.kind == 'bad':
                self.report_unlinkable(ev)
                self.emit_byte(b)
            else:
                self.emit_link_expr(ev, 1)

    def emit_external_ref(self, name, offset=0):
        """Emit a word that is an external symbol plus a constant.

        As MACRO-80 writes it: a nonzero constant as special item 9
        (External plus offset - the linker adds it to the word at this
        location once the external is known; EXT-1 is FFFFH), then the word,
        which the linker fills from the external's chain.  (um80 used to put
        the constant in the chain's name, "EXT+3", which LINK-80 takes for
        an undefined symbol.)  Each reference gets a chain record of its own
        and holds absolute 0, a chain of one: linking references through
        the words would make one at offset 0 of a segment read as the end.

        LINK-80 takes a chain head of absolute 0 for an empty chain, so a
        reference AT absolute address 0 cannot be in one; it goes out as an
        extension link item instead.
        """
        name = name.upper()
        offset = self._ext_offset(offset)
        if self.seg_type == ADDR_ABSOLUTE and self.loc == 0:
            self.emit_link_expr(ExprValue(offset, ext=True, name=name), 2)
            return
        if self.pass_num == 2:
            self.select_for_load()
            if offset:
                self.output.write_external_plus_offset(ADDR_ABSOLUTE,
                                                       offset & 0xFFFF)
            self.ext_chains.setdefault(name, []).append(
                (self.seg_type, self.loc, self.current_common))
        self.emit_word(0, mark=self.LIST_MARK_EXTERNAL)

    def register_value(self, text):
        """The value of a register operand of an 8080 instruction, or None.

        MACRO-80 and DRI's MAC read a register operand as an expression in
        which each register name stands for its number (REG_VALUES): `RD EQU
        D' makes RD 2, and `MOV A,2', `DAD RD' and `PUSH PSW+0' are MOV A,D,
        DAD D and PUSH PSW.  None if the operand cannot be read, or is a
        symbol the pass cannot read yet (the caller reports it).

        An address is read as M80 reads it: a relocatable value is its
        offset in its segment, an external its constant.  `DAD LAB', LAB two
        bytes into the code, is DAD D, and `MOV A,Y' with Y EXTRN is MOV
        A,B.  M80 flags nothing, RMAC flags it V, and um80 warns; um80 0.3.50
        took a relocatable label's offset too.  Anything else computed from
        an address (`HIGH LAB', `LAB-Y') is None, as it was in 0.3.50.
        """
        name = text.strip().upper()
        self.register_number = None
        if name in REG_VALUES and not self.names_symbol(name):
            self.register_number = REG_VALUES[name]
            return self.register_number
        errors = len(self.errors)
        self.register_operand = True
        try:
            ev = self.eval_operand(text)
        finally:
            self.register_operand = False
        if len(self.errors) > errors:
            del self.errors[errors:]
            return None
        if ev.kind not in ('abs', 'rel', 'ext'):
            return None
        if ev.kind != 'abs' and self.pass_num == 2 and 0 <= ev.value <= 7:
            what = 'an external' if ev.kind == 'ext' else 'an address'
            self.warning(f"register operand '{text.strip()}' is {what}: its offset,"
                         f" {ev.value}, is taken for the register, as in M80 (RMAC: V)")
        self.register_number = ev.value
        return ev.value

    def resolve_register_alias(self, name):
        """The register (B, C, D, E, H, L, M or A) an operand names, or None.

        The operand is a register name or an expression whose value is the
        register's number, 0 to 7 (register_value()).
        """
        if name.strip().upper() in REGS and not self.names_symbol(name.strip()):
            return name.strip().upper()
        val = self.register_value(name)
        for reg, num in REGS.items():
            if num == val:
                return reg
        return None

    def resolve_regpair_alias(self, name, regpair_dict):
        """The register pair in `regpair_dict' an operand names, or None.

        A pair name in the table stands for itself.  Anything else is an
        expression whose value is the number of the pair's first register
        (register_value()): 0 B, 2 D, 4 H, and 6 SP or PSW, whichever the
        instruction takes.  `RD EQU D' then `DAD RD' is DAD D (19H); um80
        took the 2 for the pair encoding, H, and assembled DAD H (29H).
        An odd number is not a pair: M80 flags `DAD 1' or `DAD E' A, and
        MAC flags it R.
        """
        upper = name.strip().upper()
        if upper in regpair_dict and not self.names_symbol(upper):
            return upper
        val = self.register_value(name)
        if val is None or val & 1 or not 0 <= val <= 6:
            return None
        for rp in ({0: ('B',), 2: ('D',), 4: ('H',), 6: ('SP', 'PSW')}[val]):
            if rp in regpair_dict:
                return rp
        return None

    def assemble_instruction(self, operator, operands):
        """Assemble a CPU instruction."""
        operator = operator.upper()
        ops = self.split_operands(operands, angles=not self.dri) if operands else []

        # No-operand instructions
        if operator in NO_OPERAND:
            if ops:
                self.error_no_operand(operator, ops)
                return True
            code = encode_no_operand(operator)
            for b in code:
                self.emit_byte(b)
            return True

        # Conditional returns
        if operator in COND_RETS:
            if ops:
                self.error_no_operand(operator, ops)
                return True
            cond = get_cond_from_mnemonic(operator)
            code = encode_cond_ret(cond)
            for b in code:
                self.emit_byte(b)
            return True

        # MOV dst, src
        if operator == 'MOV':
            if len(ops) != 2:
                self.error("MOV requires two operands")
                return True
            dst = self.resolve_register_alias(ops[0])
            src = self.resolve_register_alias(ops[1])
            if dst is None or src is None:
                self.error(f"Invalid register for MOV: {ops[0]}, {ops[1]}")
                return True
            if dst == 'M' and src == 'M':
                self.error("MOV M,M is invalid (HLT)")
                return True
            code = encode_mov(dst, src)
            for b in code:
                self.emit_byte(b)
            return True

        # MVI reg, imm8
        if operator == 'MVI':
            if len(ops) != 2:
                self.error("MVI requires two operands")
                return True
            reg = self.resolve_register_alias(ops[0])
            if reg is None:
                self.error(f"Invalid register for MVI: {ops[0]}")
                return True
            ev = self.eval_operand(ops[1])
            self.emit_code(encode_mvi(reg, ev.value), {1: ev})
            return True

        # LXI rp, imm16
        if operator == 'LXI':
            if len(ops) != 2:
                self.error("LXI requires two operands")
                return True
            rp = self.resolve_regpair_alias(ops[0], REGPAIRS)
            if rp is None:
                self.error(f"Invalid register pair for LXI: {ops[0]}")
                return True
            # Parse expression BEFORE emit so $ evaluates to instruction start
            ev = self.eval_operand(ops[1])
            self.emit_byte(LXI_BASE | (REGPAIRS[rp] << 4))
            self.emit_word_operand(ev)
            return True

        # INR/DCR reg
        if operator in ('INR', 'DCR'):
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            reg = self.resolve_register_alias(ops[0])
            if reg is None:
                self.error(f"Invalid register for {operator}: {ops[0]}")
                return True
            if operator == 'INR':
                code = encode_inr(reg)
            else:
                code = encode_dcr(reg)
            for b in code:
                self.emit_byte(b)
            return True

        # INX/DCX/DAD rp
        if operator in ('INX', 'DCX', 'DAD'):
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            rp = self.resolve_regpair_alias(ops[0], REGPAIRS)
            if rp is None:
                self.error(f"Invalid register pair for {operator}: {ops[0]}")
                return True
            if operator == 'INX':
                code = encode_inx(rp)
            elif operator == 'DCX':
                code = encode_dcx(rp)
            else:
                code = encode_dad(rp)
            for b in code:
                self.emit_byte(b)
            return True

        # LDAX/STAX rp (B or D only)
        if operator in ('LDAX', 'STAX'):
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            rp = self.resolve_regpair_alias(ops[0], REGPAIRS_LDAX)
            if rp is None:
                self.error(f"Invalid register pair for {operator}: {ops[0]} (must be B or D)")
                return True
            if operator == 'LDAX':
                code = encode_ldax(rp)
            else:
                code = encode_stax(rp)
            for b in code:
                self.emit_byte(b)
            return True

        # PUSH/POP rp
        if operator in ('PUSH', 'POP'):
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            rp = self.resolve_regpair_alias(ops[0], REGPAIRS_PUSHPOP)
            if rp is None and self.register_number == 7:
                # PUSH A, POP A, PUSH 7: MAC and RMAC take it for PSW.  M80
                # flags it A (and pushes PSW).
                if not self.dri:
                    self.error(f"{operator} {ops[0].strip()}: A (7) is not a register"
                               f" pair (M80: A; MAC takes it for PSW: --dri)")
                    return True
                rp = 'PSW'
            if rp is None:
                self.error(f"Invalid register pair for {operator}: {ops[0]}")
                return True
            if operator == 'PUSH':
                code = encode_push(rp)
            else:
                code = encode_pop(rp)
            for b in code:
                self.emit_byte(b)
            return True

        # ALU with register (ADD, ADC, SUB, SBB, ANA, XRA, ORA, CMP)
        if operator in ALU_REG:
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            reg = self.resolve_register_alias(ops[0])
            if reg is None:
                self.error(f"Invalid register for {operator}: {ops[0]}")
                return True
            code = encode_alu_reg(operator, reg)
            for b in code:
                self.emit_byte(b)
            return True

        # ALU immediate (ADI, ACI, SUI, SBI, ANI, XRI, ORI, CPI)
        if operator in ALU_IMM:
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            ev = self.eval_operand(ops[0])
            self.emit_code(encode_alu_imm(operator, ev.value), {1: ev})
            return True

        # JMP addr
        if operator == 'JMP':
            if len(ops) != 1:
                self.error("JMP requires one operand")
                return True
            # Parse expression BEFORE emit so $ evaluates to instruction start
            ev = self.eval_operand(ops[0])
            self.emit_byte(JMP)
            self.emit_word_operand(ev)
            return True

        # Conditional jumps
        if operator in COND_JUMPS:
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            cond = get_cond_from_mnemonic(operator)
            # Parse expression BEFORE emit so $ evaluates to instruction start
            ev = self.eval_operand(ops[0])
            self.emit_byte(COND_JMP_BASE | (CONDITIONS[cond] << 3))
            self.emit_word_operand(ev)
            return True

        # CALL addr
        if operator == 'CALL':
            if len(ops) != 1:
                self.error("CALL requires one operand")
                return True
            # Parse expression BEFORE emit so $ evaluates to instruction start
            ev = self.eval_operand(ops[0])
            self.emit_byte(CALL)
            self.emit_word_operand(ev)
            return True

        # Conditional calls
        if operator in COND_CALLS:
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            cond = get_cond_from_mnemonic(operator)
            # Parse expression BEFORE emit so $ evaluates to instruction start
            ev = self.eval_operand(ops[0])
            self.emit_byte(COND_CALL_BASE | (CONDITIONS[cond] << 3))
            self.emit_word_operand(ev)
            return True

        # RST n
        if operator == 'RST':
            if len(ops) != 1:
                self.error("RST requires one operand")
                return True
            val = self.number_operand(ops[0], 'RST').value
            if val > 7:
                self.error("RST operand must be 0-7")
                return True
            code = encode_rst(val)
            for b in code:
                self.emit_byte(b)
            return True

        # LDA/STA/LHLD/SHLD addr
        if operator in ('LDA', 'STA', 'LHLD', 'SHLD'):
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            # Parse expression BEFORE emit so $ evaluates to instruction start
            ev = self.eval_operand(ops[0])
            if operator == 'LDA':
                self.emit_byte(LDA)
            elif operator == 'STA':
                self.emit_byte(STA)
            elif operator == 'LHLD':
                self.emit_byte(LHLD)
            else:
                self.emit_byte(SHLD)
            self.emit_word_operand(ev)
            return True

        # IN/OUT port
        if operator in ('IN', 'OUT'):
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            ev = self.eval_operand(ops[0])
            if operator == 'IN':
                code = encode_in(ev.value)
            else:
                code = encode_out(ev.value)
            self.emit_code(code, {1: ev})
            return True

        return False  # Not a CPU instruction

    def relative_target(self, text, operator):
        """(value, seg, reachable) of a JR/DJNZ target; in pass 2, refuse
        one it cannot reach.

        The displacement is target - (here + 2), so both must be in the
        same segment - which then moves as one - and known now.  LINK-80 has
        no PC-relative operator.  An external or link-time target (`JR EXT'
        came out 18 FE, a jump to itself, or promoted to JP 0000H with the
        external dropped), an address in another segment (`JR DLAB' from
        CSEG), or an absolute address from relocatable code or the other way
        round, is an error, as in M80 (E for an external, R otherwise).
        `reachable' is False for these, so pass 1 does not promote the
        jump to JP for being far from a target it read as 0 (the error
        came with a "promoted to JP" note).
        """
        ev = self.eval_operand(text)
        reachable = ev.kind in ('abs', 'rel') and ev.seg == self.pc_seg
        if self.pass_num == 2:
            if ev.kind not in ('abs', 'rel'):
                self.error(f"{operator} to '{text.strip()}': its target "
                           f"{self.link_time_reason(ev)}, and a relative "
                           f"jump needs the distance now")
            elif ev.seg != self.pc_seg:
                if ev.seg == ADDR_ABSOLUTE:
                    what = "an absolute address, but this code is relocatable"
                elif self.pc_seg == ADDR_ABSOLUTE:
                    what = "a relocatable address, but this code is absolute"
                else:
                    what = "an address in another segment"
                self.error(f"{operator} to '{text.strip()}': {what}, so the "
                           f"distance depends on where the linker puts them")
        return ev.value & 0xFFFF, ev.seg, reachable

    def parse_z80_indexed(self, operand):
        """Parse (IX+d) or (IY+d) operand.

        Returns (reg, displacement, ev) or None, where ev is the ExprValue
        of the displacement (None when there is none) for emit_code().
        """
        operand = operand.strip()
        if not operand.startswith('(') or not operand.endswith(')'):
            return None
        inner = operand[1:-1].strip().upper()
        for reg in ('IX', 'IY'):
            if inner.startswith(reg):
                rest = inner[2:].strip()
                if not rest:
                    return (reg, 0, None)
                if rest.startswith('+'):
                    ev = self.eval_operand(rest[1:])
                    return (reg, ev.value & 0xFF, ev)
                if rest.startswith('-'):
                    ev = self.eval_operand(rest)
                    return (reg, ev.value & 0xFF, ev)
                return None
        return None

    def assemble_z80_instruction(self, operator, operands):
        """Assemble a Z80 CPU instruction."""
        operator = operator.upper()
        ops = self.split_operands(operands, angles=not self.dri) if operands else []

        # No-operand instructions
        if operator in Z80_NO_OPERAND:
            if ops:
                self.error_no_operand(operator, ops)
                return True
            self.emit_byte(Z80_NO_OPERAND[operator])
            return True

        # ED-prefix no-operand instructions
        if operator in Z80_ED_NO_OPERAND:
            if ops:
                self.error_no_operand(operator, ops)
                return True
            self.emit_byte(PREFIX_ED)
            self.emit_byte(Z80_ED_NO_OPERAND[operator])
            return True

        # EX instructions
        if operator == 'EX':
            if len(ops) != 2:
                self.error("EX requires two operands")
                return True
            op1, op2 = ops[0].upper().strip(), ops[1].upper().strip()
            if op1 == 'DE' and op2 == 'HL':
                self.emit_byte(0xEB)
                return True
            if op1 == 'AF' and op2 == "AF'":
                self.emit_byte(0x08)
                return True
            if op1 == '(SP)' and op2 == 'HL':
                self.emit_byte(0xE3)
                return True
            if op1 == '(SP)' and op2 == 'IX':
                self.emit_byte(PREFIX_DD)
                self.emit_byte(0xE3)
                return True
            if op1 == '(SP)' and op2 == 'IY':
                self.emit_byte(PREFIX_FD)
                self.emit_byte(0xE3)
                return True
            self.error(f"Invalid operands for EX: {op1},{op2}")
            return True

        # LD - the most complex instruction
        if operator == 'LD':
            if len(ops) != 2:
                self.error("LD requires two operands")
                return True
            dst, src = ops[0].strip(), ops[1].strip()
            dst_upper = dst.upper()
            src_upper = src.upper()

            # LD r,r' or LD r,(HL)
            if dst_upper in Z80_REGS_M and src_upper in Z80_REGS_M:
                if dst_upper == '(HL)' and src_upper == '(HL)':
                    self.error("LD (HL),(HL) is invalid")
                    return True
                for b in encode_z80_ld_r_r(dst, src):
                    self.emit_byte(b)
                return True

            # LD A,I and LD A,R (load from interrupt/refresh register). Must
            # precede the generic 'LD r,n' immediate path below, which would
            # otherwise treat the bare I/R as an undefined symbol and wrongly
            # emit LD A,0 (3E 00).
            if dst_upper == 'A' and src_upper in ('I', 'R'):
                self.emit_byte(PREFIX_ED)
                self.emit_byte(0x57 if src_upper == 'I' else 0x5F)
                return True

            # LD r,n (immediate byte) - but NOT if src is (nn) memory access
            if dst_upper in Z80_REGS_M and src_upper not in Z80_REGS_M:
                # Check for indexed addressing first
                indexed = self.parse_z80_indexed(src)
                if indexed:
                    # LD r,(IX+d) or LD r,(IY+d)
                    reg, disp, dev = indexed
                    if reg == 'IX':
                        code = encode_z80_ld_r_ixd(dst, disp)
                    else:
                        code = encode_z80_ld_r_iyd(dst, disp)
                    self.emit_code(code, {2: dev})
                    return True
                # If src is (expr), this might be LD A,(nn) - handle below
                if src.startswith('(') and src.endswith(')'):
                    # Fall through to LD A,(nn) / LD (nn),A handling
                    pass
                else:
                    # LD r,n (immediate byte)
                    ev = self.eval_operand(src)
                    self.emit_code(encode_z80_ld_r_n(dst, ev.value), {1: ev})
                    return True

            # LD (IX+d),r or LD (IY+d),r or LD (IX+d),n or LD (IY+d),n
            indexed = self.parse_z80_indexed(dst)
            if indexed:
                reg, disp, dev = indexed
                if src_upper in Z80_REGS and src_upper != '(HL)':
                    if reg == 'IX':
                        code = encode_z80_ld_ixd_r(disp, src)
                    else:
                        code = encode_z80_ld_iyd_r(disp, src)
                    self.emit_code(code, {2: dev})
                else:
                    ev = self.eval_operand(src)
                    if reg == 'IX':
                        code = encode_z80_ld_ixd_n(disp, ev.value)
                    else:
                        code = encode_z80_ld_iyd_n(disp, ev.value)
                    self.emit_code(code, {2: dev, 3: ev})
                return True

            # LD A,(BC) / LD A,(DE) / LD A,(nn)
            if dst_upper == 'A':
                if src_upper == '(BC)':
                    self.emit_byte(0x0A)
                    return True
                if src_upper == '(DE)':
                    self.emit_byte(0x1A)
                    return True
                if src_upper == 'I':
                    self.emit_byte(PREFIX_ED)
                    self.emit_byte(0x57)
                    return True
                if src_upper == 'R':
                    self.emit_byte(PREFIX_ED)
                    self.emit_byte(0x5F)
                    return True
                if src.startswith('(') and src.endswith(')'):
                    ev = self.eval_operand(src[1:-1])
                    self.emit_byte(0x3A)  # LD A,(nn) opcode
                    self.emit_word_operand(ev)
                    return True

            # LD (BC),A / LD (DE),A / LD (nn),A
            if src_upper == 'A':
                if dst_upper == '(BC)':
                    self.emit_byte(0x02)
                    return True
                if dst_upper == '(DE)':
                    self.emit_byte(0x12)
                    return True
                if dst.startswith('(') and dst.endswith(')'):
                    ev = self.eval_operand(dst[1:-1])
                    self.emit_byte(0x32)  # LD (nn),A opcode
                    self.emit_word_operand(ev)
                    return True

            # LD I,A / LD R,A
            if dst_upper == 'I' and src_upper == 'A':
                self.emit_byte(PREFIX_ED)
                self.emit_byte(0x47)
                return True
            if dst_upper == 'R' and src_upper == 'A':
                self.emit_byte(PREFIX_ED)
                self.emit_byte(0x4F)
                return True

            # LD SP,HL / LD SP,IX / LD SP,IY (must check before LD dd,nn)
            if dst_upper == 'SP':
                if src_upper == 'HL':
                    self.emit_byte(0xF9)
                    return True
                if src_upper == 'IX':
                    self.emit_byte(PREFIX_DD)
                    self.emit_byte(0xF9)
                    return True
                if src_upper == 'IY':
                    self.emit_byte(PREFIX_FD)
                    self.emit_byte(0xF9)
                    return True

            # LD dd,nn (16-bit immediate)
            if dst_upper in Z80_PAIRS_BC_DE_HL_SP:
                if src.startswith('(') and src.endswith(')'):
                    # LD dd,(nn)
                    ev = self.eval_operand(src[1:-1])
                    if dst_upper == 'HL':
                        self.emit_byte(0x2A)  # LD HL,(nn) opcode
                    else:
                        # BC=0x4B, DE=0x5B, SP=0x7B
                        dd_opcodes = {'BC': 0x4B, 'DE': 0x5B, 'SP': 0x7B}
                        self.emit_byte(PREFIX_ED)
                        self.emit_byte(dd_opcodes[dst_upper])
                    self.emit_word_operand(ev)
                else:
                    ev = self.eval_operand(src)
                    self.emit_byte(0x01 | (Z80_PAIRS_BC_DE_HL_SP[dst_upper] << 4))
                    self.emit_word_operand(ev)
                return True

            # LD IX,nn / LD IY,nn
            if dst_upper == 'IX':
                if src.startswith('(') and src.endswith(')'):
                    ev = self.eval_operand(src[1:-1])
                    self.emit_byte(PREFIX_DD)
                    self.emit_byte(0x2A)  # LD IX,(nn)
                    self.emit_word_operand(ev)
                else:
                    ev = self.eval_operand(src)
                    self.emit_byte(PREFIX_DD)
                    self.emit_byte(0x21)
                    self.emit_word_operand(ev)
                return True
            if dst_upper == 'IY':
                if src.startswith('(') and src.endswith(')'):
                    ev = self.eval_operand(src[1:-1])
                    self.emit_byte(PREFIX_FD)
                    self.emit_byte(0x2A)  # LD IY,(nn)
                    self.emit_word_operand(ev)
                else:
                    ev = self.eval_operand(src)
                    self.emit_byte(PREFIX_FD)
                    self.emit_byte(0x21)
                    self.emit_word_operand(ev)
                return True

            # LD (nn),dd / LD (nn),IX / LD (nn),IY
            if dst.startswith('(') and dst.endswith(')'):
                addr_expr = dst[1:-1]
                ev = self.eval_operand(addr_expr)
                if src_upper == 'HL':
                    self.emit_byte(0x22)  # LD (nn),HL opcode
                    self.emit_word_operand(ev)
                    return True
                if src_upper in Z80_PAIRS_BC_DE_HL_SP:
                    # BC=0x43, DE=0x53, HL handled above, SP=0x73
                    dd_opcodes = {'BC': 0x43, 'DE': 0x53, 'SP': 0x73}
                    if src_upper in dd_opcodes:
                        self.emit_byte(PREFIX_ED)
                        self.emit_byte(dd_opcodes[src_upper])
                        self.emit_word_operand(ev)
                    return True
                if src_upper == 'IX':
                    self.emit_byte(PREFIX_DD)
                    self.emit_byte(0x22)  # LD (nn),IX
                    self.emit_word_operand(ev)
                    return True
                if src_upper == 'IY':
                    self.emit_byte(PREFIX_FD)
                    self.emit_byte(0x22)  # LD (nn),IY
                    self.emit_word_operand(ev)
                    return True

            self.error(f"Invalid operands for LD: {dst},{src}")
            return True

        # PUSH/POP
        if operator in ('PUSH', 'POP'):
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            reg = ops[0].upper().strip()
            if reg == 'IX':
                self.emit_byte(PREFIX_DD)
                self.emit_byte(0xE5 if operator == 'PUSH' else 0xE1)
                return True
            if reg == 'IY':
                self.emit_byte(PREFIX_FD)
                self.emit_byte(0xE5 if operator == 'PUSH' else 0xE1)
                return True
            if reg in Z80_PAIRS_BC_DE_HL_AF:
                p = Z80_PAIRS_BC_DE_HL_AF[reg]
                if operator == 'PUSH':
                    self.emit_byte(0xC5 | (p << 4))
                else:
                    self.emit_byte(0xC1 | (p << 4))
                return True
            self.error(f"Invalid register for {operator}: {reg}")
            return True

        # ALU operations: ADD, ADC, SUB, SBC, AND, XOR, OR, CP
        if operator in Z80_ALU_MNEMONICS:
            # No ALU form has more than two operands; without the upper bound
            # 'ADD A,B,C' assembled as ADD A and dropped the rest.
            if len(ops) < 1 or len(ops) > 2:
                self.error(f"{operator} requires one or two operands")
                return True
            # Handle ADD A,r vs ADD HL,ss vs ADD IX,pp etc.
            if operator == 'ADD' and len(ops) == 2:
                dst, src = ops[0].upper().strip(), ops[1].upper().strip()
                if dst == 'HL' and src in Z80_PAIRS_BC_DE_HL_SP:
                    for b in encode_z80_add_hl_ss(src):
                        self.emit_byte(b)
                    return True
                if dst == 'IX' and src in Z80_PAIRS_BC_DE_IX_SP:
                    for b in encode_z80_add_ix_pp(src):
                        self.emit_byte(b)
                    return True
                if dst == 'IY' and src in Z80_PAIRS_BC_DE_IY_SP:
                    for b in encode_z80_add_iy_rr(src):
                        self.emit_byte(b)
                    return True
                if dst == 'A':
                    # Process as ADD r. Keep the operand's ORIGINAL case: src
                    # is an uppercased copy for register matching only, and
                    # an expression like 'a'-'A' must not become 'A'-'A' (=0).
                    ops = [ops[1].strip()]

            if operator == 'ADC' and len(ops) == 2:
                dst, src = ops[0].upper().strip(), ops[1].upper().strip()
                if dst == 'HL' and src in Z80_PAIRS_BC_DE_HL_SP:
                    for b in encode_z80_adc_hl_ss(src):
                        self.emit_byte(b)
                    return True
                if dst == 'A':
                    ops = [ops[1].strip()]  # original case (see ADD above)

            if operator == 'SBC' and len(ops) == 2:
                dst, src = ops[0].upper().strip(), ops[1].upper().strip()
                if dst == 'HL' and src in Z80_PAIRS_BC_DE_HL_SP:
                    for b in encode_z80_sbc_hl_ss(src):
                        self.emit_byte(b)
                    return True
                if dst == 'A':
                    ops = [ops[1].strip()]  # original case (see ADD above)

            # SUB/AND/XOR/OR/CP take one operand, the accumulator being
            # implicit -- but `CP A,5` is a common Z80 spelling and the
            # Zilog syntax every other assembler accepts.  ADD/ADC/SBC
            # collapse `A,src` above; these five had no such branch, so
            # ops[0] ("A") was taken as the operand: `CP A,5` assembled as
            # `CP A` (BF, which always sets Z) and the 5 was dropped
            # entirely.  Exit 0, no diagnostic, and a comparison that is
            # always equal.
            if len(ops) == 2 and operator in ('SUB', 'AND', 'XOR', 'OR', 'CP'):
                if ops[0].upper().strip() != 'A':
                    self.error(f"{operator} takes one operand, or "
                               f"{operator} A,<operand>; "
                               f"'{ops[0].strip()}' is not the accumulator")
                    return True
                ops = [ops[1].strip()]  # original case (see ADD above)

            # Anything still holding two operands reached none of the
            # forms above -- e.g. `ADD B,C`, which used to assemble as
            # `ADD B` and drop the C the same way.
            if len(ops) == 2:
                self.error(f"Invalid operands for {operator}: "
                           f"{ops[0].strip()},{ops[1].strip()}")
                return True

            # ALU A,r or ALU A,(HL) or ALU A,(IX+d) or ALU A,n
            op = ops[0].strip()
            op_upper = op.upper()
            indexed = self.parse_z80_indexed(op)
            if indexed:
                reg, disp, dev = indexed
                if reg == 'IX':
                    code = encode_z80_alu_ixd(operator, disp)
                else:
                    code = encode_z80_alu_iyd(operator, disp)
                self.emit_code(code, {2: dev})
                return True
            if op_upper in Z80_REGS_M:
                for b in encode_z80_alu_r(operator, op):
                    self.emit_byte(b)
                return True
            # Immediate
            ev = self.eval_operand(op)
            self.emit_code(encode_z80_alu_n(operator, ev.value), {1: ev})
            return True

        # INC/DEC
        if operator in ('INC', 'DEC'):
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            op = ops[0].upper().strip()
            # 16-bit: INC/DEC ss
            if op in Z80_PAIRS_BC_DE_HL_SP:
                p = Z80_PAIRS_BC_DE_HL_SP[op]
                if operator == 'INC':
                    self.emit_byte(0x03 | (p << 4))
                else:
                    self.emit_byte(0x0B | (p << 4))
                return True
            if op == 'IX':
                self.emit_byte(PREFIX_DD)
                self.emit_byte(0x23 if operator == 'INC' else 0x2B)
                return True
            if op == 'IY':
                self.emit_byte(PREFIX_FD)
                self.emit_byte(0x23 if operator == 'INC' else 0x2B)
                return True
            # 8-bit: INC/DEC r
            if op in Z80_REGS_M:
                r = Z80_REGS_M[op]
                if operator == 'INC':
                    self.emit_byte(0x04 | (r << 3))
                else:
                    self.emit_byte(0x05 | (r << 3))
                return True
            # Indexed
            indexed = self.parse_z80_indexed(ops[0])
            if indexed:
                reg, disp, dev = indexed
                if operator == 'INC':
                    if reg == 'IX':
                        code = encode_z80_inc_ixd(disp)
                    else:
                        code = encode_z80_inc_iyd(disp)
                else:
                    if reg == 'IX':
                        code = encode_z80_dec_ixd(disp)
                    else:
                        code = encode_z80_dec_iyd(disp)
                self.emit_code(code, {2: dev})
                return True
            self.error(f"Invalid operand for {operator}: {op}")
            return True

        # Rotate/shift: RLC, RRC, RL, RR, SLA, SRA, SLL, SRL
        if operator in Z80_ROT_MNEMONICS:
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            op = ops[0].upper().strip()
            if op in Z80_REGS:
                for b in encode_z80_rot_r(operator, op):
                    self.emit_byte(b)
                return True
            indexed = self.parse_z80_indexed(ops[0])
            if indexed:
                reg, disp, dev = indexed
                if reg == 'IX':
                    code = encode_z80_rot_ixd(operator, disp)
                else:
                    code = encode_z80_rot_iyd(operator, disp)
                self.emit_code(code, {2: dev})
                return True
            self.error(f"Invalid operand for {operator}: {op}")
            return True

        # Bit operations: BIT, RES, SET
        if operator in Z80_BIT_MNEMONICS:
            if len(ops) != 2:
                self.error(f"{operator} requires two operands")
                return True
            bit_val = self.number_operand(ops[0], operator).value
            if bit_val < 0 or bit_val > 7:
                self.error(f"Bit number must be 0-7: {bit_val}")
                return True
            op = ops[1].upper().strip()
            if op in Z80_REGS:
                if operator == 'BIT':
                    for b in encode_z80_bit_b_r(bit_val, op):
                        self.emit_byte(b)
                elif operator == 'RES':
                    for b in encode_z80_res_b_r(bit_val, op):
                        self.emit_byte(b)
                else:
                    for b in encode_z80_set_b_r(bit_val, op):
                        self.emit_byte(b)
                return True
            indexed = self.parse_z80_indexed(ops[1])
            if indexed:
                reg, disp, dev = indexed
                if operator == 'BIT':
                    if reg == 'IX':
                        code = encode_z80_bit_b_ixd(bit_val, disp)
                    else:
                        code = encode_z80_bit_b_iyd(bit_val, disp)
                elif operator == 'RES':
                    if reg == 'IX':
                        code = encode_z80_res_b_ixd(bit_val, disp)
                    else:
                        code = encode_z80_res_b_iyd(bit_val, disp)
                else:
                    if reg == 'IX':
                        code = encode_z80_set_b_ixd(bit_val, disp)
                    else:
                        code = encode_z80_set_b_iyd(bit_val, disp)
                self.emit_code(code, {2: dev})
                return True
            self.error(f"Invalid operand for {operator}: {ops[1]}")
            return True

        # JP - jumps
        if operator == 'JP':
            if len(ops) == 1:
                op = ops[0].upper().strip()
                if op == '(HL)':
                    self.emit_byte(0xE9)
                    return True
                if op == '(IX)':
                    self.emit_byte(PREFIX_DD)
                    self.emit_byte(0xE9)
                    return True
                if op == '(IY)':
                    self.emit_byte(PREFIX_FD)
                    self.emit_byte(0xE9)
                    return True
                # A condition with no address - but a symbol named like a
                # condition is the address, as in M80: after `P: NOP',
                # `JP P' is C3 and P (um80 stopped with this error, so
                # uplm80 wrote `JP 0+P').  One defined further down is a
                # symbol from the second time through pass 1.
                if op in Z80_CONDITIONS and not self.names_symbol(op):
                    if self.pass_num == 2:
                        self.error("JP with condition requires address")
                    self.emit_byte(0xC3)
                    self.emit_word(0)
                    return True
                # Unconditional JP nn
                ev = self.eval_operand(ops[0])
                self.emit_byte(0xC3)
                self.emit_word_operand(ev)
                return True
            if len(ops) == 2:
                cond = ops[0].upper().strip()
                if cond not in Z80_CONDITIONS:
                    self.error(f"Invalid condition for JP: {cond}")
                    return True
                ev = self.eval_operand(ops[1])
                c = Z80_CONDITIONS[cond]
                self.emit_byte(0xC2 | (c << 3))
                self.emit_word_operand(ev)
                return True
            self.error("JP requires one or two operands")
            return True

        # JR - relative jumps (with automatic promotion to JP if out of range)
        if operator == 'JR':
            # Check range only after first iteration (when all symbols are defined)
            # or on pass 2. On pass 1 iteration 0, forward refs are undefined.
            can_check_range = (self.pass_num == 2 or
                               (self.pass_num == 1 and getattr(self, 'pass1_iteration', 0) > 0))

            if len(ops) == 1:
                # Unconditional JR
                val, seg, reachable = self.relative_target(ops[0], 'JR')
                # For forward refs on pass 1 iter>0, use prev_symbols if available
                if can_check_range and val == 0 and self.pass_num == 1:
                    expr = ops[0].strip().upper()
                    prev_syms = getattr(self, 'prev_symbols', {})
                    if expr in prev_syms:
                        val, seg = prev_syms[expr]
                        reachable = seg == self.pc_seg
                # An unreachable target is an error, not a far one.
                can_check_range = can_check_range and reachable
                # Check if already promoted to JP
                if self.line_num in self.promoted_jr:
                    # Emit JP instead (3 bytes)
                    self.emit_byte(0xC3)
                    self.emit_word(val, seg)
                    return True
                # Calculate offset assuming JR (2 bytes)
                offset = val - (self.pc + 2)
                if can_check_range and (offset < -128 or offset > 127):
                    if self.strict_jr:
                        if self.pass_num == 2:
                            self.error(f"JR offset out of range: {offset}")
                        self.emit_byte(0x18)
                        self.emit_byte(offset & 0xFF)
                    else:
                        # Promote to JP
                        self.promoted_jr.add(self.line_num)
                        self.emit_byte(0xC3)
                        self.emit_word(val, seg)
                    return True
                self.emit_byte(0x18)
                self.emit_byte(offset & 0xFF)
                return True
            if len(ops) == 2:
                cond = ops[0].upper().strip()
                if cond not in Z80_JR_CONDITIONS:
                    self.error(f"Invalid condition for JR (only NZ,Z,NC,C): {cond}")
                    return True
                val, seg, reachable = self.relative_target(ops[1], 'JR')
                # For forward refs on pass 1 iter>0, use prev_symbols if available
                if can_check_range and val == 0 and self.pass_num == 1:
                    expr = ops[1].strip().upper()
                    prev_syms = getattr(self, 'prev_symbols', {})
                    if expr in prev_syms:
                        val, seg = prev_syms[expr]
                        reachable = seg == self.pc_seg
                can_check_range = can_check_range and reachable
                # Check if already promoted to JP
                if self.line_num in self.promoted_jr:
                    # Emit JP cc instead (3 bytes)
                    c = Z80_CONDITIONS[cond]  # Same codes for NZ,Z,NC,C
                    self.emit_byte(0xC2 | (c << 3))
                    self.emit_word(val, seg)
                    return True
                # Calculate offset assuming JR (2 bytes)
                offset = val - (self.pc + 2)
                if can_check_range and (offset < -128 or offset > 127):
                    if self.strict_jr:
                        if self.pass_num == 2:
                            self.error(f"JR offset out of range: {offset}")
                        c = Z80_JR_CONDITIONS[cond]
                        self.emit_byte(0x20 | (c << 3))
                        self.emit_byte(offset & 0xFF)
                    else:
                        # Promote to JP
                        self.promoted_jr.add(self.line_num)
                        c = Z80_CONDITIONS[cond]
                        self.emit_byte(0xC2 | (c << 3))
                        self.emit_word(val, seg)
                    return True
                c = Z80_JR_CONDITIONS[cond]
                self.emit_byte(0x20 | (c << 3))
                self.emit_byte(offset & 0xFF)
                return True
            self.error("JR requires one or two operands")
            return True

        # DJNZ (with automatic promotion to DEC B + JP NZ if out of range)
        if operator == 'DJNZ':
            if len(ops) != 1:
                self.error("DJNZ requires one operand")
                return True
            # Check range only after first iteration (when all symbols are defined)
            can_check_range = (self.pass_num == 2 or
                               (self.pass_num == 1 and getattr(self, 'pass1_iteration', 0) > 0))

            val, seg, reachable = self.relative_target(ops[0], 'DJNZ')
            # For forward refs on pass 1 iter>0, use prev_symbols if available
            if can_check_range and val == 0 and self.pass_num == 1:
                expr = ops[0].strip().upper()
                prev_syms = getattr(self, 'prev_symbols', {})
                if expr in prev_syms:
                    val, seg = prev_syms[expr]
                    reachable = seg == self.pc_seg
            can_check_range = can_check_range and reachable
            # Check if already promoted
            if self.line_num in self.promoted_jr:
                # Emit DEC B + JP NZ instead (4 bytes)
                self.emit_byte(0x05)  # DEC B
                self.emit_byte(0xC2)  # JP NZ
                self.emit_word(val, seg)
                return True
            # Calculate offset assuming DJNZ (2 bytes)
            offset = val - (self.pc + 2)
            if can_check_range and (offset < -128 or offset > 127):
                if self.strict_jr:
                    if self.pass_num == 2:
                        self.error(f"DJNZ offset out of range: {offset}")
                    self.emit_byte(0x10)
                    self.emit_byte(offset & 0xFF)
                else:
                    # Promote to DEC B + JP NZ
                    self.promoted_jr.add(self.line_num)
                    self.emit_byte(0x05)  # DEC B
                    self.emit_byte(0xC2)  # JP NZ
                    self.emit_word(val, seg)
                return True
            self.emit_byte(0x10)
            self.emit_byte(offset & 0xFF)
            return True

        # CALL
        if operator == 'CALL':
            if len(ops) == 1:
                ev = self.eval_operand(ops[0])
                self.emit_byte(0xCD)
                self.emit_word_operand(ev)
                return True
            if len(ops) == 2:
                cond = ops[0].upper().strip()
                if cond not in Z80_CONDITIONS:
                    self.error(f"Invalid condition for CALL: {cond}")
                    return True
                ev = self.eval_operand(ops[1])
                c = Z80_CONDITIONS[cond]
                self.emit_byte(0xC4 | (c << 3))
                self.emit_word_operand(ev)
                return True
            self.error("CALL requires one or two operands")
            return True

        # RET
        if operator == 'RET':
            if not ops:
                self.emit_byte(0xC9)
                return True
            if len(ops) == 1:
                cond = ops[0].upper().strip()
                if cond not in Z80_CONDITIONS:
                    self.error(f"Invalid condition for RET: {cond}")
                    return True
                c = Z80_CONDITIONS[cond]
                self.emit_byte(0xC0 | (c << 3))
                return True
            self.error("RET takes zero or one operand")
            return True

        # RST
        if operator == 'RST':
            if len(ops) != 1:
                self.error("RST requires one operand")
                return True
            val = self.number_operand(ops[0], 'RST').value
            # Accept 0-7 or 0,8,16,24,32,40,48,56
            if val > 7:
                if val not in (0, 8, 16, 24, 32, 40, 48, 56):
                    self.error(f"Invalid RST vector: {val}")
                    return True
                val = val >> 3
            self.emit_byte(0xC7 | (val << 3))
            return True

        # IN
        if operator == 'IN':
            if len(ops) == 2:
                dst, src = ops[0].upper().strip(), ops[1].upper().strip()
                if dst == 'A' and src.startswith('(') and src.endswith(')'):
                    inner = src[1:-1].strip().upper()
                    if inner == 'C':
                        # IN A,(C)
                        self.emit_byte(PREFIX_ED)
                        self.emit_byte(0x78)
                        return True
                    # IN A,(n)
                    ev = self.eval_operand(src[1:-1])
                    self.emit_code([0xDB, ev.value & 0xFF], {1: ev})
                    return True
                if dst in Z80_REGS and src == '(C)':
                    # IN r,(C)
                    for b in encode_z80_in_r_c(dst):
                        self.emit_byte(b)
                    return True
            self.error("Invalid IN operands")
            return True

        # OUT
        if operator == 'OUT':
            if len(ops) == 2:
                dst, src = ops[0].upper().strip(), ops[1].upper().strip()
                if dst == '(C)' and src in Z80_REGS:
                    # OUT (C),r
                    for b in encode_z80_out_c_r(src):
                        self.emit_byte(b)
                    return True
                if dst.startswith('(') and dst.endswith(')') and src == 'A':
                    inner = dst[1:-1].strip().upper()
                    if inner == 'C':
                        # OUT (C),A
                        self.emit_byte(PREFIX_ED)
                        self.emit_byte(0x79)
                        return True
                    # OUT (n),A
                    ev = self.eval_operand(dst[1:-1])
                    self.emit_code([0xD3, ev.value & 0xFF], {1: ev})
                    return True
            self.error("Invalid OUT operands")
            return True

        # IM
        if operator == 'IM':
            if len(ops) != 1:
                self.error("IM requires one operand")
                return True
            val = self.number_operand(ops[0], 'IM').value
            if val not in (0, 1, 2):
                self.error(f"Invalid interrupt mode: {val}")
                return True
            for b in encode_z80_im(val):
                self.emit_byte(b)
            return True

        return False  # Not a Z80 instruction

    # Directives whose operands are values: with --dri a < or > in them is an
    # operator, not a bracket (split_operands()).
    _VALUE_DIRECTIVES = frozenset({
        'DB', 'DEFB', 'DEFM', 'DC', 'DW', 'DEFW', 'DS', 'DEFS', 'ORG', 'EQU',
        'SET', 'DEFL', 'ASET', 'IF', 'IFT', 'IFE', 'IFF', 'COND', 'END'})

    def assemble_pseudo_op(self, operator, operands, label):
        """Assemble a pseudo-operation (directive)."""
        operator = operator.upper()
        ops = self.split_operands(operands, angles=not (
            self.dri and operator in self._VALUE_DIRECTIVES)) if operands else []

        # ORG - set location counter
        if operator == 'ORG':
            if len(ops) != 1:
                self.error("ORG requires one operand")
                return True
            ev = self.number_operand(ops[0], 'ORG')
            val = ev.value & 0xFFFF
            if ev.kind == 'rel' and ev.seg != self.seg_type \
                    and self.pass_num == 2:
                # `ORG $+10' moves within the segment; an address in
                # another segment is no place in this one (M80: 'R').
                self.error(f"ORG to '{ops[0].strip()}', an address in "
                           f"another segment")
            self.loc = val
            self.mark_location(val)
            # Track first ORG as segment origin, but ONLY for ASEG (absolute segment).
            # For relocatable segments (CSEG/DSEG), ORG just sets the location counter
            # without affecting symbol relocation. This handles "org $-1" patterns
            # correctly - they just back up the location counter, not set segment base.
            seg_obj = self.segments[self.current_seg]
            if not seg_obj.org_set and self.current_seg == 'ASEG' \
                    and self.current_common is None:
                seg_obj.org = val
                seg_obj.org_set = True
            if self.pass_num == 2:
                # ORG sets the location counter within the current segment.
                # For relocatable segments (CSEG/DSEG), the segment type doesn't change.
                # Only use ASEG if we're actually in ASEG.  It replaces the
                # item an ASEG directive just before it held back.
                self.output.drop_deferred_location()
                self.select_common(self.current_common)
                self.output.write_set_location(self.seg_type, val)
            return True

        # EQU - equate symbol to value
        if operator == 'EQU':
            if not label:
                self.error("EQU requires a label")
                return True
            if len(ops) != 1:
                self.error("EQU requires one operand")
                return True
            # A register name is its number, as in M80 and MAC: `MR EQU B'
            # is 0, and MR then names register B (register_value()); `X EQU
            # SP' and `X EQU PSW' are 6.
            op_upper = ops[0].strip().upper()
            if op_upper in REG_VALUES and not self.names_symbol(op_upper):
                self.define_symbol(label, REG_VALUES[op_upper], ADDR_ABSOLUTE)
                return True
            reads = {} if self.pass_num == 1 else None
            self.reading = reads
            self.reading_pure = True
            try:
                ev = self.eval_operand(ops[0],
                                       allow_undefined=(self.pass_num == 1))
            finally:
                self.reading = None
            if reads is not None:
                self.note_definition((label.upper(), 0), 'EQU', ops[0], reads)
            # An external plus a constant makes the symbol an alias of the
            # external.  A value only the linker can compute, e.g. HIGH BUF
            # with BUF relocatable, makes the symbol stand for the
            # expression, so each use of it is passed to the linker the way
            # the expression itself would be.  (M80 keeps the mode and loses
            # the HIGH: `X EQU HIGH BUF' then `MVI A,X' loads the LOW byte
            # of BUF.)
            self.define_value(label, ev)
            sym = self.symbols.get(label.upper())
            if reads is not None and sym is not None and sym.defined:
                self.def_value[(sym.name, 0)] = self.symbol_value(sym)
            return True

        # SET/DEFL/ASET - like EQU but redefinable
        if operator in ('SET', 'DEFL', 'ASET'):
            if not label:
                self.error(f"{operator} requires a label")
                return True
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            # A register name is its number (see EQU)
            op_upper = ops[0].strip().upper()
            link_expr = None
            name = label.upper()
            k = self.set_count.get(name, 0) + 1  # this SET's node: (name, k)
            if op_upper in REG_VALUES and not self.names_symbol(op_upper):
                val, seg = REG_VALUES[op_upper], ADDR_ABSOLUTE
            else:
                # `X SET X+1' reads the X of the line before, not the one
                # this line makes: in pass 1 an X not yet SET reads 0, as it
                # always has, rather than the previous iteration's final X
                # (see forward_value()), which would never settle.
                reads = {} if self.pass_num == 1 else None
                self.defining = name
                self.reading = reads
                self.reading_pure = True
                try:
                    ev = self.eval_operand(ops[0],
                                           allow_undefined=(self.pass_num == 1))
                finally:
                    self.defining = None
                    self.reading = None
                if reads is not None:
                    self.note_definition((name, k), operator, ops[0], reads)
                val, seg, ext, _ = ev.as_tuple()
                if ev.kind in ('expr', 'bad'):
                    link_expr = ev  # see EQU
                elif ext:
                    self.error(f"Cannot use external in {operator}")
                    return True
            # SET/DEFL/ASET defines a redefinable symbol. It may only redefine
            # another redefinable (SET-class) symbol; redefining an EQU/label
            # symbol is multiply-defined (the class is fixed at first definition).
            sym = self.lookup_symbol(label)
            if sym.defined and sym.defined_pass == self.pass_num and not sym.redefinable:
                self.error(f"Symbol '{label.upper()}' multiply defined")
                return True
            sym.value = val
            sym.seg_type = seg
            sym.defined = True
            sym.defined_pass = self.pass_num
            sym.redefinable = True
            sym.link_expr = link_expr
            sym.line = self.line_num
            self.set_count[name] = k
            if self.pass_num == 1:
                self.def_value[(name, k)] = self.symbol_value(sym)
            return True

        # DB - define bytes
        if operator in ('DB', 'DEFB', 'DEFM'):
            for op in ops:
                op = op.strip()
                # A string, not an expression that begins and ends with a
                # quote: DB 'A'+'B' is the byte 83H.
                if is_string_literal(op):
                    s = op[1:-1]
                    # A doubled quote stands for one.
                    s = s.replace(op[0] * 2, op[0])
                    for ch in s:
                        self.emit_byte(ord(ch))
                else:
                    ev = self.eval_operand(op)
                    self.emit_code([ev.value & 0xFF], {0: ev})
            return True

        # DC - define character string with high bit set on last character (M80 compatible)
        if operator == 'DC':
            if len(ops) != 1:
                self.error("DC requires one string operand")
                return True
            op = ops[0].strip()
            if is_string_literal(op):
                s = op[1:-1]
                # A doubled quote stands for one.
                s = s.replace(op[0] * 2, op[0])
                if not s:
                    self.error("DC requires non-empty string")
                    return True
                for i, ch in enumerate(s):
                    byte_val = ord(ch)
                    if i == len(s) - 1:
                        byte_val |= 0x80  # Set high bit on last character
                    self.emit_byte(byte_val)
            else:
                self.error("DC requires a string operand")
            return True

        # DW - define words
        if operator in ('DW', 'DEFW'):
            for op in ops:
                ev = self.eval_operand(op.strip())
                self.emit_word_operand(ev)
            return True

        # DS - define space
        # M80 supports an optional fill-value operand: DEFS count[,fill]
        # Without fill, just advance the location counter (leaves zeros in the
        # linker's output buffer). With fill, emit `count` bytes of that value.
        if operator in ('DS', 'DEFS'):
            if len(ops) < 1:
                self.error("DS requires size operand")
                return True
            val = self.number_operand(ops[0], operator).value & 0xFFFF
            if len(ops) >= 2:
                fill = self.eval_operand(ops[1])
                if fill.kind == 'bad':
                    # Once, not once for every byte it fills.
                    self.report_unlinkable(fill)
                    fill = ExprValue(fill.value)
                for _ in range(val):
                    self.emit_code([fill.value & 0xFF], {0: fill})
            else:
                # Just advance location counter (don't emit anything for DS)
                if self.pass_num == 2:
                    # For REL format, we need to advance by emitting zeros or using set_location
                    # Using set_location to skip over the space
                    new_loc = self.loc + val
                    self.select_common(self.current_common)
                    self.output.write_set_location(self.seg_type, new_loc)
                self.loc += val
                self.mark_location()
            return True

        # CSEG/DSEG/ASEG - segment selection
        if operator in ('CSEG', 'DSEG', 'ASEG'):
            self.enter_segment(operator)
            return True

        # COMMON - define/select common block
        if operator == 'COMMON':
            name = ''
            if ops:
                name = ops[0].strip()
                if name.startswith('/') and name.endswith('/'):
                    name = name[1:-1]
            if name not in self.common_blocks:
                self.common_blocks[name] = Segment(name, ADDR_COMMON_REL)
            self.leave_segment()
            self.current_common = name
            # Every COMMON statement starts at the beginning of its block,
            # as in MACRO-80 and FORTRAN (a block declared again lays its
            # contents over the same storage); um80 went on from where the
            # block was left.  Its size stays the most any statement used.
            self.loc = 0
            if self.pass_num == 2:
                # Select the block and say where in it the bytes that follow
                # load: um80 wrote the selection alone, so the linker went on
                # loading them into the segment before - `DB 55H' in a
                # COMMON block overwrote the CSEG byte after the code.
                self.output.drop_deferred_location()
                self.select_common(name)
                self.output.write_set_location(ADDR_COMMON_REL, self.loc)
            return True

        # PUBLIC/ENTRY - declare public symbols
        if operator in ('PUBLIC', 'ENTRY', 'GLOBAL'):
            for op in ops:
                sym = self.lookup_symbol(op.strip())
                sym.public = True
                sym.public_line = sym.public_line or self.line_num
            return True

        # EXTRN/EXT/EXTERNAL - declare external symbols
        if operator in ('EXTRN', 'EXT', 'EXTERNAL'):
            for op in ops:
                sym = self.lookup_symbol(op.strip())
                sym.external = True
            return True

        # NAME('modname') - the module name, the first six characters, as
        # MACRO-80 3.44 keeps them.  NAME('XYZ') went into the .REL as 'XYZ'
        # with its quotes.  (M80 wants the parentheses and the quotes; um80
        # also takes NAME 'XYZ' and NAME XYZ.)
        if operator == 'NAME':
            if ops:
                name = ops[0].strip()
                if name.startswith('(') and name.endswith(')'):
                    name = name[1:-1].strip()
                if len(name) >= 2 and name[0] in "'\"" and name[-1] == name[0]:
                    name = name[1:-1]
                self.module_name = name.upper()[:6]
            return True

        # TITLE/SUBTTL - listing titles.  Without a NAME, MACRO-80 names the
        # module after the last TITLE: the first six characters of its text
        # up to a blank, whatever they are (TITLE 'BASIC' is the module
        # 'BASIC).  M80's $TITLE('text') is a subtitle, and names nothing.
        if operator in ('TITLE', 'SUBTTL', '$TITLE'):
            if operator == 'TITLE' and operands and operands.strip():
                self.title_name = operands.split()[0].upper()[:6]
            return True

        # PAGE/*EJECT/$EJECT - new page in listing (ignore for now)
        if operator in ('PAGE', '*EJECT', '$EJECT'):
            return True

        # .LIST/.XLIST - listing control
        if operator == '.LIST':
            self.list_on = True
            return True
        if operator == '.XLIST':
            self.list_on = False
            return True

        # .RADIX - set default radix. M80 always evaluates the operand in
        # decimal, regardless of the current radix, so '.RADIX 16' sets hex
        # (and re-evaluates correctly on every pass).
        if operator == '.RADIX':
            if len(ops) != 1:
                self.error(".RADIX requires one operand")
                return True
            saved_radix = self.radix
            self.radix = 10
            try:
                val = self.number_operand(ops[0], '.RADIX').value
            finally:
                self.radix = saved_radix
            if val < 2 or val > 16:
                self.error("Radix must be 2-16")
                return True
            self.radix = val
            return True

        # .Z80/.8080 - processor mode
        if operator == '.8080':
            self.z80_mode = False
            return True
        if operator == '.Z80':
            self.z80_mode = True
            return True

        # .SALL/.LALL/.XALL - macro listing control
        if operator in ('.SALL', '.LALL', '.XALL'):
            return True

        # .SFCOND/.LFCOND/.TFCOND - conditional listing control
        if operator in ('.SFCOND', '.LFCOND', '.TFCOND'):
            return True

        # .PRINTX - print message during assembly
        if operator == '.PRINTX':
            if operands and self.pass_num == 2:
                msg = operands.strip()
                if len(msg) >= 2:
                    delim = msg[0]
                    if msg[-1] == delim:
                        msg = msg[1:-1]
                print(msg)
            return True

        # .COMMENT - multi-line comment (simplified)
        if operator == '.COMMENT':
            return True

        # .REQUEST - request library search
        if operator == '.REQUEST':
            for op in ops:
                if self.pass_num == 2:
                    self.output.write_request_library(op.strip())
            return True

        # .PHASE addr / .DEPHASE: code loaded here runs at addr (see pc).
        if operator == '.PHASE':
            if len(ops) != 1:
                self.error(".PHASE requires one operand")
                return True
            ev = self.number_operand(ops[0], '.PHASE')
            if ev.kind == 'rel' and self.pass_num == 2:
                self.error(f".PHASE needs an absolute address, but "
                           f"'{ops[0].strip()}' is relocatable")
            self.phase = (ev.value & 0xFFFF, self.loc)
            return True
        if operator == '.DEPHASE':
            self.phase = None
            return True

        # END - end of source
        if operator == 'END':
            if ops:
                ev = self.number_operand(ops[0], 'END')
                self.entry_point = (ev.value & 0xFFFF, ev.seg)
            # The end of the source: MACRO-80, MAC and RMAC read no further,
            # from a macro, a REPT or an INCLUDE file too.  um80 went on,
            # and assembled what followed.
            self.ended = True
            return True

        # Conditional assembly
        if operator == 'IF' or operator == 'IFT':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                val = self.number_operand(ops[0] if ops else '0',
                                          operator).value
                if val == 0:
                    self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        if operator in ('IFE', 'IFF'):
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                val = self.number_operand(ops[0] if ops else '0',
                                          operator).value
                if val != 0:
                    self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        if operator == 'IFDEF':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                name = ops[0].strip() if ops else ''
                sym = self.symbols.get(name.upper())
                if not sym or (not sym.defined and not sym.external):
                    self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        if operator == 'IFNDEF':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                name = ops[0].strip() if ops else ''
                sym = self.symbols.get(name.upper())
                if sym and (sym.defined or sym.external):
                    self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        if operator == 'IF1':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            elif self.pass_num != 1:
                self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        if operator == 'IF2':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            elif self.pass_num != 2:
                self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        # IFB - true if argument is blank
        if operator == 'IFB':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                # Argument must be in angle brackets
                arg = ops[0].strip() if ops else ''
                if arg.startswith('<') and arg.endswith('>'):
                    arg = arg[1:-1]
                if arg.strip():  # Not blank
                    self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        # IFNB - true if argument is not blank
        if operator == 'IFNB':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                arg = ops[0].strip() if ops else ''
                if arg.startswith('<') and arg.endswith('>'):
                    arg = arg[1:-1]
                if not arg.strip():  # Is blank
                    self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        # IFIDN - true if two arguments are identical
        if operator == 'IFIDN':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                if len(ops) >= 2:
                    arg1 = ops[0].strip()
                    arg2 = ops[1].strip()
                    # Strip angle brackets if present
                    if arg1.startswith('<') and arg1.endswith('>'):
                        arg1 = arg1[1:-1]
                    if arg2.startswith('<') and arg2.endswith('>'):
                        arg2 = arg2[1:-1]
                    if arg1.upper() != arg2.upper():
                        self.cond_false_depth = 1
                else:
                    self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        # IFDIF - true if two arguments are different
        if operator == 'IFDIF':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                if len(ops) >= 2:
                    arg1 = ops[0].strip()
                    arg2 = ops[1].strip()
                    # Strip angle brackets if present
                    if arg1.startswith('<') and arg1.endswith('>'):
                        arg1 = arg1[1:-1]
                    if arg2.startswith('<') and arg2.endswith('>'):
                        arg2 = arg2[1:-1]
                    if arg1.upper() == arg2.upper():
                        self.cond_false_depth = 1
                else:
                    pass  # No args means they're different (empty vs empty? treat as true)
            self.cond_stack.append(operator)
            return True

        if operator == 'ELSE':
            if not self.cond_stack:
                self.error("ELSE without IF")
                return True
            # Only one ELSE is allowed per conditional level (M80 flags a
            # second ELSE as an error). Keep the toggle so the emitted bytes
            # still match M80, which assembles the duplicate branch anyway.
            level = len(self.cond_stack)
            if level in self.cond_else_levels:
                self.error("Duplicate ELSE")
            else:
                self.cond_else_levels.add(level)
            if self.cond_false_depth == 1:
                self.cond_false_depth = 0
            elif self.cond_false_depth == 0:
                self.cond_false_depth = 1
            return True

        if operator == 'ENDIF' or operator == 'ENDC':
            if not self.cond_stack:
                self.error(f"{operator} without IF")
                return True
            self.cond_else_levels.discard(len(self.cond_stack))
            self.cond_stack.pop()
            if self.cond_false_depth > 0:
                self.cond_false_depth -= 1
            return True

        # COND - Z80 alias for IFT (true if expression is not 0)
        if operator == 'COND':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                val = self.number_operand(ops[0] if ops else '0',
                                          operator).value
                if val == 0:
                    self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        # INCLUDE/$INCLUDE/MACLIB - include source file
        if operator in ('INCLUDE', '$INCLUDE', 'MACLIB'):
            if not ops:
                self.error(f"{operator} requires a filename")
                return True
            filename = ops[0].strip()
            # Remove quotes if present
            if (filename.startswith("'") and filename.endswith("'")) or \
               (filename.startswith('"') and filename.endswith('"')):
                filename = filename[1:-1]
            # Remove angle brackets if present
            if filename.startswith('<') and filename.endswith('>'):
                filename = filename[1:-1]

            # Try to find the include file
            include_path = self.find_include_file(filename)
            if include_path is None:
                self.error(f"Cannot find include file: {filename}")
                return True

            # Check for infinite recursion
            if len(self.include_stack) > 10:
                self.error("Include nesting too deep")
                return True

            # Process the include file
            self.process_include_file(include_path,
                                      library=(operator == 'MACLIB'))
            return True

        # MACRO definition - starts collecting
        if operator == 'MACRO':
            if not label:
                self.error("MACRO requires a name (label)")
                return True
            # Parse parameters from operands
            params = []
            if operands:
                params = [p.strip().upper() for p in operands.split(',')]
            self.collecting_macro = label.upper()
            self.block_open_line = self.line_num
            self.macro_params = params
            self.macro_body = []
            self.macro_nest_depth = 0
            return True

        # ENDM outside of macro definition is an error
        if operator == 'ENDM':
            self.error("ENDM without MACRO")
            return True

        # EXITM - exit from macro expansion
        if operator == 'EXITM':
            # Handled during expansion - here it just returns
            return True

        # LOCAL - declare local symbols in macro
        if operator == 'LOCAL':
            # Handled during expansion - here it's ignored
            return True

        # REPT - repeat block
        if operator == 'REPT':
            if not ops:
                self.error("REPT requires a count")
                return True
            count = self.number_operand(ops[0], 'REPT').value & 0xFFFF
            self.block_open_line = self.line_num
            self.repeat_stack.append(('REPT', count, [], None, label))
            return True

        # IRP - iterate with list
        if operator == 'IRP':
            if len(ops) < 2:
                self.error("IRP requires parameter and list")
                return True
            param = ops[0].strip().upper()
            inner = self.repeat_list(operator, operands)
            if inner is None:
                # No <...>: the rest of the operands are the list (M80
                # wants the brackets; um80 takes the list without them).
                values = ops[1:]
            else:
                # Split while respecting nested <...> groups (so
                # <<1,2>,<3,4>> yields two items, not four) and '!' (so
                # <1!,2,3> yields "1,2" and "3"). An empty list <> still
                # iterates once with an empty argument (matches real M80).
                values = self.split_operands(inner, escape_bang=True) \
                    if inner.strip() else ['']
            if not self.dri:
                # M80 reads an item as it reads a macro argument, `%' and
                # all: `IRP X,<%E,2>' iterates over E's value then, and 2.
                # MAC and RMAC read the list as text.  M80 flags a `%' in
                # the last item O and passes 0.
                last = values[-1]
                values = [self.percent_argument(v) for v in values]
                if values[-1] != last and self.pass_num == 2:
                    self.warning("M80 flags a `%' in the last item of an IRP"
                                 " list O; um80 takes its value")
            self.block_open_line = self.line_num
            self.repeat_stack.append(('IRP', values, [], param, label))
            return True

        # IRPC - iterate over characters
        if operator == 'IRPC':
            if not ops or ',' not in operands:
                self.error("IRPC requires parameter and string")
                return True
            param = ops[0].strip().upper()
            chars = self.repeat_list(operator, operands)
            if chars is None:
                # No <...>: the string ends at a blank or a comma.
                text = operands.split(',', 1)[1].strip()
                chars = re.split(r'[\s,]', text, maxsplit=1)[0]
                self._repeat_line_tail(text[len(chars):],
                                       "IRPC string ends at a blank or a comma")
            chars = list(chars)
            if not chars and (self.dri or self.irpc_from_argument):
                # An empty string: MAC and RMAC go round once, with the
                # parameter empty (SEQIO.LIB's `IRPC ?FC,FC' tests NUL ?FC
                # for it).  M80 does not, except where a macro's empty
                # argument made the string empty (expand_macro()).
                chars = ['']
            self.block_open_line = self.line_num
            self.repeat_stack.append(('IRPC', chars, [], param, label))
            return True

        # ENDM for REPT/IRP/IRPC
        # (Note: ENDM for MACRO is handled in process_line)

        return False  # Not a pseudo-op

    def repeat_list(self, operator, operands):
        """The text inside the <...> list of an IRP or IRPC, as M80 reads it.

        Returns None when the list does not start with '<'.  MACRO-80 3.44
        ends the list at the '>' that matches its '<' - counting nested
        brackets, and for IRP (whose items are read like macro arguments)
        skipping a '!'-quoted character and a quoted string - and ignores
        the rest of the line: `IRPC C,<>>' iterates over nothing and
        `IRP X,<1,2>,3' over 1 and 2.  um80 used to drop the first and last
        characters of the operand, so those were '>' and "1,2>,3".  In an
        IRPC list '!' and quotes are ordinary characters: `IRPC C,<!>>' is
        '!', and `IRPC C,<A'>'B>' is A and a quote.  In an IRP list a
        string is one piece of text: `IRP X,<'A>B','Hi!'>' is 'A>B' and
        'Hi!'.  A list with no matching '>' runs to the end of the line,
        and M80 flags it 'Q': `IRPC C,<<>' is '<' and '>'.  This matters
        where a macro wraps its argument in brackets, `IRPC CH,<STR>', and
        the argument is `!>': the '>' closes the list.
        """
        rest = operands.split(',', 1)[1].lstrip() if ',' in operands else ''
        if not rest.startswith('<'):
            return None
        depth, i = 0, 0
        while i < len(rest):
            ch = rest[i]
            if operator == 'IRP':
                if ch == '!':
                    i += 2
                    continue
                if self._starts_string(rest, i):
                    i = self._string_end(rest, i)
                    continue
            if ch == '<':
                depth += 1
            elif ch == '>':
                depth -= 1
                if depth == 0:
                    self._repeat_line_tail(
                        rest[i + 1:], f"{operator} list ends at the '>' that"
                        " matches its '<'")
                    return rest[1:i]
            i += 1
        if self.pass_num == 2:
            self.warning(f"{operator} list has no closing '>' (M80: Q)")
        return rest[1:]

    @staticmethod
    def _starts_string(text, i):
        """Whether the character at text[i] opens a quoted string.

        The rule split_operands() and parse_line() use: a ' after a letter
        or digit is not a quote (the Z80's AF').
        """
        ch = text[i]
        return ch == '"' or (ch == "'" and not (i and text[i - 1].isalnum()))

    @staticmethod
    def _string_end(text, i):
        """The index just past the quoted string that opens at text[i].

        A doubled quote is a quote inside the string; a string with no
        closing quote runs to the end of the text.
        """
        quote, i = text[i], i + 1
        while i < len(text):
            if text[i] == quote:
                if text[i + 1:i + 2] != quote:
                    return i + 1
                i += 1
            i += 1
        return i

    def _repeat_line_tail(self, tail, where):
        """The text after an IRP or IRPC list on its line.

        M80 ignores it, and um80 warns.  Text that starts with '!' is DRI's
        statement separator instead - `IRPC C,AB ! DB '&C' ! ENDM', which
        um80 0.3.49 assembled - and process_line() assembles the statements
        after the IRP or IRPC line.  Inside the list a '!' is M80's.
        """
        tail = tail.strip()
        if tail.startswith('!'):
            self.repeat_line_tail = tail[1:]
        elif tail and self.pass_num == 2:
            self.warning(f"{where}: '{tail}' after it is ignored")

    def _line_invokes_macro(self, line):
        """Return True if this line's operator is a defined macro name, IRP or IRPC.

        Used to suppress DRI '!' statement-splitting on macro-call lines, where
        '!' is instead the M80 argument-quote operator (issue #3), and on IRP
        and IRPC lines. The '!' check is a cheap guard so we only parse lines
        that could be affected.
        """
        if '!' not in line:
            return False
        operator = self.parse_line(line)[1]
        if operator is None:
            return False
        # IRP and IRPC lists too: '!' quotes a character in an IRP list and
        # is an ordinary character in an IRPC list (`IRPC C,<A!B>').
        return operator in self.macros or operator.upper() in ('IRP', 'IRPC')

    def _dri_statement(self, line):
        """One statement as --dri reads it: without the `$' inside a name.

        MAC and RMAC drop a `$' where they read a name: a label, an
        operator, an instruction's or a directive's operands, a macro's
        formal parameters, the parameter of an IRP or IRPC.  The arguments
        of a macro call and the list of an IRP or IRPC are text to them, and
        keep every `$': `PRINT HELLO$' passes HELLO$ - its BDOS terminator
        intact - and `IRPC C,12$3' iterates four times.  The expanded lines
        come back through here, so an argument that becomes a name there
        loses its `$' then (`MM NMB$LST' with a body of `LDA P' loads
        NMBLST).

        A line of a MACRO, REPT, IRP or IRPC body is kept as written, and
        read when it is expanded: MAC matches a formal parameter in the body
        as written, and a `$' ends the name it looks for.  With the formal
        A, `DB A$B' is `DB X$B' after `MM X', and `DB P$1' is not the formal
        P1 (U in MAC).
        """
        if ('$' not in line or self.collecting_macro is not None
                or self.repeat_stack):
            return line
        dropped = drop_name_dollars(line)
        label, operator, operands, _ = self.parse_line(dropped)
        if not operands or (operator not in self.macros
                            and operator not in ('IRP', 'IRPC')):
            return dropped
        # The label and the operator, as parse_line() finds them.
        head = re.match(r'\s*' + (r'[$A-Za-z_@?][A-Za-z0-9_@?$.]*(?:::?)?\s*'
                                  if label else '')
                        + r'([$A-Za-z_@?.][A-Za-z0-9_@?$.]*)\s*', line)
        if not head or drop_name_dollars(head.group(1)).upper() != operator:
            return dropped
        rest = line[head.end():]
        if operator in ('IRP', 'IRPC'):
            param, comma, items = rest.partition(',')
            rest = drop_name_dollars(param) + comma + items
        return drop_name_dollars(head.group()) + rest

    def process_line(self, line):
        """Process a single source line."""
        self.line_num += 1
        self._start_listing_line()
        read = self._dri_statement if self.dri else (lambda stmt: stmt)
        statement = read(line)

        # DRI extension: split on '!' separator for multi-statement lines.
        # Only do this when not collecting macro or repeat bodies, and not on a
        # macro-invocation line. On a macro call, '!' is the M80 argument-quote
        # operator (e.g. head FOO,!!CF) rather than a DRI statement separator;
        # splitting here would shred the arguments (issue #3).
        if (self.collecting_macro is None and not self.repeat_stack
                and not self._line_invokes_macro(statement)):
            statements = self.split_on_exclamation(line)
            if len(statements) > 1:
                # Process first statement normally (with label if any)
                self._process_single_statement(read(statements[0]))
                # Process subsequent statements (they can't have labels from original line)
                for stmt in statements[1:]:
                    if self.ended:
                        break
                    # Add leading space to prevent treating first word as label
                    if stmt and not stmt[0].isspace():
                        stmt = '        ' + stmt.strip()
                    self._process_single_statement(read(stmt))
                return
        # Fall through to normal processing (single statement or macro/repeat body)
        self._process_single_statement(statement)
        # DRI statements after an IRP or IRPC list: `IRPC C,AB ! DB '&C' ! ENDM'.
        tail, self.repeat_line_tail = self.repeat_line_tail, None
        if tail is not None:
            for stmt in self.split_on_exclamation(tail):
                if stmt.strip() and not self.ended:
                    self._process_single_statement(read('        ' + stmt.strip()))

    def _body_statement(self, label, operator, line):
        """The label and operator of a line of a body being collected.

        A label may be made with `&' there - `L&X:' is L1 and L2 in `IRP
        X,<1,2>' - and parse_line() does not read one: it takes the `L' of
        `L&X: ENDM' for the operation (or, with --dri, for a label, with no
        operation after it), so the ENDM did not end the IRP, and every line
        after it went into the body ("Unterminated IRP").  M80, MAC and RMAC
        end it there.
        """
        if '&' in line:
            m = re.match(r'\s*([$A-Za-z_@?&][A-Za-z0-9_@?$.&]*)::?(\s.*)?$', line)
            if m and '&' in m.group(1):
                return m.group(1), self.parse_line('\t' + (m.group(2) or ''))[1]
        return label, operator

    def _endm_label(self, label, body):
        """A label on the ENDM that ends a body being collected.

        MAC and RMAC define it where the body ends, each time it is
        expanded or repeated: DRI's CONTROL/STACK.LIB ends SIZ with `STACK:
        ENDM' (a LOCAL name, the stack top), COMPARE.LIB's GTR with `FL:
        ENDM', SEQIO.LIB's FILLFCB with `PFCB: ENDM'.  With --dri it goes at
        the end of the body.  MACRO-80 3.44 ignores it (a reference to it is
        U), and so does um80 without --dri.
        """
        if label and self.dri:
            body.append(label + ':')

    def _process_single_statement(self, line):
        """Process a single statement (internal helper for ! separator support)."""
        label, operator, operands, comment = self.parse_line(line)
        if self.collecting_macro is not None or self.repeat_stack:
            label, operator = self._body_statement(label, operator, line)
        upper_op = operator.upper() if operator else ''

        # If collecting macro definition, handle specially
        if self.collecting_macro is not None:
            # Strip ;; comments (not preserved in macro expansion)
            line_for_macro = line
            dbl_semi_pos = line_for_macro.find(';;')
            if dbl_semi_pos >= 0:
                # Make sure it's not inside a string
                in_string = False
                string_char = None
                for i, ch in enumerate(line_for_macro):
                    if i >= dbl_semi_pos:
                        break
                    if in_string:
                        if ch == string_char:
                            in_string = False
                    elif ch in "'\"":
                        in_string = True
                        string_char = ch
                if not in_string:
                    line_for_macro = line_for_macro[:dbl_semi_pos]

            if upper_op == 'MACRO':
                # Nested macro definition
                self.macro_nest_depth += 1
                self.macro_body.append(line_for_macro)
            elif upper_op in ('REPT', 'IRP', 'IRPC'):
                # REPT/IRP/IRPC also use ENDM, so track nesting
                self.macro_nest_depth += 1
                self.macro_body.append(line_for_macro)
            elif upper_op == 'ENDM':
                if self.macro_nest_depth > 0:
                    self.macro_nest_depth -= 1
                    self.macro_body.append(line_for_macro)
                else:
                    # End of macro definition
                    self._endm_label(label, self.macro_body)
                    self.macros[self.collecting_macro] = Macro(
                        self.collecting_macro, self.macro_params, self.macro_body
                    )
                    self.collecting_macro = None
                    self.macro_params = []
                    self.macro_body = []
            else:
                self.macro_body.append(line_for_macro)
            return

        # If collecting REPT/IRP/IRPC body, handle specially
        if self.repeat_stack:
            if upper_op in ('REPT', 'IRP', 'IRPC'):
                # Nested repeat: keep the directive line verbatim in the outer
                # body and just count the nesting depth. The nested block is
                # re-collected and executed when execute_repeat replays the
                # outer body, so its own body must NOT be discarded here.
                self.repeat_stack[-1][2].append(line)
                self.repeat_nest_depth += 1
            elif upper_op == 'ENDM':
                if self.repeat_nest_depth > 0:
                    # ENDM of a nested block - keep it in the outer body.
                    self.repeat_nest_depth -= 1
                    self.repeat_stack[-1][2].append(line)
                else:
                    # ENDM of the outer block - execute it.
                    rept_type, param_or_count, body, iter_var, rept_label = self.repeat_stack.pop()
                    self._endm_label(label, body)
                    self.execute_repeat(rept_type, param_or_count, body, iter_var)
            else:
                self.repeat_stack[-1][2].append(line)
            return

        # Handle conditional directives even in false blocks
        if upper_op in ('IF', 'IFT', 'IFE', 'IFF', 'IFDEF', 'IFNDEF',
                        'IF1', 'IF2', 'IFB', 'IFNB', 'IFIDN', 'IFDIF',
                        'COND', 'ELSE', 'ENDIF', 'ENDC'):
            self.assemble_pseudo_op(operator, operands, label)
            self._save_listing_entry(line)
            return

        if self.cond_false_depth > 0:
            self._save_listing_entry(line)
            return

        # A labelled Z80 `SET bit,reg' is the instruction: the SET directive
        # takes one operand.  (`X1: SET 7,(IX+1)' was "SET requires one
        # operand"; M80 assembles DD CB 01 FE.)
        z80_set = (self.z80_mode and upper_op == 'SET' and label
                   and len(self.split_operands(operands or '')) == 2)

        # Define label if present
        if label and (z80_set or upper_op not in
                      ('EQU', 'SET', 'DEFL', 'ASET', 'MACRO')):
            self.define_value(label, self.here())

        if not operator:
            if operands:
                # A statement that starts with a value: `5,6', `'AB''.
                self.statement_of_values(None, operands)
            self._save_listing_entry(line)
            return

        # In Z80 mode, SET with a label is the directive, not the instruction
        # (Z80 SET instruction is "SET bit,reg" which doesn't have a label)
        # ASET is always a directive (no Z80 instruction conflict)
        if self.z80_mode and upper_op in ('SET', 'ASET') and label \
                and not z80_set:
            if self.assemble_pseudo_op(operator, operands, label):
                self._save_listing_entry(line)
                return

        # A user macro shadows a built-in instruction or pseudo-op of the same
        # name (M80 resolves the macro table before the instruction/pseudo-op
        # tables). Checked after the SET/ASET directive disambiguation above.
        if upper_op in self.macros:
            self.expand_macro(upper_op, operands)
            self._save_listing_entry(line)
            return

        # Try CPU instruction
        if self.z80_mode:
            if self.assemble_z80_instruction(operator, operands):
                self._save_listing_entry(line)
                return
        else:
            if self.assemble_instruction(operator, operands):
                self._save_listing_entry(line)
                return

        # Try pseudo-op
        if self.assemble_pseudo_op(operator, operands, label):
            self._save_listing_entry(line)
            return

        self.statement_of_values(operator, operands,
                                 column_one=not line[:1].isspace())
        self._save_listing_entry(line)

    def statement_of_values(self, word, rest, column_one=False):
        """A statement whose first word, `word' (None if it starts with
        something else), is no instruction, directive or macro.

        MACRO-80 3.44 assembles it as a DB of the whole statement: after
        `FOO EQU 5', `FOO' is the byte 05, `FOO+1,'AB'' is 06 41 42 and
        `LAB: 5,6' is 05 06.  um80 left out a statement that started with a
        value, without a word.  It warns, as M80 does not: M80 takes a
        mistyped mnemonic or a label with no colon for a value too (`LAB
        DS 1' is U, and one byte).  --dri reads the source as MAC and RMAC
        do, which assemble no such statement (S) - a word there is a label
        (parse_line()).
        """
        text = f"{word} {rest}".strip() if word else rest
        shown = text if len(text) <= 40 else text[:37] + '...'
        errors = len(self.errors)
        # An instruction of the other processor (`OR A' before .Z80) is not
        # a value, but for a symbol of that name: say so now, not in pass 2
        # (the operator OR with nothing in front of it is only reported
        # there).
        other = word in (INSTRUCTIONS_8080 if self.z80_mode else INSTRUCTIONS_Z80) \
            and not self.names_symbol(word)
        if not self.dri and not text.startswith('*') and not other:
            self.assemble_pseudo_op('DB', text, None)
            if len(self.errors) == errors:
                if self.pass_num == 2:
                    self.warning(f"'{shown}' is no instruction, directive or "
                                 f"macro: it is assembled as DB {shown}, as in M80")
                return
            cause = self.errors[errors].message
            del self.errors[errors:]
        else:
            cause = ''
        if word is None:
            # `LAB: 5,FOO' with no FOO: say so.
            hint = f" ({cause})" if cause.startswith('Undefined symbol') else ''
            if not self.dri and text.startswith('*'):
                hint = (" (a comment starts with ';': MAC's '*' comment lines"
                        " are read with --dri)")
            elif not self.dri and LINE_NUMBER.match(text):
                hint = " (MAC's line numbers are read with --dri)"
            self.error(f"'{shown}' is not an instruction, directive or macro, "
                       f"nor values to assemble{hint}")
            return
        hint = ''
        after = NAME_WORD.match(rest or '')
        if not self.dri and (after and self.is_operation(after.group(1))
                             or not rest and column_one):
            hint = (" (a label needs a colon, as in M80: MAC's labels"
                    " without one are read with --dri)")
        elif word in (INSTRUCTIONS_8080 if self.z80_mode else INSTRUCTIONS_Z80):
            hint = (" (an 8080 instruction: .8080 assembles 8080 mnemonics)"
                    if self.z80_mode else
                    " (a Z80 instruction: .Z80 assembles Z80 mnemonics)")
        self.error(f"Unknown instruction or directive: {word}{hint}")

    def process_macro_argument(self, arg):
        """Process a macro argument, handling angle brackets and ! operator.

        A '!' quotes the next character, except inside a quoted string,
        where it is itself: M80 reads `<'Hi!'>' as 'Hi!' - in a macro call
        and in an IRP list - and um80 dropped the '!'.
        """
        # Strip outer angle brackets (used to preserve special chars in arglist)
        if arg.startswith('<') and arg.endswith('>'):
            arg = arg[1:-1]
        # Process ! operator (makes next character literal)
        result = []
        i = 0
        while i < len(arg):
            if arg[i] == '!' and i + 1 < len(arg):
                # ! makes next character literal
                result.append(arg[i + 1])
                i += 2
            elif self._starts_string(arg, i):
                end = self._string_end(arg, i)
                result.append(arg[i:end])
                i = end
            else:
                result.append(arg[i])
                i += 1
        return ''.join(result)

    def _string_spans(self, line):
        """Return (start, end) index spans of quoted '...'/"..." literals.

        Honors M80 doubled-quote ('') escapes. A "'" preceded by an
        alphanumeric is not treated as a string start (Z80 AF' register, the
        same rule used by parse_line/split_operands).
        """
        spans = []
        i = 0
        n = len(line)
        while i < n:
            c = line[i]
            if c == "'" and i > 0 and line[i - 1].isalnum():
                i += 1
                continue
            if c in "'\"":
                q = c
                start = i
                i += 1
                while i < n:
                    if line[i] == q:
                        if i + 1 < n and line[i + 1] == q:
                            i += 2  # doubled quote = escaped, stays in string
                            continue
                        i += 1  # closing quote
                        break
                    i += 1
                spans.append((start, i))
            else:
                i += 1
        return spans

    def substitute_macro_params(self, line, subst):
        """`line' with each name in `subst' replaced by its text.

        A body line is read as MACRO-80 - or with --dri MAC - reads it: a
        run of name characters (M80_NAME_CHARS, DRI_NAME_CHARS) is one
        name, and only a name that is a parameter is replaced.  With the
        parameter ?Y, `'&?Y'' and `ADC&?C' are replaced (um80 used to miss
        any parameter that starts with `?' or `@'), and with X, `?X' and
        `X?' are other names; `1X' is 1 then X, as in M80 and MAC (15 after
        `MM 5').  Outside a quoted string a name is replaced wherever it
        is, and an `&' next to it on either side is dropped: `A&X' and
        `X&B'.  Names fold case.

        Inside a string only a name next to an `&' is a parameter.  In M80
        that is one after the `&' (`'&X'', `'A&X''), and M80 drops the `&'
        only in the first one, and in a chain `&X&Y' right after it: `'&X
        &X'' is 'K &K', `'&X&Y'' KL.  In MAC a name before an `&' is one
        too (`'X&B'' is KB), and every such `&' goes.  Names fold case here
        too, as in M80 and RMAC 1.1; MAC 2.0 matches a string as written,
        so `'&abc'' is not its parameter ABC.

        A LOCAL name is in subst too, with its unique name: M80 and MAC read
        it as a parameter, so `'&L'' is the unique name, `L?:' with LOCAL
        L? is one, and an argument's text is not matched again (`MM LL'
        with LOCAL LL and `DB P' is the LL outside the macro).
        """
        table = {name.upper(): text for name, text in subst.items() if name}
        if not table:
            return line
        out = []
        pos = 0
        for (s, e) in self._string_spans(line):
            out.append(self._substitute_names(line[pos:s], table))
            out.append(self._substitute_in_string(line[s:e], table))
            pos = e
        out.append(self._substitute_names(line[pos:], table))
        return ''.join(out)

    def _name_end(self, text, i):
        """The end of the name that starts at text[i], or None."""
        start, chars = ((DRI_NAME_START, DRI_NAME_CHARS) if self.dri
                        else (M80_NAME_START, M80_NAME_CHARS))
        if text[i] not in start:
            return None
        j = i + 1
        while j < len(text) and text[j] in chars:
            j += 1
        return j

    def _substitute_names(self, text, table):
        """substitute_macro_params() outside a quoted string."""
        res = []
        amp = False  # the last thing copied is an `&'
        i, n = 0, len(text)
        while i < n:
            j = self._name_end(text, i)
            if j is None:
                amp = text[i] == '&'
                res.append(text[i])
                i += 1
                continue
            value = table.get(text[i:j].upper())
            if value is None:
                res.append(text[i:j])
            else:
                if amp:
                    res.pop()
                res.append(value)
                if j < n and text[j] == '&':
                    j += 1
            amp = False
            i = j
        return ''.join(res)

    def _substitute_in_string(self, text, table):
        """substitute_macro_params() in a quoted string, quotes and all."""
        res = []
        amp = False   # the last thing copied is an `&'
        chain = -1    # where a name's dropped `&' after it leads
        first = True  # M80: no `&' dropped yet
        i, n = 0, len(text)
        while i < n:
            j = self._name_end(text, i)
            if j is None:
                if chain == i:
                    first = False
                amp = text[i] == '&'
                res.append(text[i])
                i += 1
                continue
            word = text[i:j]
            value = table.get(word.upper())
            before, amp = amp, False
            chained = chain == i
            after = j < n and text[j] == '&'
            if value is None or not (before or chained or (self.dri and after)):
                if chained:
                    first = False
                res.append(word)
            elif self.dri or first:
                if before:
                    res.pop()
                res.append(value)
                if after:
                    j += 1
                    chain = j
                else:
                    first = False
            else:
                res.append(value)
            i = j
        return ''.join(res)

    def percent_argument(self, arg):
        """A macro argument with its `%expression' replaced by the value.

        `%' makes an argument a value: the expression after it is
        evaluated when the macro is called, and the argument is the value's
        digits in the current radix, as MACRO-80 writes them: with .RADIX
        16 26 is 1A and 160 is 0A0 (a 0 before a letter, and no H), with
        .RADIX 8 it is 32, and in any other radix decimal - 26, even with
        .RADIX 2.  MAC has only decimal.  The expression runs to the end of
        the argument, blanks and all (`%(A + 1)', `% A').  MAC and M80 both
        evaluate it at the call: `GEN %E' passes E's value then, however
        the body changes E, and a call in a REPT body inside a macro is
        evaluated on each repetition - DRI's SELECT.LIB counts its cases so.
        The digits substitute like any other text, so `LB&N:' is LB10 and
        `DB '&N'' is '10'.  In M80 the `%' may follow other text (`A%E' is
        A7); in MAC and RMAC (--dri) only an argument that starts with `%'
        is a value, and --dri reads a name in the expression without its
        `$', so `%N$C' is the value of NC.  An argument in <...> is text,
        as is a `%' after `!' or in a quoted string.
        """
        i = self._percent_position(arg)
        if i is None or not arg[i + 1:].strip():
            return arg
        expr = arg[i + 1:]
        if self.dri:
            expr = drop_name_dollars(expr)
        # An undefined name is an error, as in M80 and MAC (U), where it
        # was a silent 0; pass 1 reads a forward reference as 0 or as its
        # predicted value (forward_value()).
        value = self.number_operand(expr, 'The % operator',
                                    allow_undefined=(self.pass_num == 1)
                                    ).value & 0xFFFF
        if self.radix == 16:
            text = f'{value:X}'
            text = '0' + text if text[0] > '9' else text
        elif self.radix == 8:
            text = f'{value:o}'
        else:
            text = str(value)
        return arg[:i] + text

    def _percent_position(self, arg):
        """Where the `%' that makes `arg' a value is, or None."""
        if self.dri:
            return 0 if arg.startswith('%') else None
        i = 0
        while i < len(arg):
            ch = arg[i]
            if ch == '<':
                return None
            if ch == '!':
                i += 2
                continue
            if self._starts_string(arg, i):
                i = self._string_end(arg, i)
                continue
            if ch == '%':
                return i
            i += 1
        return None

    def expand_macro(self, name, operands):
        """Expand a macro."""
        macro = self.macros.get(name)
        if not macro:
            self.error(f"Undefined macro: {name}")
            return

        # Parse actual arguments, handling ! operator. '!' quotes the next
        # character (including an argument-separating comma), so split with
        # escape_bang and let process_macro_argument() resolve the escapes.
        # A `%expression' is evaluated now, at the call (percent_argument()).
        args = []
        if operands:
            raw_args = self.split_operands(operands, escape_bang=True)
            args = [self.process_macro_argument(self.percent_argument(arg))
                    for arg in raw_args]

        # Build substitution map
        subst = {}
        for i, param in enumerate(macro.params):
            if i < len(args):
                subst[param] = args[i]
            else:
                subst[param] = ''  # Missing args become empty

        # Generate unique local symbol suffix
        self.local_counter += 1
        local_suffix = f'?{self.local_counter:04d}'

        # Track local symbols declared in this expansion
        local_syms = set()

        # Expand body lines with parameter substitution
        self.macro_level += 1
        cond_depth = len(self.cond_stack)
        for body_line in macro.body:
            if self.ended:
                break
            # Check for LOCAL directive
            label, op, opnds, comment = self.parse_line(body_line)
            if op and op.upper() == 'LOCAL':
                # Add these symbols to local set
                if opnds:
                    for sym in opnds.split(','):
                        # --dri: MAC reads a LOCAL name as a name, and the
                        # body line is still as written (_dri_statement()).
                        sym = drop_name_dollars(sym) if self.dri else sym
                        local_syms.add(sym.strip().upper())
                continue
            if (op and op.upper() == 'EXITM' and self.cond_false_depth == 0
                    and not self.repeat_stack and self.collecting_macro is None):
                # Exit macro expansion early. Ignored inside a false conditional
                # branch (the canonical IF cond / EXITM / ENDIF idiom), and in
                # a REPT/IRP/IRPC body being collected: that EXITM ends the
                # repeat when it runs, not the macro now.  It ends the IFs
                # of the expansion too - their ENDIFs are not read.
                self.end_conditionals(cond_depth)
                break

            # Parameters and LOCAL names, in one pass, as M80 reads a LOCAL
            # name as a parameter: an argument's text is not read again.
            names = {sym: sym + local_suffix for sym in local_syms}
            names.update(subst)
            expanded = self.substitute_macro_params(body_line, names)

            # M80 goes round an IRPC once, with its parameter empty, when an
            # empty argument made its string empty (`IRPC C,P' with P
            # empty), though not for `IRPC C,' or `IRPC C,<>' as written.
            self.irpc_from_argument = (
                op == 'IRPC' and self._irpc_string(opnds) not in ('', '<>')
                and self._irpc_string(self.parse_line(expanded)[2]) in ('', '<>'))

            # Process the expanded line
            try:
                self.process_line(expanded)
            finally:
                self.irpc_from_argument = False
        if self.dri:
            # MAC and RMAC end the IFs a body leaves open at its ENDM (M80
            # carries them on).
            self.end_conditionals(cond_depth)

        self.macro_level -= 1

    @staticmethod
    def _irpc_string(operands):
        """The text after the comma of an IRPC's operands, stripped."""
        return (operands or '').partition(',')[2].strip()

    def execute_repeat(self, rept_type, param_or_count, body, iter_var):
        """Execute a REPT/IRP/IRPC block."""
        if rept_type == 'REPT':
            count = param_or_count
            for i in range(count):
                if self._run_repeat_iteration(body, iter_var, None):
                    break

        elif rept_type == 'IRP':
            for value in param_or_count:
                # An item is read like a macro argument: M80 strips one level
                # of angle brackets from it, and '!' quotes a character.
                value = self.process_macro_argument(value)
                if self._run_repeat_iteration(body, iter_var, value):
                    break

        elif rept_type == 'IRPC':
            for char in param_or_count:
                if self._run_repeat_iteration(body, iter_var, char):
                    break

    def _run_repeat_iteration(self, body, iter_var, value):
        """Run one iteration of a repeat body, substituting iter_var with value.

        Returns True if EXITM terminated the expansion (so the caller stops
        iterating). EXITM is honored only at this level (not while a nested
        repeat is being collected) and not inside a false conditional branch.
        """
        cond_depth = len(self.cond_stack)
        for line in body:
            if self.ended:
                return True
            expanded = line
            if iter_var and value is not None:
                # As a macro's parameter (substitute_macro_params()): in a
                # string only next to an `&', and `?X' is another name.
                expanded = self.substitute_macro_params(line, {iter_var: value})
            if not self.repeat_stack and self.cond_false_depth == 0:
                _, op, _, _ = self.parse_line(expanded)
                if op and op.upper() == 'EXITM':
                    self.end_conditionals(cond_depth)
                    return True
            self.process_line(expanded)
        if self.dri:
            self.end_conditionals(cond_depth)
        return False

    def end_conditionals(self, depth):
        """End the IFs opened since the conditional stack was `depth' deep.

        An EXITM ends a macro expansion or a repetition inside the IFs it
        opened, and their ENDIFs are never read: `IF 1 / EXITM / ENDIF' left
        its IF open to the end of the file ("Unterminated conditional"),
        where MACRO-80 3.44, MAC 2.0 and RMAC 1.1 close it without a word.
        The expansion began in a true state, so every IF above `depth' is
        true, or the EXITM would have been skipped.

        MAC and RMAC also end the IFs a body leaves open at its end, true
        or false, and with --dri so does um80, after each expansion and
        each repetition.  DRI's libraries leave them so: COMPARE.LIB's
        TEST? ends `IF ... / ELSE / LXI H,Y / SUB M' with its ENDM, and
        SEQIO.LIB's `IRPC ?C,FN / IF NOT (...) / @C SET 0 / ENDM' opens one
        IF each time round.  M80 carries them on past the ENDM (a false
        one skips the rest of the file) and says "Unterminated
        Conditional"; without --dri um80 does the same.
        """
        if len(self.cond_stack) > depth:
            del self.cond_stack[depth:]
            self.cond_else_levels = {level for level in self.cond_else_levels
                                     if level <= depth}
            self.cond_false_depth = 0

    def find_include_file(self, filename):
        """Find an include file, searching in various locations."""
        # Add default extension if none present
        if '.' not in filename:
            filename = filename + '.MAC'

        # Try the filename as-is if absolute
        if os.path.isabs(filename):
            if os.path.exists(filename):
                return filename
            return None

        # Try relative to base path (source file directory)
        if self.base_path:
            path = os.path.join(self.base_path, filename)
            if os.path.exists(path):
                return path

        # Try relative to current directory
        if os.path.exists(filename):
            return filename

        # Try additional include paths
        for inc_path in self.include_paths:
            path = os.path.join(inc_path, filename)
            if os.path.exists(path):
                return path

        return None

    def process_include_file(self, filepath, library=False):
        """Process an include file.

        An END in it ends the source, as in MACRO-80, which reads a MACLIB
        file as an INCLUDE file.  With --dri, a MACLIB file (`library') is
        MAC's and RMAC's library: its END ends the library, and the source
        goes on after the MACLIB; the address on that END is not the start
        address (RMAC's REL has none).  Without --dri um80 warns, as the
        rest of a DRI source is then left out, without a word from M80.
        """
        # Save current state
        saved_line_num = self.line_num
        saved_entry_point = self.entry_point

        # Push onto include stack
        self.include_stack.append((filepath, saved_line_num))

        try:
            # Read the include file
            with open(filepath, 'rb') as f:
                lines = source_lines(f.read())

            # Reset line number for include file
            self.line_num = 0

            # Process each line
            for line in lines:
                if self.ended:
                    break
                self.process_line(line)

        except IOError as e:
            self.error(f"Error reading include file {filepath}: {e}")

        finally:
            # Pop from include stack and restore line number
            self.include_stack.pop()
            self.line_num = saved_line_num

        if library and self.ended:
            if self.dri:
                self.ended = False
                self.entry_point = saved_entry_point
            elif self.pass_num == 2:
                self.warning(f"END in MACLIB file {os.path.basename(filepath)}"
                             " ends the source, as in M80; MAC and RMAC go on"
                             " after the MACLIB (--dri)")

    def assemble_pass(self, lines, pass_num):
        """Run one pass of assembly."""
        self.pass_num = pass_num
        self.line_num = 0
        self.cond_stack = []
        self.cond_false_depth = 0
        self.cond_else_levels = set()
        self.radix = 10  # Default radix resets each pass (a .RADIX re-applies)
        self.set_count = {}
        # Same reasoning as the radix: a .Z80/.8080 re-applies on every
        # pass, so the mode must start each pass at the default.  Left
        # over from the previous pass, a .Z80 anywhere in the file made
        # pass 2 assemble the lines ABOVE it as Z80 -- `JP addr` silently
        # became C3 instead of the 8080 F2 (jump if positive), and `CP n`
        # became a two-byte FE instead of a three-byte F4, which moves
        # every label after it.  Exit 0, no diagnostic.
        self.z80_mode = False
        self.repeat_nest_depth = 0
        # A MACRO, REPT, IRP or IRPC left open by the last pass must not
        # swallow this one's lines as well.
        self.repeat_stack = []
        self.repeat_line_tail = None
        self.collecting_macro = None
        self.macro_params = []
        self.macro_body = []
        self.macro_nest_depth = 0
        self.phase = None

        # Reset segment locations for pass 2
        if pass_num == 2:
            for seg in self.segments.values():
                seg.loc = seg.size = seg.mark = 0
            for com in self.common_blocks.values():
                com.loc = 0
                com.size = 0
            self.current_seg = self.default_seg
            self.current_common = None
            self.rel_common = None  # no COMMON block selected in the .REL yet

        self.ended = False
        for line in lines:
            if self.ended:
                break
            self.process_line(line)

        # An IF/IFx/COND left open at end of pass is an error (M80 reports
        # "Unterminated Conditional"). Report once, on the final pass.
        if self.cond_stack and pass_num == 2:
            self.warning("Unterminated conditional (missing ENDIF)")
        # So is a MACRO, REPT, IRP or IRPC with no ENDM: every line after it
        # became its body, and none of them was assembled.  M80 says
        # "Unterminated REPT/IRP/IRPC/MACRO".
        if pass_num == 2 and (self.repeat_stack or self.collecting_macro is not None):
            kind = (f"MACRO {self.collecting_macro}" if self.collecting_macro is not None
                    else self.repeat_stack[-1][0])
            self.warning(f"Unterminated {kind} (line {self.block_open_line}): no ENDM,"
                         " so nothing after it was assembled")

    def write_listing(self, filepath):
        """Write the listing file."""
        with open(filepath, 'w') as f:
            for entry in self.listing_lines:
                line_num = entry['line_num']
                addr = entry['addr']
                code_bytes = entry['bytes']
                source = entry['source']

                # Format: line_num  addr  bytes  source
                # Line number: 5 chars right-aligned
                # Address: 4 hex digits (or blank if no code)
                # Bytes: up to 4 bytes shown (8 hex chars with spaces)

                marks = entry.get('marks', {})

                if code_bytes:
                    addr_str = f"{addr:04X}"
                    # Show up to 4 bytes on first line
                    bytes_str = self._listing_cells(code_bytes, marks, 0)
                else:
                    addr_str = "    "
                    bytes_str = " " * 12

                f.write(f"{line_num:5d}  {addr_str}  {bytes_str}  {source}\n")

                # If more than 4 bytes, show continuation lines
                for first in range(4, len(code_bytes), 4):
                    bytes_str = self._listing_cells(code_bytes, marks, first)
                    f.write(f"       {addr + first:04X}  {bytes_str}\n")

    @staticmethod
    def _listing_cells(code_bytes, marks, first):
        """The byte column for code_bytes[first:first+4]: each byte, then
        its mark or a space - a field the linker finishes ends in ' " ! or
        * (M80's marks)."""
        return ''.join(f"{code_bytes[i]:02X}{marks.get(i, ' ')}"
                       for i in range(first, min(first + 4, len(code_bytes)))
                       ).rstrip().ljust(12)

    def assemble(self, source_file, pre_items=None):
        """Assemble a source file.

        Args:
            source_file: Path to the main source file
            pre_items: List of (type, value) tuples where type is 'e' for inline code
                      or 'pre' for pre-include file. Processed in order before main source.
        """
        # Set base path for include file resolution
        self.base_path = os.path.dirname(os.path.abspath(source_file))

        # Process pre-items (inline code and pre-include files)
        pre_lines = []
        if pre_items:
            for item_type, item_value in pre_items:
                if item_type == 'e':
                    # Inline code - split on ! for multiple statements (DRI notation)
                    statements = item_value.split('!')
                    pre_lines.extend(statements)
                elif item_type == 'pre':
                    # Pre-include file - read and add its lines
                    filepath = self.find_include_file(item_value)
                    if filepath is None:
                        self.error(f"Pre-include file not found: {item_value}")
                        return False
                    try:
                        with open(filepath, 'rb') as f:
                            pre_lines.extend(source_lines(f.read()))
                    except IOError as e:
                        self.error(f"Cannot read pre-include file {filepath}: {e}")
                        return False

        # Read source - handle CP/M format (CR/LF, ^Z EOF, 128-byte records)
        with open(source_file, 'rb') as f:
            lines = pre_lines + source_lines(f.read())
        self.source_lines = lines

        # Pass 1: Build symbol table (iterate until JR/DJNZ promotions stabilize)
        # We need multiple iterations because:
        # - Iteration 0: Build symbol table; can't check JR range (forward refs undefined)
        # - Iteration 1+: Use symbol table from previous iteration for range checking
        # - Keep iterating until no new promotions (sizes stabilize)
        #
        # The table must also settle: an EQU (or anything else) whose value
        # depends on a symbol defined further down reads, the first time,
        # a 0 for that symbol, and from then on the value prev_defs gives it
        # (forward_value()); pass 1 is over when that is the value the pass
        # computes, which is also what pass 2 reads above the defining line.
        # prev_defs is each symbol's value at the end of the previous time
        # through, with each EQU and SET evaluated again in the order they
        # read each other (predict_forward_values()), so a chain of forward
        # references settles in one repeat.  After three such guesses that
        # were not what the pass then computed, prev_defs is only the values
        # at the end of the time before: a chain of N forward references
        # then settles after N repeats, so the limit on repeats grows with
        # the longest chain (it was a flat 64, and the 65th EQU of a longer
        # chain was reported as circular).  A chain that comes back to where
        # it started is an error, whether or not it ever settles: `X EQU Y /
        # Y EQU X' settled on 0 and assembled silently.
        slack = 64  # repeats beyond the EQU chains: labels, JR promotion
        prev_symbols = {}  # Symbol table from previous iteration for forward refs
        prev_defs = {}
        prev_keys = None
        prev_cycle = None
        iteration = 0
        guessed = misses = 0  # times a guess was read, and was wrong
        guessing = False
        while True:
            self.pass1_iteration = iteration  # Track iteration for JR range checking
            self.prev_symbols = prev_symbols  # Make available for JR range checking
            self.prev_defs = prev_defs
            # Reset state for pass 1
            for seg in self.segments.values():
                seg.loc = seg.size = seg.mark = 0
                seg.org = 0
                seg.org_set = False
            for com in self.common_blocks.values():
                com.loc = 0
                com.size = 0
            self.current_seg = self.default_seg
            self.current_common = None
            self.errors = []  # Clear errors between iterations
            self.local_counter = 0  # Reset LOCAL symbol counter for consistent naming
            self.def_deps = {}
            self.def_text = {}
            self.def_line = {}
            self.def_replay = {}
            self.def_value = {}
            # Clear symbol definitions (but keep promoted_jr)
            # We need to rebuild symbol table each time
            # since addresses change when JR->JP promotion happens
            self.symbols = {}
            for name, value in self.predefined.items():
                sym = Symbol(name, value, ADDR_ABSOLUTE, defined=True)
                self.symbols[name] = sym

            prev_promotions = len(self.promoted_jr)
            self.assemble_pass(lines, 1)

            if self.errors:
                return False

            # Save symbol table for next iteration
            prev_symbols = {name: (sym.value, sym.seg_type) for name, sym in self.symbols.items() if sym.defined}
            prev_defs = {name: self.symbol_value(sym)
                         for name, sym in self.symbols.items()
                         if sym.defined or sym.external}
            keys = {name: self.value_key(ev) for name, ev in prev_defs.items()}
            settled = keys == prev_keys
            unsettled = [] if settled or prev_keys is None else sorted(
                name for name in set(keys) | set(prev_keys)
                if keys.get(name) != prev_keys.get(name))
            prev_keys = keys
            if guessing and not settled:
                misses += 1

            # A circular definition, once it has settled or shows up twice
            # (the first time through, conditional assembly on a symbol
            # still undefined may have read other lines).
            cycle, depth, order = self.definition_graph()
            if cycle and (settled or frozenset(cycle) == prev_cycle):
                self.report_circular(cycle)
                return False
            prev_cycle = frozenset(cycle) if cycle else None

            # Always run at least 2 iterations:
            # - Iteration 0 builds symbol table (can't check range yet)
            # - Iteration 1 checks range with symbol values from iteration 0
            # After that, check if promotions have stabilized
            if (iteration >= 1 and len(self.promoted_jr) == prev_promotions
                    and settled):
                break  # Stable - no new promotions, no symbol still moving
            iteration += 1
            if iteration < slack + depth + guessed:
                guess = self.predict_forward_values(order, prev_defs) \
                    if misses < 3 and not cycle else None
                guessing = guess is not None
                if guessing:
                    guessed += 1
                    prev_defs = guess
                    prev_keys = {name: self.value_key(ev)
                                 for name, ev in guess.items()}
                continue
            if unsettled:
                for name in unsettled[:10]:
                    sym = self.symbols.get(name)
                    self.errors.append(AssemblerError(
                        f"Cannot resolve the value of '{name}': it was still "
                        f"changing after the source was read {iteration} "
                        f"times, so it depends on itself - through the "
                        f"address of a label that its own value moves (a DS,"
                        f" ORG or IF of a symbol defined further down)",
                        sym.line if sym else None))
                return False
            # Warn about promotions on last iteration
            self.warnings.append(f"Warning: JR/DJNZ promotion did not "
                                 f"stabilize after {iteration} iterations")
            break

        # Report promotions
        if self.promoted_jr and not self.strict_jr:
            self.warnings.append(f"Note: {len(self.promoted_jr)} JR/DJNZ instruction(s) promoted to JP due to range")

        if self.errors:
            return False

        # Pass 2: Generate code.  The body - code, data and everything
        # pass 2 writes as it goes - goes to a writer of its own, so the
        # module header can carry the segment and COMMON sizes pass 2
        # arrives at: LINK-80 3.44 needs a COMMON block's size before
        # anything refers to it ("?Loading Error"), and MACRO-80 writes the
        # sizes there.
        self.local_counter = 0  # Reset LOCAL symbol counter for pass 2
        self.output = RELWriter(truncate_symbols=self.truncate_symbols)
        self.ext_chains = {}

        # Entry symbols (PUBLIC symbols for library search), as pass 1 left
        # them: -g leaves out a link-time EQU.
        entry_names = [sym.name for sym in self.symbols.values()
                       if (sym.public or self.export_all_symbols) and sym.defined
                       and not (sym.link_expr is not None and not sym.public)]

        if self.default_seg == 'ASEG':
            # --aseg: the code before any ORG or segment directive is
            # absolute too.  The linker starts in CSEG, and loaded it there.
            # Held back like an ASEG directive's, so a source that starts
            # with an ORG does not say it loads at 0000H.
            self.output.defer_set_location(ADDR_ABSOLUTE, 0)
        self.assemble_pass(lines, 2)

        if self.errors:
            return False

        body = self.output
        self.output = RELWriter(truncate_symbols=self.truncate_symbols)
        name = self.module_name or self.title_name or Path(source_file).stem.upper()[:6]
        self.output.write_program_name(name)
        for entry_name in entry_names:
            self.output.write_entry_symbol(entry_name)

        # Segment and COMMON sizes, before the code, as MACRO-80 writes them
        # (a COMMON block's size is also the highest location reached in it:
        # the location at the end undercounts a block re-entered or ORGed
        # back).
        # An empty block gets its size too: MACRO-80 writes item 5 with 0,
        # and LINK-80 stops with '?Loading Error' at the SELECT_COMMON of a
        # block it was never given a size for.
        for cname, com in self.common_blocks.items():
            self.output.write_define_common_size(ADDR_ABSOLUTE, com.size,
                                                 cname if cname else ' ')
        cseg = self.segments['CSEG']
        dseg = self.segments['DSEG']
        cseg_size = cseg.extent()
        dseg_size = dseg.extent()
        # Item 10 even for no DSEG at all, as MACRO-80 writes it: without
        # it LINK-80 3.44 drops the constant of an item 9 in ASEG (`DW
        # EXT+1' there linked to EXT).
        self.output.write_define_data_size(dseg_size)
        if cseg_size > 0:
            self.output.write_define_program_size(cseg_size)
        self.output.append(body)

        # Finalize output
        # Write public symbol definitions
        # For relocatable symbols, subtract segment ORG so linker can add its base
        for sym in self.symbols.values():
            if (sym.public or self.export_all_symbols) and sym.defined:
                if sym.link_expr is not None:
                    # A public symbol is an address or a constant; this one
                    # is neither until the program is linked.  -g (export
                    # everything) just leaves it out.
                    if sym.public:
                        self.errors.append(AssemblerError(
                            f"PUBLIC {sym.name} cannot be exported: its value"
                            f" (defined at line {sym.line}) depends on where"
                            f" the linker puts a segment or on an external"
                            f" symbol, and a .REL public symbol can only"
                            f" carry an address or a constant",
                            sym.public_line or sym.line))
                    continue
                # Check if this is an external alias (EQU external+offset)
                if sym.ext_alias_base:
                    # Emit aliased entry point with special name format:
                    # "NEWNAME=EXTERNAL" or "NEWNAME=EXTERNAL+N"
                    if sym.ext_alias_offset != 0:
                        alias_name = f"{sym.name}={sym.ext_alias_base}+{sym.ext_alias_offset}"
                    else:
                        alias_name = f"{sym.name}={sym.ext_alias_base}"
                    # Use ADDR_ABSOLUTE with value 0 since actual value is determined at link time
                    self.output.write_define_entry_point(ADDR_ABSOLUTE, 0, alias_name)
                else:
                    value = sym.value
                    if sym.seg_type == ADDR_PROGRAM_REL and self.segments['CSEG'].org_set:
                        value -= self.segments['CSEG'].org
                    elif sym.seg_type == ADDR_DATA_REL and self.segments['DSEG'].org_set:
                        value -= self.segments['DSEG'].org
                    elif sym.seg_type == ADDR_COMMON_REL:
                        self.select_common(sym.common_block)
                    self.output.write_define_entry_point(sym.seg_type, value, sym.name)

        # Write external chains: a record of its own for every reference
        # (see emit_external_ref()).
        for name, refs in self.ext_chains.items():
            for seg, offset, block in refs:
                if seg == ADDR_COMMON_REL:
                    self.select_common(block)
                self.output.write_chain_external(seg, offset, name)
        # And, as MACRO-80 does, an empty chain (its head is absolute 0, where
        # LINK-80 chains end) for every other external: one declared and never
        # used, or used only in a link-time expression.  It is what tells the
        # linker the module needs the symbol, so that it searches a library
        # for it - `EXTRN X' alone pulls X's module out of a library - and
        # reports it if nothing defines it.
        for sym in self.symbols.values():
            if sym.external and not sym.defined and sym.name not in self.ext_chains:
                self.output.write_chain_external(ADDR_ABSOLUTE, 0, sym.name)

        # Write end with optional entry point
        if self.entry_point:
            val, seg = self.entry_point
            self.output.write_end_program(self._reloc_value(val, seg), seg)
        else:
            self.output.write_end_program()

        self.output.write_end_file()

        return not self.errors


class PreAction(argparse.Action):
    """Custom action to collect -e and --pre in order."""
    def __call__(self, parser, namespace, values, option_string=None):
        if not hasattr(namespace, 'pre_items') or namespace.pre_items is None:
            namespace.pre_items = []
        # Tag with 'e' for execute or 'pre' for pre-include
        tag = 'e' if option_string in ('-e', '--execute') else 'pre'
        namespace.pre_items.append((tag, values))


def main():
    parser = argparse.ArgumentParser(description='um80 - MACRO-80 compatible assembler')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('input', help='Input .MAC file')
    parser.add_argument('-o', '--output', help='Output .REL file')
    parser.add_argument('-l', '--listing', help='Listing .PRN file')
    parser.add_argument('-D', '--define', action='append', metavar='SYMBOL[=VALUE]',
                        help='Define symbol (can be used multiple times)')
    parser.add_argument('-I', '--include', action='append', metavar='PATH',
                        help='Add include search path (can be used multiple times)')
    parser.add_argument('-e', '--execute', action=PreAction, metavar='CODE',
                        help='Execute assembly code before source (can be repeated, use ! for multiple statements)')
    parser.add_argument('--pre', action=PreAction, metavar='FILE',
                        help='Include file before source (can be repeated)')
    parser.add_argument('-g', '--globals', action='store_true',
                        help='Export all symbols as PUBLIC (for debug symbol files)')
    parser.add_argument('-t', '--truncate', action='store_true',
                        help='Cut PUBLIC, EXTRN and module names to 6 characters, as M80 does')
    parser.add_argument('--aseg', action='store_true',
                       help='Assemble as absolute code, the way DRI\'s MAC does: '
                            'the file starts in ASEG, so ORG is an absolute address')
    parser.add_argument('--dri', action='store_true',
                        help='Read the source as DRI\'s MAC and RMAC do where they '
                             'differ from M80: a $ inside a name is ignored '
                             '(NMB$LST is NMBLST), a macro body is read with '
                             'MAC\'s names, an IF a macro body leaves open '
                             'ends with it, a label needs no colon, PUSH A is '
                             'PUSH PSW, and = < <= > >= <> are relations')
    parser.add_argument('-s', '--strict', action='store_true',
                        help='Strict mode: error on out-of-range JR/DJNZ instead of promoting to JP')

    args = parser.parse_args()

    # Determine output file name
    input_path = Path(args.input)
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_suffix('.rel')

    # Parse command line symbol definitions
    predefined = {}
    if args.define:
        for defn in args.define:
            if '=' in defn:
                name, val = defn.split('=', 1)
                try:
                    predefined[name.upper()] = int(val, 0)
                except ValueError:
                    predefined[name.upper()] = 1
            else:
                predefined[defn.upper()] = 1

    # Create assembler and run
    asm = Assembler(predefined=predefined, export_all_symbols=args.globals,
                    truncate_symbols=args.truncate, strict_jr=args.strict,
                    dri=args.dri)
    if args.aseg:
        asm.default_seg = 'ASEG'
        asm.current_seg = 'ASEG'
    if args.include:
        asm.include_paths = args.include
    if args.listing:
        asm.generate_listing = True
    pre_items = getattr(args, 'pre_items', None) or []
    success = asm.assemble(args.input, pre_items=pre_items)

    # Report errors and warnings
    for err in asm.errors:
        print(err.format_message(), file=sys.stderr)
    for warn in asm.warnings:
        print(warn, file=sys.stderr)

    if not success:
        sys.exit(1)

    # Write output
    with open(output_path, 'wb') as f:
        f.write(asm.output.get_bytes())

    # Write listing file if requested
    if args.listing:
        asm.write_listing(args.listing)

    cseg = asm.segments['CSEG']
    dseg = asm.segments['DSEG']
    cseg_size = cseg.extent()
    dseg_size = dseg.extent()

    print(f"Assembled {args.input} -> {output_path}")
    print(f"  Code segment: {cseg_size} bytes (ORG {cseg.org:04X}H)" if cseg.org_set else f"  Code segment: {cseg_size} bytes")
    print(f"  Data segment: {dseg_size} bytes")
    print(f"  Symbols: {len(asm.symbols)}")

    sys.exit(0)


if __name__ == '__main__':
    main()
