#!/usr/bin/env python3
"""
um80 - Microsoft MACRO-80 compatible assembler for Linux.

Usage: um80 [-o output.rel] [-l listing.prn] input.mac
"""

import sys
import os
import re
import argparse
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


class Symbol:
    """Symbol table entry."""
    def __init__(self, name, value=0, seg_type=ADDR_ABSOLUTE,
                 defined=False, public=False, external=False):
        self.name = name.upper()
        self.value = value
        self.seg_type = seg_type  # ADDR_ABSOLUTE, ADDR_PROGRAM_REL, etc.
        self.defined = defined
        self.public = public
        self.external = external
        self.references = []  # Line numbers where referenced


class Segment:
    """Code/data segment."""
    def __init__(self, name, seg_type):
        self.name = name
        self.seg_type = seg_type
        self.loc = 0  # Location counter
        self.org = 0  # Starting origin (first ORG or 0)
        self.org_set = False  # Whether org has been set
        self.size = 0  # High water mark
        self.data = bytearray()


class Macro:
    """Macro definition."""
    def __init__(self, name, params, body):
        self.name = name.upper()
        self.params = params  # List of parameter names
        self.body = body  # List of source lines


class Assembler:
    """MACRO-80 compatible assembler."""

    def __init__(self, predefined=None, export_all_symbols=False, truncate_symbols=False,
                 strict_jr=False):
        self.symbols = {}  # Symbol table
        self.export_all_symbols = export_all_symbols  # -g flag: export all as PUBLIC
        self.truncate_symbols = truncate_symbols  # -t flag: truncate symbols to 8 chars
        self.strict_jr = strict_jr  # --strict flag: error on out-of-range JR instead of promoting to JP
        self.promoted_jr = set()  # Line numbers where JR/DJNZ was promoted to JP
        self.macros = {}   # Macro definitions
        self.segments = {
            'ASEG': Segment('ASEG', ADDR_ABSOLUTE),
            'CSEG': Segment('CSEG', ADDR_PROGRAM_REL),
            'DSEG': Segment('DSEG', ADDR_DATA_REL),
        }
        self.common_blocks = {}  # COMMON blocks
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

        self.local_counter = 0  # For LOCAL symbols in macros
        self.expanding_macro = False
        self.macro_level = 0

        # Macro definition collection state
        self.collecting_macro = None  # Name of macro being defined
        self.macro_params = []  # Parameters of macro being defined
        self.macro_body = []  # Lines of macro being defined
        self.macro_nest_depth = 0  # For nested MACRO/ENDM

        # REPT/IRP/IRPC state
        self.repeat_stack = []  # Stack of (type, count/list, body, iter_var)

        self.entry_point = None  # END address if specified
        self.module_name = None

        # Save predefined symbols for pass iterations
        self.predefined = predefined or {}

        # Add predefined symbols from command line
        for name, value in self.predefined.items():
            sym = Symbol(name, value, ADDR_ABSOLUTE, defined=True)
            self.symbols[name] = sym

        # External reference chains
        self.ext_chains = {}  # name -> list of (seg, offset, expr_offset) references

        # Forward reference chains (for labels within module)
        self.fwd_chains = {}  # name -> list of (seg, offset) references

        self.output = RELWriter(truncate_symbols=truncate_symbols)
        self.listing_lines = []
        self.source_lines = []

        # Listing generation
        self.generate_listing = False
        self.current_line_bytes = []
        self.current_line_start_loc = 0
        self.current_line_start_seg = 'CSEG'

        # Include file handling
        self.include_stack = []  # Stack of (filename, line_num) for nested includes
        self.base_path = None  # Base path for resolving relative includes
        self.include_paths = []  # Additional search paths for includes

        # Processor mode
        self.z80_mode = False  # False = 8080 mode, True = Z80 mode

    @property
    def loc(self):
        """Current location counter."""
        if self.current_common:
            return self.common_blocks[self.current_common].loc
        return self.segments[self.current_seg].loc

    @loc.setter
    def loc(self, value):
        if self.current_common:
            self.common_blocks[self.current_common].loc = value
        else:
            self.segments[self.current_seg].loc = value

    @property
    def seg_type(self):
        """Current segment type."""
        if self.current_common:
            return ADDR_COMMON_REL
        return self.segments[self.current_seg].seg_type

    def error(self, msg):
        """Record an error."""
        self.errors.append(AssemblerError(msg, self.line_num))

    def warning(self, msg):
        """Record a warning."""
        self.warnings.append(f"Warning at line {self.line_num}: {msg}")

    def _start_listing_line(self):
        """Prepare for listing capture at start of line processing."""
        if self.pass_num == 2 and self.generate_listing:
            self.current_line_start_loc = self.loc
            self.current_line_start_seg = self.current_seg
            self.current_line_bytes = []

    def _save_listing_entry(self, line):
        """Save a listing entry for the current line."""
        if self.pass_num == 2 and self.generate_listing:
            self.listing_lines.append({
                'line_num': self.line_num,
                'addr': self.current_line_start_loc,
                'seg': self.current_line_start_seg,
                'bytes': self.current_line_bytes[:],
                'source': line
            })

    def define_symbol(self, name, value, seg_type=None, public=False):
        """Define or update a symbol."""
        name = name.upper()
        if seg_type is None:
            seg_type = self.seg_type

        if name in self.symbols:
            sym = self.symbols[name]
            if sym.defined and sym.value != value and not sym.external:
                if self.pass_num == 2:
                    self.error(f"Symbol '{name}' multiply defined")
                return
            sym.value = value
            sym.seg_type = seg_type
            sym.defined = True
            if public:
                sym.public = True
        else:
            self.symbols[name] = Symbol(name, value, seg_type, defined=True, public=public)

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
        """Parse character constant like 'A' or 'AB'."""
        if len(s) >= 2 and s[0] in "'\"" and s[-1] == s[0]:
            chars = s[1:-1]
            if len(chars) == 1:
                return (ord(chars), True)
            elif len(chars) == 2:
                return (ord(chars[0]) | (ord(chars[1]) << 8), True)
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
                                # Word operator - needs boundaries
                                before_ok = (start == 0 or not expr[start-1].isalnum())
                                after_ok = (i+1 >= len(expr) or not expr[i+1].isalnum())
                                if before_ok and after_ok:
                                    return (start, len(op))
                            else:
                                # Symbol operator
                                return (start, len(op))
            i -= 1
        return (-1, 0)

    def parse_expression(self, expr, allow_undefined=False):
        """
        Parse an expression, return (value, seg_type, is_external, ext_name).
        Uses recursive descent with proper precedence and parenthesis handling.
        """
        expr = expr.strip()
        if not expr:
            return (0, ADDR_ABSOLUTE, False, None)

        # Handle special symbols
        if expr == '$':
            return (self.loc, self.seg_type, False, None)

        # Handle unary operators first
        upper = expr.upper()

        # NUL operator - returns true (0FFFFh) if argument is null/empty
        if upper.startswith('NUL '):
            arg = expr[4:].strip()
            if not arg or arg == '<>' or arg == "''":
                return (0xFFFF, ADDR_ABSOLUTE, False, None)
            return (0, ADDR_ABSOLUTE, False, None)

        # DRI extension: HIGH(expr) and LOW(expr) function-call syntax
        if upper.startswith('HIGH(') and expr.endswith(')'):
            # Find matching closing paren
            inner = expr[5:-1]  # Extract content between HIGH( and )
            val, seg, ext, name = self.parse_expression(inner, allow_undefined)
            return ((val >> 8) & 0xFF, ADDR_ABSOLUTE, ext, name)
        if upper.startswith('LOW(') and expr.endswith(')'):
            inner = expr[4:-1]  # Extract content between LOW( and )
            val, seg, ext, name = self.parse_expression(inner, allow_undefined)
            return (val & 0xFF, ADDR_ABSOLUTE, ext, name)
        # Original M80 syntax: HIGH expr and LOW expr (with space)
        if upper.startswith('HIGH '):
            val, seg, ext, name = self.parse_expression(expr[5:], allow_undefined)
            return ((val >> 8) & 0xFF, ADDR_ABSOLUTE, ext, name)
        if upper.startswith('LOW '):
            val, seg, ext, name = self.parse_expression(expr[4:], allow_undefined)
            return (val & 0xFF, ADDR_ABSOLUTE, ext, name)
        if upper.startswith('NOT '):
            val, seg, ext, name = self.parse_expression(expr[4:], allow_undefined)
            return ((~val) & 0xFFFF, ADDR_ABSOLUTE, False, None)

        # TYPE operator - returns byte describing expression characteristics
        # Lower 2 bits: mode (0=abs, 1=prog rel, 2=data rel, 3=common rel)
        # Bit 5 (20H): defined
        # Bit 7 (80H): external
        if upper.startswith('TYPE '):
            arg = expr[5:].strip()
            # Check if it's a valid symbol
            if re.match(r'^[A-Za-z_@?][A-Za-z0-9_@?$.]*$', arg):
                sym = self.symbols.get(arg.upper())
                if sym:
                    result = sym.seg_type & 0x03  # Mode bits
                    if sym.defined:
                        result |= 0x20
                    if sym.external:
                        result |= 0x80
                    return (result, ADDR_ABSOLUTE, False, None)
            # If not a symbol or not found, return 0
            return (0, ADDR_ABSOLUTE, False, None)

        # Handle unary minus at start (but not subtraction)
        if expr.startswith('-') and len(expr) > 1:
            val, seg, ext, name = self.parse_expression(expr[1:], allow_undefined)
            return ((-val) & 0xFFFF, seg, ext, name)

        # Handle unary plus at start
        if expr.startswith('+') and len(expr) > 1:
            return self.parse_expression(expr[1:], allow_undefined)

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
                            return self.parse_expression(expr[1:-1], allow_undefined)
                        else:
                            # Parens close before end, not fully wrapped
                            break

        # Lowest precedence: OR
        idx, oplen = self.find_op_at_level0(expr, [' OR '])
        if idx >= 0:
            left_val, _, _, _ = self.parse_expression(expr[:idx], allow_undefined)
            right_val, _, _, _ = self.parse_expression(expr[idx+oplen:], allow_undefined)
            return ((left_val | right_val) & 0xFFFF, ADDR_ABSOLUTE, False, None)

        # XOR
        idx, oplen = self.find_op_at_level0(expr, [' XOR '])
        if idx >= 0:
            left_val, _, _, _ = self.parse_expression(expr[:idx], allow_undefined)
            right_val, _, _, _ = self.parse_expression(expr[idx+oplen:], allow_undefined)
            return ((left_val ^ right_val) & 0xFFFF, ADDR_ABSOLUTE, False, None)

        # AND
        idx, oplen = self.find_op_at_level0(expr, [' AND '])
        if idx >= 0:
            left_val, _, _, _ = self.parse_expression(expr[:idx], allow_undefined)
            right_val, _, _, _ = self.parse_expression(expr[idx+oplen:], allow_undefined)
            return ((left_val & right_val) & 0xFFFF, ADDR_ABSOLUTE, False, None)

        # Comparison operators: EQ, NE, LT, LE, GT, GE
        idx, oplen = self.find_op_at_level0(expr, [' EQ ', ' NE ', ' LT ', ' LE ', ' GT ', ' GE '])
        if idx >= 0:
            op = expr[idx:idx+oplen].strip().upper()
            left_val, _, _, _ = self.parse_expression(expr[:idx], allow_undefined)
            right_val, _, _, _ = self.parse_expression(expr[idx+oplen:], allow_undefined)
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
            return (result, ADDR_ABSOLUTE, False, None)

        # Addition and subtraction (lowest arithmetic precedence, right to left)
        idx, oplen = self.find_op_at_level0(expr, ['+', '-'])
        if idx >= 0:
            op = expr[idx:idx+oplen]
            left = expr[:idx].strip()
            right = expr[idx+oplen:].strip()

            # Don't split if left side is empty (unary operator case handled above)
            if left:
                left_val, left_seg, left_ext, left_name = self.parse_expression(left, allow_undefined)
                right_val, right_seg, right_ext, right_name = self.parse_expression(right, allow_undefined)

                if left_ext or right_ext:
                    # External reference with offset
                    ext_name = left_name if left_ext else right_name
                    offset = right_val if left_ext else left_val
                    if op == '-' and not left_ext:
                        offset = -offset
                    return (offset, ADDR_ABSOLUTE, True, ext_name)

                if op == '+':
                    result = left_val + right_val
                else:
                    result = left_val - right_val

                # Determine result segment type
                if left_seg == right_seg and op == '-':
                    result_seg = ADDR_ABSOLUTE
                elif right_seg == ADDR_ABSOLUTE:
                    result_seg = left_seg
                elif left_seg == ADDR_ABSOLUTE:
                    result_seg = right_seg
                else:
                    result_seg = left_seg

                return (result & 0xFFFF, result_seg, False, None)

        # Multiplication, division, MOD, SHL, SHR
        idx, oplen = self.find_op_at_level0(expr, ['*', '/', ' MOD ', ' SHL ', ' SHR '])
        if idx >= 0:
            op = expr[idx:idx+oplen].strip().upper()
            left_val, _, _, _ = self.parse_expression(expr[:idx], allow_undefined)
            right_val, _, _, _ = self.parse_expression(expr[idx+oplen:], allow_undefined)
            if op == '*':
                return ((left_val * right_val) & 0xFFFF, ADDR_ABSOLUTE, False, None)
            elif op == '/':
                if right_val == 0:
                    self.error("Division by zero")
                    return (0, ADDR_ABSOLUTE, False, None)
                return ((left_val // right_val) & 0xFFFF, ADDR_ABSOLUTE, False, None)
            elif op == 'MOD':
                if right_val == 0:
                    self.error("Division by zero")
                    return (0, ADDR_ABSOLUTE, False, None)
                return ((left_val % right_val) & 0xFFFF, ADDR_ABSOLUTE, False, None)
            elif op == 'SHL':
                return ((left_val << right_val) & 0xFFFF, ADDR_ABSOLUTE, False, None)
            elif op == 'SHR':
                return ((left_val >> right_val) & 0xFFFF, ADDR_ABSOLUTE, False, None)

        # Handle ## suffix (6-character truncation operator, implies external)
        if expr.endswith('##'):
            # Truncate symbol to 6 chars and look it up
            sym_name = expr[:-2][:6]
            sym = self.lookup_symbol(sym_name)
            if sym.external:
                return (0, ADDR_ABSOLUTE, True, sym.name)
            if not sym.defined:
                # ## implies external if not defined locally
                sym.external = True
                return (0, ADDR_ABSOLUTE, True, sym.name)
            return (sym.value, sym.seg_type, False, None)

        # Try as simple symbol
        if re.match(r'^[$A-Za-z_@?][A-Za-z0-9_@?$.]*$', expr):
            upper = expr.upper()

            # Check if it's a register (not a symbol)
            if upper in REGS or upper in REGPAIRS or upper in REGPAIRS_PUSHPOP:
                self.error(f"Register '{expr}' used as value")
                return (0, ADDR_ABSOLUTE, False, None)

            # Check if it's an opcode (usable as one-byte operand per M80 manual p.2-4)
            if upper in OPCODE_VALUES:
                return (OPCODE_VALUES[upper], ADDR_ABSOLUTE, False, None)

            sym = self.lookup_symbol(expr)
            if sym.external:
                return (0, ADDR_ABSOLUTE, True, sym.name)
            if not sym.defined and not allow_undefined:
                if self.pass_num == 2:
                    self.error(f"Undefined symbol '{expr}'")
                return (0, ADDR_ABSOLUTE, False, None)
            return (sym.value, sym.seg_type, False, None)

        # Try as number
        val, ok = self.parse_number(expr)
        if ok:
            return (val & 0xFFFF, ADDR_ABSOLUTE, False, None)

        # Try as character constant
        val, ok = self.parse_char_const(expr)
        if ok:
            return (val & 0xFFFF, ADDR_ABSOLUTE, False, None)

        self.error(f"Cannot parse expression: '{expr}'")
        return (0, ADDR_ABSOLUTE, False, None)

    def parse_line(self, line):
        """Parse a source line, return (label, operator, operands, comment)."""
        # Remove comment
        comment = ''
        in_string = False
        string_char = None
        for i, ch in enumerate(line):
            if in_string:
                if ch == string_char:
                    in_string = False
            elif ch in "'\"":
                in_string = True
                string_char = ch
            elif ch == ';':
                comment = line[i+1:]
                line = line[:i]
                break

        line = line.rstrip()
        if not line:
            return (None, None, None, comment)

        # Parse label (if any)
        # Labels can be at column 1 or indented, but are identified by trailing colon
        # Conditional directives (IF, ELSE, ENDIF, etc.) at column 1 without colon are NOT labels
        CONDITIONAL_DIRECTIVES = {
            'IF', 'IFT', 'IFE', 'IFF', 'IFDEF', 'IFNDEF',
            'IF1', 'IF2', 'IFB', 'IFNB', 'IFIDN', 'IFDIF',
            'COND', 'ELSE', 'ENDIF', 'ENDC'
        }
        label = None
        stripped = line.lstrip()
        # Check for label: identifier followed by : or ::
        match = re.match(r'^([$A-Za-z_@?][A-Za-z0-9_@?$.]*)(::|:)\s*', stripped)
        if match:
            # Has a colon, so it's definitely a label
            label = match.group(1)
            colons = match.group(2)
            stripped = stripped[match.end():]
            line = stripped  # Continue with remainder
            if colons == '::':
                self.lookup_symbol(label).public = True
        elif not line[0].isspace() if line else False:
            # At column 1, no colon - check if it's a conditional directive
            match = re.match(r'^([$A-Za-z_@?][A-Za-z0-9_@?$.]*)\s*', stripped)
            if match:
                potential = match.group(1).upper()
                if potential not in CONDITIONAL_DIRECTIVES:
                    # Not a directive, treat as label (M80 allows labels without colons at col 1)
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

        return (label, operator, operands, comment)

    def split_operands(self, operands):
        """Split operands by comma, respecting strings, parentheses, and angle brackets."""
        if not operands:
            return []

        result = []
        current = ''
        paren_depth = 0
        angle_depth = 0
        in_string = False
        string_char = None

        for ch in operands:
            if in_string:
                current += ch
                if ch == string_char:
                    in_string = False
            elif ch in "'\"":
                in_string = True
                string_char = ch
                current += ch
            elif ch == '(':
                paren_depth += 1
                current += ch
            elif ch == ')':
                paren_depth -= 1
                current += ch
            elif ch == '<':
                angle_depth += 1
                current += ch
            elif ch == '>':
                angle_depth -= 1
                current += ch
            elif ch == ',' and paren_depth == 0 and angle_depth == 0:
                result.append(current.strip())
                current = ''
            else:
                current += ch

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

    def emit_byte(self, value):
        """Emit a byte to current segment."""
        if self.pass_num == 2:
            self.output.write_absolute_byte(value & 0xFF)
            if self.generate_listing:
                self.current_line_bytes.append(value & 0xFF)
        self.loc += 1

    def emit_word(self, value, seg_type=ADDR_ABSOLUTE):
        """Emit a 16-bit word to current segment."""
        if self.pass_num == 2:
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
                self.output.write_common_relative(value)
            if self.generate_listing:
                self.current_line_bytes.append(value & 0xFF)
                self.current_line_bytes.append((value >> 8) & 0xFF)
        self.loc += 2

    def emit_external_ref(self, name, offset=0):
        """Emit reference to external symbol.

        The offset parameter is the expression offset (e.g., +1 in RNDX+1),
        which is added to the resolved address during linking.

        External references form a chain - each location contains the offset
        of the previous reference (or 0 for the first). The linker walks the
        chain backwards from the head (last reference) to resolve all refs.

        Separate chains are maintained for each unique (name, offset) pair,
        so RNDX and RNDX+1 have independent chains.
        """
        name = name.upper()
        # Key by (name, expr_offset) so different offsets get separate chains
        chain_key = (name, offset)
        if chain_key not in self.ext_chains:
            self.ext_chains[chain_key] = []

        # Get the previous reference location (for chain link) or 0 if first
        chain = self.ext_chains[chain_key]
        if chain:
            prev_seg, prev_offset = chain[-1]
            chain_link = prev_offset
        else:
            chain_link = 0

        # Record this reference location (will be the new head)
        chain.append((self.seg_type, self.loc))

        # Emit chain link (0 for first reference, else previous offset)
        self.emit_word(chain_link)

    def resolve_register_alias(self, name):
        """
        DRI extension: Resolve a register name or alias.
        If name is a direct register (B, C, D, E, H, L, M, A), return it.
        If name is a symbol with EQU value 0-7, return the corresponding register.
        Returns the register name or None if not a valid register/alias.
        """
        name = name.upper()
        if name in REGS:
            return name
        # Check if it's a symbol with a register value
        sym = self.symbols.get(name)
        if sym and sym.defined and 0 <= sym.value <= 7:
            # Map value to register name
            for reg, val in REGS.items():
                if val == sym.value:
                    return reg
        return None

    def resolve_regpair_alias(self, name, regpair_dict):
        """
        DRI extension: Resolve a register pair name or alias.
        If name is a direct register pair in regpair_dict, return it.
        If name is a symbol with EQU value matching a pair encoding, return the pair.
        Also handles single register -> register pair mapping for DRI compatibility:
        - B(0)/C(1) -> BC, D(2)/E(3) -> DE, H(4)/L(5) -> HL
        Returns the register pair name or None if not valid.
        """
        name = name.upper()
        if name in regpair_dict:
            return name
        # Check if it's a symbol with a register pair value
        sym = self.symbols.get(name)
        if sym and sym.defined:
            val = sym.value
            # First, try direct match with register pair encoding (0-3)
            for rp, rpval in regpair_dict.items():
                if rpval == val:
                    return rp
            # DRI extension: single register value -> register pair
            # B(0)/C(1) -> BC(0), D(2)/E(3) -> DE(1), H(4)/L(5) -> HL(2)
            if val in (0, 1):  # B or C -> BC
                if 'B' in regpair_dict or 'BC' in regpair_dict:
                    return 'B' if 'B' in regpair_dict else 'BC'
            elif val in (2, 3):  # D or E -> DE
                if 'D' in regpair_dict or 'DE' in regpair_dict:
                    return 'D' if 'D' in regpair_dict else 'DE'
            elif val in (4, 5):  # H or L -> HL
                if 'H' in regpair_dict or 'HL' in regpair_dict:
                    return 'H' if 'H' in regpair_dict else 'HL'
        return None

    def assemble_instruction(self, operator, operands):
        """Assemble a CPU instruction."""
        operator = operator.upper()
        ops = self.split_operands(operands) if operands else []

        # No-operand instructions
        if operator in NO_OPERAND:
            if ops:
                self.warning(f"Operands ignored for {operator}")
            code = encode_no_operand(operator)
            for b in code:
                self.emit_byte(b)
            return True

        # Conditional returns
        if operator in COND_RETS:
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
            val, seg, ext, name = self.parse_expression(ops[1])
            if ext:
                self.error("Cannot use external in immediate byte")
                return True
            code = encode_mvi(reg, val)
            for b in code:
                self.emit_byte(b)
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
            self.emit_byte(LXI_BASE | (REGPAIRS[rp] << 4))
            val, seg, ext, name = self.parse_expression(ops[1])
            if ext:
                self.emit_external_ref(name, val)
            else:
                self.emit_word(val, seg)
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
            # DRI extension: PUSH A / POP A is alias for PUSH PSW / POP PSW
            op_upper = ops[0].strip().upper()
            if op_upper == 'A':
                rp = 'PSW'
            else:
                rp = self.resolve_regpair_alias(ops[0], REGPAIRS_PUSHPOP)
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
            val, seg, ext, name = self.parse_expression(ops[0])
            if ext:
                self.error("Cannot use external in immediate byte")
                return True
            code = encode_alu_imm(operator, val)
            for b in code:
                self.emit_byte(b)
            return True

        # JMP addr
        if operator == 'JMP':
            if len(ops) != 1:
                self.error("JMP requires one operand")
                return True
            self.emit_byte(JMP)
            val, seg, ext, name = self.parse_expression(ops[0])
            if ext:
                self.emit_external_ref(name, val)
            else:
                self.emit_word(val, seg)
            return True

        # Conditional jumps
        if operator in COND_JUMPS:
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            cond = get_cond_from_mnemonic(operator)
            self.emit_byte(COND_JMP_BASE | (CONDITIONS[cond] << 3))
            val, seg, ext, name = self.parse_expression(ops[0])
            if ext:
                self.emit_external_ref(name, val)
            else:
                self.emit_word(val, seg)
            return True

        # CALL addr
        if operator == 'CALL':
            if len(ops) != 1:
                self.error("CALL requires one operand")
                return True
            self.emit_byte(CALL)
            val, seg, ext, name = self.parse_expression(ops[0])
            if ext:
                self.emit_external_ref(name, val)
            else:
                self.emit_word(val, seg)
            return True

        # Conditional calls
        if operator in COND_CALLS:
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            cond = get_cond_from_mnemonic(operator)
            self.emit_byte(COND_CALL_BASE | (CONDITIONS[cond] << 3))
            val, seg, ext, name = self.parse_expression(ops[0])
            if ext:
                self.emit_external_ref(name, val)
            else:
                self.emit_word(val, seg)
            return True

        # RST n
        if operator == 'RST':
            if len(ops) != 1:
                self.error("RST requires one operand")
                return True
            val, seg, ext, name = self.parse_expression(ops[0])
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
            if operator == 'LDA':
                self.emit_byte(LDA)
            elif operator == 'STA':
                self.emit_byte(STA)
            elif operator == 'LHLD':
                self.emit_byte(LHLD)
            else:
                self.emit_byte(SHLD)
            val, seg, ext, name = self.parse_expression(ops[0])
            if ext:
                self.emit_external_ref(name, val)
            else:
                self.emit_word(val, seg)
            return True

        # IN/OUT port
        if operator in ('IN', 'OUT'):
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            val, seg, ext, name = self.parse_expression(ops[0])
            if ext:
                self.error("Cannot use external for port number")
                return True
            if operator == 'IN':
                code = encode_in(val)
            else:
                code = encode_out(val)
            for b in code:
                self.emit_byte(b)
            return True

        return False  # Not a CPU instruction

    def parse_z80_indexed(self, operand):
        """Parse (IX+d) or (IY+d) operand, return (reg, displacement) or None."""
        operand = operand.strip()
        if not operand.startswith('(') or not operand.endswith(')'):
            return None
        inner = operand[1:-1].strip().upper()
        if inner.startswith('IX'):
            rest = inner[2:].strip()
            if not rest:
                return ('IX', 0)
            if rest.startswith('+'):
                val, _, _, _ = self.parse_expression(rest[1:])
                return ('IX', val & 0xFF)
            elif rest.startswith('-'):
                val, _, _, _ = self.parse_expression(rest)
                return ('IX', val & 0xFF)
        elif inner.startswith('IY'):
            rest = inner[2:].strip()
            if not rest:
                return ('IY', 0)
            if rest.startswith('+'):
                val, _, _, _ = self.parse_expression(rest[1:])
                return ('IY', val & 0xFF)
            elif rest.startswith('-'):
                val, _, _, _ = self.parse_expression(rest)
                return ('IY', val & 0xFF)
        return None

    def assemble_z80_instruction(self, operator, operands):
        """Assemble a Z80 CPU instruction."""
        operator = operator.upper()
        ops = self.split_operands(operands) if operands else []

        # No-operand instructions
        if operator in Z80_NO_OPERAND:
            if ops:
                self.warning(f"Operands ignored for {operator}")
            self.emit_byte(Z80_NO_OPERAND[operator])
            return True

        # ED-prefix no-operand instructions
        if operator in Z80_ED_NO_OPERAND:
            if ops:
                self.warning(f"Operands ignored for {operator}")
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

            # LD r,n (immediate byte) - but NOT if src is (nn) memory access
            if dst_upper in Z80_REGS_M and src_upper not in Z80_REGS_M:
                # Check for indexed addressing first
                indexed = self.parse_z80_indexed(src)
                if indexed:
                    # LD r,(IX+d) or LD r,(IY+d)
                    reg, disp = indexed
                    if reg == 'IX':
                        for b in encode_z80_ld_r_ixd(dst, disp):
                            self.emit_byte(b)
                    else:
                        for b in encode_z80_ld_r_iyd(dst, disp):
                            self.emit_byte(b)
                    return True
                # If src is (expr), this might be LD A,(nn) - handle below
                if src.startswith('(') and src.endswith(')'):
                    # Fall through to LD A,(nn) / LD (nn),A handling
                    pass
                else:
                    # LD r,n (immediate byte)
                    val, seg, ext, name = self.parse_expression(src)
                    for b in encode_z80_ld_r_n(dst, val):
                        self.emit_byte(b)
                    return True

            # LD (IX+d),r or LD (IY+d),r or LD (IX+d),n or LD (IY+d),n
            indexed = self.parse_z80_indexed(dst)
            if indexed:
                reg, disp = indexed
                if src_upper in Z80_REGS and src_upper != '(HL)':
                    if reg == 'IX':
                        for b in encode_z80_ld_ixd_r(disp, src):
                            self.emit_byte(b)
                    else:
                        for b in encode_z80_ld_iyd_r(disp, src):
                            self.emit_byte(b)
                else:
                    val, seg, ext, name = self.parse_expression(src)
                    if reg == 'IX':
                        for b in encode_z80_ld_ixd_n(disp, val):
                            self.emit_byte(b)
                    else:
                        for b in encode_z80_ld_iyd_n(disp, val):
                            self.emit_byte(b)
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
                    val, seg, ext, name = self.parse_expression(src[1:-1])
                    self.emit_byte(0x3A)  # LD A,(nn) opcode
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
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
                    val, seg, ext, name = self.parse_expression(dst[1:-1])
                    self.emit_byte(0x32)  # LD (nn),A opcode
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
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
                    val, seg, ext, name = self.parse_expression(src[1:-1])
                    if dst_upper == 'HL':
                        self.emit_byte(0x2A)  # LD HL,(nn) opcode
                    else:
                        # BC=0x4B, DE=0x5B, SP=0x7B
                        dd_opcodes = {'BC': 0x4B, 'DE': 0x5B, 'SP': 0x7B}
                        self.emit_byte(PREFIX_ED)
                        self.emit_byte(dd_opcodes[dst_upper])
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
                else:
                    val, seg, ext, name = self.parse_expression(src)
                    self.emit_byte(0x01 | (Z80_PAIRS_BC_DE_HL_SP[dst_upper] << 4))
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
                return True

            # LD IX,nn / LD IY,nn
            if dst_upper == 'IX':
                if src.startswith('(') and src.endswith(')'):
                    val, seg, ext, name = self.parse_expression(src[1:-1])
                    self.emit_byte(PREFIX_DD)
                    self.emit_byte(0x2A)  # LD IX,(nn)
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
                else:
                    val, seg, ext, name = self.parse_expression(src)
                    self.emit_byte(PREFIX_DD)
                    self.emit_byte(0x21)
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
                return True
            if dst_upper == 'IY':
                if src.startswith('(') and src.endswith(')'):
                    val, seg, ext, name = self.parse_expression(src[1:-1])
                    self.emit_byte(PREFIX_FD)
                    self.emit_byte(0x2A)  # LD IY,(nn)
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
                else:
                    val, seg, ext, name = self.parse_expression(src)
                    self.emit_byte(PREFIX_FD)
                    self.emit_byte(0x21)
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
                return True

            # LD (nn),dd / LD (nn),IX / LD (nn),IY
            if dst.startswith('(') and dst.endswith(')'):
                addr_expr = dst[1:-1]
                val, seg, ext, name = self.parse_expression(addr_expr)
                if src_upper == 'HL':
                    self.emit_byte(0x22)  # LD (nn),HL opcode
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
                    return True
                if src_upper in Z80_PAIRS_BC_DE_HL_SP:
                    # BC=0x43, DE=0x53, HL handled above, SP=0x73
                    dd_opcodes = {'BC': 0x43, 'DE': 0x53, 'SP': 0x73}
                    if src_upper in dd_opcodes:
                        self.emit_byte(PREFIX_ED)
                        self.emit_byte(dd_opcodes[src_upper])
                        if ext:
                            self.emit_external_ref(name, val)
                        else:
                            self.emit_word(val, seg)
                    return True
                if src_upper == 'IX':
                    self.emit_byte(PREFIX_DD)
                    self.emit_byte(0x22)  # LD (nn),IX
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
                    return True
                if src_upper == 'IY':
                    self.emit_byte(PREFIX_FD)
                    self.emit_byte(0x22)  # LD (nn),IY
                    if ext:
                        self.emit_external_ref(name, val)
                    else:
                        self.emit_word(val, seg)
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
            if len(ops) < 1:
                self.error(f"{operator} requires operand(s)")
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
                    ops = [src]  # Process as ADD r

            if operator == 'ADC' and len(ops) == 2:
                dst, src = ops[0].upper().strip(), ops[1].upper().strip()
                if dst == 'HL' and src in Z80_PAIRS_BC_DE_HL_SP:
                    for b in encode_z80_adc_hl_ss(src):
                        self.emit_byte(b)
                    return True
                if dst == 'A':
                    ops = [src]

            if operator == 'SBC' and len(ops) == 2:
                dst, src = ops[0].upper().strip(), ops[1].upper().strip()
                if dst == 'HL' and src in Z80_PAIRS_BC_DE_HL_SP:
                    for b in encode_z80_sbc_hl_ss(src):
                        self.emit_byte(b)
                    return True
                if dst == 'A':
                    ops = [src]

            # ALU A,r or ALU A,(HL) or ALU A,(IX+d) or ALU A,n
            op = ops[0].strip()
            op_upper = op.upper()
            indexed = self.parse_z80_indexed(op)
            if indexed:
                reg, disp = indexed
                if reg == 'IX':
                    for b in encode_z80_alu_ixd(operator, disp):
                        self.emit_byte(b)
                else:
                    for b in encode_z80_alu_iyd(operator, disp):
                        self.emit_byte(b)
                return True
            if op_upper in Z80_REGS_M:
                for b in encode_z80_alu_r(operator, op):
                    self.emit_byte(b)
                return True
            # Immediate
            val, seg, ext, name = self.parse_expression(op)
            for b in encode_z80_alu_n(operator, val):
                self.emit_byte(b)
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
                reg, disp = indexed
                if operator == 'INC':
                    if reg == 'IX':
                        for b in encode_z80_inc_ixd(disp):
                            self.emit_byte(b)
                    else:
                        for b in encode_z80_inc_iyd(disp):
                            self.emit_byte(b)
                else:
                    if reg == 'IX':
                        for b in encode_z80_dec_ixd(disp):
                            self.emit_byte(b)
                    else:
                        for b in encode_z80_dec_iyd(disp):
                            self.emit_byte(b)
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
                reg, disp = indexed
                if reg == 'IX':
                    for b in encode_z80_rot_ixd(operator, disp):
                        self.emit_byte(b)
                else:
                    for b in encode_z80_rot_iyd(operator, disp):
                        self.emit_byte(b)
                return True
            self.error(f"Invalid operand for {operator}: {op}")
            return True

        # Bit operations: BIT, RES, SET
        if operator in Z80_BIT_MNEMONICS:
            if len(ops) != 2:
                self.error(f"{operator} requires two operands")
                return True
            bit_val, seg, ext, name = self.parse_expression(ops[0])
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
                reg, disp = indexed
                if operator == 'BIT':
                    if reg == 'IX':
                        for b in encode_z80_bit_b_ixd(bit_val, disp):
                            self.emit_byte(b)
                    else:
                        for b in encode_z80_bit_b_iyd(bit_val, disp):
                            self.emit_byte(b)
                elif operator == 'RES':
                    if reg == 'IX':
                        for b in encode_z80_res_b_ixd(bit_val, disp):
                            self.emit_byte(b)
                    else:
                        for b in encode_z80_res_b_iyd(bit_val, disp):
                            self.emit_byte(b)
                else:
                    if reg == 'IX':
                        for b in encode_z80_set_b_ixd(bit_val, disp):
                            self.emit_byte(b)
                    else:
                        for b in encode_z80_set_b_iyd(bit_val, disp):
                            self.emit_byte(b)
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
                # Check if it's a condition
                if op in Z80_CONDITIONS:
                    self.error("JP with condition requires address")
                    return True
                # Unconditional JP nn
                val, seg, ext, name = self.parse_expression(ops[0])
                self.emit_byte(0xC3)
                if ext:
                    self.emit_external_ref(name, val)
                else:
                    self.emit_word(val, seg)
                return True
            if len(ops) == 2:
                cond = ops[0].upper().strip()
                if cond not in Z80_CONDITIONS:
                    self.error(f"Invalid condition for JP: {cond}")
                    return True
                val, seg, ext, name = self.parse_expression(ops[1])
                c = Z80_CONDITIONS[cond]
                self.emit_byte(0xC2 | (c << 3))
                if ext:
                    self.emit_external_ref(name, val)
                else:
                    self.emit_word(val, seg)
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
                val, seg, ext, name = self.parse_expression(ops[0])
                # For forward refs on pass 1 iter>0, use prev_symbols if available
                if can_check_range and val == 0 and self.pass_num == 1:
                    expr = ops[0].strip().upper()
                    prev_syms = getattr(self, 'prev_symbols', {})
                    if expr in prev_syms:
                        val, seg = prev_syms[expr]
                # Check if already promoted to JP
                if self.line_num in self.promoted_jr:
                    # Emit JP instead (3 bytes)
                    self.emit_byte(0xC3)
                    self.emit_word(val, seg)
                    return True
                # Calculate offset assuming JR (2 bytes)
                offset = val - (self.loc + 2)
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
                val, seg, ext, name = self.parse_expression(ops[1])
                # For forward refs on pass 1 iter>0, use prev_symbols if available
                if can_check_range and val == 0 and self.pass_num == 1:
                    expr = ops[1].strip().upper()
                    prev_syms = getattr(self, 'prev_symbols', {})
                    if expr in prev_syms:
                        val, seg = prev_syms[expr]
                # Check if already promoted to JP
                if self.line_num in self.promoted_jr:
                    # Emit JP cc instead (3 bytes)
                    c = Z80_CONDITIONS[cond]  # Same codes for NZ,Z,NC,C
                    self.emit_byte(0xC2 | (c << 3))
                    self.emit_word(val, seg)
                    return True
                # Calculate offset assuming JR (2 bytes)
                offset = val - (self.loc + 2)
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

            val, seg, ext, name = self.parse_expression(ops[0])
            # For forward refs on pass 1 iter>0, use prev_symbols if available
            if can_check_range and val == 0 and self.pass_num == 1:
                expr = ops[0].strip().upper()
                prev_syms = getattr(self, 'prev_symbols', {})
                if expr in prev_syms:
                    val, seg = prev_syms[expr]
            # Check if already promoted
            if self.line_num in self.promoted_jr:
                # Emit DEC B + JP NZ instead (4 bytes)
                self.emit_byte(0x05)  # DEC B
                self.emit_byte(0xC2)  # JP NZ
                self.emit_word(val, seg)
                return True
            # Calculate offset assuming DJNZ (2 bytes)
            offset = val - (self.loc + 2)
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
                val, seg, ext, name = self.parse_expression(ops[0])
                self.emit_byte(0xCD)
                if ext:
                    self.emit_external_ref(name, val)
                else:
                    self.emit_word(val, seg)
                return True
            if len(ops) == 2:
                cond = ops[0].upper().strip()
                if cond not in Z80_CONDITIONS:
                    self.error(f"Invalid condition for CALL: {cond}")
                    return True
                val, seg, ext, name = self.parse_expression(ops[1])
                c = Z80_CONDITIONS[cond]
                self.emit_byte(0xC4 | (c << 3))
                if ext:
                    self.emit_external_ref(name, val)
                else:
                    self.emit_word(val, seg)
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
            val, seg, ext, name = self.parse_expression(ops[0])
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
                    val, seg, ext, name = self.parse_expression(src[1:-1])
                    self.emit_byte(0xDB)
                    self.emit_byte(val & 0xFF)
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
                    val, seg, ext, name = self.parse_expression(dst[1:-1])
                    self.emit_byte(0xD3)
                    self.emit_byte(val & 0xFF)
                    return True
            self.error("Invalid OUT operands")
            return True

        # IM
        if operator == 'IM':
            if len(ops) != 1:
                self.error("IM requires one operand")
                return True
            val, seg, ext, name = self.parse_expression(ops[0])
            if val not in (0, 1, 2):
                self.error(f"Invalid interrupt mode: {val}")
                return True
            for b in encode_z80_im(val):
                self.emit_byte(b)
            return True

        return False  # Not a Z80 instruction

    def assemble_pseudo_op(self, operator, operands, label):
        """Assemble a pseudo-operation (directive)."""
        operator = operator.upper()
        ops = self.split_operands(operands) if operands else []

        # ORG - set location counter
        if operator == 'ORG':
            if len(ops) != 1:
                self.error("ORG requires one operand")
                return True
            val, expr_seg_type, ext, name = self.parse_expression(ops[0])
            if ext:
                self.error("Cannot use external in ORG")
                return True
            self.loc = val
            # Track first ORG as segment origin
            seg_obj = self.segments[self.current_seg]
            if not seg_obj.org_set:
                seg_obj.org = val
                seg_obj.org_set = True
            if self.pass_num == 2:
                # Use the expression's segment type (absolute for absolute ORG values)
                self.output.write_set_location(expr_seg_type, val)
            return True

        # EQU - equate symbol to value
        if operator == 'EQU':
            if not label:
                self.error("EQU requires a label")
                return True
            if len(ops) != 1:
                self.error("EQU requires one operand")
                return True
            # DRI extension: allow register names as EQU values
            # e.g., "MR EQU B" means MR is an alias for register B (value 0)
            op_upper = ops[0].strip().upper()
            if op_upper in REGS:
                self.define_symbol(label, REGS[op_upper], ADDR_ABSOLUTE)
                return True
            # Also support register pairs
            if op_upper in REGPAIRS:
                self.define_symbol(label, REGPAIRS[op_upper], ADDR_ABSOLUTE)
                return True
            if op_upper in REGPAIRS_PUSHPOP:
                self.define_symbol(label, REGPAIRS_PUSHPOP[op_upper], ADDR_ABSOLUTE)
                return True
            val, seg, ext, name = self.parse_expression(ops[0], allow_undefined=(self.pass_num == 1))
            if ext:
                self.error("Cannot use external in EQU")
                return True
            self.define_symbol(label, val, seg)
            return True

        # SET/DEFL - like EQU but redefinable
        if operator == 'SET' or operator == 'DEFL':
            if not label:
                self.error(f"{operator} requires a label")
                return True
            if len(ops) != 1:
                self.error(f"{operator} requires one operand")
                return True
            # DRI extension: allow register names as values
            op_upper = ops[0].strip().upper()
            if op_upper in REGS:
                val, seg = REGS[op_upper], ADDR_ABSOLUTE
            elif op_upper in REGPAIRS:
                val, seg = REGPAIRS[op_upper], ADDR_ABSOLUTE
            elif op_upper in REGPAIRS_PUSHPOP:
                val, seg = REGPAIRS_PUSHPOP[op_upper], ADDR_ABSOLUTE
            else:
                val, seg, ext, name = self.parse_expression(ops[0], allow_undefined=(self.pass_num == 1))
                if ext:
                    self.error(f"Cannot use external in {operator}")
                    return True
            # SET/DEFL allows redefinition
            sym = self.lookup_symbol(label)
            sym.value = val
            sym.seg_type = seg
            sym.defined = True
            return True

        # DB - define bytes
        if operator in ('DB', 'DEFB', 'DEFM'):
            for op in ops:
                op = op.strip()
                # Check for string
                if (op.startswith("'") and op.endswith("'")) or \
                   (op.startswith('"') and op.endswith('"')):
                    s = op[1:-1]
                    # Handle '' escape sequence (doubled apostrophe = single apostrophe)
                    s = s.replace("''", "'")
                    for ch in s:
                        self.emit_byte(ord(ch))
                else:
                    val, seg, ext, name = self.parse_expression(op)
                    if ext:
                        self.error("Cannot use external in DB")
                    else:
                        self.emit_byte(val)
            return True

        # DC - define character string with high bit set on last character (M80 compatible)
        if operator == 'DC':
            if len(ops) != 1:
                self.error("DC requires one string operand")
                return True
            op = ops[0].strip()
            if (op.startswith("'") and op.endswith("'")) or \
               (op.startswith('"') and op.endswith('"')):
                s = op[1:-1]
                # Handle '' escape sequence (doubled apostrophe = single apostrophe)
                s = s.replace("''", "'")
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
                val, seg, ext, name = self.parse_expression(op.strip())
                if ext:
                    self.emit_external_ref(name, val)
                else:
                    self.emit_word(val, seg)
            return True

        # DS - define space
        if operator in ('DS', 'DEFS'):
            if len(ops) < 1:
                self.error("DS requires size operand")
                return True
            val, seg, ext, name = self.parse_expression(ops[0])
            if ext:
                self.error("Cannot use external in DS")
                return True
            # Just advance location counter (don't emit anything for DS)
            if self.pass_num == 2:
                # For REL format, we need to advance by emitting zeros or using set_location
                # Using set_location to skip over the space
                new_loc = self.loc + val
                self.output.write_set_location(self.seg_type, new_loc)
            self.loc += val
            return True

        # CSEG/DSEG/ASEG - segment selection
        if operator == 'CSEG':
            self.current_seg = 'CSEG'
            self.current_common = None
            return True
        if operator == 'DSEG':
            self.current_seg = 'DSEG'
            self.current_common = None
            return True
        if operator == 'ASEG':
            self.current_seg = 'ASEG'
            self.current_common = None
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
            self.current_common = name
            if self.pass_num == 2:
                self.output.write_select_common(name if name else ' ')
            return True

        # PUBLIC/ENTRY - declare public symbols
        if operator in ('PUBLIC', 'ENTRY', 'GLOBAL'):
            for op in ops:
                sym = self.lookup_symbol(op.strip())
                sym.public = True
            return True

        # EXTRN/EXT/EXTERNAL - declare external symbols
        if operator in ('EXTRN', 'EXT', 'EXTERNAL'):
            for op in ops:
                sym = self.lookup_symbol(op.strip())
                sym.external = True
            return True

        # NAME - module name
        if operator == 'NAME':
            if ops:
                name = ops[0].strip()
                if name.startswith("'") or name.startswith('"'):
                    name = name[1:-1]
                elif name.startswith('(') and name.endswith(')'):
                    name = name[1:-1]
                self.module_name = name
            return True

        # TITLE/SUBTTL - listing titles (ignore for now)
        if operator in ('TITLE', 'SUBTTL'):
            return True

        # PAGE/*EJECT - new page in listing (ignore for now)
        if operator == 'PAGE' or operator == '*EJECT':
            return True

        # .LIST/.XLIST - listing control
        if operator == '.LIST':
            self.list_on = True
            return True
        if operator == '.XLIST':
            self.list_on = False
            return True

        # .RADIX - set default radix
        if operator == '.RADIX':
            if len(ops) != 1:
                self.error(".RADIX requires one operand")
                return True
            val, _, _, _ = self.parse_expression(ops[0])
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

        # .PHASE/.DEPHASE - phase shift
        if operator in ('.PHASE', '.DEPHASE'):
            return True

        # END - end of source
        if operator == 'END':
            if ops:
                val, seg, ext, name = self.parse_expression(ops[0])
                if ext:
                    self.error("Cannot use external as entry point")
                else:
                    self.entry_point = (val, seg)
            return True

        # Conditional assembly
        if operator == 'IF' or operator == 'IFT':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                val, _, _, _ = self.parse_expression(ops[0] if ops else '0')
                if val == 0:
                    self.cond_false_depth = 1
            self.cond_stack.append(operator)
            return True

        if operator in ('IFE', 'IFF'):
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                val, _, _, _ = self.parse_expression(ops[0] if ops else '0')
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
            if self.cond_false_depth == 1:
                self.cond_false_depth = 0
            elif self.cond_false_depth == 0:
                self.cond_false_depth = 1
            return True

        if operator == 'ENDIF' or operator == 'ENDC':
            if not self.cond_stack:
                self.error(f"{operator} without IF")
                return True
            self.cond_stack.pop()
            if self.cond_false_depth > 0:
                self.cond_false_depth -= 1
            return True

        # COND - Z80 alias for IFT (true if expression is not 0)
        if operator == 'COND':
            if self.cond_false_depth > 0:
                self.cond_false_depth += 1
            else:
                val, _, _, _ = self.parse_expression(ops[0] if ops else '0')
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
            self.process_include_file(include_path)
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
            count, _, _, _ = self.parse_expression(ops[0])
            self.repeat_stack.append(('REPT', count, [], None, label))
            return True

        # IRP - iterate with list
        if operator == 'IRP':
            if len(ops) < 2:
                self.error("IRP requires parameter and list")
                return True
            param = ops[0].strip().upper()
            # Rest of ops are the list values
            values = ops[1:]
            # Handle <> enclosed list
            if len(values) == 1 and values[0].startswith('<') and values[0].endswith('>'):
                values = [v.strip() for v in values[0][1:-1].split(',')]
            self.repeat_stack.append(('IRP', values, [], param, label))
            return True

        # IRPC - iterate over characters
        if operator == 'IRPC':
            if len(ops) < 2:
                self.error("IRPC requires parameter and string")
                return True
            param = ops[0].strip().upper()
            chars = ops[1].strip()
            if chars.startswith('<') and chars.endswith('>'):
                chars = chars[1:-1]
            self.repeat_stack.append(('IRPC', list(chars), [], param, label))
            return True

        # ENDM for REPT/IRP/IRPC
        # (Note: ENDM for MACRO is handled in process_line)

        return False  # Not a pseudo-op

    def process_line(self, line):
        """Process a single source line."""
        self.line_num += 1
        self._start_listing_line()

        # DRI extension: split on '!' separator for multi-statement lines
        # Only do this when not collecting macro or repeat bodies
        if self.collecting_macro is None and not self.repeat_stack:
            statements = self.split_on_exclamation(line)
            if len(statements) > 1:
                # Process first statement normally (with label if any)
                self._process_single_statement(statements[0])
                # Process subsequent statements (they can't have labels from original line)
                for stmt in statements[1:]:
                    # Add leading space to prevent treating first word as label
                    if stmt and not stmt[0].isspace():
                        stmt = '        ' + stmt.strip()
                    self._process_single_statement(stmt)
                return
        # Fall through to normal processing (single statement or macro/repeat body)
        self._process_single_statement(line)

    def _process_single_statement(self, line):
        """Process a single statement (internal helper for ! separator support)."""
        label, operator, operands, comment = self.parse_line(line)
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
                # Nested repeat - add to body and track nesting
                self.repeat_stack[-1][2].append(line)
                self.repeat_stack.append(('NESTED', 0, [], None, None))
            elif upper_op == 'ENDM':
                if len(self.repeat_stack) > 1 and self.repeat_stack[-1][0] == 'NESTED':
                    # End of nested repeat
                    self.repeat_stack.pop()
                    self.repeat_stack[-1][2].append(line)
                else:
                    # End of outer repeat - execute it
                    rept_type, param_or_count, body, iter_var, rept_label = self.repeat_stack.pop()
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

        # Define label if present
        if label and upper_op not in ('EQU', 'SET', 'DEFL', 'MACRO'):
            self.define_symbol(label, self.loc, self.seg_type)

        if not operator:
            self._save_listing_entry(line)
            return

        # In Z80 mode, SET with a label is the directive, not the instruction
        # (Z80 SET instruction is "SET bit,reg" which doesn't have a label)
        if self.z80_mode and upper_op == 'SET' and label:
            if self.assemble_pseudo_op(operator, operands, label):
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

        # Check if it's a macro call
        if upper_op in self.macros:
            self.expand_macro(upper_op, operands)
            self._save_listing_entry(line)
            return

        self.error(f"Unknown instruction or directive: {operator}")
        self._save_listing_entry(line)

    def process_macro_argument(self, arg):
        """Process a macro argument, handling angle brackets and ! operator."""
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
            else:
                result.append(arg[i])
                i += 1
        return ''.join(result)

    def process_percent_operator(self, line):
        """Process % operator in a line, converting expressions to numbers."""
        result = []
        i = 0
        while i < len(line):
            if line[i] == '%':
                # Find the expression following %
                # Expression ends at comma, space, or end of line
                j = i + 1
                paren_depth = 0
                while j < len(line):
                    ch = line[j]
                    if ch == '(':
                        paren_depth += 1
                    elif ch == ')':
                        if paren_depth > 0:
                            paren_depth -= 1
                        else:
                            break
                    elif paren_depth == 0 and ch in ',; \t':
                        break
                    j += 1
                expr = line[i + 1:j]
                if expr:
                    val, _, _, _ = self.parse_expression(expr, allow_undefined=True)
                    # Convert to current radix
                    if self.radix == 16:
                        result.append(f'{val:X}H')
                    elif self.radix == 8:
                        result.append(f'{val:o}O')
                    elif self.radix == 2:
                        result.append(f'{val:b}B')
                    else:
                        result.append(str(val))
                    i = j
                else:
                    result.append('%')
                    i += 1
            else:
                result.append(line[i])
                i += 1
        return ''.join(result)

    def expand_macro(self, name, operands):
        """Expand a macro."""
        macro = self.macros.get(name)
        if not macro:
            self.error(f"Undefined macro: {name}")
            return

        # Parse actual arguments, handling ! operator
        args = []
        if operands:
            raw_args = self.split_operands(operands)
            args = [self.process_macro_argument(arg) for arg in raw_args]

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
        for body_line in macro.body:
            # Check for LOCAL directive
            label, op, opnds, comment = self.parse_line(body_line)
            if op and op.upper() == 'LOCAL':
                # Add these symbols to local set
                if opnds:
                    for sym in opnds.split(','):
                        local_syms.add(sym.strip().upper())
                continue
            if op and op.upper() == 'EXITM':
                # Exit macro expansion early
                break

            # Substitute parameters and local symbols
            expanded = body_line
            for param, value in subst.items():
                # Replace &param with value (for concatenation)
                expanded = expanded.replace(f'&{param}', value)
                # Replace standalone param with value
                expanded = re.sub(r'\b' + re.escape(param) + r'\b', value, expanded, flags=re.IGNORECASE)

            # Replace local symbols with unique versions
            for local_sym in local_syms:
                expanded = re.sub(r'\b' + re.escape(local_sym) + r'\b',
                                  local_sym + local_suffix, expanded, flags=re.IGNORECASE)

            # Process % operator (convert expressions to numbers)
            expanded = self.process_percent_operator(expanded)

            # Process the expanded line
            self.process_line(expanded)

        self.macro_level -= 1

    def execute_repeat(self, rept_type, param_or_count, body, iter_var):
        """Execute a REPT/IRP/IRPC block."""
        if rept_type == 'REPT':
            # Repeat body 'count' times
            count = param_or_count
            for i in range(count):
                for line in body:
                    self.process_line(line)

        elif rept_type == 'IRP':
            # Iterate with list of values
            values = param_or_count
            for value in values:
                for line in body:
                    # Substitute iter_var with value
                    expanded = line
                    if iter_var:
                        # Replace &iter_var with value (for concatenation)
                        expanded = expanded.replace(f'&{iter_var}', value)
                        expanded = expanded.replace(f'&{iter_var.lower()}', value)
                        # Replace standalone iter_var with value
                        expanded = re.sub(r'\b' + re.escape(iter_var) + r'\b',
                                          value, expanded, flags=re.IGNORECASE)
                    self.process_line(expanded)

        elif rept_type == 'IRPC':
            # Iterate over characters
            chars = param_or_count
            for char in chars:
                for line in body:
                    # Substitute iter_var with character
                    expanded = line
                    if iter_var:
                        # Replace &iter_var with char (for concatenation)
                        expanded = expanded.replace(f'&{iter_var}', char)
                        expanded = expanded.replace(f'&{iter_var.lower()}', char)
                        # Replace standalone iter_var with char
                        expanded = re.sub(r'\b' + re.escape(iter_var) + r'\b',
                                          char, expanded, flags=re.IGNORECASE)
                    self.process_line(expanded)

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

    def process_include_file(self, filepath):
        """Process an include file."""
        # Save current state
        saved_line_num = self.line_num

        # Push onto include stack
        self.include_stack.append((filepath, saved_line_num))

        try:
            # Read the include file
            with open(filepath, 'rb') as f:
                data = f.read()

            # Strip ^Z (0x1A) and everything after it (CP/M EOF marker)
            eof_pos = data.find(0x1A)
            if eof_pos >= 0:
                data = data[:eof_pos]

            # Decode to text
            text = data.decode('ascii', errors='replace')
            text = text.replace('\r\n', '\n').replace('\r', '\n')
            text = text.rstrip('\x00')

            lines = text.split('\n')

            # Reset line number for include file
            self.line_num = 0

            # Process each line
            for line in lines:
                self.process_line(line)

        except IOError as e:
            self.error(f"Error reading include file {filepath}: {e}")

        finally:
            # Pop from include stack and restore line number
            self.include_stack.pop()
            self.line_num = saved_line_num

    def assemble_pass(self, lines, pass_num):
        """Run one pass of assembly."""
        self.pass_num = pass_num
        self.line_num = 0
        self.cond_stack = []
        self.cond_false_depth = 0

        # Reset segment locations for pass 2
        if pass_num == 2:
            for seg in self.segments.values():
                seg.loc = 0
            for com in self.common_blocks.values():
                com.loc = 0
            self.current_seg = 'CSEG'
            self.current_common = None

        for line in lines:
            self.process_line(line)

    def write_output(self):
        """Write the REL file content."""
        # Write module name
        name = self.module_name or 'MODULE'
        self.output.write_program_name(name)

        # Write entry symbols (for library search)
        for sym in self.symbols.values():
            if (sym.public or self.export_all_symbols) and sym.defined:
                self.output.write_entry_symbol(sym.name)

        # Reset for code generation
        for seg in self.segments.values():
            seg.loc = 0
        for com in self.common_blocks.values():
            com.loc = 0
        self.current_seg = 'CSEG'
        self.current_common = None

        # Second pass already wrote the code bytes

        # Write public symbol definitions
        # For relocatable symbols, subtract segment ORG so linker can add its base
        for sym in self.symbols.values():
            if (sym.public or self.export_all_symbols) and sym.defined:
                value = sym.value
                if sym.seg_type == ADDR_PROGRAM_REL and self.segments['CSEG'].org_set:
                    value -= self.segments['CSEG'].org
                elif sym.seg_type == ADDR_DATA_REL and self.segments['DSEG'].org_set:
                    value -= self.segments['DSEG'].org
                self.output.write_define_entry_point(sym.seg_type, value, sym.name)

        # Write external chains
        # The chain head is the LAST reference; linker walks backward through chain
        # Key is (name, expr_offset), so we emit separate entries for RNDX vs RNDX+1
        for (name, expr_offset), refs in self.ext_chains.items():
            if refs:
                # Get the last reference (head of chain)
                seg, offset = refs[-1]
                # For non-zero offsets, append "+N" to symbol name
                # Linker will parse this and add the offset to resolved address
                if expr_offset != 0:
                    sym_name = f"{name}+{expr_offset}"
                else:
                    sym_name = name
                self.output.write_chain_external(seg, offset, sym_name)

        # Write segment sizes (actual bytes, not location counter value)
        cseg = self.segments['CSEG']
        dseg = self.segments['DSEG']
        cseg_size = cseg.loc - cseg.org if cseg.org_set else cseg.loc
        dseg_size = dseg.loc - dseg.org if dseg.org_set else dseg.loc

        if cseg_size > 0:
            self.output.write_define_program_size(cseg_size)
        if dseg_size > 0:
            self.output.write_define_data_size(dseg_size)

        # Write COMMON sizes
        for name, com in self.common_blocks.items():
            if com.loc > 0:
                self.output.write_define_common_size(ADDR_ABSOLUTE, com.loc, name if name else ' ')

        # Write end
        if self.entry_point:
            val, seg = self.entry_point
            self.output.write_end_program(val, seg)
        else:
            self.output.write_end_program()

        self.output.write_end_file()

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

                if code_bytes:
                    addr_str = f"{addr:04X}"
                    # Show up to 4 bytes on first line
                    bytes_shown = code_bytes[:4]
                    bytes_str = ' '.join(f"{b:02X}" for b in bytes_shown)
                    bytes_str = bytes_str.ljust(11)  # 4 bytes = "XX XX XX XX"
                else:
                    addr_str = "    "
                    bytes_str = "           "

                f.write(f"{line_num:5d}  {addr_str}  {bytes_str}  {source}\n")

                # If more than 4 bytes, show continuation lines
                if len(code_bytes) > 4:
                    remaining = code_bytes[4:]
                    cont_addr = addr + 4
                    while remaining:
                        chunk = remaining[:4]
                        remaining = remaining[4:]
                        bytes_str = ' '.join(f"{b:02X}" for b in chunk)
                        bytes_str = bytes_str.ljust(11)
                        f.write(f"       {cont_addr:04X}  {bytes_str}\n")
                        cont_addr += len(chunk)

    def assemble(self, source_file):
        """Assemble a source file."""
        # Set base path for include file resolution
        self.base_path = os.path.dirname(os.path.abspath(source_file))

        # Read source - handle CP/M format (CR/LF, ^Z EOF, 128-byte records)
        with open(source_file, 'rb') as f:
            data = f.read()

        # Strip ^Z (0x1A) and everything after it (CP/M EOF marker)
        eof_pos = data.find(0x1A)
        if eof_pos >= 0:
            data = data[:eof_pos]

        # Decode to text, handling CR/LF and stripping trailing nulls
        text = data.decode('ascii', errors='replace')
        text = text.replace('\r\n', '\n').replace('\r', '\n')  # Normalize line endings
        text = text.rstrip('\x00')  # Strip padding nulls

        lines = text.split('\n')
        self.source_lines = lines

        # Pass 1: Build symbol table (iterate until JR/DJNZ promotions stabilize)
        # We need multiple iterations because:
        # - Iteration 0: Build symbol table; can't check JR range (forward refs undefined)
        # - Iteration 1+: Use symbol table from previous iteration for range checking
        # - Keep iterating until no new promotions (sizes stabilize)
        max_iterations = 10  # Prevent infinite loops
        prev_symbols = {}  # Symbol table from previous iteration for forward refs
        for iteration in range(max_iterations):
            self.pass1_iteration = iteration  # Track iteration for JR range checking
            self.prev_symbols = prev_symbols  # Make available for JR range checking
            # Reset state for pass 1
            for seg in self.segments.values():
                seg.loc = 0
                seg.org = 0
                seg.org_set = False
            for com in self.common_blocks.values():
                com.loc = 0
            self.current_seg = 'CSEG'
            self.current_common = None
            self.errors = []  # Clear errors between iterations
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

            # Always run at least 2 iterations:
            # - Iteration 0 builds symbol table (can't check range yet)
            # - Iteration 1 checks range with symbol values from iteration 0
            # After that, check if promotions have stabilized
            if iteration >= 1 and len(self.promoted_jr) == prev_promotions:
                break  # Stable - no new promotions

            # Warn about promotions on last iteration
            if iteration == max_iterations - 1:
                self.warnings.append(f"Warning: JR/DJNZ promotion did not stabilize after {max_iterations} iterations")

        # Report promotions
        if self.promoted_jr and not self.strict_jr:
            self.warnings.append(f"Note: {len(self.promoted_jr)} JR/DJNZ instruction(s) promoted to JP due to range")

        if self.errors:
            return False

        # Pass 2: Generate code
        self.output = RELWriter(truncate_symbols=self.truncate_symbols)
        self.ext_chains = {}

        # Write module header
        name = self.module_name or Path(source_file).stem.upper()[:6]
        self.output.write_program_name(name)

        # Write entry symbols (PUBLIC symbols for library search)
        for sym in self.symbols.values():
            if (sym.public or self.export_all_symbols) and sym.defined:
                self.output.write_entry_symbol(sym.name)

        self.assemble_pass(lines, 2)

        if self.errors:
            return False

        # Finalize output
        # Write public symbol definitions
        # For relocatable symbols, subtract segment ORG so linker can add its base
        for sym in self.symbols.values():
            if (sym.public or self.export_all_symbols) and sym.defined:
                value = sym.value
                if sym.seg_type == ADDR_PROGRAM_REL and self.segments['CSEG'].org_set:
                    value -= self.segments['CSEG'].org
                elif sym.seg_type == ADDR_DATA_REL and self.segments['DSEG'].org_set:
                    value -= self.segments['DSEG'].org
                self.output.write_define_entry_point(sym.seg_type, value, sym.name)

        # Write external chains
        # The chain head is the LAST reference; linker walks backward through chain
        # Key is (name, expr_offset), so we emit separate entries for RNDX vs RNDX+1
        for (name, expr_offset), refs in self.ext_chains.items():
            if refs:
                # Get the last reference (head of chain)
                seg, offset = refs[-1]
                # For non-zero offsets, append "+N" to symbol name
                # Linker will parse this and add the offset to resolved address
                if expr_offset != 0:
                    sym_name = f"{name}+{expr_offset}"
                else:
                    sym_name = name
                self.output.write_chain_external(seg, offset, sym_name)

        # Write segment sizes (actual bytes, not location counter value)
        cseg = self.segments['CSEG']
        dseg = self.segments['DSEG']
        cseg_size = cseg.loc - cseg.org if cseg.org_set else cseg.loc
        dseg_size = dseg.loc - dseg.org if dseg.org_set else dseg.loc

        if cseg_size > 0:
            self.output.write_define_program_size(cseg_size)
        if dseg_size > 0:
            self.output.write_define_data_size(dseg_size)

        # Write COMMON sizes
        for name, com in self.common_blocks.items():
            if com.loc > 0:
                self.output.write_define_common_size(ADDR_ABSOLUTE, com.loc, name if name else ' ')

        # Write end with optional entry point
        if self.entry_point:
            val, seg = self.entry_point
            self.output.write_end_program(val, seg)
        else:
            self.output.write_end_program()

        self.output.write_end_file()

        return True


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
    parser.add_argument('-g', '--globals', action='store_true',
                        help='Export all symbols as PUBLIC (for debug symbol files)')
    parser.add_argument('-t', '--truncate', action='store_true',
                        help='Truncate symbols to 8 chars (M80 compatible)')
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
                    truncate_symbols=args.truncate, strict_jr=args.strict)
    if args.include:
        asm.include_paths = args.include
    if args.listing:
        asm.generate_listing = True
    success = asm.assemble(args.input)

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
    cseg_size = cseg.loc - cseg.org if cseg.org_set else cseg.loc
    dseg_size = dseg.loc - dseg.org if dseg.org_set else dseg.loc

    print(f"Assembled {args.input} -> {output_path}")
    print(f"  Code segment: {cseg_size} bytes (ORG {cseg.org:04X}H)" if cseg.org_set else f"  Code segment: {cseg_size} bytes")
    print(f"  Data segment: {dseg_size} bytes")
    print(f"  Symbols: {len(asm.symbols)}")

    sys.exit(0)


if __name__ == '__main__':
    main()
