"""Variables of a program: types, scopes, locations, values and expressions.

docs/debug_info.md (Variables) describes the data.  This module reads the
`types` and `vars` tables of prog.dbg and evaluates C expressions on them
for udb80 (um80/udb80.py) and for the GDB helper (um80/gdb/udb80_vars.py).
It uses only the standard library and reads memory through a function, so
both programs share it.

The value of a variable in a frame depends on the frame:

- ["at", ADDR]: the byte at ADDR.  This holds for a global, a static and a
  local in the shared area ??AUTO, in the frame of its routine.
- ["ix", N]: the byte at IX+N, where IX is the frame base of the routine.
  The frame base is known where the stack depth or the IX range says so.
- ["reg", R]: the register R, in the PC ranges of the record, in the
  innermost frame only (the other registers are not saved).
- null: "<not available>".
"""

import re

NOT_AVAILABLE = '<not available>'
MAX_ELEMENTS = 200

_NAMED = re.compile(r'^(struct|union|enum|typedef):([A-Za-z0-9_.$~]+)')
_BASE = re.compile(r'^([a-z]+):(\d+)')

BASE_C_NAMES = {
    'char': 'char', 'schar': 'signed char', 'uchar': 'unsigned char',
    'short': 'short', 'ushort': 'unsigned short', 'int': 'int',
    'uint': 'unsigned int', 'long': 'long', 'ulong': 'unsigned long',
    'llong': 'long long', 'ullong': 'unsigned long long', 'bool': '_Bool',
    'float': 'float', 'double': 'double', 'ldouble': 'long double',
}
UNSIGNED = ('uchar', 'ushort', 'uint', 'ulong', 'ullong', 'bool')
FLOATS = ('float', 'double', 'ldouble')
CHARS = ('char', 'schar', 'uchar')


class VarError(Exception):
    """A message for the user."""


class NoSuchName(VarError):
    """The name is not a variable in this scope."""


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

def parse_type(text):
    """The type of a type expression: a tuple.
    ('void',), ('base', name, size), ('ptr', t), ('arr', n or None, t),
    ('func', t), ('struct'|'union'|'enum'|'typedef', name), ('raw', n)."""
    t, rest = _parse(text)
    return t


def _parse(text):
    if text.startswith('*'):
        t, rest = _parse(text[1:])
        return ('ptr', t), rest
    if text.startswith('['):
        end = text.index(']')
        n = text[1:end]
        t, rest = _parse(text[end + 1:])
        return ('arr', int(n) if n else None, t), rest
    if text.startswith('func('):
        depth, i = 0, 4
        while i < len(text):
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        t, _ = _parse(text[5:i])
        return ('func', t), text[i + 1:]
    if text.startswith('void'):
        return ('void',), text[4:]
    m = _NAMED.match(text)
    if m:
        return (m.group(1), m.group(1) + ':' + m.group(2)), text[m.end():]
    m = re.match(r'^raw:(\d+)', text)
    if m:
        return ('raw', int(m.group(1))), text[m.end():]
    m = _BASE.match(text)
    if m:
        return ('base', m.group(1), int(m.group(2))), text[m.end():]
    raise VarError('unknown type "%s"' % text)


class Program(object):
    """The variables of a prog.dbg document."""

    def __init__(self, data):
        self.types = data.get('types') or {}
        self.vars = [Var(self, row) for row in (data.get('vars') or [])]
        self._parsed = {}
        self.ptr_size = 2

    def has_vars(self):
        return bool(self.vars)

    def type(self, text):
        t = self._parsed.get(text)
        if t is None:
            t = self._parsed[text] = parse_type(text)
        return t

    def resolve(self, t):
        """The type without typedef names."""
        seen = 0
        while t[0] == 'typedef' and seen < 32:
            d = self.types.get(t[1])
            if d is None:
                raise VarError('type %s is not defined' % t[1])
            t = self.type(d['target'])
            seen += 1
        return t

    def size(self, t):
        t = self.resolve(t)
        k = t[0]
        if k == 'base':
            return t[2]
        if k == 'ptr':
            return self.ptr_size
        if k == 'arr':
            return (t[1] or 0) * self.size(t[2])
        if k in ('struct', 'union', 'enum'):
            d = self.types.get(t[1])
            if d is None or d.get('size') is None:
                raise VarError('%s has no known size' % self.name(t))
            return d['size']
        if k == 'raw':
            return t[1]
        return 0

    def name(self, t, inner=''):
        """The C spelling of a type, with `inner' as the declarator text."""
        k = t[0]
        if k == 'void':
            return ('void ' + inner).rstrip()
        if k == 'base':
            return (BASE_C_NAMES.get(t[1], t[1]) + ' ' + inner).rstrip()
        if k == 'ptr':
            sub = t[1]
            if sub[0] in ('arr', 'func'):
                return self.name(sub, '(*' + inner + ')')
            return self.name(sub, '*' + inner)
        if k == 'arr':
            n = '' if t[1] is None else str(t[1])
            return self.name(t[2], inner + '[' + n + ']')
        if k == 'func':
            return self.name(t[1], inner + '(void)')
        if k in ('struct', 'union', 'enum'):
            tag = source_name(t[1].split(':', 1)[1])
            tag = '{...}' if tag.startswith('.') else tag
            return ('%s %s %s' % (k, tag, inner)).rstrip().replace('  ', ' ')
        if k == 'typedef':
            return (source_name(t[1].split(':', 1)[1]) + ' ' + inner).rstrip()
        if k == 'raw':
            return ('char[%d] %s' % (t[1], inner)).rstrip()
        return '?'

    def describe(self, t):
        """The text of `ptype': the definition of a struct, union or enum is
        written out; other types are spelled as C."""
        t = self.resolve(t) if t[0] == 'typedef' else t
        core, wrap = t, []
        while core[0] in ('ptr', 'arr', 'func'):
            wrap.append(core)
            core = core[2] if core[0] == 'arr' else core[1]
        if core[0] == 'typedef':
            core = self.resolve(core)
        if core[0] in ('struct', 'union', 'enum'):
            body = self._body(core)
            text = self.name(t)
            head = self.name(core)
            return text.replace(head, body, 1) if head in text else body
        return self.name(t)

    def _body(self, t):
        d = self.types.get(t[1])
        tag = t[1].split(':', 1)[1]
        head = t[0] + ('' if tag.startswith('.') else ' ' + tag)
        if d is None:
            return head + ' {\n    <incomplete type>\n}'
        if t[0] == 'enum':
            vals = ', '.join('%s = %d' % (n, v) for n, v in d['values'])
            return head + ' {' + vals + '}'
        lines = []
        for m in d['members']:
            decl = self.name(self.type(m[1]), m[0])
            if len(m) > 3:
                decl += ' : %d' % m[3]
            lines.append('    %s;' % decl)
        return head + ' {\n' + '\n'.join(lines) + '\n}'

    def member(self, t, name):
        """(offset, member type text, bit width, bit offset) or raise."""
        t = self.resolve(t)
        d = self.types.get(t[1]) if t[0] in ('struct', 'union') else None
        if d is None:
            raise VarError('There is no member named %s.' % name)
        for m in d['members']:
            if m[0] == name:
                return (m[2], self.type(m[1]),
                        m[3] if len(m) > 3 else None,
                        m[4] if len(m) > 4 else None)
        raise VarError('There is no member named %s.' % name)


class Var(object):
    """One row of the `vars' table of prog.dbg."""

    def __init__(self, program, row):
        (self.name, self.type_text, self.kind, self.loc, self.func,
         self.scope, self.ranges, self.decl) = row[:8]
        self.module = row[8] if len(row) > 8 else None
        self.why = row[9] if len(row) > 9 else None
        self.program = program

    @property
    def type(self):
        return self.program.type(self.type_text)


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

class Frame(object):
    """What a variable needs to know about a frame.

    pc: the address to look up (a return address minus 1 above frame 0)
    func: start address of the routine that holds pc, or None
    pos: (file index, line) of pc, or None
    index: 0 for the innermost frame
    regs: register values of frame 0, else None
    ix_base: the frame base of an IX routine, or None
    """

    def __init__(self, pc, func, pos, index, regs, ix_base):
        self.pc, self.func, self.pos = pc, func, pos
        self.index, self.regs, self.ix_base = index, regs, ix_base
        self.args_only = False      # ix_base is valid for IX+N with N > 0 only


def visible(program, frame):
    """The variables that the frame can name, innermost block first, then
    the statics and globals."""
    local, outer = [], []
    for v in program.vars:
        if v.func is None:
            outer.append(v)
        elif frame.func is not None and v.func == frame.func:
            local.append(v)
    keep = []
    for v in local:
        if frame.pos is not None and v.scope is not None:
            f, a, b = v.scope
            if f != frame.pos[0] or not a <= frame.pos[1] <= b:
                continue
            if (v.kind != 'param' and v.decl is not None
                    and v.decl[0] == f and frame.pos[1] < v.decl[1]):
                continue
        keep.append(v)

    def span(v):
        return (v.scope[2] - v.scope[1]) if v.scope else 1 << 30

    keep.sort(key=lambda v: (span(v), -(v.decl[1] if v.decl else 0)))
    return keep + outer


def source_name(name):
    """A tag or typedef name as the C source spells it: uc80 gives a type
    that two files define differently the suffix __tN in a multi-file build."""
    return re.sub(r'__t\d+$', '', name)


def lookup(program, frame, name):
    found = [v for v in visible(program, frame) if v.name == name]
    if found:
        # two files can each have a static of this name: the file of the
        # frame decides, else the first one
        if frame.pos is not None:
            for v in found:
                if v.decl is not None and v.decl[0] == frame.pos[0]:
                    return v
        return found[0]
    raise NoSuchName('No symbol "%s" in current context.' % name)


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------

class Value(object):
    """A typed value: in memory at `addr', or the bytes `raw'."""

    def __init__(self, type_, addr=None, raw=None, available=True,
                 bits=None):
        self.type, self.addr, self.raw = type_, addr, raw
        self.available = available
        self.bits = bits            # (width, shift) of a bitfield


class Context(object):
    """Memory, the frame and the program, for the evaluator."""

    def __init__(self, program, read, frame, symbolize=None, lookup_symbol=None):
        self.program = program
        self.read = read            # read(addr, length) -> bytes
        self.frame = frame
        self.symbolize = symbolize or (lambda a: '')
        self.lookup_symbol = lookup_symbol or (lambda n: None)

    # -- locations ----------------------------------------------------------

    def in_ranges(self, v):
        if not v.ranges:
            return True
        pc = self.frame.pc
        return any(a <= pc < b for a, b in v.ranges)

    def variable(self, v):
        """The Value of variable v in the frame."""
        t = v.type
        if v.loc is None or not self.in_ranges(v):
            return Value(t, available=False)
        kind = v.loc[0]
        if kind == 'at':
            return Value(t, addr=v.loc[1])
        if kind == 'ix':
            base = self.frame.ix_base
            if base is None or (self.frame.args_only and v.loc[1] < 4):
                return Value(t, available=False)
            return Value(t, addr=(base + v.loc[1]) & 0xFFFF)
        if kind == 'reg':
            regs = self.frame.regs
            if regs is None or self.frame.index != 0:
                return Value(t, available=False)
            raw = register_bytes(regs, v.loc[1])
            if raw is None:
                return Value(t, available=False)
            size = self.program.size(t)
            return Value(t, raw=raw[:size] if size else raw)
        return Value(t, available=False)

    # -- bytes ---------------------------------------------------------------

    def bytes_of(self, val, size=None):
        size = self.program.size(val.type) if size is None else size
        if not val.available:
            raise VarError(NOT_AVAILABLE)
        if val.raw is not None:
            return val.raw[:size].ljust(size, b'\0')
        data = self.read(val.addr, size)
        if len(data) < size:
            raise VarError('Cannot access memory at address 0x%04x'
                           % ((val.addr + len(data)) & 0xFFFF))
        return data

    def integer(self, val):
        t = self.program.resolve(val.type)
        if not val.available or (t[0] == 'arr' and val.addr is None):
            raise VarError(NOT_AVAILABLE)
        if t[0] == 'arr':
            return val.addr
        data = self.bytes_of(val)
        n = int.from_bytes(data, 'little')
        if val.bits:
            width, shift = val.bits
            n = (n >> shift) & ((1 << width) - 1)
            if self._signed(t) and n >> (width - 1):
                n -= 1 << width
            return n
        if self._signed(t) and data and n >> (len(data) * 8 - 1):
            n -= 1 << (len(data) * 8)
        return n

    def _signed(self, t):
        if t[0] == 'base':
            return t[1] not in UNSIGNED and t[1] not in FLOATS
        if t[0] == 'enum':
            return any(v < 0 for _n, v in
                       self.program.types.get(t[1], {}).get('values', ()))
        return False

    # -- formatting ------------------------------------------------------------

    def format(self, val, top=True):
        p = self.program
        if not val.available:
            return NOT_AVAILABLE
        t = p.resolve(val.type)
        k = t[0]
        if k == 'base':
            name = t[1]
            if name in FLOATS:
                return '<%s %s>' % (name, ' '.join(
                    '%02x' % b for b in self.bytes_of(val)))
            n = self.integer(val)
            if name in CHARS:
                return "%d %s" % (n, char_text(n & 0xFF))
            if name == 'bool':
                return 'true' if n else 'false'
            return str(n)
        if k == 'enum':
            n = self.integer(val)
            vals = p.types.get(t[1], {}).get('values', ())
            for name, v in vals:
                if v == n:
                    return name
            return str(n)
        if k == 'ptr':
            n = self.integer(val)
            target = p.resolve(t[1])
            sym = self.symbolize(n)
            if target[0] == 'base' and target[1] in CHARS and n:
                return '0x%04x%s %s' % (n, ' ' + sym if sym else '',
                                        self.c_string(n))
            if target[0] == 'func':
                return '(%s) 0x%04x%s' % (p.name(val.type), n,
                                          ' ' + sym if sym else '')
            text = '0x%04x' % n
            if sym:
                text += ' ' + sym
            return ('(%s) %s' % (p.name(val.type), text)) if top else text
        if k == 'arr':
            return self._array(val, t)
        if k in ('struct', 'union'):
            d = p.types.get(t[1])
            if d is None:
                raise VarError('%s is not defined' % p.name(t))
            parts = []
            for m in d['members']:
                sub = self.member(val, m[0])
                parts.append('%s = %s' % (m[0], self.format(sub, False)))
            return '{' + ', '.join(parts) + '}'
        if k == 'func':
            return '{%s} 0x%04x %s' % (p.name(val.type), val.addr or 0,
                                        self.symbolize(val.addr or 0))
        if k == 'void':
            return 'void'
        data = self.bytes_of(val)
        return '{' + ', '.join('0x%02x' % b for b in data) + '}'

    def _array(self, val, t):
        p = self.program
        elem = p.resolve(t[2])
        n = t[1] or 0
        esize = p.size(elem)
        if elem[0] == 'base' and elem[1] in CHARS and esize == 1 and n:
            data = self.bytes_of(val, n)
            end = data.find(b'\0')
            body = data if end < 0 else data[:end]
            return '"%s"' % escape_bytes(body)
        items = []
        shown = min(n, MAX_ELEMENTS)
        for i in range(shown):
            items.append(self.format(self.element(val, t, i), False))
        text = ', '.join(_runs(items))
        if n > shown:
            text += '...'
        return '{' + text + '}'

    def c_string(self, addr, limit=200):
        out = b''
        while len(out) < limit:
            chunk = self.read((addr + len(out)) & 0xFFFF, 1)
            if not chunk:
                return '<error: Cannot access memory at address 0x%04x>' % addr
            if chunk == b'\0':
                return '"%s"' % escape_bytes(out)
            out += chunk
        return '"%s"...' % escape_bytes(out)

    # -- navigation --------------------------------------------------------------

    def element(self, val, t, i):
        p = self.program
        esize = p.size(t[2])
        if not val.available or (val.raw is None and val.addr is None):
            return Value(t[2], available=False)
        if val.raw is not None:
            return Value(t[2], raw=val.raw[i * esize:(i + 1) * esize])
        return Value(t[2], addr=(val.addr + i * esize) & 0xFFFF,
                     available=val.available)

    def member(self, val, name):
        offset, mtype, width, shift = self.program.member(val.type, name)
        if not val.available:
            return Value(mtype, available=False)
        size = self.program.size(mtype)
        bits = (width, shift) if width else None
        if val.raw is not None:
            return Value(mtype, raw=val.raw[offset:offset + size], bits=bits)
        return Value(mtype, addr=(val.addr + offset) & 0xFFFF, bits=bits)

    def deref(self, val):
        t = self.program.resolve(val.type)
        if t[0] == 'ptr':
            target = t[1]
            n = self.integer(val)
            if self.program.resolve(target)[0] == 'void':
                raise VarError('Attempt to take contents of a non-pointer value.')
            return Value(target, addr=n & 0xFFFF)
        if t[0] == 'arr':
            return Value(t[2], addr=val.addr, available=val.available)
        raise VarError('Attempt to take contents of a non-pointer value.')


def register_bytes(regs, name):
    """The bytes of register `name' (upper case) from a dict with af, bc, de,
    hl, sp, pc, ix and iy, or None."""
    name = name.upper()
    pair = {'BC': 'bc', 'DE': 'de', 'HL': 'hl', 'IX': 'ix', 'IY': 'iy',
            'SP': 'sp', 'AF': 'af'}.get(name)
    if pair:
        return regs[pair].to_bytes(2, 'little')
    single = {'A': ('af', 1), 'B': ('bc', 1), 'C': ('bc', 0),
              'D': ('de', 1), 'E': ('de', 0), 'H': ('hl', 1),
              'L': ('hl', 0)}.get(name)
    if single:
        return bytes([(regs[single[0]] >> (8 * single[1])) & 0xFF])
    return None


def char_text(n):
    if 32 <= n < 127 and n != 39 and n != 92:
        return "'%s'" % chr(n)
    named = {0: '\\000', 7: '\\a', 8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f',
             13: '\\r', 39: "\\'", 92: '\\\\'}
    return "'%s'" % named.get(n, '\\%03o' % n)


def escape_bytes(data):
    out = ''
    for b in data:
        if b == 34:
            out += '\\"'
        elif b == 92:
            out += '\\\\'
        elif 32 <= b < 127:
            out += chr(b)
        else:
            out += {10: '\\n', 9: '\\t', 13: '\\r'}.get(b, '\\%03o' % b)
    return out


def _runs(items):
    """The item texts with a run of 10 or more equal items shortened as
    gdb does: `0 <repeats 12 times>`."""
    out, i = [], 0
    while i < len(items):
        j = i
        while j < len(items) and items[j] == items[i]:
            j += 1
        if j - i >= 10:
            out.append('%s <repeats %d times>' % (items[i], j - i))
        else:
            out.extend(items[i:j])
        i = j
    return out


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(0[xX][0-9a-fA-F]+|\d+|'(?:\\.|[^'\\])'|->|[A-Za-z_]\w*"
                    r"|\$\w+|[-+*/%&()\[\].])")


def tokenize(text):
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise VarError('Invalid character in "%s".' % text[pos:])
        out.append(m.group(1))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return out


INT_TYPE = ('base', 'int', 2)


class Evaluator(object):
    """Evaluates a C expression on variables.  Supported: names, numbers,
    character constants, `*p`, `&x`, `a[i]`, `s.m`, `p->m`, unary minus,
    `+ - * / %` on integers and pointer plus or minus an integer, and
    parentheses."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.p = ctx.program

    def evaluate(self, text):
        toks = tokenize(text)
        if not toks:
            raise VarError('Argument required (an expression).')
        self.toks, self.pos = toks, 0
        val = self.expr()
        if self.pos != len(toks):
            raise VarError('Invalid expression near "%s".' % toks[self.pos])
        return val

    # -- parser -------------------------------------------------------------

    def peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def take(self):
        t = self.peek()
        self.pos += 1
        return t

    def expr(self):
        v = self.term()
        while self.peek() in ('+', '-'):
            op = self.take()
            v = self.add(v, self.term(), op)
        return v

    def term(self):
        v = self.unary()
        while self.peek() in ('*', '/', '%'):
            # `*' after a complete operand is multiplication
            op = self.take()
            w = self.unary()
            a, b = self.number(v), self.number(w)
            if op == '*':
                r = a * b
            elif b == 0:
                raise VarError('Division by zero')
            elif op == '/':
                r = int(a / b)
            else:
                r = a - b * int(a / b)
            v = self.make_int(r)
        return v

    def unary(self):
        t = self.peek()
        if t == '-':
            self.take()
            return self.make_int(-self.number(self.unary()))
        if t == '*':
            self.take()
            return self.ctx.deref(self.unary())
        if t == '&':
            self.take()
            v = self.unary()
            if not v.available:
                raise VarError(NOT_AVAILABLE)
            if v.addr is None:
                raise VarError('Attempt to take address of value not located in memory.')
            return Value(('ptr', v.type), raw=(v.addr & 0xFFFF).to_bytes(2, 'little'))
        return self.postfix()

    def postfix(self):
        v = self.primary()
        while True:
            t = self.peek()
            if t == '[':
                self.take()
                idx = self.number(self.expr())
                if self.take() != ']':
                    raise VarError('A "]" is missing.')
                v = self.index(v, idx)
            elif t == '.':
                self.take()
                v = self.ctx.member(v, self.take())
            elif t == '->':
                self.take()
                v = self.ctx.member(self.ctx.deref(v), self.take())
            else:
                return v

    def primary(self):
        t = self.take()
        if t is None:
            raise VarError('Invalid expression: it ends too early.')
        if t == '(':
            v = self.expr()
            if self.take() != ')':
                raise VarError('A ")" is missing.')
            return v
        if t[0] == "'":
            body = t[1:-1]
            n = ord(body[-1]) if body[0] != '\\' else {
                'n': 10, 't': 9, 'r': 13, '0': 0, '\\': 92, "'": 39}.get(
                body[1], ord(body[1]))
            return self.make_int(n, ('base', 'char', 1))
        if t[0].isdigit():
            return self.make_int(int(t, 0))
        if not (t[0].isalpha() or t[0] == '_'):
            raise NoSuchName('Invalid token "%s".' % t)
        v = lookup(self.p, self.ctx.frame, t)
        return self.ctx.variable(v)

    # -- operations ------------------------------------------------------------

    def make_int(self, n, type_=INT_TYPE):
        size = self.p.size(type_)
        return Value(type_, raw=(n & ((1 << (8 * size)) - 1)).to_bytes(size, 'little'))

    def number(self, v):
        t = self.p.resolve(v.type)
        if t[0] not in ('base', 'enum', 'ptr', 'arr') or (
                t[0] == 'base' and t[1] in FLOATS):
            raise VarError('Argument to arithmetic operation not a number or boolean.')
        return self.ctx.integer(v)

    def add(self, a, b, op):
        ta, tb = self.p.resolve(a.type), self.p.resolve(b.type)
        sign = 1 if op == '+' else -1
        if not a.available or not b.available:
            raise VarError(NOT_AVAILABLE)
        if ta[0] in ('ptr', 'arr') and tb[0] not in ('ptr', 'arr'):
            elem = ta[1] if ta[0] == 'ptr' else ta[2]
            step = max(self.p.size(elem), 1)
            n = (self.number(a) + sign * self.number(b) * step) & 0xFFFF
            return Value(('ptr', elem), raw=n.to_bytes(2, 'little'))
        if tb[0] in ('ptr', 'arr') and ta[0] not in ('ptr', 'arr') and op == '+':
            return self.add(b, a, op)
        if ta[0] in ('ptr', 'arr') and tb[0] in ('ptr', 'arr') and op == '-':
            elem = ta[1] if ta[0] == 'ptr' else ta[2]
            return self.make_int((self.number(a) - self.number(b))
                                 // max(self.p.size(elem), 1))
        return self.make_int(self.number(a) + sign * self.number(b))

    def index(self, v, i):
        t = self.p.resolve(v.type)
        if t[0] == 'arr':
            if t[1] is not None and not 0 <= i < t[1]:
                # gdb reads outside the array; so does this debugger
                pass
            return self.ctx.element(v, t, i)
        if t[0] == 'ptr':
            esize = self.p.size(t[1])
            return Value(t[1], addr=(self.ctx.integer(v) + i * esize) & 0xFFFF)
        raise VarError('cannot subscript something of type `%s\''
                       % self.p.name(v.type))
