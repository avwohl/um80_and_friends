"""GDB commands for the variables that GDB cannot read from DWARF.

Load the file in GDB with a `source` line, after udb80_unwind.py:

    (gdb) source /path/to/um80/gdb/udb80_vars.py

`python3 -m um80.dbg2elf --vars-path` prints the path.  docs/gdb.md has the
user view.

What GDB 18.1 does without this file (measured with the z80 target):

- A variable at a fixed address (a global, a static, a local in the shared
  area ??AUTO) works: `dbg2elf` writes DW_OP_addr.
- A variable at IX+N works when udb80_unwind.py is loaded: `dbg2elf` writes
  DW_OP_fbreg N-4 with the frame base DW_OP_call_frame_cfa, and the unwinder
  gives each frame an id whose stack address is the address after the
  return address (IX+4).  Without the unwinder GDB cannot compute the CFA.
- A variable in a register does not work: the z80 port has no DWARF register
  numbers, and the register of a local holds the local only in part of the
  routine.  `dbg2elf` writes no record for it.

The commands below read prog.dbg themselves (the same file as udb80) and give
every kind of variable, with the same rules as udb80:

    zlocals            the locals of the selected frame
    zargs              the arguments of the selected frame
    zprint EXPR        a C expression on variables: name, *p, p->m, s.m,
                       a[i], &x, + and -
    zptype EXPR|TYPE   the type of an expression, or the definition of a type
    udb80-vars-dbg F   use the debug file F

A variable in a register is shown only in frame 0 and inside the PC ranges of
its record; elsewhere GDB shows <not available>.
"""

import importlib.util
import os

import gdb  # pylint: disable=import-error


def _vars_load(name, filename):
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(os.path.dirname(here), filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vardata = _vars_load('udb80_vardata', 'vardata.py')


class VarsState(object):
    def __init__(self):
        self.path = None
        self.loaded = None          # (path, program, funcs)

    def find(self):
        path = self.path or os.environ.get('UDB80_DBG')
        if not path:
            try:
                prog = gdb.selected_inferior().progspace.filename
            except (gdb.error, AttributeError):
                prog = None
            if prog:
                path = os.path.splitext(prog)[0] + '.dbg'
        if not path or not os.path.exists(path):
            raise gdb.GdbError('no prog.dbg: use "udb80-vars-dbg FILE" or '
                               'set UDB80_DBG')
        if self.loaded is None or self.loaded[0] != path:
            import json
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            funcs = sorted((f for f in data.get('funcs') or []
                            if f.get('start') is not None),
                           key=lambda f: f['start'])
            lines = sorted(data.get('lines') or [], key=lambda r: r[0])
            self.loaded = (path, vardata.Program(data), funcs, lines)
        return self.loaded


VARS_STATE = VarsState()


def _vars_func_at(funcs, addr):
    best = None
    for f in funcs:
        if f['start'] <= addr and (f.get('end') is None or addr < f['end']):
            best = f
    return best


def _vars_read(addr, length):
    try:
        return bytes(gdb.selected_inferior().read_memory(addr, length))
    except gdb.MemoryError:
        return b''


def _vars_regs(frame):
    out = {}
    for name in ('af', 'bc', 'de', 'hl', 'sp', 'pc', 'ix', 'iy'):
        try:
            out[name] = int(frame.read_register(name)) & 0xFFFF
        except gdb.error:
            out[name] = 0
    return out


def vars_context(frame=None):
    """(vardata.Context, funcs) for a GDB frame (default: the selected one)."""
    _path, program, funcs, lines = VARS_STATE.find()
    frame = frame or gdb.selected_frame()
    level = frame.level()
    pc = int(frame.pc())
    probe = pc if level == 0 else pc - 1
    rec = _vars_func_at(funcs, probe)
    start = rec['start'] if rec else None
    pos = None
    for e in lines:
        if e[0] <= probe < e[1]:
            pos = (e[2][-1][0], e[2][-1][1])
            break
    base = None
    args_only = False
    if rec is not None and rec.get('frame') == 'ix':
        older = frame.older()
        rng = rec.get('ix')
        if older is not None:
            # the unwinder gives the caller the SP after the return: the CFA
            # of this frame, which is IX + 4 + pops
            base = int(older.read_register('sp')) - 4 - (rec.get('pops') or 0)
            if level == 0 and not (rng and rng[0] <= pc <= rng[1]):
                args_only = True
        elif level == 0 and rng and rng[0] <= pc <= rng[1]:
            base = int(frame.read_register('ix')) & 0xFFFF
    vframe = vardata.Frame(probe, start, pos, level,
                           _vars_regs(frame) if level == 0 else None, base)
    vframe.args_only = args_only
    ctx = vardata.Context(program, _vars_read, vframe)
    return ctx, program


def _vars_lines(params):
    ctx, program = vars_context()
    out = []
    for v in vardata.visible(program, ctx.frame):
        if v.func is None or (v.kind == 'param') != params:
            continue
        try:
            text = ctx.format(ctx.variable(v))
        except vardata.VarError as e:
            text = f'<{e}>'
        out.append(f'{v.name} = {text}')
    return out


class ZLocals(gdb.Command):
    """List the locals of the selected frame, including register locals."""

    def __init__(self):
        super(ZLocals, self).__init__('zlocals', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        text = _vars_lines(False)
        print('\n'.join(text) if text else 'No locals.')


class ZArgs(gdb.Command):
    """List the arguments of the selected frame, including register ones."""

    def __init__(self):
        super(ZArgs, self).__init__('zargs', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        text = _vars_lines(True)
        print('\n'.join(text) if text else 'No arguments.')


class ZPrint(gdb.Command):
    """Print a C expression on the variables of the selected frame."""

    def __init__(self):
        super(ZPrint, self).__init__('zprint', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        if not arg.strip():
            raise gdb.GdbError('Argument required (an expression).')
        ctx, _program = vars_context()
        try:
            val = vardata.Evaluator(ctx).evaluate(arg)
            print(ctx.format(val))
        except vardata.VarError as e:
            raise gdb.GdbError(str(e))


class ZPtype(gdb.Command):
    """Print the type of an expression, or the definition of a type."""

    def __init__(self):
        super(ZPtype, self).__init__('zptype', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        ctx, program = vars_context()
        text = arg.strip()
        import re
        m = re.fullmatch(r'(struct|union|enum)\s+(\S+)', text)
        try:
            if m:
                key = m.group(1) + ':' + m.group(2)
                if key not in program.types:
                    raise gdb.GdbError(f'No {m.group(1)} type named {m.group(2)}.')
                t = (m.group(1), key)
            elif 'typedef:' + text in program.types:
                t = ('typedef', 'typedef:' + text)
            else:
                t = vardata.Evaluator(ctx).evaluate(text).type
        except vardata.VarError as e:
            raise gdb.GdbError(str(e))
        print('type = ' + program.describe(t))


class VarsDbgFile(gdb.Command):
    """udb80-vars-dbg FILE: the prog.dbg file for zlocals and zprint."""

    def __init__(self):
        super(VarsDbgFile, self).__init__('udb80-vars-dbg', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        VARS_STATE.path = arg.strip() or None
        VARS_STATE.loaded = None
        VARS_STATE.find()


for _cls in (ZLocals, ZArgs, ZPrint, ZPtype, VarsDbgFile):
    _cls()
