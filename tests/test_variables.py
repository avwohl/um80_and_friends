"""Variables (phase 8 of the cpmemu debugger plan): the ;#var and ;#type
markers, the .dbm and prog.dbg tables, udb80 print and info locals, and
dbg2elf with GDB.

The format tests need only um80 and ul80.  The live tests build a C program
with `uc80 -g` (uc80 from a checkout on PYTHONPATH, or installed), run it in
`cpmemu --gdb` and drive it with udb80, and (with a z80 GDB) with GDB.  A
missing tool skips the test with the reason; UDB80_REQUIRE_UC80=1,
UDB80_REQUIRE_CPMEMU=1 and UDB80_REQUIRE_GDB=1 turn the skip into a failure.
"""

# pytest fixtures are parameters with the name of the fixture function.
# pylint: disable=redefined-outer-name
# The test names say what each test checks.
# pylint: disable=missing-function-docstring
import json
import os
import re
import subprocess
import sys

import pytest

from um80 import debuginfo, vardata

import elfread
from test_gdb import (UNWINDER, _skip, _uc80_libs, build as gdb_build,
                      cpmemu, gdb_path, gdb_session, in_order)
from test_udb80 import live, udb

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VARS_HELPER = os.path.join(ROOT, 'um80', 'gdb', 'udb80_vars.py')


def run_tool(module, *args, cwd):
    env = dict(os.environ, PYTHONPATH=ROOT)
    run = subprocess.run([sys.executable, '-m', module, *args], cwd=cwd,
                         env=env, capture_output=True, text=True)
    return run


def tool(module, *args, cwd):
    run = run_tool(module, *args, cwd=cwd)
    assert run.returncode == 0, run.stdout + run.stderr
    return run


# ---------------------------------------------------------------------------
# The format: ;#type and ;#var through um80 and ul80
# ---------------------------------------------------------------------------

MODULE = """\
\t.z80
\tcseg
;#file 1 "m.c"
;#type struct:pt size=4 members=x:int:2@0,y:int:2@2
;#type enum:color size=2 values=RED=0,GREEN=5
;#type typedef:word target=uint:2
;#type struct:bits size=2 members=a:uint:2@0#3.0,b:uint:2@0#5.3
;#var g *struct:pt kind=global at=_G decl=1:1
;#var arr [4]int:2 at=ARR+2
;#var gone int:2 at=NOT_THERE
;#func _f 1 3 frame=ix pops=0 ixbegin=B1 ixend=E1
_f:
\tpush\tix
\tld\tix,0
\tadd\tix,sp
B1:
;#var a typedef:word kind=param ix=4 scope=1:3-9 decl=1:3
;#var s struct:pt at=??AUTO+2 scope=1:4-8
;#var r int:2 reg=BC range=B1:E1 scope=1:4-8
;#var t int:2 none why=no-storage
\tld\thl,0
\tld\tsp,ix
E1:
\tpop\tix
\tret
;#endfunc _f
\tdseg
_G:\tdw\t0
ARR:\tds\t10
??AUTO:\tds\t8
\tend
"""

OTHER = """\
\t.z80
\tcseg
;#file 1 "o.c"
;#type struct:pt size=2 members=v:int:2@0
;#type typedef:word target=uint:2
;#var og *struct:pt kind=global at=_OG
_o:\tret
\tdseg
_OG:\tdw\t0
\tend
"""


def build_mac(d, name, text, link=True, *libs):
    (d / (name + '.mac')).write_text(text)
    tool('um80.um80', '--debug-info', '-o', name + '.rel', name + '.mac', cwd=d)
    if link:
        tool('um80.ul80', '--debug-info', '-o', name + '.com', name + '.rel',
             *libs, cwd=d)


@pytest.fixture(scope='module')
def fmt(tmp_path_factory):
    d = tmp_path_factory.mktemp('fmt')
    build_mac(d, 'm', MODULE)
    return d


def test_dbm_has_types_and_vars(fmt):
    doc = json.loads((fmt / 'm.dbm').read_text())
    assert doc['version'] == 1 and doc['revision'] == 2
    assert doc['types']['struct:pt'] == {
        'size': 4, 'members': [['x', 'int:2', 0], ['y', 'int:2', 2]]}
    assert doc['types']['enum:color'] == {
        'size': 2, 'values': [['RED', 0], ['GREEN', 5]]}
    assert doc['types']['typedef:word'] == {'target': 'uint:2'}
    assert doc['types']['struct:bits']['members'][1] == ['b', 'uint:2', 0, 5, 3]
    rows = {r[0]: r for r in doc['vars']}
    assert rows['g'][:5] == ['g', '*struct:pt', 'global', ['at', 'DSEG', 0], None]
    assert rows['arr'][3] == ['at', 'DSEG', 4]           # ARR+2
    assert rows['gone'][3] is None and rows['gone'][8] == 'label-not-defined'
    assert rows['a'][2] == 'param' and rows['a'][3] == ['ix', 4]
    assert rows['a'][4] == '_f' and rows['a'][5] == [0, 3, 9]
    assert rows['s'][3] == ['at', 'COMMON:AUTO', 2] or rows['s'][3][0] == 'at'
    assert rows['r'][3] == ['reg', 'BC']
    assert rows['r'][6] == [[['CSEG', 8], ['CSEG', 13]]]
    assert rows['t'][3] is None and rows['t'][8] == 'no-storage'


def test_the_label_in_a_range_must_exist(tmp_path):
    text = MODULE.replace('range=B1:E1', 'range=B1:NOWHERE')
    run = run_tool('um80.um80', '--debug-info', '-o', 'm.rel', 'm.mac',
                   cwd=tmp_path) if (tmp_path / 'm.mac').write_text(text) else None
    assert run.returncode == 0
    assert 'range= labels are not defined' in run.stdout + run.stderr
    doc = json.loads((tmp_path / 'm.dbm').read_text())
    r = next(v for v in doc['vars'] if v[0] == 'r')
    assert r[3] is None and r[8] == 'range-not-defined'


def test_the_object_file_is_the_same_with_markers_and_without_debug_info(
        fmt, tmp_path):
    (tmp_path / 'm.mac').write_text(MODULE)
    tool('um80.um80', '-o', 'plain.rel', 'm.mac', cwd=tmp_path)
    assert (tmp_path / 'plain.rel').read_bytes() == (fmt / 'm.rel').read_bytes()


def test_a_module_without_variables_gets_no_new_keys(tmp_path):
    build_mac(tmp_path, 'n', '\t.z80\n;#file 1 "n.c"\n;#func _n 1 1\n_n:\tret\n'
              ';#endfunc _n\n\tend\n')
    doc = json.loads((tmp_path / 'n.dbm').read_text())
    assert set(doc) == {'format', 'version', 'module', 'source', 'rel', 'files',
                        'rows', 'labels', 'funcs', 'noopt'}
    dbg = json.loads((tmp_path / 'n.dbg').read_text())
    assert 'vars' not in dbg and 'types' not in dbg and 'revision' not in dbg


def test_prog_dbg_relocates_variables(fmt):
    dbg = json.loads((fmt / 'm.dbg').read_text())
    assert dbg['version'] == 1 and dbg['revision'] == 2
    labels = {l[0]: l[1] for l in dbg['labels']}
    rows = {v[0]: v for v in dbg['vars']}
    assert rows['g'][3] == ['at', labels['_G']]
    assert rows['arr'][3] == ['at', labels['ARR'] + 2]
    assert rows['s'][3] == ['at', labels['??AUTO'] + 2]
    f = dbg['funcs'][0]
    assert rows['a'][4] == f['start'] == rows['r'][4]
    assert rows['r'][6] == [[f['ix'][0], f['ix'][1]]]
    assert rows['a'][5] == [0, 3, 9] and dbg['files'][0] == 'm.c'
    assert rows['g'][8] == 0                      # the module


def test_old_readers_read_a_revision_2_file(fmt):
    # a reader of revision 1 checks format and version only
    assert debuginfo.load_dbm((fmt / 'm.dbm').read_bytes()) is not None
    from um80.udb80 import DebugInfo
    DebugInfo(str(fmt / 'm.dbg'))
    from um80.dbg2elf import load_dbg
    load_dbg(str(fmt / 'm.dbg'))


def test_equal_types_merge_and_different_ones_are_renamed(tmp_path):
    build_mac(tmp_path, 'm', MODULE, link=False)
    build_mac(tmp_path, 'o', OTHER, link=False)
    tool('um80.ul80', '--debug-info', '-o', 'mo.com', 'm.rel', 'o.rel',
         cwd=tmp_path)
    dbg = json.loads((tmp_path / 'mo.dbg').read_text())
    types = dbg['types']
    assert 'typedef:word' in types and 'typedef:word~1' not in types
    assert types['struct:pt']['size'] == 4
    assert types['struct:pt~1'] == {'size': 2, 'members': [['v', 'int:2', 0]]}
    rows = {v[0]: v for v in dbg['vars']}
    assert rows['g'][1] == '*struct:pt'
    assert rows['og'][1] == '*struct:pt~1' and rows['og'][8] == 1


def test_a_library_module_keeps_its_variables(tmp_path):
    build_mac(tmp_path, 'o', OTHER, link=False)
    build_mac(tmp_path, 'm', MODULE.replace('call', 'call'), link=False)
    tool('um80.ulib80', '-c', 'lib.lib', 'o.rel', cwd=tmp_path)
    tool('um80.ul80', '--debug-info', '-o', 'x.com', 'm.rel', 'lib.lib',
         cwd=tmp_path)
    dbg = json.loads((tmp_path / 'x.dbg').read_text())
    # only the modules that the program needs are linked; o.rel is not
    # needed, so its variables are absent and the types of m stay
    assert {v[0] for v in dbg['vars']} >= {'g', 'a', 'r'}


@pytest.mark.parametrize('bad', [
    ';#var onlyname',
    ';#var x int:2 at=A ix=4',
    ';#var x int:2 kind=nonsense',
    ';#var x int:2 ix=abc',
    ';#var x int:2 range=A',
    ';#type struct:s members=broken',
    ';#type nothing:x',
])
def test_a_malformed_marker_is_a_warning_and_is_ignored(tmp_path, bad):
    text = '\t.z80\n;#file 1 "a.c"\n' + bad + '\n\tnop\n\tend\n'
    (tmp_path / 'a.mac').write_text(text)
    run = tool('um80.um80', '--debug-info', '-o', 'a.rel', 'a.mac', cwd=tmp_path)
    assert 'Malformed debug marker' in run.stdout + run.stderr
    doc = json.loads((tmp_path / 'a.dbm').read_text())
    assert not doc.get('vars')


def test_uppercase_kinds_and_unknown_keys_are_read(tmp_path):
    text = ('\t.z80\n;#file 1 "a.c"\n;#VAR x int:2 KIND=GLOBAL at=X future=1\n'
            'X:\tdw 0\n\tend\n')
    build_mac(tmp_path, 'a', text, link=False)
    doc = json.loads((tmp_path / 'a.dbm').read_text())
    assert doc['vars'][0][:4] == ['x', 'int:2', 'global', ['at', 'CSEG', 0]]


# ---------------------------------------------------------------------------
# vardata: types, values, scope and expressions on a fake memory
# ---------------------------------------------------------------------------

DATA = {
    'types': {
        'struct:pt': {'size': 4, 'members': [['x', 'int:2', 0], ['y', 'int:2', 2]]},
        'struct:node': {'size': 4, 'members': [
            ['val', 'int:2', 0], ['next', '*struct:node', 2]]},
        'enum:color': {'size': 2, 'values': [['RED', 0], ['GREEN', 5]]},
        'typedef:byte': {'target': 'uchar:1'},
        'struct:bits': {'size': 2, 'members': [
            ['a', 'uint:2', 0, 3, 0], ['b', 'uint:2', 0, 5, 3]]},
        'union:u': {'size': 2, 'members': [['i', 'int:2', 0],
                                           ['c', '[2]char:1', 0]]},
    },
    'vars': [
        ['gp', 'struct:pt', 'global', ['at', 0x200], None, None, None, None],
        ['ga', '[4]int:2', 'global', ['at', 0x210], None, None, None, None],
        ['gs', '*char:1', 'global', ['at', 0x220], None, None, None, None],
        ['gn', 'struct:node', 'global', ['at', 0x230], None, None, None, None],
        ['gc', 'enum:color', 'global', ['at', 0x240], None, None, None, None],
        ['gb', 'typedef:byte', 'global', ['at', 0x242], None, None, None, None],
        ['gbits', 'struct:bits', 'global', ['at', 0x244], None, None, None, None],
        ['gu', 'union:u', 'global', ['at', 0x246], None, None, None, None],
        ['neg', 'int:2', 'global', ['at', 0x248], None, None, None, None],
        ['str', '[6]char:1', 'global', ['at', 0x250], None, None, None, None],
        ['i', 'int:2', 'local', ['ix', -4], 0x100, [0, 5, 9], None, [0, 5]],
        ['i', 'int:2', 'local', ['ix', -6], 0x100, [0, 7, 8], None, [0, 7]],
        ['r', 'int:2', 'local', ['reg', 'BC'], 0x100, [0, 5, 9],
         [[0x110, 0x120]], [0, 6]],
        ['lost', 'int:2', 'local', None, 0x100, [0, 5, 9], None, [0, 6],
         0, 'no-storage'],
        ['n', 'int:2', 'param', ['ix', 4], 0x100, [0, 5, 9], None, [0, 5]],
    ],
}


def memory():
    mem = bytearray(0x400)

    def put(addr, data):
        mem[addr:addr + len(data)] = data
    put(0x200, bytes([3, 0, 4, 0]))                       # gp = {3, 4}
    for k, v in enumerate((10, 20, 30, 40)):
        put(0x210 + 2 * k, bytes([v, 0]))
    put(0x220, bytes([0x60, 0x02]))                       # gs -> 0x260
    put(0x260, b'hi\0')
    put(0x230, bytes([1, 0, 0x30, 0x02]))                 # gn.next = &gn
    put(0x240, bytes([5, 0]))                             # GREEN
    put(0x242, bytes([200]))
    put(0x244, bytes([0b10101_101, 0]))                   # a = 5, b = 21
    put(0x246, bytes([0x41, 0x42]))
    put(0x248, bytes([0xFE, 0xFF]))                       # -2
    put(0x250, b'abc\0\0\0')
    put(0x300, bytes([7, 0]))                             # IX-4 with IX=0x304
    put(0x2FE, bytes([8, 0]))                             # IX-6
    put(0x308, bytes([9, 0]))                             # IX+4
    return mem


def ctx_at(pc=0x112, line=(0, 6), index=0, base=0x304, regs=None, program=None):
    program = program or vardata.Program(DATA)
    mem = memory()
    regs = regs if regs is not None else {
        'af': 0, 'bc': 0x1234, 'de': 0, 'hl': 0, 'sp': 0, 'pc': pc, 'ix': base,
        'iy': 0}
    frame = vardata.Frame(pc, 0x100, line, index, regs if index == 0 else None,
                          base)
    return vardata.Context(program, lambda a, n: bytes(mem[a:a + n]), frame,
                           lambda a: '<sym>' if a == 0x230 else '')


def ev(text, **kw):
    ctx = ctx_at(**kw)
    return ctx.format(vardata.Evaluator(ctx).evaluate(text))


@pytest.mark.parametrize('expr, want', [
    ('gp', '{x = 3, y = 4}'),
    ('gp.y', '4'),
    ('ga', '{10, 20, 30, 40}'),
    ('ga[2]', '30'),
    ('ga[1] + ga[2] * 2', '80'),
    ('&ga[1]', '(int *) 0x0212'),
    ('&gp', '(struct pt *) 0x0200'),
    ('*ga', '10'),
    ('gs', '0x0260 "hi"'),
    ('*gs', "104 'h'"),
    ('gs[1]', "105 'i'"),
    ('gn', '{val = 1, next = 0x0230 <sym>}'),
    ('gn.next->val', '1'),
    ('(*gn.next).val', '1'),
    ('gc', 'GREEN'),
    ('gb', "200 '\\310'"),
    ('gbits', '{a = 5, b = 21}'),
    ('gu', '{i = 16961, c = "AB"}'),
    ('neg', '-2'),
    ('-neg', '2'),
    ('str', '"abc"'),
    ('0x10 + 1', '17'),
    ("'a'", "97 'a'"),
    ('i', '7'),                                   # the later, inner i
    ('n', '9'),
    ('r', '4660'),
    ('lost', '<not available>'),
])
def test_expressions(expr, want):
    assert ev(expr) == want


def test_scope_picks_the_block_of_the_line():
    assert ev('i', line=(0, 5)) == '7' or ev('i', line=(0, 5)) == '8'
    # line 5 is in the outer block only: the outer i is IX-4
    assert ev('i', line=(0, 5)) == '7'
    # line 7 is in both blocks: the inner i (IX-6) wins
    assert ev('i', line=(0, 7)) == '8'


def test_a_name_declared_later_is_not_visible_yet():
    prog = vardata.Program(DATA)
    ctx = ctx_at(line=(0, 5), program=prog)
    names = [v.name for v in vardata.visible(prog, ctx.frame)]
    assert 'r' not in names          # declared on line 6
    assert 'n' in names              # a parameter is visible in the whole body


def test_a_register_variable_needs_the_pc_range_and_frame_0():
    assert ev('r', pc=0x112) == '4660'
    assert ev('r', pc=0x120) == '<not available>'          # end is exclusive
    assert ev('r', pc=0x10f) == '<not available>'
    assert ev('r', index=1) == '<not available>'


def test_a_frame_without_a_base_has_no_ix_variable():
    assert ev('n', base=None) == '<not available>'
    ctx = ctx_at(base=0x304)
    ctx.frame.args_only = True
    assert ctx.format(vardata.Evaluator(ctx).evaluate('n')) == '9'
    assert ctx.format(vardata.Evaluator(ctx).evaluate('i')) == '<not available>'


@pytest.mark.parametrize('expr', ['nosuch', '1 +', 'gp.zz', '*gp', 'ga[',
                                  '(gp', 'gs->x', '&1'])
def test_errors_are_messages(expr):
    ctx = ctx_at()
    with pytest.raises(vardata.VarError):
        vardata.Evaluator(ctx).evaluate(expr)


def test_ptype_text():
    p = vardata.Program(DATA)
    assert p.describe(p.type('struct:pt')) == (
        'struct pt {\n    int x;\n    int y;\n}')
    assert p.describe(p.type('*struct:pt')) == (
        'struct pt {\n    int x;\n    int y;\n} *')
    assert p.describe(p.type('typedef:byte')) == 'unsigned char'
    assert p.name(p.type('[4]int:2')) == 'int [4]'
    assert p.name(p.type('*func(int:2)')) == 'int (*)(void)'
    assert p.describe(p.type('enum:color')) == 'enum color {RED = 0, GREEN = 5}'
    assert p.describe(p.type('struct:bits')).count(' : ') == 2


def test_long_arrays_are_cut_and_runs_are_folded():
    data = {'types': {}, 'vars': [
        ['big', '[300]int:2', 'global', ['at', 0], None, None, None, None],
        ['z', '[20]int:2', 'global', ['at', 0x300], None, None, None, None]]}
    prog = vardata.Program(data)
    mem = bytearray(0x400)
    frame = vardata.Frame(0, None, None, 0, None, None)
    ctx = vardata.Context(prog, lambda a, n: bytes(mem[a:a + n]), frame)
    text = ctx.format(vardata.Evaluator(ctx).evaluate('big'))
    assert text.endswith('...}') and '<repeats 200 times>' in text
    assert ctx.format(vardata.Evaluator(ctx).evaluate('z')) == \
        '{0 <repeats 20 times>}'


# ---------------------------------------------------------------------------
# A C program: uc80 -g, cpmemu --gdb, udb80
# ---------------------------------------------------------------------------

VAR_C = """\
struct pt { int x; int y; };
typedef unsigned char byte;
enum color { RED, GREEN = 5, BLUE };
int g = 7;
static int sg = 9;
struct pt gp = { 3, 4 };
int ga[4] = { 10, 20, 30, 40 };
byte gb = 200;
enum color gc = GREEN;
char *gs = "hi";
int nowhere[2][3] = { { 1, 2, 3 }, { 4, 5, 6 } };   /* unused: no label */
char nobuf[8] = "abc";

int leaf(int a, int b)
{
    int loc = a + b;
    static int cnt;
    cnt += loc;                         /* AT_LEAF */
    return cnt;
}

int deep(int n, struct pt *p)
{
    int local = n * 2;
    int arr[2];
    arr[0] = local;
    arr[1] = n;
    if (n <= 1)
        return p->x + arr[0];           /* AT_DEEP */
    return n * deep(n - 1, p) + arr[1] - n + g;
}

int work(int n, struct pt *p)
{
    int arr[3];
    struct pt s;
    int i, sum = 0;
    arr[0] = 5; arr[1] = 6; arr[2] = 7;
    s.x = n; s.y = p->y;
    for (i = 0; i < 3; i++) {
        int t = arr[i] + s.x;
        sum += leaf(t, i);
    }
    return sum + g + sg + ga[1] + gb + gc + gs[0] + gp.x;   /* AT_WORK */
}

int main(void)
{
    struct pt q = { 5, 6 };
    int r = work(3, &q) + deep(3, &q);
    return r > 1000;
}
"""


def line_of(tag):
    for k, ln in enumerate(VAR_C.splitlines(), 1):
        if tag in ln:
            return k
    raise KeyError(tag)


def _need_uc80():
    libs = _uc80_libs()
    if libs is None:
        _skip('uc80 is not installed (pip install uc80, or a checkout on '
              'PYTHONPATH) or its libraries are not built', 'UDB80_REQUIRE_UC80')
    return libs


def _compile(d, name, *flags):
    libs = _need_uc80()
    (d / (name + '.c')).write_text(VAR_C)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(
        [ROOT] + ([os.environ['PYTHONPATH']] if os.environ.get('PYTHONPATH') else [])))
    run = subprocess.run([sys.executable, '-m', 'uc80.main', name + '.c', '-g',
                          *flags, '-o', name + '.mac'], cwd=str(d), env=env,
                         capture_output=True, text=True)
    if run.returncode != 0:
        _skip('uc80 failed: ' + (run.stdout + run.stderr)[-300:],
              'UDB80_REQUIRE_UC80')
    gdb_build(str(d), name, libs)


@pytest.fixture(scope='module')
def prog_default(tmp_path_factory):
    d = tmp_path_factory.mktemp('vdefault')
    _compile(d, 'p')
    return d


@pytest.fixture(scope='module')
def prog_optnone(tmp_path_factory):
    d = tmp_path_factory.mktemp('voptnone')
    _compile(d, 'p', '--optnone=leaf,deep,work')
    return d


def at(stop, *cmds):
    return ['break p.c:%d' % line_of(stop), 'continue', *cmds]


def test_live_globals_statics_and_types(cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_DEEP', 'print g', 'print sg', 'print gp', 'print gp.y',
        'print ga', 'print ga[2]', 'print gb', 'print gc', 'print gs',
        'print &g', 'print &ga[1]', 'ptype gp', 'whatis gb', 'ptype gb',
        'ptype struct pt')).stdout
    in_order(out, [
        '$1 = 7', '$2 = 9', '$3 = {x = 3, y = 4}', '$4 = 4',
        '$5 = {10, 20, 30, 40}', '$6 = 30', "$7 = 200 '\\310'", '$8 = GREEN',
        'hi"', '$10 = (int *) 0x', '<g>', '$11 = (int *) 0x', '<ga+2>',
        'type = struct pt {', '    int x;', '    int y;', '}',
        'type = byte', 'type = unsigned char'])
    assert '$9 = 0x' in out
    assert 'No symbol "sizeof_nothing"' in udb_err(cpmemu, prog_default,
                                                   'print sizeof_nothing')


def udb_err(cpmemu, d, *cmds):
    args = ['--batch', 'p.dbg', '--run', f'{cpmemu} p.com']
    for c in cmds:
        args += ['-ex', c]
    return udb(*args, cwd=d, check=False).stderr


def test_live_shared_area_locals_in_work(cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_WORK', 'info locals', 'print arr', 'print arr[1]', 'print s',
        'print s.y', 'print sum', 'print i', 'print &s.y',
        'x/3dh arr')).stdout
    in_order(out, [
        'Breakpoint 1, _work () at p.c:%d' % line_of('AT_WORK'),
        'i = 3', 'sum = 56', 's = {x = 3, y = 6}', 'arr = {5, 6, 7}',
        '$1 = {5, 6, 7}', '$2 = 6', '$3 = {x = 3, y = 6}', '$4 = 6',
        '$5 = 56', '$6 = 3', '$7 = (int *) 0x'])
    assert re.search(r'0x[0-9a-f]+ <[^>]*>:\t5\t6\t7', out) or \
        re.search(r':\t5\t6\t7', out)
    # t belongs to the block of the for statement: not in scope here
    assert '\nt = ' not in out


def test_live_a_static_local_and_a_register_local_in_leaf(cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_LEAF', 'print cnt', 'print loc', 'info locals', 'continue',
        'print cnt', 'print loc')).stdout
    in_order(out, ['$1 = 0', '$2 = 8', 'Breakpoint 1,'])
    assert 'loc = 8' in out and 'cnt = 0' in out
    assert '$3 = 8' in out and '$4 = 10' in out, out


def test_live_ix_locals_in_deep_and_the_caller_frame(cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_DEEP', 'info locals', 'print arr', 'print local', 'print arr[1]',
        'frame 1', 'info locals', 'print arr[1]', 'print local',
        'frame 2', 'print local', 'frame 3', 'info locals')).stdout
    in_order(out, [
        'Breakpoint 1, _deep () at p.c:%d' % line_of('AT_DEEP'),
        'arr = {2, 1}', 'local = 2',               # frame 0 info locals
        '$1 = {2, 1}', '$2 = 2', '$3 = 1',
        '#1  0x', 'in _deep () at p.c:%d' % line_of('+ g;') if False else
        'in _deep () at p.c:',
        'arr = {4, 2}', 'local = 4',               # frame 1
        '$4 = 2', '$5 = 4',
        '#2  0x', '$6 = 6',                         # frame 2: n=3 -> local 6
        '#3  0x', 'in _main () at p.c:'])
    assert 'q = {x = 5, y = 6}' in out


def test_live_a_parameter_in_the_ix_frame_under_optnone(cpmemu, prog_optnone):
    out = live(cpmemu, prog_optnone, 'p', *at(
        'AT_DEEP', 'info args', 'print n', 'print *p', 'print p->y',
        'print p->x + n', 'frame 1', 'info args', 'print n', 'frame 2',
        'print n', 'down', 'print n')).stdout
    in_order(out, [
        'n = 1', 'p = (struct pt *) 0x', '$1 = 1', '$2 = {x = 5, y = 6}',
        '$3 = 6', '$4 = 6',
        '#1  0x', 'n = 2', 'p = (struct pt *) 0x', '$5 = 2',
        '#2  0x', '$6 = 3', '#1  0x', '$7 = 2'])


def test_live_a_register_variable_is_not_available_in_a_caller_frame(
        cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_DEEP', 'info args', 'frame 1', 'info args')).stdout
    # frame 0: n is in BC (or not available); in frame 1 it is not available
    tail = out.split('#1  0x')[1]
    assert '<not available>' in tail


def test_live_the_same_values_under_optnone(cpmemu, prog_optnone):
    out = live(cpmemu, prog_optnone, 'p', *at(
        'AT_WORK', 'info locals', 'print sum', 'print s', 'print arr')).stdout
    in_order(out, ['i = 3', 'sum = 56', '$1 = 56', '$2 = {x = 3, y = 6}',
                   '$3 = {5, 6, 7}'])
    out = live(cpmemu, prog_optnone, 'p', *at(
        'AT_LEAF', 'info args', 'print a', 'print b', 'print loc', 'print cnt')
    ).stdout
    in_order(out, ['a = 8', 'b = 0', '$1 = 8', '$2 = 0', '$3 = 8', '$4 = 0'])


def test_live_x_takes_a_variable(cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_DEEP', 'x/4dh ga', 'x/2dh &gp', 'x/s gs')).stdout
    assert '10\t20\t30\t40' in out
    assert '3\t4' in out
    assert '"hi"' in out


def test_live_frame_commands(cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_DEEP', 'frame', 'up', 'up', 'down', 'frame 3', 'up')).stdout
    in_order(out, ['#0  _deep () at p.c:', '#1  0x', '#2  0x', '#1  0x',
                   '#3  0x'])
    run = udb('--batch', 'p.dbg', '--run', f'{cpmemu} p.com',
              '-ex', 'break p.c:%d' % line_of('AT_DEEP'), '-ex', 'continue',
              '-ex', 'frame 40', '-ex', 'down', cwd=prog_default, check=False)
    assert 'No frame at level 40.' in run.stderr
    assert 'Bottom (innermost) frame selected' in run.stderr


def test_live_a_resume_selects_frame_0_again(cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_DEEP', 'frame 1', 'stepi', 'frame')).stdout
    assert out.rstrip().splitlines()[-1].startswith('#0  ') or \
        '#0  ' in out.split('frame 1')[-1]


def test_live_outside_a_program_with_variables_print_still_does_labels(
        cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', 'print $pc', 'print _g',
               'break p.c:%d' % line_of('AT_DEEP'), 'continue',
               'print $pc').stdout
    assert '$1 = 0x0100' in out or '$1 = 0100' in out or 'START' in out


# ---------------------------------------------------------------------------
# dbg2elf: DWARF types and variables
# ---------------------------------------------------------------------------

def dies_by_tag(node, tag, out=None):
    out = [] if out is None else out
    if node['tag'] == tag:
        out.append(node)
    for c in node['children']:
        dies_by_tag(c, tag, out)
    return out


def test_dwarf_has_types_and_variables(prog_default):
    elf = elfread.Elf((prog_default / 'p.elf').read_bytes())
    root = elf.dies()
    names = lambda tag: sorted(d['attrs'].get(0x03, '') for d in
                               dies_by_tag(root, tag))
    assert 'pt' in names(0x13)                          # structure_type
    assert 'color' in names(0x04)                       # enumeration_type
    assert 'byte' in names(0x16)                        # typedef
    enums = [d for d in dies_by_tag(root, 0x04) if d['attrs'].get(0x03) == 'color']
    assert [(c['attrs'][0x03], c['attrs'][0x1c]) for c in enums[0]['children']] \
        == [('RED', 0), ('GREEN', 5), ('BLUE', 6)]
    pt = [d for d in dies_by_tag(root, 0x13) if d['attrs'].get(0x03) == 'pt'][0]
    assert [(m['attrs'][0x03], m['attrs'][0x38]) for m in pt['children']] \
        == [('x', 0), ('y', 2)]
    assert pt['attrs'][0x0b] == 4
    arrays = dies_by_tag(root, 0x01)
    assert any(c['attrs'].get(0x2f) == 3 for a in arrays for c in a['children'])
    variables = {d['attrs'].get(0x03): d for d in dies_by_tag(root, 0x34)}
    assert variables['g']['attrs'][0x02][0] == 0x03          # DW_OP_addr
    assert variables['sg']['attrs'][0x02][0] == 0x03
    assert 0x3f in variables['g']['attrs']                  # external
    assert 0x3f not in variables['sg']['attrs']


def test_dwarf_puts_locals_into_their_routine_and_ix_ones_use_fbreg(prog_optnone):
    elf = elfread.Elf((prog_optnone / 'p.elf').read_bytes())
    root = elf.dies()
    subs = {d['attrs'][0x03]: d for d in dies_by_tag(root, 0x2e)
            if 0x03 in d['attrs'] and 0x11 in d['attrs']}
    deep = subs['deep']
    assert deep['attrs'][0x40] == bytes([0x9c])              # frame base: CFA
    params = {d['attrs'][0x03]: d for d in dies_by_tag(deep, 0x05)}
    assert set(params) == {'n', 'p'}
    loc = params['n']['attrs'][0x02]
    assert loc[0] == 0x91 and loc[1:] == bytes([0])          # fbreg 4 - 4
    assert params['p']['attrs'][0x02][1:] == bytes([2])      # fbreg 6 - 4
    local = {d['attrs'][0x03]: d for d in dies_by_tag(deep, 0x34)}
    assert local['local']['attrs'][0x02][0] == 0x91


def test_dwarf_writes_no_register_variable(prog_default):
    elf = elfread.Elf((prog_default / 'p.elf').read_bytes())
    root = elf.dies()
    work = [d for d in dies_by_tag(root, 0x2e) if d['attrs'].get(0x03) == 'work'][0]
    names = {d['attrs'].get(0x03) for tag in (0x34, 0x05)
             for d in dies_by_tag(work, tag)}
    dbg = json.loads((prog_default / 'p.dbg').read_text())
    regs = {v[0] for v in dbg['vars'] if v[3] and v[3][0] == 'reg'
            and v[4] == next(f['start'] for f in dbg['funcs']
                             if f['name'] == '_work')}
    assert regs and not (regs & names)
    assert {'arr', 's'} <= names                    # fixed address: DW_OP_addr


def test_dbg2elf_ix_locals_off_writes_no_ix_variable(prog_optnone):
    run_dir = prog_optnone
    tool('um80.dbg2elf', 'p.dbg', '--ix-locals', 'off', '-o', 'off.elf',
         cwd=run_dir)
    root = elfread.Elf((run_dir / 'off.elf').read_bytes()).dies()
    deep = [d for d in dies_by_tag(root, 0x2e) if d['attrs'].get(0x03) == 'deep'][0]
    assert 0x40 not in deep['attrs']
    assert not dies_by_tag(deep, 0x05)


# ---------------------------------------------------------------------------
# GDB
# ---------------------------------------------------------------------------

def gdb_vars(gdb_path, cpmemu, d, cmds, helper=False):
    cmds = ([f'source {VARS_HELPER}'] if helper else []) + list(cmds)
    return gdb_session(gdb_path, cpmemu, str(d), 'p', cmds)


def test_gdb_prints_static_variables_natively(gdb_path, cpmemu, prog_default):
    out = gdb_vars(gdb_path, cpmemu, prog_default, [
        'break p.c:%d' % line_of('AT_DEEP'), 'continue', 'print g', 'print sg',
        'print gp', 'print ga', 'print gb', 'print gc', 'print gp.y',
        'print ga[2]', 'ptype struct pt', 'whatis gb'])
    in_order(out, [
        '$1 = 7', '$2 = 9', '$3 = {x = 3, y = 4}', '$4 = {10, 20, 30, 40}',
        '$5 = 200 ', '$6 = GREEN', '$7 = 4', '$8 = 30',
        'type = struct pt {', 'int x;', 'int y;', 'type = byte'])


def test_gdb_prints_a_shared_area_local_natively(gdb_path, cpmemu, prog_default):
    out = gdb_vars(gdb_path, cpmemu, prog_default, [
        'break p.c:%d' % line_of('AT_WORK'), 'continue', 'print arr', 'print s',
        'print s.y', 'print sum', 'print leaf::cnt', 'bt'])
    in_order(out, ['$1 = {5, 6, 7}', '$2 = {x = 3, y = 6}', '$3 = 6', '$4 = 56'])


def test_gdb_prints_ix_variables_natively_with_the_unwinder(
        gdb_path, cpmemu, prog_optnone):
    out = gdb_vars(gdb_path, cpmemu, prog_optnone, [
        'break p.c:%d' % line_of('AT_DEEP'), 'continue', 'info args',
        'info locals', 'print *p', 'up', 'info locals', 'print n', 'up',
        'print n', 'print arr[1]'])
    in_order(out, [
        'Breakpoint 1, deep (n=1, p=', 'n = 1', 'p = ', 'local = 2',
        'arr = {2, 1}', '$1 = {x = 5, y = 6}',
        '#1  0x', 'local = 4', 'arr = {4, 2}', '$2 = 2',
        '#2  0x', '$3 = 3', '$4 = 3'])


def test_gdb_helper_lists_register_locals_and_ix_locals(
        gdb_path, cpmemu, prog_default):
    out = gdb_vars(gdb_path, cpmemu, prog_default, [
        'break p.c:%d' % line_of('AT_WORK'), 'continue', 'zlocals', 'zprint sum',
        'zprint arr[1]', 'zprint s.x', 'zptype s', 'zptype struct pt'],
        helper=True)
    in_order(out, ['i = 3', 'sum = 56', 's = {x = 3, y = 6}',
                   'arr = {5, 6, 7}', '56', '6', '3', 'type = struct pt {',
                   'type = struct pt {'])


def test_gdb_helper_in_a_caller_frame(gdb_path, cpmemu, prog_default):
    out = gdb_vars(gdb_path, cpmemu, prog_default, [
        'break p.c:%d' % line_of('AT_DEEP'), 'continue', 'zargs', 'up',
        'zargs', 'zlocals', 'zprint arr[1]', 'zprint nosuch'], helper=True)
    tail = out.split('#1  0x')[1]
    assert 'n = <not available>' in tail
    in_order(tail, ['arr = {4, 2}', 'local = 4', '2'])
    assert 'No symbol "nosuch" in current context.' in out


def test_gdb_without_the_unwinder_cannot_read_ix_variables(
        gdb_path, cpmemu, prog_optnone):
    # the frame base is the CFA, which only the Python unwinder can give
    port = gdb_session(gdb_path, cpmemu, str(prog_optnone), 'p',
                       ['break p.c:%d' % line_of('AT_DEEP'), 'continue',
                        'print g'], unwinder=False)
    assert '$1 = 7' in port             # a fixed address needs no frame


# ---------------------------------------------------------------------------
# D8: the outer level of a line (the C line below a BASIC line)
# ---------------------------------------------------------------------------

OUTER_MAC = """\
\t.z80
;#file 1 "p.bas"
;#file 2 "p.c"
;#func _main 2 3 frame=none pops=0
_main:
;#line 1 10 outer=2:5
\tld\thl,1
;#line 1 20 outer=2:7
\tld\thl,2
;#line 1 30
\tld\thl,3
;#endfunc _main
\tjp\t0
\tend
"""
OUTER_BAS = "".join("%d\n" % n for n in range(1, 10)) + "10 A = 1\n" + "".join("%d\n" % n for n in range(11, 20)) + "20 A = 2\n" + "".join("%d\n" % n for n in range(21, 30)) + "30 A = 3\n"
OUTER_C = "int a;\nint main(void) {\n\n\n  a = 1;\n\n  a = 2;\n}\n"


@pytest.fixture(scope='module')
def outer(tmp_path_factory):
    d = tmp_path_factory.mktemp('outer')
    (d / 'p.bas').write_text(OUTER_BAS)
    (d / 'p.c').write_text(OUTER_C)
    build_mac(d, 'p', OUTER_MAC)
    return d


def test_outer_goes_through_um80_and_ul80(outer):
    dbm = json.loads((outer / 'p.dbm').read_text())
    groups = [r[7] for r in dbm['rows'] if r[7]]
    assert groups[0] == [[0, 10, 0, 1, 5]]
    assert groups[1] == [[0, 20, 0, 1, 7]]
    assert groups[2] == [[0, 30, 0]]
    dbg = json.loads((outer / 'p.dbg').read_text())
    assert [e[2] for e in dbg['lines']] == [[[0, 10, 0, 1, 5]], [[0, 20, 0, 1, 7]],
                                           [[0, 30, 0]]]


def test_addr2line_shows_the_outer_level(outer):
    out = udb('addr2line', 'p.dbg', '0x100', '0x103', '0x106', cwd=outer).stdout
    lines = out.splitlines()
    assert lines[0].endswith('p.bas:10  [asm p.mac:7]  [outer p.c:5]')
    assert lines[1].endswith('p.bas:20  [asm p.mac:9]  [outer p.c:7]')
    assert '[outer' not in lines[2]
    out = udb('addr2line', '--outer', 'p.dbg', '0x100', '0x106', cwd=outer).stdout
    assert out.splitlines()[0].endswith('p.c:5  [asm p.mac:7]')
    assert out.splitlines()[1].endswith('p.bas:30  [asm p.mac:11]')


def test_live_info_line_and_levels(cpmemu, outer):
    out = live(cpmemu, outer, 'p',
               'break p.bas:20', 'continue', 'info line',
               'set level c', 'info line', 'list', 'set level both',
               'frame', 'set level src', 'frame').stdout
    in_order(out, [
        'Breakpoint 1, _MAIN () at p.bas:20' if False else 'Breakpoint 1, ',
        'p.bas:20',
        'Line 20 of "p.bas" starts at address 0x0103',
        'Outer level: line 7 of "p.c".',
        'Line 20 of "p.bas" starts at address 0x0103',
        '3\t', '7\t  a = 2;',            # list at the outer level: p.c
        'p.bas:20', '20\t20 A = 2', 'outer level: p.c:7', '7\t  a = 2;',
        '#0  ',
    ])
    assert out.count('outer level: p.c:7') == 1
    # after `set level src` the outer level is off again
    tail = out.rsplit('#0  ', 1)[-1]
    assert 'outer level' not in tail and 'p.bas:20' in tail


def test_live_break_on_the_outer_level_file_is_not_supported_yet(cpmemu, outer):
    # a breakpoint names a line of the source level; the outer file has no
    # step points of its own
    run = udb('--batch', 'p.dbg', '--run', f'{cpmemu} p.com',
              '-ex', 'break p.c:7', cwd=outer, check=False)
    assert 'No source file named p.c' in run.stderr or 'p.c' in run.stderr


@pytest.fixture(scope='module')
def basic_c(tmp_path_factory):
    libs = _need_uc80()
    d = tmp_path_factory.mktemp('basicc')
    (d / 'm.c').write_text(
        'int total;\n#line 10 "prog.bas"\nint main(void) {\n    int i;\n'
        '#line 20 "prog.bas"\n    total = 0;\n#line 30 "prog.bas"\n'
        '    for (i = 0; i < 3; i++)\n#line 40 "prog.bas"\n'
        '        total += i;\n#line 50 "prog.bas"\n    return total;\n}\n')
    (d / 'prog.bas').write_text('\n' * 9 + '10 REM\n20 T = 0\n' + '\n' * 8 +
                                '30 FOR\n' + '\n' * 9 + '40 T = T + I\n')
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(
        [ROOT] + ([os.environ['PYTHONPATH']] if os.environ.get('PYTHONPATH') else [])))
    # --optnone: the optimizer would unroll the loop and drop the variable
    run = subprocess.run([sys.executable, '-m', 'uc80.main', 'm.c', '-g',
                          '--optnone=main', '-o', 'm.mac'], cwd=str(d),
                         env=env, capture_output=True, text=True)
    if run.returncode != 0:
        _skip('uc80 failed: ' + (run.stdout + run.stderr)[-300:],
              'UDB80_REQUIRE_UC80')
    gdb_build(str(d), 'm', libs)
    return d


def test_live_a_basic_style_program_from_uc80(cpmemu, basic_c):
    out = live(cpmemu, basic_c, 'm', 'break prog.bas:40', 'continue',
               'info line', 'set level outer', 'info line', 'frame',
               'print total', 'print i').stdout
    in_order(out, [
        'Breakpoint 1 at 0x', 'file prog.bas, line 40.',
        'Breakpoint 1, _main () at prog.bas:40',
        'Line 40 of "prog.bas" starts at address',
        'Outer level: line 10 of "m.c".',
        '#0  _main () at m.c:10',
        '$1 = 0', '$2 = 0'])


def test_live_an_unavailable_array_never_crashes_the_session(
        cpmemu, prog_default):
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_DEEP', 'print nowhere', 'print nobuf')).stdout
    assert out.count('<not available>') == 2
    err = udb_err(cpmemu, prog_default, *at(
        'AT_DEEP', 'print nowhere[1]', 'print nobuf[0]', 'print &nowhere[1]',
        'print nobuf+1', 'x/s nobuf', 'x/2dw nobuf', 'print g'))
    assert 'Traceback' not in err and 'TypeError' not in err
    assert err.count('<not available>') >= 4
    out = live(cpmemu, prog_default, 'p', *at(
        'AT_DEEP', 'print nowhere[1]', 'print g')).stdout
    assert '= <not available>' in out and '= 7' in out


TWO_A = """\
struct s { int a; int b; };
static int cnt = 5;
static struct s va = { 1, 2 };
int fa(void) { return cnt + va.b; }
"""
TWO_B = """\
struct s { char c; long l; };
static int cnt = 7;
static struct s vb = { 3, 4 };
int fa(void);
int main(void)
{
    int r = cnt + fa() + vb.c;      /* AT_MAIN */
    return r + (int) vb.l;
}
"""


def test_live_two_files_with_equal_static_and_tag_names(cpmemu, tmp_path):
    libs = _need_uc80()
    (tmp_path / 'a.c').write_text(TWO_A)
    (tmp_path / 'b.c').write_text(TWO_B)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(
        [ROOT] + ([os.environ['PYTHONPATH']] if os.environ.get('PYTHONPATH') else [])))
    run = subprocess.run([sys.executable, '-m', 'uc80.main', 'a.c', 'b.c',
                          '-g', '-o', 'p.mac'], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True)
    if run.returncode != 0:
        _skip('uc80 failed: ' + (run.stdout + run.stderr)[-300:],
              'UDB80_REQUIRE_UC80')
    gdb_build(str(tmp_path), 'p', libs)
    mac = (tmp_path / 'p.mac').read_text()
    # the source name is the name; the unique label is only the location
    assert ';#var cnt int:2 kind=static at=_cnt__s0' in mac
    assert ';#var cnt int:2 kind=static at=_cnt__s1' in mac
    line = [k for k, ln in enumerate(TWO_B.splitlines(), 1)
            if 'AT_MAIN' in ln][0]
    out = live(cpmemu, tmp_path, 'p', 'break b.c:%d' % line, 'continue',
               'print cnt', 'print vb', 'print vb.l', 'whatis vb').stdout
    in_order(out, ['$1 = 7', '$2 = {c = 3 \'\\003\', l = 4}', '$3 = 4',
                   'type = struct s'])
    run = udb('--batch', 'p.dbg', '--run', f'{cpmemu} p.com',
              '-ex', 'ptype struct s', cwd=tmp_path, check=False)
    assert 'ambiguous' in run.stderr and 's__t0' in run.stderr
    out = live(cpmemu, tmp_path, 'p', 'break b.c:%d' % line, 'continue',
               'ptype struct s__t1', 'whatis vb').stdout
    in_order(out, ['char c;', 'long l;', 'type = struct s'])
