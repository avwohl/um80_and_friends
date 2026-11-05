"""dbg2elf: the structure of the ELF file, the line rows and the DIE tree.

The tests parse the file back with tests/elfread.py (a reader written for
these tests, because pyelftools is not a dependency).  The program of the
golden checks is tools/dbg2elf_proto/sumto.mac; the other programs are
prog.dbg data written by hand, so that each rule has a small case:

- rule D4: each line of a merged group is a row at one address, in source
  order, and only a nostmt row has is_stmt off
- a gap between line entries ends the sequence
- the inline stack of the line entries becomes DW_TAG_inlined_subroutine
  records, nested, with the call file and the call line
- the call line that ;#endinline puts back is not a statement of its own
- a stale program file is refused
"""

# pytest fixtures are parameters with the name of the fixture function.
# pylint: disable=redefined-outer-name
# The test names say what each test checks.
# pylint: disable=missing-function-docstring
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import elfread  # noqa: E402
from um80 import dbg2elf  # noqa: E402

SUMTO = os.path.join(ROOT, 'tools', 'dbg2elf_proto')

DW_TAG_subprogram, DW_TAG_variable, DW_TAG_inlined_subroutine = 0x2e, 0x34, 0x1d
DW_TAG_base_type, DW_TAG_array_type = 0x24, 0x01
NAME, LOW, HIGH, EXT, TYPE, LOC = 0x03, 0x11, 0x12, 0x3f, 0x49, 0x02
ORIGIN, CALL_FILE, CALL_LINE, DECL_LINE, DECL_FILE, INLINE = 0x31, 0x58, 0x59, 0x3b, 0x3a, 0x20


def run_tool(module, *args, cwd, check=True):
    env = dict(os.environ, PYTHONPATH=ROOT)
    run = subprocess.run([sys.executable, '-m', module, *args], cwd=cwd, env=env,
                         capture_output=True, text=True)
    if check:
        assert run.returncode == 0, run.stdout + run.stderr
    return run


@pytest.fixture(scope='module')
def sumto(tmp_path_factory):
    d = tmp_path_factory.mktemp('sumto')
    for f in ('sumto.mac', 'sumto.c'):
        shutil.copy(os.path.join(SUMTO, f), d / f)
    run_tool('um80.um80', '--debug-info', '-o', 'sumto.rel', 'sumto.mac', cwd=str(d))
    run_tool('um80.ul80', '--debug-info', '-o', 'sumto.com', 'sumto.rel', cwd=str(d))
    run_tool('um80.dbg2elf', 'sumto.dbg', '-o', 'sumto.elf', cwd=str(d))
    elf = elfread.Elf((d / 'sumto.elf').read_bytes())
    return dict(dir=str(d), elf=elf, com=(d / 'sumto.com').read_bytes())


def children(node, tag):
    return [c for c in node['children'] if c['tag'] == tag]


# ---------------------------------------------------------------------------
# sumto: golden structure
# ---------------------------------------------------------------------------

def test_elf_header(sumto):
    e = sumto['elf']
    assert (e.ei_class, e.ei_data, e.ei_version) == (1, 1, 1)     # ELF32, little endian
    assert (e.e_type, e.e_machine, e.e_flags) == (2, 220, 1)      # EXEC, EM_Z80, EF_Z80_MACH_Z80
    assert e.e_entry == 0x100
    assert e.e_ehsize == 52 and e.e_phentsize == 32 and e.e_shentsize == 40


def test_text_is_the_image_at_the_load_address(sumto):
    e = sumto['elf']
    assert len(e.phdrs) == 1
    ph = e.phdrs[0]
    assert (ph['type'], ph['vaddr'], ph['paddr'], ph['flags']) == (1, 0x100, 0x100, 5)
    assert ph['filesz'] == ph['memsz'] == len(sumto['com']) == 128
    text = e.sections['.text']
    assert text['addr'] == 0x100 and text['flags'] == 6
    assert text['data'] == sumto['com']
    assert e.blob[ph['offset']:ph['offset'] + ph['filesz']] == sumto['com']


def test_section_names(sumto):
    names = [s['name'] for s in sumto['elf'].section_list]
    assert names == ['', '.text', '.debug_abbrev', '.debug_info', '.debug_line',
                     '.debug_str', '.symtab', '.strtab', '.shstrtab']


def test_symbol_table(sumto):
    syms = sumto['elf'].symbols()
    got = [(s['name'], s['value'], s['size'], s['bind'], s['type']) for s in syms[1:]]
    # locals first (STB_LOCAL 0), then the globals; STT_FUNC 2, STT_OBJECT 1.
    # prog.dbg has no ;#func here, so the routines are the labels that start
    # with an underscore, with the size to the next routine or data row.
    assert got == [('loop', 0x108, 0, 0, 0),
                   ('_main', 0x100, 32, 1, 2),
                   ('_add', 0x120, 2, 1, 2),
                   ('_total', 0x122, 2, 1, 1)]
    symtab = sumto['elf'].sections['.symtab']
    assert symtab['info'] == 2              # the index of the first global symbol
    assert symtab['link'] == 7              # .strtab


SUMTO_ROWS = [
    # address, line, is_stmt   (file 1 is sumto.c)
    (0x100, 12, True),
    (0x106, 13, True),
    (0x108, 14, True),
    (0x114, 13, False),             # ;#line 1 13 nostmt: the loop increment
    (0x11a, 15, True),              # a merged group: both lines are rows
    (0x11a, 16, True),              # ... and the last one is primary
    (0x120, 5, True),
    (0x120, 6, True),
    (0x121, 7, True),
]


def test_line_rows(sumto):
    files, rows = sumto['elf'].line_table()
    assert files == ['sumto.c', 'sumto.mac']
    real = [r for r in rows if not r[4]]
    assert [(a, l, s) for a, f, l, s, _e in real] == SUMTO_ROWS
    assert all(f == 1 for _a, f, _l, _s, _e in real)
    ends = [r for r in rows if r[4]]
    assert [r[0] for r in ends] == [0x122]          # one sequence, to the end of the code


def test_compile_unit_and_routines(sumto):
    cu = sumto['elf'].dies()
    a = cu['attrs']
    assert a[NAME] == 'sumto.c'
    assert (a[LOW], a[HIGH]) == (0x100, 0x122 + 2 - 0x100)
    assert a[0x13] == 0x0c and a[0x10] == 0
    assert os.path.isabs(a[0x1b])
    subs = {c['attrs'][NAME]: c['attrs'] for c in children(cu, DW_TAG_subprogram)}
    # the C name has no leading underscore
    assert (subs['main'][LOW], subs['main'][HIGH]) == (0x100, 32)
    assert (subs['add'][LOW], subs['add'][HIGH]) == (0x120, 2)
    assert subs['main'][EXT] is True


def test_static_variable_has_dw_op_addr(sumto):
    cu = sumto['elf'].dies()
    [var] = children(cu, DW_TAG_variable)
    assert var['attrs'][NAME] == 'total'
    assert var['attrs'][LOC] == bytes([0x03]) + struct.pack('<H', 0x122)
    t = [c for c in cu['children'] if c['offset'] == var['attrs'][TYPE]][0]
    assert (t['tag'], t['attrs'][NAME], t['attrs'][0x0b]) == (DW_TAG_base_type, 'int', 2)


def test_cli_messages(sumto, tmp_path):
    d = sumto['dir']
    run = run_tool('um80.dbg2elf', 'sumto.dbg', '-o', str(tmp_path / 'x.elf'), cwd=d)
    assert 'wrote' in run.stdout
    bad = tmp_path / 'sumto.com'
    bad.write_bytes(sumto['com'][:-1] + b'\x55')
    shutil.copy(os.path.join(d, 'sumto.dbg'), tmp_path / 'sumto.dbg')
    run = run_tool('um80.dbg2elf', 'sumto.dbg', cwd=str(tmp_path), check=False)
    assert run.returncode == 1
    assert 'does not match' in run.stderr and 'stale' in run.stderr
    assert not (tmp_path / 'sumto.elf').exists()


def test_unwinder_path():
    run = run_tool('um80.dbg2elf', '--unwinder-path', cwd=ROOT)
    path = run.stdout.strip()
    assert os.path.isfile(path) and path.endswith(os.path.join('gdb', 'udb80_unwind.py'))


# ---------------------------------------------------------------------------
# Data written by hand
# ---------------------------------------------------------------------------

def make_dbg(**kw):
    dbg = {'format': 'um80-dbg', 'version': 1, 'producer': 'test',
           'image': {'file': 'p.com', 'kind': 'com', 'length': 128, 'sha256': '0',
                     'load': 256, 'offset': 0, 'model': 'cpm'},
           'files': ['a.c', 'b.h', 'a.mac'], 'modules': [], 'lines': [], 'asm': [],
           'labels': [], 'funcs': [], 'noopt': [], 'moved': [], 'dropped_rows': 0}
    dbg.update(kw)
    return dbg


def elf_of(dbg, **opts):
    ns = argparse.Namespace(keep_case=False, keep_underscore=False, no_variables=False,
                            asm_lines='auto', language='c')
    for k, v in opts.items():
        setattr(ns, k, v)
    return elfread.Elf(dbg2elf.build_elf(dbg, bytes(128), ns, '/src'))


def rows_of(elf):
    files, rows = elf.line_table()
    return [(a, f, l, s, e) for a, f, l, s, e in rows]


def test_rule_d4_group_rows_in_source_order():
    dbg = make_dbg(lines=[[256, 260, [[0, 5, 0], [0, 6, 0], [0, 7, 1]]],
                          [260, 262, [[0, 9, 0]]]])
    rows = rows_of(elf_of(dbg))
    assert rows == [(256, 1, 5, True, False), (256, 1, 6, True, False),
                    (256, 1, 7, False, False),      # nostmt: is_stmt off
                    (260, 1, 9, True, False), (262, 1, 9, True, True)]


def test_gap_ends_the_sequence_and_files_switch():
    dbg = make_dbg(lines=[[256, 260, [[0, 5, 0]]],
                          [270, 275, [[1, 40, 0], [0, 6, 0]]]])
    rows = rows_of(elf_of(dbg))
    assert rows == [(256, 1, 5, True, False), (260, 1, 5, True, True),
                    (270, 2, 40, True, False), (270, 1, 6, True, False),
                    (275, 1, 6, True, True)]


def test_large_jumps_use_advance_opcodes():
    dbg = make_dbg(lines=[[256, 300, [[0, 1000, 0]]], [300, 400, [[0, 3, 0]]]])
    rows = rows_of(elf_of(dbg))
    assert rows == [(256, 1, 1000, True, False), (300, 1, 3, True, False),
                    (400, 1, 3, True, True)]


def test_asm_rows_when_there_are_no_source_lines():
    asm = [[256, 259, 'i', 2, 5], [259, 262, 'i', 2, 5], [262, 263, 'i', 2, 9],
           [263, 265, 'd', 2, 10], [265, 275, 's', 2, 11]]
    dbg = make_dbg(asm=asm, labels=[['_START', 256, 0, 1]])
    elf = elf_of(dbg)
    rows = rows_of(elf)
    # file 3 is a.mac; the second instruction of line 5 adds no row; the DS
    # with no fill makes no bytes and no row
    assert rows == [(256, 3, 5, True, False), (262, 3, 9, True, False),
                    (263, 3, 10, True, False), (265, 3, 10, True, True)]
    assert rows_of(elf_of(dbg, asm_lines='never')) == []


def test_func_records_name_the_routines():
    dbg = make_dbg(
        funcs=[{'name': '_main', 'file': 0, 'line': 3, 'start': 256, 'end': 270},
               {'name': 'helper', 'file': 0, 'line': 9, 'start': 270, 'end': None}],
        asm=[[256, 280, 'i', 2, 1]], lines=[[256, 280, [[0, 3, 0]]]],
        labels=[['_MAIN', 256, 0, 1], ['@MAIN_RET', 268, 0, 0], ['HELPER', 270, 0, 1]])
    elf = elf_of(dbg)
    cu = elf.dies()
    subs = {c['attrs'][NAME]: c['attrs'] for c in children(cu, DW_TAG_subprogram)}
    assert (subs['main'][LOW], subs['main'][HIGH], subs['main'][DECL_LINE]) == (256, 14, 3)
    # a routine with no ;#endfunc ends where the code ends
    assert (subs['helper'][LOW], subs['helper'][HIGH]) == (270, 10)
    assert subs['main'][DECL_FILE] == 1
    syms = {s['name']: s for s in elf.symbols()}
    assert syms['_main']['type'] == 2 and syms['_main']['size'] == 14
    # a local label inside a routine that has a record is not a symbol
    assert '@main_ret' not in syms and '@MAIN_RET' not in syms


def test_data_labels_become_variables_by_size():
    asm = [[256, 258, 'i', 2, 1], [258, 259, 'd', 2, 2], [259, 261, 'd', 2, 3],
           [261, 269, 'd', 2, 4], [269, 271, 's', 2, 5]]
    labels = [['_ONE', 258, 0, 1], ['_TWO', 259, 0, 1], ['_BUF', 261, 0, 0],
              ['_BSS', 269, 0, 0], ['@HIDDEN', 258, 0, 0]]
    cu = elf_of(make_dbg(asm=asm, labels=labels)).dies()
    byname = {v['attrs'][NAME]: v for v in children(cu, DW_TAG_variable)}
    assert set(byname) == {'one', 'two', 'buf', 'bss'}
    types = {c['offset']: c for c in cu['children']}
    assert types[byname['one']['attrs'][TYPE]]['attrs'][NAME] == 'unsigned char'
    assert types[byname['two']['attrs'][TYPE]]['attrs'][NAME] == 'int'
    arr = types[byname['buf']['attrs'][TYPE]]
    assert arr['tag'] == DW_TAG_array_type
    assert arr['children'][0]['attrs'][0x2f] == 7          # upper bound of 8 bytes
    assert byname['bss']['attrs'][LOC] == bytes([3]) + struct.pack('<H', 269)
    assert elf_of(make_dbg(asm=asm, labels=labels), no_variables=True).dies()['children'][-1]['tag'] \
        != DW_TAG_variable


def test_names_keep_case_and_underscore_on_request():
    asm = [[256, 258, 'd', 2, 2]]
    labels = [['_Total', 256, 0, 1]]
    cu = elf_of(make_dbg(asm=asm, labels=labels), keep_case=True, keep_underscore=True).dies()
    assert children(cu, DW_TAG_variable)[0]['attrs'][NAME] == '_Total'


# --- inline records ---------------------------------------------------------

INLINE_FUNCS = [{'name': '_main', 'file': 0, 'line': 8, 'start': 256, 'end': 300}]


def inline_tree(lines, funcs=None):
    dbg = make_dbg(lines=lines, funcs=funcs or INLINE_FUNCS)
    cu = elf_of(dbg).dies()
    [main] = [c for c in children(cu, DW_TAG_subprogram) if LOW in c['attrs']]
    by_offset = {c['offset']: c for c in cu['children']}

    def conv(node):
        origin = by_offset[node['attrs'][ORIGIN]]
        return (origin['attrs'][NAME], node['attrs'][LOW], node['attrs'][HIGH],
                node['attrs'][CALL_FILE], node['attrs'][CALL_LINE],
                [conv(c) for c in node['children']])
    return [conv(c) for c in main['children']], cu


def test_inline_stack_becomes_nested_inlined_subroutines():
    lines = [[256, 258, [[0, 8, 0]]],
             [258, 262, [[0, 11, 0], [0, 3, 0]], [['sq', 0, 11]]],
             [262, 266, [[0, 4, 0]], [['sq', 0, 11]]],                    # same call: one record
             [266, 270, [[0, 20, 0]], [['sq', 0, 11], ['cube', 1, 4]]],   # nested
             [270, 274, [[0, 21, 0]], [['sq', 0, 11]]],                   # back out
             [274, 280, [[0, 12, 0]]],
             [280, 290, [[0, 13, 0]], [['sq', 0, 13]]]]                   # a second call of sq
    tree, cu = inline_tree(lines)
    assert tree == [('sq', 258, 16, 1, 11, [('cube', 266, 4, 2, 4, [])]),
                    ('sq', 280, 10, 1, 13, [])]
    # one abstract subprogram for each name, with DW_AT_inline set
    abstract = {c['attrs'][NAME]: c['attrs'] for c in children(cu, DW_TAG_subprogram)
                if LOW not in c['attrs']}
    assert set(abstract) == {'sq', 'cube'}
    assert abstract['sq'][INLINE] == 1


def test_endinline_call_line_is_not_a_row_of_its_own():
    lines = [[256, 262, [[0, 11, 0], [0, 3, 0]], [['sq', 0, 11]]],
             [262, 266, [[0, 11, 0], [0, 12, 0]]],        # ;#endinline put 11 back
             [266, 270, [[0, 11, 0]], [['sq', 0, 11]]],
             [270, 274, [[0, 11, 0]]]]                     # code of line 11 after the call
    dbg = make_dbg(lines=lines, funcs=INLINE_FUNCS)
    rows = [(a, l) for a, f, l, s, e in rows_of(elf_of(dbg)) if not e]
    assert rows == [(256, 11), (256, 3), (262, 12), (266, 11), (270, 11)]


def test_inline_outside_a_routine_is_dropped():
    lines = [[256, 262, [[0, 3, 0]], [['sq', 0, 11]]]]
    tree, cu = inline_tree(lines, funcs=[{'name': '_x', 'file': 0, 'line': 1,
                                          'start': 300, 'end': 310}])
    assert tree == []


def test_inline_stack_needs_no_func_record_for_rows():
    # rows are written even when no routine holds the entry
    lines = [[256, 262, [[0, 3, 0]], [['sq', 0, 11]]]]
    rows = rows_of(elf_of(make_dbg(lines=lines)))
    assert rows[0][:3] == (256, 1, 3)


def test_refuses_an_image_that_has_no_flat_form():
    dbg = make_dbg()
    dbg['image']['kind'] = 'hex'
    with pytest.raises(dbg2elf.Dbg2ElfError):
        dbg2elf.read_image(dbg, 'p.dbg', None)


def test_refuses_a_program_file_longer_than_the_image(sumto, tmp_path):
    for f in ('sumto.dbg', 'sumto.com'):
        shutil.copy(os.path.join(sumto['dir'], f), tmp_path / f)
    (tmp_path / 'sumto.com').write_bytes(sumto['com'] + b'\x00')
    run = run_tool('um80.dbg2elf', 'sumto.dbg', '-o', 'x.elf', cwd=str(tmp_path),
                   check=False)
    assert run.returncode == 1, run.stdout + run.stderr
    assert 'stale' in run.stderr
    assert not (tmp_path / 'x.elf').exists()
