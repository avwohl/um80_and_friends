"""um80 --debug-info, ulib80 container version 2 and ul80 --debug-info.

docs/debug_info.md is the specification these tests check.  One program has
a macro, a JR that is promoted to JP, a .PHASE block, a DS with no fill, a
DSEG and a library module; its markers include a merged group and a
nostmt line.  The checks:

- the .rel files and the output file are the same with and without the
  options, byte for byte
- the address of each label in prog.dbg is the address in the .SYM file that
  `um80 -g` and `ul80 -s` write
- each instruction row has the line of the .PRN listing, and a macro row has
  the body line too
- the line table follows the merge rule of D4
- a row of bytes that a later module loaded over is dropped
- --rom-data gives a load address that differs from the run address
- the prog.dbg of tools/dbg2elf_proto/sumto.mac has the line rows that the
  prototype computed from the .PRN
"""

import hashlib
import json
import os
import re
import subprocess
import sys

import pytest

from um80 import debuginfo
from um80.ulib80 import Library

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MAIN = """\
\t.z80
\textrn\tlibfn
\tpublic\tstart
swap2\tmacro\ta,b
\tpush\ta
\tpush\tb
\tpop\ta
\tpop\tb
\tendm
;#file 1 "demo.c"
;#file 2 "demo.h"
;#func start 1 3 frame=none pops=0
start:
;#line 1 3
\tld\thl,1
; #line 1 4
;#line 1 5
\tld\tde,2
;#line 2 9 nostmt
\tswap2\thl,de
;#line 1 6
\tjr\tfar
\tds\t200
far:
;#line 1 7
\tcall\tlibfn
\t.phase\t8000h
ph1:\tld\ta,1
ph2:\tjp\tph1
\t.dephase
\tld\tb,b\t;#line 1 99
;#endfunc start
after:\tjp\t0
\tdseg
buf:\tds\t4
tbl:\tdb\t1,2,3
"""

LIB = """\
\t.z80
\tpublic\tlibfn
;#file 1 "lib.c"
;#line 1 40
libfn:\tld\ta,5
;#line 1 41
\tret
libtail:\tret
"""


def _run(module, *args, cwd, check=True):
    env = dict(os.environ, PYTHONPATH=ROOT)
    run = subprocess.run([sys.executable, '-m', module, *args], cwd=cwd,
                         env=env, capture_output=True, text=True)
    if check:
        assert run.returncode == 0, run.stdout + run.stderr
    return run


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return path


def _sym(path):
    out = {}
    for line in path.read_text().splitlines():
        addr, name = line.split()
        out[name] = int(addr, 16)
    return out


def _prn_rows(path):
    """{(line, address)} of the listing lines that have bytes."""
    rows = set()
    for text in path.read_text().split('\n'):
        if (text[:5].strip().isdigit() and text[5:7] == '  '
                and re.match(r'[0-9A-F]{4}$', text[7:11])
                and text[13:25].strip()):
            rows.add((int(text[:5]), int(text[7:11], 16)))
    return rows


@pytest.fixture(scope='module')
def program(tmp_path_factory):
    """MAIN and LIB built with and without the debug options."""
    d = tmp_path_factory.mktemp('prog')
    _write(d, 'main.mac', MAIN)
    _write(d, 'lib.mac', LIB)
    plain = d / 'plain'
    debug = d / 'debug'
    for sub in (plain, debug):
        sub.mkdir()
        for name in ('main.mac', 'lib.mac'):
            (sub / name).write_text((d / name).read_text())
    for name in ('main', 'lib'):
        _run('um80.um80', '-g', '-l', f'{name}.prn', f'{name}.mac',
             cwd=plain)
        _run('um80.um80', '-g', '--debug-info', '-l', f'{name}.prn',
             f'{name}.mac', cwd=debug)
    _run('um80.ulib80', '-c', 'prog.lib', 'lib.rel', cwd=plain)
    _run('um80.ulib80', '-c', 'prog.lib', 'lib.rel', cwd=debug)
    _run('um80.ul80', '-s', '-o', 'prog.com', 'main.rel', 'prog.lib',
         cwd=plain)
    _run('um80.ul80', '-s', '--debug-info', '-o', 'prog.com', 'main.rel',
         'prog.lib', cwd=debug)
    return plain, debug, json.loads((debug / 'prog.dbg').read_text())


def test_rel_and_com_are_the_same_with_the_options(program):
    plain, debug, _ = program
    for name in ('main.rel', 'lib.rel', 'prog.com', 'main.prn', 'lib.prn',
                 'prog.sym'):
        assert (plain / name).read_bytes() == (debug / name).read_bytes(), name
    # The library has the .dbm of lib.rel, so it is a version 2 file.
    assert (debug / 'prog.lib').read_bytes()[4:6] == b'\x02\x00'
    assert (plain / 'prog.lib').read_bytes()[4:6] == b'\x01\x00'
    assert (debug / 'main.dbm').exists() and not (plain / 'main.dbm').exists()


def test_label_addresses_are_the_sym_addresses(program):
    plain, debug, dbg = program
    sym = _sym(debug / 'prog.sym')
    labels = {name: addr for name, addr, _, _ in dbg['labels']}
    for name, addr in sym.items():
        if name.startswith('__'):
            continue
        assert labels.get(name) == addr, name
    assert set(labels) <= set(sym)
    # Spot checks that the program is the one meant: the phase labels are
    # run addresses, and a library label is after the code of the main
    # module.
    assert labels['PH1'] == 0x8000 and labels['PH2'] == 0x8002
    assert labels['LIBFN'] > labels['AFTER']
    assert labels['LIBTAIL'] == labels['LIBFN'] + 3
    # -g made all of them global; --debug-info said so.
    assert all(flag == 1 for _, _, _, flag in dbg['labels'])


def test_every_instruction_has_its_listing_line(program):
    plain, debug, dbg = program
    dbm = json.loads((debug / 'main.dbm').read_text())
    files = dbm['files']
    assert files == ['demo.c', 'demo.h', 'main.mac']
    main = files.index('main.mac')
    rows = [debuginfo.row_fields(r) for r in dbm['rows']]
    got = set()
    for seg, off, length, run, mfile, mline, kind, *_ in rows:
        assert mfile == main
        if kind != 's':
            got.add((mline, run if run is not None else off))
    # DSEG offsets and CSEG offsets are both in the listing's address column.
    assert got == _prn_rows(debug / 'main.prn')
    kinds = {r[6] for r in rows}
    assert kinds == {'i', 'd', 's'}
    # The DS with no fill is a row with no bytes.
    spaces = [r for r in rows if r[6] == 's']
    assert [(r[0], r[2]) for r in spaces] == [('CSEG', 200), ('DSEG', 4)]


def test_macro_rows_have_the_call_line_and_the_body_line(program):
    _, debug, _ = program
    dbm = json.loads((debug / 'main.dbm').read_text())
    lines = MAIN.split('\n')
    call = 1 + next(i for i, t in enumerate(lines) if 'swap2\thl,de' in t)
    body = [debuginfo.row_fields(r) for r in dbm['rows']
            if debuginfo.row_fields(r)[5] == call]
    assert len(body) == 4
    # Body lines 5 to 8 of the source: push, push, pop, pop.
    assert [r[10] for r in body] == [5, 6, 7, 8]
    assert all(r[9] == dbm['files'].index('main.mac') for r in body)


def test_jr_promotion_moves_the_labels_and_keeps_the_rows(program):
    _, debug, dbg = program
    labels = {name: addr for name, addr, _, _ in dbg['labels']}
    dbm = json.loads((debug / 'main.dbm').read_text())
    jumps = [debuginfo.row_fields(r) for r in dbm['rows']
             if 'jr' in MAIN.split('\n')[debuginfo.row_fields(r)[5] - 1]]
    assert [r[2] for r in jumps] == [3]    # JP, three bytes, not JR
    # far is after ld hl, ld de, the macro (push hl, push de, pop hl, pop
    # de: four bytes), the JP and the 200 bytes of DS.
    assert labels['FAR'] == labels['START'] + 3 + 3 + 4 + 3 + 200


def test_phase_block_has_run_addresses_and_a_load_address(program):
    _, debug, dbg = program
    labels = {name: addr for name, addr, _, _ in dbg['labels']}
    asm = {row[0]: row for row in dbg['asm']}
    assert 0x8000 in asm and 0x8002 in asm
    far = labels['FAR']
    # Load address of the block: where the CALL ended, after FAR.
    load = far + 3
    assert [0x8000, load, 5] in dbg['moved']
    # The row after .DEPHASE runs where it is loaded.
    assert asm[load + 5][2] == 'i'


def test_line_table_has_the_merge_rule(program):
    _, debug, dbg = program
    names = dbg['files']
    assert names == ['demo.c', 'demo.h', 'main.mac', 'lib.c', 'lib.mac']
    demo, header = names.index('demo.c'), names.index('demo.h')
    labels = {name: addr for name, addr, _, _ in dbg['labels']}
    by_start = {row[0]: row for row in dbg['lines']}
    start = labels['START']
    # ld hl,1 : line 3.
    assert by_start[start][2] == [[demo, 3, 0]]
    # ld de,2 : lines 4 and 5, in source order; the "; #line" (blank
    # before the #) counts; 5 is the primary line (the last).
    assert by_start[start + 3][2] == [[demo, 4, 0], [demo, 5, 0]]
    # swap2: line 9 of demo.h, nostmt: not a step point.  Four rows with no
    # marker between them are one entry.
    swap = start + 6
    assert by_start[swap][2] == [[header, 9, 1]]
    assert by_start[swap][1] == swap + 4
    # jp far: line 6, and the ds after it has no row of its own.
    assert by_start[swap + 4][2] == [[demo, 6, 0]]
    assert by_start[swap + 4][1] == swap + 7
    # A marker in a trailing comment is no marker: line 99 never appears.
    assert all(group[1] != 99 for row in dbg['lines'] for group in row[2])
    # The routine ends at its endfunc: nothing after has a source line,
    # except the library, which has its own.
    after = labels['AFTER']
    assert not any(row[0] <= after < row[1] and row[2][0][0] == demo
                   for row in dbg['lines'])
    # The library module has its own lines.
    lib = names.index('lib.c')
    assert any(row[2][0][0] == lib and row[2][0][1] == 40
               for row in dbg['lines'])


def test_funcs_and_modules(program):
    _, debug, dbg = program
    labels = {name: addr for name, addr, _, _ in dbg['labels']}
    assert [f['name'] for f in dbg['funcs']] == ['start']
    func = dbg['funcs'][0]
    assert func['start'] == labels['START']
    assert func['end'] == labels['AFTER']
    assert (func['frame'], func['pops']) == ('none', 0)
    assert dbg['files'][func['file']] == 'demo.c' and func['line'] == 3
    assert [(m['name'], m['debug']) for m in dbg['modules']] == [
        ('MAIN', True), ('LIB', True)]


def test_image_is_the_com_file_as_written(program):
    _, debug, dbg = program
    data = (debug / 'prog.com').read_bytes()
    image = dbg['image']
    assert image['file'] == 'prog.com' and image['kind'] == 'com'
    assert image['length'] == len(data) and len(data) % 128 == 0
    assert image['sha256'] == hashlib.sha256(data).hexdigest()
    assert (image['load'], image['offset']) == (0x100, 0)
    assert dbg['format'] == 'um80-dbg' and dbg['version'] == 1


def test_library_stores_the_dbm_by_module_name(program):
    _, debug, _ = program
    lib = Library.load(str(debug / 'prog.lib'))
    assert [m.name for m in lib.modules] == ['LIB']
    dbm = debuginfo.load_dbm(lib.modules[0].dbm)
    assert dbm['module'] == 'LIB' and dbm['source'] == 'lib.mac'
    listing = _run('um80.ulib80', '-l', 'prog.lib', cwd=debug).stdout
    assert 'bytes debug info' in listing
    # Saved again, the container stays version 2 with the same modules.
    lib.save(str(debug / 'again.lib'))
    again = Library.load(str(debug / 'again.lib'))
    assert again.modules[0].dbm == lib.modules[0].dbm


def test_ul80_reads_a_version_1_library_and_a_missing_dbm(tmp_path):
    _write(tmp_path, 'main.mac', MAIN)
    _write(tmp_path, 'lib.mac', LIB)
    _run('um80.um80', '-g', 'main.mac', cwd=tmp_path)
    _run('um80.um80', '-g', 'lib.mac', cwd=tmp_path)
    _run('um80.ulib80', '-c', 'v1.lib', 'lib.rel', cwd=tmp_path)
    assert (tmp_path / 'v1.lib').read_bytes()[4:6] == b'\x01\x00'
    _run('um80.ul80', '--debug-info', '-o', 'v1.com', 'main.rel', 'v1.lib',
         cwd=tmp_path)
    dbg = json.loads((tmp_path / 'v1.dbg').read_text())
    # No .dbm anywhere: no rows, and the public symbols as labels.
    assert dbg['asm'] == [] and dbg['lines'] == []
    assert {l[0] for l in dbg['labels']} >= {'START', 'LIBFN', 'LIBTAIL'}
    assert [m['debug'] for m in dbg['modules']] == [False, False]


def test_stale_dbm_is_refused(tmp_path):
    _write(tmp_path, 'main.mac', "\t.z80\n;#file 1 \"a.c\"\n;#line 1 1\n"
           "\tnop\n")
    _run('um80.um80', '--debug-info', 'main.mac', cwd=tmp_path)
    (tmp_path / 'main.rel').write_bytes((tmp_path / 'main.rel').read_bytes()
                                        + b'\x00')
    run = _run('um80.ul80', '--debug-info', '-o', 'main.com', 'main.rel',
               cwd=tmp_path, check=False)
    assert 'made for another .rel' in run.stdout + run.stderr
    dbg = json.loads((tmp_path / 'main.dbg').read_text())
    assert dbg['asm'] == []


def test_a_row_of_bytes_a_later_module_overwrote_is_dropped(tmp_path):
    _write(tmp_path, 'a.mac',
           "\t.z80\n\taseg\n\torg\t100h\nfirst:\tld\ta,1\n\tnop\nlast:\tnop\n")
    _write(tmp_path, 'b.mac',
           "\t.z80\n\taseg\n\torg\t101h\nsecond:\tnop\n\tnop\n")
    for name in ('a', 'b'):
        _run('um80.um80', '--debug-info', f'{name}.mac', cwd=tmp_path)
    _run('um80.ul80', '--allow-overlap', '--debug-info', '-o', 'ab.com',
         'a.rel', 'b.rel', cwd=tmp_path)
    dbg = json.loads((tmp_path / 'ab.dbg').read_text())
    # ld a,1 (100H and 101H) and the nop at 102H lost a byte to b.  The
    # rows that stay: b's two nops, and a's last nop at 103H.
    assert [(row[0], dbg['files'][row[3]], row[4]) for row in dbg['asm']] == [
        (0x101, 'b.mac', 4), (0x102, 'b.mac', 5), (0x103, 'a.mac', 6)]
    assert dbg['dropped_rows'] == 2


def test_rom_data_has_a_load_address_that_differs_from_the_run_address(
        tmp_path):
    _write(tmp_path, 'rom.mac',
           "\t.z80\n\tpublic\tmain\nmain:\tld\thl,data\n\tret\n"
           "\tdseg\ndata:\tdb\t1,2,3\nbss:\tds\t4\n")
    _run('um80.um80', '--debug-info', 'rom.mac', cwd=tmp_path)
    _run('um80.ul80', '--debug-info', '--rom-data', '-d', '8000', '--bin',
         '-p', '0', '-o', 'rom.bin', 'rom.rel', cwd=tmp_path)
    dbg = json.loads((tmp_path / 'rom.dbg').read_text())
    image = (tmp_path / 'rom.bin').read_bytes()
    assert dbg['image']['kind'] == 'bin' and dbg['image']['load'] == 0
    assert dbg['image']['sha256'] == hashlib.sha256(image).hexdigest()
    data = [row for row in dbg['asm'] if row[2] == 'd'][0]
    assert data[:2] == [0x8000, 0x8003]
    # The three bytes and the 4-byte DS are in the image after the code,
        # at 4.
    assert dbg['moved'] == [[0x8000, 4, 7]]
    assert image[4:7] == bytes([1, 2, 3])
    labels = {name: addr for name, addr, _, _ in dbg['labels']}
    assert labels['DATA'] == 0x8000 and labels['BSS'] == 0x8003
    # The space row is at its run address and is not in the image.
    assert [row[:3] for row in dbg['asm'] if row[2] == 's'] == [
        [0x8003, 0x8007, 's']]


def test_nothing_is_written_without_the_option(tmp_path):
    _write(tmp_path, 'main.mac', MAIN)
    run = _run('um80.um80', 'main.mac', cwd=tmp_path)
    assert not (tmp_path / 'main.dbm').exists()
    assert 'marker' not in run.stdout + run.stderr


# The marker grammar --------------------------------------------------------

@pytest.mark.parametrize('line, kind', [
    (';#file 1 "a.c"', 'file'),
    (';  #line 1 12', 'line'),
    ('\t;\t#line 1 12 nostmt', 'line'),
    (';#inline 1 34 sq', 'inline'),
    (';#endinline', 'endinline'),
    (';#func _f 1 10 frame=ix pops=2 ixbegin=A ixend=B', 'func'),
    (';#endfunc _f', 'endfunc'),
    (';#noopt begin', 'noopt'),
    (';#NOOPT END', 'noopt'),
])
def test_marker_kinds(line, kind):
    assert debuginfo.parse_marker(line)[0] == kind


@pytest.mark.parametrize('line', [
    'nop ;#line 1 2',          # a trailing comment is no marker
    ';; #line 1 2',
    '; line 1 2',
    ';#unknown 1 2',           # a kind this version does not know
    '',
])
def test_not_a_marker(line):
    assert debuginfo.parse_marker(line) is None


@pytest.mark.parametrize('line', [
    ';#file x "a.c"', ';#file 1 a.c', ';#file 0 "a.c"',
    ';#line 1', ';#line a 2', ';#line 1 2 outer=3',
    ';#inline 1 2', ';#func f 1', ';#func f 1 2 frame=banana',
    ';#func f 1 2 pops=x', ';#noopt maybe', ';#noopt',
])
def test_malformed_marker(line):
    with pytest.raises(debuginfo.MarkerError):
        debuginfo.parse_marker(line)


def test_marker_fields():
    kind, fields = debuginfo.parse_marker(
        r';#file 3 "dir\\a \"b\".c"')
    assert fields == {'number': 3, 'path': r'dir\a "b".c'}
    kind, fields = debuginfo.parse_marker(
        ';#line 1 12 nostmt outer=2:7 future')
    assert fields == {'file': 1, 'line': 12, 'nostmt': True,
                      'outer': (2, 7)}
    kind, fields = debuginfo.parse_marker(';#func f 1 10 later=1')
    assert fields == {'name': 'f', 'file': 1, 'line': 10, 'frame': 'none',
                      'pops': 0, 'ixbegin': None, 'ixend': None}


def _assemble(tmp_path, source):
    _write(tmp_path, 't.mac', source)
    run = _run('um80.um80', '--debug-info', 't.mac', cwd=tmp_path,
               check=False)
    dbm = json.loads((tmp_path / 't.dbm').read_text()) \
        if (tmp_path / 't.dbm').exists() else None
    return run, dbm


def test_bad_markers_warn_and_assemble(tmp_path):
    run, dbm = _assemble(tmp_path,
                         "\t.z80\n;#line 5 1\n;#line x\n;#endfunc\n"
                         ";#file 1 \"a.c\"\n;#line 1 2\n\tnop\n")
    assert run.returncode == 0
    err = run.stderr
    assert 'file number 5, which no #file marker defined' in err
    assert 'Malformed debug marker' in err
    assert '#endfunc with no #func' in err
    assert [r[7] for r in dbm['rows']] == [[[0, 2, 0]]]


def test_inline_and_outer_and_clear(tmp_path):
    run, dbm = _assemble(tmp_path, (
        "\t.z80\n;#file 1 \"a.c\"\n;#file 2 \"b.bas\"\n"
        ";#line 1 10 outer=2:100\n\tnop\n"
        ";#inline 1 11 sq\n;#line 1 30\n\tnop\n\tnop\n"
        ";#endinline\n\tnop\n"
        ";#line 0 0\n\tnop\n"))
    rows = [debuginfo.row_fields(r) for r in dbm['rows']]
    files = dbm['files']
    assert files[:2] == ['a.c', 'b.bas']
    assert rows[0][7] == [[0, 10, 0, 1, 100]]
    # Inside the inline: the position of the callee; the call site is in
    # the inline stack.
    assert rows[1][7] == [[0, 30, 0]] and rows[1][8] == [['sq', 0, 11]]
    assert rows[2][7] is None and rows[2][8] is None
    # After #endinline: the position that was current at #inline.
    assert rows[3][7] == [[0, 10, 0, 1, 100]] and rows[3][8] == []
    # file 0 clears the position.
    assert rows[4][7] == []


def test_func_ix_range_and_noopt(tmp_path):
    run, dbm = _assemble(tmp_path, (
        "\t.z80\n;#file 1 \"a.c\"\n"
        ";#func f 1 7 frame=ix pops=3 ixbegin=b1 ixend=b2\n"
        "f:\tpush\tix\nb1:\tadd\tix,sp\n;#noopt begin\n\tnop\n;#noopt end\n"
        "b2:\tld\tsp,ix\n\tret\n;#endfunc f\n"))
    func = dbm['funcs'][0]
    assert func['frame'] == 'ix' and func['pops'] == 3
    assert func['ix'] == [['CSEG', 2], ['CSEG', 5]]
    assert func['start'] == ['CSEG', 0, None]
    assert func['end'] == ['CSEG', 8, None]
    assert dbm['noopt'] == [[['CSEG', 4, None], ['CSEG', 5, None]]]


def test_markers_inside_a_macro_run_at_the_expansion(tmp_path):
    run, dbm = _assemble(tmp_path, (
        "\t.z80\nm1\tmacro\n;#line 1 5\n\tnop\n\tendm\n"
        ";#file 1 \"a.c\"\n\tm1\n"))
    # The #line is read when the macro runs, after the #file.
    assert [r[7] for r in dbm['rows']] == [[[0, 5, 0]]]


# The prototype of phase 0 ----------------------------------------------------

def _proto_rows(mac, prn):
    """The rows tools/dbg2elf_proto/dbg2elf_proto.py (VARIANT=B) computes
    from the .PRN: [(address, [(line, stmt)...])]."""
    src = mac.read_text().split('\n')
    rows, pending = [], []
    for text in prn.read_text().split('\n'):
        if not text[:5].strip().isdigit():
            continue
        num = int(text[:5])
        line = src[num - 1]
        found = re.match(r';\s*#(\w+)\s*(.*)', line)
        if found:
            kind, rest = found.groups()
            if kind == 'line':
                words = rest.split()
                pending.append((int(words[1]), 'nostmt' not in words[2:]))
            continue
        has_bytes = re.match(r'\s*\d+\s+([0-9A-F]{4})\s+[0-9A-F]{2}', text)
        if (has_bytes and not line.lstrip().startswith(('dw', 'db'))
                and '\tdw\t' not in line and pending):
            rows.append((0x100 + int(has_bytes.group(1), 16), pending))
            pending = []
    return rows


def test_sumto_lines_are_the_rows_of_the_prototype(tmp_path):
    folder = os.path.join(ROOT, 'tools', 'dbg2elf_proto')
    for name in ('sumto.mac',):
        _write(tmp_path, name, open(os.path.join(folder, name)).read())
    _run('um80.um80', '--debug-info', '-l', 'sumto.prn', 'sumto.mac',
         cwd=tmp_path)
    _run('um80.ul80', '--debug-info', '-o', 'sumto.com', 'sumto.rel',
         cwd=tmp_path)
    dbg = json.loads((tmp_path / 'sumto.dbg').read_text())
    got = [(row[0], [(g[1], g[2] == 0) for g in row[2]])
           for row in dbg['lines']]
    assert got == _proto_rows(tmp_path / 'sumto.mac', tmp_path / 'sumto.prn')
    assert got == [
        (0x100, [(12, True)]),
        (0x106, [(13, True)]),
        (0x108, [(14, True)]),
        (0x114, [(13, False)]),
        (0x11A, [(15, True), (16, True)]),     # 16 is primary
        (0x120, [(5, True), (6, True)]),       # 6 is primary
        (0x121, [(7, True)]),
    ]
    assert dbg['files'][0] == 'sumto.c'
    labels = {name: addr for name, addr, _, _ in dbg['labels']}
    assert labels == {'_MAIN': 0x100, 'LOOP': 0x108, '_ADD': 0x120,
                      '_TOTAL': 0x122}


@pytest.mark.parametrize('block_a,block_b', [('/blk/', '/BLK/'),
                                             ('/Blk/', '/blk/')])
def test_common_block_rows_survive_any_case_of_the_name(tmp_path, block_a,
                                                         block_b):
    _write(tmp_path, 'a.mac',
           f"\t.z80\n\tcommon\t{block_a}\nla:\tdb\t5\n\tdb\t7\n\tcseg\n\tnop\n")
    _write(tmp_path, 'b.mac',
           f"\t.z80\n\tcommon\t{block_b}\nlb:\tdb\t6\n")
    for name in ('a', 'b'):
        _run('um80.um80', '--debug-info', f'{name}.mac', cwd=tmp_path)
    _run('um80.ul80', '--debug-info', '-o', 'ab.com', 'a.rel', 'b.rel',
         cwd=tmp_path)
    dbg = json.loads((tmp_path / 'ab.dbg').read_text())
    names = [(dbg['files'][r[3]], r[4]) for r in dbg['asm']]
    # b's byte replaced a's first byte of the shared block: a keeps the
    # second db (and the nop), b keeps its db.  One row is dropped.
    assert ('b.mac', 3) in names
    assert ('a.mac', 3) not in names
    assert ('a.mac', 4) in names
    assert dbg['dropped_rows'] == 1
    labels = {l[0]: l[1] for l in dbg['labels']}
    assert labels['LA'] == labels['LB']
