"""MACLIB: which file a library is read from, and how it is read.

MACRO-80 3.44 reads `MACLIB NAME' as `INCLUDE NAME', from NAME.MAC, and a
name with an extension from that file.  DRI's MAC 2.0 and RMAC 1.1 read
NAME.LIB, whatever follows the name (`MACLIB NAME.MAC' is NAME.LIB, and
flagged S), and have no INCLUDE.  um80 --dri looked for NAME.MAC, so DRI's
`maclib diskdef' (MP/M II's CONTROL/RESXIOS.ASM, CP/M 2.0's os4bios.asm)
was "Cannot find include file".  With --dri it is NAME.LIB, and then
NAME.MAC, as um80 read it before.

A CP/M file name has no case, and DRI's sources name DISKDEF.LIB `diskdef':
a name is looked for as written, then in upper case, then in lower case.

The expected values are what M80, MAC and RMAC assemble under cpmemu with
INC.LIB holding `X EQU 1' and INC.MAC `X EQU 2'.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.ul80 import Linker
from um80.um80 import Assembler

BOTH = {'INC.LIB': "x\tequ\t1\n", 'INC.MAC': "x\tequ\t2\n"}


def _assemble(source, files, **kw):
    """(ok, code bytes, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        for name, text in files.items():
            with open(os.path.join(d, name), 'w') as f:
                f.write(text)
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE') if ok else b''
    return ok, code, [str(e) for e in asm.errors]


@pytest.mark.parametrize('name,m80,mac', [
    ('INC', '02', '01'),
    ('inc', '02', '01'),
    ('INC.LIB', '01', '01'),
    # MAC reads INC.LIB and flags the line S; um80 reads the file named.
    ('INC.MAC', '02', None),
])
def test_maclib_file(name, m80, mac):
    source = f"\tmaclib\t{name}\n\tdb\tx\n\tend\n"
    ok, code, errors = _assemble(source, BOTH)
    assert ok, errors
    assert code.hex() == m80
    ok, code, errors = _assemble(source, BOTH, dri=True)
    assert ok, errors
    assert code.hex() == (mac or m80)


def test_dri_maclib_falls_back_to_name_mac():
    # MAC and RMAC find no INC.LIB and stop; um80 --dri reads INC.MAC, as
    # it did before it read INC.LIB.
    ok, code, errors = _assemble("\tmaclib\tinc\n\tdb\tx\n\tend\n",
                                 {'INC.MAC': "x\tequ\t2\n"}, dri=True)
    assert ok, errors
    assert code.hex() == '02'


def test_m80_maclib_reads_no_name_lib():
    # M80 finds no INC.MAC: V, and X is undefined.
    ok, _, errors = _assemble("\tmaclib\tinc\n\tdb\tx\n\tend\n",
                              {'INC.LIB': "x\tequ\t1\n"})
    assert not ok
    assert any('Cannot find include file: inc, as inc.MAC' in e and '--dri' in e
               for e in errors), errors


def test_dri_maclib_names_the_files_it_looked_for():
    ok, _, errors = _assemble("\tmaclib\tnone\n\tend\n", {}, dri=True)
    assert not ok
    assert any('none.LIB or none.MAC' in e for e in errors), errors


def test_dri_maclib_diskdef():
    # MP/M II's CONTROL/RESXIOS.ASM: `maclib diskdef', and DISKDEF.LIB.
    lib = ("diskdef\tmacro\tdn,fsc\n\tdb\tdn,fsc\n\tendm\n"
           "ndisks\tmacro\tnd\nnumdsk\tset\tnd\n\tendm\n")
    source = "\tmaclib\tdiskdef\n\tndisks\t2\n\tdiskdef\t0,1\n\tdb\tnumdsk\n\tend\n"
    ok, code, errors = _assemble(source, {'DISKDEF.LIB': lib}, dri=True)
    assert ok, errors
    assert code.hex() == '000102'


def test_include_name_in_another_case():
    # `include inc' of INC.MAC, and `include INC' of inc.mac.
    for name, fname in (('inc', 'INC.MAC'), ('INC', 'inc.mac')):
        ok, code, errors = _assemble(f"\tinclude\t{name}\n\tdb\tx\n\tend\n",
                                     {fname: "x\tequ\t2\n"})
        assert ok, errors
        assert code.hex() == '02'


# MAC and RMAC read a library in pass 1 only: its macros and the symbols it
# defines are there in pass 2, but none of its code or data is assembled,
# and a symbol it defines keeps the value pass 1 gave it.  M80 reads the
# file as an INCLUDE file.  um80 --dri assembled it as M80 does.  The
# values are M80's, MAC's and RMAC's under cpmemu (INC.LIB and INC.MAC hold
# the same library here).

def _lib(text):
    return {'INC.LIB': text, 'INC.MAC': text}


def _rel(source, files, **kw):
    """(ok, REL items, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        for name, text in files.items():
            with open(os.path.join(d, name), 'w') as f:
                f.write(text)
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        items = RELReader(asm.output.get_bytes()).read_all() if ok else []
    return ok, items, [str(e) for e in asm.errors]


def _image(items):
    """{address: byte} of an absolute REL."""
    mem, loc = {}, 0
    for it in items:
        if it[0] == 'SET_LOC':
            loc = it[1][1]
        elif it[0] == 'ABSOLUTE_BYTE':
            mem[loc] = it[1]
            loc += 1
    return ' '.join(f'{a:04X}:{b:02X}' for a, b in sorted(mem.items()))


@pytest.mark.parametrize('main,lib,m80,mac', [
    # A library's code, data, ORG and macro calls assemble nothing.
    ("\tdb\t2\n", "\tdb\t1\n", '0100:01 0101:02', '0100:02'),
    ("\tdb\t2\n", "\torg\t200h\n", '0200:02', '0100:02'),
    ("\tdb\t2\n", "mx\tmacro\n\tdb\t9\n\tendm\n\tmx\n",
     '0100:09 0101:02', '0100:02'),
    # A label it defines keeps its value from pass 1.
    ("\tdw\tll\n", "ll:\tdb\t1\n", '0100:01 0101:00 0102:01', '0100:00 0101:01'),
    # A SET: the value at the end of pass 1.
    ("\tdb\tx\nx\tset\t2\n\tdb\tx\n", "x\tset\t1\n", '0100:01 0101:02',
     '0100:02 0101:02'),
    ("\tdb\tx\nx\tset\tx+1\n\tdb\tx\n", "x\tset\t1\n", '0100:01 0101:02',
     '0100:02 0101:03'),
    # Macros and EQUs, as DRI's libraries have them, are the same in all.
    ("\tmx\n\tdb\ty\n", "mx\tmacro\n\tdb\t9\n\tendm\ny\tequ\t5\n",
     '0100:09 0101:05', '0100:09 0101:05'),
    ("\tmx\n\tdb\t2\n", "mx\tmacro\n\tlocal\tl\nl:\tdb\t9\n\tdw\tl\n\tendm\n",
     '0100:09 0101:00 0102:01 0103:02', '0100:09 0101:00 0102:01 0103:02'),
    ("\tdw\t$\n", "\tdb\t1\n", '0100:01 0101:01 0102:01', '0100:00 0101:01'),
])
def test_maclib_is_read_in_pass_1_only(main, lib, m80, mac):
    source = f"\taseg\n\torg\t100h\n\tmaclib\tinc\n{main}\tend\n"
    for dri, want in ((False, m80), (True, mac)):
        ok, items, errors = _rel(source, _lib(lib), dri=dri)
        assert ok, errors
        assert _image(items) == want, (dri, _image(items))


@pytest.mark.parametrize('main,name,before,after', [
    ("lab:\tdb\t2\n\tdw\tlab\n", 'LAB', '0101', '0100'),
    ("lab:\tmvi\ta,5\n\tdw\tlab\n", 'LAB', '0101', '0100'),
    ("\tnop\nlab:\n\tdb\t8\n\tdw\tlab\n", 'LAB', '0102', '0101'),
    ("lab\tequ\t$\n\tdw\tlab\n", 'LAB', '0101', '0100'),
])
def test_dri_a_label_a_librarys_code_moved_is_a_phase_error(main, name, before, after):
    # MAC and RMAC flag the label P, and keep its address of pass 1.
    source = f"\taseg\n\torg\t100h\n\tmaclib\tinc\n{main}\tend\n"
    ok, _, errors = _rel(source, _lib("\tdb\t1\n"), dri=True)
    assert not ok
    # The file is inc.LIB where file names have no case, INC.LIB elsewhere.
    assert any(f"PHASE ERROR: '{name}' IS {before}H IN PASS 1 AND {after}H IN PASS 2:"
               " MACLIB INC.LIB HAS CODE OR DATA" in e.upper() for e in errors), errors


def test_dri_the_segment_sizes_are_those_of_pass_1():
    # RMAC writes the size pass 1 reached, which counts the library's code:
    # 2 bytes, one of them loaded, and with a library `ORG 200H' 201H.
    for lib, size in (("\tdb\t1\n", 0x102), ("\torg\t200h\n", 0x201)):
        ok, items, errors = _rel("\torg\t100h\n\tmaclib\tinc\n\tdb\t2\n\tend\n",
                                 _lib(lib), dri=True)
        assert ok, errors
        assert ('DEFINE_PROG_SIZE', (1, size)) in items, items
        assert [it for it in items if it[0] == 'ABSOLUTE_BYTE'] == [('ABSOLUTE_BYTE', 2)]


@pytest.mark.parametrize('lib,main,prog,item', [
    # A library that reserves data or COMMON space and goes back to the
    # code segment where it started: RMAC writes the size it reserved.
    ("\tdseg\n\tdb\t9\n\tcseg\n", "lb:\tdb\t2\n\tdw\tlb\n", 0x103,
     ('DEFINE_DATA_SIZE', (0, 1))),
    ("\tdseg\n\tds\t10\n\tcseg\n", "\tdb\t2\n", 0x101,
     ('DEFINE_DATA_SIZE', (0, 10))),
    ("\tdseg\nbuf:\tds\t10\nbend:\n\tcseg\n", "\tlxi\th,buf\n\tlxi\td,bend\n",
     0x106, ('DEFINE_DATA_SIZE', (0, 10))),
    ("\tcommon\t/cb/\ncbuf:\tds\t6\n\tcseg\n", "\tlxi\th,cbuf\n", 0x103,
     ('DEFINE_COMMON_SIZE', (0, 6), 'CB')),
])
def test_dri_a_library_that_goes_back_keeps_its_data_and_common_sizes(lib, main, prog, item):
    # um80 --dri wrote 0: the library had not moved the location counter of
    # the segment it started in, so pass 1's sizes were not used.  0.3.51,
    # which assembled the library in both passes, wrote RMAC's sizes.
    ok, items, errors = _rel(f"\torg\t100h\n\tmaclib\tinc\n{main}\tend\n",
                             _lib(lib), dri=True)
    assert ok, errors
    assert item in items, items
    assert ('DEFINE_PROG_SIZE', (1, prog)) in items, items


def test_dri_data_a_library_reserves_is_not_linked_over():
    # A library reserves 10 bytes of data, and another module has a byte of
    # data.  LINK-80 puts that byte at 0110H with RMAC's RELs, after the 10;
    # um80 --dri wrote a data size of 0, and ul80 put it at 0106H, on BUF.
    with tempfile.TemporaryDirectory() as d:
        sources = {
            'INC.LIB': "\tdseg\nbuf:\tds\t10\n\tcseg\n",
            'a.asm': "\tmaclib\tinc\n\tlxi\th,buf\n\tend\n",
            'b.asm': "\tdseg\nx:\tdb\t55h\n\tcseg\n\tlxi\td,x\n\tend\n",
        }
        for name, text in sources.items():
            with open(os.path.join(d, name), 'w') as f:
                f.write(text)
        linker = Linker()
        linker.code_base = 0x100
        for stem in ('a', 'b'):
            asm = Assembler(dri=True)
            assert asm.assemble(os.path.join(d, stem + '.asm')), asm.errors
            rel = os.path.join(d, stem + '.rel')
            with open(rel, 'wb') as f:
                f.write(asm.output.get_bytes())
            linker.load_rel(rel)
        assert linker.link()
        image = bytes(linker.output[0x100 - linker.output_base:])
    assert image == bytes.fromhex('210601111001') + bytes(10) + b'\x55', image.hex()


def test_dri_public_and_extrn_in_a_library():
    # RMAC: A1 is a public at 0102H, and E1 an external.
    ok, items, errors = _rel("\torg\t100h\n\tmaclib\tinc\n\tdw\te1\na1:\tdb\t3\n\tend\n",
                             _lib("\tpublic\ta1\n\textrn\te1\n"), dri=True)
    assert ok, errors
    assert any(it[0] == 'DEFINE_ENTRY' and it[2] == 'A1' for it in items), items
    assert any(it[0] == 'CHAIN_EXTERNAL' and it[2] == 'E1' for it in items), items
