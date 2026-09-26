"""MACLIB: which file a library is read from.

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
