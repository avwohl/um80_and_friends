"""END ends the source.

MACRO-80 3.44, MAC 2.0 and RMAC 1.1 read nothing after an END: not the
rest of the file, not the rest of a macro or a REPT that assembles one, and
a label defined after it is undefined (U in all three).  An END in a false
IF is skipped.  um80 went on reading, and assembled what followed - `DB 1
/ END / DB 2' was 01 02.

The expected bytes are what the three assemble from the same source under
cpmemu.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, files=None, **kw):
    """(ok, code bytes, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        for name, text in (files or {}).items():
            with open(os.path.join(d, name), 'w') as f:
                f.write(text)
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE') if ok else b''
    return ok, code, [str(e) for e in asm.errors]


@pytest.mark.parametrize('source,code', [
    ("\tdb\t1\n\tend\n\tdb\t2\n", '01'),
    ("\tdb\t1\nend\n\tdb\t2\n\tend\n", '01'),                       # column 1
    ("s:\tnop\n\tend\ts\n\tdb\t2\n", '00'),
    ("mm\tmacro\n\tdb\t1\n\tend\n\tdb\t7\n\tendm\n\tmm\n\tdb\t2\n\tend\n", '01'),
    ("\trept\t2\n\tdb\t1\n\tend\n\tendm\n\tdb\t2\n\tend\n", '01'),
    ("\tif\t0\n\tend\n\tendif\n\tdb\t1\n\tend\n", '01'),             # skipped
])
def test_nothing_after_end(source, code):
    for dri in (False, True):
        ok, got, errors = _assemble(source, dri=dri)
        assert ok, errors
        assert got.hex() == code


def test_a_label_after_end_is_undefined():
    # All three: C3 00 00, U.
    ok, _, errors = _assemble("\tjmp\tx\n\tend\nx:\tnop\n")
    assert not ok
    assert any("Undefined symbol 'x'" in e for e in errors), errors


def test_end_in_an_include_file():
    ok, code, errors = _assemble("\tdb\t1\n\tinclude\tinc.mac\n\tdb\t3\n\tend\n",
                                 {'inc.mac': "\tdb\t2\n\tend\n\tdb\t9\n"})
    assert ok, errors
    assert code.hex() == '0102'


# MACLIB.  MACRO-80 3.44 reads a MACLIB file as it reads an INCLUDE file, so
# an END in one ends the source: `MACLIB INC.LIB / DB 2' with INC.LIB `DB 1
# / END' is 01, and with `FOO EQU 7 / END' and `DB FOO' after the MACLIB M80
# assembles nothing.  MAC 2.0 and RMAC 1.1 stop reading the library at its
# END and go on with the source: 07, and a macro defined before the END is
# there (`X MACRO / DB 9 / ENDM / END', then `X / DB 2': 09 02).  A name
# defined after the END is undefined (MAC P and U, RMAC U), and an address
# on it is not the start address (RMAC's REL has none).  um80 went on with
# the library, and after the commit that made END end the source it ended
# the whole assembly in both modes, without a word.

MACLIB_MAIN = "\torg\t100h\n\tmaclib\tINC\n\tdb\tFOO\n\tend\n"


def test_dri_end_in_a_maclib_file_ends_the_library():
    ok, code, errors = _assemble(MACLIB_MAIN, {'INC.MAC': "FOO\tequ\t7\n\tend\n"},
                                 dri=True)
    assert ok, errors
    assert code.hex() == '07'


def test_dri_a_macro_in_a_library_that_ends_with_end():
    ok, code, errors = _assemble("\torg\t100h\n\tmaclib\tINC\n\tX\n\tdb\t2\n\tend\n",
                                 {'INC.MAC': "X\tmacro\n\tdb\t9\n\tendm\n\tend\n"},
                                 dri=True)
    assert ok, errors
    assert code.hex() == '0902'


def test_dri_nothing_after_end_in_a_maclib_file_is_read():
    ok, _, errors = _assemble("\tmaclib\tINC\n\tdb\tFOO,BAR\n\tend\n",
                              {'INC.MAC': "FOO\tequ\t7\n\tend\nBAR\tequ\t8\n"},
                              dri=True)
    assert not ok
    assert any("Undefined symbol 'BAR'" in e for e in errors), errors


def test_dri_the_address_on_a_librarys_end_is_not_the_start():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, 'INC.MAC'), 'w') as f:
            f.write("\tend\t1234h\n")
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write("\tmaclib\tINC\n\tdb\t2\n\tend\n")
        asm = Assembler(dri=True)
        assert asm.assemble(p), [str(e) for e in asm.errors]
        assert asm.entry_point is None


def test_m80_end_in_a_maclib_file_ends_the_source():
    ok, code, errors = _assemble("\tdb\t1\n\tmaclib\tINC.LIB\n\tdb\t3\n\tend\n",
                                 {'INC.LIB': "\tdb\t2\n\tend\n\tdb\t9\n"})
    assert ok, errors
    assert code.hex() == '0102'


def test_m80_end_in_a_maclib_file_is_reported():
    # M80 says nothing, and assembles nothing after the MACLIB; um80 warns,
    # as a DRI library read without --dri loses the rest of the source.
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, 'INC.MAC'), 'w') as f:
            f.write("FOO\tequ\t7\n\tend\n")
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(MACLIB_MAIN)
        asm = Assembler()
        assert asm.assemble(p), [str(e) for e in asm.errors]
        assert any('MACLIB' in w and 'END' in w and '--dri' in w
                   for w in asm.warnings), asm.warnings
