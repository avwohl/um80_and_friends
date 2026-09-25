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
