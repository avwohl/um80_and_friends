"""An empty operand in a DB or a DW.

MACRO-80 3.44 assembles an empty operand as 0: `DB' with none is 00, `DB
1,' 01 00 and `DB 1,,2' 01 00 02, each flagged Q, and `DW' is 00 00, `DW
1,' 01 00 00 00 and `DW 1,,2' 01 00 00 00 02 00, not flagged; `DW ''' is
00 00.  um80 assembled nothing for `DB', `DW' and a comma at the end, so
every address after them moved, without a word, and `DW ''' was an error.
It now assembles M80's bytes, and warns.

DRI's MAC 2.0 and RMAC 1.1 assemble 00 for each too, and flag it E (`DB
1,,2' is 01 00 00 there), and um80 --dri reports it.  An empty string,
`DB ''', is nothing in all three.

The bytes are M80's, MAC's and RMAC's under cpmemu, before a `DB 5'.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, **kw):
    """(ok, code bytes, errors, warnings)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE') if ok else b''
    return ok, code, [str(e) for e in asm.errors], asm.warnings


@pytest.mark.parametrize('line,m80', [
    ('\tdb', '0005'),
    ('\tdb\t1,', '010005'),
    ('\tdb\t1,,2', '01000205'),
    ('\tdb\t;c', '0005'),
    ('\tdw', '000005'),
    ('\tdw\t1,', '0100000005'),
    ('\tdw\t1,,2', '01000000020005'),
    ('\tdefb\t1,', '010005'),
    ('\tdefw', '000005'),
])
def test_empty_operand(line, m80):
    source = f"{line}\n\tdb\t5\n\tend\n"
    ok, code, errors, warnings = _assemble(source)
    assert ok, errors
    assert code.hex() == m80
    assert any('as M80 assembles it' in w for w in warnings), warnings
    ok, _, errors, _ = _assemble(source, dri=True)
    assert not ok                                   # MAC and RMAC: E
    assert any('MAC and RMAC flag an empty operand' in e for e in errors), errors


def test_an_empty_string():
    # `DB ''' is nothing and `DB 1,'',2' 01 02 in MAC and RMAC; `DW ''' is
    # 00 00 in M80 (MAC and RMAC: E).
    for dri in (False, True):
        ok, code, errors, warnings = _assemble("\tdb\t''\n\tdb\t5\n\tend\n", dri=dri)
        assert ok, errors
        assert code.hex() == '05'
        assert not warnings
    ok, code, errors, _ = _assemble("\tdb\t1,'',2\n\tend\n", dri=True)
    assert ok, errors
    assert code.hex() == '0102'
    ok, code, errors, _ = _assemble("\tdw\t''\n\tend\n")
    assert ok, errors
    assert code.hex() == '0000'
    ok, _, errors, _ = _assemble("\tdw\t''\n\tend\n", dri=True)
    assert not ok
