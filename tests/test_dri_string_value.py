"""A two-character string used as a value.

MACRO-80 3.44 makes the first character the high-order byte, 'AB' =
4142H; DRI's MAC 2.0 and RMAC 1.1 make it the low-order byte, 'AB' = 4241H.
um80 --dri gave M80's order, without a word: `DW 'AB'' was 42 41 where MAC
assembles 41 42.  A string in a DB is its characters in all three.

The expected bytes are what M80, MAC and RMAC assemble from the same
source under cpmemu.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, **kw):
    """(ok, code bytes, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE') if ok else b''
    return ok, code, [str(e) for e in asm.errors]


# (source, M80's bytes, MAC's and RMAC's bytes)
CASES = [
    ("\tdw\t'AB'\n", '4241', '4142'),
    ("\tlxi\th,'AB'\n", '214241', '214142'),
    ("x\tequ\t'AB'\n\tdw\tx\n", '4241', '4142'),
    ("x\tset\t'AB'\n\tdw\tx\n", '4241', '4142'),
    ("\tdw\t('AB')\n", '4241', '4142'),
    ("\tdb\t('AB') shr 8\n", '41', '42'),
    ("\tdb\tlow 'AB'\n", '42', '41'),
    ("\tdb\thigh 'AB'\n", '41', '42'),
    ("\tdw\t'AB' and 0ffh\n", '4200', '4100'),
    ("\tdw\t'AB'+1\n", '4341', '4242'),
    ("\tdw\t-'AB'\n", 'bebe', 'bfbd'),
    ("\tdw\t'''A'\n", '4127', '2741'),              # a doubled quote
    ("\tif\t'AB' eq 4241h\n\tdb\t1\n\tendif\n\tdb\t2\n", '02', '0102'),
    ("\tif\t'AB' eq 'A'*256+'B'\n\tdb\t1\n\tendif\n\tdb\t2\n", '0102', '02'),
    # One character, and a string in a DB, are the same in all three.
    ("\tdw\t'A'\n", '4100', '4100'),
    ("\tdb\t'AB'\n", '4142', '4142'),
]


@pytest.mark.parametrize('source,m80,mac', CASES)
def test_two_character_string_value(source, m80, mac):
    for dri, want in ((False, m80), (True, mac)):
        ok, code, errors = _assemble(source + "\tend\n", dri=dri)
        assert ok, errors
        assert code.hex() == want, (dri, code.hex())
