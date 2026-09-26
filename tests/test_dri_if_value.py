"""Which value makes an IF true.

MACRO-80 3.44 takes an IF as true when its value is not 0.  DRI's MAC 2.0
and RMAC 1.1 take it as true only when bit 0 of the value is set: `IF 2',
`IF 100H', `IF 0FFFEH' and `IF NOT 1' are false there.  A relation is 0 or
0FFFFH in all three, so `IF X EQ 2' is the same everywhere.  um80 --dri
took any value but 0 as true, as M80 does, without a word.

MAC has no IFT, IFE, IFF, COND, IF1, IF2, IFDEF, IFNDEF, IFB or IFNB: it
reads `IFT 2' as a label and flags the ELSE and ENDIF after it B.  um80
keeps them with --dri, with M80's meaning.

The expected bytes are what M80, MAC and RMAC assemble from the same source
under cpmemu.
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


def _if(directive, value):
    return (f"\t{directive}\t{value}\n\tdb\t1\n\telse\n\tdb\t2\n\tendif\n"
            "\tdb\t3\n\tend\n")


# (value, M80's bytes, MAC's and RMAC's bytes)
@pytest.mark.parametrize('value,m80,mac', [
    ('1', '0103', '0103'),
    ('3', '0103', '0103'),
    ('0ffh', '0103', '0103'),
    ('-1', '0103', '0103'),
    ("'A'", '0103', '0103'),
    ('2 eq 2', '0103', '0103'),
    ('0', '0203', '0203'),
    ('1 and 2', '0203', '0203'),
    ('2', '0103', '0203'),
    ('100h', '0103', '0203'),
    ('0fffeh', '0103', '0203'),
    ('not 1', '0103', '0203'),
    ("'B'", '0103', '0203'),
])
def test_if(value, m80, mac):
    for dri, want in ((False, m80), (True, mac)):
        ok, code, errors = _assemble(_if('if', value), dri=dri)
        assert ok, errors
        assert code.hex() == want, (dri, code.hex())


@pytest.mark.parametrize('source,m80,mac', [
    # An IF nested in a false one is skipped, and one in a true one is read.
    ("\tif\t2\n\tif\t1\n\tdb\t1\n\tendif\n\tdb\t4\n\telse\n\tdb\t2\n\tendif\n"
     "\tdb\t3\n\tend\n", '010403', '0203'),
    ("\tif\t1\n\tif\t2\n\tdb\t1\n\telse\n\tdb\t4\n\tendif\n\tendif\n\tdb\t3\n"
     "\tend\n", '0103', '0403'),
    ("x\tequ\t4\n\tif\tx\n\tdb\t1\n\tendif\n\tdb\t3\n\tend\n", '0103', '03'),
    # A macro's argument.
    ("mm\tmacro\tp\n\tif\tp\n\tdb\t1\n\tendif\n\tendm\n\tmm\t2\n\tmm\t3\n"
     "\tdb\t3\n\tend\n", '010103', '0103'),
])
def test_if_in_context(source, m80, mac):
    for dri, want in ((False, m80), (True, mac)):
        ok, code, errors = _assemble(source, dri=dri)
        assert ok, errors
        assert code.hex() == want, (dri, code.hex())


# um80's directives MAC does not have keep M80's meaning with --dri.
@pytest.mark.parametrize('directive,value,m80', [
    ('ift', '2', '0103'),
    ('ift', '0', '0203'),
    ('cond', '2', '0103'),
    ('ife', '2', '0203'),
    ('ife', '0', '0103'),
    ('iff', '2', '0203'),
])
def test_m80_directives_keep_their_meaning(directive, value, m80):
    for dri in (False, True):
        ok, code, errors = _assemble(_if(directive, value), dri=dri)
        assert ok, errors
        assert code.hex() == m80, (dri, code.hex())
