"""--dri: MAC's relational operators, and HIGH and LOW bind loosest.

DRI's MAC and RMAC take `=', `<', `<=', `>', `>=' and `<>' for EQ, LT, LE,
GT, GE and NE, at the same level, unsigned, true 0FFFFH (MAC manual, and
the genuine MAC 2.0 and RMAC 1.1; MAC 2.0 itself flags `<>' E, which RMAC
and the manual have).  CONTROL/DEBLOCK.ASM has `IF @Y = 1'.  M80 has no
such operator (O), and without --dri um80 reports them.  With --dri a `<'
or `>' in a list of values is an operator, not a bracket: `DW 1<2,3' is
two words.

The MAC manual's table puts HIGH and LOW below every other operator, and
MAC and RMAC apply them to all that follows: `HIGH 1234H OR 0F00H' is
HIGH(1F34H), 1FH, `HIGH(100H)+1' is HIGH(101H), 1, and `LOW 1234H SHR 4'
23H.  M80 applies them to the term after them - 12H OR 0F00H, 2, 03H - and
so does um80 without --dri.

The fixtures are the .REL files RMAC 1.1 writes for the same sources; MAC
2.0 assembles the same bytes but for its E at `<>'.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, **kw):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        items = RELReader(asm.output.get_bytes()).read_all() if ok else None
    return ok, items, [str(e) for e in asm.errors]


def _code(items):
    return bytes(it[1] for it in items if it[0] == 'ABSOLUTE_BYTE')


RELATIONS = ("\tdw\t1 = 1,1 = 2,1 < 2,2 <= 2,3 > 2,3 >= 4,1 <> 2,1+1 = 2\n"
             "\tdw\tnot 1 = 1,1 = 1 and 0,1 = 1 = 1,-1 < 1,'A' = 41h,5 and 3 = 3,"
             "1=1,1<2\n\tend\n")
RMAC_RELATIONS = bytes.fromhex(
    '845525000013520007fbfc00007fbfdfeff7fbfc00007fbfdfeff0000000000000000007fbfc0a007f'
    'bfdfeff9c000009e')

HIGH_LOW = ("\tdw\thigh 100h+1,low 1ffh+1,high 1234h and 0fh,low 1234h shr 4,"
            "high 1234h or 0f00h\n\tdw\thigh(100h)+1,(high 100h)+1,high 1234h eq 12h,"
            "low 1 = 1,high 2 * 100h\n\tend\n")
RMAC_HIGH_LOW = bytes.fromhex(
    '845525000013514000080000000000046000f80002000100000007f80004009c0000009e')

COMMAS = ("x\tequ\t2\n\tdw\t1<2,3\n\tdb\t2>1,3,x<3,x>=3\n\tif\tx<3\n\tdb\t1\n\tendif\n"
          "\tmvi\ta,x=2\n\tend\n")
RMAC_COMMAS = bytes.fromhex('84552500001350b007fbfc06007f80dfe00008f9ff3800009e')


@pytest.mark.parametrize('source,rmac,code', [
    # FFFF 0000 FFFF FFFF FFFF 0000 FFFF FFFF; NOT (1 = 1), (1 = 1) AND 0,
    # (1 = 1) = 1, 0FFFFH < 1: 0 0 0 0; FFFF, 5 AND (3 = 3): 5, FFFF FFFF.
    (RELATIONS, RMAC_RELATIONS, 'ffff0000ffffffffffff0000ffffffff'
                                '0000000000000000ffff0500ffffffff'),
    # 01 00 23 1F 01, (HIGH 100H)+1 is 2, HIGH (1234H EQ 12H) 0, LOW (1 =
    # 1) FF, HIGH 200H 2.  M80: 02 01 02 03 0F12 02 02 FFFF 01 00.
    (HIGH_LOW, RMAC_HIGH_LOW, '0100000000002300' '1f00010002000000ff000200'),
    (COMMAS, RMAC_COMMAS, 'ffff0300' 'ff03ff00' '01' '3eff'),
])
def test_as_rmac_with_dri(source, rmac, code):
    ok, items, errors = _assemble(source, dri=True)
    assert ok, errors
    assert _code(items) == _code(RELReader(rmac).read_all())
    assert _code(items).hex() == code


@pytest.mark.parametrize('source', [
    "@y\tequ\t1\n\tif\t@y = 1\n\tdb\t1\n\tendif\n\tend\n",  # DEBLOCK.ASM; M80: O
    "\tdw\t1 < 2\n\tend\n",
    "\tdw\t1 <> 2\n\tend\n",
])
def test_not_without_dri(source):
    ok, _, errors = _assemble(source)
    assert not ok and errors


def test_high_and_low_bind_tightest_without_dri():
    # M80: 02 00, 01 00, 0F12, 02 00.
    ok, items, errors = _assemble("\tdw\thigh 100h+1,low 1ffh+1,high 1234h or 0f00h,"
                                  "high(100h)+1\n\tend\n")
    assert ok, errors
    assert _code(items).hex() == '02000001120f0200'
