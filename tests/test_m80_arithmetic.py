"""A unary sign, division and MOD, as MACRO-80 and as MAC read them.

MACRO-80 3.44 applies a unary minus or plus to the term after it, before
*, /, MOD, SHL and SHR: `-1 SHR 8' is (-1) SHR 8, 00FFH, and `-2 SHR 1'
7FFFH.  (Its manual puts the sign below them; the assembler does not.)  It
divides signed: 8000H/2 is 0C000H, 0FFFEH/2 is 0FFFFH, 7/-2 is 0FFFDH (the
quotient rounds toward 0), and the remainder of MOD has the sign of the
quotient: 4 MOD -3 and -4 MOD 3 are 0FFFFH, and -4 MOD -3 is 1.

DRI's MAC 2.0 and RMAC 1.1 (--dri) apply a unary sign to all of those, as
MAC's manual says: `-1 SHR 8' is -(1 SHR 8), 0; and they divide unsigned:
8000H/2 is 4000H.  um80 read MAC's way in either mode, so without --dri
those were 0, 0FFFFH, 4000H, 7FFFH, 0 and 4, without a word.

x MOD 0 is x in all three, without a flag; x/0 is 0FFFFH in MAC and RMAC,
without a flag, and M80 flags it O.  um80 reported both as a division by
zero; now it warns, and x/0 is still an error without --dri.

Each value is what M80, MAC and RMAC assemble from `DW expr' under cpmemu.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _dw(expr, **kw):
    """(ok, the word, errors, warnings)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(f"x1\tequ\t1\n\tdw\t{expr}\n\tend\n")
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE') if ok else b''
    word = code[0] | code[1] << 8 if len(code) == 2 else None
    return ok, word, [str(e) for e in asm.errors], asm.warnings


# (expression, M80's value, MAC's and RMAC's value)
CASES = [
    ('-1 shr 8', 0x00FF, 0x0000),
    ('-(1) shr 8', 0x00FF, 0x0000),
    ('- 1 shr 8', 0x00FF, 0x0000),
    ('-x1 shr 8', 0x00FF, 0x0000),
    ('-2 shr 1', 0x7FFF, 0xFFFF),
    ("-'A' shr 4", 0x0FFB, 0xFFFC),
    ('-(-1) shr 8', 0x0000, 0xFF01),
    ('-1 mod 3 shr 1', 0x7FFF, 0x0000),
    ('-x1+1 shr 8', 0xFFFF, 0xFFFF),
    ('0-1 shr 8', 0x0000, 0x0000),
    ('(-1) shr 8', 0x00FF, 0x00FF),
    ('-(1 shr 8)', 0x0000, 0x0000),
    ('-1 shl 8', 0xFF00, 0xFF00),
    ('-2*3', 0xFFFA, 0xFFFA),
    ('-4/2', 0xFFFE, 0xFFFE),
    ('-7/2', 0xFFFD, 0xFFFD),
    ('-6/2', 0xFFFD, 0xFFFD),
    ('8000h/2', 0xC000, 0x4000),
    ('0fffeh/2', 0xFFFF, 0x7FFF),
    ('0ffffh/2', 0x0000, 0x7FFF),
    ('1/0ffffh', 0xFFFF, 0x0000),
    ('8000h/0ffffh', 0x8000, 0x0000),
    ('0fff0h/10h', 0xFFFF, 0x0FFF),
    ('-1/2', 0x0000, 0x0000),
    ('4 mod 3', 0x0001, 0x0001),
    ('-4 mod 3', 0xFFFF, 0xFFFF),
    ('-5 mod 3', 0xFFFE, 0xFFFE),
    ('-7 mod 2', 0xFFFF, 0xFFFF),
    ('-10 mod 3', 0xFFFF, 0xFFFF),
    ('8000h mod 3', 0xFFFE, 0x0002),
    ('0ffffh mod 10', 0xFFFF, 0x0005),
    ('8000h mod 0ffffh', 0x0000, 0x8000),
    ('-1 lt 1', 0x0000, 0x0000),          # relations are unsigned in all three
    ('8000h lt 7fffh', 0x0000, 0x0000),
    ('0fff0h shr 4', 0x0FFF, 0x0FFF),
]

# MAC and RMAC flag a sign after an operator (E, and 0); M80 takes it.
M80_ONLY = [
    ('7/-2', 0xFFFD),
    ('-7/-2', 0x0003),
    ('5/-1', 0xFFFB),
    ('8000h/-1', 0x8000),
    ('10/-3', 0xFFFD),
    ('4 mod -3', 0xFFFF),
    ('-4 mod -3', 0x0001),
    ('5 mod -3', 0xFFFE),
    ('10 mod -3', 0xFFFF),
    ('-10 mod -3', 0x0001),
    ('6/-2*-1', 0x0003),
    ('2+-1 shr 8', 0x0101),
    ('2*-3 shr 1', 0x7FFD),
]


@pytest.mark.parametrize('expr,m80,mac', CASES)
def test_value(expr, m80, mac):
    for dri, want in ((False, m80), (True, mac)):
        ok, word, errors, _ = _dw(expr, dri=dri)
        assert ok, errors
        assert word == want, (dri, hex(word))


@pytest.mark.parametrize('expr,m80', M80_ONLY)
def test_m80_value(expr, m80):
    ok, word, errors, _ = _dw(expr)
    assert ok, errors
    assert word == m80, hex(word)


@pytest.mark.parametrize('expr,value', [('5 mod 0', 5), ('-1 mod 0', 0xFFFF)])
def test_mod_0_is_the_value_divided(expr, value):
    # All three: no flag.  um80 warns.
    for dri in (False, True):
        ok, word, errors, warnings = _dw(expr, dri=dri)
        assert ok, errors
        assert word == value
        assert any('MOD 0 is the value divided' in w for w in warnings), warnings


def test_division_by_0():
    # MAC and RMAC: 0FFFFH, and -5/0 is -(5/0), 1; no flag.  M80: O.
    for expr, value in (('5/0', 0xFFFF), ('-5/0', 0x0001)):
        ok, word, errors, warnings = _dw(expr, dri=True)
        assert ok, errors
        assert word == value
        assert any('division by 0 is 0FFFFH' in w for w in warnings), warnings
        ok, _, errors, _ = _dw(expr)
        assert not ok
        assert any('Division by zero' in e for e in errors), errors
