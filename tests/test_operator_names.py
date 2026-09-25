"""A name that is, or ends in, an operator of expressions.

M80 3.44 reads a name whole: `X1EQ+2' is X1EQ plus 2, and so are
`@P$NUL-1', `X1LOW+1' and `AB_AND+1'.  um80 took the letters in front of a
+ or - for a word operator whenever they spelled one, so each of those was
"Cannot parse expression" - and `TYPE+2' was TYPE of +2, without a word.

A program may also name a symbol like an operator (MAC and RMAC flag it S;
M80 takes it), and M80 then reads the name as the symbol wherever it occurs,
even defined further down: after `TYPE EQU 5', `TYPE+2' is 07; after `EQ:
NOP', `DW EQ' is the label.  It is no longer the operator there: `DB 1 EQ 1'
is an error (O).  um80 read EQ, NE, LT, LE, GT, GE, SHL, SHR and NUL as the
operators they spell, so `DW EQ' was 0FFFFH (0 EQ 0), and `CALL EQ' called
it.  With no such symbol, EQ or SHL alone has nothing on one side: M80
flags it O, and um80 now reports it.

TYPE of an expression is 20H (defined) with the mode in the low bits, 80H
for an external: `TYPE 5' is 20H and `TYPE (LAB)' 21H in M80, where um80
gave 0.

The fixtures are the .REL files M80 3.44 writes for the same sources.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, **kw):
    """(ok, REL items or None, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        items = RELReader(asm.output.get_bytes()).read_all() if ok else None
    return ok, items, [str(e) for e in asm.errors]


def _fields(items):
    """Every byte and relocatable word loaded, in order."""
    out = []
    for it in items:
        if it[0] == 'ABSOLUTE_BYTE':
            out.append(f'{it[1]:02X}')
        elif it[0] == 'PROGRAM_REL':
            out.append(f'P{it[1]:04X}')
    return out


ENDINGS = ("x1eq\tequ\t5\n@p$nul\tequ\t5\nx1low\tequ\t5\nab_and\tequ\t3\nxtype\tequ\t9\n"
           "\tdb\tx1eq+2,x1eq-1,x1eq +2,@p$nul+2,@p$nul-1,x1low-1,x1low+1,"
           "ab_and+1,ab_and-1,xtype+1\n\tend\n")
M80_ENDINGS = bytes.fromhex('84552500001350a00038100e07020100c040102a7000009e1a')

NAMES = ("\tdb\ttype+2\ntype\tequ\t5\nnul\tequ\t5\n\tdb\tnul,nul+1,type\n"
         "\tdw\teq,eq+1,low,low+1\neq:\tnop\nlow:\tnop\n\tend\n")
M80_NAMES = bytes.fromhex('84552500001350e00038140c05a180143402868050e00000027000009e1a')

TYPES = ("lab:\tdb\ttype 5,type 'A',type (lab),type +2,type(5),type lab+1,"
         "type lab,type 2 eq 2\n\tend\n")
M80_TYPES = bytes.fromhex('845525000013508001008042201008842009c000009e1a')


@pytest.mark.parametrize('source,m80,fields', [
    # 07 04 07 07 04 04 06 04 02 0A
    (ENDINGS, M80_ENDINGS, '07 04 07 07 04 04 06 04 02 0A'),
    # TYPE+2 before and after `TYPE EQU 5' is 07; NUL, NUL+1 and TYPE are
    # 05 06 05; EQ, EQ+1, LOW and LOW+1 are the labels.  um80: 00 FF 00 05,
    # FFFF, FFFF, 00, and "LOW+1" the label's offset plus 1.
    (NAMES, M80_NAMES, '07 05 06 05 P000C P000D P000D P000E 00 00'),
    # TYPE of a number, a string, (LAB), +2 and (5) - um80 gave 00 for each
    # - and TYPE LAB+1, which is (TYPE LAB)+1.
    (TYPES, M80_TYPES, '20 20 21 20 20 22 21 00'),
])
def test_as_m80(source, m80, fields):
    for dri in (False, True):
        ok, items, errors = _assemble(source, dri=dri)
        assert ok, errors
        assert _fields(items) == _fields(RELReader(m80).read_all())
        assert ' '.join(_fields(items)) == fields


def test_an_external_named_like_an_operator():
    ok, items, errors = _assemble("\textrn\tshr\n\tdw\tshr,shr+1\n\tend\n")
    assert ok, errors
    assert [it[2] for it in items if it[0] == 'CHAIN_EXTERNAL'] == ['SHR', 'SHR']


@pytest.mark.parametrize('source', [
    "eq\tequ\t5\n\tdb\t1 eq 1\n\tend\n",          # M80: O
    "mod\tequ\t3\n\tdb\t7 mod 2\n\tend\n",        # M80: O
    "high\tequ\t3\n\tdb\thigh 1234h\n\tend\n",    # M80: O
    "not\tequ\t3\n\tdb\tnot 0\n\tend\n",          # M80: O
    "type\tequ\t5\nlab:\tdb\ttype lab\n\tend\n",  # M80: O
])
def test_a_symbol_is_no_longer_the_operator(source):
    ok, _, errors = _assemble(source)
    assert not ok and errors


@pytest.mark.parametrize('operand', ['eq', 'ne', 'shl', 'shr', 'mod', 'and', '1 eq', 'lt 2'])
def test_an_operator_with_nothing_on_one_side(operand):
    # M80: O, for each.  um80 took the missing value for 0: `DW EQ' was
    # 0FFFFH.
    ok, _, errors = _assemble(f"\tdw\t{operand}\n\tend\n")
    assert not ok
    assert any('needs a value on each side' in e for e in errors), errors


def test_nul_alone_is_still_nul():
    # NUL of nothing is true: M80 FFFF 0000.
    ok, items, errors = _assemble("\tdw\tnul\n\tdw\tnul+1\n\tend\n")
    assert ok, errors
    assert _fields(items) == ['FF', 'FF', '00', '00']
