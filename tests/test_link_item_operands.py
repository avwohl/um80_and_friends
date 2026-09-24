"""A constant added to an address goes to the linker as an operand of its own.

In a link-time expression um80 folded a constant into the relocatable value
beside it: `MVI A,HIGH(C1+100H)', C1 at offset 0 of COMMON /BLK1/, went out
as the one extension item C(common, 0100H) and HIGH.  MACRO-80 3.44 writes
the expression as the source spells it - C(common, 0000H) C(abs, 0100H)
A(+) A(HIGH) - and LINK-80 3.44 gets a COMMON-relative value that lies past
the end of its block wrong: with BLK1 300H bytes long, M80's object links
to 05H and um80's to A0H.  (L80 is right for a CSEG or DSEG value of any
size, so only COMMON showed it; um80 now writes M80's form for all three.)
An EQU is folded, as in M80: `X EQU C1+100H' is one COMMON-relative value,
which LINK-80 gets wrong for M80's object too.
"""

import os
import tempfile

from um80.relformat import (ADDR_ABSOLUTE, ADDR_COMMON_REL, ADDR_DATA_REL,
                            ADDR_PROGRAM_REL, EXT_OP_HIGH, EXT_OP_LOW,
                            EXT_OP_MINUS, EXT_OP_PLUS, EXT_OP_STORE_BYTE,
                            RELReader)
from um80.ul80 import Linker
from um80.um80 import Assembler


def _asm(d, name, source):
    p = os.path.join(d, name + ".mac")
    with open(p, "w", encoding="ascii") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), [e.format_message() for e in asm.errors]
    return asm.output.get_bytes()


def _expressions(rel):
    """The link-time expressions of a REL: one list of items per store."""
    out, cur = [], []
    for item in RELReader(rel).read_all():
        if item[0] == 'EXT_VALUE':
            cur.append(('C',) + item[1])
        elif item[0] == 'EXT_SYMBOL':
            cur.append(('B', item[1]))
        elif item[0] == 'EXT_OPERATOR':
            cur.append(('A', item[1]))
            if item[1] == EXT_OP_STORE_BYTE:
                out.append(cur)
                cur = []
    return out


def _c(addr_type, value):
    return ('C', addr_type, value)


PLUS, MINUS, HIGH, LOW, STORE = (('A', op) for op in (
    EXT_OP_PLUS, EXT_OP_MINUS, EXT_OP_HIGH, EXT_OP_LOW, EXT_OP_STORE_BYTE))

COMOFF = ("\tCSEG\n\tMVI A,HIGH(C1+100H)\n\tMVI A,HIGH(C1+400H)\n"
          "\tMVI A,LOW(C1+5)\n\tMVI A,HIGH(C2+20H)\n\tMVI A,LOW(C2+20H)\n"
          "\tMVI A,HIGH(C2+100H)\n\tDB LOW(C2-1)\n"
          "\tCOMMON /BLK1/\nC1:\tDS 300H\n\tCOMMON /BLK2/\nC2:\tDS 10H\n"
          "\tEND\n")


def test_constant_beside_a_common_address_is_its_own_operand():
    with tempfile.TemporaryDirectory() as d:
        exprs = _expressions(_asm(d, "C", COMOFF))
    blk = ADDR_COMMON_REL
    assert exprs[:2] == [
        [_c(blk, 0), _c(ADDR_ABSOLUTE, 0x100), PLUS, HIGH, STORE],
        [_c(blk, 0), _c(ADDR_ABSOLUTE, 0x400), PLUS, HIGH, STORE]]
    assert exprs[6] == [_c(blk, 0), _c(ADDR_ABSOLUTE, 1), MINUS, LOW, STORE]


def test_operands_in_source_order_as_macro80_writes_them():
    """Items MACRO-80 3.44 writes for the same lines (C2 at 2 in BLK1)."""
    src = ("\tCSEG\nLAB:\tNOP\n\tMVI A,HIGH(C2+100H+5)\n\tMVI A,HIGH(5+C2)\n"
           "\tMVI A,HIGH(C2-5)\n\tMVI A,C2+5\n\tMVI A,HIGH(LAB+300H)\n"
           "\tMVI A,LOW(BUF+80H)\n\tMVI A,HIGH BUF\n"
           "\tDSEG\n\tDS 3\nBUF:\tDS 1\n"
           "\tCOMMON /BLK1/\n\tDS 2\nC2:\tDS 300H\n\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        exprs = _expressions(_asm(d, "M", src))
    com, a = ADDR_COMMON_REL, ADDR_ABSOLUTE
    assert exprs == [
        [_c(com, 2), _c(a, 0x100), PLUS, _c(a, 5), PLUS, HIGH, STORE],
        [_c(a, 5), _c(com, 2), PLUS, HIGH, STORE],
        [_c(com, 2), _c(a, 5), MINUS, HIGH, STORE],
        [_c(com, 2), _c(a, 5), PLUS, STORE],
        [_c(ADDR_PROGRAM_REL, 0), _c(a, 0x300), PLUS, HIGH, STORE],
        [_c(ADDR_DATA_REL, 3), _c(a, 0x80), PLUS, LOW, STORE],
        [_c(ADDR_DATA_REL, 3), HIGH, STORE]]


def test_an_equate_is_one_value_as_in_macro80():
    """Used before and after the EQU (no phase error either way)."""
    src = ("\tCSEG\n\tMVI A,HIGH X\n\tMVI A,HIGH X\n"
           "\tCOMMON /BLK1/\nC1:\tDS 30H\nX\tEQU C1+100H\n"
           "\tCSEG\n\tMVI A,HIGH X\n\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        exprs = _expressions(_asm(d, "Q", src))
    assert exprs == [[_c(ADDR_COMMON_REL, 0x100), HIGH, STORE]] * 3


def test_linked_values():
    """C1 = 010DH (after 13 bytes of code), C2 = C1+300H."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.rel")
        with open(p, "wb") as f:
            f.write(_asm(d, "C", COMOFF))
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(p)
        assert linker.link(), linker.errors
    c1 = 0x100 + 13
    c2 = c1 + 0x300
    assert bytes(linker.output[:13]) == bytes([
        0x3E, (c1 + 0x100) >> 8, 0x3E, (c1 + 0x400) >> 8,
        0x3E, (c1 + 5) & 0xFF, 0x3E, (c2 + 0x20) >> 8,
        0x3E, (c2 + 0x20) & 0xFF, 0x3E, (c2 + 0x100) >> 8,
        (c2 - 1) & 0xFF])
