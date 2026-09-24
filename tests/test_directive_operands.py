"""A directive that needs a number now refuses one only the linker knows.

ORG, DS, IF/IFE/COND, REPT, RST, IM, BIT, END, .RADIX and the macro %
operator use their operand while assembling.  HIGH/LOW of a relocatable
value, any other link-time expression, an external, or AND/OR/... of a
relocatable value has no such value: the one um80 has is computed from
segment offsets, and it was used silently - `DS 100H-LOW($)' aligned to
the start of the segment, not to a page, and `X EQU LOW(LAB+5)' / `DS X'
reserved the low byte of an offset.  0.3.48 rejected `IF 5-EXT' and
`REPT EXT+EXT' (as "cannot subtract an external symbol"); the branch that
made those link-time expressions let them through here as 0.  MACRO-80 3.44
flags every one of these 'R' (checked under cpmemu).  A relocatable address
used as a number is still its offset, as before, and ORG within the current
segment (`ORG $+10') still moves the location counter.
"""

import os
import tempfile

import pytest

from um80.um80 import Assembler


def _asm(source):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
    return ok, asm


HEAD = "\tEXTRN EXA\n\tCSEG\nLAB:\tNOP\nLAB2:\tNOP\n"
TAIL = "\tDSEG\nDL:\tDS 2\n\tEND\n"


@pytest.mark.parametrize("body", [
    "\tDS 100H-LOW($)\n",
    "\tIF LOW(LAB+1) EQ 1\n\tDB 22H\n\tENDIF\n",
    "\tDS HIGH(LAB+300H)\n",
    "X\tEQU LOW(LAB+5)\n\tDS X\n",
    "\tIF 5-EXA\n\tDB 11H\n\tENDIF\n",
    "\tIFE EXA\n\tENDIF\n",
    "\tCOND LOW LAB\n\tENDC\n",
    "\tREPT EXA+EXA\n\tDB 14H\n\tENDM\n",
    "\tDS 2*(EXA-5) AND 0\n",
    "\tRST EXA\n",
    "\tIF $ GT 1000H\n\tENDIF\n",
    "\tIF ($ AND 0FFH) EQ 0\n\tENDIF\n",
    "\tORG HIGH LAB\n",
    "\tORG DL\n",
    "\tDS -LAB2\n",
    "M\tMACRO\n\tDB %LOW(LAB)\n\tENDM\n\tM\n",
])
def test_link_time_operand_of_a_directive_is_an_error(body):
    ok, asm = _asm(HEAD + body + TAIL)
    assert not ok, "assembled silently"
    assert len(asm.errors) == 1, [e.message for e in asm.errors]


def test_z80_operands_that_need_a_number():
    ok, asm = _asm(".Z80\n\tEXTRN EXA\n\tCSEG\nLAB:\tNOP\n\tIM LOW LAB\n"
                   "\tBIT EXA,A\n\tEND\n")
    assert not ok
    assert len(asm.errors) == 2, [e.message for e in asm.errors]


@pytest.mark.parametrize("body", [
    "\tORG $+10\n",
    "\tIF LAB2-LAB\n\tDB 5\n\tENDIF\n",
    "\tIF LAB2 GT LAB\n\tDB 7\n\tENDIF\n",
    "\tIF LAB2\n\tDB 2\n\tENDIF\n",
    "\tDS LAB2\n",
    "\tREPT LAB2-LAB\n\tNOP\n\tENDM\n",
])
def test_what_the_assembler_knows_is_still_accepted(body):
    ok, asm = _asm(HEAD + body + TAIL)
    assert ok, [e.message for e in asm.errors]


def test_absolute_code_is_unaffected():
    ok, asm = _asm("\tASEG\n\tORG 103H\nLAB:\tNOP\n\tDS 100H-LOW($)\n"
                   "\tIF LOW(LAB+1) EQ 4\n\tDB 1\n\tENDIF\n\tEND\n")
    assert ok, [e.message for e in asm.errors]
    assert asm.segments['ASEG'].loc == 0x201
