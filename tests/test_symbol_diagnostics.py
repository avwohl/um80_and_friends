"""Redefinitions and link-time errors are reported where they are, once.

- `X EQU PC0' then `X EQU PD0' (same offset, different segments) was
  accepted; so was a link-time EQU redefined as another expression.  M80
  flags both 'M'.
- An EQU whose value uses AND/OR/... on a relocatable value was reported at
  every line that used it, never at the EQU, and without its name - on
  CP/M's ASM.COM sources the error pointed at `LXI SP,ENDMOD', which has no
  AND in it.  M80 flags the EQU.  A DS fill value repeated the error once
  per byte.
- PUBLIC of a link-time EQU was reported at a line past END.
"""

import os
import tempfile

from um80.um80 import Assembler


def _asm(source):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
    return ok, asm


def test_equ_redefined_in_another_segment_is_multiply_defined():
    ok, asm = _asm("\tPUBLIC PC0,PD0\n\tCSEG\nPC0:\tNOP\nX\tEQU PC0\n"
                   "X\tEQU PD0\n\tDSEG\nPD0:\tNOP\n\tEND\n")
    assert not ok
    assert [(e.line_num, e.message) for e in asm.errors] == [
        (5, "Symbol 'X' multiply defined")]


def test_link_time_equ_redefined_as_another_expression():
    ok, asm = _asm("\tCSEG\nPC0:\tNOP\nY\tEQU HIGH(PC0+300H)\n"
                   "Y\tEQU HIGH(PD0+300H)\n\tMVI A,Y\n\tDSEG\nPD0:\tNOP\n\tEND\n")
    assert not ok
    assert [(e.line_num, e.message) for e in asm.errors] == [
        (4, "Symbol 'Y' multiply defined")]


def test_equ_redefined_with_the_same_value_is_accepted():
    ok, asm = _asm("\tCSEG\nL:\tNOP\nX\tEQU L\nX\tEQU L\nZ\tEQU 5\nZ\tEQU 5\n"
                   "\tEND\n")
    assert ok, [e.message for e in asm.errors]


def test_unlinkable_equ_is_reported_once_at_its_definition():
    ok, asm = _asm("\tCSEG\n\tLXI SP,ENDMOD\n\tDS 10\n\tJMP ENDMOD\n"
                   "ENDMOD\tEQU ($ AND 0FF00H)+100H\n\tEND\n")
    assert not ok
    assert len(asm.errors) == 1, [e.message for e in asm.errors]
    err = asm.errors[0]
    assert err.line_num == 5
    assert err.message.startswith("ENDMOD, used at line 2: AND cannot")


def test_ds_fill_error_is_reported_once():
    ok, asm = _asm("\tCSEG\nLAB:\tDS 200,LAB AND 0FFH\n\tEND\n")
    assert not ok
    assert len(asm.errors) == 1, len(asm.errors)


def test_public_link_time_equ_is_reported_at_the_public():
    ok, asm = _asm("\tcseg\n\tpublic x\nx\tequ high buf\n\tnop\n\tdseg\n"
                   "buf:\tds 1\n\tend\n")
    assert not ok
    assert [e.line_num for e in asm.errors] == [2]
    assert "defined at line 3" in asm.errors[0].message
