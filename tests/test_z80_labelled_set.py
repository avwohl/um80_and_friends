"""A labelled Z80 SET instruction is the instruction, not the SET directive.

`X1: SET 7,(IX+1)' and `X3: SET 1,A' were "SET requires one operand" in
.Z80 mode: any SET with a label was taken for the directive.  The
directive has one operand, the instruction two; MACRO-80 3.44 assembles
DD CB 01 FE and CB CF.  (M80 fails on the colon-less `X4 SET 2,B'; with two
operands it can only be the instruction, and um80 assembles it as that.)
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler


def _asm(source):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
        rel = asm.output.get_bytes() if ok else None
    return ok, asm, rel


def _bytes(rel):
    reader = RELReader(rel)
    out = []
    while True:
        item = reader.read_item()
        if item is None or item[0] in ('END_PROGRAM', 'END_FILE'):
            return out
        if item[0] == 'ABSOLUTE_BYTE':
            out.append(item[1])


def test_labelled_set_instruction():
    ok, asm, rel = _asm(".Z80\n\tASEG\n\tORG 100H\nX1:\tSET 7,(IX+1)\n"
                        "X3:\tSET 1,A\nX4\tSET 2,B\n\tJP X3\n\tEND\n")
    assert ok, [e.message for e in asm.errors]
    assert _bytes(rel) == [0xDD, 0xCB, 0x01, 0xFE, 0xCB, 0xCF, 0xCB, 0xD0,
                           0xC3, 0x04, 0x01]
    assert asm.symbols['X4'].value == 0x106


def test_set_directive_still_works_in_z80_mode():
    ok, asm, rel = _asm(".Z80\n\tASEG\n\tORG 100H\nV\tSET 5\nV\tSET V+1\n"
                        "\tDB V\n\tEND\n")
    assert ok, [e.message for e in asm.errors]
    assert _bytes(rel) == [6]
