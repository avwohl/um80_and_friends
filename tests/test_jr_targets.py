"""JR/DJNZ to a target whose distance is not known now is an error.

`JR EXT' assembled to 18 FE (a jump to itself) with the external dropped
from the .REL, or, far from the start of the segment, was promoted to
`JP 0000H' - absolute, still without the external.  `JR DLAB' from CSEG
used the difference of two offsets in different segments.  LINK-80 has no
PC-relative operator, so none of these can be fixed at link time; MACRO-80
3.44 flags them E (external) or R (checked under cpmemu).
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


HEAD = ".Z80\n\tEXTRN EXA\n\tCSEG\nCLAB:\tNOP\n"
TAIL = "\tDSEG\nDLAB:\tNOP\n\tEND\n"


@pytest.mark.parametrize("body", [
    "\tJR EXA\n",
    "\tJR EXA+3\n",
    "\tJR NZ,EXA\n",
    "\tDJNZ EXA-1\n",
    "\tJR DLAB\n",
    "\tDJNZ DLAB\n",
    "\tJR 0100H\n",
    "\tJR LOW CLAB\n",
    "\tDS 200\n\tJR EXA\n",  # far enough to have been promoted to JP 0000H
])
def test_unreachable_relative_target_is_an_error(body):
    ok, asm = _asm(HEAD + body + TAIL)
    assert not ok, "assembled silently"
    assert len(asm.errors) == 1, [e.message for e in asm.errors]


def test_relative_jump_from_absolute_code_to_a_relocatable_label():
    ok, asm = _asm(HEAD + "\tASEG\n\tORG 100H\n\tJR CLAB\n\tEND\n")
    assert not ok
    assert "a relocatable address, but this code is absolute" in \
        asm.errors[0].message


@pytest.mark.parametrize("body", [
    "\tJR CLAB\n", "\tJR $+5\n\tNOP\n\tNOP\n\tNOP\n", "\tDJNZ CLAB+1\n",
    "\tJR Z,FWD\nFWD:\tNOP\n",
])
def test_reachable_relative_target(body):
    ok, asm = _asm(HEAD + body + TAIL)
    assert ok, [e.message for e in asm.errors]


def test_absolute_code_to_an_absolute_address():
    ok, asm = _asm(".Z80\n\tASEG\n\tORG 100H\n\tJR 102H\n\tJR 100H\n\tEND\n")
    assert ok, [e.message for e in asm.errors]
