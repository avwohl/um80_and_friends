"""The assembler starts every pass in the default 8080 mode.

z80_mode was set in __init__ and never reset between passes, so whatever
mode pass 1 ended in became pass 2's starting mode.  A `.Z80` anywhere in
a file therefore assembled the lines ABOVE it as Z80 on the second pass:

    ASEG
    ORG 100H
    JP 200H         ; 8080 F2 = jump if positive
    .Z80            ; ...this line, further down, changed the one above
    END

gave C3 instead of F2 -- a different instruction, silently.  With `CP n`
it also changes the length (two-byte FE against the three-byte 8080 F4,
call if plus), which moves every label after it.  Exit 0, no diagnostic.

The radix is reset each pass for exactly this reason, with the comment "a
.RADIX re-applies"; the same is true of .Z80/.8080.
"""

import os
import tempfile

import pytest

from um80.um80 import Assembler
from um80.ul80 import Linker


def image(source, length=4):
    """Link `source` at 100H and return the first bytes of the image."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
        assert ok, asm.errors
        rel = os.path.join(d, "t.rel")
        with open(rel, "wb") as f:
            f.write(asm.output.get_bytes())
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(rel)
        linker.link()
        com = os.path.join(d, "t.com")
        linker.save_com(com)
        with open(com, "rb") as f:
            return f.read()[:length]


JP_8080 = 0xF2   # 8080 JP addr: jump if positive
JP_Z80 = 0xC3    # Z80 JP addr: unconditional


class TestDirectiveIsPositional:
    def test_no_directive_is_8080(self):
        assert image("\tCSEG\n\tJP 200H\n\tEND\n")[0] == JP_8080

    def test_directive_after_the_instruction_does_not_reach_back(self):
        """The reported case: a .Z80 below the JP used to rewrite it."""
        assert image("\tCSEG\n\tJP 200H\n\t.Z80\n\tEND\n")[0] == JP_8080

    def test_directive_before_the_instruction_applies(self):
        assert image("\t.Z80\n\tCSEG\n\tJP 200H\n\tEND\n")[0] == JP_Z80

    def test_mode_switches_back(self):
        assert image("\t.Z80\n\tCSEG\n\t.8080\n\tJP 200H\n\tEND\n")[0] == JP_8080

    def test_two_instructions_either_side_of_the_directive(self):
        img = image("\tCSEG\n\tJP 200H\n\t.Z80\n\tJP 200H\n\tEND\n", length=8)
        assert img[0] == JP_8080
        assert img[3] == JP_Z80


class TestLengthChangesAreStable:
    """CP n is 3 bytes in 8080 (F4, call if plus) and 2 in Z80 (FE)."""

    def test_label_after_a_cp_keeps_its_address(self):
        src = ("\tCSEG\n\tCP 5\n\tNOP\n%s\tEND\n")
        without = image(src % "", length=6)
        with_late_z80 = image(src % "\t.Z80\n", length=6)
        assert without == with_late_z80
        assert without[0] == 0xF4

    def test_a_leading_directive_still_shortens_it(self):
        assert image("\t.Z80\n\tCSEG\n\tCP 5\n\tNOP\n\tEND\n",
                     length=3) == bytes([0xFE, 0x05, 0x00])


class TestRepeatedAssemblyIsStable:
    """One Assembler instance is used for both passes; a second run of a
    fresh instance must agree with the first."""

    def test_same_source_twice(self):
        src = "\tCSEG\n\tJP 200H\n\t.Z80\n\tEND\n"
        assert image(src) == image(src)
