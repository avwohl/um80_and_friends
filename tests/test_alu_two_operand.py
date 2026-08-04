"""SUB/AND/XOR/OR/CP accept the `A,` spelling instead of dropping it.

ADD, ADC and SBC each collapse a leading `A,` to the one-operand form.
SUB, AND, XOR, OR and CP had no such branch, so ops[0] -- the "A" -- was
taken as the operand and the real one was discarded:

    CP A,5      assembled as CP A     (BF, always sets Z)
    SUB A,5     assembled as SUB A    (97, always zero)
    AND A,0FH   assembled as AND A    (A7)

Exit 0, no diagnostic, and in CP's case a comparison that always compares
equal.  `CP A,n` is ordinary Zilog syntax, so this is a spelling people
write.  The two-operand guard added for `ADD A,B,C` only rejected three
or more, which is why it did not catch this.

A destination that is not the accumulator is now an error rather than a
silent drop, for these five and for ADD/ADC/SBC alike (`ADD B,C` used to
assemble as `ADD B`).
"""

import os
import tempfile

import pytest

from um80.um80 import Assembler
from um80.ul80 import Linker


def assemble(source):
    """Assemble `source`; returns (ok, error messages).

    Assembler.errors holds AssemblerError objects, unlike Linker.errors
    which holds strings, so render them here.
    """
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
        return ok, [str(e) for e in asm.errors]


ACCUMULATOR_FORMS = [
    ("CP A,5", "CP 5"),
    ("SUB A,5", "SUB 5"),
    ("AND A,0FH", "AND 0FH"),
    ("XOR A,5", "XOR 5"),
    ("OR A,5", "OR 5"),
    ("CP A,B", "CP B"),
    ("SUB A,B", "SUB B"),
    ("AND A,C", "AND C"),
    ("XOR A,C", "XOR C"),
    ("OR A,(HL)", "OR (HL)"),
    ("CP A,(HL)", "CP (HL)"),
    ("CP A,(IX+3)", "CP (IX+3)"),
    ("SUB A,(IY+1)", "SUB (IY+1)"),
]


def emitted(source_line, length=4):
    """The bytes one instruction assembles to.

    The assembler streams into the REL object rather than filling a
    segment buffer, so link it and read the image back.
    """
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write("\t.Z80\n\tCSEG\n\t%s\n\tEND\n" % source_line)
        asm = Assembler()
        ok = asm.assemble(p)
        assert ok, "%s: %r" % (source_line, asm.errors)
        assert not asm.errors, "%s: %r" % (source_line, asm.errors)
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
            return f.read()[:length].rstrip(b"\x00") or b"\x00"


class TestAccumulatorSpelling:
    @pytest.mark.parametrize("two_operand,one_operand", ACCUMULATOR_FORMS)
    def test_matches_the_one_operand_form(self, two_operand, one_operand):
        assert emitted(two_operand) == emitted(one_operand)

    def test_cp_a_n_is_not_cp_a(self):
        """The exact reported case: FE 05, not BF."""
        assert emitted("CP A,5") == bytes([0xFE, 0x05])
        assert emitted("CP A") == bytes([0xBF])

    def test_sub_and_and_keep_their_immediate(self):
        assert emitted("SUB A,5") == bytes([0xD6, 0x05])
        assert emitted("AND A,0FH") == bytes([0xE6, 0x0F])

    def test_case_of_the_operand_is_preserved(self):
        """As for ADD: 'a'-'A' must not become 'A'-'A'."""
        assert emitted("CP A,'a'-'A'") == bytes([0xFE, 0x20])


class TestNonAccumulatorDestinationIsAnError:
    @pytest.mark.parametrize("line", [
        "SUB B,C", "AND B,C", "XOR B,C", "OR B,C", "CP B,5", "CP B,ZZZ",
    ])
    def test_single_operand_alu(self, line):
        ok, errors = assemble("\t.Z80\n\tCSEG\n\t%s\n\tEND\n" % line)
        assert errors, line
        assert "not the accumulator" in errors[0], errors

    @pytest.mark.parametrize("line", ["ADD B,C", "ADC B,C", "SBC B,C"])
    def test_two_operand_alu(self, line):
        """These fell through to `ADD B` and dropped the C the same way."""
        ok, errors = assemble("\t.Z80\n\tCSEG\n\t%s\n\tEND\n" % line)
        assert errors, line
        assert "Invalid operands" in errors[0], errors

    @pytest.mark.parametrize("line", ["AND B,C,D", "CP A,B,C"])
    def test_three_operands_still_rejected(self, line):
        ok, errors = assemble("\t.Z80\n\tCSEG\n\t%s\n\tEND\n" % line)
        assert errors, line


class TestExistingFormsUnaffected:
    @pytest.mark.parametrize("line,want", [
        ("ADD A,5", [0xC6, 0x05]),
        ("ADC A,5", [0xCE, 0x05]),
        ("SBC A,5", [0xDE, 0x05]),
        ("ADD HL,BC", [0x09]),
        ("ADD HL,SP", [0x39]),
        ("ADC HL,BC", [0xED, 0x4A]),
        ("SBC HL,BC", [0xED, 0x42]),
        ("CP 5", [0xFE, 0x05]),
        ("SUB B", [0x90]),
        ("OR (HL)", [0xB6]),
    ])
    def test_byte_for_byte(self, line, want):
        assert emitted(line) == bytes(want)
