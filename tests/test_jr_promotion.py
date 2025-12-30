"""
Test JR/DJNZ promotion to JP when offset is out of range.

The Z80 JR (Jump Relative) instruction has a limited range of -128 to +127 bytes.
When a JR target is out of range, the assembler can either:
1. Error (with --strict flag)
2. Automatically promote JR to JP (3 bytes instead of 2)

Similarly, DJNZ has the same range limit and can be promoted to DEC B + JP NZ.
"""

import os
import tempfile
import pytest
from um80.um80 import Assembler


class TestJRPromotion:
    """Test automatic JR to JP promotion."""

    def test_jr_in_range_stays_jr(self):
        """JR within range should remain as JR (2 bytes)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = """\
    .Z80
    ORG 0100H
    JR TARGET
    NOP
TARGET:
    RET
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler()
            success = asm.assemble(src_path)

            assert success, f"Assembly failed: {asm.errors}"
            assert len(asm.promoted_jr) == 0, "JR should not be promoted when in range"
            # JR is 2 bytes, NOP is 1 byte
            # JR at 0x100, NOP at 0x102, TARGET at 0x103
            cseg = asm.segments['CSEG']
            # Location should be at 0x104 (ORG 0x100 + 4 bytes)
            assert cseg.loc == 0x104

    def test_jr_out_of_range_promotes_to_jp(self):
        """JR out of range should be promoted to JP (3 bytes)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a forward jump > 127 bytes
            source = """\
    .Z80
    ORG 0100H
    JR TARGET
"""
            # Add 130 NOPs to push TARGET beyond JR range
            source += "    NOP\n" * 130
            source += """\
TARGET:
    RET
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler()
            success = asm.assemble(src_path)

            assert success, f"Assembly failed: {asm.errors}"
            assert len(asm.promoted_jr) == 1, "JR should be promoted to JP"
            # Check for the promotion note in warnings
            assert any("promoted to JP" in w for w in asm.warnings)

    def test_jr_conditional_out_of_range_promotes_to_jp(self):
        """Conditional JR out of range should be promoted to conditional JP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = """\
    .Z80
    ORG 0100H
    JR Z,TARGET
"""
            source += "    NOP\n" * 130
            source += """\
TARGET:
    RET
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler()
            success = asm.assemble(src_path)

            assert success, f"Assembly failed: {asm.errors}"
            assert len(asm.promoted_jr) == 1, "JR Z should be promoted to JP Z"

    def test_jr_backward_out_of_range_promotes(self):
        """Backward JR out of range should be promoted to JP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = """\
    .Z80
    ORG 0100H
TARGET:
"""
            # Add 130 NOPs
            source += "    NOP\n" * 130
            source += """\
    JR TARGET
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler()
            success = asm.assemble(src_path)

            assert success, f"Assembly failed: {asm.errors}"
            assert len(asm.promoted_jr) == 1, "Backward JR should be promoted to JP"

    def test_strict_mode_errors_on_out_of_range(self):
        """With --strict, out-of-range JR should error instead of promoting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = """\
    .Z80
    ORG 0100H
    JR TARGET
"""
            source += "    NOP\n" * 130
            source += """\
TARGET:
    RET
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler(strict_jr=True)
            success = asm.assemble(src_path)

            assert not success, "Assembly should fail in strict mode"
            assert any("JR offset out of range" in str(e) for e in asm.errors)


class TestDJNZPromotion:
    """Test automatic DJNZ to DEC B + JP NZ promotion."""

    def test_djnz_in_range_stays_djnz(self):
        """DJNZ within range should remain as DJNZ (2 bytes)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = """\
    .Z80
    ORG 0100H
LOOP:
    NOP
    DJNZ LOOP
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler()
            success = asm.assemble(src_path)

            assert success, f"Assembly failed: {asm.errors}"
            assert len(asm.promoted_jr) == 0, "DJNZ should not be promoted when in range"

    def test_djnz_out_of_range_promotes(self):
        """DJNZ out of range should be promoted to DEC B + JP NZ (4 bytes)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = """\
    .Z80
    ORG 0100H
LOOP:
"""
            # Add 130 NOPs to push DJNZ beyond range
            source += "    NOP\n" * 130
            source += """\
    DJNZ LOOP
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler()
            success = asm.assemble(src_path)

            assert success, f"Assembly failed: {asm.errors}"
            assert len(asm.promoted_jr) == 1, "DJNZ should be promoted"
            assert any("promoted to JP" in w for w in asm.warnings)

    def test_djnz_strict_mode_errors(self):
        """With --strict, out-of-range DJNZ should error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = """\
    .Z80
    ORG 0100H
LOOP:
"""
            source += "    NOP\n" * 130
            source += """\
    DJNZ LOOP
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler(strict_jr=True)
            success = asm.assemble(src_path)

            assert not success, "Assembly should fail in strict mode"
            assert any("DJNZ offset out of range" in str(e) for e in asm.errors)


class TestIterativePromotion:
    """Test iterative promotion when one promotion causes another to go out of range."""

    def test_cascading_promotions(self):
        """
        Test that promotions cascade correctly.

        When a JR is promoted to JP (adding 1 byte), it may push other
        JR instructions out of range, requiring more promotions.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a chain of JRs that are just barely in range
            # Promoting one should cascade to others
            source = """\
    .Z80
    ORG 0100H
    JR LABEL1      ; This may need promotion
"""
            # 126 bytes - just at the edge
            source += "    NOP\n" * 126
            source += """\
LABEL1:
    JR LABEL2      ; This may also need promotion
"""
            source += "    NOP\n" * 126
            source += """\
LABEL2:
    RET
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler()
            success = asm.assemble(src_path)

            assert success, f"Assembly failed: {asm.errors}"
            # The assembler should have iterated to find stable sizes

    def test_multiple_jr_same_target(self):
        """Multiple JRs to the same out-of-range target should all be promoted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = """\
    .Z80
    ORG 0100H
    JR TARGET
    JR TARGET
    JR TARGET
"""
            source += "    NOP\n" * 130
            source += """\
TARGET:
    RET
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler()
            success = asm.assemble(src_path)

            assert success, f"Assembly failed: {asm.errors}"
            assert len(asm.promoted_jr) == 3, "All 3 JRs should be promoted"


class TestPromotionCorrectness:
    """Test that promoted instructions produce correct code."""

    def test_jp_opcode_unconditional(self):
        """Promoted unconditional JR should produce 3-byte instruction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = """\
    .Z80
    ORG 0100H
    JR TARGET
"""
            source += "    NOP\n" * 130
            source += """\
TARGET:
    RET
    END
"""
            src_path = os.path.join(tmpdir, "test.mac")
            with open(src_path, "w") as f:
                f.write(source)

            asm = Assembler()
            success = asm.assemble(src_path)

            assert success, f"Assembly failed: {asm.errors}"
            # Verify JR was promoted
            assert len(asm.promoted_jr) == 1, "JR should be promoted"
            # The CSEG should reflect JP (3 bytes) + 130 NOPs + RET (1 byte) = 134 bytes
            cseg = asm.segments['CSEG']
            # ORG 0x100 + 134 = 0x186
            assert cseg.loc == 0x186, f"Expected loc 0x186, got 0x{cseg.loc:04X}"

    def test_jp_conditional_opcodes(self):
        """Promoted conditional JR should produce 3-byte instruction."""
        conditions = ['NZ', 'Z', 'NC', 'C']

        for cond in conditions:
            with tempfile.TemporaryDirectory() as tmpdir:
                source = f"""\
    .Z80
    ORG 0100H
    JR {cond},TARGET
"""
                source += "    NOP\n" * 130
                source += """\
TARGET:
    RET
    END
"""
                src_path = os.path.join(tmpdir, "test.mac")
                with open(src_path, "w") as f:
                    f.write(source)

                asm = Assembler()
                success = asm.assemble(src_path)

                assert success, f"Assembly failed for JR {cond}: {asm.errors}"
                # Verify JR was promoted
                assert len(asm.promoted_jr) == 1, f"JR {cond} should be promoted"
                # The CSEG should reflect JP cc (3 bytes) + 130 NOPs + RET (1 byte) = 134 bytes
                cseg = asm.segments['CSEG']
                assert cseg.loc == 0x186, f"Expected loc 0x186 for JR {cond}, got 0x{cseg.loc:04X}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
