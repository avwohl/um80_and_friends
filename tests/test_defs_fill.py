"""Test DEFS/DS with an optional fill-value operand.

M80 supports `DEFS count[,fill]`. When fill is present, the assembler must emit
`count` bytes of that fill value rather than merely advancing the location
counter (which leaves zero bytes in the linked output).
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _assemble_and_link(source, code_base=0x0100):
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "test.mac")
        with open(src_path, "w") as f:
            f.write(source)

        asm = Assembler()
        assert asm.assemble(src_path), f"Assembly failed: {asm.errors}"

        rel_path = os.path.join(tmpdir, "test.rel")
        with open(rel_path, "wb") as f:
            f.write(asm.output.get_bytes())

        linker = Linker()
        linker.code_base = code_base
        linker.load_rel(rel_path)
        assert linker.link(), f"Link failed: {linker.errors}"
        return linker.output


def test_defs_with_space_fill():
    """DEFS count,' ' should emit `count` space bytes, not zero bytes."""
    source = """\
    .Z80
    ASEG
    ORG 0100H
START:
    DEFS 10,' '
    RET
    END START
"""
    output = _assemble_and_link(source)
    # 10 spaces (0x20), then RET (0xC9)
    assert output[0:10] == bytes([0x20] * 10), (
        f"Expected 10 spaces, got {output[0:10].hex()}"
    )
    assert output[10] == 0xC9


def test_defs_with_expression_count_and_fill():
    """DEFS with an expression count and a numeric fill value."""
    source = """\
    .Z80
    ASEG
    ORG 0100H
START:
    DEFS 0108H-$,0FFH
END_AREA:
    RET
    END START
"""
    output = _assemble_and_link(source)
    # 8 bytes of 0xFF, then RET (0xC9)
    assert output[0:8] == bytes([0xFF] * 8)
    assert output[8] == 0xC9


def test_defs_without_fill_still_reserves_space():
    """DEFS without a fill value should still reserve the right number of bytes."""
    source = """\
    .Z80
    ASEG
    ORG 0100H
START:
    DB 0AAH
    DEFS 4
    DB 0BBH
    END START
"""
    output = _assemble_and_link(source)
    assert output[0] == 0xAA
    assert output[5] == 0xBB
    # Total length should be 6 bytes (1 + 4 reserved + 1)
    assert len(output) == 6


def test_defs_fill_in_cseg():
    """DEFS with fill should work inside a CSEG (relocatable) module too."""
    source = """\
    .Z80
    CSEG
START:
    DEFS 4,'X'
    RET
    END START
"""
    output = _assemble_and_link(source)
    assert output[0:4] == b"XXXX"
    assert output[4] == 0xC9
