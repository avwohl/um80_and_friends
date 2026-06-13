"""`.RADIX` and conditional-assembly diagnostics, verified against real M80 3.44.

- .RADIX evaluates its operand in decimal regardless of the current radix, so
  `.RADIX 16` sets hex (and works across passes).
- An IF/IFx/COND left open at end of pass warns "Unterminated conditional".
- A second ELSE for one conditional level is an error (bytes still match M80).
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _assemble(source):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "t.mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler()
    ok = asm.assemble(p)
    return asm, ok, p, d


def _image(source):
    asm, ok, p, d = _assemble(source)
    assert ok, f"Assembly failed: {asm.errors}"
    rel = os.path.join(d, "t.rel")
    with open(rel, "wb") as f:
        f.write(asm.output.get_bytes())
    linker = Linker()
    linker.code_base = 0x0100
    linker.load_rel(rel)
    assert linker.link(), f"Link failed: {linker.errors}"
    return bytes(linker.output)


def test_radix_16_operand_is_decimal():
    out = _image("\tASEG\n\tORG 100H\n\t.RADIX 16\n\tDB 10\n\tDB 0FF\n\tEND\n")
    assert out[0:2] == bytes([0x10, 0xFF])


def test_radix_11_operand_is_decimal():
    out = _image("\t.RADIX 11\n\tASEG\n\tORG 100H\n\tDB 10\n\tEND\n")
    assert out[0:1] == bytes([0x0B])  # 10 in base 11 = 11 = 0x0B


def test_radix_resets_each_pass():
    # Forward reference forces multiple passes; .RADIX must not compound.
    out = _image("\tASEG\n\tORG 100H\n\t.RADIX 16\n\tDB FWD\nFWD\tEQU 20\n\tEND\n")
    assert out[0:1] == bytes([0x20])


def test_unterminated_conditional_warns():
    asm, ok, _, _ = _assemble("\tASEG\n\tORG 100H\n\tIF 0\n\tDB 0AAH\n\tEND\n")
    assert ok  # warning, not fatal (matches M80)
    assert any("nterminated" in w for w in asm.warnings)


def test_duplicate_else_is_error():
    asm, ok, _, _ = _assemble(
        "\tASEG\n\tORG 100H\n\tIF 1\n\tDB 011H\n\tELSE\n\tDB 022H\n"
        "\tELSE\n\tDB 033H\n\tENDIF\n\tDB 044H\n\tEND\n"
    )
    assert not ok
    assert any("Duplicate ELSE" in str(e) for e in asm.errors)


def test_single_else_still_works():
    # Regression: a normal single ELSE must not be flagged.
    out = _image(
        "\tASEG\n\tORG 100H\n\tIF 0\n\tDB 011H\n\tELSE\n\tDB 022H\n\tENDIF\n\tEND\n"
    )
    assert out[0:1] == bytes([0x22])


def test_reused_else_level_after_endif_ok():
    # Two separate conditionals each with their own ELSE must be fine.
    out = _image(
        "\tASEG\n\tORG 100H\n"
        "\tIF 1\n\tDB 1\n\tELSE\n\tDB 2\n\tENDIF\n"
        "\tIF 0\n\tDB 3\n\tELSE\n\tDB 4\n\tENDIF\n\tEND\n"
    )
    assert out[0:2] == bytes([0x01, 0x04])
