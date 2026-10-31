"""
JR/DJNZ promotion and phase errors: code across the 64K mark, jumps near the
127-byte limit, and conditional assembly labels between them.

A relocatable segment longer than 64K made a JR over the 64K mark look far
in one pass and near in the next (the target was cut to 16 bits, the
location counter was not), so pass 2 put labels one byte away from where
pass 1 had them and um80 said "Phase error".
"""

import os
import random
import tempfile

import pytest
from um80.um80 import Assembler


def assemble(source):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "t.mac")
        with open(path, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(path)
        return asm, ok


@pytest.mark.parametrize("pad", [0xFFF0, 0xFFF8, 0xFFFA, 0xFFFB, 0xFFFD,
                                 0xFFFE, 0xFFFF])
def test_jr_over_64k_mark_has_no_phase_error(pad):
    asm, ok = assemble(f"""\
\t.Z80
\tCSEG
\tDS {pad}
\tJR Z,L1
\tNOP
L1:\tNOP
\tJR L2
L2:\tRET
\tDJNZ L3
L3:\tRET
\tEND
""")
    assert ok, asm.errors
    # Short jumps stay short: 3 JR/DJNZ of 2 bytes, NOP, NOP, RET, RET.
    assert not asm.promoted_jr
    assert asm.segments['CSEG'].extent() == pad + 2 + 1 + 1 + 2 + 1 + 2 + 1


def test_far_jr_over_64k_mark_is_promoted():
    asm, ok = assemble("""\
\t.Z80
\tCSEG
\tDS 0FFFEH
\tJR Z,FAR
\tDS 200
FAR:\tRET
\tEND
""")
    assert ok, asm.errors
    assert len(asm.promoted_jr) == 1


def test_backward_jr_over_64k_mark():
    asm, ok = assemble("""\
\t.Z80
\tCSEG
\tDS 0FFF0H
BACK:\tNOP
\tDS 20
\tJR BACK
\tEND
""")
    assert ok, asm.errors
    assert not asm.promoted_jr


def test_phase_block_jr_wraps_at_64k():
    """In a .PHASE block the addresses are 16-bit: a JR wraps around."""
    asm, ok = assemble("""\
\t.Z80
\tASEG
\tORG 100H
\t.PHASE 0FFFEH
\tJR NEXT
NEXT:\tNOP
\t.DEPHASE
\tEND
""")
    assert ok, asm.errors
    assert not asm.promoted_jr


def test_real_phase_error_is_still_reported():
    asm, ok = assemble("""\
\t.Z80
\tDW LAB
\tIF2
\tDB 1
\tENDIF
LAB:\tNOP
\tEND
""")
    assert not ok
    assert any("Phase error" in str(e) for e in asm.errors)


def build_random(seed, pad):
    """Many forward JR/JP/DJNZ near the 127-byte limit, with IF labels."""
    rnd = random.Random(seed)
    lines = ["\t.Z80", "\tCSEG", f"\tDS {pad}"]
    n = 40
    for i in range(n):
        gap = rnd.choice([100, 120, 124, 125, 126, 127, 128, 129, 130, 140])
        op = rnd.choice(["JR", "JR Z,", "JR NC,", "DJNZ", "JP"])
        sep = " " if op in ("JR", "DJNZ", "JP") else ""
        lines.append(f"\t{op}{sep}T{i}")
        if rnd.random() < 0.5:
            lines.append(f"\tIF 1\n@IF{i}:\tNOP\n\tELSE\n@EL{i}:\tNOP\n\tENDIF")
            lines.append(f"\tJR @IF{i}")
        lines.append(f"\tDS {gap}")
        lines.append(f"T{i}:\tNOP")
    lines.append("\tEND")
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("pad", [0, 0xFF00, 0xFF80, 0xFFC0, 0xFFF0, 0xFFFF])
@pytest.mark.parametrize("seed", range(6))
def test_generated_jumps_near_the_limit(seed, pad):
    asm, ok = assemble(build_random(seed, pad))
    assert ok, asm.errors
    assert not [e for e in asm.errors if "Phase" in str(e)]
