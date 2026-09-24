"""ul80 segment placement: absolute ASEG, mixed CSEG+ASEG, COMMON-only.

Verified against real LINK-80 3.44:
- ASEG (absolute) bytes are placed at their absolute address, not rebased to
  the relocatable load address.
- A module mixing CSEG and ASEG keeps the CSEG relocatable AND emits the ASEG
  block at its absolute ORG (previously the CSEG was dropped).
- A module contributing only a COMMON block does not consume code space (its
  bytes are not miscounted as program code).
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _rel(tmpdir, name, source):
    p = os.path.join(tmpdir, name + ".mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), asm.errors
    rp = os.path.join(tmpdir, name + ".rel")
    with open(rp, "wb") as f:
        f.write(asm.output.get_bytes())
    return rp


def test_absolute_aseg_placed_at_org_not_code_base():
    with tempfile.TemporaryDirectory() as d:
        r = _rel(d, "ABS", "\tASEG\n\tORG 300H\n\tMVI A,7\n\tRET\n\tEND\n")
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(r)
        assert linker.link()
        base = linker.output_base
        assert base == 0x300
        assert bytes(linker.output[0x300 - base:0x300 - base + 3]) == bytes([0x3E, 0x07, 0xC9])


def test_mixed_cseg_and_aseg():
    with tempfile.TemporaryDirectory() as d:
        r = _rel(d, "MIX",
                 "\tCSEG\nST:\tMVI A,1\n\tRET\n\tASEG\n\tORG 200H\n\tJMP ST\n\tEND\n")
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(r)
        assert linker.link()
        base = linker.output_base
        # CSEG (relocatable) at code_base 0x100
        assert bytes(linker.output[0x100 - base:0x100 - base + 3]) == bytes([0x3E, 0x01, 0xC9])
        # ASEG at its absolute ORG 0x200; JMP ST resolves to START = 0x100
        assert bytes(linker.output[0x200 - base:0x200 - base + 3]) == bytes([0xC3, 0x00, 0x01])


def test_common_only_module_does_not_consume_code_space():
    with tempfile.TemporaryDirectory() as d:
        ra = _rel(d, "A", "\tNAME (MODA)\n\tCOMMON /CM/\n\tDS 4\n\tEND\n")
        rb = _rel(d, "B",
                  "\tNAME (MODB)\n\tPUBLIC ENTRY\n\tCSEG\nENTRY:\tMVI A,0AAH\n\tRET\n\tEND\n")
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(ra)  # COMMON-only module loaded first
        linker.load_rel(rb)
        assert linker.link()
        # The code region holds only B's code; the COMMON bytes are not in it.
        assert bytes(linker.output) == bytes([0x3E, 0xAA, 0xC9])
        midx, val, seg, _ = linker.globals["ENTRY"]
        assert linker.relocate_value(linker.modules[midx], val, seg) == 0x100


def test_aseg_org_back_below_the_first_byte():
    """`ORG 200H / DB 1 / ORG 180H / DB 4': ul80 took the first address
    loaded for the start of the module's ASEG and dropped the 4 (its hex
    held only 0200H).  LINK-80 has 04 at 0180H."""
    with tempfile.TemporaryDirectory() as d:
        r = _rel(d, "OB", "\tASEG\n\tORG 200H\n\tDB 1\n\tORG 180H\n\tDB 4\n"
                          "\tEND\n")
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(r)
        assert linker.link()
        base = linker.output_base
        assert base == 0x180
        assert linker.output[0x180 - base] == 4
        assert linker.output[0x200 - base] == 1
        com = os.path.join(d, "ob.com")
        linker.save_com(com)
        with open(com, "rb") as f:
            image = f.read()
    # The .COM starts at the origin, as LINK-80's (384 bytes, the same);
    # it started at the first byte, which CP/M then loaded at 0100H.
    assert len(image) == 384
    assert image[0x80] == 4 and image[0x100] == 1
    assert image.count(0) == len(image) - 2


def test_com_below_the_origin_starts_at_the_lowest_byte():
    """Absolute code under the origin stays in the .COM, from its lowest
    byte, as in LINK-80 (M80's `ASEG / ORG 0 / JMP GO' linked /P:100)."""
    with tempfile.TemporaryDirectory() as d:
        r = _rel(d, "LO", "\tASEG\n\tORG 0\n\tJMP GO\n\tCSEG\nGO:\tRET\n"
                          "\tEND\n")
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(r)
        assert linker.link()
        com = os.path.join(d, "lo.com")
        linker.save_com(com)
        with open(com, "rb") as f:
            image = f.read()
    assert image[:3] == b"\xc3\x00\x01" and image[0x100] == 0xC9
