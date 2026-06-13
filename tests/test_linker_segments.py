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
