"""ul80: absolute (ASEG) code in a link with other modules.

The gap an ORG or DS leaves in a module's absolute code loads nothing, as in
LINK-80: ul80 wrote the zeros it keeps there into the image, over any code
another module had loaded at those addresses.
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _asm(d, name, source):
    p = os.path.join(d, name + ".mac")
    with open(p, "w", encoding="ascii") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), [e.message for e in asm.errors]
    rp = os.path.join(d, name + ".rel")
    with open(rp, "wb") as f:
        f.write(asm.output.get_bytes())
    return rp


def _linker(d, *sources, origin=0x100):
    linker = Linker()
    linker.code_base = origin
    for i, src in enumerate(sources):
        if isinstance(src, bytes):
            p = os.path.join(d, f"M{i}.rel")
            with open(p, "wb") as f:
                f.write(src)
        else:
            p = _asm(d, f"M{i}", src)
        linker.load_rel(p)
    return linker


def _link(d, *sources, origin=0x100):
    linker = _linker(d, *sources, origin=origin)
    assert linker.link(), linker.errors
    return linker


def _addr(linker, name):
    """The linked address of global `name'."""
    midx, value, seg, _ = linker.globals[name]
    return linker.relocate_value(linker.modules[midx], value, seg,
                                 linker.global_blocks.get(name))


def _at(linker, addr, n):
    """`n' bytes of the image at `addr'."""
    o = addr - linker.output_base
    return bytes(linker.output[o:o + n])


def _cs(k, code=2, data=1):
    """A module with `code' bytes in CSEG (CSk) and `data' in DSEG (DSk)."""
    return (f"\tCSEG\n\tPUBLIC CS{k}\nCS{k}:\tDB "
            + ",".join(str(0x10 * k + i) for i in range(code))
            + f"\n\tDSEG\n\tPUBLIC DS{k}\nDS{k}:\tDB "
            + ",".join(["0D0H"] * data) + "\n\tEND\n")


def test_a_gap_in_absolute_code_does_not_overwrite_earlier_code():
    """ASEG bytes at 0080H and 0300H in a module after a CSEG module at
    0100H: the gap between them is not loaded, and the CSEG was
    overwritten with its zeros."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, _cs(1, code=8), "\tASEG\n\tORG 80H\n\tDB 1\n"
                                           "\tORG 300H\n\tDB 2\n\tEND\n")
        assert _addr(linker, "CS1") == 0x100
        assert _at(linker, 0x100, 8) == bytes(range(16, 24))
        assert _at(linker, 0x80, 1) == b"\x01"
        assert _at(linker, 0x300, 1) == b"\x02"
