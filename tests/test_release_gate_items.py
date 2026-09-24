"""Two gaps the 0.3.49 release gate found.

An empty COMMON block was given no size (item 5).  MACRO-80 writes the item
with size 0, and LINK-80 stops with '?Loading Error' at the SELECT_COMMON of
a block it was never given a size for, so a um80 object declaring one could
not be loaded by the genuine L80.

ul80 followed an external's chain until a link led outside the bytes the
module loaded and then stopped without a word, leaving the references after
that point unfilled.  No correct object has such a chain, but the objects
um80 0.3.48 assembled with --aseg from relocatable sources do (their code
went to CSEG while the chain heads stayed absolute), so ul80 now says so.
"""

import os
import tempfile

from um80.relformat import ADDR_PROGRAM_REL, RELReader, RELWriter
from um80.ul80 import Linker
from um80.um80 import Assembler


def _assemble(d, name, source):
    p = os.path.join(d, name + ".mac")
    with open(p, "w", encoding="ascii") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), [e.message for e in asm.errors]
    return asm.output.get_bytes()


def _common_sizes(rel):
    return [item for item in RELReader(rel).read_all()
            if item[0] == 'DEFINE_COMMON_SIZE']


def test_an_empty_common_block_gets_its_size():
    with tempfile.TemporaryDirectory() as d:
        rel = _assemble(d, "e", "\tcommon /x/\n\tcseg\n\tnop\n\tend\n")
    sizes = _common_sizes(rel)
    assert len(sizes) == 1
    (_, (_, size), name) = sizes[0]
    assert size == 0 and name.strip().upper() == 'X'


def test_a_block_with_contents_still_gets_its_size():
    with tempfile.TemporaryDirectory() as d:
        rel = _assemble(d, "f", "\tcommon /y/\n\tds 5\n\tcseg\n\tnop\n\tend\n")
    (_, (_, size), _) = _common_sizes(rel)[0]
    assert size == 5


def _module(body, size):
    w = RELWriter()
    w.write_program_name("P")
    w.write_define_program_size(size)
    body(w)
    w.write_end_program()
    w.write_end_file()
    return w.get_bytes()


def _link(*objects):
    with tempfile.TemporaryDirectory() as d:
        linker = Linker()
        linker.code_base = 0x100
        for i, data in enumerate(objects):
            p = os.path.join(d, f"M{i}.rel")
            with open(p, "wb") as f:
                f.write(data)
            linker.load_rel(p)
        ok = linker.link()
        return ok, linker


def _defines_ext(w):
    w.write_define_entry_point(ADDR_PROGRAM_REL, 0, "EXT")
    w.write_absolute_byte(0xC9)


def test_a_chain_leading_outside_the_module_is_reported():
    """A chain head past the module's 3 bytes: nothing to fill there, and
    ul80 says so instead of linking on in silence."""
    def refers(w):
        for b in (0xCD, 0, 0):
            w.write_absolute_byte(b)
        w.write_chain_external(ADDR_PROGRAM_REL, 0x40, "EXT")

    ok, linker = _link(_module(refers, 3), _module(_defines_ext, 1))
    assert ok, linker.errors
    assert any("EXT" in w and "leads outside" in w for w in linker.warnings), \
        linker.warnings


def test_a_well_formed_chain_is_not_reported():
    def refers(w):
        w.write_absolute_byte(0xCD)
        w.write_absolute_byte(0)
        w.write_absolute_byte(0)
        w.write_chain_external(ADDR_PROGRAM_REL, 1, "EXT")

    ok, linker = _link(_module(refers, 3), _module(_defines_ext, 1))
    assert ok, linker.errors
    assert not linker.warnings, linker.warnings
    off = 0x100 - linker.output_base
    # EXT is the second module's first byte, right after these three.
    assert bytes(linker.output[off:off + 3]) == bytes([0xCD, 0x03, 0x01])
