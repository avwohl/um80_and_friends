"""ul80: a byte loaded over a word the linker still had to finish.

LINK-80 relocates a word as it loads it, and fills the chain of special
item 12 when it reads the item, so a byte loaded there afterwards - an ORG
back, a COMMON block declared again, another module loading the same COMMON
bytes - simply replaces that byte of the finished word.  ul80 relocated
after loading everything and kept the relocation of a word something had
been loaded over, so it added the segment base to whatever bytes replaced
it: `COMMON /C/' / `C1: DW C1' / `DB 7' / `COMMON /C/' / `DB 9,9' linked to
0C 0A 07 instead of 09 09 07 (MACRO-80 starts every COMMON statement at the
beginning of its block, and so does um80 now).

Items 8 and 9 (external plus or minus a constant) and link-time
expressions are another matter: LINK-80 applies them after everything is
loaded, to whatever is there then, and an external's chain is filled once
both the module and the one defining the symbol are loaded.  Every
expected value here is what the genuine M80 and L80 3.44 give (under
cpmemu), for M80's objects and for um80's.
"""

import os
import tempfile

from um80.relformat import ADDR_PROGRAM_REL, RELWriter
from um80.ul80 import Linker
from um80.um80 import Assembler

# M80 3.44's object for
#   \tcseg / \tlxi h,c2 / \tcommon /c/ / \tdw c2 / \tcommon /d/ / \tdb 1 /
#   c2:\tdb 2 / \tcommon /c/ / \tdw c2 / \tend
# The word at C+0 is loaded twice, each time D-relative 1.
M80_COMMON_TWICE = bytes.fromhex(
    "84934c228040050e2804005125000013503009680000860944e020104a1c"
    "bc00020944e02012f00000080a094397800041289c04027000009e")


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


def _linker(d, *sources):
    linker = Linker()
    linker.code_base = 0x100
    for i, src in enumerate(sources):
        if isinstance(src, bytes):
            p = os.path.join(d, f"M{i}.rel")
            with open(p, "wb") as f:
                f.write(src)
        else:
            p = _asm(d, f"M{i}", src)
        linker.load_rel(p)
    return linker


def _image(*sources, n):
    """The first `n' bytes of the image from 0100H."""
    with tempfile.TemporaryDirectory() as d:
        linker = _linker(d, *sources)
        assert linker.link(), linker.errors
        off = 0x100 - linker.output_base
        return bytes(linker.output[off:off + n])


def test_common_declared_again_over_a_relocatable_word():
    """The verifier's case: um80 now starts the second COMMON /C/ at the
    start of the block, as M80 does, and the 9,9 replace C1's word."""
    assert _image("\tcseg\n\tlxi h,c1\n\tcommon /c/\nc1:\tdw c1\n\tdb 7\n"
                  "\tcommon /c/\n\tdb 9,9\n\tend\n", n=6) \
        == bytes([0x21, 0x03, 0x01, 0x09, 0x09, 0x07])
    # The word loaded again as the same relocatable value: relocated once.
    assert _image("\tcseg\n\tlxi h,c1\n\tcommon /c/\nc1:\tdw c1\n"
                  "\tcommon /c/\n\tdw c1\n\tend\n", n=5) \
        == bytes([0x21, 0x03, 0x01, 0x03, 0x01])


def test_m80s_object_with_a_common_word_loaded_twice():
    """ul80 gave 0B 02 for the D-relative word at C+0 (the base of D added
    twice); L80 gives 06 01."""
    assert _image(M80_COMMON_TWICE, n=7) \
        == bytes([0x21, 0x06, 0x01, 0x06, 0x01, 0x01, 0x02])


def test_org_back_over_a_relocatable_word():
    """In one segment: the bytes loaded later are the ones in the image,
    and a byte of the word nothing replaced keeps its relocated value."""
    src = "\tcseg\n\tnop\nx:\tdw x\n\torg {}\n\t{}\n\tend\n"
    cases = {
        (1, "db 5,6"): [0, 5, 6],
        (1, "dw x"): [0, 1, 1],
        (1, "db 5"): [0, 5, 1],
        (2, "db 5"): [0, 1, 5],
        (2, "dw x"): [0, 1, 1, 1],
    }
    for (org, stmt), want in cases.items():
        assert _image(src.format(org, stmt), n=len(want)) == bytes(want), \
            (org, stmt)
    # In DSEG too.
    assert _image("\tcseg\n\tnop\n\tdseg\ny:\tdw y\n\tcseg\n\tdw y\n"
                  "\tdseg\n\torg 0\n\tdb 7\n\tend\n", n=5) \
        == bytes([0x00, 0x03, 0x01, 0x07, 0x01])


def test_another_module_loading_the_same_common_bytes():
    """The later module's bytes replace the earlier one's relocated word,
    or one byte of it."""
    first = "\tcseg\n\tlxi h,c1\n\tcommon /c/\nc1:\tdw c1\n\tdb 7\n\tend\n"
    second = "\tcseg\n\tnop\n\tcommon /c/\n{}\n\tend\n"
    cases = {
        "\tdb 1,2": [1, 2, 7],
        "\tdb 1": [1, 1, 7],
        "\tds 1\n\tdb 9": [4, 9, 7],
        "c2:\tdw c2": [4, 1, 7],
        "c2:\tds 1\n\tdw c2": [4, 4, 1],
        "\tds 3": [4, 1, 7],
    }
    for stmt, want in cases.items():
        image = _image(first, second.format(stmt), n=7)
        assert image == bytes([0x21, 0x04, 0x01, 0x00] + want), stmt


def test_an_externals_chain_is_filled_when_linkers_fills_it():
    """EX is filled into M1's COMMON word at the end of M1 when M0 defines
    it, and M2's bytes load after that; defined by the module that loads
    over the word, it is filled after that module's bytes.  The constant
    of EX+3 is added last, to whatever is there."""
    user = "\textrn ex\n\tcseg\n\tlxi h,c1\n\tcommon /c/\nc1:\tdw {}\n" \
           "\tdb 7\n\tend\n"
    over = "\tcseg\n\tnop\n\tcommon /c/\n\tdb 8,9\n\tend\n"
    define = "\tpublic ex\n\tcseg\nex:\tnop\n\tend\n"
    assert _image(define, user.format("ex"), over, n=8) \
        == bytes([0x00, 0x21, 0x05, 0x01, 0x00, 0x08, 0x09, 0x07])
    assert _image(define, user.format("ex+3"), over, n=8) \
        == bytes([0x00, 0x21, 0x05, 0x01, 0x00, 0x0B, 0x09, 0x07])
    define_over = "\tpublic ex\n\tcseg\nex:\tnop\n\tcommon /c/\n" \
                  "\tdb 8,9\n\tend\n"
    assert _image(user.format("ex"), define_over, n=7) \
        == bytes([0x21, 0x04, 0x01, 0x00, 0x03, 0x01, 0x07])


def test_a_link_time_expression_is_stored_last():
    """L80 stores HIGH(C1) at the end of the link, over the byte M1 loaded
    there, and so does ul80 (unchanged)."""
    assert _image("\tcseg\n\tlxi h,c1\n\tcommon /c/\nc1:\tdb 1\n"
                  "\tdb high c1\n\tdb 7\n\tend\n",
                  "\tcseg\n\tnop\n\tcommon /c/\n\tdb 8,9\n\tend\n", n=7) \
        == bytes([0x21, 0x04, 0x01, 0x00, 0x08, 0x01, 0x07])


def _item12(body):
    """A hand-made module of 6 CSEG bytes."""
    w = RELWriter()
    w.write_program_name("P")
    w.write_define_program_size(6)
    body(w)
    w.write_end_program()
    w.write_end_file()
    return w.get_bytes()


def test_item_12_chain_filled_when_the_item_is_read():
    """A word of the chain loaded over after item 12 keeps the later bytes
    (L80: 00 05 01 and 00 07 07 09 01)."""
    def one(w):
        for _ in range(4):
            w.write_absolute_byte(0)
        w.write_chain_address(ADDR_PROGRAM_REL, 1)   # 0104H into 0101H
        w.write_set_location(ADDR_PROGRAM_REL, 1)
        w.write_absolute_byte(5)
        w.write_set_location(ADDR_PROGRAM_REL, 6)

    def two(w):
        for _ in range(3):
            w.write_absolute_byte(0)
        w.write_program_relative(1)                  # link: the word at 1
        w.write_chain_address(ADDR_PROGRAM_REL, 3)   # 0105H into 3 and 1
        w.write_set_location(ADDR_PROGRAM_REL, 1)
        for b in (7, 7, 9):
            w.write_absolute_byte(b)
        w.write_set_location(ADDR_PROGRAM_REL, 6)

    assert _image(_item12(one), n=4) == bytes([0, 5, 1, 0])
    assert _image(_item12(two), n=5) == bytes([0, 7, 7, 9, 1])


def test_prl_bitmap_leaves_out_a_byte_loaded_over():
    """The high byte of a relocated word is marked only while it is still
    that byte."""
    def bits(source):
        with tempfile.TemporaryDirectory() as d:
            linker = _linker(d, source)
            linker.page_zero_relative = True
            assert linker.link(), linker.errors
            p = os.path.join(d, "x.prl")
            linker.save_prl(p)
            with open(p, "rb") as f:
                data = f.read()
            length = data[1] | (data[2] << 8)
            bitmap = data[256 + length:256 + length + (length + 7) // 8]
            return [i for i in range(length)
                    if bitmap[i // 8] & (0x80 >> (i % 8))]
    src = "\tcseg\n\tnop\nx:\tdw x\n\tdb 0\n\torg {}\n\tdb 5\n\tend\n"
    assert bits(src.format(2)) == []       # the high byte replaced
    assert bits(src.format(1)) == [2]      # only the low byte replaced
