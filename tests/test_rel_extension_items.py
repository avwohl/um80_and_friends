"""HIGH/LOW of a relocatable or external value is computed by the linker.

`LOW(expr)' and `HIGH(expr)' of an address in a relocatable segment, or of an
external, evaluated to the byte of the module-relative offset and went out
as an absolute byte, so no relocation reached the linker.  MP/M II's
MPMLDR/LDRLWR.ASM, a CSEG module GENSYS links after GENSYS.PLM, does

        mvi     a,low(bitmap+128)

bitmap+128 was at 256CH in the linked GENSYS.COM, but the instruction came
out MVI A,0A6H - the low byte of 01A6H, its offset in the module.  GENSYS
read its relocation bitmap at the wrong time and generated a wrong MPM.SYS.
It only worked by accident in a one-module .COM whose CSEG starts at 0100H,
where LOW happens to agree.

MACRO-80 3.44 and LINK-80 3.44 pass such a value to the linker as
"extension link items" (special link item 4): a postfix expression ending in
a store operator, written immediately before the placeholder byte(s) of the
field it fills - see relformat.py.  The same goes for any relocatable or
external value in a one-byte field (`MVI A,BUF', `DB LAB').  An operator the
linker does not have (AND, OR, XOR, SHL, SHR, a comparison) on such a value
is an error, as it is in M80 ('R').

For MP/M's page-relocatable .PRL/.SPR the loader adds its page to every byte
the bitmap marks: HIGH of an address is marked, LOW is not (a page move
never changes a low byte), a word that is an address is marked on its high
byte, and anything that does not move by exactly 0 or 1 page is an error.
"""

import os
import subprocess
import sys
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler
from um80.ul80 import Linker, LinkerError


def _asm(tmpdir, name, source):
    p = os.path.join(tmpdir, name + ".mac")
    with open(p, "w", encoding="ascii") as f:
        f.write(source)
    asm = Assembler()
    ok = asm.assemble(p)
    return ok, asm


def _rel(tmpdir, name, source):
    ok, asm = _asm(tmpdir, name, source)
    assert ok, [e.format_message() for e in asm.errors]
    rp = os.path.join(tmpdir, name + ".rel")
    with open(rp, "wb") as f:
        f.write(asm.output.get_bytes())
    return rp


def _errors(tmpdir, source):
    ok, asm = _asm(tmpdir, "E", source)
    assert not ok, "expected an error, got a silent result"
    return ' '.join(e.format_message() for e in asm.errors)


# FIRST occupies 6 bytes of CSEG and 3 of DSEG, so the next module's code and
# data start at addresses that are not a multiple of 256.
FIRST = ("\tPUBLIC X\n\tCSEG\n\tDB 1,2,3,4,5\nX:\tDB 0\n"
         "\tDSEG\n\tDB 7,7,7\n\tEND\n")

SECOND = """\
\tEXTRN X
\tPUBLIC BUF,LAB
\tCSEG
\tMVI A,LOW(BUF+128)
\tMVI A,HIGH(BUF+128)
\tMVI A,LOW LAB
\tMVI A,HIGH LAB
\tDB LOW(X),HIGH(X+300H)
\tDW X
\tDW BUF
\tMVI A,LOW(X-1)
\tMVI A,BUF
\tDB LAB
LAB:\tRET
\tDSEG
\tDS 3
BUF:\tDS 256
\tEND
"""


def _link(d, origin=0x100, prl=False, first=FIRST, second=SECOND):
    linker = Linker()
    linker.code_base = origin
    linker.page_zero_relative = prl
    linker.load_rel(_rel(d, "FIRST", first))
    linker.load_rel(_rel(d, "SECOND", second))
    assert linker.link(), linker.errors
    return linker


def _addr(linker, name):
    mod_idx, value, seg, _ = linker.globals[name]
    return linker.relocate_value(linker.modules[mod_idx], value, seg)


def _image(linker, addr, n):
    off = addr - linker.output_base
    return bytes(linker.output[off:off + n])


def _expected(linker):
    """SECOND's code as it must be, from where the linker put everything."""
    buf, lab, x = (_addr(linker, n) for n in ("BUF", "LAB", "X"))
    return bytes([
        0x3E, (buf + 128) & 0xFF,
        0x3E, (buf + 128) >> 8,
        0x3E, lab & 0xFF,
        0x3E, lab >> 8,
        x & 0xFF, (x + 0x300) >> 8,
        x & 0xFF, x >> 8,
        buf & 0xFF, buf >> 8,
        0x3E, (x - 1) & 0xFF,
        0x3E, buf & 0xFF,
        lab & 0xFF,
        0xC9,
    ])


def test_high_and_low_of_relocatable_and_external_in_com():
    """LOW/HIGH of CSEG, DSEG and external addresses at unaligned bases."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d)
        start = _addr(linker, "LAB") - 19
        # The point of the exercise: nothing is page aligned.
        assert start & 0xFF and _addr(linker, "BUF") & 0xFF
        assert _image(linker, start, 20) == _expected(linker)


def test_same_fields_at_another_origin():
    """Linked elsewhere the bytes follow the addresses, not the offsets."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, origin=0x3456)
        start = _addr(linker, "LAB") - 19
        assert _image(linker, start, 20) == _expected(linker)


def _save_prl(linker, d):
    path = os.path.join(d, "OUT.PRL")
    linker.save_prl(path)
    with open(path, "rb") as f:
        image = f.read()
    n = image[1] | (image[2] << 8)
    code, bitmap = image[256:256 + n], image[256 + n:]
    marked = {i for i in range(n) if bitmap[i >> 3] & (0x80 >> (i & 7))}
    return code, marked


@pytest.mark.parametrize("origin", [0x100, 0x0])  # .PRL and .SPR
def test_page_relocatable_bytes_and_bitmap(origin):
    """.PRL (100H) and .SPR (0): right bytes, HIGH marked, LOW not."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, origin=origin, prl=True)
        code, marked = _save_prl(linker, d)
        start = _addr(linker, "LAB") - 19 - origin
        assert code[start:start + 20] == _expected(linker)
        # HIGH of an address is marked; LOW never is; DW X / DW BUF are
        # marked on their high byte.
        high = {start + 3, start + 7, start + 9, start + 11, start + 13}
        low = {start + 1, start + 5, start + 8, start + 10, start + 12,
               start + 15, start + 17, start + 18}
        assert high <= marked, sorted(marked)
        assert not low & marked, sorted(low & marked)


@pytest.mark.parametrize("origin", [0x100, 0x0])
def test_bitmap_relocation_reproduces_a_higher_link(origin):
    """What MP/M does to the image equals linking it that many pages up."""
    with tempfile.TemporaryDirectory() as d:
        code, marked = _save_prl(_link(d, origin=origin, prl=True), d)
        for pages in (1, 0x25, 0x7F):
            moved = bytearray(code)
            for i in marked:
                moved[i] = (moved[i] + pages) & 0xFF
            higher = _link(d, origin=origin + pages * 0x100, prl=True)
            assert bytes(moved) == bytes(higher.output), pages


def test_cli_prl_marks_high_but_not_low():
    """Drive ul80 --prl itself, as the MP/M build does."""
    with tempfile.TemporaryDirectory() as d:
        _rel(d, "FIRST", FIRST)
        _rel(d, "SECOND", SECOND)
        out = os.path.join(d, "OUT.PRL")
        r = subprocess.run([sys.executable, "-m", "um80.ul80", "--prl", "-o",
                            out, "FIRST.rel", "SECOND.rel"],
                           cwd=d, capture_output=True, text=True, check=False)
        assert r.returncode == 0, r.stderr
        with open(out, "rb") as f:
            image = f.read()
        n = image[1] | (image[2] << 8)
        code, bitmap = image[256:256 + n], image[256 + n:]
        # SECOND starts after FIRST's 6 code bytes: MVI A,LOW(BUF+128) at 6.
        assert code[6] == 0x3E and code[8] == 0x3E
        assert not bitmap[7 >> 3] & (0x80 >> (7 & 7))   # LOW: not marked
        assert bitmap[9 >> 3] & (0x80 >> (9 & 7))       # HIGH: marked


def test_high_and_low_of_an_external_symbol():
    """External plus or minus an offset, defined absolute and relocatable."""
    src = ("\tEXTRN X,K\n\tCSEG\n"
           "\tMVI A,HIGH(X+1FFH)\n\tMVI B,LOW(X-2)\n"
           "\tMVI C,HIGH(K+1)\n\tMVI D,LOW(K-1)\n\tEND\n")
    const = "K\tEQU 12FFH\n\tPUBLIC K\n\tEND\n"
    with tempfile.TemporaryDirectory() as d:
        linker = Linker()
        linker.code_base = 0x100
        linker.page_zero_relative = True
        linker.load_rel(_rel(d, "FIRST", FIRST))
        linker.load_rel(_rel(d, "S", src))
        linker.load_rel(_rel(d, "K", const))
        assert linker.link(), linker.errors
        x = _addr(linker, "X")
        assert _image(linker, 0x106, 8) == bytes([
            0x3E, (x + 0x1FF) >> 8, 0x06, (x - 2) & 0xFF,
            0x0E, 0x13, 0x16, 0xFE])
        _, marked = _save_prl(linker, d)
        # HIGH(X+1FFH) moves with the program; the constant K does not.
        assert 7 in marked and not {9, 11, 13} & marked, sorted(marked)


def test_equate_of_high_relocatable_is_computed_where_used():
    """`BMHI EQU HIGH BUF' stands for the expression, not a constant."""
    src = ("\tCSEG\nBMHI\tEQU HIGH(BUF+1)\nBMLO\tSET LOW BUF\n"
           "\tMVI A,BMHI\n\tMVI A,BMLO\n\tDSEG\n\tDS 300\nBUF:\tDS 1\n\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, second=src)
        buf = linker.modules[1].data_base + 300
        assert _image(linker, 0x106, 4) == bytes([0x3E, (buf + 1) >> 8,
                                                  0x3E, buf & 0xFF])


def test_z80_immediates_and_displacements():
    """Z80 immediates and (IX+d)/(IY+d) displacements are byte fields too."""
    src = ("\t.Z80\n\tCSEG\n\tLD A,HIGH BUF\n\tCP LOW BUF\n"
           "\tLD (IX+5),HIGH BUF\n\tLD B,(IY+LOW BUF)\n"
           "\tDSEG\n\tDS 300\nBUF:\tDS 1\n\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, second=src)
        buf = linker.modules[1].data_base + 300
        hi, lo = buf >> 8, buf & 0xFF
        assert _image(linker, 0x106, 11) == bytes([
            0x3E, hi, 0xFE, lo, 0xDD, 0x36, 0x05, hi, 0xFD, 0x46, lo])


def test_absolute_code_is_unchanged():
    """ASEG: HIGH/LOW of a label is a constant; no item 4 is written."""
    src = ("\tASEG\n\tORG 1234H\nHERE:\tMVI A,HIGH HERE\n\tMVI A,LOW HERE\n"
           "\tDB HIGH(HERE+100H),HERE\n\tMVI A,HIGH 5678H\n\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        with open(_rel(d, "A", src), "rb") as f:
            items = RELReader(f.read()).read_all()
        assert not [i for i in items if i[0].startswith("EXT")], items
        body = [i[1] for i in items if i[0] == "ABSOLUTE_BYTE"]
        assert body == [0x3E, 0x12, 0x3E, 0x34, 0x13, 0x34, 0x3E, 0x56]


@pytest.mark.parametrize("operand, op", [
    ("MVI A,BUF AND 0FFH", "AND"),
    ("MVI A,BUF SHR 8", "SHR"),
    ("DB BUF OR 1", "OR"),
    ("DW BUF SHR 8", "SHR"),
    ("LXI H,(BUF+255) AND 0FF00H", "AND"),
    ("CPI X XOR 1", "XOR"),
])
def test_operator_the_linker_lacks_is_an_error(operand, op):
    """M80 flags these 'R'; assembling the offset-based value is wrong."""
    with tempfile.TemporaryDirectory() as d:
        msg = _errors(d, f"\tEXTRN X\n\tCSEG\n\t{operand}\n"
                         f"\tDSEG\nBUF:\tDS 1\n\tEND\n")
        assert op in msg, msg


def test_public_symbol_with_link_time_value_is_an_error():
    """A .REL public carries an address or a constant, not an expression."""
    with tempfile.TemporaryDirectory() as d:
        msg = _errors(d, "\tPUBLIC P\n\tCSEG\nP\tEQU HIGH BUF\nBUF:\tRET\n\tEND\n")
        assert "PUBLIC P" in msg, msg


@pytest.mark.parametrize("operand, want", [
    # moves by two pages
    ("MVI A,HIGH(BUF)+HIGH(LAB)",
     lambda buf, lab: [0x3E, ((buf >> 8) + (lab >> 8)) & 0xFF]),
    # moves down a page
    ("DW 200H-BUF", lambda buf, lab: [(0x200 - buf) & 0xFF,
                                      ((0x200 - buf) >> 8) & 0xFF]),
    # moves by two pages
    ("DW BUF*2", lambda buf, lab: [(buf * 2) & 0xFF, (buf * 2) >> 8 & 0xFF]),
])
def test_page_relocation_that_a_bitmap_cannot_express(operand, want):
    """Right in a .COM; refused for .PRL/.SPR rather than mis-relocated."""
    src = f"\tCSEG\nLAB:\t{operand}\n\tDSEG\nBUF:\tDS 1\n\tEND\n"
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, second=src)           # right as a .COM ...
        second = linker.modules[1]
        expect = bytes(want(second.data_base, second.code_base))
        assert _image(linker, second.code_base, len(expect)) == expect
        prl = _link(d, prl=True, second=src)    # ... but not relocatable
        with pytest.raises(LinkerError, match="page relocation bitmap"):
            prl.save_prl(os.path.join(d, "X.PRL"))
