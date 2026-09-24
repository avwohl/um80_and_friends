"""An offset subtracted from an external symbol kept its sign.

`LXI H,PDTBL-34H' assembled to PDTBL+34H.  A `symbol + constant' reference
carries the constant beside the name, and the two branches of the
expression had to be told apart; they were swapped, so the constant on the
right of a `-' was added and the one on the left negated.

Found in MP/M II's NUCLEUS/CLI.ASM, where it made every transient program
unrunnable: the CLI primed the process's initial stack through
`PDTBL-34H', wrote it 0x68 bytes past the real table, and the dispatcher
resumed the new process at whatever happened to be there.  A source-built
system loaded a .PRL, printed its load line and then warm-booted.
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
    ok = asm.assemble(p)
    rp = os.path.join(tmpdir, name + ".rel")
    if ok:
        with open(rp, "wb") as f:
            f.write(asm.output.get_bytes())
    return ok, asm, rp


# FOO is 0x100 bytes into B's CSEG, which the linker places after A's 9 bytes.
TARGET = "\tCSEG\n\tDS 100H\nFOO:\tDB 0\n\tPUBLIC FOO\n\tEND\n"


def _link(d, prog):
    ok, asm, ra = _rel(d, "A", prog)
    assert ok, asm.errors
    _, _, rb = _rel(d, "B", TARGET)
    linker = Linker()
    linker.code_base = 0x100
    linker.load_rel(ra)
    linker.load_rel(rb)
    assert linker.link()
    return linker


def _operand(linker, i):
    return linker.output[i * 3 + 1] | (linker.output[i * 3 + 2] << 8)


def test_offset_subtracted_from_external_keeps_its_sign():
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tEXTRN FOO\n\tCSEG\n"
                          "\tLXI H,FOO-34H\n\tLXI D,FOO+10H\n\tLXI B,FOO\n\tEND\n")
        foo = 0x100 + 9 + 0x100
        assert _operand(linker, 2) == foo, hex(_operand(linker, 2))
        assert _operand(linker, 1) == foo + 0x10, hex(_operand(linker, 1))
        assert _operand(linker, 0) == foo - 0x34, hex(_operand(linker, 0))


def test_offset_added_on_the_left_is_not_negated():
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tEXTRN FOO\n\tCSEG\n\tLXI H,10H+FOO\n\tEND\n")
        foo = 0x100 + 3 + 0x100
        assert _operand(linker, 0) == foo + 0x10, hex(_operand(linker, 0))


def test_subtracting_an_external_is_computed_by_the_linker():
    """n-SYM is not `symbol + constant'; MACRO-80 passes it to the linker as
    an expression (extension link items), and so does um80 now."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tEXTRN FOO\n\tCSEG\n\tLXI H,200H-FOO\n\tEND\n")
        foo = 0x100 + 3 + 0x100
        assert _operand(linker, 0) == (0x200 - foo) & 0xFFFF, \
            hex(_operand(linker, 0))


def test_two_externals_in_one_expression_are_computed_by_the_linker():
    """FOO+BAR and FOO-BAR: two externals, one expression for the linker."""
    with tempfile.TemporaryDirectory() as d:
        ok, asm, ra = _rel(d, "A", "\tEXTRN FOO\n\tEXTRN BAR\n\tCSEG\n"
                                   "\tLXI H,FOO+BAR\n\tLXI D,FOO-BAR\n\tEND\n")
        assert ok, asm.errors
        _, _, rb = _rel(d, "B", TARGET)
        _, _, rc = _rel(d, "C", "BAR\tEQU 1234H\n\tPUBLIC BAR\n\tEND\n")
        linker = Linker()
        linker.code_base = 0x100
        for r in (ra, rb, rc):
            linker.load_rel(r)
        assert linker.link(), linker.errors
        foo = 0x100 + 6 + 0x100
        assert _operand(linker, 0) == foo + 0x1234, hex(_operand(linker, 0))
        assert _operand(linker, 1) == (foo - 0x1234) & 0xFFFF, \
            hex(_operand(linker, 1))


def test_constant_added_to_an_offset_external_is_kept():
    """EXT+2+3 is EXT+5: the constant EXT+2 already carries was dropped.

    `_add_sub' kept only the constant on the right of the newest +/-, so
    EXT+2+3 linked to EXT+3, (EXT+2)-1 to EXT-1 and 1+EXT+1 to EXT+1, and
    `EQX EQU EXT+2' / `DW EQX+1' to EXT+1.  MACRO-80 3.44 lists these as
    0005*, 0001*, 0002* and 0003*.
    """
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tEXTRN FOO\n\tCSEG\n"
                          "\tLXI H,FOO+2+3\n\tLXI H,(FOO+2)-1\n"
                          "\tLXI H,1+FOO+1\nEQX\tEQU FOO+2\n\tLXI H,EQX+1\n"
                          "\tLXI H,FOO+5-2\n\tLXI H,(FOO+5)-(LAB-LAB)\n"
                          "LAB:\tEND\n")
        foo = 0x100 + 18 + 0x100
        want = [foo + 5, foo + 1, foo + 2, foo + 3, foo + 3, foo + 5]
        got = [_operand(linker, i) for i in range(6)]
        assert got == want, [hex(v) for v in got]


def test_byte_of_an_offset_external_keeps_the_whole_offset():
    """MVI A,EQX+1 and HIGH(FOO+100H+1): the byte fields the linker fills
    were built from the same truncated offset."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tEXTRN FOO\n\tCSEG\nEQX\tEQU FOO+2\n"
                          "\tMVI A,EQX+1\n\tMVI A,HIGH(FOO+100H+1)\n\tEND\n")
        foo = 0x100 + 4 + 0x100
        assert linker.output[1] == (foo + 3) & 0xFF, hex(linker.output[1])
        assert linker.output[3] == (foo + 0x101) >> 8, hex(linker.output[3])


def test_shift_by_a_negative_external_offset_is_an_error_not_a_crash():
    """`1 SHR (EXT-1)' raised ValueError: negative shift count."""
    with tempfile.TemporaryDirectory() as d:
        ok, asm, _ = _rel(d, "A", "\tEXTRN FOO\n\tCSEG\n"
                                  "\tDW 1 SHR (FOO-1)\n\tDW 2 SHL (FOO-1)\n\tEND\n")
        assert not ok
        assert any('SHR' in e.message for e in asm.errors), asm.errors
