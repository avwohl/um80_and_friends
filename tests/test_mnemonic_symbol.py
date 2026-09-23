"""A symbol whose name is also a mnemonic must win over the opcode byte.

M80 lets an instruction name stand for its own byte, so `DB MOV' assembles to
40H (manual p.2-4). um80 applied that before consulting the symbol table, so a
program could not have a label called ADD: every reference to it assembled to
80H, the encoding of `ADD A,B'.

Found in MP/M II. UTIL4/STAT.PLM declares

    add: procedure(ap,bp);

and `call add(ptr(i),.fac)' came out as `CALL 0080H' - a call into the CP/M DMA
buffer at 0080H, which executed whatever the command tail happened to hold and
fell through into the program's own entry jump at 0100H, restarting STAT. It
printed its drive line forever and never printed a figure.
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _link(tmpdir, source):
    p = os.path.join(tmpdir, "T.mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), asm.errors
    rp = os.path.join(tmpdir, "T.rel")
    with open(rp, "wb") as f:
        f.write(asm.output.get_bytes())
    linker = Linker()
    linker.code_base = 0x100
    linker.load_rel(rp)
    assert linker.link()
    return linker


# Five calls (15 bytes), then five one-byte routines at 0110H onward.
PROG = ("\tCSEG\n"
        "\tCALL ADD\n\tCALL SUB\n\tCALL CP\n\tCALL OUT\n\tCALL MYPROC\n"
        "ADD:\tRET\nSUB:\tRET\nCP:\tRET\nOUT:\tRET\nMYPROC:\tRET\n\tEND\n")


def test_labels_named_after_mnemonics_resolve_to_their_address():
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, PROG)
        out = linker.output
        for i, name in enumerate(("ADD", "SUB", "CP", "OUT", "MYPROC")):
            got = out[i * 3 + 1] | (out[i * 3 + 2] << 8)
            want = 0x100 + 15 + i
            assert got == want, f"CALL {name} -> {got:04X}, expected {want:04X}"


def test_a_forward_label_named_add_is_not_the_opcode_byte():
    """The specific shape that broke STAT: the definition follows the call."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, PROG)
        assert (linker.output[1] | (linker.output[2] << 8)) != 0x0080


def test_an_opcode_name_that_is_not_a_symbol_still_gives_its_byte():
    """`DB MOV' keeps working, since nothing defines MOV here."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tCSEG\n\tDB MOV\n\tDB ADD\n\tDB SUB\n\tEND\n")
        assert bytes(linker.output[:3]) == bytes([0x40, 0x80, 0x90])


def test_a_defined_equ_also_wins_over_the_opcode_byte():
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "ADD\tEQU 1234H\n\tCSEG\n\tLXI H,ADD\n\tEND\n")
        assert (linker.output[1] | (linker.output[2] << 8)) == 0x1234
