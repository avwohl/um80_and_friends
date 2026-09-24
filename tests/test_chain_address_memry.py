"""Special item 12 (chain address) and LINK-80's $MEMRY.

FORTRAN-80 writes a jump or a reference to a label further down as a
chain through the words that need the label's address, each holding the
address of the next (typed like any word; absolute 0 ends it), and when it
reaches the label writes special item 12, "chain address", whose A-field
is the head of that chain: the linker stores the current location counter
- the label's address - in every word of it.  F80 does the same for a
FORMAT string it puts in the data segment and for constants after the
code.  ul80 read item 12 and never applied it, so the words kept their
links: a 10-line DO/WRITE/FORMAT program compiled with F80 and linked
against FORLIB came out wrong in 8 bytes (0136-7, 0142-3, 0145-6, 014E,
0159) compared with `L80 /P:100/D:19D3,T,FORLIB/S'.

LINK-80 also stores, in the word at the global $MEMRY if a module defines
it, the address of the first free byte after the data area - the end of
the program, in the layout ul80 uses (data and COMMON after the code).
FORLIB's DSKDRV defines $MEMRY and allocates its file buffers from there;
ul80 left it 0000H (1A2A-B in that program; L80 stores 1BCEH).  Probed
with L80 3.44: the word is overwritten whatever the module loaded there,
in DSEG or CSEG, and with /D below /P it is still the end of the data
area, not of the program.
"""

import os
import tempfile

from um80.relformat import (ADDR_ABSOLUTE, ADDR_DATA_REL, ADDR_PROGRAM_REL,
                            RELWriter)
from um80.ul80 import Linker
from um80.um80 import Assembler

# FORTRAN-80 3.44's T.REL for
#       PROGRAM T / INTEGER I,J / REAL X / J=0 / DO 10 I=1,10 / J=J+I*I /
#   10  CONTINUE / X=FLOAT(J)/3.0 / WRITE(1,20) J,X /
#   20  FORMAT(1X,I6,F10.3) / END
# 110 bytes of code, 22 of data.  Item 12 at DSEG 9 (the FORMAT string)
# for the chain at CSEG 66, at CSEG 102 (the INTEGER 1 of the DO) for
# 89 -> 78 -> 69, and at CSEG 106 (REAL 3.0) for 54.
F80_T = bytes.fromhex(
    "845523a00005521e464f524c494200d0600618000021000004580c0042010008b00800ab"
    "0080150bacd00001d62ac06001911603001560100118f814951f00138f2a1e0021c0600c"
    "d00000420000334000010e050066800001100000420000334000008e030010d45001f009"
    "9a00000470280086a7000f804cd000019a00004b824026284012d63009704800a0625816"
    "1246c2c230c4602e198a65ac6012816006680001195e0064892631953006489261193300"
    "a8c989e82a93159000080000008c8200524494e49548c8c003244d39989b000000040414"
    "64e401922221464fc01922a18c652001922b99465840192272246590019222ac4d5b8027"
    "2000009e")
T_EXTERNALS = ("$I1", "$I0", "FLOAT", "$INIT", "$M9", "$DB", "$T1", "$W2",
               "$ND", "$EX")


def _stub(names):
    """A module defining each of `names' as an absolute address."""
    w = RELWriter()
    w.write_program_name("STUB")
    for i, name in enumerate(names):
        w.write_define_entry_point(ADDR_ABSOLUTE, 0xE000 + 3 * i, name)
    w.write_end_program()
    w.write_end_file()
    return w.get_bytes()


def _link(d, *objects, prl=False):
    linker = Linker()
    linker.code_base = 0x100
    linker.page_zero_relative = prl
    for i, data in enumerate(objects):
        p = os.path.join(d, f"m{i}.rel")
        with open(p, "wb") as f:
            f.write(data)
        linker.load_rel(p)
    assert linker.link(), linker.errors
    return linker


def _word(linker, addr):
    off = addr - linker.output_base
    return linker.output[off] | (linker.output[off + 1] << 8)


def _prl_marks(linker, d):
    p = os.path.join(d, "out.prl")
    linker.save_prl(p)
    with open(p, "rb") as f:
        image = f.read()
    n = image[1] | (image[2] << 8)
    bitmap = image[256 + n:]
    return {i for i in range(n) if bitmap[i >> 3] & (0x80 >> (i & 7))}


def test_fortran80_forward_references():
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, F80_T, _stub(T_EXTERNALS))
    data = 0x100 + 110
    assert _word(linker, 0x100 + 54) == 0x100 + 106      # LHLD of REAL 3.0
    assert _word(linker, 0x100 + 66) == data + 9         # the FORMAT string
    for at in (69, 78, 89):                              # the INTEGER 1
        assert _word(linker, 0x100 + at) == 0x100 + 102, at


def _chain_module():
    """CSEG: JMP L / JMP L / DB 0 / L: (item 12) / LXI H,D1 / DSEG D1:
    (item 12); the first chain's second word links to the first (P 0001H),
    as F80 and M80 chain."""
    w = RELWriter()
    w.write_program_name("CH")
    w.write_define_data_size(2)
    w.write_define_program_size(10)
    for b in (0xC3, 0, 0, 0xC3):
        w.write_absolute_byte(b)
    w.write_program_relative(1)
    w.write_absolute_byte(0)
    w.write_chain_address(ADDR_PROGRAM_REL, 4)       # L: CSEG 7
    for b in (0x21, 0, 0):
        w.write_absolute_byte(b)
    w.write_set_location(ADDR_DATA_REL, 1)
    w.write_chain_address(ADDR_PROGRAM_REL, 8)       # D1: DSEG 1
    w.write_absolute_byte(0x55)
    w.write_end_program()
    w.write_end_file()
    return w.get_bytes()


def test_chain_address_fills_every_word_and_moves_in_a_prl():
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, _chain_module(), prl=True)
        marks = _prl_marks(linker, d)
    assert bytes(linker.output[:10]) == bytes.fromhex("c30701c3070100210b01")
    assert linker.output[11] == 0x55
    # All three words are program addresses: their high bytes are marked.
    assert marks == {2, 5, 9}


MEMRY = ("\tPUBLIC $MEMRY\n\tCSEG\n\tDB 1,2,3\n\tDSEG\n\tDB 7\n"
         "$MEMRY:\tDW 1234H\n\tDB 9\n\tEND\n")


def _asm(d, source):
    p = os.path.join(d, "m.mac")
    with open(p, "w", encoding="ascii") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), [e.message for e in asm.errors]
    return asm.output.get_bytes()


def test_memry_is_the_first_free_byte():
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, _asm(d, MEMRY))
    # Code 0100-0102, data 0103-0106: $MEMRY at 0104H holds 0107H.
    assert _word(linker, 0x104) == 0x107
    assert _word(linker, 0x104) == linker.globals['__END__'][1]


def test_memry_counts_common_and_reserved_space_and_moves():
    src = MEMRY.replace("\tDB 9\n", "\tDB 9\n\tDS 30H\n\tCOMMON /CB/\n"
                                    "\tDS 20H\n")
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, _asm(d, src), prl=True)
        marks = _prl_marks(linker, d)
    assert _word(linker, 0x104) == 0x107 + 0x30 + 0x20
    assert 5 in marks                        # its high byte, at 0105H


def test_memry_in_code_is_overwritten_too():
    src = ("\tPUBLIC $MEMRY\n\tCSEG\n$MEMRY:\tDB 1,2,3\n\tDS 50H\n\tDSEG\n"
           "\tDB 7\n\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, _asm(d, src))
    assert _word(linker, 0x100) == 0x100 + 3 + 0x50 + 1
