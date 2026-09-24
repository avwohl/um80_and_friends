"""um80 .REL files LINK-80 can load, and MACRO-80 .REL files ul80 links right.

Checked against the real MACRO-80 and LINK-80 3.44 under cpmemu.  The M80
objects below are its own output, byte for byte (the CP/M 1AH padding
after the end-file item dropped).

- Special item 14 (end program) has an A-field, the start address; um80 left
  it out and LINK-80 refused every um80 object ("?Loading Error", or a
  hang).  Item 13 (program size) is typed program relative, as M80 writes
  it: LINK-80 writes no output when it is absolute.  RELReader reads both
  layouts, so objects from earlier um80 releases still link.
- M80 writes `JMP EXT+3' as item 9 (External plus offset, A = 3) before the
  word, and chains every reference to an external through the words
  (typed program relative).  ul80 ignored item 9 and walked only the chain
  head, adding the segment base to the other links: `jmp ext+3' linked to
  EXT, and of three `call x' the second went to x+100H.
- A chain head of absolute 0 is an empty chain in LINK-80 (M80 writes one
  for an external used only inside an expression).  ul80 followed it when
  the module had ASEG code, writing the external's address over address 0.
- A .REL may hold several modules; ul80 loaded only the first, and ulib80
  stored them as one.
- Several COMMON blocks: M80 selects a block (item 1) before anything
  relative to it; ul80 ignored the selection and put every block at one
  address, and um80 selected a block only at its COMMON directive.  Bytes
  assembled into a COMMON block went into the segment before it.
"""

import os
import tempfile

from um80.relformat import (RELReader, RELWriter, ADDR_ABSOLUTE,
                            ADDR_PROGRAM_REL)
from um80.ul80 import Linker
from um80.ulib80 import Library
from um80.um80 import Assembler

# \tcseg / \textrn ext / \tjmp ext+3 / \tlxi h,ext-1 / \tcall ext /
# \tcall ext / \tdw 3+ext / \tend
M80_J1 = bytes.fromhex(
    "84928c6500001350e0096800030e480600000008649ffff404019b410019b41c02480"
    "60142802321800d1561527000009e")
# \tcseg / \tpublic ext / \tds 123h / ext:\tnop / \tend
M80_E = bytes.fromhex(
    "84516034558549400004d490065a00012d2301004748c05a2ac2a4e000009e")
# \taseg / \torg 0 / \tjmp go / \tdb 0aah,0bbh,0cch / \tcseg / \textrn ext /
# go:\tmvi a,ext / \tmvi a,high(ext) / \tret / \tend
M80_AS = bytes.fromhex(
    "849054e50000135050096000030e80002a976cc9680000fa24424558548890404003e"
    "89109156152224103889040400c98c000034558549c0000009e")
# \tpublic c1,c2 / \tcseg / \tdw c1 / \tdw c2 / \tdb low(c2),high(c2) /
# \tcommon /blk1/ / c1:\tdb 11h,12h / \tds 300h /
# \tcommon /blk2/ / c2:\tdb 21h,22h / \tds 10h / \tend
M80_CA = bytes.fromhex(
    "8490d060243318090cca280407109312cc6282401109312cca50000135060096800041"
    "884989663c00020c424c4b32e0001122181800044482091120808022443030000889040"
    "e22410100418849896632f00000884a5e040706212625994bc00004222978900418849"
    "896631f000048663062126259947c000121994e0000009e")
# \tcseg / \tdw d2 / \tdw d1 / \tcommon /blk2/ / \tdb 0 / d2:\tds 1 /
# \tcommon /blk1/ / \tdb 0 / d1:\tds 1 / \tend
M80_CB = bytes.fromhex(
    "8490d0a280401109312cca280401109312cc650000135040096800041884989665c040"
    "20c424c4b31e020106212625994bc0000012f020083109312cc65e0000009781004e00"
    "00009e")
# \textrn ext / \taseg / \torg 4000h / \tdw ext / \tcseg / \tcall ext / \tend
# (the chain runs from CSEG 0001H to ASEG 4000H: the link is absolute)
M80_XA = bytes.fromhex(
    "84934c2500001350300960020000012d0000668008119010068ab0a93800009e")
# \textrn ext / \tcseg / \tcall ext / \taseg / \torg 4000h / \tdw ext / \tend
# (from ASEG 4000H to CSEG 0001H: the link is program relative)
M80_AX = bytes.fromhex(
    "84934c25000013503009680003340000960020501008c002034558549c0000009e")

# \tcseg / \tdb 0 / \tcommon /blk1/ / \tdw c2 / \tdb 7 / \tcommon /blk2/ /
# \tdb 9 / c2:\tds 1 / \tend - M80 selects BLK2 for the DW and does not
# select BLK1 back; `common /blk2/' is then a set-location alone.
M80_XCW = bytes.fromhex(
    "84934c2280601109312cc6280401109312cca5000013501009680000020c424c4b31"
    "97800041884989665c04000f2f000004cbc080270000009e")
# The same with \tmvi a,low(c2) / \tmvi b,7 in BLK1.
M80_XC = bytes.fromhex(
    "84934c2280801109312cc6280401109312cca5000013501009680000020c424c4b31"
    "9780000fa0c424c4b328910c0c04022241048890404000603cbc0000132f02009c00"
    "00009e")
# um80 0.3.34 on \textrn ext / \tcseg / \tnop / \tcall ext / \tnop /
# \tcall ext / \tlxi h,ext / \tend: one chain through untyped words, each
# the offset of the previous reference in CSEG, and item 14 without an
# A-field.
V0334_M2 = bytes.fromhex(
    "84934c800cd0000000cd010004206004642401a2ac2a4d02c027009e")
# um80 0.3.34 on \tcseg / \tpublic ext / \tds 10h / ext:\tret / \tend
V0334_D = bytes.fromhex(
    "84512034558549688003263a2000d1561526822013809e")


def _link(d, *objects, origin=0x100):
    """Link (name, REL bytes) pairs; return the Linker."""
    linker = Linker()
    linker.code_base = origin
    for name, data in objects:
        p = os.path.join(d, name + ".rel")
        with open(p, "wb") as f:
            f.write(data)
        linker.load_rel(p)
    assert linker.link(), linker.errors
    return linker


def _asm(d, name, source):
    p = os.path.join(d, name + ".mac")
    with open(p, "w", encoding="ascii") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), [e.message for e in asm.errors]
    return asm.output.get_bytes()


def _word(out, i):
    return out[i] | (out[i + 1] << 8)


def test_m80_external_plus_offset_and_multi_reference_chain():
    """LINK-80: C3 34 02 21 30 02 CD 31 02 CD 31 02 34 02 (EXT = 0231H)."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, ("J1", M80_J1), ("E", M80_E))
    assert bytes(linker.output[:14]) == bytes.fromhex(
        "c33402213002cd3102cd31023402")


def test_m80_empty_chain_with_aseg_code_keeps_address_0():
    """LINK-80 (/P:100): C3 00 01 AA BB CC at 0000H."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, ("AS", M80_AS), ("E", M80_E))
    assert linker.output_base == 0
    assert bytes(linker.output[:6]) == bytes.fromhex("c30001aabbcc")
    ext = 0x100 + 5 + 0x123
    assert linker.output[0x101] == ext & 0xFF
    assert linker.output[0x103] == ext >> 8


def test_m80_common_blocks_are_placed_apart():
    """BLK1 (302H bytes) and BLK2 each at its own address; the second
    module declares them in the other order."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, ("CA", M80_CA), ("CB", M80_CB))
    blk1 = 0x100 + 6 + 4
    blk2 = blk1 + 0x302
    out = linker.output
    assert _word(out, 0) == blk1 and _word(out, 2) == blk2
    assert out[4] == blk2 & 0xFF and out[5] == blk2 >> 8
    assert _word(out, 6) == blk2 + 1 and _word(out, 8) == blk1 + 1
    # The DB 11H,12H / DB 21H,22H in the blocks are in the image, and the
    # second module's DB 0 at the start of each block overwrote the first
    # byte (LINK-80 gives the same 00 12).
    assert out[blk1 - 0x100:blk1 - 0x100 + 2] == b"\x00\x12"
    assert out[blk2 - 0x100:blk2 - 0x100 + 2] == b"\x00\x22"


def _word_at(linker, addr):
    return _word(linker.output, addr - linker.output_base)


def test_m80_chain_from_relocatable_code_into_aseg():
    """An absolute chain link is an address in ASEG.  ul80 read it as an
    offset in the segment the word is in, found nothing at CSEG+4000H and
    left the reference at 4000H zero (LINK-80 fills both)."""
    ext = 0x100 + 3 + 0x123
    for name, rel in (("XA", M80_XA), ("AX", M80_AX)):
        with tempfile.TemporaryDirectory() as d:
            linker = _link(d, (name, rel), ("E", M80_E))
        assert _word_at(linker, 0x101) == ext, name
        assert _word_at(linker, 0x4000) == ext, name


def test_reader_reads_m80_and_old_um80_end_items():
    items = RELReader(M80_E).read_all()
    assert items[-2:] == [('END_PROGRAM', (ADDR_ABSOLUTE, 0)), ('END_FILE',)]
    # um80 0.3.48 on `CSEG / NOP / END': item 14 without an A-field.
    old = bytes.fromhex("8453c013401009c09e")
    items = RELReader(old).read_all()
    assert items[-2:] == [('END_PROGRAM', None), ('END_FILE',)]


def test_um80_writes_what_link80_reads():
    with tempfile.TemporaryDirectory() as d:
        rel = _asm(d, "A", "\tCSEG\nST:\tNOP\n\tJMP EXT+3\n\tEXTRN EXT\n"
                           "\tEND ST\n")
    items = RELReader(rel).read_all()
    kinds = [i[0] for i in items]
    # Sizes before the code, as M80 writes them; program size typed P.
    assert kinds.index('DEFINE_PROG_SIZE') < kinds.index('ABSOLUTE_BYTE')
    assert ('DEFINE_PROG_SIZE', (ADDR_PROGRAM_REL, 4)) in items
    # EXT+3 is item 9 before the word and a chain of plain EXT.
    i = items.index(('EXTERNAL_PLUS_OFFSET', (ADDR_ABSOLUTE, 3)))
    assert items[i - 1] == ('ABSOLUTE_BYTE', 0xC3)
    assert ('CHAIN_EXTERNAL', (ADDR_PROGRAM_REL, 2), 'EXT') in items
    # END ST: the start address in item 14's A-field.
    assert items[-2:] == [('END_PROGRAM', (ADDR_PROGRAM_REL, 0)),
                          ('END_FILE',)]


def test_data_size_is_written_when_there_is_no_data():
    """MACRO-80 writes item 10 (data size) in every module, 0 when there
    is no DSEG, and LINK-80 3.44 needs it: without it, `DW EXT+1' in ASEG
    (item 9, then a chain of one) linked in L80 to EXT - the constant was
    lost - where the same object with the item gives EXT+1."""
    with tempfile.TemporaryDirectory() as d:
        rel = _asm(d, "A", "\tEXTRN EXT\n\tASEG\n\tORG 4000H\n"
                           "\tDW EXT+1\n\tEND\n")
    items = RELReader(rel).read_all()
    assert items[1] == ('DEFINE_DATA_SIZE', (ADDR_ABSOLUTE, 0))
    assert [i[0] for i in items].count('DEFINE_PROG_SIZE') == 0


def test_um80_and_m80_objects_link_together():
    """um80's EXT+3 / EXT-1 and M80's, in one program."""
    with tempfile.TemporaryDirectory() as d:
        mine = _asm(d, "U", "\tEXTRN EXT\n\tCSEG\n\tJMP EXT+3\n"
                            "\tLXI H,EXT-1\n\tDW EXT\n\tEND\n")
        linker = _link(d, ("U", mine), ("J1", M80_J1), ("E", M80_E))
    ext = 0x100 + 8 + 14 + 0x123
    out = linker.output
    assert (_word(out, 1), _word(out, 4), _word(out, 6)) == \
        (ext + 3, ext - 1, ext)
    assert _word(out, 9) == ext + 3 and _word(out, 12) == ext - 1


def test_reference_at_absolute_zero():
    """A chain cannot start at absolute 0 (that is an empty chain), so um80
    writes `DW EXT' at 0000H as an extension link item."""
    with tempfile.TemporaryDirectory() as d:
        mine = _asm(d, "Z", "\tEXTRN EXT\n\tASEG\n\tORG 0\n\tDW EXT\n"
                            "\tDW EXT+1\n\tEND\n")
        linker = _link(d, ("Z", mine), ("E", M80_E))
    ext = 0x100 + 0x123
    assert _word(linker.output, 0) == ext
    assert _word(linker.output, 2) == ext + 1


def test_old_um80_objects_still_link():
    """0.3.48's layout: item 14 without an A-field, `EXT+3' in the chain
    name, and a reference at absolute 0 in a chain."""
    w = RELWriter()
    w.write_program_name("OLD")
    w.write_set_location(ADDR_ABSOLUTE, 0)
    for b in (0, 0, 0xC3, 0, 0):
        w.write_absolute_byte(b)
    w.write_chain_external(ADDR_ABSOLUTE, 0, "EXT")
    w.write_chain_external(ADDR_ABSOLUTE, 3, "EXT+3")
    w.bits.write_bits(0b100, 3)  # the old END_PROGRAM: item 14, no A-field
    w.bits.write_bits(14, 4)
    w.bits.force_byte_boundary()
    w.write_end_file()
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, ("OLD", w.get_bytes()), ("E", M80_E))
    ext = 0x100 + 0x123
    assert _word(linker.output, 0) == ext
    assert _word(linker.output, 3) == ext + 3


def test_m80_operand_in_another_common_block():
    """Selecting a COMMON block (item 1) says what a COMMON-relative value
    is relative to; LINK-80 moves where bytes load only at a set-location.
    ul80 loaded the rest of BLK1 into BLK2 once M80 selected BLK2 for an
    operand (00 00 00 00 0D 01).  LINK-80: 00 05 01 07 09 00 and
    00 3E 06 06 07 09 00 (the last byte is C2's DS)."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, ("XCW", M80_XCW))
    assert bytes(linker.output[:5]) == bytes.fromhex("0005010709")
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, ("XC", M80_XC))
    assert bytes(linker.output[:6]) == bytes.fromhex("003e06060709")


def test_um80_0334_chain_through_untyped_words():
    """um80 0.2.1 to 0.3.34 chained an external's references through
    untyped words holding the previous reference's offset in the same
    segment.  Reading an absolute link as an ASEG address (as M80's is)
    filled only the head: 00 CD 00 00 00 CD 02 00 21 1B 01."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, ("M2", V0334_M2), ("D", V0334_D))
    assert linker.modules[0].legacy_um80
    assert bytes(linker.output[:11]) == bytes.fromhex(
        "00cd1b0100cd1b01211b01")


def _two_module_rel():
    w = RELWriter()
    for name, byte in (("ONE", 0x11), ("TWO", 0x22)):
        w.write_program_name(name)
        w.write_entry_symbol(name + "P")
        w.write_define_program_size(1)
        w.write_absolute_byte(byte)
        w.write_define_entry_point(ADDR_PROGRAM_REL, 0, name + "P")
        w.write_end_program()
    w.write_end_file()
    return w.get_bytes()


def test_every_module_of_a_multi_module_rel_is_loaded():
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, ("LIB", _two_module_rel()))
    assert [m.name for m in linker.modules] == ["ONE", "TWO"]
    assert bytes(linker.output[:2]) == b"\x11\x22"


def test_ulib80_splits_a_multi_module_rel():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "both.rel")
        with open(p, "wb") as f:
            f.write(_two_module_rel())
        lib = Library()
        assert lib.add_rel_file(p) == ["ONE", "TWO"]
    assert lib.find_module_for_symbol("TWOP") == "TWO"
    assert [m.publics for m in lib.modules] == [["ONEP"], ["TWOP"]]


def test_um80_common_blocks():
    """Two COMMON blocks in um80's own objects, initialized data in them
    that refers to the other block, and a PUBLIC in one."""
    with tempfile.TemporaryDirectory() as d:
        a = _asm(d, "A", "\tPUBLIC BL\n\tCSEG\n\tLXI H,AL\n\tLXI D,BL\n"
                         "\tRET\n\tCOMMON /AA/\nAL:\tDB 2\n\tDW BL\n"
                         "\tDB HIGH BL\n\tCOMMON /BB/\n\tDS 4\nBL:\tDB 5\n"
                         "\tDW AL\n\tCSEG\n\tDW BL-AL\n\tEND\n")
        b = _asm(d, "B", "\tEXTRN BL\n\tCSEG\n\tLXI H,BL+1\n"
                         "\tCOMMON /BB/\n\tDS 7\n\tEND\n")
        linker = _link(d, ("A", a), ("B", b))
    aa = 0x100 + 9 + 3
    bl = aa + 4 + 4
    out = linker.output
    assert (_word(out, 1), _word(out, 4)) == (aa, bl)
    assert _word(out, 7) == (bl - aa)
    assert _word(out, 10) == bl + 1
    assert out[aa - 0x100:aa - 0x100 + 4] == bytes([2, bl & 0xFF, bl >> 8,
                                                    bl >> 8])
    assert out[bl - 0x100:bl - 0x100 + 3] == bytes([5, aa & 0xFF, aa >> 8])


def test_prl_reserves_memory_for_common():
    with tempfile.TemporaryDirectory() as d:
        rel = _asm(d, "B", "\tCSEG\n\tLXI H,CBUF\n\tRET\n"
                           "\tCOMMON /BLK/\nCBUF:\tDS 1000H\n\tEND\n")
        linker = _link(d, ("B", rel))
        p = os.path.join(d, "b.prl")
        linker.save_prl(p)
        with open(p, "rb") as f:
            header = f.read(6)
    assert header[1] | header[2] << 8 == 4
    assert header[4] | header[5] << 8 == 0x1000


def test_aseg_code_before_any_org_is_absolute():
    """--aseg: code before an ORG starts at absolute 0, where its labels
    are; ul80 used to load it into CSEG, so an external in it stayed 0."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "h.mac")
        with open(p, "w", encoding="ascii") as f:
            f.write("\tEXTRN EXT\nHB:\tDW EXT\n\tDW HB\n\tEND\n")
        asm = Assembler()
        asm.default_seg = asm.current_seg = 'ASEG'
        assert asm.assemble(p)
        linker = _link(d, ("H", asm.output.get_bytes()), ("E", M80_E))
    assert linker.output_base == 0
    assert _word(linker.output, 0) == 0x100 + 0x123
    assert _word(linker.output, 2) == 0


def test_lib80_library_is_searched():
    """A LIB-80 library - .REL modules one after another, like FORTRAN-80's
    FORLIB - was refused ("bad magic"); it is searched like ulib80's."""
    import subprocess
    import sys
    import um80
    root = os.path.dirname(os.path.dirname(os.path.abspath(um80.__file__)))
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "two.lib"), "wb") as f:
            f.write(_two_module_rel())
        with open(os.path.join(d, "MAIN.rel"), "wb") as f:
            f.write(_asm(d, "MAIN", "\tEXTRN TWOP\n\tCSEG\n\tCALL TWOP\n"
                                    "\tRET\n\tEND\n"))
        r = subprocess.run([sys.executable, "-m", "um80.ul80", "-o", "m.com",
                            "MAIN.rel", "two.lib"], cwd=d,
                           env=dict(os.environ, PYTHONPATH=root),
                           capture_output=True, text=True, check=False)
        assert r.returncode == 0, r.stderr
        with open(os.path.join(d, "m.com"), "rb") as f:
            image = f.read()
    # Only TWO is loaded, after MAIN's 4 bytes.
    assert image[:5] == bytes([0xCD, 0x04, 0x01, 0xC9, 0x22])
