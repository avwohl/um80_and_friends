"""An ASEG directive writes its set-location item only when something follows.

um80 wrote special item 11, set location, ASEG 0000H, at every ASEG
directive.  For `ASEG / ORG 100H / ...' that is an item saying the module
loads at 0000H, and the genuine LINK-80 3.44 believes it: HI.MAC below,
assembled by um80 and linked with `L80 /P:100,HI,HI/N/E', gave a 384-byte
.COM starting at 0000H ("Data 0000 010C"), where MACRO-80's object gives
"Data 0100 010C", 12 bytes.  MACRO-80 3.44 holds the ASEG directive's item
back until something is loaded, reserved or declared in the segment (a
byte, a word, DS); an ORG, or a switch to another segment, before that
replaces it.  CSEG and DSEG write theirs at once, and so does um80.  The
item lists below are MACRO-80's, checked under cpmemu.
"""

import os
import tempfile

from um80.relformat import ADDR_ABSOLUTE, ADDR_PROGRAM_REL, RELReader
from um80.um80 import Assembler

HI = ("\taseg\n\torg 100h\n\tmvi c,9\n\tlxi d,msg\n\tcall 5\n\trst 0\n"
      "msg:\tdb 'hi$'\n\tend\n")


def _items(source, aseg=False):
    """The set-location items and loaded bytes um80 writes for `source'."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w", encoding="ascii") as f:
            f.write(source)
        asm = Assembler()
        if aseg:
            asm.default_seg = asm.current_seg = 'ASEG'
        assert asm.assemble(p), [e.message for e in asm.errors]
        items = RELReader(asm.output.get_bytes()).read_all()
    return [i if i[0] == 'SET_LOC' else ('B', i[1]) for i in items
            if i[0] in ('SET_LOC', 'ABSOLUTE_BYTE')]


def _loc(addr_type, addr):
    return ('SET_LOC', (addr_type, addr))


def test_aseg_then_org_loads_at_the_org_only():
    items = _items(HI)
    assert items[0] == _loc(ADDR_ABSOLUTE, 0x100)
    assert _loc(ADDR_ABSOLUTE, 0) not in items


def test_aseg_with_code_at_zero_still_says_so():
    assert _items("\taseg\n\tdb 1\n\tend\n") == [
        _loc(ADDR_ABSOLUTE, 0), ('B', 1)]


def test_aseg_left_before_anything_is_loaded():
    # M80: P 0000, 01, P 0001, 02 - nothing for the ASEG.
    assert _items("\tcseg\n\tdb 1\n\taseg\n\tcseg\n\tdb 2\n\tend\n") == [
        ('B', 1), _loc(ADDR_PROGRAM_REL, 1), ('B', 2)]


def test_aseg_reserved_space_writes_it():
    # M80: A 0000, A 0003, 01.
    assert _items("\taseg\n\tds 3\n\tdb 1\n\tend\n") == [
        _loc(ADDR_ABSOLUTE, 0), _loc(ADDR_ABSOLUTE, 3), ('B', 1)]


def test_aseg_returned_to_says_where():
    # M80: A 0000, 01, P 0000, 02, A 0001, 03.
    assert _items("\taseg\n\tdb 1\n\tcseg\n\tdb 2\n\taseg\n\tdb 3\n"
                  "\tend\n") == [
        _loc(ADDR_ABSOLUTE, 0), ('B', 1), _loc(ADDR_PROGRAM_REL, 0),
        ('B', 2), _loc(ADDR_ABSOLUTE, 1), ('B', 3)]


def test_aseg_mode_source_starting_with_org():
    """--aseg: the module starts in ASEG; an ORG first is the only item."""
    items = _items("\torg 100h\n\tdb 1\n\tend\n", aseg=True)
    assert items == [_loc(ADDR_ABSOLUTE, 0x100), ('B', 1)]
    assert _items("\tdb 1\n\tend\n", aseg=True) == [
        _loc(ADDR_ABSOLUTE, 0), ('B', 1)]
