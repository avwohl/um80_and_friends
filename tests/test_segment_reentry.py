"""Where a segment or COMMON directive goes on, and a segment's size.

Each checked against MACRO-80 3.44 under cpmemu (its listing and .REL):

- Every COMMON statement starts at the beginning of its block, as the
  MACRO-80 manual says for FORTRAN: `COMMON /C/ / DB 7 / ASEG / ... /
  COMMON /C/ / DB 8' puts the 8 over the 7.  um80 went on where the block
  was left.
- MACRO-80 keeps for each of CSEG, DSEG and ASEG the most of the locations
  set in it (ORG, the end of a DS) and of those it was left at, and a
  segment directive goes on from there: after `ORG 200H / DB 1,2,3 /
  ORG 180H / DB 4', ASEG goes on at 0200H (over the 1), and after `DS 10H
  / ORG 4 / DB 1', CSEG at 10H.  um80 went on where the segment was left.
- A segment's size is the most it reached.  um80 wrote the location at the
  end, so after `ORG 20H / DB 1 / ORG 10H / DB 2' the program size was 11H
  and the next module was linked over the 1.  (MACRO-80 writes 20H there,
  one short: its size is the most of the locations set and the one at the
  end, which leaves out bytes loaded past the highest ORG.)
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler
from um80.ul80 import Linker


def _asm(d, name, source):
    p = os.path.join(d, name + ".mac")
    with open(p, "w", encoding="ascii") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), [e.message for e in asm.errors]
    return asm.output.get_bytes()


def _layout(source):
    """(sizes, [(segment type, block, address, byte)]) of um80's .REL."""
    with tempfile.TemporaryDirectory() as d:
        items = RELReader(_asm(d, "t", source)).read_all()
    seg, loc, block, where, sizes = 1, 0, None, [], {}
    for item in items:
        if item[0] == 'SET_LOC':
            seg, loc = item[1]
        elif item[0] == 'SELECT_COMMON':
            block = item[1]
        elif item[0] == 'ABSOLUTE_BYTE':
            where.append((seg, block if seg == 3 else None, loc, item[1]))
            loc += 1
        elif item[0] in ('DEFINE_PROG_SIZE', 'DEFINE_DATA_SIZE'):
            sizes[item[0]] = item[1][1]
        elif item[0] == 'DEFINE_COMMON_SIZE':
            sizes[item[2]] = item[1][1]
    return sizes, where


def test_common_statement_starts_at_the_beginning_of_its_block():
    """M80: 4 over the 1 in /C/, 9 over the 8 in blank COMMON."""
    sizes, where = _layout("\tCOMMON /C/\n\tDB 1,2,3\n\tCOMMON /D/\n\tDB 7\n"
                           "\tCOMMON /C/\n\tDB 4\n\tCSEG\n\tDB 5\n"
                           "\tCOMMON //\n\tDB 8\n\tCOMMON //\n\tDB 9\n\tEND\n")
    assert where == [(3, 'C', 0, 1), (3, 'C', 1, 2), (3, 'C', 2, 3),
                     (3, 'D', 0, 7), (3, 'C', 0, 4), (1, None, 0, 5),
                     (3, ' ', 0, 8), (3, ' ', 0, 9)]
    assert (sizes['C'], sizes['D'], sizes[' ']) == (3, 1, 1)


def test_aseg_goes_on_at_the_highest_location_set():
    """M80: 1,2,3 at 0200H, 4 at 0180H, 5 at CSEG 0, 6 at 0200H."""
    src = "\tASEG\n\tORG 200H\n\tDB 1,2,3\n\tORG 180H\n\tDB 4\n"
    _, where = _layout(src + "\tCSEG\n\tDB 5\n\tASEG\n\tDB 6\n\tEND\n")
    assert where[-2:] == [(1, None, 0, 5), (0, None, 0x200, 6)]
    _, where = _layout(src + "\tASEG\n\tDB 6\n\tEND\n")
    assert where[-1] == (0, None, 0x200, 6)


def test_cseg_goes_on_past_the_highest_location_set():
    """M80: after ORG 20H / ORG 10H CSEG goes on at 20H; after a DS it
    goes on past the DS; an ORG back to patch ($-1) changes nothing."""
    _, where = _layout("\tCSEG\n\tORG 20H\n\tDB 1\n\tORG 10H\n\tDB 2\n"
                       "\tDSEG\n\tDB 3\n\tCSEG\n\tDB 4\n\tDSEG\n\tCSEG\n"
                       "\tDB 5\n\tEND\n")
    assert [(s, a, b) for s, _, a, b in where] == [
        (1, 0x20, 1), (1, 0x10, 2), (2, 0, 3), (1, 0x20, 4), (1, 0x21, 5)]
    _, where = _layout("\tCSEG\n\tDS 10H\n\tORG 4\n\tDB 1\n\tDSEG\n\tCSEG\n"
                       "\tDB 5\n\tEND\n")
    assert where[-1] == (1, None, 0x10, 5)
    _, where = _layout("\tCSEG\n\tDB 1,2,3\n\tORG $-1\n\tDB 9\n\tDSEG\n"
                       "\tCSEG\n\tDB 5\n\tEND\n")
    assert where[-1] == (1, None, 3, 5)


def test_segment_size_is_the_most_it_reached():
    """So the next module is linked past the byte at 20H."""
    sizes, _ = _layout("\tCSEG\n\tORG 20H\n\tDB 1\n\tORG 10H\n\tDB 2\n\tEND\n")
    assert sizes['DEFINE_PROG_SIZE'] == 0x21
    sizes, _ = _layout("\tDSEG\n\tORG 30H\n\tDB 1\n\tORG 8\n\tDB 2\n\tEND\n")
    assert sizes['DEFINE_DATA_SIZE'] == 0x31
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for name, src in (("A", "\tCSEG\n\tORG 20H\n\tDB 1\n\tORG 10H\n"
                                "\tDB 2\n\tEND\n"),
                          ("B", "\tCSEG\n\tDB 0BBH\n\tEND\n")):
            p = os.path.join(d, name + ".rel")
            with open(p, "wb") as f:
                f.write(_asm(d, name, src))
            paths.append(p)
        linker = Linker()
        linker.code_base = 0x100
        for p in paths:
            linker.load_rel(p)
        assert linker.link()
    out = linker.output
    assert (out[0x10], out[0x20], out[0x21]) == (2, 1, 0xBB)
