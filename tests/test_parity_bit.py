"""A source byte with bit 7 set is read as the same byte with it clear.

MACRO-80 3.44 and DRI's MAC 2.0 and RMAC 1.1 all clear bit 7 - the parity
bit some CP/M editors and serial links left set - of every byte they read
from a source file.  um80 decoded such a byte as a character that no name,
number or operator starts with.  A line that began with one was then
dropped without a word: DRI's MP/M II NUCLEUS/MEMMGR.ASM ends six lines
with CR and 8AH (a line feed with bit 7 set), so the line after each one
started with 8AH, and one of the six lines lost was an INX B.  In a string
such a byte came out as FDH.

Each expected result below is what M80, MAC and RMAC produce from the same
bytes, run under cpmemu (MAC's .HEX, RMAC's listing, M80's .REL).
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(data, include=None):
    """Assemble the bytes `data'; returns (ok, bytes loaded, errors)."""
    with tempfile.TemporaryDirectory() as d:
        if include is not None:
            with open(os.path.join(d, 'inc.mac'), 'wb') as f:
                f.write(include)
        p = os.path.join(d, 't.mac')
        with open(p, 'wb') as f:
            f.write(data)
        asm = Assembler()
        ok = asm.assemble(p)
        errors = [str(e) for e in asm.errors]
        if not ok:
            return ok, b'', errors
        items = RELReader(asm.output.get_bytes()).read_all()
        return ok, bytes(it[1] for it in items if it[0] == 'ABSOLUTE_BYTE'), errors


def test_line_after_cr_8ah_is_assembled():
    # The repro: `nop' then a line ending CR 8AH, then `inx b'.  M80, MAC
    # and RMAC: 00 03.  um80 0.3.50: 00, and no diagnostic.
    ok, code, errors = _assemble(b'\tnop\r\x8a\tinx\tb\r\n\tend\r\n')
    assert ok, errors
    assert code == bytes([0x00, 0x03])


def test_bit_7_in_a_string_is_cleared():
    # DB 'a', C1H, 'b': M80, MAC and RMAC all give 61 41 62.  um80 gave
    # 61 FD 62 (the Unicode replacement character's low byte).
    ok, code, errors = _assemble(b"\tdb\t'a\xc1b'\r\n\tend\r\n")
    assert ok, errors
    assert code == b'aAb'


def test_bit_7_anywhere_in_a_statement():
    # A letter, a blank, a tab and a CR with bit 7 set, a CR 8AH line end
    # and a comment with bit-7 letters.  M80, MAC and RMAC agree on every
    # byte: 03 13 23 01 02 03 04 05 06 07.
    src = (b'\t\xe9nx\tb\r\n'        # E9H = i
           b'\tinx\xa0d\r\n'         # A0H = blank
           b'\tinx\x89h\r\n'         # 89H = tab
           b'\tdb\t1\x8d\n'          # 8DH = CR
           b'\tdb\t2\r\n'
           b'\tdb\t3\r\n'
           b'\tdb\t4\r\x8a'
           b'\tdb\t5 ;\xe9\xe9\r\n'
           b'\tdb\t6 ;x\x8d\x8a'
           b'\tdb\t7\r\n'
           b'\tend\r\n')
    ok, code, errors = _assemble(src)
    assert ok, errors
    assert code == bytes([0x03, 0x13, 0x23, 1, 2, 3, 4, 5, 6, 7])


def test_lone_8ah_is_dropped_as_in_m80():
    # An 8AH that does not follow a CR (or 8DH) is not a line end: M80 3.44
    # drops it, like every LF.  MAC and RMAC do not end the line there
    # either, and um80 0.3.50 read it as U+FFFD; only CR 8AH is a CR LF.
    # A line end there made the rest of a comment a statement: `nop ; abc',
    # 8AH, `inx b' was 00 03, where M80, MAC and RMAC give 00.
    cases = [
        (b'\tnop\t; abc\x8a\tinx\tb\r\n', b'\x00'),
        # UTF-8 comments: U+4E0A is E4 B8 8A, U+044A is D1 8A.
        (b'\tnop\t; \xe4\xb8\x8a\tinx\tb\r\n', b'\x00'),
        (b'\tnop\t; \xd1\x8a text\r\n\tdb\t1\r\n', b'\x00\x01'),
        # In a string M80 gives 61 62 (MAC and RMAC 61 0A 62, 0.3.50 61 FD 62).
        (b"\tdb\t'a\x8ab'\r\n", b'ab'),
        (b'\tdb\t"a\x8ab",2\r\n', b'ab\x02'),
        # Inside a name or a number M80 reads on past it.
        (b'\tin\x8ax\tb\r\n', b'\x03'),
        (b'\tdb\t1\x8a2\r\n', b'\x0c'),
        (b'\tdb\t5\x8a;x\r\n', b'\x05'),
        # After a CR LF it starts no line of its own; after CR 8AH neither.
        (b'\tnop\r\n\x8a\tinx\tb\r\n', b'\x00\x03'),
        (b'\tnop\r\x8a\x8a\tinx\tb\r\n', b'\x00\x03'),
    ]
    for src, want in cases:
        ok, code, errors = _assemble(src + b'\tend\r\n')
        assert ok, (src, errors)
        assert code == want, src


def test_include_file_is_read_the_same_way():
    ok, code, errors = _assemble(b'\tinclude\tinc.mac\r\n\tdb\t9\r\n\tend\r\n',
                                 include=b'\tnop\r\x8a\tinx\tb\r\x8a\tdb\t\'\xc1\'\r\n')
    assert ok, errors
    assert code == bytes([0x00, 0x03, 0x41, 0x09])


def test_source_lines():
    from um80.um80 import source_lines  # pylint: disable=import-outside-toplevel
    assert source_lines(b'a\r\x8ab\r\nc\x8d\x8ad\x1a\xe5') == ['a', 'b', 'c', 'd']
    # A lone 8AH is dropped; a lone LF is a line end, for files from Unix.
    assert source_lines(b'a\x8ab\r\n\x8ac\nd') == ['ab', 'c', 'd']
    # 9AH is not an end of file (M80); a 1AH is.
    assert source_lines(b'a\r\n\x9a\r\nb\x1ac') == ['a', '\x1a', 'b']
