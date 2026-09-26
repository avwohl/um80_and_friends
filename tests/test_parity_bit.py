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


def _assemble(data, include=None, dri=False):
    """Assemble the bytes `data'; returns (ok, bytes loaded, errors)."""
    with tempfile.TemporaryDirectory() as d:
        if include is not None:
            with open(os.path.join(d, 'inc.mac'), 'wb') as f:
                f.write(include)
        p = os.path.join(d, 't.mac')
        with open(p, 'wb') as f:
            f.write(data)
        asm = Assembler(dri=dri)
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


# With --dri, an 8AH or 8DH inside a line is read as MAC and RMAC read it.
# They clear bit 7 and then take the byte for a LF or a CR, where M80 leaves
# out an 8AH and ends the line at an 8DH.  An 8AH that does not follow a CR
# is a character: in a string the byte 0AH, in a comment nothing, anywhere
# else an error (E).  An 8DH ends the statement, and MAC then reads the
# next word or character, after any blanks, as the LF it expects after a
# CR; the rest of the line is the next statement.  um80 --dri read both as
# M80 does.  The bytes are what MAC 2.0 and RMAC 1.1 assemble.
DRI_PARITY = [
    # A 8AH in a string: MAC 41 0A 42 (M80 41 42).
    (b"\tdb\t'A\x8aB'\r\n", '410a42'),
    (b"mm\tmacro\r\n\tdb\t'A\x8aB'\r\n\tendm\r\n\tmm\r\n", '410a42'),
    # In a comment it is nothing.
    (b'\tdb\t1 ;x\x8a\tdb\t2\r\n\tdb\t3\r\n', '0103'),
    # An 8DH in a comment: the word after it goes for the LF, and the rest
    # of the line, `2', is a line number.  M80 01 02 03.
    (b'\tdb\t1 ;x\x8d\tdb\t2\r\n\tdb\t3\r\n', '0103'),
    (b'\tdb\t1 ;x\x8ddb 2\r\n\tdb\t3\r\n', '0103'),
    (b'\tdb\t1\x8d\t\tdb\t2\r\n\tdb\t3\r\n', '0103'),
    (b';x\x8d\tdb\t2\r\n\tdb\t3\r\n', '03'),
    # Here the word is `x', and `<TAB>DB 2' is assembled.
    (b'\tdb\t1 ;x\x8dx\tdb\t2\r\n\tdb\t3\r\n', '010203'),
    # A second 8DH, or an 8AH, is the LF.
    (b'\tdb\t1\x8d\x8d\tdb\t2\r\n\tdb\t3\r\n', '010203'),
    (b'\tdb\t1 ;x\x8d\x8a\tdb\t2\r\n\tdb\t3\r\n', '010203'),
    (b'\tdb\t1\x8d\ndb\t2\r\n', '0102'),
    # A `,' is the LF, and `2' a line number.  M80 01 00 02 03 (Q).
    (b'\tdb\t1\x8d,2\r\n\tdb\t3\r\n', '0103'),
    # CR 8AH is a CR LF, as MP/M II's MEMMGR.ASM ends six lines.
    (b'\tdb\t1\r\x8a\tdb\t2\r\n', '0102'),
]


def test_dri_reads_8ah_and_8dh_as_mac():
    for src, want in DRI_PARITY:
        ok, code, errors = _assemble(src + b'\tend\r\n', dri=True)
        assert ok, (src, errors)
        assert code.hex() == want, src


def test_dri_flags_what_mac_flags():
    # MAC and RMAC flag each (E or S) and assemble none, or not all, of it.
    for src in [
            b'\tdb\t1\x8a\r\n\tdb\t2\r\n',           # E: 00 02
            b'\tdb\t1\x8a,2\r\n\tdb\t3\r\n',          # E: 00 00 03
            b"\tdb\t'A\x8dB'\r\n",                    # O: 00
            # The line end after an 8DH is the LF, so the next line
            # starts with the real LF (S), and MAC drops it: 00 and 01.
            b'\tnop\x8d\r\n\tinx\tb\r\n',
            b'\tdb\t1 ;x\x8d\r\n\tdb\t3\r\n',
            b'\tdb\t1\x8d;c\r\n\tdb\t3\r\n',
            # The LF after it is the LF, so a line that starts with 8AH
            # starts with a LF (M80 and um80 without --dri: 00 03).
            b'\tnop\r\n\x8a\tinx\tb\r\n',
            # `MVI' is the LF, and `B,2' no statement (MAC: 3E 01 03, S).
            b'lab:\tmvi\ta,1 ;load\x8d\tmvi\tb,2\r\n\tdb\t3\r\n']:
        ok, _, errors = _assemble(src + b'\tend\r\n', dri=True)
        assert not ok, src
        ok, _, errors = _assemble(src.replace(b'\x8d', b'').replace(b'\x8a', b'')
                                  + b'\tend\r\n', dri=True)
        assert ok, (src, errors)


# An 8AH in the arguments of a macro call, or the list of an IRP or IRPC, is
# a LF there, which MAC and RMAC pass on as text: with a body of `DB '&P''
# it is the byte 0AH (um80 --dri reported it).  M80 leaves it out.  The
# bytes are MAC's, RMAC's and M80's under cpmemu, before a `DB 9'.
MM = b"mm\tmacro\tp\r\n\tdb\t'&p'\r\n\tendm\r\n"
ARG_8AH = [
    (MM + b'\tmm\tA\x8aB\r\n', '410a42', '4142'),
    (MM + b'\tmm\t<A\x8aB>\r\n', '410a42', '4142'),
    (MM + b'\tmm\t\x8aAB\r\n', '0a4142', '4142'),
    (b"mm\tmacro\tp,q\r\n\tdb\t'&p',q\r\n\tendm\r\n\tmm\tA\x8a,2\r\n",
     '410a02', '4102'),
    (b"\tirpc\tx,A\x8aB\r\n\tdb\t'&x'\r\n\tendm\r\n", '410a42', '4142'),
    (b"\tirp\tx,<A\x8aB,C>\r\n\tdb\t'&x'\r\n\tendm\r\n", '410a4243', '414243'),
]


def test_8ah_in_a_macro_argument():
    for src, mac, m80 in ARG_8AH:
        src += b'\tdb\t9\r\n\tend\r\n'
        ok, code, errors = _assemble(src, dri=True)
        assert ok, (src, errors)
        assert code.hex() == mac + '09', src
        ok, code, errors = _assemble(src)
        assert ok, (src, errors)
        assert code.hex() == m80 + '09', src


def test_dri_source_lines():
    from um80.um80 import source_lines  # pylint: disable=import-outside-toplevel
    # Without --dri, M80's reading.
    assert source_lines(b'a ;x\x8dy b\r\nc\x8ad\r\n') == ['a ;x', 'y b', 'cd', '']
    assert source_lines(b'a ;x\x8dy b\r\nc\x8ad\r\n', dri=True) == \
        ['a ;x', ' b', 'c\nd', '']
    # A CR LF, a CR 8AH, an 8DH 8AH and a LF alone end a line, as before.
    assert source_lines(b'a\r\nb\r\x8ac\x8d\x8ad\ne\x1af', dri=True) == \
        ['a', 'b', 'c', 'd', 'e']
    # After an 8DH, the CR of the line end is the LF, and the next line
    # starts with its LF.
    assert source_lines(b'a\x8d\r\nb\r\nc', dri=True) == ['a', '\nb', 'c']
    # Where no 8AH or 8DH is inside a line, MAC's reading is M80's.
    from um80.um80 import mac_source_lines  # pylint: disable=import-outside-toplevel
    for data in (b'a\r\nb\r\x8ac\nd\re\r\r\nf\xc1\r\n\x00\x00',
                 b'a\r\n\x00b\x00\x00', b'\r\n', b''):
        assert mac_source_lines(data) == source_lines(data) == \
            source_lines(data, dri=True), data
