"""The first word of a statement: an operation, a label, or a value.

MACRO-80 3.44 has no label without a colon, in column 1 or not.  The first
word of a statement (after a `LABEL:', and but for the name in front of an
EQU, SET, DEFL, ASET or MACRO) is its operation, and one that is not an
instruction, directive or macro starts a list of values that M80 assembles
as a DB: after `FOO EQU 5', `FOO' alone is the byte 05, and `LAB DS 1' is
U (LAB is not defined) and one byte.  um80 took any word in column 1 for a
label, even an instruction or a directive, so `NOP', `RET', `END' or `DB 7'
there assembled nothing, without a word, and an ENDM or LOCAL in column 1 was
never seen.  A statement that starts with a value (`LAB: 5,6') was left out.

DRI's MAC 2.0 and RMAC 1.1 (--dri) take a word that is not an instruction,
directive or macro for a label, colon or not, in any column; they ignore a
line number in front of a statement, a line that starts with `*', and MAC's
assembly controls ($-MACRO).

The expected bytes are what the genuine M80 3.44 (the .REL fixture) and MAC
and RMAC assemble from the same source under cpmemu.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, **kw):
    """(ok, REL items or None, error messages, warnings)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        items = RELReader(asm.output.get_bytes()).read_all() if ok else None
    return ok, items, [str(e) for e in asm.errors], asm.warnings


def _loaded(items):
    """[(address, byte)] of every absolute byte loaded."""
    out, loc = [], 0
    for it in items:
        if it[0] == 'SET_LOC':
            loc = it[1][1]
        elif it[0] == 'ABSOLUTE_BYTE':
            out.append((loc, it[1]))
            loc += 1
        elif it[0] in ('PROGRAM_REL', 'DATA_REL', 'COMMON_REL'):
            loc += 2
    return out


COLUMN_ONE = (
    "nop\nret\nxchg\nmvi\ta,5\ndb\t7\ndw\t1234h\nds\t2\n\tdb\t0aah\n"
    "mm\tmacro\n\tdb\t9\n\tendm\nmm\n"
    "rept\t2\n\tdb\t1\nendm\n"
    "if\t1\n\tdb\t2\nelse\n\tdb\t3\nendif\n"
    "mm2\tmacro\nlocal\tq\nq:\tdb\t8\n\tendm\n\tmm2\n"
    "$title\t('subtitle')\n$eject\n*eject\n\tend\n")
M80_COLUMN_ONE = bytes.fromhex(
    '8455250000135100000325d63e0281c68129685002a81201008081138000009e1a')


def test_operations_in_column_one_as_m80():
    # M80: 00 C9 EB 3E 05 07 34 12, two bytes reserved, AA 09 01 01 02 08,
    # with no error.  MAC and RMAC assemble the same bytes (and flag the
    # $TITLE, M80's).  um80 0.3.50 assembled AA alone, and took everything
    # after the REPT for its body.
    ok, items, errors, _ = _assemble(COLUMN_ONE)
    assert ok, errors
    m80 = _loaded(RELReader(M80_COLUMN_ONE).read_all())
    assert _loaded(items) == m80
    assert bytes(b for _, b in m80).hex() == '00c9eb3e0507341' + '2aa090101' + '0208'
    assert m80[8][0] == 0x0A


def test_same_with_dri():
    ok, items, errors, _ = _assemble(COLUMN_ONE, dri=True)
    assert ok, errors
    assert _loaded(items) == _loaded(RELReader(M80_COLUMN_ONE).read_all())


VALUES = "foo\tequ\t5\nfoo\n\tfoo+1,'AB'\nlab:\t5,6\n\t-1\n\t(3)\n\tend\n"
M80_VALUES = bytes.fromhex('8455250000135080002818824202819fe039c000009e1a')


def test_a_statement_of_values_is_a_db_as_m80():
    # M80: 05 06 41 42 05 06 FF 03, no error.  um80 assembled nothing (and
    # took the second FOO for a label, defined twice).  It warns.
    ok, items, errors, warnings = _assemble(VALUES)
    assert ok, errors
    assert _loaded(items) == _loaded(RELReader(M80_VALUES).read_all())
    assert bytes(b for _, b in _loaded(items)).hex() == '0506414205' + '06ff03'
    assert len(warnings) == 5 and all('as DB' in w for w in warnings), warnings


@pytest.mark.parametrize('line,why', [
    ('foo\tnop', 'a label needs a colon'),          # M80: U, and one byte
    ('obp\tds\t1', 'a label needs a colon'),        # GENHEX.ASM; M80: U
    ('\tfoo\tnop', 'a label needs a colon'),        # M80: U
    ('foo', 'a label needs a colon'),               # M80: U
    ('* a comment', "'*' comment lines"),           # M80: U
    ('10\tnop', 'line numbers'),                    # M80: O
    ('foo\tbar', 'Unknown instruction or directive: FOO'),
])
def test_m80_has_no_label_without_a_colon(line, why):
    ok, _, errors, _ = _assemble(f"{line}\n\tdb\t1\n\tend\n")
    assert not ok
    assert len(errors) == 1 and why in errors[0], errors


DRI = ("foo\tnop\n\tbar\tnop\nbaz\n10\tnop\n00020 qux:\tret\n"
       "halt\tlxi\th,1\nlist\tjmp\t0\n* a comment ! nop\n$-macro\n"
       "\tdb\tbar-foo,baz-foo,qux-foo,halt-foo,list-foo\n\tend\n")


def test_dri_labels_line_numbers_and_comment_lines():
    # MAC 2.0 and RMAC 1.1: 00 00 00 C9 21 01 00 C3 00 00 00 01 02 03 04 07.
    # FOO, BAR, BAZ, HALT and LIST are labels (HALT is no 8080 instruction,
    # and LIST no directive, of MAC's or um80's); 10 and 00020 are line
    # numbers; `*' starts a comment line, which the `!' still ends; $-MACRO
    # is a MAC control (RMAC flags it S).
    ok, items, errors, _ = _assemble(DRI, dri=True)
    assert ok, errors
    assert bytes(b for _, b in _loaded(items)).hex() == \
        '000000c9210100c30000' + '000102030407'


def test_a_word_in_column_one_is_not_a_label_after_z80():
    # HALT is a Z80 instruction: after .Z80 it is the instruction (M80: 76).
    ok, items, errors, _ = _assemble("\t.z80\nhalt\n\tend\n", dri=True)
    assert ok, errors
    assert bytes(b for _, b in _loaded(items)) == b'\x76'


def test_name_of_an_equ_is_still_a_name():
    # M80 takes an instruction's name for the name of an EQU or SET: `NOP
    # EQU 5' then `DB NOP' is 05 (MAC flags S).
    ok, items, errors, _ = _assemble("nop\tequ\t5\n\tdb\tnop\nx\tset\t3\n\tdb\tx\n\tend\n")
    assert ok, errors
    assert bytes(b for _, b in _loaded(items)) == b'\x05\x03'


def test_an_instruction_of_the_other_processor_is_reported_at_once():
    # Every one of them, from the first time through, not only in pass 2
    # (where a value that does not assemble is reported): OR A, XOR A, HALT
    # and JR $ before .Z80, and MVI A,1 after it.  M80: U or O for each.
    ok, _, errors, _ = _assemble("\tor\ta\n\txor\ta\n\thalt\n\tjr\t$\n"
                                 "\t.z80\n\tmvi\ta,1\n\tend\n")
    assert not ok
    assert [e.split(': ', 1)[0] for e in errors] == [
        f'Error at line {n}' for n in (1, 2, 3, 4, 6)], errors
    assert all('Z80 instruction' in e for e in errors[:4])
    assert '8080 instruction' in errors[4]
