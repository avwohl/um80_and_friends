"""A LOCAL after a `!' in a macro body.

A LOCAL is a statement like any other: `NOP! LOCAL QQ', `LOCAL QQ! NOP'
and `NOP! LOCAL QQ! NOP' declare QQ in DRI's MAC 2.0 and RMAC 1.1, and so do
`LOCAL QQ ;c! NOP', `NOP ;c! LOCAL QQ' and `MM ;c! LOCAL QQ', where a `!'
ends the comment.  um80 read a body line for its first statement only, so
QQ was not local and the second expansion said "QQ multiply defined" (and
`LOCAL QQ! NOP' took `QQ! NOP' for the name).  MACRO-80 3.44 has no `!'
separator: it reads `LOCAL QQ! NOP' as LOCAL QQ, clean, and the rest of the
line not at all; um80 reads the `!' in either mode (EXTENSIONS.md), and
without --dri a `;' comment runs to the end of the line, as in M80.

Each body is expanded twice after `QQ: DB 1 / DW QQ'.  The expected bytes
are MAC's and RMAC's under cpmemu.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, **kw):
    """(ok, code bytes, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE') if ok else b''
    return ok, code, [str(e) for e in asm.errors]


def _source(line, pre=''):
    return (pre + "mm\tmacro\n" + line + "qq:\tdb\t1\n\tdw\tqq\n\tendm\n"
            "\taseg\n\torg\t100h\n\tmm\n\tmm\n\tend\n")


M2 = "m2\tmacro\n\tdb\t7\n\tendm\n"


# (body line, what precedes the macro, MAC's bytes, um80's without --dri)
@pytest.mark.parametrize('line,pre,mac,m80', [
    ("\tnop! local qq\n", '', '0001010100010501', '0001010100010501'),
    ("\tlocal qq! nop\n", '', '0001010100010501', '0001010100010501'),
    ("\tlocal qq,rr! nop\n", '', '0001010100010501', '0001010100010501'),
    ("\tlocal rr! local qq\n", '', '010001010301', '010001010301'),
    ("\tnop! local qq! nop\n", '', '00000102010000010701', '00000102010000010701'),
    # A `!' ends a comment with --dri, as in MAC; without, the comment runs
    # to the end of the line, as in M80.
    ("\tlocal qq ;c! nop\n", '', '0001010100010501', '010001010301'),
    ("\tnop ;c! local qq\n", '', '0001010100010501', None),
    ("\tm2 ;c! local qq\n", M2, '0701010107010501', None),
])
def test_local_after_a_bang(line, pre, mac, m80):
    ok, code, errors = _assemble(_source(line, pre), dri=True)
    assert ok, errors
    assert code.hex() == mac
    ok, code, errors = _assemble(_source(line, pre))
    if m80 is None:
        # M80: QQ multiply defined (M), as the LOCAL is in the comment.
        assert not ok
        assert any("Symbol 'QQ' multiply defined" in e for e in errors), errors
    else:
        assert ok, errors
        assert code.hex() == m80


def test_a_line_of_locals_only_is_not_assembled():
    # As before: `LOCAL QQ' alone, and `LOCAL QQ ;c' without --dri.
    for dri in (False, True):
        ok, code, errors = _assemble(_source("\tlocal qq\n\tlocal rr! local ss\n"),
                                     dri=dri)
        assert ok, errors
        assert code.hex() == '010001010301'


# A LOCAL declares its names for what follows it: the statements after it on
# the line and the lines after it.  A statement before it on the line reads
# the name as it was, in MAC and RMAC, which read a LOCAL as they come to it.
# um80 declared the names for the whole line, so that statement read the
# local name, without a word.  Each body is expanded twice (once for the
# label); the bytes are MAC's and RMAC's under cpmemu, which flag none of
# them, and M80's for the first two, which it flags O (it has no `!'
# separator).  um80 reads the `!' in either mode.
@pytest.mark.parametrize('pre,body,calls,mac', [
    ("qq\tequ\t7\n", "\tlxi\th,qq! local qq\nqq:\tdb\t5\n", 2,
     '2107000521070005'),
    ("qq\tequ\t7\n", "\tjmp\tqq! local qq\nqq:\tnop\n", 2, 'c3070000c3070000'),
    ("qq\tequ\t7\n", "\tmvi\ta,qq! local qq! lxi h,qq\nqq:\tdb\t5\n", 2,
     '3e07210501053e07210b0105'),
    ("rr\tequ\t9\n",
     "\tlxi\th,rr! local qq! local rr! lxi d,qq\nqq:\tdb\t5\nrr:\tdb\t6\n", 2,
     '2109001106010506210900110e010506'),
    ('', "qq:\tnop! local qq\nqq:\tdb\t5\n\tlxi\th,qq\n", 1, '0005210101'),
])
def test_a_local_after_a_bang_is_not_read_before_it(pre, body, calls, mac):
    source = (pre + "mm\tmacro\n" + body + "\tendm\n\taseg\n\torg\t100h\n"
              + "\tmm\n" * calls + "\tend\n")
    for dri in (True, False):
        ok, code, errors = _assemble(source, dri=dri)
        assert ok, (dri, errors)
        assert code.hex() == mac, dri


@pytest.mark.parametrize('body,error', [
    # MAC and RMAC: U, as QQ is not local yet (M80: O, and QQ M).
    ("\tlxi\th,qq! local qq\nqq:\tdb\t5\n", "Undefined symbol 'QQ'"),
    ("\tdw\tqq! local qq\nqq:\tdb\t5\n", "Undefined symbol 'QQ'"),
    # MAC and RMAC: P, the label QQ defined twice (M80: M).
    ("qq:\tnop! local qq\n\tlxi\th,qq\n", "Symbol 'QQ' multiply defined"),
    ("qq:\tnop! local qq\nqq:\tdb\t5\n\tlxi\th,qq\n", "Symbol 'QQ' multiply defined"),
])
def test_a_name_read_before_its_local_on_the_line(body, error):
    source = "mm\tmacro\n" + body + "\tendm\n\taseg\n\torg\t100h\n\tmm\n\tmm\n\tend\n"
    for dri in (True, False):
        ok, _, errors = _assemble(source, dri=dri)
        assert not ok, dri
        assert any(error.upper() in e.upper() for e in errors), (dri, errors)


# With --dri a LOCAL that MAC and RMAC leave out after a macro call
# (_dri_macro_call()) declares nothing: in `NN! LOCAL QQ', with NN a macro
# of no parameters, the `!' is text of the call and the rest of the line is
# left out, as it is in `NOP! NN! LOCAL QQ'.  um80 --dri warned that the
# LOCAL was left out, but made QQ local all the same (09 01 01 01 09 01 05
# 01), where MAC and RMAC flag the second QQ P.  Expanded once, QQ is the
# label outside the macro in both (MAC: 09 01 01 01).
NN = "nn\tmacro\n\tdb\t9\n\tendm\n"


@pytest.mark.parametrize('line', ["\tnn! local qq\n", "\tnop! nn! local qq\n"])
def test_dri_a_local_left_out_after_a_macro_call(line):
    ok, _, errors = _assemble(_source(line, NN), dri=True)
    assert not ok
    assert any("Symbol 'QQ' multiply defined" in e for e in errors), errors


def test_dri_a_local_left_out_after_a_macro_call_expanded_once():
    source = (NN + "mm\tmacro\n\tnn! local qq\nqq:\tdb\t1\n\tdw\tqq\n\tendm\n"
              "\taseg\n\torg\t100h\n\tmm\n\tend\n")
    asm = Assembler(dri=True)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(source)
        assert asm.assemble(p), asm.errors
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE')
    assert code.hex() == '09010101'
    assert any("'local qq' after a macro call is left out" in w.lower()
               for w in asm.warnings), asm.warnings
