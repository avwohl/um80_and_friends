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
