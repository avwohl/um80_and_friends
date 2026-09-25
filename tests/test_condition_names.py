"""A symbol named like a condition is JP's address.

In Z80 code `JP P' is a condition with no address, which um80 rejects.  But
a program may have a label P, and M80 3.44 then reads `JP P' as a jump to
it (C3), as it reads `JP Z', `JP NZ', `JP PE' and `JP PO' after such
labels.  um80 stopped with "JP with condition requires address", so uplm80
wrote `JP 0+P' for a jump to its procedure P.  (`JR Z' and `CALL Z', with
one operand, already took Z for the address.)

The fixture is the .REL file M80 3.44 writes for the same source.
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
        items = RELReader(asm.output.get_bytes()).read_all() if ok else None
    return ok, items, [str(e) for e in asm.errors]


def _fields(items):
    out = []
    for it in items:
        if it[0] == 'ABSOLUTE_BYTE':
            out.append(f'{it[1]:02X}')
        elif it[0] == 'PROGRAM_REL':
            out.append(f'P{it[1]:04X}')
    return out


LABELS = ("\t.z80\np:\tnop\n\tjp\tp\nz:\tnop\n\tjr\tz\n\tjp\tz\n\tcall\tz\n"
          "nz:\tnop\n\tjp\tnz\npe:\tjp\tpe\npo:\tjp\tpo\n\tend\n")
M80_LABELS = bytes.fromhex('845525000013517000030e800000030fd61d040066d04000030e868030e888'
                           '030e8a004e0000009e1a')


def test_a_label_named_like_a_condition_as_m80():
    ok, items, errors = _assemble(LABELS)
    assert ok, errors
    assert _fields(items) == _fields(RELReader(M80_LABELS).read_all())
    assert ' '.join(_fields(items)) == ('00 C3 P0000 00 18 FD C3 P0004 CD P0004 00 C3 P000D'
                                        ' C3 P0011 C3 P0014')


def test_defined_further_down():
    # M80 gets this one wrong (P, a phase error: its pass 1 took `JP NC'
    # for a one-byte instruction), and jumps to 18H.
    ok, items, errors = _assemble("\t.z80\n\tjp\tnc\n\tnop\nnc:\tnop\n\tend\n")
    assert ok, errors
    assert _fields(items) == ['C3', 'P0004', '00', '00']


def test_a_condition_with_no_such_symbol_is_still_an_error():
    ok, _, errors = _assemble("\t.z80\n\tjp\tp\n\tend\n")
    assert not ok
    assert any('JP with condition requires address' in e for e in errors), errors
