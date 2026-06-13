"""Symbol redefinability class (SET vs EQU/label), verified against M80 3.44.

A symbol's class is fixed by its first definition: SET/DEFL/ASET symbols are
redefinable only by SET/DEFL/ASET, and EQU/label symbols are not redefinable.
Cross-class redefinition is a multiply-defined error. Same-class redefinition
keeps its existing value-driven rule (EQU to the same value is allowed).
"""

import os
import tempfile

from um80.um80 import Assembler


def _run(source):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "t.mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler()
    ok = asm.assemble(p)
    return asm, ok


def _err(asm):
    return any("multiply defined" in str(e) for e in asm.errors)


def test_set_then_equ_is_error():
    asm, ok = _run("\tASEG\n\tORG 100H\nY\tSET 1\nY\tEQU 2\n\tEND\n")
    assert not ok and _err(asm)


def test_equ_then_set_is_error():
    asm, ok = _run("\tASEG\n\tORG 100H\nX\tEQU 1\nX\tSET 2\n\tEND\n")
    assert not ok and _err(asm)


def test_set_then_set_ok():
    asm, ok = _run("\tASEG\n\tORG 100H\nZ\tSET 1\nZ\tSET 2\n\tEND\n")
    assert ok, asm.errors


def test_equ_same_value_ok():
    asm, ok = _run("\tASEG\n\tORG 100H\nF\tEQU 5\nF\tEQU 5\n\tEND\n")
    assert ok, asm.errors


def test_equ_different_value_is_error():
    asm, ok = _run("\tASEG\n\tORG 100H\nG\tEQU 5\nG\tEQU 6\n\tEND\n")
    assert not ok and _err(asm)


def test_label_redefined_same_address_ok():
    asm, ok = _run("\tASEG\n\tORG 100H\nL:\nL:\n\tDB 0\n\tEND\n")
    assert ok, asm.errors


def test_label_then_equ_different_is_error():
    asm, ok = _run("\tASEG\n\tORG 100H\nL:\tDB 0\nL\tEQU 5\n\tEND\n")
    assert not ok and _err(asm)
