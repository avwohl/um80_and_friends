"""REPT/IRP/IRPC fixes, validated against real MACRO-80 3.44.

- A directly nested REPT/IRP/IRPC block is no longer dropped.
- IRP over <<1,2>,<3,4>> splits into two items (not four) and strips one
  bracket level per item on substitution.
- EXITM terminates the current REPT/IRP/IRPC expansion.
- An empty IRP list <> still iterates once with an empty argument (M80).
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _image(source):
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "t.mac")
        with open(src_path, "w") as f:
            f.write(source)
        asm = Assembler()
        assert asm.assemble(src_path), f"Assembly failed: {asm.errors}"
        rel_path = os.path.join(tmpdir, "t.rel")
        with open(rel_path, "wb") as f:
            f.write(asm.output.get_bytes())
        linker = Linker()
        linker.code_base = 0x0100
        linker.load_rel(rel_path)
        assert linker.link(), f"Link failed: {linker.errors}"
        return bytes(linker.output)


def test_nested_repeat_not_dropped():
    src = """\
\tASEG
\tORG 100H
\tREPT 2
\tDB 0B0H
\tREPT 2
\tDB 0AAH
\tDB 0BBH
\tENDM
\tDB 0C0H
\tENDM
\tEND
"""
    out = _image(src)
    assert out == bytes.fromhex("b0aabbaabbc0b0aabbaabbc0")


def test_irp_nested_sublists_iteration_count():
    src = """\
\tASEG
\tORG 100H
\tIRP X,<<1,2>,<3,4>>
\tDB 0FFH
\tENDM
\tEND
"""
    assert _image(src) == bytes([0xFF, 0xFF])  # two items, not four


def test_irp_nested_sublist_value_strips_one_bracket_level():
    src = """\
\tASEG
\tORG 100H
\tIRP X,<<1,2>,<3,4>>
\tDB X
\tENDM
\tEND
"""
    assert _image(src) == bytes([1, 2, 3, 4])  # DB 1,2 then DB 3,4


def test_exitm_terminates_repeat():
    src = """\
\tASEG
\tORG 100H
\tREPT 5
\tDB 0AAH
\tEXITM
\tENDM
\tEND
"""
    assert _image(src) == bytes([0xAA])  # one iteration only


def test_empty_irp_list_iterates_once():
    # Real M80 runs an empty <> list once with an empty argument.
    src = """\
\tASEG
\tORG 100H
\tDB 11H
\tIRP X,<>
\tDB 99H
\tENDM
\tDB 22H
\tEND
"""
    assert _image(src) == bytes([0x11, 0x99, 0x22])
