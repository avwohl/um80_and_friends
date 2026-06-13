"""Macro expansion fixes, validated against real MACRO-80 3.44.

- EXITM inside a FALSE conditional branch is ignored (the IF/EXITM/ENDIF idiom).
- A user macro shadows a built-in instruction/pseudo-op of the same name.
- Parameter / LOCAL / % substitution does not corrupt quoted string literals.
- IF NUL <param> works when the argument is omitted (empty).
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
        return asm, bytes(linker.output)


def test_exitm_ignored_in_false_conditional():
    src = """\
\tASEG
\tORG 100H
ex\tMACRO X
\tDB 1
\tIF X
\tEXITM
\tENDIF
\tDB 2
\tENDM
\tex 0
\tex 1
\tEND
"""
    _, out = _image(src)
    # ex 0: IF false -> EXITM skipped -> DB 2 emits (01 02); ex 1: EXITM fires (01)
    assert out[0:3] == bytes([0x01, 0x02, 0x01])


def test_macro_shadows_instruction():
    src = """\
\tASEG
\tORG 100H
NOP\tMACRO
\tDB 0FFH
\tENDM
MOV\tMACRO
\tDB 0EEH
\tENDM
\tNOP
\tMOV
\tEND
"""
    _, out = _image(src)
    assert out[0:2] == bytes([0xFF, 0xEE])


def test_percent_does_not_corrupt_string():
    src = """\
\tASEG
\tORG 100H
pct\tMACRO
\tDB '100%'
\tENDM
\tpct
\tEND
"""
    asm, out = _image(src)
    assert out[0:4] == b"100%"
    assert asm.errors == []


def test_local_not_substituted_in_string():
    src = """\
\tASEG
\tORG 100H
loc\tMACRO
\tLOCAL LBL
LBL:\tDB 'LBL'
\tJMP LBL
\tENDM
\tloc
\tEND
"""
    _, out = _image(src)
    # 'LBL' string stays 3 bytes; the JMP target is the renamed local label.
    assert out[0:3] == b"LBL"
    assert out[3] == 0xC3  # JMP
    # JMP operand points back at the label (0x0100), not corrupted.
    assert out[4] | (out[5] << 8) == 0x0100


def test_param_not_substituted_in_string():
    src = """\
\tASEG
\tORG 100H
prm\tMACRO C
\tDB 'C'
\tENDM
\tprm X
\tEND
"""
    _, out = _image(src)
    assert out[0:1] == b"C"  # literal 'C', not the argument X


def test_param_substituted_in_string_with_ampersand():
    # The Camel-FORTH idiom: &param inside a string DOES substitute.
    src = """\
\tASEG
\tORG 100H
prm\tMACRO C
\tDB '&C'
\tENDM
\tprm X
\tEND
"""
    _, out = _image(src)
    assert out[0:1] == b"X"


def test_nul_with_omitted_argument():
    src = """\
\tASEG
\tORG 100H
m\tMACRO X
\tIF NUL X
\tDB 1
\tELSE
\tDB 2
\tENDIF
\tENDM
\tm
\tm Q
\tEND
"""
    asm, out = _image(src)
    assert asm.errors == []
    assert out[0:2] == bytes([0x01, 0x02])
