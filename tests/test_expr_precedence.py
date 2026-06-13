"""Expression operator precedence, validated against real MACRO-80 3.44.

M80 precedence (lowest binding first): OR/XOR < AND < NOT < relational
(EQ/NE/LT/LE/GT/GE) < binary +/- < unary +/- < * / MOD SHL SHR < HIGH/LOW.

Previously the unary operators (NOT, unary minus, HIGH/LOW) were evaluated at
the top of parse_expression, giving them the LOWEST precedence, so e.g.
-2+3 wrongly computed -(2+3). Each expected value below was confirmed by
assembling the same source with the genuine M80 binary under cpmemu.
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _image(body):
    source = "\tASEG\n\tORG 100H\n" + body + "\tEND\n"
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


def _db(expr):
    return _image(f"\tDB {expr}\n")[0]


def _dw(expr):
    out = _image(f"\tDW {expr}\n")
    return out[0] | (out[1] << 8)


def test_unary_minus_binds_tighter_than_add():
    assert _db("-2+3") == 0x01          # (-2)+3 = 1


def test_minus_after_binary_operator_is_unary():
    assert _db("3*-2 AND 0FFH") == 0xFA  # 3*(-2) = -6
    assert _db("5--3") == 0x08           # 5-(-3) = 8
    assert _db("1+-2") == 0xFF           # 1+(-2) = -1


def test_not_binds_tighter_than_and_or():
    assert _db("NOT 1 AND 2") == 0x02    # (NOT 1) AND 2 = 2
    assert _db("NOT 0 OR 1") == 0xFF     # (NOT 0) OR 1 = 0FFFFH


def test_not_binds_looser_than_relational():
    assert _db("NOT 1 EQ 0") == 0xFF     # NOT (1 EQ 0) = NOT 0 = 0FFFFH


def test_relational_binds_looser_than_add():
    assert _dw("1+1 EQ 2") == 0xFFFF     # (1+1) EQ 2 = true


def test_unary_minus_binds_tighter_than_relational():
    assert _db("LOW (-1 GT 1)") == 0xFF  # (-1) GT 1 unsigned = true


def test_high_low_bind_tightest():
    assert _dw("HIGH(1234H)+LOW(5678H)") == 0x008A   # 12H + 78H
    assert _db("HIGH 1234H + 1") == 0x13             # (HIGH 1234H)+1
    assert _db("HIGH 1234H * 2") == 0x24             # (HIGH 1234H)*2
    assert _db("HIGH 12H SHL 8") == 0x00             # (HIGH 12H) SHL 8 = 0


def test_shl_right_operand_unary_minus():
    assert _db("2 SHL -1 AND 0FFH") == 0x00          # 2 SHL (-1) = 0


def test_left_associative_and_parens_unchanged():
    assert _db("10-3-2") == 0x05
    assert _db("8/4/2") == 0x01
    assert _db("(1+2)*3") == 0x09
    assert _db("0FFH-1") == 0xFE
    assert _db("-5") == 0xFB


def test_high_low_function_form_followed_by_operator():
    # The DRI HIGH(..)/LOW(..) form must not swallow a trailing operator.
    assert _dw("HIGH(1234H)+LOW(5678H)") == 0x008A
    assert _db("LOW(1234H)+1") == 0x35
