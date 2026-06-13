"""M80 '&' macro parameter concatenation operator.

In M80 macros, '&' concatenates a parameter with adjacent text and is removed
during expansion. It may appear before the parameter (``&name``), after it
(``name&suffix``), or between two parameters (``a&b``, where the single '&' is
shared). Parameter names fold case. A '&' that is not adjacent to a parameter
(e.g. a literal ``&`` inside a string) is left untouched.
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _assemble_and_link(source, code_base=0x0100):
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "test.mac")
        with open(src_path, "w") as f:
            f.write(source)
        asm = Assembler()
        assert asm.assemble(src_path), f"Assembly failed: {asm.errors}"
        rel_path = os.path.join(tmpdir, "test.rel")
        with open(rel_path, "wb") as f:
            f.write(asm.output.get_bytes())
        linker = Linker()
        linker.code_base = code_base
        linker.load_rel(rel_path)
        assert linker.link(), f"Link failed: {linker.errors}"
        return asm, bytes(linker.output)


def test_leading_ampersand_in_string():
    """``&name`` inside a string substitutes and drops the '&' (issue #3)."""
    src = """\
        .Z80
        ASEG
        ORG 100H
mk      MACRO  name
        DB "&name"
        ENDM
        mk ABC
        END
"""
    _, out = _assemble_and_link(src)
    assert out[0:3] == b"ABC"
    assert ord('&') not in out


def test_trailing_ampersand_in_string_is_literal():
    """Inside a string, trailing ``pfx&_x`` does NOT substitute (real M80 3.44).

    Only the leading-'&' form substitutes inside a string, so "pfx&_x" stays
    exactly "pfx&_x" (the parameter before the '&' and the '&' are literal).
    """
    src = """\
        .Z80
        ASEG
        ORG 100H
mk      MACRO  pfx
        DB "pfx&_x"
        ENDM
        mk FOO
        END
"""
    _, out = _assemble_and_link(src)
    assert out[0:6] == b"pfx&_x"


def test_trailing_ampersand_concatenation_outside_string():
    """Outside a string, ``pfx&_x`` appends literal text and drops the '&'."""
    src = """\
        .Z80
        ASEG
        ORG 100H
mk      MACRO  pfx
pfx&_x: DB 0
        ENDM
        mk FOO
        END
"""
    asm, _ = _assemble_and_link(src)
    syms = {s.upper() for s in asm.symbols}
    assert "FOO_X" in syms
    assert not any('&' in s for s in syms)


def test_trailing_ampersand_in_label():
    """``pfx&_end:`` forms the symbol FOO_END with no stray '&' in the name."""
    src = """\
        .Z80
        ASEG
        ORG 100H
mk      MACRO  pfx
pfx&_end:
        DB 0
        ENDM
        mk FOO
        END
"""
    asm, _ = _assemble_and_link(src)
    syms = {s.upper() for s in asm.symbols}
    assert "FOO_END" in syms
    assert not any('&' in s for s in syms)


def test_shared_ampersand_outside_string():
    """Outside a string, ``a&b`` concatenates both parameter values."""
    src = """\
        .Z80
        ASEG
        ORG 100H
two     MACRO  a,b
a&b:
        DB 0
        ENDM
        two FOO,BAR
        END
"""
    asm, _ = _assemble_and_link(src)
    syms = {s.upper() for s in asm.symbols}
    assert "FOOBAR" in syms
    assert not any('&' in s for s in syms)


def test_in_string_only_leading_ampersand_substitutes():
    """Inside a string only &param substitutes (verified vs real M80 3.44).

    "a&b" with a=AB, b=CD -> "aCD": the &b substitutes b and drops the '&',
    but the leading 'a' (no preceding '&') stays literal.
    """
    src = """\
        .Z80
        ASEG
        ORG 100H
two     MACRO  a,b
        DB "a&b"
        ENDM
        two AB,CD
        END
"""
    _, out = _assemble_and_link(src)
    assert out[0:3] == b"aCD"


def test_literal_ampersand_preserved():
    """A '&' not adjacent to any parameter is emitted literally."""
    src = """\
        .Z80
        ASEG
        ORG 100H
msg     MACRO  who
        DB "Tom & &who"
        ENDM
        msg JIM
        END
"""
    _, out = _assemble_and_link(src)
    # "Tom & JIM": the standalone '&' survives, the '&who' substitutes.
    assert b"Tom & JIM" in out


def test_case_insensitive_param_match():
    """A lowercase ``&name`` body reference matches an upper-cased parameter."""
    src = """\
        .Z80
        ASEG
        ORG 100H
mk      MACRO  NAME
        DB "&name"
        ENDM
        mk Q
        END
"""
    _, out = _assemble_and_link(src)
    assert out[0:1] == b"Q"
    assert ord('&') not in out
