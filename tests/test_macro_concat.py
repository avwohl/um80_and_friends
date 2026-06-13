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


def test_trailing_ampersand_concatenation():
    """``pfx&_x`` appends literal text to the parameter and drops the '&'."""
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
    assert out[0:5] == b"FOO_x"
    assert ord('&') not in out


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


def test_shared_ampersand_between_two_params():
    """``a&b`` concatenates both parameters' values, consuming the single '&'."""
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
    assert out[0:4] == b"ABCD"
    assert ord('&') not in out


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
