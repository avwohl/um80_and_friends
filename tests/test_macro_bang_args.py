"""Macro arguments vs. the DRI '!' multi-statement extension (issue #3).

um80 started as an M80-compatible assembler, where '!' in a macro-call
argument list quotes the following character (so a name like ``!CF`` is written
``!!CF`` and a literal comma is written ``!,``). Later it gained Digital
Research's '!' multi-statement-line separator. The two collide on a macro-call
line: ``head STORECF,3,!!CF,docolon`` must NOT be split on '!', and the escaped
comma in ``head COMMA,1,!,,docode`` must stay part of one argument.

M80 macro semantics win on a macro-call line: '!' is the argument quote
operator there, never a statement separator.
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _assemble(source):
    """Assemble source text; return the Assembler so callers can read errors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "test.mac")
        with open(src_path, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(src_path)
        return asm, ok


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
        return bytes(linker.output)


# --- argument resolution unit tests -----------------------------------------

def _resolve_args(asm, operands):
    raw = asm.split_operands(operands, escape_bang=True)
    return [asm.process_macro_argument(arg) for arg in raw]


def test_escaped_bang_in_argument():
    """``!!CF`` is a single argument resolving to the literal name ``!CF``."""
    asm = Assembler()
    assert _resolve_args(asm, "STORECF,3,!!CF,docolon") == \
        ["STORECF", "3", "!CF", "docolon"]


def test_escaped_comma_is_not_a_separator():
    """``!,`` is an escaped comma: one argument with value ``,``, not a split."""
    asm = Assembler()
    assert _resolve_args(asm, "COMMA,1,!,,docode") == \
        ["COMMA", "1", ",", "docode"]


def test_escaped_comma_embedded_in_name():
    """Escaped commas combine with surrounding text (e.g. ``C,`` and ``,CF``)."""
    asm = Assembler()
    assert _resolve_args(asm, "CSTORE,2,C!,,docode") == \
        ["CSTORE", "2", "C,", "docode"]
    assert _resolve_args(asm, "X,3,!,CF,docolon") == \
        ["X", "3", ",CF", "docolon"]


def test_bare_bang_name():
    """``!!`` resolves to the single literal character ``!``."""
    asm = Assembler()
    assert _resolve_args(asm, "BANG,1,!!,docolon") == \
        ["BANG", "1", "!", "docolon"]


def test_escape_bang_off_by_default():
    """Without escape_bang, '!' is just an ordinary character (instruction path)."""
    asm = Assembler()
    # An escaped comma would otherwise split here; with the flag off it does.
    assert asm.split_operands("A,!,B") == ["A", "!", "B"]


# --- end-to-end assembly tests ----------------------------------------------

# Camel-FORTH-style header macro, written exactly as in the bug report: a
# lowercase &name concatenation referencing an (upper-cased) parameter.
HEAD_MACRO = """\
        .Z80
docolon EQU 1
docode  EQU 0
        ASEG
        ORG 100H
head    MACRO  label,length,name,action
        DB length,"&name"
label:
        ENDM
"""


def test_macro_call_not_split_on_bang():
    """The reported failure: a macro call with ``!!CF`` no longer errors."""
    src = HEAD_MACRO + "    head STORECF,3,!!CF,docolon\n        END\n"
    asm, ok = _assemble(src)
    assert ok, f"Assembly failed: {asm.errors}"
    assert asm.errors == [], asm.errors


def test_macro_names_with_bang_and_comma_emit_correctly():
    """Names ``!CF`` and ``,`` reach the macro body intact and are emitted."""
    src = HEAD_MACRO + (
        "    head STORECF,3,!!CF,docolon\n"
        "    head COMMA,1,!,,docode\n"
        "        END\n"
    )
    out = _assemble_and_link(src)
    # head STORECF,3,!!CF  ->  DB 3,"!CF"  ->  03 '!' 'C' 'F'
    assert bytes([3, ord('!'), ord('C'), ord('F')]) in out
    # head COMMA,1,!,      ->  DB 1,","    ->  01 ','
    assert bytes([1, ord(',')]) in out


def test_lowercase_ampersand_param_substitution():
    """A lowercase ``&name`` substitutes its parameter and drops the ``&``.

    Parameter names fold case in M80, so ``&name`` must match the (upper-cased)
    parameter ``name``; a case-sensitive match would leave a stray ``&`` byte in
    the output.
    """
    src = HEAD_MACRO + "    head DUP,3,DUP,docolon\n        END\n"
    out = _assemble_and_link(src)
    # DB 3,"DUP"  ->  03 'D' 'U' 'P'  with no leading '&' (0x26) byte.
    assert bytes([3, ord('D'), ord('U'), ord('P')]) in out
    assert bytes([3, ord('&')]) not in out


def test_dri_multistatement_still_works():
    """A non-macro line is still split on '!' (DRI extension preserved)."""
    src = """\
        .Z80
        ASEG
        ORG 100H
        INC A ! INC B ! INC C
        END
"""
    out = _assemble_and_link(src)
    # INC A=3C, INC B=04, INC C=0C emitted as three consecutive instructions.
    assert out[0:3] == bytes([0x3C, 0x04, 0x0C])
