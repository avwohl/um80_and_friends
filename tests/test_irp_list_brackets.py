"""The <...> list of an IRP or IRPC is read the way MACRO-80 3.44 reads it.

M80 ends the list at the '>' that matches its '<' and ignores the rest of the
line; um80 dropped the first and last characters of the operand instead.  The
two differ where a macro wraps its argument in brackets and the argument is a
'>' or a '<' - mbasic2025's 4K and 8K BASIC sources build their keyword
tables with

    rdc     macro   str
            irpc    ch,<str>
            ...
    rdc     <!>>            ; the keyword '>'

The call's `!>' is a '>', so the body reads `irpc ch,<>>': M80 iterates over
nothing (the list `<>' is empty) and the keyword byte is missing, where um80
iterated over '>'.  um80 built the historic 8K BASIC; the genuine M80
assembled the source one byte short.  Now both assemble what M80 does, and
um80 warns about the '>' it ignores.

Also: a '!' in an IRP or IRPC line is not the DRI statement separator (in an
IRPC list it is an ordinary character, in an IRP list it quotes the next
character, as in a macro argument), and an unbracketed IRPC string ends at a
blank.  In an IRP list, as in a macro argument, a quoted string is text: a
'<', '>', ',' or '!' inside it is itself (`IRP M,<'Error!','A>B'>').  In an
IRPC list a quote is an ordinary character.  Every expected value was
produced by the genuine MACRO-80 3.44 under a CP/M emulator.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _asm(source):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
        assert ok, [e.message for e in asm.errors]
        return asm, asm.output.get_bytes()


def _bytes(rel):
    return bytes(it[1] for it in RELReader(rel).read_all() if it[0] == 'ABSOLUTE_BYTE')


def _irpc(lst):
    return f"\tirpc\tch,{lst}\n\tdb\t'&ch'\n\tendm\n\tdb\t0FFh\n\tend\n"


def _irp(lst):
    return f"\tirp\tx,{lst}\n\tdb\tx\n\tendm\n\tdb\t0FFh\n\tend\n"


RDC = "rdc\tmacro\tstr\n\tirpc\tch,<str>\n\tdb\t'&ch'\n\tendm\n\tendm\n"

# (source, bytes M80 3.44 assembles, whether M80 flags the line 'Q')
CASES = {
    'rdc <!>>': (RDC + "\trdc\t<!>>\n\tdb\t0FFh\n\tend\n", 'ff', False),
    'rdc <!<>': (RDC + "\trdc\t<!<>\n\tdb\t0FFh\n\tend\n", '3c3eff', True),
    'rdc <A!>B>': (RDC + "\trdc\t<A!>B>\n\tdb\t0FFh\n\tend\n", '41ff', False),
    'rdc <!!>': (RDC + "\trdc\t<!!>\n\tdb\t0FFh\n\tend\n", '21ff', False),
    'rdc <!+>': (RDC + "\trdc\t<!+>\n\tdb\t0FFh\n\tend\n", '2bff', False),
    'irpc <>>': (_irpc('<>>'), 'ff', False),
    'irpc <<>': (_irpc('<<>'), '3c3eff', True),
    'irpc <<<>': (_irpc('<<<>'), '3c3c3eff', True),
    'irpc <': (_irpc('<'), 'ff', True),
    'irpc <a>b': (_irpc('<a>b'), '61ff', False),
    'irpc <a<b>c>': (_irpc('<a<b>c>'), '613c623e63ff', False),
    'irpc <!>>': (_irpc('<!>>'), '21ff', False),
    'irpc <!a>': (_irpc('<!a>'), '2161ff', False),
    'irpc <ab!>': (_irpc('<ab!>'), '616221ff', False),
    'irpc a!b': (_irpc('a!b'), '612162ff', False),
    'irpc a b': (_irpc('a b'), '61ff', False),
    'irpc a,b': (_irpc('a,b'), '61ff', False),
    'irpc <a b>': (_irpc('<a b>'), '612062ff', False),
    'irpc <>': (_irpc('<>'), 'ff', False),
    'irp <1!,2,3>': (_irp('<1!,2,3>'), '010203ff', False),
    'irp <1,2>,3': (_irp('<1,2>,3'), '0102ff', False),
    'irp <1,2>>': (_irp('<1,2>>'), '0102ff', False),
    'irp <1,<2,3>>': (_irp('<1,<2,3>>'), '010203ff', False),
    'irp <1,2': (_irp('<1,2'), '0102ff', True),
}


@pytest.mark.parametrize('name', list(CASES))
def test_list_as_m80_reads_it(name):
    source, expect, _ = CASES[name]
    _, rel = _asm(source)
    assert _bytes(rel).hex() == expect


@pytest.mark.parametrize('name', [n for n, c in CASES.items() if c[2]])
def test_unclosed_list_warns(name):
    """Where M80 flags the list 'Q' (no closing '>'), um80 warns."""
    asm, _ = _asm(CASES[name][0])
    assert any("no closing '>'" in w for w in asm.warnings), asm.warnings


def test_text_after_list_warns():
    """M80 says nothing about the '>' it ignores; um80 does."""
    asm, _ = _asm(CASES['rdc <!>>'][0])
    assert any("'>' after it is ignored" in w for w in asm.warnings), asm.warnings
    asm, _ = _asm(CASES['irpc <>'][0])
    assert not asm.warnings


def test_mbasic2025_keyword_table():
    """8K BASIC's `rdc <!>>' / `rdc <!=>' / `db '<'+80h', as M80 builds it.

    The '>' keyword is lost (the source wants BE BD BC); mbasic2025 has to
    write that one `db '>'+80h', as it already does the '<'.
    """
    rdc = ("rdc\tmacro\tstr\n\tlocal\tfirst\nfirst\tset\t1\n\tirpc\tch,<str>\n"
           "\tif\tfirst\n\tdb\t'&ch' + 80h\nfirst\tset\t0\n\telse\n\tdb\t'&ch'\n"
           "\tendif\n\tendm\n\tendm\n")
    _, rel = _asm(rdc + "\trdc\t<!>>\n\trdc\t<!=>\n\tdb\t'<'+80h\n\trdc\t<SGN>\n\tend\n")
    assert _bytes(rel).hex() == 'bdbcd3474e'
    _, rel = _asm(rdc + "\tdb\t'>'+80h\n\trdc\t<!=>\n\tdb\t'<'+80h\n\trdc\t<SGN>\n\tend\n")
    assert _bytes(rel).hex() == 'bebdbcd3474e'


# A quoted string in an IRP list or a macro argument, as M80 3.44 reads it:
# the brackets, commas and '!' inside it are text.  um80 0.3.49 kept those,
# except that it dropped a '!' in a macro argument; the first fix of the
# bracket matching counted a '>' inside a string and dropped every '!'.
MM = "mm\tmacro\tq\n\tdb\tq\n\tendm\n"
MM2 = "mm\tmacro\tp,q\n\tdb\tp,q\n\tendm\n"
LST = "lst\tmacro\tl\n\tirp\tx,<l>\n\tdb\tx\n\tendm\n\tendm\n"
STRING_CASES = {
    "irp <'Hi!'>": (_irp("<'Hi!'>"), '486921ff'),
    'irp <"Hi!">': (_irp('<"Hi!">'), '486921ff'),
    "irp <'!'>": (_irp("<'!'>"), '21ff'),
    "irp <'a>b'>": (_irp("<'a>b'>"), '613e62ff'),
    'irp <"a>">': (_irp('<"a>">'), '613eff'),
    "irp <'>'>": (_irp("<'>'>"), '3eff'),
    "irp <'<',2>": (_irp("<'<',2>"), '3c02ff'),
    "irp <'a!>b'>": (_irp("<'a!>b'>"), '61213e62ff'),
    "irp <'a!,b',3>": (_irp("<'a!,b',3>"), '61212c6203ff'),
    "irp <<'a>b'>,2>": (_irp("<<'a>b'>,2>"), '613e6202ff'),
    "irp <'it''s'>": (_irp("<'it''s'>"), '69742773ff'),
    "irp <'Error!','Ok'>": (_irp("<'Error!','Ok'>"), '4572726f72214f6bff'),
    # The list is a and a quote; um80 warns about the 'b> it ignores.
    "irpc <a'>'b>": ("\tirpc\tc,<a'>'b>\n\tdb\t1\n\tendm\n\tdb\t0FFh\n\tend\n", '0101ff'),
    "irpc <'!'>": ("\tirpc\tc,<'!'>\n\tdb\t1\n\tendm\n\tdb\t0FFh\n\tend\n", '010101ff'),
    "mm <'Hi!'>": (MM + "\tmm\t<'Hi!'>\n\tend\n", '486921'),
    "mm 'Hi!'": (MM + "\tmm\t'Hi!'\n\tend\n", '486921'),
    "mm <'a!'>": (MM + "\tmm\t<'a!'>\n\tend\n", '6121'),
    "mm 'a!',2": (MM2 + "\tmm\t'a!',2\n\tend\n", '612102'),
    'mm <"x!y">': (MM + '\tmm\t<"x!y">\n\tend\n', '782179'),
    "mm <'a>b'>": (MM + "\tmm\t<'a>b'>\n\tend\n", '613e62'),
    "lst <'Hi!','a>b'>": (LST + "\tlst\t<'Hi!','a>b'>\n\tdb\t0FFh\n\tend\n",
                          '486921613e62ff'),
}


@pytest.mark.parametrize('name', list(STRING_CASES))
def test_quoted_string_is_text(name):
    """M80's bytes for a quoted string in an IRP list or a macro argument."""
    source, expect = STRING_CASES[name]
    asm, rel = _asm(source)
    assert _bytes(rel).hex() == expect
    assert not asm.warnings or name.startswith('irpc <a'), asm.warnings

