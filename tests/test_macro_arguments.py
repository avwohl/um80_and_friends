"""How a macro call's arguments, and an IRP or IRPC list, are read.

The expected bytes are what MACRO-80 3.44 (the source with ASEG), MAC 2.0
and RMAC 1.1 assemble under cpmemu.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler

HEAD = "\taseg\n\torg\t100h\n"


def _assemble(source, **kw):
    """(ok, bytes, errors, warnings)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(HEAD + source + "\tend\n")
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE').hex() if ok else None
    return ok, code, [str(e) for e in asm.errors], asm.warnings


def _code(source, **kw):
    ok, code, errors, _ = _assemble(source, **kw)
    assert ok, errors
    return code


BOTH = pytest.mark.parametrize('dri', [False, True], ids=['m80', 'dri'])


@BOTH
def test_a_semicolon_in_brackets_is_text(dri):
    # In a macro call's arguments and an IRP list a `;' inside <...> is not
    # a comment.  DRI's CONTROL/DISKDEF.LIB passes `<;sec per track>' to a
    # macro whose body is `dw data comment'.  M80, MAC and RMAC: 01 3B 58
    # 09; 05 00 09; 31 3B 32.  um80 cut each line at the `;': 01 3C 09,
    # "Cannot parse expression: '5 <'", and 31 3C.
    assert _code("GEN\tMACRO\tA,B\n\tDB\tA\n\tDB\t'&B'\n\tENDM\n"
                 "\tGEN\t1,<;X> ; a comment\n\tDB\t9\n", dri=dri) == '013b5809'
    assert _code("DDW\tMACRO\tD,C\n\tDW\tD\t\tC\n\tENDM\n"
                 "\tDDW\t5,<;comment here>\n\tDB\t9\n", dri=dri) == '050009'
    ok, code, _, warnings = _assemble("\tIRP\tX,<1,<;>,2>\n\tDB\t'&X'\n\tENDM\n",
                                      dri=dri)
    assert ok and code == '313b32' and warnings == []


@BOTH
def test_a_semicolon_elsewhere_still_starts_a_comment(dri):
    # `IF 1<2 ;x' has no brackets: MAC reads < as LT.  And a comment after
    # a bracketed argument is a comment.
    assert _code("GEN\tMACRO\tA\n\tDB\tA\n\tENDM\n\tGEN\t<3> ;<;\n"
                 "\tDB\t1 ;<\n", dri=dri) == '0301'


# An IRPC with an empty string.  um80 stopped at `IRPC C,' with "IRPC
# requires parameter and string", then "ENDM without MACRO".
EMPTY = {
    'top': "\tIRPC\tC,\n\tDB\t1\n\tENDM\n\tDB\t9\n",
    'top_brackets': "\tIRPC\tC,<>\n\tDB\t1\n\tENDM\n\tDB\t9\n",
    'argument': "MM\tMACRO\tP\n\tIRPC\tC,P\n\tDB\t1\n\tENDM\n\tENDM\n\tMM\n\tDB\t9\n",
    'argument_brackets': "MM\tMACRO\tP\n\tIRPC\tC,<P>\n\tDB\t1\n\tENDM\n\tENDM\n"
                         "\tMM\n\tDB\t9\n",
    'in_a_macro': "MM\tMACRO\n\tIRPC\tC,\n\tDB\t1\n\tENDM\n\tENDM\n\tMM\n\tDB\t9\n",
    # SEQIO.LIB's FILLNAM: `IRPC ?FC,FC' then `IF NUL ?FC / EXITM'.
    'nul': "MM\tMACRO\tP\n\tIRPC\tC,P\n\tIF\tNUL C\n\tEXITM\n\tENDIF\n\tDB\t1\n"
           "\tENDM\n\tENDM\n\tMM\n\tDB\t9\n",
}


@pytest.mark.parametrize('case, m80, mac', [
    # M80 goes round once only where an empty argument made the string
    # empty; MAC and RMAC always go round once.
    ('top', '09', '0109'),
    ('top_brackets', '09', '0109'),
    ('argument', '0109', '0109'),
    ('argument_brackets', '0109', '0109'),
    ('in_a_macro', '09', '0109'),
    ('nul', '09', '09'),
])
def test_an_irpc_with_an_empty_string(case, m80, mac):
    assert _code(EMPTY[case]) == m80
    assert _code(EMPTY[case], dri=True) == mac


def test_an_irpc_with_no_comma_is_still_an_error():
    ok, _, errors, _ = _assemble("\tIRPC\tC\n\tDB\t1\n\tENDM\n")
    assert not ok and "IRPC requires parameter and string" in errors[0]


# A <...> group inside a macro argument or an IRP item: MACRO-80 3.44, MAC
# 2.0 and RMAC 1.1 drop its brackets, wherever it is in the argument, and
# keep its text.  um80 dropped them only when they were the whole argument:
# without --dri `MM 1<2>3' was "Cannot parse expression: '1<2>3'", and with
# --dri MAC's relational operators made it (1<2)>3, 0FFH, without a word.
TEXT = "MM\tMACRO\tP\n\tDB\t0EEH\n\tDB\t'&P'\n\tENDM\n"


@BOTH
@pytest.mark.parametrize('call, expect', [
    ('MM\t1<2>3', '7b'),        # 123
    ('MM\t5<>5', '37'),         # 55
    ('MM\t2<3 ;x>', '17'),      # 23, and a comment
    ('MM\t<1>2<3>', '7b'),
])
def test_brackets_inside_a_macro_argument_go(dri, call, expect):
    assert _code("MM\tMACRO\tP\n\tDB\tP\n\tENDM\n\t" + call + "\n", dri=dri) == expect


@BOTH
@pytest.mark.parametrize('call, text', [
    ('<1>2<3>', b'123'),
    ('1<2<3>4>5', b'12<3>45'),  # only the outer brackets go
    ('<1,2>3', b'1,23'),
    ('X<>', b'X'),
    ('<>X', b'X'),
    ('A<;B>C', b'A;BC'),
    ('A< B >C', b'A B C'),
    ('<<A>>', b'<A>'),
])
def test_the_text_of_a_bracketed_argument(dri, call, text):
    assert _code(TEXT + "\tMM\t" + call + "\n", dri=dri) == 'ee' + text.hex()


@BOTH
def test_brackets_inside_each_argument_go(dri):
    two = ("MM\tMACRO\tP,Q\n\tDB\t0EEH\n\tDB\t'&P'\n\tDB\t0EEH\n\tDB\t'&Q'\n"
           "\tENDM\n\tMM\t<A>B,C<D>\n")
    assert _code(two, dri=dri) == 'ee4142ee4344'


@BOTH
@pytest.mark.parametrize('lst, expect', [
    ('<1<2>3,4>', '7b04'),
    ('<<1>2,3>', '0c03'),
])
def test_brackets_inside_an_irp_item_go(dri, lst, expect):
    assert _code(f"\tIRP\tP,{lst}\n\tDB\tP\n\tENDM\n", dri=dri) == expect


@BOTH
@pytest.mark.parametrize('lst, text', [
    ('<A<B>C,D>', [b'ABC', b'D']),
    ('<<A>B,C>', [b'AB', b'C']),
    ('<A<;>B,C>', [b'A;B', b'C']),
])
def test_the_text_of_a_bracketed_irp_item(dri, lst, text):
    want = ''.join('ee' + t.hex() for t in text)
    assert _code(f"\tIRP\tP,{lst}\n\tDB\t0EEH\n\tDB\t'&P'\n\tENDM\n", dri=dri) == want


def test_a_quoted_bracket_inside_an_argument():
    # `!>' is a `>' inside the brackets too: M80 1>2 (MAC and RMAC flag V).
    assert _code(TEXT + "\tMM\t1<!>>2\n") == 'ee' + b'1>2'.hex()


@BOTH
def test_a_bracket_with_no_close_goes_with_a_warning(dri):
    # M80 (X) and MAC and RMAC (V) flag it, and pass AB.
    ok, code, _, warnings = _assemble(TEXT + "\tMM\tA<B\n", dri=dri)
    assert ok and code == 'ee' + b'AB'.hex()
    assert any("no '>'" in w for w in warnings), warnings


# The items of an IRP list.  MACRO-80 3.44 ends an item at a `,', a `;', a
# blank or a tab, and skips the blanks in front of one.  4558825 made a `;'
# inside the list's <...> text, so `IRP P,<A;B;C>' went round once, with
# `A;B;C', without a word (0.3.50 took A alone, and warned).  MAC and RMAC
# flag such a `;' B.  The body prints a marker, then the item if it is not
# blank (M80 puts a 00 in a string for an empty one; MAC and RMAC do not).
ITEM = "\tDB\t0EEH\n\tIFNB\t<P>\n\tDB\t'&P'\n\tENDIF\n\tENDM\n"
VALUE = "\tDB\t0EEH\n\tIFNB\t<P>\n\tDB\tP\n\tENDIF\n\tENDM\n"


def _items(*items):
    return ''.join('ee' + t.hex() for t in items)


@pytest.mark.parametrize('lst, items', [
    ('<A;B;C>', [b'A', b'B', b'C']),
    ('<A;;B>', [b'A', b'', b'B']),
    ('<A;>', [b'A', b'']),
    ('<;A>', [b'', b'A']),
    ('<A; B>', [b'A', b'B']),
    ('<A;B> ;comment', [b'A', b'B']),
    ('<A,B;C,D>', [b'A', b'B', b'C', b'D']),
    # A blank or a tab ends an item too.
    ('<A B>', [b'A', b'B']),
    ('<A\tB>', [b'A', b'B']),
    ('<A B;C>', [b'A', b'B', b'C']),
    ('<A <B>,C>', [b'A', b'B', b'C']),
    ('<A ,B>', [b'A', b'', b'B']),
    ('<A >', [b'A', b'']),
    ('<A ,>', [b'A', b'', b'']),
    ('<  A  ,  B  >', [b'A', b'', b'B', b'']),
    ('< >', [b'']),
    # Not in a nested group, a string or after a `!'.
    ('<<A;B>,C>', [b'A;B', b'C']),
    ('<<A B>,C>', [b'A B', b'C']),
    ('<A!;B>', [b'A;B']),
    ('<A! B>', [b'A B']),
])
def test_m80_ends_an_irp_item_at_a_semicolon_or_a_blank(lst, items):
    assert _code(f"\tIRP\tP,{lst}\n" + ITEM) == _items(*items)


@pytest.mark.parametrize('lst, values', [
    ('<1,;2>', [1, None, 2]),
    ("<1,';',2>", [1, 0x3B, 2]),
    # A `%' item is an expression, to a `,' or a `;'.
    ('<%1 + 1,5>', [2, 5]),
    ('<%1;2>', [1, 2]),
])
def test_m80_irp_values(lst, values):
    want = ''.join('ee' + (f'{v:02x}' if v is not None else '') for v in values)
    assert _code(f"\tIRP\tP,{lst}\n" + VALUE) == want


def test_m80_a_macro_argument_with_a_semicolon_in_an_irp_list():
    # `MM <1;2>' passes `1;2' (a `;' in brackets is text), and the IRP of
    # the body then goes round twice.
    assert _code("MM\tMACRO\tQ\n\tIRP\tP,<Q>\n" + VALUE + "\tENDM\n\tMM\t<1;2>\n") \
        == 'ee01ee02'


def test_m80_an_unclosed_list_with_a_semicolon():
    ok, code, _, warnings = _assemble("\tIRP\tP,<A;B\n" + ITEM)
    assert ok and code == _items(b'A', b'B')
    assert any("no closing '>'" in w for w in warnings), warnings


@BOTH
@pytest.mark.parametrize('lst, items', [
    # A comma at the end is an empty item, in M80, MAC and RMAC.
    ('<A,>', [b'A', b'']),
    ('<,>', [b'', b'']),
    ('<,A>', [b'', b'A']),
])
def test_a_comma_at_the_end_of_an_irp_list(dri, lst, items):
    body = "\tDB\t0EEH\n\tIF\tNUL P\n\tELSE\n\tDB\t'&P'\n\tENDIF\n\tENDM\n"
    assert _code(f"\tIRP\tP,{lst}\n" + body, dri=dri) == _items(*items)


@pytest.mark.parametrize('lst, items', [
    ('<A ,B>', [b'A', b'B']),
    ('< A>', [b'A']),
    ('<<A;B>,C>', [b'A;B', b'C']),
])
def test_mac_ends_an_irp_item_at_a_comma(lst, items):
    body = "\tDB\t0EEH\n\tDB\t'&P'\n\tENDM\n"
    assert _code(f"\tIRP\tP,{lst}\n" + body, dri=True) == _items(*items)


@pytest.mark.parametrize('source', [
    "\tIRP\tP,<A;B;C>\n\tDB\t'&P'\n\tENDM\n",
    "\tIRP\tP,<A;B> ;comment\n\tDB\t'&P'\n\tENDM\n",
    "MM\tMACRO\tQ\n\tIRP\tP,<Q>\n\tDB\tP\n\tENDM\n\tENDM\n\tMM\t<1;2>\n",
])
def test_mac_flags_a_semicolon_in_an_irp_list(source):
    ok, _, errors, _ = _assemble(source, dri=True)
    assert not ok and any("';'" in e and 'IRP' in e for e in errors), errors
