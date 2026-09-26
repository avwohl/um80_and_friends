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


# A `>' with no `<' open before it in a macro call's arguments.  MAC 2.0
# and RMAC 1.1 read it as text, and a later comma still ends the argument:
# `MM 1>2,3' passes `1>2' and 3.  MACRO-80 3.44 ends the argument at it, as
# at a comma, and flags the line Q: there `MM 1>2,3' passes 1, 2 and 3.
# um80 took it for a closing bracket, so the depth went below 0 and no
# later comma split: `MM 1>2,3' was one argument, `1>2,3' - with --dri EE
# 00 03 EE, without a word, and without it "Cannot parse expression".
TWO = "MM\tMACRO\tP,Q\n\tDB\t0EEH\n\tDB\tP\n\tDB\t0EEH\n\tDB\tQ\n\tENDM\n"
THREE = ("MM\tMACRO\tP,Q,R\n\tDB\t0EEH\n\tDB\tP\n\tDB\t0EEH\n\tDB\tQ\n"
         "\tDB\t0EEH\n\tDB\tR\n\tENDM\n")
TWO_TEXT = ("MM\tMACRO\tP,Q\n\tDB\t0EEH\n\tDB\t'Z&P'\n\tDB\t0EEH\n\tDB\t'Y&Q'\n"
            "\tENDM\n")
THREE_TEXT = ("MM\tMACRO\tP,Q,R\n\tDB\t0EEH\n\tDB\t'Z&P'\n\tDB\t0EEH\n"
              "\tDB\t'Y&Q'\n\tDB\t0EEH\n\tDB\t'X&R'\n\tENDM\n")
MACROS = {'2': TWO, '3': THREE, "2'": TWO_TEXT, "3'": THREE_TEXT}


@pytest.mark.parametrize('macro, call, mac', [
    ('2', '1>2,3', 'ee00ee03'),
    ('2', '5>(2),4', 'eeffee04'),
    ('2', '1>=2,3', 'ee00ee03'),
    ('2', '3>2=0FFH,4', 'ee00ee04'),
    ('3', '2>1,1,3', 'eeffee01ee03'),
    ('2', '<1>2>1,4', 'eeffee04'),
    ('2', '%5>2,4', 'eeffee04'),
    ("2'", 'A>B,C', 'ee5a413e42ee5943'),                  # ZA>B, YC
    ("3'", 'A>,B', 'ee5a413eee5942ee58'),
    ("3'", '>A,B', 'ee5a3e41ee5942ee58'),
    ("3'", 'A,>,B', 'ee5a41ee593eee5842'),
    ("3'", '<A>B>C,D', 'ee5a41423e43ee5944ee58'),
    ("3'", '<A,B>>C,D', 'ee5a412c423e43ee5944ee58'),
    ("3'", '(A>B),C', 'ee5a28413e4229ee5943ee58'),
    ("3'", 'A(>)B,C', 'ee5a41283e2942ee5943ee58'),
])
def test_mac_reads_a_close_bracket_with_no_open_as_text(macro, call, mac):
    ok, code, errors, warnings = _assemble(MACROS[macro] + "\tMM\t" + call + "\n", dri=True)
    assert ok, errors
    assert code == mac and warnings == []


@pytest.mark.parametrize('macro, call, m80', [
    ('2', '1>2,3', 'ee01ee02'),
    ('2', '5>(2),4', 'ee05ee02'),
    ('3', '2>1,1,3', 'ee02ee01ee01'),
    ('2', '<1>2>1,4', 'ee0cee01'),
    ('3', '1,2>3', 'ee01ee02ee03'),
    # An empty argument in a string is a 00 byte in M80.
    ("2'", 'A>B,C', 'ee5a41ee5942'),                      # ZA, YB
    ("2'", '<A>>B', 'ee5a41ee5942'),
    ("2'", '>', 'ee5a00ee5900'),
    ("3'", 'A>,B', 'ee5a41ee5900ee5842'),
    ("3'", 'A>>B', 'ee5a41ee5900ee5842'),
    ("3'", 'A>B;C', 'ee5a41ee5942ee5800'),
    ("3'", '>A,B', 'ee5a00ee5941ee5842'),
    ("3'", 'A,>,B', 'ee5a41ee5900ee5800'),
    ("3'", '<A>B>C,D', 'ee5a4142ee5943ee5844'),
    ("3'", 'A,B,C>D', 'ee5a41ee5942ee5843'),
    # Inside parentheses too.
    ("3'", '(A>B),C', 'ee5a2841ee594229ee5843'),
    ("3'", 'A(>)B,C', 'ee5a4128ee592942ee5843'),
])
def test_m80_ends_an_argument_at_a_close_bracket_with_no_open(macro, call, m80):
    ok, code, errors, warnings = _assemble(MACROS[macro] + "\tMM\t" + call + "\n")
    assert ok, errors
    assert code == m80
    assert any("has no '<'" in w for w in warnings), warnings


@pytest.mark.parametrize('call, m80', [
    ('"A>B",C', 'ee5a22413e4222ee5943ee5800'),   # in a string
    ('A!>B,C', 'ee5a413e42ee5943ee5800'),        # after a `!'
    ('A<(>)B,C', 'ee5a41282942ee5943ee5800'),     # it closes the `<'
])
def test_m80_a_close_bracket_that_is_text_ends_nothing(call, m80):
    # M80 flags none of these.
    ok, code, errors, warnings = _assemble(THREE_TEXT + "\tMM\t" + call + "\n")
    assert ok, errors
    assert code == m80 and warnings == []


# A parenthesis in a macro call's arguments is text to MACRO-80 3.44, MAC
# 2.0 and RMAC 1.1: a comma inside one ends the argument, so `MM (A,B),C'
# passes `(A', `B)' and C.  um80 kept such a comma in the argument, and a
# `)' with no `(' (`MM A),B,C') or a `(' with no `)' (`MM A(B,C') stopped
# every later comma from ending one, with or without --dri, without a word.
# M80 puts a 00 in a string for an empty argument, MAC and RMAC nothing.
@BOTH
@pytest.mark.parametrize('call, m80, mac', [
    ('(A,B),C', 'ee5a2841ee594229ee5843', None),              # (A, B), C
    ('((A,B),C),D', 'ee5a282841ee594229ee584329', None),       # ((A, B), C)
    ('A(B,C)D,E', 'ee5a412842ee59432944ee5845', None),        # A(B, C)D, E
    ('A((B,C)),D', 'ee5a41282842ee59432929ee5844', None),
    ('A),B,C', 'ee5a4129ee5942ee5843', None),                 # A), B, C
    ('A),(B,C', 'ee5a4129ee592842ee5843', None),
    ('A(B,C', 'ee5a412842ee5943ee5800', 'ee5a412842ee5943ee58'),
    ('A,(B,C', 'ee5a41ee592842ee5843', None),
])
def test_a_comma_in_parentheses_ends_a_macro_argument(dri, call, m80, mac):
    ok, code, errors, warnings = _assemble(THREE_TEXT + "\tMM\t" + call + "\n",
                                           dri=dri)
    assert ok, errors
    assert code == (mac or m80 if dri else m80) and warnings == []


@BOTH
@pytest.mark.parametrize('call, expect', [
    ('(1),2', 'ee01ee02'),
    ('(1+2)*2,3', 'ee06ee03'),
    ('%(1+2),3', 'ee03ee03'),
    ('%(1+(2)),3', 'ee03ee03'),
    ('%(1),(2)', 'ee01ee02'),
])
def test_an_argument_in_parentheses_is_as_before(dri, call, expect):
    # The same bytes in M80, MAC and RMAC.
    ok, code, errors, warnings = _assemble(TWO + "\tMM\t" + call + "\n", dri=dri)
    assert ok, errors
    assert code == expect and warnings == []


# A blank or a tab ends a macro argument outside a string and a <...>
# group.  MACRO-80 3.44 reads the arguments one after another, and the
# blanks after one separate it from the next, as a comma does: `MM A B'
# passes A and B, and `MM A ,B' A, an empty argument and B.  um80 kept the
# blanks in the argument (`A B'; `A' and B), without a word.
FOUR_TEXT = ("MM\tMACRO\tP,Q,R,S\n\tDB\t0EEH\n\tDB\t'Z&P'\n\tDB\t0EEH\n"
             "\tDB\t'Y&Q'\n\tDB\t0EEH\n\tDB\t'X&R'\n\tDB\t0EEH\n\tDB\t'W&S'\n"
             "\tENDM\n")
MACROS["4'"] = FOUR_TEXT


@pytest.mark.parametrize('macro, call, m80', [
    ("3'", 'A B', 'ee5a41ee5942ee5800'),                   # A, B
    ("3'", 'A  B', 'ee5a41ee5942ee5800'),
    ("3'", 'A\tB', 'ee5a41ee5942ee5800'),
    ("3'", 'A\t\tB', 'ee5a41ee5942ee5800'),
    ("3'", 'A B;C', 'ee5a41ee5942ee5800'),
    ("3'", 'A,B C', 'ee5a41ee5942ee5843'),
    ("3'", ',A B', 'ee5a00ee5941ee5842'),
    ("3'", '1 + 1,5', 'ee5a31ee592bee5831'),               # 1, +, 1
    ("3'", 'A !B', 'ee5a41ee5942ee5800'),
    # A comma after the blanks separates another argument.
    ("3'", 'A ,B', 'ee5a41ee5900ee5842'),                   # A, empty, B
    ("3'", 'A\t,B', 'ee5a41ee5900ee5842'),
    ("3'", 'A , B', 'ee5a41ee5900ee5842'),
    ("4'", 'A , ,B', 'ee5a41ee5900ee5800ee5742'),
    ("4'", 'A B ,C', 'ee5a41ee5942ee5800ee5743'),
    # In a <...> group or a string a blank is text; after one it ends it.
    ("3'", '<A> <B>,C', 'ee5a41ee5942ee5843'),
    ("3'", 'A<B C>D E', 'ee5a4142204344ee5945ee5800'),     # AB CD, E
    ("3'", '<A,B> C', 'ee5a412c42ee5943ee5800'),
    ("4'", '<A B> C D', 'ee5a412042ee5943ee5844ee5700'),
    ("4'", 'A<B> C', 'ee5a4142ee5943ee5800ee5700'),
    ("3'", 'A"B C",D', 'ee5a412242204322ee5944ee5800'),
    ("3'", '"A B" C,D', 'ee5a2241204222ee5943ee5844'),
    ("3'", '(A B),C', 'ee5a2841ee594229ee5843'),           # (A, B), C
    # A '!'-quoted blank is text; M80 steps back to it and skips the
    # blanks from there, so after one it drops a character.
    ("4'", 'A! B C', 'ee5a412042ee5943ee5800ee5700'),      # A B, C
    ("4'", 'A!\tB C', 'ee5a410942ee5943ee5800ee5700'),
    ("3'", 'A! ,B', 'ee5a4120ee5942ee5800'),               # `A ', B
    ("3'", 'A!, B', 'ee5a412cee5942ee5800'),               # `A,', B
    ("3'", 'A!  B,C', 'ee5a4120ee5900ee5843'),             # `A ', empty, C
    ("3'", 'A!\t\tB,C', 'ee5a4109ee5900ee5843'),
    ("3'", 'A!  ,B', 'ee5a4120ee5942ee5800'),              # `A ', B
])
def test_m80_ends_a_macro_argument_at_a_blank(macro, call, m80):
    ok, code, errors, warnings = _assemble(MACROS[macro] + "\tMM\t" + call + "\n")
    assert ok, errors
    assert code == m80 and warnings == []


@pytest.mark.parametrize('call, m80', [
    ('A >B', 'ee5a41ee5900ee5842ee5700'),       # A, empty, B
    ('A >,B', 'ee5a41ee5900ee5800ee5742'),      # A, empty, empty, B
    ('A> B', 'ee5a41ee5942ee5800ee5700'),       # A, B
])
def test_m80_a_blank_and_a_close_bracket_with_no_open(call, m80):
    ok, code, errors, warnings = _assemble(FOUR_TEXT + "\tMM\t" + call + "\n")
    assert ok, errors
    assert code == m80
    assert any("has no '<'" in w for w in warnings), warnings


# A `%' expression runs to its comma, blanks and all, in M80, MAC and RMAC.
# M80 evaluates one wherever its `%' is outside a <...> group, after one too
# (um80 took a `%' after a `<' for text): `MM <A>%1+1' passes A2.
@BOTH
@pytest.mark.parametrize('macro, call, expect', [
    ('2', '%1 + 1,5', 'ee02ee05'),
    ('2', '%1 ,5', 'ee01ee05'),
    ('3', '%1 + 1 ,5,6', 'ee02ee05ee06'),
    ('3', '1,%2 * 3 ,4', 'ee01ee06ee04'),
])
def test_a_percent_expression_runs_to_its_comma(dri, macro, call, expect):
    ok, code, errors, warnings = _assemble(MACROS[macro] + "\tMM\t" + call + "\n",
                                           dri=dri)
    assert ok, errors
    assert code == expect and warnings == []


@pytest.mark.parametrize('call, m80', [
    ('A%1 + 1,C', 'ee5a4132ee5943ee5800'),        # A2, C
    ('<A>%1+1,B', 'ee5a4132ee5942ee5800'),        # A2, B
    ('<A>%1 + 1,B', 'ee5a4132ee5942ee5800'),
    ('A<B>%2,C', 'ee5a414232ee5943ee5800'),       # AB2, C
])
def test_m80_a_percent_after_other_text(call, m80):
    ok, code, errors, warnings = _assemble(THREE_TEXT + "\tMM\t" + call + "\n")
    assert ok, errors
    assert code == m80 and warnings == []


# MAC 2.0 and RMAC 1.1 end the arguments at the blanks after one: a comma
# there starts the next - `MM A ,B' passes A and B - and anything else they
# flag S and leave out (`MM A B' passes A).  With --dri um80 does the same,
# and the S is an error; it passed `A B', without a word.
@pytest.mark.parametrize('macro, call, mac', [
    ("3'", 'A ,B', 'ee5a41ee5942ee58'),
    ("3'", 'A\t,B', 'ee5a41ee5942ee58'),
    ("3'", 'A , B', 'ee5a41ee5942ee58'),
    ("4'", 'A , ,B', 'ee5a41ee59ee5842ee57'),
    ("3'", '<A B>,C', 'ee5a412042ee5943ee58'),
    ("3'", 'A, B', 'ee5a41ee5942ee58'),
])
def test_mac_a_comma_after_the_blanks(macro, call, mac):
    ok, code, errors, warnings = _assemble(MACROS[macro] + "\tMM\t" + call + "\n",
                                           dri=True)
    assert ok, errors
    assert code == mac and warnings == []


@pytest.mark.parametrize('call', [
    'A B', 'A\tB', 'A  B', 'A B;C', 'A,B C', ',A B', '1 + 1,5', '(A B),C',
    '<A> <B>,C', 'A<B C>D E', '<A,B> C', 'A >B', 'A> B', 'A >,B', 'A%1 + 1,C',
    '<A>%1 + 1,B',
])
def test_mac_flags_text_after_the_blanks_s(call):
    ok, _, errors, _ = _assemble(THREE_TEXT + "\tMM\t" + call + "\n", dri=True)
    assert not ok
    assert any('flag it S' in e for e in errors), errors


# A `!' quotes the next character in a macro call's arguments and an IRP
# list, a `;' too: MACRO-80 3.44 reads `MM A!;B' as the one argument `A;B'.
# um80 cut the line at its first `;' outside a string before it read the
# arguments, so it passed `A!' - and after a `!'-quoted quote (`MM A!"B;C')
# it took the rest of the line for a string - without a word.
@pytest.mark.parametrize('call, m80', [
    ('A!;B', 'ee5a413b42ee5900ee5800'),                   # `A;B'
    ('A!;B,C', 'ee5a413b42ee5943ee5800'),
    ('!;,B', 'ee5a3bee5942ee5800'),
    ('A,!;', 'ee5a41ee593bee5800'),
    ('A,B!;', 'ee5a41ee59423bee5800'),
    ('A!;B;C', 'ee5a413b42ee5900ee5800'),
    ('A!;B ;comment', 'ee5a413b42ee5900ee5800'),
    ('A!;;B', 'ee5a413bee5900ee5800'),                    # `A;'
    ('A!;B!;C', 'ee5a413b423b43ee5900ee5800'),
    ('A!!!;B', 'ee5a41213b42ee5900ee5800'),               # `A!;B'
    ('A!;B C', 'ee5a413b42ee5943ee5800'),                 # `A;B', C
    ('A!;B<C;D>', 'ee5a413b42433b44ee5900ee5800'),        # `A;BC;D'
    # A quoted quote opens no string.
    ('A!"B;C', 'ee5a412242ee5900ee5800'),                 # `A"B'
    ('!"A;B",C', 'ee5a2241ee5900ee5800'),                 # `"A'
    # A quoted bracket opens or closes no group.
    ('<A!>;B>,C', 'ee5a413e3b42ee5943ee5800'),            # `A>;B', C
    ('A!<;B', 'ee5a413cee5900ee5800'),                    # `A<'
    ('<A!<>;B,C', 'ee5a413cee5900ee5800'),
    # A quoted blank or tab at the end is kept.
    ('A! ;B', 'ee5a4120ee5900ee5800'),                    # `A '
    ('A!\t;B', 'ee5a4109ee5900ee5800'),
    ('A!  ;B', 'ee5a4120ee5900ee5800'),
    ('A! ', 'ee5a4120ee5900ee5800'),
    # As before.
    ('A!!;B', 'ee5a4121ee5900ee5800'),                    # `A!'
    ('A!,B;C', 'ee5a412c42ee5900ee5800'),                 # `A,B'
])
def test_m80_a_bang_quotes_a_semicolon(call, m80):
    ok, code, errors, warnings = _assemble(THREE_TEXT + "\tMM\t" + call + "\n")
    assert ok, errors
    assert code == m80 and warnings == []


Q_ITEM = "\tDB\t0EEH\n\tDB\t'Q&X'\n\tENDM\n"


@pytest.mark.parametrize('head, m80', [
    # In an IRP list too: `<A!>;B>' is `A>' and B (a `;' ends an item);
    # um80 took the `>' for the list's end.
    ('IRP\tX,<A!>;B>', 'ee51413eee5142'),
    # As before.
    ('IRP\tX,<A!;B,C>', 'ee51413b42ee5143'),
    # In an IRPC string a `!' is text, and a `;' starts the comment.
    ('IRPC\tX,A!;B', 'ee5141ee5121'),
])
def test_m80_a_bang_in_an_irp_list_quotes_a_semicolon(head, m80):
    ok, code, errors, warnings = _assemble("\t" + head + "\n" + Q_ITEM)
    assert ok, errors
    assert code == m80 and warnings == []


# MAC 2.0 and RMAC 1.1 quote a string with `'' only: a `"' in a macro
# call's arguments or an IRP list is text, and a comma, a blank or a `;'
# after it is what it is anywhere else - `MM "A,B",C' passes `"A', `B"' and
# C.  um80 --dri read `"A,B"' as a string, as M80 does, so it passed `"A,B"'
# and C, and `MM "A;B",C' `"A;B"' and C, without a word.
@pytest.mark.parametrize('call, mac', [
    ('"A,B",C', 'ee5a2241ee594222ee5843'),                # `"A', `B"', C
    ('A"B,C"', 'ee5a412242ee594322ee58'),
    ('A","B', 'ee5a4122ee592242ee58'),
    ('A, "B,C"', 'ee5a41ee592242ee584322'),
    ('"A;B",C', 'ee5a2241ee59ee58'),                      # `"A'
    ('"A,B" ;"C', 'ee5a2241ee594222ee58'),
    ('"<A,B>",C', 'ee5a22412c4222ee5943ee58'),            # `"A,B"', C
    ('<">,A', 'ee5a22ee5941ee58'),                        # `"', A
    # As before.
    ('"A>B",C', 'ee5a22413e4222ee5943ee58'),
    ('"""",A', 'ee5a22222222ee5941ee58'),
])
def test_mac_a_double_quote_in_a_macro_argument_is_text(call, mac):
    ok, code, errors, warnings = _assemble(THREE_TEXT + "\tMM\t" + call + "\n",
                                           dri=True)
    assert ok, errors
    assert code == mac and warnings == []


def test_mac_a_blank_after_a_double_quote_ends_the_arguments():
    # `MM "A B",C': MAC and RMAC flag `B",C' S; um80 passed `"A B"' and C.
    ok, _, errors, _ = _assemble(THREE_TEXT + "\tMM\t\"A B\",C\n", dri=True)
    assert not ok
    assert any('flag it S' in e for e in errors), errors


@pytest.mark.parametrize('call, m80', [
    # M80 reads `"...."' as a string.
    ('"A,B",C', 'ee5a22412c4222ee5943ee5800'),
    ('"A;B",C', 'ee5a22413b4222ee5943ee5800'),
    ('"<A,B>",C', 'ee5a223c412c423e22ee5943ee5800'),
    ('"A B",C', 'ee5a2241204222ee5943ee5800'),
])
def test_m80_a_double_quote_in_a_macro_argument_quotes(call, m80):
    ok, code, errors, warnings = _assemble(THREE_TEXT + "\tMM\t" + call + "\n")
    assert ok, errors
    assert code == m80 and warnings == []


@pytest.mark.parametrize('head, m80, mac', [
    # An IRP list: M80's string, MAC's text.
    ('IRP\tX,<"A,B">', 'ee5122412c4222', 'ee512241ee514222'),
    # An IRPC string: text in all three, so a `;' starts the comment (um80
    # went round `"A;B"' with or without --dri).
    ('IRPC\tX,"A;B"', 'ee5122ee5141', 'ee5122ee5141'),
    ('IRPC\tX,"A;B" ;C', 'ee5122ee5141', 'ee5122ee5141'),
    ('IRPC\tX,A"B;C"', 'ee5141ee5122ee5142', 'ee5141ee5122ee5142'),
])
def test_a_double_quote_in_an_irp_list_or_an_irpc_string(head, m80, mac):
    for dri, want in ((False, m80), (True, mac)):
        ok, code, errors, warnings = _assemble("\t" + head + "\n" + Q_ITEM, dri=dri)
        assert ok, errors
        assert code == want and warnings == [], dri


@pytest.mark.parametrize('lst, m80', [
    ('<"A;B">', 'ee5122413b4222'),
    ('<A,"B;C">', 'ee5141ee5122423b4322'),
])
def test_mac_flags_a_semicolon_after_a_double_quote_in_an_irp_list(lst, m80):
    assert _code("\tIRP\tX," + lst + "\n" + Q_ITEM) == m80
    ok, _, errors, _ = _assemble("\tIRP\tX," + lst + "\n" + Q_ITEM, dri=True)
    assert not ok and any("';'" in e and 'IRP' in e for e in errors), errors


# In a macro call's argument that starts with `%', MAC 2.0 and RMAC 1.1
# read a `<' or a `>' as an operator, not a bracket: `MM %1<2,3' passes 1<2's
# value, 65535, and 3.  um80 --dri read `<2,3' as a group that ran to the end
# of the line - "Cannot parse expression" - and a `;' after such a `<' was
# not a comment.  (M80 flags the `<' O.)
MACROS['1'] = "MM\tMACRO\tP\n\tDB\t0EEH\n\tDB\tP\n\tENDM\n"


@pytest.mark.parametrize('macro, call, mac', [
    ('2', '%1<2,3', 'eeffee03'),
    ('2', '%2<1,3', 'ee00ee03'),
    ('2', '%1<=2,3', 'eeffee03'),
    ('2', '%1 < 2,3', 'eeffee03'),
    ('2', '%1<2 ,3', 'eeffee03'),
    ('2', '%1<=2 , 3', 'eeffee03'),
    ('2', '%0<-1,3', 'eeffee03'),
    ('2', '%(1<2),3', 'eeffee03'),
    ('2', "%'<'<2,3", 'ee00ee03'),
    ('2', '%1<2,<3>', 'eeffee03'),
    ('2', '%1<2,%3<2', 'eeffee00'),
    ('3', '5,%1<2,3', 'ee05eeffee03'),
    # A `;' after it starts the comment.
    ('1', '%1<2;X', 'eeff'),
    ('1', '%1<2 ;<X', 'eeff'),
    ('1', '%2<1;<', 'ee00'),
    ('2', '%(1<2),3;X', 'eeffee03'),
    ('2', '%1<2,<3;4>', 'eeffee03'),
    # As before.
    ('2', '%1<2>1,3', 'eeffee03'),
    ('2', '1,%2<3', 'ee01eeff'),
    ('2', '<1>,%1<2', 'ee01eeff'),
])
def test_mac_a_bracket_in_a_percent_argument_is_an_operator(macro, call, mac):
    ok, code, errors, warnings = _assemble(MACROS[macro] + "\tMM\t" + call + "\n",
                                           dri=True)
    assert ok, errors
    assert code == mac and warnings == []


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
    # MAC and RMAC end an item at a comma, and skip a blank or a tab at the
    # start of one.
    ('<A,B>', [b'A', b'B']),
    ('< A>', [b'A']),
    ('<A, B>', [b'A', b'B']),
    ('<A,  B>', [b'A', b'B']),
    ('<A,\tB,\tC>', [b'A', b'B', b'C']),
    ('<\tA,B>', [b'A', b'B']),
    # A blank in a nested <...> is text.
    ('<<A;B>,C>', [b'A;B', b'C']),
    ('<<A B>,C>', [b'A B', b'C']),
    ('<A, <B C>>', [b'A', b'B C']),
])
def test_mac_ends_an_irp_item_at_a_comma(lst, items):
    body = "\tDB\t0EEH\n\tDB\t'&P'\n\tENDM\n"
    assert _code(f"\tIRP\tP,{lst}\n" + body, dri=True) == _items(*items)


@pytest.mark.parametrize('lst', [
    # A blank MAC and RMAC do not skip: they read the list otherwise, and
    # um80 --dri took each for the items around its commas, without a
    # word.  In MAC and RMAC: A, B and an empty item; A and `,'; `,'; 1, 1
    # and an empty item.
    '<A ,B ,C>',
    '<A, ,B>',
    '< ,A>',
    '<1\t,1 ,A>',
    # MAC: A and C, and RMAC stops and writes nothing, without a word; MAC:
    # A and B, and RMAC stops.
    '<A ,B,C>',
    '<A ,B>',
    # MAC flags these S or B, and RMAC stops.
    '<A B>',
    '<A >',
    '< >',
    '<A,B >',
    '<%1 + 1,5>',
])
def test_mac_reads_any_other_blank_in_an_irp_list_otherwise(lst):
    ok, _, errors, _ = _assemble(f"\tIRP\tP,{lst}\n\tDB\t0EEH\n\tDB\t'&P'\n"
                                 "\tENDM\n", dri=True)
    assert not ok and any('blank' in e and 'IRP' in e for e in errors), errors


@pytest.mark.parametrize('source', [
    "\tIRP\tP,<A;B;C>\n\tDB\t'&P'\n\tENDM\n",
    "\tIRP\tP,<A;B> ;comment\n\tDB\t'&P'\n\tENDM\n",
    "MM\tMACRO\tQ\n\tIRP\tP,<Q>\n\tDB\tP\n\tENDM\n\tENDM\n\tMM\t<1;2>\n",
])
def test_mac_flags_a_semicolon_in_an_irp_list(source):
    ok, _, errors, _ = _assemble(source, dri=True)
    assert not ok and any("';'" in e and 'IRP' in e for e in errors), errors
