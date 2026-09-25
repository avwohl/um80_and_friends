"""A macro body is matched to its parameters name by name.

MACRO-80 3.44, MAC 2.0 and RMAC 1.1 read a macro body as names and other
text, and replace a name that is a parameter.  um80 matched a parameter with
a regular expression's word boundary, which a `?' or `@' is not part of:

- a parameter that starts with `?' or `@' was never replaced - DRI's
  CONTROL/COMPARE.LIB (`TDIG? SET '&?Y'-'0''), STACK.LIB (`LHLD ADC&?C'),
  NCOMPARE.LIB and Z80.LIB (`?N', `?DD') use them;
- a parameter was replaced inside another name that has a `?', `@', `$' or
  `.' in it: with the parameter FC, SEQIO.LIB's `IRPC ?FC,FC' became
  `IRPC ?X,X';
- `1X' was left alone, where M80 and MAC read 1 and then the name X.

In M80 a name is letters, digits and $ . ? @ _; in MAC letters, digits, ?
and @, and a `$', `_' or `.' ends it.  The expected bytes are what M80 3.44
(the source with ASEG), MAC 2.0 and RMAC 1.1 assemble under cpmemu.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler

HEAD = "\taseg\n\torg\t100h\n"


def _code(source, **kw):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(HEAD + source + "\tend\n")
        asm = Assembler(**kw)
        assert asm.assemble(p), [str(e) for e in asm.errors]
        return bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE').hex()


BOTH = pytest.mark.parametrize('dri', [False, True], ids=['m80', 'dri'])


@BOTH
def test_a_parameter_may_start_with_a_question_mark_or_at(dri):
    # M80, MAC, RMAC: 2A 82 10 (LHLD ADC1), 37 07 08.
    src = ("ADC1\tEQU\t1082H\nRDM\tMACRO\t?C\n\tLHLD\tADC&?C\n\tENDM\n"
           "PR\tMACRO\t?M,@N\n\tDB\t'&?M',?M,@N\n\tENDM\n"
           "\tRDM\t1\n\tPR\t7,8\n")
    assert _code(src, dri=dri) == '2a8210' '370708'


@BOTH
def test_compare_lib_reads_the_first_character(dri):
    # COMPARE.LIB's TEST?: the IRPC parameter ?Y is not the macro's Y.
    # M80, MAC, RMAC: 05, 28 ('X'-'0').
    src = ("TEST?\tMACRO\tX,Y\n\tIRPC\t?Y,Y\nTDIG?\tSET\t'&?Y'-'0'\n\tEXITM\n"
           "\tENDM\n\tDB\tTDIG?\n\tENDM\n\tTEST?\tA,5\n\tTEST?\tA,X1\n")
    assert _code(src, dri=dri) == '0528'


@BOTH
def test_a_name_with_the_parameter_in_it_is_another_name(dri):
    # With the parameter X and `MM K': ?X, X?, @X and X@ are themselves
    # (11 12 13 14, not ?K ... 21 22 23 24), so are '&X?' and '&X@'
    # (26 58 3F, 26 58 40); `1X,0X' after `MN 5' is 15,05 (0F 05).  M80,
    # MAC and RMAC alike.
    src = ("?X\tEQU\t11H\nX?\tEQU\t12H\n@X\tEQU\t13H\nX@\tEQU\t14H\n"
           "?K\tEQU\t21H\nK?\tEQU\t22H\n@K\tEQU\t23H\nK@\tEQU\t24H\n"
           "MM\tMACRO\tX\n\tDB\t?X,X?,@X,X@\n\tDB\t'&X?','&X@'\n\tENDM\n"
           "\tMM\tK\n"
           "MN\tMACRO\tX\n\tDB\t1X,0X\n\tENDM\n\tMN\t5\n")
    assert _code(src, dri=dri) == '11121314' '26583f' '265840' '0f05'


def test_m80_a_dollar_dot_or_underscore_is_part_of_the_name():
    # M80: X$1, A$X, X.1, A.X, $X, _X and X_ are not the parameter X
    # (11 ... 17), and neither are '&X$', '&X.' and '&X_'.  um80 gave
    # 21 22 23 24 25 16 17, then K$ K. &X_.
    src = ("X$1\tEQU\t11H\nA$X\tEQU\t12H\nX.1\tEQU\t13H\nA.X\tEQU\t14H\n"
           "$X\tEQU\t15H\n_X\tEQU\t16H\nX_\tEQU\t17H\n"
           "K$1\tEQU\t21H\nA$K\tEQU\t22H\nK.1\tEQU\t23H\nA.K\tEQU\t24H\n"
           "$K\tEQU\t25H\n_K\tEQU\t26H\nK_\tEQU\t27H\n"
           "MM\tMACRO\tX\n\tDB\tX$1,A$X,X.1,A.X,$X,_X,X_\n"
           "\tDB\t'&X$','&X.','&X_'\n\tENDM\n\tMM\tK\n")
    assert _code(src) == '11121314151617' '265824' '26582e' '26585f'


def test_dri_a_dollar_dot_or_underscore_ends_the_name():
    # MAC and RMAC: X$1 is K$1 = K1 (21) and A$X is A$K = AK (22); in
    # strings K$, K. and K_.
    src = ("K1\tEQU\t21H\nAK\tEQU\t22H\nX1\tEQU\t11H\nAX\tEQU\t12H\n"
           "MM\tMACRO\tX\n\tDB\tX$1,A$X\n\tDB\t'&X$','&X.','&X_'\n\tENDM\n"
           "\tMM\tK\n")
    assert _code(src, dri=True) == '2122' '4b24' '4b2e' '4b5f'
