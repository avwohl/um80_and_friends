"""The `%' operator: a macro argument that is a value, taken at the call.

`GEN %E' passes the value of E, as digits, when GEN is called - MACRO-80
3.44, MAC 2.0 and RMAC 1.1 all evaluate it then.  um80 used to leave the
`%E' in the argument and evaluate each `%' in a body line as that line was
expanded, which went wrong three ways:

- a call in a REPT body inside a macro was evaluated when the outer macro
  expanded, so every repetition got the first value (DRI's CONTROL/
  SELECT.LIB builds its case table so: M80 and MAC give 10 01 15 01 1A 01,
  um80 gave 10 01 10 01 10 01);
- with --dri the argument kept the `$' of `%N$C' (59a4d13) and N$C was
  looked up as it is written: an undefined name, 0 without a word;
- the value was never text: `DB '&N'' gave '%E', `LB&N:' a parse error,
  and a body that changed E before it used N read the new E.

The expected bytes are what M80 3.44 (the source with ASEG) and MAC 2.0 and
RMAC 1.1 (without) assemble under cpmemu; RMAC's are the same, relocatable.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler

HEAD = "\taseg\n\torg\t100h\n"


def _assemble(source, **kw):
    """(ok, bytes or None, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(HEAD + source + "\tend\n")
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE') if ok else None
    return ok, code, [str(e) for e in asm.errors]


def _code(source, **kw):
    ok, code, errors = _assemble(source, **kw)
    assert ok, errors
    return code.hex()


BOTH = pytest.mark.parametrize('dri', [False, True], ids=['m80', 'dri'])

REPT_IN_MACRO = """GEN\tMACRO\tN
\tDB\tN
\tENDM
OUTER\tMACRO
CNT\tSET\t0
\tREPT\t3
\tGEN\t%CNT
CNT\tSET\tCNT+1
\tENDM
\tENDM
\tOUTER
"""

# SELECT.LIB's pattern: labels made from %K, and a table of them made by a
# REPT inside a macro.
CASE_TABLE = """CASE\tMACRO\tN
C&N:\tNOP
\tENDM
ELT\tMACRO\tN
\tDW\tC&N
\tENDM
TABLE\tMACRO\tCOUNT
K\tSET\t0
\tREPT\tCOUNT
\tELT\t%K
K\tSET\tK+1
\tENDM
\tENDM
K\tSET\t0
\tREPT\t3
\tCASE\t%K
K\tSET\tK+1
\tENDM
\tTABLE\t3
"""


@BOTH
def test_a_call_in_a_rept_body_in_a_macro_is_evaluated_each_time(dri):
    # M80, MAC, RMAC: 00 01 02 (um80 0.3.50: 00 00 00).
    assert _code(REPT_IN_MACRO, dri=dri) == '000102'
    # M80, MAC: 00 00 00, then DW C0,C1,C2 = 00 01 01 01 02 01.
    assert _code(CASE_TABLE, dri=dri) == '000000' '000101010201'


@BOTH
def test_the_value_is_taken_at_the_call(dri):
    # M80, MAC, RMAC: 05 06 - N is 5 however the body changes VV.
    assert _code("GEN\tMACRO\tN\nVV\tSET\tVV+1\n\tDB\tN,VV\n\tENDM\n"
                 "VV\tSET\t5\n\tGEN\t%VV\n", dri=dri) == '0506'


@BOTH
def test_the_value_is_text(dri):
    # M80, MAC, RMAC: 36 35 42, 36 34 00, 36 35 00, 31 30 36 35 00,
    # 36 35 35 33 35 00, 0A, then DW LB10 = 14 01.  The expression runs to
    # the end of the argument, blanks and all, and a blank after the `%' is
    # skipped; -1 is 65535.
    src = ("STR\tMACRO\tN,M\n\tDB\t'&N',M\n\tENDM\n"
           "LBL\tMACRO\tN\nLB&N:\tDB\tN\n\tENDM\n"
           "VV\tEQU\t65\n"
           "\tSTR\t%VV,%VV+1\n"
           "\tSTR\t% VV-1,0 ;x\n"
           "\tSTR\t%'A',0\n"
           "\tSTR\t%(VV + 1000),0\n"
           "\tSTR\t%-1,0\n"
           "\tLBL\t%VV-55\n"
           "\tDW\tLB10\n")
    assert _code(src, dri=dri) == ('363542' '363400' '363500' '3130363500'
                                   '363535333500' '0a' '1401')


def test_m80_writes_the_value_in_the_current_radix():
    # M80: 31 41 (1A), 30 41 30 (0A0: a 0 before a letter, and no H), 30,
    # 30 46 46 46 46, 31 31 (octal), 35 (.RADIX 2 is decimal).  MAC has no
    # .RADIX.
    src = ("STR\tMACRO\tN\n\tDB\t'&N'\n\tENDM\n"
           "\t.RADIX\t16\n\tSTR\t%1A\n\tSTR\t%0A0\n\tSTR\t%0\n\tSTR\t%0FFFF\n"
           "\t.RADIX\t8\n\tSTR\t%11\n"
           "\t.RADIX\t2\n\tSTR\t%101\n"
           "\t.RADIX\t10\n")
    assert _code(src) == '3141' '304130' '30' '3046464646' '3131' '35'


def test_where_the_percent_may_be():
    src = "STR\tMACRO\tN\n\tDB\t'&N'\n\tENDM\nVV\tEQU\t7\n\tSTR\tA%VV\n"
    # M80 evaluates a `%' after other text: 41 37.  `!%' is a `%': 25 56 56.
    assert _code(src + "\tSTR\t!%VV\n") == '4137' '255656'
    # MAC and RMAC only one that starts the argument, and not in <...>:
    # 41 25 56 56 25 56 56 (M80 flags <%VV> O).
    assert _code(src + "\tSTR\t<%VV>\n", dri=True) == '41255656' '255656'


@BOTH
def test_a_percent_in_a_body_line_is_an_error(dri):
    # Only an argument is a value: M80 flags `DB %VV' O and MAC E, and both
    # assemble 00.  um80 used to assemble 07.
    ok, _, errors = _assemble("VV\tEQU\t7\nMM\tMACRO\n\tDB\t%VV\n\tENDM\n\tMM\n",
                              dri=dri)
    assert not ok
    assert len(errors) == 1, errors


def test_dri_a_dollar_in_the_expression_is_ignored():
    # MAC and RMAC: 05 0A, 05 0A (in a macro body), 06 07 (an IRP body),
    # 05 05 (a REPT body).  um80 with --dri gave 00 05 00 05 01 02 00 00.
    src = ("GEN\tMACRO\tN\n\tDB\tN\n\tENDM\n"
           "MM\tMACRO\n\tGEN\t%N$C\n\tGEN\t%NC+N$C\n\tENDM\n"
           "NC\tEQU\t5\n"
           "\tGEN\t%N$C\n\tGEN\t%NC+N$C\n"
           "\tMM\n"
           "\tIRP\tX,<1,2>\n\tGEN\t%N$C+X\n\tENDM\n"
           "\tREPT\t2\n\tGEN\t%N$C\n\tENDM\n")
    assert _code(src, dri=True) == '050a' '050a' '0607' '0505'


@BOTH
def test_an_undefined_name_is_an_error(dri):
    # M80 3.44 flags `GEN %UNDF' U (a fatal error) and MAC U; both pass 0.
    # um80 passed 0 without a word.
    ok, _, errors = _assemble("GEN\tMACRO\tN\n\tDB\tN\n\tENDM\n\tGEN\t%UNDF\n"
                              "\tDB\t1\n", dri=dri)
    assert not ok
    assert errors == ["Error at line 6: Undefined symbol 'UNDF'"], errors


def test_without_dri_a_dollar_name_is_undefined_there_too():
    # M80: N$C is not NC, and each `%N$C' is U.
    ok, _, errors = _assemble("GEN\tMACRO\tN\n\tDB\tN\n\tENDM\nNC\tEQU\t5\n"
                              "\tGEN\t%N$C\n\tGEN\t%NC+N$C\n")
    assert not ok
    assert len(errors) == 2 and all("'N$C'" in e for e in errors), errors


def test_a_forward_reference_is_its_value():
    # M80 (which flags it V in pass 1) and MAC: 09.
    assert _code("GEN\tMACRO\tN\n\tDB\tN\n\tENDM\n\tGEN\t%F\nF\tEQU\t9\n") == '09'
    assert _code("GEN\tMACRO\tN\n\tDB\tN\n\tENDM\n\tGEN\t%F\nF\tEQU\t9\n",
                 dri=True) == '09'
