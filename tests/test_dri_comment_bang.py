"""--dri: a `!' ends a `;' comment and starts the next statement, as in MAC.

DRI's MAC 2.0 and RMAC 1.1 read a comment to the end of the line or to a
`!', whichever comes first, and the `!' then separates statements as it
does outside a comment: `NOP ;c! DB 1' is 00 01, and `; whole line! DB 1'
is 01.  DRI's sources rely on it.  CP/M 2.0's CCP (os2ccp.asm) has `nosub:
;no submit file! call del$sub', `setnam1: mov m,a ;store character to fcb!
inx d' and `mov d,a ;save value! mov a,b ;mult by 10'; MP/M II's
disk2_files/ldrbios.asm has `;<TAB>in 0f5h ! ani 2 ! rz'.  um80 --dri read
the comment to the end of the line and dropped those statements without a
word: 1523 of MAC's 1887 bytes of the CCP differed, and 298 of LDRBIOS.

A quote in a comment starts no string (`NOP ;it's! DB 1' is 00 01), and a
`*' comment line ends at a `!' too (`* a;b! DB 1' is 01).  A statement
after the `!' may be a REPT, IRP or IRPC body line, IF, ENDIF, ENDM or an
EQU, as after any `!'.  After a macro call's arguments MAC leaves out the
statement after the `!' (`NOP! MM 1! DB 6' is 00 and MM's bytes); see
test_dri_after_macro_call.py.

Without --dri a comment runs to the end of the line, as in MACRO-80 3.44
(`NOP ;c! DB 1' is 00 there).

Every expected result below is what MAC 2.0 and RMAC 1.1 (or M80 3.44)
assemble from the same CR LF source under cpmemu.
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, dri=True):
    """(ok, bytes loaded, errors, warnings) for a source in CR LF lines."""
    data = (source + '\tEND\n').replace('\n', '\r\n').encode('latin1')
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'wb') as f:
            f.write(data)
        asm = Assembler(dri=dri)
        ok = asm.assemble(p)
        errors = [str(e) for e in asm.errors]
        warnings = [str(w) for w in asm.warnings]
        if not ok:
            return ok, b'', errors, warnings
        code = bytearray()
        for it in RELReader(asm.output.get_bytes()).read_all():
            if it[0] == 'ABSOLUTE_BYTE':
                code.append(it[1])
            elif it[0] == 'PROGRAM_REL':
                code += it[1].to_bytes(2, 'little')
        return ok, bytes(code), errors, warnings


def _code(source, dri=True):
    ok, code, errors, _ = _assemble(source, dri)
    assert ok, errors
    return code.hex(' ')


MM = "MM\tMACRO\tP\n\tDB\tP\n\tENDM\n"


# --- a statement after the comment -----------------------------------------

def test_a_bang_ends_a_comment():
    # MAC and RMAC: 00 01 02.  um80 --dri 0.3.51 before this: 00 02.
    assert _code("\tNOP\t;comment! DB 1\n\tDB\t2\n") == '00 01 02'


def test_a_comment_line_ends_at_a_bang():
    # 01; um80 left the line out.
    assert _code("; whole line comment! DB 1\n") == '01'
    assert _code("LAB:\t;comment ! DB 1\n\tDB\t2\n") == '01 02'


def test_the_next_statement_may_have_a_comment_too():
    # 00 03, 00 04 (y is a label), 00 00 04, 00 01.
    assert _code("\tNOP\t;c!;d! DB 3\n") == '00 03'
    assert _code("\tNOP\t;x!y! DB 4\n") == '00 04'
    assert _code("\tNOP\t;x!NOP! DB 4\n") == '00 00 04'
    assert _code("\tNOP\t;c!! DB 1\n") == '00 01'


def test_a_quote_in_a_comment_starts_no_string():
    # 00 01 each: the comment is text to the `!'.
    assert _code("\tNOP\t;it's! DB 1\n") == '00 01'
    assert _code("\tNOP\t;a 'b! DB 1\n") == '00 01'
    assert _code("\tNOP\t;a \"b! DB 1\n") == '00 01'


def test_the_ccp_lines():
    # CP/M 2.0's os2ccp.asm, lines 226, 347 and 499.  MAC and RMAC (at 0):
    # CD 09 00 / 77 13 / 3E 01 57 78 / C9.
    src = ("NOSUB:\t;no submit file! call del$sub\n"
           "SETNAM1: MOV M,A ;store character to fcb! INX D\n"
           "\tMVI\tA,1\n"
           "\tMOV\tD,A ;save value! MOV A,B ;mult by 10\n"
           "DEL$SUB: RET\n")
    assert _code(src) == 'cd 09 00 77 13 3e 01 57 78 c9'


def test_an_equ_and_a_label_after_the_comment():
    # 05; 00 01 01 00 (LAB is 0001H).
    assert _code("X\tEQU\t5 ;c! DB X\n") == '05'
    assert _code("\tNOP\t;c!\tLAB: DB 1\n\tDW\tLAB\n") == '00 01 01 00'


# --- conditionals ----------------------------------------------------------

def test_an_if_and_an_endif_after_the_comment():
    # 08 09; 00 03; 02.  um80: 09, "ENDIF without IF", "Unterminated
    # conditional".
    assert _code("\tIF\t1 ;c! DB 8\n\tDB\t9\n\tENDIF\n") == '08 09'
    assert _code("\tNOP\t;c! IF 0\n\tDB 2\n\tENDIF\n\tDB 3\n") == '00 03'
    assert _code("\tIF\t0\n\tNOP\t;c! ENDIF\n\tDB 2\n") == '02'


def test_a_false_if_skips_the_statement_after_the_comment():
    # 0A.
    assert _code("\tIF\t0 ;c! DB 8\n\tDB\t9\n\tENDIF\n\tDB 0AH\n") == '0a'


# --- macro bodies ----------------------------------------------------------

def test_a_macro_body_line():
    # 00 07, and 07 for a comment line.
    assert _code("MM\tMACRO\n\tNOP\t;c! DB 7\n\tENDM\n\tMM\n") == '00 07'
    assert _code("MM\tMACRO\n;c! DB 7\n\tENDM\n\tMM\n") == '07'


def test_a_double_semicolon_comment_ends_at_a_bang():
    # MAC stores `NOP! DB 7': 00 07, 00 07, 00 00 02.
    assert _code("MM\tMACRO\n\tNOP\t;;c! DB 7\n\tENDM\n\tMM\n") == '00 07'
    assert _code("MM\tMACRO\n\tNOP\t;c ;;d! DB 7\n\tENDM\n\tMM\n") == '00 07'
    assert _code("MM\tMACRO\n\tNOP\t;c! NOP ;;d! DB 2\n\tENDM\n\tMM\n") \
        == '00 00 02'


def test_the_macro_line_itself():
    # `MM MACRO P ;c! DB P' then `MM 3': 03.
    assert _code("MM\tMACRO\tP ;c! DB P\n\tENDM\n\tMM\t3\n") == '03'


def test_a_parameter_after_a_quote_in_a_comment():
    # 00 01 31 00 02 32: the quote in `it's' does not pair with the one
    # before &X.  00 04 with the parameter in the comment.
    assert _code("\tIRP\tX,<1,2>\n\tNOP\t;it's! DB X,'&X'\n\tENDM\n") \
        == '00 01 31 00 02 32'
    assert _code("MM\tMACRO\tP\n\tNOP\t;P! DB P\n\tENDM\n\tMM 4\n") == '00 04'
    assert _code("\tIRPC\tX,AB\n\tNOP\t;c! DB '&X'\n\tENDM\n") == '00 41 00 42'


def test_a_quote_after_a_blank_in_a_comment():
    # 00 01 31 00 02 32 and 00 07: `'b! DB X,'' is no string.
    assert _code("\tIRP\tX,<1,2>\n\tNOP\t;a 'b! DB X,'&X'\n\tENDM\n") \
        == '00 01 31 00 02 32'
    assert _code("MM\tMACRO\n\tNOP\t;a 'b! DB 7\n\tENDM\n\tMM\n") == '00 07'


def test_an_exitm_after_the_comment_ends_the_expansion():
    # 00 07, 00 07, 07, 07 and 05 07.  um80: 00 05 07, 00 05 06 07, 05 07,
    # 05 07 and 05 07.
    assert _code("MM\tMACRO\n\tNOP ;c! EXITM\n\tDB 5\n\tENDM\n\tMM\n"
                 "\tDB 7\n") == '00 07'
    assert _code("MM\tMACRO\n\tNOP! EXITM! DB 5\n\tDB 6\n\tENDM\n\tMM\n"
                 "\tDB 7\n") == '00 07'
    assert _code("MM\tMACRO\n\tIF 1! EXITM! ENDIF\n\tDB 5\n\tENDM\n\tMM\n"
                 "\tDB 7\n") == '07'
    assert _code("MM\tMACRO\n\tIF 1 ;c! EXITM ;d! ENDIF\n\tDB 5\n\tENDM\n"
                 "\tMM\n\tDB 7\n") == '07'
    assert _code("MM\tMACRO\n\tIF 0! EXITM! ENDIF\n\tDB 5\n\tENDM\n\tMM\n"
                 "\tDB 7\n") == '05 07'


def test_an_exitm_after_a_bang_ends_the_repetition():
    # 00 07, 00 07 and 00 05 07 (the REPT's EXITM ends the REPT, not MM).
    # um80: 00 05 06 07, 00 05 00 05 07 and 00 00 05 07.
    assert _code("\tREPT\t1\n\tNOP! EXITM! DB 5\n\tDB 6\n\tENDM\n\tDB 7\n") \
        == '00 07'
    assert _code("\tIRPC\tX,AB\n\tNOP! EXITM\n\tDB 5\n\tENDM\n\tDB 7\n") \
        == '00 07'
    assert _code("MM\tMACRO\n\tREPT 2\n\tNOP! EXITM\n\tENDM\n\tDB 5\n"
                 "\tENDM\n\tMM\n\tDB 7\n") == '00 05 07'


def test_an_endm_after_the_comment_ends_the_body():
    # 00 01, 00 00 01 each: MAC ends the MACRO or REPT at that ENDM.  um80:
    # "Unterminated MACRO", nothing assembled.
    assert _code("MM\tMACRO\n\tNOP ;c! ENDM\n\tMM\n\tDB 1\n") == '00 01'
    assert _code("MM\tMACRO\n\tNOP! ENDM\n\tMM\n\tDB 1\n") == '00 01'
    assert _code("\tREPT\t2\n\tNOP ;c! ENDM\n\tDB 1\n") == '00 00 01'
    assert _code("\tREPT\t2\n\tNOP! ENDM\n\tDB 1\n") == '00 00 01'


def test_the_statements_after_the_endm_are_assembled():
    # 05 00 01: DB 5 is assembled where the macro is defined.
    assert _code("MM\tMACRO\n\tNOP! ENDM! DB 5\n\tMM\n\tDB 1\n") == '05 00 01'


def test_an_irpc_after_the_comment_in_a_macro_body_nests():
    # 00 41 42: the IRPC's ENDM does not end MM.  um80: "ENDM without
    # MACRO".
    assert _code("MM\tMACRO\n\tNOP\t;c! IRPC X,AB ;d! DB '&X'\n"
                 "\tENDM\n\tENDM\n\tMM\n") == '00 41 42'


# --- REPT, IRP and IRPC lines ----------------------------------------------

def test_a_rept_line():
    # 05 06 05 06; 00 05 00 05.
    assert _code("\tREPT\t2 ;c! DB 5\n\tDB\t6\n\tENDM\n") == '05 06 05 06'
    assert _code("\tREPT\t2 ;c! NOP ;d! DB 5\n\tENDM\n") == '00 05 00 05'


def test_an_irp_line():
    # 05 01 05 02; 01 02; 00 01 00 02.
    assert _code("\tIRP\tX,<1,2> ;c! DB 5\n\tDB\tX\n\tENDM\n") == '05 01 05 02'
    assert _code("\tIRP\tX,<1,2>;c! DB X\n\tENDM\n") == '01 02'
    assert _code("\tIRP\tX,<1,2> ! NOP ;c! DB X\n\tENDM\n") == '00 01 00 02'


def test_an_irpc_line():
    # 05 41 05 42; 41 09 42 09; 41 42; 00 41 00 42.
    assert _code("\tIRPC\tX,AB ;c! DB 5\n\tDB\t'&X'\n\tENDM\n") == '05 41 05 42'
    assert _code("\tIRPC\tX,AB ;c! DB '&X'\n\tDB\t9\n\tENDM\n") == '41 09 42 09'
    assert _code("\tIRPC\tX,AB;c! DB '&X'\n\tENDM\n") == '41 42'
    assert _code("\tIRPC\tX,AB ! NOP ;c! DB '&X'\n\tENDM\n") == '00 41 00 42'


# --- macro calls -----------------------------------------------------------

def test_a_macro_call_ends_the_line():
    # 01 07 (as before); 00 01 07 twice: MAC leaves out the statement after
    # the `!' after a macro call's arguments, in its comment or not.  um80:
    # 00 01 06 07 for the second.
    assert _code(MM + "\tMM\t1 ;c! DB 6\n\tDB 7\n") == '01 07'
    assert _code(MM + "\tNOP\t;c! MM 1 ;d! DB 6\n\tDB 7\n") == '00 01 07'
    assert _code(MM + "\tNOP! MM 1! DB 6\n\tDB 7\n") == '00 01 07'


def test_the_statement_left_out_after_a_macro_call_is_warned_about():
    ok, code, errors, warnings = _assemble(MM + "\tNOP! MM 1! DB 6\n")
    assert ok, errors
    assert code.hex(' ') == '00 01'
    assert any('DB 6' in w for w in warnings), warnings


# --- `*' comment lines -----------------------------------------------------

def test_a_star_line_ends_at_a_bang():
    # 01 each: a quote or a `;' in it starts nothing.
    assert _code("* it's! DB 1\n") == '01'
    assert _code("  * it's! DB 1\n") == '01'
    assert _code("* a;b! DB 1\n") == '01'
    assert _code("* star line! DB 1\n") == '01'


def test_a_line_feed_in_a_comment():
    # An 8AH that follows no CR is a LF, which is nothing in a comment -
    # a `;' one or a `*' line - and the `!' still ends it: 00 01 and 01.
    # um80: 00, and "A line feed outside a string or a comment" for the
    # second.
    assert _code("\tNOP\t;a\x8ab! DB 1\n") == '00 01'
    assert _code("* a\x8ab! DB 1\n") == '01'


# --- without --dri ---------------------------------------------------------

def test_without_dri_a_comment_runs_to_the_end_of_the_line():
    # M80 3.44: 00; 00 02.
    assert _code("\tNOP\t;c! DB 1\n", dri=False) == '00'
    assert _code("\tNOP\t;c!\n\tDB\t2\n", dri=False) == '00 02'
