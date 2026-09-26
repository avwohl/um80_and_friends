"""--dri: what MAC and RMAC assemble after a macro call on its line.

MAC 2.0 and RMAC 1.1 read what follows a macro call's arguments as text,
to the first `!' there that follows a character other than a blank or a
tab, and go on with the statement after that `!'.  Up to it a `;' starts a
comment that ends at the next `!', which counts as such a character, and a
`!' after a blank is text; the first character after the macro's name is
text whatever it is, when the call has no arguments.  A `!' that ends the
arguments ends the call's statement, and the next one is left out the same
way.  So a call with no arguments and a `;' comment ends at the comment's
`!', as any other statement does: `MM ;c! DB 1' assembles DB 1.  `MM A;c!
DB 1', `MM A ! DB 1', `MM ! DB 1', `MM ;c ! DB 1' and `MM ;;c! DB 1' leave
it out, and `MM A;c!! DB 1' does not (the statement left out is empty).
A call reads as many arguments as the macro has parameters, and the rest
as text: `NOP! MM A! DB 1' assembles DB 1 where MM has no parameter, and
leaves it out where MM has one.  (At the start of a line a `!' right after
an argument is still M80's quote in um80, but for a macro with no
parameters.)

um80 --dri left out all that followed a call's arguments: `MM ;c! DB 1' was
MM's bytes only, without a word, and `NOP! MM ;c! DB 1' warned, wrongly,
that MAC leaves DB 1 out.  It took `MM A ! DB 1' and `MM ! DB 1' for
arguments it reported.  And a line of a body being defined that starts
with a macro call, or an IRP or IRPC, was not read for the ENDM after a
`!' (`NN MACRO / MM ;c! ENDM', `IRPC C,AB ! NOP ! ENDM' in a macro), so
the body ran to the end of the file; nor was a macro call's line in a
false IF for its ENDIF.

Every expected result is what MAC 2.0 and RMAC 1.1 assemble from the same
CR LF source under cpmemu (--dri --aseg, ORG 100H).
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler

M0 = "MM\tMACRO\n\tDB\t0EEH\n\tENDM\n"
M1 = "MM\tMACRO\tP\n\tDB\t0EEH,'&P'\n\tENDM\n"

# (source, MAC's bytes); none leaves out a statement.
GOES_ON = {
    'comment': (M0 + "\tMM ;c! DB 1\n", 'ee 01'),
    'comment_p': (M1 + "\tMM ;c! DB 1\n", 'ee 01'),
    'no_blanks': (M0 + "\tMM;c!DB 1\n", 'ee 01'),
    'words': (M1 + "\tMM ;no submit file! DB 1\n", 'ee 01'),
    'label': (M0 + "LAB:\tMM ;c! DB 1\n\tDW\tLAB\n", 'ee 01 00 01'),
    'label_no_colon': (M0 + "LAB\tMM ;c! DB 1\n\tDW\tLAB\n", 'ee 01 00 01'),
    'after_bang': (M0 + "\tNOP! MM ;c! DB 1\n", '00 ee 01'),
    'two_after': (M0 + "\tMM ;c! NOP! DB 1\n", 'ee 00 01'),
    'comment_after': (M0 + "\tMM ;c!;d!DB 1\n", 'ee 01'),
    'empty_left_out': (M0 + "\tMM !! DB 1\n", 'ee 01'),
    'empty_left_out_arg': (M1 + "\tMM A;c!! DB 1\n", 'ee 41 01'),
    'empty_after_blank': (M1 + "\tMM A ! ;c!! DB 1\n", 'ee 41 01'),
    'percent': (M1 + "\tMM %1+1!! DB 1\n", 'ee 32 01'),
    'two_calls': (M1 + "\tMM ;c! MM B;d!! DB 1\n", 'ee ee 42 01'),
    'equ': (M0 + "\tMM ;c! X EQU 5\n\tDB\tX\n", 'ee 05'),
    'irpc': (M0 + "\tMM ;c! IRPC Y,AB\n\tDB\t'&Y'\n\tENDM\n", 'ee 41 42'),
    'end': (M0 + "\tMM ;c! END\n\tDB\t9\n", 'ee'),
    'else': (M0 + "\tIF\t1\n\tMM ;c! ELSE\n\tDB\t2\n\tENDIF\n\tDB\t9\n", 'ee 09'),
    # MM with no parameter reads no argument; with one, the second is text.
    'no_parameter': (M0 + "\tMM A! DB 1\n", 'ee 01'),
    'no_parameter_words': (M0 + "\tMM A B,C! DB 1\n", 'ee 01'),
    'after_bang_no_parameter': (M0 + "\tNOP! MM A! DB 1\n", '00 ee 01'),
    'after_bang_extra': (M1 + "\tNOP! MM A,B! DB 1\n", '00 ee 41 01'),
    'after_bang_empty': (M1 + "\tNOP! MM A!! DB 1\n", '00 ee 41 01'),
    # In a body, where it is expanded or repeated.
    'body': (M0 + "NN\tMACRO\n\tMM ;c! DB 1\n\tENDM\n\tNN\n\tNN\n", 'ee 01 ee 01'),
    'rept': (M0 + "\tREPT\t2\n\tMM ;c! DB 1\n\tENDM\n", 'ee 01 ee 01'),
    'irp': (M0 + "\tIRP\tX,<1,2>\n\tMM ;c! DB X\n\tENDM\n", 'ee 01 ee 02'),
    'irp_argument': (M1 + "\tIRP\tX,<1,2>\n\tMM X;c!! DB X\n\tENDM\n",
                     'ee 31 01 ee 32 02'),
    'exitm': (M0 + "NN\tMACRO\n\tMM ;c! EXITM\n\tDB\t3\n\tENDM\n\tNN\n\tDB\t9\n",
              'ee 09'),
}

# (source, MAC's bytes, the statements um80 warns it leaves out).
LEAVES_OUT = {
    'blank_before_bang': (M0 + "\tMM ;c ! DB 1\n", 'ee', 'DB 1'),
    'second_semicolon': (M0 + "\tMM ;;c! DB 1\n", 'ee', 'DB 1'),
    'bang_first': (M0 + "\tMM ! DB 1\n", 'ee', 'DB 1'),
    'bang_first_p': (M1 + "\tMM ! DB 1\n", 'ee', 'DB 1'),
    'argument_blank': (M1 + "\tMM A ! DB 1\n", 'ee 41', 'DB 1'),
    'argument_comment': (M1 + "\tMM A;c! DB 1\n", 'ee 41', 'DB 1'),
    'next_one_goes_on': (M1 + "\tMM A ;c! DB 1! DB 2\n", 'ee 41 02', 'DB 1'),
    'blank_bang_twice': (M0 + "\tMM ;c ! ! DB 1! DB 2\n", 'ee 02', 'DB 1'),
    'percent_blank': (M1 + "\tMM %1+1 ! DB 1! DB 2\n", 'ee 32 02', 'DB 1'),
    'after_bang_parameter': (M1 + "\tNOP! MM A! DB 1\n", '00 ee 41', 'DB 1'),
    'after_bang_blank': (M0 + "\tNOP! MM ;c ! DB 1! DB 2\n", '00 ee 02', 'DB 1'),
    'else_left_out': (M1 + "\tIF\t1\n\tMM A;c! ELSE\n\tDB\t2\n\tENDIF\n",
                      'ee 41 02', 'ELSE'),
    # The second call leaves out DB 2.
    'second_call': (M1 + "\tMM A;c! DB 1! MM B! DB 2\n", 'ee 41 ee 42',
                    'DB 1', 'DB 2'),
}

# A line of a body being defined, read for the ENDM after a `!'; and a
# call's line in a false IF, read for the ENDIF.
BODIES = {
    'endm': (M0 + "NN\tMACRO\n\tMM ;c! ENDM\n\tNN\n\tDB\t9\n", 'ee 09'),
    'endm_then': (M0 + "NN\tMACRO\n\tMM ;c! ENDM! DB 5\n\tNN\n\tDB\t9\n",
                  '05 ee 09'),
    'rept_in_body': (M0 + "NN\tMACRO\n\tMM ;c! REPT 2\n\tDB\t1\n\tENDM\n"
                     "\tDB\t3\n\tENDM\n\tNN\n\tDB\t9\n", 'ee 01 01 03 09'),
    'irpc_in_body': (M0 + "NN\tMACRO\n\tMM ;c! IRPC C,AB\n\tDB\t'&C'\n\tENDM\n"
                     "\tENDM\n\tNN\n\tDB\t9\n", 'ee 41 42 09'),
    'rept_endm': (M0 + "\tREPT\t2\n\tMM ;c! ENDM\n\tDB\t9\n", 'ee ee 09'),
    'irpc_line': ("MM\tMACRO\n\tIRPC C,AB ! NOP ! ENDM\n\tDB\t3\n\tENDM\n"
                  "\tMM\n\tDB\t9\n", '00 00 03 09'),
    'false_if': (M0 + "\tIF\t0\n\tMM ;c ! ENDIF\n\tDB\t2\n", '02'),
    'false_if_argument': (M1 + "\tIF\t0\n\tMM A;c! ENDIF\n\tDB\t2\n", '02'),
}


def _assemble(source):
    """(ok, bytes loaded, errors, warnings), --dri --aseg at 0100H."""
    data = ("\tORG\t100H\n" + source + "\tEND\n").replace('\n', '\r\n')
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'wb') as f:
            f.write(data.encode('latin1'))
        asm = Assembler(dri=True)
        asm.default_seg = asm.current_seg = 'ASEG'
        ok = asm.assemble(p)
        code = bytearray()
        if ok:
            for it in RELReader(asm.output.get_bytes()).read_all():
                if it[0] == 'ABSOLUTE_BYTE':
                    code.append(it[1])
    return ok, code.hex(' '), [str(e) for e in asm.errors], asm.warnings


def test_a_call_goes_on_at_the_bang_after_its_comment():
    for name, (source, code) in GOES_ON.items():
        ok, got, errors, warnings = _assemble(source)
        assert ok, (name, errors)
        assert (got, warnings) == (code, []), name


def test_the_statement_left_out_is_warned_about():
    for name, (source, code, *left) in LEAVES_OUT.items():
        ok, got, errors, warnings = _assemble(source)
        assert ok, (name, errors)
        assert got == code, name
        assert [w.split(': ', 1)[1] for w in warnings] == [
            f"'{stmt}' after a macro call is left out, as in MAC and RMAC (--dri)"
            for stmt in left], (name, warnings)


def test_a_body_line_is_read_for_its_endm_and_a_false_if_for_its_endif():
    for name, (source, code) in BODIES.items():
        ok, got, errors, warnings = _assemble(source)
        assert ok, (name, errors)
        assert (got, warnings) == (code, []), name


def test_a_bang_in_the_arguments_of_the_first_statement_is_as_before():
    # M80's quote, as EXTENSIONS.md says (MAC: EE 41, the rest left out):
    # `MM A!B' passes AB, and `MM A! DB 1' is an argument um80 reports.
    ok, got, _, _ = _assemble(M1 + "\tMM A!B\n")
    assert ok and got == 'ee 41 42'
    ok, _, errors, _ = _assemble(M1 + "\tMM A! DB 1\n")
    assert not ok and any('after the blank that ends the arguments' in e
                          for e in errors), errors
