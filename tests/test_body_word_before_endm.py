"""A word with no colon in front of the ENDM, MACRO, REPT, IRP, IRPC or LOCAL
of a body being defined.

MACRO-80 3.44 reads each line of a MACRO, IRP or IRPC body it defines for
the directives that nest in the body and the ENDM that ends it, and takes
one after a word that is no instruction or directive (a label with no
colon, in any column, a macro's name, or a word made with `&'): `LAB ENDM'
and `<TAB>LAB<TAB>ENDM' end the body, `L&P ENDM' too, `LAB REPT 2' opens a
block the next ENDM ends, and `LAB LOCAL QQ' declares QQ.  The word is not
defined.  After an instruction or a directive the word is its operand, and
not read (`NOP ENDM', `DB ENDM'), and nor is a third word (`LAB FOO ENDM').
A REPT body is read for the first word only: `LAB ENDM' does not end one.

um80 0.3.50 took any word in column 1 for a label, so `LAB ENDM' ended
the body there, but `<TAB>LAB<TAB>ENDM' and `L&P ENDM' did not.  Once a
label needed its colon (column_one), `LAB ENDM' did not either: the body
ran to the end of the file, with only a warning that nothing after it was
assembled, and um80 exited 0 with that code missing.  `LAB LOCAL QQ' was an
unknown instruction.

With --dri a word with an `&' is a label as any other that is no
operation, as in MAC and RMAC, which define it where the body ends:
`L&P ENDM' ends the body there, `L&P REPT 2' opens a REPT, and `L&P LOCAL
QQ' declares QQ.  um80 --dri did not see the directive after such a word.

The expected bytes are what the genuine M80 3.44 (and MAC 2.0 and RMAC 1.1
for --dri) assemble from the same CR LF sources under cpmemu.
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, dri=False):
    """(ok, bytes loaded, errors, warnings) for `source' at 0100H."""
    head = "\tORG\t100H\n" if dri else "\tASEG\n\tORG\t100H\n"
    data = (head + source + "\tEND\n").replace('\n', '\r\n').encode('latin1')
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'wb') as f:
            f.write(data)
        asm = Assembler(dri=dri)
        if dri:
            asm.default_seg = asm.current_seg = 'ASEG'    # --aseg
        ok = asm.assemble(p)
        errors = [str(e) for e in asm.errors]
        warnings = [str(w) for w in asm.warnings]
        code = bytearray()
        if ok:
            for it in RELReader(asm.output.get_bytes()).read_all():
                if it[0] == 'ABSOLUTE_BYTE':
                    code.append(it[1])
                elif it[0] == 'PROGRAM_REL':
                    code += it[1].to_bytes(2, 'little')
    return ok, code.hex(' '), errors, warnings


def _code(source, dri=False):
    ok, code, errors, warnings = _assemble(source, dri)
    assert ok, errors
    assert not any('Unterminated' in w for w in warnings), warnings
    return code


# --- MACRO-80 --------------------------------------------------------------

def test_a_label_with_no_colon_on_the_endm():
    # M80: 01 02 09, 01 02, 01 02 09 - and um80 0.3.50.
    assert _code("\tIRP\tX,<1,2>\n\tDB\tX\nLAB\tENDM\n\tDB\t9\n") == '01 02 09'
    assert _code("MM\tMACRO\n\tDB\t1\nLAB\tENDM\n\tMM\n\tDB\t2\n") == '01 02'
    assert _code("\tIRPC\tX,12\n\tDB\tX\nLAB\tENDM\n\tDB\t9\n") == '01 02 09'
    assert _code("MM\tMACRO\n\tDB\t1\nlab\tendm\t;c\n\tMM\n\tDB\t2\n") == '01 02'


def test_in_any_column():
    # M80: 01 02 09, 01 02 (um80 0.3.50: unterminated too).
    assert _code("\tIRP\tX,<1,2>\n\tDB\tX\n\tLAB\tENDM\n\tDB\t9\n") == '01 02 09'
    assert _code("MM\tMACRO\n\tDB\t1\n\tLAB\tENDM\n\tMM\n\tDB\t2\n") == '01 02'


def test_a_word_made_with_an_ampersand():
    # M80: 03 02 each, and 01 02 09.
    for line in ("L&P\tENDM", "\tL&P\tENDM", "A&P&B\tENDM"):
        assert _code(f"MM\tMACRO\tP\n\tDB\tP\n{line}\n\tMM\t3\n\tDB\t2\n") == '03 02'
    assert _code("\tIRP\tX,<1,2>\n\tDB\tX\nL&X\tENDM\n\tDB\t9\n") == '01 02 09'


def test_nested_blocks():
    # M80: 01 02 07 02 (an IRP in a macro), 05 02 (a macro in a macro),
    # 01 02 02 (an IRPC in a macro).
    assert _code("MM\tMACRO\n\tIRP\tX,<1,2>\n\tDB\tX\nLAB\tENDM\n\tDB\t7\n"
                 "\tENDM\n\tMM\n\tDB\t2\n") == '01 02 07 02'
    assert _code("MM\tMACRO\nNN\tMACRO\n\tDB\t5\nLAB\tENDM\nLAB2\tENDM\n"
                 "\tMM\n\tNN\n\tDB\t2\n") == '05 02'
    assert _code("MM\tMACRO\n\tIRPC\tX,12\n\tDB\tX\nLAB\tENDM\n\tENDM\n"
                 "\tMM\n\tDB\t2\n") == '01 02 02'


def test_after_z80():
    # M80: 01 02.
    assert _code("\t.Z80\nMM\tMACRO\n\tDB\t1\nLAB\tENDM\n\tMM\n\tDB\t2\n") == '01 02'


def test_a_local_after_a_word():
    # M80: 01 01, 01 02 01 02, 01 01, 01 02 - QQ is local each time.
    assert _code("MM\tMACRO\nLAB\tLOCAL\tQQ\nQQ:\tDB\t1\n\tENDM\n\tMM\n\tMM\n") == '01 01'
    assert _code("MM\tMACRO\n\tDB\t1\nLAB\tLOCAL\tQQ\nQQ:\tDB\t2\n\tENDM\n"
                 "\tMM\n\tMM\n") == '01 02 01 02'
    assert _code("MM\tMACRO\n\tlab\tlocal\tQQ\nQQ:\tDB\t1\n\tENDM\n\tMM\n\tMM\n") == '01 01'
    assert _code("MM\tMACRO\tP\nL&P\tLOCAL\tQQ\nQQ:\tDB\tP\n\tENDM\n"
                 "\tMM\t1\n\tMM\t2\n") == '01 02'


def test_the_word_is_not_defined():
    # M80: U at DW LAB.
    ok, _, errors, _ = _assemble("MM\tMACRO\n\tDB\t1\nLAB\tENDM\n\tMM\n\tDW\tLAB\n")
    assert not ok
    assert any("Undefined symbol 'LAB'" in e for e in errors), errors


def test_a_block_opened_after_a_word_nests():
    # M80 reads `LAB REPT 2' for the REPT, so the macro ends at the second
    # ENDM, and then flags the expanded `LAB REPT 2' U and its ENDM O.
    ok, _, errors, warnings = _assemble(
        "MM\tMACRO\nLAB\tREPT\t2\n\tDB\t1\n\tENDM\n\tENDM\n\tMM\n\tDB\t2\n")
    assert not ok
    assert any('Unknown instruction or directive: LAB' in e for e in errors), errors
    # Not at the macro's own ENDM, line 7: um80 ended the body at the first.
    assert 'Error at line 7: ENDM without MACRO' not in errors, errors
    assert not any('Unterminated' in w for w in warnings), warnings


def test_not_after_an_instruction_a_directive_or_a_second_word():
    # M80 goes on to the next ENDM: 01 00 03 02 (Q), 01 00 03 02 (U), and
    # 01 00 03 02 (U) twice.
    for line in ("\tNOP\tENDM", "\tDB\tENDM", "LAB\tFOO\tENDM", "LAB:\tFOO\tENDM",
                 "LAB,ENDM", "LAB\tENDMX"):
        ok, _, errors, warnings = _assemble(
            f"MM\tMACRO\n\tDB\t1\n{line}\n\tDB\t3\n\tENDM\n\tMM\n\tDB\t2\n")
        assert not ok, line
        assert not any('Unterminated' in w for w in warnings), (line, warnings)
        assert not any('ENDM without MACRO' in e for e in errors), (line, errors)


def test_the_word_is_no_instruction_of_the_processor_in_use():
    # M80 ends the body at `HALT ENDM' in 8080 code, at `MOV ENDM' after
    # .Z80, and at `MM ENDM' where MM is a macro, then flags the ENDM after
    # it O: 03 01 02.
    for head, line in (("", "HALT\tENDM"), ("", "LDIR\tENDM"),
                       ("\t.Z80\n", "MOV\tENDM"),
                       ("MM\tMACRO\n\tDB\t7\n\tENDM\n", "MM\tENDM")):
        ok, _, errors, _ = _assemble(
            f"{head}NN\tMACRO\n\tDB\t1\n{line}\n\tDB\t3\n\tENDM\n\tNN\n\tDB\t2\n")
        assert not ok, line
        assert any('ENDM without MACRO' in e for e in errors), (line, errors)


def test_a_rept_body_is_read_for_the_first_word_only():
    # M80 does not end a REPT at `LAB ENDM': "Unterminated REPT".
    for line in ("LAB\tENDM", "\tLAB\tENDM"):
        _, _, _, warnings = _assemble(f"\tREPT\t2\n\tDB\t1\n{line}\n\tDB\t2\n")
        assert any('Unterminated REPT' in w for w in warnings), (line, warnings)
    # ... and a `LAB: ENDM' does: 01 01 02.
    assert _code("\tREPT\t2\n\tDB\t1\nLAB:\tENDM\n\tDB\t2\n") == '01 01 02'


# --- MAC and RMAC (--dri) --------------------------------------------------

def test_dri_a_word_made_with_an_ampersand():
    # MAC and RMAC: 03 02 each, and 01 02 09.
    for line in ("L&P\tENDM", "\tL&P\tENDM", "A&P&B\tENDM"):
        assert _code(f"MM\tMACRO\tP\n\tDB\tP\n{line}\n\tMM\t3\n\tDB\t2\n",
                     dri=True) == '03 02'
    assert _code("\tIRP\tX,<1,2>\n\tDB\tX\nL&X\tENDM\n\tDB\t9\n", dri=True) == '01 02 09'
    assert _code("\tIRP\tX,<1,2>\n\tDB\tX\n\tL&X\tENDM\n\tDB\t9\n", dri=True) == '01 02 09'


def test_dri_the_word_is_a_label_where_the_body_ends():
    # MAC: 03, then DW L3 = 0101H.
    assert _code("MM\tMACRO\tP\n\tDB\tP\nL&P\tENDM\n\tMM\t3\n\tDW\tL3\n",
                 dri=True) == '03 01 01'


def test_dri_a_rept_and_a_local_after_the_word():
    # MAC and RMAC: 03 03 02, and 01 02.
    assert _code("MM\tMACRO\tP\nL&P\tREPT\t2\n\tDB\tP\n\tENDM\n\tENDM\n"
                 "\tMM\t3\n\tDB\t2\n", dri=True) == '03 03 02'
    assert _code("MM\tMACRO\tP\nL&P\tLOCAL\tQQ\nQQ:\tDB\tP\n\tENDM\n"
                 "\tMM\t1\n\tMM\t2\n", dri=True) == '01 02'
