"""Messages and the listing name the physical line of the source file.

um80 counted every line it read, an expansion line of a macro or a REPT
included, so the message for a mistake after a macro call named a line
that is further down than the mistake (a file of 9 lines said line 15).
The position is now the line of the file, the file is named for a line in
an INCLUDE file, and -e and --pre text does not move the numbers of the
source file.  An expansion line has the position of the line that called
the macro or began the REPT.
"""

import subprocess
import sys

from um80.um80 import Assembler

MACRO_THEN_ERROR = ("M1\tMACRO\n\tnop\n\tnop\n\tnop\n\tENDM\n"
                    "\tM1\n\tM1\n\n\tbogus1\n")


def _run(tmp_path, source, *args, name='t.mac', files=None):
    """(exit code, stderr lines, listing lines) of the um80 command."""
    for fname, text in (files or {}).items():
        (tmp_path / fname).write_text(text)
    src = tmp_path / name
    src.write_text(source)
    listing = tmp_path / 't.prn'
    run = subprocess.run(
        [sys.executable, '-m', 'um80.um80', *args, str(src),
         '-o', str(tmp_path / 't.rel'), '-l', str(listing)],
        capture_output=True, text=True, cwd=tmp_path, check=False)
    lines = listing.read_text().split('\n') if listing.exists() else []
    return run.returncode, run.stderr.splitlines(), lines


def _numbers(listing):
    """The line numbers of the listing lines that have source text (the
    empty line after the last line end has none)."""
    return [int(line.split()[0]) for line in listing
            if len(line.split()) > 1]


def test_error_after_macro_calls(tmp_path):
    code, err, _ = _run(tmp_path, MACRO_THEN_ERROR)
    assert code == 1
    assert err == ['Error at line 9: Unknown instruction or directive: BOGUS1']


def test_error_after_rept(tmp_path):
    code, err, _ = _run(tmp_path, "\tREPT 5\n\tnop\n\tENDM\n\n\tbogus1\n")
    assert code == 1
    assert err == ['Error at line 5: Unknown instruction or directive: BOGUS1']


def test_error_inside_a_macro_is_at_the_call(tmp_path):
    code, err, _ = _run(tmp_path, "M1\tMACRO\n\tbogus1\n\tENDM\n\n\tM1\n")
    assert code == 1
    assert err == ['Error at line 5: Unknown instruction or directive: BOGUS1']


def test_warning_after_macro_calls(tmp_path):
    # The unterminated IF is reported at the END line, the 9th of the file.
    code, err, _ = _run(tmp_path, "M1\tMACRO\n\tnop\n\tnop\n\tENDM\n"
                        "\tM1\n\tM1\n\tIF 1\n\tnop\n\tend\n")
    assert code == 0
    assert err == ['Warning at line 9: Unterminated conditional '
                   '(missing ENDIF)']


def test_error_in_an_include_file_names_the_file(tmp_path):
    inc = "\tnop\nM1\tMACRO\n\tnop\n\tENDM\n\tM1\n\tM1\n\tbogus2\n"
    code, err, _ = _run(tmp_path, "\tnop\n\tINCLUDE inc.mac\n\tbogus3\n",
                        files={'inc.mac': inc})
    assert code == 1
    assert err == [
        'Error at line 7 of inc.mac: Unknown instruction or directive: BOGUS2',
        'Error at line 3: Unknown instruction or directive: BOGUS3']


def test_error_after_an_include_file_is_in_the_main_file(tmp_path):
    code, err, _ = _run(tmp_path, "\tINCLUDE inc.mac\n\tnop\n\tbogus3\n",
                        files={'inc.mac': "\tnop\n\tnop\n\tnop\n"})
    assert code == 1
    assert err == ['Error at line 3: Unknown instruction or directive: BOGUS3']


def test_error_after_execute_text(tmp_path):
    code, err, _ = _run(tmp_path, MACRO_THEN_ERROR, '-e', 'nop!nop!nop')
    assert code == 1
    assert err == ['Error at line 9: Unknown instruction or directive: BOGUS1']


def test_error_in_execute_text_names_it(tmp_path):
    code, err, _ = _run(tmp_path, "\tnop\n", '-e', 'nop!bogus1')
    assert code == 1
    assert len(err) == 1
    assert err[0].startswith('Error at line 2 of -e: Unknown instruction or '
                             'directive: BOGUS1')


def test_error_after_a_pre_file(tmp_path):
    code, err, _ = _run(tmp_path, "\tnop\n\tbogus1\n",
                        '--pre', 'pre.inc',
                        files={'pre.inc': "\tnop\n\tnop\n\tnop\n"})
    assert code == 1
    assert err == ['Error at line 2: Unknown instruction or directive: BOGUS1']


def test_listing_numbers_are_the_physical_lines(tmp_path):
    code, _, lst = _run(tmp_path, "swap\tMACRO a,b\n\tpush a\n\tpop b\n\tENDM\n"
                        "\t.z80\n\tld a,1\n\tswap bc,de\n\tld b,2\n"
                        "\tREPT 2\n\tnop\n\tENDM\n\tinc a\n")
    assert code == 0
    nums = _numbers(lst)
    # The two NOPs of the REPT have the REPT's line, 9.
    assert nums == [1, 5, 6, 7, 7, 7, 8, 9, 9, 9, 12]


def test_listing_call_line_has_no_bytes_and_comes_first(tmp_path):
    # The call line used to follow its expansion and repeat the last byte
    # of it: `7  0003  D1  swap bc,de' after `pop de'.
    _, _, lst = _run(tmp_path, "swap\tMACRO a,b\n\tpush a\n\tpop b\n\tENDM\n"
                     "\t.z80\n\tld a,1\n\tswap bc,de\n\tld b,2\n")
    rows = [line for line in lst if line.strip()]
    call = [i for i, row in enumerate(rows) if row.endswith('swap bc,de')]
    assert len(call) == 1
    assert rows[call[0]][5:25].strip() == ''  # no address, no bytes
    assert rows[call[0] + 1].split()[1:3] == ['0002', 'C5']
    assert rows[call[0] + 2].split()[1:3] == ['0003', 'D1']


def test_listing_numbers_in_an_include_file(tmp_path):
    _, _, lst = _run(tmp_path, "\tINCLUDE inc.mac\n\tnop\n",
                     files={'inc.mac': "\tnop\n\tnop\n"})
    nums = _numbers(lst)
    # The lines of the file, then the INCLUDE line and the line after it.
    assert nums == [1, 2, 1, 2]


def test_physical_position_leaves_the_jr_choice_alone(tmp_path):
    # Each expansion line keeps its own JR promotion: the call that jumps a
    # short way stays a JR (2 bytes), the call that jumps over the DS
    # becomes a JP (3 bytes).  If the two calls shared a key, both would be
    # JPs and the segment 207 bytes.
    p = tmp_path / 'j.mac'
    p.write_text("\t.z80\nM1\tMACRO\tt\n\tjr t\n\tENDM\n"
                 "near:\tM1 near\n\tM1 far\n\tds 200\nfar:\tnop\n\tend\n")
    asm = Assembler()
    assert asm.assemble(str(p))
    assert asm.segments['CSEG'].extent() == 2 + 3 + 200 + 1


def test_error_inside_a_rept_is_at_the_rept_line(tmp_path):
    # Each of the two repetitions reports the line of the REPT, not the
    # line of its ENDM (the 6th).
    code, err, _ = _run(tmp_path, "\tnop\n\tREPT 2\n\tnop\n\tbogusR\n"
                        "\tnop\n\tENDM\n\tnop\n\tret\n")
    assert code == 1
    assert err == ['Error at line 2: Unknown instruction or directive: BOGUSR'] * 2


def test_two_execute_options_count_on(tmp_path):
    code, err, _ = _run(tmp_path, "\tnop\n", '-e', ' bad1', '-e', ' bad2')
    assert code == 1
    assert err == ['Error at line 1 of -e: Unknown instruction or directive: BAD1',
                   'Error at line 2 of -e: Unknown instruction or directive: BAD2']


def test_block_line_in_a_warning_names_the_include_file(tmp_path):
    code, err, _ = _run(tmp_path, "\tnop\n\tINCLUDE inc.mac\n",
                        files={'inc.mac': "\tnop\n\tnop\nM2\tMACRO\n\tnop\n"})
    assert code == 0
    assert len(err) == 1
    assert '(line 3 of inc.mac): no ENDM' in err[0]
