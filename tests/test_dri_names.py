"""--dri: a `$' inside a name is ignored, as in DRI's MAC and RMAC.

DRI's MAC and RMAC ignore a `$' embedded in a name (MAC manual: "All
characters are significant in an identifier, except for the embedded dollar
sign ($) which can be used to improve readability"): NMB$LST and NMBLST are
one symbol.  MACRO-80 3.44 keeps it - `nmblst equ 5' then `lda nmb$lst' is an
undefined symbol there, and `ab equ 1' with `a$b equ 2' is two symbols - so
um80 keeps M80's reading by default and takes DRI's with --dri
(Assembler(dri=True)).

MP/M II's sources depend on it: NUCLEUS/MPM.ASM stores to nmb$lst, which
DATAPG.ASM defines as nmblst; RESBDOS1.ASM calls both SET$DMABUFA and
SET$DMA$BUFA; CLI.ASM defines cli$slct$user and uses cli$slctuser;
BNKBDOS.ASM defines getmemseg and calls GET$MEM$SEG.

The expected values are what MAC 2.0 and RMAC 1.1 assemble from the same
source under cpmemu; the ones without --dri are M80 3.44's.
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, **kw):
    """(ok, REL items or None, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        items = RELReader(asm.output.get_bytes()).read_all() if ok else None
    return ok, items, [str(e) for e in asm.errors]


def _code(items):
    return bytes(it[1] for it in items if it[0] == 'ABSOLUTE_BYTE')


REPRO = ("\taseg\n\torg\t100h\nnmblst\tequ\t5\n\tlda\tnmb$lst\n"
         "seekdir:\n\tcall\tseek$dir\n\tlxi\th,a$b$c\na$bc:\tnop\n"
         "\tani\t0001$1111b\n\tend\n")


def test_dollar_in_a_name_is_ignored_with_dri():
    # MAC and RMAC: 3A 05 00, CD 03 01, 21 09 01, 00, E6 1F.
    ok, items, errors = _assemble(REPRO, dri=True)
    assert ok, errors
    assert _code(items).hex() == '3a0500cd0301210901' + '00e61f'


def test_without_dri_a_dollar_is_part_of_the_name():
    # M80 3.44 flags each use U: NMB$LST, SEEK$DIR and A$B$C are not defined.
    ok, _, errors = _assemble(REPRO)
    assert not ok
    assert any("'nmb$lst'" in e for e in errors), errors


def test_m80_keeps_two_names_dri_makes_one():
    src = "\taseg\n\torg\t100h\nab\tequ\t1\na$b\tequ\t2\n\tdb\tab,a$b\n\tend\n"
    ok, items, errors = _assemble(src)
    assert ok, errors
    assert _code(items) == bytes([1, 2])           # M80: two symbols
    ok, _, errors = _assemble(src, dri=True)
    assert not ok                                  # MAC: AB defined twice (P)


def test_strings_the_location_counter_and_macros():
    # MAC 2.0 assembles this to 01010101 0203 702431 0405 702431
    # 61246224 1201120116011A01 EE 07 02FF.  Inside quotes a $ stays; a $
    # that starts a word is the location counter; a macro's name and
    # parameters lose theirs too.
    src = ("\taseg\n\torg\t100h\nab\tequ\t1\n"
           "\tdb\ta$b,a$$b,ab$,ab$$\n"
           "m$ac\tmacro\tp$1,q\n\tdb\tp1,q$\n\tdb\t'p$1'\n\tendm\n"
           "\tmac\t2,3\n\tm$a$c\t4,5\n"
           "\tdb\t'a$b','$'\n"
           "x$y:\tdw\txy,x$y,$,$+2\n"
           "\tif\ta$b eq 1\n\tdb\t0eeh\n\tendif\n"
           "z$z\tset\t7\n\tdb\tzz\n"
           "\tdb\t1$0b,0$ffh\t; a$b in a comment\n\tend\n")
    ok, items, errors = _assemble(src, dri=True)
    assert ok, errors
    assert _code(items).hex() == ('01010101' '0203' '702431' '0405' '702431'
                                  '61246224' '1201120116011a01' 'ee' '07' '02ff')


def test_public_and_extrn_names():
    # RMAC 1.1 writes ENTRY ABCDEF and the external CD, and keeps the $ of
    # the quoted NAME.
    src = ("\tname\t'm$od'\n\tpublic\ta$bcdefgh\n\textrn\tc$d\n"
           "a$bcdefgh:\tcall\tc$d\n\tcall\tcd\n\tend\n")
    ok, items, errors = _assemble(src, dri=True, truncate_symbols=True)
    assert ok, errors
    names = {it[0]: it[-1] for it in items
             if it[0] in ('PROGRAM_NAME', 'DEFINE_ENTRY', 'CHAIN_EXTERNAL')}
    assert names == {'PROGRAM_NAME': 'M$OD', 'DEFINE_ENTRY': 'ABCDEF',
                     'CHAIN_EXTERNAL': 'CD'}


def test_drop_name_dollars():
    from um80.um80 import drop_name_dollars  # pylint: disable=import-outside-toplevel
    assert drop_name_dollars("\tlda\tnmb$lst") == "\tlda\tnmblst"
    assert drop_name_dollars("x$y:\tdw\t$+2,$") == "xy:\tdw\t$+2,$"
    assert drop_name_dollars("\tdb\t'it''s$',x$y ; c$d") == "\tdb\t'it''s$',xy ; c$d"
    assert drop_name_dollars("$-MACRO") == "$-MACRO"
    assert drop_name_dollars("\tex\taf,af' ;x$y") == "\tex\taf,af' ;x$y"


def test_cli_option(tmp_path):
    import subprocess  # pylint: disable=import-outside-toplevel
    import sys  # pylint: disable=import-outside-toplevel
    src = tmp_path / "t.asm"
    src.write_text("nmblst\tequ\t5\n\tlda\tnmb$lst\n\tend\n")
    env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(__file__)))
    run = subprocess.run([sys.executable, "-m", "um80.um80", "--dri", str(src)],
                         capture_output=True, text=True, env=env, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    run = subprocess.run([sys.executable, "-m", "um80.um80", str(src)],
                         capture_output=True, text=True, env=env, check=False)
    assert run.returncode == 1
    assert "nmb$lst" in run.stderr
