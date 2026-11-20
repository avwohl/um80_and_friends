"""A name may begin with a dot, as in MACRO-80 (issue #7).

um80 read a word that began with '.' as a dot-directive (.Z80, .PHASE, ...)
and never as a name: `.FOO:' was "Unknown instruction or directive: .FOO"
and `JP .FOO' was "Cannot parse expression".  Worse, `.Z80:<TAB>NOP' took
the Z80 directive, defined no label, and dropped the NOP without a word.

Measured with MACRO-80 3.44 and LINK-80 3.44 under cpmemu on 2026-11-20,
every expected value below read from the real programs in that run (an
ASEG program at 100H gives the bytes of the .PRN directly; the two-module
link gives the OUT.COM bytes): a name is [A-Za-z$.?@_] and then
[A-Za-z0-9$.?@_]*, so .FOO, ..BAR, .XC.0, .201B, .0, .1H and even '.' are
names, and a name with a leading dot acts in every position as the same
name without it.  The one special case is the first word of a statement that
is a dot-directive and is not followed at once by ':': that is the
directive.  `.Z80:' (also indented, also `::') is a label, and the mode, the
listing and the phase do not change.  '.' is not the location counter ($ is),
and M80 has no `.AND.'-style operators: `.AND.' is an undefined name.  M80
keeps 16 characters of a name and writes 6 in the .REL.

--dri follows MAC for a name with no colon (a dot word with no colon stays an
error, so a mistyped dot-directive is not a label), and accepts `.NAME:'
labels, which MAC does not: that part is not measured with MAC.
"""

import os

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler
from um80.ul80 import Linker


def _asm(source, tmp_path, name="t", **kw):
    p = os.path.join(str(tmp_path), name + ".mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler(**kw)
    return asm.assemble(p), asm


def _absolute_bytes(asm):
    return bytes(i[1] for i in RELReader(asm.output.get_bytes()).read_all()
                 if i[0] == 'ABSOLUTE_BYTE').hex()


def _program(body, z80):
    return ("\t.Z80\n" if z80 else "") + "\tASEG\n\tORG\t100H\n" + body + "\tEND\n"


def _bytes_of(body, z80, tmp_path, **kw):
    ok, asm = _asm(_program(body, z80), tmp_path, **kw)
    assert ok, [e.message for e in asm.errors]
    return _absolute_bytes(asm)


# (id, Z80 mode, body, the bytes of M80's .PRN; None where M80 reports an error)
CASES = [
    ('issue_repro', True,
     '.FOO:\tNOP\n\tJP\t.FOO\n',
     '00c30001'),
    ('label_indented_dcolon_alone', False,
     '\t.FOO:\tNOP\n\t..BAR::\tNOP\n.A:\n.B:\tNOP\n.C:\t; comment\n\tDW\t.FOO,..BAR,.A,.B,.C\n',
     '00000000010101020102010301'),
    ('forward_ref', False,
     '\tJMP\t.FWD\n.FWD:\tNOP\n',
     'c3030100'),
    ('def_EQU_col1', False,
     '.FOO\tEQU\t5\n\tMVI\tA,.FOO\n',
     '3e05'),
    ('def_EQU_indented', False,
     '\t.FOO\tEQU\t5\n\tMVI\tA,.FOO\n',
     '3e05'),
    ('def_SET_col1', False,
     '.FOO\tSET\t5\n\tMVI\tA,.FOO\n',
     '3e05'),
    ('def_SET_indented', False,
     '\t.FOO\tSET\t5\n\tMVI\tA,.FOO\n',
     '3e05'),
    ('def_DEFL_col1', False,
     '.FOO\tDEFL\t5\n\tMVI\tA,.FOO\n',
     '3e05'),
    ('def_DEFL_indented', False,
     '\t.FOO\tDEFL\t5\n\tMVI\tA,.FOO\n',
     '3e05'),
    ('def_aset', False,
     '.FOO\tDEFL\t5\n.FOO\tASET\t6\n\tDB\t.FOO\n',
     '06'),
    ('set_redefine', False,
     '.BAR\tSET\t1\n\tDB\t.BAR\n.BAR\tSET\t.BAR+1\n\tDB\t.BAR\n',
     '0102'),
    ('equ_alias', False,
     '.FOO\tEQU\t7\n.BAR\tEQU\t.FOO\n\tDB\t.BAR\n',
     '07'),
    ('equ_forward', False,
     '\tDB\t.FWD\n.FWD\tEQU\t6\n',
     '06'),
    ('expr_ops', False,
     '.FOO\tEQU\t5\n.BAR\tEQU\t3\n\tDB\t.FOO+1,1+.FOO,.FOO-.BAR,-.FOO,NOT .FOO\n\tDB\tHIGH .FOO,LOW .FOO,.FOO SHL 1,.FOO EQ 5,.FOO GT 4\n\tDB\t.FOO MOD .BAR,.FOO*2,.FOO/2,.FOO OR 2,.FOO XOR 1,.FOO AND 4,(.FOO)\n\tDB\t.FOO SHR 1,+.FOO,1 + .FOO,.FOO+.FOO*2\n',
     '060602fbfa00050affff020a02070404050205060f'),
    ('expr_reloc', False,
     '.FOO:\tNOP\n.BAR:\tNOP\n\tDW\t.FOO+1,1+.FOO,.FOO-.BAR,-.FOO\n\tDW\tNOT .FOO\n\tDB\tHIGH .FOO,LOW .FOO\n',
     '000001010101ffff00fffffe0100'),
    ('expr_z80_indirect', True,
     '.FOO\tEQU\t5\n\tLD\tA,(.FOO)\n\tLD\tHL,(.FOO)\n\tLD\t(.FOO),A\n\tLD\t(.FOO),HL\n\tLD\tBC,(.FOO)\n\tLD\tA,(.FOO+1)\n\tLD\tIX,.FOO\n\tADD\tA,.FOO\n\tCP\t.FOO\n\tBIT\t.FOO,A\n\tOUT\t(.FOO),A\n\tIN\tA,(.FOO)\n',
     '3a05002a0500320500220500ed4b05003a0600dd210500c605fe05cb6fd305db05'),
    ('expr_z80_index', True,
     '.A\tEQU\t3\n\tLD\t(IX+.A),5\n\tLD\tA,(IY+.A)\n\tLD\t(IX+.A),B\n',
     'dd360305fd7e03dd7003'),
    ('expr_z80_jumps', True,
     '.FOO:\tNOP\n\tJR\t.FOO\n\tJR\tNZ,.FOO\n\tDJNZ\t.FWD\n\tCALL\tNZ,.FWD\n\tJP\t(.FOO)\n.FWD:\tNOP\n',
     '0018fd20fb1006c40d01c3000100'),
    ('expr_8080_forms', False,
     '.A\tEQU\t3\n\tLXI\tB,.A\n\tLXI\tD,.A+1\n\tLXI\tSP,.A\n\tADI\t.A\n\tRST\t.A\n\tCPI\t.A\n',
     '010300110400310300c603dffe03'),
    ('org_ds', False,
     '.A\tEQU\t3\n\tDS\t.A\n\tDB\t1\n',
     '01'),
    ('type_ifdef', False,
     '.FOO:\tNOP\n\tDB\tTYPE .FOO\n\tIFDEF\t.FOO\n\tDB\t1\n\tENDIF\n\tIFNDEF\t.FOO\n\tDB\t2\n\tENDIF\n\tIFDEF\t.NOPE\n\tDB\t3\n\tENDIF\n\tIFNDEF\t.NOPE\n\tDB\t4\n\tENDIF\n',
     '00200104'),
    ('if_family', False,
     '.FOO\tEQU\t1\n\tIF\t.FOO\n\tDB\t1\n\tENDIF\n\tIFE\t.FOO\n\tDB\t2\n\tENDIF\n\tIFNB\t<.FOO>\n\tDB\t3\n\tENDIF\n\tIFIDN\t<.FOO>,<.FOO>\n\tDB\t4\n\tENDIF\n',
     '010304'),
    ('macro_dot_name_param', False,
     '.MM\tMACRO\t.P\n\tDB\t.P\n\tDB\t.P+1\n\tENDM\n\t.MM\t5\n.X:\t.MM\t7\n',
     '05060708'),
    ('macro_label_endm', False,
     'MM\tMACRO\n\tLOCAL\t.L\n.L:\tNOP\n\tJMP\t.L\n.LAB\tENDM\n\tMM\n\tMM\n',
     '00c3000100c30401'),
    ('macro_param_not_in_dotted', False,
     'MM\tMACRO\tP\n\tDB\tP,.P,P.,A.P\n\tENDM\n.P\tEQU\t1\nP.\tEQU\t2\nA.P\tEQU\t3\n\tMM\t9\n',
     '09010203'),
    ('macro_dotparam_exact', False,
     '.PX\tEQU\t9\nMM\tMACRO\t.P\n\tDB\t.P,.PX\n\tENDM\n\tMM\t5\n',
     '0509'),
    ('irp_label_splice', False,
     '\tIRP\tX,<A,B>\n.L&X:\tNOP\n\tENDM\n\tJMP\t.LA\n\tJMP\t.LB\n',
     '0000c30001c30101'),
    ('irpc_label_splice', False,
     '\tIRPC\tX,<AB>\n.L&X:\tNOP\n\tENDM\n\tJMP\t.LA\n\tJMP\t.LB\n',
     '0000c30001c30101'),
    ('macro_amp_label', False,
     'MM\tMACRO\tP\n.X&P:\tNOP\n\tJMP\t.X&P\n\tENDM\n\tMM\t1\n\tMM\t2\n',
     '00c3000100c30401'),
    ('rept_dup_label', False,
     '\tREPT\t2\n.R:\tNOP\n\tENDM\n',
     None),
    ('dup_label', False,
     '.A:\tNOP\n.A:\tNOP\n',
     None),
    ('dirlabel_z80_mode_unchanged', False,
     '.Z80:\tNOP\n\tLD\tA,B\n',
     None),
    ('dirlabel_z80_nop_kept', False,
     '.Z80:\tNOP\n\tNOP\n\tJMP\t.Z80\n',
     '0000c30001'),
    ('dirlabel_8080_dcolon', True,
     '.8080::\tNOP\n\tNOP\n',
     '0000'),
    ('dirlabel_indented', False,
     '\t.Z80:\tNOP\n\t.LIST:\tNOP\n\tJMP\t.Z80\n\tJMP\t.LIST\n',
     '0000c30001c30101'),
    ('dirlabel_phase_no_phase', False,
     '.PHASE:\tNOP\n\tJMP\t.PHASE\n',
     '00c30001'),
    ('dirlabel_radix_unchanged', False,
     '.RADIX:\tNOP\n\tDB\t10\n',
     '000a'),
    ('dirlabel_lower', False,
     '.z80:\tNOP\n\tJMP\t.Z80\n',
     '00c30001'),
    ('label_then_directive', False,
     '.FOO:\t.Z80\n\tLD\tA,B\n\tJP\t.FOO\n',
     '78c30001'),
    ('label_then_phase', False,
     '.FOO:\t.PHASE\t200H\n\tNOP\n\tJMP\t.FOO\n\t.DEPHASE\n',
     '00c30001'),
    ('dir_z80', False,
     '\t.Z80\n\tLD\tA,B\n',
     '78'),
    ('dir_z80_lower', False,
     '\t.z80\n\tLD\tA,B\n',
     '78'),
    ('dir_phase', False,
     '\t.PHASE\t200H\n.X:\tNOP\n\tJMP\t.X\n\t.DEPHASE\n',
     '00c30002'),
    ('dir_radix', False,
     '\t.RADIX\t16\n\tDB\t10\n',
     '10'),
    ('dir_printx', False,
     '\t.PRINTX\t/a: b/\n\tNOP\n',
     '00'),
    ('dir_z80_name_equ', False,
     '.Z80\tEQU\t5\n\tDB\t.Z80\n',
     '05'),
    ('dir_list_name_set', False,
     '.LIST\tSET\t7\n\tDB\t.LIST\n',
     '07'),
    ('bare_defined', False,
     '.FOO\tEQU\t5\n.FOO\n\tNOP\n',
     '0500'),
    ('bare_undefined', False,
     '.FOO\n\tNOP\n',
     None),
    ('dot_alone_label', False,
     '.:\tNOP\n\tDB\t$-.\n',
     '0001'),
    ('dot_alone_undefined', False,
     '\tDW\t.\n',
     None),
    ('dot_is_not_location', False,
     '\tNOP\n\tDW\t$\n\tDW\t.\n',
     None),
    ('dot_and_name', False,
     '\tDB\t5 .AND. 3\n',
     None),
    ('dollar_dot', False,
     '$.FOO:\tNOP\n.$X:\tNOP\n\tJMP\t$.FOO\n\tJMP\t.$X\n',
     '0000c30001c30101'),
    ('long_distinct', False,
     '.ABCDEFGH:\tNOP\n.ABCDEFXX:\tNOP\n\tDW\t.ABCDEFGH,.ABCDEFXX\n',
     '000000010101'),
    ('long_undefined', False,
     '.ABCDEFGH:\tNOP\n\tJMP\t.ABCDEFXX\n',
     None),
    ('case_fold', False,
     '.foo:\tnop\n\tjmp\t.FOO\n\tjmp\t.Foo\n',
     '00c30001c30001'),
    ('strings', False,
     '.FOO\tEQU\t5\n\tDB\t\'.FOO\',".FOO",\'A\'+.FOO\n\tDB\t.FOO ; .BAR\n',
     '2e464f4f2e464f4f4605'),
]


@pytest.mark.parametrize("body,z80,expected", [(c[2], c[1], c[3]) for c in CASES],
                         ids=[c[0] for c in CASES])
def test_matches_m80(body, z80, expected, tmp_path):
    if expected is None:
        ok, asm = _asm(_program(body, z80), tmp_path)
        assert not ok
    else:
        assert _bytes_of(body, z80, tmp_path) == expected


NAMES = ['.FOO', '..BAR', '.XC.0', '.201B', '.HJ001', '.0', '.1H']


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("z80,jump", [(False, 'f2'), (True, 'c3')])
def test_label_and_reference(name, z80, jump, tmp_path):
    # M80: NOP at 100H and a jump to it; JP is jump-if-plus (F2) in 8080 mode.
    body = "%s:\tNOP\n\tJP\t%s\n" % (name, name)
    assert _bytes_of(body, z80, tmp_path) == '00' + jump + '0001'


DOT_DIRECTIVES = ['.Z80', '.8080', '.PHASE', '.RADIX', '.LIST', '.XLIST',
                  '.SFCOND', '.LFCOND', '.TFCOND', '.CREF', '.XCREF',
                  '.PRINTX', '.REQUEST', '.COMMENT', '.SALL', '.LALL',
                  '.XALL', '.DEPHASE']


@pytest.mark.parametrize("name", DOT_DIRECTIVES)
def test_dot_directive_with_colon_is_a_label(name, tmp_path):
    # M80: a label, no mode or listing change, `JP' and `DW' read the name.
    body = "%s:\tNOP\n\tJP\t%s\n\tDW\t%s\n" % (name, name, name)
    assert _bytes_of(body, False, tmp_path) == '00f200010001'


def test_dot_z80_label_does_not_drop_the_instruction(tmp_path):
    # The silent bug: um80 took `.Z80:<TAB>NOP' for the directive and
    # assembled no NOP.  M80 (case dirlabel_z80_nop_kept): 00 00 C3 00 01.
    body = ".Z80:\tNOP\n\tNOP\n\tJMP\t.Z80\n"
    assert _bytes_of(body, False, tmp_path) == '0000c30001'
    ok, asm = _asm(_program(".Z80:\tNOP\n\tLD\tA,B\n", False), tmp_path)
    assert not ok      # still the 8080 instruction set, as in M80


def test_colonless_dot_word_is_a_statement_of_values(tmp_path):
    # M80: an undefined `.FOO' alone is U; a defined one is DB of its value.
    ok, asm = _asm(_program(".FOO\n", False), tmp_path)
    assert not ok
    assert any('.FOO' in e.message for e in asm.errors)


def test_dot_and_dot_is_a_name_not_an_operator(tmp_path):
    ok, asm = _asm(_program("\tDB\t.AND.\n", False), tmp_path)
    assert not ok      # M80: U, the symbol table lists `.AND.'
    assert [e.message for e in asm.errors] == ["Undefined symbol '.AND.'"]


def test_single_dot_is_a_name_not_the_location_counter(tmp_path):
    ok, asm = _asm(_program("\tNOP\n\tDW\t.\n", False), tmp_path)
    assert not ok      # M80: U; `$' is the location counter
    assert [e.message for e in asm.errors] == ["Undefined symbol '.'"]


# The sources of the two-module link measured with M80 and L80.
LINK_A = ("\tCSEG\n.BAR::\tRET\n..MG0::\tRET\n.XC.0::\tRET\n"
          ".ABCDEFGH::\tRET\n.201B::\tRET\n\tPUBLIC\t.PUB\n.PUB:\tRET\n"
          "\tEND\n")
LINK_B = ("\tCSEG\n\tEXTRN\t.BAR\n\tCALL\t.BAR\n\tCALL\t..MG0##\n"
          "\tCALL\t.XC.0##\n{long}\tCALL\t.201B##\n\tDW\t.BAR+1\n"
          "\tEXTRN\t.EXT\n\tJMP\t.EXT\n\tJMP\t.PUB##\n\tEND\n")
LINK_C = "\tCSEG\n.EXT::\tRET\n\tEND\n"
LONG_CALL = "\tCALL\t.ABCDEFXX##\n"
# OUT.COM of L80 (M1,M2,M3,OUT/N/E) without its 3 bytes at 100H.  A is at
# 103H, six RETs; B follows; C is the last RET.  Only M80 and L80 meet
# .ABCDEFXX## and .ABCDEFGH:: through their first 6 characters.
M80_LINK = 'c9c9c9c9c9c9cd0301cd0401cd0501cd07010401c31d01c30801c9'
M80_LINK_LONG = 'c9c9c9c9c9c9cd0301cd0401cd0501cd0601cd07010401c32001c30801c9'


def _link(b_source, tmp_path, **kw):
    rels = []
    for name, src in (("a", LINK_A), ("b", b_source), ("c", LINK_C)):
        ok, asm = _asm(src, tmp_path, name, **kw)
        assert ok, [e.message for e in asm.errors]
        out = os.path.join(str(tmp_path), name + ".rel")
        with open(out, "wb") as f:
            f.write(asm.output.get_bytes())
        rels.append(out)
    linker = Linker()
    linker.code_base = 0x103
    for r in rels:
        linker.load_rel(r)
    assert linker.link(), linker.errors
    return bytes(linker.output).hex()


def test_two_module_link_equals_l80(tmp_path):
    out = _link(LINK_B.format(long=""), tmp_path)
    assert out == M80_LINK


def test_two_module_link_with_long_name_equals_l80_under_t(tmp_path):
    # Without -t `.ABCDEFXX' and `.ABCDEFGH' are two names (as in M80's
    # symbol table); with -t the .REL has both as `.ABCDE', as M80 has.
    out = _link(LINK_B.format(long=LONG_CALL), tmp_path, truncate_symbols=True)
    assert out == M80_LINK_LONG
    ok, asm = _asm(LINK_B.format(long=LONG_CALL), tmp_path, "b2")
    assert ok
    items = RELReader(asm.output.get_bytes()).read_all()
    assert '.ABCDEFXX' in [i[-1] for i in items if i[0] == 'CHAIN_EXTERNAL']


def test_rel_names_keep_the_leading_dot(tmp_path):
    ok, asm = _asm(LINK_A, tmp_path, "a")
    assert ok
    items = RELReader(asm.output.get_bytes()).read_all()
    entries = [i[-1] for i in items if i[0] == 'DEFINE_ENTRY']
    assert entries == ['.BAR', '..MG0', '.XC.0', '.ABCDEFGH', '.201B', '.PUB']
    ok, asm = _asm(LINK_A, tmp_path, "at", truncate_symbols=True)
    items = RELReader(asm.output.get_bytes()).read_all()
    assert '.ABCDE' in [i[-1] for i in items if i[0] == 'DEFINE_ENTRY']


DRI_PROGRAM = ("\tASEG\n\tORG\t100H\nMM\tMACRO\tP\n\tDB\tP\n\tENDM\n"
               "AB\tEQU\t5\n{label}:\tMM\tA$B\n\tJMP\t{label}\n\tEND\n")


def test_dri_takes_dot_label_with_colon(tmp_path):
    # MAC does not read '.' in a name; the colon form is um80's extension.
    ok, asm = _asm("\tASEG\n\tORG\t100H\n.FOO:\tNOP\n\tJMP\t.FOO\n\tEND\n",
                   tmp_path, dri=True)
    assert ok, [e.message for e in asm.errors]
    assert _absolute_bytes(asm) == '00c30001'


def test_dri_dot_label_before_a_macro_call_with_dollar(tmp_path):
    # The head of the call line in _dri_statement() reads the label as
    # parse_line() does; not measured with MAC.
    got = []
    for label in ('FOO', '.FOO'):
        ok, asm = _asm(DRI_PROGRAM.format(label=label), tmp_path, dri=True)
        assert ok, [e.message for e in asm.errors]
        got.append(_absolute_bytes(asm))
    assert got[0] == got[1]


def test_dri_colonless_dot_word_stays_an_error(tmp_path):
    # MAC's rule for a label with no colon is kept, so a mistyped
    # dot-directive is no label.
    ok, asm = _asm("\tASEG\n.BAR\tNOP\n\tEND\n", tmp_path, dri=True)
    assert not ok
    assert any('.BAR' in e.message for e in asm.errors)


def test_dri_dot_directive_still_a_directive(tmp_path):
    ok, asm = _asm("\tASEG\n\t.Z80\n\tLD\tA,B\n\tEND\n", tmp_path, dri=True)
    assert ok, [e.message for e in asm.errors]
    assert _absolute_bytes(asm) == '78'
