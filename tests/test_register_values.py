"""An 8080 register operand is an expression; a register name is its number.

In 8080 code MACRO-80 3.44 and DRI's MAC 2.0 and RMAC 1.1 give each register
name a number - B 0, C 1, D 2, E 3, H 4, L 5, M 6, A 7, SP and PSW 6 - and
read a register or register pair operand as an expression: `RD EQU D' is 2,
`DAD RD' and `DAD 2' are DAD D (19H), `PUSH 6' is PUSH PSW, `MOV A,SP' is
MOV A,M.  um80 took the value of an EQU for a register pair's encoding, so
`RD EQU D' then `DAD RD' was DAD H (29H) and `PUSH RD' PUSH H (E5H), and
`X EQU SP' was 3.  MP/M II's MPMLDR/LDRBDOS.ASM names registers this way.

The fixtures are the .REL files the genuine M80 3.44 writes; MAC and RMAC
assemble the same bytes.  An odd number for a register pair (`DAD E',
`DAD 1', `PUSH 3'), `LDAX H' and a register number above 7 are errors in all
three: M80 flags them A, MAC and RMAC R or V.

An address is a register operand too, in M80: its offset in its segment, or
an external's constant, is the number, and nothing is flagged.  `DAD LAB',
LAB two bytes into the code, is DAD D; `MOV A,Y' with Y EXTRN is MOV A,B.
um80 0.3.50 took a relocatable label's offset as well (for a pair, as the
pair's encoding).  RMAC flags it V.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler

ALIASES = (
    "\taseg\n\torg\t100h\n"
    "rd\tequ\td\nrh\tequ\th\nrsp\tequ\tsp\nrpsw\tequ\tpsw\nrb\tequ\tb\nre\tequ\te\n"
    "\tdad\trd\n\tpush\trd\n\tpop\trh\n\tmov\ta,rd\n\tinx\trsp\n\tpush\trpsw\n"
    "\tlxi\trb,1234h\n\tdad\t2\n\tdad\t4\n\tdad\t6\n\tpush\t6\n\tldax\trd\n"
    "\tstax\trb\n\tdcx\t0\n\tmov\ta,sp\n\tend\n")
M80_ALIASES = bytes.fromhex('84948d65000012c00010cb55c27a19bd402340906452397a86'
                            '8040b3f4e000009e1a')

# Register names used before they are defined, and register expressions.
FORWARD = ("\taseg\n\torg\t100h\n"
           "\tmov\ta,rx\n\tdad\try\n\tpush\try\n\tmov\ta,sp\n\tmov\ta,2\n"
           "\tmvi\t7,5\n\tpush\tpsw+0\n\tlxi\tsp-2,1\n"
           "rx\tequ\td\nry\tequ\th\n\tend\n")
M80_FORWARD = bytes.fromhex('84918d25000012c00013d0a5ca7e3d0f80af510804013800009e1a')


def _assemble(source):
    """(ok, absolute bytes loaded, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
        errors = [str(e) for e in asm.errors]
        rel = asm.output.get_bytes() if ok else b''
    return ok, _code(rel) if ok else b'', errors


def _code(rel):
    return bytes(it[1] for it in RELReader(rel).read_all() if it[0] == 'ABSOLUTE_BYTE')


def test_register_equates_as_m80():
    ok, code, errors = _assemble(ALIASES)
    assert ok, errors
    assert code == _code(M80_ALIASES)
    assert code.hex() == '19d5e17a33f5013412192939f51a020b7e'


def test_forward_register_equates_and_expressions_as_m80():
    ok, code, errors = _assemble(FORWARD)
    assert ok, errors
    assert code == _code(M80_FORWARD)
    assert code.hex() == '7a29e57e7a3e05f5210100'


def test_ldrbdos_register_pairs():
    # MPMLDR/LDRBDOS.ASM, with its names for BC, DE and HL.  MAC: D5 C5 E5.
    src = ("\taseg\n\torg\t100h\n"
           "\tarech  equ b! arecl  equ c\n\tcrech  equ d! crecl  equ e\n"
           "\tctrkh  equ h! ctrkl  equ l\n"
           "\tpush crech! push arech! push ctrkh\n\tend\n")
    ok, code, errors = _assemble(src)
    assert ok, errors
    assert code == bytes([0xD5, 0xC5, 0xE5])


# Labels in the code, data and a COMMON block, an EXTRN (also as Y##) and
# a name equated further down to a label, each used as a register.
ADDRESSES = ("\textrn\ty\n"
             "\tnop\n\tnop\nlab2:\tnop\nlab3:\tnop\nlab4:\tnop\n\tnop\n\tnop\nlab7:\n"
             "\tmov\ta,lab2\n\tmov\tlab7,a\n\tmvi\tlab3,5\n\tinr\tlab4\n\tadd\tlab7\n"
             "\tdad\tlab2\n\tpush\tlab4\n\tpop\tlab2\n\tlxi\tlab4,1234h\n\tinx\tlab2\n"
             "\tldax\tlab2\n\tstax\tlab2-2\n\tdad\tlab4+2\n\tpush\tlab4+2\n"
             "\tmov\ta,y\n\tmov\ta,y+2\n\tdad\ty##+4\n\tpush\tdl\n\tdcx\tcl\n"
             "\tmov\ta,fw\n\tmov\ta,lab4-lab2\n"
             "\tdseg\n\tds\t2\ndl:\n\tcommon\t/cb/\n\tds\t4\ncl:\n\tcseg\n"
             "fw\tequ\tlab4+1\n\tend\n")
M80_ADDRESSES = bytes.fromhex(
    '8455228080090d0a500401351f0000000000000000007a3f8780a2443865cad1108d0241'
    '30d00872f53c1e852d5159f4f52e000097010041486852f00009782004b47c0230000056'
    '670000009e1a')


def test_address_as_register_is_its_offset_as_m80():
    ok, code, errors = _assemble(ADDRESSES)
    assert ok, errors
    assert code == _code(M80_ADDRESSES)
    assert code.hex() == '00' * 7 + '7a7f1e05248719e5d1213412131a0239f5787a29d52b7d7a'


def test_address_as_register_is_a_warning():
    # M80 flags nothing; RMAC flags V.  um80 assembles it and says so.
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write("\textrn\ty\n\tnop\n\tnop\nlab:\tdad\tlab\n\tmov\ta,y\n"
                    "\tmov\ta,lab-lab\n\tend\n")
        asm = Assembler()
        assert asm.assemble(p)
    warned = [w for w in asm.warnings if 'register operand' in w]
    assert len(warned) == 2, asm.warnings
    assert "'lab' is an address: its offset, 2," in warned[0]
    assert "'y' is an external: its offset, 0," in warned[1]


@pytest.mark.parametrize('line', ['mov\ta,high lab', 'mov\ta,lab-y', 'dad\tlab and 7'])
def test_other_values_from_an_address_are_errors(line):
    # Not an address plus a constant: as in 0.3.50, not a register.  (M80
    # flags `LAB AND 7' and takes HIGH LAB and LAB-Y.)
    ok, _, errors = _assemble(f"\textrn\ty\n\tnop\n\tnop\nlab:\t{line}\n\tend\n")
    assert not ok
    assert any('Invalid register' in e for e in errors), errors


@pytest.mark.parametrize('line', [
    'dad\tre', 'dad\t1', 'push\t3', 'inx\t5', 'ldax\th', 'stax\t6', 'mov\ta,8',
    'mvi\t9,0',
    # An address whose value is not a register's number, as M80 flags it A.
    'dad\tlab1', 'push\tlab1', 'mov\ta,lab8', 'mvi\tlab8,0', 'ldax\tlab1+3',
    'inx\ty+1', 'mov\ta,y+8', 'pop\ty-2',
])
def test_not_a_register_is_an_error(line):
    ok, _, errors = _assemble("re\tequ\te\n\textrn\ty\n\tnop\nlab1:\tnop\n"
                              + "\tnop\n" * 6 + f"lab8:\n\t{line}\n\tend\n")
    assert not ok
    assert any('Invalid register' in e for e in errors), errors


# A name defined further down that is also an instruction's name: on pass 1
# it is not a symbol yet, and an instruction's name stands for its opcode
# there (`DAD RP' read F0H, RP's opcode).  M80 3.44 reads the symbol, and
# assembles each of these as shown; um80 stopped with "Invalid register
# pair for DAD: RP" (a register operand was fine with a name like R1).
OPCODE_NAMES = [
    ("\tdad\trp\nrp\tequ\th\n", '29'),
    ("\tpush\trp\nrp\tequ\td\n", 'd5'),
    ("\tpop\trp\nrp\tequ\tpsw\n", 'f1'),
    ("\tlxi\trp,1\nrp\tequ\tb\n", '010100'),
    ("\tinx\trp\nrp\tequ\tsp\n", '33'),
    ("\tldax\trp\nrp\tequ\td\n", '1a'),
    ("\tdad\trp\nrp\tset\th\n", '29'),
    ("\tdad\trp+0\nrp\tequ\th\n", '29'),
    ("\tmov\ta,rz\nrz\tequ\te\n", '7b'),
    ("\tmvi\trz,2\nrz\tequ\te\n", '1e02'),
    ("\tinr\trz\n\tadd\trz\nrz\tequ\te\n", '1c83'),
    ("\tdcx\trc\n\tstax\trc\nrc\tequ\tb\n", '0b02'),
    ("\tpush\tjmp\njmp\tequ\th\n", 'e5'),
    ("\tmov\trnc,rpe\nrnc\tequ\ta\nrpe\tequ\tm\n", '7e'),
]


@pytest.mark.parametrize('source, code', OPCODE_NAMES)
def test_an_instruction_name_defined_further_down_as_m80(source, code):
    ok, got, errors = _assemble("\taseg\n\torg\t100h\n" + source + "\tend\n")
    assert ok, errors
    assert got.hex() == code


@pytest.mark.parametrize('line', ['dad\tcpi', 'mov\ta,rz', 'push\trp'])
def test_an_instruction_name_that_is_no_symbol_is_still_an_error(line):
    # M80: DAD CPI is 39 and MOV A,RZ 78, each flagged A.
    ok, _, errors = _assemble(f"\t{line}\n\tend\n")
    assert not ok
    assert any('Invalid register' in e for e in errors), errors


def test_with_dri_an_instruction_name_is_its_opcode_as_in_mac():
    # MAC and RMAC flag `RP EQU H' S (an instruction's name is no symbol)
    # and `DAD RP' V: F0H is no register.  --dri keeps the error.
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write("\tdad\trp\nrp\tequ\th\n\tend\n")
        asm = Assembler(dri=True)
        assert not asm.assemble(p)
    assert any('Invalid register pair' in str(e) for e in asm.errors)
