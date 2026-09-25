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


@pytest.mark.parametrize('line', [
    'dad\tre', 'dad\t1', 'push\t3', 'inx\t5', 'ldax\th', 'stax\t6', 'mov\ta,8',
    'mvi\t9,0', 'dad\tlab', 'mov\ta,lab',
])
def test_not_a_register_is_an_error(line):
    ok, _, errors = _assemble(f"re\tequ\te\nlab:\tnop\n\t{line}\n\tend\n")
    assert not ok
    assert any('Invalid register' in e for e in errors), errors
