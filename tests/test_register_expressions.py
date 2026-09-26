"""In 8080 code a register name is its number in any expression.

M80 3.44 and MAC 2.0 give each register name a number - B 0, C 1, D 2, E 3,
H 4, L 5, M 6, A 7, SP and PSW 6 (M80 also BC 0, DE 2, HL 4) - wherever an
expression may have a value: `X EQU D+1' is 3 (so `MOV A,X' is 7B), `DB B'
00, `MVI A,B' 3E 00, `JMP B' C3 00 00, `IF B EQ 0' true.  um80 took the
number only in a register operand, and elsewhere stopped with "Register 'B'
used as value".

Where the two differ, M80 is the default and MAC is --dri:

* M80 flags an expression with two register names in it O (`A*256+B',
  `C-B'), though it computes it; MAC does not.  Through symbols (`X EQU A'
  / `Y EQU B' / `X-Y') neither flags anything.
* M80 flags `PUSH A', `POP A' and `PUSH 7' A, and pushes PSW; MAC and RMAC
  take them for PSW without a flag (and flag the other odd numbers R).
  um80 took `PUSH A' for PSW and rejected `PUSH 7'.
* M80 flags `MOV M,M' (and `MOV 6,M') A, and assembles 76H, HLT's opcode;
  MAC and RMAC assemble 76H without a flag.  um80 reported it in either
  mode.
* A program may define a symbol named like a register (MAC flags it S), and
  M80 then reads the name as the symbol, in a register operand too: after
  `C EQU 2', `MOV A,C' is MOV A,D and `DB C' 02; after `H EQU 2', `DAD H'
  is DAD D.

In Z80 code M80 gives every register name 0 in an expression; um80 keeps
reporting it (a symbol of the name is read as the symbol, as in M80).

The fixtures are the .REL files M80 3.44 and, for --dri, RMAC 1.1 write for
the same sources.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _assemble(source, **kw):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        items = RELReader(asm.output.get_bytes()).read_all() if ok else None
    return ok, items, [str(e) for e in asm.errors]


def _fields(items):
    out = []
    for it in items:
        if it[0] == 'ABSOLUTE_BYTE':
            out.append(f'{it[1]:02X}')
        elif it[0] == 'PROGRAM_REL':
            out.append(f'P{it[1]:04X}')
    return out


VALUES = ("x\tequ\td+1\n\tmov\ta,x\n\tdb\tx\n\tdb\tb,c,d,e,h,l,m,a,sp,psw\n"
          "\tmvi\ta,b\n\tmvi\tb,m+1\n\tlxi\th,sp\n\tlxi\th,psw*2\n\tdw\tpsw+1,h shl 8\n"
          "\tjmp\tb\n\tcall\tpsw\n\tlda\tm\n\tout\ta\n\tin\tb\n\trst\tm\n"
          "\tif\tb eq 0\n\tdb\t1\n\tendif\n\tdb\tbc,de,hl,type a,-a,not a,low a\n\tend\n")
M80_VALUES = bytes.fromhex(
    '845525000013530003d80c00010100c08050301c0c061f0000c07108180021060000e000001186'
    '00003340c001d01800d303b6c00f7008000404103e5f0079c000009e')

SYMBOLS = ("c\tequ\t2\nh\tequ\t2\npsw\tequ\t0\n\tmov\ta,c\n\tdb\tc\n\tdad\th\n"
           "\tpush\tpsw\n\tdb\th,psw\n\tend\n")
M80_SYMBOLS = bytes.fromhex('845525000013506003d00832c50100270000009e')

DRI = "\tpush\ta\n\tpop\ta\n\tpush\t7\n\tdw\ta*256+b,a-b\n\tend\n"
RMAC_DRI = bytes.fromhex('845525000013507007abc5ea000381c0138000009e')


def test_register_names_are_numbers_as_m80():
    # M80 and MAC: 7B 03, 00 .. 07 06 06, 3E 00 06 07, 21 06 00 21 0C 00,
    # 07 00 00 04, C3 00 00, CD 06 00, 3A 06 00, D3 07, DB 00, F7, 01; M80
    # (MAC: U) 00 02 04 for BC, DE, HL, 20 for TYPE A, F9 F8 07.
    for dri in (False, True):
        ok, items, errors = _assemble(VALUES, dri=dri)
        assert ok, errors
        assert _fields(items) == _fields(RELReader(M80_VALUES).read_all())


def test_a_symbol_named_like_a_register_as_m80():
    # M80: 7A 02 19 C5 02 00 (MOV A,D; DAD D; PUSH B).  um80: MOV A,C,
    # "Register 'c' used as value", DAD H, PUSH PSW.
    ok, items, errors = _assemble(SYMBOLS)
    assert ok, errors
    assert _fields(items) == _fields(RELReader(M80_SYMBOLS).read_all())
    assert ' '.join(_fields(items)) == '7A 02 19 C5 02 00'


def test_push_a_and_two_register_names_with_dri_as_rmac():
    # MAC and RMAC: F5 F1 F5 00 07 07 00.
    ok, items, errors = _assemble(DRI, dri=True)
    assert ok, errors
    assert _fields(items) == _fields(RELReader(RMAC_DRI).read_all())


@pytest.mark.parametrize('line', ['\tpush\ta', '\tpop\ta', '\tpush\t7', '\tpop\t3+4'])
def test_push_a_is_an_error_without_dri(line):
    # M80: A (it pushes PSW).
    ok, _, errors = _assemble(f"{line}\n\tend\n")
    assert not ok
    assert any('not a register pair' in e and '--dri' in e for e in errors), errors


@pytest.mark.parametrize('line', ['\tmov\tm,m', '\tmov\t6,m', '\tmov\tm,3*2'])
def test_mov_m_m(line):
    # MAC and RMAC: 76.  M80: A (76).
    ok, items, errors = _assemble(f"{line}\n\tend\n", dri=True)
    assert ok, errors
    assert _fields(items) == ['76']
    ok, _, errors = _assemble(f"{line}\n\tend\n")
    assert not ok
    assert any('MOV M,M' in e and '--dri' in e for e in errors), errors


@pytest.mark.parametrize('expr', ['a*256+b', 'a-b', 'c-b', 'a eq b', '(a)*(b)', 'sp+psw'])
def test_two_register_names_are_an_error_without_dri(expr):
    # M80: O, for each.
    ok, _, errors = _assemble(f"\tdw\t{expr}\n\tend\n")
    assert not ok
    assert any('2 register names' in e for e in errors), errors


def test_two_register_names_through_symbols_are_not():
    # M80: 07 00 00 00, no flag.
    ok, items, errors = _assemble("x\tequ\ta\ny\tequ\tb\n\tdw\tx-y,x*y\n\tend\n")
    assert ok, errors
    assert _fields(items) == ['07', '00', '00', '00']


def test_z80_register_names_are_still_not_values():
    ok, _, errors = _assemble("\t.z80\n\tdb\tb\n\tend\n")
    assert not ok
    assert any("Register 'b' used as value" in e for e in errors), errors
