"""The name of an EQU, SET, DEFL, ASET or MACRO need not be in column 1.

MACRO-80 3.44, and DRI's MAC 2.0 and RMAC 1.1, all take `<TAB>FOO<TAB>EQU 5':
the word before EQU, SET, DEFL, ASET or MACRO is the name wherever the line
starts, even when it is also an instruction or a macro (`<TAB>NOP EQU 2'
defines NOP).  um80 took an indented name as the operator and stopped with
"Unknown instruction or directive: FOO".  MP/M II's MPMLDR/LDRBDOS.ASM has
`<TAB>arech  equ b! arecl  equ c'.

Worse, a macro defined inside a macro with its name indented was not seen
as a nested definition, so its ENDM ended the outer macro.

The fixtures are the .REL files the genuine M80 3.44 writes for the same
sources; MAC and RMAC assemble the same bytes.
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler

INDENTED = (
    "\taseg\n\torg\t100h\n"
    "\tfoo\tequ\t5\n"
    "  bar equ 6\n"
    "\tbaz\tset\t7\n"
    "\tmvi\ta,foo\n\tmvi\ta,bar\n\tmvi\ta,baz\n"
    "\tmac1\tmacro\tx\n\tdb\tx\n\tendm\n"
    "\tmac1\t9\n"
    "\tm1\tequ\t1\n"          # M1 is a macro as well
    "\tnop\tequ\t2\n"         # NOP is an instruction as well
    "\tq2\tdefl\t3\n"
    "\tq3\taset\t4\n"
    "\tdb\tm1,nop,q2,q3\n"
    "\tbaz\tset\tbaz+1\n"
    "\tdb\tbaz\n"
    "\tend\n")
M80_INDENTED = bytes.fromhex('84918ce5000012c00011f0147c061f01c12010100c08089c0000009e1a')

NESTED = ("\taseg\n\torg\t100h\n"
          "outer\tmacro\n\tinner\tmacro\n\tdb\t1\n\tendm\n\tdb\t2\n\tendm\n"
          "\tdb\t3\n\touter\n\tinner\n\tend\n")
M80_NESTED = bytes.fromhex('8491cce5000012c000101808033800009e1a')


def _loaded(rel):
    """{address: byte} of the absolute bytes a .REL loads."""
    out, loc = {}, 0
    for it in RELReader(rel).read_all():
        if it[0] == 'SET_LOC':
            loc = it[1][1]
        elif it[0] == 'ABSOLUTE_BYTE':
            out[loc] = it[1]
            loc += 1
    return out


def _assemble(source):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
        assert ok, [str(e) for e in asm.errors]
        return asm.output.get_bytes()


def test_indented_names_as_m80():
    assert _loaded(_assemble(INDENTED)) == _loaded(M80_INDENTED)
    assert bytes(_loaded(M80_INDENTED).values()) == bytes.fromhex('3e053e063e07090102030408')


def test_indented_macro_inside_a_macro():
    assert _loaded(_assemble(NESTED)) == _loaded(M80_NESTED) == {0x100: 3, 0x101: 2, 0x102: 1}


def test_ldrbdos_register_names():
    # MPMLDR/LDRBDOS.ASM line 455, and a use of each name.  MAC and RMAC:
    # 78 79 (MOV A,B and MOV A,C).
    src = ("\taseg\n\torg\t100h\n"
           "\tarech  equ b! arecl  equ c\n"
           "\tmov a,arech! mov a,arecl\n\tend\n")
    assert bytes(_loaded(_assemble(src)).values()) == bytes([0x78, 0x79])
