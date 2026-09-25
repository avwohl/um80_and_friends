"""The module name in a .REL is the one MACRO-80 3.44 writes.

`NAME('XYZ')' went into the .REL as 'XYZ' with its quotes, and a TITLE was
ignored: M80 names a module without a NAME after its last TITLE - the first
six characters of the title's text, up to a blank, quotes and all.  So
mbasic2025's BINTRP.MAC (`title basic mpu 8080/8085/z80/8086 (5.11) ...')
is the module BASIC from M80 and was BINTRP from um80.  LINK-80 prints the
name in its map, and a library lists its modules by it.  Every expected
value was produced by the genuine MACRO-80 3.44 under a CP/M emulator.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _name(source, **kw):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler(**kw)
        assert asm.assemble(p), [e.message for e in asm.errors]
        items = RELReader(asm.output.get_bytes()).read_all()
    return [it[1] for it in items if it[0] == 'PROGRAM_NAME']


CASES = {
    "\tdb\t1\n": 'T',
    "\tsubttl\tsub title\n\tdb\t1\n": 'T',
    "\ttitle\n\tdb\t1\n": 'T',
    "\ttitle\thello world\n\tdb\t1\n": 'HELLO',
    "\ttitle\t'hello world'\n\tdb\t1\n": "'HELLO",
    "\ttitle\tabcdefghij\n\tdb\t1\n": 'ABCDEF',
    "\ttitle\tfirst one\n\tdb\t1\n\ttitle\tsecond\n\tdb\t2\n": 'SECOND',
    "\ttitle\ta-b.c\n\tdb\t1\n": 'A-B.C',
    "\ttitle\t   lead\n\tdb\t1\n": 'LEAD',
    "\ttitle\t8080 basic\n\tdb\t1\n": '8080',
    "\ttitle\taBc1$x\n\tdb\t1\n": 'ABC1$X',
    "\tname('xyz')\n\tdb\t1\n": 'XYZ',
    "\tname('abcdefghij')\n\tdb\t1\n": 'ABCDEF',
    "\tname('xyz')\n\ttitle\tabc\n\tdb\t1\n": 'XYZ',
    "\ttitle\tabc\n\tname('xyz')\n\tdb\t1\n": 'XYZ',
}


@pytest.mark.parametrize('source', list(CASES))
def test_module_name_as_m80(source):
    assert _name(source + "\tend\n") == [CASES[source]]


@pytest.mark.parametrize('form', ["name 'xyz'", 'name xyz', 'name("xyz")'])
def test_name_without_m80_syntax(form):
    """M80 wants NAME('xyz') (the others are an 'A' error); um80 takes them."""
    assert _name(f"\t{form}\n\tdb\t1\n\tend\n") == ['XYZ']
