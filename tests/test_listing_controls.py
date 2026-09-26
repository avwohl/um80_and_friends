"""M80's listing controls assemble nothing.

MACRO-80 3.44 takes each of these and assembles the next line as if it
were not there; um80 writes no cross-reference file, and reported .CREF and
.XCREF as "Unknown instruction or directive".  Checked with M80 under
cpmemu: each is followed by `DB 1', which is 01.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


@pytest.mark.parametrize('control', [
    '.CREF', '.XCREF', '.LIST', '.XLIST', '.SFCOND', '.LFCOND', '.TFCOND',
    '.LALL', '.SALL', '.XALL', 'PAGE', 'PAGE\t60', 'SUBTTL\tXY', "$TITLE('X')",
    '$EJECT', '.PRINTX\t/X/', '.RADIX\t10',
])
def test_listing_control(control):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.mac')
        with open(p, 'w') as f:
            f.write(f"\t{control}\n\tdb\t1\n\tend\n")
        asm = Assembler()
        assert asm.assemble(p), [str(e) for e in asm.errors]
        code = [it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                if it[0] == 'ABSOLUTE_BYTE']
    assert code == [1]
