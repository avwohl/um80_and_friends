""".PHASE addr ... .DEPHASE: code loaded here that runs at addr.

.PHASE and .DEPHASE were accepted and ignored, so labels and $ inside the
block got their load addresses: `X: JP X' after `.PHASE 0F000H' came out
C3 01 00 (relocatable) instead of C3 00 F0.  MACRO-80 3.44 gives the
block's labels and $ the absolute addresses it runs at and loads its bytes
at the current location (bytes below checked against M80 under cpmemu).
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler


def _asm(source):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
        rel = asm.output.get_bytes() if ok else None
    return ok, asm, rel


def _items(rel):
    reader = RELReader(rel)
    out = []
    while True:
        item = reader.read_item()
        if item is None or item[0] in ('END_PROGRAM', 'END_FILE'):
            return out
        if item[0] == 'ABSOLUTE_BYTE':
            out.append(item[1])
        elif item[0] == 'PROGRAM_REL':
            out.append(('P', item[1]))


SRC = """\t.Z80
\tCSEG
\tNOP
\t.PHASE 0F000H
X:\tJP X
\tLD HL,$
\tJR X
\tDW Y
\t.DEPHASE
Y:\tDW X
\tLD HL,$
\tEND
"""


def test_phase_block_runs_at_its_address():
    ok, asm, rel = _asm(SRC)
    assert ok, [e.message for e in asm.errors]
    assert _items(rel) == [0x00, 0xC3, 0x00, 0xF0, 0x21, 0x03, 0xF0,
                           0x18, 0xF8, ('P', 0x0B), 0x00, 0xF0,
                           0x21, ('P', 0x0D)]
    assert asm.symbols['X'].value == 0xF000
    assert asm.symbols['X'].seg_type == 0  # absolute
    assert asm.symbols['Y'].value == 0x0B


def test_phase_needs_an_absolute_address():
    ok, asm, _ = _asm("\tCSEG\nLL:\tNOP\n\t.PHASE LL\n\tNOP\n\t.DEPHASE\n\tEND\n")
    assert not ok
    assert "absolute" in asm.errors[0].message
