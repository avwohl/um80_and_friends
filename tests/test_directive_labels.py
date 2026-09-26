"""A label on the line of a directive.

A label on an ORG is the location the ORG sets in DRI's MAC 2.0 and RMAC
1.1 - `DB 1 / LAB ORG 300H / DW LAB' is 01 00 03 at 0100H - and the
location before the ORG in MACRO-80 3.44 (01 01 01).  um80 --dri gave M80's.
MP/M II's GENMOD sources are MAC's.

The expected bytes are what M80, MAC and RMAC assemble from the same source
under cpmemu.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler


def _image(source, **kw):
    """(ok, 'addr:byte ...' of an absolute REL, error messages)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        items = RELReader(asm.output.get_bytes()).read_all() if ok else []
    mem, loc = {}, 0
    for it in items:
        if it[0] == 'SET_LOC':
            loc = it[1][1]
        elif it[0] == 'ABSOLUTE_BYTE':
            mem[loc] = it[1]
            loc += 1
    return ok, ' '.join(f'{a:04X}:{b:02X}' for a, b in sorted(mem.items())), \
        [str(e) for e in asm.errors]


# (lines after `ASEG / ORG 100H', M80's image, MAC's and RMAC's)
@pytest.mark.parametrize('body,m80,mac', [
    ("\tdb\t1\nlab:\torg\t300h\n\tdw\tlab\n",
     '0100:01 0300:01 0301:01', '0100:01 0300:00 0301:03'),
    ("\tdb\t1\nlab:\torg\t$+4\n\tdw\tlab\n",
     '0100:01 0105:01 0106:01', '0100:01 0105:05 0106:01'),
    ("\tdb\t1,2,3,4\nlab:\torg\t102h\n\tdw\tlab\n",
     '0100:01 0101:02 0102:04 0103:01', '0100:01 0101:02 0102:02 0103:01'),
    ("\tdw\tlab\nlab:\torg\t300h\n\tdw\tlab\n",
     '0100:02 0101:01 0300:02 0301:01', '0100:00 0101:03 0300:00 0301:03'),
    # Before a DS it is where the DS starts, in all three.
    ("\tdb\t1\nlab:\tds\t4\n\tdw\tlab\n",
     '0100:01 0105:01 0106:01', '0100:01 0105:01 0106:01'),
])
def test_label_on_org(body, m80, mac):
    source = "\taseg\n\torg\t100h\n" + body + "\tend\n"
    for dri, want in ((False, m80), (True, mac)):
        ok, image, errors = _image(source, dri=dri)
        assert ok, errors
        assert image == want, (dri, image)


def test_dri_label_with_no_colon_on_org():
    # MAC: `LAB ORG 300H' (M80: LAB is U, and a byte).
    ok, image, errors = _image("\taseg\n\torg\t100h\n\tdb\t1\nlab\torg\t300h\n"
                               "\tdw\tlab\n\tend\n", dri=True)
    assert ok, errors
    assert image == '0100:01 0300:00 0301:03'
