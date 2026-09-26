"""A label on the line of a directive.

A label on an ORG is the location the ORG sets in DRI's MAC 2.0 and RMAC
1.1 - `DB 1 / LAB ORG 300H / DW LAB' is 01 00 03 at 0100H - and the
location before the ORG in MACRO-80 3.44 (01 01 01).  um80 --dri gave M80's.
MP/M II's GENMOD sources are MAC's.

A label on an IF, ELSE, ENDIF or EXITM line is defined, where the line
before it was assembled, in all three: `LAB: IF 0', `LAB: ELSE' after a true
IF, `LAB: ENDIF' after one, `LAB: EXITM' in a macro or a REPT; not `LAB:
ELSE' or `LAB: ENDIF' after a false IF, nor any line inside one (U).  um80
defined none of them.

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


# A label on an ORG of a symbol defined further down: MAC and RMAC flag it P
# and keep the location before the ORG, which their pass 1 gave it (`DB 1 /
# LAB ORG X / DW LAB / X EQU 200H' is 01 01 01), where um80 --dri, whose
# pass 1 reads X's value there as pass 2 does, gave LAB 0200H (01 00 02)
# without a word.  M80 gives LAB the location before the ORG, flagging
# nothing, and so does um80 without --dri.
@pytest.mark.parametrize('line,m80', [
    ("lab:\torg\tx\n", '0100:01 0200:01 0201:01'),
    ("lab\torg\tx\n", None),
    ("lab:\torg\tx+10h\n", '0100:01 0210:01 0211:01'),
])
def test_dri_label_on_org_of_a_symbol_defined_further_down(line, m80):
    source = ("\taseg\n\torg\t100h\n\tdb\t1\n" + line
              + "\tdw\tlab\nx\tequ\t200h\n\tend\n")
    ok, _, errors = _image(source, dri=True)
    assert not ok
    assert any("reads a symbol defined further down: MAC and RMAC flag it P"
               in e for e in errors), errors
    if m80:
        ok, image, errors = _image(source)
        assert ok, errors
        assert image == m80


def test_dri_label_on_org_of_a_symbol_not_defined():
    # Undefined, as before (MAC and RMAC: U), not defined further down.
    ok, _, errors = _image("\taseg\n\torg\t100h\nlab\torg\tfoo\n\tend\n",
                           dri=True)
    assert not ok
    assert errors == ["Error at line 3: Undefined symbol 'foo'"], errors


@pytest.mark.parametrize('body,mac', [
    # MAC and RMAC flag none of these.
    ("\tdb\t1\n\torg\tx\n\tdb\t2\nx\tequ\t200h\n", '0100:01 0200:02'),
    ("x\tequ\t200h\n\tdb\t1\nlab:\torg\tx\n\tdw\tlab\n",
     '0100:01 0200:00 0201:02'),
    ("\tdb\t1\nlab:\torg\t$+4\n\tdw\tlab\n", '0100:01 0105:05 0106:01'),
])
def test_dri_org_that_mac_does_not_flag(body, mac):
    ok, image, errors = _image("\taseg\n\torg\t100h\n" + body + "\tend\n",
                               dri=True)
    assert ok, errors
    assert image == mac


# (lines after `ASEG / ORG 100H', M80's, MAC's and RMAC's image, or None
# where LAB is U in all three)
@pytest.mark.parametrize('body,image', [
    ("\tdb\t1\nlab:\tif\t1\n\tdb\t2\n\tendif\n\tdw\tlab\n",
     '0100:01 0101:02 0102:01 0103:01'),
    ("\tdb\t1\nlab:\tif\t0\n\tdb\t2\n\tendif\n\tdw\tlab\n",
     '0100:01 0101:01 0102:01'),
    ("\tdb\t1\n\tif\t1\n\tdb\t2\nlab:\tendif\n\tdw\tlab\n",
     '0100:01 0101:02 0102:02 0103:01'),
    ("\tdb\t1\n\tif\t1\n\tdb\t2\nlab:\telse\n\tdb\t3\n\tendif\n\tdw\tlab\n",
     '0100:01 0101:02 0102:02 0103:01'),
    ("mm\tmacro\n\tdb\t9\nlab:\texitm\n\tdb\t8\n\tendm\n\tdb\t1\n\tmm\n"
     "\tdw\tlab\n", '0100:01 0101:09 0102:02 0103:01'),
    ("mm\tmacro\tp\n\tdb\t9\nl&p:\texitm\n\tendm\n\tdb\t1\n\tmm\t7\n"
     "\tdw\tl7\n", '0100:01 0101:09 0102:02 0103:01'),
    ("\trept\t3\n\tdb\t1\nlab:\texitm\n\tendm\n\tdw\tlab\n",
     '0100:01 0101:01 0102:01'),
    ("\tirpc\tx,ab\n\tdb\t1\nl&x:\texitm\n\tendm\n\tdw\tla\n",
     '0100:01 0101:01 0102:01'),
    ("\tdb\t1\n\tif\t0\n\tdb\t2\nlab:\tendif\n\tdw\tlab\n", None),
    ("\tdb\t1\n\tif\t0\n\tdb\t2\nlab:\telse\n\tdb\t3\n\tendif\n\tdw\tlab\n",
     None),
    ("\tdb\t1\n\tif\t0\nlab:\tif\t1\n\tendif\n\tendif\n\tdw\tlab\n", None),
    ("mm\tmacro\n\tif\t0\nlab:\texitm\n\tendif\n\tdb\t9\n\tendm\n\tmm\n"
     "\tdw\tlab\n", None),
])
def test_label_on_a_conditional_or_exitm(body, image):
    source = "\taseg\n\torg\t100h\n" + body + "\tend\n"
    for dri in (False, True):
        ok, got, errors = _image(source, dri=dri)
        if image is None:
            assert not ok
            assert any("undefined symbol 'lab'" in e.lower() for e in errors), errors
        else:
            assert ok, errors
            assert got == image, (dri, got)
