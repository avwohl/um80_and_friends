"""A label on the ENDM that ends a MACRO, REPT, IRP or IRPC body.

MAC 2.0 and RMAC 1.1 define it where the body ends, each time the body is
expanded: DRI's CONTROL/STACK.LIB ends its SIZ macro with `STACK: ENDM' (a
LOCAL name, the top of the stack it reserves), COMPARE.LIB's GTR with `FL:
ENDM' and SEQIO.LIB's FILLFCB with `PFCB: ENDM'.  MACRO-80 3.44 ignores it,
and a reference to it is U.  um80 ignored it, with or without --dri, and did
not see `L&X: ENDM' as an ENDM at all: every line after it went into the
body ("Unterminated IRP").  M80, MAC and RMAC end the IRP there.

The expected bytes are MAC's and RMAC's under cpmemu; M80's errors are U.
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler

HEAD = "\taseg\n\torg\t100h\n"


def _assemble(source, **kw):
    """(ok, bytes, errors, warnings)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(HEAD + source + "\tend\n")
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE').hex() if ok else None
    return ok, code, [str(e) for e in asm.errors], asm.warnings


# COMPARE.LIB's GTR: a LOCAL label on the ENDM, so each expansion jumps to
# its own end.  MAC and RMAC: C3 04 01 00, C3 08 01 00, 09.
LOCAL_LABEL = "MM\tMACRO\n\tLOCAL\tFL\n\tJMP\tFL\n\tNOP\nFL:\tENDM\n\tMM\n\tMM\n\tDB\t9\n"
# MAC and RMAC: 00, then DW XX = 01 01.
PLAIN_LABEL = "MM\tMACRO\n\tNOP\nXX:\tENDM\n\tMM\n\tDW\tXX\n"
# MAC and RMAC: 01 02, then DW L1,L2 = 01 01 02 01.
IRP_LABEL = "\tIRP\tX,<1,2>\n\tDB\tX\nL&X:\tENDM\n\tDW\tL1,L2\n"


def test_dri_defines_it_where_the_body_ends():
    for src, code in ((LOCAL_LABEL, 'c3040100c308010009'),
                      (PLAIN_LABEL, '000101'),
                      (IRP_LABEL, '010201010201')):
        ok, got, errors, warnings = _assemble(src, dri=True)
        assert ok, errors
        assert got == code and warnings == []


def test_m80_ignores_it():
    # M80: U at each JMP FL, at DW XX and at DW L1,L2 - the label is not
    # defined.  The IRP still ends at `L&X: ENDM' (M80: 01 02).
    for src, name in ((LOCAL_LABEL, 'FL?0001'), (PLAIN_LABEL, 'XX'),
                      (IRP_LABEL, 'L1')):
        ok, _, errors, warnings = _assemble(src)
        assert not ok
        assert any(f"Undefined symbol '{name}'" in e for e in errors), errors
        assert warnings == []
