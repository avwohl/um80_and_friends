"""The IFs of a macro expansion, or of one repetition of a REPT, IRP or IRPC.

EXITM ends an expansion inside the IFs it opened, and their ENDIFs are not
read.  MACRO-80 3.44, MAC 2.0 and RMAC 1.1 close them without a word; um80
left them open to the end of the file and warned "Unterminated conditional
(missing ENDIF)" - DRI's CONTROL/INTER.LIB SETLITE with DEBUG TRUE, or
`IF NUL P / EXITM / ENDIF' inside another IF.

The expected bytes are what M80 3.44 (the source with ASEG), MAC 2.0 and
RMAC 1.1 assemble under cpmemu.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler

HEAD = "\taseg\n\torg\t100h\n"


def _assemble(source, **kw):
    """(bytes, warnings)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 't.asm')
        with open(p, 'w') as f:
            f.write(HEAD + source + "\tend\n")
        asm = Assembler(**kw)
        assert asm.assemble(p), [str(e) for e in asm.errors]
        code = bytes(it[1] for it in RELReader(asm.output.get_bytes()).read_all()
                     if it[0] == 'ABSOLUTE_BYTE')
    return code.hex(), asm.warnings


BOTH = pytest.mark.parametrize('dri', [False, True], ids=['m80', 'dri'])

EXITM = ("MM\tMACRO\tP\n\tDB\t1\n\tIF\t1\n\tIF\tNUL P\n\tEXITM\n\tENDIF\n"
         "\tENDIF\n\tDB\t2\n\tENDM\n"
         "\tIF\t1\n\tMM\n\tMM\tX\n\tENDIF\n"
         "\tIRPC\tC,ABC\n\tIF\t1\n\tDB\t'&C'\n\tEXITM\n\tENDIF\n\tENDM\n"
         "\tREPT\t3\n\tDB\t4\n\tIF\t1\n\tEXITM\n\tENDIF\n\tENDM\n\tDB\t3\n")


@BOTH
def test_exitm_ends_the_ifs_it_is_in(dri):
    # M80, MAC, RMAC: 01, 01 02, 41, 04, 03, and no message.  The IF 1
    # around the calls is not one of the macro's: its ENDIF still ends it.
    code, warnings = _assemble(EXITM, dri=dri)
    assert code == '01' '0102' '41' '04' '03'
    assert warnings == []


# A body that leaves an IF open: MAC and RMAC end it with the expansion, or
# with the repetition; M80 carries it on.
OPEN = ("MM\tMACRO\tP\n\tIF\tP\n\tDB\t1\n\tELSE\n\tDB\t2\n\tENDM\n"
        "INNR\tMACRO\n\tIF\t0\n\tENDM\nMO\tMACRO\n\tINNR\n\tDB\t5\n\tENDM\n"
        "\tMM\t0\n\tMM\t1\n\tMO\n"
        "\tIRPC\tC,0123\n\tIF\tC AND 1\n\tDB\tC\n\tENDM\n"
        "\tDB\t9\n")


def test_dri_an_if_a_body_leaves_open_ends_with_it():
    # MAC and RMAC: 02 01 05 01 03 09 - COMPARE.LIB's TEST? and SEQIO.LIB's
    # FILLFCB leave IFs open so.  um80 --dri gave 02 01 and warned.
    code, warnings = _assemble(OPEN, dri=True)
    assert code == '0201' '05' '0103' '09'
    assert warnings == []


def test_m80_carries_an_open_if_on():
    # M80: 02 01, then MM 1's ELSE is false to the end of the file
    # ("Unterminated Conditional", and no END seen).
    code, warnings = _assemble(OPEN)
    assert code == '0201'
    assert warnings == ['Warning at line 33: Unterminated conditional (missing ENDIF)']
