"""How a macro call's arguments, and an IRP or IRPC list, are read.

The expected bytes are what MACRO-80 3.44 (the source with ASEG), MAC 2.0
and RMAC 1.1 assemble under cpmemu.
"""

import os
import tempfile

import pytest

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


def _code(source, **kw):
    ok, code, errors, _ = _assemble(source, **kw)
    assert ok, errors
    return code


BOTH = pytest.mark.parametrize('dri', [False, True], ids=['m80', 'dri'])


@BOTH
def test_a_semicolon_in_brackets_is_text(dri):
    # In a macro call's arguments and an IRP list a `;' inside <...> is not
    # a comment.  DRI's CONTROL/DISKDEF.LIB passes `<;sec per track>' to a
    # macro whose body is `dw data comment'.  M80, MAC and RMAC: 01 3B 58
    # 09; 05 00 09; 31 3B 32.  um80 cut each line at the `;': 01 3C 09,
    # "Cannot parse expression: '5 <'", and 31 3C.
    assert _code("GEN\tMACRO\tA,B\n\tDB\tA\n\tDB\t'&B'\n\tENDM\n"
                 "\tGEN\t1,<;X> ; a comment\n\tDB\t9\n", dri=dri) == '013b5809'
    assert _code("DDW\tMACRO\tD,C\n\tDW\tD\t\tC\n\tENDM\n"
                 "\tDDW\t5,<;comment here>\n\tDB\t9\n", dri=dri) == '050009'
    ok, code, _, warnings = _assemble("\tIRP\tX,<1,<;>,2>\n\tDB\t'&X'\n\tENDM\n",
                                      dri=dri)
    assert ok and code == '313b32' and warnings == []


@BOTH
def test_a_semicolon_elsewhere_still_starts_a_comment(dri):
    # `IF 1<2 ;x' has no brackets: MAC reads < as LT.  And a comment after
    # a bracketed argument is a comment.
    assert _code("GEN\tMACRO\tA\n\tDB\tA\n\tENDM\n\tGEN\t<3> ;<;\n"
                 "\tDB\t1 ;<\n", dri=dri) == '0301'
