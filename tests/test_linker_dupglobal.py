"""A multiply-defined PUBLIC global is a link error (real L80 3.44).

L80 reports "%Mult. Def. Global <name>" for a symbol made PUBLIC by more than
one module, keeps the first definition, and still produces output. ul80 now
records it as an error (was only a warning) while still linking.
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _rel(tmpdir, name, source):
    p = os.path.join(tmpdir, name + ".mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), asm.errors
    rp = os.path.join(tmpdir, name + ".rel")
    with open(rp, "wb") as f:
        f.write(asm.output.get_bytes())
    return rp


def test_duplicate_public_global_is_error():
    with tempfile.TemporaryDirectory() as d:
        r1 = _rel(d, "M1", "\tNAME (M1)\n\tPUBLIC DUP\n\tCSEG\nDUP:\tRET\n\tEND\n")
        r2 = _rel(d, "M2", "\tNAME (M2)\n\tPUBLIC DUP\n\tCSEG\nDUP:\tNOP\n\tEND\n")
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(r1)
        linker.load_rel(r2)
        linker.link()
        assert any("Multiply defined global" in e and "DUP" in e for e in linker.errors)


def test_distinct_globals_link_clean():
    with tempfile.TemporaryDirectory() as d:
        r1 = _rel(d, "M1", "\tNAME (M1)\n\tPUBLIC A\n\tCSEG\nA:\tRET\n\tEND\n")
        r2 = _rel(d, "M2", "\tNAME (M2)\n\tPUBLIC B\n\tCSEG\nB:\tNOP\n\tEND\n")
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(r1)
        linker.load_rel(r2)
        assert linker.link()
        assert linker.errors == []
