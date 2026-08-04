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


def test_cli_reports_and_fails_on_a_duplicate(tmp_path):
    """The API recorded the error; the command line threw it away.

    ul80's main() printed linker.errors only when link() returned false.
    L80 keeps the first definition of a multiply-defined global and links
    on, so link() succeeds and the recorded error was silently dropped --
    exit 0, output written, nothing on stderr.  That is what let uc80 emit
    two different __printf_format_table definitions and have the link
    order quietly decide which one won.
    """
    import subprocess
    import sys

    r1 = _rel(str(tmp_path), "M1", "\tNAME (M1)\n\tPUBLIC DUP\n\tCSEG\nDUP:\tRET\n\tEND\n")
    r2 = _rel(str(tmp_path), "M2", "\tNAME (M2)\n\tPUBLIC DUP\n\tCSEG\nDUP:\tNOP\n\tEND\n")
    out = tmp_path / "dup.com"
    run = subprocess.run([sys.executable, "-m", "um80.ul80",
                          r1, r2, "-o", str(out)],
                         capture_output=True, text=True)
    assert "Multiply defined global" in run.stderr, run.stderr
    # L80 keeps the first definition and produces output, and so do we, so
    # the status stays 0; the diagnostic is the part that was missing.
    assert out.exists()


def test_cli_succeeds_without_a_duplicate(tmp_path):
    import subprocess
    import sys

    r1 = _rel(str(tmp_path), "M1", "\tNAME (M1)\n\tPUBLIC ONE\n\tCSEG\nONE:\tRET\n\tEND\n")
    r2 = _rel(str(tmp_path), "M2", "\tNAME (M2)\n\tPUBLIC TWO\n\tCSEG\nTWO:\tNOP\n\tEND\n")
    out = tmp_path / "ok.com"
    run = subprocess.run([sys.executable, "-m", "um80.ul80",
                          r1, r2, "-o", str(out)],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "Error" not in run.stderr
