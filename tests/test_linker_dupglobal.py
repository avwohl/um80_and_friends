"""A global defined by two modules: LINK-80's %Mult. Def. Global.

LINK-80 3.44 prints "%Mult. Def. Global FOO", binds every reference to the
first definition it loaded and writes the program.  ul80 does the same, and
names both modules and the one used:

    Warning: %Mult. Def. Global FOO: defined in A and in B; A's definition is used

ul80 up to 0.3.50 recorded "Error: Multiply defined global 'FOO'" but still
wrote the output and exited 0, so a build script could not tell; MP/M II's
CLI was mis-linked that way once its names were cut to six characters.  With
--fatal-mult-def (Linker.fatal_mult_def) it is an error: no output, exit 1.

A, B and C below are the .REL files the genuine M80 3.44 writes for

    A:  cseg / public foo / foo: nop / end
    B:  cseg / public foo / foo: ret / end
    C:  cseg / extrn foo / call foo / end

and the images are what the genuine L80 3.44 links from them (`C,A,B' and
`C,B,A', /P default 0103H).
"""

import os
import subprocess
import sys
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker

M80_A = bytes.fromhex('8450603464f4f9400004d40400011d000068c9e9f38000009e')
M80_B = bytes.fromhex('8450a03464f4f9400004d40401931d000068c9e9f38000009e')
M80_C = bytes.fromhex('8450e500001350300668000119010068c9e9f38000009e')
# L80 3.44, from 0103H: CALL 0106H, then the modules in link order.
L80_CAB = bytes.fromhex('cd060100c9')
L80_CBA = bytes.fromhex('cd0601c900')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _write(d, name, data):
    p = os.path.join(d, name + '.rel')
    with open(p, 'wb') as f:
        f.write(data)
    return p


def _link(d, order, fatal=False):
    linker = Linker()
    linker.code_base = 0x103
    linker.fatal_mult_def = fatal
    rels = {'A': M80_A, 'B': M80_B, 'C': M80_C}
    for name in order:
        linker.load_rel(_write(d, name, rels[name]))
    return linker.link(), linker


def test_first_definition_is_used_as_link80():
    with tempfile.TemporaryDirectory() as d:
        ok, linker = _link(d, 'CAB')
        assert ok, linker.errors
        assert bytes(linker.output) == L80_CAB
        assert linker.errors == []
        assert linker.warnings == [
            "Warning: %Mult. Def. Global FOO: defined in A and in B; "
            "A's definition is used"]
        assert linker.mult_defs == [('FOO', 'A', 'B')]
        ok, linker = _link(d, 'CBA')
        assert ok, linker.errors
        assert bytes(linker.output) == L80_CBA


def test_fatal_mult_def_fails_the_link():
    with tempfile.TemporaryDirectory() as d:
        ok, linker = _link(d, 'CAB', fatal=True)
    assert not ok
    assert linker.errors == ["Error: %Mult. Def. Global FOO: defined in A and in B"]


def _ul80(*args, cwd):
    env = dict(os.environ, PYTHONPATH=REPO)
    return subprocess.run([sys.executable, '-m', 'um80.ul80', *args], cwd=cwd,
                          capture_output=True, text=True, env=env, check=False)


def test_cli_warns_and_links_by_default(tmp_path):
    rels = [_write(str(tmp_path), n, r) for n, r in (('C', M80_C), ('A', M80_A), ('B', M80_B))]
    out = tmp_path / 'x.com'
    run = _ul80('-p', '103', '-o', str(out), *rels, cwd=tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "%Mult. Def. Global FOO: defined in A and in B; A's definition is used" in run.stderr
    assert '--fatal-mult-def' in run.stderr
    assert out.read_bytes()[:5] == L80_CAB


def test_cli_fatal_mult_def_exits_1_and_writes_nothing(tmp_path):
    rels = [_write(str(tmp_path), n, r) for n, r in (('C', M80_C), ('A', M80_A), ('B', M80_B))]
    out = tmp_path / 'x.com'
    run = _ul80('--fatal-mult-def', '-o', str(out), *rels, cwd=tmp_path)
    assert run.returncode == 1, run.stdout + run.stderr
    assert "Error: %Mult. Def. Global FOO: defined in A and in B" in run.stderr
    assert not out.exists()


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


def test_distinct_globals_link_clean():
    with tempfile.TemporaryDirectory() as d:
        r1 = _rel(d, "M1", "\tNAME (M1)\n\tPUBLIC A\n\tCSEG\nA:\tRET\n\tEND\n")
        r2 = _rel(d, "M2", "\tNAME (M2)\n\tPUBLIC B\n\tCSEG\nB:\tNOP\n\tEND\n")
        linker = Linker()
        linker.code_base = 0x100
        linker.fatal_mult_def = True
        linker.load_rel(r1)
        linker.load_rel(r2)
        assert linker.link()
        assert linker.errors == [] and linker.warnings == []


def test_an_alias_defined_twice(tmp_path):
    """A PUBLIC alias of an external (X EQU EXT+n) that another module also
    defines is the same warning, or with fatal_mult_def the same error."""
    d = str(tmp_path)
    base = _rel(d, "M1", "\tNAME (M1)\n\tPUBLIC EXT,DUP\n\tCSEG\nEXT:\tNOP\nDUP:\tRET\n\tEND\n")
    alias = _rel(d, "M2", "\tNAME (M2)\n\tEXTRN EXT\n\tPUBLIC DUP\nDUP\tEQU EXT+1\n\tEND\n")
    for fatal in (False, True):
        linker = Linker()
        linker.code_base = 0x100
        linker.fatal_mult_def = fatal
        linker.load_rel(base)
        linker.load_rel(alias)
        assert linker.link() is not fatal
        assert linker.mult_defs == [('DUP', 'M1', 'M2')]


def test_cli_succeeds_without_a_duplicate(tmp_path):
    r1 = _rel(str(tmp_path), "M1", "\tNAME (M1)\n\tPUBLIC ONE\n\tCSEG\nONE:\tRET\n\tEND\n")
    r2 = _rel(str(tmp_path), "M2", "\tNAME (M2)\n\tPUBLIC TWO\n\tCSEG\nTWO:\tNOP\n\tEND\n")
    out = tmp_path / "ok.com"
    run = _ul80('--fatal-mult-def', r1, r2, "-o", str(out), cwd=tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "Error" not in run.stderr and "Mult" not in run.stderr
