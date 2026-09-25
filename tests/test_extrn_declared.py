"""An EXTRN a module declares and never uses is still in its .REL.

MACRO-80 3.44 writes an item 6 (chain external) for every external symbol,
with the head of the chain at absolute 0 - where LINK-80's chains end - when
no instruction refers to it: an EXTRN declared and never used, or one used
only inside a link-time expression.  The item is what tells the linker that
the module needs the symbol: LINK-80 searches a library for it (so `EXTRN X'
alone pulls X's module out of a library) and lists it with its undefined
globals if nothing defines it.  um80 wrote nothing, so the library module
was not linked; mbasic2025's BINTRP.MAC declares 40-odd externals it never
uses.  Checked with the genuine M80 and L80 3.44 under a CP/M emulator.

ul80, for its part, stopped with "Undefined symbol" on such an external that
nothing defines - on M80's objects too - where LINK-80 lists it and writes
the program: there is nothing in the program to fill in.  It is a warning
now.  An external something refers to is still an error.
"""

import os
import subprocess
import sys
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler
from um80.ul80 import Linker
from um80.ulib80 import Library


def _rel(source, d, name, **kw):
    p = os.path.join(d, name + ".mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler(**kw)
    assert asm.assemble(p), [e.message for e in asm.errors]
    out = os.path.join(d, name + ".rel")
    with open(out, "wb") as f:
        f.write(asm.output.get_bytes())
    return out


def _chains(path):
    with open(path, "rb") as f:
        items = RELReader(f.read()).read_all()
    return [(it[1], it[2]) for it in items if it[0] == 'CHAIN_EXTERNAL']


def test_declared_extrn_written_as_empty_chain():
    with tempfile.TemporaryDirectory() as d:
        p = _rel("\textrn\tfoo,bar,baz\n\tcall\tbar\n\tmvi\ta,low(baz)\n\tend\n", d, "t")
        chains = _chains(p)
    assert ((0, 0), 'FOO') in chains
    assert ((0, 0), 'BAZ') in chains          # used only in a link-time expression
    assert [c for c in chains if c[1] == 'BAR'] == [((1, 1), 'BAR')]


def _link(paths):
    linker = Linker()
    linker.code_base = 0x100
    for p in paths:
        linker.load_rel(p)
    ok = linker.link()
    return ok, linker


def test_library_module_pulled_for_declared_extrn(tmp_path):
    """`EXTRN FOO' alone links FOO's module out of a library, as LINK-80 does."""
    d = str(tmp_path)
    t = _rel("\textrn\tfoo\n\tdb\t1\n\tend\n", d, "t")
    f = _rel("\tpublic\tfoo\nfoo:\tdb\t0AAh,0BBh\n\tend\n", d, "f")
    g = _rel("\tpublic\tgoo\ngoo:\tdb\t0CCh\n\tend\n", d, "g")
    lib = Library()
    lib.add_rel_file(g)
    lib.add_rel_file(f)
    lib.save(os.path.join(d, "fg.lib"))
    out = os.path.join(d, "t.com")
    run = subprocess.run([sys.executable, "-m", "um80.ul80", t, os.path.join(d, "fg.lib"),
                          "-o", out], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    with open(out, "rb") as fh:
        assert fh.read()[:4] == bytes([0x01, 0xAA, 0xBB, 0x00])


def test_undefined_declared_extrn_is_a_warning():
    with tempfile.TemporaryDirectory() as d:
        t = _rel("\textrn\tfoo,bar\n\tcall\tbar\n\tdb\t1\n\tend\n", d, "t")
        b = _rel("\tpublic\tbar\nbar:\tret\n\tend\n", d, "b")
        ok, linker = _link([t, b])
    assert ok, linker.errors
    assert any('FOO' in w for w in linker.warnings), linker.warnings
    assert bytes(linker.output) == bytes([0xCD, 0x04, 0x01, 0x01, 0xC9])


def test_undefined_used_extrn_is_still_an_error():
    with tempfile.TemporaryDirectory() as d:
        t = _rel("\textrn\tfoo\n\tcall\tfoo\n\tend\n", d, "t")
        ok, linker = _link([t])
        assert not ok
        assert any('FOO' in e for e in linker.errors)
        t = _rel("\textrn\tfoo\n\tmvi\ta,low(foo)\n\tend\n", d, "t")
        ok, linker = _link([t])
        assert not ok
        assert any('FOO' in e for e in linker.errors)
