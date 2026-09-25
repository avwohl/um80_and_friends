"""um80 -t cuts names to the six characters MACRO-80 keeps.

M80 3.44 keeps the first six characters of a name: mbasic2025's BINTRP.MAC
declares `public fbufp27', and M80 writes the PUBLIC FBUFP2; F4.MAC, which
uses it, asks for FBUFP2.  um80 writes the whole name.  Built entirely with
either assembler, MBASIC links; linked from BINTRP.REL of one assembler and
F4.REL of the other, LINK-80 reports an undefined global and ul80 stops.
`-t' was meant for this but cut names to 8 characters, which neither M80
nor LINK-80 (it reads 7) does; it now cuts them to 6.
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler
from um80.ul80 import Linker

# The .REL the genuine MACRO-80 3.44 writes for
#       public  fbufp27
# fbufp27: db   55h
#       end
M80_REL = bytes.fromhex('84910de064642554650329400004d40400ab1d0000c8c84aa8ca06538000009e')

USER = "\textrn\tfbufp27\n\tlxi\th,fbufp27\n\tend\n"


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


def _link(d, user_kw):
    m80 = os.path.join(d, "d7.rel")
    with open(m80, "wb") as f:
        f.write(M80_REL)
    user = _rel(USER, d, "u", **user_kw)
    linker = Linker()
    linker.code_base = 0x100
    linker.load_rel(user)
    linker.load_rel(m80)
    return linker.link(), linker


def test_m80_fixture_names_fbufp2():
    names = [it[-1] for it in RELReader(M80_REL).read_all() if it[0] == 'DEFINE_ENTRY']
    assert names == ['FBUFP2']


def test_truncate_links_with_m80_object():
    with tempfile.TemporaryDirectory() as d:
        ok, linker = _link(d, {'truncate_symbols': True})
    assert ok, linker.errors
    # LXI H,0103H: FBUFP2 is the byte after the 3-byte LXI.
    assert bytes(linker.output) == bytes([0x21, 0x03, 0x01, 0x55])


def test_without_truncate_the_long_name_is_not_found():
    with tempfile.TemporaryDirectory() as d:
        ok, linker = _link(d, {})
    assert not ok
    assert any('FBUFP27' in e for e in linker.errors)


def test_truncate_cuts_every_name_to_six():
    src = ("\tname('longmodule')\n\tpublic\tpublic7\n\textrn\texternal8\n"
           "public7:\tdw\texternal8\n\tmvi\ta,low(external8)\n\tend\n")
    with tempfile.TemporaryDirectory() as d:
        with open(_rel(src, d, "t", truncate_symbols=True), "rb") as f:
            items = RELReader(f.read()).read_all()
    names = {it[-1] for it in items
             if it[0] in ('PROGRAM_NAME', 'DEFINE_ENTRY', 'CHAIN_EXTERNAL', 'EXT_SYMBOL')}
    assert names == {'LONGMO', 'PUBLIC', 'EXTERN'}
