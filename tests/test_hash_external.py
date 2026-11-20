"""X## names an external by its whole name, as EXTRN and PUBLIC do (issue #6).

um80 cut the name of a ## reference to 6 characters before the symbol
lookup, so STAYTOP## became an external STAYTO that the STAYTOP:: of another
module never met (ul80: "Undefined symbol: STAYTO"), and a plain STAYTOP after
STAYTOP## was "Undefined symbol".  The cut came from a first model of M80,
made before -t existed.

Measured with MACRO-80 3.44 and LINK-80 3.44 under cpmemu on 2026-11-20:
M80 keeps 16 characters of a name in its symbol table (STAYTOP and STAYTO are
two symbols, so `LXI H,STAYTO' after `LXI D,STAYTOP##' is flagged U) and
writes the first 6 characters of a PUBLIC or external name in the .REL.
STAYTOP## then STAYTOP in one module: one external, no error.  EXTRN LONGEXT,
LONGEXT## and LONGEXT: one symbol.  LONGNAME1## and LONGNAME2##: two
externals, both written LONGNA.  Module A with STAYTOP:: and module B with
LD DE,STAYTOP## link in L80.  um80 writes the whole name unless -t is given;
-t cuts to 6 in the .REL only, which gives M80's .REL.
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler
from um80.ul80 import Linker

# The .REL of the genuine MACRO-80 3.44 for
#       lxi h,longname1##
#       lxi d,longname2##
#       end
M80_TWO_EXT = bytes.fromhex(
    '8515d3d492e500001350600108000011000023202019313d391d39063208019313d39'
    '1d390670000009e')

A = "\t.Z80\n\tCSEG\nSTAYTOP::\n\tNOP\n\tRET\n\tEND\n"
B = "\t.Z80\n\tCSEG\n\tLD\tDE,STAYTOP##\n\tRET\n\tEND\n"


def _asm(source, d, name, **kw):
    p = os.path.join(d, name + ".mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler(**kw)
    ok = asm.assemble(p)
    return ok, asm


def _rel(source, d, name, **kw):
    ok, asm = _asm(source, d, name, **kw)
    assert ok, [e.message for e in asm.errors]
    out = os.path.join(d, name + ".rel")
    with open(out, "wb") as f:
        f.write(asm.output.get_bytes())
    return out


def _items(path):
    with open(path, "rb") as f:
        return RELReader(f.read()).read_all()


def _ext_names(items):
    return [it[-1] for it in items if it[0] == 'CHAIN_EXTERNAL']


def _link(d, **kw):
    a = _rel(A, d, "a", **kw)
    b = _rel(B, d, "b", **kw)
    linker = Linker()
    linker.code_base = 0x100
    linker.load_rel(a)
    linker.load_rel(b)
    return linker.link(), linker, b


def test_hash_links_with_double_colon_definition():
    with tempfile.TemporaryDirectory() as d:
        ok, linker, b = _link(d)
        names = _ext_names(_items(b))
    assert ok, linker.errors
    assert names == ['STAYTOP']


def test_hash_links_with_t_both_sides_cut():
    with tempfile.TemporaryDirectory() as d:
        ok, linker, b = _link(d, truncate_symbols=True)
        names = _ext_names(_items(b))
    assert ok, linker.errors
    assert names == ['STAYTO']


def test_hash_then_plain_name_is_one_external():
    src = "\tLXI\tD,STAYTOP##\n\tLXI\tH,STAYTOP\n\tEND\n"
    with tempfile.TemporaryDirectory() as d:
        rel = _rel(src, d, "c")
        assert _ext_names(_items(rel)) == ['STAYTOP', 'STAYTOP']
        rel = _rel(src, d, "ct", truncate_symbols=True)
        assert _ext_names(_items(rel)) == ['STAYTO', 'STAYTO']


def test_extrn_hash_and_plain_are_one_symbol():
    src = ("\tEXTRN\tLONGEXT\n\tLXI\tH,LONGEXT##\n\tLXI\tD,LONGEXT\n"
           "\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        ok, asm = _asm(src, d, "c")
        assert ok, [e.message for e in asm.errors]
        syms = [n for n in asm.symbols if n.upper().startswith("LONGEX")]
        assert syms == ["LONGEXT"]
        rel = _rel(src, d, "c2")
        assert set(_ext_names(_items(rel))) == {'LONGEXT'}
        rel = _rel(src, d, "c3", truncate_symbols=True)
        assert set(_ext_names(_items(rel))) == {'LONGEX'}


def test_two_long_hash_names_are_two_externals():
    src = "\tLXI\tH,LONGNAME1##\n\tLXI\tD,LONGNAME2##\n\tEND\n"
    with tempfile.TemporaryDirectory() as d:
        rel = _rel(src, d, "c")
        assert _ext_names(_items(rel)) == ['LONGNAME1', 'LONGNAME2']
        rel = _rel(src, d, "ct", truncate_symbols=True)
        # The module name comes from the file name; the rest is M80's.
        mine = [i for i in _items(rel) if i[0] != 'PROGRAM_NAME']
        m80 = [i for i in RELReader(M80_TWO_EXT).read_all()
               if i[0] != 'PROGRAM_NAME']
        assert mine == m80
        assert _ext_names(_items(rel)) == ['LONGNA', 'LONGNA']


def test_cut_name_after_hash_is_undefined_as_in_m80():
    src = "\tLXI\tD,STAYTOP##\n\tLXI\tH,STAYTO\n\tEND\n"
    with tempfile.TemporaryDirectory() as d:
        ok, asm = _asm(src, d, "c")
        msgs = [e.message for e in asm.errors]
    assert not ok
    assert any("STAYTO" in m and "ndefined" in m for m in msgs), msgs


def test_hash_of_local_long_alias_gives_alias_value():
    # M80 flags M for a ## of a name defined in the same module; um80 reads
    # the ## as the definition (not changed by issue #6).  Before the fix a
    # long name missed its alias, because the cut name was another symbol.
    src = ("\tCSEG\nLONGALIAS\tEQU\t1234H\n\tLXI\tH,LONGALIAS##\n"
           "\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        rel = _rel(src, d, "c")
        assert _ext_names(_items(rel)) == []
        assert _program_bytes(rel) == bytes([0x21, 0x34, 0x12])


def _program_bytes(rel):
    out = b""
    for it in _items(rel):
        if it[0] == 'ABSOLUTE_BYTE':
            out += bytes([it[1]])
    return out


def test_high_low_offset_type_of_long_hash_name():
    src = ("\tMVI\tA,HIGH LONGNAME1##\n\tMVI\tA,LOW LONGNAME1##\n"
           "\tLXI\tH,LONGNAME1##+2\n\tMVI\tA,TYPE LONGNAME1##\n\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        rel = _rel(src, d, "c")
        items = _items(rel)
        text = repr(items)
    assert text.count("LONGNAME1") >= 3, items
    assert "LONGNA'" not in text
