"""What a .PRL/.SPR bitmap marks: every address that moves with the program.

- __END__ (and __BSS_START/__BSS_END) are computed by the linker as absolute
  values, but they are program addresses.  Neither a word resolved through
  an external chain nor a link-time expression marked them, so PL/M's
  .MEMORY in a .PRL pointed at the linked address, not the loaded one: MP/M
  II's SDIR (UTIL7/DSE.PLM puts its hash table AT(.MEMORY), DM.PLM imports
  it through `X EQU __END__') wrote outside its memory segment whenever
  MP/M loaded it anywhere but at the link base.  A full MP/M II build now
  marks 17 more words in ED.PRL, 9 in PIP, 4 in SDIR and 3 in STAT, every
  one of them a reference to the program's end.
- Page zero moves with the program under MP/M; whether a reference is to
  page zero was judged on symbol+offset in the external chain and on the
  symbol in a link-time expression, so `LXI H,TBUF+80H' (0100H) escaped the
  bitmap while `MVI A,HIGH(TBUF+80H)' was marked.  It is the symbol now, in
  both.
- (BUF+255)/256, the page-rounding idiom, is HIGH(BUF+255) and can be
  relocated; it was refused.
"""

import os
import subprocess
import sys
import tempfile

import um80
from um80.um80 import Assembler
from um80.ul80 import Linker
from um80.ulib80 import Library

# Run the ul80 of this tree, not whatever `um80' is installed.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(um80.__file__)))


def _ul80(d, args, **env):
    return subprocess.run([sys.executable, "-m", "um80.ul80"] + args, cwd=d,
                          env=dict(os.environ, PYTHONPATH=ROOT, **env),
                          capture_output=True, text=True, check=False)


def _rel(d, name, source):
    p = os.path.join(d, name + ".mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), [e.message for e in asm.errors]
    rp = os.path.join(d, name + ".rel")
    with open(rp, "wb") as f:
        f.write(asm.output.get_bytes())
    return rp


def _prl_marks(linker, d):
    p = os.path.join(d, "out.prl")
    linker.save_prl(p)
    image = open(p, "rb").read()
    n = image[1] | (image[2] << 8)
    bitmap = image[256 + n:]
    return {i for i in range(n) if bitmap[i >> 3] & (0x80 >> (i & 7))}


def _link(d, *rels, origin=0x100):
    linker = Linker()
    linker.code_base = origin
    linker.page_zero_relative = True
    for r in rels:
        linker.load_rel(r)
    assert linker.link(), linker.errors
    return linker


def test_end_symbol_moves_with_the_program():
    with tempfile.TemporaryDirectory() as d:
        a = _rel(d, "A", "\textrn __END__\n\tcseg\n\tlxi h,__END__\n"
                         "\tmvi a,high(__END__)\n\tmvi a,low(__END__)\n"
                         "\tdb high(__END__+100h)\n\tdw __END__\n\tend\n")
        linker = _link(d, a)
        marks = _prl_marks(linker, d)
    assert _word(linker.output, 1) == 0x10A
    assert marks == {2, 4, 7, 9}, sorted(marks)


def test_alias_of_end_moves_too():
    """UTIL7: DSE exports `HT EQU __END__', DM uses HT and HT+2."""
    with tempfile.TemporaryDirectory() as d:
        dse = _rel(d, "DSE", ".z80\n\textrn __END__\n\tpublic HT\n\tcseg\n"
                             "\tld hl,HT\nHT\tequ __END__\n\tds 8\n\tend\n")
        dm = _rel(d, "DM", ".z80\n\textrn HT\n\tcseg\n\tld hl,HT\n"
                           "\tld (HT+2),a\n\tend\n")
        linker = _link(d, dm, dse)
        marks = _prl_marks(linker, d)
    assert {2, 5} <= marks, sorted(marks)


def test_page_zero_is_judged_on_the_symbol():
    with tempfile.TemporaryDirectory() as d:
        pz = _rel(d, "PZ", "\tpublic tbuf,khi\ntbuf\tequ 80h\nkhi\tequ 1234h\n"
                           "\tend\n")
        a = _rel(d, "A", "\textrn tbuf,khi\n\tcseg\n\tlxi h,tbuf+80h\n"
                         "\tlxi h,tbuf+7fh\n\tmvi a,high(tbuf+80h)\n"
                         "\tlxi h,khi-1200h\n\tret\n\tend\n")
        linker = _link(d, a, pz)
        marks = _prl_marks(linker, d)
    assert _word(linker.output, 1) == 0x100
    # Both words and the HIGH byte of TBUF+n are marked; KHI-1200H (0034H,
    # a constant) is not.
    assert {2, 5, 7} <= marks, sorted(marks)
    assert 10 not in marks, sorted(marks)


def test_page_rounding_can_be_relocated():
    with tempfile.TemporaryDirectory() as d:
        b = _rel(d, "B", "\tcseg\n\tmvi a,(buf+255)/256\n\tlxi h,(buf+255)/256\n"
                         "\tmvi a,buf mod 256\n\tret\n\tdseg\nbuf:\tds 10\n\tend\n")
        linker = _link(d, b)
        marks = _prl_marks(linker, d)
    buf = 0x100 + 8
    assert linker.output[1] == (buf + 255) // 256
    assert marks == {1, 3}, sorted(marks)


def _word(out, i):
    return out[i] | (out[i + 1] << 8)


def test_library_search_is_in_library_order_and_reproducible():
    """The order modules came out of a library depended on Python's string
    hashing, so two runs of the same link could give different images."""
    with tempfile.TemporaryDirectory() as d:
        _rel(d, "MAIN", "\textrn f1,v2\n\tcseg\n\tcall f1\n\tlxi h,v2+3\n"
                        "\tret\n\tend\n")
        m1 = _rel(d, "M1", "\tpublic f1\n\textrn v2\n\tcseg\nf1:\tlxi h,buf\n"
                           "\tdw v2\n\tret\n\tdseg\nbuf:\tds 2\n\tend\n")
        m2 = _rel(d, "M2", "\tpublic v2\n\tcseg\n\tdb 9,9\nv2:\tdw v2\n\tend\n")
        m3 = _rel(d, "M3", "\tpublic zz\n\tcseg\nzz:\tdw zz\n\tend\n")
        lib = Library()
        for r in (m1, m2, m3):
            lib.add_rel_file(r)
        lib.save(os.path.join(d, "o.lib"))
        images = set()
        for seed in ("1", "2", "3", "4", "5", "6"):
            r = _ul80(d, ["-o", f"n{seed}.com", "MAIN.rel", "o.lib"],
                      PYTHONHASHSEED=seed)
            assert r.returncode == 0, r.stderr
            images.add(open(os.path.join(d, f"n{seed}.com"), "rb").read())
        assert len(images) == 1


def test_library_module_needed_only_by_an_expression_is_loaded():
    with tempfile.TemporaryDirectory() as d:
        main = _rel(d, "MAIN", "\textrn u3\n\tcseg\n\tmvi a,low(u3-1)\n"
                               "\tret\n\tend\n")
        m3 = _rel(d, "M3", "\tpublic u3\n\tcseg\n\tds 5\nu3:\tnop\n\tend\n")
        lib = Library()
        lib.add_rel_file(m3)
        lib.save(os.path.join(d, "o.lib"))
        r = _ul80(d, ["-o", "o.com", main, os.path.join(d, "o.lib")])
        assert r.returncode == 0, r.stderr
        image = open(os.path.join(d, "o.com"), "rb").read()
    assert image[1] == (0x100 + 3 + 5 - 1) & 0xFF


def test_expression_without_a_store_fails_the_link():
    """ul80 printed the error, wrote the image with the field left 0, and
    exited 0."""
    from um80.relformat import (RELWriter, ADDR_PROGRAM_REL, EXT_OP_HIGH)
    w = RELWriter()
    w.write_program_name("BAD")
    w.write_set_location(ADDR_PROGRAM_REL, 0)
    w.write_absolute_byte(0x3E)
    w.write_ext_value(ADDR_PROGRAM_REL, 0)
    w.write_ext_operator(EXT_OP_HIGH)
    w.write_absolute_byte(0)
    w.write_absolute_byte(0xC9)
    w.write_end_program()
    w.write_end_file()
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "bad.rel"), "wb") as f:
            f.write(w.get_bytes())
        r = _ul80(d, ["-o", "bad.com", "bad.rel"])
        assert r.returncode != 0
        assert "no store operator" in r.stderr
        assert not os.path.exists(os.path.join(d, "bad.com"))


def test_chained_reference_to_an_absolute_symbol_is_not_marked():
    """A MACRO-80 chain runs through the words: `CALL X' twice leaves the
    second word holding P 0001H, the link to the first.  Its relocation
    record said program relative, and the bitmap marked the word by it,
    although the word ends up holding X - here the constant 1234H, which
    does not move.  Only what the filled-in value is decides."""
    from um80.relformat import (RELWriter, ADDR_ABSOLUTE, ADDR_PROGRAM_REL)
    with tempfile.TemporaryDirectory() as d:
        w = RELWriter()
        w.write_program_name("A")
        w.write_define_entry_point(ADDR_ABSOLUTE, 0x1234, "X")
        w.write_define_entry_point(ADDR_PROGRAM_REL, 0, "Y")
        w.write_define_program_size(1)
        w.write_absolute_byte(0xC9)
        w.write_end_program()
        w.write_end_file()
        a = os.path.join(d, "a.rel")
        with open(a, "wb") as f:
            f.write(w.get_bytes())
        w = RELWriter()
        w.write_program_name("M")
        w.write_define_program_size(12)
        for b in (0xCD, 0, 0, 0xCD):  # CALL X (end of chain), CALL X
            w.write_absolute_byte(b)
        w.write_program_relative(1)
        for b in (0xCD, 0, 0, 0xCD):  # CALL Y (end of chain), CALL Y
            w.write_absolute_byte(b)
        w.write_program_relative(7)
        w.write_chain_external(ADDR_PROGRAM_REL, 4, "X")
        w.write_chain_external(ADDR_PROGRAM_REL, 10, "Y")
        w.write_end_program()
        w.write_end_file()
        m = os.path.join(d, "m.rel")
        with open(m, "wb") as f:
            f.write(w.get_bytes())
        linker = Linker()
        linker.code_base = 0x100
        linker.page_zero_relative = True
        linker.load_rel(m)
        linker.load_rel(a)
        assert linker.link(), linker.errors
        assert bytes(linker.output[:12]) == bytes.fromhex(
            "cd3412cd3412cd0c01cd0c01")
        # Y's two words move (high bytes at 8 and 11); X's do not.
        assert _prl_marks(linker, d) == {8, 11}
