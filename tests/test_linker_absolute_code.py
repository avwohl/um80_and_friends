"""ul80: where relocatable code goes when absolute (ASEG) code is loaded.

ul80 placed each module's code straight after the previous module's, even
where an earlier module had loaded absolute code: `ASEG / ORG 100H' in one
module and a CSEG in the next linked the CSEG on top of the absolute code,
without a message.

LINK-80 3.44, probed under cpmemu, starts the next module's area above the
highest absolute location loaded so far (a byte loaded, or a location set
by ORG or DS), when that is above where it would go: with the default
origin, with /P:, and whether the absolute code is at the origin or above
it (ASEG at 0200H, /P:100: the next module goes at 0204H, not 0100H).
Absolute code below the origin moves nothing.  A module's own absolute code
does not move its own program area, which L80 allocates before loading
it.  Where absolute code does land on relocatable code - the module's own,
an earlier module's, or the data and COMMON that ul80 puts after all the
code - or on another module's absolute code, L80 prints "%Overlaying
Program area" (or Data area) and writes a mixture; ul80 fails the link
with an error - or with --allow-overlap, for a patch or overlay module
loaded over code on purpose, warns and writes the byte loaded last, as
L80 does with /D.
"""

import os
import subprocess
import sys
import tempfile

import um80
from um80.um80 import Assembler
from um80.ul80 import Linker

# M80 3.44's objects for
#   \taseg / \torg 100h / \textrn ext / \tjmp ext / \tdb 'x' / \tend
M80_ABS = bytes.fromhex(
    "84934c25000012c00016180000788c0080b4558549c000009e")
#   \tcseg / \tpublic ext / \tds 5 / ext:\tret / \tend
M80_CS = bytes.fromhex(
    "84934c6034558549400004d418025a00012d050064c741401a2ac2a4e000009e")


def _asm(d, name, source):
    p = os.path.join(d, name + ".mac")
    with open(p, "w", encoding="ascii") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(p), [e.message for e in asm.errors]
    rp = os.path.join(d, name + ".rel")
    with open(rp, "wb") as f:
        f.write(asm.output.get_bytes())
    return rp


def _linker(d, *sources, origin=0x100, allow_overlap=False):
    linker = Linker()
    linker.code_base = origin
    linker.allow_overlap = allow_overlap
    for i, src in enumerate(sources):
        if isinstance(src, bytes):
            p = os.path.join(d, f"M{i}.rel")
            with open(p, "wb") as f:
                f.write(src)
        else:
            p = _asm(d, f"M{i}", src)
        linker.load_rel(p)
    return linker


def _link(d, *sources, origin=0x100, allow_overlap=False):
    linker = _linker(d, *sources, origin=origin, allow_overlap=allow_overlap)
    assert linker.link(), linker.errors
    return linker


def _addr(linker, name):
    """The linked address of global `name'."""
    midx, value, seg, _ = linker.globals[name]
    return linker.relocate_value(linker.modules[midx], value, seg,
                                 linker.global_blocks.get(name))


def _at(linker, addr, n):
    """`n' bytes of the image at `addr'."""
    o = addr - linker.output_base
    return bytes(linker.output[o:o + n])


def _abs(org, n=4, extra=""):
    """A module loading `n' bytes of AAH at `org' in ASEG."""
    return (f"\tASEG\n\tORG {org}\n\tPUBLIC A{org}\nA{org}:\tDB "
            + ",".join(["0AAH"] * n) + f"\n{extra}\tEND\n")


def _cs(k, code=2, data=1):
    """A module with `code' bytes in CSEG (CSk) and `data' in DSEG (DSk)."""
    return (f"\tCSEG\n\tPUBLIC CS{k}\nCS{k}:\tDB "
            + ",".join(str(0x10 * k + i) for i in range(code))
            + f"\n\tDSEG\n\tPUBLIC DS{k}\nDS{k}:\tDB "
            + ",".join(["0D0H"] * data) + "\n\tEND\n")


def test_m80_objects_link_as_l80_links_them():
    """M80's ASEG module at 0100H, then its CSEG module: L80 /P:100 puts
    the CSEG at 0104H, EXT at 0109H.  ul80 put it at 0100H, over the
    JMP."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, M80_ABS, M80_CS)
        assert _at(linker, 0x100, 10) == bytes.fromhex("c30901780000000000c9")


def test_um80_objects_too():
    """The same program assembled by um80."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tASEG\n\tORG 100H\n\tEXTRN EXT\n\tJMP EXT\n"
                          "\tDB 'x'\n\tEND\n",
                       "\tCSEG\n\tPUBLIC EXT\n\tDS 5\nEXT:\tRET\n\tEND\n")
        assert _at(linker, 0x100, 10) == bytes.fromhex("c30901780000000000c9")


def test_absolute_code_above_the_origin_moves_the_next_module_above_it():
    """ASEG at 0200H: L80 puts the next module at 0204H although 0100H to
    01FFH is free.  The data follows the code."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, _abs("200H"), _cs(1), _cs(2))
        assert _addr(linker, "CS1") == 0x204
        assert _addr(linker, "CS2") == 0x206
        assert _addr(linker, "DS1") == 0x208
        assert _at(linker, 0x200, 8) == bytes([0xAA] * 4 + [16, 17, 32, 33])


def test_absolute_code_below_the_origin_moves_nothing():
    """ASEG at 0080H, linked at 0100H: L80 starts at 0100H (0103H without
    /P:)."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, _abs("80H"), _cs(1))
        assert _addr(linker, "CS1") == 0x100
    with tempfile.TemporaryDirectory() as d:
        # -p 200 and absolute code at 0100H: L80 /P:200 starts at 0200H.
        linker = _link(d, _abs("100H"), _cs(1), origin=0x200)
        assert _addr(linker, "CS1") == 0x200


def test_between_modules_only_what_is_loaded_before_counts():
    """CSEG, then ASEG at 0200H, then CSEG: L80 leaves the first module at
    the origin and puts the third above the absolute code."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, _cs(1), _abs("200H"), _cs(2))
        assert _addr(linker, "CS1") == 0x100
        assert _addr(linker, "CS2") == 0x204


def test_the_highest_location_reached_counts():
    """L80 goes by the highest absolute location: bytes loaded past an ORG
    back (0304H, not 0281H), a DS with nothing after it (0310H), an ORG
    at the end (0300H)."""
    cases = [("\tASEG\n\tORG 300H\n\tDB 1,2,3,4\n\tORG 280H\n\tDB 5\n"
              "\tEND\n", 0x304),
             ("\tASEG\n\tORG 300H\n\tDS 10H\n\tEND\n", 0x310),
             ("\tASEG\n\tORG 200H\n\tDB 1,2,3,4\n\tORG 300H\n\tEND\n", 0x300)]
    for src, where in cases:
        with tempfile.TemporaryDirectory() as d:
            linker = _link(d, src, _cs(1))
            assert _addr(linker, "CS1") == where, src


def test_a_modules_own_absolute_code_does_not_move_its_code():
    """CSEG then ASEG at 0200H in one module: its CSEG stays at 0100H
    (L80 allocates it first) and the next module goes above 0204H."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tCSEG\n\tPUBLIC CS0\nCS0:\tDB 1,2\n\tASEG\n"
                          "\tORG 200H\n\tDB 0AAH,0AAH,0AAH,0AAH\n\tEND\n",
                       _cs(1))
        assert _addr(linker, "CS0") == 0x100
        assert _addr(linker, "CS1") == 0x204
        assert _at(linker, 0x100, 2) == b"\x01\x02"


def test_end_is_past_absolute_code_loaded_last():
    """L80 stores the end of absolute code loaded last, above the program,
    at $MEMRY (0304H here, as `L80 /P:100,M0,M1'); __END__ (PL/M's
    .MEMORY) was the end of the relocatable areas, below it."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tPUBLIC $MEMRY\n\tCSEG\n\tDB 1,2\n$MEMRY:\tDW 5555H\n"
                          "\tDSEG\n\tDB 7\n\tEND\n", _abs("300H"))
        assert linker.globals["__END__"][1] == 0x304
        assert _at(linker, 0x102, 3) == bytes([0x04, 0x03, 7])


def test_a_gap_in_absolute_code_does_not_overwrite_earlier_code():
    """ASEG bytes at 0080H and 0300H in a module after a CSEG module at
    0100H: the gap between them is not loaded, and the CSEG was
    overwritten with its zeros."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, _cs(1, code=8), "\tASEG\n\tORG 80H\n\tDB 1\n"
                                           "\tORG 300H\n\tDB 2\n\tEND\n")
        assert _addr(linker, "CS1") == 0x100
        assert _at(linker, 0x100, 8) == bytes(range(16, 24))
        assert _at(linker, 0x80, 1) == b"\x01"
        assert _at(linker, 0x300, 1) == b"\x02"


def _fails(d, *sources, origin=0x100):
    linker = _linker(d, *sources, origin=origin)
    assert not linker.link()
    text = "\n".join(linker.errors)
    assert "overlap" in text, text
    return text


def test_absolute_code_over_an_earlier_modules_code_is_an_error():
    """A CSEG module at 0100H, then ASEG code at 0100H: L80 warns
    "%Overlaying" and writes a mixture of the two."""
    with tempfile.TemporaryDirectory() as d:
        text = _fails(d, _cs(1, code=8, data=4), _abs("100H", 16))
        assert "0100H" in text and "M1" in text and "M0" in text


def test_absolute_code_over_the_modules_own_code_is_an_error():
    """ASEG at 0100H and a CSEG in one module, linked at 0100H (L80's
    default origin is 0103H, which leaves room for such a JMP; ul80's is
    0100H)."""
    with tempfile.TemporaryDirectory() as d:
        text = _fails(d, "\tASEG\n\tORG 100H\n\tJMP GO\n\tCSEG\n"
                         "GO:\tMVI A,1\n\tRET\n\tEND\n")
        assert "0100H-0102H" in text
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, "\tASEG\n\tORG 100H\n\tJMP GO\n\tCSEG\n"
                          "GO:\tMVI A,1\n\tRET\n\tEND\n", origin=0x103)
        assert _at(linker, 0x100, 6) == bytes([0xC3, 0x03, 0x01, 0x3E, 1, 0xC9])


def test_absolute_code_over_another_modules_absolute_code_is_an_error():
    """Two modules loading 0102H and 0103H: L80 warns "%Overlaying"."""
    with tempfile.TemporaryDirectory() as d:
        text = _fails(d, _abs("100H"), _abs("102H"))
        assert "0102H-0103H" in text


def test_absolute_code_over_data_or_common_is_an_error():
    """Data and COMMON follow the code, and absolute code a module loads
    just past it (its own, or a later module's) meets them.  L80, which
    puts a module's data before its code, has the same clash with the
    code (and with /D: set to the end of the code, with the data)."""
    with tempfile.TemporaryDirectory() as d:
        text = _fails(d, _cs(1, code=2, data=2), _abs("102H"))
        assert "the data area of module M0 (0102H-0103H)" in text
    with tempfile.TemporaryDirectory() as d:
        text = _fails(d, "\tCSEG\n\tDB 1,2\n\tCOMMON /C/\n\tDS 8\n"
                         "\tASEG\n\tORG 104H\n\tDB 1\n\tEND\n")
        assert "0104H overlaps COMMON /C/ (0102H-0109H)" in text


def test_command_line_fails_without_writing_the_image():
    """ul80 exits 1 and writes no image when absolute code overlaps; the
    same modules the other way round link."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(um80.__file__)))
    with tempfile.TemporaryDirectory() as d:
        _asm(d, "A", _abs("100H", 16))
        _asm(d, "C", _cs(1, code=8))
        r = subprocess.run([sys.executable, "-m", "um80.ul80", "-o", "x.com",
                            "C.rel", "A.rel"], cwd=d,
                           env=dict(os.environ, PYTHONPATH=root),
                           capture_output=True, text=True, check=False)
        assert r.returncode == 1, r.stdout + r.stderr
        assert "overlap" in r.stderr
        assert not os.path.exists(os.path.join(d, "x.com"))
        r = subprocess.run([sys.executable, "-m", "um80.ul80", "-o", "y.com",
                            "A.rel", "C.rel"], cwd=d,
                           env=dict(os.environ, PYTHONPATH=root),
                           capture_output=True, text=True, check=False)
        assert r.returncode == 0, r.stdout + r.stderr
        with open(os.path.join(d, "y.com"), "rb") as f:
            image = f.read()
        assert image[:24] == bytes([0xAA] * 16 + list(range(16, 24)))


def _overlaid(*sources, n):
    """The first `n' bytes from 0100H of the image --allow-overlap links,
    and the warnings."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, *sources, allow_overlap=True)
        return _at(linker, 0x100, n), "\n".join(linker.warnings)


def test_allow_overlap_takes_the_byte_loaded_last():
    """With --allow-overlap absolute code over other code is a warning, and
    the image has the byte loaded last, as L80 (/D) writes it: a patch
    module's over the code before it (a relocated word keeps the relocated
    byte nothing replaced), and in one module the byte it loaded later,
    absolute or not.  Each checked with M80 and L80 3.44."""
    code = "\tCSEG\n\tLXI H,X\n\tNOP\nX:\tDW X\n\tDB 7\n\tEND\n"
    image, warned = _overlaid(code, "\tASEG\n\tORG 105H\n\tDB 0AAH\n\tEND\n",
                              n=7)
    assert image == bytes([0x21, 0x04, 0x01, 0x00, 0x04, 0xAA, 0x07])
    assert "Warning: Module M1: absolute code at 0105H overlaps the " \
           "program area of module M0 (0100H-0106H)" in warned
    image, _ = _overlaid(code, "\tASEG\n\tORG 101H\n\tDB 0AAH,0BBH\n\tEND\n",
                         n=7)
    assert image == bytes([0x21, 0xAA, 0xBB, 0x00, 0x04, 0x01, 0x07])
    cases = {
        "\tCSEG\n\tDB 1,2,3,4\n\tASEG\n\tORG 101H\n\tDB 9\n\tCSEG\n"
        "\tDB 5\n\tEND\n": [1, 9, 3, 4, 5],
        "\tASEG\n\tORG 101H\n\tDB 9\n\tCSEG\n\tDB 1,2,3,4\n\tEND\n":
            [1, 2, 3, 4],
        "\tCSEG\n\tNOP\nX:\tDW X\n\tDB 7\n\tASEG\n\tORG 102H\n\tDB 9\n"
        "\tEND\n": [0, 1, 9, 7],
        "\tASEG\n\tORG 102H\n\tDB 9\n\tCSEG\n\tNOP\nX:\tDW X\n\tDB 7\n"
        "\tEND\n": [0, 1, 1, 7],
    }
    for source, want in cases.items():
        image, warned = _overlaid(source, n=len(want))
        assert image == bytes(want), source
        assert "its own program area" in warned


def test_allow_overlap_on_the_command_line():
    """Without the switch the link fails and says how to link it anyway;
    with it ul80 warns and writes the image."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(um80.__file__)))
    with tempfile.TemporaryDirectory() as d:
        _asm(d, "C", "\tCSEG\n\tDB 1,2,3,4\n\tEND\n")
        _asm(d, "P", "\tASEG\n\tORG 102H\n\tDB 9\n\tEND\n")

        def run(*args):
            return subprocess.run(
                [sys.executable, "-m", "um80.ul80", *args, "C.rel", "P.rel"],
                cwd=d, env=dict(os.environ, PYTHONPATH=root),
                capture_output=True, text=True, check=False)
        r = run("-o", "x.com")
        assert r.returncode == 1, r.stdout + r.stderr
        assert "overlaps the program area of module C" in r.stderr
        assert "--allow-overlap" in r.stderr
        assert not os.path.exists(os.path.join(d, "x.com"))
        r = run("--allow-overlap", "-o", "y.com")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Warning: Module P: absolute code at 0102H overlaps" in r.stderr
        with open(os.path.join(d, "y.com"), "rb") as f:
            assert f.read(4) == bytes([1, 2, 9, 4])
