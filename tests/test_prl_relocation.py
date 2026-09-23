"""MP/M page-relocatable output: origins and page-zero relocation.

MP/M loads the two flavours of the PRL container at different places but
relocates both the same way - CLI.ASM's relocate() adds the memory segment's
base *page* to every byte the bitmap marks.

  * A transient .PRL is loaded at segment_bottom+0100H ("base = segment$bottom
    + 0100H" in CLI.ASM), so the extra page has to come from the link: the
    image is linked at 0100H, exactly like a .COM.  Linking it at 0 puts every
    relocated address one page below the code.
  * A .SPR/.RSP is loaded at the segment base itself, so it is linked at 0.

Page zero belongs to the process's memory segment, not to absolute address 0,
so a reference to the BDOS entry, the default FCB or the DMA buffer has to be
relocated too.  DRI got this from linking twice against X0100.ASM / X0200.ASM,
whose `offset' equate shifted those addresses, and diffing the two images with
GENMOD; here the linker marks any resolved reference to an absolute symbol in
page zero.
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


PAGE_ZERO = "BDOS\tEQU 5\nFCB\tEQU 5CH\n\tPUBLIC BDOS,FCB\n\tEND\n"

# LXI H,MSG / CALL BDOS / LXI D,FCB / RET, then the message.
PROG = ("\tEXTRN BDOS\n\tEXTRN FCB\n\tCSEG\n"
        "ST:\tLXI H,MSG\n\tCALL BDOS\n\tLXI D,FCB\n\tRET\n"
        "MSG:\tDB 'HI$'\n\tEND\n")


def _link(d, origin, page_zero_relative):
    linker = Linker()
    linker.code_base = origin
    linker.page_zero_relative = page_zero_relative
    linker.load_rel(_rel(d, "PROG", PROG))
    linker.load_rel(_rel(d, "PZ", PAGE_ZERO))
    assert linker.link()
    return linker


def test_transient_prl_is_linked_at_0100h():
    """A .PRL image is ORG 100H, so MSG resolves above page zero."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, 0x100, True)
        assert linker.output_base == 0x100
        # LXI H,MSG - MSG is 10 bytes into the CSEG.
        msg = linker.output[1] | (linker.output[2] << 8)
        assert msg == 0x100 + 10, hex(msg)


def test_spr_is_linked_at_zero():
    """A .SPR/.RSP image is ORG 0: the loader supplies the whole address."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, 0x0, True)
        assert linker.output_base == 0
        msg = linker.output[1] | (linker.output[2] << 8)
        assert msg == 10, hex(msg)


def test_page_zero_references_are_relocated():
    """BDOS (0005H) and FCB (005CH) reach the relocation bitmap."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, 0x100, True)
        marked = set(linker.external_relocations)
        # CALL BDOS at offset 3; LXI D,FCB at offset 6. The operand is at +1.
        assert linker.output[4] == 0x05 and linker.output[5] == 0x00
        assert linker.output[7] == 0x5C and linker.output[8] == 0x00
        assert 4 in marked, sorted(marked)
        assert 7 in marked, sorted(marked)


def test_page_zero_is_not_relocated_for_com_output():
    """A .COM keeps absolute page-zero addresses absolute."""
    with tempfile.TemporaryDirectory() as d:
        linker = _link(d, 0x100, False)
        marked = set(linker.external_relocations)
        assert 4 not in marked and 7 not in marked, sorted(marked)


def test_absolute_symbols_above_page_zero_stay_absolute():
    """Only page zero moves with the segment; a real absolute does not."""
    with tempfile.TemporaryDirectory() as d:
        linker = Linker()
        linker.code_base = 0x100
        linker.page_zero_relative = True
        linker.load_rel(_rel(d, "P", "\tEXTRN PORT\n\tCSEG\n\tLXI H,PORT\n\tRET\n\tEND\n"))
        linker.load_rel(_rel(d, "A", "PORT\tEQU 8000H\n\tPUBLIC PORT\n\tEND\n"))
        assert linker.link()
        assert linker.output[1] == 0x00 and linker.output[2] == 0x80
        # external_relocations records the operand, not its high byte.
        assert 1 not in set(linker.external_relocations)


def _run_ul80(d, args):
    """Drive the command line so the *default* origin is what is tested."""
    import subprocess
    import sys
    return subprocess.run([sys.executable, "-m", "um80.ul80"] + args,
                          cwd=d, capture_output=True, text=True)


def test_cli_defaults_prl_to_0100h_and_spr_to_zero():
    with tempfile.TemporaryDirectory() as d:
        _rel(d, "PROG", PROG)
        _rel(d, "PZ", PAGE_ZERO)
        for flag, want in (("--prl", 0x100 + 10), ("--spr", 10)):
            out = os.path.join(d, "OUT")
            r = _run_ul80(d, [flag, "-o", out, "PROG.rel", "PZ.rel"])
            assert r.returncode == 0, r.stderr
            with open(out, "rb") as f:
                image = f.read()
            code = image[256:]
            msg = code[1] | (code[2] << 8)
            assert msg == want, f"{flag}: {hex(msg)} != {hex(want)}"


def test_cli_prl_marks_page_zero_in_the_bitmap():
    with tempfile.TemporaryDirectory() as d:
        _rel(d, "PROG", PROG)
        _rel(d, "PZ", PAGE_ZERO)
        out = os.path.join(d, "OUT.PRL")
        r = _run_ul80(d, ["--prl", "-o", out, "PROG.rel", "PZ.rel"])
        assert r.returncode == 0, r.stderr
        with open(out, "rb") as f:
            image = f.read()
        n = image[1] | (image[2] << 8)
        bitmap = image[256 + n:]
        marked = {i for i in range(n) if bitmap[i >> 3] & (0x80 >> (i & 7))}
        # CALL BDOS's operand sits at 4-5 and LXI D,FCB's at 7-8; the bitmap
        # marks the high byte of each, which is what the loader offsets.
        assert {5, 8} <= marked, sorted(marked)
