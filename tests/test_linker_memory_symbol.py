"""__END__ and the extra memory a .PRL asks MP/M for.

PL/M-80's `AT (.MEMORY)' puts storage at the first free byte after the program.
That address is the LINKER's to know - a label at the end of a module is the
end of that module, which in a multi-module program is somewhere in the middle.
MP/M II's SDIR is eight modules, and its 128-entry hash table landed on top of
another module's strings and cleared them.
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


# A defines HT as an alias for the linker's __END__ and exports it; B imports it.
A = ("\t.z80\n\textrn\t__END__\n\tpublic\tHT\n\tcseg\n"
     "\tld\thl,HT\nHT\tEQU\t__END__\n\tds\t8\n\tend\n")
B = "\t.z80\n\textrn\tHT\n\tcseg\n\tld\tbc,HT\n\tend\n"


def test_a_public_aliased_to_end_is_exported_with_the_program_end():
    """The alias is registered before externals are resolved, but __END__ has
    no value until the segments are placed, so it has to be recomputed."""
    with tempfile.TemporaryDirectory() as d:
        linker = Linker()
        linker.code_base = 0x100
        linker.load_rel(_rel(d, "A", A))
        linker.load_rel(_rel(d, "B", B))
        assert linker.link()
        end = 0x100 + 11 + 3   # A: ld hl,nn (3) + ds 8; then B: ld bc,nn (3)
        assert linker.globals["__END__"][1] == end, linker.globals["__END__"]
        assert linker.globals["HT"][1] == end, linker.globals["HT"]
        out = linker.output
        assert (out[1] | (out[2] << 8)) == end, "reference inside A"
        assert (out[12] | (out[13] << 8)) == end, "reference from B"


def test_prl_extra_reserves_memory_past_the_image():
    """A program that places storage at .MEMORY needs memory beyond its image,
    and nothing in the object files says how much. DRI named the figure at
    build time - `genmod pip.hex pip.prl $1000' - and so does ul80."""
    with tempfile.TemporaryDirectory() as d:
        r = _rel(d, "P", "\t.z80\n\tcseg\n\tld\ta,1\n\tret\n\tend\n")
        for extra in (0, 0x1000):
            linker = Linker()
            linker.code_base = 0x100
            linker.prl_extra = extra
            linker.load_rel(r)
            assert linker.link()
            out = os.path.join(d, "OUT.PRL")
            linker.save_prl(out)
            with open(out, "rb") as f:
                header = f.read(8)
            assert (header[4] | (header[5] << 8)) == extra, header[:8].hex()
