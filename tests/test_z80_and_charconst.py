"""Z80 encoding and character-constant fixes, validated against real MACRO-80 3.44.

- LD A,I / LD A,R must encode ED 57 / ED 5F (were wrongly emitted as LD A,0).
- A two-character constant 'AB' has the first char in the HIGH byte (0x4142),
  so DW 'AB' emits little-endian bytes 42 41 and DB 'AB' AND 0FFH emits 42.
"""

import os
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _image(source, code_base=0x0100):
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "test.mac")
        with open(src_path, "w") as f:
            f.write(source)
        asm = Assembler()
        assert asm.assemble(src_path), f"Assembly failed: {asm.errors}"
        rel_path = os.path.join(tmpdir, "test.rel")
        with open(rel_path, "wb") as f:
            f.write(asm.output.get_bytes())
        linker = Linker()
        linker.code_base = code_base
        linker.load_rel(rel_path)
        assert linker.link(), f"Link failed: {linker.errors}"
        return bytes(linker.output)


def test_ld_a_i_and_ld_a_r():
    src = "\t.Z80\n\tASEG\n\tORG 100H\n\tLD A,I\n\tLD A,R\n\tEND\n"
    out = _image(src)
    assert out[0:4] == bytes([0xED, 0x57, 0xED, 0x5F]), out[0:4].hex()


def test_ld_i_a_and_ld_r_a_unchanged():
    src = "\t.Z80\n\tASEG\n\tORG 100H\n\tLD I,A\n\tLD R,A\n\tEND\n"
    out = _image(src)
    assert out[0:4] == bytes([0xED, 0x47, 0xED, 0x4F]), out[0:4].hex()


def test_two_char_constant_byte_order_dw():
    # 'AB' = 0x4142; DW stores little-endian -> bytes 42 41 (matches real M80).
    src = "\tASEG\n\tORG 100H\n\tDW 'AB'\n\tEND\n"
    assert _image(src)[0:2] == bytes([0x42, 0x41])


def test_two_char_constant_low_byte():
    # 'AB' AND 0FFH = 0x42 ('B'), the low byte (matches real M80).
    src = "\tASEG\n\tORG 100H\n\tDB 'AB' AND 0FFH\n\tEND\n"
    assert _image(src)[0:1] == bytes([0x42])


def test_single_char_constant_unchanged():
    src = "\tASEG\n\tORG 100H\n\tDB 'A'\n\tEND\n"
    assert _image(src)[0:1] == bytes([0x41])
