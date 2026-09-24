"""LINK-80 extension link items: reading them, and linking what M80 writes.

Special link item 4 is a B-field-only item whose first byte names a kind of
extension.  MACRO-80 3.44 uses three kinds - 'A' operator, 'B' external
symbol, 'C' value - to hand LINK-80 3.44 a postfix expression it cannot
evaluate itself (HIGH/LOW of a relocatable value, any relocatable value in a
one-byte field), ending in a store operator placed just before the
placeholder byte(s) of the field; see um80/relformat.py.

The reader returned item 4 as ('UNKNOWN_SPECIAL', 4) without consuming its
B-field, so the rest of the module was read out of step: ulib80 indexed four
garbage "public symbols" from the M80 module below, and ul80 could not link
it.  The M80_* objects are the genuine article, assembled by MACRO-80 3.44
under a CP/M emulator.  LINK-80 3.44 lays segments out differently (each
module's data before its code) but, for its own layout, stores the same
thing in every field: the byte or word of the linked address.
"""

import os
import tempfile

from um80.relformat import (
    RELReader, RELWriter, ADDR_ABSOLUTE, ADDR_DATA_REL,
    EXT_OP_HIGH, EXT_OP_LOW, EXT_OP_PLUS, EXT_OP_STORE_BYTE,
)
from um80.ul80 import Linker
from um80.ulib80 import Library


def _addr(linker, name):
    mod_idx, value, seg, _ = linker.globals[name]
    return linker.relocate_value(linker.modules[mod_idx], value, seg)


def _image(linker, addr, n):
    off = addr - linker.output_base
    return bytes(linker.output[off:off + n])


def test_reader_round_trip_of_extension_items():
    """Every kind of item 4 reads back, and so does what follows it."""
    w = RELWriter()
    w.write_program_name("M")
    w.write_ext_value(ADDR_DATA_REL, 0x1234)
    w.write_ext_value(ADDR_ABSOLUTE, 0x0080)
    w.write_ext_operator(EXT_OP_PLUS)
    w.write_ext_operator(EXT_OP_HIGH)
    w.write_ext_symbol("SHORT")
    w.write_ext_symbol("SEVENCH")             # 'B' + 7 = the full 8 bytes
    w.write_ext_symbol("AVERYLONGNAME")       # extended B-field
    w.write_ext_operator(EXT_OP_LOW)
    w.write_ext_value(ADDR_ABSOLUTE, 0x7A61)  # bytes that look like 'a','z'
    w.write_ext_operator(EXT_OP_STORE_BYTE)
    w.write_extension([0x35, 0x02])           # COBOL overlay sentinel
    w.write_absolute_byte(0xAA)
    w.write_define_entry_point(ADDR_ABSOLUTE, 0x55AA, "AFTER")
    w.write_end_program()
    w.write_end_file()
    items = RELReader(w.get_bytes()).read_all()
    assert items == [
        ('PROGRAM_NAME', 'M'),
        ('EXT_VALUE', (ADDR_DATA_REL, 0x1234)),
        ('EXT_VALUE', (ADDR_ABSOLUTE, 0x0080)),
        ('EXT_OPERATOR', EXT_OP_PLUS),
        ('EXT_OPERATOR', EXT_OP_HIGH),
        ('EXT_SYMBOL', 'SHORT'),
        ('EXT_SYMBOL', 'SEVENCH'),
        ('EXT_SYMBOL', 'AVERYLONGNAME'),
        ('EXT_OPERATOR', EXT_OP_LOW),
        ('EXT_VALUE', (ADDR_ABSOLUTE, 0x7A61)),
        ('EXT_OPERATOR', EXT_OP_STORE_BYTE),
        ('EXTENSION', 0x35, b'\x02'),
        ('ABSOLUTE_BYTE', 0xAA),
        ('DEFINE_ENTRY', (ADDR_ABSOLUTE, 0x55AA), 'AFTER'),
        ('END_PROGRAM',),
        ('END_FILE',),
    ]


# Assembled by the real MACRO-80 3.44 under a CP/M emulator:
#   M0:     cseg / public ext / db 1,2,3,4,5 / ext: db 0 / dseg / db 7,7,7
#   M1:     cseg / public start / extrn ext
#           start: mvi a,low(buf+128) / mvi a,high(buf+128)
#                  db low(lab) / db high(lab) / dw buf / mvi a,buf / db lab
#                  mvi a,low(ext+5) / mvi a,high(ext-5) / mvi a,ext
#           lab:   nop / dseg / ds 3 / buf: ds 256
M80_M0 = bytes.fromhex(
    "84950c2034558549401804d418025a0000010100c0805004b800000e0703c741401a"
    "2ac2a4e000009e")
M80_M1 = bytes.fromhex(
    "84950c6055354415254940180cd448025a00003e8910c080c02244300800088904"
    "222241048890404003e8910c080c0224430080008890422224103889040401122180"
    "888044482091120808022443011100889040e22410100603001f4488604060111208"
    "080224430111008890404003e89109156152244300050088904222241048890404003"
    "e891091561522443000500889041e2241038890404003e89109156152224101000025"
    "c00012e0300970180c600001a2ac2a4740002a9aa20a92a4e000009e")


def test_links_macro80_output():
    """ul80 reads what M80 writes and computes the same bytes L80 does."""
    linker = Linker()
    linker.code_base = 0x100
    linker.load_rel_data("M0", M80_M0)
    linker.load_rel_data("M1", M80_M1)
    assert linker.link(), linker.errors
    ext, start = _addr(linker, "EXT"), _addr(linker, "START")
    buf = linker.modules[1].data_base + 3
    lab = start + 0x11
    assert _image(linker, start, 18) == bytes([
        0x3E, (buf + 128) & 0xFF, 0x3E, (buf + 128) >> 8,
        lab & 0xFF, lab >> 8, buf & 0xFF, buf >> 8,
        0x3E, buf & 0xFF, lab & 0xFF,
        0x3E, (ext + 5) & 0xFF, 0x3E, (ext - 5) >> 8, 0x3E, ext & 0xFF, 0x00])


def test_library_index_survives_extension_items():
    """ulib80 indexes the module's publics and nothing else.

    A reader that did not consume item 4's B-field lost its place in the bit
    stream and indexed whatever the following bits spelled as "symbols".
    """
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "M1.REL")
        with open(path, "wb") as f:
            f.write(M80_M1)
        lib = Library()
        lib.add_rel_file(path)
        assert lib.modules[0].publics == ["START"], lib.modules[0].publics
