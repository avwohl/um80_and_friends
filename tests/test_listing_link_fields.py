"""The listing shows what the .REL carries in a field the linker fills.

A field the linker computes - HIGH/LOW or another link-time expression of a
relocatable or external value - is a placeholder in the .REL, 0 (see
relformat.py), but the listing showed the value computed from segment
offsets: `MVI A,HIGH(BUF)' with BUF at DSEG 0300H listed as 3E 03, a byte
the program never contains.  It lists the placeholder now, and every field
that is not final until the program is linked is marked the way MACRO-80
3.44 marks it: ' program relative, " data relative, ! COMMON, * external.
A relocatable word still shows its offset, as M80's listing does; a byte
or word the linker computes shows 00 and the mark of what it depends on.
"""

import os
import tempfile

from um80.um80 import Assembler

SOURCE = """\
\textrn ext
\tcseg
lab:\tmvi a,high(buf)
\tmvi a,low(ext+3)
\tdw ext
\tdw buf
\tlxi h,lab
\tdb 1,high(lab),2
\tmvi a,3
\tdw c1
\tmvi a,high(c1+2)
\tdw ext-lab
\tdseg
\tds 300h
buf:\tds 1
\tcommon /blk/
c1:\tds 5
\tend
"""


def _listing(source):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w", encoding="ascii") as f:
            f.write(source)
        asm = Assembler()
        asm.generate_listing = True
        assert asm.assemble(p), [e.message for e in asm.errors]
        lst = os.path.join(d, "t.prn")
        asm.write_listing(lst)
        with open(lst, encoding="ascii") as f:
            return f.read().splitlines()


def _bytes_of(lines, text):
    """The byte column of the listing line for source `text'."""
    for line in lines:
        if line.endswith(text):
            return line[13:25].rstrip()
    raise AssertionError(f"no line for {text!r}")


def test_link_time_fields_list_placeholder_and_mark():
    """Each kind of field, as MACRO-80 marks it."""
    lines = _listing(SOURCE)
    assert _bytes_of(lines, "mvi a,high(buf)") == '3E 00"'
    assert _bytes_of(lines, "mvi a,low(ext+3)") == "3E 00*"
    assert _bytes_of(lines, "dw ext") == "00 00*"
    assert _bytes_of(lines, "dw buf") == '00 03"'
    assert _bytes_of(lines, "lxi h,lab") == "21 00 00'"
    assert _bytes_of(lines, "db 1,high(lab),2") == "01 00'02"
    assert _bytes_of(lines, "mvi a,3") == "3E 03"
    assert _bytes_of(lines, "dw c1") == "00 00!"
    assert _bytes_of(lines, "mvi a,high(c1+2)") == "3E 00!"
    assert _bytes_of(lines, "dw ext-lab") == "00 00*"
