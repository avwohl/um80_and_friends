"""Expression syntax MACRO-80 accepts, and values it computes, that um80 did not.

Every value below was checked against the real MACRO-80 3.44 under cpmemu
(ASEG, X EQU 1234H):

- a word operator next to a tab or a parenthesis: HIGH<TAB>X, X<TAB>AND<TAB>0FH,
  NOT(X), X AND(0FH), (X)SHR(4), LOW(X)OR 1, 1 EQ(1), X MOD(3) - all
  "Cannot parse expression";
- OR and XOR are one precedence level, left to right: 1 OR 1 XOR 1 is 0 (um80
  evaluated 1 OR (1 XOR 1) = 1); DRI's MAC agrees;
- '''' is the one character 27H (it was 2727H);
- DB 'A'+'B' is the byte 83H, not the five bytes 41 27 2B 27 42;
- X## of a local alias of an external, or of a link-time EQU, stands for
  what X does (it gave the alias's offset as an absolute word);
- EXT EQ EXT compares two offsets from one external, which M80 accepts.
"""

import os
import tempfile

import pytest

from um80.relformat import RELReader
from um80.um80 import Assembler
from um80.ul80 import Linker


def _asm(source):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler()
        ok = asm.assemble(p)
        rel = asm.output.get_bytes() if ok else None
    return ok, asm, rel


def _bytes(rel):
    reader = RELReader(rel)
    out = []
    while True:
        item = reader.read_item()
        if item is None or item[0] in ('END_PROGRAM', 'END_FILE'):
            return out
        if item[0] == 'ABSOLUTE_BYTE':
            out.append(item[1])


@pytest.mark.parametrize("line,want", [
    ("DB HIGH\tX", [0x12]),
    ("DB LOW\tX", [0x34]),
    ("DW NOT\tX", [0xCB, 0xED]),
    ("DW X\tAND\t0FH", [0x04, 0x00]),
    ("DW NOT(X)", [0xCB, 0xED]),
    ("DW X AND(0FH)", [0x04, 0x00]),
    ("DW (X)SHR(4)", [0x23, 0x01]),
    ("DB LOW(X)OR 1", [0x35]),
    ("DB 1 EQ(1)", [0xFF]),
    ("DW X MOD(3)", [0x01, 0x00]),
    ("DB NOT(5)", [0xFA]),
    ("DW 1 OR 1 XOR 1", [0x00, 0x00]),
    ("DW 1 XOR 1 OR 1", [0x01, 0x00]),
    ("DW 3 AND 1 OR 4", [0x05, 0x00]),
    ("DW 4 OR 3 AND 1", [0x05, 0x00]),
    ("DW ''''", [0x27, 0x00]),
    ("DW 'A'+''''", [0x68, 0x00]),
    ("DB 'A'+'B'", [0x83]),
    ("DB 'X'-'A'", [0x17]),
    ("DB 'A','B'+1", [0x41, 0x43]),
    ("DB 'it''s'", [0x69, 0x74, 0x27, 0x73]),
    ("DB 'A' OR 80H", [0xC1]),
    ("DW HIGH (X)+1", [0x13, 0x00]),
    ("DW X SHR 4 SHL 4", [0x30, 0x12]),
])
def test_value_matches_m80(line, want):
    ok, asm, rel = _asm(f"\tASEG\n\tORG 100H\nX\tEQU 1234H\n\t{line}\n\tEND\n")
    assert ok, [e.message for e in asm.errors]
    assert _bytes(rel) == want


@pytest.mark.parametrize("line", [
    "DW MY_OR", "DW XOR_1", "DW ANDY", "DW NOTE", "DW HIGHEST", "DW LOW.1",
])
def test_names_that_contain_an_operator_word(line):
    names = "MY_OR\tEQU 1\nXOR_1\tEQU 2\nANDY\tEQU 3\nNOTE\tEQU 4\n" \
            "HIGHEST\tEQU 5\nLOW.1\tEQU 6\n"
    ok, asm, rel = _asm(f"\tASEG\n\tORG 100H\n{names}\t{line}\n\tEND\n")
    assert ok, [e.message for e in asm.errors]
    assert _bytes(rel)[0] in range(1, 7)


def test_double_hash_of_an_alias_or_link_time_equ():
    src = ("\tEXTRN EXA\n\tCSEG\nX\tEQU EXA+2\nHB\tEQU HIGH BUF\n"
           "\tDW X##\n\tDW X\n\tMVI A,HB##\n\tMVI A,HB\n"
           "\tDSEG\n\tDS 305H\nBUF:\tDS 1\n\tEND\n")
    other = "\tPUBLIC EXA\n\tCSEG\n\tDS 3\nEXA:\tNOP\n\tEND\n"
    with tempfile.TemporaryDirectory() as d:
        linker = Linker()
        linker.code_base = 0x100
        for i, text in enumerate((src, other)):
            ok, asm, rel = _asm(text)
            assert ok, [e.message for e in asm.errors]
            p = os.path.join(d, f"m{i}.rel")
            with open(p, "wb") as f:
                f.write(rel)
            linker.load_rel(p)
        assert linker.link(), linker.errors
    exa = 0x100 + 8 + 3
    buf = 0x100 + 8 + 4 + 0x305
    out = list(linker.output[:8])
    assert out[0:2] == out[2:4] == [(exa + 2) & 0xFF, (exa + 2) >> 8]
    assert out[4:6] == out[6:8] == [0x3E, buf >> 8]


def test_comparing_offsets_of_one_external():
    ok, asm, rel = _asm("\tEXTRN EXT\n\tCSEG\n\tDW EXT EQ EXT\n"
                        "\tDW EXT+1 GT EXT\n\tEND\n")
    assert ok, [e.message for e in asm.errors]
    assert _bytes(rel) == [0xFF, 0xFF, 0xFF, 0xFF]


def test_comparing_two_externals_is_still_an_error():
    """M80 compares their assembly-time values (both 0) and links
    `EXT NE EXT2' to 0 even when they differ; um80 refuses."""
    ok, asm, _ = _asm("\tEXTRN EXT,EXT2\n\tCSEG\n\tDW EXT NE EXT2\n\tEND\n")
    assert not ok
