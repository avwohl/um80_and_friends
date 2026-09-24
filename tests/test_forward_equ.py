"""A symbol used before the EQU that defines it gets the EQU's final value.

    MVI  A,X
X   EQU  FWD+1
FWD EQU  5

assembled to MVI A,01H, with no error.  Pass 1 read the EQU while FWD was
still undefined, so X became 0+1, and pass 2 - which reads X at the MVI,
above the line that recomputes it - used that 1.  The same froze a forward
`X EQU HIGH BUF' as the absolute byte 0, and made `100/COUNT' a division by
zero.  MACRO-80 3.44 flags such uses 'U'; um80 now repeats pass 1 until the
symbol table stops changing, reading a forward reference as its value at
the end of the previous time through, so X settles on 6.  A definition that
never settles (a symbol defined in terms of itself) is an error, and a
value that differs between the passes after it was used is a phase error.
"""

import os
import tempfile

from um80.relformat import RELReader
from um80.um80 import Assembler
from um80.ul80 import Linker


def _asm(source, **kw):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.mac")
        with open(p, "w") as f:
            f.write(source)
        asm = Assembler(**kw)
        ok = asm.assemble(p)
        rel = asm.output.get_bytes() if ok else None
    return ok, asm, rel


def _bytes(rel):
    """Absolute bytes of a REL, in order (ASEG/CSEG code)."""
    reader = RELReader(rel)
    out = []
    while True:
        item = reader.read_item()
        if item is None or item[0] in ('END_PROGRAM', 'END_FILE'):
            return out
        if item[0] == 'ABSOLUTE_BYTE':
            out.append(item[1])


def _link(*sources):
    with tempfile.TemporaryDirectory() as d:
        linker = Linker()
        linker.code_base = 0x100
        for i, src in enumerate(sources):
            ok, asm, rel = _asm(src)
            assert ok, [e.message for e in asm.errors]
            p = os.path.join(d, f"m{i}.rel")
            with open(p, "wb") as f:
                f.write(rel)
            linker.load_rel(p)
        assert linker.link(), linker.errors
    return linker


def _errors(asm):
    return [e.message for e in asm.errors]


def test_forward_equ_of_a_forward_equ():
    ok, asm, rel = _asm("\tASEG\n\tORG 100H\n\tMVI A,X\nX\tEQU FWD+1\n"
                        "FWD\tEQU 5\n\tMVI A,X\n\tEND\n")
    assert ok, _errors(asm)
    assert _bytes(rel) == [0x3E, 0x06, 0x3E, 0x06]


def test_forward_chain_used_in_a_word_and_a_byte():
    ok, asm, rel = _asm("\tASEG\n\tORG 100H\n\tDW BUFSIZ\n\tMVI A,BUFSIZ\n"
                        "BUFSIZ\tEQU RECSIZ*2\nRECSIZ\tEQU 40H\n"
                        "\tDW BUFSIZ\n\tEND\n")
    assert ok, _errors(asm)
    assert _bytes(rel) == [0x80, 0x00, 0x3E, 0x80, 0x80, 0x00]


def test_deep_forward_chain_settles():
    lines = ["\tASEG", "\tORG 100H", "\tDW S0"]
    lines += [f"S{i}\tEQU S{i + 1}+1" for i in range(25)]
    lines += ["S25\tEQU 1000H", "\tDS S0-1000H", "LL:\tDW LL", "\tEND"]
    ok, asm, rel = _asm("\n".join(lines) + "\n")
    assert ok, _errors(asm)
    assert _bytes(rel) == [0x19, 0x10, 0x1B, 0x01]  # LL = 100H+2+19H


def test_forward_size_moves_the_labels_after_it():
    """DS of a size defined further down: the labels after it are right in
    pass 1 too, so a forward jump over it lands on them."""
    ok, asm, rel = _asm("\tASEG\n\tORG 100H\n\tJMP LAB\n\tDS SIZE\n"
                        "LAB:\tNOP\nSIZE\tEQU 10H\n\tEND\n")
    assert ok, _errors(asm)
    assert _bytes(rel)[:3] == [0xC3, 0x13, 0x01]


def test_forward_link_time_equ():
    """`X EQU HIGH BUF' below its uses: the uses are link-time expressions
    too, not the absolute 0 pass 1 first computed for X."""
    src = ("\tCSEG\n\tMVI A,X\n\tLXI H,X\n\tLXI D,Y\nX\tEQU HIGH BUF\n"
           "Y\tEQU BUF+4\n\tDSEG\n\tDS 10H\nBUF:\tDS 1\n\tEND\n")
    linker = _link(src)
    buf = 0x100 + 8 + 0x10
    assert list(linker.output[:8]) == [
        0x3E, buf >> 8, 0x21, buf >> 8, 0x00, 0x11,
        (buf + 4) & 0xFF, (buf + 4) >> 8]


def test_forward_alias_of_an_external():
    src = "\tEXTRN EXA\n\tCSEG\n\tLXI H,FQA\nFQA\tEQU EXA+4\n\tEND\n"
    other = "\tPUBLIC EXA\n\tCSEG\n\tDS 20H\nEXA:\tNOP\n\tEND\n"
    linker = _link(src, other)
    exa = 0x100 + 3 + 0x20
    assert list(linker.output[:3]) == [0x21, (exa + 4) & 0xFF, (exa + 4) >> 8]


def test_forward_set_reads_the_final_value_of_the_pass_before():
    """A SET symbol read above any SET of it reads its last value, as in
    M80 (verified: `DB Y / Y SET Z / Z SET 3' gives 03)."""
    ok, asm, rel = _asm("\tASEG\n\tORG 100H\nY\tSET Z\n\tDB Y\nZ\tSET 3\n"
                        "\tDB Y\n\tEND\n")
    assert ok, _errors(asm)
    assert _bytes(rel) == [3, 3]


def test_set_of_itself_is_positional():
    """`CN SET CN+1' reads the CN of the line before; one never SET before
    still reads its pass-1 value above the first SET (M80 and 0.3.48)."""
    ok, asm, rel = _asm("\tASEG\n\tORG 100H\nCN\tSET 0\n\tDB CN\n"
                        "CN\tSET CN+1\n\tDB CN\nCN\tSET CN+1\n\tDB CN\n\tEND\n")
    assert ok, _errors(asm)
    assert _bytes(rel) == [0, 1, 2]


def test_circular_equs_are_an_error():
    ok, asm, _ = _asm("\tASEG\n\tORG 100H\n\tDB X\nX\tEQU Y+1\n"
                      "Y\tEQU X+1\n\tEND\n")
    assert not ok
    assert any("Cannot resolve the value of 'X'" in e for e in _errors(asm))


def test_equ_of_itself_is_an_error():
    ok, asm, _ = _asm("\tASEG\n\tORG 100H\n\tDB X\nX\tEQU X+1\n\tEND\n")
    assert not ok
    assert any("'X'" in e for e in _errors(asm))


def test_value_that_differs_between_passes_after_use_is_a_phase_error():
    """IFDEF of a symbol defined later is false in pass 1 and true in pass
    2; LAB moved after JMP LAB was assembled with its pass-1 address."""
    ok, asm, _ = _asm("\tASEG\n\tORG 100H\n\tJMP LAB\n\tIFDEF LATER\n"
                      "\tDS 10\n\tENDIF\nLAB:\tNOP\nLATER\tEQU 1\n\tEND\n")
    assert not ok
    assert any("Phase error: 'LAB'" in e for e in _errors(asm))


def test_divisor_defined_later_is_not_a_division_by_zero():
    ok, asm, rel = _asm("\tASEG\n\tORG 100H\n\tMVI A,100/COUNT\n"
                        "\tDB 7 MOD COUNT\nCOUNT\tEQU 5\n\tEND\n")
    assert ok, _errors(asm)
    assert _bytes(rel) == [0x3E, 20, 2]


def test_constant_zero_divisor_is_still_an_error():
    ok, asm, _ = _asm("\tASEG\n\tORG 100H\n\tDB 1/0\n\tEND\n")
    assert not ok
    assert "Division by zero" in _errors(asm)


def test_mod_by_an_external_is_computed_by_the_linker():
    """M80 writes C(1000H) B(EXT) A(MOD); L80 links it (FD for EXT=0225H)."""
    src = "\tEXTRN EXT\n\tCSEG\n\tDW 1000H MOD EXT\n\tEND\n"
    other = "\tPUBLIC EXT\n\tCSEG\n\tDS 20H\nEXT:\tNOP\n\tEND\n"
    linker = _link(src, other)
    ext = 0x100 + 2 + 0x20
    value = 0x1000 % ext
    assert list(linker.output[:2]) == [value & 0xFF, value >> 8]


def test_export_all_does_not_announce_a_forward_link_time_equ():
    """-g wrote ENTRY_SYMBOL HB with no DEFINE_ENTRY for it: pass 1 saw
    `HB EQU HIGH FWD' as absolute and pass 2 as a link-time expression."""
    ok, asm, rel = _asm("\tCSEG\n\tMVI A,HB\nHB\tEQU HIGH FWD\n\tNOP\n"
                        "FWD:\tNOP\n\tEND\n", export_all_symbols=True)
    assert ok, _errors(asm)
    reader = RELReader(rel)
    names = []
    while True:
        item = reader.read_item()
        if item is None or item[0] == 'END_FILE':
            break
        if item[0] == 'ENTRY_SYMBOL':
            names.append(item[1])
    assert 'HB' not in names


def test_long_reversed_chain_settles():
    """Each repeat of pass 1 settles one more forward reference, so a chain
    of N EQUs each defined in terms of the next needs N repeats.  Pass 1
    stopped after 64 and reported the 65th and later as "defined in terms
    of itself"; the limit now grows with the chain."""
    n = 100
    lines = ["\tASEG", "\tORG 100H", "\tDW S0"]
    lines += [f"S{i}\tEQU S{i + 1}+1" for i in range(n)]
    lines += [f"S{n}\tEQU 1000H", "\tDW S0", "\tEND"]
    ok, asm, rel = _asm("\n".join(lines) + "\n")
    assert ok, _errors(asm)[:3]
    value = 0x1000 + n
    assert _bytes(rel) == [value & 0xFF, value >> 8] * 2


def _circular(source):
    ok, asm, _ = _asm(source)
    assert not ok, "a circular definition assembled"
    return " ".join(_errors(asm))


def test_circular_equs_with_a_fixed_point_are_an_error():
    """`X EQU Y / Y EQU X' settled on X = Y = 0 and assembled silently, as
    did any pair whose value satisfies both (AA = BB+1, BB = AA-1)."""
    for src in ("\tASEG\n\tORG 100H\n\tDB X\nX\tEQU Y\nY\tEQU X\n\tEND\n",
                "\tASEG\n\tORG 100H\nX\tEQU Y\nY\tEQU X\n\tDB X\n\tEND\n",
                "\tCSEG\nAA\tEQU BB+1\nBB\tEQU AA-1\n\tDW AA,BB\n\tEND\n",
                "\tCSEG\n\tDW X\nX\tEQU X\n\tEND\n"):
        text = _circular(src)
        assert "defined in terms of itself" in text, (src, text)
    text = _circular("\tASEG\n\tORG 100H\nP\tEQU Q\nQ\tEQU R\nR\tEQU P\n"
                     "\tDB P\n\tEND\n")
    assert "P EQU Q, Q EQU R, R EQU P" in text


def test_circular_equs_without_a_fixed_point_name_the_cycle():
    """The error names the EQUs of the cycle, operands and all."""
    text = _circular("\tASEG\n\tORG 100H\n\tDB X\nX\tEQU Y+1\n"
                     "Y\tEQU X+1\n\tEND\n")
    assert "X EQU Y+1, Y EQU X+1" in text


def test_an_equ_restated_from_itself_is_not_circular():
    """Redefined with the value it already has, through another symbol."""
    ok, asm, rel = _asm("\tASEG\n\tORG 100H\nX\tEQU 5\nY\tEQU X\nX\tEQU Y\n"
                        "\tDB X,Y\n\tEND\n")
    assert ok, _errors(asm)
    assert _bytes(rel) == [5, 5]


def test_forward_chain_through_set_symbols_settles():
    """SET symbols were left out of the chain depth: a chain of forward
    references that alternates EQU and SET stopped after 64 repeats with
    "still changing ... through the address of a label", although the
    same chain of EQUs alone assembles, as does this one in reverse."""
    n = 70
    lines = ["\tASEG", "\tORG 100H", "\tDW A0"]
    lines += [f"A{i}\t{'SET' if i % 2 else 'EQU'} A{i + 1}+1"
              for i in range(n - 1)]
    lines += [f"A{n - 1}\tSET 5", "\tDW A0", "\tEND"]
    ok, asm, rel = _asm("\n".join(lines) + "\n")
    assert ok, _errors(asm)[:3]
    value = 5 + n - 1
    assert _bytes(rel) == [value & 0xFF, value >> 8] * 2


def test_circular_through_a_set_is_an_error():
    """A cycle through a SET symbol settled silently: `X SET Y+1 /
    Y EQU X-1' gave X = 1, Y = 0."""
    text = _circular("\tASEG\n\tORG 100H\n\tDW X,Y\nX\tSET Y+1\n"
                     "Y\tEQU X-1\n\tEND\n")
    assert "(X SET Y+1, Y EQU X-1)" in text
    text = _circular("\tASEG\n\tORG 100H\n\tDW X\nX\tEQU Y\nY\tSET X\n"
                     "\tDW Y\n\tEND\n")
    assert "(X EQU Y, Y SET X)" in text
    text = _circular("\tASEG\n\tORG 100H\n\tDB AA\nAA\tEQU X+1\nX\tSET 3\n"
                     "X\tSET AA\n\tEND\n")
    assert "(AA EQU X+1, X SET AA)" in text


def test_an_earlier_set_is_not_in_the_cycle():
    """A forward reference reads a SET symbol's last definition, so a use
    of the reader by an earlier SET of it is no cycle: AA is 7."""
    ok, asm, rel = _asm("\tASEG\n\tORG 100H\n\tDB AA\nAA\tEQU X\n"
                        "X\tSET AA\nX\tSET 7\n\tDB AA,X\n\tEND\n")
    assert ok, _errors(asm)
    assert _bytes(rel) == [7, 7, 7]
    ok, asm, rel = _asm("\tASEG\n\tORG 100H\n\tDB TOTAL\nTOTAL\tEQU CNT\n"
                        "CNT\tSET 0\n\tREPT 3\nCNT\tSET CNT+1\n\tENDM\n"
                        "\tDB TOTAL,CNT\n\tEND\n")
    assert ok, _errors(asm)
    assert _bytes(rel) == [3, 3, 3]


def test_long_forward_chain_is_settled_in_a_few_readings():
    """Settling one link per reading of the source made a chain of N
    forward EQUs cost N readings: 500 deep took 92 s.  Each reading now
    evaluates the EQUs and SETs again in the order they read each other,
    and the next one checks that guess."""
    n = 500
    lines = ["\tASEG", "\tORG 100H", "\tDW A0"]
    lines += [f"A{i}\t{'SET' if i % 7 == 6 else 'EQU'} A{i + 1}+1"
              for i in range(n)]
    lines += [f"A{n}\tEQU 5", "\tDW A0", "\tEND"]
    ok, asm, rel = _asm("\n".join(lines) + "\n")
    assert ok, _errors(asm)[:3]
    assert _bytes(rel) == [(5 + n) & 0xFF, (5 + n) >> 8] * 2
    assert asm.pass1_iteration <= 2


def test_a_guess_that_moves_a_label_is_checked():
    """DS of a chain's value moves L1, which ends another chain: the
    first guess at B0 used L1 where it was before the DS grew."""
    lines = ["\tCSEG", "\tDW B0", "\tDS A0", "L1:\tNOP"]
    lines += [f"B{i}\tEQU B{i + 1}+1" for i in range(40)] + ["B40\tEQU L1"]
    lines += [f"A{i}\tEQU A{i + 1}+1" for i in range(40)]
    lines += ["A40\tEQU 10", "\tDW A0,B0,L1", "\tEND"]
    linker = _link("\n".join(lines) + "\n")
    l1 = 0x100 + 2 + 50
    out = linker.output
    assert (out[0] | out[1] << 8) == l1 + 40
    end = 2 + 50 + 1
    assert list(out[end:end + 6]) == [50, 0, (l1 + 40) & 0xFF, (l1 + 40) >> 8,
                                      l1 & 0xFF, l1 >> 8]


def test_guesses_through_dollar_radix_externals_and_link_time_values():
    """$ is read where the EQU is, an operand under .RADIX 16 in hex, an
    alias of an external and HIGH of a relocatable value stay what they
    are when the chain above them is guessed."""
    lines = ["\tASEG", "\tORG 100H", "\tDW C0", "\tDW D0"]
    lines += [f"C{i}\tEQU C{i + 1}+1" for i in range(20)]
    lines += ["C20\tEQU $+C21", "\t.RADIX 16", "C21\tEQU D0+10", "\t.RADIX 10"]
    lines += [f"D{i}\tEQU D{i + 1}+10" for i in range(20)]
    lines += ["D20\tEQU 1", "\tEND"]
    ok, asm, rel = _asm("\n".join(lines) + "\n")
    assert ok, _errors(asm)
    d0 = 1 + 200
    c0 = 0x104 + d0 + 0x10 + 20
    assert _bytes(rel) == [c0 & 0xFF, c0 >> 8, d0, 0]

    src = ["\tEXTRN EXA", "\tCSEG", "\tLXI H,X0", "\tMVI A,H0"]
    src += [f"X{i}\tEQU X{i + 1}+1" for i in range(30)] + ["X30\tEQU EXA"]
    src += [f"H{i}\tEQU H{i + 1}" for i in range(30)] + ["H30\tEQU HIGH BUF"]
    src += ["\tDSEG", "\tDS 300H", "BUF:\tDS 1", "\tEND"]
    other = "\tPUBLIC EXA\n\tCSEG\n\tDS 20H\nEXA:\tNOP\n\tEND\n"
    linker = _link("\n".join(src) + "\n", other)
    exa = 0x100 + 5 + 0x20
    buf = 0x100 + 5 + 0x21 + 0x300
    assert list(linker.output[:5]) == [0x21, (exa + 30) & 0xFF,
                                       (exa + 30) >> 8, 0x3E, buf >> 8]
