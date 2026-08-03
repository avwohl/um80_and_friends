"""An operand given to an instruction that takes none is an error.

Real MACRO-80 3.44 flags these 'Q' (questionable), assembles the instruction
without its operand and still writes the .REL.  In 8080 mode that turns
`RET NZ` into an unconditional RET (C9) and `RLC B` into RLC A (07), and the
conditional returns (`RZ FOO`) dropped their operand with no diagnostic at
all.  um80 rejects them instead; see CHANGELOG.md for the divergence note.

The same source assembled after a `.Z80` directive must still produce the
proper Z80 encodings.
"""

import os
import subprocess
import sys
import tempfile

from um80.um80 import Assembler
from um80.ul80 import Linker


def _assemble(source):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "t.mac")
    with open(p, "w") as f:
        f.write(source)
    asm = Assembler()
    ok = asm.assemble(p)
    return asm, ok


def _errors(source):
    asm, ok = _assemble(source)
    assert not ok, "expected assembly to fail"
    return [e.format_message() for e in asm.errors]


def _image(source, code_base=0x0100):
    d = tempfile.mkdtemp()
    src_path = os.path.join(d, "t.mac")
    with open(src_path, "w") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(src_path), f"Assembly failed: {asm.errors}"
    assert not asm.warnings, f"unexpected warnings: {asm.warnings}"
    rel_path = os.path.join(d, "t.rel")
    with open(rel_path, "wb") as f:
        f.write(asm.output.get_bytes())
    linker = Linker()
    linker.code_base = code_base
    linker.load_rel(rel_path)
    assert linker.link(), f"Link failed: {linker.errors}"
    return bytes(linker.output)


# ---------------------------------------------------------------- 8080 mode

def test_ret_cc_in_8080_mode_is_an_error():
    # Was: warning only, emitted C9 = unconditional RET.
    errs = _errors("\tASEG\n\tORG 100H\n\tRET NZ\n\tEND\n")
    assert len(errs) == 1, errs
    assert "RET" in errs[0]
    assert "RNZ" in errs[0]
    assert ".Z80" in errs[0]


def test_rlc_r_in_8080_mode_is_an_error():
    # Was: warning only, emitted 07 = RLC A.
    errs = _errors("\tASEG\n\tORG 100H\n\tRLC B\n\tEND\n")
    assert len(errs) == 1, errs
    assert "RLC" in errs[0]
    assert ".Z80" in errs[0]


def test_rrc_r_in_8080_mode_is_an_error():
    errs = _errors("\tASEG\n\tORG 100H\n\tRRC C\n\tEND\n")
    assert len(errs) == 1, errs
    assert "RRC" in errs[0]


def test_rlc_indirect_hl_in_8080_mode_is_an_error():
    errs = _errors("\tASEG\n\tORG 100H\n\tRLC (HL)\n\tEND\n")
    assert len(errs) == 1, errs
    assert ".Z80" in errs[0]


def test_conditional_return_with_operand_is_an_error():
    # Was: dropped silently, not even a warning.
    errs = _errors("\tASEG\n\tORG 100H\n\tRZ FOO\n\tEND\n")
    assert len(errs) == 1, errs
    assert "RZ takes no operand" in errs[0]


def test_plain_no_operand_instruction_with_operand_is_an_error():
    errs = _errors("\tASEG\n\tORG 100H\n\tNOP 5\n\tEND\n")
    assert len(errs) == 1, errs
    assert "NOP takes no operand" in errs[0]


def test_no_operand_forms_still_assemble():
    out = _image("\tASEG\n\tORG 100H\n\tNOP\n\tRET\n\tXCHG\n\tRZ\n\tRLC\n\tEND\n")
    assert out[0:5] == bytes([0x00, 0xC9, 0xEB, 0xC8, 0x07]), out[0:5].hex()


def test_conditional_returns_still_assemble():
    out = _image("\tASEG\n\tORG 100H\n\tRNZ\n\tRZ\n\tRNC\n\tRC\n"
                 "\tRPO\n\tRPE\n\tRP\n\tRM\n\tEND\n")
    assert out[0:8] == bytes([0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8])


# ----------------------------------------------------------------- Z80 mode

def test_same_source_assembles_after_z80_directive():
    out = _image("\t.Z80\n\tASEG\n\tORG 100H\n\tRLC B\n\tRRC C\n\tRET NZ\n\tEND\n")
    assert out[0:5] == bytes([0xCB, 0x00, 0xCB, 0x09, 0xC0]), out[0:5].hex()


def test_z80_no_operand_instruction_with_operand_is_an_error():
    errs = _errors("\t.Z80\n\tASEG\n\tORG 100H\n\tEXX A\n\tEND\n")
    assert len(errs) == 1, errs
    assert "EXX takes no operand" in errs[0]


def test_z80_ed_no_operand_instruction_with_operand_is_an_error():
    # LDIR B used to assemble as LDIR with a warning.
    errs = _errors("\t.Z80\n\tASEG\n\tORG 100H\n\tLDIR B\n\tEND\n")
    assert len(errs) == 1, errs
    assert "LDIR takes no operand" in errs[0]


def test_z80_alu_with_three_operands_is_an_error():
    # Was: assembled as ADD A and dropped ',B,C'.
    errs = _errors("\t.Z80\n\tASEG\n\tORG 100H\n\tADD A,B,C\n\tEND\n")
    assert len(errs) == 1, errs
    assert "ADD requires one or two operands" in errs[0]


def test_z80_alu_one_and_two_operand_forms_still_assemble():
    out = _image("\t.Z80\n\tASEG\n\tORG 100H\n\tADD A,B\n\tADD B\n"
                 "\tADD HL,SP\n\tADD A,5\n\tEND\n")
    assert out[0:5] == bytes([0x80, 0x80, 0x39, 0xC6, 0x05]), out[0:5].hex()


# ------------------------------------------------------- command-line status

def _run_um80(args, cwd):
    return subprocess.run([sys.executable, "-m", "um80.um80"] + args,
                          cwd=cwd, capture_output=True, text=True)


def test_cli_exits_nonzero_and_writes_no_output():
    d = tempfile.mkdtemp()
    src = os.path.join(d, "bad.mac")
    with open(src, "w") as f:
        f.write("\tASEG\n\tORG 100H\n\tRET NZ\n\tEND\n")
    out = os.path.join(d, "bad.rel")
    lst = os.path.join(d, "bad.prn")
    proc = _run_um80(["bad.mac", "-o", "bad.rel", "-l", "bad.prn"], d)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "RET takes no operand" in proc.stderr, proc.stderr
    assert not os.path.exists(out), "output file written despite the error"
    assert not os.path.exists(lst), "listing written despite the error"
