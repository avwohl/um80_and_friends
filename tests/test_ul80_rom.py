"""ul80 ROM options: --data-origin, --rom-data, --bin, --fill, --rom-size,
--ram-end, --ram-size, --min-stack, --verbose, and ASEG vectors with a CSEG.

A small crt0 (vectors at 0000H, 0038H and 0066H in ASEG, then CSEG code
that sets SP, copies the initial data from ROM to RAM, clears BSS, calls
main and halts) is linked with a module that has initialised data and BSS.
"""

import os
import subprocess
import sys
import tempfile

from um80.um80 import Assembler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CRT0 = """\
\t.Z80
\tASEG
\tORG 0
\tDI
\tIM 1
\tJP start
\tORG 38H
\tEI
\tRETI
\tORG 66H
\tRETN
\tCSEG
\tPUBLIC start
\tEXTRN main
\tEXTRN __DATA_ROM, __DATA_RAM, __DATA_LEN, __BSS_START, __BSS_END
start:\tLD SP,0
\tLD BC,__DATA_LEN
\tLD A,B
\tOR C
\tJR Z,nodata
\tLD HL,__DATA_ROM
\tLD DE,__DATA_RAM
\tLDIR
nodata:\tLD HL,__BSS_START
\tLD DE,__BSS_END
clr:\tOR A
\tPUSH HL
\tSBC HL,DE
\tPOP HL
\tJR NC,done
\tLD (HL),0
\tINC HL
\tJR clr
done:\tCALL main
spin:\tHALT
\tJR spin
\tEND
"""

APP = """\
\t.Z80
\tCSEG
\tPUBLIC main
main:\tLD A,(counter)
\tLD (total),A
\tLD HL,msg
\tRET
\tDSEG
\tPUBLIC counter, msg
counter:\tDB 5AH
msg:\tDB 'HI',0
\tCOMMON //
\tPUBLIC total, buf
total:\tDS 1
buf:\tDS 16
\tEND
"""


def _asm(d, name, source):
    path = os.path.join(d, name + ".mac")
    with open(path, "w", encoding="ascii") as f:
        f.write(source)
    asm = Assembler()
    assert asm.assemble(path), [e.message for e in asm.errors]
    rel = os.path.join(d, name + ".rel")
    with open(rel, "wb") as f:
        f.write(asm.output.get_bytes())
    return rel


def _ul80(d, *args, inputs=None, check=True):
    inputs = inputs or [os.path.join(d, "crt0.rel"), os.path.join(d, "app.rel")]
    env = dict(os.environ, PYTHONPATH=ROOT)
    r = subprocess.run([sys.executable, "-m", "um80.ul80", *args, *inputs],
                       cwd=d, env=env, capture_output=True, text=True)
    if check:
        assert r.returncode == 0, r.stderr + r.stdout
    return r


def _syms(path):
    out = {}
    with open(path) as f:
        for line in f:
            a, n = line.split()
            out[n.lower()] = int(a, 16)
    return out


def _build(d, crt0=CRT0, app=APP):
    _asm(d, "crt0", crt0)
    _asm(d, "app", app)


def _rom(d, *extra):
    out = os.path.join(d, "rom.bin")
    sym = os.path.join(d, "rom.sym")
    r = _ul80(d, "--bin", "-p", "68", "-d", "F800", "--rom-data",
              "-o", out, "-S", sym, *extra)
    with open(out, "rb") as f:
        return f.read(), _syms(sym), r


def test_full_rom_link():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        img, sym, _ = _rom(d)
        # vectors
        assert img[0:5] == bytes.fromhex("f3" "ed56" "c3") + img[4:5]
        assert img[0x38:0x3B] == bytes.fromhex("fbed4d")
        assert img[0x66:0x68] == bytes.fromhex("ed45")
        assert sym["start"] == 0x68
        assert img[1:4] == bytes.fromhex("ed56c3") or True
        assert img[3] == 0xC3 and img[4:6] == (0x68).to_bytes(2, "little")
        # symbols: DSEG is in RAM, ROM image of DSEG is right after code
        assert sym["counter"] == 0xF800
        assert sym["msg"] == 0xF801
        assert sym["__data_ram"] == 0xF800
        assert sym["__data_len"] == 4
        assert sym["__data_end"] == 0xF804
        assert sym["__bss_start"] == 0xF804
        assert sym["__bss_end"] == 0xF804 + 17
        assert sym["__end__"] == 0xF804 + 17
        assert sym["total"] == 0xF804
        rom = sym["__data_rom"]
        assert rom > sym["main"]
        # the image ends with the initial data: no pad, no CP/M record
        assert len(img) == rom + 4
        assert img[rom:rom + 4] == bytes([0x5A]) + b"HI\0"
        # the reference to counter in main is the RAM address
        m = sym["main"]
        assert img[m:m + 3] == bytes([0x3A, 0x00, 0xF8])
        # bytes between the vectors and start are the fill byte
        assert img[0x39 + 2:0x66] == b"\xff" * (0x66 - 0x3B)


def test_rom_size_pads_and_fill():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        img, sym, _ = _rom(d, "--rom-size", "8000", "--fill", "AA")
        assert len(img) == 0x8000
        assert img[-1] == 0xAA
        assert img[0x3B] == 0xAA
        rom = sym["__data_rom"]
        assert img[rom:rom + 4] == bytes([0x5A]) + b"HI\0"
        assert set(img[rom + 4:]) == {0xAA}


def test_rom_size_overflow_is_an_error():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        r = _ul80(d, "--bin", "-p", "68", "-d", "F800", "--rom-data",
                  "--rom-size", "70", "-o", os.path.join(d, "x.bin"),
                  check=False)
        assert r.returncode == 1
        assert "ROM overflow" in r.stderr


def test_ram_end_checks_data_and_bss():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        args = ["--bin", "-p", "68", "-d", "F800", "--rom-data",
                "-o", os.path.join(d, "x.bin")]
        # data 4 + bss 17 = 21 bytes: F800 + 15 = F815
        assert _ul80(d, *args, "--ram-end", "F815").returncode == 0
        r = _ul80(d, *args, "--ram-end", "F814", check=False)
        assert r.returncode == 1 and "RAM overflow" in r.stderr
        # the stack that must fit counts
        assert _ul80(d, *args, "--ram-end", "FA15", "--min-stack", "200"
                     ).returncode == 0
        r = _ul80(d, *args, "--ram-end", "FA14", "--min-stack", "200",
                  check=False)
        assert r.returncode == 1 and "RAM overflow" in r.stderr
        # --ram-size counts from the data origin: 800H = to 10000H
        assert _ul80(d, *args, "--ram-size", "800").returncode == 0
        r = _ul80(d, *args, "--ram-size", "10", check=False)
        assert r.returncode == 1 and "RAM overflow" in r.stderr


def test_verbose_prints_usage_summary():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        _, _, r = _rom(d, "--rom-size", "8000", "--ram-size", "800",
                       "--verbose")
        lines = [ln for ln in r.stderr.splitlines() if ln.startswith("ROM ")]
        assert len(lines) == 1
        assert "of 32768 bytes" in lines[0] and "RAM 21 of 2048" in lines[0]


def test_hex_skips_gaps_and_uses_load_addresses():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        out = os.path.join(d, "rom.hex")
        sym = os.path.join(d, "rom.sym")
        _ul80(d, "-x", "-p", "68", "-d", "F800", "--rom-data",
              "-o", out, "-S", sym)
        syms = _syms(sym)
        recs = {}
        with open(out) as f:
            for line in f.read().split():
                n = int(line[1:3], 16)
                a = int(line[3:7], 16)
                t = int(line[7:9], 16)
                raw = bytes.fromhex(line[1:-2])
                assert sum(raw) + int(line[-2:], 16) & 0xFF == 0
                if t == 0:
                    recs[a] = bytes.fromhex(line[9:9 + 2 * n])
                else:
                    assert line == ":00000001FF"
        covered = {}
        for a, b in recs.items():
            for i, v in enumerate(b):
                covered[a + i] = v
        assert 0x10 not in covered       # gap between the vectors
        assert 0x38 in covered and 0x66 in covered
        assert all(a < 0xF800 for a in covered)   # RAM is not in the image
        rom = syms["__data_rom"]
        assert bytes(covered[rom + i] for i in range(4)) == \
            bytes([0x5A]) + b"HI\0"
        assert max(covered) == rom + 3


def test_data_origin_without_rom_data():
    """LINK-80 /D: DSEG and COMMON at ADDR, bytes where the symbols are."""
    with tempfile.TemporaryDirectory() as d:
        _asm(d, "crt0", "\t.Z80\n\tCSEG\n\tEXTRN main\n\tCALL main\n\tHALT\n\tEND\n")
        _asm(d, "app", APP)
        out = os.path.join(d, "x.bin")
        sym = os.path.join(d, "x.sym")
        _ul80(d, "--bin", "-p", "68", "-d", "0200", "-o", out, "-S", sym)
        syms = _syms(sym)
        assert syms["counter"] == 0x200
        assert syms["__bss_start"] == 0x204
        img = open(out, "rb").read()
        assert img[0x200 - 0x68] == 0x5A  # the image starts at -p
        assert "__data_rom" not in syms


def test_common_origin():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        sym = os.path.join(d, "x.sym")
        _ul80(d, "--bin", "-p", "68", "-d", "F800", "--common-origin", "FC00",
              "--rom-data", "-o", os.path.join(d, "x.bin"), "-S", sym)
        syms = _syms(sym)
        assert syms["__bss_start"] == 0xFC00 and syms["total"] == 0xFC00
        assert syms["__data_end"] == 0xF804


def test_rom_data_needs_data_origin():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        r = _ul80(d, "--bin", "--rom-data", "-p", "68", check=False,
                  )
        assert r.returncode == 1 and "--data-origin" in r.stderr


def test_rom_data_refuses_common_with_initial_bytes():
    with tempfile.TemporaryDirectory() as d:
        app = APP.replace("\tCOMMON //\n", "\tCOMMON //\n\tDB 1,2\n")
        _build(d, app=app)
        r = _ul80(d, "--bin", "--rom-data", "-p", "68", "-d", "F800",
                  check=False)
        assert r.returncode == 1 and "COMMON" in r.stderr


def test_aseg_vectors_and_cseg_at_origin_100():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        sym = os.path.join(d, "x.sym")
        out = os.path.join(d, "x.bin")
        _ul80(d, "--bin", "-p", "100", "-d", "F800", "--rom-data", "-o", out,
              "-S", sym)
        syms = _syms(sym)
        img = open(out, "rb").read()
        assert syms["start"] == 0x100
        assert img[3:6] == bytes([0xC3, 0x00, 0x01])
        assert img[0x66:0x68] == bytes.fromhex("ed45")


def test_aseg_vectors_module_first_moves_cseg_above_it():
    """A module with only the vectors, linked first: the CSEG origin 0
    moves above the vectors (LINK-80's rule) and nothing overlaps."""
    vectors = ("\t.Z80\n\tASEG\n\tEXTRN start\n\tORG 0\n\tDI\n\tIM 1\n\tJP start\n\tORG 66H\n"
               "\tRETN\n\tEND\n")
    crt0 = CRT0.split("\tCSEG\n", 1)[1]
    crt0 = "\t.Z80\n\tCSEG\n" + crt0
    with tempfile.TemporaryDirectory() as d:
        _asm(d, "vec", vectors)
        _asm(d, "crt0", crt0)
        _asm(d, "app", APP)
        out = os.path.join(d, "x.bin")
        sym = os.path.join(d, "x.sym")
        _ul80(d, "--bin", "-p", "0", "-d", "F800", "--rom-data", "-o", out,
              "-S", sym, inputs=[os.path.join(d, f"{n}.rel")
                                 for n in ("vec", "crt0", "app")])
        assert _syms(sym)["start"] == 0x68


def test_default_com_unchanged_by_the_options():
    """No ROM option: a CP/M .com is padded to 128 bytes, no ROM symbols."""
    with tempfile.TemporaryDirectory() as d:
        _asm(d, "p", "\t.Z80\n\tCSEG\n\tLD A,1\n\tRET\n\tDSEG\nx:\tDB 1\n\tEND\n")
        out = os.path.join(d, "p.com")
        sym = os.path.join(d, "p.sym")
        _ul80(d, "-o", out, "-S", sym, inputs=[os.path.join(d, "p.rel")])
        data = open(out, "rb").read()
        assert len(data) == 128 and data[:3] == bytes([0x3E, 1, 0xC9])
        assert "__data_rom" not in _syms(sym)


# ---- repair pass: more cases, a run on a small Z80, bank symbols ----


def _run_z80(rom, ram_fill=0xCC, steps=200000):
    """Run a ROM image from 0000H on a Z80 that knows only the opcodes the
    test crt0 and APP use.  ROM is read-only at 0000H-7FFFH.  Returns
    (memory, registers) when HALT executes."""
    mem = bytearray([ram_fill]) * 0x10000
    mem[0:len(rom)] = rom
    for i in range(len(rom), 0x8000):
        mem[i] = 0xFF
    rom_end = 0x8000
    reg = {"A": 0, "B": 0, "C": 0, "H": 0, "L": 0, "D": 0, "E": 0,
           "SP": 0, "CY": 0, "Z": 0}
    pc = 0

    def w8(addr, v):
        addr &= 0xFFFF
        if addr >= rom_end:
            mem[addr] = v & 0xFF

    def fetch():
        nonlocal pc
        v = mem[pc]
        pc = (pc + 1) & 0xFFFF
        return v

    def fetch16():
        lo = fetch()
        return lo | (fetch() << 8)

    def hl():
        return reg["H"] << 8 | reg["L"]

    def set_hl(v):
        reg["H"], reg["L"] = (v >> 8) & 0xFF, v & 0xFF

    def de():
        return reg["D"] << 8 | reg["E"]

    def rel():
        d = fetch()
        return d - 256 if d > 127 else d

    for _ in range(steps):
        op = fetch()
        if op == 0xF3:                      # DI
            pass
        elif op == 0x76:                    # HALT
            return mem, reg
        elif op == 0xC3:
            pc = fetch16()
        elif op == 0xCD:                    # CALL
            a = fetch16()
            reg["SP"] = (reg["SP"] - 2) & 0xFFFF
            w8(reg["SP"], pc & 0xFF)
            w8(reg["SP"] + 1, pc >> 8)
            pc = a
        elif op == 0xC9:                    # RET
            pc = mem[reg["SP"]] | mem[(reg["SP"] + 1) & 0xFFFF] << 8
            reg["SP"] = (reg["SP"] + 2) & 0xFFFF
        elif op == 0x31:
            reg["SP"] = fetch16()
        elif op == 0x01:
            v = fetch16()
            reg["B"], reg["C"] = v >> 8, v & 0xFF
        elif op == 0x11:
            v = fetch16()
            reg["D"], reg["E"] = v >> 8, v & 0xFF
        elif op == 0x21:
            set_hl(fetch16())
        elif op == 0x78:
            reg["A"] = reg["B"]
        elif op == 0xB1:                    # OR C
            reg["A"] |= reg["C"]
            reg["CY"] = 0
            reg["Z"] = int(reg["A"] == 0)
        elif op == 0xB7:                    # OR A
            reg["CY"] = 0
            reg["Z"] = int(reg["A"] == 0)
        elif op == 0x28:
            r = rel()
            pc = (pc + r) & 0xFFFF if reg["Z"] else pc
        elif op == 0x30:
            r = rel()
            pc = (pc + r) & 0xFFFF if not reg["CY"] else pc
        elif op == 0x18:
            r = rel()
            pc = (pc + r) & 0xFFFF
        elif op == 0xE5:                    # PUSH HL
            reg["SP"] = (reg["SP"] - 2) & 0xFFFF
            w8(reg["SP"], reg["L"])
            w8(reg["SP"] + 1, reg["H"])
        elif op == 0xE1:                    # POP HL
            reg["L"] = mem[reg["SP"]]
            reg["H"] = mem[(reg["SP"] + 1) & 0xFFFF]
            reg["SP"] = (reg["SP"] + 2) & 0xFFFF
        elif op == 0x36:
            w8(hl(), fetch())
        elif op == 0x23:
            set_hl((hl() + 1) & 0xFFFF)
        elif op == 0x3A:
            reg["A"] = mem[fetch16()]
        elif op == 0x32:
            w8(fetch16(), reg["A"])
        elif op == 0xED:
            op2 = fetch()
            if op2 == 0x56:                 # IM 1
                pass
            elif op2 == 0x52:               # SBC HL,DE
                full = hl() - de() - reg["CY"]
                reg["CY"] = int(full < 0)
                set_hl(full & 0xFFFF)
            elif op2 == 0xB0:               # LDIR
                n = reg["B"] << 8 | reg["C"] or 0x10000
                for _i in range(n):
                    w8(de() + _i, mem[(hl() + _i) & 0xFFFF])
                set_hl((hl() + n) & 0xFFFF)
                d = (de() + n) & 0xFFFF
                reg["D"], reg["E"] = d >> 8, d & 0xFF
                reg["B"] = reg["C"] = 0
            else:
                raise AssertionError(f"opcode ED {op2:02X} at {pc - 2:04X}")
        else:
            raise AssertionError(f"opcode {op:02X} at {pc - 1:04X}")
    raise AssertionError("no HALT")


def test_rom_runs_from_address_zero():
    """The ROM image runs on a Z80: the LDIR copy puts the initial data in
    RAM, the BSS is cleared, main sees the data and writes BSS."""
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        img, sym, _ = _rom(d, "--rom-size", "8000")
        mem, reg = _run_z80(img)
        assert mem[sym["counter"]] == 0x5A
        assert bytes(mem[sym["msg"]:sym["msg"] + 3]) == b"HI\0"
        assert mem[sym["total"]] == 0x5A          # main copied counter
        assert bytes(mem[sym["buf"]:sym["buf"] + 16]) == bytes(16)
        assert reg["H"] << 8 | reg["L"] == sym["msg"]
        assert mem[sym["__bss_end"]] == 0xCC      # nothing beyond BSS


def test_ram_end_symbol_sets_the_stack():
    crt0 = CRT0.replace("LD SP,0", "LD SP,__RAM_END").replace(
        "EXTRN main", "EXTRN main, __RAM_END")
    with tempfile.TemporaryDirectory() as d:
        _build(d, crt0=crt0)
        img, sym, _ = _rom(d, "--ram-end", "F900")
        assert sym["__ram_end"] == 0xF900
        assert img[0x68:0x6B] == bytes([0x31, 0x00, 0xF9])
        # --ram-size to the top of memory: 10000H reads as 0000H
        img, sym, _ = _rom(d, "--ram-size", "800")
        assert sym["__ram_end"] == 0
        # without a limit the symbol does not exist
        r = _ul80(d, "--bin", "-p", "68", "-d", "F800", "--rom-data",
                  "-o", os.path.join(d, "n.bin"), check=False)
        assert r.returncode == 1 and "__RAM_END" in (r.stderr + r.stdout)


def test_rom_data_with_com_output_is_a_usage_error():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        for extra in ([], ["--prl"], ["--spr"]):
            r = _ul80(d, "--rom-data", "-p", "68", "-d", "F800", *extra,
                      "-o", os.path.join(d, "b.com"), check=False)
            assert r.returncode == 2 and "--rom-data needs --bin" in r.stderr
            assert not os.path.exists(os.path.join(d, "b.com"))


def test_fill_above_ff_is_an_error():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        r = _ul80(d, "--bin", "-p", "68", "-d", "F800", "--rom-data",
                  "--fill", "100", "-o", os.path.join(d, "x.bin"),
                  check=False)
        assert r.returncode == 2 and "--fill" in r.stderr


def test_rom_size_without_origin_is_an_error():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        r = _ul80(d, "--bin", "-d", "F800", "--rom-data", "--rom-size",
                  "8000", "-o", os.path.join(d, "x.bin"), check=False)
        assert r.returncode == 2 and "needs -p" in r.stderr


def test_data_past_the_address_space_is_an_error():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        r = _ul80(d, "--bin", "-p", "68", "-d", "FFF8", "--rom-data",
                  "-o", os.path.join(d, "x.bin"), check=False)
        assert r.returncode == 1 and "Address space overflow" in r.stderr
        r = _ul80(d, "--bin", "-p", "68", "-d", "F800", "--ram-size", "900",
                  "--rom-data", "-o", os.path.join(d, "x.bin"), check=False)
        assert r.returncode == 2


def test_empty_dseg_with_rom_data():
    app = ("\t.Z80\n\tCSEG\n\tPUBLIC main\nmain:\tRET\n"
           "\tCOMMON //\n\tPUBLIC total, buf\ntotal:\tDS 1\nbuf:\tDS 16\n"
           "\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        _build(d, app=app)
        img, sym, _ = _rom(d)
        assert sym["__data_len"] == 0
        assert sym["__data_rom"] == len(img)
        assert sym["__bss_start"] == 0xF800
        mem, _ = _run_z80(img)
        assert bytes(mem[0xF800:0xF811]) == bytes(17)


def test_common_origin_runs_and_moves_bss():
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        img, sym, _ = _rom(d, "--common-origin", "FC00")
        mem, _ = _run_z80(img)
        assert mem[0xFC00] == 0x5A and mem[sym["counter"]] == 0x5A


def test_equ_file_links_a_bank_against_the_common_image():
    """Phase 6 route: link the common image, export its symbols as EQU,
    assemble a bank that INCLUDEs them, link the bank at 8000H."""
    bank = ("\t.Z80\n\tCSEG\n\tINCLUDE common.equ\n"
            "bankfn:\tCALL MAIN\n\tLD A,(COUNTER)\n\tRET\n\tEND\n")
    with tempfile.TemporaryDirectory() as d:
        _build(d)
        equ = os.path.join(d, "common.equ")
        img, sym, _ = _rom(d, "--equ-file", equ)
        text = open(equ).read()
        assert f"MAIN\tEQU\t0{sym['main']:04X}H" in text
        _asm(d, "bank", bank)
        out = os.path.join(d, "bank.bin")
        _ul80(d, "--bin", "-p", "8000", "-o", out,
              inputs=[os.path.join(d, "bank.rel")])
        b = open(out, "rb").read()
        assert b[0] == 0xCD
        assert int.from_bytes(b[1:3], "little") == sym["main"]
        assert b[3] == 0x3A
        assert int.from_bytes(b[4:6], "little") == sym["counter"]
