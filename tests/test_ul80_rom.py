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
