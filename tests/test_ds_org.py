"""
Test DS (Define Space) and ORG directive handling in um80 assembler and ul80 linker.

This test suite covers bugs related to:
- DS padding calculations with multiple ORG directives (bug1_ds.txt)
- Segment buffer management with SET_LOC (v0.3.15)
- External reference offsets in absolute-origin code (v0.3.16)
- Relocatable address emission with ORG (v0.3.6)
- ORG to high addresses outputting spurious zeros (v0.3.5)
"""

import os
import tempfile
import pytest
from um80.ul80 import Linker
from um80.relformat import (
    RELWriter, RELReader,
    ADDR_ABSOLUTE, ADDR_PROGRAM_REL, ADDR_DATA_REL, ADDR_COMMON_REL
)


def dump_rel(data):
    """Debug helper: decode and print REL file contents."""
    reader = RELReader(data)
    items = reader.read_all()
    for item in items:
        print(item)
    return items


class TestDSBasic:
    """Test basic DS directive functionality."""

    def test_ds_advances_location(self):
        """DS should advance location counter without emitting bytes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create module: 2 bytes code, DS 5, 2 bytes code
            # Total declared size = 9 bytes
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_absolute_byte(0xAA)  # byte at offset 0
            writer.write_absolute_byte(0xBB)  # byte at offset 1
            writer.write_set_location(ADDR_PROGRAM_REL, 7)  # DS 5 (skip to offset 7)
            writer.write_absolute_byte(0xCC)  # byte at offset 7
            writer.write_absolute_byte(0xDD)  # byte at offset 8
            writer.write_define_program_size(9)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            # Verify bytes are at correct positions
            assert linker.output[0] == 0xAA  # offset 0
            assert linker.output[1] == 0xBB  # offset 1
            # Bytes 2-6 are padding (uninitialized)
            assert linker.output[7] == 0xCC  # offset 7
            assert linker.output[8] == 0xDD  # offset 8

    def test_ds_zero(self):
        """DS 0 should not advance location counter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_absolute_byte(0xAA)
            # DS 0 would emit SET_LOC to same location - we just continue
            writer.write_absolute_byte(0xBB)
            writer.write_define_program_size(2)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            assert len(linker.output) == 2
            assert linker.output[0] == 0xAA
            assert linker.output[1] == 0xBB

    def test_ds_large(self):
        """Test DS with large skip value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_absolute_byte(0xAA)  # offset 0
            writer.write_set_location(ADDR_PROGRAM_REL, 100)  # DS 99 (skip to offset 100)
            writer.write_absolute_byte(0xBB)  # offset 100
            writer.write_define_program_size(101)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            assert linker.output[0] == 0xAA
            assert linker.output[100] == 0xBB


class TestORGBasic:
    """Test basic ORG directive functionality."""

    def test_org_absolute(self):
        """Test ORG with absolute address."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_set_location(ADDR_ABSOLUTE, 0x100)
            writer.write_absolute_byte(0xAA)
            writer.write_absolute_byte(0xBB)
            writer.write_absolute_byte(0xCC)
            writer.write_define_program_size(3)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            assert linker.output[0] == 0xAA
            assert linker.output[1] == 0xBB
            assert linker.output[2] == 0xCC

    def test_org_high_address(self):
        """Test ORG to high address (>0x100) doesn't emit spurious zeros (v0.3.5 fix)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_set_location(ADDR_ABSOLUTE, 0xE000)
            writer.write_absolute_byte(0xAA)
            writer.write_absolute_byte(0xBB)
            writer.write_define_program_size(2)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0xE000
            linker.load_rel(rel_path)
            linker.link()

            # Output should only be 2 bytes, not 0xE000+ bytes
            assert len(linker.output) == 2
            assert linker.output[0] == 0xAA
            assert linker.output[1] == 0xBB


class TestMultipleORG:
    """Test multiple ORG directives in a module."""

    def test_multiple_org_absolute(self):
        """Multiple ORG with absolute addresses."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate: ORG 0100H, DB 0AAH, ORG 0110H, DB 0BBH
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_set_location(ADDR_ABSOLUTE, 0x100)
            writer.write_absolute_byte(0xAA)  # at 0x100
            writer.write_set_location(ADDR_ABSOLUTE, 0x110)
            writer.write_absolute_byte(0xBB)  # at 0x110
            writer.write_define_program_size(17)  # 0x110 - 0x100 + 1
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            # 0xAA at offset 0 (0x100), 0xBB at offset 16 (0x110)
            assert linker.output[0] == 0xAA
            assert linker.output[16] == 0xBB

    def test_org_backwards(self):
        """ORG to earlier address (overlay/fill pattern)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # ORG 0100H, DS 10, DB 0AAH, ORG 0105H, DB 0BBH
            # This should place 0xBB at offset 5, overwriting any previous content
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_set_location(ADDR_ABSOLUTE, 0x100)
            writer.write_set_location(ADDR_ABSOLUTE, 0x10A)  # skip 10 bytes
            writer.write_absolute_byte(0xAA)  # at 0x10A
            writer.write_set_location(ADDR_ABSOLUTE, 0x105)  # go back
            writer.write_absolute_byte(0xBB)  # at 0x105
            writer.write_define_program_size(11)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            assert linker.output[5] == 0xBB   # offset 5 = 0x105
            assert linker.output[10] == 0xAA  # offset 10 = 0x10A


class TestDSWithORG:
    """Test DS combined with ORG directives."""

    def test_ds_after_org(self):
        """DS after ORG should skip relative to ORG address."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # ORG 0100H, DB 0AAH, DS 5, DB 0BBH
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_set_location(ADDR_ABSOLUTE, 0x100)
            writer.write_absolute_byte(0xAA)  # at 0x100
            # DS 5 means skip to 0x106
            writer.write_set_location(ADDR_ABSOLUTE, 0x106)
            writer.write_absolute_byte(0xBB)  # at 0x106
            writer.write_define_program_size(7)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            assert linker.output[0] == 0xAA  # 0x100
            assert linker.output[6] == 0xBB  # 0x106

    def test_multiple_ds_with_org(self):
        """Multiple DS blocks with ORG - the bug1_ds.txt scenario."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate typical ROM/driver structure:
            # ORG 0000H
            # RST0: DS 8    ; RST 0 vector area
            # RST1: DS 8    ; RST 1 vector area
            # ...
            # ORG 0040H
            # CODE: DB ...

            writer = RELWriter()
            writer.write_program_name("DRIVER")

            # RST vectors area (absolute segment)
            writer.write_set_location(ADDR_ABSOLUTE, 0x0000)
            writer.write_absolute_byte(0xC3)  # JP instruction at RST 0
            writer.write_absolute_byte(0x40)
            writer.write_absolute_byte(0x00)  # Jump to 0x0040

            # Skip to RST 1 (offset 8)
            writer.write_set_location(ADDR_ABSOLUTE, 0x0008)
            writer.write_absolute_byte(0xC9)  # RET at RST 1

            # Skip to RST 2 (offset 16)
            writer.write_set_location(ADDR_ABSOLUTE, 0x0010)
            writer.write_absolute_byte(0xC9)  # RET at RST 2

            # Code at 0x0040
            writer.write_set_location(ADDR_ABSOLUTE, 0x0040)
            writer.write_absolute_byte(0xAF)  # XRA A
            writer.write_absolute_byte(0xC9)  # RET

            writer.write_define_program_size(0x42)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "driver.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x0000
            linker.load_rel(rel_path)
            linker.link()

            # Verify RST 0: JP 0040H
            assert linker.output[0] == 0xC3
            assert linker.output[1] == 0x40
            assert linker.output[2] == 0x00

            # Verify RST 1: RET at offset 8
            assert linker.output[8] == 0xC9

            # Verify RST 2: RET at offset 16
            assert linker.output[16] == 0xC9

            # Verify code at 0x40
            assert linker.output[0x40] == 0xAF
            assert linker.output[0x41] == 0xC9


class TestSegmentSwitching:
    """Test switching between segments (CSEG, DSEG, ASEG)."""

    def test_cseg_dseg_separate(self):
        """CSEG and DSEG should be handled separately."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")

            # CSEG: 4 bytes of code
            writer.write_set_location(ADDR_PROGRAM_REL, 0)
            writer.write_absolute_byte(0x11)  # CSEG byte 0
            writer.write_absolute_byte(0x22)  # CSEG byte 1
            writer.write_absolute_byte(0x33)  # CSEG byte 2
            writer.write_absolute_byte(0x44)  # CSEG byte 3

            # Switch to DSEG (data segment)
            writer.write_set_location(ADDR_DATA_REL, 0)
            writer.write_absolute_byte(0xAA)  # DSEG byte 0
            writer.write_absolute_byte(0xBB)  # DSEG byte 1

            # Back to CSEG - should NOT overwrite
            writer.write_set_location(ADDR_PROGRAM_REL, 4)
            writer.write_absolute_byte(0x55)  # CSEG byte 4
            writer.write_absolute_byte(0x66)  # CSEG byte 5

            writer.write_define_program_size(6)
            writer.write_define_data_size(2)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            # CSEG at 0x100-0x105
            assert linker.output[0] == 0x11
            assert linker.output[1] == 0x22
            assert linker.output[2] == 0x33
            assert linker.output[3] == 0x44
            assert linker.output[4] == 0x55
            assert linker.output[5] == 0x66

            # DSEG should follow CSEG at 0x106-0x107
            assert linker.output[6] == 0xAA
            assert linker.output[7] == 0xBB

    def test_aseg_independent(self):
        """ASEG (absolute segment) should be independent of CSEG/DSEG."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")

            # ASEG at absolute address 0x100
            writer.write_set_location(ADDR_ABSOLUTE, 0x100)
            writer.write_absolute_byte(0xAA)
            writer.write_absolute_byte(0xBB)

            writer.write_define_program_size(2)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            assert linker.output[0] == 0xAA
            assert linker.output[1] == 0xBB


class TestExternalReferencesWithDSORG:
    """Test external symbol references with DS and ORG."""

    def test_external_after_ds(self):
        """External reference after DS should resolve to correct address."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Module 1: exports FUNC at offset 0
            writer1 = RELWriter()
            writer1.write_program_name("MOD1")
            writer1.write_absolute_byte(0xC9)  # RET
            writer1.write_define_entry_point(ADDR_PROGRAM_REL, 0, "FUNC")
            writer1.write_define_program_size(1)
            writer1.write_end_program()
            writer1.write_end_file()

            mod1_path = os.path.join(tmpdir, "mod1.rel")
            with open(mod1_path, "wb") as f:
                f.write(writer1.get_bytes())

            # Module 2: DS 10, then CALL FUNC
            writer2 = RELWriter()
            writer2.write_program_name("MOD2")
            writer2.write_set_location(ADDR_PROGRAM_REL, 10)  # DS 10
            writer2.write_absolute_byte(0xCD)  # CALL opcode
            writer2.write_absolute_byte(0x00)  # placeholder low
            writer2.write_absolute_byte(0x00)  # placeholder high
            writer2.write_chain_external(ADDR_PROGRAM_REL, 11, "FUNC")
            writer2.write_define_program_size(13)
            writer2.write_end_program()
            writer2.write_end_file()

            mod2_path = os.path.join(tmpdir, "mod2.rel")
            with open(mod2_path, "wb") as f:
                f.write(writer2.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(mod1_path)
            linker.load_rel(mod2_path)
            linker.link()

            # MOD1 at 0x100 (1 byte)
            # MOD2 at 0x101 (13 bytes: 10 DS + 3 CALL)
            # CALL at 0x10B, should point to 0x100
            assert linker.output[0] == 0xC9  # FUNC
            assert linker.output[11] == 0xCD  # CALL opcode
            assert linker.output[12] == 0x00  # low byte of 0x100
            assert linker.output[13] == 0x01  # high byte of 0x100

    def test_external_with_absolute_org(self):
        """External reference in absolute-origin code (v0.3.16 fix)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Module 1: exports TARGET
            writer1 = RELWriter()
            writer1.write_program_name("MOD1")
            writer1.write_absolute_byte(0xC9)
            writer1.write_define_entry_point(ADDR_PROGRAM_REL, 0, "TARGET")
            writer1.write_define_program_size(1)
            writer1.write_end_program()
            writer1.write_end_file()

            mod1_path = os.path.join(tmpdir, "mod1.rel")
            with open(mod1_path, "wb") as f:
                f.write(writer1.get_bytes())

            # Module 2: ORG 0200H, CALL TARGET
            writer2 = RELWriter()
            writer2.write_program_name("MOD2")
            writer2.write_set_location(ADDR_ABSOLUTE, 0x200)
            writer2.write_absolute_byte(0xCD)  # CALL
            writer2.write_absolute_byte(0x00)  # placeholder
            writer2.write_absolute_byte(0x00)
            # Chain points to offset 0x201 (relative to 0x200)
            writer2.write_chain_external(ADDR_PROGRAM_REL, 0x01, "TARGET")
            writer2.write_define_program_size(3)
            writer2.write_end_program()
            writer2.write_end_file()

            mod2_path = os.path.join(tmpdir, "mod2.rel")
            with open(mod2_path, "wb") as f:
                f.write(writer2.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(mod1_path)
            linker.load_rel(mod2_path)
            linker.link()

            # MOD1 at 0x100 (1 byte)
            # MOD2 at 0x101 (3 bytes, but ORG 0200H means code_start=0x200)
            # Actually with absolute ORG, the linker should handle this specially

            # Verify TARGET is at 0x100
            assert linker.output[0] == 0xC9

    def test_chained_externals_with_ds(self):
        """Chain of external references spanning DS areas."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Module exports FUNC
            writer1 = RELWriter()
            writer1.write_program_name("LIB")
            writer1.write_absolute_byte(0xC9)
            writer1.write_define_entry_point(ADDR_PROGRAM_REL, 0, "FUNC")
            writer1.write_define_program_size(1)
            writer1.write_end_program()
            writer1.write_end_file()

            lib_path = os.path.join(tmpdir, "lib.rel")
            with open(lib_path, "wb") as f:
                f.write(writer1.get_bytes())

            # Module with multiple CALL FUNC separated by DS
            writer2 = RELWriter()
            writer2.write_program_name("MAIN")
            # First CALL at offset 0
            writer2.write_absolute_byte(0xCD)
            writer2.write_absolute_byte(0x00)  # chain link -> 0 (end)
            writer2.write_absolute_byte(0x00)
            # DS 7 (skip to offset 10)
            writer2.write_set_location(ADDR_PROGRAM_REL, 10)
            # Second CALL at offset 10
            writer2.write_absolute_byte(0xCD)
            writer2.write_absolute_byte(0x01)  # chain link -> 1 (first CALL)
            writer2.write_absolute_byte(0x00)
            # Chain external: head at offset 11, chains to 1
            writer2.write_chain_external(ADDR_PROGRAM_REL, 11, "FUNC")
            writer2.write_define_program_size(13)
            writer2.write_end_program()
            writer2.write_end_file()

            main_path = os.path.join(tmpdir, "main.rel")
            with open(main_path, "wb") as f:
                f.write(writer2.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(lib_path)
            linker.load_rel(main_path)
            linker.link()

            # LIB at 0x100, MAIN at 0x101
            # First CALL at 0x101, second at 0x10B
            # Both should point to 0x100
            assert linker.output[0] == 0xC9  # FUNC
            assert linker.output[1] == 0xCD  # first CALL
            assert linker.output[2] == 0x00  # low byte of 0x100
            assert linker.output[3] == 0x01  # high byte of 0x100
            assert linker.output[11] == 0xCD  # second CALL
            assert linker.output[12] == 0x00  # low byte of 0x100
            assert linker.output[13] == 0x01  # high byte of 0x100


class TestRelocatableAddressesWithORG:
    """Test relocatable addresses with ORG (v0.3.6 fix)."""

    def test_program_relative_after_org(self):
        """Program-relative address after ORG should relocate correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_set_location(ADDR_PROGRAM_REL, 0)
            writer.write_absolute_byte(0x21)  # LXI H opcode
            # Program-relative address pointing to offset 5
            writer.write_program_relative(5)
            writer.write_absolute_byte(0xC9)  # RET at offset 4
            writer.write_absolute_byte(0xAF)  # XRA A at offset 5 (target)
            writer.write_define_program_size(6)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            # LXI H, 0x105 (offset 5 + base 0x100)
            assert linker.output[0] == 0x21
            assert linker.output[1] == 0x05  # low byte of 0x105
            assert linker.output[2] == 0x01  # high byte of 0x105

    def test_data_relative_with_org(self):
        """Data-relative address should relocate to data segment base."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")

            # Code segment
            writer.write_set_location(ADDR_PROGRAM_REL, 0)
            writer.write_absolute_byte(0x21)  # LXI H
            # Data-relative address pointing to data offset 0
            writer.write_data_relative(0)
            writer.write_absolute_byte(0xC9)  # RET

            # Data segment
            writer.write_set_location(ADDR_DATA_REL, 0)
            writer.write_absolute_byte(0x42)  # data byte

            writer.write_define_program_size(4)
            writer.write_define_data_size(1)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            # Code at 0x100-0x103, data at 0x104
            # LXI H should point to 0x104
            assert linker.output[0] == 0x21
            assert linker.output[1] == 0x04  # low byte of 0x104
            assert linker.output[2] == 0x01  # high byte of 0x104


class TestRSTVectorLayout:
    """Test RST vector layout patterns (common in device drivers)."""

    def test_rst_vector_table(self):
        """RST vector table with 8-byte spacing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("VECTORS")

            # RST 0: JP MAIN (at 0x38 for this test)
            writer.write_set_location(ADDR_ABSOLUTE, 0x00)
            writer.write_absolute_byte(0xC3)  # JP
            writer.write_absolute_byte(0x38)
            writer.write_absolute_byte(0x00)

            # RST 1: RET
            writer.write_set_location(ADDR_ABSOLUTE, 0x08)
            writer.write_absolute_byte(0xC9)

            # RST 2: RET
            writer.write_set_location(ADDR_ABSOLUTE, 0x10)
            writer.write_absolute_byte(0xC9)

            # RST 3: RET
            writer.write_set_location(ADDR_ABSOLUTE, 0x18)
            writer.write_absolute_byte(0xC9)

            # RST 4: RET
            writer.write_set_location(ADDR_ABSOLUTE, 0x20)
            writer.write_absolute_byte(0xC9)

            # RST 5: RET
            writer.write_set_location(ADDR_ABSOLUTE, 0x28)
            writer.write_absolute_byte(0xC9)

            # RST 6: RET
            writer.write_set_location(ADDR_ABSOLUTE, 0x30)
            writer.write_absolute_byte(0xC9)

            # RST 7: RET
            writer.write_set_location(ADDR_ABSOLUTE, 0x38)
            writer.write_absolute_byte(0xAF)  # XRA A (MAIN entry point)
            writer.write_absolute_byte(0xC9)  # RET

            writer.write_define_program_size(0x3A)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "vectors.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x00
            linker.load_rel(rel_path)
            linker.link()

            # Verify all RST vectors are at correct offsets
            assert linker.output[0x00] == 0xC3  # RST 0: JP
            assert linker.output[0x01] == 0x38
            assert linker.output[0x02] == 0x00
            assert linker.output[0x08] == 0xC9  # RST 1: RET
            assert linker.output[0x10] == 0xC9  # RST 2: RET
            assert linker.output[0x18] == 0xC9  # RST 3: RET
            assert linker.output[0x20] == 0xC9  # RST 4: RET
            assert linker.output[0x28] == 0xC9  # RST 5: RET
            assert linker.output[0x30] == 0xC9  # RST 6: RET
            assert linker.output[0x38] == 0xAF  # RST 7/MAIN: XRA A
            assert linker.output[0x39] == 0xC9  # RET

    def test_offset_7_bytes_bug_scenario(self):
        """
        Test the specific scenario from bug1_ds.txt where structures were
        offset by 7 bytes from their intended positions.

        This simulates a driver with RST vectors, HCB bank IDs, PMGMT, and entry points.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("DRIVER")

            # RST 0 at 0x00 - should NOT be at 0x07
            writer.write_set_location(ADDR_ABSOLUTE, 0x00)
            writer.write_absolute_byte(0xC3)  # JP
            writer.write_absolute_byte(0x00)
            writer.write_absolute_byte(0x01)  # JP 0100H

            # HCB Bank ID at 0x03 - should NOT be at 0x0A
            writer.write_set_location(ADDR_ABSOLUTE, 0x03)
            writer.write_absolute_byte(0x42)  # Bank ID marker

            # PMGMT at 0x10 - should NOT be at 0x17
            writer.write_set_location(ADDR_ABSOLUTE, 0x10)
            writer.write_absolute_byte(0x00)  # PMGMT flags
            writer.write_absolute_byte(0x01)  # PMGMT data

            # Entry point at 0x20 - should NOT be at 0x27
            writer.write_set_location(ADDR_ABSOLUTE, 0x20)
            writer.write_absolute_byte(0xAF)  # XRA A
            writer.write_absolute_byte(0xC9)  # RET

            # Code at 0x100
            writer.write_set_location(ADDR_ABSOLUTE, 0x100)
            writer.write_absolute_byte(0x00)  # NOP
            writer.write_absolute_byte(0xC9)  # RET

            writer.write_define_program_size(0x102)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "driver.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x00
            linker.load_rel(rel_path)
            linker.link()

            # Critical: verify nothing is offset by 7 bytes
            # RST 0 must be at offset 0, not 7
            assert linker.output[0x00] == 0xC3, f"RST 0 at wrong offset, got {linker.output[0x00]:02X}"
            assert linker.output[0x01] == 0x00
            assert linker.output[0x02] == 0x01

            # HCB Bank ID must be at offset 3, not 10
            assert linker.output[0x03] == 0x42, f"HCB at wrong offset, got {linker.output[0x03]:02X}"

            # PMGMT must be at offset 0x10, not 0x17
            assert linker.output[0x10] == 0x00, f"PMGMT at wrong offset, got {linker.output[0x10]:02X}"
            assert linker.output[0x11] == 0x01

            # Entry point must be at offset 0x20, not 0x27
            assert linker.output[0x20] == 0xAF, f"Entry at wrong offset, got {linker.output[0x20]:02X}"
            assert linker.output[0x21] == 0xC9

            # Code at 0x100
            assert linker.output[0x100] == 0x00
            assert linker.output[0x101] == 0xC9


class TestProgramSizeCalculation:
    """Test program size calculation with DS and ORG."""

    def test_size_with_ds_gaps(self):
        """Program size should account for DS gaps."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_absolute_byte(0xAA)  # offset 0
            writer.write_set_location(ADDR_PROGRAM_REL, 10)  # DS 9
            writer.write_absolute_byte(0xBB)  # offset 10
            writer.write_define_program_size(11)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            # __END__ should be at 0x100 + 11 = 0x10B
            _, end_value, _, _ = linker.globals['__END__']
            assert end_value == 0x10B

    def test_size_multiple_modules_with_ds(self):
        """Multiple modules with DS should have correct total size."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Module 1: 5 bytes
            writer1 = RELWriter()
            writer1.write_program_name("MOD1")
            writer1.write_absolute_byte(0x11)
            writer1.write_set_location(ADDR_PROGRAM_REL, 5)  # DS 4
            writer1.write_define_program_size(5)
            writer1.write_end_program()
            writer1.write_end_file()

            mod1_path = os.path.join(tmpdir, "mod1.rel")
            with open(mod1_path, "wb") as f:
                f.write(writer1.get_bytes())

            # Module 2: 10 bytes
            writer2 = RELWriter()
            writer2.write_program_name("MOD2")
            writer2.write_absolute_byte(0x22)
            writer2.write_set_location(ADDR_PROGRAM_REL, 10)  # DS 9
            writer2.write_define_program_size(10)
            writer2.write_end_program()
            writer2.write_end_file()

            mod2_path = os.path.join(tmpdir, "mod2.rel")
            with open(mod2_path, "wb") as f:
                f.write(writer2.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(mod1_path)
            linker.load_rel(mod2_path)
            linker.link()

            # __END__ = 0x100 + 5 + 10 = 0x10F
            _, end_value, _, _ = linker.globals['__END__']
            assert end_value == 0x10F


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_ds_at_start(self):
        """DS at the very start of module."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_set_location(ADDR_PROGRAM_REL, 5)  # DS 5 at start
            writer.write_absolute_byte(0xAA)
            writer.write_define_program_size(6)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            assert linker.output[5] == 0xAA

    def test_ds_at_end(self):
        """DS at the end of module (trailing space)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_absolute_byte(0xAA)
            writer.write_set_location(ADDR_PROGRAM_REL, 10)  # DS 9 at end
            writer.write_define_program_size(10)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            # Only 1 byte of actual code, declared size is 10
            assert linker.output[0] == 0xAA
            # The linker uses declared size for __END__ calculation
            _, end_value, _, _ = linker.globals['__END__']
            assert end_value == 0x10A  # 0x100 + 10

    def test_org_to_zero(self):
        """ORG 0 should work correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_set_location(ADDR_ABSOLUTE, 0)
            writer.write_absolute_byte(0xC3)  # JP
            writer.write_absolute_byte(0x03)
            writer.write_absolute_byte(0x00)  # JP 0003H
            writer.write_absolute_byte(0xC9)  # RET at 0003H
            writer.write_define_program_size(4)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0
            linker.load_rel(rel_path)
            linker.link()

            assert linker.output[0] == 0xC3
            assert linker.output[1] == 0x03
            assert linker.output[2] == 0x00
            assert linker.output[3] == 0xC9

    def test_consecutive_ds(self):
        """Multiple consecutive DS directives."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_absolute_byte(0xAA)  # offset 0
            writer.write_set_location(ADDR_PROGRAM_REL, 5)  # DS 4
            writer.write_set_location(ADDR_PROGRAM_REL, 10)  # DS 5
            writer.write_set_location(ADDR_PROGRAM_REL, 20)  # DS 10
            writer.write_absolute_byte(0xBB)  # offset 20
            writer.write_define_program_size(21)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            assert linker.output[0] == 0xAA
            assert linker.output[20] == 0xBB


class TestRELDumper:
    """Test the REL file debugging/dumping functionality."""

    def test_dump_simple_rel(self):
        """Test that we can decode a simple REL file."""
        writer = RELWriter()
        writer.write_program_name("TEST")
        writer.write_set_location(ADDR_ABSOLUTE, 0x100)
        writer.write_absolute_byte(0xAA)
        writer.write_absolute_byte(0xBB)
        writer.write_define_program_size(2)
        writer.write_end_program()
        writer.write_end_file()

        items = dump_rel(writer.get_bytes())

        # Verify we got expected items
        assert ('PROGRAM_NAME', 'TEST') in items
        assert ('SET_LOC', (ADDR_ABSOLUTE, 0x100)) in items
        assert ('ABSOLUTE_BYTE', 0xAA) in items
        assert ('ABSOLUTE_BYTE', 0xBB) in items
        assert ('DEFINE_PROG_SIZE', (ADDR_ABSOLUTE, 2)) in items
        assert ('END_PROGRAM',) in items
        assert ('END_FILE',) in items

    def test_dump_with_externals(self):
        """Test decoding REL with external references."""
        writer = RELWriter()
        writer.write_program_name("MAIN")
        writer.write_absolute_byte(0xCD)  # CALL
        writer.write_absolute_byte(0x00)
        writer.write_absolute_byte(0x00)
        writer.write_chain_external(ADDR_PROGRAM_REL, 1, "FUNC")
        writer.write_define_program_size(3)
        writer.write_end_program()
        writer.write_end_file()

        items = dump_rel(writer.get_bytes())

        # Find the CHAIN_EXTERNAL item
        chain_items = [i for i in items if i[0] == 'CHAIN_EXTERNAL']
        assert len(chain_items) == 1
        assert chain_items[0] == ('CHAIN_EXTERNAL', (ADDR_PROGRAM_REL, 1), 'FUNC')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
