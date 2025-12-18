"""
Test the __END__ linker symbol.

The ul80 linker provides a predefined __END__ symbol that points to the
first free byte after all linked code, data, and common blocks. This is
useful for dynamic memory allocation in CP/M programs.
"""

import os
import tempfile
import pytest
from um80.ul80 import Linker
from um80.relformat import RELWriter, ADDR_PROGRAM_REL, ADDR_DATA_REL, ADDR_ABSOLUTE


class TestEndSymbol:
    """Test the __END__ predefined linker symbol."""

    def test_end_symbol_predefined(self):
        """Verify __END__ is predefined in the linker's global symbols."""
        linker = Linker()
        assert '__END__' in linker.globals
        assert linker.globals['__END__'][3] is True  # is_defined

    def test_end_symbol_code_only(self):
        """Test __END__ with code segment only."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a simple module with 10 bytes of code
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_define_program_size(10)
            for _ in range(10):
                writer.write_absolute_byte(0x00)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100  # Standard CP/M origin
            linker.load_rel(rel_path)
            linker.link()

            # __END__ should be at 0x100 + 10 = 0x10A
            mod_idx, value, seg_type, is_defined = linker.globals['__END__']
            assert is_defined
            assert seg_type == ADDR_ABSOLUTE
            assert value == 0x10A

    def test_end_symbol_code_and_data(self):
        """Test __END__ with code and data segments."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_define_program_size(5)   # 5 bytes code
            writer.write_define_data_size(8)      # 8 bytes data
            for _ in range(5):
                writer.write_absolute_byte(0x00)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            # __END__ = code_base + code_size + data_size = 0x100 + 5 + 8 = 0x10D
            _, value, _, _ = linker.globals['__END__']
            assert value == 0x10D

    def test_end_symbol_with_common(self):
        """Test __END__ with code, data, and common blocks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_define_program_size(4)   # 4 bytes code
            writer.write_define_data_size(4)      # 4 bytes data
            writer.write_define_common_size(0, 10, "BLK1")  # 10 bytes common
            for _ in range(4):
                writer.write_absolute_byte(0x00)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            # __END__ = 0x100 + 4 (code) + 4 (data) + 10 (common) = 0x112
            _, value, _, _ = linker.globals['__END__']
            assert value == 0x112

    def test_end_symbol_multiple_modules(self):
        """Test __END__ with multiple linked modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Module 1: 6 bytes code, 4 bytes data
            writer1 = RELWriter()
            writer1.write_program_name("MOD1")
            writer1.write_define_program_size(6)
            writer1.write_define_data_size(4)
            for _ in range(6):
                writer1.write_absolute_byte(0x00)
            writer1.write_end_program()
            writer1.write_end_file()

            mod1_path = os.path.join(tmpdir, "mod1.rel")
            with open(mod1_path, "wb") as f:
                f.write(writer1.get_bytes())

            # Module 2: 4 bytes code, 6 bytes data
            writer2 = RELWriter()
            writer2.write_program_name("MOD2")
            writer2.write_define_program_size(4)
            writer2.write_define_data_size(6)
            for _ in range(4):
                writer2.write_absolute_byte(0x00)
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

            # __END__ = 0x100 + (6+4) code + (4+6) data = 0x100 + 10 + 10 = 0x114
            _, value, _, _ = linker.globals['__END__']
            assert value == 0x114

    def test_end_symbol_in_sym_file(self):
        """Test that __END__ appears in generated symbol files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_define_entry_point(1, 0, "START")
            writer.write_define_program_size(3)
            writer.write_absolute_byte(0xC9)  # RET
            writer.write_absolute_byte(0x00)
            writer.write_absolute_byte(0x00)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)
            linker.link()

            sym_path = os.path.join(tmpdir, "test.sym")
            linker.save_sym(sym_path)

            with open(sym_path, "r") as f:
                content = f.read()

            assert "__END__" in content
            assert "0103 __END__" in content  # 0x100 + 3 bytes code

    def test_end_symbol_resolves_external(self):
        """Test that external references to __END__ are resolved."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create module that references __END__ externally
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_set_location(ADDR_ABSOLUTE, 0x100)
            writer.write_absolute_byte(0x21)  # LXI H opcode
            writer.write_absolute_byte(0x00)  # placeholder low
            writer.write_absolute_byte(0x00)  # placeholder high
            writer.write_absolute_byte(0xC9)  # RET
            writer.write_chain_external(ADDR_PROGRAM_REL, 0x101, "__END__")
            writer.write_define_program_size(4)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0x100
            linker.load_rel(rel_path)

            # Should resolve without error
            assert linker.resolve_externals() is True
            assert linker.link() is True

            # Verify __END__ was patched into the code
            # __END__ should be 0x104 (0x100 + 4 bytes code)
            # Output bytes: 21 04 01 C9
            assert linker.output[1] == 0x04  # low byte
            assert linker.output[2] == 0x01  # high byte

    def test_end_symbol_custom_origin(self):
        """Test __END__ with non-standard origin address."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_define_program_size(16)
            for _ in range(16):
                writer.write_absolute_byte(0x00)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            linker = Linker()
            linker.code_base = 0xE000  # High memory origin
            linker.load_rel(rel_path)
            linker.link()

            # __END__ = 0xE000 + 16 = 0xE010
            _, value, _, _ = linker.globals['__END__']
            assert value == 0xE010


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
