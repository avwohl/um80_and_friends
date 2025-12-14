"""
Test case sensitivity handling in the um80 toolchain.

The original Microsoft L80 linker was case-insensitive - all symbols were
converted to uppercase internally. This test verifies that behavior.
"""

import os
import tempfile
import pytest
from um80.relformat import RELWriter, RELReader


class TestRELFormatCaseSensitivity:
    """Test that REL format handles symbol case correctly."""

    def test_read_b_field_uppercases_symbols(self):
        """Verify _read_b_field returns uppercase symbols for L80 compatibility."""
        # Write a REL file with a lowercase symbol using the writer
        # (which uppercases on write), then verify reader also uppercases
        writer = RELWriter()
        writer.write_entry_symbol("lowercase")
        writer.write_end_file()
        data = writer.get_bytes()

        reader = RELReader(data)
        item = reader.read_item()

        assert item[0] == 'ENTRY_SYMBOL'
        assert item[1] == 'LOWERCAS'  # Truncated to 8 chars, uppercased

    def test_mixed_case_symbols_normalized(self):
        """Verify mixed case symbols are normalized to uppercase."""
        writer = RELWriter()
        writer.write_entry_symbol("MixedCase")
        writer.write_end_file()
        data = writer.get_bytes()

        reader = RELReader(data)
        item = reader.read_item()

        assert item[0] == 'ENTRY_SYMBOL'
        assert item[1] == 'MIXEDCAS'

    def test_already_uppercase_unchanged(self):
        """Verify uppercase symbols pass through correctly."""
        writer = RELWriter()
        writer.write_entry_symbol("ALREADY")
        writer.write_end_file()
        data = writer.get_bytes()

        reader = RELReader(data)
        item = reader.read_item()

        assert item[0] == 'ENTRY_SYMBOL'
        assert item[1] == 'ALREADY'

    def test_external_chain_uppercase(self):
        """Verify CHAIN_EXTERNAL symbol names are uppercased."""
        writer = RELWriter()
        writer.write_chain_external(0, 0x1234, "extfunc")
        writer.write_end_file()
        data = writer.get_bytes()

        reader = RELReader(data)
        item = reader.read_item()

        assert item[0] == 'CHAIN_EXTERNAL'
        assert item[2] == 'EXTFUNC'

    def test_define_entry_uppercase(self):
        """Verify DEFINE_ENTRY (PUBLIC) symbol names are uppercased."""
        writer = RELWriter()
        writer.write_define_entry_point(1, 0x100, "myPublic")
        writer.write_end_file()
        data = writer.get_bytes()

        reader = RELReader(data)
        item = reader.read_item()

        assert item[0] == 'DEFINE_ENTRY'
        assert item[2] == 'MYPUBLIC'

    def test_common_block_uppercase(self):
        """Verify COMMON block names are uppercased."""
        writer = RELWriter()
        writer.write_define_common_size(0, 100, "myCommon")
        writer.write_end_file()
        data = writer.get_bytes()

        reader = RELReader(data)
        item = reader.read_item()

        assert item[0] == 'DEFINE_COMMON_SIZE'
        assert item[2] == 'MYCOMMON'

    def test_program_name_uppercase(self):
        """Verify program names are uppercased."""
        writer = RELWriter()
        writer.write_program_name("myModule")
        writer.write_end_file()
        data = writer.get_bytes()

        reader = RELReader(data)
        item = reader.read_item()

        assert item[0] == 'PROGRAM_NAME'
        assert item[1] == 'MYMODULE'


class TestLinkerCaseSensitivity:
    """Integration tests for linker case sensitivity."""

    def test_linker_resolves_mixed_case_externals(self):
        """Verify linker resolves external references case-insensitively."""
        from um80.ul80 import Linker

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create module1.rel with lowercase public symbol
            writer1 = RELWriter()
            writer1.write_program_name("MOD1")
            writer1.write_define_entry_point(1, 0, "mysymbol")  # lowercase
            writer1.write_define_program_size(3)
            writer1.write_absolute_byte(0xC9)  # RET
            writer1.write_absolute_byte(0x00)
            writer1.write_absolute_byte(0x00)
            writer1.write_end_program()
            writer1.write_end_file()

            mod1_path = os.path.join(tmpdir, "mod1.rel")
            with open(mod1_path, "wb") as f:
                f.write(writer1.get_bytes())

            # Create module2.rel with uppercase external reference
            writer2 = RELWriter()
            writer2.write_program_name("MOD2")
            writer2.write_chain_external(0, 1, "MYSYMBOL")  # uppercase
            writer2.write_define_program_size(4)
            writer2.write_absolute_byte(0xCD)  # CALL
            writer2.write_absolute_byte(0x00)  # placeholder
            writer2.write_absolute_byte(0x00)
            writer2.write_absolute_byte(0xC9)  # RET
            writer2.write_end_program()
            writer2.write_end_file()

            mod2_path = os.path.join(tmpdir, "mod2.rel")
            with open(mod2_path, "wb") as f:
                f.write(writer2.get_bytes())

            # Link them
            linker = Linker()
            linker.load_rel(mod1_path)
            linker.load_rel(mod2_path)

            # Should resolve without "undefined symbol" error
            assert linker.resolve_externals() is True

    def test_sym_file_contains_uppercase(self):
        """Verify .SYM output contains uppercase symbols."""
        from um80.ul80 import Linker

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a module with mixed case symbols
            writer = RELWriter()
            writer.write_program_name("TEST")
            writer.write_define_entry_point(1, 0, "LowerCase")
            writer.write_define_entry_point(1, 3, "UPPERCASE")
            writer.write_define_entry_point(1, 6, "mixedCase")
            writer.write_define_program_size(9)
            for _ in range(9):
                writer.write_absolute_byte(0xC9)
            writer.write_end_program()
            writer.write_end_file()

            rel_path = os.path.join(tmpdir, "test.rel")
            with open(rel_path, "wb") as f:
                f.write(writer.get_bytes())

            # Link and generate symbol file
            linker = Linker()
            linker.load_rel(rel_path)
            linker.resolve_externals()
            linker.calculate_addresses()

            sym_path = os.path.join(tmpdir, "test.sym")
            linker.save_sym(sym_path)

            # Read and verify symbol file
            with open(sym_path, "r") as f:
                content = f.read()

            # All symbols should be uppercase
            assert "LOWERCAS" in content
            assert "UPPERCAS" in content
            assert "MIXEDCAS" in content
            # No lowercase versions should exist
            assert "LowerCase" not in content
            assert "mixedCase" not in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
