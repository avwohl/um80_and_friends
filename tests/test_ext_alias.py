"""Test external symbol aliases (EQU external+offset)."""

import pytest
import tempfile
import os


def assemble(source, tmpdir, filename="test.mac"):
    """Assemble source code and return REL bytes."""
    from um80.um80 import Assembler
    src_path = os.path.join(tmpdir, filename)
    with open(src_path, "w") as f:
        f.write(source)
    asm = Assembler()
    if not asm.assemble(src_path):
        raise AssertionError(f"Assembly failed: {asm.errors}")
    return asm.output.get_bytes()


def link(modules):
    """Link multiple modules (list of (name, rel_bytes)) and return output."""
    from um80.ul80 import Linker
    linker = Linker()
    for name, rel_bytes in modules:
        linker.load_rel_data(name, rel_bytes)
    if not linker.link():
        raise AssertionError(f"Link failed: {linker.errors}")
    return linker.output, linker.globals


def test_basic_external_alias():
    """Test basic EQU external+offset alias."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_src = """\
    .Z80
    CSEG
    PUBLIC  FUNC
FUNC:
    LD  A,10
    ADD A,B
    RET
    END
"""
        alias_src = """\
    .Z80
    CSEG
    EXTRN   FUNC
    PUBLIC  FUNC_ALT
FUNC_ALT    EQU FUNC+2
    END
"""
        main_src = """\
    .Z80
    CSEG
    EXTRN   FUNC
    EXTRN   FUNC_ALT
START:
    CALL    FUNC
    CALL    FUNC_ALT
    RET
    END START
"""
        base_rel = assemble(base_src, tmpdir, "base.mac")
        alias_rel = assemble(alias_src, tmpdir, "alias.mac")
        main_rel = assemble(main_src, tmpdir, "main.mac")

        output, globals_table = link([
            ('MAIN', main_rel),
            ('ALIAS', alias_rel),
            ('BASE', base_rel),
        ])

        # Check that FUNC_ALT is defined and equals FUNC+2
        assert 'FUNC' in globals_table
        assert 'FUNC_ALT' in globals_table

        func_addr = globals_table['FUNC'][1]  # value
        func_alt_addr = globals_table['FUNC_ALT'][1]

        # FUNC_ALT should be FUNC+2
        assert func_alt_addr == func_addr + 2, f"FUNC_ALT ({func_alt_addr}) should be FUNC ({func_addr}) + 2"


def test_external_alias_zero_offset():
    """Test EQU external+0 (simple alias)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_src = """\
    .Z80
    CSEG
    PUBLIC  ORIG
ORIG:
    NOP
    RET
    END
"""
        alias_src = """\
    .Z80
    CSEG
    EXTRN   ORIG
    PUBLIC  ALIAS
ALIAS   EQU ORIG
    END
"""
        main_src = """\
    .Z80
    CSEG
    EXTRN   ALIAS
START:
    CALL    ALIAS
    RET
    END START
"""
        base_rel = assemble(base_src, tmpdir, "base.mac")
        alias_rel = assemble(alias_src, tmpdir, "alias.mac")
        main_rel = assemble(main_src, tmpdir, "main.mac")

        output, globals_table = link([
            ('MAIN', main_rel),
            ('ALIAS', alias_rel),
            ('BASE', base_rel),
        ])

        # ALIAS should equal ORIG
        orig_addr = globals_table['ORIG'][1]
        alias_addr = globals_table['ALIAS'][1]
        assert alias_addr == orig_addr


def test_chained_external_alias():
    """Test using an aliased symbol in code that references it with an offset."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_src = """\
    .Z80
    CSEG
    PUBLIC  BASE
BASE:
    LD  A,1
    LD  A,2
    LD  A,3
    RET
    END
"""
        alias_src = """\
    .Z80
    CSEG
    EXTRN   BASE
    PUBLIC  MID
MID EQU BASE+2
    END
"""
        main_src = """\
    .Z80
    CSEG
    EXTRN   MID
START:
    ; Use MID+2 (which is BASE+4)
    CALL    MID+2
    RET
    END START
"""
        base_rel = assemble(base_src, tmpdir, "base.mac")
        alias_rel = assemble(alias_src, tmpdir, "alias.mac")
        main_rel = assemble(main_src, tmpdir, "main.mac")

        output, globals_table = link([
            ('MAIN', main_rel),
            ('ALIAS', alias_rel),
            ('BASE', base_rel),
        ])

        # MID should be BASE+2
        base_addr = globals_table['BASE'][1]
        mid_addr = globals_table['MID'][1]
        assert mid_addr == base_addr + 2


def test_external_alias_undefined_base():
    """Test that aliased symbol with undefined base produces error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        alias_src = """\
    .Z80
    CSEG
    EXTRN   NONEXISTENT
    PUBLIC  ALIAS
ALIAS   EQU NONEXISTENT+5
    END
"""
        main_src = """\
    .Z80
    CSEG
    EXTRN   ALIAS
START:
    CALL    ALIAS
    RET
    END START
"""
        alias_rel = assemble(alias_src, tmpdir, "alias.mac")
        main_rel = assemble(main_src, tmpdir, "main.mac")

        from um80.ul80 import Linker
        linker = Linker()
        linker.load_rel_data('MAIN', main_rel)
        linker.load_rel_data('ALIAS', alias_rel)

        # Should fail to link
        result = linker.link()
        assert not result
        assert any('NONEXISTENT' in e for e in linker.errors)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
