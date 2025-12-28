#!/usr/bin/env python3
"""
ul80 - Microsoft LINK-80 compatible linker for Linux.

Usage: ul80 [-o output.com] file1.rel file2.rel ... [lib1.lib ...]

Supports both .rel object files and .lib library files (created by ulib80).
Library modules are automatically extracted to resolve undefined symbols.
"""

import sys
import os
import argparse
from pathlib import Path

from um80 import __version__
from um80.relformat import *
from um80.ulib80 import Library, LibraryError


class LinkerError(Exception):
    """Linker error."""
    pass


class Module:
    """A loaded REL module."""
    def __init__(self, name):
        self.name = name
        self.code = bytearray()  # Loaded code/data
        self.code_size = 0
        self.data_size = 0
        self.code_base = 0  # Will be set during linking
        self.data_base = 0
        self.code_start = 0  # Starting offset within code buffer (for absolute ORG)

        # Symbols defined in this module
        self.publics = {}  # name -> (value, seg_type)

        # External references (chains to be fixed up)
        self.externals = {}  # name -> list of (offset_in_module, seg_type)

        # Internal chains (forward references resolved within module)
        self.chains = {}  # offset -> list of offsets to fix

        # Common blocks
        self.commons = {}  # name -> size

        # Relocation info: list of (offset, seg_type) for addresses that need relocation
        self.relocations = []

        # Segment buffer offsets: maps segment type to buffer offset where that segment starts
        # Used to convert segment-relative addresses to buffer offsets during chain following
        self.seg_buf_start = {}  # seg_type -> buffer start offset


class Linker:
    """LINK-80 compatible linker."""

    def __init__(self):
        self.modules = []
        self.globals = {}  # name -> (module_idx, value, seg_type, is_defined)
        self.commons = {}  # name -> size (largest wins)

        # Pre-define __END__ symbol (value computed in calculate_addresses)
        # mod_idx=0 is placeholder, value will be absolute address
        self.globals['__END__'] = (0, 0, ADDR_ABSOLUTE, True)

        self.code_base = 0x0103  # Default CP/M load address + 3 for JMP
        self.data_base = None  # Will be after code if not specified
        self.common_base = None  # After data

        self.output = bytearray()
        self.entry_point = None  # (value, seg_type) or None

        self.errors = []
        self.warnings = []

    def error(self, msg):
        self.errors.append(f"Error: {msg}")

    def warning(self, msg):
        self.warnings.append(f"Warning: {msg}")

    def load_rel(self, filename):
        """Load a REL file and add to modules list."""
        with open(filename, 'rb') as f:
            data = f.read()

        reader = RELReader(data)
        module = Module(Path(filename).stem.upper())

        current_loc = 0  # Position within current segment
        current_seg = ADDR_PROGRAM_REL  # Default to code segment
        first_loc_set = False  # Track if we've seen the first location

        # Use separate buffers for each segment to avoid overwrites when
        # switching between segments (e.g., CSEG -> DSEG -> CSEG)
        seg_buffers = {}  # seg_type -> bytearray

        def get_seg_buffer():
            """Get or create buffer for current segment."""
            if current_seg not in seg_buffers:
                seg_buffers[current_seg] = bytearray()
            return seg_buffers[current_seg]

        def write_byte_to_seg(value):
            """Write a byte at current_loc in current segment's buffer."""
            buf = get_seg_buffer()
            while len(buf) <= current_loc:
                buf.append(0)
            buf[current_loc] = value

        # Track relocations with segment-relative offsets before combining
        pending_relocations = []  # (seg_type, seg_offset, reloc_type)
        pending_externals = []  # (name, seg_type, head_offset)
        pending_chains = []  # (chain_seg, head_offset, cur_seg, cur_offset)

        while True:
            try:
                item = reader.read_item()
            except EOFError:
                break

            if item is None:
                break

            item_type = item[0]

            if item_type == 'ABSOLUTE_BYTE':
                write_byte_to_seg(item[1])
                current_loc += 1

            elif item_type == 'PROGRAM_REL':
                # 16-bit program-relative value - needs relocation
                value = item[1]
                write_byte_to_seg(value & 0xFF)
                # Record relocation at low byte position
                pending_relocations.append((current_seg, current_loc, ADDR_PROGRAM_REL))
                current_loc += 1
                write_byte_to_seg((value >> 8) & 0xFF)
                current_loc += 1

            elif item_type == 'DATA_REL':
                # 16-bit data-relative value - needs relocation
                value = item[1]
                write_byte_to_seg(value & 0xFF)
                pending_relocations.append((current_seg, current_loc, ADDR_DATA_REL))
                current_loc += 1
                write_byte_to_seg((value >> 8) & 0xFF)
                current_loc += 1

            elif item_type == 'COMMON_REL':
                # 16-bit common-relative value - needs relocation
                value = item[1]
                write_byte_to_seg(value & 0xFF)
                pending_relocations.append((current_seg, current_loc, ADDR_COMMON_REL))
                current_loc += 1
                write_byte_to_seg((value >> 8) & 0xFF)
                current_loc += 1

            elif item_type == 'PROGRAM_NAME':
                module.name = item[1]

            elif item_type == 'ENTRY_SYMBOL':
                # Symbol this module exports (for library search)
                pass

            elif item_type == 'DEFINE_ENTRY':
                # PUBLIC symbol definition
                a_field, name = item[1], item[2]
                addr_type, value = a_field
                module.publics[name] = (value, addr_type)

            elif item_type == 'CHAIN_EXTERNAL':
                # External reference chain - store segment-relative for now
                a_field, name = item[1], item[2]
                addr_type, head = a_field
                pending_externals.append((name, addr_type, head))

            elif item_type == 'SET_LOC':
                a_field = item[1]
                addr_type, value = a_field
                current_loc = value
                current_seg = addr_type
                # Track the first absolute location as code_start
                if not first_loc_set and addr_type == ADDR_ABSOLUTE:
                    module.code_start = value
                    first_loc_set = True

            elif item_type == 'CHAIN_ADDRESS':
                # Internal forward reference chain - store segment-relative
                a_field = item[1]
                addr_type, head = a_field
                pending_chains.append((addr_type, head, current_seg, current_loc))

            elif item_type == 'DEFINE_PROG_SIZE':
                a_field = item[1]
                _, size = a_field
                module.code_size = size

            elif item_type == 'DEFINE_DATA_SIZE':
                a_field = item[1]
                _, size = a_field
                module.data_size = size

            elif item_type == 'DEFINE_COMMON_SIZE':
                a_field, name = item[1], item[2]
                _, size = a_field
                module.commons[name] = size

            elif item_type == 'SELECT_COMMON':
                # Switch to common block
                pass

            elif item_type == 'REQUEST_LIB':
                # Library search request
                pass

            elif item_type == 'END_PROGRAM':
                # End of module
                pass

            elif item_type == 'END_FILE':
                break

        # Combine segment buffers into single code buffer
        # Order: ASEG (absolute), CSEG (program), DSEG (data), COMMON
        code_bytes = bytearray()
        seg_buf_start = {}

        for seg_type in [ADDR_ABSOLUTE, ADDR_PROGRAM_REL, ADDR_DATA_REL, ADDR_COMMON_REL]:
            if seg_type in seg_buffers:
                seg_buf_start[seg_type] = len(code_bytes)
                code_bytes.extend(seg_buffers[seg_type])

        # Convert segment-relative relocations to buffer offsets
        for seg_type, seg_offset, reloc_type in pending_relocations:
            if seg_type in seg_buf_start:
                buf_offset = seg_buf_start[seg_type] + seg_offset
                module.relocations.append((buf_offset, reloc_type))

        # Convert pending externals to buffer offsets
        for name, addr_type, head in pending_externals:
            if name not in module.externals:
                module.externals[name] = []
            if addr_type in seg_buf_start:
                buf_head = seg_buf_start[addr_type] + head
            else:
                buf_head = seg_buf_start.get(ADDR_ABSOLUTE, len(code_bytes)) + head
            module.externals[name].append((buf_head, addr_type))

        # Convert pending chains to buffer offsets
        for chain_seg, head, cur_seg, cur_offset in pending_chains:
            if chain_seg in seg_buf_start:
                buf_head = seg_buf_start[chain_seg] + head
            else:
                buf_head = len(code_bytes) + head
            if cur_seg in seg_buf_start:
                buf_cur = seg_buf_start[cur_seg] + cur_offset
            else:
                buf_cur = len(code_bytes) + cur_offset
            if buf_head not in module.chains:
                module.chains[buf_head] = []
            module.chains[buf_head].append((buf_cur, chain_seg))

        module.code = code_bytes
        module.seg_buf_start = seg_buf_start  # Save for chain following during link
        self.modules.append(module)

        # Register public symbols
        mod_idx = len(self.modules) - 1
        for name, (value, seg_type) in module.publics.items():
            if name in self.globals and self.globals[name][3]:
                self.warning(f"Multiple definition of '{name}'")
            else:
                self.globals[name] = (mod_idx, value, seg_type, True)

        # Track common block sizes
        for name, size in module.commons.items():
            if name not in self.commons or size > self.commons[name]:
                self.commons[name] = size

        return True

    def load_rel_data(self, name, data):
        """Load REL data from bytes (e.g., from a library module)."""
        reader = RELReader(data)
        module = Module(name.upper())

        current_loc = 0  # Position within current segment
        current_seg = ADDR_PROGRAM_REL  # Default to code segment
        first_loc_set = False  # Track if we've seen the first location

        # Use separate buffers for each segment to avoid overwrites when
        # switching between segments (e.g., CSEG -> DSEG -> CSEG)
        seg_buffers = {}  # seg_type -> bytearray

        def get_seg_buffer():
            """Get or create buffer for current segment."""
            if current_seg not in seg_buffers:
                seg_buffers[current_seg] = bytearray()
            return seg_buffers[current_seg]

        def write_byte_to_seg(value):
            """Write a byte at current_loc in current segment's buffer."""
            buf = get_seg_buffer()
            while len(buf) <= current_loc:
                buf.append(0)
            buf[current_loc] = value

        # Track relocations with segment-relative offsets before combining
        pending_relocations = []  # (seg_type, seg_offset, reloc_type)
        pending_externals = []  # (name, seg_type, head_offset)
        pending_chains = []  # (chain_seg, head_offset, cur_seg, cur_offset)

        while True:
            try:
                item = reader.read_item()
            except EOFError:
                break

            if item is None:
                break

            item_type = item[0]

            if item_type == 'ABSOLUTE_BYTE':
                write_byte_to_seg(item[1])
                current_loc += 1

            elif item_type == 'PROGRAM_REL':
                # 16-bit program-relative value - needs relocation
                value = item[1]
                write_byte_to_seg(value & 0xFF)
                # Record relocation at low byte position
                pending_relocations.append((current_seg, current_loc, ADDR_PROGRAM_REL))
                current_loc += 1
                write_byte_to_seg((value >> 8) & 0xFF)
                current_loc += 1

            elif item_type == 'DATA_REL':
                # 16-bit data-relative value - needs relocation
                value = item[1]
                write_byte_to_seg(value & 0xFF)
                pending_relocations.append((current_seg, current_loc, ADDR_DATA_REL))
                current_loc += 1
                write_byte_to_seg((value >> 8) & 0xFF)
                current_loc += 1

            elif item_type == 'COMMON_REL':
                # 16-bit common-relative value - needs relocation
                value = item[1]
                write_byte_to_seg(value & 0xFF)
                pending_relocations.append((current_seg, current_loc, ADDR_COMMON_REL))
                current_loc += 1
                write_byte_to_seg((value >> 8) & 0xFF)
                current_loc += 1

            elif item_type == 'PROGRAM_NAME':
                module.name = item[1]

            elif item_type == 'ENTRY_SYMBOL':
                # Symbol this module exports (for library search)
                pass

            elif item_type == 'DEFINE_ENTRY':
                # PUBLIC symbol definition
                a_field, sym_name = item[1], item[2]
                addr_type, value = a_field
                module.publics[sym_name] = (value, addr_type)

            elif item_type == 'CHAIN_EXTERNAL':
                # External reference chain - store segment-relative for now
                a_field, sym_name = item[1], item[2]
                addr_type, head = a_field
                pending_externals.append((sym_name, addr_type, head))

            elif item_type == 'SET_LOC':
                a_field = item[1]
                addr_type, value = a_field
                current_loc = value
                current_seg = addr_type
                # Track the first absolute location as code_start
                if not first_loc_set and addr_type == ADDR_ABSOLUTE:
                    module.code_start = value
                    first_loc_set = True

            elif item_type == 'CHAIN_ADDRESS':
                # Internal forward reference chain - store segment-relative
                a_field = item[1]
                addr_type, head = a_field
                pending_chains.append((addr_type, head, current_seg, current_loc))

            elif item_type == 'DEFINE_PROG_SIZE':
                a_field = item[1]
                _, size = a_field
                module.code_size = size

            elif item_type == 'DEFINE_DATA_SIZE':
                a_field = item[1]
                _, size = a_field
                module.data_size = size

            elif item_type == 'DEFINE_COMMON_SIZE':
                a_field, sym_name = item[1], item[2]
                _, size = a_field
                module.commons[sym_name] = size

            elif item_type == 'SELECT_COMMON':
                # Switch to common block
                pass

            elif item_type == 'REQUEST_LIB':
                # Library search request
                pass

            elif item_type == 'END_PROGRAM':
                # End of module
                pass

            elif item_type == 'END_FILE':
                break

        # Combine segment buffers into single code buffer
        # Order: ASEG (absolute), CSEG (program), DSEG (data), COMMON
        code_bytes = bytearray()
        seg_buf_start = {}

        for seg_type in [ADDR_ABSOLUTE, ADDR_PROGRAM_REL, ADDR_DATA_REL, ADDR_COMMON_REL]:
            if seg_type in seg_buffers:
                seg_buf_start[seg_type] = len(code_bytes)
                code_bytes.extend(seg_buffers[seg_type])

        # Convert segment-relative relocations to buffer offsets
        for seg_type, seg_offset, reloc_type in pending_relocations:
            if seg_type in seg_buf_start:
                buf_offset = seg_buf_start[seg_type] + seg_offset
                module.relocations.append((buf_offset, reloc_type))

        # Convert pending externals to buffer offsets
        for sym_name, addr_type, head in pending_externals:
            if sym_name not in module.externals:
                module.externals[sym_name] = []
            if addr_type in seg_buf_start:
                buf_head = seg_buf_start[addr_type] + head
            else:
                buf_head = seg_buf_start.get(ADDR_ABSOLUTE, len(code_bytes)) + head
            module.externals[sym_name].append((buf_head, addr_type))

        # Convert pending chains to buffer offsets
        for chain_seg, head, cur_seg, cur_offset in pending_chains:
            if chain_seg in seg_buf_start:
                buf_head = seg_buf_start[chain_seg] + head
            else:
                buf_head = len(code_bytes) + head
            if cur_seg in seg_buf_start:
                buf_cur = seg_buf_start[cur_seg] + cur_offset
            else:
                buf_cur = len(code_bytes) + cur_offset
            if buf_head not in module.chains:
                module.chains[buf_head] = []
            module.chains[buf_head].append((buf_cur, chain_seg))

        module.code = code_bytes
        module.seg_buf_start = seg_buf_start  # Save for chain following during link
        self.modules.append(module)

        # Register public symbols
        mod_idx = len(self.modules) - 1
        for sym_name, (value, seg_type) in module.publics.items():
            if sym_name in self.globals and self.globals[sym_name][3]:
                self.warning(f"Multiple definition of '{sym_name}'")
            else:
                self.globals[sym_name] = (mod_idx, value, seg_type, True)

        # Track common block sizes
        for sym_name, size in module.commons.items():
            if sym_name not in self.commons or size > self.commons[sym_name]:
                self.commons[sym_name] = size

        return True

    def get_undefined_symbols(self):
        """Get list of undefined external symbols."""
        undefined = set()
        for module in self.modules:
            for name in module.externals:
                # Parse "SYMBOL+N" format - check base symbol
                base_name = name
                if '+' in name:
                    parts = name.rsplit('+', 1)
                    try:
                        int(parts[1])  # Valid offset?
                        base_name = parts[0]
                    except ValueError:
                        pass  # Not a valid offset, use full name

                if base_name not in self.globals or not self.globals[base_name][3]:
                    undefined.add(base_name)
        return undefined

    def resolve_externals(self):
        """Check that all external references can be resolved."""
        undefined = []
        for module in self.modules:
            for name in module.externals:
                # Parse "SYMBOL+N" format - check base symbol
                base_name = name
                if '+' in name:
                    parts = name.rsplit('+', 1)
                    try:
                        int(parts[1])  # Valid offset?
                        base_name = parts[0]
                    except ValueError:
                        pass  # Not a valid offset, use full name

                if base_name not in self.globals or not self.globals[base_name][3]:
                    undefined.append(name)

        if undefined:
            for name in set(undefined):
                self.error(f"Undefined symbol: {name}")
            return False
        return True

    def calculate_addresses(self):
        """Calculate base addresses for all modules."""
        # Calculate total code size
        total_code = 0
        for module in self.modules:
            module.code_base = self.code_base + total_code
            total_code += module.code_size if module.code_size else len(module.code)

        # Data follows code
        if self.data_base is None:
            self.data_base = self.code_base + total_code

        total_data = 0
        for module in self.modules:
            module.data_base = self.data_base + total_data
            total_data += module.data_size

        # Common follows data
        if self.common_base is None:
            self.common_base = self.data_base + total_data

        # Calculate total common size
        total_common = sum(self.commons.values())

        # Add __END__ symbol pointing to first free byte after all segments
        # This is an absolute address, not module-relative
        end_addr = self.common_base + total_common
        self.globals['__END__'] = (0, end_addr, ADDR_ABSOLUTE, True)

    def relocate_value(self, module, value, seg_type):
        """Relocate a value based on its segment type."""
        if seg_type == ADDR_ABSOLUTE:
            return value
        elif seg_type == ADDR_PROGRAM_REL:
            return value + module.code_base
        elif seg_type == ADDR_DATA_REL:
            return value + module.data_base
        elif seg_type == ADDR_COMMON_REL:
            return value + self.common_base
        return value

    def link(self):
        """Link all loaded modules."""
        if not self.resolve_externals():
            return False

        self.calculate_addresses()

        # Build output starting at origin (code_base of first module)
        # Determine output base address (lowest module address)
        self.output_base = min(m.code_base for m in self.modules)

        # Calculate total output size - use actual buffer length which includes
        # both CSEG and initialized DSEG data (DB/DW in DSEG)
        total_size = 0
        for module in self.modules:
            # Actual bytes to output = full code buffer minus code_start offset
            actual_bytes = len(module.code) - module.code_start
            end_addr = module.code_base + actual_bytes - self.output_base
            if end_addr > total_size:
                total_size = end_addr

        self.output = bytearray(total_size)

        # Copy and relocate each module
        for module in self.modules:
            # Copy all bytes in the code buffer (CSEG + initialized DSEG)
            actual_bytes = len(module.code) - module.code_start
            dest_offset = module.code_base - self.output_base

            # Copy code bytes from the code_start position in the source buffer
            # (accounts for absolute ORG where code is stored at offset > 0)
            src_start = module.code_start
            for i in range(actual_bytes):
                src_idx = src_start + i
                if src_idx < len(module.code) and dest_offset + i < len(self.output):
                    self.output[dest_offset + i] = module.code[src_idx]

        # Fix up external references
        for mod_idx, module in enumerate(self.modules):
            dest_offset = module.code_base - self.output_base
            src_start = module.code_start  # For absolute ORG adjustment

            for name, refs in module.externals.items():
                # Parse "SYMBOL+N" format for expression offsets
                expr_offset = 0
                base_name = name
                if '+' in name:
                    parts = name.rsplit('+', 1)
                    base_name = parts[0]
                    try:
                        expr_offset = int(parts[1])
                    except ValueError:
                        pass  # Not a valid offset, use full name

                if base_name not in self.globals:
                    continue

                target_mod_idx, target_value, target_seg_type, _ = self.globals[base_name]
                target_module = self.modules[target_mod_idx]
                target_addr = self.relocate_value(target_module, target_value, target_seg_type)
                target_addr += expr_offset  # Add expression offset (e.g., +1 for SYMBOL+1)

                for head, ref_seg_type in refs:
                    # Follow the chain and fix up each reference
                    # head is now a buffer offset, convert to output offset
                    offset = head - src_start
                    seg_base = module.seg_buf_start.get(ref_seg_type, 0)
                    visited = set()  # Prevent infinite loops
                    while offset not in visited and offset >= 0:
                        visited.add(offset)
                        abs_offset = dest_offset + offset
                        if abs_offset + 1 < len(self.output) and abs_offset >= 0:
                            # Get value at this location (this is the next chain link)
                            # For ADDR_ABSOLUTE, values are absolute addresses
                            # For relative segments, values are segment-relative offsets
                            value = self.output[abs_offset] | (self.output[abs_offset + 1] << 8)

                            # Chain format: each link points to previous reference
                            # End of chain is marked by value 0
                            # Resolve this location with target address
                            self.output[abs_offset] = target_addr & 0xFF
                            self.output[abs_offset + 1] = (target_addr >> 8) & 0xFF

                            if value == 0:
                                # End of chain
                                break
                            else:
                                # Follow chain to previous reference
                                # Convert segment-relative value to output offset using seg_buf_start
                                offset = seg_base + value - src_start
                        else:
                            break

        # Apply relocations for program-relative, data-relative, and common-relative addresses
        for module in self.modules:
            dest_offset = module.code_base - self.output_base
            src_start = module.code_start  # For absolute ORG adjustment
            for buf_offset, seg_type in module.relocations:
                # buf_offset is now a buffer offset, convert to output offset
                abs_offset = dest_offset + (buf_offset - src_start)
                if abs_offset >= 0 and abs_offset + 1 < len(self.output):
                    # Read current value
                    value = self.output[abs_offset] | (self.output[abs_offset + 1] << 8)
                    # Apply relocation based on segment type
                    if seg_type == ADDR_PROGRAM_REL:
                        value += module.code_base
                    elif seg_type == ADDR_DATA_REL:
                        value += module.data_base
                    elif seg_type == ADDR_COMMON_REL:
                        value += self.common_base
                    # Write relocated value
                    self.output[abs_offset] = value & 0xFF
                    self.output[abs_offset + 1] = (value >> 8) & 0xFF

        return True

    def save_com(self, filename):
        """Save as CP/M .COM file."""
        # For .COM file, code loads and executes at 0x100
        # Only prepend JMP if entry point is not at 0x100
        with open(filename, 'wb') as f:
            f.write(bytes(self.output))
            # Pad to CP/M record boundary (128 bytes)
            remainder = len(self.output) % 128
            if remainder:
                f.write(bytes(128 - remainder))

    def save_hex(self, filename):
        """Save as Intel HEX format."""
        with open(filename, 'w') as f:
            addr = self.output_base
            data = bytes(self.output)

            idx = 0
            while idx < len(data):
                # Write 16 bytes per line
                line_len = min(16, len(data) - idx)
                line_data = data[idx:idx + line_len]

                # Calculate checksum
                checksum = line_len + (addr >> 8) + (addr & 0xFF) + 0  # record type 0
                checksum += sum(line_data)
                checksum = (~checksum + 1) & 0xFF

                # Write line
                hex_data = ''.join(f'{b:02X}' for b in line_data)
                f.write(f':{line_len:02X}{addr:04X}00{hex_data}{checksum:02X}\n')

                addr += line_len
                idx += line_len

            # Write EOF record
            f.write(':00000001FF\n')

    def save_prl(self, filename):
        """Save as MP/M .PRL (Page Relocatable) format.

        PRL files can be loaded at any page boundary. The relocation bitmap
        marks high bytes of 16-bit addresses that need adjustment when loaded
        at a different page than 0x100.

        Format:
        - 256-byte header (code length at offset 1-2, BSS at 4-5)
        - Code/data (code_length bytes)
        - Relocation bitmap ((code_length + 7) / 8 bytes)
        """
        code_length = len(self.output)

        # Calculate total BSS (uninitialized data) size from all modules
        # BSS = declared DSEG size - initialized DSEG bytes actually emitted
        # Initialized DSEG bytes = total buffer - code_start - CSEG size
        bss_size = 0
        for module in self.modules:
            actual_bytes = len(module.code) - module.code_start
            cseg_size = module.code_size if module.code_size else 0
            initialized_dseg = actual_bytes - cseg_size
            uninitialized_dseg = module.data_size - initialized_dseg
            if uninitialized_dseg > 0:
                bss_size += uninitialized_dseg

        # Build relocation bitmap - one bit per byte of code
        # Bit is set if corresponding byte is a HIGH byte of relocatable address
        bitmap_size = (code_length + 7) // 8
        bitmap = bytearray(bitmap_size)

        # Collect all relocation high-byte offsets from all modules
        for module in self.modules:
            dest_offset = module.code_base - self.output_base
            src_start = module.code_start

            for buf_offset, seg_type in module.relocations:
                # buf_offset is buffer offset, points to low byte of 16-bit address
                # high byte is at buf_offset + 1
                abs_offset = dest_offset + (buf_offset - src_start)
                high_byte_offset = abs_offset + 1

                if 0 <= high_byte_offset < code_length:
                    # Set bit in bitmap
                    # Bit 7 of byte 0 = code byte 0, bit 6 = code byte 1, etc.
                    byte_idx = high_byte_offset // 8
                    bit_idx = 7 - (high_byte_offset % 8)
                    bitmap[byte_idx] |= (1 << bit_idx)

        # Build header (256 bytes)
        # MP/M II PRL format (verified from PRLCM.PLM):
        # Byte 0: Type/reserved (0)
        # Bytes 1-2: Code length (16-bit little-endian)
        # Byte 3: Reserved (0)
        # Bytes 4-5: BSS/extra size (optional)
        # Bytes 6-255: Reserved (0)
        header = bytearray(256)
        header[0] = 0  # Type/reserved
        header[1] = code_length & 0xFF  # Code length low byte
        header[2] = (code_length >> 8) & 0xFF  # Code length high byte
        header[3] = 0  # Reserved
        header[4] = bss_size & 0xFF  # BSS size low byte
        header[5] = (bss_size >> 8) & 0xFF  # BSS size high byte
        header[6] = 0  # Always 0
        header[7] = 0  # Load address low (0 for PRL)
        header[8] = 0  # Load address high (0 for PRL)
        # Bytes 9-255 remain 0

        with open(filename, 'wb') as f:
            f.write(bytes(header))
            f.write(bytes(self.output))
            f.write(bytes(bitmap))
            # Pad to CP/M record boundary (128 bytes)
            total_size = 256 + code_length + bitmap_size
            remainder = total_size % 128
            if remainder:
                f.write(bytes(128 - remainder))

    def save_sym(self, filename):
        """Save symbol table file (.SYM) compatible with SID/ZSID debuggers.

        Format: ADDR NAME (one per line, LF endings)
        Sorted alphabetically by symbol name.
        """
        # Build list of (name, address) for all defined globals
        symbols = []
        for name, (mod_idx, value, seg_type, is_defined) in self.globals.items():
            if is_defined:
                module = self.modules[mod_idx]
                addr = self.relocate_value(module, value, seg_type)
                symbols.append((name, addr))

        # Sort alphabetically by symbol name (DRI convention)
        symbols.sort(key=lambda x: x[0])

        with open(filename, 'w') as f:
            # SID .SYM format: ADDR NAME (one per line)
            # Use LF line endings - cpmemu converts to CR-LF in text mode
            for name, addr in symbols:
                f.write(f"{addr:04X} {name}\n")


def main():
    parser = argparse.ArgumentParser(description='ul80 - LINK-80 compatible linker')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('inputs', nargs='+', help='Input .REL and .LIB files')
    parser.add_argument('-o', '--output', help='Output file (default: first input with .com)')
    parser.add_argument('-x', '--hex', action='store_true', help='Output Intel HEX format')
    parser.add_argument('--prl', action='store_true', help='Output MP/M .PRL (Page Relocatable) format')
    parser.add_argument('-s', '--sym', action='store_true', help='Generate .SYM symbol file')
    parser.add_argument('-S', '--sym-file', metavar='FILE', help='Generate .SYM symbol file with specified name')
    parser.add_argument('-p', '--origin', type=lambda x: int(x, 16) if not x.startswith(('0x', '0X', '0o', '0O', '0b', '0B')) else int(x, 0), default=None,
                       help='Program origin as hex (e.g., E000, 0xE000, default: 0 for PRL, 100 for COM)')

    args = parser.parse_args()

    linker = Linker()
    # Default origin: 0 for PRL/SPR (page relocatable), 0x100 for COM (CP/M TPA)
    if args.origin is None:
        args.origin = 0 if args.prl else 0x100
    linker.code_base = args.origin

    # Separate .rel and .lib files
    rel_files = []
    lib_files = []
    for filename in args.inputs:
        if not os.path.exists(filename):
            print(f"Error: File not found: {filename}", file=sys.stderr)
            sys.exit(1)
        ext = Path(filename).suffix.lower()
        if ext == '.lib':
            lib_files.append(filename)
        else:
            rel_files.append(filename)

    # Load all .rel files first
    for filename in rel_files:
        if not linker.load_rel(filename):
            print(f"Error loading {filename}", file=sys.stderr)
            sys.exit(1)

    # Load libraries
    libraries = []
    for filename in lib_files:
        try:
            lib = Library.load(filename)
            libraries.append((filename, lib))
        except LibraryError as e:
            print(f"Error loading library {filename}: {e}", file=sys.stderr)
            sys.exit(1)

    # Resolve undefined symbols from libraries
    # Keep searching until no more symbols can be resolved
    modules_loaded = set()  # Track which library modules we've already loaded
    while libraries:
        undefined = linker.get_undefined_symbols()
        if not undefined:
            break

        resolved_any = False
        for symbol in list(undefined):
            # Search libraries for this symbol
            for lib_filename, lib in libraries:
                module_name = lib.find_module_for_symbol(symbol)
                if module_name:
                    # Check if we already loaded this module
                    lib_mod_key = (lib_filename, module_name)
                    if lib_mod_key in modules_loaded:
                        continue

                    # Get the module and load its REL data
                    lib_module = lib.get_module(module_name)
                    if lib_module:
                        linker.load_rel_data(module_name, lib_module.data)
                        modules_loaded.add(lib_mod_key)
                        resolved_any = True
                        break
            if resolved_any:
                break  # Restart the search with updated undefined symbols

        if not resolved_any:
            # No more symbols can be resolved from libraries
            break

    # Link
    if not linker.link():
        for err in linker.errors:
            print(err, file=sys.stderr)
        sys.exit(1)

    # Determine output filename
    if args.output:
        output_path = args.output
    else:
        if args.hex:
            ext = '.hex'
        elif args.prl:
            ext = '.prl'
        else:
            ext = '.com'
        output_path = Path(args.inputs[0]).with_suffix(ext)

    # Save output
    if args.hex:
        linker.save_hex(str(output_path))
    elif args.prl:
        linker.save_prl(str(output_path))
    else:
        linker.save_com(str(output_path))

    # Save symbol file if requested
    if args.sym or args.sym_file:
        if args.sym_file:
            sym_path = Path(args.sym_file)
        else:
            sym_path = Path(output_path).with_suffix('.sym')
        linker.save_sym(str(sym_path))
        print(f"Symbol file -> {sym_path}")

    # Report warnings
    for warn in linker.warnings:
        print(warn, file=sys.stderr)

    print(f"Linked -> {output_path}")
    print(f"  Modules: {len(linker.modules)}")
    print(f"  Global symbols: {len(linker.globals)}")

    sys.exit(0)


if __name__ == '__main__':
    main()
