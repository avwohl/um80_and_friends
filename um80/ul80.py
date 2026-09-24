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

        # Aliased entry points: SYMBOL EQU EXTERNAL+offset made PUBLIC
        # These are resolved after all externals are resolved
        self.aliased_publics = {}  # new_name -> (base_external, offset)

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

        # Fields the linker computes from extension link items (HIGH/LOW of
        # a relocatable or external value, and the like): a list of
        # (buf_offset, size, items) - `size' bytes at `buf_offset' get the
        # value of the postfix expression `items' (RELReader EXT_* tuples).
        self.expressions = []


class Linker:
    """LINK-80 compatible linker."""

    def __init__(self):
        self.modules = []
        self.globals = {}  # name -> (module_idx, value, seg_type, is_defined)
        self.commons = {}  # name -> size (largest wins)

        # Pre-define linker symbols (values computed in calculate_addresses)
        # mod_idx=0 is placeholder, value will be absolute address
        self.globals['__END__'] = (0, 0, ADDR_ABSOLUTE, True)
        self.globals['__BSS_START'] = (0, 0, ADDR_ABSOLUTE, True)
        self.globals['__BSS_END'] = (0, 0, ADDR_ABSOLUTE, True)

        self.code_base = 0x0103  # Default CP/M load address + 3 for JMP
        self.data_base = None  # Will be after code if not specified
        self.common_base = None  # After data

        self.output = bytearray()
        self.entry_point = None  # (value, seg_type) or None

        self.errors = []

        # External relocations: output offsets (low byte position) that need
        # relocation due to external symbol resolution to CSEG symbols.
        # Populated by resolve_externals(), used by save_prl().
        self.external_relocations = []
        # MP/M relocatable output: page-zero references (BDOS entry, default
        # FCB, DMA buffer) are relative to the memory segment the program is
        # loaded into, so they belong in the relocation bitmap too.
        self.page_zero_relative = False
        # Extra memory a .PRL asks MP/M for beyond its image, for storage the
        # program places at .MEMORY.  DRI passed this to GENMOD as its third
        # argument: `genmod pip.hex pip.prl $1000'.
        self.prl_extra = 0

        # Link-time expressions (extension link items), filled in by link():
        # output offsets of bytes a page relocation bitmap must mark, and a
        # description of each expression a bitmap cannot express.
        self.expr_relocations = []
        self.expr_unrelocatable = []

        # When True, emit zeros for DS (reserve space) directives instead of
        # treating them as BSS. Required for PRL/SPR format where all segments
        # must be contiguous in the output. Default is True for compatibility.
        self.emit_ds_zeros = True
        self.warnings = []

    def error(self, msg):
        self.errors.append(f"Error: {msg}")

    def warning(self, msg):
        self.warnings.append(f"Warning: {msg}")

    def load_rel(self, filename):
        """Load a REL file and add to modules list."""
        with open(filename, 'rb') as f:
            data = f.read()
        return self.load_rel_data(Path(filename).stem, data)

    def load_rel_data(self, name, data):
        """Load REL data from bytes (e.g., from a library module)."""
        reader = RELReader(data)
        module = Module(name.upper())

        current_loc = 0  # Position within current segment
        current_seg = ADDR_PROGRAM_REL  # Default to code segment
        first_abs_data = False  # Track if actual data bytes written to ASEG

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
        pending_exprs = []  # (seg_type, seg_offset, size, items)
        expr_items = []  # extension items read since the last store

        while True:
            try:
                item = reader.read_item()
            except EOFError:
                break

            if item is None:
                break

            item_type = item[0]

            if item_type == 'ABSOLUTE_BYTE':
                if not first_abs_data and current_seg == ADDR_ABSOLUTE:
                    first_abs_data = True
                write_byte_to_seg(item[1])
                current_loc += 1

            elif item_type == 'PROGRAM_REL':
                # 16-bit program-relative value - needs relocation
                if not first_abs_data and current_seg == ADDR_ABSOLUTE:
                    first_abs_data = True
                value = item[1]
                write_byte_to_seg(value & 0xFF)
                # Record relocation at low byte position
                pending_relocations.append((current_seg, current_loc, ADDR_PROGRAM_REL))
                current_loc += 1
                write_byte_to_seg((value >> 8) & 0xFF)
                current_loc += 1

            elif item_type == 'DATA_REL':
                # 16-bit data-relative value - needs relocation
                if not first_abs_data and current_seg == ADDR_ABSOLUTE:
                    first_abs_data = True
                value = item[1]
                write_byte_to_seg(value & 0xFF)
                pending_relocations.append((current_seg, current_loc, ADDR_DATA_REL))
                current_loc += 1
                write_byte_to_seg((value >> 8) & 0xFF)
                current_loc += 1

            elif item_type == 'COMMON_REL':
                # 16-bit common-relative value - needs relocation
                if not first_abs_data and current_seg == ADDR_ABSOLUTE:
                    first_abs_data = True
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
                # Check for aliased entry (format: "NEWNAME=EXTERNAL" or "NEWNAME=EXTERNAL+N")
                if '=' in sym_name:
                    new_name, alias_spec = sym_name.split('=', 1)
                    # Parse the alias spec: "EXTERNAL" or "EXTERNAL+N"
                    if '+' in alias_spec:
                        base_ext, offset_str = alias_spec.rsplit('+', 1)
                        try:
                            offset = int(offset_str)
                        except ValueError:
                            offset = 0
                            base_ext = alias_spec
                    else:
                        base_ext = alias_spec
                        offset = 0
                    module.aliased_publics[new_name] = (base_ext, offset)
                else:
                    module.publics[sym_name] = (value, addr_type)

            elif item_type == 'CHAIN_EXTERNAL':
                # External reference chain - store segment-relative for now
                a_field, sym_name = item[1], item[2]
                addr_type, head = a_field
                pending_externals.append((sym_name, addr_type, head))

            elif item_type == 'SET_LOC':
                a_field = item[1]
                addr_type, value = a_field
                # If emit_ds_zeros is enabled, fill gaps with zeros
                # This handles DS directives which advance without emitting bytes
                if self.emit_ds_zeros and value > 0:
                    # Switch to target segment first to write to correct buffer
                    current_seg = addr_type
                    # Get current buffer size for this segment
                    buf = get_seg_buffer()
                    fill_from = len(buf)
                    if value > fill_from:
                        # Temporarily set current_loc to fill position
                        current_loc = fill_from
                        while current_loc < value:
                            write_byte_to_seg(0)
                            current_loc += 1
                current_loc = value
                current_seg = addr_type
                # Track the lowest non-zero ASEG SET_LOC as code_start, until
                # actual data is written.  SET_LOC(ABS, 0) is skipped because it
                # is typically just a segment switch (ASEG directive) and the
                # default code_start of 0 already covers code-at-address-0.
                if not first_abs_data and addr_type == ADDR_ABSOLUTE:
                    if value > 0 and (module.code_start == 0 or value < module.code_start):
                        module.code_start = value

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

            elif item_type in ('EXT_VALUE', 'EXT_SYMBOL'):
                # An operand of a link-time expression (see relformat.py).
                expr_items.append(item)
                if item_type == 'EXT_SYMBOL':
                    # Make the name an external of this module, so a library
                    # module defining it is loaded and an undefined one is
                    # reported like any other.
                    module.externals.setdefault(item[1], [])

            elif item_type == 'EXT_OPERATOR':
                if item[1] in (EXT_OP_STORE_BYTE, EXT_OP_STORE_WORD):
                    # The store writes where the location counter is now:
                    # the assembler follows it with the field itself as
                    # placeholder bytes, which load here and are replaced
                    # once every segment is placed (link()).
                    size = 1 if item[1] == EXT_OP_STORE_BYTE else 2
                    pending_exprs.append((current_seg, current_loc, size,
                                          expr_items))
                    expr_items = []
                else:
                    expr_items.append(item)

            elif item_type == 'EXTENSION':
                # An extension item this linker does not implement (e.g. the
                # COBOL overlay segment sentinel).  The reader has consumed
                # it, so the rest of the module still loads.
                self.warning(f"Module {module.name}: extension link item "
                             f"{item[1]:02X}H ignored")

            elif item_type == 'END_PROGRAM':
                # End of module
                break

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
        # Store (buf_offset, reloc_type, ref_seg_type) where ref_seg_type is which segment the reference is in
        for seg_type, seg_offset, reloc_type in pending_relocations:
            if seg_type in seg_buf_start:
                buf_offset = seg_buf_start[seg_type] + seg_offset
                module.relocations.append((buf_offset, reloc_type, seg_type))

        # Convert pending externals to buffer offsets
        for sym_name, addr_type, head in pending_externals:
            if sym_name not in module.externals:
                module.externals[sym_name] = []
            if (addr_type == ADDR_ABSOLUTE and head == 0
                    and ADDR_ABSOLUTE not in seg_buf_start):
                # LINK-80 chains end at absolute 0, so this is an empty
                # chain: MACRO-80 writes one to declare an external used
                # only inside a link-time expression.  (um80 writes a
                # record per reference, and one at absolute 0 would need
                # the module to have absolute code there.)
                continue
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

        if expr_items:
            self.error(f"Module {module.name}: link-time expression has no "
                       f"store operator")
        for seg_type, seg_offset, size, items in pending_exprs:
            buf_offset = seg_buf_start.get(seg_type, len(code_bytes)) + seg_offset
            module.expressions.append((buf_offset, size, items))

        module.code = code_bytes
        module.seg_buf_start = seg_buf_start  # Save for chain following during link
        self.modules.append(module)

        # Register public symbols
        mod_idx = len(self.modules) - 1
        for sym_name, (value, seg_type) in module.publics.items():
            if sym_name in self.globals and self.globals[sym_name][3]:
                self.error(f"Multiply defined global '{sym_name}'")
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

    def resolve_aliased_publics(self, refresh: bool = False):
        """Resolve aliased public symbols (EQU external+offset made PUBLIC).

        These are symbols defined as SYMBOL EQU EXTERNAL+N and exported.
        After all externals are resolved, we can compute the actual addresses
        for these aliased symbols and add them to the global table.

        Called twice.  The first pass has to run before resolve_externals(), so
        that a reference to the alias from another module finds the name.  But
        a symbol the LINKER defines - __END__, __BSS_START, __BSS_END - has no
        value until calculate_addresses() has placed every segment, so an alias
        onto one of those would export zero.  PL/M-80's `AT (.MEMORY)' compiles
        to exactly that: MP/M II's UTIL7/DSE.PLM declares its hash table there
        and UTIL7/DM.PLM imports it.  The second pass, with refresh set,
        recomputes the values now that the bases are known.
        """
        for mod_idx, module in enumerate(self.modules):
            for new_name, (base_ext, offset) in module.aliased_publics.items():
                # Look up the base external symbol
                if base_ext not in self.globals:
                    self.error(f"Aliased symbol '{new_name}' references undefined external '{base_ext}'")
                    continue

                base_mod_idx, base_value, base_seg_type, is_defined = self.globals[base_ext]
                if not is_defined:
                    self.error(f"Aliased symbol '{new_name}' references undefined external '{base_ext}'")
                    continue

                # The new symbol's value is base_value + offset, same segment type
                new_value = base_value + offset
                # Register the aliased symbol in globals
                if new_name in self.globals and self.globals[new_name][3] and not refresh:
                    self.error(f"Multiply defined global '{new_name}'")
                else:
                    # Use the same module index as the base external
                    self.globals[new_name] = (base_mod_idx, new_value, base_seg_type, True)

    def _segment_ranges(self, module):
        """Yield (seg_type, buf_start, buf_end) for each segment buffer."""
        starts = sorted(module.seg_buf_start.items(), key=lambda kv: kv[1])
        for i, (seg, start) in enumerate(starts):
            end = starts[i + 1][1] if i + 1 < len(starts) else len(module.code)
            yield seg, start, end

    def _cseg_len(self, module):
        """Program-size contribution of a module to the relocatable counter.

        Uses the module's declared DEFINE_PROG_SIZE when present (which covers
        CSEG, and ASEG program size for an absolute module). Falls back to the
        CSEG buffer length, which is 0 for a module that contributes only a
        COMMON or DSEG block (so those don't inflate the code counter).
        """
        if module.code_size:
            return module.code_size
        if ADDR_PROGRAM_REL not in module.seg_buf_start:
            return 0
        start = module.seg_buf_start[ADDR_PROGRAM_REL]
        end = len(module.code)
        for s, st in module.seg_buf_start.items():
            if st > start and st < end:
                end = st
        return end - start

    def _buf_offset_addr(self, module, buf_offset):
        """Absolute output address for a module.code buffer offset.

        ASEG buffer index == absolute address; CSEG/DSEG/COMMON offsets are
        rebased onto code_base/data_base/common_base respectively.
        """
        seg, seg_start = ADDR_PROGRAM_REL, 0
        for s, st in module.seg_buf_start.items():
            if st <= buf_offset and st >= seg_start:
                seg, seg_start = s, st
        rel = buf_offset - seg_start
        if seg == ADDR_ABSOLUTE:
            return buf_offset
        if seg == ADDR_DATA_REL:
            return module.data_base + rel
        if seg == ADDR_COMMON_REL:
            return self.common_base + rel
        return module.code_base + rel

    def calculate_addresses(self):
        """Calculate base addresses for all modules."""
        # Calculate total code size (CSEG/program-relative bytes only)
        total_code = 0
        for module in self.modules:
            module.code_base = self.code_base + total_code
            total_code += self._cseg_len(module)

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

        # BSS region = COMMON area (uninitialized data, zeroed by crt0)
        self.globals['__BSS_START'] = (0, self.common_base, ADDR_ABSOLUTE, True)
        self.globals['__BSS_END'] = (0, end_addr, ADDR_ABSOLUTE, True)

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
        # Resolve aliased public symbols first (EQU external+offset made PUBLIC)
        # These need to be in globals before resolve_externals() checks references
        self.resolve_aliased_publics()

        if not self.resolve_externals():
            return False

        self.calculate_addresses()

        # Aliases onto a linker-defined symbol (__END__ and friends) only get a
        # value once the segments are placed.
        self.resolve_aliased_publics(refresh=True)

        # Place each module's segments at their output addresses. ASEG bytes go
        # to their absolute address; CSEG -> code_base; DSEG -> data_base.
        # COMMON is BSS and is not emitted. The leading zero padding of an ASEG
        # buffer (from offset 0 up to its ORG) is skipped. output_base is the
        # lowest address actually written; the output size covers the highest.
        lo = None
        hi = 0

        def _span(addr_start, addr_end):
            nonlocal lo, hi
            if addr_end <= addr_start:
                return
            if lo is None or addr_start < lo:
                lo = addr_start
            if addr_end > hi:
                hi = addr_end

        placements = []  # (addr, source bytes iterable as (out_addr, byte))
        for module in self.modules:
            for seg, start, end in self._segment_ranges(module):
                if seg == ADDR_COMMON_REL:
                    continue  # COMMON is uninitialized (BSS), not emitted
                begin = max(start, module.code_start) if seg == ADDR_ABSOLUTE else start
                if begin < end:
                    _span(self._buf_offset_addr(module, begin),
                          self._buf_offset_addr(module, end - 1) + 1)
            # Account for declared sizes beyond the materialized buffer
            if ADDR_PROGRAM_REL in module.seg_buf_start:
                _span(module.code_base, module.code_base + self._cseg_len(module))
            if module.data_size > 0 and self.emit_ds_zeros:
                _span(module.data_base, module.data_base + module.data_size)

        if lo is None:
            lo = self.code_base
            hi = self.code_base
        self.output_base = lo
        self.output = bytearray(max(0, hi - lo))

        for module in self.modules:
            for seg, start, end in self._segment_ranges(module):
                if seg == ADDR_COMMON_REL:
                    continue
                begin = max(start, module.code_start) if seg == ADDR_ABSOLUTE else start
                for o in range(begin, end):
                    out = self._buf_offset_addr(module, o) - self.output_base
                    if 0 <= out < len(self.output):
                        self.output[out] = module.code[o]

        # Fix up external references
        # Track which (module_index, buf_offset) pairs are resolved externally
        # so Phase 2 relocation doesn't double-apply segment bases
        resolved_external_locs = set()

        for mod_idx, module in enumerate(self.modules):
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
                    # Mark this location as externally resolved so Phase 2 skips it
                    resolved_external_locs.add((mod_idx, head))

                    # Follow the chain of references. head is a buffer offset;
                    # each chain link holds the segment-relative offset of the
                    # previous reference (0 ends the chain).
                    seg_base = module.seg_buf_start.get(ref_seg_type, 0)
                    cur_buf = head
                    visited = set()  # Prevent infinite loops
                    while cur_buf is not None and cur_buf not in visited:
                        visited.add(cur_buf)
                        abs_offset = self._buf_offset_addr(module, cur_buf) - self.output_base
                        if abs_offset < 0 or abs_offset + 1 >= len(self.output):
                            break
                        value = self.output[abs_offset] | (self.output[abs_offset + 1] << 8)
                        self.output[abs_offset] = target_addr & 0xFF
                        self.output[abs_offset + 1] = (target_addr >> 8) & 0xFF
                        if target_seg_type in (ADDR_PROGRAM_REL, ADDR_DATA_REL, ADDR_COMMON_REL):
                            self.external_relocations.append(abs_offset)
                        elif (self.page_zero_relative
                              and target_seg_type == ADDR_ABSOLUTE
                              and target_addr < 0x100):
                            # Under MP/M page zero belongs to the memory segment,
                            # not to absolute address 0, so a resolved reference to
                            # BDOS/FCB/TBUFF/... relocates like any program address.
                            self.external_relocations.append(abs_offset)
                        if value == 0:
                            break
                        cur_buf = seg_base + value

        # Apply relocations for program-relative, data-relative, and common-relative addresses
        for mod_idx, module in enumerate(self.modules):
            for reloc_entry in module.relocations:
                # Handle both old 2-tuple and new 3-tuple format
                if len(reloc_entry) == 3:
                    buf_offset, seg_type, ref_seg_type = reloc_entry
                else:
                    buf_offset, seg_type = reloc_entry
                    ref_seg_type = ADDR_PROGRAM_REL  # Default to CSEG for compatibility

                # Skip locations already resolved by external reference fixup
                if (mod_idx, buf_offset) in resolved_external_locs:
                    continue

                # Output offset for the reference (ASEG absolute, CSEG/DSEG rebased)
                abs_offset = self._buf_offset_addr(module, buf_offset) - self.output_base

                if abs_offset >= 0 and abs_offset + 1 < len(self.output):
                    # Read current value
                    value = self.output[abs_offset] | (self.output[abs_offset + 1] << 8)
                    # Apply relocation based on what the value points to
                    if seg_type == ADDR_PROGRAM_REL:
                        value += module.code_base
                    elif seg_type == ADDR_DATA_REL:
                        value += module.data_base
                    elif seg_type == ADDR_COMMON_REL:
                        value += self.common_base
                    # Write relocated value
                    self.output[abs_offset] = value & 0xFF
                    self.output[abs_offset + 1] = (value >> 8) & 0xFF

        # Fields computed from extension link items, last: every segment is
        # placed and every symbol known, and each field's placeholder bytes
        # are already in the image to be overwritten.
        return self.apply_expressions()

    # How a value moves when MP/M loads a page-relocatable image P pages
    # higher, for the bitmap in save_prl().  A value's `move' m says it
    # becomes value + m*P: 256 for an address in the program (its high byte
    # gains P), 0 for a constant, 1 for HIGH of an address (the byte itself
    # gains P).  `exact' is False when that only holds modulo 256 - after
    # HIGH or LOW, whose result wraps, or after arithmetic on such a byte -
    # and `byte' marks the direct result of HIGH or LOW, a byte whose upper
    # half is 0 however it moves.  None: the move is not a whole number of
    # pages at all (the product of two addresses, an address divided).
    @staticmethod
    def _move(m, exact=True, byte=False):
        if m == 0 and exact:
            byte = False
        return (m, exact, byte)

    def _eval_expression(self, module, items):
        """Evaluate one link-time expression.

        `items' is the postfix list from load_rel_data() without its store
        operator.  Returns (value, move) - see _move() - or None after
        recording an error.
        """
        stack = []
        for item in items:
            if item[0] == 'EXT_VALUE':
                addr_type, value = item[1]
                value = self.relocate_value(module, value, addr_type) & 0xFFFF
                stack.append((value, self._move(
                    0 if addr_type == ADDR_ABSOLUTE else 256)))
                continue
            if item[0] == 'EXT_SYMBOL':
                name = item[1]
                if name not in self.globals or not self.globals[name][3]:
                    self.error(f"Undefined symbol: {name}")
                    return None
                t_idx, t_value, t_seg, _ = self.globals[name]
                value = self.relocate_value(self.modules[t_idx], t_value,
                                            t_seg) & 0xFFFF
                # The same rule resolve-by-chain uses: a program address, or
                # page zero when MP/M relocates page zero with the program.
                moves = t_seg != ADDR_ABSOLUTE or (self.page_zero_relative
                                                   and value < 0x100)
                stack.append((value, self._move(256 if moves else 0)))
                continue
            op = item[1]
            unary = op in (EXT_OP_HIGH, EXT_OP_LOW, EXT_OP_NOT, EXT_OP_NEG)
            if len(stack) < (1 if unary else 2) or op not in EXT_OP_NAMES \
                    or op in (EXT_OP_STORE_BYTE, EXT_OP_STORE_WORD):
                self.error(f"Module {module.name}: malformed link-time "
                           f"expression (operator {op})")
                return None
            if unary:
                a, move_a = stack.pop()
                stack.append((self._apply_unary(op, a),
                              self._unary_move(op, move_a)))
                continue
            b, move_b = stack.pop()
            a, move_a = stack.pop()
            if op in (EXT_OP_DIV, EXT_OP_MOD) and b == 0:
                self.error(f"Module {module.name}: division by zero in a "
                           f"link-time expression")
                return None
            stack.append((self._apply_binary(op, a, b),
                          self._binary_move(op, a, move_a, b, move_b)))
        if len(stack) != 1:
            self.error(f"Module {module.name}: malformed link-time expression")
            return None
        return stack[0]

    @staticmethod
    def _apply_unary(op, a):
        if op == EXT_OP_HIGH:
            return (a >> 8) & 0xFF
        if op == EXT_OP_LOW:
            return a & 0xFF
        if op == EXT_OP_NOT:
            return ~a & 0xFFFF
        return -a & 0xFFFF

    @staticmethod
    def _apply_binary(op, a, b):
        if op == EXT_OP_PLUS:
            value = a + b
        elif op == EXT_OP_MINUS:
            value = a - b
        elif op == EXT_OP_MUL:
            value = a * b
        elif op == EXT_OP_DIV:
            value = a // b
        else:
            value = a % b
        return value & 0xFFFF

    def _unary_move(self, op, move_a):
        if move_a is None:
            return None
        m, exact, _ = move_a
        if op == EXT_OP_HIGH:
            # HIGH(x + m*P) is HIGH(x) + (m/256)*P, wrapping - but only when
            # x is exact and moves by whole pages; otherwise the carry out of
            # the low byte depends on P.
            if not exact or m % 256:
                return None
            page = (m // 256) % 256
            return self._move(page, page == 0, True)
        if op == EXT_OP_LOW:
            page = m % 256
            return self._move(page, page == 0, True)
        return self._move(-m, exact)  # NOT x is -x-1, so both negate m

    def _binary_move(self, op, a, move_a, b, move_b):
        if move_a is None or move_b is None:
            return None
        ma, ea, _ = move_a
        mb, eb, _ = move_b
        exact = ea and eb
        if op == EXT_OP_PLUS:
            return self._move(ma + mb, exact)
        if op == EXT_OP_MINUS:
            return self._move(ma - mb, exact)
        if op == EXT_OP_MUL:
            if ma == 0:
                return self._move(a * mb, exact)
            if mb == 0:
                return self._move(b * ma, exact)
            return None
        # DIV, MOD: only of values that do not move at all.
        return self._move(0) if ma == mb == 0 and exact else None

    def apply_expressions(self):
        """Store every link-time expression's value in the image.

        Also works out what a page relocation bitmap has to mark for each:
        a stored byte moves by m*P modulo 256, so it is marked when m is 1
        (HIGH of an address) and left alone when m is 0 (LOW of an address,
        which a page move never changes); a stored word is marked on its
        high byte when it moves exactly like an address.  Anything else
        cannot be expressed and is reported by save_prl().
        """
        ok = True
        for module in self.modules:
            for buf_offset, size, items in module.expressions:
                result = self._eval_expression(module, items)
                if result is None:
                    ok = False
                    continue
                value, m = result
                out = self._buf_offset_addr(module, buf_offset) - self.output_base
                if not 0 <= out <= len(self.output) - size:
                    continue  # not in the image (as for other fix-ups)
                self.output[out] = value & 0xFF
                if size == 2:
                    self.output[out + 1] = (value >> 8) & 0xFF
                mark = self._bitmap_mark(size, m)
                if mark is None:
                    self.expr_unrelocatable.append(
                        f"{module.name}: the {'byte' if size == 1 else 'word'}"
                        f" at {out + self.output_base:04X}H, "
                        f"{self.describe_expression(items)}, does not move by "
                        f"0 or 1 page when MP/M relocates the program, which a"
                        f" page relocation bitmap cannot express")
                elif mark >= 0:
                    self.expr_relocations.append(out + mark)
        return ok

    @staticmethod
    def _bitmap_mark(size, move):
        """Byte of a stored field to mark (0 or 1), -1 for none, None if impossible."""
        if move is None:
            return None
        m, exact, byte = move
        if size == 1:
            return {0: -1, 1: 0}.get(m % 256)
        if exact:
            return {0: -1, 256: 1}.get(m % 65536)
        if byte and m % 256 == 1:
            return 0  # HIGH/LOW stored as a word: the upper byte stays 0
        return None

    @staticmethod
    def describe_expression(items):
        """Infix text of a postfix link-time expression, for messages."""
        stack = []
        marks = {ADDR_ABSOLUTE: 'H', ADDR_PROGRAM_REL: "H'",
                 ADDR_DATA_REL: 'H"', ADDR_COMMON_REL: 'H!'}
        for item in items:
            if item[0] == 'EXT_VALUE':
                addr_type, value = item[1]
                stack.append(f"{value:04X}{marks.get(addr_type, 'H')}")
            elif item[0] == 'EXT_SYMBOL':
                stack.append(item[1])
            elif item[1] in (EXT_OP_HIGH, EXT_OP_LOW, EXT_OP_NOT) and stack:
                stack.append(f"{EXT_OP_NAMES[item[1]]}({stack.pop()})")
            elif item[1] == EXT_OP_NEG and stack:
                stack.append(f"-({stack.pop()})")
            elif len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                stack.append(f"({a}{EXT_OP_NAMES.get(item[1], '?')}{b})")
        text = ' '.join(stack)
        return text[1:-1] if text.startswith('(') and text.endswith(')') else text

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
        if self.expr_unrelocatable:
            # The image is right where it was linked but would be wrong
            # anywhere else MP/M put it.
            raise LinkerError('\n'.join(
                f"Error: {msg}" for msg in self.expr_unrelocatable))

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

            for reloc_entry in module.relocations:
                # Handle both old 2-tuple and new 3-tuple format
                if len(reloc_entry) == 3:
                    buf_offset, seg_type, ref_seg_type = reloc_entry
                else:
                    buf_offset, seg_type = reloc_entry
                    ref_seg_type = ADDR_PROGRAM_REL

                # Calculate output offset based on which segment the reference is in
                if ref_seg_type == ADDR_DATA_REL:
                    dseg_start = module.seg_buf_start.get(ADDR_DATA_REL, 0)
                    seg_offset = buf_offset - dseg_start
                    abs_offset = (module.data_base - self.output_base) + seg_offset
                else:
                    abs_offset = dest_offset + (buf_offset - src_start)

                high_byte_offset = abs_offset + 1

                if 0 <= high_byte_offset < code_length:
                    # Set bit in bitmap
                    # Bit 7 of byte 0 = code byte 0, bit 6 = code byte 1, etc.
                    byte_idx = high_byte_offset // 8
                    bit_idx = 7 - (high_byte_offset % 8)
                    bitmap[byte_idx] |= (1 << bit_idx)

        # Also include external relocations (resolved refs to CSEG symbols)
        for abs_offset in self.external_relocations:
            high_byte_offset = abs_offset + 1
            if 0 <= high_byte_offset < code_length:
                byte_idx = high_byte_offset // 8
                bit_idx = 7 - (high_byte_offset % 8)
                bitmap[byte_idx] |= (1 << bit_idx)

        # And the bytes of link-time expressions that move with the program
        # (these are the byte to mark itself, not the low byte of a word).
        for offset in self.expr_relocations:
            if 0 <= offset < code_length:
                bitmap[offset // 8] |= 0x80 >> (offset % 8)

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
        # A program that puts storage at .MEMORY needs memory past its image,
        # and nothing in the object files says how much - PL/M's .MEMORY is
        # "whatever is left".  DRI named the figure at build time and so do we.
        bss_size = max(bss_size, self.prl_extra)
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
    parser.add_argument('--prl', action='store_true',
                       help='Output MP/M .PRL (Page Relocatable) transient, linked at 100H')
    parser.add_argument('--spr', action='store_true',
                       help='Output MP/M .SPR/.RSP (System Page Relocatable), linked at 0')
    parser.add_argument('--extra', metavar='HEX', default='0',
                       type=lambda x: int(x, 16) if not x.startswith(('0x', '0X')) else int(x, 0),
                       help='Extra memory (hex) a .PRL asks MP/M for beyond its '
                            'image, for storage placed at .MEMORY (GENMOD\'s third argument)')
    parser.add_argument('--no-ds-zeros', action='store_true',
                       help='Do not emit zeros for DS (reserve space) directives (default: emit zeros)')
    parser.add_argument('-s', '--sym', action='store_true', help='Generate .SYM symbol file')
    parser.add_argument('-S', '--sym-file', metavar='FILE', help='Generate .SYM symbol file with specified name')
    parser.add_argument('-p', '--origin', type=lambda x: int(x, 16) if not x.startswith(('0x', '0X', '0o', '0O', '0b', '0B')) else int(x, 0), default=None,
                       help='Program origin as hex (e.g., E000, 0xE000; default: 0 for SPR, 100 for PRL and COM)')

    args = parser.parse_args()

    linker = Linker()
    # Page-relocatable output shares one container format but two origins.
    #
    # A .SPR/.RSP is loaded at the base of its memory segment and MP/M adds the
    # segment's base page to every marked byte, so the image is linked at 0.
    #
    # A transient .PRL is loaded at segment_bottom+0100H (CLI.ASM: "base =
    # segment$bottom + 0100H") while relocate() still adds only the segment base
    # page.  The extra page has to come from the link, so the image is linked at
    # 0100H - the same origin a .COM uses.  Linking a .PRL at 0 lands every
    # relocated address one page below the code.
    prl_output = args.prl or args.spr
    if args.origin is None:
        args.origin = 0 if args.spr else 0x100
    linker.code_base = args.origin
    linker.page_zero_relative = prl_output
    linker.prl_extra = args.extra

    # Emit zeros for DS directives (default: True)
    if args.no_ds_zeros:
        linker.emit_ds_zeros = False

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

    # Link.  Report anything the linker recorded, not only the errors that
    # made link() give up: L80 keeps going after a multiply-defined global
    # (it takes the first definition) and so do we, and reporting only on
    # failure meant that error was recorded and then silently dropped --
    # exit 0, output written, nothing said.  Two objects each defining the
    # same PUBLIC linked quietly, which is exactly the case
    # tests/test_linker_dupglobal.py was written to catch and could not,
    # because it drives the Linker API rather than this entry point.
    ok = linker.link()
    for err in linker.errors:
        print(err, file=sys.stderr)
    if not ok:
        sys.exit(1)

    # Determine output filename
    if args.output:
        output_path = args.output
    else:
        if args.hex:
            ext = '.hex'
        elif prl_output:
            ext = '.spr' if args.spr else '.prl'
        else:
            ext = '.com'
        output_path = Path(args.inputs[0]).with_suffix(ext)

    # Save output
    if args.hex:
        linker.save_hex(str(output_path))
    elif prl_output:
        try:
            linker.save_prl(str(output_path))
        except LinkerError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
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

    # A recorded-but-recoverable error leaves the exit status at 0 for now.
    # L80 keeps the first definition of a multiply-defined global and
    # produces output, and so do we; making the status non-zero as well is
    # a policy change that would reject link lines L80 accepts -- including
    # uc80's own documented one, which passes runtime.lib alongside a module
    # that has already embedded the runtime, so __sret_buf can arrive twice.
    # Printing it is the part that was plainly wrong and is fixed above.
    sys.exit(0)


if __name__ == '__main__':
    main()
