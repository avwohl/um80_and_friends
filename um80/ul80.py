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
from array import array
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
        self.public_blocks = {}  # name -> COMMON block, for a COMMON-relative public

        # Aliased entry points: SYMBOL EQU EXTERNAL+offset made PUBLIC
        # These are resolved after all externals are resolved
        self.aliased_publics = {}  # new_name -> (base_external, offset)

        # External references (chains to be fixed up)
        self.externals = {}  # name -> list of (buf_offset of the chain head, segment key)

        # Special item 12 (chain address): (buf_offset of a word of the
        # chain, segment key, offset, bytes) - the word gets the address of
        # that offset in that segment, where the item appeared.  The chain
        # is followed when the item is read, as LINK-80 fills it then; `bytes'
        # has bit 0 (the low byte) and bit 1 (the high byte) set for the
        # bytes of the word nothing was loaded over after that.
        self.chain_addresses = []

        # Common blocks
        self.commons = {}  # name -> size

        # Relocation info: (buf_offset, reloc_type, segment key of the
        # location, COMMON block of a COMMON-relative value or None, the
        # value loaded, bytes) - `bytes' as for chain_addresses: LINK-80
        # relocates a word as it loads it, so a byte loaded over it later
        # replaces that byte of the relocated word.
        self.relocations = []

        # Where each segment's bytes start in `code'.  The key is a segment
        # type, or (ADDR_COMMON_REL, name) for a COMMON block: every named
        # block is a segment of its own.
        self.seg_buf_start = {}

        # Fields the linker computes from extension link items (HIGH/LOW of
        # a relocatable or external value, and the like): a list of
        # (buf_offset, size, items) - `size' bytes at `buf_offset' get the
        # value of the postfix expression `items' (RELReader EXT_* tuples;
        # a COMMON-relative EXT_VALUE carries its block as a third element).
        self.expressions = []

        # Special items 9 and 8 (External plus/minus offset): (buf_offset,
        # sign, a_field, block) - the A value, relocated, times sign is added
        # to the word at buf_offset once every reference is filled in.
        self.offsets = []

        # The bytes a module loads into a COMMON block, as opposed to the
        # zeros DS leaves there: segment key -> set of offsets in the block.
        # Only these are put in the image (FORTRAN's BLOCK DATA, DB in a
        # COMMON block); a COMMON block is otherwise uninitialized.
        self.common_data = {}

        # Absolute (ASEG) code: one past the highest location the module
        # reached in ASEG, by a byte loaded there or a location set (an ORG
        # or DS, even with nothing after it), and the addresses it loaded
        # bytes at (a DS or ORG gap between them loads nothing).
        self.abs_top = 0
        self.abs_loaded = set()

        # Item 14's A-field (the start address), None when the module was
        # written by um80 up to 0.3.48, which left the A-field out.
        self.entry = None
        self.legacy_um80 = False

        # buf_offset -> (relocation type, COMMON block) of each relocatable
        # word still whole, built when a chain is first followed
        # (Linker._fill_chain()).
        self.link_types = None


class Linker:
    """LINK-80 compatible linker."""

    # Addresses the linker computes from the layout (absolute values, but
    # program addresses: they move when MP/M relocates the image).
    LINKER_SYMBOLS = ('__END__', '__BSS_START', '__BSS_END')

    def __init__(self):
        self.modules = []
        self.globals = {}  # name -> (module_idx, value, seg_type, is_defined)
        self.global_blocks = {}  # name -> COMMON block of a COMMON-relative global
        self.commons = {}  # name -> size (largest wins), in order of declaration
        self.common_bases = {}  # name -> address, set by calculate_addresses()
        self.total_common = 0

        # Pre-define linker symbols (values computed in calculate_addresses)
        # mod_idx=0 is placeholder, value will be absolute address
        for name in self.LINKER_SYMBOLS:
            self.globals[name] = (0, 0, ADDR_ABSOLUTE, True)
        # Symbols whose value is a program address although it is absolute:
        # the linker's own, and PUBLIC aliases of them (X EQU __END__).
        self.moving = set(self.LINKER_SYMBOLS)

        self.code_base = 0x0103  # Default CP/M load address + 3 for JMP
        self.data_base = None  # Will be after code if not specified
        self.common_base = None  # After data

        self.output = bytearray()
        self.output_base = 0
        self.entry_point = None  # (value, seg_type) or None

        self.errors = []
        # An object that cannot be linked correctly (link() then fails).
        self.load_failed = False

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
        # (module index, buffer offset) of every chain word link() filled.
        self.chained_locs = set()

        # When True, emit zeros for DS (reserve space) directives instead of
        # treating them as BSS. Required for PRL/SPR format where all segments
        # must be contiguous in the output. Default is True for compatibility.
        self.emit_ds_zeros = True
        self.warnings = []

        # For each byte of the image, the index of the module whose byte it
        # is and the offset in that module's buffer (-1: none), set by
        # link().
        self.owner_mod = array('i')
        self.owner_off = array('i')

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
        """Load REL data from bytes (e.g., from a library module).

        Every module in it: a .REL can hold several, one after another,
        each ending in item 14 and the last followed by item 15 (FORTRAN-80's
        FORLIB.REL has 106).  Only the first was loaded.
        """
        reader = RELReader(data)
        count = 0
        while True:
            more = self._load_module(reader, name if count == 0
                                     else f"{name}_{count}")
            if more is None:
                break
            count += 1
            if not more:
                break
        return True

    def _load_module(self, reader, name):
        """Load the next module from `reader'.

        Returns True if another may follow (it ended in item 14), False if
        the data ended with it, or None if there was no module at all.
        """
        module = Module(name.upper())

        current_loc = 0  # Position within current segment
        current_seg = ADDR_PROGRAM_REL  # Default to code segment
        # The COMMON block special item 1 selected last, which a
        # COMMON-relative value refers to; and the block bytes load into,
        # the one selected when the location was last set into COMMON.
        # LINK-80 moves loading only at a set-location item: MACRO-80
        # selects another block for an operand inside a COMMON block and
        # does not select back, and the bytes after it still load where
        # they were loading.
        current_block = load_block = None
        first_abs_data = False  # Track if actual data bytes written to ASEG
        any_item = False
        more = False

        # Use separate buffers for each segment to avoid overwrites when
        # switching between segments (e.g., CSEG -> DSEG -> CSEG)
        seg_buffers = {}  # segment key -> bytearray

        def seg_key(seg=None):
            """The buffer key of segment type `seg', a COMMON-relative value
            being in the block selected last; by default, where bytes load
            now."""
            if seg is None:
                return (ADDR_COMMON_REL, load_block) \
                    if current_seg == ADDR_COMMON_REL else current_seg
            return (ADDR_COMMON_REL, current_block) if seg == ADDR_COMMON_REL \
                else seg

        # The word each byte loaded so far belongs to, if it is a relocatable
        # word or a word an item-12 chain filled: (segment key, offset) ->
        # (record, 0 for its low byte or 1 for its high byte).  A record is a
        # list whose last element is a mask of the bytes still its own.
        # LINK-80 relocates a word as it loads it and fills an item-12 chain
        # as it reads the item, so a byte loaded there afterwards (an ORG
        # back, a COMMON block declared again) simply replaces that byte,
        # and the other keeps what LINK-80 stored.  ul80 kept the relocation
        # and added the segment base to whatever was loaded over the word.
        word_at = {}

        def claim(rec):
            """Make the word of `rec' the owner of its two bytes."""
            for i in (0, 1):
                where = (rec[0], rec[1] + i)
                old = word_at.get(where)
                if old is not None:
                    old[0][-1] &= ~(1 << old[1])
                word_at[where] = (rec, i)

        def write_byte_to_seg(value, loaded=True):
            """Write a byte at current_loc in current segment's buffer."""
            key = seg_key()
            buf = seg_buffers.setdefault(key, bytearray())
            while len(buf) <= current_loc:
                buf.append(0)
            buf[current_loc] = value
            if not loaded:
                return
            old = word_at.pop((key, current_loc), None)
            if old is not None:
                old[0][-1] &= ~(1 << old[1])
            if current_seg == ADDR_COMMON_REL:
                module.common_data.setdefault(key, set()).add(current_loc)
            if current_seg == ADDR_ABSOLUTE:
                module.abs_loaded.add(current_loc)
                module.abs_top = max(module.abs_top, current_loc + 1)
                # Loaded below where ASEG was thought to start: `ORG 200H /
                # DB 1 / ORG 180H / DB 4' lost the 4.
                module.code_start = min(module.code_start, current_loc)

        def fill_chain(key, off, cur_key, cur_offset):
            """Item 12: every word of the chain at `off' in segment `key'
            gets the address of `cur_offset' in `cur_key'.  Each link is
            typed by the relocation of the word holding it, as in
            Linker._fill_chain(), and absolute 0 ends the chain."""
            if key == ADDR_ABSOLUTE and off == 0:
                return  # an empty chain, as for an external
            seen = set()
            while (key, off) not in seen:
                seen.add((key, off))
                buf = seg_buffers.get(key)
                if buf is None or not 0 <= off < len(buf) - 1:
                    break
                link = buf[off] | (buf[off + 1] << 8)
                low, high = word_at.get((key, off)), word_at.get((key, off + 1))
                link_type, link_block = ADDR_ABSOLUTE, None
                if low is not None and high is not None and low[0] is high[0] \
                        and low[1] == 0 and len(low[0]) == 6:
                    link_type, link_block = low[0][2], low[0][3]
                rec = [key, off, cur_key, cur_offset, 3]
                claim(rec)  # the link it held is not relocated now
                pending_chains.append(rec)
                if link_type == ADDR_ABSOLUTE and link == 0:
                    break
                key = (ADDR_COMMON_REL, link_block) \
                    if link_type == ADDR_COMMON_REL else link_type
                off = link

        # Track relocations with segment-relative offsets before combining
        # [seg key, seg_offset, reloc_type, block, value, bytes]
        pending_relocations = []
        pending_externals = []  # (name, seg key, head_offset)
        # item 12, a word of a chain: [seg key, offset, cur key, cur_offset,
        # bytes]
        pending_chains = []
        pending_exprs = []  # (seg key, seg_offset, size, items)
        pending_offsets = []  # (seg key, seg_offset, sign, a_field, block)
        expr_items = []  # extension items read since the last store

        while True:
            try:
                item = reader.read_item()
            except EOFError:
                break

            if item is None:
                break

            item_type = item[0]
            if item_type == 'END_FILE':
                break
            any_item = True

            if item_type == 'ABSOLUTE_BYTE':
                if not first_abs_data and current_seg == ADDR_ABSOLUTE:
                    first_abs_data = True
                write_byte_to_seg(item[1])
                current_loc += 1

            elif item_type in ('PROGRAM_REL', 'DATA_REL', 'COMMON_REL'):
                # 16-bit relocatable value - needs relocation
                if not first_abs_data and current_seg == ADDR_ABSOLUTE:
                    first_abs_data = True
                reloc_type = {'PROGRAM_REL': ADDR_PROGRAM_REL,
                              'DATA_REL': ADDR_DATA_REL,
                              'COMMON_REL': ADDR_COMMON_REL}[item_type]
                value = item[1]
                # Record relocation at low byte position; a COMMON-relative
                # value is relative to the block selected last.
                rec = [seg_key(), current_loc, reloc_type,
                       current_block if reloc_type == ADDR_COMMON_REL else None,
                       value, 3]
                write_byte_to_seg(value & 0xFF)
                current_loc += 1
                write_byte_to_seg((value >> 8) & 0xFF)
                current_loc += 1
                claim(rec)
                pending_relocations.append(rec)

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
                    if addr_type == ADDR_COMMON_REL:
                        module.public_blocks[sym_name] = current_block

            elif item_type == 'CHAIN_EXTERNAL':
                # External reference chain - store segment-relative for now
                a_field, sym_name = item[1], item[2]
                addr_type, head = a_field
                pending_externals.append((sym_name, seg_key(addr_type), head))

            elif item_type == 'SET_LOC':
                a_field = item[1]
                addr_type, value = a_field
                if addr_type == ADDR_COMMON_REL:
                    load_block = current_block
                # If emit_ds_zeros is enabled, fill gaps with zeros
                # This handles DS directives which advance without emitting bytes
                if self.emit_ds_zeros and value > 0:
                    # Switch to target segment first to write to correct buffer
                    current_seg = addr_type
                    # Get current buffer size for this segment
                    buf = seg_buffers.setdefault(seg_key(), bytearray())
                    fill_from = len(buf)
                    if value > fill_from:
                        # Temporarily set current_loc to fill position
                        current_loc = fill_from
                        while current_loc < value:
                            write_byte_to_seg(0, loaded=False)
                            current_loc += 1
                current_loc = value
                current_seg = addr_type
                if addr_type == ADDR_ABSOLUTE:
                    module.abs_top = max(module.abs_top, value)
                # Track the lowest non-zero ASEG SET_LOC as code_start, until
                # actual data is written.  SET_LOC(ABS, 0) is skipped because it
                # is typically just a segment switch (ASEG directive) and the
                # default code_start of 0 already covers code-at-address-0.
                if not first_abs_data and addr_type == ADDR_ABSOLUTE:
                    if value > 0 and (module.code_start == 0 or value < module.code_start):
                        module.code_start = value

            elif item_type == 'CHAIN_ADDRESS':
                # A forward reference (FORTRAN-80 writes every one this
                # way): the chain gets the current location's address.
                a_field = item[1]
                addr_type, head = a_field
                fill_chain(seg_key(addr_type), head, seg_key(), current_loc)

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
                # What COMMON-relative items refer to from here on (bytes
                # load into it after the next set-location).
                current_block = item[1]

            elif item_type == 'REQUEST_LIB':
                # Library search request
                pass

            elif item_type in ('EXTERNAL_PLUS_OFFSET', 'EXTERNAL_OFFSET'):
                # MACRO-80 writes `JMP EXT+3' as item 9 (A = 3) just before
                # the word, which is a reference in EXT's chain; LINK-80 adds
                # A to the word once it is filled in.  Item 8 subtracts.
                a_field = item[1]
                pending_offsets.append(
                    (seg_key(), current_loc,
                     1 if item_type == 'EXTERNAL_PLUS_OFFSET' else -1,
                     a_field, current_block))

            elif item_type in ('EXT_VALUE', 'EXT_SYMBOL'):
                # An operand of a link-time expression (see relformat.py).
                if item_type == 'EXT_VALUE' and item[1][0] == ADDR_COMMON_REL:
                    item = ('EXT_VALUE', item[1], current_block)
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
                    pending_exprs.append((seg_key(), current_loc, size,
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
                # End of module; the A-field is the start address.
                module.entry = item[1]
                module.legacy_um80 = item[1] is None
                more = True
                break

        if not any_item:
            return None

        # A COMMON-relative item before any block was selected: um80 up to
        # 0.3.48 selected the block only at its COMMON directive.  Take the
        # module's first block.
        default_block = next(iter(module.commons), ' ')

        def norm(key):
            if isinstance(key, tuple) and key[1] is None:
                return (ADDR_COMMON_REL, default_block)
            return key

        def block_of(block):
            return default_block if block is None else block

        # Combine segment buffers into single code buffer
        # Order: ASEG (absolute), CSEG (program), DSEG (data), each COMMON block
        code_bytes = bytearray()
        seg_buf_start = {}
        keys = [ADDR_ABSOLUTE, ADDR_PROGRAM_REL, ADDR_DATA_REL]
        keys += [k for k in seg_buffers if isinstance(k, tuple)]
        for key in keys:
            if key in seg_buffers and norm(key) not in seg_buf_start:
                seg_buf_start[norm(key)] = len(code_bytes)
                code_bytes.extend(seg_buffers[key])
        for key, positions in list(module.common_data.items()):
            del module.common_data[key]
            module.common_data.setdefault(norm(key), set()).update(positions)
        for name_, block in list(module.public_blocks.items()):
            module.public_blocks[name_] = block_of(block)

        def buf_offset(key, offset, fallback):
            key = norm(key)
            if key in seg_buf_start:
                return seg_buf_start[key] + offset
            return fallback + offset

        # Convert segment-relative relocations to buffer offsets; a word
        # loaded over entirely, or filled by an item-12 chain, has none.
        for key, seg_offset, reloc_type, block, value, mask in \
                pending_relocations:
            if mask and norm(key) in seg_buf_start:
                module.relocations.append(
                    (seg_buf_start[norm(key)] + seg_offset, reloc_type,
                     norm(key), block_of(block)
                     if reloc_type == ADDR_COMMON_REL else None, value, mask))

        # Convert pending externals to buffer offsets
        for sym_name, key, head in pending_externals:
            if sym_name not in module.externals:
                module.externals[sym_name] = []
            if key == ADDR_ABSOLUTE and head == 0 and (
                    not module.legacy_um80
                    or ADDR_ABSOLUTE not in seg_buf_start):
                # LINK-80 chains end at absolute 0, so this is an empty
                # chain: MACRO-80 writes one to declare an external used
                # only inside a link-time expression, or not at all.  (um80
                # up to 0.3.48 wrote a record per reference, and one at
                # absolute 0 meant a reference there; um80 now writes such a
                # reference as an extension link item.)
                continue
            buf_head = buf_offset(key, head,
                                  seg_buf_start.get(ADDR_ABSOLUTE, len(code_bytes)))
            module.externals[sym_name].append((buf_head, norm(key)))

        # Item 12: each word of the chain as a buffer offset; the address it
        # gets stays a segment and an offset until the segments are placed.
        for key, off, cur_key, cur_offset, mask in pending_chains:
            if mask and norm(key) in seg_buf_start:
                module.chain_addresses.append(
                    (seg_buf_start[norm(key)] + off, norm(cur_key),
                     cur_offset, mask))

        if expr_items:
            self.error(f"Module {module.name}: link-time expression has no "
                       f"store operator")
            self.load_failed = True
        for key, seg_offset, size, items in pending_exprs:
            module.expressions.append(
                (buf_offset(key, seg_offset, len(code_bytes)), size,
                 [(t[0], t[1], block_of(t[2])) if len(t) == 3 else t
                  for t in items]))
        for key, seg_offset, sign, a_field, block in pending_offsets:
            module.offsets.append(
                (buf_offset(key, seg_offset, len(code_bytes)), sign, a_field,
                 block_of(block)))

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
                if seg_type == ADDR_COMMON_REL:
                    self.global_blocks[sym_name] = module.public_blocks.get(sym_name)

        # Track common block sizes
        for sym_name, size in module.commons.items():
            if sym_name not in self.commons or size > self.commons[sym_name]:
                self.commons[sym_name] = size

        return more

    @staticmethod
    def _split_offset_name(name):
        """(base name, offset) of a chain name um80 up to 0.3.48 wrote as
        "SYMBOL+N" for SYMBOL plus a constant; (name, 0) otherwise."""
        if '+' in name:
            base, offset = name.rsplit('+', 1)
            try:
                return base, int(offset)
            except ValueError:
                pass
        return name, 0

    def get_undefined_symbols(self):
        """Undefined external symbols, in the order the modules use them."""
        undefined = {}
        for module in self.modules:
            for name in module.externals:
                base_name, _ = self._split_offset_name(name)
                if base_name not in self.globals or not self.globals[base_name][3]:
                    undefined[base_name] = True
        return list(undefined)

    def resolve_externals(self):
        """Check that all external references can be resolved."""
        undefined = {}
        for module in self.modules:
            for name in module.externals:
                base_name, _ = self._split_offset_name(name)
                if base_name not in self.globals or not self.globals[base_name][3]:
                    undefined[name] = True

        if undefined:
            for name in undefined:
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
        for module in self.modules:
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
                    if base_ext in self.global_blocks:
                        self.global_blocks[new_name] = self.global_blocks[base_ext]
                    if base_ext in self.moving:
                        self.moving.add(new_name)

    def _moves(self, name, value, seg_type):
        """Whether global `name' moves when MP/M relocates the image.

        A relocatable symbol does, and so does an address the linker
        computes (__END__, and an alias of it such as PL/M's .MEMORY).  With
        page_zero_relative, so does an absolute symbol in page zero - judged
        on the symbol, not on symbol plus offset, so TBUF+80H (0100H) moves
        with TBUF and does not escape the bitmap.
        """
        return (seg_type != ADDR_ABSOLUTE or name in self.moving
                or (self.page_zero_relative and value < 0x100))

    def _segment_ranges(self, module):
        """Yield (segment key, buf_start, buf_end) for each segment buffer."""
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
        for st in module.seg_buf_start.values():
            if start < st < end:
                end = st
        return end - start

    @staticmethod
    def _seg_at(module, buf_offset):
        """(segment key, start) of the buffer that holds `buf_offset'.

        An empty buffer starts where the next one does; the later wins.
        """
        seg, seg_start = ADDR_PROGRAM_REL, 0
        for s, st in module.seg_buf_start.items():
            if seg_start <= st <= buf_offset:
                seg, seg_start = s, st
        return seg, seg_start

    def _buf_offset_addr(self, module, buf_offset):
        """Absolute output address for a module.code buffer offset.

        ASEG buffer index == absolute address; CSEG/DSEG/COMMON offsets are
        rebased onto code_base/data_base/the block's base respectively.
        """
        seg, seg_start = self._seg_at(module, buf_offset)
        rel = buf_offset - seg_start
        if seg == ADDR_ABSOLUTE:
            return buf_offset
        if seg == ADDR_DATA_REL:
            return module.data_base + rel
        if isinstance(seg, tuple):
            return self.common_bases.get(seg[1], self.common_base) + rel
        return module.code_base + rel

    def _fill_chain(self, module, mod_idx, head, value, moves, until):
        """Store `value' in every word of the chain that starts at `head'.

        A chain is LINK-80's list of the places a value goes (the references
        to an external, item 6): each word holds the address of the next,
        typed like any other word - program, data or COMMON relative, or
        absolute, which is an address in ASEG - and absolute 0 ends it.
        `head' is a buffer offset in `module'.  Every word filled is
        recorded in chained_locs, so the relocation pass (which would add a
        segment base to the value) and the .PRL bitmap (which would mark it
        by the type of the link it held) leave it alone; `moves' says
        whether the value moves with the program, for the bitmap.  An
        absolute link was read as an offset in the segment of the word
        holding it: MACRO-80 chains a CSEG reference to one in ASEG that
        way, and that one was left 0000H.

        LINK-80 fills the chain once the module has been loaded and the
        external defined, which is at the end of module `until' (the later
        of the two): a byte a later module loads over a word of the chain,
        in a COMMON block they share, is not overwritten.

        Except in an object from um80 up to 0.3.48 (legacy_um80: item 14
        has no A-field).  um80 0.2.0 to 0.3.34 chained all the references to
        an external through untyped words, each the offset of the previous
        reference in whichever segment that one was in - the link does not
        say which.  ul80 reads it as an offset in the segment of the word
        holding it (read as an ASEG address, only the head was filled), so
        a chain whose references are in more than one segment is not
        followed right, in this ul80 or any earlier one.  (0.3.35 to 0.3.48
        wrote a chain of one per reference, whose link is 0 however it is
        read.)
        """
        link_types = module.link_types
        if link_types is None:
            link_types = module.link_types = {
                r[0]: (r[1], r[3]) for r in module.relocations if r[5] == 3}
        cur = head
        visited = set()  # Prevent infinite loops
        while (cur is not None and cur not in visited
               and 0 <= cur < len(module.code) - 1):
            visited.add(cur)
            self.chained_locs.add((mod_idx, cur))
            link = module.code[cur] | (module.code[cur + 1] << 8)
            link_type, link_block = link_types.get(cur, (ADDR_ABSOLUTE, None))
            out = self._buf_offset_addr(module, cur) - self.output_base
            stored = self._store_word(
                out, value, [0 <= out + i < len(self.output)
                             and self.owner_mod[out + i] <= until
                             for i in (0, 1)])
            if moves and stored & 2:
                self.external_relocations.append(out)
            if link_type == ADDR_ABSOLUTE and link == 0:
                break
            if link_type == ADDR_COMMON_REL:
                key = (ADDR_COMMON_REL, link_block)
            elif link_type == ADDR_ABSOLUTE and module.legacy_um80:
                key = self._seg_at(module, cur)[0]
            else:
                key = link_type
            start = module.seg_buf_start.get(key)
            cur = None if start is None else start + link

    def _store_word(self, out, value, which):
        """Store the bytes of `value' at image offset `out' for which
        `which' (low byte, high byte) is true.  Returns a mask of those
        stored: 1 the low byte, 2 the high byte."""
        stored = 0
        for i in (0, 1):
            if which[i]:
                self.output[out + i] = (value >> (8 * i)) & 0xFF
                stored |= 1 << i
        return stored

    def _own(self, mod_idx, buf_offset, out, mask):
        """(low, high): whether each byte of the word at buffer offset
        `buf_offset' of module `mod_idx', image offset `out', is in `mask'
        and is still the byte that module loaded there - nothing loaded
        later went over it."""
        return [bool(mask >> i & 1) and 0 <= out + i < len(self.output)
                and self.owner_mod[out + i] == mod_idx
                and self.owner_off[out + i] == buf_offset + i
                for i in (0, 1)]

    def calculate_addresses(self):
        """Calculate base addresses for all modules.

        Each module's code goes after the previous module's - or above the
        absolute code the modules before it loaded, if that reaches higher.
        LINK-80 3.44 does that (probed under cpmemu): it starts the next
        module's area above the highest absolute location loaded so far,
        a byte or a location set by ORG or DS, with /P: or without, when
        that is above where the area would go; absolute code below it moves
        nothing.  ul80 went on from the end of the previous module's code,
        so `ASEG / ORG 100H' in one module put the next module's CSEG on top
        of it.  A module's own absolute code does not move its own code:
        L80 allocates the program area before it loads anything.  Data and
        COMMON follow all the code, which is above every absolute location
        of the modules before the last; absolute code that still meets
        something (a module's own, or a later module's) is reported by
        link().  The first free address, __END__, is past the absolute code
        too, as L80's $MEMRY is.
        """
        # One past the highest absolute location of the modules before each.
        abs_before = []
        abs_top = 0
        for module in self.modules:
            abs_before.append(abs_top)
            abs_top = max(abs_top, module.abs_top)

        loc = self.code_base
        for module, below in zip(self.modules, abs_before):
            loc = max(loc, below)
            module.code_base = loc
            loc += self._cseg_len(module)

        # Data follows code
        if self.data_base is None:
            self.data_base = loc

        total_data = 0
        for module in self.modules:
            module.data_base = self.data_base + total_data
            total_data += module.data_size

        # Common follows data
        if self.common_base is None:
            self.common_base = self.data_base + total_data

        # Each COMMON block gets its own place, in the order the blocks were
        # first declared, the size of its largest declaration.  (They were
        # all placed at common_base, on top of each other.)
        self.common_bases = {}
        total_common = 0
        for name, size in self.commons.items():
            self.common_bases[name] = self.common_base + total_common
            total_common += size
        self.total_common = total_common

        # Add __END__ symbol pointing to first free byte after all segments
        # and absolute code.  This is an absolute address, not
        # module-relative.
        end_addr = self.common_base + total_common
        self.globals['__END__'] = (0, max(end_addr, abs_top), ADDR_ABSOLUTE,
                                   True)

        # BSS region = COMMON area (uninitialized data, zeroed by crt0)
        self.globals['__BSS_START'] = (0, self.common_base, ADDR_ABSOLUTE, True)
        self.globals['__BSS_END'] = (0, end_addr, ADDR_ABSOLUTE, True)

    def relocate_value(self, module, value, seg_type, block=None):
        """Relocate a value based on its segment type (and COMMON block)."""
        if seg_type == ADDR_ABSOLUTE:
            return value
        elif seg_type == ADDR_PROGRAM_REL:
            return value + module.code_base
        elif seg_type == ADDR_DATA_REL:
            return value + module.data_base
        elif seg_type == ADDR_COMMON_REL:
            return value + self.common_bases.get(block, self.common_base)
        return value

    def _global_address(self, name):
        """(address, module_idx, value, seg_type) of a defined global."""
        mod_idx, value, seg_type, _ = self.globals[name]
        module = self.modules[mod_idx] if self.modules else None
        if module is None:
            return value, mod_idx, value, seg_type
        return (self.relocate_value(module, value, seg_type,
                                    self.global_blocks.get(name)),
                mod_idx, value, seg_type)

    def link(self):
        """Link all loaded modules."""
        if self.load_failed:
            return False

        # Resolve aliased public symbols first (EQU external+offset made PUBLIC)
        # These need to be in globals before resolve_externals() checks references
        self.resolve_aliased_publics()

        if not self.resolve_externals():
            return False

        self.calculate_addresses()
        if not self.check_absolute_overlaps():
            return False

        # Aliases onto a linker-defined symbol (__END__ and friends) only get a
        # value once the segments are placed.
        self.resolve_aliased_publics(refresh=True)

        # Place each module's segments at their output addresses. ASEG bytes go
        # to their absolute address; CSEG -> code_base; DSEG -> data_base.
        # Of a COMMON block only the bytes a module loads into it are placed
        # (a DB in it, FORTRAN's BLOCK DATA); the rest is uninitialized.
        # The leading zero padding of an ASEG buffer (from offset 0 up to
        # its ORG) is skipped. output_base is the lowest address actually
        # written; the output size covers the highest.
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

        def _placed(module, seg, start, end, loaded=False):
            """Buffer offsets of `module' that the image covers, or with
            `loaded', that it takes bytes from.  Of ASEG that is only what
            the module loaded: the gap an ORG or DS leaves is zeros in the
            buffer, and those went over any code another module had there
            (a CSEG at 0100H, after it a module loading at 0080H and
            0300H)."""
            if isinstance(seg, tuple):
                return [start + p for p in sorted(module.common_data.get(seg, ()))
                        if start + p < end]
            if seg == ADDR_ABSOLUTE and loaded:
                return [start + p for p in sorted(module.abs_loaded)
                        if start + p < end]
            begin = max(start, module.code_start) if seg == ADDR_ABSOLUTE else start
            return range(begin, end)

        for module in self.modules:
            for seg, start, end in self._segment_ranges(module):
                placed = _placed(module, seg, start, end)
                if isinstance(seg, tuple):
                    for o in placed:
                        addr = self._buf_offset_addr(module, o)
                        _span(addr, addr + 1)
                elif len(placed):
                    _span(self._buf_offset_addr(module, placed[0]),
                          self._buf_offset_addr(module, placed[-1]) + 1)
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

        # Which module's byte each byte of the image is, and at what offset
        # in its buffer: the later module's where two load the same byte
        # (a COMMON block they share).
        self.owner_mod = array('i', [-1]) * len(self.output)
        self.owner_off = array('i', [-1]) * len(self.output)

        def _put(idx, module, o):
            out = self._buf_offset_addr(module, o) - self.output_base
            if 0 <= out < len(self.output):
                self.output[out] = module.code[o]
                self.owner_mod[out] = idx
                self.owner_off[out] = o

        for idx, module in enumerate(self.modules):
            for seg, start, end in self._segment_ranges(module):
                for o in _placed(module, seg, start, end, loaded=True):
                    _put(idx, module, o)

        # Fix up external references
        # Track which (module_index, buf_offset) pairs are resolved externally
        # so Phase 2 relocation doesn't double-apply segment bases
        resolved_external_locs = self.chained_locs = set()

        for mod_idx, module in enumerate(self.modules):
            for name, refs in module.externals.items():
                # "SYMBOL+N": the offset in the name, as um80 up to 0.3.48
                # wrote a reference to SYMBOL plus a constant.
                base_name, expr_offset = self._split_offset_name(name)

                if base_name not in self.globals:
                    continue

                target_addr, def_idx, target_value, target_seg_type = \
                    self._global_address(base_name)
                target_addr += expr_offset
                # Under MP/M page zero belongs to the memory segment, so a
                # reference to BDOS/FCB/TBUFF relocates like any program
                # address.
                moves = self._moves(base_name, target_value, target_seg_type)
                # LINK-80 fills the chain when both this module and the
                # one defining the symbol are loaded (the linker's own
                # symbols: at the end).
                until = len(self.modules) if base_name in self.moving \
                    else max(mod_idx, def_idx)

                for head, _ in refs:
                    self._fill_chain(module, mod_idx, head, target_addr, moves,
                                     until)

            # Item 12: the address of where the item appeared, in every
            # word of the chain it heads (ul80 read the item and never
            # applied it, so FORTRAN-80's forward jumps kept their chain
            # links).  The chain was followed when the module was loaded.
            for buf_offset, key, offset, mask in module.chain_addresses:
                seg_type, block = key if isinstance(key, tuple) else (key, None)
                value = self.relocate_value(module, offset, seg_type, block)
                out = self._buf_offset_addr(module, buf_offset) - self.output_base
                stored = self._store_word(
                    out, value, self._own(mod_idx, buf_offset, out, mask))
                if seg_type != ADDR_ABSOLUTE and stored & 2:
                    self.external_relocations.append(out)

        # Apply relocations for program-relative, data-relative, and
        # common-relative addresses: to the value each word was loaded with,
        # in each byte of it nothing was loaded over later.
        for mod_idx, module in enumerate(self.modules):
            for buf_offset, seg_type, _, block, value, mask in module.relocations:
                # Skip locations already resolved by external reference fixup
                if (mod_idx, buf_offset) in resolved_external_locs:
                    continue

                # Output offset for the reference (ASEG absolute, CSEG/DSEG rebased)
                abs_offset = self._buf_offset_addr(module, buf_offset) - self.output_base
                value = self.relocate_value(module, value, seg_type, block)
                self._store_word(abs_offset, value,
                                 self._own(mod_idx, buf_offset, abs_offset, mask))

        # Items 9 and 8: the constant of EXT+n / EXT-n, added once the word
        # holds EXT.  (They were read and ignored: every JMP EXT+3 in an
        # object MACRO-80 wrote linked to EXT.)
        for module in self.modules:
            for buf_offset, sign, (a_type, a_value), block in module.offsets:
                out = self._buf_offset_addr(module, buf_offset) - self.output_base
                if 0 <= out and out + 1 < len(self.output):
                    delta = self.relocate_value(module, a_value, a_type, block)
                    value = self.output[out] | (self.output[out + 1] << 8)
                    value = (value + sign * delta) & 0xFFFF
                    self.output[out] = value & 0xFF
                    self.output[out + 1] = value >> 8

        # Fields computed from extension link items, last: every segment is
        # placed and every symbol known, and each field's placeholder bytes
        # are already in the image to be overwritten.
        ok = self.apply_expressions()
        self.store_memry()
        return ok

    def _areas(self):
        """(what, module index or None, first, end) of each relocatable
        area: every module's program and data area, and every COMMON
        block.

        A module that loads absolute code and nothing in CSEG (or DSEG)
        has no program (data) area, whatever size it declares: an object
        that gives its absolute code's size as the program size is not
        overlapping itself.
        """
        for idx, module in enumerate(self.modules):
            size = {seg: end - start
                    for seg, start, end in self._segment_ranges(module)}
            code = max(self._cseg_len(module), size.get(ADDR_PROGRAM_REL, 0))
            data = max(module.data_size, size.get(ADDR_DATA_REL, 0))
            if code and (ADDR_PROGRAM_REL in size or not module.abs_loaded):
                yield 'program area', idx, module.code_base, module.code_base + code
            if data and (ADDR_DATA_REL in size or not module.abs_loaded):
                yield 'data area', idx, module.data_base, module.data_base + data
        for name, size in self.commons.items():
            if size:
                base = self.common_bases[name]
                label = f"COMMON /{name.strip()}/" if name.strip() \
                    else 'blank COMMON'
                yield label, None, base, base + size

    @staticmethod
    def _ranges(addrs):
        """`0100H-0107H, 0200H' for a sorted list of addresses."""
        runs = []
        for a in addrs:
            if runs and a == runs[-1][1] + 1:
                runs[-1][1] = a
            else:
                runs.append([a, a])
        return ', '.join(f"{lo:04X}H" if lo == hi else f"{lo:04X}H-{hi:04X}H"
                         for lo, hi in runs)

    def check_absolute_overlaps(self):
        """Report absolute code loaded where something else is: in a
        module's program or data area (its own, or another's), in a COMMON
        block, or where another module loaded absolute code.

        LINK-80 prints "%Overlaying Program area" (or Data area) and writes
        a mixture of the two - with /D: the later bytes, without it partly
        the earlier ones.  The image is wrong either way, so here it is an
        error and the link fails.  Absolute code a module loads twice
        itself (an ORG back over its own bytes) is the module's business:
        the later bytes load, as in the assembler.  Returns False if there
        was any.
        """
        owner = {}  # address -> index of the module whose absolute byte it is
        found = []
        for idx, module in enumerate(self.modules):
            clash = {}  # other module's index -> addresses both load
            for a in sorted(module.abs_loaded):
                other = owner.setdefault(a, idx)
                if other != idx:
                    clash.setdefault(other, []).append(a)
            found += [self._overlap(idx, addrs, "absolute code of module "
                                    + self.modules[other].name)
                      for other, addrs in clash.items()]
        for what, area_idx, first, end in self._areas() if owner else ():
            hits = {}  # module index -> its absolute addresses in the area
            for a in range(first, end):
                if a in owner:
                    hits.setdefault(owner[a], []).append(a)
            found += [self._overlap(idx, addrs,
                                    f"{self._whose(what, area_idx, idx)} "
                                    f"({first:04X}H-{end - 1:04X}H)")
                      for idx, addrs in hits.items()]
        for msg in found:
            self.error(msg)
        return not found

    def _whose(self, what, area_idx, idx):
        """`what' (an area of module `area_idx', or a COMMON block if
        None) as the message for module `idx' names it."""
        if area_idx is None:
            return what
        if area_idx == idx:
            return f"its own {what}"
        return f"the {what} of module {self.modules[area_idx].name}"

    def _overlap(self, idx, addrs, what):
        """The message for module `idx' loading absolute code at `addrs'
        over `what'."""
        return (f"Module {self.modules[idx].name}: absolute code at "
                f"{self._ranges(addrs)} overlaps {what}")

    def store_memry(self):
        """Store the first free address in the word at $MEMRY, as LINK-80.

        If a module defines the global $MEMRY, LINK-80 3.44 overwrites the
        word there with the address of the first byte after the data area
        (its /E summary prints the same number): FORTRAN-80's FORLIB
        (module DSKDRV) allocates its file buffers from it.  Probed with
        L80: it is written whatever the module loaded there, in DSEG or
        CSEG, and it is the end of the data area even when /D puts that
        below the program.  ul80 puts data and COMMON after the code, so
        that is __END__.  The value is a program address: it moves in a
        .PRL.
        """
        if '$MEMRY' not in self.globals or not self.globals['$MEMRY'][3]:
            return
        addr = self._global_address('$MEMRY')[0]
        end = self.globals['__END__'][1] & 0xFFFF
        out = addr - self.output_base
        if 0 <= out and out + 1 < len(self.output):
            self.output[out] = end & 0xFF
            self.output[out + 1] = end >> 8
            self.external_relocations.append(out)

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
                block = item[2] if len(item) > 2 else None
                value = self.relocate_value(module, value, addr_type,
                                            block) & 0xFFFF
                stack.append((value, self._move(
                    0 if addr_type == ADDR_ABSOLUTE else 256)))
                continue
            if item[0] == 'EXT_SYMBOL':
                name = item[1]
                if name not in self.globals or not self.globals[name][3]:
                    self.error(f"Undefined symbol: {name}")
                    return None
                value, _, t_value, t_seg = self._global_address(name)
                value &= 0xFFFF
                # The same rule resolve-by-chain uses (_moves()).
                moves = self._moves(name, t_value, t_seg)
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
        # DIV, MOD: of values that do not move at all; and an address that
        # moves by whole pages divided by 256 or taken MOD 256 - the page
        # rounding (BUF+255)/256 - which is HIGH or LOW of it: the quotient
        # moves by the pages, the remainder not at all.
        if ma == mb == 0 and exact:
            return self._move(0)
        if mb == 0 and eb and ea and b == 256 and ma % 256 == 0:
            if op == EXT_OP_DIV:
                page = (ma // 256) % 256
                return self._move(page, page == 0, True)
            return self._move(0)
        return None

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
        """Save as CP/M .COM file: the image from the origin (-p, 100H by
        default), or from below it if absolute code lies there.

        A program with only absolute code above the origin (`ASEG / ORG
        200H') started at its lowest byte, which CP/M then loaded at 0100H;
        LINK-80 writes the .COM from the origin, as here.
        """
        data = bytes(self.output)
        if self.output_base > self.code_base:
            data = bytes(self.output_base - self.code_base) + data
        with open(filename, 'wb') as f:
            f.write(data)
            # Pad to CP/M record boundary (128 bytes)
            remainder = len(data) % 128
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
        # COMMON is placed after the image and is not in it: the memory MP/M
        # allocates has to reach its end.  (It asked for none: a program
        # with COMMON wrote past its segment.)
        if self.total_common:
            common_end = self.common_base + self.total_common
            bss_size = max(bss_size,
                           common_end - (self.output_base + code_length))

        # Build relocation bitmap - one bit per byte of code
        # Bit is set if corresponding byte is a HIGH byte of relocatable address
        bitmap_size = (code_length + 7) // 8
        bitmap = bytearray(bitmap_size)

        # Collect all relocation high-byte offsets from all modules: the
        # words that are addresses, where link() put them.  A word in a
        # chain holds what link() filled in, not the link its relocation
        # record describes: external_relocations has it if that moves.
        for mod_idx, module in enumerate(self.modules):
            for buf_offset, _, _, _, _, mask in module.relocations:
                if (mod_idx, buf_offset) in self.chained_locs:
                    continue
                abs_offset = self._buf_offset_addr(module, buf_offset) \
                    - self.output_base
                high_byte_offset = abs_offset + 1

                # Not a byte loaded over later, which is not an address.
                if self._own(mod_idx, buf_offset, abs_offset, mask)[1]:
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
        for name, (_, _, _, is_defined) in self.globals.items():
            if is_defined and self.modules:
                symbols.append((name, self._global_address(name)[0]))

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

    # Resolve undefined symbols from libraries, as LINK-80 searches one:
    # each library in turn, its modules in library order, loading every
    # module that defines a symbol still undefined (one it loads may need
    # more).  Repeat until nothing more is loaded.  The search went through
    # a Python set of the undefined names, so the modules - and the image -
    # came out in an order that changed from run to run.
    modules_loaded = set()  # Track which library modules we've already loaded
    loaded_any = True
    while libraries and loaded_any:
        loaded_any = False
        for lib_filename, lib in libraries:
            for lib_module in lib.modules:
                undefined = set(linker.get_undefined_symbols())
                if not undefined:
                    break
                lib_mod_key = (lib_filename, lib_module.name)
                if lib_mod_key in modules_loaded:
                    continue
                if undefined.intersection(lib_module.publics):
                    linker.load_rel_data(lib_module.name, lib_module.data)
                    modules_loaded.add(lib_mod_key)
                    loaded_any = True

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
