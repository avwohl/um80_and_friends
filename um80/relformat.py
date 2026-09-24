"""
Microsoft REL relocatable object file format for um80/ul80.

REL files are bit streams. Items are NOT byte-aligned.

Bit patterns:
- 0 + 8 bits: Absolute byte to load
- 1 00: Special LINK item
- 1 01 + 16 bits: Program relative (add to code segment base)
- 1 10 + 16 bits: Data relative (add to data segment base)
- 1 11 + 16 bits: Common relative (add to common base)

Special LINK items (100 + 4-bit control):
Control  A-field  B-field  Meaning
0        -        B        Entry symbol (for library search)
1        -        B        Select COMMON block
2        -        B        Program name
3        -        B        Request library search
4        -        B        Extension link item (see below)
5        A        B        Define COMMON size
6        A        B        Chain external (A=head, B=name)
7        A        B        Define entry point (A=addr, B=name)
8        A        -        External - offset (subtract A from the word here)
9        A        -        External + offset (add A to the word here)
10       A        -        Define Data area size
11       A        -        Set location counter
12       A        -        Chain address (A=head of chain)
13       A        -        Define program size (MACRO-80 types A program
                           relative; LINK-80 3.44 writes no output when
                           it is absolute)
14       A        -        End program (A=start address, or absolute 0;
                           then force byte boundary)
15       -        -        End file

Up to 0.3.48 um80 wrote item 14 without its A-field, which LINK-80 3.44
rejects ("?Loading Error", or a hang).  RELReader still reads such files:
see _read_end_program().

A word that is an external plus a constant - `JMP EXT+3', `LXI H,EXT-1' -
is written the way MACRO-80 writes it: item 9 with the constant (16-bit,
so EXT-1 is FFFFH), then the word itself as a reference in the external's
chain.  LINK-80 adds the constant once the chain is resolved.  um80 used to
put the constant in the chain's name instead ("EXT+3"), which only ul80
understood; ul80 still reads that too.  LINK-80 ends a chain at absolute 0,
so a reference AT absolute 0 cannot be in a chain: um80 writes that one as
an extension link item (B(EXT) A(store word)).

A-field: 2-bit address type + 16-bit value
  00 = absolute
  01 = program relative
  10 = data relative
  11 = common relative

B-field: 3-bit length (0-7, but 0 means 8 chars) + 8 bits per character.
LINK-80 3.44 refuses a count of 0 ("?Loading Error"), so an L80-readable
B-field has at most 7 bytes: a symbol of 7 characters, or an extension item
'B' naming an external of at most 6.  MACRO-80 truncates every symbol to 6
characters, so it never writes more.

Extension link items (special item 4)
-------------------------------------
The Microsoft Utility Software Manual defines item 4 as a B-field-only item
whose first byte names the kind of extension and whose remaining 1-7 bytes
are its data (the manual itself lists only X'35', the COBOL overlay segment
sentinel).  MACRO-80 3.44 and LINK-80 3.44 use three more kinds to pass an
expression the assembler cannot evaluate - one whose value depends on where
the linker puts a segment or on an external symbol - to the linker as a
postfix program:

  'A' (41H) op          arithmetic operator:
                          1 store as byte     2 store as word
                          3 HIGH              4 LOW
                          5 NOT               6 unary minus
                          7 minus             8 plus
                          9 multiply         10 divide        11 MOD
  'B' (42H) name        push the value of the external symbol `name'
  'C' (43H) t lo hi     push the 16-bit value lo+256*hi of address type t
                        (0 absolute, 1 program, 2 data, 3 common relative),
                        relocated like a 1 01/1 10/1 11 item

Operands are pushed in source order and a binary operator pops its right
operand first, so `buf+128' is  C(data,buf) C(abs,128) A(plus), and
`high(ext-5)' is  B(ext) C(abs,5) A(minus) A(HIGH).  Every expression ends in
a store operator.  The store writes the result at the location counter it
finds - the items come immediately BEFORE the field they fill - and the
assembler then emits the field itself as absolute placeholder bytes (0, or
0 0 for a word), which load at that location and advance the counter as
usual.  The linker evaluates the expression once every segment is placed and
every external defined, and overwrites the placeholder.

Nothing above is in the published manual beyond the item 4 format; it was
established by assembling test sources with the real MACRO-80 3.44 and
linking them with LINK-80 3.44 (09-Dec-81) under a CP/M emulator, and agrees
with the description in the Nestor80 project's RelocatableFileFormat.md.
For example M80 turns `MVI A,LOW(BUF+128)' (BUF data-relative 0003H) into

  0 3E                      absolute byte: the MVI opcode
  100 0100 100 43 02 03 00  C: data-relative 0003H
  100 0100 100 43 00 80 00  C: absolute 0080H
  100 0100 010 41 08        A: plus
  100 0100 010 41 04        A: LOW
  100 0100 010 41 01        A: store as byte
  0 00                      the placeholder byte

and M80 uses the same form for any relocatable or external value in a
one-byte field (`MVI A,BUF' is C(data,3) A(store byte)).  Digital Research's
LINK-80 lists item 4 as unused and RMAC rejects HIGH/LOW of a relocatable
value with an 'E' error, so DRI's tools neither write nor read it.

An external name of more than 7 characters after the 'B' uses um80's
extended B-field (length 0, then FFH, then the real length), as other long
symbols do.  ul80 reads it; LINK-80 does not (see B-field above), nor a 'B'
item of exactly 8 bytes (a 7-character name).
"""


class BitWriter:
    """Write bits to a byte stream."""

    def __init__(self):
        self.bytes = bytearray()
        self.current_byte = 0
        self.bit_pos = 0  # 0-7, next bit to write (MSB first)

    def write_bit(self, bit):
        """Write a single bit (0 or 1)."""
        if bit:
            self.current_byte |= (0x80 >> self.bit_pos)
        self.bit_pos += 1
        if self.bit_pos == 8:
            self.bytes.append(self.current_byte)
            self.current_byte = 0
            self.bit_pos = 0

    def write_bits(self, value, count):
        """Write 'count' bits from value (MSB first)."""
        for i in range(count - 1, -1, -1):
            self.write_bit((value >> i) & 1)

    def write_byte(self, value):
        """Write 8 bits."""
        self.write_bits(value & 0xFF, 8)

    def write_word(self, value):
        """Write 16 bits (low byte first, as per 8080 convention)."""
        self.write_byte(value & 0xFF)
        self.write_byte((value >> 8) & 0xFF)

    def force_byte_boundary(self):
        """Pad to next byte boundary."""
        if self.bit_pos != 0:
            self.bytes.append(self.current_byte)
            self.current_byte = 0
            self.bit_pos = 0

    def append(self, other):
        """Write every bit `other' holds, as if written here."""
        for byte in other.bytes:
            self.write_byte(byte)
        for i in range(other.bit_pos):
            self.write_bit((other.current_byte >> (7 - i)) & 1)

    def get_bytes(self):
        """Get the byte array, padding if necessary."""
        result = bytearray(self.bytes)
        if self.bit_pos != 0:
            result.append(self.current_byte)
        return bytes(result)


class BitReader:
    """Read bits from a byte stream."""

    def __init__(self, data):
        self.data = data
        self.byte_pos = 0
        self.bit_pos = 0  # 0-7, next bit to read (MSB first)

    def read_bit(self):
        """Read a single bit."""
        if self.byte_pos >= len(self.data):
            raise EOFError("End of REL file")
        bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1
        self.bit_pos += 1
        if self.bit_pos == 8:
            self.byte_pos += 1
            self.bit_pos = 0
        return bit

    def read_bits(self, count):
        """Read 'count' bits and return as integer."""
        value = 0
        for _ in range(count):
            value = (value << 1) | self.read_bit()
        return value

    def read_byte(self):
        """Read 8 bits."""
        return self.read_bits(8)

    def read_word(self):
        """Read 16 bits (low byte first)."""
        low = self.read_byte()
        high = self.read_byte()
        return low | (high << 8)

    def at_end(self):
        """Check if at end of data."""
        return self.byte_pos >= len(self.data)

    def force_byte_boundary(self):
        """Skip to next byte boundary."""
        if self.bit_pos != 0:
            self.byte_pos += 1
            self.bit_pos = 0


# Address type constants
ADDR_ABSOLUTE = 0
ADDR_PROGRAM_REL = 1
ADDR_DATA_REL = 2
ADDR_COMMON_REL = 3

# Special link item types
LINK_ENTRY_SYMBOL = 0
LINK_SELECT_COMMON = 1
LINK_PROGRAM_NAME = 2
LINK_REQUEST_LIB = 3
LINK_EXTENSION = 4
LINK_RESERVED = LINK_EXTENSION  # former name, kept for callers
LINK_DEFINE_COMMON_SIZE = 5
LINK_CHAIN_EXTERNAL = 6
LINK_DEFINE_ENTRY = 7
LINK_EXTERNAL_OFFSET = 8
LINK_EXTERNAL_PLUS_OFFSET = 9
LINK_DEFINE_DATA_SIZE = 10
LINK_SET_LOC = 11
LINK_CHAIN_ADDRESS = 12
LINK_DEFINE_PROG_SIZE = 13
LINK_END_PROGRAM = 14
LINK_END_FILE = 15

# Extension link item kinds (first byte of an item 4's B-field)
EXT_ITEM_OPERATOR = 0x41  # 'A': arithmetic operator
EXT_ITEM_SYMBOL = 0x42    # 'B': value of an external symbol
EXT_ITEM_VALUE = 0x43     # 'C': (relocatable) value

# Arithmetic operator codes of an 'A' extension item
EXT_OP_STORE_BYTE = 1
EXT_OP_STORE_WORD = 2
EXT_OP_HIGH = 3
EXT_OP_LOW = 4
EXT_OP_NOT = 5
EXT_OP_NEG = 6
EXT_OP_MINUS = 7
EXT_OP_PLUS = 8
EXT_OP_MUL = 9
EXT_OP_DIV = 10
EXT_OP_MOD = 11

EXT_OP_NAMES = {
    EXT_OP_STORE_BYTE: 'store byte', EXT_OP_STORE_WORD: 'store word',
    EXT_OP_HIGH: 'HIGH', EXT_OP_LOW: 'LOW', EXT_OP_NOT: 'NOT',
    EXT_OP_NEG: 'unary -', EXT_OP_MINUS: '-', EXT_OP_PLUS: '+',
    EXT_OP_MUL: '*', EXT_OP_DIV: '/', EXT_OP_MOD: 'MOD',
}


class RELWriter:
    """Write Microsoft REL format relocatable object files."""

    def __init__(self, truncate_symbols=False):
        self.bits = BitWriter()
        self.truncate_symbols = truncate_symbols  # If True, truncate to 8 chars like M80

    def write_absolute_byte(self, value):
        """Write an absolute byte (0 + 8 bits)."""
        self.bits.write_bit(0)
        self.bits.write_byte(value)

    def write_program_relative(self, value):
        """Write program-relative 16-bit value."""
        self.bits.write_bits(0b101, 3)  # 1 01
        self.bits.write_word(value)

    def write_data_relative(self, value):
        """Write data-relative 16-bit value."""
        self.bits.write_bits(0b110, 3)  # 1 10
        self.bits.write_word(value)

    def write_common_relative(self, value):
        """Write common-relative 16-bit value."""
        self.bits.write_bits(0b111, 3)  # 1 11
        self.bits.write_word(value)

    def _write_a_field(self, addr_type, value):
        """Write A-field: 2-bit type + 16-bit value."""
        self.bits.write_bits(addr_type, 2)
        self.bits.write_word(value)

    def _write_raw_b_field(self, data):
        """Write a B-field holding raw bytes (no case folding).

        Up to 8 bytes use the standard 3-bit count (0 meaning 8); more use
        um80's extended form: count 0, FFH, the real length, the bytes.
        """
        length = len(data)
        if length <= 8:
            self.bits.write_bits(length & 7, 3)  # 8 is written as 0
        else:
            self.bits.write_bits(0, 3)
            self.bits.write_byte(0xFF)
            self.bits.write_byte(length)
        for b in data:
            self.bits.write_byte(b)

    def _write_b_field(self, name):
        """Write B-field: 3-bit length + characters.

        Extended format for symbols > 8 chars (unless truncate_symbols is set):
        - 3-bit length = 0
        - First byte = 0xFF (marker for extended mode)
        - Second byte = actual length (9-255)
        - Then the characters
        """
        name = name.upper()

        if self.truncate_symbols:
            # M80 compatible: truncate to 8 chars
            name = name[:8]

        length = len(name)

        if length <= 8:
            # Standard format
            if length == 8:
                length = 0  # 0 means 8 characters in standard format
            self.bits.write_bits(length, 3)
            for ch in name:
                self.bits.write_byte(ord(ch))
        else:
            # Extended format for symbols > 8 chars
            self.bits.write_bits(0, 3)  # Length field = 0
            self.bits.write_byte(0xFF)  # Extended mode marker
            self.bits.write_byte(length)  # Actual length (up to 255)
            for ch in name:
                self.bits.write_byte(ord(ch))

    def _write_special(self, control, a_field=None, b_field=None):
        """Write a special LINK item."""
        self.bits.write_bits(0b100, 3)  # 1 00
        self.bits.write_bits(control, 4)
        if a_field is not None:
            addr_type, value = a_field
            self._write_a_field(addr_type, value)
        if b_field is not None:
            self._write_b_field(b_field)

    def write_entry_symbol(self, name):
        """Entry symbol for library search."""
        self._write_special(LINK_ENTRY_SYMBOL, b_field=name)

    def write_select_common(self, name):
        """Select COMMON block."""
        self._write_special(LINK_SELECT_COMMON, b_field=name)

    def write_program_name(self, name):
        """Set program/module name."""
        self._write_special(LINK_PROGRAM_NAME, b_field=name)

    def write_request_library(self, name):
        """Request library search (.REQUEST)."""
        self._write_special(LINK_REQUEST_LIB, b_field=name)

    def write_define_common_size(self, addr_type, size, name):
        """Define COMMON block size."""
        self._write_special(LINK_DEFINE_COMMON_SIZE,
                          a_field=(addr_type, size), b_field=name)

    def write_chain_external(self, addr_type, head, name):
        """Chain external reference."""
        self._write_special(LINK_CHAIN_EXTERNAL,
                          a_field=(addr_type, head), b_field=name)

    def write_define_entry_point(self, addr_type, addr, name):
        """Define entry point (PUBLIC symbol)."""
        self._write_special(LINK_DEFINE_ENTRY,
                          a_field=(addr_type, addr), b_field=name)

    def write_external_offset(self, addr_type, offset, name=None):
        """External minus offset (for JMP/CALL to external).

        An A-field-only item in the Microsoft manual; `name' is ignored and
        kept only so existing callers still work.
        """
        del name
        self._write_special(LINK_EXTERNAL_OFFSET,
                          a_field=(addr_type, offset))

    def write_external_plus_offset(self, addr_type, offset):
        """Add offset to external at current location."""
        self._write_special(LINK_EXTERNAL_PLUS_OFFSET,
                          a_field=(addr_type, offset))

    def write_define_data_size(self, size):
        """Define data segment size."""
        self._write_special(LINK_DEFINE_DATA_SIZE,
                          a_field=(ADDR_ABSOLUTE, size))

    def write_set_location(self, addr_type, addr):
        """Set location counter."""
        self._write_special(LINK_SET_LOC,
                          a_field=(addr_type, addr))

    def write_chain_address(self, addr_type, head):
        """Chain address - fill chain with current location."""
        self._write_special(LINK_CHAIN_ADDRESS,
                          a_field=(addr_type, head))

    def write_define_program_size(self, size):
        """Define program (code) segment size.

        Typed program relative, as MACRO-80 writes it: LINK-80 3.44 exits
        without writing any output when it is absolute.
        """
        self._write_special(LINK_DEFINE_PROG_SIZE,
                          a_field=(ADDR_PROGRAM_REL, size))

    def write_extension(self, data):
        """Extension link item (special item 4) with the given B-field bytes."""
        self.bits.write_bits(0b100, 3)
        self.bits.write_bits(LINK_EXTENSION, 4)
        self._write_raw_b_field(bytes(data))

    def write_ext_operator(self, code):
        """Extension item 'A': arithmetic or store operator `code'."""
        self.write_extension([EXT_ITEM_OPERATOR, code])

    def write_ext_symbol(self, name):
        """Extension item 'B': push the value of external symbol `name'."""
        name = name.upper()
        if self.truncate_symbols:
            name = name[:8]
        self.write_extension(bytes([EXT_ITEM_SYMBOL]) + name.encode('ascii'))

    def write_ext_value(self, addr_type, value):
        """Extension item 'C': push `value' of address type `addr_type'."""
        value &= 0xFFFF
        self.write_extension([EXT_ITEM_VALUE, addr_type,
                              value & 0xFF, value >> 8])

    def write_end_program(self, entry_addr=None, entry_type=ADDR_ABSOLUTE):
        """End of program: item 14, whose A-field is the start address.

        With no start address the A-field is absolute 0, as MACRO-80 writes
        it.  (um80 wrote a set-location item for the start address and no
        A-field up to 0.3.48.)
        """
        if entry_addr is None:
            entry_addr, entry_type = 0, ADDR_ABSOLUTE
        self._write_special(LINK_END_PROGRAM,
                            a_field=(entry_type, entry_addr & 0xFFFF))
        self.bits.force_byte_boundary()

    def write_end_file(self):
        """End of file marker."""
        self._write_special(LINK_END_FILE)
        self.bits.force_byte_boundary()

    def append(self, other):
        """Append the items another RELWriter holds (no byte boundary)."""
        self.bits.append(other.bits)

    def get_bytes(self):
        """Get the REL file content."""
        return self.bits.get_bytes()


class RELReader:
    """Read Microsoft REL format relocatable object files."""

    def __init__(self, data):
        self.bits = BitReader(data)

    def _read_a_field(self):
        """Read A-field, return (addr_type, value)."""
        addr_type = self.bits.read_bits(2)
        value = self.bits.read_word()
        return (addr_type, value)

    def _read_raw_b_field(self):
        """Read a B-field and return its bytes, unaltered.

        Extended format detection:
        - If 3-bit length = 0 and first byte = 0xFF, use extended format
        - Extended: next byte is actual length (9-255), then characters
        - Standard: length 0 means 8 chars
        """
        length = self.bits.read_bits(3)
        if length == 0:
            # Could be standard 8-char or extended format
            first_byte = self.bits.read_byte()
            if first_byte == 0xFF:
                # Extended format: next byte is actual length
                length = self.bits.read_byte()
                return bytes(self.bits.read_byte() for _ in range(length))
            # Standard 8-char format, first_byte is first char
            return bytes([first_byte]) + bytes(self.bits.read_byte()
                                               for _ in range(7))
        # Standard format with explicit length 1-7
        return bytes(self.bits.read_byte() for _ in range(length))

    def _read_b_field(self):
        """Read B-field, return symbol name (uppercased for L80 compatibility)."""
        return ''.join(chr(b) for b in self._read_raw_b_field()).upper()

    def _read_extension(self):
        """Read an extension link item's B-field and decode it.

        Returns ('EXT_OPERATOR', code), ('EXT_SYMBOL', name),
        ('EXT_VALUE', (addr_type, value)), or, for a kind this module does
        not interpret (such as the COBOL overlay sentinel),
        ('EXTENSION', kind_byte, payload_bytes).  The whole B-field is always
        consumed, so the bit stream stays in step whatever the kind.
        """
        data = self._read_raw_b_field()
        kind, payload = (data[0], data[1:]) if data else (None, b'')
        if kind == EXT_ITEM_OPERATOR and len(payload) == 1:
            return ('EXT_OPERATOR', payload[0])
        if kind == EXT_ITEM_SYMBOL and payload:
            return ('EXT_SYMBOL', ''.join(chr(b) for b in payload).upper())
        if kind == EXT_ITEM_VALUE and len(payload) == 3:
            return ('EXT_VALUE', (payload[0], payload[1] | (payload[2] << 8)))
        return ('EXTENSION', kind, payload)

    def _byte_at_boundary(self, byte_pos, bit_pos):
        """The byte at the first byte boundary at or after a bit position."""
        pos = byte_pos + (1 if bit_pos else 0)
        return self.bits.data[pos] if pos < len(self.bits.data) else None

    def _read_end_program(self):
        """The A-field of item 14 (end program), or None if it has none.

        MACRO-80 writes the start address there (absolute 0 if none); um80 up
        to 0.3.48 wrote no A-field, going straight to the byte boundary,
        and always followed it with item 15 (end file, byte 9EH once
        aligned).  Both are read: the A-field is taken to be absent only if
        reading it would run past the end of the data, or if what follows
        it is not an item that can follow item 14 while the byte right after
        the control field's boundary is the end-file item.
        """
        byte_pos, bit_pos = self.bits.byte_pos, self.bits.bit_pos
        legacy_next = self._byte_at_boundary(byte_pos, bit_pos)
        try:
            a = self._read_a_field()
        except EOFError:
            a = None
        if a is not None:
            after = self._byte_at_boundary(self.bits.byte_pos, self.bits.bit_pos)
            # End file, or a module that begins with its name (item 2) or
            # an entry symbol (item 0): 1 00 0010 / 1 00 0000.
            follows = after == 0x9E or (after is not None
                                        and (after & 0xFE) in (0x84, 0x80))
            if follows or legacy_next != 0x9E:
                return a
        self.bits.byte_pos, self.bits.bit_pos = byte_pos, bit_pos
        return None

    def read_item(self):
        """
        Read next item from REL file.
        Returns tuple describing the item, or None at end.
        """
        if self.bits.at_end():
            return None

        first_bit = self.bits.read_bit()

        if first_bit == 0:
            # Absolute byte
            return ('ABSOLUTE_BYTE', self.bits.read_byte())

        # Relocatable item
        reloc_type = self.bits.read_bits(2)

        if reloc_type == 0:
            # Special LINK item
            control = self.bits.read_bits(4)

            if control == LINK_ENTRY_SYMBOL:
                return ('ENTRY_SYMBOL', self._read_b_field())
            elif control == LINK_SELECT_COMMON:
                return ('SELECT_COMMON', self._read_b_field())
            elif control == LINK_PROGRAM_NAME:
                return ('PROGRAM_NAME', self._read_b_field())
            elif control == LINK_REQUEST_LIB:
                return ('REQUEST_LIB', self._read_b_field())
            elif control == LINK_EXTENSION:
                return self._read_extension()
            elif control == LINK_DEFINE_COMMON_SIZE:
                a = self._read_a_field()
                b = self._read_b_field()
                return ('DEFINE_COMMON_SIZE', a, b)
            elif control == LINK_CHAIN_EXTERNAL:
                a = self._read_a_field()
                b = self._read_b_field()
                return ('CHAIN_EXTERNAL', a, b)
            elif control == LINK_DEFINE_ENTRY:
                a = self._read_a_field()
                b = self._read_b_field()
                return ('DEFINE_ENTRY', a, b)
            elif control == LINK_EXTERNAL_OFFSET:
                # A-field only (Microsoft manual: "External - offset").
                return ('EXTERNAL_OFFSET', self._read_a_field())
            elif control == LINK_EXTERNAL_PLUS_OFFSET:
                a = self._read_a_field()
                return ('EXTERNAL_PLUS_OFFSET', a)
            elif control == LINK_DEFINE_DATA_SIZE:
                a = self._read_a_field()
                return ('DEFINE_DATA_SIZE', a)
            elif control == LINK_SET_LOC:
                a = self._read_a_field()
                return ('SET_LOC', a)
            elif control == LINK_CHAIN_ADDRESS:
                a = self._read_a_field()
                return ('CHAIN_ADDRESS', a)
            elif control == LINK_DEFINE_PROG_SIZE:
                a = self._read_a_field()
                return ('DEFINE_PROG_SIZE', a)
            elif control == LINK_END_PROGRAM:
                a = self._read_end_program()
                self.bits.force_byte_boundary()
                return ('END_PROGRAM', a)
            else:
                # LINK_END_FILE: the sixteenth and last control value.
                self.bits.force_byte_boundary()
                return ('END_FILE',)

        elif reloc_type == 1:
            # Program relative
            return ('PROGRAM_REL', self.bits.read_word())
        elif reloc_type == 2:
            # Data relative
            return ('DATA_REL', self.bits.read_word())
        elif reloc_type == 3:
            # Common relative
            return ('COMMON_REL', self.bits.read_word())

    def read_all(self):
        """Read all items, return as list."""
        items = []
        while True:
            item = self.read_item()
            if item is None:
                break
            items.append(item)
            if item[0] == 'END_FILE':
                break
        return items
