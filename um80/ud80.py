#!/usr/bin/env python3
"""
ud80 - 8080/Z80 Disassembler for CP/M .COM files.

Produces .MAC output compatible with um80 assembler.

Usage: ud80 [-z] [-o output.mac] [-e entry] [-d datarange] input.com

Options:
    -z, --z80       Z80 mode: use Zilog mnemonics and decode Z80-only opcodes
                    (CB, DD, ED, FD prefixes including undocumented instructions)
    -o, --output    Output file (default: input.mac)
    -e, --entry     Additional entry point (hex address)
    -d, --data      Force data range (hex: start-end)
    --org           Origin address (default: 0100 for CP/M)
"""

import sys
import os
import argparse
from collections import defaultdict

# 8080 instruction table: opcode -> (mnemonic, size, operand_type)
# Operand types:
#   None - no operands
#   'r' - single register in bits 3-5
#   's' - single register in bits 0-2
#   'rp' - register pair in bits 4-5
#   'rp2' - register pair for PUSH/POP (includes PSW)
#   'd8' - 8-bit immediate
#   'd16' - 16-bit immediate/address
#   'a16' - 16-bit address (for jumps/calls)
#   'rst' - RST vector in bits 3-5

REGS = ['B', 'C', 'D', 'E', 'H', 'L', 'M', 'A']
REGPAIRS = ['BC', 'DE', 'HL', 'SP']
REGPAIRS_PUSH = ['BC', 'DE', 'HL', 'PSW']
CONDITIONS = ['NZ', 'Z', 'NC', 'C', 'PO', 'PE', 'P', 'M']

# Build instruction table
OPCODES = {}

# No operand instructions
NO_OP = {
    0x00: 'NOP', 0x07: 'RLC', 0x0F: 'RRC', 0x17: 'RAL', 0x1F: 'RAR',
    0x27: 'DAA', 0x2F: 'CMA', 0x37: 'STC', 0x3F: 'CMC', 0x76: 'HLT',
    0xC9: 'RET', 0xE9: 'PCHL', 0xF9: 'SPHL', 0xEB: 'XCHG', 0xE3: 'XTHL',
    0xF3: 'DI', 0xFB: 'EI',
}
for op, mn in NO_OP.items():
    OPCODES[op] = (mn, 1, None)

# MOV r,r' (01 ddd sss) - but 76 is HLT
for d in range(8):
    for s in range(8):
        op = 0x40 | (d << 3) | s
        if op != 0x76:  # HLT
            OPCODES[op] = ('MOV', 1, ('r', 's'))

# MVI r,d8 (00 rrr 110)
for r in range(8):
    op = 0x06 | (r << 3)
    OPCODES[op] = ('MVI', 2, ('r', 'd8'))

# LXI rp,d16 (00 rp0 001)
for rp in range(4):
    op = 0x01 | (rp << 4)
    OPCODES[op] = ('LXI', 3, ('rp', 'd16'))

# INR r (00 rrr 100)
for r in range(8):
    op = 0x04 | (r << 3)
    OPCODES[op] = ('INR', 1, ('r',))

# DCR r (00 rrr 101)
for r in range(8):
    op = 0x05 | (r << 3)
    OPCODES[op] = ('DCR', 1, ('r',))

# INX rp (00 rp0 011)
for rp in range(4):
    op = 0x03 | (rp << 4)
    OPCODES[op] = ('INX', 1, ('rp',))

# DCX rp (00 rp0 011)
for rp in range(4):
    op = 0x0B | (rp << 4)
    OPCODES[op] = ('DCX', 1, ('rp',))

# DAD rp (00 rp1 001)
for rp in range(4):
    op = 0x09 | (rp << 4)
    OPCODES[op] = ('DAD', 1, ('rp',))

# LDAX rp (00 rp0 010) - only BC,DE
for rp in range(2):
    op = 0x0A | (rp << 4)
    OPCODES[op] = ('LDAX', 1, ('rp',))

# STAX rp (00 rp0 010) - only BC,DE
for rp in range(2):
    op = 0x02 | (rp << 4)
    OPCODES[op] = ('STAX', 1, ('rp',))

# PUSH rp (11 rp0 101)
for rp in range(4):
    op = 0xC5 | (rp << 4)
    OPCODES[op] = ('PUSH', 1, ('rp2',))

# POP rp (11 rp0 001)
for rp in range(4):
    op = 0xC1 | (rp << 4)
    OPCODES[op] = ('POP', 1, ('rp2',))

# ALU r (10 ooo rrr)
ALU_OPS = ['ADD', 'ADC', 'SUB', 'SBB', 'ANA', 'XRA', 'ORA', 'CMP']
for alu in range(8):
    for r in range(8):
        op = 0x80 | (alu << 3) | r
        OPCODES[op] = (ALU_OPS[alu], 1, ('s',))

# ALU immediate (11 ooo 110)
ALU_IMM = ['ADI', 'ACI', 'SUI', 'SBI', 'ANI', 'XRI', 'ORI', 'CPI']
for alu in range(8):
    op = 0xC6 | (alu << 3)
    OPCODES[op] = (ALU_IMM[alu], 2, ('d8',))

# Conditional returns (11 ccc 000)
for c in range(8):
    op = 0xC0 | (c << 3)
    mn = 'R' + CONDITIONS[c]
    OPCODES[op] = (mn, 1, None)

# Conditional jumps (11 ccc 010)
for c in range(8):
    op = 0xC2 | (c << 3)
    mn = 'J' + CONDITIONS[c]
    OPCODES[op] = (mn, 3, ('a16',))

# Conditional calls (11 ccc 100)
for c in range(8):
    op = 0xC4 | (c << 3)
    mn = 'C' + CONDITIONS[c]
    OPCODES[op] = (mn, 3, ('a16',))

# JMP
OPCODES[0xC3] = ('JMP', 3, ('a16',))

# CALL
OPCODES[0xCD] = ('CALL', 3, ('a16',))

# RST n (11 nnn 111)
for n in range(8):
    op = 0xC7 | (n << 3)
    OPCODES[op] = ('RST', 1, ('rst',))

# Memory reference
OPCODES[0x3A] = ('LDA', 3, ('a16',))
OPCODES[0x32] = ('STA', 3, ('a16',))
OPCODES[0x2A] = ('LHLD', 3, ('a16',))
OPCODES[0x22] = ('SHLD', 3, ('a16',))

# I/O
OPCODES[0xDB] = ('IN', 2, ('d8',))
OPCODES[0xD3] = ('OUT', 2, ('d8',))

# Z80 extended opcodes
# Z80 register names for Zilog syntax
Z80_REGS = ['B', 'C', 'D', 'E', 'H', 'L', '(HL)', 'A']
Z80_REGPAIRS = ['BC', 'DE', 'HL', 'SP']
Z80_REGPAIRS_AF = ['BC', 'DE', 'HL', 'AF']
Z80_CONDITIONS = ['NZ', 'Z', 'NC', 'C', 'PO', 'PE', 'P', 'M']

# CB-prefix opcodes: bit operations
CB_OPCODES = {}
CB_OPS = ['RLC', 'RRC', 'RL', 'RR', 'SLA', 'SRA', 'SLL', 'SRL']
for op_idx in range(8):
    for r in range(8):
        opcode = (op_idx << 3) | r
        CB_OPCODES[opcode] = (CB_OPS[op_idx], 2, ('cb_r',))

# BIT n,r (01 nnn rrr)
for n in range(8):
    for r in range(8):
        opcode = 0x40 | (n << 3) | r
        CB_OPCODES[opcode] = ('BIT', 2, ('bit_n', 'cb_r'))

# RES n,r (10 nnn rrr)
for n in range(8):
    for r in range(8):
        opcode = 0x80 | (n << 3) | r
        CB_OPCODES[opcode] = ('RES', 2, ('bit_n', 'cb_r'))

# SET n,r (11 nnn rrr)
for n in range(8):
    for r in range(8):
        opcode = 0xC0 | (n << 3) | r
        CB_OPCODES[opcode] = ('SET', 2, ('bit_n', 'cb_r'))

# ED-prefix opcodes
ED_OPCODES = {}

# IN r,(C) / OUT (C),r
for r in range(8):
    if r != 6:  # 6 is special
        ED_OPCODES[0x40 | (r << 3)] = ('IN', 2, ('ed_r', '(C)'))
        ED_OPCODES[0x41 | (r << 3)] = ('OUT', 2, ('(C)', 'ed_r'))
ED_OPCODES[0x70] = ('IN', 2, ('(C)',))  # IN (C) - result discarded

# SBC HL,rp / ADC HL,rp
for rp in range(4):
    ED_OPCODES[0x42 | (rp << 4)] = ('SBC', 2, ('HL', 'ed_rp'))
    ED_OPCODES[0x4A | (rp << 4)] = ('ADC', 2, ('HL', 'ed_rp'))

# LD (nn),rp / LD rp,(nn)
for rp in range(4):
    ED_OPCODES[0x43 | (rp << 4)] = ('LD', 4, ('(a16)', 'ed_rp'))
    ED_OPCODES[0x4B | (rp << 4)] = ('LD', 4, ('ed_rp', '(a16)'))

# NEG (all map to same instruction)
for i in range(8):
    ED_OPCODES[0x44 | (i << 3)] = ('NEG', 2, None)

# RETN / RETI
ED_OPCODES[0x45] = ('RETN', 2, None)
ED_OPCODES[0x4D] = ('RETI', 2, None)
ED_OPCODES[0x55] = ('RETN', 2, None)
ED_OPCODES[0x5D] = ('RETN', 2, None)
ED_OPCODES[0x65] = ('RETN', 2, None)
ED_OPCODES[0x6D] = ('RETN', 2, None)
ED_OPCODES[0x75] = ('RETN', 2, None)
ED_OPCODES[0x7D] = ('RETN', 2, None)

# IM 0/1/2
ED_OPCODES[0x46] = ('IM', 2, ('im0',))
ED_OPCODES[0x56] = ('IM', 2, ('im1',))
ED_OPCODES[0x5E] = ('IM', 2, ('im2',))
ED_OPCODES[0x4E] = ('IM', 2, ('im0',))
ED_OPCODES[0x66] = ('IM', 2, ('im0',))
ED_OPCODES[0x6E] = ('IM', 2, ('im0',))
ED_OPCODES[0x76] = ('IM', 2, ('im1',))
ED_OPCODES[0x7E] = ('IM', 2, ('im2',))

# Special registers
ED_OPCODES[0x47] = ('LD', 2, ('I', 'A'))
ED_OPCODES[0x4F] = ('LD', 2, ('R', 'A'))
ED_OPCODES[0x57] = ('LD', 2, ('A', 'I'))
ED_OPCODES[0x5F] = ('LD', 2, ('A', 'R'))

# Rotate BCD
ED_OPCODES[0x67] = ('RRD', 2, None)
ED_OPCODES[0x6F] = ('RLD', 2, None)

# Block operations
ED_OPCODES[0xA0] = ('LDI', 2, None)
ED_OPCODES[0xA1] = ('CPI', 2, None)
ED_OPCODES[0xA2] = ('INI', 2, None)
ED_OPCODES[0xA3] = ('OUTI', 2, None)
ED_OPCODES[0xA8] = ('LDD', 2, None)
ED_OPCODES[0xA9] = ('CPD', 2, None)
ED_OPCODES[0xAA] = ('IND', 2, None)
ED_OPCODES[0xAB] = ('OUTD', 2, None)
ED_OPCODES[0xB0] = ('LDIR', 2, None)
ED_OPCODES[0xB1] = ('CPIR', 2, None)
ED_OPCODES[0xB2] = ('INIR', 2, None)
ED_OPCODES[0xB3] = ('OTIR', 2, None)
ED_OPCODES[0xB8] = ('LDDR', 2, None)
ED_OPCODES[0xB9] = ('CPDR', 2, None)
ED_OPCODES[0xBA] = ('INDR', 2, None)
ED_OPCODES[0xBB] = ('OTDR', 2, None)

# DD/FD prefix - index register operations
# These modify HL->IX/IY, H->IXH/IYH, L->IXL/IYL in certain instructions
# We'll handle this dynamically in decode_instruction

# Z80-only base opcodes (8080 treats these as undocumented NOPs)
Z80_ONLY_OPCODES = {
    0x08: ('EX', 1, ('af_af',)),      # EX AF,AF'
    0x10: ('DJNZ', 2, ('rel8',)),     # DJNZ d
    0x18: ('JR', 2, ('rel8',)),       # JR d
    0x20: ('JR', 2, ('NZ', 'rel8')),  # JR NZ,d
    0x28: ('JR', 2, ('Z', 'rel8')),   # JR Z,d
    0x30: ('JR', 2, ('NC', 'rel8')),  # JR NC,d
    0x38: ('JR', 2, ('C', 'rel8')),   # JR C,d
}


def format_hex8(val):
    """Format 8-bit value as hex with leading 0 if needed."""
    s = f'{val:02X}H'
    if s[0].isalpha():
        s = '0' + s
    return s


def format_hex16(val):
    """Format 16-bit value as hex with leading 0 if needed."""
    s = f'{val:04X}H'
    if s[0].isalpha():
        s = '0' + s
    return s


class Disassembler:
    """8080/Z80 Disassembler."""

    def __init__(self, data, org=0x0100, z80_mode=False):
        self.data = data
        self.org = org
        self.end = org + len(data)
        self.z80_mode = z80_mode

        # Analysis results
        self.labels = {}  # addr -> label name
        self.code_addrs = set()  # Addresses that are code
        self.data_addrs = set()  # Addresses that are data
        self.refs_from = defaultdict(set)  # addr -> set of addresses that reference it
        self.refs_to = defaultdict(set)  # addr -> set of addresses it references
        self.entry_points = set()  # Known entry points
        self.strings = {}  # addr -> string content

        # Output
        self.output_lines = []

    def byte_at(self, addr):
        """Get byte at address."""
        if addr < self.org or addr >= self.end:
            return None
        return self.data[addr - self.org]

    def word_at(self, addr):
        """Get 16-bit word at address (little endian)."""
        lo = self.byte_at(addr)
        hi = self.byte_at(addr + 1)
        if lo is None or hi is None:
            return None
        return lo | (hi << 8)

    def decode_instruction(self, addr):
        """Decode instruction at address. Returns (mnemonic, size, operands, target)."""
        opcode = self.byte_at(addr)
        if opcode is None:
            return None

        # Z80 mode: handle prefix bytes and Z80-only opcodes
        if self.z80_mode:
            if opcode == 0xCB:
                return self.decode_cb_instruction(addr)
            elif opcode == 0xED:
                return self.decode_ed_instruction(addr)
            elif opcode == 0xDD:
                return self.decode_index_instruction(addr, 'IX')
            elif opcode == 0xFD:
                return self.decode_index_instruction(addr, 'IY')
            elif opcode in Z80_ONLY_OPCODES:
                return self.decode_z80_only_opcode(addr, opcode)

        if opcode not in OPCODES:
            # Unknown opcode - treat as data
            return ('DB', 1, [format_hex8(opcode)], None)

        mnemonic, size, operand_type = OPCODES[opcode]
        operands = []
        target = None

        if operand_type is None:
            pass
        elif operand_type == ('r', 's'):
            # MOV r,r' (8080) / LD r,r' (Z80)
            dst = REGS[(opcode >> 3) & 7]
            src = REGS[opcode & 7]
            if self.z80_mode:
                mnemonic = 'LD'
                dst = Z80_REGS[(opcode >> 3) & 7]
                src = Z80_REGS[opcode & 7]
            operands = [dst, src]
        elif operand_type == ('r', 'd8'):
            # MVI r,d8 (8080) / LD r,n (Z80)
            reg = REGS[(opcode >> 3) & 7]
            imm = self.byte_at(addr + 1)
            if imm is None:
                return None
            if self.z80_mode:
                mnemonic = 'LD'
                reg = Z80_REGS[(opcode >> 3) & 7]
            operands = [reg, format_hex8(imm)]
        elif operand_type == ('r',):
            # INR/DCR r (8080) / INC/DEC r (Z80)
            reg = REGS[(opcode >> 3) & 7]
            if self.z80_mode:
                reg = Z80_REGS[(opcode >> 3) & 7]
                mnemonic = 'INC' if mnemonic == 'INR' else 'DEC'
            operands = [reg]
        elif operand_type == ('s',):
            # ALU r
            reg = REGS[opcode & 7]
            if self.z80_mode:
                reg = Z80_REGS[opcode & 7]
                # Z80 uses different ALU mnemonics
                mnemonic = self.z80_alu_mnemonic(mnemonic, reg)
            operands = [reg] if not self.z80_mode or mnemonic not in ('ADD', 'ADC', 'SBC') else ['A', reg]
        elif operand_type == ('rp',):
            # Register pair operations
            rp = REGPAIRS[(opcode >> 4) & 3]
            if self.z80_mode:
                rp = Z80_REGPAIRS[(opcode >> 4) & 3]
                if mnemonic == 'INX':
                    mnemonic = 'INC'
                elif mnemonic == 'DCX':
                    mnemonic = 'DEC'
                elif mnemonic == 'DAD':
                    mnemonic = 'ADD'
                    operands = ['HL', rp]
                    return (mnemonic, size, operands, target)
                elif mnemonic == 'LDAX':
                    mnemonic = 'LD'
                    operands = ['A', '(' + rp + ')']
                    return (mnemonic, size, operands, target)
                elif mnemonic == 'STAX':
                    mnemonic = 'LD'
                    operands = ['(' + rp + ')', 'A']
                    return (mnemonic, size, operands, target)
            operands = [rp]
        elif operand_type == ('rp2',):
            # PUSH/POP with PSW
            rp = REGPAIRS_PUSH[(opcode >> 4) & 3]
            if self.z80_mode:
                rp = Z80_REGPAIRS_AF[(opcode >> 4) & 3]
            operands = [rp]
        elif operand_type == ('rp', 'd16'):
            # LXI rp,d16 (8080) / LD rp,nn (Z80)
            rp = REGPAIRS[(opcode >> 4) & 3]
            imm = self.word_at(addr + 1)
            if imm is None:
                return None
            if self.z80_mode:
                mnemonic = 'LD'
                rp = Z80_REGPAIRS[(opcode >> 4) & 3]
            operands = [rp, format_hex16(imm)]
            # Check if this might be a code reference
            if self.org <= imm < self.end:
                target = imm
        elif operand_type == ('d8',):
            # 8-bit immediate
            imm = self.byte_at(addr + 1)
            if imm is None:
                return None
            if self.z80_mode:
                mnemonic, operands = self.z80_imm8_mnemonic(mnemonic, imm)
            else:
                operands = [format_hex8(imm)]
        elif operand_type == ('d16',):
            # 16-bit immediate
            imm = self.word_at(addr + 1)
            if imm is None:
                return None
            operands = [format_hex16(imm)]
        elif operand_type == ('a16',):
            # 16-bit address (jumps/calls/memory)
            target = self.word_at(addr + 1)
            if target is None:
                return None
            if self.z80_mode:
                mnemonic, operands = self.z80_addr_mnemonic(mnemonic, target)
            else:
                operands = [format_hex16(target)]
        elif operand_type == ('rst',):
            # RST vector
            n = (opcode >> 3) & 7
            if self.z80_mode:
                operands = [format_hex8(n * 8)]  # Z80 uses actual address
            else:
                operands = [str(n)]

        # Handle Z80 unconditional no-operand mappings
        if self.z80_mode and operand_type is None:
            mnemonic, operands = self.z80_noarg_mnemonic(mnemonic)

        return (mnemonic, size, operands, target)

    def z80_alu_mnemonic(self, mnemonic, reg):
        """Convert 8080 ALU mnemonic to Z80."""
        mapping = {
            'ADD': 'ADD', 'ADC': 'ADC', 'SUB': 'SUB', 'SBB': 'SBC',
            'ANA': 'AND', 'XRA': 'XOR', 'ORA': 'OR', 'CMP': 'CP'
        }
        return mapping.get(mnemonic, mnemonic)

    def z80_imm8_mnemonic(self, mnemonic, imm):
        """Convert 8080 immediate mnemonic to Z80."""
        mapping = {
            'ADI': ('ADD', ['A', format_hex8(imm)]),
            'ACI': ('ADC', ['A', format_hex8(imm)]),
            'SUI': ('SUB', [format_hex8(imm)]),
            'SBI': ('SBC', ['A', format_hex8(imm)]),
            'ANI': ('AND', [format_hex8(imm)]),
            'XRI': ('XOR', [format_hex8(imm)]),
            'ORI': ('OR', [format_hex8(imm)]),
            'CPI': ('CP', [format_hex8(imm)]),
            'IN': ('IN', ['A', '(' + format_hex8(imm) + ')']),
            'OUT': ('OUT', ['(' + format_hex8(imm) + ')', 'A']),
        }
        return mapping.get(mnemonic, (mnemonic, [format_hex8(imm)]))

    def z80_addr_mnemonic(self, mnemonic, target):
        """Convert 8080 address mnemonic to Z80."""
        addr_str = format_hex16(target)
        mapping = {
            'LDA': ('LD', ['A', '(' + addr_str + ')']),
            'STA': ('LD', ['(' + addr_str + ')', 'A']),
            'LHLD': ('LD', ['HL', '(' + addr_str + ')']),
            'SHLD': ('LD', ['(' + addr_str + ')', 'HL']),
        }
        return mapping.get(mnemonic, (mnemonic, [addr_str]))

    def z80_noarg_mnemonic(self, mnemonic):
        """Convert 8080 no-operand mnemonic to Z80."""
        mapping = {
            'RLC': ('RLCA', []),
            'RRC': ('RRCA', []),
            'RAL': ('RLA', []),
            'RAR': ('RRA', []),
            'CMA': ('CPL', []),
            'STC': ('SCF', []),
            'CMC': ('CCF', []),
            'PCHL': ('JP', ['(HL)']),
            'SPHL': ('LD', ['SP', 'HL']),
            'XCHG': ('EX', ['DE', 'HL']),
            'XTHL': ('EX', ['(SP)', 'HL']),
            'LDAX': ('LD', ['A', '(BC)']),  # handled elsewhere
            'STAX': ('LD', ['(BC)', 'A']),  # handled elsewhere
        }
        return mapping.get(mnemonic, (mnemonic, []))

    def decode_cb_instruction(self, addr):
        """Decode CB-prefixed instruction."""
        opcode2 = self.byte_at(addr + 1)
        if opcode2 is None:
            return None

        if opcode2 not in CB_OPCODES:
            return ('DB', 2, [format_hex8(0xCB), format_hex8(opcode2)], None)

        mnemonic, _, operand_type = CB_OPCODES[opcode2]
        operands = []
        r_idx = opcode2 & 7

        if operand_type == ('cb_r',):
            # Shift/rotate operations
            operands = [Z80_REGS[r_idx]]
        elif operand_type == ('bit_n', 'cb_r'):
            # BIT/RES/SET
            n = (opcode2 >> 3) & 7
            operands = [str(n), Z80_REGS[r_idx]]

        return (mnemonic, 2, operands, None)

    def decode_ed_instruction(self, addr):
        """Decode ED-prefixed instruction."""
        opcode2 = self.byte_at(addr + 1)
        if opcode2 is None:
            return None

        if opcode2 not in ED_OPCODES:
            # Unknown ED opcode - treat as NOP NOP
            return ('DB', 2, [format_hex8(0xED), format_hex8(opcode2)], None)

        mnemonic, size, operand_type = ED_OPCODES[opcode2]
        operands = []
        target = None

        if operand_type is None:
            pass
        elif operand_type == ('ed_r', '(C)'):
            r_idx = (opcode2 >> 3) & 7
            operands = [Z80_REGS[r_idx], '(C)']
        elif operand_type == ('(C)', 'ed_r'):
            r_idx = (opcode2 >> 3) & 7
            operands = ['(C)', Z80_REGS[r_idx]]
        elif operand_type == ('(C)',):
            operands = ['(C)']
        elif operand_type == ('HL', 'ed_rp'):
            rp_idx = (opcode2 >> 4) & 3
            operands = ['HL', Z80_REGPAIRS[rp_idx]]
        elif operand_type == ('(a16)', 'ed_rp'):
            rp_idx = (opcode2 >> 4) & 3
            target = self.word_at(addr + 2)
            if target is None:
                return None
            operands = ['(' + format_hex16(target) + ')', Z80_REGPAIRS[rp_idx]]
        elif operand_type == ('ed_rp', '(a16)'):
            rp_idx = (opcode2 >> 4) & 3
            target = self.word_at(addr + 2)
            if target is None:
                return None
            operands = [Z80_REGPAIRS[rp_idx], '(' + format_hex16(target) + ')']
        elif operand_type == ('im0',):
            operands = ['0']
        elif operand_type == ('im1',):
            operands = ['1']
        elif operand_type == ('im2',):
            operands = ['2']
        elif len(operand_type) == 2 and isinstance(operand_type[0], str) and isinstance(operand_type[1], str):
            # Simple register pair like ('I', 'A')
            operands = list(operand_type)

        return (mnemonic, size, operands, target)

    def decode_index_instruction(self, addr, index_reg):
        """Decode DD/FD-prefixed instruction (IX/IY)."""
        opcode2 = self.byte_at(addr + 1)
        if opcode2 is None:
            return None

        # DD CB / FD CB - indexed bit operations
        if opcode2 == 0xCB:
            return self.decode_indexed_cb_instruction(addr, index_reg)

        # Map H->IXH/IYH, L->IXL/IYL, (HL)->(IX+d)/(IY+d)
        ih = index_reg + 'H'
        il = index_reg + 'L'

        # Check for instructions that use index register
        if opcode2 in OPCODES:
            mnemonic, size, operand_type = OPCODES[opcode2]

            # Instructions that use (HL) get displacement
            uses_hl_indirect = False
            if operand_type in [('r', 's'), ('r', 'd8'), ('r',), ('s',)]:
                r_bits = (opcode2 >> 3) & 7 if operand_type != ('s',) else opcode2 & 7
                s_bits = opcode2 & 7
                if r_bits == 6 or (operand_type in [('r', 's'), ('s',)] and s_bits == 6):
                    uses_hl_indirect = True

            if uses_hl_indirect:
                # These need displacement byte
                disp = self.byte_at(addr + 2)
                if disp is None:
                    return None
                disp_signed = disp if disp < 128 else disp - 256
                idx_operand = f'({index_reg}{disp_signed:+d})'

                if operand_type == ('r', 's'):
                    # LD r,(IX+d) or LD (IX+d),r
                    d = (opcode2 >> 3) & 7
                    s = opcode2 & 7
                    if d == 6:  # LD (IX+d),r
                        dst = idx_operand
                        src = Z80_REGS[s]
                    else:  # LD r,(IX+d)
                        dst = Z80_REGS[d]
                        src = idx_operand
                    return ('LD', 3, [dst, src], None)
                elif operand_type == ('r', 'd8'):
                    # LD (IX+d),n
                    imm = self.byte_at(addr + 3)
                    if imm is None:
                        return None
                    return ('LD', 4, [idx_operand, format_hex8(imm)], None)
                elif operand_type == ('r',):
                    # INC/DEC (IX+d)
                    mnemonic = 'INC' if mnemonic == 'INR' else 'DEC'
                    return (mnemonic, 3, [idx_operand], None)
                elif operand_type == ('s',):
                    # ALU (IX+d)
                    z80_mn = self.z80_alu_mnemonic(mnemonic, idx_operand)
                    if z80_mn in ('ADD', 'ADC', 'SBC'):
                        return (z80_mn, 3, ['A', idx_operand], None)
                    return (z80_mn, 3, [idx_operand], None)

            # Instructions using HL register pair
            if operand_type == ('rp',) or operand_type == ('rp2',):
                rp_idx = (opcode2 >> 4) & 3
                if rp_idx == 2:  # HL -> IX/IY
                    rp = index_reg
                else:
                    rp = Z80_REGPAIRS[rp_idx] if operand_type == ('rp',) else Z80_REGPAIRS_AF[rp_idx]

                if mnemonic == 'INX':
                    return ('INC', 2, [rp], None)
                elif mnemonic == 'DCX':
                    return ('DEC', 2, [rp], None)
                elif mnemonic == 'DAD':
                    src_rp = Z80_REGPAIRS[rp_idx]
                    if rp_idx == 2:
                        src_rp = index_reg
                    return ('ADD', 2, [index_reg, src_rp], None)
                elif mnemonic in ('PUSH', 'POP'):
                    return (mnemonic, 2, [rp], None)

            elif operand_type == ('rp', 'd16'):
                rp_idx = (opcode2 >> 4) & 3
                if rp_idx == 2:  # HL -> IX/IY
                    imm = self.word_at(addr + 2)
                    if imm is None:
                        return None
                    return ('LD', 4, [index_reg, format_hex16(imm)], None)

            # Undocumented: H/L -> IXH/IXL/IYH/IYL
            if operand_type == ('r', 's'):
                d = (opcode2 >> 3) & 7
                s = opcode2 & 7
                # Undocumented LD with IXH/IXL/IYH/IYL
                if d in (4, 5) or s in (4, 5):
                    dst_map = {4: ih, 5: il}
                    src_map = {4: ih, 5: il}
                    dst = dst_map.get(d, Z80_REGS[d])
                    src = src_map.get(s, Z80_REGS[s])
                    return ('LD', 2, [dst, src], None)

            if operand_type == ('r', 'd8'):
                r = (opcode2 >> 3) & 7
                if r in (4, 5):
                    imm = self.byte_at(addr + 2)
                    if imm is None:
                        return None
                    reg = ih if r == 4 else il
                    return ('LD', 3, [reg, format_hex8(imm)], None)

            if operand_type == ('r',):
                r = (opcode2 >> 3) & 7
                if r in (4, 5):
                    reg = ih if r == 4 else il
                    mnemonic = 'INC' if mnemonic == 'INR' else 'DEC'
                    return (mnemonic, 2, [reg], None)

            if operand_type == ('s',):
                r = opcode2 & 7
                if r in (4, 5):
                    reg = ih if r == 4 else il
                    z80_mn = self.z80_alu_mnemonic(mnemonic, reg)
                    if z80_mn in ('ADD', 'ADC', 'SBC'):
                        return (z80_mn, 2, ['A', reg], None)
                    return (z80_mn, 2, [reg], None)

        # Special cases
        if opcode2 == 0xE9:  # JP (IX)/(IY)
            return ('JP', 2, ['(' + index_reg + ')'], None)
        if opcode2 == 0xF9:  # LD SP,IX/IY
            return ('LD', 2, ['SP', index_reg], None)
        if opcode2 == 0xE3:  # EX (SP),IX/IY
            return ('EX', 2, ['(SP)', index_reg], None)
        if opcode2 == 0x2A:  # LD IX/IY,(nn)
            target = self.word_at(addr + 2)
            if target is None:
                return None
            return ('LD', 4, [index_reg, '(' + format_hex16(target) + ')'], target)
        if opcode2 == 0x22:  # LD (nn),IX/IY
            target = self.word_at(addr + 2)
            if target is None:
                return None
            return ('LD', 4, ['(' + format_hex16(target) + ')', index_reg], target)

        # Prefix has no effect on this opcode - output as prefix + instruction
        # (undocumented behavior)
        return ('DB', 1, [format_hex8(0xDD if index_reg == 'IX' else 0xFD)], None)

    def decode_indexed_cb_instruction(self, addr, index_reg):
        """Decode DD CB / FD CB indexed bit operations."""
        disp = self.byte_at(addr + 2)
        opcode3 = self.byte_at(addr + 3)
        if disp is None or opcode3 is None:
            return None

        disp_signed = disp if disp < 128 else disp - 256
        idx_operand = f'({index_reg}{disp_signed:+d})'
        r_idx = opcode3 & 7

        # Determine operation
        if opcode3 < 0x40:
            # Rotate/shift
            op_idx = (opcode3 >> 3) & 7
            mnemonic = CB_OPS[op_idx]
            if r_idx == 6:
                return (mnemonic, 4, [idx_operand], None)
            else:
                # Undocumented: result also stored in register
                return (mnemonic, 4, [idx_operand, Z80_REGS[r_idx]], None)
        elif opcode3 < 0x80:
            # BIT
            n = (opcode3 >> 3) & 7
            return ('BIT', 4, [str(n), idx_operand], None)
        elif opcode3 < 0xC0:
            # RES
            n = (opcode3 >> 3) & 7
            if r_idx == 6:
                return ('RES', 4, [str(n), idx_operand], None)
            else:
                # Undocumented: result also stored in register
                return ('RES', 4, [str(n), idx_operand, Z80_REGS[r_idx]], None)
        else:
            # SET
            n = (opcode3 >> 3) & 7
            if r_idx == 6:
                return ('SET', 4, [str(n), idx_operand], None)
            else:
                # Undocumented: result also stored in register
                return ('SET', 4, [str(n), idx_operand, Z80_REGS[r_idx]], None)

    def decode_z80_only_opcode(self, addr, opcode):
        """Decode Z80-only base opcodes (JR, DJNZ, EX AF,AF')."""
        mnemonic, size, operand_type = Z80_ONLY_OPCODES[opcode]
        operands = []
        target = None

        if operand_type == ('af_af',):
            # EX AF,AF'
            operands = ['AF', "AF'"]
        elif operand_type == ('rel8',):
            # JR d or DJNZ d
            disp = self.byte_at(addr + 1)
            if disp is None:
                return None
            disp_signed = disp if disp < 128 else disp - 256
            target = addr + 2 + disp_signed
            operands = [format_hex16(target)]
        elif len(operand_type) == 2 and operand_type[1] == 'rel8':
            # JR cc,d
            cond = operand_type[0]
            disp = self.byte_at(addr + 1)
            if disp is None:
                return None
            disp_signed = disp if disp < 128 else disp - 256
            target = addr + 2 + disp_signed
            operands = [cond, format_hex16(target)]

        return (mnemonic, size, operands, target)

    def is_unconditional_transfer(self, mnemonic):
        """Check if instruction is unconditional transfer of control."""
        # Include both 8080 and Z80 mnemonics
        return mnemonic in ('JMP', 'RET', 'PCHL', 'HLT', 'JP', 'RETI', 'RETN')

    def is_call(self, mnemonic):
        """Check if instruction is a call."""
        return mnemonic in ('CALL', 'CNZ', 'CZ', 'CNC', 'CC', 'CPO', 'CPE', 'CP', 'CM', 'RST')

    def is_jump(self, mnemonic):
        """Check if instruction is a jump."""
        return mnemonic in ('JMP', 'JNZ', 'JZ', 'JNC', 'JC', 'JPO', 'JPE', 'JP', 'JM', 'PCHL')

    def analyze_code_flow(self, entry_points):
        """Trace code flow from entry points to identify code regions."""
        work_list = list(entry_points)
        visited = set()

        while work_list:
            addr = work_list.pop()

            if addr in visited:
                continue
            if addr < self.org or addr >= self.end:
                continue

            visited.add(addr)

            while addr < self.end:
                if addr in self.code_addrs:
                    break

                result = self.decode_instruction(addr)
                if result is None:
                    break

                mnemonic, size, operands, target = result

                # Mark as code
                for i in range(size):
                    self.code_addrs.add(addr + i)

                # Track references
                if target is not None and self.org <= target < self.end:
                    self.refs_from[target].add(addr)
                    self.refs_to[addr].add(target)

                    if self.is_jump(mnemonic) or self.is_call(mnemonic):
                        if target not in visited:
                            work_list.append(target)

                # Follow conditional branches
                if self.is_unconditional_transfer(mnemonic):
                    break

                addr += size

    def find_strings(self, min_len=4):
        """Find potential ASCII strings in non-code areas."""
        i = 0
        while i < len(self.data):
            addr = self.org + i
            if addr in self.code_addrs:
                i += 1
                continue

            # Look for printable ASCII sequence
            start = i
            while i < len(self.data):
                b = self.data[i]
                # Accept printable ASCII and common control chars
                if 0x20 <= b <= 0x7E or b in (0x0D, 0x0A, 0x09):
                    i += 1
                elif b == 0 and i > start:  # Null terminator
                    i += 1
                    break
                elif b & 0x80 and 0x20 <= (b & 0x7F) <= 0x7E:
                    # High bit set - common in BASIC for tokenized text
                    i += 1
                    break
                else:
                    break

            if i - start >= min_len:
                self.strings[self.org + start] = self.data[start:i]
            elif i == start:
                i += 1

    def generate_labels(self):
        """Generate labels for all referenced addresses."""
        # Build set of instruction start addresses
        instr_starts = set()
        addr = self.org
        while addr < self.end:
            if addr in self.code_addrs:
                instr_starts.add(addr)
                result = self.decode_instruction(addr)
                if result:
                    addr += result[1]  # Skip instruction size
                else:
                    addr += 1
            else:
                addr += 1

        # Entry points
        for addr in self.entry_points:
            if addr not in self.labels and addr in instr_starts:
                self.labels[addr] = f'L{addr:04X}'

        # Jump/call targets - only create labels at instruction boundaries
        for addr in self.refs_from:
            if addr not in self.labels and self.org <= addr < self.end:
                # Only create label if it's at an instruction start or data location
                if addr in instr_starts:
                    self.labels[addr] = f'L{addr:04X}'
                elif addr not in self.code_addrs:
                    # Data reference
                    self.labels[addr] = f'D{addr:04X}'
                # If it's mid-instruction, don't create a label

    def format_operand(self, op, addr):
        """Format operand, using label if available."""
        if op.endswith('H'):
            # Strip leading 0 if present for parsing
            hex_part = op[:-1]
            if hex_part.startswith('0') and len(hex_part) > 1:
                hex_part = hex_part[1:]
            if len(hex_part) == 4:
                # 16-bit address
                target = int(hex_part, 16)
                if target in self.labels:
                    return self.labels[target]
                # If target is within our range but has no label, keep as hex
                # (it won't cause undefined symbol errors in assembler)
        return op

    def disassemble(self, entry_points=None):
        """Perform full disassembly."""
        # Default entry point is start of COM file
        if entry_points is None:
            entry_points = [self.org]
        self.entry_points = set(entry_points)

        # Analyze code flow
        self.analyze_code_flow(entry_points)

        # Generate labels
        self.generate_labels()

        # Find strings in data areas
        self.find_strings()

        # Generate output
        return self.generate_output()

    def generate_output(self):
        """Generate .MAC output."""
        lines = []
        lines.append('; Disassembled by ud80')
        lines.append(f'; Source file size: {len(self.data)} bytes')
        lines.append(f'; Mode: {"Z80" if self.z80_mode else "8080"}')
        lines.append('')
        lines.append('\t.Z80' if self.z80_mode else '\t.8080')
        lines.append('')
        lines.append(f'\tORG\t{format_hex16(self.org)}')
        lines.append('')

        addr = self.org
        while addr < self.end:
            line_parts = []

            # Add label if present
            if addr in self.labels:
                line_parts.append(f'{self.labels[addr]}:')
            else:
                line_parts.append('')

            if addr in self.code_addrs:
                # Disassemble instruction
                result = self.decode_instruction(addr)
                if result:
                    mnemonic, size, operands, target = result

                    # Format operands with labels
                    formatted_ops = [self.format_operand(op, addr) for op in operands]

                    if formatted_ops:
                        line_parts.append(f'\t{mnemonic}\t{",".join(formatted_ops)}')
                    else:
                        line_parts.append(f'\t{mnemonic}')

                    # Add address comment
                    bytes_str = ' '.join(f'{self.byte_at(addr+i):02X}' for i in range(size))
                    line_parts.append(f'\t; {addr:04X}: {bytes_str}')

                    lines.append(''.join(line_parts))
                    addr += size
                else:
                    # Shouldn't happen, but handle it
                    b = self.byte_at(addr)
                    line_parts.append(f'\tDB\t{format_hex8(b)}')
                    line_parts.append(f'\t; {addr:04X}')
                    lines.append(''.join(line_parts))
                    addr += 1
            else:
                # Data byte - output one at a time to allow labels at any position
                b = self.byte_at(addr)
                line_parts.append(f'\tDB\t{format_hex8(b)}')
                line_parts.append(f'\t; {addr:04X}')
                lines.append(''.join(line_parts))
                addr += 1

        lines.append('')
        lines.append('\tEND')

        return '\n'.join(lines)


def parse_range(s):
    """Parse address range like '1000-2000' or '1000'."""
    if '-' in s:
        start, end = s.split('-', 1)
        return (int(start, 16), int(end, 16))
    else:
        return (int(s, 16), int(s, 16))


def main():
    parser = argparse.ArgumentParser(description='8080/Z80 Disassembler for CP/M .COM files')
    parser.add_argument('input', help='Input .COM file')
    parser.add_argument('-o', '--output', help='Output .MAC file')
    parser.add_argument('-e', '--entry', action='append',
                       help='Additional entry point (hex address)')
    parser.add_argument('-d', '--data', action='append',
                       help='Force data range (hex: start-end)')
    parser.add_argument('--org', default='0100',
                       help='Origin address (default: 0100 for CP/M)')
    parser.add_argument('-z', '--z80', action='store_true',
                       help='Z80 mode: use Zilog mnemonics and decode Z80-only instructions')

    args = parser.parse_args()

    # Read input file
    with open(args.input, 'rb') as f:
        data = f.read()

    org = int(args.org, 16)

    # Create disassembler
    disasm = Disassembler(data, org, z80_mode=args.z80)

    # Parse entry points
    entry_points = [org]
    if args.entry:
        for e in args.entry:
            entry_points.append(int(e, 16))

    # Parse data ranges
    if args.data:
        for d in args.data:
            start, end = parse_range(d)
            for addr in range(start, end + 1):
                disasm.data_addrs.add(addr)

    # Disassemble
    output = disasm.disassemble(entry_points)

    # Write output
    if args.output:
        output_path = args.output
    else:
        base = os.path.splitext(args.input)[0]
        output_path = base + '.mac'

    with open(output_path, 'w') as f:
        f.write(output)

    mode = 'Z80' if args.z80 else '8080'
    print(f'Disassembled {args.input} -> {output_path} ({mode} mode)')
    print(f'  Code bytes: {len(disasm.code_addrs)}')
    print(f'  Data bytes: {len(data) - len(disasm.code_addrs)}')
    print(f'  Labels: {len(disasm.labels)}')


if __name__ == '__main__':
    main()
