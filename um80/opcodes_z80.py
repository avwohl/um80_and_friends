"""
Z80 CPU instruction definitions for um80 assembler.

Z80 instructions use prefix bytes:
- No prefix: Main instructions (overlap with 8080)
- CB: Bit operations (BIT, SET, RES, rotates/shifts)
- DD: IX register operations
- ED: Extended instructions
- FD: IY register operations
- DD CB / FD CB: IX/IY bit operations
"""

# Register encodings (3-bit) - same as 8080 but different names
Z80_REGS = {
    'B': 0, 'C': 1, 'D': 2, 'E': 3, 'H': 4, 'L': 5, '(HL)': 6, 'A': 7
}

# Also accept M for (HL) for compatibility
Z80_REGS_M = {
    'B': 0, 'C': 1, 'D': 2, 'E': 3, 'H': 4, 'L': 5, '(HL)': 6, 'M': 6, 'A': 7
}

# 16-bit register pairs for various instructions
Z80_PAIRS_BC_DE_HL_SP = {
    'BC': 0, 'DE': 1, 'HL': 2, 'SP': 3
}

Z80_PAIRS_BC_DE_HL_AF = {
    'BC': 0, 'DE': 1, 'HL': 2, 'AF': 3
}

Z80_PAIRS_BC_DE_IX_SP = {
    'BC': 0, 'DE': 1, 'IX': 2, 'SP': 3
}

Z80_PAIRS_BC_DE_IY_SP = {
    'BC': 0, 'DE': 1, 'IY': 2, 'SP': 3
}

# Condition codes for JR (only NZ, Z, NC, C)
Z80_JR_CONDITIONS = {
    'NZ': 0, 'Z': 1, 'NC': 2, 'C': 3
}

# Condition codes for JP/CALL/RET (all 8)
Z80_CONDITIONS = {
    'NZ': 0, 'Z': 1, 'NC': 2, 'C': 3, 'PO': 4, 'PE': 5, 'P': 6, 'M': 7
}

# Prefix bytes
PREFIX_CB = 0xCB
PREFIX_DD = 0xDD
PREFIX_ED = 0xED
PREFIX_FD = 0xFD

# ============================================================
# No-operand instructions (single byte)
# ============================================================
Z80_NO_OPERAND = {
    'NOP':  0x00,
    'RLCA': 0x07,
    'RRCA': 0x0F,
    'RLA':  0x17,
    'RRA':  0x1F,
    'DAA':  0x27,
    'CPL':  0x2F,
    'SCF':  0x37,
    'CCF':  0x3F,
    'HALT': 0x76,
    'EXX':  0xD9,
    'DI':   0xF3,
    'EI':   0xFB,
}

# ============================================================
# ED-prefix no-operand instructions
# ============================================================
Z80_ED_NO_OPERAND = {
    'NEG':  0x44,
    'RETN': 0x45,
    'RETI': 0x4D,
    'RRD':  0x67,
    'RLD':  0x6F,
    'LDI':  0xA0,
    'CPI':  0xA1,
    'INI':  0xA2,
    'OUTI': 0xA3,
    'LDD':  0xA8,
    'CPD':  0xA9,
    'IND':  0xAA,
    'OUTD': 0xAB,
    'LDIR': 0xB0,
    'CPIR': 0xB1,
    'INIR': 0xB2,
    'OTIR': 0xB3,
    'LDDR': 0xB8,
    'CPDR': 0xB9,
    'INDR': 0xBA,
    'OTDR': 0xBB,
}

# ============================================================
# Exchange/transfer instructions
# ============================================================
# EX DE,HL: 0xEB
# EX AF,AF': 0x08
# EX (SP),HL: 0xE3
# EX (SP),IX: DD E3
# EX (SP),IY: FD E3

# ============================================================
# 8-bit load group: LD r,r' / LD r,n / LD r,(HL) etc.
# ============================================================

def encode_z80_ld_r_r(dst, src):
    """LD r,r' - 01 ddd sss"""
    d = Z80_REGS_M[dst.upper()]
    s = Z80_REGS_M[src.upper()]
    return bytes([0x40 | (d << 3) | s])

def encode_z80_ld_r_n(reg, n):
    """LD r,n - 00 rrr 110 nn"""
    r = Z80_REGS_M[reg.upper()]
    return bytes([0x06 | (r << 3), n & 0xFF])

def encode_z80_ld_r_ixd(reg, disp):
    """LD r,(IX+d) - DD 01 rrr 110 dd"""
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_DD, 0x46 | (r << 3), disp & 0xFF])

def encode_z80_ld_r_iyd(reg, disp):
    """LD r,(IY+d) - FD 01 rrr 110 dd"""
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_FD, 0x46 | (r << 3), disp & 0xFF])

def encode_z80_ld_ixd_r(disp, reg):
    """LD (IX+d),r - DD 01 110 rrr dd"""
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_DD, 0x70 | r, disp & 0xFF])

def encode_z80_ld_iyd_r(disp, reg):
    """LD (IY+d),r - FD 01 110 rrr dd"""
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_FD, 0x70 | r, disp & 0xFF])

def encode_z80_ld_ixd_n(disp, n):
    """LD (IX+d),n - DD 36 dd nn"""
    return bytes([PREFIX_DD, 0x36, disp & 0xFF, n & 0xFF])

def encode_z80_ld_iyd_n(disp, n):
    """LD (IY+d),n - FD 36 dd nn"""
    return bytes([PREFIX_FD, 0x36, disp & 0xFF, n & 0xFF])

def encode_z80_ld_a_bc():
    """LD A,(BC) - 0A"""
    return bytes([0x0A])

def encode_z80_ld_a_de():
    """LD A,(DE) - 1A"""
    return bytes([0x1A])

def encode_z80_ld_a_nn(addr):
    """LD A,(nn) - 3A nn nn"""
    return bytes([0x3A, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_bc_a():
    """LD (BC),A - 02"""
    return bytes([0x02])

def encode_z80_ld_de_a():
    """LD (DE),A - 12"""
    return bytes([0x12])

def encode_z80_ld_nn_a(addr):
    """LD (nn),A - 32 nn nn"""
    return bytes([0x32, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_a_i():
    """LD A,I - ED 57"""
    return bytes([PREFIX_ED, 0x57])

def encode_z80_ld_a_r():
    """LD A,R - ED 5F"""
    return bytes([PREFIX_ED, 0x5F])

def encode_z80_ld_i_a():
    """LD I,A - ED 47"""
    return bytes([PREFIX_ED, 0x47])

def encode_z80_ld_r_a():
    """LD R,A - ED 4F"""
    return bytes([PREFIX_ED, 0x4F])

# ============================================================
# 16-bit load group
# ============================================================

def encode_z80_ld_dd_nn(pair, nn):
    """LD dd,nn - 00 dd0 001 nn nn"""
    p = Z80_PAIRS_BC_DE_HL_SP[pair.upper()]
    return bytes([0x01 | (p << 4), nn & 0xFF, (nn >> 8) & 0xFF])

def encode_z80_ld_ix_nn(nn):
    """LD IX,nn - DD 21 nn nn"""
    return bytes([PREFIX_DD, 0x21, nn & 0xFF, (nn >> 8) & 0xFF])

def encode_z80_ld_iy_nn(nn):
    """LD IY,nn - FD 21 nn nn"""
    return bytes([PREFIX_FD, 0x21, nn & 0xFF, (nn >> 8) & 0xFF])

def encode_z80_ld_hl_ind(addr):
    """LD HL,(nn) - 2A nn nn"""
    return bytes([0x2A, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_dd_ind(pair, addr):
    """LD dd,(nn) - ED 01 dd 1011 nn nn"""
    p = Z80_PAIRS_BC_DE_HL_SP[pair.upper()]
    return bytes([PREFIX_ED, 0x4B | (p << 4), addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_ix_ind(addr):
    """LD IX,(nn) - DD 2A nn nn"""
    return bytes([PREFIX_DD, 0x2A, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_iy_ind(addr):
    """LD IY,(nn) - FD 2A nn nn"""
    return bytes([PREFIX_FD, 0x2A, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_ind_hl(addr):
    """LD (nn),HL - 22 nn nn"""
    return bytes([0x22, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_ind_dd(addr, pair):
    """LD (nn),dd - ED 01 dd 0011 nn nn"""
    p = Z80_PAIRS_BC_DE_HL_SP[pair.upper()]
    return bytes([PREFIX_ED, 0x43 | (p << 4), addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_ind_ix(addr):
    """LD (nn),IX - DD 22 nn nn"""
    return bytes([PREFIX_DD, 0x22, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_ind_iy(addr):
    """LD (nn),IY - FD 22 nn nn"""
    return bytes([PREFIX_FD, 0x22, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ld_sp_hl():
    """LD SP,HL - F9"""
    return bytes([0xF9])

def encode_z80_ld_sp_ix():
    """LD SP,IX - DD F9"""
    return bytes([PREFIX_DD, 0xF9])

def encode_z80_ld_sp_iy():
    """LD SP,IY - FD F9"""
    return bytes([PREFIX_FD, 0xF9])

def encode_z80_push(pair):
    """PUSH qq - 11 qq0 101"""
    p = Z80_PAIRS_BC_DE_HL_AF[pair.upper()]
    return bytes([0xC5 | (p << 4)])

def encode_z80_push_ix():
    """PUSH IX - DD E5"""
    return bytes([PREFIX_DD, 0xE5])

def encode_z80_push_iy():
    """PUSH IY - FD E5"""
    return bytes([PREFIX_FD, 0xE5])

def encode_z80_pop(pair):
    """POP qq - 11 qq0 001"""
    p = Z80_PAIRS_BC_DE_HL_AF[pair.upper()]
    return bytes([0xC1 | (p << 4)])

def encode_z80_pop_ix():
    """POP IX - DD E1"""
    return bytes([PREFIX_DD, 0xE1])

def encode_z80_pop_iy():
    """POP IY - FD E1"""
    return bytes([PREFIX_FD, 0xE1])

# ============================================================
# Exchange group
# ============================================================

def encode_z80_ex_de_hl():
    """EX DE,HL - EB"""
    return bytes([0xEB])

def encode_z80_ex_af_af():
    """EX AF,AF' - 08"""
    return bytes([0x08])

def encode_z80_ex_sp_hl():
    """EX (SP),HL - E3"""
    return bytes([0xE3])

def encode_z80_ex_sp_ix():
    """EX (SP),IX - DD E3"""
    return bytes([PREFIX_DD, 0xE3])

def encode_z80_ex_sp_iy():
    """EX (SP),IY - FD E3"""
    return bytes([PREFIX_FD, 0xE3])

# ============================================================
# 8-bit arithmetic/logic group
# ============================================================

Z80_ALU_OPS = {
    'ADD': 0, 'ADC': 1, 'SUB': 2, 'SBC': 3,
    'AND': 4, 'XOR': 5, 'OR': 6, 'CP': 7
}

def encode_z80_alu_r(op, reg):
    """ALU A,r - 10 ooo rrr"""
    o = Z80_ALU_OPS[op.upper()]
    r = Z80_REGS_M[reg.upper()]
    return bytes([0x80 | (o << 3) | r])

def encode_z80_alu_n(op, n):
    """ALU A,n - 11 ooo 110 nn"""
    o = Z80_ALU_OPS[op.upper()]
    return bytes([0xC6 | (o << 3), n & 0xFF])

def encode_z80_alu_ixd(op, disp):
    """ALU A,(IX+d) - DD 10 ooo 110 dd"""
    o = Z80_ALU_OPS[op.upper()]
    return bytes([PREFIX_DD, 0x86 | (o << 3), disp & 0xFF])

def encode_z80_alu_iyd(op, disp):
    """ALU A,(IY+d) - FD 10 ooo 110 dd"""
    o = Z80_ALU_OPS[op.upper()]
    return bytes([PREFIX_FD, 0x86 | (o << 3), disp & 0xFF])

def encode_z80_inc_r(reg):
    """INC r - 00 rrr 100"""
    r = Z80_REGS_M[reg.upper()]
    return bytes([0x04 | (r << 3)])

def encode_z80_dec_r(reg):
    """DEC r - 00 rrr 101"""
    r = Z80_REGS_M[reg.upper()]
    return bytes([0x05 | (r << 3)])

def encode_z80_inc_ixd(disp):
    """INC (IX+d) - DD 34 dd"""
    return bytes([PREFIX_DD, 0x34, disp & 0xFF])

def encode_z80_dec_ixd(disp):
    """DEC (IX+d) - DD 35 dd"""
    return bytes([PREFIX_DD, 0x35, disp & 0xFF])

def encode_z80_inc_iyd(disp):
    """INC (IY+d) - FD 34 dd"""
    return bytes([PREFIX_FD, 0x34, disp & 0xFF])

def encode_z80_dec_iyd(disp):
    """DEC (IY+d) - FD 35 dd"""
    return bytes([PREFIX_FD, 0x35, disp & 0xFF])

# ============================================================
# 16-bit arithmetic group
# ============================================================

def encode_z80_add_hl_ss(pair):
    """ADD HL,ss - 00 ss 1001"""
    p = Z80_PAIRS_BC_DE_HL_SP[pair.upper()]
    return bytes([0x09 | (p << 4)])

def encode_z80_adc_hl_ss(pair):
    """ADC HL,ss - ED 01 ss 1010"""
    p = Z80_PAIRS_BC_DE_HL_SP[pair.upper()]
    return bytes([PREFIX_ED, 0x4A | (p << 4)])

def encode_z80_sbc_hl_ss(pair):
    """SBC HL,ss - ED 01 ss 0010"""
    p = Z80_PAIRS_BC_DE_HL_SP[pair.upper()]
    return bytes([PREFIX_ED, 0x42 | (p << 4)])

def encode_z80_add_ix_pp(pair):
    """ADD IX,pp - DD 00 pp 1001"""
    p = Z80_PAIRS_BC_DE_IX_SP[pair.upper()]
    return bytes([PREFIX_DD, 0x09 | (p << 4)])

def encode_z80_add_iy_rr(pair):
    """ADD IY,rr - FD 00 rr 1001"""
    p = Z80_PAIRS_BC_DE_IY_SP[pair.upper()]
    return bytes([PREFIX_FD, 0x09 | (p << 4)])

def encode_z80_inc_ss(pair):
    """INC ss - 00 ss 0011"""
    p = Z80_PAIRS_BC_DE_HL_SP[pair.upper()]
    return bytes([0x03 | (p << 4)])

def encode_z80_dec_ss(pair):
    """DEC ss - 00 ss 1011"""
    p = Z80_PAIRS_BC_DE_HL_SP[pair.upper()]
    return bytes([0x0B | (p << 4)])

def encode_z80_inc_ix():
    """INC IX - DD 23"""
    return bytes([PREFIX_DD, 0x23])

def encode_z80_dec_ix():
    """DEC IX - DD 2B"""
    return bytes([PREFIX_DD, 0x2B])

def encode_z80_inc_iy():
    """INC IY - FD 23"""
    return bytes([PREFIX_FD, 0x23])

def encode_z80_dec_iy():
    """DEC IY - FD 2B"""
    return bytes([PREFIX_FD, 0x2B])

# ============================================================
# Rotate and shift group
# ============================================================

# CB-prefix rotates/shifts: CB 00 ooo rrr
Z80_ROT_OPS = {
    'RLC': 0, 'RRC': 1, 'RL': 2, 'RR': 3,
    'SLA': 4, 'SRA': 5, 'SLL': 6, 'SRL': 7
}

def encode_z80_rot_r(op, reg):
    """Rotate/shift r - CB 00 ooo rrr"""
    o = Z80_ROT_OPS[op.upper()]
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_CB, (o << 3) | r])

def encode_z80_rot_ixd(op, disp):
    """Rotate/shift (IX+d) - DD CB dd 00 ooo 110"""
    o = Z80_ROT_OPS[op.upper()]
    return bytes([PREFIX_DD, PREFIX_CB, disp & 0xFF, (o << 3) | 6])

def encode_z80_rot_iyd(op, disp):
    """Rotate/shift (IY+d) - FD CB dd 00 ooo 110"""
    o = Z80_ROT_OPS[op.upper()]
    return bytes([PREFIX_FD, PREFIX_CB, disp & 0xFF, (o << 3) | 6])

# ============================================================
# Bit manipulation group
# ============================================================

def encode_z80_bit_b_r(bit, reg):
    """BIT b,r - CB 01 bbb rrr"""
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_CB, 0x40 | (bit << 3) | r])

def encode_z80_res_b_r(bit, reg):
    """RES b,r - CB 10 bbb rrr"""
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_CB, 0x80 | (bit << 3) | r])

def encode_z80_set_b_r(bit, reg):
    """SET b,r - CB 11 bbb rrr"""
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_CB, 0xC0 | (bit << 3) | r])

def encode_z80_bit_b_ixd(bit, disp):
    """BIT b,(IX+d) - DD CB dd 01 bbb 110"""
    return bytes([PREFIX_DD, PREFIX_CB, disp & 0xFF, 0x46 | (bit << 3)])

def encode_z80_res_b_ixd(bit, disp):
    """RES b,(IX+d) - DD CB dd 10 bbb 110"""
    return bytes([PREFIX_DD, PREFIX_CB, disp & 0xFF, 0x86 | (bit << 3)])

def encode_z80_set_b_ixd(bit, disp):
    """SET b,(IX+d) - DD CB dd 11 bbb 110"""
    return bytes([PREFIX_DD, PREFIX_CB, disp & 0xFF, 0xC6 | (bit << 3)])

def encode_z80_bit_b_iyd(bit, disp):
    """BIT b,(IY+d) - FD CB dd 01 bbb 110"""
    return bytes([PREFIX_FD, PREFIX_CB, disp & 0xFF, 0x46 | (bit << 3)])

def encode_z80_res_b_iyd(bit, disp):
    """RES b,(IY+d) - FD CB dd 10 bbb 110"""
    return bytes([PREFIX_FD, PREFIX_CB, disp & 0xFF, 0x86 | (bit << 3)])

def encode_z80_set_b_iyd(bit, disp):
    """SET b,(IY+d) - FD CB dd 11 bbb 110"""
    return bytes([PREFIX_FD, PREFIX_CB, disp & 0xFF, 0xC6 | (bit << 3)])

# ============================================================
# Jump group
# ============================================================

def encode_z80_jp_nn(addr):
    """JP nn - C3 nn nn"""
    return bytes([0xC3, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_jp_cc_nn(cc, addr):
    """JP cc,nn - 11 ccc 010 nn nn"""
    c = Z80_CONDITIONS[cc.upper()]
    return bytes([0xC2 | (c << 3), addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_jr_e(offset):
    """JR e - 18 ee (relative, -126 to +129)"""
    return bytes([0x18, offset & 0xFF])

def encode_z80_jr_cc_e(cc, offset):
    """JR cc,e - 001 cc 000 ee (NZ/Z/NC/C only)"""
    c = Z80_JR_CONDITIONS[cc.upper()]
    return bytes([0x20 | (c << 3), offset & 0xFF])

def encode_z80_jp_hl():
    """JP (HL) - E9"""
    return bytes([0xE9])

def encode_z80_jp_ix():
    """JP (IX) - DD E9"""
    return bytes([PREFIX_DD, 0xE9])

def encode_z80_jp_iy():
    """JP (IY) - FD E9"""
    return bytes([PREFIX_FD, 0xE9])

def encode_z80_djnz(offset):
    """DJNZ e - 10 ee"""
    return bytes([0x10, offset & 0xFF])

# ============================================================
# Call and return group
# ============================================================

def encode_z80_call_nn(addr):
    """CALL nn - CD nn nn"""
    return bytes([0xCD, addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_call_cc_nn(cc, addr):
    """CALL cc,nn - 11 ccc 100 nn nn"""
    c = Z80_CONDITIONS[cc.upper()]
    return bytes([0xC4 | (c << 3), addr & 0xFF, (addr >> 8) & 0xFF])

def encode_z80_ret():
    """RET - C9"""
    return bytes([0xC9])

def encode_z80_ret_cc(cc):
    """RET cc - 11 ccc 000"""
    c = Z80_CONDITIONS[cc.upper()]
    return bytes([0xC0 | (c << 3)])

def encode_z80_rst(n):
    """RST p - 11 ttt 111 (p = 0,8,10H,18H,20H,28H,30H,38H)"""
    # Accept either the vector (0,1,2..7) or the address (0,8,16...)
    if n > 7:
        n = n >> 3
    return bytes([0xC7 | (n << 3)])

# ============================================================
# I/O group
# ============================================================

def encode_z80_in_a_n(port):
    """IN A,(n) - DB nn"""
    return bytes([0xDB, port & 0xFF])

def encode_z80_in_r_c(reg):
    """IN r,(C) - ED 01 rrr 000"""
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_ED, 0x40 | (r << 3)])

def encode_z80_out_n_a(port):
    """OUT (n),A - D3 nn"""
    return bytes([0xD3, port & 0xFF])

def encode_z80_out_c_r(reg):
    """OUT (C),r - ED 01 rrr 001"""
    r = Z80_REGS[reg.upper()]
    return bytes([PREFIX_ED, 0x41 | (r << 3)])

# ============================================================
# Interrupt mode
# ============================================================

def encode_z80_im(mode):
    """IM 0/1/2 - ED 46/56/5E"""
    if mode == 0:
        return bytes([PREFIX_ED, 0x46])
    elif mode == 1:
        return bytes([PREFIX_ED, 0x56])
    else:  # mode == 2
        return bytes([PREFIX_ED, 0x5E])

# ============================================================
# Opcode values for use as operands (Z80 mnemonics)
# ============================================================

Z80_OPCODE_VALUES = {
    # No-operand
    'NOP': 0x00, 'RLCA': 0x07, 'RRCA': 0x0F, 'RLA': 0x17, 'RRA': 0x1F,
    'DAA': 0x27, 'CPL': 0x2F, 'SCF': 0x37, 'CCF': 0x3F, 'HALT': 0x76,
    'EXX': 0xD9, 'DI': 0xF3, 'EI': 0xFB,
    # Returns
    'RET': 0xC9,
    # Jumps
    'JP': 0xC3,
    # Call
    'CALL': 0xCD,
    # LD base
    'LD': 0x40,  # Base for LD r,r
    # ALU bases
    'ADD': 0x80, 'ADC': 0x88, 'SUB': 0x90, 'SBC': 0x98,
    'AND': 0xA0, 'XOR': 0xA8, 'OR': 0xB0, 'CP': 0xB8,
    # INC/DEC bases
    'INC': 0x04, 'DEC': 0x05,
    # Bit ops (CB prefix)
    'RLC': 0x00, 'RRC': 0x08, 'RL': 0x10, 'RR': 0x18,
    'SLA': 0x20, 'SRA': 0x28, 'SRL': 0x38,
    'BIT': 0x40, 'RES': 0x80, 'SET': 0xC0,
    # I/O
    'IN': 0xDB, 'OUT': 0xD3,
    # Prefixes
    'CB': 0xCB, 'DD': 0xDD, 'ED': 0xED, 'FD': 0xFD,
    # JR/DJNZ
    'JR': 0x18, 'DJNZ': 0x10,
    # RST base
    'RST': 0xC7,
    # PUSH/POP bases
    'PUSH': 0xC5, 'POP': 0xC1,
    # EX
    'EX': 0xEB,
}

# ============================================================
# Sets for instruction recognition
# ============================================================

Z80_ALU_MNEMONICS = {'ADD', 'ADC', 'SUB', 'SBC', 'AND', 'XOR', 'OR', 'CP'}
Z80_ROT_MNEMONICS = {'RLC', 'RRC', 'RL', 'RR', 'SLA', 'SRA', 'SLL', 'SRL'}
Z80_BIT_MNEMONICS = {'BIT', 'RES', 'SET'}
Z80_JR_CONDITIONS_SET = {'NZ', 'Z', 'NC', 'C'}
Z80_COND_JP = {'JP'}  # JP can be conditional
Z80_COND_CALL = {'CALL'}  # CALL can be conditional
Z80_COND_RET = {'RET'}  # RET can be conditional
