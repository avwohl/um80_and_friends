#!/usr/bin/env python3
"""
ux80 - 8080 to Z80 assembly translator.

Translates Intel 8080 assembly source code to Zilog Z80 assembly,
producing code that assembles to the identical byte sequence.

Usage: ux80 [-o output.mac] input.mac
"""

import sys
import os
import argparse
import re

from um80 import __version__


class TranslatorError(Exception):
    """Translation error with context."""
    def __init__(self, message, line_num=None, line_text=None):
        self.message = message
        self.line_num = line_num
        self.line_text = line_text
        super().__init__(self.format_message())

    def format_message(self):
        if self.line_num:
            return f"Error at line {self.line_num}: {self.message}"
        return f"Error: {self.message}"


class Translator:
    """8080 to Z80 assembly translator."""

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.line_num = 0

        # 8080 register to Z80 register mapping
        # M (memory via HL) -> (HL)
        self.reg_map = {
            'A': 'A', 'B': 'B', 'C': 'C', 'D': 'D',
            'E': 'E', 'H': 'H', 'L': 'L', 'M': '(HL)',
        }

        # 8080 register pair to Z80 register pair mapping
        self.regpair_map = {
            'B': 'BC', 'BC': 'BC',
            'D': 'DE', 'DE': 'DE',
            'H': 'HL', 'HL': 'HL',
            'SP': 'SP',
            'PSW': 'AF',
        }

        # 8080 condition codes map directly to Z80
        self.conditions = {'NZ', 'Z', 'NC', 'C', 'PO', 'PE', 'P', 'M'}

        # 8080 no-operand instructions -> Z80 equivalents
        self.no_operand_map = {
            'NOP':  'NOP',
            'RLC':  'RLCA',
            'RRC':  'RRCA',
            'RAL':  'RLA',
            'RAR':  'RRA',
            'DAA':  'DAA',
            'CMA':  'CPL',
            'STC':  'SCF',
            'CMC':  'CCF',
            'HLT':  'HALT',
            'RET':  'RET',
            'PCHL': 'JP (HL)',
            'SPHL': 'LD SP,HL',
            'XCHG': 'EX DE,HL',
            'XTHL': 'EX (SP),HL',
            'DI':   'DI',
            'EI':   'EI',
        }

        # Conditional returns: R<cond> -> RET <cond>
        self.cond_rets = {'RNZ', 'RZ', 'RNC', 'RC', 'RPO', 'RPE', 'RP', 'RM'}

        # Conditional jumps: J<cond> -> JP <cond>
        self.cond_jumps = {'JNZ', 'JZ', 'JNC', 'JC', 'JPO', 'JPE', 'JP', 'JM'}

        # Conditional calls: C<cond> -> CALL <cond>
        self.cond_calls = {'CNZ', 'CZ', 'CNC', 'CC', 'CPO', 'CPE', 'CP', 'CM'}

        # ALU register operations: <op> r -> <z80_op> A,r
        self.alu_reg_map = {
            'ADD': 'ADD', 'ADC': 'ADC', 'SUB': 'SUB', 'SBB': 'SBC',
            'ANA': 'AND', 'XRA': 'XOR', 'ORA': 'OR', 'CMP': 'CP',
        }

        # ALU immediate operations: <op>I n -> <z80_op> A,n
        self.alu_imm_map = {
            'ADI': 'ADD', 'ACI': 'ADC', 'SUI': 'SUB', 'SBI': 'SBC',
            'ANI': 'AND', 'XRI': 'XOR', 'ORI': 'OR', 'CPI': 'CP',
        }

        # Pattern to match identifiers (labels, symbols)
        self.ident_pattern = re.compile(r'^[A-Za-z_$@?][A-Za-z0-9_$@?]*$')

        # Pattern to match a label at start of line (single or double colon)
        self.label_pattern = re.compile(
            r'^([A-Za-z_$@?][A-Za-z0-9_$@?]*)\s*(::?)(.*)$'
        )

        # Pattern for label without colon (at column 0)
        self.label_no_colon_pattern = re.compile(
            r'^([A-Za-z_$@?][A-Za-z0-9_$@?]*)\s+(.+)$'
        )

    def error(self, msg):
        """Record an error."""
        self.errors.append(f"Error at line {self.line_num}: {msg}")

    def warning(self, msg):
        """Record a warning."""
        self.warnings.append(f"Warning at line {self.line_num}: {msg}")

    def map_register(self, reg):
        """Map 8080 register to Z80 register."""
        upper = reg.upper()
        if upper in self.reg_map:
            return self.reg_map[upper]
        return reg  # Return as-is if not a register

    def map_regpair(self, rp):
        """Map 8080 register pair to Z80 register pair."""
        upper = rp.upper()
        if upper in self.regpair_map:
            return self.regpair_map[upper]
        return rp  # Return as-is if not a register pair

    def get_condition(self, mnemonic):
        """Extract condition from conditional mnemonic."""
        m = mnemonic.upper()
        if m.startswith('J') and m in self.cond_jumps:
            cond = m[1:]
            return cond if cond in self.conditions else None
        elif m.startswith('C') and m in self.cond_calls:
            cond = m[1:]
            return cond if cond in self.conditions else None
        elif m.startswith('R') and m in self.cond_rets:
            cond = m[1:]
            return cond if cond in self.conditions else None
        return None

    def split_operands(self, operands_str):
        """Split operands string handling quoted strings."""
        if not operands_str:
            return []

        operands = []
        current = ""
        in_string = False
        string_char = None
        paren_depth = 0

        for ch in operands_str:
            if in_string:
                current += ch
                if ch == string_char:
                    in_string = False
            elif ch in ('"', "'"):
                in_string = True
                string_char = ch
                current += ch
            elif ch == '(':
                paren_depth += 1
                current += ch
            elif ch == ')':
                paren_depth -= 1
                current += ch
            elif ch == ',' and paren_depth == 0:
                operands.append(current.strip())
                current = ""
            else:
                current += ch

        if current.strip():
            operands.append(current.strip())

        return operands

    def translate_instruction(self, mnemonic, operands_str):
        """Translate a single 8080 instruction to Z80."""
        mnem_upper = mnemonic.upper()
        operands = self.split_operands(operands_str) if operands_str else []

        # No-operand instructions
        if mnem_upper in self.no_operand_map:
            return self.no_operand_map[mnem_upper]

        # Conditional returns: RNZ -> RET NZ
        if mnem_upper in self.cond_rets:
            cond = mnem_upper[1:]  # Strip 'R'
            return f"RET {cond}"

        # Conditional jumps: JNZ addr -> JP NZ,addr
        if mnem_upper in self.cond_jumps:
            cond = mnem_upper[1:]  # Strip 'J'
            addr = operands[0] if operands else ""
            return f"JP {cond},{addr}"

        # Unconditional JMP
        if mnem_upper == 'JMP':
            addr = operands[0] if operands else ""
            return f"JP {addr}"

        # Conditional calls: CNZ addr -> CALL NZ,addr
        if mnem_upper in self.cond_calls:
            cond = mnem_upper[1:]  # Strip 'C'
            addr = operands[0] if operands else ""
            return f"CALL {cond},{addr}"

        # Unconditional CALL
        if mnem_upper == 'CALL':
            addr = operands[0] if operands else ""
            return f"CALL {addr}"

        # RST n
        if mnem_upper == 'RST':
            n = operands[0] if operands else "0"
            return f"RST {n}"

        # MOV dst,src -> LD dst,src
        if mnem_upper == 'MOV':
            if len(operands) >= 2:
                dst = self.map_register(operands[0])
                src = self.map_register(operands[1])
                return f"LD {dst},{src}"
            else:
                self.error(f"MOV requires two operands")
                return f"LD ???"

        # MVI r,n -> LD r,n
        if mnem_upper == 'MVI':
            if len(operands) >= 2:
                reg = self.map_register(operands[0])
                val = operands[1]
                return f"LD {reg},{val}"
            else:
                self.error(f"MVI requires two operands")
                return f"LD ???"

        # LXI rp,nn -> LD rp,nn
        if mnem_upper == 'LXI':
            if len(operands) >= 2:
                rp = self.map_regpair(operands[0])
                val = operands[1]
                return f"LD {rp},{val}"
            else:
                self.error(f"LXI requires two operands")
                return f"LD ???"

        # LDA addr -> LD A,(addr)
        if mnem_upper == 'LDA':
            addr = operands[0] if operands else ""
            return f"LD A,({addr})"

        # STA addr -> LD (addr),A
        if mnem_upper == 'STA':
            addr = operands[0] if operands else ""
            return f"LD ({addr}),A"

        # LHLD addr -> LD HL,(addr)
        if mnem_upper == 'LHLD':
            addr = operands[0] if operands else ""
            return f"LD HL,({addr})"

        # SHLD addr -> LD (addr),HL
        if mnem_upper == 'SHLD':
            addr = operands[0] if operands else ""
            return f"LD ({addr}),HL"

        # LDAX rp -> LD A,(rp)
        if mnem_upper == 'LDAX':
            if operands:
                rp = self.map_regpair(operands[0])
                return f"LD A,({rp})"
            else:
                self.error(f"LDAX requires a register pair operand")
                return f"LD A,(???)"

        # STAX rp -> LD (rp),A
        if mnem_upper == 'STAX':
            if operands:
                rp = self.map_regpair(operands[0])
                return f"LD ({rp}),A"
            else:
                self.error(f"STAX requires a register pair operand")
                return f"LD (???),A"

        # INR r -> INC r
        if mnem_upper == 'INR':
            if operands:
                reg = self.map_register(operands[0])
                return f"INC {reg}"
            else:
                self.error(f"INR requires a register operand")
                return f"INC ???"

        # DCR r -> DEC r
        if mnem_upper == 'DCR':
            if operands:
                reg = self.map_register(operands[0])
                return f"DEC {reg}"
            else:
                self.error(f"DCR requires a register operand")
                return f"DEC ???"

        # INX rp -> INC rp
        if mnem_upper == 'INX':
            if operands:
                rp = self.map_regpair(operands[0])
                return f"INC {rp}"
            else:
                self.error(f"INX requires a register pair operand")
                return f"INC ???"

        # DCX rp -> DEC rp
        if mnem_upper == 'DCX':
            if operands:
                rp = self.map_regpair(operands[0])
                return f"DEC {rp}"
            else:
                self.error(f"DCX requires a register pair operand")
                return f"DEC ???"

        # DAD rp -> ADD HL,rp
        if mnem_upper == 'DAD':
            if operands:
                rp = self.map_regpair(operands[0])
                return f"ADD HL,{rp}"
            else:
                self.error(f"DAD requires a register pair operand")
                return f"ADD HL,???"

        # PUSH rp
        if mnem_upper == 'PUSH':
            if operands:
                rp = self.map_regpair(operands[0])
                return f"PUSH {rp}"
            else:
                self.error(f"PUSH requires a register pair operand")
                return f"PUSH ???"

        # POP rp
        if mnem_upper == 'POP':
            if operands:
                rp = self.map_regpair(operands[0])
                return f"POP {rp}"
            else:
                self.error(f"POP requires a register pair operand")
                return f"POP ???"

        # ALU with register: ADD r -> ADD r (Z80 implicit A destination)
        if mnem_upper in self.alu_reg_map:
            z80_op = self.alu_reg_map[mnem_upper]
            if operands:
                reg = self.map_register(operands[0])
                return f"{z80_op} {reg}"
            else:
                self.error(f"{mnem_upper} requires a register operand")
                return f"{z80_op} ???"

        # ALU immediate: ADI n -> ADD n (Z80 implicit A destination)
        if mnem_upper in self.alu_imm_map:
            z80_op = self.alu_imm_map[mnem_upper]
            if operands:
                val = operands[0]
                return f"{z80_op} {val}"
            else:
                self.error(f"{mnem_upper} requires an immediate operand")
                return f"{z80_op} ???"

        # IN port -> IN A,(port)
        if mnem_upper == 'IN':
            port = operands[0] if operands else ""
            return f"IN A,({port})"

        # OUT port -> OUT (port),A
        if mnem_upper == 'OUT':
            port = operands[0] if operands else ""
            return f"OUT ({port}),A"

        # Not a recognized 8080 instruction - pass through
        # (could be a directive, macro, Z80 instruction, etc.)
        if operands_str:
            return f"{mnemonic} {operands_str}"
        return mnemonic

    def is_8080_instruction(self, mnemonic):
        """Check if mnemonic is an 8080 instruction we should translate."""
        m = mnemonic.upper()
        return (m in self.no_operand_map or
                m in self.cond_rets or
                m in self.cond_jumps or
                m in self.cond_calls or
                m == 'JMP' or m == 'CALL' or m == 'RST' or
                m == 'MOV' or m == 'MVI' or m == 'LXI' or
                m == 'LDA' or m == 'STA' or m == 'LHLD' or m == 'SHLD' or
                m == 'LDAX' or m == 'STAX' or
                m == 'INR' or m == 'DCR' or m == 'INX' or m == 'DCX' or
                m == 'DAD' or m == 'PUSH' or m == 'POP' or
                m in self.alu_reg_map or m in self.alu_imm_map or
                m == 'IN' or m == 'OUT')

    def translate_line(self, line):
        """Translate a single line of 8080 assembly to Z80."""
        # Preserve empty lines
        if not line.strip():
            return line

        # Extract comment if present
        comment_idx = -1
        in_string = False
        string_char = None
        for i, ch in enumerate(line):
            if in_string:
                if ch == string_char:
                    in_string = False
            elif ch in ('"', "'"):
                in_string = True
                string_char = ch
            elif ch == ';':
                comment_idx = i
                break

        if comment_idx >= 0:
            code_part = line[:comment_idx]
            comment_part = line[comment_idx:]
        else:
            code_part = line
            comment_part = ""

        # Handle pure comment lines
        if not code_part.strip():
            return line

        # Extract label if present (with colon or double colon)
        label = ""
        rest = code_part

        match = self.label_pattern.match(code_part)
        if match:
            label = match.group(1) + match.group(2)  # Preserve : or ::
            rest = match.group(3)
        else:
            # Check for label without colon (starts at column 0, no leading whitespace)
            if code_part and not code_part[0].isspace():
                match = self.label_no_colon_pattern.match(code_part)
                if match:
                    potential_label = match.group(1).upper()
                    # Only treat as label if not an instruction
                    if not self.is_8080_instruction(potential_label):
                        label = match.group(1)
                        rest = match.group(2)

        # Parse the instruction
        rest = rest.strip()
        if not rest:
            # Just a label, no instruction
            if label:
                if comment_part:
                    return label + comment_part
                return label
            return line

        # Split into mnemonic and operands
        parts = rest.split(None, 1)
        mnemonic = parts[0]
        operands_str = parts[1] if len(parts) > 1 else ""

        # Check if this is something we should translate
        if self.is_8080_instruction(mnemonic):
            translated = self.translate_instruction(mnemonic, operands_str)
        else:
            # Pass through directives, macros, and already-Z80 code
            translated = rest

        # Reconstruct the line
        result_parts = []
        if label:
            result_parts.append(label)

        # Preserve original leading whitespace (tabs, spaces, form-feeds, etc.)
        if label:
            result_parts.append("\t")
        else:
            # Extract all leading whitespace from original code_part
            leading_ws = ""
            for ch in code_part:
                if ch.isspace():
                    leading_ws += ch
                else:
                    break
            result_parts.append(leading_ws)

        result_parts.append(translated)

        if comment_part:
            # Add space before comment if needed
            if not translated.endswith(' ') and not comment_part.startswith(' '):
                result_parts.append(' ')
            result_parts.append(comment_part)

        return ''.join(result_parts)

    def translate_file(self, input_path, output_path=None):
        """Translate an 8080 assembly file to Z80."""
        self.errors = []
        self.warnings = []
        self.line_num = 0

        # Read input file
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
        except IOError as e:
            print(f"Error reading {input_path}: {e}", file=sys.stderr)
            return False

        # Handle CP/M format (strip ^Z and everything after)
        if b'\x1a' in data:
            data = data[:data.index(b'\x1a')]

        # Decode
        try:
            text = data.decode('utf-8', errors='replace')
        except:
            text = data.decode('latin-1', errors='replace')

        # Normalize line endings
        lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')

        # Translate each line
        output_lines = []

        # Add .Z80 directive at top if not already present
        has_z80_directive = any(
            line.strip().upper() in ('.Z80', '.8080') or
            line.strip().upper().startswith('.Z80') or
            line.strip().upper().startswith('.8080')
            for line in lines
        )
        if not has_z80_directive:
            output_lines.append('\t.Z80')

        for i, line in enumerate(lines, 1):
            self.line_num = i
            translated = self.translate_line(line)
            output_lines.append(translated)

        # Determine output path
        if output_path is None:
            # Default: replace .mac with _z80.mac or append _z80
            base, ext = os.path.splitext(input_path)
            output_path = base + '_z80' + ext

        # Write output
        output_text = '\n'.join(output_lines)
        try:
            with open(output_path, 'w') as f:
                f.write(output_text)
        except IOError as e:
            print(f"Error writing {output_path}: {e}", file=sys.stderr)
            return False

        # Report warnings
        for warning in self.warnings:
            print(warning, file=sys.stderr)

        # Report errors
        for error in self.errors:
            print(error, file=sys.stderr)

        return len(self.errors) == 0


def main():
    parser = argparse.ArgumentParser(
        description='ux80 - Translate 8080 assembly to Z80 assembly')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('input', help='Input 8080 assembly file (.mac)')
    parser.add_argument('-o', '--output', help='Output Z80 assembly file '
                        '(default: <input>_z80.mac)')

    args = parser.parse_args()

    # Check input file exists
    if not os.path.exists(args.input):
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Translate
    translator = Translator()

    print(f"Translating {args.input}...", file=sys.stderr)
    if translator.translate_file(args.input, args.output):
        output_path = args.output
        if output_path is None:
            base, ext = os.path.splitext(args.input)
            output_path = base + '_z80' + ext
        print(f"Output written to {output_path}")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
