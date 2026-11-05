"""A small reader for the ELF32 files that dbg2elf writes (test helper).

It reads the ELF header, the program header, the sections, the symbol table,
the DWARF 4 line table (the whole state machine, special opcodes included)
and the DIE tree of .debug_info.  It checks the structure as it reads, so
a wrong length or a wrong offset in the file raises ElfError.
"""

import struct


class ElfError(Exception):
    pass


class Elf:
    def __init__(self, blob):
        self.blob = blob
        if blob[:4] != b'\x7fELF':
            raise ElfError('not an ELF file')
        ident = blob[4:16]
        self.ei_class, self.ei_data, self.ei_version = ident[0], ident[1], ident[2]
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
         self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
            '<HHIIIIIHHHHHH', blob, 16)
        self.phdrs = []
        for i in range(self.e_phnum):
            (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags,
             p_align) = struct.unpack_from('<IIIIIIII', blob, self.e_phoff + i * self.e_phentsize)
            self.phdrs.append(dict(type=p_type, offset=p_offset, vaddr=p_vaddr, paddr=p_paddr,
                                   filesz=p_filesz, memsz=p_memsz, flags=p_flags, align=p_align))
        raw = []
        for i in range(self.e_shnum):
            raw.append(struct.unpack_from('<IIIIIIIIII', blob, self.e_shoff + i * self.e_shentsize))
        shstr = raw[self.e_shstrndx]
        self.sections = {}
        self.section_list = []
        for (name, typ, flags, addr, off, size, link, info, align, entsize) in raw:
            nm = self._cstr(blob, shstr[4] + name)
            if off + size > len(blob):
                raise ElfError(f'section {nm} runs past the end of the file')
            sec = dict(name=nm, type=typ, flags=flags, addr=addr, offset=off, size=size,
                       link=link, info=info, align=align, entsize=entsize,
                       data=blob[off:off + size])
            self.section_list.append(sec)
            self.sections[nm] = sec

    @staticmethod
    def _cstr(blob, off):
        end = blob.index(b'\0', off)
        return blob[off:end].decode('utf-8')

    def symbols(self):
        sym, strs = self.sections['.symtab'], self.sections['.strtab']['data']
        out = []
        for i in range(0, sym['size'], 16):
            name, value, size, info, other, shndx = struct.unpack_from('<IIIBBH', sym['data'], i)
            out.append(dict(name=self._cstr(strs, name), value=value, size=size,
                            bind=info >> 4, type=info & 15, shndx=shndx))
        return out

    # -- .debug_line -------------------------------------------------------

    def line_table(self):
        """Returns (file names, rows).  A row is (address, file, line, is_stmt,
        end_sequence), file is the 1 based DWARF number."""
        d = self.sections['.debug_line']['data']
        unit_len, version, hdr_len = struct.unpack_from('<IHI', d, 0)
        if unit_len + 4 != len(d):
            raise ElfError('.debug_line length %d, section %d' % (unit_len + 4, len(d)))
        if version != 4:
            raise ElfError('line table version %d' % version)
        pos = 10
        prog_start = pos + hdr_len
        (min_inst, max_ops, default_stmt, line_base, line_range,
         opcode_base) = struct.unpack_from('<BBBbBB', d, pos)
        pos += 6
        lengths = list(d[pos:pos + opcode_base - 1])
        pos += opcode_base - 1
        dirs = []
        while d[pos] != 0:
            end = d.index(b'\0', pos)
            dirs.append(d[pos:end].decode())
            pos = end + 1
        pos += 1
        files = []
        while d[pos] != 0:
            end = d.index(b'\0', pos)
            name = d[pos:end].decode()
            pos = end + 1
            _dir, pos = _uleb(d, pos)
            _mt, pos = _uleb(d, pos)
            _ln, pos = _uleb(d, pos)
            files.append(name)
        pos += 1
        if pos != prog_start:
            raise ElfError('line table header ends at %d, header_length says %d' % (pos, prog_start))
        rows = []
        addr, file_, line, stmt = 0, 1, 1, bool(default_stmt)
        while pos < len(d):
            op = d[pos]
            pos += 1
            if op >= opcode_base:
                adj = op - opcode_base
                addr += (adj // line_range) * min_inst
                line += line_base + adj % line_range
                rows.append((addr, file_, line, stmt, False))
            elif op == 0:
                n, pos = _uleb(d, pos)
                sub = d[pos]
                body = d[pos + 1:pos + n]
                pos += n
                if sub == 1:
                    rows.append((addr, file_, line, stmt, True))
                    addr, file_, line, stmt = 0, 1, 1, bool(default_stmt)
                elif sub == 2:
                    addr = int.from_bytes(body, 'little')
                else:
                    raise ElfError('extended opcode %d' % sub)
            elif op == 1:
                rows.append((addr, file_, line, stmt, False))
            elif op == 2:
                v, pos = _uleb(d, pos)
                addr += v * min_inst
            elif op == 3:
                v, pos = _sleb(d, pos)
                line += v
            elif op == 4:
                file_, pos = _uleb(d, pos)
            elif op == 6:
                stmt = not stmt
            elif op == 5 or op == 12:
                _v, pos = _uleb(d, pos)
            elif op in (7, 10, 11):
                pass
            elif op == 8:
                addr += ((255 - opcode_base) // line_range) * min_inst
            elif op == 9:
                addr += struct.unpack_from('<H', d, pos)[0]
                pos += 2
            else:
                raise ElfError('line opcode %d' % op)
        return files, rows

    # -- .debug_info -------------------------------------------------------

    def dies(self):
        """The DIE tree of the one compile unit: a dict with tag, attrs (name
        to value), offset and children.  Forms are decoded to Python values
        (strings for strp, an offset for ref4)."""
        info = self.sections['.debug_info']['data']
        abbrev = self.sections['.debug_abbrev']['data']
        dstr = self.sections['.debug_str']['data']
        unit_len, version, abbrev_off, addr_size = struct.unpack_from('<IHIB', info, 0)
        if unit_len + 4 != len(info):
            raise ElfError('.debug_info length %d, section %d' % (unit_len + 4, len(info)))
        if (version, addr_size) != (4, 2):
            raise ElfError('version %d address size %d' % (version, addr_size))
        table = {}
        p = abbrev_off
        while abbrev[p] != 0:
            code, p = _uleb(abbrev, p)
            tag, p = _uleb(abbrev, p)
            children = abbrev[p]
            p += 1
            attrs = []
            while True:
                a, p = _uleb(abbrev, p)
                f, p = _uleb(abbrev, p)
                if a == 0 and f == 0:
                    break
                attrs.append((a, f))
            table[code] = (tag, bool(children), attrs)
        pos = 11

        def read_die():
            nonlocal pos
            off = pos
            code, pos = _uleb(info, pos)
            if code == 0:
                return None
            tag, has_children, attrs = table[code]
            vals = {}
            for a, f in attrs:
                if f == 0x0e:
                    o = struct.unpack_from('<I', info, pos)[0]
                    pos += 4
                    v = Elf._cstr(dstr, o)
                elif f == 0x01:
                    v = struct.unpack_from('<H', info, pos)[0]
                    pos += 2
                elif f == 0x0b:
                    v = info[pos]
                    pos += 1
                elif f == 0x05:
                    v = struct.unpack_from('<H', info, pos)[0]
                    pos += 2
                elif f in (0x06, 0x17, 0x13):
                    v = struct.unpack_from('<I', info, pos)[0]
                    pos += 4
                elif f == 0x0f:
                    v, pos = _uleb(info, pos)
                elif f == 0x0d:
                    v, pos = _sleb(info, pos)
                elif f == 0x18:
                    n, pos = _uleb(info, pos)
                    v = bytes(info[pos:pos + n])
                    pos += n
                elif f == 0x19:
                    v = True
                else:
                    raise ElfError('form %#x' % f)
                vals[a] = v
            node = dict(tag=tag, attrs=vals, offset=off, children=[])
            if has_children:
                while True:
                    c = read_die()
                    if c is None:
                        break
                    node['children'].append(c)
            return node

        root = read_die()
        if pos != len(info):
            raise ElfError('.debug_info has %d bytes after the unit' % (len(info) - pos))
        return root


def _uleb(d, pos):
    v = shift = 0
    while True:
        b = d[pos]
        pos += 1
        v |= (b & 0x7f) << shift
        shift += 7
        if not b & 0x80:
            return v, pos


def _sleb(d, pos):
    v = shift = 0
    while True:
        b = d[pos]
        pos += 1
        v |= (b & 0x7f) << shift
        shift += 7
        if not b & 0x80:
            if b & 0x40:
                v -= 1 << shift
            return v, pos
