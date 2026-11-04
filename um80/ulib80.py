#!/usr/bin/env python3
"""
ulib80 - Microsoft LIB-80 compatible library manager for Linux.

Usage:
    ulib80 -c library.lib file1.rel file2.rel ...   Create library
    ulib80 -l library.lib                           List contents
    ulib80 -x library.lib [module ...]              Extract modules
    ulib80 -a library.lib file.rel ...              Add modules
    ulib80 -d library.lib module ...                Delete modules
    ulib80 -p library.lib                           Print public symbols
"""

import sys
import os
import argparse
import struct
from pathlib import Path

from um80 import __version__
from um80.relformat import RELReader
from um80 import debuginfo


class LibraryError(Exception):
    """Library error."""
    pass


class Module:
    """A module in a library."""
    def __init__(self, name, data=None):
        self.name = name.upper()
        self.data = data or bytearray()
        self.publics = []  # List of public symbol names
        self.size = len(self.data) if data else 0
        self.dbm = None  # bytes of the module's .dbm file (--debug-info), or None

    def __repr__(self):
        return f"Module({self.name}, {self.size} bytes, {len(self.publics)} publics)"


class Library:
    """A .LIB library file."""

    # Library file format:
    # - Magic: "ULIB" (4 bytes)
    # - Version: 1 or 2 (2 bytes)
    # - Module count (2 bytes)
    # - For each module:
    #   - Name length (1 byte)
    #   - Name (N bytes)
    #   - Data offset (4 bytes)
    #   - Data size (4 bytes)
    #   - Version 2 only: .dbm size (4 bytes), 0 for none
    #   - Public count (2 bytes)
    #   - For each public:
    #     - Symbol length (1 byte)
    #     - Symbol name (N bytes)
    # - Module data (concatenated); version 2: each module's .dbm bytes
    #   follow the module's own data
    #
    # A library is written as version 1 when no module has a .dbm, so the
    # file is the same as before --debug-info existed.  Both versions load.

    MAGIC = b'ULIB'
    VERSION = 1
    VERSION_DEBUG = 2

    def __init__(self):
        self.modules = []  # List of Module objects
        self.symbol_index = {}  # symbol_name -> module_name

    @staticmethod
    def read_dbm(filename, rel_data, whole):
        """The bytes of the .dbm beside `filename' (a .REL), or None.

        A .dbm made for another .REL (its length or SHA-256 differ) is
        refused with a warning.  `whole' is true when the .REL is stored as
        it is, so that the check applies.
        """
        path = Path(filename).with_suffix('.dbm')
        if not path.exists():
            return None
        data = path.read_bytes()
        document = debuginfo.load_dbm(data)
        if document is None:
            print(f"Warning: {path} is not a .dbm file of this version: "
                  "not stored", file=sys.stderr)
            return None
        rel = document.get('rel') or {}
        if whole and (rel.get('length') != len(rel_data)
                      or rel.get('sha256') != debuginfo.sha256_hex(rel_data)):
            print(f"Warning: {path} was made for another {filename}: not "
                  "stored", file=sys.stderr)
            return None
        return data

    def add_rel_file(self, filename):
        """Add a .REL file to the library: each module in it.

        A .REL can hold several modules one after another (a LIB-80
        library is one: FORTRAN-80's FORLIB.REL has 106); each becomes a
        module of its own, named by its program name, so a link loads only
        the ones it needs.  A file with one module is stored as it is,
        under the file's name.
        """
        with open(filename, 'rb') as f:
            data = f.read()

        stem = Path(filename).stem.upper()
        parts = self.split_modules(data)
        if len(parts) <= 1:
            parts = [(stem, data)]
        dbm = self.read_dbm(filename, data, len(parts) == 1)
        dbm_module = None
        if dbm is not None:
            dbm_module = (debuginfo.load_dbm(dbm).get('module') or '').upper()
        added = []
        for name, part in parts:
            name = name.upper() or stem
            taken = {mod.name for mod in self.modules}
            if len(parts) == 1 and name in taken:
                raise LibraryError(f"Module '{name}' already exists in library")
            base, n = name, 1
            while name in taken:
                name = f"{base}_{n}"
                n += 1
            module = Module(name, bytearray(part))

            # Parse the REL data to extract public symbols
            module.publics = self._extract_publics(part)
            # The .dbm goes with the module of its own name; a .REL of one
            # module takes it whatever the stored name is.
            if dbm is not None and (len(parts) == 1
                                    or dbm_module == name.upper()):
                module.dbm = dbm

            # Update symbol index
            for sym in module.publics:
                if sym in self.symbol_index:
                    print(f"Warning: Symbol '{sym}' defined in multiple modules", file=sys.stderr)
                self.symbol_index[sym] = name

            self.modules.append(module)
            added.append(name)
        return added

    @staticmethod
    def split_modules(data):
        """[(program name, REL bytes)] of each module in `data'.

        A module ends with special item 14, which ends on a byte boundary;
        each piece gets an end-file item of its own.
        """
        reader = RELReader(data)
        parts = []
        start = 0
        name = ''
        while True:
            try:
                item = reader.read_item()
            except EOFError:
                break
            if item is None or item[0] == 'END_FILE':
                break
            if item[0] == 'PROGRAM_NAME' and not name:
                name = item[1]
            elif item[0] == 'END_PROGRAM':
                end = reader.bits.byte_pos
                parts.append((name, bytes(data[start:end]) + b'\x9e'))
                start, name = end, ''
        return parts

    def _extract_publics(self, data):
        """Extract public symbol names from REL data, in order."""
        publics = {}
        try:
            reader = RELReader(data)
            while True:
                try:
                    item = reader.read_item()
                    if item is None:
                        break
                    if item[0] == 'DEFINE_ENTRY':
                        # Public symbol definition
                        _, name = item[1], item[2]
                        publics[name.upper()] = True
                    elif item[0] == 'ENTRY_SYMBOL':
                        # Entry symbol (also public)
                        name = item[1]
                        publics[name.upper()] = True
                    elif item[0] == 'END_FILE':
                        break
                except EOFError:
                    break
        except Exception as e:
            print(f"Warning: Error parsing REL data: {e}", file=sys.stderr)
        return list(publics)

    def remove_module(self, name):
        """Remove a module from the library."""
        name = name.upper()
        for i, mod in enumerate(self.modules):
            if mod.name == name:
                # Remove from symbol index
                for sym in mod.publics:
                    if self.symbol_index.get(sym) == name:
                        del self.symbol_index[sym]
                del self.modules[i]
                return True
        return False

    def get_module(self, name):
        """Get a module by name."""
        name = name.upper()
        for mod in self.modules:
            if mod.name == name:
                return mod
        return None

    def find_module_for_symbol(self, symbol):
        """Find which module defines a symbol."""
        return self.symbol_index.get(symbol.upper())

    def save(self, filename):
        """Save library to file."""
        version = self.VERSION_DEBUG if any(m.dbm for m in self.modules) \
            else self.VERSION
        with open(filename, 'wb') as f:
            # Write header
            f.write(self.MAGIC)
            f.write(struct.pack('<H', version))
            f.write(struct.pack('<H', len(self.modules)))

            # Calculate data offsets
            # First, calculate index size
            index_size = 8  # Magic + version + count
            for mod in self.modules:
                index_size += 1 + len(mod.name.encode('ascii'))  # Name
                index_size += 4 + 4  # Offset + size
                if version == self.VERSION_DEBUG:
                    index_size += 4  # .dbm size
                index_size += 2  # Public count
                for pub in mod.publics:
                    index_size += 1 + len(pub.encode('ascii'))

            # Write module index
            data_offset = index_size
            for mod in self.modules:
                # Name
                name_bytes = mod.name.encode('ascii')
                f.write(struct.pack('B', len(name_bytes)))
                f.write(name_bytes)

                # Offset and size
                f.write(struct.pack('<I', data_offset))
                f.write(struct.pack('<I', len(mod.data)))
                data_offset += len(mod.data)
                if version == self.VERSION_DEBUG:
                    dbm_size = len(mod.dbm) if mod.dbm else 0
                    f.write(struct.pack('<I', dbm_size))
                    data_offset += dbm_size

                # Publics
                f.write(struct.pack('<H', len(mod.publics)))
                for pub in mod.publics:
                    pub_bytes = pub.encode('ascii')
                    f.write(struct.pack('B', len(pub_bytes)))
                    f.write(pub_bytes)

            # Write module data
            for mod in self.modules:
                f.write(mod.data)
                if version == self.VERSION_DEBUG and mod.dbm:
                    f.write(mod.dbm)

    @classmethod
    def load(cls, filename):
        """Load library from file."""
        lib = cls()

        with open(filename, 'rb') as f:
            # Read header
            magic = f.read(4)
            if magic != cls.MAGIC:
                # A LIB-80 library is .REL modules one after another
                # (FORTRAN-80's FORLIB.LIB): index it as such.
                f.seek(0)
                data = f.read()
                parts = cls.split_modules(data)
                if not parts:
                    raise LibraryError(f"Invalid library file (bad magic: {magic})")
                for i, (name, part) in enumerate(parts):
                    mod = Module(name or f"MODULE{i}", bytearray(part))
                    mod.publics = lib._extract_publics(part)
                    lib.modules.append(mod)
                    for sym in mod.publics:
                        lib.symbol_index.setdefault(sym, mod.name)
                return lib

            version = struct.unpack('<H', f.read(2))[0]
            if version not in (cls.VERSION, cls.VERSION_DEBUG):
                raise LibraryError(f"Unsupported library version: {version}")

            module_count = struct.unpack('<H', f.read(2))[0]

            # Read module index
            modules_info = []
            for _ in range(module_count):
                name_len = struct.unpack('B', f.read(1))[0]
                name = f.read(name_len).decode('ascii')

                offset = struct.unpack('<I', f.read(4))[0]
                size = struct.unpack('<I', f.read(4))[0]
                dbm_size = 0
                if version == cls.VERSION_DEBUG:
                    dbm_size = struct.unpack('<I', f.read(4))[0]

                pub_count = struct.unpack('<H', f.read(2))[0]
                publics = []
                for _ in range(pub_count):
                    pub_len = struct.unpack('B', f.read(1))[0]
                    pub = f.read(pub_len).decode('ascii')
                    publics.append(pub)

                modules_info.append((name, offset, size, publics, dbm_size))

            # Read module data
            for name, offset, size, publics, dbm_size in modules_info:
                f.seek(offset)
                data = f.read(size)

                mod = Module(name, bytearray(data))
                mod.publics = publics
                if dbm_size:
                    mod.dbm = f.read(dbm_size)
                lib.modules.append(mod)

                # Update symbol index
                for sym in publics:
                    lib.symbol_index[sym] = name

        return lib


def cmd_create(args):
    """Create a new library."""
    lib = Library()

    for relfile in args.files:
        if not os.path.exists(relfile):
            print(f"Error: File not found: {relfile}", file=sys.stderr)
            return 1
        try:
            for name in lib.add_rel_file(relfile):
                print(f"  Added: {name}")
        except LibraryError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    lib.save(args.library)
    print(f"Created library: {args.library}")
    print(f"  Modules: {len(lib.modules)}")
    print(f"  Symbols: {len(lib.symbol_index)}")
    return 0


def cmd_list(args):
    """List library contents."""
    if not os.path.exists(args.library):
        print(f"Error: Library not found: {args.library}", file=sys.stderr)
        return 1

    try:
        lib = Library.load(args.library)
    except LibraryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Library: {args.library}")
    print(f"Modules: {len(lib.modules)}")
    print()

    for mod in lib.modules:
        debug = f"  {len(mod.dbm):6d} bytes debug info" if mod.dbm else ""
        print(f"  {mod.name:12s}  {mod.size:6d} bytes  {len(mod.publics):3d} publics{debug}")

    return 0


def cmd_publics(args):
    """Print public symbols."""
    if not os.path.exists(args.library):
        print(f"Error: Library not found: {args.library}", file=sys.stderr)
        return 1

    try:
        lib = Library.load(args.library)
    except LibraryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Library: {args.library}")
    print(f"Public symbols:")
    print()

    # Group by module
    for mod in lib.modules:
        if mod.publics:
            print(f"  {mod.name}:")
            for pub in sorted(mod.publics):
                print(f"    {pub}")
            print()

    return 0


def cmd_extract(args):
    """Extract modules from library."""
    if not os.path.exists(args.library):
        print(f"Error: Library not found: {args.library}", file=sys.stderr)
        return 1

    try:
        lib = Library.load(args.library)
    except LibraryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # If no modules specified, extract all
    if not args.modules:
        modules_to_extract = [mod.name for mod in lib.modules]
    else:
        modules_to_extract = [m.upper() for m in args.modules]

    for name in modules_to_extract:
        mod = lib.get_module(name)
        if not mod:
            print(f"Warning: Module '{name}' not found in library", file=sys.stderr)
            continue

        outfile = f"{name.lower()}.rel"
        with open(outfile, 'wb') as f:
            f.write(mod.data)
        print(f"  Extracted: {name} -> {outfile}")
        if mod.dbm:
            dbm_file = f"{name.lower()}.dbm"
            with open(dbm_file, 'wb') as f:
                f.write(mod.dbm)
            print(f"  Extracted: {name} debug info -> {dbm_file}")

    return 0


def cmd_add(args):
    """Add modules to library."""
    if not os.path.exists(args.library):
        print(f"Error: Library not found: {args.library}", file=sys.stderr)
        return 1

    try:
        lib = Library.load(args.library)
    except LibraryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    for relfile in args.files:
        if not os.path.exists(relfile):
            print(f"Error: File not found: {relfile}", file=sys.stderr)
            return 1
        try:
            for name in lib.add_rel_file(relfile):
                print(f"  Added: {name}")
        except LibraryError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    lib.save(args.library)
    print(f"Updated library: {args.library}")
    print(f"  Modules: {len(lib.modules)}")
    return 0


def cmd_delete(args):
    """Delete modules from library."""
    if not os.path.exists(args.library):
        print(f"Error: Library not found: {args.library}", file=sys.stderr)
        return 1

    try:
        lib = Library.load(args.library)
    except LibraryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    for name in args.modules:
        if lib.remove_module(name):
            print(f"  Deleted: {name.upper()}")
        else:
            print(f"Warning: Module '{name}' not found in library", file=sys.stderr)

    lib.save(args.library)
    print(f"Updated library: {args.library}")
    print(f"  Modules: {len(lib.modules)}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='ulib80 - LIB-80 compatible library manager',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  ulib80 -c mylib.lib foo.rel bar.rel    Create library from REL files
                                         (a foo.dbm beside foo.rel is stored
                                         with the module)
  ulib80 -l mylib.lib                    List modules in library
  ulib80 -p mylib.lib                    List public symbols
  ulib80 -x mylib.lib                    Extract all modules
  ulib80 -x mylib.lib FOO BAR            Extract specific modules
  ulib80 -a mylib.lib baz.rel            Add module to library
  ulib80 -d mylib.lib FOO                Delete module from library
"""
    )
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c', '--create', action='store_true',
                       help='Create new library')
    group.add_argument('-l', '--list', action='store_true',
                       help='List library contents')
    group.add_argument('-p', '--publics', action='store_true',
                       help='Print public symbols')
    group.add_argument('-x', '--extract', action='store_true',
                       help='Extract modules')
    group.add_argument('-a', '--add', action='store_true',
                       help='Add modules to library')
    group.add_argument('-d', '--delete', action='store_true',
                       help='Delete modules from library')

    parser.add_argument('library', help='Library file (.lib)')
    parser.add_argument('files', nargs='*', help='REL files or module names')

    args = parser.parse_args()

    # Route to appropriate command
    if args.create:
        if not args.files:
            print("Error: No input files specified", file=sys.stderr)
            return 1
        return cmd_create(args)
    elif args.list:
        return cmd_list(args)
    elif args.publics:
        return cmd_publics(args)
    elif args.extract:
        args.modules = args.files
        return cmd_extract(args)
    elif args.add:
        if not args.files:
            print("Error: No input files specified", file=sys.stderr)
            return 1
        return cmd_add(args)
    elif args.delete:
        if not args.files:
            print("Error: No modules specified", file=sys.stderr)
            return 1
        args.modules = args.files
        return cmd_delete(args)

    return 0


if __name__ == '__main__':
    sys.exit(main())
