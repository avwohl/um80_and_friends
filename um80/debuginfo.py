"""Debug information: the ;# markers, the .dbm module file, the prog.dbg file.

docs/debug_info.md is the specification.  This module holds what um80,
ulib80 and ul80 share: the marker parser, the collector that um80 fills
while it assembles, the readers and the writers of the two JSON files.
"""

import hashlib
import json
import re

DBM_FORMAT = 'um80-dbm'
DBM_VERSION = 1
DBG_FORMAT = 'um80-dbg'
DBG_VERSION = 1

# Columns of a row of a .dbm file (docs/debug_info.md).  A row may end
# early: the missing columns are null.
ROW_COLUMNS = 11


class MarkerError(ValueError):
    """A ;# line that is a marker but is not well formed."""


_MARKER = re.compile(r'^[ \t]*;[ \t]*#([A-Za-z]+)(.*)$')
_FILE_ARGS = re.compile(r'^[ \t]*(\d+)[ \t]+"((?:[^"\\]|\\.)*)"')
_POSITION = re.compile(r'^(\d+):(\d+)$')
_NAME_CHARS = re.compile(r'^[^\s;]+$')

MARKER_KINDS = ('file', 'line', 'inline', 'endinline', 'func', 'endfunc',
                'noopt')
FRAME_KINDS = ('none', 'ix', 'static')


def _number(word, what):
    if not word.isdigit():
        raise MarkerError(f"{what} must be a decimal number, not '{word}'")
    return int(word)


def parse_marker(line):
    """Read one source line as a debug marker.

    Returns None when the line is not a marker (it is no whole-line comment,
    or the word after ';#' is not a marker kind: readers skip such a line).
    Returns (kind, fields), `fields' a dict, for a marker.  Raises
    MarkerError for a marker kind with wrong fields.
    """
    found = _MARKER.match(line)
    if not found:
        return None
    kind = found.group(1).lower()
    rest = found.group(2)
    if kind not in MARKER_KINDS:
        return None
    if kind == 'file':
        args = _FILE_ARGS.match(rest)
        if not args:
            raise MarkerError('#file needs a number and a path in double '
                              'quotes')
        number = int(args.group(1))
        if number < 1:
            raise MarkerError('#file numbers start at 1')
        path = re.sub(r'\\(.)', r'\1', args.group(2))
        return kind, {'number': number, 'path': path}
    words = rest.split()
    if kind == 'line':
        if len(words) < 2:
            raise MarkerError('#line needs a file number and a line')
        fields = {'file': _number(words[0], 'the file number'),
                  'line': _number(words[1], 'the line'),
                  'nostmt': False, 'outer': None}
        for word in words[2:]:
            low = word.lower()
            if low == 'nostmt':
                fields['nostmt'] = True
            elif low.startswith('outer='):
                pos = _POSITION.match(word[6:])
                if not pos:
                    raise MarkerError('outer= needs FILE:LINE')
                fields['outer'] = (int(pos.group(1)), int(pos.group(2)))
            # any other word: ignored, so a later version can add words
        return kind, fields
    if kind == 'inline':
        if len(words) < 3:
            raise MarkerError('#inline needs a file number, a line and a '
                              'name')
        if not _NAME_CHARS.match(words[2]):
            raise MarkerError('#inline name is not a name')
        return kind, {'file': _number(words[0], 'the file number'),
                      'line': _number(words[1], 'the line'),
                      'name': words[2]}
    if kind == 'endinline':
        return kind, {}
    if kind == 'func':
        if len(words) < 3:
            raise MarkerError('#func needs a name, a file number and a line')
        fields = {'name': words[0],
                  'file': _number(words[1], 'the file number'),
                  'line': _number(words[2], 'the line'),
                  'frame': 'none', 'pops': 0, 'ixbegin': None,
                  'ixend': None}
        for word in words[3:]:
            key, sep, value = word.partition('=')
            key = key.lower()
            if not sep:
                continue
            if key == 'frame':
                if value.lower() not in FRAME_KINDS:
                    raise MarkerError(f"frame= is none, ix or static, not "
                                      f"'{value}'")
                fields['frame'] = value.lower()
            elif key == 'pops':
                fields['pops'] = _number(value, 'pops=')
            elif key in ('ixbegin', 'ixend'):
                fields[key] = value
            # any other key: ignored
        return kind, fields
    if kind == 'endfunc':
        return kind, {'name': words[0] if words else None}
    # noopt
    if len(words) != 1 or words[0].lower() not in ('begin', 'end'):
        raise MarkerError('#noopt is followed by begin or end')
    return kind, {'what': words[0].lower()}


def seg_name(seg_type, block=None, absolute_name='ABS'):
    """The name of a segment in a .dbm file."""
    from um80.relformat import (ADDR_ABSOLUTE, ADDR_PROGRAM_REL,
                                ADDR_DATA_REL)
    if seg_type == ADDR_ABSOLUTE:
        return absolute_name
    if seg_type == ADDR_PROGRAM_REL:
        return 'CSEG'
    if seg_type == ADDR_DATA_REL:
        return 'DSEG'
    return 'COMMON:' + (block.upper() if block else ' ')


class DebugCollector:
    """What um80 --debug-info records during pass 2."""

    def __init__(self, main_source, warn):
        self.main_source = main_source
        self.warn = warn            # warn(message): a warning at the line
        self.files = []             # paths: the .mac files and the sources
        self.file_index = {}
        self.numbers = {}           # marker file number -> index in files
        self.rows = []
        self.labels = []
        self.label_names = set()
        self.funcs = []
        self.open_func = None
        self.noopt = []             # [start, end] triples
        self.noopt_open = None
        self.noopt_depth = 0
        # The position state, as GNU as keeps .loc.  `pending' is None
        # while no marker came since the last row, and otherwise the
        # group the next row gets (an empty list: no position).
        self.pending = None
        self.last = None            # the primary position now in force
        self.inline = []            # [name, file, line, position at #inline]
        self.inline_dirty = False

    def file(self, path):
        """The index of `path' in the file table."""
        if path is None:
            path = self.main_source
        index = self.file_index.get(path)
        if index is None:
            index = self.file_index[path] = len(self.files)
            self.files.append(path)
        return index

    def _known(self, number):
        index = self.numbers.get(number)
        if index is None:
            self.warn(f"Debug marker names file number {number}, which no "
                      "#file marker defined: marker ignored")
        return index

    def marker(self, kind, fields, where):
        """Apply a marker.  `where' is [segment, offset, run address or
        None] of the next byte."""
        if kind == 'file':
            self.numbers[fields['number']] = self.file(fields['path'])
        elif kind == 'line':
            if fields['file'] == 0:
                self.pending = []
                self.last = None
                return
            index = self._known(fields['file'])
            if index is None:
                return
            outer = None
            if fields['outer'] is not None:
                if fields['outer'][0] == 0:
                    outer = None
                else:
                    outer_index = self._known(fields['outer'][0])
                    outer = None if outer_index is None else \
                        (outer_index, fields['outer'][1])
            entry = [index, fields['line'], 1 if fields['nostmt'] else 0]
            if outer:
                entry += [outer[0], outer[1]]
            if self.pending is None:
                self.pending = []
            self.pending.append(entry)
            self.last = entry
        elif kind == 'inline':
            index = self._known(fields['file'])
            if index is None:
                return
            self.inline.append([fields['name'], index, fields['line'],
                                self.last])
            self.inline_dirty = True
        elif kind == 'endinline':
            if not self.inline:
                self.warn("#endinline with no #inline before it: marker "
                          "ignored")
                return
            saved = self.inline.pop()[3]
            self.inline_dirty = True
            self.pending = [saved] if saved else []
            self.last = saved
        elif kind == 'func':
            if self.open_func is not None:
                self.warn(f"#func {fields['name']} inside {self.open_func['name']}"
                          ": the first one has no #endfunc")
                self.open_func['end'] = None
            index = self._known(fields['file']) if fields['file'] else None
            func = {'name': fields['name'],
                    'file': index, 'line': fields['line'],
                    'frame': fields['frame'], 'pops': fields['pops'],
                    'start': list(where), 'end': None,
                    'ixbegin': fields['ixbegin'], 'ixend': fields['ixend']}
            self.funcs.append(func)
            self.open_func = func
        elif kind == 'endfunc':
            func = self.open_func
            if func is None:
                self.warn("#endfunc with no #func before it: marker ignored")
                return
            if fields['name'] and fields['name'] != func['name']:
                self.warn(f"#endfunc {fields['name']} closes #func "
                          f"{func['name']}")
            func['end'] = list(where)
            self.open_func = None
            # The bytes after the routine have no source position.
            self.pending = []
            self.last = None
        elif kind == 'noopt':
            if fields['what'] == 'begin':
                if self.noopt_depth == 0:
                    self.noopt_open = list(where)
                self.noopt_depth += 1
            else:
                if self.noopt_depth == 0:
                    self.warn("#noopt end with no #noopt begin: marker "
                              "ignored")
                    return
                self.noopt_depth -= 1
                if self.noopt_depth == 0:
                    self.noopt.append([self.noopt_open, list(where)])

    def row(self, seg, offset, length, run, mac_file, mac_line, kind,
            body=None):
        """Record the bytes of one instruction or data statement."""
        src, self.pending = self.pending, None
        inl = None
        if self.inline_dirty:
            inl = [[name, f, line] for name, f, line, _ in self.inline]
            self.inline_dirty = False
        row = [seg, offset, length, run, self.file(mac_file), mac_line, kind,
               src, inl, None, None]
        if body is not None:
            row[9] = self.file(body[0])
            row[10] = body[1]
        while row and row[-1] is None:
            row.pop()
        self.rows.append(row)

    def label(self, name, seg, offset, mac_file, mac_line):
        if name in self.label_names:
            return
        self.label_names.add(name)
        self.labels.append([name, seg, offset, self.file(mac_file), mac_line])

    def finish(self, module, source, rel_bytes, resolve):
        """The .dbm document.  `resolve(label)' gives [segment, offset] of a
        label or None."""
        if self.open_func is not None:
            self.warn(f"#func {self.open_func['name']} has no #endfunc")
        if self.noopt_depth:
            self.warn("#noopt begin has no #noopt end")
        funcs = []
        for func in self.funcs:
            ix = None
            if func['ixbegin'] or func['ixend']:
                begin = resolve(func['ixbegin']) if func['ixbegin'] else None
                end = resolve(func['ixend']) if func['ixend'] else None
                if begin is None or end is None:
                    self.warn(f"#func {func['name']}: ixbegin= and ixend= "
                              "must name two labels")
                else:
                    ix = [begin, end]
            funcs.append({'name': func['name'], 'file': func['file'],
                          'line': func['line'], 'frame': func['frame'],
                          'pops': func['pops'], 'start': func['start'],
                          'end': func['end'], 'ix': ix})
        return {'format': DBM_FORMAT, 'version': DBM_VERSION,
                'module': module, 'source': source,
                'rel': {'length': len(rel_bytes),
                        'sha256': hashlib.sha256(rel_bytes).hexdigest()},
                'files': self.files, 'rows': self.rows,
                'labels': self.labels, 'funcs': funcs,
                'noopt': self.noopt}


def row_fields(row):
    """A .dbm row as a list of ROW_COLUMNS values."""
    return list(row) + [None] * (ROW_COLUMNS - len(row))


def dumps(document, tables):
    """JSON text of `document'.  Each table of `tables' (a key whose value is
    a list of rows) has one row to a line, which keeps a diff readable."""
    parts = []
    for key, value in document.items():
        if key in tables:
            body = ',\n'.join(json.dumps(row, separators=(',', ':'))
                              for row in value)
            parts.append(json.dumps(key) + ':[\n' + body + '\n]'
                         if value else json.dumps(key) + ':[]')
        else:
            parts.append(json.dumps(key) + ':'
                         + json.dumps(value, separators=(',', ':')))
    return '{' + ',\n'.join(parts) + '}\n'


DBM_TABLES = ('rows', 'labels')
DBG_TABLES = ('lines', 'asm', 'labels', 'moved', 'noopt')


def load_dbm(data):
    """The document of .dbm bytes, or None when the data is no .dbm of a
    version this program reads."""
    try:
        document = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    if (not isinstance(document, dict)
            or document.get('format') != DBM_FORMAT
            or document.get('version') != DBM_VERSION):
        return None
    return document


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()
