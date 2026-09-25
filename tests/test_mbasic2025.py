"""mbasic2025's sources, built with this checkout's um80 and ul80, are byte-exact.

mbasic2025 (https://github.com/avwohl/mbasic2025) reconstructs the source of
historic Microsoft BASIC binaries: MBASIC 5.21 for CP/M, as 14 modules and
as one Z80 file, and Altair 4K and 8K BASIC 4.0.  Each variant builds with
um80/ul80, and the build is checked against the historic binary.  This test
runs each variant's own build commands (its build.sh / makefile) with this
checkout's um80 and ul80 and compares the result with the reference:

    mbasic_521    mbasic_521/build.sh       com/mbasic.com   MBASIC 5.21
    mbasicz       mbasicz/build.sh          com/mbasic.com   the same binary
    4k            4k8k/4k/build_4k.sh       4kbas40.bin      Altair 4K BASIC 4.0
    4k-annotated  as build_4k.sh, from the annotated 4kbas40.mac
    8k            4k8k/8k/build_8k.sh       8kbas.bin        Altair 8K BASIC 4.0
    mbasic_52     mbasic_52/makefile        (none: see below)

The historic binaries are pinned by SHA-256, so a reference that changes in
the checkout is noticed rather than trusted.  mbasic_52 - the MBASIC 5.2
sources of an OEM build ("BASIC 5.2 / MAGIC Operating System / Copyright
1982") - has no historic binary; its image is pinned by SHA-256 too, as the
image MACRO-80 3.44 and LINK-80 3.44 build from it (tools/fourway_mbasic.py
built it with the genuine tools and every mix of them with um80 and ul80).

ul80 pads its output to a 128-byte CP/M record, as LINK-80 writes whole
records, so a reference that is not a whole number of records (4K BASIC's
3833 bytes) is compared up to its length and the rest must be zeros.
(build_4k.sh compares the whole file with cmp, which has failed since ul80
0.3.18 began padding.)

Some sources have a defect the historic binary does not: they assembled
right only because of an um80 behavior that was not MACRO-80's, since
corrected.  Until mbasic2025 changes them, the test applies the change to its
copy first and says so in a warning (see SOURCE_FIXES).  Two of those
(`rdc <!>>' in 4K and 8K BASIC) built the historic bytes with um80 0.3.49 and
do not with this um80: until mbasic2025 changes them, its own build_8k.sh
reports a mismatch.

The sources are found at $MBASIC2025_DIR, or in a mbasic2025 checkout next
to this repository; without them the test is skipped (unless
$MBASIC2025_REQUIRED is set).  CI checks out avwohl/mbasic2025 for it:
.github/workflows/tests.yml.  docs/mbasic2025.md has more, and
tools/fourway_mbasic.py builds the same sources with every mix of um80/ul80
and the genuine MACRO-80/LINK-80.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MBASIC2025 = os.environ.get('MBASIC2025_DIR') or os.path.join(os.path.dirname(REPO), 'mbasic2025')

if not os.path.isdir(os.path.join(MBASIC2025, 'mbasic_521', 'mbasic_src')):
    if os.environ.get('MBASIC2025_REQUIRED'):
        # CI sets this, so that a checkout in the wrong place fails the job
        # instead of skipping the test.
        raise RuntimeError(f'MBASIC2025_REQUIRED, and no mbasic2025 checkout at {MBASIC2025}')
    pytest.skip(f'no mbasic2025 checkout at {MBASIC2025} (set MBASIC2025_DIR)',
                allow_module_level=True)

MB521 = ['bintrp', 'f4', 'biptrg', 'biedit', 'biprtu', 'bio', 'bimisc',
         'bistrs', 'binlin', 'fiveo', 'dskcom', 'dcpm', 'fivdsk', 'init']
MB52 = ['bintrp', 'biedit', 'bimisc', 'binlin', 'bio', 'biprtu', 'biptrg',
        'bistrs', 'dcpm', 'dskcom', 'f4', 'fivdsk', 'fiveo', 'init']

MBASIC_521_SHA = '29d957fc6899c24f6296a1662a27eca545d85ee3f7d70d2794c9d045d92ff157'
ALTAIR_4K_SHA = '3aaa9907f8a2c32452b9b4580c9b4cced2146d7877129cdcd0b9a50c798fb616'
ALTAIR_8K_SHA = 'dfe4b1576c6ac9fe1a47e9ba0fe697f098209ef8eab61cd54cffc626a84152d3'
# ul80's mbasic52.com: the M80 + L80 image of mbasic_52 (24338 bytes, its
# DS space zero) and the zeros that fill its last record.
MBASIC_52_SHA = 'feaa39b5ccc2363a4c5216bf14d536063695f6dc2a8b1e2ebce72b7cdaddf43c'

# name: (directory, [(tool, arguments...)], output, reference, its SHA-256)
VARIANTS = {
    'mbasic_521': (
        'mbasic_521',
        [('um80', f'mbasic_src/{m}.mac', '-o', f'out/{m}.rel') for m in MB521]
        + [('ul80', '-o', 'out/mbasic_go.com', '-s', *[f'out/{m}.rel' for m in MB521])],
        'out/mbasic_go.com', 'com/mbasic.com', MBASIC_521_SHA),
    'mbasicz': (
        'mbasicz',
        [('um80', 'mbasicz.mac', '-o', 'out/mbasicz.rel'),
         ('ul80', '-o', 'out/mbasicz.com', '-s', 'out/mbasicz.rel')],
        'out/mbasicz.com', 'com/mbasic.com', MBASIC_521_SHA),
    '4k': (
        '4k8k/4k',
        [('um80', '4kbas40_new.mac', '-o', '4kbas40.rel'),
         ('ul80', '4kbas40.rel', '-o', '4kbas40_built.bin', '-p', '0')],
        '4kbas40_built.bin', '4kbas40.bin', ALTAIR_4K_SHA),
    '4k-annotated': (
        '4k8k/4k',
        [('um80', '4kbas40.mac', '-o', '4kbas40.rel'),
         ('ul80', '4kbas40.rel', '-o', '4kbas40_built.bin', '-p', '0')],
        '4kbas40_built.bin', '4kbas40.bin', ALTAIR_4K_SHA),
    '8k': (
        '4k8k/8k',
        [('um80', '8kbas_src.mac', '-o', '8kbas_built.rel'),
         ('ul80', '8kbas_built.rel', '-o', '8kbas_built.bin', '-p', '0')],
        '8kbas_built.bin', '8kbas.bin', ALTAIR_8K_SHA),
    'mbasic_52': (
        'mbasic_52',
        [('um80', '-o', f'{m}.rel', '-l', f'{m}.prn', f'{m}.mac') for m in MB52]
        + [('ul80', '-s', *[f'{m}.rel' for m in MB52], '-o', 'mbasic52.com')],
        'mbasic52.com', None, MBASIC_52_SHA),
}

# Where each image loads: an address in a failure message is this plus the
# file offset.
ORIGIN = {'mbasic_521': 0x100, 'mbasicz': 0x100, '4k': 0, '4k-annotated': 0, '8k': 0,
          'mbasic_52': 0x100}

# Source defects the historic binaries do not have: (file, [(text,
# replacement)], why).  A replacement is made only where the text is still in
# the source.
SOURCE_FIXES = {
    'mbasicz': [
        ('mbasicz.mac',
         [(f"\tdc\t'{s}'", f"\tdb\t'{s}'")
          for s in (' in ', 'Ok', 'Break', '?Redo from start', 'Undefined line ',
                    'Random number seed (-32768 to 32767)', 'Owned by Microsoft',
                    ' Bytes free', 'BASIC-80 Rev. 5.21', '[CP/M Version]',
                    'Copyright 1977-1981 (C) by Microsoft', 'Created: 28-Jul-81')],
         "DC for DB: DC sets the high bit of a string's last character (M80, and"
         " um80 since 0.3.7), and these messages have none in MBASIC 5.21;"
         " mbasic_521 has used DB for them since mbasic2025 1ba49ad"),
    ],
    '4k-annotated': [
        ('4kbas40.mac',
         [('\trdc\t<!>>\n', "\tdb\t'>'+80h\n"), ('\trdc\t<!<>\n', "\tdb\t'<'+80h\n")],
         "`rdc <!>>' makes the macro's `irpc ch,<str>' read `irpc ch,<>>', an"
         " empty list to M80 (and now to um80, which reads the list as M80 does)"
         ", and `rdc <!<>' makes `irpc ch,<<>', '<' and '>' to M80.  um80 0.3.49"
         " built the historic bytes from the unchanged lines; this um80 does not"),
    ],
    '8k': [
        ('8kbas_src.mac', [('\trdc\t<!>>\n', "\tdb\t'>'+80h\n")],
         "`rdc <!>>' makes the macro's `irpc ch,<str>' read `irpc ch,<>>', an"
         " empty list to M80 (and now to um80, which reads the list as M80 does)"
         "; the source already writes the '<' keyword as `db '<'+80h'.  um80"
         " 0.3.49 built the historic bytes from the unchanged line; this um80"
         " does not, so mbasic2025's build_8k.sh fails until the line changes"),
    ],
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _run(tool, args, cwd):
    """Run this checkout's um80 or ul80, as the build scripts run theirs."""
    env = dict(os.environ, PYTHONPATH=REPO, PYTHONDONTWRITEBYTECODE='1')
    try:
        # The largest module assembles in a few seconds.
        r = subprocess.run([sys.executable, '-m', f'um80.{tool}', *args], cwd=cwd,
                           capture_output=True, text=True, env=env, check=False,
                           timeout=300)
    except subprocess.TimeoutExpired as e:
        raise AssertionError(f'{tool} {" ".join(args)}: no result in {e.timeout} s') from e
    if r.returncode:
        raise AssertionError(f'{tool} {" ".join(args)}:\n{r.stdout}{r.stderr}')


def _build(name, root, pool):
    """Build a variant in a copy under `root'; return (image, source changes made)."""
    subdir, steps, output, _, _ = VARIANTS[name]
    d = os.path.join(root, name)
    shutil.copytree(os.path.join(MBASIC2025, subdir), d,
                    ignore=shutil.ignore_patterns('out', '*.rel', '*.prn', '*.sym'))
    os.makedirs(os.path.join(d, 'out'), exist_ok=True)
    changed = []
    for fname, edits, why in SOURCE_FIXES.get(name, []):
        p = os.path.join(d, fname)
        with open(p, encoding='latin1') as f:
            text = f.read()
        n = 0
        for old, new in edits:
            if old in text:
                text = text.replace(old, new)
                n += 1
        if n:
            with open(p, 'w', encoding='latin1') as f:
                f.write(text)
            changed.append(f'{subdir}/{fname}: {n} line(s): {why}')
    # The modules assemble independently: all at once, then the link.
    for job in [pool.submit(_run, tool, args, d) for tool, *args in steps if tool == 'um80']:
        job.result()
    for tool, *args in steps:
        if tool != 'um80':
            _run(tool, args, d)
    with open(os.path.join(d, output), 'rb') as f:
        return f.read(), changed


@pytest.fixture(scope='module')
def built(tmp_path_factory):
    """Every variant, built at once: {name: (image, changes) or the exception}."""
    root = str(tmp_path_factory.mktemp('mbasic2025'))
    out = {}
    with ThreadPoolExecutor(max_workers=max(2, os.cpu_count() or 2)) as pool, \
            ThreadPoolExecutor(max_workers=len(VARIANTS)) as outer:
        jobs = {name: outer.submit(_build, name, root, pool) for name in VARIANTS}
        for name, job in jobs.items():
            try:
                out[name] = job.result()
            except AssertionError as e:
                out[name] = e
    return out


def _first_difference(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))


@pytest.mark.parametrize('name', [n for n, v in VARIANTS.items() if v[3]])
def test_historic_reference_is_pinned(name):
    subdir, _, _, ref, sha = VARIANTS[name]
    with open(os.path.join(MBASIC2025, subdir, ref), 'rb') as f:
        assert _sha(f.read()) == sha, f'{subdir}/{ref} is not the historic binary'


@pytest.mark.parametrize('name', list(VARIANTS))
def test_builds_byte_exact(name, built):
    subdir, _, _, ref, sha = VARIANTS[name]
    if isinstance(built[name], Exception):
        raise built[name]
    image, changed = built[name]
    for change in changed:
        warnings.warn(f'mbasic2025 source changed for this build: {change}')
    if ref is None:
        assert _sha(image) == sha, f'{name}: {len(image)} bytes, SHA-256 {_sha(image)}'
        return
    with open(os.path.join(MBASIC2025, subdir, ref), 'rb') as f:
        want = f.read()
    # The record padding, as ul80 writes it: zeros up to a multiple of 128.
    padded = want + bytes(-len(want) % 128)
    i = _first_difference(image, padded)
    n = sum(1 for x, y in zip(image, padded) if x != y) + abs(len(image) - len(padded))
    assert image == padded, (f'{name}: {n} byte{"s" * (n != 1)} differ{"s" * (n == 1)}'
                             f' from {subdir}/{ref}, the first at'
                             f' address {ORIGIN[name] + i:04X}H (file offset {i:X}H;'
                             f' built {len(image)} bytes, reference {len(want)})')
