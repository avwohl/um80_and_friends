"""The source distribution carries what the project names, and nothing it
names is missing.

The sdist of 0.3.51 had no CHANGELOG.md, which README.md and the man
pages refer to; pyproject.toml listed a package file, um80/py.typed, that
does not exist; and MANIFEST.in asked for PDFs in a docs/external that
does not exist, so `python -m build' warned.
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(ROOT, name)) as f:
        return f.read()


def test_manifest_includes_the_changelog():
    assert re.search(r'^include\s+CHANGELOG\.md\s*$', _read('MANIFEST.in'), re.M)


def test_every_file_the_manifest_names_exists():
    for line in _read('MANIFEST.in').splitlines():
        words = line.split()
        if words[:1] == ['include']:
            for name in words[1:]:
                assert os.path.exists(os.path.join(ROOT, name)), name
        elif words[:1] == ['recursive-include']:
            assert os.path.isdir(os.path.join(ROOT, words[1])), words[1]


def test_every_package_data_file_exists():
    text = _read('pyproject.toml')
    section = re.search(r'^\[tool\.setuptools\.package-data\]\n(.*?)(?=^\[|\Z)',
                        text, re.M | re.S)
    if section is None:
        return
    for package, files in re.findall(r'^(\S+)\s*=\s*\[(.*?)\]', section.group(1), re.M):
        for name in re.findall(r'"([^"]+)"', files):
            assert os.path.exists(os.path.join(ROOT, package, name)), (package, name)
