"""The documents follow the mechanical rules of docs/writing.md.

The documents are written in the style of ASD-STE100 Simplified Technical
English.  These tests check the part of that style that a program can see:
no semicolons, contractions or Latin abbreviations in prose, no paragraph of
more than six sentences, no very long sentence, and man pages that mandoc
reads without an error.  They cannot check that a word is the right one or
that a fact is true; docs/writing.md and docs/glossary.md cover that.

Text that the rules do not touch is skipped: code blocks, code spans, URLs,
HTML, table rows, and quoted text ("...").
"""

import glob
import os
import re
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Task notes kept as a record (docs/writing.md, "Files that follow these
# rules").
FROZEN = {'docs/project.txt', 'docs/build_rom.md'}

# STE allows 25 words in a descriptive sentence and 20 in a procedure,
# counted with the rules of the standard (a code span is one word, and so
# on).  This count is rougher, so the limit has a margin: a sentence over it
# is a run-on sentence by any count.
MAX_SENTENCE_WORDS = 40
MAX_PARAGRAPH_SENTENCES = 6

TOOLS = ['um80', 'ul80', 'ulib80', 'ucref80', 'ud80', 'ux80', 'udb80',
         'dbg2elf']


def _doc_files():
    names = ['README.md', 'CHANGELOG.md', 'tools/dbg2elf_proto/README.md']
    names += sorted(os.path.relpath(p, ROOT)
                    for p in glob.glob(os.path.join(ROOT, 'docs', '*.md')))
    return [n for n in names if n not in FROZEN]


DOCS = _doc_files()


def _clean(text):
    """The prose of a paragraph, with the parts that the rules skip removed."""
    text = re.sub(r'<!--.*?-->', ' ', text, flags=re.S)
    text = re.sub(r'(`+)(.+?)\1', ' CODE ', text, flags=re.S)
    text = re.sub(r'\]\([^)]*\)', ']', text)
    text = re.sub(r'<https?://[^>]*>', ' URL ', text)
    text = re.sub(r'https?://\S+', ' URL ', text)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'&\w+;', ' ', text)
    text = re.sub(r'"[^"\n]*"', ' QUOTE ', text)
    text = re.sub(r'“[^”]*”', ' QUOTE ', text)
    return text


_TABLE_RULE = re.compile(r'^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$')


def _table_lines(lines):
    """The line numbers of Markdown tables: the header, the rule under it
    and the rows up to the next blank line."""
    out = set()
    for index, line in enumerate(lines):
        if index and _TABLE_RULE.match(line.strip()):
            end = index
            while end < len(lines) and lines[end].strip():
                end += 1
            out.update(range(index, end + 1))
    return out


def _paragraphs(path):
    """Yield (line number, prose) for each paragraph and list item.

    A list item is a paragraph of its own.  Headings, table rows, code
    blocks and indented code are not prose.
    """
    with open(os.path.join(ROOT, path), encoding='utf-8') as f:
        lines = f.read().split('\n')
    table = _table_lines(lines)
    fence = None
    para, start = [], 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        match = re.match(r'(`{3,}|~{3,})', stripped)
        if fence:
            if match and stripped.startswith(fence):
                fence = None
            continue
        if match:
            fence = match.group(1)
            if para:
                yield start, ' '.join(para)
            para = []
            continue
        is_item = re.match(r'\s*([-*+]|\d+[.)])\s+', line)
        if (not stripped or number in table
                or stripped.startswith(('#', '|', '<', '>'))
                or re.match(r'^[-=*_ ]{3,}$', stripped)
                or line.startswith('    ') and not para):
            if para:
                yield start, ' '.join(para)
            para = []
            continue
        if is_item and para:
            yield start, ' '.join(para)
            para = []
        if not para:
            start = number
        para.append(stripped)
    if para:
        yield start, ' '.join(para)


# A sentence ends at ".", "!" or "?" before a blank and a capital letter, a
# digit, a placeholder or the lowercase name of a tool ("um80 reads ...").
# "M80 3.44." does not end at "3." because a digit follows the dot with no
# blank.
_SENTENCE_END = re.compile(
    r'(?<=[.!?])\s+(?=[A-Z0-9(\[*_]|(?:u[a-z]*80|dbg2elf|cpmemu|mbasic\w*'
    r'|pip|pytest|mandoc)\b)')


def _sentences(prose):
    prose = re.sub(r'\b(e\.g|i\.e|etc|vs|cf|No|Inc|Fig)\.', r'\1', prose)
    return [s for s in _SENTENCE_END.split(prose) if re.search(r'\w', s)]


def _findings(path, check):
    out = []
    for number, para in _paragraphs(path):
        prose = _clean(para)
        for problem in check(prose):
            out.append(f'{path}:{number}: {problem}')
    return out


def _check_semicolon(prose):
    if ';' in prose:
        yield 'semicolon in prose (rule 8.1): write two sentences'


_CONTRACTION = re.compile(
    r"\b(\w+n't|(it|that|there|here|what|who|let)'s|\w+'(re|ve|ll|d|m))\b",
    re.IGNORECASE)


def _check_contraction(prose):
    for match in _CONTRACTION.finditer(prose):
        yield f'contraction {match.group(0)!r} (rule 4.2)'


_LATIN = re.compile(r'(?<![\w.])(e\.g\.|i\.e\.|etc\.|vs\.|cf\.|via)(?!\w)',
                    re.IGNORECASE)


def _check_latin(prose):
    for match in _LATIN.finditer(prose):
        yield f'{match.group(0)!r}: write "for example", "that is", the ' \
              f'names of the items, "compared with" or "through"'


def _check_paragraph(prose):
    sentences = _sentences(prose)
    if len(sentences) > MAX_PARAGRAPH_SENTENCES:
        yield (f'paragraph of {len(sentences)} sentences (rule 6.6: at most '
               f'{MAX_PARAGRAPH_SENTENCES})')
    for sentence in sentences:
        words = len(sentence.split())
        if words > MAX_SENTENCE_WORDS:
            yield (f'sentence of {words} words (limit {MAX_SENTENCE_WORDS}): '
                   f'{sentence[:60]}...')


@pytest.mark.parametrize('path', DOCS)
def test_no_semicolons_in_prose(path):
    assert _findings(path, _check_semicolon) == []


@pytest.mark.parametrize('path', DOCS)
def test_no_contractions(path):
    assert _findings(path, _check_contraction) == []


@pytest.mark.parametrize('path', DOCS)
def test_no_latin_abbreviations(path):
    assert _findings(path, _check_latin) == []


@pytest.mark.parametrize('path', DOCS)
def test_paragraphs_and_sentences_are_short(path):
    assert _findings(path, _check_paragraph) == []


def test_the_checks_find_the_old_style():
    """The checks find each fault in a sample of the old style of the
    documents, so a test that passes is not a test that sees nothing."""
    old = ('M80 flags it; MAC does not. It doesn\'t matter, e.g. for `A;B`. '
           + 'One. ' * 7)
    prose = _clean(old)
    assert list(_check_semicolon(prose))
    assert list(_check_contraction(prose))
    assert list(_check_latin(prose))
    assert list(_check_paragraph(prose))
    assert not list(_check_semicolon(_clean('Use `DB 1;c` here.')))


MAN_PAGES = sorted(os.path.relpath(p, ROOT)
                   for p in glob.glob(os.path.join(ROOT, 'docs', 'man', '*.1')))


@pytest.mark.skipif(shutil.which('mandoc') is None,
                    reason='mandoc is not installed')
@pytest.mark.parametrize('path', MAN_PAGES)
def test_man_page_has_no_mandoc_error(path):
    """mandoc -T lint finds no error and no warning.  The date in the .TH
    line is free text, which mandoc reports and which is allowed."""
    result = subprocess.run(['mandoc', '-T', 'lint', os.path.join(ROOT, path)],
                            capture_output=True, text=True, check=False)
    problems = [line for line in (result.stdout + result.stderr).splitlines()
                if ('ERROR' in line or 'WARNING' in line)
                and 'cannot parse date' not in line]
    assert problems == []


@pytest.mark.parametrize('tool', TOOLS)
def test_help_text_prints(tool):
    """argparse reads a lone "%" in a help string as a format character, so
    a help text with one fails only when a user asks for --help."""
    result = subprocess.run([sys.executable, '-m', f'um80.{tool}', '--help'],
                            capture_output=True, text=True, check=False,
                            cwd=ROOT)
    assert result.returncode == 0, result.stderr
    assert 'usage:' in result.stdout
