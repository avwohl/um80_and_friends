"""ucref80 reads a name as MACRO-80 does: a '.' may begin it or be inside it.

ucref80 read the source with a name pattern that had no '.' at all, so
`.FOO' was listed as FOO, `X.1' as X, and `.FOO:' was never a definition
(issue #7).  A name is letters, digits and $ . ? @ _ and a digit does not
start one (measured with MACRO-80 3.44 on 2026-11-20: .FOO, ..BAR, .201B and
X.1 are names; `.Z80:' is a label, `.Z80' alone is the directive).  A number
(0FFH, 1.5), a string and a comment hold no symbol.
"""

import os

from um80.ucref80 import CrossReference

SOURCE = """\
\t.Z80
FOO:\tNOP
.FOO:\tNOP
X.1:\tNOP
..BAR::\tNOP
.Z80:\tNOP
\tJP\t.FOO
\tJP\tFOO
\tJP\tX.1
\tLD\tA,0FFH
\tDB\t1.5,.Z80,'.STR',".STR2" ; .NOPE
.EQ1\tEQU\t.FOO+1
.MM\tMACRO
\tNOP
\tENDM
\t.PRINTX /.Q: x/
.LISTING:\tNOP
\tEND
"""


def _xref(tmp_path):
    p = os.path.join(str(tmp_path), "t.mac")
    with open(p, "w") as f:
        f.write(SOURCE)
    x = CrossReference()
    assert x.process_file(p)
    return x


def _lines(refs):
    return [n for _, n in refs]


def test_dot_names_are_symbols_of_their_own(tmp_path):
    x = _xref(tmp_path)
    assert sorted(x.symbols) == ['..BAR', '.EQ1', '.FOO', '.LISTING', '.Z80',
                                 'FOO', 'X.1']
    assert _lines(x.symbols['.FOO'].definitions) == [3]
    assert _lines(x.symbols['.FOO'].references) == [7, 12]
    assert _lines(x.symbols['FOO'].definitions) == [2]
    assert _lines(x.symbols['FOO'].references) == [8]
    assert _lines(x.symbols['X.1'].definitions) == [4]
    assert _lines(x.symbols['X.1'].references) == [9]
    assert _lines(x.symbols['..BAR'].definitions) == [5]
    assert _lines(x.symbols['.EQ1'].definitions) == [12]


def test_dot_directive_with_colon_is_a_label(tmp_path):
    x = _xref(tmp_path)
    assert _lines(x.symbols['.Z80'].definitions) == [6]
    assert _lines(x.symbols['.Z80'].references) == [11]


def test_numbers_strings_and_comments_hold_no_symbol(tmp_path):
    x = _xref(tmp_path)
    for name in ('FFH', '.5', '5', '.STR', '.STR2', '.NOPE', '.Q'):
        assert name not in x.symbols


def test_dot_directive_without_colon_is_no_symbol(tmp_path):
    x = _xref(tmp_path)
    assert '.PRINTX' not in x.symbols
    # a word that only begins like a directive is a name: .LISTING, not .LIST
    assert '.LIST' not in x.symbols
