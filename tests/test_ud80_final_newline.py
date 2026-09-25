"""ud80 ends its output with a newline after END.

MACRO-80 reads a line only once it ends, so a source whose last line is
`\\tEND' with nothing after it has no END statement to M80 ("%No END
statement").  mbasic2025's 4kbas40_new.mac, written by ud80, lacked the
newline until mbasic2025 ba573d2 added it by hand.
"""

import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_output_ends_with_a_newline_after_end():
    with tempfile.TemporaryDirectory() as d:
        com = os.path.join(d, 'x.com')
        with open(com, 'wb') as f:
            f.write(bytes([0x3E, 0x01, 0xC9]))  # MVI A,1 / RET
        out = os.path.join(d, 'x.mac')
        env = dict(os.environ, PYTHONPATH=REPO)
        subprocess.run([sys.executable, '-m', 'um80.ud80', com, '-o', out],
                       check=True, capture_output=True, env=env)
        with open(out, encoding='ascii') as f:
            text = f.read()
    assert text.endswith('\tEND\n'), repr(text[-20:])
