"""Benchmark parity gate: 424 findings, not one more and not one less.

Scans `benchmark/` with the working copy and compares every finding key -- `(file, line, cwe,
category, message, severity)` -- with the frozen baseline `parity_before.keys` in this directory.
A missing key is a lost true positive, so this gate is the false-negative alarm; a new key is a
claim the engine cannot support.

The baseline is an authority, never an output: nothing in this gate writes to it, and the live keys
never touch the disk, so a run cannot leave a look-alike baseline lying around. Each of the 424
rows was hand-written into a fixture, so the file moves only when a human adds or removes one.
It was re-blessed from 425 to 424 once, and the header of `parity_before.keys` records which key
left and why: a CWE-89 row naming line 6 of a two-line cookie fixture that holds no SQL.

Usage: python benchmark/gates/aa_parity.py
"""
from __future__ import annotations

import os
import sys

from gate_common import (META, GATES_DIR, ROOT, GatePathError, diff, load_keys, report, scan_rows)


def main() -> int:
    meta = META['parity']
    before = load_keys(os.path.join(GATES_DIR, meta['keys_file']), 'parity')
    after = scan_rows('parity', os.path.join(ROOT, meta['scan_root']))
    missing, new = diff(before, after)
    return report('parity', len(before), len(after), missing, new, meta['expected_keys'])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except GatePathError as error:
        print(f'GATE ERROR: {error}')
        sys.exit(2)
