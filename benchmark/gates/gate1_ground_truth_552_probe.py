"""Gate 1 as a tracked file: the 552-case ground-truth matrix, plus the OOP-constructor witness.

Why this gate exists
--------------------
`scripts/run_all_checks.py` Check 1 is the only place all 552 labelled corpus cases are scored, and the
roster that runs it lives in gitignored `scratch/`. A fresh checkout therefore never asks them, and at
`9242456` it did not have to: the pushed baseline carried exactly one false negative that every tracked
gate was blind to. The suite scored 275 TP / 276 TN / 0 FP / 1 FN, and the whole regression was one line
of stdout in a script nothing ran -- `47/47 gates` was reported green in the commit that shipped it.

The case is `TCS-BENCH-CWE22-V04-BAD`, `benchmark/corpus/cwe_22_traversal/test_v04_bad.py`:

    class FileReader:
        def __init__(self, filename):
            self.path = f"/var/app/uploads/{filename}"
        def read(self):
            with open(self.path) as f: ...

    filename = input("filename: ")
    print(FileReader(filename).read())

`_resolve_function_scope` resolves a call onto the callee class's METHODS and onto module-level
functions, but never onto `ClassName.__init__`. The constructor call therefore handed its argument to no
scope at all: `filename` inside `__init__` was never tainted, `self.path` was never written with taint,
and the `open(self.path)` sink had nothing to report. The fix is the four `.__init__` fallbacks in that
resolver ([ast_scanner.py:13071](../../ast_scanner.py)) -- gated on `audit_all` exactly as the
resolver's other maximum-recall arms are, which is why the default high-signal mode, where speculative
POTENTIAL data flow is suppressed anyway, cannot move on account of it, nor the arena, nor the 24 blessed
keys, nor either parity corpus. `benchmark/runner.py` scores every case with `audit_all=True`.

The causal claim is measured, not argued: `9242456` checked out clean gives FN=1, and that same tree with
only those four lines applied gives TP=276, FP=0, FN=0.

The fix is a rule, not a fixture name, and a second gate proves it independently: `cwe22_pil_tempfile_probe.py`
books the shape `GateCase(request.args.get("d")).clean()` -> `self.outdir = where` -> `shutil.rmtree(self.outdir)`,
which round 3 had filed as quiet because the walk could not cross the same constructor hop. Applying these four
lines moves that row loud, and that gate's own mutation `retire_constructor_scope_resolution` moves it back to
quiet -- the identical mechanism, a different CWE-22 emitter, a different root (`request` here, `input()` in the
corpus case), and no other row of its 61-shape table moving.

What each tier proves
---------------------
TIER 1 scores the whole matrix under the contract `run_all_checks` itself asserts -- 0 FP, 0 FN, and 6 TP
    + 6 TN for every implemented CWE -- and reads the case list from the manifest instead of baking a
    total in, so the gate cannot drift away from the suite it is meant to duplicate.
TIER 2 names the witness on its own line. "275 of 276" is precisely how this survived a push; the next
    one has to be a test id that a reader can find.
TIER 3 is the mutation: refuse the `.__init__` answer the resolver now produces and the witness MUST go
    quiet. Without it this file could be passing for some unrelated reason and keep passing after
    somebody deleted the fix.
"""

from __future__ import annotations

import contextlib
import io as _io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

from benchmark.manifest import get_benchmark_cases  # noqa: E402
from benchmark.runner import BenchmarkRunner, ConfusionMatrix  # noqa: E402
import ast_scanner  # noqa: E402

T = ast_scanner.TaintTracker
WITNESS_ID = 'TCS-BENCH-CWE22-V04-BAD'
WITNESS_FILE = 'benchmark/corpus/cwe_22_traversal/test_v04_bad.py'
BUCKET = {'TP': 'tp', 'FP': 'fp', 'TN': 'tn', 'FN': 'fn'}


def score(cases):
    """`(per-test-id classification, per-CWE matrix, totals)` for the ground-truth cases.

    The engine prints collector/profile chatter per case, which would bury the scorecard, so the whole
    pass runs with stdout and stderr parked; a broken case cannot hide in there either, because
    `BenchmarkRunner.run_case` turns an exception into an FN/FP classification rather than a crash.
    """
    runner = BenchmarkRunner(precision_threshold=0.0, recall_threshold=0.0)
    found, matrices = {}, {}
    chatter = _io.StringIO()
    with contextlib.redirect_stdout(chatter), contextlib.redirect_stderr(chatter):
        for case in cases:
            res = runner.run_case(case)
            found[case.test_id] = res.classification
            cm = matrices.setdefault(case.cwe, ConfusionMatrix())
            key = BUCKET[res.classification]
            setattr(cm, key, getattr(cm, key) + 1)
    return found, matrices


def check_matrix(cases):
    failures = []
    print('\nTIER 1  the whole 552-case matrix (the contract run_all_checks Check 1 asserts)')
    found, matrices = score(cases)
    totals = ConfusionMatrix()
    for name in ('tp', 'fp', 'tn', 'fn'):
        setattr(totals, name, sum(getattr(cm, name) for cm in matrices.values()))
    print(f'  cases={len(cases):3d} TP={totals.tp} TN={totals.tn} FP={totals.fp} FN={totals.fn} '
          f'precision={totals.precision:.4f} recall={totals.recall:.4f}')
    if len(cases) < 552:
        failures.append(f'the corpus shrank below 552 cases: {len(cases)}')
    if totals.fp:
        failures.append(f'{totals.fp} false positives: '
                        + ', '.join(sorted(t for t, c in found.items() if c == 'FP')))
    if totals.fn:
        failures.append(f'{totals.fn} false negatives: '
                        + ', '.join(sorted(t for t, c in found.items() if c == 'FN')))
    for cwe in sorted(matrices):
        cm = matrices[cwe]
        if cm.tp != 6 or cm.tn != 6:
            failures.append(f'{cwe}: expected 6 TP + 6 TN, got {cm.tp} TP + {cm.tn} TN '
                            f'(fp={cm.fp} fn={cm.fn})')
    print(f'  {"OK " if not failures else "FAIL"} {len(matrices)} CWEs at 6 TP + 6 TN, 0 FP, 0 FN')
    return found, failures


def check_witness(found):
    failures = []
    print('\nTIER 2  the OOP constructor witness, named (not subtracted from a total)')
    got = found.get(WITNESS_ID)
    ok = got == 'TP'
    print(f'  {"OK " if ok else "FAIL"} {WITNESS_ID}  {WITNESS_FILE}  classification={got}')
    if not ok:
        failures.append(f'{WITNESS_ID} must be TP, got {got}')
    return failures


_RESOLVE = T._resolve_function_scope


def _no_dunder_init(self, *args, **kwargs):
    """The resolver as it was at `9242456`: a constructor call resolves to no scope at all."""
    found = _RESOLVE(self, *args, **kwargs)
    return None if isinstance(found, str) and found.endswith('.__init__') else found


def check_mutation(cases):
    failures = []
    print('\nTIER 3  the fix refused (the witness must go FN, or this gate proves nothing)')
    witness = [c for c in cases if c.test_id == WITNESS_ID]
    if not witness:
        return [f'{WITNESS_ID} is no longer in the manifest']
    T._resolve_function_scope = _no_dunder_init
    try:
        mutated = score(witness)
    finally:
        T._resolve_function_scope = _RESOLVE
    got = mutated[0].get(WITNESS_ID)
    ok = got == 'FN'
    print(f'  {"CAUGHT" if ok else "MISSED"} __init__ scope resolution refused -> '
          f'{WITNESS_ID}={got}')
    if not ok:
        failures.append(f'{WITNESS_ID} stayed {got} with the resolver weakened, so the matrix is not '
                        f'being passed by the .__init__ fallback this gate exists to lock')
    return failures


def main() -> int:
    cases = get_benchmark_cases()
    found, failures = check_matrix(cases)
    failures += check_witness(found)
    failures += check_mutation(cases)
    for message in failures:
        print(f'  FAILURE {message}')
    print('VERDICT: ' + ('PASS' if not failures else 'FAIL'))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
