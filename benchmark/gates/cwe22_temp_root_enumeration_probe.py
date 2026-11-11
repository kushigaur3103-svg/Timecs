"""Round 7: a `for` target over a directory the program created is a path the program chose.

What this gate is for
---------------------
`_c22_path_is_proven_temp_root` already proves that `tempfile.mkdtemp()` / `TemporaryDirectory()`
handed this program a root the OS picked, and the engine already spends that proof on deletes
(`_c22_cleanup_is_temp_teardown`) and on `self.<field>` reads (`_c22_self_attribute_is_temp_sink`).
What it could not answer was a LOOP TARGET: `for f in Path(temp_dir).glob("*")` binds `f` through an
`ast.For`, not an assignment, so the positive origin proof reads that absence as "no origin". Absence
of evidence is not evidence of a caller-chosen path.

The one arena row this retires is `src/transformers/integrations/integration_utils.py:800` --
`with tempfile.TemporaryDirectory() as temp_dir:` at 776, `for f in Path(temp_dir).glob("*")` at 799,
`f.read_bytes()` inside it. Measured solo against HEAD's committed blob and the candidate, one process
per arm, printing EVERY row of the file: HEAD reports 5 rows, the candidate 4, the retired row is
exactly (800, CWE-22, `f.read_bytes`), nothing added and nothing moved.

This is the ONE row of the mandate's Lever C that is provably local. The other nine `no_entrypoint_fact`
rows are declined, and the decline is booked with its evidence in
`benchmark/gates/cwe22_no_entrypoint_decline_probe.py`: three of them are `open(inputs)` in the `else`
branch of a `startswith("http")` test on a public pipeline API, which is a genuine traversal, and three
more sit under `is_remote_url -> download_url`. "No entrypoint in this file" is not "no attacker": a
library's caller is the entrypoint, and the engine cannot see it from here.

What the clause refuses, and why each refusal is load-bearing
------------------------------------------------------------
  * the receiver must be a PROVEN temp root, so a parameter or a request body does not qualify;
  * the enumerator must be one of three pathlib leaves. `iglob` and `scandir` are DELIBERATE declines:
    they stay loud, and `enumerator_leaf_blind` is the mutation that proves the table is closed;
  * the pattern must be a constant with no `..` segment and no absolute root, because pathlib ignores
    the receiver for an absolute pattern: `Path(tmp).glob("/etc/*")` reads /etc;
  * the FIRST enclosing `for` that names the target decides, so an inner loop that rebinds the name
    cannot borrow the outer loop's proof;
  * a callable boundary ends the search, because past it the name is a parameter or a closure.

A comprehension target is DECLINED, not retired: `[f.read_bytes() for f in Path(tmp).glob("*")]` binds
through `ast.comprehension`, a different shape, and crediting it needs its own proof and its own
fixtures. TIER 3 asks the PREDICATE about it rather than a row, because a row-level "still loud" claim
on a fixture that is quiet for its own reasons would be false.

Four shapes are booked in TIER 1b as INHERITED QUIET, measured against HEAD's own blob rather than
assumed. Three of them (`rglob`, a starred pattern, a plain assignment) produce no row at HEAD either:
the fallback emitter reports this row for a closed set of enumeration leaves, and `rglob` is not in it.
The fourth (`joinpath`) is retired by a DIFFERENT clause -- `joinpath` is a path reshaper over a proven
temp root, so `_c22_value_is_proven_module_origin` already answers it. None of the four may be claimed
by this refinement, and none of them can witness a mutation.

Two fixture-fidelity traps, both of which read as PASS-shaped silence rather than as an error:
  * `_c22_slice_g_module_facts` wants the NAME `tempfile` to appear as an `ast.Name`, which `import
    tempfile` alone does not create. A hiding shape whose module only imports tempfile never reaches
    the clause, so `receiver_proof_dropped` cannot move it. Hence the unrelated `tempfile.mkdtemp()`
    call in `receiver_is_parameter`.
  * the proof walks PARENT LINKS and reads the assignment table by SCOPE ID. A privately `ast.parse`d
    tree has neither, so TIER 3 asks the tracker's own tree with the sink record's own scope_id, and
    runs a control first: the same question on `glob_temp_dir` must answer True, or a harness that can
    see nothing would report False everywhere and read as a PASS.

How to read the tiers
---------------------
TIER 0 checks the enumerator table is closed. TIER 1 is the retirements, attributed against a
`loop_proof_off` arm so a row this clause did not retire cannot be booked to it. TIER 1b books the
shapes already quiet under both arms. TIER 2 is the hiding shapes, each required loud under BOTH arms.
TIER 3 is the decline, asked on the proof, behind a control. TIER 4 is one weakening per clause, each
with the rows it was measured to move; the baseline is read BEFORE the weakening is installed, because
reading it afterwards compares the mutated engine with itself and reports every mutation as MISSED.

Every pin is the fixture's own `read_bytes()` line, read off its AST rather than counted by hand.

    python benchmark/gates/cwe22_temp_root_enumeration_probe.py
    python benchmark/gates/cwe22_temp_root_enumeration_probe.py --mutate=enumerator_leaf_blind
"""
from __future__ import annotations

import ast
import contextlib
import io as _io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)
sys.path.insert(0, GATES_DIR)

import ast_scanner  # noqa: E402
import cli  # noqa: E402

T = ast_scanner.TaintTracker


def module(*lines):
    return ''.join(line + '\n' for line in lines)


def pinned(table, leaf='read_bytes'):
    """label -> source becomes label -> (the fixture's own sink line, source)."""
    out = {}
    for label, source in table.items():
        lines = [node.lineno for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and node.func.attr == leaf]
        if len(lines) != 1:
            raise AssertionError(f'{label}: expected exactly one .{leaf}() call, found {lines}')
        out[label] = (lines[0], source)
    return out


HEAD = ('import tempfile', 'from pathlib import Path', 'import requests')


def program(*body):
    return module(*HEAD, 'def main():', *('    ' + line for line in body))


def with_temp(*body):
    return program('with tempfile.TemporaryDirectory() as temp_dir:',
                   *('    ' + line for line in body))


# --------------------------------------------------------------------------- TIER 1: the retirements
RETIRED_BY_TEMP_ENUMERATION = pinned({
    'glob_temp_dir': with_temp(
        'for f in Path(temp_dir).glob("*"):',
        '    data = f.read_bytes()'),
    'iterdir_temp_dir': with_temp(
        'for f in Path(temp_dir).iterdir():',
        '    data = f.read_bytes()'),
    'mkdtemp_glob': program(
        'temp_dir = tempfile.mkdtemp()',
        'for f in Path(temp_dir).glob("*.bin"):',
        '    data = f.read_bytes()'),
    # The arena's own shape: a callback method on a class, in a library module with no entrypoint.
    'class_method_arena_shape': module(
        *HEAD,
        'class Callback:',
        '    def on_train_end(self, args):',
        '        with tempfile.TemporaryDirectory() as temp_dir:',
        '            for f in Path(temp_dir).glob("*"):',
        '                if f.is_file():',
        '                    data = f.read_bytes()'),
})

# Quiet under BOTH arms, and quiet at HEAD's own blob too, so this clause may not claim them.
INHERITED_QUIET = pinned({
    'rglob_temp_dir': with_temp(
        'for f in Path(temp_dir).rglob("*"):',
        '    data = f.read_bytes()'),
    'starred_pattern': with_temp(
        'patterns = ["*"]',
        'for f in Path(temp_dir).glob(*patterns):',
        '    data = f.read_bytes()'),
    'not_a_loop_target': program(
        'f = payload()',
        'data = f.read_bytes()'),
    # Retired by the reshaper proof, not by this clause: `joinpath` is in `_C22_PATH_FUNCS`, so
    # `_c22_value_is_proven_module_origin` answers it through the loop target's binding.
    'not_an_enumerator': with_temp(
        'for f in Path(temp_dir).joinpath("*"):',
        '    data = f.read_bytes()'),
})

# --------------------------------------------------------------------------- TIER 2: the hiding shapes
LOUD_BY_UNPROVEN_ENUMERATION = pinned({
    # The unrelated mkdtemp() call is the presence fact: `import tempfile` alone creates no ast.Name,
    # so without it the module never reaches the clause and no mutation could move this row.
    'receiver_is_parameter': module(
        *HEAD,
        'def unrelated():',
        '    return tempfile.mkdtemp()',
        'def helper(temp_dir):',
        '    for f in Path(temp_dir).glob("*"):',
        '        data = f.read_bytes()'),
    'receiver_is_request': with_temp(
        'for f in Path(requests.get("http://evil/d").text).glob("*"):',
        '    data = f.read_bytes()'),
    'absolute_pattern': with_temp(
        'for f in Path(temp_dir).glob("/etc/*"):',
        '    data = f.read_bytes()'),
    'windows_absolute_pattern': with_temp(
        'for f in Path(temp_dir).glob("C:/Windows/*"):',
        '    data = f.read_bytes()'),
    'dotdot_pattern': with_temp(
        'for f in Path(temp_dir).glob("../*"):',
        '    data = f.read_bytes()'),
    'nonconstant_pattern': module(
        *HEAD,
        'def helper(pattern):',
        '    with tempfile.TemporaryDirectory() as temp_dir:',
        '        for f in Path(temp_dir).glob(pattern):',
        '            data = f.read_bytes()'),
    'keyword_pattern': with_temp(
        'for f in Path(temp_dir).glob(pattern="*"):',
        '    data = f.read_bytes()'),
    'two_patterns': with_temp(
        'for f in Path(temp_dir).glob("*", "*"):',
        '    data = f.read_bytes()'),
    'iterdir_with_arg': with_temp(
        'for f in Path(temp_dir).iterdir("*"):',
        '    data = f.read_bytes()'),
    'inner_loop_rebinds': with_temp(
        'for f in Path(temp_dir).glob("*"):',
        '    for f in payload():',
        '        data = f.read_bytes()'),
    'temp_dir_rebound': with_temp(
        'temp_dir = requests.get("http://evil/d").text',
        'for f in Path(temp_dir).glob("*"):',
        '    data = f.read_bytes()'),
    # Deliberate declines, not soundness claims: the table is closed to three leaves, and these two
    # are reported at HEAD and stay reported. They are what `enumerator_leaf_blind` moves.
    'iglob_declined': with_temp(
        'for f in Path(temp_dir).iglob("*"):',
        '    data = f.read_bytes()'),
    'scandir_declined': with_temp(
        'for f in Path(temp_dir).scandir("*"):',
        '    data = f.read_bytes()'),
})

# --------------------------------------------------------------------------- TIER 3: the decline
DECLINED_COMPREHENSION = pinned({
    'comprehension_target': with_temp(
        'data = [f.read_bytes() for f in Path(temp_dir).glob("*")]'),
})


def scan_module(source, module_name='m.py'):
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files={module_name: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(int(row['line']), row['message']) for row in rows if row['cwe'] == 'CWE-22'})


def rows_at(found, line):
    return [message for row_line, message in found if row_line == line]


def loop_proof_off(source):
    """The round-6 behaviour: a loop target has no binding, so it has no proven origin."""
    original = T._c22_loop_target_enumerates_temp_root
    T._c22_loop_target_enumerates_temp_root = lambda *a, **k: False
    try:
        return scan_module(source)
    finally:
        T._c22_loop_target_enumerates_temp_root = original


def tracker_for(source):
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files={'m.py': source}, max_workers=1)
        tracker.analyze()
    return tracker


def loop_proof_on_record(tracker, label):
    """Ask the proof the way the cascade asks it: the tracker's tree, the record's own scope_id.

    A privately parsed tree has no parent links and a guessed scope_id finds no assignment records,
    so either one would answer False for every fixture and read as a PASS.
    """
    record = next(r for r in tracker.sink_records
                  if (r.security_node.metadata or {}).get('cwe') == 'CWE-22')
    tree = tracker.modules.get(ast_scanner.scope_module(record.scope_id))
    target = record.node.func.value
    if tree is None or not isinstance(target, ast.Name):
        raise AssertionError(f'{label}: no Name receiver on the CWE-22 record')
    return tracker._c22_loop_target_enumerates_temp_root(target, record.scope_id, record.lineno)


# --------------------------------------------------------------------------- tiers
def check_tables():
    failures = []
    print('\nTIER 0  enumerator table is closed')
    for name in ('glob', 'rglob', 'iterdir'):
        if name not in ast_scanner.CWE22_TEMP_ROOT_ENUMERATION_LEAVES:
            failures.append(f'enumerator {name} missing from the table')
    for name in ('scandir', 'listdir', 'open', 'joinpath', 'read_text', 'walk', 'iglob', 'match'):
        if name in ast_scanner.CWE22_TEMP_ROOT_ENUMERATION_LEAVES:
            failures.append(f'{name} must NOT be in the enumerator table')
    print(f'  leaves={len(ast_scanner.CWE22_TEMP_ROOT_ENUMERATION_LEAVES)} '
          f'failures={len(failures)}')
    return failures


def check_retirements():
    failures = []
    print('\nTIER 1  retirements (quiet shipped, loud with the loop proof reverted)')
    for label, (line, source) in sorted(RETIRED_BY_TEMP_ENUMERATION.items()):
        shipped = rows_at(scan_module(source), line)
        reverted = rows_at(loop_proof_off(source), line)
        ok = not shipped and bool(reverted)
        print(f'  {"OK " if ok else "FAIL"} {label:28s} line={line:3d} '
              f'shipped={len(shipped)} loop_proof_off={len(reverted)}')
        if not ok:
            failures.append(f'{label}: shipped={shipped} loop_proof_off={reverted}')
    return failures


def check_inherited():
    failures = []
    print('\nTIER 1b  already quiet at HEAD (this clause must not claim them)')
    for label, (line, source) in sorted(INHERITED_QUIET.items()):
        shipped = rows_at(scan_module(source), line)
        reverted = rows_at(loop_proof_off(source), line)
        ok = not shipped and not reverted
        print(f'  {"OK " if ok else "FAIL"} {label:28s} line={line:3d} '
              f'shipped={len(shipped)} loop_proof_off={len(reverted)}')
        if not ok:
            failures.append(f'{label}: shipped={shipped} loop_proof_off={reverted}')
    return failures


def check_hiding_shapes():
    failures = []
    print('\nTIER 2  hiding shapes (loud under BOTH arms)')
    for label, (line, source) in sorted(LOUD_BY_UNPROVEN_ENUMERATION.items()):
        shipped = rows_at(scan_module(source), line)
        reverted = rows_at(loop_proof_off(source), line)
        ok = bool(shipped) and bool(reverted)
        print(f'  {"OK " if ok else "FAIL"} {label:28s} line={line:3d} '
              f'shipped={len(shipped)} loop_proof_off={len(reverted)}')
        if not ok:
            failures.append(f'{label}: shipped={shipped} loop_proof_off={reverted}')
    return failures


def check_declined():
    failures = []
    print('\nTIER 3  declined comprehension target (asked on the proof, behind a control)')
    control = loop_proof_on_record(tracker_for(RETIRED_BY_TEMP_ENUMERATION['glob_temp_dir'][1]),
                                   'control_glob_temp_dir')
    print(f'  {"OK " if control else "FAIL"} control_glob_temp_dir          loop_proof={control}')
    if not control:
        failures.append(f'control_glob_temp_dir: loop_proof={control}')
    for label, (line, source) in sorted(DECLINED_COMPREHENSION.items()):
        shipped = loop_proof_on_record(tracker_for(source), label)
        ok = shipped is False
        print(f'  {"OK " if ok else "FAIL"} {label:28s} loop_proof={shipped}')
        if not ok:
            failures.append(f'{label}: loop_proof={shipped}')
    return failures


# --------------------------------------------------------------------------- TIER 4: mutations
def _loop_outer_wins(self, expr, scope_id='', lineno=0, depth=0):
    """An outer loop may lend its proof to a name an inner loop rebound."""
    if not isinstance(expr, ast.Name) or depth > 8:
        return False
    node = getattr(expr, 'parent', None)
    found = False
    while node is not None:
        if isinstance(node, (ast.For, ast.AsyncFor)):
            if expr.id in ast_scanner._c22_target_names(node.target):
                found = self._c22_enumeration_is_over_temp_root(node.iter, scope_id, lineno) or found
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return found
        node = getattr(node, 'parent', None)
    return found


def _enum_shape(self, iter_expr, scope_id, lineno, leaf_blind=False, absolute_ok=False,
                dotdot_ok=False, nonconstant_ok=False, receiver_unproven=False):
    """One copy of the shipped enumeration check with a single clause switchable."""
    if not isinstance(iter_expr, ast.Call) or not isinstance(iter_expr.func, ast.Attribute):
        return False
    leaf = iter_expr.func.attr
    if not leaf_blind and leaf not in ast_scanner.CWE22_TEMP_ROOT_ENUMERATION_LEAVES:
        return False
    if iter_expr.keywords or any(isinstance(a, ast.Starred) for a in iter_expr.args):
        return False
    if leaf == 'iterdir':
        if iter_expr.args:
            return False
    else:
        if len(iter_expr.args) != 1:
            return False
        pattern = iter_expr.args[0]
        if isinstance(pattern, ast.Constant) and isinstance(pattern.value, str):
            if not dotdot_ok and not self._c22_anchor_literal_ok(pattern, True):
                return False
            text = pattern.value.replace('\\', '/')
            if not absolute_ok and (text.startswith('/') or (len(text) > 1 and text[1] == ':')):
                return False
        elif not nonconstant_ok:
            return False
    if receiver_unproven:
        return True
    return self._c22_path_is_proven_temp_root(iter_expr.func.value, scope_id, lineno)


def _enum_leaf_blind(self, iter_expr, scope_id, lineno):
    return _enum_shape(self, iter_expr, scope_id, lineno, leaf_blind=True)


def _enum_absolute_allowed(self, iter_expr, scope_id, lineno):
    return _enum_shape(self, iter_expr, scope_id, lineno, absolute_ok=True)


def _enum_dotdot_allowed(self, iter_expr, scope_id, lineno):
    return _enum_shape(self, iter_expr, scope_id, lineno, dotdot_ok=True)


def _enum_nonconstant_allowed(self, iter_expr, scope_id, lineno):
    return _enum_shape(self, iter_expr, scope_id, lineno, nonconstant_ok=True)


def _enum_receiver_dropped(self, iter_expr, scope_id, lineno):
    return _enum_shape(self, iter_expr, scope_id, lineno, receiver_unproven=True)


MUTATIONS = {
    'loop_proof_off': (
        'the whole clause reverted: a loop target has no proven origin',
        '_c22_loop_target_enumerates_temp_root', lambda *a, **k: False,
        tuple(sorted(RETIRED_BY_TEMP_ENUMERATION))),
    'outer_loop_wins': (
        'an inner loop that rebinds the name may borrow the outer proof',
        '_c22_loop_target_enumerates_temp_root', _loop_outer_wins,
        ('inner_loop_rebinds',)),
    'enumerator_leaf_blind': (
        'any pathlib method counts as an enumerator, not only the three leaves',
        '_c22_enumeration_is_over_temp_root', _enum_leaf_blind,
        ('iglob_declined', 'scandir_declined')),
    'absolute_pattern_allowed': (
        'an absolute pattern keeps the receiver proof it actually discards',
        '_c22_enumeration_is_over_temp_root', _enum_absolute_allowed,
        ('absolute_pattern', 'windows_absolute_pattern')),
    'dotdot_pattern_allowed': (
        'a `..` segment in the pattern no longer voids the proof',
        '_c22_enumeration_is_over_temp_root', _enum_dotdot_allowed,
        ('dotdot_pattern',)),
    'nonconstant_pattern_allowed': (
        'a pattern the engine cannot read counts as relative and harmless',
        '_c22_enumeration_is_over_temp_root', _enum_nonconstant_allowed,
        ('nonconstant_pattern',)),
    'receiver_proof_dropped': (
        'the enumerated directory no longer has to be a proven temp root',
        '_c22_enumeration_is_over_temp_root', _enum_receiver_dropped,
        ('receiver_is_parameter', 'receiver_is_request')),
}


def run_mutation(name):
    description, attribute, replacement, expected = MUTATIONS[name]
    tables = dict(RETIRED_BY_TEMP_ENUMERATION)
    tables.update(LOUD_BY_UNPROVEN_ENUMERATION)
    # The baseline is read BEFORE the weakening is installed. Reading it afterwards would compare the
    # mutated engine with itself and report every mutation as MISSED.
    before = {label: bool(rows_at(scan_module(tables[label][1]), tables[label][0]))
              for label in expected}
    original = getattr(T, attribute)
    setattr(T, attribute, replacement)
    try:
        moved = [label for label in expected
                 if bool(rows_at(scan_module(tables[label][1]), tables[label][0])) != before[label]]
    finally:
        setattr(T, attribute, original)
    return description, expected, moved


def check_mutations(only=None):
    failures = []
    print('\nTIER 4  mutations (one weakening per clause)')
    for name in sorted(MUTATIONS):
        if only and name != only:
            continue
        description, expected, moved = run_mutation(name)
        ok = sorted(moved) == sorted(expected)
        print(f'  {"CAUGHT" if ok else "MISSED"} {name:28s} moved={moved}')
        if not ok:
            failures.append(f'{name}: expected {sorted(expected)} moved {sorted(moved)}')
    return failures


def main():
    only = next((a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--mutate=')), None)
    if only and only not in MUTATIONS:
        print(f'unknown mutation {only}; known: {sorted(MUTATIONS)}')
        return 2
    failures = []
    if not only:
        failures += check_tables()
        failures += check_retirements()
        failures += check_inherited()
        failures += check_hiding_shapes()
        failures += check_declined()
    failures += check_mutations(only)
    print(f'\nretired={len(RETIRED_BY_TEMP_ENUMERATION)} '
          f'held_loud={len(LOUD_BY_UNPROVEN_ENUMERATION)} '
          f'inherited_quiet={len(INHERITED_QUIET)} '
          f'declined={len(DECLINED_COMPREHENSION)} '
          f'mutations={len(MUTATIONS) if not only else 1} failures={len(failures)}')
    for failure in failures:
        print(f'  FAILURE {failure}')
    print('VERDICT: ' + ('PASS' if not failures else 'FAIL'))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())