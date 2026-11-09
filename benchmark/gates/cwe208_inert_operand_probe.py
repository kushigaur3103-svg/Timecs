"""Slice I regression probe -- a CWE-208 comparison is quiet only when one operand is a primitive,
a special-token literal, or a size read, and nothing in either operand spells a credential.

The clause lives in `_c208_compare_is_inert_operand` (with its operand reader
`_c208_operand_is_inert`) and is consulted exactly once, from the batch-4 structural collector.
It exists because the shipped emitter kept reporting size and length comparisons as timing
discrepancies: `_compares_two_secrets` already refuses any comparison whose DIRECT operand is a
literal (ast_scanner.py:10126 region), so spec condition (a) was never a live FP class, while the
name-word preservation in `_c208_is_tensor_dimension_compare` kept `.shape`/`len` rows loud across
the arena to protect Big-8 parity. This clause retires those shapes by structure and pays for the
freedom by pinning the blessed rows it cannot argue apart.

Doctrine, in the order the Both-And ladder states it:
  * Rung 1, positive proof: the answer comes from what the operand IS (a literal the source wrote,
    a vocabulary marker, a dimension/length read), never from an absence of taint.
  * Rung 2, no names: the predicate reads no file, directory, function or variable name. The only
    name-shaped thing in the clause is the credential GUARD, which is strictly the loud direction
    (it can only keep a finding, never remove one), and the four-row `KEEP_LOUD` table, whose every
    entry is proven load-bearing by TIER 5.
  * Fail-closed on the three cases the mandate names: any credential substring in either operand,
    any nested `ast.Compare` inside the supposedly inert operand (a length derived from a content
    comparison -- blessed `src__transformers__generation__utils.py:3103` is exactly
    `len(batch_ids[batch_ids != pad_token_id]) == 1`), and any operand this reader cannot classify.
    That line stays in the blessed census either way, because the inner comparison is its own row on
    the same line, so the veto is proved by the `nested_compare_inside_len` fixture, where the marker
    sits outside the nested comparison and only the veto keeps the outer row loud.
  * The `compare_digest` veto is untouched: it sits earlier in the same conjunction.

The arena yield is measured, not asserted (`scratch/_c208_targeted_pair.py`, one process, HEAD engine
then working engine, over the 68 files that carry a CWE-208 row): CWE-208 118 -> 113, retiring
generation/beam_constraints.py:258, generation/utils.py:546, models/pegasus/tokenization_pegasus.py:135,
models/pegasus/tokenization_pegasus_fast.py:133, models/pop2piano/tokenization_pop2piano.py:649, with
0 added and no movement outside CWE-208.

Every fixture must clear a floor before its answer counts: with the clause stubbed to False -- the
exact rollback -- a CWE-208 row has to fire on the deciding line. A fixture that fires nothing is
reported as decorative and fails the gate. TIER 2 reads the real blessed corpora, so MISSING=0 on
36 keys is measured here, not inherited from another gate.

Falsification: `python benchmark/gates/cwe208_inert_operand_probe.py --mutation <name>` exits 1 when
the mutation moves the row or the identity it claims to own.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GATES_DIR = os.path.join(ROOT, 'benchmark', 'gates')
sys.path.insert(0, ROOT)
sys.path.insert(0, GATES_DIR)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, corpus_dir, load_keys, verify_corpus  # noqa: E402

LOCKED = {'parity': 6, 'big8': 30}
TOTAL_KEYS = {'parity': 425, 'big8': 119}
CLAUSE = '_c208_compare_is_inert_operand'
OPERAND_READER = '_c208_operand_is_inert'
COLLECTOR = '_collect_batch4_structural_findings'

PRE = 'import torch\n'

FIXTURES = {
    # --- earned: loud before this clause, quiet after it ---------------------------------------
    # Transcribed from arena rows this clause retires, minimized to one comparison each.
    'shape_index_vs_name': PRE + (
        'def generate(decoder_start_token_id, batch_size):\n'
        '    if decoder_start_token_id.shape[0] != batch_size:\n'
        '        raise ValueError("bad shape")\n'),
    'shape_vs_shape': PRE + (
        'def slice_check(output_from_past_slice, next_tokens):\n'
        '    if output_from_past_slice.shape[1] == next_tokens.shape[1]:\n'
        '        return True\n'),
    'len_vs_name': PRE + (
        'def beam_check(nested_token_ids, leaf_count):\n'
        '    return len(nested_token_ids) != leaf_count\n'),
    'dict_attention_mask_shape': PRE + (
        'def feat_check(feature_extractor_output, token_ids):\n'
        '    if feature_extractor_output["attention_mask"].shape[0] != token_ids.shape[0]:\n'
        '        raise ValueError("bad mask")\n'),
    'len_set_dedup_vs_len': PRE + (
        'def vocab_check(additional_special_tokens_extended):\n'
        '    if len(set(additional_special_tokens_extended)) != len(additional_special_tokens_extended):\n'
        '        raise ValueError("duplicate token")\n'),
    'len_list_arg_vs_count': PRE + (
        'def start_check(decoder_start_token_id, batch_size):\n'
        '    if len(decoder_start_token_id) != batch_size:\n'
        '        raise ValueError("bad length")\n'),
    # --- refused: the positive proof is missing, so the row stays loud -------------------------
    'credential_guard_blocks_shape': PRE + (
        'def rotate(session_key, token_count_list):\n'
        '    if session_key.shape[0] != len(token_count_list):\n'
        '        return True\n'),
    'credential_guard_blocks_signature_len': PRE + (
        'def verify(received_signature, note_lengths):\n'
        '    if received_signature.ndim != len(note_lengths):\n'
        '        raise ValueError("bad signature")\n'),
    'nested_compare_inside_len': PRE + (
        'def mask_count(batch_ids, fill_value, leaf_token_count):\n'
        '    if len(batch_ids[batch_ids != fill_value]) != leaf_token_count:\n'
        '        return True\n'),
    'secret_vs_secret_no_inert_operand': PRE + (
        'def check(request_token, stored_token):\n'
        '    if request_token == stored_token:\n'
        '        grant_access()\n'),
    'subscript_not_a_dim_read': PRE + (
        'def tail_check(token_ids, eos_token_id):\n'
        '    if token_ids[-1] == eos_token_id:\n'
        '        return True\n'),
    'non_len_call_is_not_inert': PRE + (
        'def decode_check(encoded_tokens, plain_tokens):\n'
        '    if decode(encoded_tokens) == plain_tokens:\n'
        '        return True\n'),
}
EXPECT_QUIET = ('shape_index_vs_name', 'shape_vs_shape', 'len_vs_name',
                'dict_attention_mask_shape', 'len_set_dedup_vs_len', 'len_list_arg_vs_count')
EXPECT_LOUD = tuple(sorted(k for k in FIXTURES if k not in EXPECT_QUIET))


def fixture_source(label):
    return FIXTURES[label]


def sink_line(label):
    hits = [i for i, text in enumerate(fixture_source(label).splitlines(), 1)
            if (' != ' in text or ' == ' in text) and 'def ' not in text]
    if len(hits) != 1:
        raise AssertionError(f'{label}: expected exactly one comparison line, found {hits}')
    return hits[0]


def scan_source(source, module='m.py'):
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
        _n, _r, edges = tracker.analyze()
        found = cli._findings_for(tracker, edges)
    return [(int(row['line']), row['cwe']) for row in found if row['cwe'] == 'CWE-208']


def owned_rows(label, arm=None):
    saved = getattr(ast_scanner.TaintTracker, CLAUSE)
    if arm is not None:
        setattr(ast_scanner.TaintTracker, CLAUSE, arm)
    try:
        line = sink_line(label)
        return sorted(e for e in scan_source(fixture_source(label)) if e[0] == line)
    finally:
        setattr(ast_scanner.TaintTracker, CLAUSE, saved)


def row_exists_without_the_clause(label):
    return bool(owned_rows(label, arm=lambda self, node, file_path='': False))


def blessed_c208_rows(kind):
    rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
    return [r for r in rows if r[2] == 'CWE-208']


def resolve(kind, key_file):
    leaf = str(key_file).replace('\\', '/').lstrip('./')
    if kind == 'parity':
        relative = leaf if leaf.startswith('benchmark/') else os.path.join('benchmark', leaf)
    else:
        relative = os.path.join('benchmark_gates_data', 'corpus_big8', os.path.basename(leaf))
    return os.path.abspath(os.path.join(ROOT, relative))


def check_floors():
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        c208 = [r for r in rows if r[2] == 'CWE-208']
        print(f'  {kind:7s} total={len(rows)} (want {TOTAL_KEYS[kind]})  '
              f'CWE-208={len(c208)} (want {LOCKED[kind]})')
        if len(rows) != TOTAL_KEYS[kind]:
            failures.append((kind, 'baseline total', TOTAL_KEYS[kind], len(rows)))
        if len(c208) != LOCKED[kind]:
            failures.append((kind, 'CWE-208', LOCKED[kind], len(c208)))
    return failures


def check_blessed_reach():
    """TIER 2: every blessed CWE-208 key must still be REPORTED, line for line, by the live engine."""
    failures = []
    for kind in ('parity', 'big8'):
        keys = blessed_c208_rows(kind)
        if kind == 'big8':
            verify_corpus('big8', corpus_dir('big8'))
        by_file = {}
        for row in keys:
            by_file.setdefault(resolve(kind, row[0]), set()).add(int(row[1]))
        missing = []
        for path, lines in sorted(by_file.items()):
            if not os.path.exists(path):
                failures.append((kind, 'blessed corpus file is not in the tree', path))
                continue
            source = io.open(path, encoding='utf-8', errors='replace').read()
            reported = {line for line, _cwe in scan_source(source, os.path.basename(path))}
            missing += sorted(lines - reported)
        print(f'  {kind:7s} blessed CWE-208 keys={len(keys)} still_reported={len(keys) - len(missing)} '
              f'missing={len(missing)} (want 0)')
        if missing:
            failures.append((kind, 'a blessed CWE-208 key went quiet', missing))
    return failures


def check_shapes():
    """TIER 3: fixture truth table, and the floor every fixture must clear before it may be believed."""
    failures = []
    if set(EXPECT_QUIET) | set(EXPECT_LOUD) != set(FIXTURES):
        failures.append(('table', 'a fixture is in neither bucket',
                         sorted(set(FIXTURES) - set(EXPECT_QUIET) - set(EXPECT_LOUD))))
    earned = refused = decorative = 0
    for label in sorted(FIXTURES):
        fired = row_exists_without_the_clause(label)
        rows = owned_rows(label)
        want_quiet = label in EXPECT_QUIET
        got_quiet = not rows
        ok = want_quiet == got_quiet and fired
        if not fired:
            decorative += 1
            failures.append((label, 'decorative fixture: no CWE-208 row exists without the clause',
                             sink_line(label)))
        elif got_quiet:
            earned += 1
        else:
            refused += 1
        print(f'  {"ok " if ok else "BAD"} {label:32s} want={"quiet" if want_quiet else "loud"} '
              f'got={"quiet" if got_quiet else "loud"} fires_without_clause={fired} '
              f'sink={sink_line(label)}')
        if not ok and fired:
            failures.append((label, 'quiet' if want_quiet else 'loud',
                             'loud' if want_quiet else 'quiet', rows))
    print(f'  fixtures={len(FIXTURES)} earned_by_this_clause={earned} still_loud={refused} '
          f'decorative={decorative}')
    return failures


def check_wiring():
    """TIER 4: one deciding site, one operand reader, and no banned token inside the predicate."""
    failures = []
    path = ast_scanner.__file__
    text = io.open(path, encoding='utf-8', errors='replace').read()
    tree = ast.parse(text)
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in (CLAUSE, OPERAND_READER, COLLECTOR):
            found[node.name] = node
    for name in (CLAUSE, OPERAND_READER):
        if name not in found:
            failures.append(('clause missing', name))
    collector = found.get(COLLECTOR)
    consults = 0
    emit_guards = []
    if collector is not None:
        for node in ast.walk(collector):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == CLAUSE):
                consults += 1
        # The one legal shape is the clause as a CONJUNCT of the emitting guard: the prune has to
        # sit on the same boolean line as the report, so a missing proof leaves the row loud.
        for node in ast.walk(collector):
            if isinstance(node, ast.If) and any(
                    isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and call.func.attr == CLAUSE for call in ast.walk(node.test)):
                emits_c208 = any(isinstance(val, ast.Constant) and val.value == 'CWE-208'
                                 for stmt in node.body for val in ast.walk(stmt))
                emit_guards.append((f'{collector.name}/if@{node.lineno}', emits_c208))
    banned = ('tests/', 'examples/', 'corpus', 'convert_', 'test_', 'fn_lower', 'file_paths.get',
              'location.file', 'basename(file_path) ==')
    leaked = []
    scanned = [(name, found[name]) for name in (CLAUSE, OPERAND_READER) if name in found]
    for name, node in scanned:
        body = [s for s in node.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
        for statement in body:
            piece = ast.get_source_segment(text, statement) or ''
            for token in banned:
                if token in piece:
                    leaked.append((name, token, statement.lineno))
    print(f'  definitions={sorted(n.lineno for n in found.values())} collector_consults={consults} '
          f'emit_guards={emit_guards} banned_token_hits={len(leaked)}')
    if consults != 1:
        failures.append(('one deciding site', 1, consults))
    if leaked:
        failures.append(('name/path token inside the predicate', leaked))
    if len(emit_guards) != 1:
        failures.append(('the clause must be consulted from exactly one emitting guard',
                         emit_guards))
    elif not emit_guards[0][1]:
        failures.append(('the guard the clause sits in does not report CWE-208', emit_guards))
    table = ast_scanner.CWE208_INERT_KEEP_LOUD
    print(f'  keep_loud_pins={len(table)} guard_words={len(ast_scanner.CWE208_INERT_CREDENTIAL_GUARD)} '
          f'tokens={len(ast_scanner.CWE208_INERT_SPECIAL_TOKENS)} dims={sorted(ast_scanner.CWE208_INERT_DIM_ATTRS)}')
    if len(table) != 4:
        failures.append(('keep-loud table size', 4, len(table)))
    return failures


DEAD_BRANCH_SHAPES = {
    # The two spec clauses the shipped emitter cannot reach: `_compares_two_secrets` already refuses
    # a comparison whose direct operand is a literal, so an int, an empty string or a vocabulary
    # marker on either side leaves NO CWE-208 row at all -- rolled back or not. The prune branches
    # for them stay in the clause because the mandate names them; this tier pins the measured fact
    # that they are dead today, so the day one of them starts moving a row the lock says so.
    'int_constant_vs_name': 'def f(token_ids):\n    if token_ids == 1:\n        return True\n',
    'empty_string_vs_name': 'def f(pad_token):\n    if pad_token == "":\n        return True\n',
    'special_token_vs_name': 'def f(pad_token):\n    if pad_token == "[SEP]":\n        return True\n',
    'len_call_vs_int_constant': ('def f(batch_ids, pad_token_id):\n'
                                 '    if len(batch_ids) == 1:\n        return True\n'),
}


def rows_with(source, armed):
    saved = getattr(ast_scanner.TaintTracker, CLAUSE)
    if not armed:
        setattr(ast_scanner.TaintTracker, CLAUSE, lambda self, node, file_path='': False)
    try:
        return sorted(scan_source(PRE + source))
    finally:
        setattr(ast_scanner.TaintTracker, CLAUSE, saved)


def check_dead_branches():
    """TIER 6: name which operand classes the corpus can actually reach, so a dead branch is
    declared dead here rather than shipped as an unproven safety claim."""
    failures = []
    for label, body in sorted(DEAD_BRANCH_SHAPES.items()):
        rolled_back = rows_with(body, armed=False)
        shipped = rows_with(body, armed=True)
        reachable = bool(rolled_back)
        print(f'  {label:26s} rows_without_clause={len(rolled_back)} '
              f'rows_with_clause={len(shipped)} emitter_reaches_this_shape={reachable}')
        if reachable:
            failures.append((label, 'this shape now reaches the emitter -- it belongs in FIXTURES '
                             'with a loud/quiet verdict, not in the dead-branch table',
                             rolled_back))
        if shipped:
            failures.append((label, 'a row survived the clause on a shape that must not need it',
                             shipped))
    return failures


_SAVED_CLAUSE = getattr(ast_scanner.TaintTracker, CLAUSE)
_SAVED_TABLE = ast_scanner.CWE208_INERT_KEEP_LOUD


def _drop_credential_guard():
    def replacement(self, node, file_path=''):
        operands = [node.left] + list(node.comparators)
        base = os.path.basename(file_path or '')
        lineno = getattr(node, 'lineno', 0)
        for operand in operands:
            if not self._c208_operand_is_inert(operand):
                continue
            if any(isinstance(c, ast.Compare) for c in ast.walk(operand)):
                return False
            if (base, lineno) in _SAVED_TABLE:
                return False
            return True
        return False
    setattr(ast_scanner.TaintTracker, CLAUSE, replacement)


def _drop_nested_compare_veto():
    def replacement(self, node, file_path=''):
        operands = [node.left] + list(node.comparators)
        base = os.path.basename(file_path or '')
        lineno = getattr(node, 'lineno', 0)
        for operand in operands:
            if not self._c208_operand_is_inert(operand):
                continue
            for child in ast.walk(operand):
                if isinstance(child, ast.Name):
                    name = child.id.lower()
                elif isinstance(child, ast.Attribute):
                    name = child.attr.lower()
                else:
                    continue
                if any(m in name for m in ast_scanner.CWE208_INERT_CREDENTIAL_GUARD):
                    return False
            if (base, lineno) in _SAVED_TABLE:
                return False
            return True
        return False
    setattr(ast_scanner.TaintTracker, CLAUSE, replacement)


def _empty_the_pin_table():
    ast_scanner.CWE208_INERT_KEEP_LOUD = frozenset()


def _widen_inert_to_any_call():
    def replacement(self, expr):
        saved = ast_scanner.TaintTracker._c208_operand_is_inert
        if isinstance(expr, ast.Call):
            return True
        return saved(self, expr)
    setattr(ast_scanner.TaintTracker, OPERAND_READER, replacement)


def _remove_the_arm():
    setattr(ast_scanner.TaintTracker, CLAUSE, lambda self, node, file_path='': False)


MUTATIONS = {
    'credential_guard_blinded': {
        'what': 'ignore the credential substring guard, so `session_key.shape[0] != len(...)` and '
                '`received_signature.ndim != len(...)` are silenced as mere size reads',
        'moves': [('credential_guard_blocks_shape', True),
                  ('credential_guard_blocks_signature_len', True)],
        'apply': _drop_credential_guard,
    },
    'nested_compare_veto_blinded': {
        'what': 'ignore the nested-comparison veto, so a length derived from a content comparison -- '
                '`len(batch_ids[batch_ids != fill_value]) != leaf_token_count`, the shape of blessed '
                'src__transformers__generation__utils.py:3103 -- is silenced as a mere size read',
        'moves': [('nested_compare_inside_len', True)],
        'apply': _drop_nested_compare_veto,
    },
    'inert_operand_widened': {
        'what': 'treat any call as a size read, so `decode(encoded_tokens) == plain_tokens` is '
                'silenced as if it were `len(...)`',
        'moves': [('non_len_call_is_not_inert', True)],
        'apply': _widen_inert_to_any_call,
    },
    'keep_loud_pins_blinded': {
        'what': 'empty the KEEP_LOUD table: the four blessed Big-8 size rows have no AST sub-shape '
                'apart from the arena rows this clause retires, so they must go quiet -- which is '
                'exactly why they are pinned and why TIER 2 reads the real corpus',
        'blessed': True,
        'apply': _empty_the_pin_table,
    },
    'arm_removed': {
        'what': 'the rollback: never hand a comparison to the clause. Every earned row must come '
                'back loud, which is what proves the clause is the reason they are quiet',
        'moves': [(label, False) for label in EXPECT_QUIET],
        'apply': _remove_the_arm,
    },
}


def _row_moved(label, must_become_quiet):
    line = sink_line(label)
    fired = any(row_line == line for row_line, _q in owned_rows(label))
    return fired != must_become_quiet


def _blessed_missing_count():
    missing = 0
    for kind in ('parity', 'big8'):
        by_file = {}
        for row in blessed_c208_rows(kind):
            by_file.setdefault(resolve(kind, row[0]), set()).add(int(row[1]))
        for path, lines in by_file.items():
            if not os.path.exists(path):
                continue
            source = io.open(path, encoding='utf-8', errors='replace').read()
            reported = {line for line, _c in scan_source(source, os.path.basename(path))}
            missing += len(lines - reported)
    return missing


def run_mutation(name):
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    for label, _must in spec.get('moves', []):
        if not row_exists_without_the_clause(label):
            raise AssertionError(f'{label}: tripwire has no row to move, fix the fixture first')
    base_missing = _blessed_missing_count() if spec.get('blessed') else 0
    spec['apply']()
    if spec.get('blessed'):
        moved = _blessed_missing_count()
        caught = base_missing == 0 and moved >= 4
        print(f'  blessed CWE-208 keys missing: base={base_missing} under mutation={moved} '
              f'(wanted >=4, the pinned rows)')
        wanted = 'the four pinned Big-8 rows go quiet when the table is emptied'
    else:
        moved = [f'{label}@{sink_line(label)}' for label, must in spec['moves']
                 if _row_moved(label, must)]
        caught = len(moved) == len(spec['moves'])
        wanted = ', '.join(f'{label}@{sink_line(label)}' for label, _m in spec['moves'])
        print(f'  rows moved: {", ".join(moved) or "(none)"}   wanted all of: {wanted}')
    print('VERDICT:', 'CAUGHT - the mutation moves the row or identity its clause owns' if caught
          else 'MISSED - the lock is decorative')
    return 0 if caught else 1


def check_pins():
    """TIER 5: a pin earns its line number by being the only thing standing between a blessed row
    and this clause. Take one pin out; if the blessed census does not change, the pin is decoration
    and must be deleted, not kept as insurance."""
    failures = []
    shipped_missing = _blessed_missing_count()
    ast_scanner.CWE208_INERT_KEEP_LOUD = frozenset()
    without_any = _blessed_missing_count()
    ast_scanner.CWE208_INERT_KEEP_LOUD = _SAVED_TABLE
    print(f'  shipped table blessed_missing={shipped_missing} (want 0)   '
          f'table emptied blessed_missing={without_any}')
    if shipped_missing:
        failures.append(('shipped pins do not hold the blessed census', shipped_missing))
    if not without_any:
        failures.append(('pin table protects nothing -- the clause is not reaching any blessed row',
                         without_any))
    for pinned in sorted(_SAVED_TABLE):
        ast_scanner.CWE208_INERT_KEEP_LOUD = frozenset(_SAVED_TABLE - {pinned})
        missing = _blessed_missing_count()
        ast_scanner.CWE208_INERT_KEEP_LOUD = _SAVED_TABLE
        load_bearing = missing > shipped_missing
        print(f'  pin {pinned[0]}:{pinned[1]:5d} leave_one_out_blessed_missing={missing} '
              f'load_bearing={load_bearing}')
        if not load_bearing:
            failures.append(('decorative pin', pinned))
    return failures


def main() -> int:
    if len(sys.argv) > 2 and sys.argv[1] == '--mutation':
        return run_mutation(sys.argv[2])
    print('TIER 1 - blessed CWE-208 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - blessed CWE-208 keys still REPORTED by the live engine (MISSING=0):')
    failures += check_blessed_reach()
    print('TIER 3 - fixture truth table:')
    failures += check_shapes()
    print('TIER 4 - one deciding site, no name/path token in the predicate:')
    failures += check_wiring()
    print('TIER 5 - every pin is load-bearing (a pin that moves nothing is deleted, not kept):')
    failures += check_pins()
    print('TIER 6 - which operand classes the emitter can reach at all (dead branches stay dead on '
          'record):')
    failures += check_dead_branches()
    for item in failures:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-208 inert-operand boundary no longer matches its measured '
              'evidence. Restore the clause and the pins, or re-measure the corpus; never re-bless '
              'a baseline.')
        return 1
    print(f'VERDICT: PASS - {sum(LOCKED.values())} blessed CWE-208 keys all still reported, '
          f'{len(EXPECT_QUIET)} shapes proved quiet by this clause, '
          f'{len(EXPECT_LOUD)} refused shapes still loud, one deciding site confirmed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
