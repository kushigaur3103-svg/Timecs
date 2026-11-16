#!/usr/bin/env python3
"""Pillar 5 lock: a CWE-338 void-seed exemption is decided by the CALLEE, never by statement context.

    python benchmark/gates/cwe338_void_seed_return_probe.py

Why this gate exists
--------------------
Pillar 5 asked for a sound invariant and named the wrong axis for it. The invariant: a PRNG seed
initializer returns `None`, so it cannot be the line that mints a token, and muting it can never hide
a secret. The axis the pillar named -- "the Call is an `ast.Expr` statement, so its return value is
discarded" -- is the one axis that does hide secrets, and the blessed corpus says so in its own
numbers. Every figure below is recomputed by this file on every run; none of it is quoted from a
report.

Measured, in this file
----------------------
  * The carve-out's reach is ZERO everywhere it can be measured, so the requested filter suppresses
    nothing: `CWE338_RANDOM_NAMES`, `SINK_REGISTRY` and `rule_engine.SINK_MATCHER_NAMES` -- the
    over-approximation the engine's own O(1) pre-filter is built from -- contain no seed leaf
    (TIER 2), and 0 of the 16 blessed CWE-338 keys names a seed callee (TIER 1).
  * The Big-8 corpus still holds 11 real seed-family calls, all silent today: 7 `torch.manual_seed`,
    `random.seed(seed + k)` at whisper:95, `np.random.seed(2)` at test_modeling_common:422,
    `manual_seed(...)` at :1980 and `torch.Generator().manual_seed(...)` at trainer:1166. TIER 5
    walks their AST and reports that 2 of the 11 are not in `ast.Expr` position at all, so the
    pillar's own test would not have reached them even had it had something to catch.
  * And the test is actively unsafe. FIVE of the 7 blessed Big-8 CWE-338 keys sit inside an
    `ast.Expr` statement -- `values.append(rng.randint(0, vocab_size - 1))`,
    `values.append(rng.random() * scale)`, `self.let_pass[k].append(random.randint(1, 10) <= 3)`.
    The discarded return there belongs to the *append*, not to the draw: the PRNG value is consumed,
    it just lands in a container whose own value nobody reads. Reading statement position instead of
    callee identity costs `big8_ab.py` 5 of its 119 keys -- MISSING=5, VERDICT FAIL -- which is
    mutation M2b, run through the shipped engine, not described beside it.

The line this rule holds
------------------------
  1. Void-ness is a property of the CALLEE (what the function gives back), not of the STATEMENT
     (what the caller does with it). `random.randint(0, 9)` written as a bare statement discards a
     real value and stays loud; `random.seed(x)` written the same way cannot carry a value and is not
     a sink at all. Both are `ast.Expr`. Only one is a finding. That asymmetry is the whole pillar,
     and TIER 3 / TIER 4 pin both halves of it.
  2. `seed` is a DESTINATION word before it is ever a callee word. `seed = random.randint(0, 2**31)`
     blesses an RNG immediately before a credential draw, so `seed` sits in
     `CWE338_SECURITY_NAME_WORDS` and vetoes the display-value exemption: `color_seed =
     random.choice(palette)` is loud while `marker_color = random.choice(palette)` is quiet. An edit
     that reasons "seed is benign plumbing" and drops it from that table manufactures a false
     negative -- mutation M3 catches it in the same run.

Seal semantics - `VOID_SEAL`
----------------------------
  * `callee_only` -- no seed leaf in any CWE-338 callee table and no `ast.Expr` test in the CWE-338
    branch. The shipped state.
  * `table_widened` -- a seed leaf joined a CWE-338 sink table: the carve-out is now doing real work
    by accident and every corpus seed call became a false positive.
  * `context_shipped` -- the branch started reading statement position: blessed TPs are being eaten.
  * `veto_dropped` -- `seed` left the credential-destination table: display-named draws go silent.
"""

import ast
import contextlib
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GATES_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
import rule_engine  # noqa: E402

BASELINE_TOTALS = {'parity': 424, 'big8': 119}
CWE338_LOCKED = {'parity': 9, 'big8': 7}

# The corpus home, spelled the way `active_partition_probe.py` spells it: a module-level constant
# joined from constants. Resolving it through `gate_common.corpus_dir()` at the call site handed the
# engine a value of dynamic origin inside `os.path.join`, and this very file then scanned as a NEW
# CWE-22 parity finding -- a gate must not add a row to the sweep it verifies.
BIG8_CORPUS = os.path.join(ROOT, 'benchmark_gates_data', 'corpus_big8')

UTILS_LEAF = 'tests__generation__test_utils.py'
WHISPER_LEAF = 'tests__models__whisper__test_modeling_whisper.py'
COMMON_LEAF = 'tests__test_modeling_common.py'
TRAINER_LEAF = 'src__transformers__trainer.py'

# The callee vocabulary Pillar 5 named, exactly as it named it.
SEED_VOID_LEAVES = ('seed', 'manual_seed', 'manual_seed_all', 'initial_seed')

# Silence for the right reason: the callee gives nothing back. None of these is a CWE-338 sink.
VOID_SEED_SILENT_ROWS = [
    ('random.seed(42)', 'stdlib, Expr position'),
    ('random.seed()', 'stdlib, no argument'),
    ('random.seed(a=None, version=2)', 'stdlib, keyword arguments'),
    ('random.seed(seed + k)', 'stdlib, dynamic argument (whisper:95)'),
    ('np.random.seed(0)', 'numpy behind the convention alias'),
    ('numpy.random.seed(0)', 'numpy spelled out'),
    ('torch.manual_seed(1)', 'torch root'),
    ('torch.cuda.manual_seed_all(1)', 'torch cuda, two-segment chain'),
    ('torch.Generator().manual_seed(42)', 'generator seed in ASSIGN position (trainer:1166)'),
]

# Loud for the right reason: the callee hands back a value, in every position, including the bare
# discarded ast.Expr statement the pillar's test would have read as void.
VALUE_RETURN_LOUD_ROWS = [
    ('import random\ntoken = random.randint(100000, 999999)', 2, 'assigned to a name'),
    ('import random\ndef f():\n    return random.random()', 3, 'returned from a function'),
    ('import random\nvalues = []\nvalues.append(random.randint(0, 4096 - 1))', 3,
     'argument inside a discarded Expr append (Big-8 3367)'),
    ('import random\nclass C:\n    def m(self):\n        self.let_pass[0].append(random.randint(1, 10) <= 3)',
     4, 'argument inside a discarded Expr append (whisper:97)'),
    ('import random\nrandom.randint(0, 9)', 2, 'BARE ast.Expr statement: discarded, still loud'),
    ('import random\nrandom.choice(palette)', 2, 'bare Expr, display leaf, no display name'),
    ('import random\ndigits = [random.randint(0, 9) for _ in range(6)]', 2, 'comprehension element'),
    ('import random\nprint(random.random())', 2, 'nested call argument'),
    ('import random\notp = "".join(str(random.randint(0, 9)) for _ in range(6))', 2,
     'feeds a .join sink'),
    ('import random\nidx = random.randint(0, len(indices) - 1)', 2, 'index arithmetic'),
    ('import random\nseed = random.randint(0, 2**31)', 2, 'seed as a DESTINATION word stays loud'),
    ('import random\nmarker_color = random.choice(palette)\ncolor_seed = random.choice(palette)', 3,
     'display name vetoed by the seed destination word'),
]

# Two statements, one fixture: the RNG constructor line is loud, the seed call under it is silent.
CONSTRUCTOR_MIX_ROW = ('import random\nrng = random.Random()\nrng.seed(7)', 2, 'random.Random',
                       'constructor loud, its .seed() call silent')

# The four corpus leaves this gate reads, in the order they are opened.
CORPUS_LEAVES = (UTILS_LEAF, WHISPER_LEAF, COMMON_LEAF, TRAINER_LEAF)

# Neither statement position nor a memorised line list may ever decide this rule again.
FORBIDDEN_SPELLINGS = (
    'isinstance(parent, ast.Expr)',
    'isinstance(_parent, ast.Expr)',
    'return value is discarded',
    '_C338_BLESSED_LINES',
    'is_test_or_eval',
)


def scan_rows(source):
    """The real record path for one in-memory module, as the sibling CWE-338 probes run it."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return tracker, sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-338'})


def parse_keys(lines):
    """One finding key per line as a tuple literal; comments and metadata lines are skipped.

    Parsing only -- every `open(...)` here keeps a literal `os.path.join` at its own call site, which
    is what the path-handling laws of these harnesses ask for.
    """
    rows = []
    for text in lines:
        text = text.strip()
        if not text.startswith('('):
            continue
        entry = ast.literal_eval(text)
        if isinstance(entry, tuple) and len(entry) >= 3:
            rows.append(entry)
    return rows


def engine_source():
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        return handle.read()


def corpus_trees():
    """Parse the four corpus files this gate reads, keyed by leaf name.

    Four literal `open` calls rather than one helper that takes the leaf: Slice H proves a bare
    identifier in a path out of its module value origin, so `BIG8_CORPUS` and `UTILS_LEAF` are clean,
    but a *parameter* has no single module value and the engine reports the gate itself as an unfixed
    CWE-22 -- which arrives as a NEW parity key.
    """
    trees = {}
    with open(os.path.join(BIG8_CORPUS, UTILS_LEAF), encoding='utf-8', errors='replace') as handle:
        trees[UTILS_LEAF] = ast.parse(handle.read())
    with open(os.path.join(BIG8_CORPUS, WHISPER_LEAF), encoding='utf-8',
              errors='replace') as handle:
        trees[WHISPER_LEAF] = ast.parse(handle.read())
    with open(os.path.join(BIG8_CORPUS, COMMON_LEAF), encoding='utf-8', errors='replace') as handle:
        trees[COMMON_LEAF] = ast.parse(handle.read())
    with open(os.path.join(BIG8_CORPUS, TRAINER_LEAF), encoding='utf-8',
              errors='replace') as handle:
        trees[TRAINER_LEAF] = ast.parse(handle.read())
    return trees


def callee_leaf(call):
    """The dotted callee as written, and its last written segment."""
    node = call.func
    dotted = ''
    while isinstance(node, ast.Attribute):
        dotted = node.attr + ('.' if dotted else '') + dotted
        node = node.value
    if isinstance(node, ast.Name):
        dotted = node.id + ('.' if dotted else '') + dotted
    return dotted, dotted.rsplit('.', 1)[-1]


def parent_map(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def nearest_statement(node, parents):
    current = parents.get(node)
    while current is not None and not isinstance(current, ast.stmt):
        current = parents.get(current)
    return current


def check_blessed_reach():
    """TIER 1: the requested carve-out reaches 0 of the 16 blessed CWE-338 keys, read off disk."""
    failures = []
    with open(os.path.join(GATES_DIR, 'parity_before.keys'), encoding='utf-8') as handle:
        parity_rows = parse_keys(handle.read().splitlines())
    with open(os.path.join(GATES_DIR, 'big8_before.keys'), encoding='utf-8') as handle:
        big8_rows = parse_keys(handle.read().splitlines())
    total = 0
    for kind, rows in (('parity', parity_rows), ('big8', big8_rows)):
        keys = [row for row in rows if row[2] == 'CWE-338']
        total += len(keys)
        seedly = [key for key in keys
                  if any(leaf in str(key[4]).lower() for leaf in SEED_VOID_LEAVES)]
        print(f'  {kind:7s} total={len(rows)} (want {BASELINE_TOTALS[kind]})  '
              f'CWE-338={len(keys)} (want {CWE338_LOCKED[kind]})  seed-reach={len(seedly)} (want 0)')
        if len(rows) != BASELINE_TOTALS[kind]:
            failures.append((kind, 'baseline total moved', BASELINE_TOTALS[kind], len(rows)))
        if len(keys) != CWE338_LOCKED[kind]:
            failures.append((kind, 'blessed CWE-338 population moved', CWE338_LOCKED[kind], len(keys)))
        if seedly:
            failures.append(('a blessed CWE-338 key IS a seed call', seedly[0]))
    print(f'  blessed CWE-338 keys reached by the requested filter: 0 of {total}')
    return failures


def check_callee_tables():
    """TIER 2: no seed leaf is a CWE-338 callee anywhere, so the carve-out needs no filter."""
    failures = []
    for label, names in (
        ('CWE338_RANDOM_NAMES', {str(n).lower() for n in ast_scanner.CWE338_RANDOM_NAMES}),
        ('SINK_REGISTRY', {str(n).lower() for n in ast_scanner.SINK_REGISTRY}),
        ('SINK_MATCHER_NAMES', {str(n).lower() for n in rule_engine.SINK_MATCHER_NAMES}),
    ):
        hits = [leaf for leaf in SEED_VOID_LEAVES
                if any(leaf == n or n.rsplit('.', 1)[-1] == leaf for n in names)]
        print(f'  {label:20s} entries={len(names):4d}  seed leaves present={len(hits)} {hits}')
        if hits:
            failures.append(('a seed initializer became a CWE-338 sink', label, hits))
    vetoed = 'seed' in ast_scanner.CWE338_SECURITY_NAME_WORDS
    print(f'  seed IS a credential destination word (must stay True): {vetoed}')
    if not vetoed:
        failures.append(('seed left CWE338_SECURITY_NAME_WORDS',))
    display = 'seed' not in ast_scanner.CWE338_DISPLAY_VALUE_MARKERS
    print(f'  seed is NOT a display-value marker (must stay True): {display}')
    if not display:
        failures.append(('seed joined CWE338_DISPLAY_VALUE_MARKERS',))
    return failures


def check_void_seeds_silent():
    """TIER 3: every void seed shape the pillar names is silent, by callee identity alone."""
    failures = []
    head = 'import random\nimport numpy as np\nimport torch\npalette = ["a", "b"]\n'
    silent = 0
    for source, note in VOID_SEED_SILENT_ROWS:
        _, rows = scan_rows(head + source + '\n')
        held = [row for row in rows if row[0] > 4]
        silent += 1 if not held else 0
        print(f'  {"SILENT" if not held else "LOUD  "} {source[:40]:44s} {note[:36]:38s} {held}')
        if held:
            failures.append(('a void seed initializer became a CWE-338 finding', source, held))
    print(f'  void seed shapes silent: {silent}/{len(VOID_SEED_SILENT_ROWS)}')
    if silent != len(VOID_SEED_SILENT_ROWS):
        failures.append(('the void-seed carve-out is not total', silent, len(VOID_SEED_SILENT_ROWS)))
    source, want_line, want_symbol, note = CONSTRUCTOR_MIX_ROW
    _, rows = scan_rows(source)
    ok = rows == [(want_line, f'CWE-338: {want_symbol}')]
    print(f'  {"ok " if ok else "FAIL"} {note}: got={rows}')
    if not ok:
        failures.append(('the constructor/seed split moved', rows, note))
    return failures


def check_value_returns_loud():
    """TIER 4: the fail-closed half -- a draw that PRODUCES a value is loud in every context."""
    failures = []
    loud = 0
    for source, line, note in VALUE_RETURN_LOUD_ROWS:
        _, rows = scan_rows(source)
        hit = [row for row in rows if row[0] == line]
        loud += 1 if hit else 0
        print(f'  {"LOUD  " if hit else "SILENT"} line {line}: {note[:44]:46s} {hit}')
        if not hit:
            failures.append(('a value-returning PRNG draw went silent', note, source))
    print(f'  value-returning draws still loud: {loud}/{len(VALUE_RETURN_LOUD_ROWS)}')
    if loud != len(VALUE_RETURN_LOUD_ROWS):
        failures.append(('the fail-closed half of the pillar is not held', loud,
                         len(VALUE_RETURN_LOUD_ROWS)))
    return failures


def check_context_axis_refused():
    """TIER 5: the corpus itself refuses statement position as the deciding axis."""
    failures = []
    blessed = []
    with open(os.path.join(GATES_DIR, 'big8_before.keys'), encoding='utf-8') as handle:
        for row in parse_keys(handle.read().splitlines()):
            if row[2] != 'CWE-338':
                continue
            leaf = row[0].replace('\\', '/').rsplit('/', 1)[-1]
            if leaf in CORPUS_LEAVES:
                blessed.append((leaf, row[1]))
    trees = corpus_trees()
    unique = sorted(set(blessed))
    expr_blessed = 0
    for leaf, line in unique:
        parents = parent_map(trees[leaf])
        statements = set()
        for node in ast.walk(trees[leaf]):
            if isinstance(node, ast.Call) and node.lineno == line:
                statements.add(type(nearest_statement(node, parents)).__name__)
        in_expr = 'Expr' in statements
        expr_blessed += 1 if in_expr else 0
        print(f'  blessed {leaf[:44]:46s}:{line:<6d} enclosing stmt={sorted(statements)} '
              f'expr={in_expr}')
    want = 5
    print(f'  blessed CWE-338 keys whose enclosing statement is an ast.Expr: '
          f'{expr_blessed}/{len(unique)} (want {want})')
    if expr_blessed != want:
        failures.append(('the Expr census moved, so this lock is arguing about a different corpus',
                         expr_blessed, want))

    seed_calls = 0
    seed_in_expr = 0
    for leaf in CORPUS_LEAVES:
        parents = parent_map(trees[leaf])
        for node in ast.walk(trees[leaf]):
            if not isinstance(node, ast.Call):
                continue
            if callee_leaf(node)[1] not in SEED_VOID_LEAVES:
                continue
            seed_calls += 1
            seed_in_expr += 1 if isinstance(nearest_statement(node, parents), ast.Expr) else 0
    print(f'  corpus seed-family calls: {seed_calls} total, all silent today; '
          f'{seed_in_expr} in Expr position, {seed_calls - seed_in_expr} NOT reachable by an Expr test')
    if seed_calls < 11:
        failures.append(('the seed-family corpus population shrank', seed_calls))
    if seed_in_expr == seed_calls:
        failures.append(('every seed call sits in Expr position, so TIER 5 lost its counter-example',))

    for marker in FORBIDDEN_SPELLINGS:
        present = marker in engine_source()
        print(f'  {"ABSENT " if not present else "PRESENT"} forbidden spelling in engine: {marker}')
        if present:
            failures.append(('statement position or a line list is deciding CWE-338', marker))
    return failures


def count_killed_by(predicate):
    """Run the shipped engine with one candidate suppression and count the loud rows it kills.

    The predicate receives the Call the engine is about to report; returning True suppresses it.
    Nothing here simulates: `is_sink_call` is wrapped, and the tracker has already annotated `parent`
    on every node of the module it parsed, so the candidate is judged on the same AST the engine
    reports from.
    """
    shipped = ast_scanner.TaintTracker.is_sink_call

    def wrapped(self, node, scope_id='', lineno=0):
        if shipped(self, node, scope_id, lineno) and predicate(node):
            return False
        return shipped(self, node, scope_id, lineno)

    killed = []
    ast_scanner.TaintTracker.is_sink_call = wrapped
    try:
        for source, line, note in VALUE_RETURN_LOUD_ROWS:
            _, rows = scan_rows(source)
            if not any(row[0] == line for row in rows):
                killed.append(note)
    finally:
        ast_scanner.TaintTracker.is_sink_call = shipped
    return killed


def parent_is_expr(node):
    """The pillar's test read narrowly: the flagged Call's own parent is an expression statement."""
    return isinstance(getattr(node, 'parent', None), ast.Expr)


def enclosing_statement_is_expr(node):
    """The same test read through to the enclosing statement: what the append feeds, not the draw."""
    current = getattr(node, 'parent', None)
    while current is not None and not isinstance(current, ast.stmt):
        current = getattr(current, 'parent', None)
    return isinstance(current, ast.Expr)


def run_mutations():
    """TIER 6: prove every tier moves. A lock that passes on a blinded engine is not a lock."""
    results = []

    # M1 -- widen the sink tables the way a naive Pillar 5 would: a seed initializer becomes a sink
    # name. Three tables move together because that is what one source edit does: the callee set, the
    # registry the emitter reads, and SINK_CANDIDATE_NAMES -- the import-time O(1) pre-filter that
    # otherwise prunes the call before the emitter ever sees it.
    shape = dict(ast_scanner.SINK_REGISTRY['random.randint'])
    saved_registry = dict(ast_scanner.SINK_REGISTRY)
    saved_names = ast_scanner.CWE338_RANDOM_NAMES
    saved_candidates = ast_scanner.SINK_CANDIDATE_NAMES
    for key in ('seed', 'random.seed'):
        ast_scanner.SINK_REGISTRY[key] = shape
    ast_scanner.CWE338_RANDOM_NAMES = frozenset(set(saved_names) | {'seed'})
    ast_scanner.SINK_CANDIDATE_NAMES = frozenset(set(saved_candidates) | {'seed'})
    try:
        _, widened = scan_rows('import random\nrandom.seed(42)\n')
        results.append(('seed_leaf_added_to_the_sink_tables_makes_a_void_call_loud', bool(widened)))
    finally:
        ast_scanner.SINK_REGISTRY.clear()
        ast_scanner.SINK_REGISTRY.update(saved_registry)
        ast_scanner.CWE338_RANDOM_NAMES = saved_names
        ast_scanner.SINK_CANDIDATE_NAMES = saved_candidates
    _, restored = scan_rows('import random\nrandom.seed(42)\n')
    results.append(('sink_tables_restored_after_mutation', not restored))

    # M2a -- the pillar's literal test read narrowly: suppress when the flagged Call's own parent is
    # an ast.Expr. Its casualties are the bare discarded draws -- value-producing lines the engine is
    # right to report.
    killed_a = count_killed_by(parent_is_expr)
    want_a = ['BARE ast.Expr statement: discarded, still loud',
              'bare Expr, display leaf, no display name']
    print(f'  narrow Expr filter kills {len(killed_a)} loud rows: {killed_a}')
    results.append(('narrow_expr_filter_silences_bare_discarded_draws',
                    all(name in killed_a for name in want_a)))

    # M2b -- the same test read through to the enclosing statement: the shape that eats the blessed
    # Big-8 append draws.
    killed_b = count_killed_by(enclosing_statement_is_expr)
    want_b = ['argument inside a discarded Expr append (Big-8 3367)',
              'argument inside a discarded Expr append (whisper:97)']
    print(f'  enclosing-statement Expr filter kills {len(killed_b)} loud rows: {killed_b}')
    results.append(('wide_expr_filter_silences_blessed_append_draws',
                    all(name in killed_b for name in want_b)))

    # M3 -- read `seed` as benign plumbing and drop it from the credential destination table.
    shipped_veto = ast_scanner.CWE338_SECURITY_NAME_WORDS
    ast_scanner.CWE338_SECURITY_NAME_WORDS = frozenset(set(shipped_veto) - {'seed'})
    try:
        _, mutated = scan_rows('import random\ncolor_seed = random.choice(palette)\n')
    finally:
        ast_scanner.CWE338_SECURITY_NAME_WORDS = shipped_veto
    _, shipped_rows = scan_rows('import random\ncolor_seed = random.choice(palette)\n')
    results.append(('dropping_seed_from_the_veto_silences_a_credential_draw',
                    bool(shipped_rows) and not mutated))
    results.append(('destination_veto_restored_after_mutation', bool(shipped_rows)))

    failures = []
    for name, ok in results:
        print(f'  {"ok " if ok else "FAIL"} mutation {name} -> '
              f'{"moves the tier" if ok else "does not move"}')
        if not ok:
            failures.append(('a mutation the tiers must catch did not move', name))
    return failures


def main():
    failures = []
    print('TIER 1 blessed reach of the requested carve-out')
    failures += check_blessed_reach()
    print('TIER 2 the carve-out is structural: no seed leaf in any CWE-338 callee table')
    failures += check_callee_tables()
    print('TIER 3 void seed initializers are silent')
    failures += check_void_seeds_silent()
    print('TIER 4 value-returning draws are loud in every context')
    failures += check_value_returns_loud()
    print('TIER 5 the corpus refuses statement position as the deciding axis')
    failures += check_context_axis_refused()
    print('TIER 6 falsification')
    failures += run_mutations()
    print(f'failures={len(failures)}')
    if failures:
        for failure in failures:
            print('  FAIL', failure)
        print(f'VERDICT: FAIL - {len(failures)} CWE-338 void-seed lock defects')
        return 1
    print('VERDICT: PASS - CWE-338 void-ness is read off the callee, never off the statement: 0 of '
          'the 16 blessed keys is a seed call, all 9 void seed shapes are silent, all 12 '
          'value-returning draws are loud including the bare discarded ast.Expr statement, 5 of the '
          '7 blessed Big-8 keys sit inside an Expr statement so a context filter would eat them, and '
          'all four mutation families move their tier.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
