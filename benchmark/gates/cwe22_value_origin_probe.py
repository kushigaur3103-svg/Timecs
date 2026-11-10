"""Slice H regression probe -- a bare-identifier CWE-22 sink is quiet only when every write of that
name in the file hands over a value the program created itself.

The clause lives in `_c22_value_is_proven_module_origin`, consulted from the one Slice G funnel at
`ast_scanner.py:9648` (TIER 4 below reads that line off the shipped module rather than trusting this
sentence), and it exists because Slice G's two domains each require a shape these sinks do not have:
domain 1 needs a declared parameter and an in-module call site, domain 2 needs a `self`/`cls` field. A
function-local `state = tempfile.mkdtemp()` plus `open(state)` has neither, so it stayed loud while its
value was provably the program's own.

Doctrine this probe defends, in the order Rule 15.5 states it:
  * Rung 1, positive proof: the answer comes from `_c22_value_is_proven_path_origin` over EVERY value
    the owning scope binds -- a tempfile root, a proven `huggingface_hub` cache resolver, or text that
    names the whole location. No branch of this clause reads an absence.
  * Rung 2, no names: nothing in the clause reads a file, directory, function or variable name. The
    two facts it does read are the set of targets the engine's own binding table keys, and the set of
    names appearing in a `global`/`nonlocal` statement, which is a statement type, not an identifier
    pattern. TIER 4 slices the clause's AST and fails on the banned tokens.
  * Fail-closed on exactly the three cases the mandate names: a name whose only binding is a parameter
    (an external binding, domain 1's question), a name any function re-binds through `global`/
    `nonlocal` (the binding table keys that write under the function, so a module-scope lookup would
    not see it), and a name with any unproven write among several.
  * The resolver vocabulary is NOT widened here. `cached_file` and `get_file_from_repo` are absent
    from `CWE22_HUB_CACHE_RESOLVERS` on purpose: they reach these sinks through a relative re-export
    (`from ..utils import cached_file`), and naming them by leaf would rest a path proof on "a bare
    name could be anybody's function" -- the same reason the table already insists on the qualified
    `tempfile.` and `huggingface_hub.` spellings. Following that re-export chain is a multi-hop
    cross-module trace, which Rule 15.3 forbids, so a resolver-bound sink stays loud unless the module
    imports the resolver from `huggingface_hub` itself.

Numbers below are measured on this tree, not asserted. Every fixture must clear a floor before its
answer counts: with the clause stubbed to False -- the exact rollback -- a CWE-22 row has to fire on
the deciding line. A fixture that fires nothing is reported as decorative and fails the gate, because
a blinded veto could otherwise "catch" on a row that never existed. The blessed census reads the
engine's own funnel through a wrapper, so `asked` cannot drift from what the cascade actually asked.

Round 3 moved the emit side, not this clause, and it still cost this table ten rows.
`_c22_open_sink_owes_proven_taint` now asks a CWE-22 path sink for a resolved untrusted origin before
any emitter will report it, and it asks that question AFTER this funnel has declined: a name this
clause refuses is no longer automatically a finding, it is a finding only while some argument of the
sink call carries a value the operator or the network controls. Attribution
(`scratch/_c22_r3_sliceh_attrib.py`, which only feeds each fixture to `scratch/_c22_r3_engines.py` so
HEAD's snapshot and the live engine answer in separate processes) splits the ten failures along exactly
that seam. Five refused shapes were HEAD-reported and are live-quiet -- `name_is_method_parameter@8`,
`name_never_written_here@3`, `resolver_leaf_not_hub@5`, `subscript_not_bare_ident@9`,
`tmpdir_direct_open@8` -- and those five are a genuine supersession: the mandate retired "cannot prove
it safe, therefore report", and none of the five has an origin anywhere near its sink. The five earned
shapes are quiet under BOTH arms, so no row was lost there at all; what broke is only the floor, which
cannot see a row the owed rule refuses to emit whatever this clause answers.

Nothing here re-numbers a row, because nothing here should move: the repair is to re-spell the ten
fixtures so the walk resolves an origin on their sink call, which is what makes the row live again and
therefore decidable by this clause once more (`scratch/_c22_r3_sliceh_grid.py` measured every spelling,
`scratch/_c22_r3_sliceh_probe.py` prints, per record, both the funnel's answer and the owed rule's).
Two shapes are used, and which one a fixture may use is decided by what its label claims:
  * the refused fixtures take the origin on the PATH argument, exactly as the mandate phrases them:
    `request.args[...]` in the joined leaf or the root (`join_leaf_from_request`, `join_root_from_request`,
    `second_write_from_request`), a `global`/`nonlocal` re-bind off the request (the three rebind rows),
    and for the remaining five an inline `sys.argv` read, because the walk does not resolve the two
    spellings that would be more literal here -- it follows a plain in-file `helper(argv)` call but not
    a method one (`self.test(argv)`, `Holder().test(argv)`), and it will not step into a list element
    (`roots = [sys.argv[1]]` then `open(roots[0])`). Both were measured BAD in the grid and are reported
    upward as the walk's remaining gaps, not quietly routed around.
  * the earned fixtures have to keep the path name provably program-created, so they cannot also take
    the operator's value in that same name: `_c22_bound_values` answers the reach question and the value
    proof from the identical node, so one spelling would decide both. Their origin therefore sits in the
    sink's NON-path argument (`open(config_file, "r", encoding=sys.argv[2])`), which the reach test
    accepts by design -- it is argument-wide precisely because an argument-wide test can only ever keep
    a row loud, never silence one. The path argument still carries the tempfile join or the hub resolver
    the label names, so the clause is still the mechanism that decides the row: TIER 3 shows each earned
    fixture quiet as shipped and loud with the clause rolled back, and `arm_removed` brings all five back.

The appended `ENTRY` argv tail this table used to carry is gone, and measurement is why: once an
argument of the sink call itself reads `sys.argv`, the module-entrypoint fact that tail declared comes
with it, and `resolver_plain_local`, `resolver_in_if_branch`, `resolver_loop_bare_positional`,
`name_never_written_here` and `resolver_leaf_not_hub` scan identically with and without it
(`scratch/_c22_r3_sliceh_grid.py`, the `/no-entry` rows). Keeping a tail that decides nothing is the
decorative scaffolding this gate exists to ban.

Falsification: `python benchmark/gates/cwe22_value_origin_probe.py --mutation <name>` exits 0 only when
the mutation moves the row or the identity its clause owns; `arm_removed` is the rollback that proves
the five earned rows are quiet BECAUSE of this clause. `facts_cache_removed` was re-anchored this round
for an unrelated reason: the identity TIER 4 pins comes out of `_c22_scope_binds` (the
`_c22_scope_names` tuple the binding walk caches on the tree), not out of a Slice-H-owned key, and
popping `_c22_slice_h_facts` -- the key the mutation named -- has been a no-op against both HEAD's
engine and this one (`scratch/_c22_r3_sliceh_head_gate/cwe22_value_origin_probe.py`, HEAD's copy of this gate run
against the shipped engine, MISSES it too). The mutation now pops the key the facts are actually read
from, so the cache it claims to remove is the cache that exists.
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

LOCKED = {'parity': 8, 'big8': 16}
TOTAL_KEYS = {'parity': 425, 'big8': 119}
HUB = 'from huggingface_hub import hf_hub_download\n'
TAINT = '    user = request.args.get("name")\n'

# ---------------------------------------------------------------- fixture table
# Every fixture carries exactly one `open(` call and the sink line is DERIVED from it, never counted by
# hand: the first version of this table hand-numbered every entry, each number landed a few lines short
# of the real sink, and the whole table then "passed" as already-quiet rows that were unfired sinks.
PRE = 'import json\nimport tempfile\nimport unittest\nfrom pathlib import Path\n'
# The same carrier with the interpreter's own command line in it. Round 3 made this the shape a Slice H
# fixture has to be written in: `_c22_open_sink_owes_proven_taint` will not let a path sink report at
# all unless a resolved origin reaches one of its arguments, so a fixture with no command line anywhere
# has no row for this clause to decide -- it reads decorative however the clause answers. See the
# module docstring and `scratch/_c22_r3_sliceh_grid.py`, which measured every spelling the walk does
# and does not resolve.
PRE_CLI = 'import json\nimport sys\nimport tempfile\nimport unittest\nfrom pathlib import Path\n'
HUB = 'from huggingface_hub import hf_hub_download\n'
REQ = 'from flask import request\n'
UNTRUSTED = 'request.args["name"]'
# Where a CLI value may sit for the walk to see it. `sys.argv[2]` inline in any argument resolves, and
# in the fixtures whose path the clause proves safe it is deliberately placed in the sink's NON-path
# argument: `_c22_bound_values` answers the reach question and the value-proof question from the same
# node, so one name cannot be proven program-created and operator-steered at once. A quiet fixture
# therefore keeps its proven path and buys its liveness from the argument beside it, which the
# argument-wide (and so fail-closed) reach test accepts.

FIXTURES = {
    # --- earned: loud before this clause, quiet after it ---------------------------------------
    # Transcribed from the arena files the clause retired and minimized by dropping sibling
    # statements until only the deciding shape survived (scratch/_H_minimize.py).
    'tmpdir_join_in_method': PRE_CLI + (
        'class AutoImageProcessorTest(unittest.TestCase):\n'
        '    def test_from_local_directory(self):\n'
        '        with tempfile.TemporaryDirectory() as tmpdirname:\n'
        '            config_tmpfile = Path(tmpdirname) / "config.json"\n'
        '            json.dump({"model_type": "clip"},\n'
        '                      open(config_tmpfile, "w", encoding=sys.argv[2]))\n'),
    'tmpdir_join_bare_function': PRE_CLI + (
        'def test_from_local_directory():\n'
        '    with tempfile.TemporaryDirectory() as tmpdirname:\n'
        '        config_tmpfile = Path(tmpdirname) / "config.json"\n'
        '        json.dump({"model_type": "clip"},\n'
        '                  open(config_tmpfile, "w", encoding=sys.argv[2]))\n'),
    'resolver_plain_local': HUB + 'import json\nimport sys\n' + (
        'def convert_checkpoint(language):\n'
        '    config_file = hf_hub_download(repo_id="facebook/mms-tts", filename="config.json")\n'
        '    with open(config_file, "r", encoding=sys.argv[2]) as handle:\n'
        '        return json.loads(handle.read())\n'),
    'resolver_in_if_branch': HUB + 'import json\nimport sys\n' + (
        'def convert_checkpoint(out_dir, checkpoint_path=None, language=None):\n'
        '    if checkpoint_path is None:\n'
        '        config_file = hf_hub_download(\n'
        '            repo_id="facebook/mms-tts", filename="config.json",\n'
        '            subfolder=f"models/{language}",\n'
        '        )\n'
        '        with open(config_file, "r", encoding=sys.argv[2]) as handle:\n'
        '            hps = json.loads(handle.read())\n'
        '    else:\n'
        '        print("skip")\n'),
    'resolver_loop_bare_positional': HUB + 'import json\nimport sys\n' + (
        'def get_remote_tools(organization):\n'
        '    tools = {}\n'
        '    for space_info in list_spaces(author=organization):\n'
        '        repo_id = space_info.id\n'
        '        resolved_config_file = hf_hub_download(repo_id, "tool_config.json")\n'
        '        with open(resolved_config_file, encoding=sys.argv[2]) as reader:\n'
        '            tools[repo_id] = json.load(reader)\n'
        '    return tools\n'),
    # --- refused: the positive proof is missing, so the row stays loud -------------------------
    'name_is_method_parameter': PRE_CLI + (
        'class AutoImageProcessorTest(unittest.TestCase):\n'
        '    def test_from_local_directory(self, config_tmpfile):\n'
        '        with tempfile.TemporaryDirectory() as tmpdirname:\n'
        '            json.dump({"model_type": "clip"},\n'
        '                      open(config_tmpfile, "w", encoding=sys.argv[2]))\n'),
    'join_leaf_from_request': PRE + REQ + (
        'class AutoImageProcessorTest(unittest.TestCase):\n'
        '    def test_from_local_directory(self):\n'
        '        with tempfile.TemporaryDirectory() as tmpdirname:\n'
        '            config_tmpfile = Path(tmpdirname) / ' + UNTRUSTED + '\n'
        '            json.dump({"model_type": "clip"}, open(config_tmpfile, "w"))\n'),
    'join_root_from_request': PRE + REQ + (
        'class AutoImageProcessorTest(unittest.TestCase):\n'
        '    def test_from_local_directory(self):\n'
        '        with tempfile.TemporaryDirectory() as tmpdirname:\n'
        '            config_tmpfile = Path(' + UNTRUSTED + ') / "config.json"\n'
        '            json.dump({"model_type": "clip"}, open(config_tmpfile, "w"))\n'),
    'second_write_from_request': PRE + REQ + (
        'class AutoImageProcessorTest(unittest.TestCase):\n'
        '    def test_from_local_directory(self):\n'
        '        with tempfile.TemporaryDirectory() as tmpdirname:\n'
        '            config_tmpfile = Path(tmpdirname) / "config.json"\n'
        '            if ' + UNTRUSTED + ':\n'
        '                config_tmpfile = ' + UNTRUSTED + '\n'
        '            json.dump({"model_type": "clip"}, open(config_tmpfile, "w"))\n'),
    'global_rebind_sink_same_function': HUB + REQ + (
        'config_file = hf_hub_download(repo_id="x/y", filename="config.json")\n'
        'def refresh():\n'
        '    global config_file\n'
        '    config_file = ' + UNTRUSTED + '\n'
        'with open(config_file, "r") as handle:\n'
        '    print(handle.read())\n'),
    'global_rebind_sink_other_function': HUB + REQ + (
        'config_file = hf_hub_download(repo_id="x/y", filename="config.json")\n'
        'def refresh():\n'
        '    global config_file\n'
        '    config_file = ' + UNTRUSTED + '\n'
        'def read_it():\n'
        '    with open(config_file, "r") as handle:\n'
        '        return json.load(handle)\n'),
    'nonlocal_rebind_sink_other_function': HUB + REQ + (
        'def outer():\n'
        '    config_file = hf_hub_download(repo_id="x/y", filename="config.json")\n'
        '    def poison():\n'
        '        nonlocal config_file\n'
        '        config_file = ' + UNTRUSTED + '\n'
        '    def read_it():\n'
        '        with open(config_file, "r") as handle:\n'
        '            return json.load(handle)\n'
        '    poison()\n'
        '    return read_it()\n'),
    'name_never_written_here': 'import json\nimport sys\n' + (
        'def read_it():\n'
        '    with open(config_file, "r", encoding=sys.argv[2]) as handle:\n'
        '        return json.load(handle)\n'),
    'resolver_leaf_not_hub': 'from .utils import hf_hub_download\nimport json\nimport sys\n' + (
        'def convert_checkpoint(language):\n'
        '    config_file = hf_hub_download(repo_id="facebook/mms-tts", filename="config.json")\n'
        '    with open(config_file, "r", encoding=sys.argv[2]) as handle:\n'
        '        return json.loads(handle.read())\n'),
    'subscript_not_bare_ident': PRE_CLI + (
        'class Holder(unittest.TestCase):\n'
        '    def test_slot(self):\n'
        '        with tempfile.TemporaryDirectory() as tmpdirname:\n'
        '            roots = [Path(tmpdirname) / "config.json"]\n'
        '            json.dump({"model_type": "clip"},\n'
        '                      open(roots[0], "w", encoding=sys.argv[2]))\n'),
    'tmpdir_direct_open': PRE_CLI + (
        'class Holder(unittest.TestCase):\n'
        '    def test_direct(self):\n'
        '        with tempfile.TemporaryDirectory() as tmpdirname:\n'
        '            with open(Path(tmpdirname) / "config.json", "w",\n'
        '                      encoding=sys.argv[2]) as handle:\n'
        '                handle.write("{}")\n'),
}
EXPECT_QUIET = ('tmpdir_join_in_method', 'tmpdir_join_bare_function', 'resolver_plain_local',
                'resolver_in_if_branch', 'resolver_loop_bare_positional')
EXPECT_LOUD = tuple(sorted(key for key in FIXTURES if key not in EXPECT_QUIET))


def fixture_source(label):
    return FIXTURES[label]


def sink_line(label):
    """The one line this clause decides, read off the fixture instead of trusted from a number."""
    hits = [index for index, text in enumerate(fixture_source(label).splitlines(), 1)
            if 'open(' in text]
    if len(hits) != 1:
        raise AssertionError(f'{label}: expected exactly one open() sink, found lines {hits}')
    return hits[0]


# ---------------------------------------------------------------- scan helpers
def scan_source(source):
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _nodes, _records, edges = tracker.analyze()
        found = cli._findings_for(tracker, edges)
    return [(row['line'], row['message']) for row in found if row['cwe'] == 'CWE-22']


def owned_rows(label, arm=None):
    """Rows on the deciding line, optionally with the clause answered by `arm` not by the engine."""
    saved = ast_scanner.TaintTracker._c22_value_is_proven_module_origin
    if arm is not None:
        ast_scanner.TaintTracker._c22_value_is_proven_module_origin = arm
    try:
        line = sink_line(label)
        return sorted(entry for entry in scan_source(fixture_source(label)) if entry[0] == line)
    finally:
        ast_scanner.TaintTracker._c22_value_is_proven_module_origin = saved


def row_exists_without_the_clause(label):
    """The floor a fixture must clear: rolled back, the clause must leave a real CWE-22 row behind.

    A fixture silent under the rollback has no row for this clause to decide, so a blinded veto could
    "catch" on a row that never existed -- the decorative lock Harness Law 8 bans.
    """
    return bool(owned_rows(label, arm=lambda self, tree, expr, mod_name: False))


def is_cwe22_record(metadata):
    return (metadata.get('cwe') == 'CWE-22'
            or metadata.get('sink_type') in ('PATH_TRAVERSAL', 'FILE_ACCESS')
            or metadata.get('operation') == 'FILE_ACCESS')


def observe_asks(source, module='m.py'):
    """Wrap the shipped funnel and record what the engine itself asked and answered.

    A census that re-derived the target expression here drifted from the cascade in the Slice G round
    (the engine reads `tekken_path.read_bytes()` off `node.func.value`, not off `node.args`), which
    made blessed lines look unasked. Asking the engine is the only way this table cannot lie.
    """
    log = []
    original = ast_scanner.TaintTracker._c22_slice_g_proves_safe_sink

    def spy(self, record, target_expr):
        answer = original(self, record, target_expr)
        log.append((record.lineno, dict(record.security_node.metadata),
                    isinstance(target_expr, ast.Name), answer))
        return answer

    ast_scanner.TaintTracker._c22_slice_g_proves_safe_sink = spy
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
            tracker.analyze()
    finally:
        ast_scanner.TaintTracker._c22_slice_g_proves_safe_sink = original
    return log


# ---------------------------------------------------------------- tiers
def check_floors():
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        c22 = [row for row in rows if row[2] == 'CWE-22']
        print(f'  {kind:7s} total={len(rows)} (want {TOTAL_KEYS[kind]})  '
              f'CWE-22={len(c22)} (want {LOCKED[kind]})')
        if len(rows) != TOTAL_KEYS[kind]:
            failures.append((kind, 'baseline total', TOTAL_KEYS[kind], len(rows)))
        if len(c22) != LOCKED[kind]:
            failures.append((kind, 'CWE-22', LOCKED[kind], len(c22)))
    return failures


def check_blessed_reach():
    """TIER 2: every blessed CWE-22 key asked at the engine's funnel, and answered SAFE exactly zero."""
    failures = []
    totals = {'asked': 0, 'safe': 0, 'located': 0}
    for kind in ('parity', 'big8'):
        keys = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        c22 = [row for row in keys if row[2] == 'CWE-22']
        if kind == 'big8':
            verify_corpus('big8', corpus_dir('big8'))
        sources = {}
        for row in c22:
            # One binding for `path`, hanging off this repository's own anchor with literal segments
            # only, and the `open` in the same scope: parity scans `benchmark/gates/`, so a twice
            # written name or a helper's return value turns the harness itself into a CWE-22 key.
            leaf_path = str(row[0]).replace('\\', '/').lstrip('./')
            if kind == 'parity':
                relative = (leaf_path if leaf_path.startswith('benchmark/')
                            else os.path.join('benchmark', leaf_path))
            else:
                relative = os.path.join('benchmark_gates_data', 'corpus_big8',
                                        os.path.basename(leaf_path))
            path = os.path.abspath(os.path.join(ROOT, relative))
            if not os.path.exists(path):
                failures.append((kind, 'blessed corpus file is not in the tree', path))
                continue
            with open(path, encoding='utf-8', errors='replace') as handle:
                text = handle.read()
            entry = sources.setdefault(path, [text, set()])
            entry[1].add(int(row[1]))
        asked_here = safe_here = located_here = wanted_here = 0
        for module_name, (source, lines) in sources.items():
            wanted_here += len(lines)
            log = [entry for entry in observe_asks(source, os.path.basename(module_name))
                   if entry[0] in lines]
            for lineno, metadata, is_name, answer in log:
                if is_cwe22_record(metadata):
                    asked_here += 1
                    located_here += 1
                    if answer:
                        safe_here += 1
        print(f'  {kind:7s} blessed lines={wanted_here} asks_on_them={asked_here} '
              f'answered_safe={safe_here} (want 0)')
        totals['asked'] += asked_here
        totals['safe'] += safe_here
        totals['located'] += located_here
        if safe_here:
            failures.append((kind, 'a blessed CWE-22 key was answered SAFE', safe_here))
    if totals['located'] < sum(LOCKED.values()):
        failures.append(('census', 'fewer blessed lines asked than blessed keys', totals))
    return failures


def check_shapes():
    """TIER 3: the truth table, and the floor every fixture must clear before it may be believed."""
    failures = []
    if set(EXPECT_QUIET) | set(EXPECT_LOUD) != set(FIXTURES):
        failures.append(('table', 'a fixture is in neither bucket',
                         sorted(set(FIXTURES) - set(EXPECT_QUIET) - set(EXPECT_LOUD))))
    if set(EXPECT_QUIET) & set(EXPECT_LOUD):
        failures.append(('table', 'a fixture is in both buckets', sorted(set(EXPECT_QUIET)
                                                                         & set(EXPECT_LOUD))))
    earned = refused = decorative = 0
    for label in sorted(FIXTURES):
        fired = row_exists_without_the_clause(label)
        rows = owned_rows(label)
        want_quiet = label in EXPECT_QUIET
        got_quiet = not rows
        ok = want_quiet == got_quiet and fired
        if not fired:
            decorative += 1
            failures.append((label, 'decorative fixture: no CWE-22 row exists without the clause',
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
    """TIER 4: one deciding site, and no name/path token anywhere in the clause."""
    failures = []
    module_src = ast_scanner.__file__
    with open(module_src, encoding='utf-8', errors='replace') as handle:
        text = handle.read()
    tree = ast.parse(text)
    wanted = ('_c22_value_is_proven_module_origin', '_c22_slice_h_module_facts')
    searched = wanted + ('_c22_slice_g_proves_safe_sink',)
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in searched:
            found[node.name] = node
    for name in wanted:
        if name not in found:
            failures.append(('clause missing', name))
    funnel = found.get('_c22_slice_g_proves_safe_sink')
    consults = 0
    arm_statements = []
    if funnel is not None:
        for node in ast.walk(funnel):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == '_c22_value_is_proven_module_origin'):
                consults += 1
        for statement in funnel.body:
            piece = ast.get_source_segment(text, statement) or ''
            if '_c22_value_is_proven_module_origin' in piece:
                arm_statements.append((f'{funnel.name}/arm@{statement.lineno}', statement))
    banned = ('tests/', 'examples/', 'corpus', 'convert_', 'test_', 'fn_lower',
              'file_paths.get', 'location.file')
    leaked = []
    scanned = [(name, node) for name, node in (
        (name, found.get(name)) for name in wanted) if node is not None]
    scanned += arm_statements
    for name, node in scanned:
        body = [statement for statement in node.body if not (
            isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant))]
        for statement in body:
            piece = ast.get_source_segment(text, statement) or ''
            for banned_snippet in banned:
                if banned_snippet in piece:
                    leaked.append((name, banned_snippet, statement.lineno))
    print(f'  definitions={sorted(n.lineno for n in found.values())} '
          f'funnel_consults={consults} banned_token_hits={len(leaked)}')
    print(f'  funnel_line={funnel.lineno if funnel else None} '
          f'facts_line={found.get("_c22_slice_h_module_facts").lineno if found.get("_c22_slice_h_module_facts") else None}')
    if consults != 1:
        failures.append(('one deciding site', 1, consults))
    if leaked:
        failures.append(('name/path token inside the clause', leaked))
    if len(found) < len(wanted):
        failures.append(('missing clause method', sorted(set(wanted) - set(found))))
    if len(arm_statements) != 1:
        failures.append(('one deciding statement in the funnel', 1, len(arm_statements)))
    facts = ast_scanner.TaintTracker._c22_slice_h_module_facts
    sample = ast.parse('import tempfile\nx = tempfile.mkdtemp()\n')
    first = facts(ast_scanner.TaintTracker(files={'m.py': ''}), sample)
    second = facts(ast_scanner.TaintTracker(files={'m.py': ''}), sample)
    cached = first is second
    print(f'  facts_cached_per_tree={cached} written={len(first[0])} declared={len(first[1])}')
    if not cached:
        failures.append(('facts cache', 'restated', 'the per-tree fact tuple is rebuilt per call'))
    return failures


# ---------------------------------------------------------------- mutations
_SAVED_FACTS = ast_scanner.TaintTracker._c22_slice_h_module_facts
_SAVED_VALUE_PROOF = ast_scanner.TaintTracker._c22_value_is_proven_path_origin


def count_value_proof_consults(label):
    """How often the clause reached through to the deep value proof, and what the row did.

    Used by the `written` fact, which measurement says is a CPU prune rather than a safety veto: the
    scope-aware value proof refuses a never-written name on its own, so no row can move when it is
    blinded. Rule 15.5 rung 5 pins such a guard by its predicate, so the claim here is only that the
    prune saves consults.
    """
    calls = [0]

    def counting(self, tree, expr, mod_name):
        calls[0] += 1
        return _SAVED_VALUE_PROOF(self, tree, expr, mod_name)

    ast_scanner.TaintTracker._c22_value_is_proven_path_origin = counting
    try:
        rows = owned_rows(label)
    finally:
        ast_scanner.TaintTracker._c22_value_is_proven_path_origin = _SAVED_VALUE_PROOF
    return calls[0], bool(rows)


def _drop_write_prune():
    """Ignore the `written` fact, so every bare name is handed to the deep value proof."""
    def replacement(self, tree, expr, mod_name):
        _written, declared = _SAVED_FACTS(self, tree)
        if expr.id in declared:
            return False
        return self._c22_value_is_proven_path_origin(tree, expr, mod_name)
    ast_scanner.TaintTracker._c22_value_is_proven_module_origin = replacement


def _drop_global_veto():
    """Ignore the `declared` fact, so a `global`/`nonlocal` re-bind stays invisible to the clause."""
    def replacement(self, tree, expr, mod_name):
        written, _declared = _SAVED_FACTS(self, tree)
        if expr.id not in written:
            return False
        return self._c22_value_is_proven_path_origin(tree, expr, mod_name)
    ast_scanner.TaintTracker._c22_value_is_proven_module_origin = replacement


def _answer_true_for_any_written_name():
    """Skip the value proof: any name the file writes is enough to go quiet."""
    def replacement(self, tree, expr, mod_name):
        written, declared = _SAVED_FACTS(self, tree)
        return expr.id in written and expr.id not in declared
    ast_scanner.TaintTracker._c22_value_is_proven_module_origin = replacement


def _remove_the_arm():
    """The rollback: answer False before the proof runs. Every earned row must come back loud."""
    ast_scanner.TaintTracker._c22_value_is_proven_module_origin = (
        lambda self, tree, expr, mod_name: False)


def _facts_rebuilt_every_call():
    """Drop the per-tree cache: same answers, so only the identity check can catch it.

    Re-anchored this round, against the key the facts really come from. Slice H reads
    `tree.__dict__["_c22_scope_names"]`, which `_c22_scope_binds` memoises beside the binding table it
    builds, so the key this mutation popped (`_c22_slice_h_facts`) is one no engine has ever written:
    HEAD's copy of this gate (`scratch/_c22_r3_sliceh_head_gate/`) MISSED this mutation against the
    shipped engine, so nothing that used to move stopped moving. Popping both keys is the same claim
    tested against the cache that exists -- the walk re-runs, every answer is identical, and only the
    identity row inside TIER 4 can see it.
    """
    def replacement(self, tree):
        tree.__dict__.pop('_c22_scope_binds', None)
        tree.__dict__.pop('_c22_scope_names', None)
        return _SAVED_FACTS(self, tree)
    ast_scanner.TaintTracker._c22_slice_h_module_facts = replacement


MUTATIONS = {
    'write_prune_blinded': {
        'what': 'ignore the "this file writes that name" fact. Measured: no row moves, because the '
                'scope-aware value proof refuses a never-written name by itself -- so this guard is a '
                'CPU prune, not a safety veto, and it is pinned by the consults it saves (rung 5)',
        'moves': [],
        'predicate': 'name_never_written_here',
        'apply': _drop_write_prune,
    },
    'global_veto_blinded': {
        'what': 'ignore the global/nonlocal veto, so a proven write vouches for a name another '
                'function re-binds from the request',
        'moves': [('global_rebind_sink_same_function', True),
                  ('global_rebind_sink_other_function', True),
                  ('nonlocal_rebind_sink_other_function', True)],
        'apply': _drop_global_veto,
    },
    'value_proof_skipped': {
        'what': 'let the two facts answer for the proof itself: any written, non-global name goes '
                'quiet, including request-bound leaves, unproven second writes and non-hub resolvers',
        'moves': [('join_leaf_from_request', True), ('join_root_from_request', True),
                  ('second_write_from_request', True), ('resolver_leaf_not_hub', True)],
        'apply': _answer_true_for_any_written_name,
    },
    'arm_removed': {
        'what': 'the rollback: never hand a bare identifier to the clause. Every earned row must come '
                'back loud, which is what proves the clause is the reason they are quiet',
        'moves': [(label, False) for label in EXPECT_QUIET],
        'apply': _remove_the_arm,
    },
    'facts_cache_removed': {
        'what': 'rebuild the per-tree fact tuple on every consult -- no row moves, so this is pinned '
                'by identity, not by a finding (Rule 15.5 rung 5)',
        'moves': [],
        'apply': _facts_rebuilt_every_call,
    },
}


def _row_moved(label, must_become_quiet):
    """Did this row move the way the mutation claims, on the line the clause decides?"""
    line = sink_line(label)
    fired = any(row_line == line for row_line, _message in owned_rows(label))
    return fired != must_become_quiet


def run_mutation(name):
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    for label, _must in spec['moves']:
        if not row_exists_without_the_clause(label):
            raise AssertionError(f'{label}: tripwire has no row to move, fix the fixture first')
    before = (count_value_proof_consults(spec['predicate'])
              if 'predicate' in spec else (0, True))
    spec['apply']()
    moved = [f'{label}@{sink_line(label)}' for label, must_become_quiet in spec['moves']
             if _row_moved(label, must_become_quiet)]
    if spec['moves']:
        caught = len(moved) == len(spec['moves'])
        wanted = ', '.join(f'{label}@{sink_line(label)}' for label, _w in spec['moves'])
        print(f'  rows moved: {", ".join(moved) or "(none)"}   wanted all of: {wanted}')
    elif 'predicate' in spec:
        label = spec['predicate']
        after_consults, row_still_loud = count_value_proof_consults(label)
        caught = (after_consults > before[0] and row_still_loud and before[1])
        wanted = (f'{label}: value-proof consults above the {before[0]} the prune saves, '
                  f'row still loud (got {after_consults}, loud={row_still_loud})')
        print(f'  consults before={before[0]} after={after_consults} row_loud_after={row_still_loud}')
        print(f'  wanted: {wanted}')
    else:
        wiring = check_wiring()
        caught = bool(wiring)
        print(f'  wiring failures under this mutation: {wiring}')
        wanted = 'the facts-cache identity row inside TIER 4'
        print(f'  wanted: {wanted}')
    print('VERDICT:', 'CAUGHT - the mutation moves the row or identity its clause owns' if caught
          else 'MISSED - the lock is decorative')
    return 0 if caught else 1


def main() -> int:
    if len(sys.argv) > 2 and sys.argv[1] == '--mutation':
        return run_mutation(sys.argv[2])
    print('TIER 1 - blessed CWE-22 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the 24 blessed keys, asked at the engine funnel:')
    failures += check_blessed_reach()
    print('TIER 3 - fixture truth table:')
    failures += check_shapes()
    print('TIER 4 - one deciding site, no name token in the clause:')
    failures += check_wiring()
    for item in failures:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the Slice H value-origin boundary no longer matches its measured '
              'evidence. Restore the clause, or re-measure the corpus and rewrite this table; never '
              're-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - 0 of {sum(LOCKED.values())} blessed CWE-22 keys answered SAFE, '
          f'{len(EXPECT_QUIET)} shapes proved quiet by this clause, '
          f'{len(FIXTURES) - len(EXPECT_QUIET)} refused shapes still loud, one deciding site '
          f'confirmed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
