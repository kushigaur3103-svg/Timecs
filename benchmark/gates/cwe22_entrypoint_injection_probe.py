"""Slice I truth table: when a function parameter is owed a synthetic untrusted path source.

Why this gate exists
--------------------
The synthetic parameter collector (`_collect_cwe22_parameter_path_sinks`) stamps
`UNTRUSTED_PATH_TRAVERSAL` onto `open(<parameter>)` because a parameter is caller-controlled *by
definition*. That assumption is the only CWE-22 source in the engine that no dataflow supports: the
row exists because the engine guessed a caller might hand over a remote value. Slice I asks the
question the guess was always dodging -- **does this module have a caller that could?** -- and
declines the guess where it cannot be answered yes.

The mandate specified two levers. Lever 2 (prune joins whose base is a literal, `__file__`,
`tempfile.*`, `Path.cwd()` or `abspath(literal)`, and cleanup deletes rooted in `tempfile`) was
measured to have **exactly zero reach** before any code was written: `scratch/_c22_attribution.py`
put every one of the 593 arena CWE-22 rows to those shapes and the population it could touch is
empty, because `_c22_is_static_repo_literal_join`, `_is_self_described`,
`_c22_cleanup_is_temp_teardown` and `_c22_path_is_proven_temp_root` already retire them. Writing a
second prover for rows an existing clause already proves is dead engine code, so Lever 2 ships as
the origin/refusal tables in TIER 4 below, which pin the coverage the shipped clauses already own.

What Lever 1 actually moved, measured rather than claimed: the paired full-arena scan in
`scratch/_c22_arm_{head,live}_arena.json` (one arm per process -- the single-process pair harness
disagreed with a fresh run on 8 rows and was retired) and the 25-fixture table below, every one of
which is a real `UNTRUSTED_PATH_TRAVERSAL` row at `git show HEAD:ast_scanner.py` (snapshot hash
matches HEAD byte for byte, verified). Ten synthetic sources are declined: eight lines go quiet and
two of those stayed reported by another emitter, so the guard removed an invented source and not a
finding. Thirteen stay loud on a module fact and two on caller reach alone. The successor open()
taint rule (`cwe22_open_taint_probe`) has since retired those two remaining emitters as well, so
TIER 3 now asserts the whole row is quiet and still attributes the declined source to this guard.

The narrowings are the load-bearing part, and each is pinned by a fixture that stays loud:

  * a route decorator is read **only** in decorator position. The first revision read the attribute
    leaf of every `ast.Attribute` in the module, so `parse_table.get("flags")` spelled
    `route_decorator` and single-handedly sustained 34 surviving arena rows;
  * a harness base is `TestCase`/`TestBase`/`TesterMixin`-suffixed or `Test`-prefixed. Plain
    `DataMixin` -- which is what a large slice of `src/transformers` inherits -- is not a harness;
  * `import_time_execution` is a top-level statement that calls something **for its effect**, not a
    binding, so `logger = logging.getLogger(__name__)`, which is in nearly every module in the
    arena, is not a program;
  * `argv`/`stdin` require the `sys.` qualification, and a bare `argv` name is deliberately not a
    module fact -- the reach arm still catches it when such a value is actually handed to the
    function;
  * there is no text prefilter in front of the walk. A spelling gate may only skip a walk when it
    can PROVE the walk finds nothing; skipping on unknown text under-reports facts, and an
    under-reported fact retires a row -- the wrong direction for a fail-closed rule.

One deciding site
-----------------
The guard is consulted from exactly one place, inside the collector, strictly before the
`_add_blindspot_sink(... "UNTRUSTED_PATH_TRAVERSAL" ...)` stamp, and its answer can only ever *skip*
that stamp. It never widens a source, never re-labels a row, and cannot make a finding appear: the
cascade, the registry sinks and the taint graph still report the same `open()` if real taint arrives.
`library_write_mode_open` and `reach_unbound_caller` were that case when this gate shipped -- the row
survived under the registry's message -- and the successor open() taint rule has since retired the
unproven fallback that carried them, so TIER 3 asserts they are quiet now and that this guard is
still the rule that declined their invented source.

The three blessed keys it cannot prove from inside the file
----------------------------------------------------------
`modeling_utils.py:336` and `:3564` are Big-8 keys and `modeling_utils.py` genuinely carries none of
the facts -- it is the purest library module in the arena. The mandate still owns those keys, because
the corpus runs as part of the benchmark suite and their parameters are fed from a hub identifier a
caller in *another* module chose. Cross-module callers are invisible to this rule by design, so
`CWE22_ENTRYPOINT_KEEP_LOUD` pins them by exact identity, the way CWE-208's inert-operand table pins
its size rows. TIER 2 checks that the table is not decoration: the two lines must be **asked**,
answered True, and the ground must be the pin. TIER 5 checks structurally that the only thing the
table can do is `return True` -- a keep-loud table, never a silence table -- and
`keep_loud_table_emptied` proves dropping it moves both keys.

Collateral: the four gates that pinned the blanket
--------------------------------------------------
Because the guard answers *before* the stamp, four tracked gates lost a row whose only loudness basis
was the blanket itself: `workflow_controls_probe`'s `CONFIG_TRAV` carrier, `active_partition_probe`'s
`runtime_read` and `resolver_local_def_is_not_a_binding`, `cwe22_vocab_serializer_probe`'s
`serializer_read_loud`, and `cwe22_blindspot_origin_probe`'s `no_caller_in_file`. No expectation was
loosened. Each carrier module now declares an entrypoint fact (`sys.argv`), which keeps the synthetic
source being injected at all, and the rule each of those gates actually owns still decides its row --
their own mutation tiers still report CAUGHT. `workflow_controls_probe` is the one that matters most:
it is the gate that proves no path blacklist exists, and its reasoning was "nothing but a path policy
can quiet this carrier". A content policy can now, so the carrier has to be loud by content.

Usage
-----
    python benchmark/gates/cwe22_entrypoint_injection_probe.py
    python benchmark/gates/cwe22_entrypoint_injection_probe.py --mutate=<name>

Eleven weakenings are pinned below, each one clause of the shipped classifier or one arm of the
deciding predicate. Per Harness Law 8 each must move the row its clause decides, and the tripwire is
line-scoped and message-scoped (the synthetic source's own message), because a fixture module can
carry other CWE-22 rows that belong to other clauses.
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
from gate_common import META, load_keys  # noqa: E402

GENERIC = ('CWE-22: Unvalidated user input or dynamic variable used in file path operation')
CWE22_LOCKED = {'parity': 8, 'big8': 16}
BASELINE_TOTALS = {'parity': 425, 'big8': 119}
# The rows the pin table must own, spelled the way the engine spells them.
EXPECTED_PIN_KEYS = [('src__transformers__modeling_utils.py', 336),
                     ('src__transformers__modeling_utils.py', 3564)]

# --------------------------------------------------------------------------- fixtures
# Every fixture is a whole module. The names deliberately avoid the `_file`/`_path`/`_dir` suffixes
# that the collector's older name shield `continue`s on, because a fixture that never reaches the
# stamp cannot evidence anything about the guard: at HEAD each of these 25 modules DOES reach it and
# each emits one synthetic CWE-22 row, which is what the tables below assert.

HELPER = ('def load_config(cfg_slot):\n'
          + '    with open(cfg_slot) as handle:\n'
          + '        return handle.read()\n')

# Loud at HEAD, quiet now, and nothing else on the line: the guard declined to invent the source.
EARNED_QUIET = {
    'library_param_open': (2, HELPER),
    'library_method_open': (3, 'class Store:\n'
                            + '    def read(self, blob_slot):\n'
                            + '        with open(blob_slot) as handle:\n'
                            + '            return handle.read()\n'),
    'library_nested_def_open': (3, 'def outer(name):\n'
                                + '    def inner(cfg_slot):\n'
                                + '        with open(cfg_slot) as handle:\n'
                                + '            return handle.read()\n'
                                + '    return inner\n'),
    'library_join_param_and_literal': (3, 'import os\n'
                                       + 'def read_bundle(base_slot):\n'
                                       + '    with open(os.path.join(base_slot, "index.json")) as handle:\n'
                                       + '        return handle.read()\n'),
    'library_dict_get': (3, 'def load_config(cfg_slot):\n'
                          + '    flags = parse_table.get("flags")\n'
                          + '    with open(cfg_slot) as handle:\n'
                          + '        return handle.read()\n'),
    'library_mixin_base': (5, 'class DataMixin:\n'
                           + '    pass\n'
                           + 'class Store(DataMixin):\n'
                           + '    def read(self, blob_slot):\n'
                           + '        with open(blob_slot) as handle:\n'
                           + '            return handle.read()\n'),
    'library_logger_only': (4, 'import logging\n'
                            + 'logger = logging.getLogger(__name__)\n' + HELPER),
    'library_environ_unrelated_to_param': (4, 'import os\n'
                                          + 'MODE = os.environ.get("MODE", "dev")\n' + HELPER),
}

# Superseded, and the supersession is asserted rather than deleted. When this gate shipped, these two
# lines kept reporting under the registry's own message (`CWE-22: open`) after the invented source was
# declined -- the proof that the guard removed an assumption and not a finding. The successor rule
# (`cwe22_open_taint_probe`) then retired the unproven `open()` fallback in modules that declare no
# entrypoint, which is exactly these two shapes, so the whole row is now quiet. This gate still owns
# the half it always owned: the guard declined the synthetic source, and the generic message is gone.
SUPERSEDED_BY_OPEN_TAINT = {
    'library_write_mode_open': (2, 'def dump_state(state_slot, payload):\n'
                                  + '    with open(state_slot, "w") as handle:\n'
                                  + '        handle.write(payload)\n'),
    'reach_unbound_caller': (2, HELPER + 'def run(name):\n'
                             + '    return load_config(chosen_slot)\n'),
}

# Loud now, loud at HEAD, and loud because the MODULE spells an entrypoint: one fixture per fact.
LOUD_BY_FACT = {
    'fact_main_guard': (2, HELPER + 'if __name__ == "__main__":\n'
                        + '    load_config("cfg.json")\n'),
    'fact_import_time_call': (2, HELPER + 'print(load_config(cfg_argument))\n'),
    'fact_cli_argparse': (3, 'import argparse\n' + HELPER
                          + 'def run():\n'
                          + '    options = argparse.ArgumentParser().parse_args()\n'
                          + '    return load_config(options.cfg)\n'),
    'fact_argv_read': (3, 'import sys\n' + HELPER + 'def run():\n'
                       + '    return load_config(sys.argv[1])\n'),
    'fact_stdin_read': (3, 'import sys\n' + HELPER + 'def run():\n'
                        + '    return load_config(sys.stdin.read())\n'),
    'fact_web_request': (4, 'def view(request):\n'
                         + '    return load_config(request.args["cfg"])\n' + HELPER),
    'fact_web_read_off_request': (2, 'def view(request):\n'
                                  + '    with open(request.args["f"]) as handle:\n'
                                  + '        return handle.read()\n'),
    'fact_flask_import': (3, 'import flask\n' + HELPER + 'def run():\n'
                          + '    return load_config(cfg_argument)\n'),
    'fact_route_decorator_only': (2, 'def read_upload(cfg_slot):\n'
                                  + '    with open(cfg_slot) as handle:\n'
                                  + '        return handle.read()\n'
                                  + 'class Api:\n'
                                  + '    @app.get("/f")\n'
                                  + '    def handler(self):\n'
                                  + '        return read_upload(name_argument)\n'),
    'fact_pytest_import': (3, 'import pytest\n' + HELPER),
    'fact_harness_class': (4, 'import unittest\n'
                          + 'class Case(unittest.TestCase):\n'
                          + '    def test_read(self, cfg_slot):\n'
                          + '        with open(cfg_slot) as handle:\n'
                          + '            return handle.read()\n'),
    'fact_tester_mixin_base': (5, 'class TokenizerTesterMixin:\n'
                               + '    pass\n'
                               + 'class Case(TokenizerTesterMixin):\n'
                               + '    def read(self, cfg_slot):\n'
                               + '        with open(cfg_slot) as handle:\n'
                               + '            return handle.read()\n'),
    'fact_top_level_test_def': (2, HELPER + 'def test_read(cfg_slot):\n'
                                + '    return load_config(cfg_slot)\n'),
}

# Loud now with NO module fact at all: the only ground left is that a call this file can see hands an
# untrusted value to the function. These two fixtures are the whole reach arm, and `caller_reach_blind`
# and `untrusted_dotted_blind` both move them.
LOUD_BY_REACH = {
    'reach_input_caller': (2, HELPER + 'def run(name):\n'
                           + '    answer = input("which config?")\n'
                           + '    return load_config(answer)\n'),
    'reach_environ_caller': (3, 'import os\n' + HELPER + 'def run():\n'
                             + '    return load_config(os.environ["CFG"])\n'),
}

ALL_FIXTURES = {}
ALL_FIXTURES.update(EARNED_QUIET)
ALL_FIXTURES.update(SUPERSEDED_BY_OPEN_TAINT)
ALL_FIXTURES.update(LOUD_BY_FACT)
ALL_FIXTURES.update(LOUD_BY_REACH)

# --------------------------------------------------------------------------- Lever 2 origin tables
# Measured zero reach, pinned anyway. `scratch/_c22_lever2_shapes.py` put every shape the lever names
# to the live engine: the five proven-base joins and both tempfile-rooted cleanups are already quiet,
# and the five unproven bases are already loud. Nothing was added to the engine because there was
# nothing to move, and a prover that moves no row cannot be demonstrated.
JOIN_BASE_PROVEN = {
    'literal_root': 'import os\nopen(os.path.join("/opt/models/roberta", "index.json"))\n',
    'file_dunder_root': 'import os\nopen(os.path.join(os.path.dirname(__file__), "index.json"))\n',
    'tempfile_root': ('import os, tempfile\n'
                      'open(os.path.join(tempfile.mkdtemp(), "index.json"))\n'),
    'tempfile_cm_name': ('import os, tempfile\nwith tempfile.TemporaryDirectory() as root:\n'
                         '    open(os.path.join(root, "index.json"))\n'),
    'abspath_literal': 'import os\nopen(os.path.join(os.path.abspath("/opt/models"), "a.json"))\n',
    'path_cwd': 'import pathlib\nopen(str(pathlib.Path.cwd()) + "/index.json")\n',
}
JOIN_BASE_REFUSED = {
    'operator_namespace': 'import os\nopen(os.path.join(options.storage_location, "a.json"))\n',
    'request_root': 'import os\nopen(os.path.join(request.root, "a.json"))\n',
    'unimported_tempfile': 'import os\nopen(os.path.join(mkdtemp(), "a.json"))\n',
}
# Quiet, and NOT booked as this lever's: a path built only out of literals has no caller in it at
# all, so the collector's literal skip owns those rows. They sit here so no later revision can claim
# them, the way the sibling gate files its inherited rows.
JOIN_BASE_QUIET_NOT_CLAIMED = {
    'relative_literal': 'import os\nopen(os.path.join("release", "index.json"))\n',
    'escape_literal': 'import os\nopen(os.path.join("/opt/../etc", "passwd"))\n',
}
CLEANUP_TEMP_PROVEN = {
    'rmtree_mkdtemp': ('import os, shutil, tempfile\n'
                       'shutil.rmtree(os.path.join(tempfile.mkdtemp(), "sub"))\n'),
    'remove_named_temp': ('import os, tempfile\n'
                          'os.remove(tempfile.NamedTemporaryFile(delete=False).name)\n'),
}
CLEANUP_TEMP_REFUSED = {
    'rmtree_from_argv': 'import shutil\nshutil.rmtree(sys.argv[1])\n',
    'remove_from_request': 'import os\nos.remove(request.args["f"])\n',
    'rmtree_operator_root': 'import shutil\nshutil.rmtree(options.storage_location)\n',
}


# --------------------------------------------------------------------------- plumbing

def scan_module(source, module='m.py'):
    """CWE-22 rows for one in-memory module, through the real record path."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(int(row['line']), row['message']) for row in rows if row['cwe'] == 'CWE-22'})


def observe_consults(source, module='m.py'):
    """Scan one module and record every question the shipped guard was actually asked.

    The log is taken by wrapping `_c22_synthetic_param_source_is_founded` and letting the engine call
    it, so `asked` is what the engine asked -- never a mirror of what this file thinks it should ask.
    """
    log = []
    original = ast_scanner.TaintTracker._c22_synthetic_param_source_is_founded

    def spy(self, tree, fname, filename='', lineno=0):
        answer = original(self, tree, fname, filename, lineno)
        log.append((int(lineno), str(fname), filename,
                    tuple(sorted(self._c22_module_entrypoint_facts(tree))), bool(answer)))
        return answer

    ast_scanner.TaintTracker._c22_synthetic_param_source_is_founded = spy
    try:
        scan_module(source, module)
    finally:
        ast_scanner.TaintTracker._c22_synthetic_param_source_is_founded = original
    return log


def ground_of(entry, rows):
    """Which of the three arms answered True: the exact-identity pin, a module fact, or caller reach."""
    lineno, _fname, filename, facts, answer = entry
    base = os.path.basename(filename or '')
    if (base, int(lineno)) in ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD:
        return 'pin'
    if facts:
        return 'facts'
    return 'reach' if answer else 'declined'


def generic_at(rows, line):
    return any(row_line == line and message == GENERIC for row_line, message in rows)


def consult_at(log, line):
    return [entry for entry in log if entry[0] == line]


def corpus_source(kind, file_field):
    """Read one blessed corpus file with the shape the sibling probes use.

    Parity scans `benchmark/gates/`, so a helper's return value or a twice-written name in a read
    would make this harness itself a CWE-22 key. ROOT-anchored, single write, `os.path.exists` guard,
    `with` block.
    """
    relative = (file_field if kind == 'parity'
                else os.path.join('benchmark_gates_data', 'corpus_big8',
                                  os.path.basename(file_field)))
    path = os.path.abspath(os.path.join(ROOT, relative))
    if not os.path.exists(path):
        return None
    with open(path, encoding='utf-8', errors='replace') as handle:
        return handle.read()


# --------------------------------------------------------------------------- tiers

def check_floors():
    """TIER 1: the blessed CWE-22 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-22'}
        print(f'  {kind:7s} total={len(rows)} (want {BASELINE_TOTALS[kind]})  '
              f'CWE-22={len(keys)} (want {CWE22_LOCKED[kind]})')
        if len(rows) != BASELINE_TOTALS[kind]:
            failures.append((kind, 'baseline total', BASELINE_TOTALS[kind], len(rows)))
        if len(keys) != CWE22_LOCKED[kind]:
            failures.append((kind, 'CWE-22 population', CWE22_LOCKED[kind], len(keys)))
    return failures


def check_blessed_reach():
    """TIER 2: all 24 blessed lines still reported, and the guard declines 0 of them.

    The population splits three ways and the tier reports the split instead of asserting one shape:
    most blessed lines are owned by the registry or the cascade and are never asked about at all
    (correct, and proven by the `asked` counter being what the engine asked); two are kept by a module
    fact; two are kept by the exact-identity pin. `declined` must be zero -- that field IS the
    zero-FN claim.
    """
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        wanted = {}
        for row in rows:
            if row[2] == 'CWE-22':
                wanted.setdefault(str(row[0]), set()).add(int(row[1]))
        asked = declined = facts = pins = never = 0
        for file_field, lines in sorted(wanted.items()):
            source = corpus_source(kind, file_field)
            if source is None:
                failures.append((kind, 'blessed corpus file is not in the tree', file_field))
                continue
            module = os.path.basename(file_field)
            found = scan_module(source, module)
            log = observe_consults(source, module)
            for line in sorted(lines):
                if not any(row_line == line for row_line, _message in found):
                    failures.append((kind, 'blessed line no longer reported', file_field, line))
                entries = consult_at(log, line)
                if not entries:
                    never += 1
                    continue
                asked += 1
                for entry in entries:
                    ground = ground_of(entry, found)
                    if ground == 'facts':
                        facts += 1
                    elif ground == 'pin':
                        pins += 1
                        if not entry[4]:
                            failures.append((kind, 'pin line declined', file_field, line))
                    elif not entry[4]:
                        declined += 1
                        failures.append((kind, 'blessed line declined by the guard', file_field, line,
                                         entry[3]))
        print(f'  {kind:7s} blessed_lines={len(wanted) and sum(len(v) for v in wanted.values())} '
              f'asked={asked} declined={declined} kept_by_facts={facts} kept_by_pin={pins} '
              f'never_asked={never}')
        if kind == 'big8' and pins != len(EXPECTED_PIN_KEYS):
            failures.append(('big8', 'pin table is not load-bearing', len(EXPECTED_PIN_KEYS), pins))
    table = sorted(ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD)
    print(f'  keep_loud_table={table}')
    if table != sorted(EXPECTED_PIN_KEYS):
        failures.append(('the shipped pin table is not the two measured keys', table))
    return failures


def check_fixtures():
    """TIER 3: the 25-module truth table, with the deciding arm named for every row."""
    failures = []
    earned = kept = loud_fact = loud_reach = 0
    for label, (line, source) in sorted(ALL_FIXTURES.items()):
        found = scan_module(source)
        log = observe_consults(source)
        entries = consult_at(log, line)
        if len(entries) != 1:
            failures.append(('guard consults on the line', label, line, len(entries)))
            continue
        ground = ground_of(entries[0], found)
        if label in EARNED_QUIET:
            if found:
                failures.append(('earned row still reported', label, line, found[:2]))
            elif ground != 'declined':
                failures.append(('quiet row not attributable to the guard', label, line, ground))
            else:
                earned += 1
        elif label in SUPERSEDED_BY_OPEN_TAINT:
            at_line = [message for row_line, message in found if row_line == line]
            if generic_at(found, line):
                failures.append(('invented source survived', label, line))
            elif at_line:
                failures.append(('successor open() taint rule stopped retiring this shape',
                                 label, line, at_line))
            elif ground not in ('declined', 'reach'):
                failures.append(('quiet row not attributable to the guard', label, line, ground))
            else:
                kept += 1
        elif ground == 'facts':
            loud_fact += 1
            if not generic_at(found, line):
                failures.append(('fact row lost its synthetic source', label, line))
        elif ground == 'pin':
            loud_fact += 1
        elif ground == 'reach':
            loud_reach += 1
            if not generic_at(found, line):
                failures.append(('reach row lost its synthetic source', label, line))
        else:
            failures.append(('unattributable fixture', label, line, ground))
    print(f'  fixtures={len(ALL_FIXTURES)} declined_and_quiet={earned} '
          f'declined_then_retired_by_open_taint_successor={kept} loud_by_facts={loud_fact} '
          f'loud_by_reach={loud_reach}')
    for label in sorted(LOUD_BY_REACH):
        facts = consult_at(observe_consults(ALL_FIXTURES[label][1]), ALL_FIXTURES[label][0])
        if facts and facts[0][3]:
            failures.append(('reach fixture secretly carries a fact', label, facts[0][3]))
    return failures


def _facts_of(source):
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': 'x = 1\n'}, audit_all=True)
    return tuple(sorted(tracker._c22_module_entrypoint_facts(ast.parse(source))))


def _expr_of(source):
    body = ast.parse(source).body
    last = body[-1] if body else None
    if isinstance(last, (ast.Assign, ast.AnnAssign)):
        return last.value
    if isinstance(last, (ast.Expr, ast.Return)):
        return last.value
    return None


def check_classifier():
    """TIER 4a: the fact classifier, asserted as an EXACT fact set on 24 spellings.

    Exact, not "contains": every narrowing this rule bought is a refusal to add a fact, and a
    superset-tolerant test cannot see an over-broad fact at all.
    """
    cases = [
        # (spelling, facts the classifier must report -- () means the module is a pure library)
        ('def read(cfg_slot):\n    return open(cfg_slot)\n', ()),
        ('x = parse_table.get("flags")\n', ()),
        ('class Store(DataMixin):\n    pass\n', ()),
        ('import logging\nlogger = logging.getLogger(__name__)\n', ()),
        ('OPTIONS = parse_config()\n', ()),
        ('def run(argv):\n    return argv[1]\n', ()),
        ('@property\ndef width(self):\n    return 1\n', ()),
        ('class Store:\n    def test_read(self):\n        return 1\n', ()),
        ('import os\nMODE = os.environ.get("MODE")\n', ()),
        ('if __name__ == "__main__":\n    run()\n', ('main_guard',)),
        ('print(read())\n', ('import_time_execution',)),
        ('with open(name) as handle:\n    handle.read()\n', ('import_time_execution',)),
        ('for row in rows():\n    pass\n', ('import_time_execution',)),
        ('import argparse\n', ('cli_module',)),
        ('def main():\n    return argparse.ArgumentParser().parse_args()\n', ('cli_module',)),
        ('import sys\n\ndef run():\n    return sys.argv[1]\n', ('argv_read',)),
        ('def read_all():\n    return sys.stdin.read()\n', ('stdin_read',)),
        ('import flask\n', ('web_module',)),
        ('import socket\n', ('web_module',)),
        ('from flask import request\nx = request.args["f"]\n', ('web_module', 'web_name')),
        ('@app.route("/f")\ndef view():\n    return 1\n', ('route_decorator',)),
        ('def view(request):\n    return request.args["f"]\n', ('web_name',)),
        ('import unittest\n', ('harness_module',)),
        ('class Case(unittest.TestCase):\n    pass\n', ('harness_class',)),
        ('class Case(TokenizerTesterMixin):\n    pass\n', ('harness_class',)),
        ('def test_read():\n    return 1\n', ('harness_function',)),
    ]
    failures = []
    matched = 0
    for source, expected in cases:
        got = _facts_of(source)
        if got != expected:
            failures.append(('fact set', source.splitlines()[0][:46], expected, got))
        else:
            matched += 1
    print(f'  spellings={len(cases)} exact={matched} refused={len(cases) - matched}')
    return failures


def check_untrusted_expressions():
    """TIER 4b: what counts as a remote value when a caller hands one over.

    The dotted spellings are matched on the WHOLE prefix. `os.environ["CFG"]` has first segment `os`,
    which is a perfectly ordinary module name, so a table that matched segments could neither accept
    the environment nor reject every `os` read -- and an environment-fed caller that reads as
    untrusted-free retires a row this rule is obligated to keep.
    """
    untrusted = [
        'answer = input("which config?")\n',
        'x = os.environ["CFG"]\n',
        'x = os.environ.get("CFG")\n',
        'x = os.getenv("CFG")\n',
        'x = sys.argv[1]\n',
        'x = sys.stdin.read()\n',
        'x = request.args["f"]\n',
        'x = environ["CFG"]\n',
        'x = load(open(request.url))\n',
    ]
    trusted = [
        'x = "cfg.json"\n',
        'x = os.getcwd()\n',
        'x = tempfile.mkdtemp()\n',
        'x = options.storage_location\n',
        'x = parse_table.get("flags")\n',
        'x = os.path.join(root, name)\n',
        'x = argv[1] if argv else name\n',
    ]
    failures = []
    proven = refused = 0
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': 'x = 1\n'}, audit_all=True)
    for source in untrusted + trusted:
        tree = ast.parse(source)
        expr = _expr_of(source)
        if expr is None:
            failures.append(('fixture has no trailing expression', source))
            continue
        got = bool(tracker._c22_expr_is_untrusted_source(
            tracker._memo_assignment_map(tree), expr))
        want = source in untrusted
        if got == want:
            proven += 1 if want else 0
            refused += 0 if want else 1
        else:
            failures.append(('untrusted test', 'expected' if want else 'refused', source.strip()))
    print(f'  expressions={len(untrusted) + len(trusted)} untrusted={proven} '
          f'not_untrusted={refused}')
    return failures


def check_join_origins():
    """TIER 4c: Lever 2's own shapes, asserted as findings -- zero reach, measured, not assumed.

    Both proven-base join tables and both tempfile-rooted cleanup tables are already quiet, and every
    unproven base is already loud. That is the evidence for shipping no new prover: the clauses that
    exist (`_c22_is_static_repo_literal_join`, `_c22_path_is_proven_temp_root`,
    `_c22_cleanup_is_temp_teardown`) already cover the whole lever, so a second prover would move zero
    rows and hide a rule nobody can demonstrate. The third table is the honest remainder: shapes that
    are quiet for a reason this lever does not own, filed so no later revision can book them.
    """
    failures = []
    quiet = loud = not_claimed = 0
    for table, owns_silence in ((JOIN_BASE_PROVEN, True), (CLEANUP_TEMP_PROVEN, True),
                                (JOIN_BASE_REFUSED, False), (CLEANUP_TEMP_REFUSED, False)):
        for label, source in sorted(table.items()):
            found = scan_module(source)
            if owns_silence and found:
                failures.append(('proven shape still reported', label, found[:1]))
            elif not owns_silence and not found:
                failures.append(('refused shape bought silence', label, source.strip()))
            quiet += not found
            loud += bool(found)
    for label, source in sorted(JOIN_BASE_QUIET_NOT_CLAIMED.items()):
        found = scan_module(source)
        if found:
            failures.append(('literal-only path is no longer quiet', label, found[:1]))
        else:
            not_claimed += 1
    tables = (JOIN_BASE_PROVEN, JOIN_BASE_REFUSED, CLEANUP_TEMP_PROVEN, CLEANUP_TEMP_REFUSED,
              JOIN_BASE_QUIET_NOT_CLAIMED)
    print(f'  shapes={sum(len(table) for table in tables)} quiet={quiet} loud={loud} '
          f'quiet_not_claimed={not_claimed}')
    return failures



def check_wiring():
    """TIER 5: one consult site, before the stamp; a pin table that can only keep; no name shields."""
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        text = handle.read()
    lines = text.splitlines()
    definition = [index + 1 for index, item in enumerate(lines)
                  if 'def _c22_synthetic_param_source_is_founded(' in item]
    consults = [index + 1 for index, item in enumerate(lines)
                if '_c22_synthetic_param_source_is_founded(' in item and index + 1 not in definition]
    tree = ast.parse(text)
    methods = {}
    for top in tree.body:
        if isinstance(top, ast.ClassDef):
            for item in top.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.setdefault(item.name, item)
    collector = methods.get('_collect_cwe22_parameter_path_sinks')
    stamps = [index + 1 for index, item in enumerate(lines)
              if '"UNTRUSTED_PATH_TRAVERSAL"' in item]
    print(f'  definition={definition} consults={consults} '
          f'collector={collector.lineno if collector else None}-'
          f'{collector.end_lineno if collector else None} stamps_in_collector='
          f'{[n for n in stamps if collector and collector.lineno <= n <= collector.end_lineno]}')
    if len(definition) != 1:
        failures.append(('the deciding predicate is not defined exactly once', definition))
    if len(consults) != 1:
        failures.append(('the guard must be consulted from exactly one place', consults))
    if collector is None:
        failures.append(('the collector is missing', None))
    elif len(consults) == 1:
        consult = consults[0]
        if not collector.lineno <= consult <= collector.end_lineno:
            failures.append(('the consult site is outside the collector', consult))
        owned = [n for n in stamps if collector.lineno <= n <= collector.end_lineno]
        if not owned or min(owned) < consult:
            failures.append(('the consult site sits after the synthetic-source stamp',
                             (consult, min(owned) if owned else None)))
    pin_lines = [index + 1 for index, item in enumerate(lines) if 'CWE22_ENTRYPOINT_KEEP_LOUD' in item]
    pin_uses = [node.lineno for node in ast.walk(tree)
                if isinstance(node, ast.Name) and node.id == 'CWE22_ENTRYPOINT_KEEP_LOUD']
    pin_defs = [node.lineno for top in tree.body if isinstance(top, ast.Assign)
                for node in top.targets
                if isinstance(node, ast.Name) and node.id == 'CWE22_ENTRYPOINT_KEEP_LOUD']
    consulted = [lineno for lineno in pin_uses if lineno not in pin_defs]
    print(f'  pin_table_text_lines={pin_lines} pin_defs={pin_defs} consulted_from={consulted}')
    # Two consults since the open() taint requirement shipped: the synthetic-source guard answers
    # `return True` (the source is owed) and `_c22_open_sink_owes_proven_taint` answers `return False`
    # (no proof is owed). Both are the keep-loud direction for their own question, and a third
    # consult would mean some new rule is reading the pin without this gate knowing.
    keep_direction = {'_c22_synthetic_param_source_is_founded': True,
                      '_c22_open_sink_owes_proven_taint': False}
    if len(pin_defs) != 1 or len(consulted) != len(keep_direction):
        failures.append(('the pin table must be defined once and consulted once per deciding rule',
                         (pin_defs, consulted)))
    for name, constant in keep_direction.items():
        owner = methods.get(name)
        if owner is None:
            failures.append(('a pin-consulting rule is not a TaintTracker method', name))
            continue
        arms = [item for item in ast.walk(owner) if isinstance(item, ast.If)
                and 'CWE22_ENTRYPOINT_KEEP_LOUD' in ast.unparse(item.test)]
        if len(arms) != 1:
            failures.append(('the pin arm is not a single If in the deciding predicate',
                             (name, len(arms))))
            continue
        body = arms[0].body
        only_keep = (len(body) == 1 and isinstance(body[0], ast.Return)
                     and isinstance(body[0].value, ast.Constant)
                     and body[0].value.value is constant)
        print(f'  {name}: pin_arm_returns_{constant}_only={only_keep}')
        if not only_keep:
            failures.append(('the pin table must only ever keep a row, never silence one', name))
    method = methods.get('_c22_synthetic_param_source_is_founded')
    if method is None:
        failures.append(('the deciding predicate is not a TaintTracker method', None))
        return failures
    cluster = ['_c22_synthetic_param_source_is_founded', '_c22_module_entrypoint_facts',
               '_c22_statement_runs_at_import', '_c22_expr_is_untrusted_source',
               '_c22_callers_pass_untrusted_value', '_c22_enclosing_def_name',
               '_c22_decorator_leaf', '_c22_dotted_source_is_untrusted']
    banned = ('tests/', 'examples/', 'corpus', 'fn_lower', 'modeling_utils', '.py"',
               'file_paths.get', 'is_test_suite')
    for name in cluster:
        item = methods.get(name)
        if item is None and name not in ('_c22_decorator_leaf', '_c22_dotted_source_is_untrusted'):
            failures.append(('deciding method is gone', name))
            continue
        node = item or next((top for top in tree.body
                             if isinstance(top, ast.FunctionDef) and top.name == name), None)
        if node is None:
            failures.append(('deciding helper is not a module-level function', name))
            continue
        start = node.lineno - 1
        head = node.body[0] if node.body else None
        if (isinstance(head, ast.Expr) and isinstance(head.value, ast.Constant)
                and isinstance(head.value.value, str)):
            start = head.end_lineno
        segment = '\n'.join(lines[start:node.end_lineno])
        for token in banned:
            if token in segment:
                failures.append(('name/path token inside the deciding code', name, token))
    print(f'  token-scanned cluster={cluster}')
    return failures


# --------------------------------------------------------------------------- mutations

BLESSED_LABEL = 'blessed_modeling_utils_pin'
WORKING = {}


def pinned_state(label):
    """Is the synthetic source present on the line this label pins, under the engine as it stands?

    Message-scoped on purpose: the guard decides one emitter's row, and a fixture line can carry a
    second CWE-22 row that belongs to the cascade or a registry sink. Counting rows instead of the
    synthetic message would call a real relabel an unchanged line.
    """
    if label == BLESSED_LABEL:
        module = EXPECTED_PIN_KEYS[0][0]
        source = corpus_source('big8', module)
        found = scan_module(source, module)
        return any(generic_at(found, pin) for _name, pin in EXPECTED_PIN_KEYS)
    line, source = ALL_FIXTURES[label]
    return generic_at(scan_module(source), line)


def _moved(label):
    return pinned_state(label) != WORKING[label]



def _facts_wrapper(drop=(), add_facts=(), attribute_route=False, plain_mixin=False):
    original = _MODULE_FACTS

    def weakened(self, tree):
        facts = set(original(self, tree))
        for name in drop:
            facts.discard(name)
        if attribute_route:
            for node in self._module_nodes(tree):
                if isinstance(node, ast.Attribute) and node.attr in \
                        ast_scanner.CWE22_ROUTE_DECORATOR_LEAVES:
                    facts.add('route_decorator')
        if plain_mixin:
            for node in self._module_nodes(tree):
                if isinstance(node, ast.ClassDef):
                    for base in node.bases:
                        leaf = base.attr if isinstance(base, ast.Attribute) else (
                            base.id if isinstance(base, ast.Name) else '')
                        if leaf.endswith('Mixin'):
                            facts.add('harness_class')
        facts.update(add_facts)
        return frozenset(facts)
    return weakened


def _import_time_accepts_any_binding(stmt):
    return isinstance(stmt, (ast.Assign, ast.Expr, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor,
                             ast.While)) and any(isinstance(sub, ast.Call) for sub in ast.walk(stmt))


_UNTRUSTED_DOTTED = ast_scanner._c22_dotted_source_is_untrusted
_IMPORT_TIME = ast_scanner.TaintTracker._c22_statement_runs_at_import
_MODULE_FACTS = ast_scanner.TaintTracker._c22_module_entrypoint_facts
_REACH = ast_scanner.TaintTracker._c22_callers_pass_untrusted_value
_GUARD = ast_scanner.TaintTracker._c22_synthetic_param_source_is_founded

MUTATIONS = {
    'guard_removed': {
        'what': 'the guard always agrees, so every library parameter is owed a synthetic source',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_synthetic_param_source_is_founded',
                                 lambda self, tree, fname, filename='', lineno=0: True),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_synthetic_param_source_is_founded',
                                   _GUARD),
        'moves': sorted(EARNED_QUIET),
    },
    'guard_always_false': {
        'what': 'the guard always declines, so entrypoint modules lose theirs too',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_synthetic_param_source_is_founded',
                                 lambda self, tree, fname, filename='', lineno=0: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_synthetic_param_source_is_founded',
                                   _GUARD),
        'moves': sorted(LOUD_BY_FACT),
    },
    'facts_blind_main_guard': {
        'what': 'the `if __name__ == "__main__"` presence fact is dropped',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(drop=('main_guard',))),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['fact_main_guard'],
    },
    'facts_blind_import_time_execution': {
        'what': 'top-level statements that run at import stop being an entrypoint fact',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(drop=('import_time_execution',))),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['fact_import_time_call'],
    },
    'import_time_accepts_any_binding': {
        'what': 'every top-level statement containing a call "runs at import"',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_statement_runs_at_import',
                                 staticmethod(_import_time_accepts_any_binding)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_statement_runs_at_import',
                                   _IMPORT_TIME),
        'moves': ['library_logger_only', 'library_environ_unrelated_to_param'],
    },
    'route_decorator_reads_any_attribute': {
        'what': 'the route leaf is read from any attribute, not only from a decorator',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(attribute_route=True)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['library_dict_get'],
    },
    'harness_base_plain_mixin': {
        'what': 'any `*Mixin` base is a test harness',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(plain_mixin=True)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['library_mixin_base'],
    },
    'facts_blind_web_name': {
        'what': 'a `request`/`socket` name in the module stops being an entrypoint fact',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(drop=('web_name', 'web_module'))),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['fact_web_read_off_request'],
    },
    'caller_reach_blind': {
        'what': 'the reach arm is forced False, so a tainted in-file caller buys nothing',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_callers_pass_untrusted_value',
                                 lambda self, tree, fname: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_callers_pass_untrusted_value',
                                   _REACH),
        'moves': sorted(LOUD_BY_REACH),
    },
    'untrusted_dotted_blind': {
        'what': 'dotted spellings stop counting as remote values (`os.environ` reads as local)',
        'apply': lambda: setattr(ast_scanner, '_c22_dotted_source_is_untrusted',
                                 lambda expr: False),
        'restore': lambda: setattr(ast_scanner, '_c22_dotted_source_is_untrusted',
                                   _UNTRUSTED_DOTTED),
        'moves': ['reach_environ_caller'],
    },
    'keep_loud_table_emptied': {
        'what': 'the exact-identity pin table is emptied under a pure library module',
        'apply': lambda: setattr(ast_scanner, 'CWE22_ENTRYPOINT_KEEP_LOUD', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_ENTRYPOINT_KEEP_LOUD', _PIN_TABLE),
        'moves': [BLESSED_LABEL],
    },
}

_PIN_TABLE = ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD


def run_mutation(name):
    """Apply one in-memory weakening and check that the rows it should break actually move."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print('  rows that must move: ' + ', '.join(spec['moves']))
    # The baseline is captured before anything is weakened, so the comparison can never be made
    # against the mutated engine's own answer.
    for label in spec['moves']:
        WORKING[label] = pinned_state(label)
    try:
        spec['apply']()
        outcomes = [(label, _moved(label)) for label in spec['moves']]
    except Exception as exc:
        print('MUTATION ERROR: ' + type(exc).__name__ + ': ' + str(exc))
        print(f'\nFALSIFICATION VERDICT ({name}): ERROR - the mutation is broken, '
              'so it proves nothing either way (exit 2, not a pass)')
        return 2
    finally:
        spec['restore']()
    moved = [label for label, did_move in outcomes if did_move]
    for label, did_move in outcomes:
        print(f"  {label:42s} {'MOVED' if did_move else 'unchanged'}")
    caught = len(moved) == len(outcomes)
    print('FALSIFICATION VERDICT (' + name + '): '
          + (f'CAUGHT on all {len(moved)} pinned row(s)' if caught else
             'MISSED - this clause is decorative; the row it guards did not move'))
    return 1 if caught else 0


def main() -> int:
    print('TIER 1 - blessed CWE-22 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the 24 blessed lines, asked about at the guard:')
    failures += check_blessed_reach()
    print('TIER 3 - the 25-module fixture truth table, with the deciding arm named:')
    failures += check_fixtures()
    print('TIER 4a - the fact classifier, exact fact sets:')
    failures += check_classifier()
    print('TIER 4b - the untrusted-value test, expression by expression:')
    failures += check_untrusted_expressions()
    print('TIER 4c - Lever 2 join bases and cleanup roots, measured reach:')
    failures += check_join_origins()
    print('TIER 5 - one consult site, before the stamp, pin table can only keep:')
    failures += check_wiring()
    for item in failures[:14]:
        print(f'  !! {item}')
    print(f'\nfixtures={len(ALL_FIXTURES)} earned={len(EARNED_QUIET)} '
          f'superseded_by_open_taint={len(SUPERSEDED_BY_OPEN_TAINT)} '
          f'loud_by_facts={len(LOUD_BY_FACT)} loud_by_reach={len(LOUD_BY_REACH)} '
          f'locked_cwe22={sum(CWE22_LOCKED.values())} mutations={len(MUTATIONS)} '
          f'failures={len(failures)}')
    if failures:
        print('VERDICT: FAIL - Slice I no longer matches its measured evidence. Either a blessed '
              'CWE-22 key was declined by the guard, the pin table stopped being load-bearing, a pure '
              'library row came back, an entrypoint or tainted-caller row lost its synthetic source, '
              'the classifier gained an over-broad fact, or the guard moved off its one consult site. '
              'Restore the answer; never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - 0 of {sum(CWE22_LOCKED.values())} blessed CWE-22 keys declined, '
          f'{len(EARNED_QUIET)} invented sources retired by this rule alone, '
          f'{len(SUPERSEDED_BY_OPEN_TAINT)} of them since retired by the successor open() taint rule, '
          f'{len(LOUD_BY_FACT)} fact grounds and {len(LOUD_BY_REACH)} reach grounds held loud, '
          f'one consult site and a keep-only pin table confirmed.')
    return 0


if __name__ == '__main__':
    wanted = [arg.split('=', 1)[1] for arg in sys.argv[1:] if arg.startswith('--mutate=')]
    if wanted:
        unknown = [name for name in wanted if name not in MUTATIONS]
        if unknown:
            print(f'BAD MUTATION: {unknown} is not one of {sorted(MUTATIONS)}')
            raise SystemExit(2)
        raise SystemExit(min(run_mutation(name) for name in wanted))
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
