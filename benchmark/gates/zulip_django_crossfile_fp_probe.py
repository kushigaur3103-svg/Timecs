"""Gate #65 -- the five Zulip/Django/cross-file FP factories, each one held by its own falsifier.

What this task moved, measured against the commit it replaces rather than asserted:

  C1  CROSS-FILE TEST SURFACE. `CrossFileTaintEngine` indexed every `.py` under the target, including
      `zerver/tests/`, while `cli.py` had already pruned that surface from its own walk: the same
      repository was production to one engine and test scaffolding to the other, and 25 of Zulip's
      cross-file findings were a test calling a test helper. The index now applies the `cli` vocabulary
      itself (`NON_PRODUCTION_DIRS` plus `test_*.py` / `*_test.py`) to the walk, with two escapes that
      keep a real chain loud: an operator who points the engine AT a test directory gets all of it, and
      a file the scanner already analysed (`reuse_trees`) is never dropped. The mandated loud half is
      measured, not claimed -- `views.py -> helper.run` is the same row with pruning on or off, and with
      the rule forced onto every path that row disappears, which is the false negative this gate refuses
      to buy.
  C2  TEST ASSERTIONS CARRY NO CONTRACT. `ZulipTestCaseMixin.assertEqual(self, first, second)` reads
      `subprocess.check_output` internally, so summarising it lifted CWE-78 onto `first` and every test
      that passed data in became a cross-file finding. An assertion compares values; it is not a place
      where data is handed to something dangerous, so the summariser now returns the bare summary for
      the seven mandated names plus the unittest/pytest neighbours. Two shapes separate cleanly and both
      are measured: the lifted contract on `out = c.assertEqual(data, "x")` is gone, while the sink
      inside the assertion's own body keeps its row -- this retires a contract, never a sink.
  C3  JSON PARSERS ARE NOT DESERIALIZATION. `KNOWN_SINKS` keys on the leaf name, and `orjson.loads`
      shares that leaf with `pickle.loads`, so `zerver/lib/queue.py` and `zerver/lib/send_email.py` were
      reported as unsafe deserialization. The receiver is resolved through the file's own import
      bindings -- which covers `import orjson as oj` and `from json import loads` -- and only a
      `json`/`orjson`/`ujson`/`simplejson` receiver is refused. A JSON parser builds dicts, lists,
      strings and numbers; it constructs no arbitrary class. `pickle.loads`, `yaml.load` and an
      unresolvable receiver answer False, and a vocabulary forced to excuse everything swallows the
      pickle row, which is the false negative the fail-closed rule exists to prevent.
  C4  DJANGO ROUTE BUILDERS. The mandate expected `reverse(...)` to be refused the way `url_for(...)`
      already is. Measured against HEAD, the refusal changes no verdict: `reverse_off` and `ship` are
      the same row set, because a `reverse` call whose arguments are not client data is already silent
      one clause earlier -- the dynamism gate never emits the row. What is real is that the emitter now
      asks this predicate instead of falling through, so the clause owns the decision: blinding it to
      always-internal retires five rows, `reverse(view)` and `reverse('home', args=[request.GET['x']])`
      among them, which is the FN the mandate warned about and the reason the endpoint has to be a
      constant and every argument has to be clean. Protocol-relative `'//' + host` stays loud under
      every arm of this clause: `_same_origin_relative_target` owns it, and it is kept as a control so
      this gate cannot quietly claim credit for an older proof.
  C5  NUMBERED MIGRATIONS AND API CONTRACTS. `zerver/migrations/0023_*.py` is a schema history: the SQL
      in it ran once against a development database and cannot be reached by a client, so CWE-89 and
      CWE-328 rows there are noise -- while `migrations/helpers.py` and a two-digit `23_add.py` are not
      numbered history and keep reporting. In the config reader, an OpenAPI/Swagger document describes an
      API rather than deploying one, so its sample credentials are documentation: refused by the file's
      own name, or by the two keys only a specification carries (`openapi:`/`swagger:` with `paths:`).
      Neither refusal reaches a vendor token, and a production config loses its row only when the rule is
      blinded -- which is what makes the exemption provable instead of convenient.

TIER 1 reads every case twice against one shared fixture: its shipped verdict, and its verdict with the
owning clause reverted. A retirement whose arm column is still quiet is not booked -- some older clause
owns it; a row that goes quiet only when the clause is blinded is counted as an FN-CLOSER, because that
is the false negative the guard is there to prevent. TIER 2 calls the shipped predicates directly. TIER 3
reads the shipped source and asks it to keep the shape each proof depends on. TIER 4 is the falsifiers:
one weakening per clause, and an exact set of rows and predicates must move.

Usage: python benchmark/gates/zulip_django_crossfile_fp_probe.py [--dump] [--mutate=<name>]
"""
from __future__ import annotations

import ast
import contextlib
import inspect
import io as _io
import os
import pathlib
import re
import shutil
import sys
import tempfile
import time
import types

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
import symbol_indexer  # noqa: E402
import function_summarizer  # noqa: E402
from cross_file_engine import CrossFileTaintEngine  # noqa: E402
from scanners import secret_scanner  # noqa: E402

T = ast_scanner.TaintTracker
FS = function_summarizer.FunctionSummarizer
OWNERS = {'T': T, 'FS': FS, 'ast_scanner': ast_scanner, 'symbol_indexer': symbol_indexer,
          'function_summarizer': function_summarizer, 'secret_scanner': secret_scanner}

BUDGET_SECONDS = 150.0
BUDGET_MUTATION_SECONDS = 45.0
BUDGET_RSS_MB = 60.0


def module(*lines):
    return ''.join(line + '\n' for line in lines)


def at(source, needle, offset=0):
    """The line an offset below a unique needle, so a fixture is read instead of hand-counted."""
    lines = [index for index, text in enumerate(source.splitlines(), 1) if needle in text]
    if len(lines) != 1:
        raise AssertionError(f'{needle!r} matched {len(lines)} lines, need exactly 1')
    return lines[0] + offset


def link(tree):
    """The parent links `T.__init__` puts on every module, so a predicate can be called directly."""
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    return tree


_CACHE = {}
_TREES = {}
_TEMP_ROOTS = []


def scan_rows(files, state='ship'):
    """(basename, line, cwe) for an in-memory Python tree or a config document."""
    key = ('scan', state, tuple(sorted(files.items())))
    if key in _CACHE:
        return _CACHE[key]
    if any(not name.endswith('.py') for name in files):
        found = secret_scanner.audit_secret_files(dict(files))
        rows = sorted({(os.path.basename(row['file']), int(row['line']), row['cwe'])
                       for row in found})
    else:
        with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
            tracker = T(files=dict(files), max_workers=1)
            _, _, edges = tracker.analyze()
            rows = sorted({(os.path.basename(row['file']), int(row['line']), row['cwe'])
                           for row in cli._findings_for(tracker, edges)})
    _CACHE[key] = rows
    return rows


def _tree_dir(tree):
    """One materialised package per distinct tree, written once and removed by `main`."""
    key = tuple(sorted(tree.items()))
    if key not in _TREES:
        base = pathlib.Path(tempfile.mkdtemp(prefix='timecs_g65_'))
        _TEMP_ROOTS.append(base)
        for name, text in sorted(tree.items()):
            handle = base / name
            handle.parent.mkdir(parents=True, exist_ok=True)
            handle.write_text(text, encoding='utf-8')
        _TREES[key] = base
    return _TREES[key]


def scan_cross(tree, state='ship', root=''):
    """(caller basename, caller line, cwe) for a cross-file run over a real tree on disk."""
    key = ('cross', state, root, tuple(sorted(tree.items())))
    if key in _CACHE:
        return _CACHE[key]

    def run():
        base = _tree_dir(tree)
        target = base / root if root else base
        with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
            engine = CrossFileTaintEngine(str(target))
            return sorted({(os.path.basename(item.caller_file), int(item.caller_lineno), item.cwe)
                           for item in engine.run()})

    rows = _apply(() if state == 'ship' else ARMS[state], run)
    _CACHE[key] = rows
    return rows


def loud(rows, name, cwe, line):
    return (name, line, cwe) in rows


CASES = []


def case(pocket, label, cwe, name, line, expect, arm, arm_expect, source, note=''):
    """expect / arm_expect: 'loud' or 'quiet', before and after the pocket's own clause.

    `source` is {'files': ...} for the single-file and config readers, or {'tree': ..., 'root': ...}
    for the cross-file engine.
    """
    CASES.append({'pocket': pocket, 'label': label, 'source': source, 'cwe': cwe, 'name': name,
                  'line': line, 'expect': expect, 'arm': arm, 'arm_expect': arm_expect,
                  'note': note})


def rows_for(entry, state='ship'):
    source = entry['source']
    if 'tree' in source:
        return scan_cross(source['tree'], state, source.get('root', ''))
    return scan_rows(source['files'], state)


# --------------------------------------------------------------------------- fixtures
HELPER = module(
    'import subprocess',
    '',
    'def run(cmd):',
    '    return subprocess.check_output(cmd, shell=True)',
)
VIEWS = module(
    'import flask',
    'from helper import run',
    '',
    'def view():',
    "    data = flask.request.args['cmd']",
    '    return run(data)',
)
TEST_VIEWS = module(
    'import flask',
    'from helper import run',
    '',
    'def test_view():',
    "    data = flask.request.args['cmd']",
    '    return run(data)',
)
UTILS = module(
    'import flask',
    'from helper import run',
    '',
    'def scenario():',
    "    data = flask.request.args['cmd']",
    '    return run(data)',
)
TEST_ROOT_CALLER = module(
    'import flask',
    'from runner import exec_it',
    '',
    'def test_shell():',
    "    data = flask.request.args['cmd']",
    '    return exec_it(data)',
)
RUNNER = module(
    'import subprocess',
    '',
    'def exec_it(cmd):',
    '    return subprocess.check_output(cmd, shell=True)',
)
MIXIN = module(
    'import subprocess',
    '',
    'class Mix:',
    '    def assertEqual(self, first, second):',
    '        return subprocess.check_output(first, shell=True)',
)
ASSERT_CALLER = module(
    'import flask',
    'from mixin import Mix',
    '',
    'def view():',
    "    data = flask.request.args['cmd']",
    '    c = Mix()',
    '    out = c.assertEqual(data, "x")',
    '    return out',
)
P_ORJSON = module(
    'import orjson',
    '',
    'def to_obj(payload):',
    '    return orjson.loads(payload)',
)
P_JSON_IMPORTED = module(
    'from json import loads',
    '',
    'def to_obj(payload):',
    '    return loads(payload)',
)
P_PICKLE = module(
    'import pickle',
    '',
    'def to_obj(payload):',
    '    return pickle.loads(payload)',
)
P_YAML = module(
    'import yaml',
    '',
    'def to_obj(payload):',
    '    return yaml.load(payload)',
)
TAINTED_CALLER = module(
    'import flask',
    'from parser import to_obj',
    '',
    'def view():',
    "    data = flask.request.args['blob']",
    '    return to_obj(data)',
)
REVERSE = module(
    'from django.urls import reverse, reverse_lazy',
    'from django.http import HttpResponseRedirect',
    'from django.shortcuts import redirect',
    '',
    'class Profile:',
    '    def self_pk(self, request):',
    "        return redirect(reverse('home', args=[self.pk]))",
    '    def self_call(self, request):',
    "        return redirect(reverse('home', args=[self.get_pk()]))",
    '    def kwargs_route(self, request):',
    "        return redirect(reverse_lazy('token_home', kwargs={'pk': self.owner.id}))",
    '',
    'def dynamic_endpoint(request, view):',
    '    return HttpResponseRedirect(reverse(view))',
    '',
    'def client_argument(request):',
    "    return HttpResponseRedirect(reverse('home', args=[request.GET['x']]))",
    '',
    'def protocol_relative(request, host):',
    "    return redirect('//' + host + '/x')",
)
MIGRATION_SQL = module(
    'import django.db',
    '',
    'def run_sql(cursor, name):',
    "    sql = 'SELECT * FROM t WHERE n = %s' % name",
    '    cursor.execute(sql)',
)
MIGRATION_HASH = module(
    'import hashlib',
    '',
    'def stamp(token):',
    '    return hashlib.md5(token.encode()).hexdigest()',
)
SPEC_HEADER = module(
    'openapi: 3.0.3',
    'info:',
    '  title: Zulip API',
    'paths:',
    '  /users/me:',
    '    get:',
    '      responses:',
    '        "200":',
    '          content:',
    '            application/json:',
    '              example:',
    '                api_key: Z4nH7qR2tY8kP3wL9cB6vN1mX5',
)
SPEC_BY_NAME = module(
    'service:',
    '  api_key: Z4nH7qR2tY8kP3wL9cB6vN1mX5',
)
SPEC_WITHOUT_PATHS = module(
    'openapi: 3.0.3',
    'info:',
    '  title: t',
    '  api_key: Z4nH7qR2tY8kP3wL9cB6vN1mX5',
)
PRODUCTION_CONFIG = module(
    'token: AKIAZ3TRVBM7QK2LFHTD',
    '  api_key: Z4nH7qR2tY8kP3wL9cB6vN1mX5',
)

# --------------------------------------------------------------------------- C1: cross-file test surface
case('C1', 'production_chain_kept', 'CWE-78', 'views.py', at(VIEWS, 'return run(data)'),
     'loud', 'prune_off_arm', 'loud', {'tree': {'helper.py': HELPER, 'views.py': VIEWS}},
     'operator dataflow stays loud whether or not the pruning rule runs')
case('C1', 'test_dir_chain_pruned', 'CWE-78', 'test_views.py', at(TEST_VIEWS, 'return run(data)'),
     'quiet', 'prune_off_arm', 'loud',
     {'tree': {'helper.py': HELPER, 'tests/test_views.py': TEST_VIEWS}},
     'a test calling a helper is not a production chain')
case('C1', 'testutils_dir_chain_pruned', 'CWE-78', 'utils.py', at(UTILS, 'return run(data)'),
     'quiet', 'prune_off_arm', 'loud',
     {'tree': {'helper.py': HELPER, 'testutils/utils.py': UTILS}},
     'the whole cli directory vocabulary, not just the name tests')
case('C1', 'test_suffix_file_pruned', 'CWE-78', 'worker_test.py', at(UTILS, 'return run(data)'),
     'quiet', 'prune_off_arm', 'loud',
     {'tree': {'helper.py': HELPER, 'worker_test.py': UTILS}},
     '*_test.py at the repository root is still a test')
case('C1', 'operator_scans_test_tree', 'CWE-78', 'test_views.py',
     at(TEST_ROOT_CALLER, 'return exec_it(data)'), 'loud', 'prune_off_arm', 'loud',
     {'tree': {'tests/runner.py': RUNNER, 'tests/test_views.py': TEST_ROOT_CALLER},
      'root': 'tests'},
     'a test directory named on the command line is analysed in full')
case('C1', 'production_chain_blind_witness', 'CWE-78', 'views.py', at(VIEWS, 'return run(data)'),
     'loud', 'prune_blind_arm', 'quiet', {'tree': {'helper.py': HELPER, 'views.py': VIEWS}},
     'pruning every path is the false negative this rule must never become')

# --------------------------------------------------------------------------- C2: assertion contracts
case('C2', 'assertion_contract_dropped', 'CWE-78', 'views.py', at(ASSERT_CALLER, 'out = c.assertEqual'),
     'quiet', 'assertion_off_arm', 'loud',
     {'tree': {'mixin.py': MIXIN, 'views.py': ASSERT_CALLER}},
     'no contract is lifted onto an assertion argument')
case('C2', 'sink_inside_assertion_kept', 'CWE-78', 'mixin.py', at(MIXIN, 'subprocess.check_output'),
     'loud', 'assertion_off_arm', 'loud', {'files': {'mixin.py': MIXIN}},
     'the rule retires a contract, never a sink in a body')
case('C2', 'ordinary_helper_contract_kept', 'CWE-78', 'views.py', at(VIEWS, 'return run(data)'),
     'loud', 'assertion_blind_arm', 'quiet', {'tree': {'helper.py': HELPER, 'views.py': VIEWS}},
     'a name that is merely not in the assertion set keeps its contract')

# --------------------------------------------------------------------------- C3: JSON parsers
case('C3', 'orjson_contract_dropped', 'CWE-502', 'cviews.py',
     at(TAINTED_CALLER, 'return to_obj(data)'), 'quiet', 'json_modules_off_arm', 'loud',
     {'tree': {'parser.py': P_ORJSON, 'cviews.py': TAINTED_CALLER}},
     'orjson.loads builds values, not objects of an attacker-chosen class')
case('C3', 'imported_loads_dropped', 'CWE-502', 'cviews.py',
     at(TAINTED_CALLER, 'return to_obj(data)'), 'quiet', 'json_modules_off_arm', 'loud',
     {'tree': {'parser.py': P_JSON_IMPORTED, 'cviews.py': TAINTED_CALLER}},
     'from json import loads resolves through the binding, not the leaf')
case('C3', 'aliased_receiver_dropped', 'CWE-502', 'cviews.py',
     at(TAINTED_CALLER, 'return to_obj(data)'), 'quiet', 'json_modules_off_arm', 'loud',
     {'tree': {'parser.py': module('import orjson as oj', '', 'def to_obj(payload):',
                                   '    return oj.loads(payload)'),
                'cviews.py': TAINTED_CALLER}},
     'import orjson as oj is the same parser under a local name')
case('C3', 'pickle_kept', 'CWE-502', 'cviews.py', at(TAINTED_CALLER, 'return to_obj(data)'),
     'loud', 'json_modules_off_arm', 'loud',
     {'tree': {'parser.py': P_PICKLE, 'cviews.py': TAINTED_CALLER}},
     'the identical leaf, a genuinely unsafe deserializer')
case('C3', 'yaml_load_kept', 'CWE-502', 'cviews.py', at(TAINTED_CALLER, 'return to_obj(data)'),
     'loud', 'json_modules_off_arm', 'loud',
     {'tree': {'parser.py': P_YAML, 'cviews.py': TAINTED_CALLER}},
     'yaml.load without SafeLoader is not a JSON parser')
case('C3', 'pickle_blind_witness', 'CWE-502', 'cviews.py', at(TAINTED_CALLER, 'return to_obj(data)'),
     'loud', 'json_blind_arm', 'quiet',
     {'tree': {'parser.py': P_PICKLE, 'cviews.py': TAINTED_CALLER}},
     'a refusal that excused every loads is the FN this rule prevents')

# --------------------------------------------------------------------------- C4: django route builders
case('C4', 'self_pk_route_kept', 'CWE-601', 'r.py', at(REVERSE, 'reverse(\'home\', args=[self.pk])'),
     'loud', 'reverse_blind_arm', 'quiet', {'files': {'r.py': REVERSE}},
     'a literal endpoint does not excuse a client-supplied argument')
case('C4', 'dynamic_endpoint_kept', 'CWE-601', 'r.py', at(REVERSE, 'HttpResponseRedirect(reverse(view)')
     , 'loud', 'reverse_blind_arm', 'quiet', {'files': {'r.py': REVERSE}},
     'a non-constant endpoint cannot be proven internal')
case('C4', 'request_argument_kept', 'CWE-601', 'r.py',
     at(REVERSE, "reverse('home', args=[request.GET"), 'loud', 'reverse_blind_arm', 'quiet',
     {'files': {'r.py': REVERSE}}, 'query data in the route is client data')
case('C4', 'kwargs_route_kept', 'CWE-601', 'r.py',
     at(REVERSE, "reverse_lazy('token_home'"), 'loud', 'reverse_blind_arm', 'quiet',
     {'files': {'r.py': REVERSE}}, 'keyword route data is read like a positional argument')
case('C4', 'protocol_relative_kept', 'CWE-601', 'r.py',
     at(REVERSE, "redirect('//' + host"), 'loud', 'reverse_blind_arm', 'loud',
     {'files': {'r.py': REVERSE}}, 'the older same-origin clause owns the // anchor')
case('C4', 'literal_endpoint_emits_nothing', 'CWE-601', 'd.py', 7, 'quiet', 'reverse_off_arm', 'quiet',
     {'files': {'d.py': module('from django.urls import reverse',
                               'from django.shortcuts import redirect', '',
                               'class Profile:', '    def go(self, request):', '',
                               "        return redirect(reverse('home'))")}},
     'HEAD answer and shipped answer agree: the dynamism gate already retired this row')

# --------------------------------------------------------------------------- C5a: numbered migrations
_MIGRATION_DIR = 'zerver/migrations/'
case('C5', 'numbered_migration_sql_dropped', 'CWE-89', '0023_add_label.py',
     at(MIGRATION_SQL, 'cursor.execute(sql)'), 'quiet', 'migration_off_arm', 'loud',
     {'files': {_MIGRATION_DIR + '0023_add_label.py': MIGRATION_SQL}},
     'schema history ran once against a development database')
case('C5', 'numbered_migration_hash_dropped', 'CWE-328', '0024_stamp_token.py',
     at(MIGRATION_HASH, 'hashlib.md5'), 'quiet', 'migration_off_arm', 'loud',
     {'files': {_MIGRATION_DIR + '0024_stamp_token.py': MIGRATION_HASH}},
     'the same refusal covers CWE-328 in the same file shape')
case('C5', 'unnumbered_migration_kept', 'CWE-89', 'helpers.py', at(MIGRATION_SQL, 'cursor.execute(sql)'),
     'loud', 'migration_off_arm', 'loud', {'files': {_MIGRATION_DIR + 'helpers.py': MIGRATION_SQL}},
     'a module inside migrations/ is not a recorded schema version')
case('C5', 'short_number_migration_kept', 'CWE-89', '23_old.py', at(MIGRATION_SQL, 'cursor.execute(sql)'),
     'loud', 'migration_off_arm', 'loud', {'files': {_MIGRATION_DIR + '23_old.py': MIGRATION_SQL}},
     'four digits is Django-versioned, two is somebody elses file name')
case('C5', 'production_sql_kept', 'CWE-89', 'ops.py', at(MIGRATION_SQL, 'cursor.execute(sql)'),
     'loud', 'migration_blind_arm', 'quiet', {'files': {'zerver/lib/ops.py': MIGRATION_SQL}},
     'live surface keeps reporting and loses its row only when the rule is blinded')

# --------------------------------------------------------------------------- C5b: api specification documents
case('C5', 'spec_by_header_dropped', 'CWE-798', 'zulip.yaml',
     at(SPEC_HEADER, 'api_key: Z4nH7'), 'quiet', 'spec_off_arm', 'loud',
     {'files': {'zerver/openapi/zulip.yaml': SPEC_HEADER}},
     'openapi: with paths: is a contract, not a deployment')
case('C5', 'spec_by_filename_dropped', 'CWE-798', 'openapi.yml',
     at(SPEC_BY_NAME, 'api_key: Z4nH7'), 'quiet', 'spec_off_arm', 'loud',
     {'files': {'deploy/openapi.yml': SPEC_BY_NAME}}, 'the documents own name says specification')
case('C5', 'header_without_paths_kept', 'CWE-798', 'no_paths.yaml',
     at(SPEC_WITHOUT_PATHS, 'api_key: Z4nH7'), 'loud', 'spec_blind_arm', 'quiet',
     {'files': {'no_paths.yaml': SPEC_WITHOUT_PATHS}},
     'a version key alone is not a specification; a config can carry one')
case('C5', 'production_generic_key_kept', 'CWE-798', 'digitalocean.conf',
     at(PRODUCTION_CONFIG, 'api_key: Z4nH7'), 'loud', 'spec_blind_arm', 'quiet',
     {'files': {'digitalocean.conf': PRODUCTION_CONFIG}},
     'blinding the rule is what silences a real credential file')
case('C5', 'vendor_token_inside_spec_kept', 'CWE-798', 'openapi_secrets.yaml', 1,
     'loud', 'spec_blind_arm', 'loud',
     {'files': {'openapi_secrets.yaml': PRODUCTION_CONFIG}},
     'a vendor token proves its own shape and no document name silences it')

# --------------------------------------------------------------------------- clause registry
def _never(self, *args, **kwargs):
    return False


def _always(self, *args, **kwargs):
    return True


def _never_static(*args, **kwargs):
    return False


def _always_static(*args, **kwargs):
    return True


ARMS = {
    # C1: off = HEAD, the walk indexes every path; blind = the rule forced onto every path.
    'prune_off_arm': (('symbol_indexer', 'is_non_production_path', _never_static),),
    'prune_blind_arm': (('symbol_indexer', 'is_non_production_path', _always_static),),
    'prune_vocab_off_arm': (('symbol_indexer', 'NON_PRODUCTION_DIRS', frozenset()),),
    'prune_vocab_narrow_arm': (('symbol_indexer', 'NON_PRODUCTION_DIRS',
                                frozenset({'tests', 'test', '__tests__', 'fixtures'})),),
    # C2: off = no name is an assertion; blind = this helper is treated as one.
    'assertion_off_arm': (('function_summarizer', 'TEST_ASSERTION_METHODS', frozenset()),),
    'assertion_blind_arm': (('function_summarizer', 'TEST_ASSERTION_METHODS',
                             frozenset({'run'})),),
    # C3: off = no receiver is a JSON parser; blind = every receiver is one.
    'json_modules_off_arm': (('function_summarizer', 'JSON_PARSER_MODULES', frozenset()),),
    'json_leaf_off_arm': (('function_summarizer', 'JSON_LEAF_SINKS', frozenset()),),
    'json_narrow_arm': (('function_summarizer', 'JSON_PARSER_MODULES',
                         frozenset({'json', 'ujson', 'simplejson'})),),
    'json_blind_arm': (('FS', '_parses_json_only', _always),),
    # C4: off = HEAD (no reverse refusal at all); blind = every reverse is an internal route.
    'reverse_off_arm': (('T', '_c601_reverse_builds_an_internal_path', _never),),
    'reverse_blind_arm': (('T', '_c601_reverse_builds_an_internal_path', _always),),
    'reverse_name_off_arm': (('T', 'CWE601_REVERSE_BUILDERS', frozenset({'reverse'})),),
    # C5: the migration path rule and the specification rule, off and blinded.
    'migration_off_arm': (('T', '_file_is_numbered_django_migration', _never),),
    'migration_blind_arm': (('T', '_file_is_numbered_django_migration', _always),),
    'migration_loose_arm': (('T', 'NUMBERED_MIGRATION_PATH_RE',
                             re.compile(r'(?:^|/)migrations/\d{2}_[^/]*\.py$')),),
    'spec_off_arm': (('secret_scanner', '_is_api_specification_document', _never_static),),
    'spec_blind_arm': (('secret_scanner', '_is_api_specification_document', _always_static),),
    'spec_name_off_arm': (('secret_scanner', 'API_SPEC_NAME_MARKS', ()),),
    'spec_paths_off_arm': (('secret_scanner', 'API_SPEC_PATHS_RE', None),),
}


def _apply(patches, function):
    """Run one measurement with a weakening installed, then restore the shipped clause."""
    saved = []
    try:
        for owner, attribute, replacement in patches:
            target = OWNERS[owner]
            if not hasattr(target, attribute):
                raise AssertionError(f'no such clause: {owner}.{attribute}')
            saved.append((target, attribute, getattr(target, attribute)))
            setattr(target, attribute, replacement)
        return function()
    finally:
        for target, attribute, value in reversed(saved):
            setattr(target, attribute, value)


def case_rows(entry, state='ship'):
    key = ('rows', state, id(entry))
    if key not in _CACHE:
        _CACHE[key] = _apply(() if state == 'ship' else ARMS[state],
                             lambda: rows_for(entry, state))
    return _CACHE[key]


def check_retirements():
    """TIER 1 -- every pocket: the shipped verdict and the verdict with its own clause reverted."""
    failures = []
    for pocket in sorted({entry['pocket'] for entry in CASES}):
        print(f'\nTIER 1  {pocket}')
        for entry in [e for e in CASES if e['pocket'] == pocket]:
            shipped = case_rows(entry)
            reverted = case_rows(entry, entry['arm'])
            now = 'loud' if loud(shipped, entry['name'], entry['cwe'], entry['line']) else 'quiet'
            arm = 'loud' if loud(reverted, entry['name'], entry['cwe'], entry['line']) else 'quiet'
            booked = (entry['expect'], arm) == ('quiet', 'loud')
            closer = (entry['expect'], arm) == ('loud', 'quiet')
            control = entry['expect'] == 'loud' and arm == 'loud'
            receipt = ('BOOKED' if booked else ('FN-CLOSER' if closer
                                                else ('CONTROL' if control else 'not booked')))
            print(f'  {now:5s} arm={arm:5s} {receipt:11s} {entry["label"]:32s} {entry["note"][:46]}')
            if now != entry['expect']:
                failures.append(f'{pocket}/{entry["label"]}: shipped {now}, want {entry["expect"]}')
            if arm != entry['arm_expect']:
                failures.append(f'{pocket}/{entry["label"]}: arm-off {arm}, want {entry["arm_expect"]}')
    return failures


# --------------------------------------------------------------------------- TIER 2 predicates
def _binding(source_module, imported_name=''):
    return types.SimpleNamespace(source_module=source_module, imported_name=imported_name)


def _summarizer_with(imports):
    """A summariser whose only need is one module's import table, so the rule can be called directly."""
    summarizer = FS.__new__(FS)
    summarizer.indexer = types.SimpleNamespace(
        modules={'m': types.SimpleNamespace(imports=imports)})
    return summarizer


def _parses(source, imports):
    node = ast.parse(source).body[0].value
    return _summarizer_with(imports)._parses_json_only(node.func, 'm')


def _call_named(source, name, leaves):
    tree = link(ast.parse(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name != name:
            continue
        if isinstance(node, ast.FunctionDef):
            for call in ast.walk(node):
                if isinstance(call, ast.Call):
                    leaf = (call.func.id if isinstance(call.func, ast.Name)
                            else getattr(call.func, 'attr', ''))
                    if leaf in leaves:
                        return call
    raise AssertionError(f'no {sorted(leaves)} call in {name}')


PROBES = {}


def probe(name, description):
    def register(function):
        PROBES[name] = (description, function)
        return function
    return register


@probe('c1_directory_vocabulary', 'all six mandated directories, and nothing that merely looks like one')
def _():
    def flagged(*segments):
        root = pathlib.PurePosixPath(*segments[:-2])
        return symbol_indexer.is_non_production_path(pathlib.PurePosixPath(*segments), root)
    return (all(flagged('repo', name, 'chain.py')
                for name in ('tests', 'test', '__tests__', 'testutils', 'fixtures', 'examples',
                             'example', 'samples', 'debug'))
            and not flagged('repo', 'latest', 'chain.py')
            and not flagged('repo', 'testing', 'chain.py')
            and not flagged('repo', 'debugger', 'chain.py'))


@probe('c1_filename_patterns', 'test_*.py and *_test.py are tests wherever the walk meets them')
def _():
    root = pathlib.PurePosixPath('/repo')
    return (symbol_indexer.is_non_production_path(pathlib.PurePosixPath('/repo/test_chain.py'), root)
            and symbol_indexer.is_non_production_path(pathlib.PurePosixPath('/repo/chain_test.py'), root)
            and not symbol_indexer.is_non_production_path(
                pathlib.PurePosixPath('/repo/attest.py'), root)
            and not symbol_indexer.is_non_production_path(
                pathlib.PurePosixPath('/repo/contest.py'), root))


@probe('c1_root_named_by_operator_is_kept', 'a test directory named on the command line is not foreign')
def _():
    root = pathlib.PurePosixPath('/repo/tests')
    return (not symbol_indexer.is_non_production_path(
                pathlib.PurePosixPath('/repo/tests/test_chain.py'), root)
            and not symbol_indexer.is_non_production_path(
                pathlib.PurePosixPath('/repo/tests/nested/test_chain.py'), root))


@probe('c1_mirrors_the_cli_vocabulary', 'the engine prunes exactly the directories cli.py prunes')
def _():
    return (frozenset(symbol_indexer.NON_PRODUCTION_DIRS) == frozenset(cli.NON_PRODUCTION_DIRS)
            and symbol_indexer.NON_PRODUCTION_PREFIXES == ('test_',)
            and symbol_indexer.NON_PRODUCTION_SUFFIXES == ('_test.py',))


@probe('c2_assertion_names_cover_the_mandate',
       'the seven mandated comparison names plus pytest.raises are all in the set')
def _():
    return frozenset({'assertEqual', 'assertNotEqual', 'assertIn', 'assertTrue', 'assertFalse',
                      'assertRaises', 'raises'}).issubset(
        function_summarizer.TEST_ASSERTION_METHODS)


@probe('c3_json_parser_vocabulary', 'four JSON parsers, and none of the unsafe leaves')
def _():
    return (frozenset({'json', 'orjson', 'ujson', 'simplejson'})
            == function_summarizer.JSON_PARSER_MODULES
            and not frozenset({'pickle', 'dill', 'marshal', 'yaml', 'jsonpickle'})
            & function_summarizer.JSON_PARSER_MODULES
            and function_summarizer.JSON_LEAF_SINKS.issubset(
                frozenset(function_summarizer.KNOWN_SINKS)))


@probe('c3_receiver_resolves_through_imports',
       'aliased and imported receivers resolve, unsafe and unresolvable receivers do not')
def _():
    return (_parses('orjson.loads(payload)', {'orjson': _binding('orjson')})
            and _parses('oj.loads(payload)', {'oj': _binding('orjson')})
            and _parses('ujson.load(payload)', {'ujson': _binding('ujson')})
            and _parses('loads(payload)', {'loads': _binding('json', 'loads')})
            and not _parses('pickle.loads(payload)', {'pickle': _binding('pickle')})
            and not _parses('loads(payload)', {'loads': _binding('pickle', 'loads')})
            and not _parses('yaml.load(payload)', {'yaml': _binding('yaml')})
            and not _parses('orjson.loads(payload)', {}))


@probe('c3_sink_table_untouched', 'the mandated dangerous leaves still answer CWE-502')
def _():
    table = function_summarizer.KNOWN_SINKS
    return (table['loads'] == 'CWE-502' and table['load'] == 'CWE-502'
            and table['open'] == 'CWE-22' and table['check_output'] == 'CWE-78')


@probe('c4_reverse_predicate_needs_a_constant_and_clean_arguments',
       'literal endpoint plus no client data is the only answer that excuses a route')
def _():
    predicate = T._c601_reverse_builds_an_internal_path
    literal = _call_named(REVERSE, 'self_pk', {'reverse'})
    dynamic = _call_named(REVERSE, 'dynamic_endpoint', {'reverse'})
    lazy = _call_named(REVERSE, 'kwargs_route', {'reverse_lazy'})
    return (predicate(None, literal, [False]) is True
            and predicate(None, literal, [True]) is False
            and predicate(None, dynamic, [False]) is False
            and predicate(None, lazy, [False, False]) is True
            and predicate(None, lazy, [False, True]) is False)


@probe('c4_reverse_builders_are_the_two_django_names', 'only reverse and reverse_lazy are route builders')
def _():
    return (frozenset({'reverse', 'reverse_lazy'}) == T.CWE601_REVERSE_BUILDERS
            and 'url_for' not in T.CWE601_REVERSE_BUILDERS
            and 'redirect' not in T.CWE601_REVERSE_BUILDERS)


@probe('c5_migration_paths_are_four_digits_under_migrations',
       'Django 0023_x.py and Odoo 9.0.1.2/pre-x.py qualify, helpers.py, 23_x.py, a phase-less Odoo '
       'helper and a production file do not')
def _():
    verdict = T._file_is_numbered_django_migration
    # The predicate reads both generated-script spellings off `self`, so the stub reader has to carry
    # both: the Django `migrations/0235_x.py` stamp and the Odoo `migrations/9.0.1.2/pre-x.py` one.
    reader = types.SimpleNamespace(NUMBERED_MIGRATION_PATH_RE=T.NUMBERED_MIGRATION_PATH_RE,
                                   ODOO_VERSIONED_MIGRATION_PATH_RE=T.ODOO_VERSIONED_MIGRATION_PATH_RE)
    return (verdict(reader, 'zerver/migrations/0023_add_label.py')
            and verdict(reader, 'zerver\\migrations\\0100_squashed.py')
            and not verdict(reader, 'zerver/migrations/helpers.py')
            and not verdict(reader, 'zerver/migrations/23_old.py')
            and not verdict(reader, 'zerver/migrations/12345_old.py.bak')
            and not verdict(reader, 'zerver/lib/ops.py')
            and not verdict(reader, 'zerver/notmigrations/0023_add.py')
            and verdict(reader, 'addons/purchase/migrations/9.0.1.2/pre-create-properties.py')
            and verdict(reader, 'addons\\sale\\upgrades\\12.0.1.0\\post-migrate.py')
            and not verdict(reader, 'addons/purchase/migrations/9.0.1.2/helpers.py'))


@probe('c5_spec_documents_by_name_and_header', 'the name or the two specification keys identify a spec')
def _():
    verdict = secret_scanner._is_api_specification_document
    return (verdict('deploy/openapi.yml', SPEC_BY_NAME)
            and verdict('deploy/swagger.json', '{}')
            and verdict('zerver/openapi/zulip.yaml', SPEC_HEADER)
            and verdict('some.conf', SPEC_HEADER)
            and not verdict('some.conf', SPEC_WITHOUT_PATHS)
            and not verdict('digitalocean.conf', PRODUCTION_CONFIG)
            and not verdict('openapi_notes.txt', ''))


@probe('c5_spec_scan_is_bounded', 'a large config is never re-read in full looking for shape')
def _():
    return (secret_scanner.API_SPEC_VERSION_HEAD_BYTES == 512
            and secret_scanner.API_SPEC_PATH_SCAN_BYTES == 65536
            and len(SPEC_HEADER) < secret_scanner.API_SPEC_PATH_SCAN_BYTES)


def probe_value(name, state='ship'):
    key = ('probe', state, name)
    if key not in _CACHE:
        try:
            _CACHE[key] = _apply(() if state == 'ship' else ARMS[state], PROBES[name][1])
        except Exception as error:
            _CACHE[key] = f'error: {type(error).__name__}: {error}'
    return _CACHE[key]


def check_predicates():
    print('\nTIER 2  predicate contracts, called directly')
    failures = []
    for name in sorted(PROBES):
        description, function = PROBES[name]
        try:
            ok = function() is True
        except Exception as error:
            ok = False
            description += f'  [{type(error).__name__}: {error}]'
        print(f'  {"OK  " if ok else "FAIL"} {name:44s} {description}')
        if not ok:
            failures.append(f'predicate {name}: {description}')
    return failures


# --------------------------------------------------------------------------- TIER 3 shipped shapes
_PIPELINE = inspect.getsource(T._analyze_pipeline)

LAWS = (
    ('C1 the walk asks the rule before it asks the resolver',
     lambda: 'is_non_production_path(full_p, self.root_dir)'
             in inspect.getsource(symbol_indexer.GlobalSymbolIndex.build)),
    ('C1 a tree the scanner already analysed is never dropped',
     lambda: 'and not (reuse_trees and str(full_p) in reuse_trees))'
             in inspect.getsource(symbol_indexer.GlobalSymbolIndex.build)),
    ('C1 pruning is one flag off two engines, not a path blacklist',
     lambda: 'prune_non_production: bool = True'
             in inspect.getsource(symbol_indexer.GlobalSymbolIndex.__init__)
             and 'prune_non_production=prune_non_production'
             in inspect.getsource(CrossFileTaintEngine.__init__)),
    ('C2 an assertion returns before any contract is read off its body',
     lambda: 0 <= inspect.getsource(FS._summarize_function).find('if node.name in '
                                                                 'TEST_ASSERTION_METHODS:')
             < inspect.getsource(FS._summarize_function).find('KNOWN_SINKS.get(call_name)')),
    ('C3 the JSON refusal is guarded by the CWE it refuses',
     lambda: 'if cwe == "CWE-502" and call_name in JSON_LEAF_SINKS:'
             in inspect.getsource(FS._summarize_function)
             and 'self._parses_json_only(sub.func, mod_name)'
             in inspect.getsource(FS._summarize_function)),
    ('C3 an unresolvable receiver stays a sink',
     lambda: 'if not bindings:' in inspect.getsource(FS._parses_json_only)
             and 'return False' in inspect.getsource(FS._parses_json_only)),
    ('C4 the endpoint has to be a constant and every argument clean',
     lambda: 'isinstance(endpoint, ast.Constant)'
             in inspect.getsource(T._c601_reverse_builds_an_internal_path)
             and 'return not any(args_read_client_input)'
             in inspect.getsource(T._c601_reverse_builds_an_internal_path)),
    ('C4 the redirect emitter asks the builder instead of falling through',
     lambda: '_reverse_builds_an_internal_path(expr, scope_id, lineno)'
             in inspect.getsource(T._collect_phase8_structural_findings)
             and 'CWE601_REVERSE_BUILDERS'
             in inspect.getsource(T._collect_phase8_structural_findings)),
    ('C5 the migration refusal sits above the synthetic-source shortcuts',
     lambda: 0 <= _PIPELINE.find('_file_is_numbered_django_migration(')
             < _PIPELINE.find('p10_source_id')),
    ('C5 the refusal names the two CWEs it covers and drops the sink',
     lambda: 'if cwe in ("CWE-89", "CWE-328")' in _PIPELINE
             and 'self.sinks.remove(sink)' in _PIPELINE),
    ('C5 four digits is the whole version rule',
     lambda: r'migrations/\d{4}_' in inspect.getsource(ast_scanner)
             and r'migrations/\d+' not in inspect.getsource(ast_scanner)),
    ('C5 the document verdict is computed once per file, not once per hit',
     lambda: len([line for line in inspect.getsource(secret_scanner.audit_secret_files).splitlines()
                  if '_is_api_specification_document(file_path' in line]) == 1),
    ('C5 the specification refusal reaches only the generic branch',
     lambda: 'kind == "generic" and generic_candidate_refused'
             in inspect.getsource(secret_scanner.audit_secret_files)),
    ('C5 the header needs both keys and bounded reading',
     lambda: 'text[:API_SPEC_VERSION_HEAD_BYTES]'
             in inspect.getsource(secret_scanner._is_api_specification_document)
             and 'API_SPEC_PATHS_RE.search'
             in inspect.getsource(secret_scanner._is_api_specification_document)),
)


def check_laws():
    print('\nTIER 3  the shipped source keeps each shape')
    failures = []
    for label, law in LAWS:
        try:
            ok = bool(law())
        except Exception as error:
            ok = False
            label = f'{label}  [{type(error).__name__}: {error}]'
        print(f'  {"OK  " if ok else "FAIL"} {label}')
        if not ok:
            failures.append(label)
    return failures


# --------------------------------------------------------------------------- TIER 4 falsifiers
MUTATIONS = {
    'c1_pruning_switched_off': (
        'C1: the walk stops asking the rule, which is what HEAD shipped -- every test chain returns',
        'prune_off_arm',
        ['test_dir_chain_pruned', 'testutils_dir_chain_pruned', 'test_suffix_file_pruned'],
        ['c1_directory_vocabulary', 'c1_filename_patterns']),
    'c1_directory_vocabulary_narrowed': (
        'C1: the vocabulary loses testutils/debug/examples, so those chains report again',
        'prune_vocab_narrow_arm',
        ['testutils_dir_chain_pruned'],
        ['c1_directory_vocabulary', 'c1_mirrors_the_cli_vocabulary']),
    'c1_pruning_blinded': (
        'C1: every path is non-production, so the production chain loses its finding',
        'prune_blind_arm',
        ['production_chain_kept', 'production_chain_blind_witness', 'ordinary_helper_contract_kept',
         'operator_scans_test_tree', 'pickle_kept', 'yaml_load_kept', 'pickle_blind_witness'],
        ['c1_directory_vocabulary', 'c1_filename_patterns', 'c1_root_named_by_operator_is_kept']),
    'c2_assertion_set_emptied': (
        'C2: no method is an assertion, so the lifted contract on the comparison call comes back',
        'assertion_off_arm',
        ['assertion_contract_dropped'],
        ['c2_assertion_names_cover_the_mandate']),
    'c3_json_vocabulary_emptied': (
        'C3: no receiver is a JSON parser, so the three parser shapes report again',
        'json_modules_off_arm',
        ['orjson_contract_dropped', 'imported_loads_dropped', 'aliased_receiver_dropped'],
        ['c3_json_parser_vocabulary', 'c3_receiver_resolves_through_imports']),
    'c3_json_vocabulary_narrowed': (
        'C3: orjson drops out of the vocabulary, so its contract returns while json stays quiet',
        'json_narrow_arm',
        ['orjson_contract_dropped', 'aliased_receiver_dropped'],
        ['c3_json_parser_vocabulary', 'c3_receiver_resolves_through_imports']),
    'c3_leaf_set_emptied': (
        'C3: the leaf guard stops matching, so the imported-loads proof stops being reached',
        'json_leaf_off_arm',
        ['imported_loads_dropped', 'orjson_contract_dropped', 'aliased_receiver_dropped'],
        ['c3_receiver_resolves_through_imports']),
    'c3_refusal_blinded': (
        'C3: every loads is treated as JSON, so pickle and yaml lose their deserialization row',
        'json_blind_arm',
        ['pickle_kept', 'yaml_load_kept', 'pickle_blind_witness'],
        ['c3_receiver_resolves_through_imports']),
    'c4_reverse_exemption_blinded': (
        'C4: every reverse is an internal route, so the five client-shaped destinations go quiet',
        'reverse_blind_arm',
        ['self_pk_route_kept', 'dynamic_endpoint_kept', 'request_argument_kept', 'kwargs_route_kept'],
        ['c4_reverse_predicate_needs_a_constant_and_clean_arguments']),
    'c5_migration_rule_removed': (
        'C5: a numbered migration is just a file again, so the recorded schema history reports',
        'migration_off_arm',
        ['numbered_migration_sql_dropped', 'numbered_migration_hash_dropped'],
        ['c5_migration_paths_are_four_digits_under_migrations']),
    'c5_migration_rule_blinded': (
        'C5: every file is migration history, so the recorded schema files and live SQL go quiet',
        'migration_blind_arm',
        ['unnumbered_migration_kept', 'short_number_migration_kept', 'production_sql_kept'],
        ['c5_migration_paths_are_four_digits_under_migrations']),
    'c5_migration_digits_loosened': (
        'C5: two digits replaces four, so the hand-named file is excused and the versioned ones are not',
        'migration_loose_arm',
        ['numbered_migration_sql_dropped', 'numbered_migration_hash_dropped',
         'short_number_migration_kept'],
        ['c5_migration_paths_are_four_digits_under_migrations']),
    'c5_spec_rule_removed': (
        'C5: a specification is an ordinary config file, so its sample credentials report',
        'spec_off_arm',
        ['spec_by_header_dropped', 'spec_by_filename_dropped'],
        ['c5_spec_documents_by_name_and_header']),
    'c5_spec_names_removed': (
        'C5: the file name stops identifying a specification, so only the header pair still refuses',
        'spec_name_off_arm',
        ['spec_by_filename_dropped'],
        ['c5_spec_documents_by_name_and_header']),
    'c5_spec_rule_blinded': (
        'C5: every document is a specification, so the production credential file goes quiet',
        'spec_blind_arm',
        ['header_without_paths_kept', 'production_generic_key_kept'],
        ['c5_spec_documents_by_name_and_header']),
}


def run_mutation(name):
    """Weaken one clause and report every row and predicate that moved.

    The baseline is read BEFORE the weakening is installed; reading it afterwards compares the mutated
    gate with itself and reports every mutation as MISSED. `moved` is the full set of changes rather
    than a filtered one, so a clause that reaches into another pocket shows up as an extra label
    instead of passing unnoticed.
    """
    description, state, expected_rows, expected_probes = MUTATIONS[name]
    moved = [entry['label'] for entry in CASES
             if loud(case_rows(entry), entry['name'], entry['cwe'], entry['line'])
             != loud(case_rows(entry, state), entry['name'], entry['cwe'], entry['line'])]
    flipped = [key for key in sorted(PROBES)
               if (probe_value(key) is True) != (probe_value(key, state) is True)]
    return description, moved, flipped, expected_rows, expected_probes


def check_mutations(only=None):
    print()
    print('TIER 4  falsifiers (one weakening per clause)')
    failures = []
    for name in sorted(MUTATIONS):
        if only and name != only:
            continue
        started = time.perf_counter()
        description, moved, flipped, expected_rows, expected_probes = run_mutation(name)
        elapsed = time.perf_counter() - started
        ok = (sorted(moved) == sorted(expected_rows)
              and sorted(flipped) == sorted(expected_probes))
        print(f'  {"CAUGHT" if ok else "MISSED"} {name:32s} rows={moved} probes={flipped} '
              f'({elapsed:.2f}s)')
        if not ok:
            failures.append(f'{name}: want rows {sorted(expected_rows)} probes '
                            f'{sorted(expected_probes)}, moved {sorted(moved)} '
                            f'flipped {sorted(flipped)}')
        if elapsed > BUDGET_MUTATION_SECONDS:
            failures.append(f'{name}: took {elapsed:.2f}s (budget {BUDGET_MUTATION_SECONDS}s)')
    return failures


def rss_mb():
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None
    if sys.platform != 'win32':
        return None

    class Counter(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD),
                    ('PeakWorkingSetSize', ctypes.c_size_t),
                    ('WorkingSetSize', ctypes.c_size_t),
                    ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                    ('PagefileUsage', ctypes.c_size_t),
                    ('PeakPagefileUsage', ctypes.c_size_t)]

    counter = Counter()
    counter.cb = ctypes.sizeof(counter)
    get_memory = ctypes.windll.psapi.GetProcessMemoryInfo
    # argtypes is load-bearing: without it the -1 pseudo-handle is passed as a 32-bit int into a 64-bit
    # slot, the upper half is garbage, and the call answers ERROR_INVALID_HANDLE.
    get_memory.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counter), wintypes.DWORD]
    get_memory.restype = wintypes.BOOL
    if not get_memory(wintypes.HANDLE(-1), ctypes.byref(counter), counter.cb):
        return None
    return counter.PeakWorkingSetSize / 1048576.0


def dump():
    for entry in CASES:
        print(f'\n=== {entry["pocket"]} {entry["label"]} expect={entry["expect"]}')
        for row in case_rows(entry):
            print('   ', row)


def _cleanup_trees():
    for path in _TEMP_ROOTS:
        shutil.rmtree(path, ignore_errors=True)
    _TEMP_ROOTS.clear()


def main():
    argv = sys.argv[1:]
    only = next((a.split('=', 1)[1] for a in argv if a.startswith('--mutate=')), None)
    if only and only not in MUTATIONS:
        print(f'unknown mutation {only}; known: {sorted(MUTATIONS)}')
        return 2
    started = time.perf_counter()
    failures = []
    try:
        if '--dump' in argv:
            dump()
            return 0
        if not only:
            failures += check_retirements()
            failures += check_predicates()
            failures += check_laws()
        failures += check_mutations(only)
    finally:
        _cleanup_trees()
    work = time.perf_counter() - started
    peak = rss_mb()
    total = len(CASES)
    booked = sum(1 for entry in CASES if entry['expect'] == 'quiet' and entry['arm_expect'] == 'loud')
    loud_cases = sum(1 for entry in CASES if entry['expect'] == 'loud')
    print(f'\ncases={total} clause_retirements={booked} expected_loud={loud_cases} '
          f'probes={len(PROBES)} mutations={len(MUTATIONS) if not only else 1} '
          f'work={work:.2f}s (budget {BUDGET_SECONDS}s) peak_rss='
          + ('n/a' if peak is None else f'{peak:.1f} MB')
          + f' (budget {BUDGET_RSS_MB:.0f} MB)')
    if work > BUDGET_SECONDS:
        failures.append(f'work {work:.2f}s over budget')
    if peak is not None and peak > BUDGET_RSS_MB:
        failures.append(f'peak RSS {peak:.1f} MB over budget')
    for failure in failures:
        print(f'  FAILURE {failure}')
    print('VERDICT: ' + ('PASS' if not failures else 'FAIL'))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
