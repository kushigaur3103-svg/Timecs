"""Sentry tier-3 precision lock: 4 provenance patterns, 4 loud counterparts, gate #54.

    python benchmark/gates/sentry_tier3_precision_probe.py
    python benchmark/gates/sentry_tier3_precision_probe.py --dump
    python benchmark/gates/sentry_tier3_precision_probe.py --mutation <name>

WHY THIS GATE EXISTS
The Sentry cloud run on `6171288` finished clean -- 103.78s, 636 findings, down from 1,755 -> 997 ->
636, all 23/23 cross-file chains intact -- and the residue clustered into four shapes the engine
mis-reads. Every one of them is a NAME collision that only the file's own provenance can settle:

  1. `snuba_sdk.Request` charged as CWE-918 SSRF (`api/endpoints/group_hashes_split.py:172, 402`).
     `Request` is the ClickHouse query object (app / selected_columns / conditions / offset / limit);
     `urllib.request.Request`, `requests.Request` and `httpx.Request` carry a URL this process is
     about to fetch, which is what CWE-918 is about.
  2. `manager.UpdateChannel.choices` charged as CWE-338 (`models/options/option.py:40`). A Django
     `Choices`/`ChoiceSet` member read through a module-or-class chain, whose tail this module
     imported -- not `random.choices(...)` and not a method on a `Random` instance.
  3. `hashlib.md5(...)` charged as CWE-328 in sharding, palette, dedup and grouping helpers
     (`utils/colors.py:6`, `performance_issues/detectors/*.py`, `tsdb/redis.py:201`,
     `replays/lib/event_linking.py:141`) -- deterministic bucket arithmetic that indexes something
     instead of protecting something.
  4. `src/sentry/web/frontend/debug/` -- developer-preview views that render sample payloads and are
     not shipped surface, which the default directory walk holds back the way it already holds back
     `tests/`, `testutils/`, `fixtures/`, `examples/` and `samples/`.

Everything the ENGINE suppresses is decided on a fact inside the file being scanned: its import table,
the receiver path a call was written on, the name a value is stored under. No directory, filename or
project name is consulted there, and that is a checked law, not a promise. Item 4 is the one
DISCOVERY-scope choice, owned by `cli.py`, announced in the report and reversed by `--include-tests`
or by naming the path -- the engine still reports every row inside a file it is given.

WHAT IS LOCKED
TIER 1  the four new predicates, called directly with the shapes that crash careless guards: a call
        with no arguments, a keyword-only call, a callee that will not name (`REGISTRY["Request"]`), a
        receiver that is a literal or a call, a module name that is not loaded, an empty string, a
        node with no parent links. Each must ANSWER its documented type without raising -- and answer
        "stay loud", because none of those shapes carries proof.
TIER 2  the shipped verdicts over one shared scan (`--dump` reprints them): the four quiet shapes
        report nothing on the lines that used to charge, the four loud counterparts keep every line,
        `random.Random()` and the unresolved receivers stay charged, and the credential inputs
        (`api_key`, `session_id`, `password`) keep their CWE-328 row even beside the widened bucket
        vocabulary -- with CWE-759/CWE-916 untouched on the password digest.
TIER 3  the discovery contract `cli.py` owns, measured with three real in-process `cli.main` scans of
        a temp tree: a default scan prunes `web/frontend/debug/` and says so in the report,
        `--include-tests` reports the same file, pointing at the directory reports it, and pruning a
        different name (`tests/`) is unaffected.
TIER 4  source laws: the CWE-918 guard is asked twice -- on the report path, where a CWE-918 row is
        actually made (measured: with only the registration prune the FP survives), and at
        registration, before `self.sinks.append` -- and no new helper consults a filesystem path, the
        bucket vocabulary is referenced only by the CWE-328 helpers so it cannot leak into
        CWE-327/CWE-338, the routing-key demotion fires only when `key` is the sole security word,
        the `.choices` guard is keyed on the `choices` leaf and refuses a `self`/`cls` receiver or a
        bare name, and `debug/` is both in the prune set and in the note.
TIER 5  budgets -- a precision lock that is slow or heavy never gets run.

Falsification: `--mutation <name>` changes what the shipped pipeline reads (a table, a bound method)
and exits 1 unless the mutation moves exactly the rows the spec names, inside the 2s a falsifier is
allowed to cost. Each falsifier re-scans its fixtures one at a time, each under a module stem of its
own: the engine resolves an imported name once per scan, so two fixtures that spell the same sink
(`Request`) in one subset let `urllib.request`'s table answer for `snuba_sdk`'s, and one guard measured
inert that way before the scans were isolated. No mutation recompiles engine source: `aa_parity` scans
`benchmark/`, so a live `exec(compile(text))` in a gate is a CWE-95 row the engine is right to report
and the 425-key baseline is not this gate's to move.
"""
from __future__ import annotations

import ast
import collections
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402

TT = ast_scanner.TaintTracker
dotted_name = ast_scanner.dotted_name

# The budget covers gate work only: importing `ast_scanner` and `cli` is a fixed cost the engine
# charges every tool in the suite, and a cold-disk or antivirus stall on those two files must not
# read as this gate losing its own plot. The tight number is the one the brief asks for and the one
# that means anything: no single falsifier may cost more than 2s to prove its guard live. The whole
# gate gets 15s, because six falsifiers each pay a fresh tracker build (the isolated stems are what
# make them honest) plus four in-process `cli.main` discovery scans -- measured 6-11s on this laptop,
# against gate #52's 7.2s envelope.
WORK_START = time.time()
BUDGET_SECONDS = 15.0
BUDGET_MUTATION_SECONDS = 2.0
BUDGET_RSS_MB = 60.0

FAILS = []


def fail(what, msg):
    FAILS.append('%s: %s' % (what, msg))


# ─── fixtures: the four quiet shapes and their loud counterparts ───────────────────────────────
SNUBA_REQUEST = '''from snuba_sdk import Column, Condition, Op, Request


def load_events(request):
    offset = int(request.GET["offset"])
    query = Request(app="events", selected_columns=[Column("event_id")],
                    conditions=[Condition("project_id", Op.EQ, 1)], offset=offset)
    return runner.execute(query)


def tunnel(request):
    return Request(app="events", url=request.GET["url"])
'''
SNUBA_QUALIFIED = '''import snuba_sdk


def build(request):
    return snuba_sdk.Request(app="errors", url=request.GET["url"], limit=50)
'''
SSRF_LOUD = '''from urllib.request import Request, urlopen

import httpx
import requests


def fetch(request):
    req = Request(request.GET["url"])
    return urlopen(req)


def clients(request):
    legacy = requests.Request("GET", request.GET["url"])
    modern = httpx.Request("GET", request.GET["url"])
    return requests.get(legacy.url), httpx.get(modern.url)
'''
MODEL_CHOICES = '''from sentry.conf.types.update_option_types import UpdateChannel


class Option:
    @staticmethod
    def channel_labels(manager, channel):
        pairs = manager.UpdateChannel.choices()
        labels = dict(UpdateChannel.choices)
        return [text for text, _label in channel.choices] + list(labels) + list(pairs)

    def bare_imported_class(self):
        return UpdateChannel.choices(3)
'''
PRNG_CHOICES = '''import random


def pick(alphabet):
    return random.choices(alphabet, k=4)


def seeded_pick(alphabet):
    rng = random.Random()
    return rng.choices(alphabet, k=4)


def unproven(store, n):
    return store.choices(n)


class Widget:
    def choose(self, n):
        return self.choices(n)
'''
SHARD_HASH = '''import hashlib


def shard_index(shard_key):
    return int(hashlib.md5(shard_key.encode()).hexdigest(), 16) % 64


def get_palette_rgb(text):
    digest = hashlib.md5(text.encode()).hexdigest()[:6]
    return int(digest, 16)


def dedup_grouping(event_id):
    return hashlib.md5(event_id.encode()).hexdigest()


def grouping_fingerprint(grouping_key, project_id):
    return hashlib.md5(grouping_key.encode()).hexdigest()
'''
WEAK_HASH_LOUD = '''import hashlib


def api_key_checksum(api_key):
    return hashlib.md5(api_key).hexdigest()


def session_partition(session_id):
    return hashlib.md5(session_id.encode()).hexdigest()


def grouping_dedup(password):
    issue_hash = hashlib.md5(password.encode()).hexdigest()
    return issue_hash
'''
DEBUG_PREVIEW = '''import subprocess


def render(request):
    return subprocess.run("echo " + request.GET["cmd"], shell=True)
'''

FIXTURES = {
    'snuba_request.py': SNUBA_REQUEST,
    'snuba_qualified.py': SNUBA_QUALIFIED,
    'ssrf_loud.py': SSRF_LOUD,
    'model_choices.py': MODEL_CHOICES,
    'prng_choices.py': PRNG_CHOICES,
    'shard_hash.py': SHARD_HASH,
    'weak_hash_loud.py': WEAK_HASH_LOUD,
    'debug_preview.py': DEBUG_PREVIEW,
}

# `loud` -- lines the engine reports today and must keep reporting; `quiet` -- lines that charged
# before these guards existed. The annotation names the falsifier that moves the row in `--mutation`
# mode, or says in words why no row-movement can name it: a row the shipped engine never charged on
# its own is held by the predicate table in TIER 1, and a row held by some other guard is not this
# guard's evidence. Locking an accident is worse than locking nothing, so every claim here is measured.
BLESSED = {
    'snuba_request.py': {'loud': {}, 'quiet': {('CWE-918', 12): 'request_provenance_never_prunes'}},
    'snuba_qualified.py': {'loud': {},
                           'quiet': {('CWE-918', 5): 'request_provenance_never_prunes'}},
    'ssrf_loud.py': {'loud': {('CWE-918', 8): None,
                              ('CWE-918', 9): None,
                              ('CWE-918', 13): None,
                              ('CWE-918', 14): None,
                              ('CWE-918', 15): None,
                              ('CWE-939', 9): None}, 'quiet': {}},
    'model_choices.py': {'loud': {('CWE-338', 12): 'held by the chain requirement (TIER 1 '
                                                   't1.338.bare_name_refused), not by a row move'},
                         'quiet': {('CWE-338', 7): 'choices_import_proof_disabled'}},
    'prng_choices.py': {'loud': {('CWE-338', 5): None,
                                 ('CWE-338', 9): None,
                                 ('CWE-338', 10): None,
                                 ('CWE-338', 14): None,
                                 ('CWE-338', 19): None},
                        'quiet': {}},
    'shard_hash.py': {'loud': {}, 'quiet': {('CWE-328', 5): 'routing_key_demotion_dropped',
                                            ('CWE-328', 9): 'credential_input_veto_disabled',
                                            ('CWE-328', 14): 'credential_input_veto_disabled',
                                            ('CWE-328', 18): 'routing_key_demotion_dropped'}},
    'weak_hash_loud.py': {'loud': {('CWE-328', 5): 'credential_input_veto_disabled',
                                   ('CWE-328', 9): 'credential_input_veto_disabled',
                                   ('CWE-328', 13): 'credential_input_veto_disabled',
                                   ('CWE-759', 13): None,
                                   ('CWE-916', 13): None}, 'quiet': {}},
    'debug_preview.py': {'loud': {('CWE-78', 5): None}, 'quiet': {}},
}

def scan_all(files):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        tracker = TT(files=dict(files), max_workers=1)
        _nodes, _rules, edges = tracker.analyze()
        return tracker, cli._findings_for(tracker, edges)


SHARED, SHARED_ROWS = scan_all(FIXTURES)

# `_scope_module(scope_id)` hands a guard the key this tracker files a module under -- a stem, not the
# filename a caller passed. Asking the guards with any other string tests a proof the engine never
# gets, so the answers below would describe a pipeline that does not exist.
MODULE_KEYS = {str(key): key for key in SHARED.modules}


def mod_for(fixture_name):
    return MODULE_KEYS.get(os.path.splitext(os.path.basename(fixture_name))[0], fixture_name)


def basenames(rows):
    out = collections.defaultdict(set)
    for row in rows:
        out[os.path.basename(str(row['file']).replace('\\', '/'))].add((row['cwe'], int(row['line'])))
    return out


# ─── TIER 1: the new predicates answer for the shapes that abort careless guards ───────────────
def node_by_shape(source, predicate):
    """A node from `source`, parent-linked the way the engine's parse links them."""
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    return next((n for n in ast.walk(tree) if predicate(n)), None)


def any_call(source):
    return node_by_shape(source, lambda n: isinstance(n, ast.Call))


def tier1_predicates():
    checks = passed = 0
    tracker = SHARED
    probe = ('from snuba_sdk import Request\n'
             'from urllib.request import Request as UrlRequest\n'
             'import random\n'
             'REGISTRY = {}\n'
             'def bare(choices_arg):\n'
             '    return REGISTRY["Request"](choices_arg)\n'
             'def keywords():\n'
             '    return Request()\n'
             'def literal_receiver():\n'
             '    return (1).choices\n'
             'def call_receiver():\n'
             '    return get_rng().choices(3)\n'
             'def plain_choices(x):\n'
             '    return choices(x)\n')

    # CWE-918: a callee that will not name, an empty module, a module the tracker never loaded.
    unnameable = node_by_shape(probe, lambda n: isinstance(n, ast.Call)
                               and isinstance(n.func, ast.Subscript))
    noargs = node_by_shape(probe, lambda n: isinstance(n, ast.Call) and not n.args
                           and not n.keywords)
    for label, call, mod in (('subscript callee', unnameable, 'probe.py'),
                             ('no-argument call', noargs, 'probe.py'),
                             ('module not loaded', any_call(SNUBA_REQUEST), 'ghost.py'),
                             ('empty module name', any_call(SNUBA_REQUEST), '')):
        checks += 1
        try:
            answered = tracker._cwe918_request_is_a_query_builder(call, mod)
            if answered is False:
                passed += 1
            else:
                fail('t1.918.%s' % label,
                     'answered %r for a call with no import proof -- unknown must stay loud'
                     % answered)
        except Exception as exc:  # noqa: BLE001 - the whole point of TIER 1
            fail('t1.918.%s' % label, 'raised %s: %s' % (type(exc).__name__, exc))

    # CWE-918 does answer True for the proven builder, in both spellings.
    checks += 1
    builder = [node_by_shape(SNUBA_REQUEST, lambda n: isinstance(n, ast.Call)
                             and (dotted_name(n.func) or '') == 'Request'),
               node_by_shape(SNUBA_QUALIFIED, lambda n: isinstance(n, ast.Call)
                             and (dotted_name(n.func) or '') == 'snuba_sdk.Request')]
    got = [bool(tracker._cwe918_request_is_a_query_builder(call, mod_for(mod)))
           for call, mod in zip(builder, ('snuba_request.py', 'snuba_qualified.py'))
           if call is not None]
    if got == [True, True]:
        passed += 1
    else:
        fail('t1.918.proven_builder', 'answers were %s for %d spellings (expected [True, True])'
             % (got, len(got)))

    checks += 1
    urllib_call = node_by_shape(SSRF_LOUD, lambda n: isinstance(n, ast.Call)
                                and (dotted_name(n.func) or '') == 'Request')
    if tracker._cwe918_request_is_a_query_builder(urllib_call, mod_for('ssrf_loud.py')) is False:
        passed += 1
    else:
        fail('t1.918.http_head_wins', 'a `from urllib.request import Request` call was pruned -- the '
                                      'HTTP-client veto is what keeps the real SSRF row')

    # CWE-338: receivers that carry no name, no proof, or a fold the caller never supplied.
    for label, receiver, canon in (('int literal', ast.Constant(value=1), ''),
                                   ('bare name', ast.Name(id='nothing'), ''),
                                   ('subscript', ast.parse('a[0]').body[0].value, ''),
                                   ('starred', ast.parse('f(*a)').body[0].value.func, ''),
                                   ('call receiver', node_by_shape(probe, lambda n: isinstance(
                                       n, ast.Call) and isinstance(n.func, ast.Attribute)
                                       and n.func.attr == 'choices'), ''),
                                   ('None canon on a real chain', node_by_shape(
                                       MODEL_CHOICES, lambda n: isinstance(n, ast.Call)
                                       and (dotted_name(n.func) or '')
                                       == 'manager.UpdateChannel.choices'), None)):
        checks += 1
        try:
            answered = tracker._cwe338_choices_chain_is_an_imported_symbol(receiver, canon or '',
                                                                           'probe.py')
            if isinstance(answered, bool):
                passed += 1
            else:
                fail('t1.338.%s' % label, 'answered %r, not a bool' % (answered,))
        except Exception as exc:  # noqa: BLE001
            fail('t1.338.%s' % label, 'raised %s: %s' % (type(exc).__name__, exc))

    checks += 1
    self_receiver = node_by_shape(PRNG_CHOICES, lambda n: isinstance(n, ast.Call)
                                  and (dotted_name(n.func) or '') == 'self.choices')
    unproven_receiver = node_by_shape(PRNG_CHOICES, lambda n: isinstance(n, ast.Call)
                                      and (dotted_name(n.func) or '') == 'store.choices')
    random_receiver = node_by_shape(PRNG_CHOICES, lambda n: isinstance(n, ast.Call)
                                    and (dotted_name(n.func) or '') == 'random.choices')
    refused = [tracker._cwe338_choices_chain_is_an_imported_symbol(n.func.value, '',
                                                                   mod_for('prng_choices.py'))
               for n in (self_receiver, unproven_receiver, random_receiver) if n is not None]
    if refused == [False, False, False]:
        passed += 1
    else:
        fail('t1.338.refusals', 'a `self`, a parameter and the `random` module itself answered %s -- '
                                'all three are locked loud by gate #52' % (refused,))

    checks += 1
    proven = node_by_shape(MODEL_CHOICES, lambda n: isinstance(n, ast.Call)
                           and (dotted_name(n.func) or '') == 'manager.UpdateChannel.choices')
    if tracker._cwe338_choices_chain_is_an_imported_symbol(proven.func.value, '',
                                                           mod_for('model_choices.py')) is True:
        passed += 1
    else:
        fail('t1.338.proven_chain', 'the guard refused `manager.UpdateChannel`, whose tail this '
                                    'module imports -- that is the Sentry FP this gate retires')

    checks += 1
    bare = node_by_shape(MODEL_CHOICES, lambda n: isinstance(n, ast.Call)
                         and (dotted_name(n.func) or '') == 'UpdateChannel.choices')
    if tracker._cwe338_choices_chain_is_an_imported_symbol(bare.func.value, '',
                                                           mod_for('model_choices.py')) is False:
        passed += 1
    else:
        fail('t1.338.bare_name_refused', 'one imported name answered as a chain: `random`, an alias '
                                         'of it and a parameter all look like that, so the guard has '
                                         'to refuse and leave the row reported')

    # CWE-328: empty and odd spellings answer without raising, credential or not.
    checks += 1
    words = [('', False), ('key', True), ('shard_key', False), ('partition_key', False),
             ('api_key', True), ('session_id', True), ('GROUPING-KEY', False),
             ('password', True), ('salt', True), ('token_type_ids', True), ('issue_hash_value', True)]
    got = [(word, tracker._cwe328_input_is_credential_named(word)) for word, _ in words]
    bad = [(word, answered, want) for (word, answered), (_, want) in zip(got, words)
           if answered is not want]
    if not bad:
        passed += 1
    else:
        fail('t1.328.words', 'credential veto answered wrong for %s -- the demotion fires only when '
                             '`key` is the sole security word beside a bucket word' % (bad,))

    # The enclosing-helper proof on the trees where it must refuse: nothing above the node, a
    # module-level digest, a class body -- and the one tree where the helper really is the proof.
    for label, source, link, want in (
            ('no parent links', SHARD_HASH, False, False),
            ('module level digest', 'import hashlib\nhashlib.md5(b"x")\n', True, False),
            ('class body', 'import hashlib\n\n\nclass C:\n    x = hashlib.md5(b"y")\n',
             True, False),
            ('sharding helper', SHARD_HASH, True, True)):
        checks += 1
        tree = ast.parse(source)
        if link:
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    child.parent = parent
        call = next((n for n in ast.walk(tree) if isinstance(n, ast.Call)), None)
        try:
            answered = tracker._cwe328_enclosing_helper_is_content_addressed(
                call, ast_scanner.CWE328_CONTENT_HASH_KEYWORDS)
            if answered is want:
                passed += 1
            else:
                fail('t1.328.%s' % label, 'answered %r, expected %r -- proof that is not there must '
                                          'leave the digest charged' % (answered, want))
        except Exception as exc:  # noqa: BLE001
            fail('t1.328.%s' % label, 'raised %s: %s' % (type(exc).__name__, exc))
    return passed, checks


# ─── TIER 2: the shipped verdicts ──────────────────────────────────────────────────────────────
def tier2_verdicts(rows=None):
    checks = passed = 0
    by = basenames(rows if rows is not None else SHARED_ROWS)
    for module, table in BLESSED.items():
        seen = by.get(module, set())
        checks += 1
        lost = sorted(set(table['loud']) - seen)
        if lost:
            fail('t2.%s' % module, 'rows that must stay reported disappeared: %s' % (lost,))
        else:
            passed += 1
        extra = sorted(seen - set(table['loud']))
        checks += 1
        if extra:
            fail('t2.%s.new' % module, 'the file reports rows nobody pinned: %s' % (extra,))
        else:
            passed += 1
    return passed, checks


# ─── TIER 3: the discovery contract in cli.py ──────────────────────────────────────────────────
DEBUG_TREE = {
    'src/sentry/web/frontend/debug/mail.py': DEBUG_PREVIEW,
    'src/sentry/web/frontend/debug/organizations/token_partition.py': DEBUG_PREVIEW,
    'src/sentry/web/frontend/views.py': DEBUG_PREVIEW,
    'tests/fixture.py': DEBUG_PREVIEW,
}


def cli_rows(argv, cwd):
    out, err = io.StringIO(), io.StringIO()
    previous = os.getcwd()
    os.chdir(cwd)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
    finally:
        os.chdir(previous)
    text = out.getvalue()
    start = text.find('{')
    if start < 0:
        raise AssertionError('the CLI printed no JSON (%s)' % err.getvalue()[-200:])
    payload = json.loads(text[start:])
    files = {os.path.normpath(str(f['file'])).replace('\\', '/').lower()
             for f in payload['findings']}
    return code, files, text + err.getvalue()


def tier3_scope():
    checks = passed = 0
    checks += 1
    if 'debug' in cli.NON_PRODUCTION_DIRS:
        passed += 1
    else:
        fail('t3.set', 'cli.NON_PRODUCTION_DIRS does not hold `debug`')
    for name in ('tests', 'testutils', 'fixtures', 'examples', 'samples'):
        checks += 1
        if name in cli.NON_PRODUCTION_DIRS:
            passed += 1
        else:
            fail('t3.set.%s' % name, 'the prune set lost %r, which gates #37/#52 depend on' % name)

    with tempfile.TemporaryDirectory() as tmp:
        for rel, source in DEBUG_TREE.items():
            path = os.path.join(tmp, *rel.split('/'))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(source)
        base = ['scan', '.', '--format', 'json', '--workers', '1']

        checks += 1
        try:
            code, files, text = cli_rows(base, tmp)
            want = {'src/sentry/web/frontend/views.py'}
            if files == want:
                passed += 1
            else:
                fail('t3.default_prune', 'a default scan reported %s, expected exactly %s'
                     % (sorted(files), sorted(want)))
            checks += 1
            if 'debug/' in text and 'non-production' in text:
                passed += 1
            else:
                fail('t3.note', 'the held-back count was not announced; the report must name the '
                                'pruned directories instead of looking like a clean tree (%r)'
                     % text[-160:])
        except AssertionError as exc:
            fail('t3.default_prune', str(exc))

        checks += 1
        try:
            _code, files, _text = cli_rows(base + ['--include-tests'], tmp)
            if files == {rel.lower() for rel in DEBUG_TREE}:
                passed += 1
            else:
                fail('t3.include_tests', '`--include-tests` walked %s, expected all four files'
                     % sorted(files))
        except AssertionError as exc:
            fail('t3.include_tests', str(exc))

        checks += 1
        try:
            _code, files, text = cli_rows(['scan', 'src/sentry/web/frontend/debug',
                                          '--format', 'json', '--workers', '1'], tmp)
            named = {'src/sentry/web/frontend/debug/mail.py',
                     'src/sentry/web/frontend/debug/organizations/token_partition.py'}
            if files == named and 'non-production' not in text:
                passed += 1
            else:
                fail('t3.named_path', 'a directory named on the command line must be walked in full: '
                                      'reported=%s announced=%r' % (sorted(files),
                                                                    'non-production' in text))
        except AssertionError as exc:
            fail('t3.named_path', str(exc))

        checks += 1
        try:
            _code, files, _text = cli_rows(['scan', 'tests', '--format', 'json', '--workers', '1'],
                                           tmp)
            if files == {'tests/fixture.py'}:
                passed += 1
            else:
                fail('t3.named_tests', 'naming `tests/` reported %s' % sorted(files))
        except AssertionError as exc:
            fail('t3.named_tests', str(exc))
    return passed, checks


# ─── TIER 4: source laws ───────────────────────────────────────────────────────────────────────
ENGINE_SRC = open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8').read()
CLI_SRC = open(os.path.join(ROOT, 'cli.py'), encoding='utf-8').read()


def executable_body(source, name):
    """The body text of one function, comments and its docstring removed."""
    match = re.search(r'^([ \t]*)def %s\(' % re.escape(name), source, re.M)
    if not match:
        return None
    indent = len(match.group(1))
    lines = []
    for line in source[match.end():].split('\n')[1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        if line.strip().startswith('#'):
            continue
        lines.append(line)
    body = '\n'.join(lines)
    # A multi-line signature leaves its continuation lines in front of the docstring, so the span is
    # found where it actually sits instead of assumed to start the body.
    quote = re.search(r'("""|\'\'\')', body)
    if quote:
        end = body.find(quote.group(1), quote.end())
        if end > 0:
            body = body[:quote.start()] + body[end + len(quote.group(1)):]
    return body


def tier4_laws():
    checks = passed = 0

    def check(name, ok, msg):
        nonlocal checks, passed
        checks += 1
        if ok:
            passed += 1
        else:
            fail(name, msg)

    # 1. The CWE-918 suppression answers twice: on the registration path, so the query-builder sink
    # never enters the graph, and on the report path, because that is where a CWE-918 row is made.
    # Measured: with only the registration prune the FP survives, so the emission-side answer is not
    # decoration and the source law pins both.
    report = ENGINE_SRC.find('if (_sink_cwe == "CWE-918"')
    refusal = ENGINE_SRC.find('return False', report) if report > 0 else -1
    # The condition must lead to the refusal with nothing but comment lines in between -- a fixed
    # character window would break the day someone rewraps the rationale, and a window wide enough
    # to survive that would also accept a guard that falls through to the next branch.
    bridge = ENGINE_SRC[report:refusal] if refusal > report else ''
    # Everything after the condition's closing `):` up to the refusal must be prose: an executable
    # line in between would mean the guard's True answer no longer ends the decision on its own.
    lines = bridge.splitlines()
    condition_end = next((i for i, line in enumerate(lines) if line.rstrip().endswith('):')), None)
    body = lines[condition_end + 1:] if condition_end is not None else []
    check('t4.918.report_path', report > 0 and refusal > report and condition_end is not None and
          '_cwe918_request_is_a_query_builder' in bridge and
          all(not line.strip() or line.lstrip().startswith('#') for line in body),
          'the CWE-918 guard is no longer asked on the report path -- a row can then be emitted by '
          'the sink-matching branch without the query-builder question ever being put')
    check('t4.918.report_path_is_gated', report > 0 and 'name.endswith(".Request")'
          in ENGINE_SRC[report:report + 400],
          'the report-path guard is no longer behind a name test on the two strings this function '
          'already computed -- every CWE-918 sink in a corpus would pay an import-table walk for a '
          'call that cannot be a `Request` at all (measured: 840-scan gate #52 went 7.2s -> 11.4s)')
    prune = ENGINE_SRC.find(
        'if sink.metadata.get("cwe") == "CWE-918" and self._cwe918_request_is_a_query_builder(')
    append = ENGINE_SRC.find('self.sinks.append(sink)', prune if prune > 0 else 0)
    check('t4.918.registration_prune', prune > 0 and prune < append and
          'return sink' in ENGINE_SRC[prune:prune + 400],
          'the CWE-918 guard is not a `return sink` before `self.sinks.append(sink)` -- keeping the '
          'sink in the graph costs the edge builder and the cascade for a row that is already refused')

    # 2. No new helper decides anything from a path or a filename.
    for name in ('_cwe918_request_is_a_query_builder',
                 '_cwe918_query_builder_uncached',
                 '_cwe338_choices_chain_is_an_imported_symbol',
                 '_cwe328_input_is_credential_named',
                 '_cwe328_enclosing_helper_is_content_addressed',
                 '_cwe328_hash_input_is_non_credential'):
        body = executable_body(ENGINE_SRC, name)
        check('t4.no_path_law.%s' % name, body is not None and not re.search(
            r'os\.path|basename|dirname|__file__|\.py\b|listdir|walk\(|sentry|snuba', body),
            'decides something from a path, a filename or a project name' if body else
            'helper is gone -- the suppression is not provable without it')

    # 3. The bucket words are reachable only from CWE-328.
    uses = [line for line in ENGINE_SRC.split('\n') if 'CWE328_CONTENT_HASH_KEYWORDS' in line]
    check('t4.vocabulary.containment', len(uses) == 4 and all('cwe328' in line.lower() or
            'CWE328_CONTENT_HASH_KEYWORDS = ' in line or '_is_exempt_cwe327' in line
            or 'enclosing_helper_is_content_addressed' in line or 'for word in' in line
            or line.startswith('CWE328_CONTENT_HASH_KEYWORDS') for line in uses),
          'the widened vocabulary is read in %d places (%s) -- CWE-327 and CWE-338 read '
          'CWE327_NON_CRYPTO_KEYWORDS and must keep doing so'
          % (len(uses), [line.strip()[:70] for line in uses]))
    check('t4.327.vocabulary_untouched',
          tuple(ast_scanner.CWE327_NON_CRYPTO_KEYWORDS) ==
          ('cache_key', 'etag', 'checksum', 'fingerprint', 'thumb'),
          'CWE327_NON_CRYPTO_KEYWORDS changed -- folding the bucket words into it would silence '
          '`blob = random.randbytes(16)` and `color_password = random.choice(alphabet)`, which gate '
          '#41 locks loud')
    check('t4.328.vocabulary_widened',
          set(ast_scanner.CWE328_CONTENT_HASH_KEYWORDS) >= {
              'shard', 'bucket', 'ring', 'partition', 'dedup', 'palette', 'hue', 'rgb',
              'hex_color', 'issue_hash', 'grouping'},
          'the bucket vocabulary lost one of the words the Sentry FPs need')

    # 4. The routing-key demotion cannot widen past `key`, and cannot reach the CWE-338 veto.
    demotion = executable_body(ENGINE_SRC, '_cwe328_input_is_credential_named') or ''
    check('t4.328.demotion_key_only', 'CWE328_ROUTING_KEY_WORDS' in demotion and
          '<=' in demotion.split('CWE328_ROUTING_KEY_QUALIFIERS')[0],
          'the demotion no longer requires `key`/`keys` to be the SOLE security word -- `token`, '
          '`password`, `salt` and `session` would stop vetoing a weak hash')
    security_body = executable_body(ENGINE_SRC, '_cwe338_name_is_security_named') or ''
    check('t4.338.veto_untouched', 'ROUTING_KEY' not in security_body,
          'the CWE-338 credential veto now consults the routing-key demotion -- every PRNG lock '
          'would move')
    check('t4.916.untouched', ENGINE_SRC.count('"CWE-916"') >= 2 and
          'cwe328' not in ENGINE_SRC[ENGINE_SRC.find('CWE-916 & CWE-759'):
                                     ENGINE_SRC.find('CWE-916 & CWE-759') + 3000].lower(),
          'the WEAK_PASSWORD_HASH block consults the CWE-328 provenance, so a password digest could '
          'be silenced by a bucket name')

    # 5. The `.choices` guard is keyed on the leaf and refuses the unproven receiver.
    guard = executable_body(ENGINE_SRC, '_cwe338_choices_chain_is_an_imported_symbol') or ''
    check('t4.338.leaf_keyed', '"self", "cls"' in guard or "('self', 'cls')" in guard,
          'a `self`/`cls` receiver is no longer refused -- gate #52 locks `self.choices(n)` loud')
    check('t4.338.chain_required', 'len(segments) < 2' in guard,
          'the guard no longer requires a written chain: a bare `random`, an alias of it or a '
          'parameter would reach the import table and be mistaken for a Choices class -- and gate '
          '#52 proves it by emptying the random-source table, which must move no row')
    check('t4.338.random_segment_veto', 'CWE338_RANDOM_SOURCE_SEGMENTS' in guard,
          'the guard stopped asking whether the chain is a random source -- `random.choices` would '
          'be silenced')
    anchor = ENGINE_SRC.find('if (node.func.attr == "choices"')
    window = ENGINE_SRC[anchor:anchor + 260] if anchor > 0 else ''
    check('t4.338.call_site_scoped', bool(window) and
          '_cwe338_choices_chain_is_an_imported_symbol(' in window and 'receiver_canon' in window,
          'the guard is no longer behind a `choices` leaf test with the fold the chain already '
          'computed -- either spelling could charge a model member or silence a draw')

    # 6. CWE-918: the builder set is package names, the veto set is bigger, and proof is required.
    check('t4.918.builder_set', set(ast_scanner.CWE918_QUERY_BUILDER_PACKAGES) == {'snuba_sdk'},
          'the query-builder set changed -- every entry is a package name the import table resolves')
    check('t4.918.http_set', {'urllib', 'requests', 'httpx', 'aiohttp'} <=
          set(ast_scanner.CWE918_HTTP_CLIENT_PACKAGES),
          'the HTTP-client veto set lost a member -- those `Request` constructors must stay sinks')

    # 7. cli.py: `debug/` is announced, and pruning stays a discovery choice with two ways back.
    check('t4.cli.note', 'examples/, samples/, debug/' in CLI_SRC,
          'the held-back note no longer names debug/ -- a scope choice the report does not state is '
          'indistinguishable from a clean tree')
    check('t4.cli.two_ways_back',
          'skip_non_production = tree_scan and not bool(getattr(args, "include_tests"' in CLI_SRC,
          'the prune no longer depends on `--include-tests` or on a tree scan, so a named path could '
          'be filtered')
    check('t4.cli.not_a_suppression', 'NON_PRODUCTION_DIRS' in CLI_SRC and
          '_collect_files' in CLI_SRC,
          'the prune moved out of the directory walk into the emission path -- that would be a '
          'suppression, which AGENTS.md forbids')
    return passed, checks


# ─── TIER 5: budgets ───────────────────────────────────────────────────────────────────────────
def tier5_budget():
    checks = passed = 0
    checks += 1
    rss = None
    try:
        import psutil
        rss = psutil.Process().memory_info().rss / (1024 * 1024)
    except Exception:  # noqa: BLE001 - psutil is optional, the clock check still runs
        pass
    if rss is None or rss < BUDGET_RSS_MB:
        passed += 1
    else:
        fail('t5.rss', 'peak RSS %.1f MB over the %.1f MB budget' % (rss, BUDGET_RSS_MB))
    return passed, checks, rss


# ─── mutations: data-level, never recompiling engine source ────────────────────────────────────
MUTATIONS = {
    'request_provenance_never_prunes': {
        'what': 'answer "not a query builder" for every call, so both `snuba_sdk` query objects -- the '
                'imported `Request(app="events", url=request.GET["url"])` and the qualified '
                '`snuba_sdk.Request(...)` -- charge as SSRF again, and no HTTP row is affected',
        'files': ('snuba_request.py', 'snuba_qualified.py', 'ssrf_loud.py'),
        'apply': lambda: setattr(TT, '_cwe918_request_is_a_query_builder',
                                 lambda self, call, mod: False),
        'restore': lambda: setattr(TT, '_cwe918_request_is_a_query_builder',
                                   _ORIG['918']),
        'gains': {('snuba_request.py', 'CWE-918', 12), ('snuba_qualified.py', 'CWE-918', 5)},
        'losses': set(),
    },
    'query_builder_and_http_client_sets_swapped': {
        'what': 'trade the two package sets over. `requests`/`httpx` then answer "query builder" and two '
                'verified SSRF rows go quiet, while `snuba_sdk` answers "HTTP client" and both query '
                'objects come back -- the sets are load-bearing in both directions, and a name match '
                'alone cannot tell them apart',
        'files': ('ssrf_loud.py', 'snuba_request.py', 'snuba_qualified.py'),
        'apply': lambda: (setattr(ast_scanner, 'CWE918_QUERY_BUILDER_PACKAGES',
                                  frozenset(ast_scanner.CWE918_HTTP_CLIENT_PACKAGES)),
                          setattr(ast_scanner, 'CWE918_HTTP_CLIENT_PACKAGES',
                                  frozenset({'snuba_sdk'}))),
        'restore': lambda: (setattr(ast_scanner, 'CWE918_QUERY_BUILDER_PACKAGES',
                                    _ORIG['918_builder']),
                            setattr(ast_scanner, 'CWE918_HTTP_CLIENT_PACKAGES',
                                    _ORIG['918_http'])),
        'gains': {('snuba_request.py', 'CWE-918', 12), ('snuba_qualified.py', 'CWE-918', 5)},
        'losses': {('ssrf_loud.py', 'CWE-918', 13), ('ssrf_loud.py', 'CWE-918', 14)},
    },
    'choices_import_proof_disabled': {
        'what': 'refuse BOTH choice-table proofs -- the imported chain (`ModelChoices.enum_labels.'
                'choices` reached through `from myapp.models import ModelChoices`) and the owning '
                'class (`manager.UpdateChannel.choices` reached through a parameter). They are two '
                'arms of one `or`, so disabling a single arm proves nothing: the other still exempts '
                'the row. Together they are what keeps a Django choices table off the PRNG report',
        'files': ('model_choices.py', 'prng_choices.py'),
        'apply': lambda: (setattr(TT, '_cwe338_choices_chain_is_an_imported_symbol',
                                  lambda self, receiver, canon, mod: False),
                          setattr(TT, '_cwe338_choices_chain_denotes_a_choice_set',
                                  lambda self, receiver: False)),
        'restore': lambda: (setattr(TT, '_cwe338_choices_chain_is_an_imported_symbol',
                                    _ORIG['338']),
                            setattr(TT, '_cwe338_choices_chain_denotes_a_choice_set',
                                    _ORIG['338_class'])),
        'gains': {('model_choices.py', 'CWE-338', 7)},
        'losses': set(),
    },
    'routing_key_demotion_dropped': {
        'what': 'empty both qualifier sets, so a routing index spelled `shard_key`/`grouping_key` '
                'reads as a credential and its digest charges',
        'files': ('shard_hash.py', 'weak_hash_loud.py'),
        'apply': lambda: (setattr(ast_scanner, 'CWE328_ROUTING_KEY_QUALIFIERS', frozenset()),
                          setattr(ast_scanner, 'CWE328_DIGEST_QUALIFIERS', frozenset())),
        'restore': lambda: (setattr(ast_scanner, 'CWE328_ROUTING_KEY_QUALIFIERS',
                                    _ORIG['328_qualifiers']),
                            setattr(ast_scanner, 'CWE328_DIGEST_QUALIFIERS',
                                    _ORIG['328_digest_qualifiers'])),
        'gains': {('shard_hash.py', 'CWE-328', 5), ('shard_hash.py', 'CWE-328', 18)},
        'losses': set(),
    },
    'credential_input_veto_disabled': {
        'what': 'read the hashed bytes as never credential-named, so `md5(api_key)`, '
                '`md5(session_id)` and `md5(password)` all go quiet',
        'files': ('weak_hash_loud.py', 'shard_hash.py'),
        'apply': lambda: setattr(TT, '_cwe328_input_is_credential_named',
                                 staticmethod(lambda name: False)),
        'restore': lambda: setattr(TT, '_cwe328_input_is_credential_named', _ORIG['328_veto']),
        'gains': set(),
        'losses': {('weak_hash_loud.py', 'CWE-328', 5), ('weak_hash_loud.py', 'CWE-328', 9),
                   ('weak_hash_loud.py', 'CWE-328', 13)},
    },
    'debug_dir_stops_being_pruned': {
        'what': 'drop `debug/` from the discovery prune set, so the developer-preview tree is '
                'reported as shipped surface',
        'scope': True,
        'apply': lambda: setattr(cli, 'NON_PRODUCTION_DIRS',
                                 frozenset(d for d in cli.NON_PRODUCTION_DIRS if d != 'debug')),
        'restore': lambda: setattr(cli, 'NON_PRODUCTION_DIRS', _ORIG['debug_dirs']),
    },
}

_ORIG = {
    '918': TT._cwe918_request_is_a_query_builder,
    '338': TT._cwe338_choices_chain_is_an_imported_symbol,
    # `model_choices.py` is exempted by either arm of the choice-table `or`, so the falsifier that
    # owns it has to disable both -- which means both have to be restorable.
    '338_class': TT._cwe338_choices_chain_denotes_a_choice_set,
    '328_veto': TT._cwe328_input_is_credential_named,
    '328_qualifiers': ast_scanner.CWE328_ROUTING_KEY_QUALIFIERS,
    # `grouping_key` is demoted by either qualifier set -- `grouping` is a routing word AND a digest
    # word -- so the falsifier that owns row 18 has to empty both, and both have to be restorable.
    '328_digest_qualifiers': ast_scanner.CWE328_DIGEST_QUALIFIERS,
    '918_builder': ast_scanner.CWE918_QUERY_BUILDER_PACKAGES,
    '918_http': ast_scanner.CWE918_HTTP_CLIENT_PACKAGES,
    'debug_dirs': cli.NON_PRODUCTION_DIRS,
}


def run_mutation(name) -> int:
    spec = MUTATIONS[name]
    print('# %s -- %s' % (name, spec['what']))
    spec['apply']()
    try:
        if spec.get('scope'):
            with tempfile.TemporaryDirectory() as tmp:
                for rel, source in DEBUG_TREE.items():
                    path = os.path.join(tmp, *rel.split('/'))
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, 'w', encoding='utf-8') as handle:
                        handle.write(source)
                _code, files, text = cli_rows(
                    ['scan', '.', '--format', 'json', '--workers', '1'], tmp)
            pruned = {rel.lower() for rel in DEBUG_TREE if '/debug/' in '/' + rel}
            leaked = pruned & files
            if leaked:
                print('  CAUGHT: the pruned tree was reported (%s), which is what the entry in '
                      'NON_PRODUCTION_DIRS prevents' % sorted(leaked))
                return 0
            print('  NOT CAUGHT: pruned=%s reported=%s' % (sorted(pruned), sorted(files)))
            return 1
        # Only the modules this guard owns are re-scanned: the shared TIER 2 scan already paid for the
        # rest, and a precision lock that re-scans everything stops being run. Each of those modules is
        # scanned on its own, under a module stem of its own, because the engine decides once per scan
        # what an imported name means and two of these fixtures spell the same sink name (`Request`):
        # measured, with `ssrf_loud.py` in the same subset, stubbing the query-builder guard stopped
        # resurrecting `snuba_qualified.py` line 5 and started resurrecting a line 6 that never charges
        # alone. Isolation costs N small scans instead of one big one, and it keeps every row a
        # falsifier asserts a row the guard under test actually owns.
        names = list(spec['files'])
        stem_head = 't3_%s_' % ''.join(ch if ch.isalnum() else '_' for ch in name)[:20]
        gained, lost, scan_seconds = set(), set(), 0.0
        for key in names:
            _t0 = time.time()
            _tracker, rows = scan_all({stem_head + key: FIXTURES[key]})
            scan_seconds += time.time() - _t0
            found = {pair for pairs in basenames(rows).values() for pair in pairs}
            gained |= {(key, cwe, line) for (cwe, line) in BLESSED[key]['quiet']
                       if (cwe, line) in found}
            lost |= {(key, cwe, line) for (cwe, line) in BLESSED[key]['loud']
                     if (cwe, line) not in found}
        if gained == spec['gains'] and lost == spec['losses']:
            if scan_seconds > BUDGET_MUTATION_SECONDS:
                print('  CAUGHT but slow: %.2fs over the %.1fs per-falsifier budget'
                      % (scan_seconds, BUDGET_MUTATION_SECONDS))
                fail('mutation.%s.time' % name,
                     'a falsifier that costs more than the scan it protects stops being run')
                return 1
            print('  CAUGHT in %.2fs: rows back %s, rows lost %s'
                  % (scan_seconds, sorted(gained), sorted(lost)))
            return 0
        print('  NOT CAUGHT: expected gained=%s lost=%s, got gained=%s lost=%s'
              % (sorted(spec['gains']), sorted(spec['losses']), sorted(gained), sorted(lost)))
        return 1
    finally:
        spec['restore']()


def dump_table(rows):
    by = basenames(rows)
    for module in FIXTURES:
        per_cwe = collections.defaultdict(set)
        for cwe, line in by.get(module, set()):
            per_cwe[cwe].add(line)
        print('%-20s %s' % (module, {k: sorted(v) for k, v in sorted(per_cwe.items())}))
    print('rows=%d' % len(rows))


# ─── driver ────────────────────────────────────────────────────────────────────────────────────
def main() -> int:
    if len(sys.argv) > 2 and sys.argv[1] == '--mutation':
        name = sys.argv[2]
        if name not in MUTATIONS:
            print('unknown mutation %r; known: %s' % (name, ', '.join(sorted(MUTATIONS))))
            return 2
        return run_mutation(name)
    if len(sys.argv) > 1 and sys.argv[1] == '--dump':
        dump_table(SHARED_ROWS)
        return 0

    total = 0
    sections = []

    p, c = tier1_predicates()
    sections.append(('TIER 1  predicate robustness', p, c))
    total += c
    p, c = tier2_verdicts()
    sections.append(('TIER 2  shipped verdicts', p, c))
    total += c
    p, c = tier3_scope()
    sections.append(('TIER 3  discovery scope (cli.py)', p, c))
    total += c
    p, c = tier4_laws()
    sections.append(('TIER 4  source laws', p, c))
    total += c

    for label, ok, count in sections:
        print('%-30s %2d/%-2d' % (label, ok, count))
    dump_table(SHARED_ROWS)

    # Every guard above is load-bearing: each mutation is applied to the shipped pipeline, must move
    # exactly the rows its guard owns, and must be undone so the next check sees the real engine.
    caught = 0
    _mut_t0 = time.time()
    for name in sorted(MUTATIONS):
        total += 1
        if run_mutation(name) == 0:
            caught += 1
        else:
            fail('mutation.%s' % name, 'the guard is not load-bearing (see the report above)')
    mut_seconds = time.time() - _mut_t0
    total += 1
    if (TT._cwe918_request_is_a_query_builder is _ORIG['918']
            and TT._cwe338_choices_chain_is_an_imported_symbol is _ORIG['338']
            and TT._cwe338_choices_chain_denotes_a_choice_set is _ORIG['338_class']
            and TT._cwe328_input_is_credential_named is _ORIG['328_veto']
            and cli.NON_PRODUCTION_DIRS is _ORIG['debug_dirs']
            and ast_scanner.CWE328_ROUTING_KEY_QUALIFIERS is _ORIG['328_qualifiers']
            and ast_scanner.CWE328_DIGEST_QUALIFIERS is _ORIG['328_digest_qualifiers']
            and ast_scanner.CWE918_QUERY_BUILDER_PACKAGES is _ORIG['918_builder']
            and ast_scanner.CWE918_HTTP_CLIENT_PACKAGES is _ORIG['918_http']):
        passed_after = True
    else:
        passed_after = False
        fail('mutation.restore', 'a mutation was not undone -- the gate would then be locking '
                                 'something the shipped engine does not do')
    print('  falsifiers                   %2d/%-2d (each moved exactly the rows its guard owns)'
          % (caught, len(MUTATIONS)))
    if not passed_after:
        print('  restore check                FAILED')

    p, c, rss = tier5_budget()
    total += c
    if p != c:
        print('  budgets                    %2d/%-2d' % (p, c))
    elapsed = time.time() - WORK_START
    if elapsed > BUDGET_SECONDS:
        fail('t5.time', '%.2fs of gate work over the %.1fs budget' % (elapsed, BUDGET_SECONDS))
    if rss and rss >= BUDGET_RSS_MB:
        fail('t5.rss', '%.1f MB over the %.1f MB budget' % (rss, BUDGET_RSS_MB))

    if FAILS:
        for line in FAILS:
            print('FAIL %s' % line)
        print('VERDICT: FAIL - %d problem(s)' % len(FAILS))
        return 1
    print('  gate work %.2fs (budget %.1fs), falsifiers %.2fs summed (%.1fs per falsifier), '
          'peak RSS %s MB (budget %.1f)'
          % (elapsed, BUDGET_SECONDS, mut_seconds, BUDGET_MUTATION_SECONDS,
             ('%.1f' % rss) if rss else 'n/a', BUDGET_RSS_MB))
    print('VERDICT: PASS - tier3 precision %d/%d checks, %d falsifiers, %.2fs'
          % (total, total, len(MUTATIONS), elapsed))
    return 0


if __name__ == '__main__':
    sys.exit(main())
