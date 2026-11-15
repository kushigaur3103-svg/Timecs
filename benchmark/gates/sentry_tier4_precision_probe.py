"""TASK 12 precision lock -- the five Sentry provenance pockets retired on top of `864aa3b`.

Read this file as a contract with five clauses. Each clause names a shape that Sentry (`24.2.0`,
cloud run `864aa3b`, 562 findings) charged, states in one sentence why the charge is wrong, and pins
the opposite shape that must keep charging:

  1. CWE-918  `from snuba_sdk.request import Request` -- the ClickHouse query object spelled through
              its submodule. `urllib.request.Request` / `requests.Request` stay loud.
  2. CWE-338  `pkg.ChoicesClass.choices` and `random.*` inside mock/sample/jitter/backoff builders
              that name no credential. `random.choice` behind a token/otp/nonce stays loud.
  3. CWE-209  `Response({"detail": str(exc)}, status=400)` and `self.respond({"error": str(exc)})` --
              a structured error envelope with no traceback, no `sys.exc_info`, no raw frame.
  4. CWE-328  checksum/etag/commit/revision/content-hash/file-hash/blob/chunk/cache/mock digests,
              strictly vetoed by any credential-named identifier.
  5. CWE-704  `float(request.GET[...])` wrapped in `except (TypeError, ValueError)` or followed by
              `math.isnan` / `math.isfinite` / `x != x`. Unguarded conversions stay loud.

Every asserted row is measured, never assumed, and each fixture is scanned on its own under a module
stem of its own: the engine resolves an imported name once per scan, so two fixtures spelling the same
sink in one subset let one file's import table answer for the other's and a live guard measures inert.

The sampling exemption in clause 2 is bounded by a name, not by a count: a draw that a marker word
makes look like demo data stays reported if any identifier it touches names a credential, and that
set includes the value it is compared against (`if random.random() > token_ttl:` is a token lifetime,
not a display cadence). That bound is measured here by the two CWE-338 falsifiers losing nothing on
`prng_loud.py`, and it is locked row-by-row in `sentry_precision_tier2_probe.py`.
"""
from __future__ import annotations

import ast
import collections
import contextlib
import io
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402

TT = ast_scanner.TaintTracker

# Interpreter boot and the two engine imports are a fixed cost every tool in the suite pays; the
# budget covers this gate's own work. Per-falsifier 2s is the number the brief asks for.
WORK_START = time.time()
BUDGET_SECONDS = 15.0
BUDGET_MUTATION_SECONDS = 2.0
BUDGET_RSS_MB = 60.0

FAILS = []

# The vocabulary this task added, named here so a falsifier can remove exactly this task's words and
# leave every earlier one alone (`CWE338_DISPLAY_VALUE_MARKERS` also predates it, as does the
# non-crypto keyword list `CWE328_CONTENT_HASH_KEYWORDS` is built from).
TASK12_DISPLAY_MARKERS = frozenset({
    'mock', 'mocks', 'sample', 'samples', 'sampling', 'fixture', 'fixtures',
    'downsample', 'experiment', 'experiments', 'bucket', 'buckets',
})
TASK12_DIGEST_WORDS = frozenset({
    'commit', 'revision', 'content_hash', 'file_hash', 'sha1_text', 'md5_text', 'cache', 'mock',
})


def fail(what, msg):
    FAILS.append('%s: %s' % (what, msg))


# ─── 1. CWE-918: the query builder spelled through its submodule, and the fetch that must stay ──
SNUBA_SUBMODULE = '''from snuba_sdk.request import Request


def load_page(request):
    query = Request(app="events", selected_columns=["event_id"],
                    offset=int(request.GET["offset"]))
    return cluster.query(query)


def tunnel(request):
    return Request(app="errors", url=request.GET["url"], limit=50)


def execute(request):
    query = Request(app="events", offset=int(request.GET["offset"]))
    return client.execute(query, timeout=30)


def inline(request):
    return apps.execute_request(
        request=Request(app="errors", project=int(request.GET["project"])),
        referrer="saas.adapters.api.endpoint",
    )
'''
HTTP_SUBMODULE = '''import urllib.request

import requests


def fetch(request):
    req = urllib.request.Request(request.GET["url"])
    return urllib.request.urlopen(req)


def post(request):
    draft = requests.Request("POST", request.GET["hook"], json={"id": request.GET["id"]})
    return requests.Session().send(draft.prepare())
'''
# ─── 2. CWE-338: a choices table and a jitter builder, against the token generator ─────────────
CHOICE_TABLE = '''from sentry.conf.types import update_channel


def describe(manager):
    return update_channel.UpdateChannel.choices


def coerce(manager, raw):
    return manager.UpdateChannel.choices(raw)
'''
SAMPLING_BUILDER = '''import random


def build_mock_event(attempt):
    return random.choice([1, 2, 3]), random.randint(0, 9)


def backoff_jitter(attempt):
    return random.uniform(0.5, 1.5) * (2 ** attempt)


def apply_sample_rate(event, sample_rate):
    if random.random() > sample_rate:
        return None
    return event
'''
PRNG_LOUD = '''import random
import string


def generate_api_token():
    return "".join(random.choice(string.ascii_letters) for _ in range(32))


def make_otp(nonce):
    return random.randint(100000, 999999)


def new_password(length):
    return "".join(random.choice(string.printable) for _ in range(length))
'''
# ─── 3. CWE-209: a structured envelope, against the traceback that leaks ──────────────────────
ERROR_ENVELOPE = '''import traceback

from django.http import JsonResponse
from rest_framework.response import Response


class DetailEndpoint(object):
    def handle(self, request):
        try:
            return resolve(request.GET["id"])
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=400)

    def json(self, request):
        try:
            return resolve(request.GET["id"])
        except KeyError as exc:
            return self.respond({"error": str(exc)}, status=400)

    def plain(self, request):
        try:
            return resolve(request.GET["q"])
        except ValueError as exc:
            return JsonResponse({"message": str(exc)}, status=400)

    def formatted(self, request):
        try:
            return resolve(request.GET["id"])
        except Exception as exc:
            return self.respond({"detail": "%s" % exc}, status=400)

    def indirect(self, request):
        try:
            return resolve(request.GET["id"])
        except Exception as exc:
            body = {"detail": str(exc)}
            return Response(body, status=400)

    def raised(self, request):
        try:
            return resolve(request.GET["id"])
        except Exception as exc:
            raise ApiError(str(exc), status_code=400)
'''
TRACEBACK_LOUD = '''import sys
import traceback

from rest_framework.response import Response


class LeakyEndpoint(object):
    def full(self, request):
        try:
            return resolve(request.GET["id"])
        except ValueError:
            return Response({"detail": traceback.format_exc()}, status=500)

    def frame(self, request):
        try:
            return resolve(request.GET["id"])
        except ValueError as exc:
            return Response({"traceback": str(exc)}, status=500)

    def raw(self, request):
        try:
            return resolve(request.GET["id"])
        except ValueError as exc:
            return str(exc)
'''
# ─── 4. CWE-328: content digests, against the credential digests ─────────────────────────────
CONTENT_DIGEST = '''import hashlib


def blob_etag(blob):
    return hashlib.md5(blob).hexdigest()


def commit_revision(sha1_text):
    return hashlib.sha1(sha1_text.encode("utf-8")).hexdigest()


def chunk_cache_key(content_hash):
    return hashlib.md5(content_hash).hexdigest()


def mock_payload_digest(mock):
    return hashlib.md5(mock.encode("utf-8")).hexdigest()
'''
CREDENTIAL_DIGEST = '''import hashlib


def api_key_md5(api_key):
    return hashlib.md5(api_key.encode("utf-8")).hexdigest()


def password_md5(password):
    return hashlib.md5(password).hexdigest()


def salted_sha1(salt, secret):
    return hashlib.sha1(salt + secret).hexdigest()
'''
# ─── 5. CWE-704: conversions the caller already vouched for, against the ones it did not ──────
GUARDED_FLOAT = '''import math


def parse_rate(request):
    try:
        rate = float(request.GET["sampleRate"])
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(rate):
        return 0.0
    return rate


def parse_weight(request):
    weight = float(request.GET["weight"])
    if math.isfinite(weight):
        return weight
    return 0.0


def parse_scale(request):
    scale = float(request.GET["scale"])
    if scale != scale:
        return 0.0
    return scale
'''
BARE_FLOAT = '''def parse_page(request):
    return float(request.GET["page"])


def parse_ratio(request):
    return float(request.GET["ratio"])


def parse_mask(request):
    return complex(request.GET["mask"])
'''

FIXTURES = {
    'snuba_submodule.py': SNUBA_SUBMODULE,
    'http_submodule.py': HTTP_SUBMODULE,
    'choice_table.py': CHOICE_TABLE,
    'sampling_builder.py': SAMPLING_BUILDER,
    'prng_loud.py': PRNG_LOUD,
    'error_envelope.py': ERROR_ENVELOPE,
    'traceback_loud.py': TRACEBACK_LOUD,
    'content_digest.py': CONTENT_DIGEST,
    'credential_digest.py': CREDENTIAL_DIGEST,
    'guarded_float.py': GUARDED_FLOAT,
    'bare_float.py': BARE_FLOAT,
}

# `loud` -- rows the engine reports and must keep reporting; `quiet` -- rows the five guards own.
# Filled from measurement: `--dump` prints what the shipped engine actually does with each fixture.
# quiet / loud are the shipped verdicts. A quiet row is one the fixture writes in the retired pattern
# AND that a mutation below proves the guard owns (measured with the guard disabled, one fixture per
# scan); a loud row is one the engine still charges. Nothing here is asserted that was not measured.
BLESSED = {
    "snuba_submodule.py": {
        "quiet": {("CWE-918", 11)},
        "loud": set(),
        "falsifier": "918_query_builder_proof_disabled",
    },
    "choice_table.py": {
        "quiet": {("CWE-338", 9)},
        "loud": set(),
        "falsifier": "338_choices_class_law_disabled",
    },
    "sampling_builder.py": {
        "quiet": {("CWE-338", 5), ("CWE-338", 9)},
        "loud": set(),
        "falsifier": "338_display_markers_stripped, 338_display_draw_law_disabled",
    },
    "error_envelope.py": {
        "quiet": {("CWE-209", 12), ("CWE-209", 24), ("CWE-209", 37)},
        "loud": set(),
        "falsifier": "209_envelope_law_disabled, 209_assignment_hop_disabled",
    },
    "content_digest.py": {
        "quiet": {("CWE-328", 9), ("CWE-328", 13), ("CWE-328", 17)},
        "loud": set(),
        "falsifier": "328_digest_vocabulary_stripped, 328_digest_qualifiers_emptied",
    },
    "guarded_float.py": {
        "quiet": {("CWE-704", 6), ("CWE-704", 15), ("CWE-704", 22)},
        "loud": set(),
        "falsifier": "704_nan_checks_emptied, 704_guard_names_disabled",
    },
    "http_submodule.py": {
        "quiet": set(),
        "loud": {("CWE-918", 7), ("CWE-918", 8), ("CWE-939", 8)},
        "falsifier": "no CWE-918 mutation loses a row here: an HTTP head vetoes before the "
                     "query-builder set, and a resolved path is consulted on top of the written name",
    },
    "prng_loud.py": {
        "quiet": set(),
        "loud": {("CWE-338", 6), ("CWE-338", 10), ("CWE-338", 14)},
        "falsifier": "no CWE-338 mutation loses a row here: 'random' is refused by the choice-set law "
                     "and token/otp/password functions are refused by the security-word veto",
    },
    "traceback_loud.py": {
        "quiet": set(),
        "loud": {("CWE-200", 12), ("CWE-209", 12), ("CWE-209", 18), ("CWE-209", 23)},
        "falsifier": "no CWE-209 mutation loses a row here: a traceback.* call fails the all-keys and "
                     "raw-frame tests before any envelope logic runs",
    },
    "credential_digest.py": {
        "quiet": set(),
        "loud": {("CWE-328", 5), ("CWE-328", 9), ("CWE-328", 13),
                 ("CWE-759", 5), ("CWE-759", 9),
                 ("CWE-916", 5), ("CWE-916", 9), ("CWE-916", 13)},
        "falsifier": "no CWE-328 mutation loses a row here: password/secret/token/otp veto before the "
                     "digest vocabulary is consulted. Line 9 also picks up a CWE-327 row in some "
                     "in-memory scans and not in others (measured across fixed and random hash seeds), "
                     "because another module's import table is visible -- a row that depends on which "
                     "other fixtures share the process is a corpus gate's job, not a precision lock's",
    },
    "bare_float.py": {
        "quiet": set(),
        "loud": {("CWE-704", 2), ("CWE-704", 6), ("CWE-704", 10)},
        "falsifier": "no CWE-704 mutation loses a row here: an unguarded conversion keeps charging",
    },
}


def scan_all(files):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        tracker = TT(files=dict(files), max_workers=1)
        _nodes, _rules, edges = tracker.analyze()
        return tracker, cli._findings_for(tracker, edges)


def basenames(rows):
    out = collections.defaultdict(set)
    for row in rows:
        out[os.path.basename(str(row['file']).replace('\\', '/'))].add((row['cwe'], int(row['line'])))
    return out


BASE_TRACKER, BASE_ROWS = scan_all(FIXTURES)


def dump_table(rows):
    by = basenames(rows)
    for module in FIXTURES:
        per_cwe = collections.defaultdict(set)
        for cwe, line in by.get(module, set()):
            per_cwe[cwe].add(line)
        print('%-22s %s' % (module, {k: sorted(v) for k, v in sorted(per_cwe.items())}))
    print('rows=%d' % len(rows))


BASE_TRACKER, BASE_ROWS = scan_all(FIXTURES)
ROWS = basenames(BASE_ROWS)

# The same fixtures scanned one at a time. This is not a second verdict -- it is the reference set the
# falsifiers are judged against, because a falsifier re-scans one fixture at a time (see
# `run_mutation`). Measured: `credential_digest.py:9` picks up a CWE-327 row only in the combined
# scan, where another module's import table is visible; in its own scan that row does not exist, and a
# mutation must not be blamed for a row it never removed.
ISOLATED = {}
for _stem in FIXTURES:
    _t, _rows = scan_all({'t4_isolated_%s' % _stem: FIXTURES[_stem]})
    ISOLATED[_stem] = {pair for pairs in basenames(_rows).values() for pair in pairs}


def _mod(stem):
    for key in BASE_TRACKER.modules:
        if str(key).replace('\\', '/').rsplit('/', 1)[-1] == stem:
            return key
    return None


def _calls(stem, written):
    key, tree = _mod(stem), BASE_TRACKER.modules.get(_mod(stem))
    if tree is None:
        return key, []
    nodes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            spelled = ast.unparse(node.func) if node.func else ''
            if spelled == written or spelled.rsplit('.', 1)[-1] == written:
                nodes.append(node)
    return key, nodes


# ─── TIER 1: the five proofs, called directly on real AST nodes ────────────────────────────────
def tier1_predicates():
    passed = checks = 0

    def ok(label, cond, why):
        nonlocal passed, checks
        checks += 1
        if cond:
            passed += 1
        else:
            fail(label, why)

    # 1. CWE-918: `from snuba_sdk.request import Request` -- the written name is bare, the binding
    #    table is what says where it came from.
    key, bare = _calls('snuba_submodule', 'Request')
    ok('t1.918.module', key is not None and len(bare) >= 3,
       'the four `Request(...)` shapes must be reachable in one module, got %r in %r' % (len(bare), key))
    resolved = set()
    for call in bare:
        resolved |= BASE_TRACKER._cwe918_request_binding_paths(call, key)
    ok('t1.918.binding_paths', resolved == {'snuba_sdk.request.Request'},
       'the binding table must resolve the aliased local name to its submodule, got %s' % sorted(resolved))
    answers = [BASE_TRACKER._cwe918_query_builder_uncached('Request', call, key) for call in bare]
    ok('t1.918.query_builder', all(answers),
       'every submodule-backed `Request` must answer "query builder", got %s' % answers)
    ok('t1.918.fail_closed',
       BASE_TRACKER._cwe918_request_binding_paths(bare[0], 'module_that_does_not_exist') == set(),
       'a call in a module the engine never parsed must resolve to nothing -- unreadable is loud')
    hkey, dotted = _calls('http_submodule', 'Request')
    http = [BASE_TRACKER._cwe918_query_builder_uncached(ast.unparse(c.func), c, hkey) for c in dotted]
    ok('t1.918.http_wins', http and not any(http),
       'a resolved HTTP path must never answer "query builder", got %s' % http)

    # 2. CWE-338: the class that owns `.choices` is the only thing separating a choices table from a
    #    PRNG draw when the chain starts at a parameter.
    def receiver(text):
        node = ast.parse(text, mode='eval').body
        return node.value if isinstance(node, ast.Attribute) else node

    law = BASE_TRACKER._cwe338_choices_chain_denotes_a_choice_set
    table_cases = [('manager.UpdateChannel.choices', 'a class reached through a parameter'),
                   ('update_channel.UpdateChannel.choices', 'a class reached through its module')]
    prng_cases = [('random.choices', 'the module itself'),
                  ('self.rng.choices', 'an instance attribute, not a class'),
                  ('random.Random(1337).choices', 'a call, which is not readable as a class'),
                  ('secrets.SystemRandom().choices', 'a call on a PRNG factory'),
                  ('random.UpdateChannel.choices', 'a chain that still names a random source'),
                  ('manager.channel.choices', 'a lowercase owner that could be anything')]
    ok('t1.338.choice_set',
       all(law(receiver(text)) is True for text, _ in table_cases)
       and not any(law(receiver(text)) for text, _ in prng_cases),
       'the choice-set law must accept %s and refuse %s' % ([t for t, _ in table_cases],
                                                             [t for t, _ in prng_cases]))
    ok('t1.338.security_word_veto',
       BASE_TRACKER._cwe338_name_is_security_named('mock_token')
       and not BASE_TRACKER._cwe338_name_is_security_named('backoff_jitter'),
       'a sampled value named for a token is still security-named; a jitter helper is not')

    # 3. CWE-209: the envelope must be a dict whose every key is a detail/error/message field.
    reply = ast.parse('Response({"detail": str(exc)}, status=400)').body[0].value
    ok('t1.209.envelope_true',
       BASE_TRACKER._c209_structured_error_envelope_only(reply) is True,
       'a one-key detail envelope handed straight to Response must read as an envelope')
    for text in ('Response({"detail": traceback.format_exc()}, status=400)',
                 'Response({"stack": str(exc)}, status=400)',
                 'Response(str(exc), status=400)',
                 'raise ApiError(str(exc), status_code=400)'):
        node = ast.parse(text).body[0]
        node = node.value if isinstance(node, ast.Expr) else node
        ok('t1.209.envelope_refuses',
           BASE_TRACKER._c209_structured_error_envelope_only(node) is False,
           'a raw frame, a key outside the vocabulary, a bare message or a raised exception must '
           'stay chargeable, refused nothing: %r' % text)

    # 4. CWE-328: a credential name is never demoted by a bucket word sitting next to it.
    named = {'password_hash', 'secret_key', 'api_key', 'session_key', 'otp_code', 'token_hash'}
    plain = {'content_hash', 'file_hash', 'commit_hash', 'etag_hash', 'cache_key', 'shard_key'}
    veto = BASE_TRACKER._cwe328_input_is_credential_named
    ok('t1.328.credential_veto',
       all(veto(name) for name in named) and not any(veto(name) for name in plain),
       'credential names must stay named and digest/bucket names must not, got %s'
       % {name: veto(name) for name in sorted(named | plain)})
    ok('t1.328.vocabulary',
       {'commit', 'revision', 'content_hash', 'file_hash', 'sha1_text', 'md5_text', 'cache', 'mock'}
       <= set(ast_scanner.CWE328_CONTENT_HASH_KEYWORDS)
       and {'content', 'file', 'blob', 'chunk', 'checksum', 'etag', 'commit', 'revision', 'cache'}
       <= set(ast_scanner.CWE328_DIGEST_QUALIFIERS),
       'the non-credential digest vocabulary and its qualifiers must both be shipped')

    # 5. CWE-704: the try body is guarded, the handler is not; the operand and its target both count.
    floats = _calls('guarded_float', 'float')[1]
    by_line = {call.lineno: call for call in floats}
    ok('t1.704.try_body',
       BASE_TRACKER._c704_conversion_is_in_guarded_try(by_line[6]) is True
       and BASE_TRACKER._c704_conversion_is_in_guarded_try(by_line[15]) is False
       and BASE_TRACKER._c704_conversion_is_in_guarded_try(by_line[22]) is False,
       'only the conversion inside the try body may claim the handler')
    names = {line: BASE_TRACKER._c704_guarded_names(by_line[line], by_line[line].args[0])
             for line in sorted(by_line)}
    ok('t1.704.assigned_name',
       names.get(6) == {'rate'} and names.get(15) == {'weight'} and names.get(22) == {'scale'},
       'the name the conversion lands in is the name the later check reads, got %s' % names)
    bare_key, bare_calls = _calls('bare_float', 'float')
    ok('t1.704.handler_refusal',
       BASE_TRACKER._c704_conversion_is_in_guarded_try(bare_calls[0]) is False,
       'a conversion with no try around it cannot claim protection')
    return passed, checks


# ─── TIER 2: what the shipped engine actually reports ──────────────────────────────────────────
def tier2_verdicts():
    passed = checks = 0
    for module, spec in sorted(BLESSED.items()):
        found = ROWS.get(module, set())
        checks += 1
        if spec['quiet'] & found:
            fail('t2.quiet.%s' % module, 'retired rows still charge: %s'
                 % sorted(spec['quiet'] & found))
        else:
            passed += 1
        checks += 1
        if spec['loud'] and not spec['loud'] <= found:
            fail('t2.loud.%s' % module, 'verified rows went quiet: %s'
                 % sorted(spec['loud'] - found))
        else:
            passed += 1
    total = len(BASE_ROWS)
    checks += 1
    if total <= 25:
        passed += 1
    else:
        fail('t2.total', '%d rows for 11 small fixtures means a pocket stayed loud' % total)
    return passed, checks


# ─── TIER 3: laws about the source, so a future rewrite has to break one on purpose ────────────
def tier3_laws():
    passed = checks = 0

    def ok(label, cond, why):
        nonlocal passed, checks
        checks += 1
        if cond:
            passed += 1
        else:
            fail(label, why)

    src = open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8').read()
    lines = src.split('\n')

    def body(name):
        out, depth, started = [], None, False
        for line in lines:
            if not started and re.match(r'    def %s\(' % name, line):
                started, depth = True, len(line) - len(line.lstrip())
                continue
            if started:
                if line.strip() and (len(line) - len(line.lstrip())) <= depth:
                    break
                out.append(line)
        return '\n'.join(out)

    report = body('is_sink_call')
    guard = report[report.index('_sink_cwe == "CWE-918"'):][:400] \
        if '_sink_cwe == "CWE-918"' in report else ''
    ok('t3.918.refused_in_report_path',
       '_cwe918_request_is_a_query_builder' in guard and 'return False' in report,
       'the report path must refuse a CWE-918 `Request` sink through the query-builder proof, got %r'
       % guard[:120])
    uncached = body('_cwe918_query_builder_uncached')
    ok('t3.918.http_before_builder',
       0 <= uncached.index('CWE918_HTTP_CLIENT_PACKAGES')
       < uncached.index('CWE918_QUERY_BUILDER_PACKAGES'),
       'an HTTP package must veto before the query-builder set is consulted')
    bindings = body('_cwe918_request_binding_paths')
    ok('t3.918.bindings_are_cached', '_cached_import_bindings' in bindings,
       'the import table is a property of the file, so it must be computed once per tree')
    ok('t3.918.alias_is_local_name', 'alias.asname' in bindings,
       'an aliased import has to be answerable under the name the file actually writes')

    choices = report
    ok('t3.338.two_proofs',
       '_cwe338_choices_chain_is_an_imported_symbol' in choices
       and '_cwe338_choices_chain_denotes_a_choice_set' in choices,
       'both choice-table proofs must be consulted, the imported chain and the owning class')
    law = body('_cwe338_choices_chain_denotes_a_choice_set')
    ok('t3.338.random_refused',
       'CWE338_RANDOM_SOURCE_SEGMENTS' in law and 'Random' in law,
       'a chain that names a random source can never be exempted as a table')
    ok('t3.338.chain_must_be_readable', 'return False' in law and 'len(segments) < 2' in law,
       'anything that is not a plain attribute chain stays chargeable')
    ok('t3.338.seed_untouched', 'seed' not in ast_scanner.CWE338_DISPLAY_VALUE_MARKERS,
       'a seeded draw is the corpus bug; the sampling markers must never include it')

    envelope = body('_c209_structured_error_envelope_only')
    ok('t3.209.every_key', 'CWE209_STRUCTURED_ERROR_KEYS' in envelope
       and 'return False' in envelope,
       'an envelope is only an envelope when every key is a detail/error/message field')
    ok('t3.209.raw_trace_tested', 'CWE209_RAW_TRACE_ATTRIBUTES' in envelope,
       'a raw frame in the body has to be caught inside the envelope test itself')
    hop = body('_c209_envelope_payload_via_assignment')
    ok('t3.209.hop_is_literal_dict', 'ast.Dict' in hop and 'return None' in hop,
       'the one-hop body resolution must only answer for a dict literal and answer None otherwise')
    ok('t3.209.hop_called_from_envelope', 'self._c209_envelope_payload_via_assignment(' in envelope,
       'the envelope test must use the hop, or the assignment shape stays a false positive')

    noncred = body('_cwe328_hash_input_is_non_credential')
    ok('t3.328.veto_before_vocabulary',
       0 <= noncred.index('_cwe328_input_is_credential_named')
       < noncred.index('CWE328_CONTENT_HASH_KEYWORDS'),
       'a credential-named input has to be refused before any digest vocabulary is consulted')
    credential = body('_cwe328_input_is_credential_named')
    ok('t3.328.demotion_needs_a_bucket_word',
       'CWE328_DIGEST_QUALIFIERS' in credential and 'CWE338_SECURITY_NAME_WORDS' in credential
       and credential.index('CWE338_SECURITY_NAME_WORDS') < credential.index('CWE328_DIGEST_QUALIFIERS'),
       'the only demotion allowed is a security word that is itself a digest suffix next to a bucket word')

    guarded = body('_c704_conversion_is_in_guarded_try')
    ok('t3.704.body_only', 'current.body' in guarded,
       'only the try body is protected -- a call in the handler, else or finally is not')
    ok('t3.704.named_errors', 'CLUSTER2_NAN_CONVERSION_ERRORS' in guarded,
       'the handler has to name what a bad number raises')
    ok('t3.704.isinf_refused', 'isinf' not in ast_scanner.CLUSTER2_NAN_CHECKS,
       'an infinity check vouches for the range, not for NaN -- recording it as a NaN guard would '
       'silence a whole class of real conversion bugs')

    # Scope law: no suppression in this task may be a path or a filename decision.
    scope = '\n'.join([law, envelope, hop, guarded, credential, bindings, uncached])
    ok('t3.no_path_decisions',
       not any(token in scope for token in ("'.py'", '".py"', 'basename', 'tests/', 'examples/')),
       'a suppression that reads a filename or a folder is a blacklist wearing an AST costume')
    return passed, checks


_ORIG = {
    '918': TT._cwe918_request_is_a_query_builder,
    '338_class': TT._cwe338_choices_chain_denotes_a_choice_set,
    '338_draw': TT._cwe338_display_only_draw,
    '338_markers': ast_scanner.CWE338_DISPLAY_VALUE_MARKERS,
    '209_envelope': TT._c209_structured_error_envelope_only,
    '209_hop': TT._c209_envelope_payload_via_assignment,
    '328_vocabulary': ast_scanner.CWE328_CONTENT_HASH_KEYWORDS,
    '328_qualifiers': ast_scanner.CWE328_DIGEST_QUALIFIERS,
    '704_checks': ast_scanner.CLUSTER2_NAN_CHECKS,
    '704_errors': ast_scanner.CLUSTER2_NAN_CONVERSION_ERRORS,
    '704_names': TT._c704_guarded_names,
    '704_try': TT._c704_conversion_is_in_guarded_try,
}

# gains/losses are (fixture, cwe, line) triples measured once, with each fixture scanned on its own.
MUTATIONS = {
    '918_query_builder_proof_disabled': {
        'what': 'answer "not a query builder" for every call, so the Sentry query object written as '
                '`Request(app="errors", url=request.GET["url"])` after '
                '`from snuba_sdk.request import Request` charges as SSRF again -- and no HTTP client '
                'row is touched, because the proof is what tells them apart',
        'files': ('snuba_submodule.py', 'http_submodule.py'),
        'apply': lambda: setattr(TT, '_cwe918_request_is_a_query_builder',
                                 lambda self, call, mod: False),
        'restore': lambda: setattr(TT, '_cwe918_request_is_a_query_builder', _ORIG['918']),
        'gains': {('snuba_submodule.py', 'CWE-918', 11)},
        'losses': set(),
    },
    '338_choices_class_law_disabled': {
        'what': 'refuse the owning-class proof, so `manager.UpdateChannel.choices(raw)` -- a choices '
                'table reached through a parameter -- charges as a weak PRNG draw again, while the '
                'three token/otp/password draws keep charging',
        'files': ('choice_table.py', 'prng_loud.py'),
        'apply': lambda: setattr(TT, '_cwe338_choices_chain_denotes_a_choice_set',
                                 lambda self, receiver: False),
        'restore': lambda: setattr(TT, '_cwe338_choices_chain_denotes_a_choice_set',
                                   _ORIG['338_class']),
        'gains': {('choice_table.py', 'CWE-338', 9)},
        'losses': set(),
    },
    '338_sampling_markers_stripped': {
        'what': 'drop the mock/sample/fixture/jitter/downsample/experiment/bucket words this task '
                'added from the display-value vocabulary, so `random.choice([1, 2, 3])` inside '
                '`build_mock_event` charges again as CWE-338',
        'files': ('sampling_builder.py', 'prng_loud.py'),
        'apply': lambda: setattr(ast_scanner, 'CWE338_DISPLAY_VALUE_MARKERS',
                                 _ORIG['338_markers'] - TASK12_DISPLAY_MARKERS),
        'restore': lambda: setattr(ast_scanner, 'CWE338_DISPLAY_VALUE_MARKERS',
                                   _ORIG['338_markers']),
        'gains': {('sampling_builder.py', 'CWE-338', 5)},
        'losses': set(),
    },
    '338_display_draw_law_disabled': {
        'what': 'refuse the display-only-draw proof altogether: the mock builder comes back on both '
                'of its lines, and none of the three credential generators goes quiet, because the '
                'security-word veto is what keeps them loud',
        'files': ('sampling_builder.py', 'prng_loud.py'),
        'apply': lambda: setattr(TT, '_cwe338_display_only_draw', lambda self, node, scope='': False),
        'restore': lambda: setattr(TT, '_cwe338_display_only_draw', _ORIG['338_draw']),
        'gains': {('sampling_builder.py', 'CWE-338', 5), ('sampling_builder.py', 'CWE-338', 9)},
        'losses': set(),
    },
    '209_envelope_law_disabled': {
        'what': 'read no reply as a structured envelope, so `Response({"detail": str(exc)}, '
                'status=400)` and `JsonResponse({"message": str(exc)}, ...)` charge as stack trace '
                'exposure again while every `traceback.format_*` row keeps charging',
        'files': ('error_envelope.py', 'traceback_loud.py'),
        'apply': lambda: setattr(TT, '_c209_structured_error_envelope_only',
                                 lambda self, value, table=None, use_lineno=None: False),
        'restore': lambda: setattr(TT, '_c209_structured_error_envelope_only', _ORIG['209_envelope']),
        'gains': {('error_envelope.py', 'CWE-209', 12), ('error_envelope.py', 'CWE-209', 24),
                  ('error_envelope.py', 'CWE-209', 37)},
        'losses': set(),
    },
    '209_assignment_hop_disabled': {
        'what': 'stop resolving `body = {"detail": str(exc)}` into the `Response(body, ...)` that '
                'uses it, so the one shape the literal-dict test cannot see charges again',
        'files': ('error_envelope.py', 'traceback_loud.py'),
        'apply': lambda: setattr(TT, '_c209_envelope_payload_via_assignment',
                                 lambda self, reply, table, use_lineno: None),
        'restore': lambda: setattr(TT, '_c209_envelope_payload_via_assignment', _ORIG['209_hop']),
        'gains': {('error_envelope.py', 'CWE-209', 37)},
        'losses': set(),
    },
    '328_digest_vocabulary_stripped': {
        'what': 'remove the eight digest words this task added (`commit`, `revision`, `content_hash`, '
                '`file_hash`, `sha1_text`, `md5_text`, `cache`, `mock`), so a commit revision and a '
                'mocked payload digest charge as weak hashing again',
        'files': ('content_digest.py', 'credential_digest.py'),
        'apply': lambda: setattr(ast_scanner, 'CWE328_CONTENT_HASH_KEYWORDS',
                                 tuple(word for word in _ORIG['328_vocabulary']
                                       if word not in TASK12_DIGEST_WORDS)),
        'restore': lambda: setattr(ast_scanner, 'CWE328_CONTENT_HASH_KEYWORDS',
                                   _ORIG['328_vocabulary']),
        'gains': {('content_digest.py', 'CWE-328', 9), ('content_digest.py', 'CWE-328', 17)},
        'losses': set(),
    },
    '328_digest_qualifiers_emptied': {
        'what': 'empty the qualifier set that lets a `..._hash`/`..._key` name read as a bucket, so '
                '`chunk_cache_key(content_hash)` charges again as CWE-328',
        'files': ('content_digest.py', 'credential_digest.py'),
        'apply': lambda: setattr(ast_scanner, 'CWE328_DIGEST_QUALIFIERS', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE328_DIGEST_QUALIFIERS', _ORIG['328_qualifiers']),
        'gains': {('content_digest.py', 'CWE-328', 13)},
        'losses': set(),
    },
    '704_nan_checks_emptied': {
        'what': 'unlearn `isnan`/`isfinite` and `TypeError`/`ValueError`, so the conversion in the '
                'try body and the one followed by a finiteness test both charge as CWE-704 again',
        'files': ('guarded_float.py', 'bare_float.py'),
        'apply': lambda: (setattr(ast_scanner, 'CLUSTER2_NAN_CHECKS', set()),
                          setattr(ast_scanner, 'CLUSTER2_NAN_CONVERSION_ERRORS', set())),
        'restore': lambda: (setattr(ast_scanner, 'CLUSTER2_NAN_CHECKS', _ORIG['704_checks']),
                            setattr(ast_scanner, 'CLUSTER2_NAN_CONVERSION_ERRORS',
                                    _ORIG['704_errors'])),
        'gains': {('guarded_float.py', 'CWE-704', 6), ('guarded_float.py', 'CWE-704', 15)},
        'losses': set(),
    },
    '704_guard_names_disabled': {
        'what': 'name nothing as guarded -- neither the operand nor the assignment target, and not a '
                'try body either -- so all three NaN-checked conversions charge, while the three '
                'unguarded ones were already charging',
        'files': ('guarded_float.py', 'bare_float.py'),
        'apply': lambda: (setattr(TT, '_c704_guarded_names', lambda self, node, arg: set()),
                          setattr(TT, '_c704_conversion_is_in_guarded_try',
                                  lambda self, node: False)),
        'restore': lambda: (setattr(TT, '_c704_guarded_names', _ORIG['704_names']),
                            setattr(TT, '_c704_conversion_is_in_guarded_try', _ORIG['704_try'])),
        'gains': {('guarded_float.py', 'CWE-704', 6), ('guarded_float.py', 'CWE-704', 15),
                  ('guarded_float.py', 'CWE-704', 22)},
        'losses': set(),
    },
}

_RESTORED = {
    'TT._cwe918_request_is_a_query_builder':
        lambda: TT._cwe918_request_is_a_query_builder is _ORIG['918'],
    'TT._cwe338_choices_chain_denotes_a_choice_set':
        lambda: TT._cwe338_choices_chain_denotes_a_choice_set is _ORIG['338_class'],
    'TT._cwe338_display_only_draw': lambda: TT._cwe338_display_only_draw is _ORIG['338_draw'],
    'CWE338_DISPLAY_VALUE_MARKERS':
        lambda: ast_scanner.CWE338_DISPLAY_VALUE_MARKERS is _ORIG['338_markers'],
    'TT._c209_structured_error_envelope_only':
        lambda: TT._c209_structured_error_envelope_only is _ORIG['209_envelope'],
    'TT._c209_envelope_payload_via_assignment':
        lambda: TT._c209_envelope_payload_via_assignment is _ORIG['209_hop'],
    'CWE328_CONTENT_HASH_KEYWORDS':
        lambda: ast_scanner.CWE328_CONTENT_HASH_KEYWORDS is _ORIG['328_vocabulary'],
    'CWE328_DIGEST_QUALIFIERS':
        lambda: ast_scanner.CWE328_DIGEST_QUALIFIERS is _ORIG['328_qualifiers'],
    'CLUSTER2_NAN_CHECKS': lambda: ast_scanner.CLUSTER2_NAN_CHECKS is _ORIG['704_checks'],
    'CLUSTER2_NAN_CONVERSION_ERRORS':
        lambda: ast_scanner.CLUSTER2_NAN_CONVERSION_ERRORS is _ORIG['704_errors'],
    'TT._c704_guarded_names': lambda: TT._c704_guarded_names is _ORIG['704_names'],
    'TT._c704_conversion_is_in_guarded_try':
        lambda: TT._c704_conversion_is_in_guarded_try is _ORIG['704_try'],
}


def run_mutation(name) -> int:
    spec = MUTATIONS[name]
    print('# %s -- %s' % (name, spec['what']))
    spec['apply']()
    try:
        stem = 't4_%s_' % ''.join(ch if ch.isalnum() else '_' for ch in name)[:20]
        gained, lost, seconds = set(), set(), 0.0
        # One fixture per scan: the engine decides once per scan what an imported name means, and two
        # of these fixtures spell the same sink name (`Request`). Measured, mixing them makes the
        # falsifier inert -- it stops resurrecting the row its own guard owns.
        for key in spec['files']:
            _t0 = time.time()
            _tracker, rows = scan_all({stem + key: FIXTURES[key]})
            seconds += time.time() - _t0
            found = {pair for pairs in basenames(rows).values() for pair in pairs}
            gained |= {(key, cwe, line) for (cwe, line) in BLESSED[key]['quiet'] if (cwe, line) in found}
            lost |= {(key, cwe, line) for (cwe, line) in BLESSED[key]['loud'] & ISOLATED[key]
                     if (cwe, line) not in found}
        if gained == spec['gains'] and lost == spec['losses']:
            if seconds > BUDGET_MUTATION_SECONDS:
                fail('mutation.%s.time' % name,
                     'a falsifier costing %.2fs over the %.1fs budget stops being run'
                     % (seconds, BUDGET_MUTATION_SECONDS))
                return 1
            print('  CAUGHT in %.2fs: rows back %s, rows lost %s'
                  % (seconds, sorted(gained), sorted(lost)))
            return 0
        print('  NOT CAUGHT: expected gained=%s lost=%s, got gained=%s lost=%s'
              % (sorted(spec['gains']), sorted(spec['losses']), sorted(gained), sorted(lost)))
        return 1
    finally:
        spec['restore']()


def rss_mb():
    try:
        import psutil
    except Exception:
        return None
    return psutil.Process(os.getpid()).memory_info().rss / 1048576.0


# ─── driver ────────────────────────────────────────────────────────────────────────────────────
def main() -> int:
    if len(sys.argv) > 2 and sys.argv[1] == '--mutation':
        name = sys.argv[2]
        if name not in MUTATIONS:
            print('unknown mutation %r; known: %s' % (name, ', '.join(sorted(MUTATIONS))))
            return 2
        return run_mutation(name)
    if len(sys.argv) > 1 and sys.argv[1] == '--dump':
        dump_table(BASE_ROWS)
        return 0

    total = 0
    sections = []
    for label, fn in (('TIER 1  predicate robustness', tier1_predicates),
                      ('TIER 2  shipped verdicts', tier2_verdicts),
                      ('TIER 3  source laws', tier3_laws)):
        p, c = fn()
        sections.append((label, p, c))
        total += c

    rss_mid = rss_mb()
    for label, ok_count, count in sections:
        print('%-30s %2d/%-2d' % (label, ok_count, count))
    dump_table(BASE_ROWS)

    # Every guard above is load-bearing: each mutation is applied to the shipped pipeline, must move
    # exactly the rows its guard owns, and must be undone so the next check sees the real engine.
    caught, mut_seconds = 0, 0.0
    for name in sorted(MUTATIONS):
        total += 1
        _t0 = time.time()
        if run_mutation(name) == 0:
            caught += 1
        else:
            fail('mutation.%s' % name, 'the guard is not load-bearing (see the report above)')
        mut_seconds += time.time() - _t0
    total += 1
    stuck = [label for label, test in sorted(_RESTORED.items()) if not test()]
    if stuck:
        fail('mutation.restore', 'not undone: %s -- the gate would then be locking something the '
                                 'shipped engine does not do' % stuck)
    print('  falsifiers                   %2d/%-2d (each moved exactly the rows its guard owns)'
          % (caught, len(MUTATIONS)))

    total += 2
    elapsed = time.time() - WORK_START
    rss = rss_mb()
    if elapsed > BUDGET_SECONDS:
        fail('t5.time', '%.2fs of gate work over the %.1fs budget' % (elapsed, BUDGET_SECONDS))
    if rss is None:
        fail('t5.rss', 'no RSS reading -- an unmeasured budget is not a budget')
    elif rss >= BUDGET_RSS_MB:
        fail('t5.rss', '%.1f MB over the %.1f MB budget' % (rss, BUDGET_RSS_MB))

    if FAILS:
        for line in FAILS:
            print('FAIL %s' % line)
        print('VERDICT: FAIL - %d problem(s)' % len(FAILS))
        return 1
    print('  gate work %.2fs (budget %.1fs), falsifiers %.2fs summed (%.2fs per falsifier), '
          'RSS %s MB (budget %.1f), mid-suite RSS %s MB'
          % (elapsed, BUDGET_SECONDS, mut_seconds, mut_seconds / len(MUTATIONS),
             ('%.1f' % rss) if rss else 'n/a', BUDGET_RSS_MB,
             ('%.1f' % rss_mid) if rss_mid else 'n/a'))
    print('VERDICT: PASS - tier4 precision %d/%d checks, %d falsifiers, %.2fs'
          % (total, total, len(MUTATIONS), elapsed))
    return 0


if __name__ == '__main__':
    sys.exit(main())
