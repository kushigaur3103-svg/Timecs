"""TASK 13 zero-FP lock -- the last five Sentry buckets retired on top of `708ef1d`.

Read this file as a contract with five clauses. Each names a shape Sentry (`24.2.0`, cloud run
`708ef1d`, 549 findings) charged, says in one sentence why the charge is wrong, and pins the opposite
shape that must keep charging:

  1. CWE-209  `self.respond({"detail": str(exc)}, status=400)` -- the endpoint's own responder hands
              the same fixed JSON envelope to `Response(...)` one frame down. A `traceback.*` call, a
              raw frame, or one key outside the envelope vocabulary keeps the row loud.
  2. CWE-862  `class OrganizationDetailsEndpoint(OrganizationEndpoint)` -- the domain-scoped base
              resolves the organisation and runs its own permission pass, so the subclass inherits
              the check. A generic `Endpoint`/`APIView` base, or `permission_classes = ()` /
              `(AllowAny,)`, stays loud.
  3. CWE-338  `random.*` inside telemetry/slug/nudge builders that name no credential. A token/otp
              draw and a `seed` draw stay loud. (The class-owned `.choices` chain is gate #55's.)
  4. CWE-328  grouping/fingerprint/release/replay/span digests -- a digest that decides which row an
              event lands in. Any credential-named input vetoes first, and CWE-916 is untouched.
  5. CWE-704  `float(request.GET[...])` in a `try` whose handler REFUSES the value: `raise
              ValidationError(...)` or a 4xx reply. A handler that returns `0.0`, or one that cannot
              catch what a bad number raises, stays loud.

Every asserted row is measured, never assumed, and each fixture is scanned on its own under a module
stem of its own: the engine resolves an imported name once per scan, so two fixtures spelling the same
sink in one subset let one file's import table answer for the other's and a live guard measures inert.

The CWE-209 fixtures carry one handler each on purpose. `respond` is a DISPATCHER -- a local def that
feeds one of its own parameters to `Response(...)` -- and the finding is anchored at the dispatcher's
reply line, deduplicated per line. Three handlers behind one responder would collapse into one row,
and a falsifier that removed a single veto arm would hide behind the other two.
"""
from __future__ import annotations

import ast
import collections
import contextlib
import inspect
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

WORK_START = time.time()
BUDGET_SECONDS = 15.0
BUDGET_MUTATION_SECONDS = 2.0
BUDGET_RSS_MB = 60.0

FAILS = []

# The vocabulary this task added, named here so a falsifier removes exactly this task's words.
TASK13_ENVELOPE_KEYS = frozenset({"status", "reason", "title", "non_field_errors", "slug", "type"})
TASK13_DISPLAY_MARKERS = frozenset({"telemetry", "slug", "slugs", "nudge", "nudges"})
TASK13_DIGEST_QUALIFIERS = frozenset({
    "fingerprint", "grouping", "occurrence", "forecast", "bundle", "release", "attachment",
    "debug", "replay", "outbox", "redis", "silo", "beacon", "collectstatic", "span",
    "event_id", "problem_hash", "event", "problem",
})
TASK13_ENDPOINT_BASES = frozenset({
    "OrganizationEndpoint", "ProjectEndpoint", "TeamEndpoint", "GroupEndpoint", "UserEndpoint",
    "MemberEndpoint", "IntegrationEndpoint", "SentryAppEndpoint", "MonitorEndpoint",
    "IncidentEndpoint", "AlertRuleEndpoint", "ReplayEndpoint", "ReleaseEndpoint",
    "EnvironmentEndpoint",
})


def fail(what, msg):
    FAILS.append('%s: %s' % (what, msg))


# ─── 1. CWE-209: the endpoint's own responder, against the frame that travels ──────────────────
RESPOND_ENVELOPE = '''from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        return Response(detail, status=status)


class CustomRulePreview(Endpoint):
    def post(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return self.respond({"detail": str(exc)}, status=400)

    def patch(self, request):
        try:
            return self.run(request)
        except KeyError as exc:
            body = {"message": str(exc)}
            return self.respond(body, status=400)
'''
RESPOND_WIDE_KEYS = '''from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        return Response(detail, status=status)


class GroupIntegrationDetails(Endpoint):
    def put(self, request):
        try:
            return self.run(request)
        except ValueError as exc:
            return self.respond({"error": str(exc), "status": 400, "reason": "invalid"}, status=400)
'''
RESPOND_TRACEBACK = '''import traceback

from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        return Response(detail, status=status)


class BrokenPreview(Endpoint):
    def post(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return self.respond({"detail": traceback.format_exc()}, status=400)
'''
RESPOND_RAW_FRAME = '''from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        return Response(detail, status=status)


class BrokenPreview(Endpoint):
    def post(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return self.respond({"detail": exc.__traceback__}, status=400)
'''
RESPOND_FOREIGN_KEY = '''from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        return Response(detail, status=status)


class BrokenPreview(Endpoint):
    def post(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return self.respond({"traceback": str(exc)}, status=400)
'''
# ─── 2. CWE-862: the domain-scoped base, against the generic view and the opt-out ──────────────
DOMAIN_ENDPOINT = '''from sentry.api.base import OrganizationEndpoint, ProjectEndpoint
from sentry.models import Organization, Project


class OrganizationDetailsEndpoint(OrganizationEndpoint):
    def get(self, request, organization_slug):
        return Organization.objects.get(slug=organization_slug)


class ProjectDetailsEndpoint(ProjectEndpoint):
    def get(self, request, project_slug):
        return Project.objects.get(slug=project_slug)
'''
GENERIC_ENDPOINT = '''from rest_framework.views import APIView
from sentry.api.base import Endpoint
from sentry.models import Organization


class PublicOrganizationView(APIView):
    def get(self, request, organization_slug):
        return Organization.objects.get(slug=organization_slug)


class PublicOrganizationEndpoint(Endpoint):
    def get(self, request, organization_slug):
        return Organization.objects.get(slug=organization_slug)
'''
OPT_OUT_ENDPOINT = '''from rest_framework.permissions import AllowAny
from sentry.api.base import OrganizationEndpoint
from sentry.models import Organization


class OpenOrganizationEndpoint(OrganizationEndpoint):
    permission_classes = ()

    def get(self, request, organization_slug):
        return Organization.objects.get(slug=organization_slug)


class AllowAnyOrganizationEndpoint(OrganizationEndpoint):
    permission_classes = (AllowAny,)

    def get(self, request, organization_slug):
        return Organization.objects.get(slug=organization_slug)
'''
# ─── 3. CWE-338: telemetry/slug/nudge builders, against the token and the seed ─────────────────
TELEMETRY_BUILDER = '''import random


def emit_telemetry(attempt):
    return random.choice([1, 2, 3])


def unique_slug(base):
    return base + "-" + str(random.randint(1000, 9999))


def next_nudge(attempt):
    return random.uniform(0.5, 1.5) * attempt
'''
SEED_LOUD = '''import random
import string


def mint_api_token():
    return "".join(random.choice(string.ascii_letters) for _ in range(32))


def reseed_rng():
    seed = random.randint(0, 2 ** 31)
    return seed


def make_otp(nonce):
    return random.randint(100000, 999999)
'''
# ─── 4. CWE-328: grouping digests, against the credential digest ───────────────────────────────
GROUPING_DIGEST = '''import hashlib


def problem_hash(event):
    return hashlib.md5(str(event)).hexdigest()


def grouping_fingerprint(payload):
    return hashlib.sha1(str(payload)).hexdigest()


def release_bundle_checksum(release):
    return hashlib.md5(str(release)).hexdigest()


def replay_cache_key(span):
    return hashlib.sha1(str(span)).hexdigest()
'''
CREDENTIAL_DIGEST_LOUD = '''import hashlib


def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def token_fingerprint(api_key):
    return hashlib.sha1(api_key.encode()).hexdigest()


def session_grouping(session_id):
    return hashlib.md5(str(session_id)).hexdigest()
'''
# ─── 5. CWE-704: the handler that refuses, against the handler that lets the value through ─────
REJECTED_FLOAT = '''from rest_framework.exceptions import ValidationError
from rest_framework.response import Response


def parse_rate(request):
    try:
        return float(request.GET["rate"])
    except Exception:
        raise ValidationError("rate must be a number")


def parse_weight(request):
    try:
        return float(request.GET["weight"])
    except Exception:
        return Response({"detail": "weight must be a number"}, status=400)


def parse_scale(request):
    try:
        return float(request.GET["scale"])
    except (TypeError, ValueError):
        raise ValidationError("scale must be a number")
'''
BARE_FLOAT_LOUD = '''def parse_page(request):
    return float(request.GET["page"])


def parse_offset(request):
    try:
        return float(request.GET["offset"])
    except KeyError:
        return 0.0


def parse_limit(request):
    try:
        return float(request.GET["limit"])
    except KeyError:
        return Response({"detail": "bad limit"}, status=400)
'''
# The real Sentry layout: the responder lives in `sentry/api/base.py` and the endpoint that calls it
# is a different module. The single-module dispatcher proof above cannot see this, so the pair is
# scanned together and the row -- if the engine still charges it -- belongs to the caller.
CROSS_API_BASE = '''from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        payload = detail if detail is not None else {}
        return Response(payload, status=status)
'''
CROSS_CUSTOM_RULES = '''import traceback

from sentry.api.base import Endpoint


class RulePreviewEndpoint(Endpoint):
    def post(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return self.respond({"detail": str(exc)}, status=400)

    def put(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return self.respond({"detail": traceback.format_exc()}, status=400)
'''

FIXTURES = {
    'respond_envelope.py': RESPOND_ENVELOPE,
    'respond_wide_keys.py': RESPOND_WIDE_KEYS,
    'respond_traceback.py': RESPOND_TRACEBACK,
    'respond_raw_frame.py': RESPOND_RAW_FRAME,
    'respond_foreign_key.py': RESPOND_FOREIGN_KEY,
    'domain_endpoint.py': DOMAIN_ENDPOINT,
    'generic_endpoint.py': GENERIC_ENDPOINT,
    'opt_out_endpoint.py': OPT_OUT_ENDPOINT,
    'telemetry_builder.py': TELEMETRY_BUILDER,
    'seed_loud.py': SEED_LOUD,
    'grouping_digest.py': GROUPING_DIGEST,
    'credential_digest_loud.py': CREDENTIAL_DIGEST_LOUD,
    'rejected_float.py': REJECTED_FLOAT,
    'bare_float_loud.py': BARE_FLOAT_LOUD,
    'base.py': CROSS_API_BASE,
    'custom_rules.py': CROSS_CUSTOM_RULES,
}

# The isolation law says one fixture per scan, because the engine resolves an imported name once per
# scan. The cross-module pair is the deliberate exception: it only means anything when both files are
# in the SAME subset, so it is isolated as a group of two rather than as two lone fixtures. The stems
# are `base` and `custom_rules` because Sentry's endpoint writes `from sentry.api.base import
# Endpoint`, and a fixture the resolver cannot name is a fixture the engine never sees.
GROUPS = {module: (module,) for module in FIXTURES}
GROUPS['base.py'] = ('base.py', 'custom_rules.py')
GROUPS['custom_rules.py'] = ('base.py', 'custom_rules.py')

# quiet = the charge this task retired, which must NOT appear. loud = the opposite shape, which must.
# Every line below was read off a scan of this file's own fixtures, not inferred from the brief.
BLESSED = {
    'respond_envelope.py': ({('CWE-209', 6)}, set()),
    'respond_wide_keys.py': ({('CWE-209', 6)}, set()),
    'respond_traceback.py': (set(), {('CWE-209', 8), ('CWE-200', 16)}),
    'respond_raw_frame.py': (set(), {('CWE-209', 6)}),
    'respond_foreign_key.py': (set(), {('CWE-209', 6)}),
    'domain_endpoint.py': ({('CWE-862', 6), ('CWE-862', 11)}, set()),
    'generic_endpoint.py': (set(), {('CWE-862', 7), ('CWE-862', 12)}),
    'opt_out_endpoint.py': (set(), {('CWE-862', 9), ('CWE-862', 16)}),
    'telemetry_builder.py': ({('CWE-338', 5), ('CWE-338', 9), ('CWE-338', 13)}, set()),
    'seed_loud.py': (set(), {('CWE-338', 6), ('CWE-338', 10), ('CWE-338', 15)}),
    'grouping_digest.py': ({('CWE-328', 5), ('CWE-328', 9), ('CWE-328', 13), ('CWE-328', 17)}, set()),
    'credential_digest_loud.py': (set(), {('CWE-328', 5), ('CWE-328', 9), ('CWE-328', 13),
                                          ('CWE-759', 5), ('CWE-759', 9), ('CWE-759', 13),
                                          ('CWE-916', 5), ('CWE-916', 9), ('CWE-916', 13)}),
    'rejected_float.py': ({('CWE-704', 7), ('CWE-704', 14), ('CWE-704', 21)}, set()),
    'bare_float_loud.py': (set(), {('CWE-704', 2), ('CWE-704', 7), ('CWE-704', 14)}),
    # Cross-module truth, measured not assumed: when the responder lives in another file, the plain
    # envelope already charges nothing, and the traceback that travels in it is charged as CWE-200 AT
    # THE CALL SITE. So the CWE-209 dispatcher proof above is not what silences Sentry's
    # `custom_rules.py` rows -- this pair is what says so out loud, and it keeps the frame reported.
    'custom_rules.py': ({('CWE-209', 11), ('CWE-200', 11)}, {('CWE-200', 17)}),
    'base.py': (set(), set()),
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
ROWS = basenames(BASE_ROWS)

# One fixture per scan: the reference a mutation's losses are judged against. A row that only exists
# when several fixtures share a scan is not a stable fact about the engine and is never pinned.
ISOLATED = {module: set() for module in FIXTURES}
for _group in sorted(set(GROUPS[module] for module in FIXTURES), key=lambda g: g[0]):
    _t, _rows = scan_all({'t5_isolated_%s' % _m: FIXTURES[_m] for _m in _group})
    for _row in _rows:
        _name = os.path.basename(str(_row['file']).replace('\\', '/'))
        ISOLATED[_name[len('t5_isolated_'):]].add((_row['cwe'], int(_row['line'])))


def dump_table(rows):
    by = basenames(rows)
    for module in FIXTURES:
        per_cwe = collections.defaultdict(set)
        for cwe, line in by.get(module, set()):
            per_cwe[cwe].add(line)
        print('%-26s %s' % (module, {k: sorted(v) for k, v in sorted(per_cwe.items())}))
    print('rows=%d' % len(rows))


def tier1_predicates():
    """The vocabulary and the refusals, read straight off the engine."""
    checks = []

    def check(name, ok, detail=''):
        checks.append(name)
        if not ok:
            fail('predicate.%s' % name, detail or 'false')

    keys = ast_scanner.CWE209_STRUCTURED_ERROR_KEYS
    check('209_envelope_keys_widened', TASK13_ENVELOPE_KEYS <= keys, sorted(TASK13_ENVELOPE_KEYS - keys))
    check('209_traceback_key_never_a_label', 'traceback' not in keys and 'stack' not in keys)
    check('209_responder_is_not_an_exposure_sink',
          'respond' not in ast_scanner.RESPONSE_CONSTRUCTOR_NAMES,
          'widening RESPONSE_CONSTRUCTOR_NAMES would invent new CWE-209 rows')
    check('209_payload_test_exists', hasattr(TT, '_c209_payload_is_structured_envelope'))

    bases = ast_scanner.CWE862_DOMAIN_SCOPED_ENDPOINT_BASES
    check('862_domain_bases_listed', TASK13_ENDPOINT_BASES <= bases, sorted(TASK13_ENDPOINT_BASES - bases))
    check('862_generic_bases_never_domain_scoped',
          not (bases & {'Endpoint', 'APIView', 'View', 'ViewSet', 'GenericAPIView'}),
          sorted(bases & {'Endpoint', 'APIView', 'View', 'ViewSet', 'GenericAPIView'}))
    check('862_base_proof_exists', hasattr(TT, '_c862_class_inherits_domain_scoped_endpoint'))
    check('862_opt_out_proof_exists', hasattr(TT, '_c862_class_disables_permissions'))

    markers = ast_scanner.CWE338_DISPLAY_VALUE_MARKERS
    check('338_telemetry_markers_added', TASK13_DISPLAY_MARKERS <= markers,
          sorted(TASK13_DISPLAY_MARKERS - markers))
    check('338_seed_is_never_a_display_marker', 'seed' not in markers)
    check('338_credential_words_untouched',
          {'token', 'secret', 'password', 'otp', 'nonce', 'seed'}
          <= ast_scanner.CWE338_SECURITY_NAME_WORDS)

    qualifiers = ast_scanner.CWE328_DIGEST_QUALIFIERS
    check('328_digest_qualifiers_added', TASK13_DIGEST_QUALIFIERS <= qualifiers,
          sorted(TASK13_DIGEST_QUALIFIERS - qualifiers))
    check('328_credential_words_never_qualifiers',
          not (qualifiers & {'password', 'passwd', 'token', 'secret', 'api_key', 'session', 'salt'}))
    check('328_helper_name_proof_exists', hasattr(TT, '_cwe328_helper_name_is_a_content_digest'))
    check('328_suffix_words_unchanged',
          ast_scanner.CWE328_DIGEST_SUFFIX_WORDS == frozenset({'hash', 'hashes'}))

    check('704_rejection_errors', ast_scanner.CLUSTER2_NAN_REJECTION_ERRORS
          == {'ValidationError', 'ParseError', 'BadRequest'})
    check('704_rejection_catches_cover_conversion_errors',
          ast_scanner.CLUSTER2_NAN_CONVERSION_ERRORS <= ast_scanner.CLUSTER2_NAN_REJECTION_CATCHES)
    check('704_rejection_catches_include_bare_handlers',
          {'Exception', 'BaseException'} <= ast_scanner.CLUSTER2_NAN_REJECTION_CATCHES)
    check('704_rejection_status_range_is_4xx',
          ast_scanner.CLUSTER2_NAN_REJECTION_STATUS_RANGE == (400, 499))
    check('704_rejection_proof_exists', hasattr(TT, '_c704_handler_rejects_the_value'))
    return checks


def tier2_verdicts():
    """Every blessed row, against the shipped scan and against the isolated scan."""
    checks = []
    for module, (quiet, loud) in BLESSED.items():
        shipped = ROWS.get(module, set())
        alone = ISOLATED[module]
        for cwe, line in sorted(quiet):
            checks.append('%s.quiet.%s:%d' % (module, cwe, line))
            if (cwe, line) in shipped:
                fail('verdict.%s' % module, '%s:%d is still loud' % (cwe, line))
        for cwe, line in sorted(loud):
            checks.append('%s.loud.%s:%d' % (module, cwe, line))
            if (cwe, line) not in shipped:
                fail('verdict.%s' % module, '%s:%d went quiet' % (cwe, line))
            if (cwe, line) not in alone:
                fail('verdict.%s' % module, '%s:%d only exists in a shared scan' % (cwe, line))
        checks.append('%s.isolated_matches_shipped' % module)
        if alone != shipped:
            fail('verdict.%s' % module, 'isolated %s != shipped %s'
                 % (sorted(alone - shipped), sorted(shipped - alone)))
    return checks


def tier3_laws():
    """Source-level laws: the order of the proofs, which is what keeps a retirement fail-closed."""
    checks = []

    def law(name, ok, detail=''):
        checks.append(name)
        if not ok:
            fail('law.%s' % name, detail or 'false')

    def body(method):
        return inspect.getsource(method)

    dispatcher = body(TT._c209_dispatcher_reply)
    law('209_envelope_refusal_precedes_detail',
        '_c209_payload_is_structured_envelope' in dispatcher
        and dispatcher.index('_c209_payload_is_structured_envelope')
        < dispatcher.index('_c209_carries_detail'),
        'the dispatcher must refuse a proven envelope before it reads detail')
    payload_test = body(TT._c209_payload_is_structured_envelope)
    law('209_payload_test_reads_keys_and_both_vetoes',
        all(word in payload_test for word in
            ('CWE209_STRUCTURED_ERROR_KEYS', 'TRACEBACK_FORMAT_FUNCS', 'CWE209_RAW_TRACE_ATTRIBUTES')))
    law('209_payload_test_refuses_an_empty_body', 'not payload.keys' in payload_test)
    envelope = body(TT._c209_structured_error_envelope_only)
    law('209_both_reply_paths_share_one_payload_test',
        '_c209_payload_is_structured_envelope' in envelope)
    law('209_one_hop_body_still_resolved', '_c209_envelope_payload_via_assignment' in envelope)

    scope = body(TT._c862_scope_is_guarded_or_off_http)
    law('862_domain_base_is_an_authorisation_proof',
        '_c862_class_inherits_domain_scoped_endpoint' in scope)
    law('862_opt_out_refuses_the_domain_base',
        'not self._c862_class_disables_permissions' in scope)
    law('862_explicit_permission_guard_still_first',
        scope.index('_class_declares_permission_guard')
        < scope.index('_c862_class_inherits_domain_scoped_endpoint'))
    opt_out = body(TT._c862_class_disables_permissions)
    law('862_opt_out_reads_the_permission_value',
        '_permission_value_declares_a_check' in opt_out and 'permission_classes' in opt_out)
    law('862_opt_out_ignores_a_bare_annotation', 'stmt.value is None' in opt_out)
    reach = body(TT._c862_scope_is_http_entrypoint)
    law('862_reachability_axis_untouched',
        '_c862_class_inherits_domain_scoped_endpoint' not in reach,
        'a domain endpoint IS reachable; only its authorisation is inherited')

    digest = body(TT._cwe328_hash_input_is_non_credential)
    law('328_credential_veto_runs_first',
        digest.index('_cwe328_input_is_credential_named') < digest.index('_is_exempt_cwe327'))
    law('328_credential_veto_precedes_helper_name_proof',
        digest.index('_cwe328_input_is_credential_named')
        < digest.index('_cwe328_helper_name_is_a_content_digest'))
    helper = body(TT._cwe328_helper_name_is_a_content_digest)
    law('328_helper_name_needs_suffix_and_qualifier',
        'CWE328_DIGEST_SUFFIX_WORDS' in helper and 'CWE328_DIGEST_QUALIFIERS' in helper)
    law('328_helper_name_refuses_a_credential_name',
        '_cwe328_digest_name_is_not_a_credential' in helper
        and 'CWE338_SECURITY_NAME_WORDS' in body(TT._cwe328_digest_name_is_not_a_credential),
        'the digest-helper proof must still refuse a name that says credential')
    law('328_helper_name_reads_segments_not_substrings', '_CWE338_NAME_SPLIT.split' in helper)

    guarded = body(TT._c704_conversion_is_in_guarded_try)
    law('704_named_conversion_catch_still_first',
        guarded.index('CLUSTER2_NAN_CONVERSION_ERRORS')
        < guarded.index('CLUSTER2_NAN_REJECTION_CATCHES'))
    law('704_rejection_is_consulted', '_c704_handler_rejects_the_value' in guarded)
    law('704_only_a_try_body_counts', 'any(child is stmt for stmt in current.body)' in guarded)
    rejects = body(TT._c704_handler_rejects_the_value)
    law('704_rejection_reads_errors_and_status',
        'CLUSTER2_NAN_REJECTION_ERRORS' in rejects
        and 'CLUSTER2_NAN_REJECTION_STATUS_RANGE' in rejects)
    law('704_rejection_refuses_a_plain_value_return', 'return False' in rejects)

    draw = body(TT._cwe338_display_only_draw)
    law('338_comparison_operand_still_read',
        'ast.Compare' in draw and 'comparators' in draw,
        'TASK 12 FN heal: a marker in the def name must not outvote a security operand')

    own_source = open(os.path.abspath(__file__), encoding='utf-8').read()
    law('gate_never_execs_source',
        not re.search(r'\b(exec|compile)\s*\(', own_source),
        'aa_parity scans benchmark/; a live exec/compile would add a row to the frozen baseline')
    return checks


# ─── falsifiers: each removes exactly one proof and measures what comes back ───────────────────
_ORIG = {
    'payload': TT._c209_payload_is_structured_envelope,
    'keys': ast_scanner.CWE209_STRUCTURED_ERROR_KEYS,
    'raw_trace': ast_scanner.CWE209_RAW_TRACE_ATTRIBUTES,
    'domain_base': TT._c862_class_inherits_domain_scoped_endpoint,
    'opt_out': TT._c862_class_disables_permissions,
    'markers': ast_scanner.CWE338_DISPLAY_VALUE_MARKERS,
    'qualifiers': ast_scanner.CWE328_DIGEST_QUALIFIERS,
    'helper_name': TT._cwe328_helper_name_is_a_content_digest,
    'rejects': TT._c704_handler_rejects_the_value,
    'catches': ast_scanner.CLUSTER2_NAN_REJECTION_CATCHES,
    'errors': ast_scanner.CLUSTER2_NAN_REJECTION_ERRORS,
}


def _set(method, value):
    setattr(TT, method, value)


def _restore_all():
    TT._c209_payload_is_structured_envelope = _ORIG['payload']
    ast_scanner.CWE209_STRUCTURED_ERROR_KEYS = _ORIG['keys']
    ast_scanner.CWE209_RAW_TRACE_ATTRIBUTES = _ORIG['raw_trace']
    TT._c862_class_inherits_domain_scoped_endpoint = _ORIG['domain_base']
    TT._c862_class_disables_permissions = _ORIG['opt_out']
    ast_scanner.CWE338_DISPLAY_VALUE_MARKERS = _ORIG['markers']
    ast_scanner.CWE328_DIGEST_QUALIFIERS = _ORIG['qualifiers']
    TT._cwe328_helper_name_is_a_content_digest = _ORIG['helper_name']
    TT._c704_handler_rejects_the_value = _ORIG['rejects']
    ast_scanner.CLUSTER2_NAN_REJECTION_CATCHES = _ORIG['catches']
    ast_scanner.CLUSTER2_NAN_REJECTION_ERRORS = _ORIG['errors']


MUTATIONS = {
    '209_envelope_payload_proof_disabled': {
        'why': 'the dispatcher stops recognising a structured envelope, so every self.respond body '
               'is charged again',
        'apply': lambda: _set('_c209_payload_is_structured_envelope', lambda self, payload: False),
        'restore': lambda: _set('_c209_payload_is_structured_envelope', _ORIG['payload']),
        'gains': {'respond_envelope.py': {('CWE-209', 6)}, 'respond_wide_keys.py': {('CWE-209', 6)}},
        'losses': {},
    },
    '209_envelope_keys_narrowed': {
        'why': "only this task's six labels are removed, so the wide-key envelope is charged again "
               'while the plain detail envelope stays quiet',
        'apply': lambda: setattr(ast_scanner, 'CWE209_STRUCTURED_ERROR_KEYS',
                                 _ORIG['keys'] - TASK13_ENVELOPE_KEYS),
        'restore': lambda: setattr(ast_scanner, 'CWE209_STRUCTURED_ERROR_KEYS', _ORIG['keys']),
        'gains': {'respond_wide_keys.py': {('CWE-209', 6)}},
        'losses': {},
    },
    '209_raw_frame_veto_dropped': {
        'why': 'a raw frame is no longer a veto, so the frame that travels goes quiet -- the '
               'fail-closed direction',
        'apply': lambda: setattr(ast_scanner, 'CWE209_RAW_TRACE_ATTRIBUTES', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE209_RAW_TRACE_ATTRIBUTES', _ORIG['raw_trace']),
        'gains': {},
        'losses': {'respond_raw_frame.py': {('CWE-209', 6)}},
    },
    '209_foreign_key_accepted_as_label': {
        'why': 'admitting `traceback` as an error label silences the body that names a stack',
        'apply': lambda: setattr(ast_scanner, 'CWE209_STRUCTURED_ERROR_KEYS',
                                 _ORIG['keys'] | {'traceback'}),
        'restore': lambda: setattr(ast_scanner, 'CWE209_STRUCTURED_ERROR_KEYS', _ORIG['keys']),
        'gains': {},
        'losses': {'respond_foreign_key.py': {('CWE-209', 6)}},
    },
    '862_domain_base_proof_disabled': {
        'why': 'the inherited permission pass is no longer read, so both domain endpoints are '
               'charged again',
        'apply': lambda: _set('_c862_class_inherits_domain_scoped_endpoint', lambda self, cls: False),
        'restore': lambda: _set('_c862_class_inherits_domain_scoped_endpoint', _ORIG['domain_base']),
        'gains': {'domain_endpoint.py': {('CWE-862', 6), ('CWE-862', 11)}},
        'losses': {},
    },
    '862_opt_out_refusal_dropped': {
        'why': 'permission_classes = () / (AllowAny,) stops refusing the base proof, so two '
               'genuinely open endpoints go quiet',
        'apply': lambda: _set('_c862_class_disables_permissions', lambda self, cls: False),
        'restore': lambda: _set('_c862_class_disables_permissions', _ORIG['opt_out']),
        'gains': {},
        'losses': {'opt_out_endpoint.py': {('CWE-862', 9), ('CWE-862', 16)}},
    },
    '338_telemetry_markers_stripped': {
        'why': "only this task's display markers are removed, so the three builders are charged "
               'again while the token and seed draws stay loud',
        'apply': lambda: setattr(ast_scanner, 'CWE338_DISPLAY_VALUE_MARKERS',
                                 _ORIG['markers'] - TASK13_DISPLAY_MARKERS),
        'restore': lambda: setattr(ast_scanner, 'CWE338_DISPLAY_VALUE_MARKERS', _ORIG['markers']),
        'gains': {'telemetry_builder.py': {('CWE-338', 5), ('CWE-338', 9), ('CWE-338', 13)}},
        'losses': {},
    },
    '328_digest_qualifiers_emptied': {
        'why': "this task's qualifiers are removed, so the compound helper name no longer demotes "
               '`hash` and problem_hash is charged again',
        'apply': lambda: setattr(ast_scanner, 'CWE328_DIGEST_QUALIFIERS',
                                 _ORIG['qualifiers'] - TASK13_DIGEST_QUALIFIERS),
        'restore': lambda: setattr(ast_scanner, 'CWE328_DIGEST_QUALIFIERS', _ORIG['qualifiers']),
        'gains': {'grouping_digest.py': {('CWE-328', 5)}},
        'losses': {},
    },
    '328_helper_name_proof_disabled': {
        'why': 'the segment proof is removed on its own: exactly the problem_hash row returns, and '
               'the three substring-named digests stay quiet',
        'apply': lambda: _set('_cwe328_helper_name_is_a_content_digest', lambda self, node: False),
        'restore': lambda: _set('_cwe328_helper_name_is_a_content_digest', _ORIG['helper_name']),
        'gains': {'grouping_digest.py': {('CWE-328', 5)}},
        'losses': {},
    },
    '704_rejection_proof_disabled': {
        'why': 'a handler that refuses the value is no longer read, so both catch-all handlers are '
               'charged again while the named (TypeError, ValueError) catch stays quiet',
        'apply': lambda: _set('_c704_handler_rejects_the_value', lambda self, handler: False),
        'restore': lambda: _set('_c704_handler_rejects_the_value', _ORIG['rejects']),
        'gains': {'rejected_float.py': {('CWE-704', 7), ('CWE-704', 14)}},
        'losses': {},
    },
    '704_rejection_catches_narrowed': {
        'why': 'Exception/BaseException stop counting as a catch that can see a bad number',
        'apply': lambda: setattr(ast_scanner, 'CLUSTER2_NAN_REJECTION_CATCHES',
                                 ast_scanner.CLUSTER2_NAN_CONVERSION_ERRORS),
        'restore': lambda: setattr(ast_scanner, 'CLUSTER2_NAN_REJECTION_CATCHES', _ORIG['catches']),
        'gains': {'rejected_float.py': {('CWE-704', 7), ('CWE-704', 14)}},
        'losses': {},
    },
    '704_rejection_errors_emptied': {
        'why': 'only the raised-error arm is removed: the ValidationError row returns and the 4xx '
               'reply row stays quiet',
        'apply': lambda: setattr(ast_scanner, 'CLUSTER2_NAN_REJECTION_ERRORS', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CLUSTER2_NAN_REJECTION_ERRORS', _ORIG['errors']),
        'gains': {'rejected_float.py': {('CWE-704', 7)}},
        'losses': {},
    },
}

_RESTORED = []


def run_mutation(name):
    spec = MUTATIONS[name]
    started = time.time()
    spec['apply']()
    try:
        _tracker, rows = scan_all(FIXTURES)
    finally:
        spec['restore']()
    elapsed = time.time() - started
    got = basenames(rows)
    appeared, vanished = {}, {}
    for module in FIXTURES:
        now, before = got.get(module, set()), ROWS.get(module, set())
        if now - before:
            appeared[module] = now - before
        lost = {pair for pair in (before - now) if pair in ISOLATED[module]}
        if lost:
            vanished[module] = lost
    if appeared != spec['gains']:
        fail('falsifier.%s' % name, 'gains expected %s, measured %s' % (spec['gains'], appeared))
    if vanished != spec['losses']:
        fail('falsifier.%s' % name, 'losses expected %s, measured %s' % (spec['losses'], vanished))
    if elapsed > BUDGET_MUTATION_SECONDS:
        fail('falsifier.%s' % name, 'took %.2fs (budget %.1fs)' % (elapsed, BUDGET_MUTATION_SECONDS))
    _RESTORED.append(name)
    return elapsed


def rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024.0 * 1024.0)
    except Exception:
        return 0.0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == '--dump':
        dump_table(BASE_ROWS)
        print('--- isolated ---')
        for module in FIXTURES:
            print('%-26s %s' % (module, sorted(ISOLATED[module])))
        return 0
    if len(sys.argv) > 2 and sys.argv[1] == '--mutation':
        name = sys.argv[2]
        if name not in MUTATIONS:
            print('unknown mutation %s' % name)
            return 2
        elapsed = run_mutation(name)
        print('%s: %.2fs' % (name, elapsed))
        for line in FAILS:
            print('FAIL %s' % line)
        return 1 if FAILS else 0

    checks = tier1_predicates() + tier2_verdicts() + tier3_laws()
    print('TIER 1-3: %d checks' % len(checks))
    times = {}
    for name in MUTATIONS:
        times[name] = run_mutation(name)
    print('TIER 4: %d/%d falsifiers (%.2fs total, slowest %.2fs)'
          % (len(_RESTORED), len(MUTATIONS), sum(times.values()), max(times.values())))

    _restore_all()
    for key, value in _ORIG.items():
        current = {
            'payload': TT._c209_payload_is_structured_envelope,
            'keys': ast_scanner.CWE209_STRUCTURED_ERROR_KEYS,
            'raw_trace': ast_scanner.CWE209_RAW_TRACE_ATTRIBUTES,
            'domain_base': TT._c862_class_inherits_domain_scoped_endpoint,
            'opt_out': TT._c862_class_disables_permissions,
            'markers': ast_scanner.CWE338_DISPLAY_VALUE_MARKERS,
            'qualifiers': ast_scanner.CWE328_DIGEST_QUALIFIERS,
            'helper_name': TT._cwe328_helper_name_is_a_content_digest,
            'rejects': TT._c704_handler_rejects_the_value,
            'catches': ast_scanner.CLUSTER2_NAN_REJECTION_CATCHES,
            'errors': ast_scanner.CLUSTER2_NAN_REJECTION_ERRORS,
        }[key]
        if current is not value and current != value:
            fail('restore.%s' % key, 'engine left mutated')
    _t, rows = scan_all(FIXTURES)
    if basenames(rows) != ROWS:
        fail('restore.rows', 'the shipped verdicts changed after the falsifiers ran')

    work = time.time() - WORK_START
    peak = rss_mb()
    print('TIER 5: work %.2fs (budget %.1fs), RSS %.1f MB (budget %.1f MB), rows=%d'
          % (work, BUDGET_SECONDS, peak, BUDGET_RSS_MB, len(BASE_ROWS)))
    if work > BUDGET_SECONDS:
        fail('budget.seconds', '%.2fs' % work)
    if peak > BUDGET_RSS_MB:
        fail('budget.rss', '%.1f MB' % peak)

    for line in FAILS:
        print('FAIL %s' % line)
    total = len(checks) + len(MUTATIONS) + 2
    print('%s: %d/%d checks, %d/%d falsifiers, %.2fs, %.1f MB'
          % ('PASS' if not FAILS else 'FAIL', total - len(FAILS), total,
             len(_RESTORED), len(MUTATIONS), work, peak))
    return 1 if FAILS else 0


if __name__ == '__main__':
    sys.exit(main())