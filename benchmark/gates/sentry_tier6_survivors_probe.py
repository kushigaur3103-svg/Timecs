"""TASK 14 zero-FP lock -- the survivor pockets Sentry (`24.2.0`, run `09c461c`, 522 findings) still
charged after tier 5, pinned one AST proof per pocket.

Read this file as a contract with five clauses. Each names a shape the cloud run charged, says in one
sentence why the charge is wrong, and pins the opposite shape that must keep charging:

  1. CWE-862  a domain `*Endpoint`/`*Mixin` base that runs its own permission pass, an authorisation
              COMPONENT (`AuthenticationBackend`, `Permission` class) that is not an entrypoint at all,
              and `dispatch`/`process_view` as the real HTTP verbs. A generic `View`, or a class that
              opts out with `permission_classes = ()` / `(AllowAny,)`, stays loud.
  2. CWE-209  an error envelope that reaches the reply already structured -- `json.dumps({...})` with
              one argument, an error-contract attribute (`exc.detail`, `err.body`), or a payload the
              responder forwards positionally. A raw frame, a traceback label, a Flask
              `jsonify(...), 500` pair and a WSGI 3-tuple stay loud: those ARE the HTTP body.
  3. CWE-338  a draw whose VALUE DOMAIN is the proof, not its name: a duration (`timedelta` argument),
              a published stdlib/corpus vocabulary, a loop bound, a permutation of work that already
              exists, a clamped continuous distribution, a registered template tag, and a separator-
              joined dotted identifier. A `"".join(...)` code, a credential-named destination, a `seed`
              draw, a `getrandbits`/`choices` mint and an unregistered helper stay loud.
  4. CWE-328  a hasher CONSTRUCTED with no input (`md5()`), where the digest is only named by its
              destination, and a helper whose name says which content it addresses. `md5(password)`,
              `password_hasher = md5()` and a helper named only for what it RETURNS (`compute_digest`)
              stay loud -- a bare noun proves nothing about the bytes. CWE-916 is untouched.
  5. CWE-704  `bool(...)` of something that cannot be a number in the first place (a mapping, a
              queryset `.exists()`-style predicate, a `values_list`, a container) and a bool that only
              feeds a telemetry label. `bool(token)`, `bool(password)` and a string attribute stay loud.

Every asserted row is measured, never assumed, and each fixture is scanned on its own under a module
stem of its own: the engine resolves an imported name once per scan, so two fixtures spelling the same
sink in one subset let one file's import table answer for the other's and a live guard measures inert.

This gate also pins two regressions that were MEASURED while building these guards, because both are
the direction that would have cost a true positive rather than a false one:

  * `compute_digest(data)` -- a helper whose name carries only the noun `digest` -- must stay LOUD. The
    noun arm that silenced it is exactly the shape a real `store_password` helper is spelled with.
  * `return jsonify({...}), 500` must stay LOUD. A tuple-shaped refusal that classified every
    `(body, status)` reply as a non-reply deleted the CWE-209 parity-corpus row that anchors the rule.
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
TASK14_DISPATCH_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "trace", "connect",
    "dispatch", "process_request", "process_view", "process_exception", "process_response",
})
TASK14_AUTHZ_SUFFIXES = ("Authentication", "Authenticator", "Permission", "Backend")
TASK14_SERIALIZERS = frozenset({"json.dumps", "dumps", "simplejson.dumps", "orjson.dumps"})
TASK14_CONTRACT_ATTRS = frozenset({
    "detail", "body", "field_errors", "error_code", "messages", "validations"})
TASK14_NEW_DISPLAY_MARKERS = frozenset({
    "host", "hosts", "client", "clients", "node", "nodes", "server", "servers"})
TASK14_CONTINUOUS_LEAVES = frozenset({
    "normalvariate", "gauss", "expovariate", "betavariate", "lognormvariate",
    "vonmisesvariate", "paretovariate", "gammavariate", "weibullvariate", "triangular"})
TASK14_STDLIB_ALPHABET_MEMBERS = frozenset({
    "ascii_letters", "ascii_lowercase", "ascii_uppercase", "digits", "hexdigits", "octdigits",
    "printable", "punctuation", "whitespace"})
TASK14_FILLER_CORPUS_MEMBERS = frozenset({"words", "sentences", "paragraphs"})
TASK14_EXISTENCE_READ_CALLEES = frozenset({
    "get_one_or_none", "get_object_or_none", "get_object",
    "first", "last", "filter", "exclude", "exists",
})


def fail(what, msg):
    FAILS.append('%s: %s' % (what, msg))


# ─── 1. CWE-862: the scoped base and the authorisation component, against the open view ────────
# The 35 rows this pocket retired are almost all one of two shapes copied below: an endpoint whose BASE
# is named for the domain it resolves (`SentryAppInstallationBaseEndpoint`), and a plain helper that
# merely RECEIVES the request (`relay_from_id(request, relay_id)`). The charge itself lands on the
# `def`, which is why the blessed lines are definition lines.
SCOPED_BASE_ENDPOINT = '''from sentry.api.base import control_silo_endpoint
from sentry.api.bases import SentryAppInstallationBaseEndpoint
from sentry.models import SentryAppInstallation


@control_silo_endpoint
class SentryAppInstallationDetailsEndpoint(SentryAppInstallationBaseEndpoint):
    def get(self, request, installation):
        return Response(serialize(SentryAppInstallation.objects.get(id=installation.id)))

    def delete(self, request, installation):
        installation = SentryAppInstallation.objects.get(id=installation.id)
        return Response(installation.id)
'''
SCOPED_MIXIN_ENDPOINT = '''from sentry.api.bases import OrganizationEventsEndpointBase
from sentry.models import Group


class GroupDetailsEndpoint(OrganizationEventsEndpointBase):
    def get(self, request, group):
        return Response(serialize(Group.objects.get(id=request.GET["group_id"])))
'''
AUTHZ_COMPONENT = '''from sentry.api.base import Endpoint
from sentry.models import ApiKey


class ApiKeyAuthentication(Endpoint):
    def get(self, request):
        return ApiKey.objects.get(id=request.GET["key_id"])
'''
HELPER_NOT_ENTRYPOINT = '''from sentry.models import Relay, RpcUser


class RelayDetailsEndpoint(BaseEndpoint):
    def get(self, request, relay_id):
        return serialize(relay_from_id(request, relay_id))


def relay_from_id(request, relay_id):
    return Relay.objects.get(id=relay_id)


def promote_request_rpc_user(request):
    return RpcUser.objects.get(id=request.user.id)
'''
GENERIC_VIEW_LOUD = '''from rest_framework.views import APIView
from sentry.api.base import Endpoint
from sentry.models import Organization


class PublicOrganizationView(APIView):
    def get(self, request, organization_slug):
        return Organization.objects.get(slug=organization_slug)


class PublicOrganizationEndpoint(Endpoint):
    def get(self, request, organization_slug):
        return Organization.objects.get(slug=organization_slug)
'''
VERB_ENTRYPOINT_LOUD = '''from sentry.models import Relay


@csrf_exempt
def relay_register_view(request):
    return dispatch(request)


def dispatch(request):
    return Relay.objects.get(id=request.POST["relay_id"])
'''
DISPATCH_ENTRYPOINT_LOUD = '''from sentry.api.base import Endpoint
from sentry.models import Organization


class UnscopedEndpoint(Endpoint):
    def dispatch(self, request, *args, **kwargs):
        return Organization.objects.get(slug=request.PARAMS.get("slug"))

    def process_view(self, request, view_func, view_args, view_kwargs):
        return Organization.objects.get(slug=request.PARAMS.get("slug"))
'''

# ─── 2. CWE-209: the envelope that is already structured, against the body that IS the reply ───
ENVELOPE_SERIALIZER = '''import json

from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        return Response(detail, status=status)


class PreviewEndpoint(Endpoint):
    def post(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return self.respond(json.dumps({"detail": str(exc)}), status=400)
'''
ENVELOPE_CONTRACT_ATTRIBUTE = '''from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        return Response(detail, status=status)


class DetailsEndpoint(Endpoint):
    def get(self, request):
        try:
            return self.run(request)
        except ApiError as exc:
            return self.respond(exc.detail, status=400)
'''
ENVELOPE_RAW_FRAME_LOUD = '''import traceback

from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        return Response(detail, status=status)


class BrokenEndpoint(Endpoint):
    def post(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return self.respond(traceback.format_exc(), status=400)
'''
FLASK_TUPLE_REPLY_LOUD = '''from flask import jsonify


@app.route("/preview")
def preview():
    try:
        return run()
    except Exception as exc:
        return jsonify({"traceback": traceback.format_exc()}), 500
'''
WSGI_TUPLE_REPLY_LOUD = '''def application(environ, start_response):
    try:
        body = render(environ)
    except Exception as exc:
        return "500 Internal Server Error", [("Content-Type", "text/plain")], [str(exc)]
    return "200 OK", [("Content-Type", "text/plain")], [body]
'''

# ─── 3. CWE-338: value-domain proofs, against the shapes that mint something ──────────────────
DURATION_DRAW = '''from datetime import timedelta

AUTH_CHECK_INTERVAL = 3600
AUTH_CHECK_SKEW = 60


def check_pending_identities():
    now = timezone.now()
    cutoff = now - timedelta(seconds=AUTH_CHECK_INTERVAL - randrange(AUTH_CHECK_SKEW))
    return AuthIdentity.objects.filter(last_checked_at__lt=cutoff)


def jitter_the_backfill(delay):
    window = timedelta(minutes=random.uniform(0, 15)) + delay
    return window
'''
DURATION_CREDENTIAL_LOUD = '''from datetime import timedelta


def salt_rotation_window():
    salt_window = timedelta(seconds=random.randint(0, 60))
    return salt_window
'''
VOCABULARY_DRAW = '''import string


def temporary_scope_letter():
    letter = random.choice(string.ascii_letters)
    return letter


def fake_commit_message():
    word = random.choice(loremipsum.words)
    return "feat: touch %s.js" % word
'''
VOCABULARY_CREDENTIAL_LOUD = '''import string


def mint_api_token():
    token = random.choice(string.ascii_letters)
    return token
'''
LOOP_COUNT_DRAW = '''def generate_commit_data(user):
    commits = []
    for i in range(random.randint(1, 20)):
        commits.append(build_commit(user))
    return commits


def write_sentences():
    words = int(random.weibullvariate(8, 3))
    return " ".join(pick_word() for _ in range(words))
'''
LOOP_COUNT_LOUD = '''def pick_a_number():
    n = random.randint(1, 20)
    return n
'''
SHUFFLE_WORK_DRAW = '''def backfill_indexes():
    indexes_needing_update = list(PendingIndex.objects.all())
    random.shuffle(indexes_needing_update)
    for index in indexes_needing_update:
        update(index)


def spread_the_hosts(hosts):
    shuffle(hosts)
    for host in hosts:
        ping(host)
'''
SHUFFLE_CREDENTIAL_LOUD = '''def rotate_tokens():
    tokens = list(Token.objects.all())
    random.shuffle(tokens)
    for token in tokens:
        revoke(token)


def permute_without_reading(rows):
    random.shuffle(rows)
    return rows
'''
CLAMPED_DISTRIBUTION_DRAW = '''def random_normal(mu, sigma, minimum, maximum=None):
    random_value = max(random.normalvariate(mu, sigma), minimum)
    if maximum is not None:
        random_value = min(random_value, maximum)
    return random_value
'''
CLAMPED_DISTRIBUTION_LOUD = '''def clamped_secret():
    secret = max(random.gauss(mu, sigma), minimum)
    return secret
'''
TEMPLATE_TAG_DRAW = '''from django import template

register = template.Library()


@register.simple_tag
def random_int(a, b=None):
    if b is None:
        a, b = 0, a
    return randint(a, b)
'''
TEMPLATE_TAG_LOUD = '''def random_int(a, b=None):
    if b is None:
        a, b = 0, a
    return randint(a, b)
'''
SEPARATED_JOIN_DRAW = '''def random_ip():
    first = random.randrange(1, 256)
    return ".".join(
        (
            str(first),
            str(random.randrange(1, 256)),
            str(random.randrange(1, 256)),
            str(random.randrange(1, 256)),
        )
    )
'''
SEPARATED_JOIN_LOUD = '''def reset_code():
    return "".join(str(random.randint(0, 9)) for _ in range(6))
'''
# The branch itself is the proof: a bounded draw compared against a declared rate decides whether work
# runs, it never produces a value. That a comparison must be the TEST of a branch is what keeps the
# whisper `CWE-338` true positive loud, and `benchmark/gates/big8_ab.py` line 97 is the lock on it.
SAMPLING_GATE_DRAW = '''SAMPLING_RATE = 5


def maybe_emit_metrics(events):
    if random.randint(0, 99) < SAMPLING_RATE:
        emit(events)
'''
CHOICE_SET_DRAW = '''def field_choices(request):
    return dict(NotificationType.choices())
'''

# ─── 4. CWE-328: a hasher with nothing in it, against the credential and the bare noun ─────────
BARE_HASHER_CONSTRUCTION = '''from hashlib import md5


class SpanGrouper:
    def build(self, spans):
        self.result = md5()
        for span in spans:
            self.result.update(span.encode())
        return self.result.hexdigest()


def index_debug_files(files):
    h = hashlib.sha1()
    for name in files:
        h.update(name.encode())
    return h.hexdigest()
'''
BARE_HASHER_CREDENTIAL_LOUD = '''from hashlib import md5


def build_password_hasher():
    password_hasher = md5()
    return password_hasher
'''
DIGEST_NOUN_LOUD = '''import hashlib


def compute_digest(data):
    return hashlib.md5(data.encode()).hexdigest()


def store_password(password):
    digest = compute_digest(password)
    print("Stored: %s" % digest)
'''

# ─── 5. CWE-704: a bool that cannot see a number, against the bool that can ────────────────────
BOOL_NONSTRING = '''def has_form_data(request):
    if bool(request.POST):
        return True
    return False


def has_related_rows(instance):
    if bool(instance.tags.values_list("id", flat=True)):
        return True
    return False


def is_empty(collection):
    return bool(collection.items())


def rollout_is_on(request):
    return bool(organization_service.check_object_permissions(request.user))
'''
BOOL_STRING_LOUD = '''def token_is_present(request):
    if bool(request.META.get("HTTP_AUTHORIZATION")):
        return True
    return False


def secret_is_set(secret):
    return bool(secret)
'''
BOOL_TELEMETRY_LABEL = '''class OAuthTokenView(View):
    def post(self, request):
        client_id = request.POST.get("client_id")
        client_secret = request.POST.get("client_secret")
        metrics.incr(
            "oauth_token.post.start",
            sample_rate=1.0,
            tags={
                "client_id_exists": bool(client_id),
                "client_secret_exists": bool(client_secret),
            },
        )


class DiscordCommand:
    def link_user(self):
        logger.warning(
            "discord.interaction.command.missing.integration",
            extra={"hasIntegration": bool(self.request.integration)},
        )
'''
DECISION_LABEL_LOUD = '''class ApiKeyRolloutView(View):
    def post(self, request):
        allow = request.POST.get("allow_api_keys")
        metrics.incr("api_keys.rollout", tags={"allowed": bool(allow)})
'''
EXISTENCE_READ = '''class SlackPlugin(Plugin):
    def needs_auth(self, request, **kwargs):
        auth = usersocialauth_service.get_one_or_none(
            filter={"user_id": request.user.id, "provider": self.auth_provider}
        )
        return bool(auth)


def has_pending_identity(request):
    identity = AuthIdentity.objects.filter(user=request.user).first()
    return bool(identity)
'''
EXISTENCE_UNBOUND_LOUD = '''def nickname_is_set(request):
    nickname = request.GET.get("nickname")
    return bool(nickname)


def token_is_required(request):
    if request.GET.get("force"):
        item = request.queryset.first()
    else:
        item = request.GET.get("token")
    return bool(item)
'''

DIRECT_SERIALIZER = '''import json

from rest_framework.response import Response


class PreviewEndpoint(Endpoint):
    def post(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return Response(json.dumps({"detail": str(exc)}), status=400)
'''
DIRECT_ATTRIBUTE = '''from rest_framework.response import Response


class DetailsEndpoint(Endpoint):
    def get(self, request):
        try:
            return self.run(request)
        except ApiError as exc:
            return Response(exc.detail, status=400)
'''
DISPATCHER_DICT_CONTROL = '''from rest_framework.response import Response


class Endpoint:
    def respond(self, detail=None, status=200):
        return Response(detail, status=status)


class ControlEndpoint(Endpoint):
    def post(self, request):
        try:
            return self.run(request)
        except Exception as exc:
            return self.respond({"detail": str(exc)}, status=400)
'''

IDENTIFIER_COMPOSITE_DIGEST = '''from hashlib import md5, sha1


def get_event_node_id(project_id, event_id):
    return md5(f"{project_id}:{event_id}".encode()).hexdigest()


def outbox_request_prefix(shard_identifier, object_identifier):
    return sha1(f"{shard_identifier}{object_identifier}".encode()).hexdigest()


def build_performance_fingerprint(span_hashes):
    joined_hashes = "-".join(span_hashes)
    return sha1(joined_hashes.encode("utf8")).hexdigest()


def watermark_digest(prev_transaction_id):
    return sha1(prev_transaction_id.encode("utf8")).hexdigest()
'''
IDENTIFIER_COMPOSITE_LOUD = '''from hashlib import md5


def token_rollout(key):
    intkey = int(md5(key).hexdigest(), base=16)
    return (intkey % 10000) / 10000


def prose_digest(message):
    return md5(f"cached value for the user: {message}".encode()).hexdigest()
'''

FIXTURES = {
    'direct_serializer.py': DIRECT_SERIALIZER,
    'direct_attribute.py': DIRECT_ATTRIBUTE,
    'dispatcher_dict_control.py': DISPATCHER_DICT_CONTROL,
    'scoped_base_endpoint.py': SCOPED_BASE_ENDPOINT,
    'scoped_mixin_endpoint.py': SCOPED_MIXIN_ENDPOINT,
    'authz_component.py': AUTHZ_COMPONENT,
    'helper_not_entrypoint.py': HELPER_NOT_ENTRYPOINT,
    'generic_view_loud.py': GENERIC_VIEW_LOUD,
    'verb_entrypoint_loud.py': VERB_ENTRYPOINT_LOUD,
    'dispatch_entrypoint_loud.py': DISPATCH_ENTRYPOINT_LOUD,
    'envelope_serializer.py': ENVELOPE_SERIALIZER,
    'envelope_contract_attribute.py': ENVELOPE_CONTRACT_ATTRIBUTE,
    'envelope_raw_frame_loud.py': ENVELOPE_RAW_FRAME_LOUD,
    'flask_tuple_reply_loud.py': FLASK_TUPLE_REPLY_LOUD,
    'wsgi_tuple_reply_loud.py': WSGI_TUPLE_REPLY_LOUD,
    'duration_draw.py': DURATION_DRAW,
    'duration_credential_loud.py': DURATION_CREDENTIAL_LOUD,
    'vocabulary_draw.py': VOCABULARY_DRAW,
    'vocabulary_credential_loud.py': VOCABULARY_CREDENTIAL_LOUD,
    'loop_count_draw.py': LOOP_COUNT_DRAW,
    'loop_count_loud.py': LOOP_COUNT_LOUD,
    'shuffle_work_draw.py': SHUFFLE_WORK_DRAW,
    'shuffle_credential_loud.py': SHUFFLE_CREDENTIAL_LOUD,
    'clamped_distribution_draw.py': CLAMPED_DISTRIBUTION_DRAW,
    'clamped_distribution_loud.py': CLAMPED_DISTRIBUTION_LOUD,
    'template_tag_draw.py': TEMPLATE_TAG_DRAW,
    'template_tag_loud.py': TEMPLATE_TAG_LOUD,
    'separated_join_draw.py': SEPARATED_JOIN_DRAW,
    'separated_join_loud.py': SEPARATED_JOIN_LOUD,
    'sampling_gate_draw.py': SAMPLING_GATE_DRAW,
    'choice_set_draw.py': CHOICE_SET_DRAW,
    'bare_hasher_construction.py': BARE_HASHER_CONSTRUCTION,
    'bare_hasher_credential_loud.py': BARE_HASHER_CREDENTIAL_LOUD,
    'digest_noun_loud.py': DIGEST_NOUN_LOUD,
    'identifier_composite_digest.py': IDENTIFIER_COMPOSITE_DIGEST,
    'identifier_composite_loud.py': IDENTIFIER_COMPOSITE_LOUD,
    'bool_nonstring.py': BOOL_NONSTRING,
    'bool_string_loud.py': BOOL_STRING_LOUD,
    'bool_telemetry_label.py': BOOL_TELEMETRY_LABEL,
    'decision_label_loud.py': DECISION_LABEL_LOUD,
    'existence_read.py': EXISTENCE_READ,
    'existence_unbound_loud.py': EXISTENCE_UNBOUND_LOUD,
}

# Every row this task retires, and every row it must not touch, measured against the shipped engine.
# The left set is a charge that the guard removes (it must be absent from the scan); the right set is a
# charge that looks like its neighbour and has to stay. A quiet row here is only meaningful because the
# falsifier below re-charges it: `--dump` proves the guard is what silences it, not a fixture the rule
# never looked at.
BLESSED = {
    'scoped_base_endpoint.py': ({('CWE-862', 8), ('CWE-862', 11)}, set()),
    'scoped_mixin_endpoint.py': ({('CWE-862', 6)}, set()),
    'authz_component.py': ({('CWE-862', 6)}, set()),
    'helper_not_entrypoint.py': ({('CWE-862', 9)}, {('CWE-862', 13)}),
    'generic_view_loud.py': (set(), {('CWE-862', 7), ('CWE-862', 12)}),
    'verb_entrypoint_loud.py': (set(), {('CWE-862', 9)}),
    'dispatch_entrypoint_loud.py': (set(), {('CWE-862', 6), ('CWE-862', 9)}),
    'envelope_serializer.py': ({('CWE-209', 8)}, set()),
    'envelope_contract_attribute.py': ({('CWE-209', 6)}, set()),
    'dispatcher_dict_control.py': ({('CWE-209', 6)}, set()),
    'envelope_raw_frame_loud.py': (set(), {('CWE-209', 8), ('CWE-200', 16)}),
    'flask_tuple_reply_loud.py': (set(), {('CWE-209', 9), ('CWE-200', 9)}),
    'wsgi_tuple_reply_loud.py': (set(), {('CWE-209', 5)}),
    'duration_draw.py': ({('CWE-338', 9), ('CWE-338', 14)}, set()),
    'duration_credential_loud.py': (set(), {('CWE-338', 5)}),
    'vocabulary_draw.py': ({('CWE-338', 5), ('CWE-338', 10)}, set()),
    'vocabulary_credential_loud.py': (set(), {('CWE-338', 5)}),
    'loop_count_draw.py': ({('CWE-338', 9)}, {('CWE-338', 3)}),
    'loop_count_loud.py': (set(), {('CWE-338', 2)}),
    'shuffle_work_draw.py': ({('CWE-338', 3), ('CWE-338', 9)}, set()),
    'shuffle_credential_loud.py': (set(), {('CWE-338', 3), ('CWE-338', 9)}),
    'clamped_distribution_draw.py': ({('CWE-338', 2)}, set()),
    'clamped_distribution_loud.py': (set(), {('CWE-338', 2)}),
    'template_tag_draw.py': ({('CWE-338', 10)}, set()),
    'template_tag_loud.py': (set(), {('CWE-338', 4)}),
    'separated_join_draw.py': ({('CWE-338', 6), ('CWE-338', 7), ('CWE-338', 8)}, set()),
    'separated_join_loud.py': (set(), {('CWE-338', 2)}),
    'sampling_gate_draw.py': ({('CWE-338', 5)}, set()),
    'choice_set_draw.py': ({('CWE-338', 2)}, set()),
    'bare_hasher_construction.py': ({('CWE-328', 6), ('CWE-328', 13)}, set()),
    'bare_hasher_credential_loud.py': (set(), {('CWE-328', 5)}),
    'digest_noun_loud.py': (set(), {('CWE-328', 5)}),
    'identifier_composite_digest.py': ({('CWE-328', 5), ('CWE-328', 9), ('CWE-328', 14),
                                        ('CWE-328', 18)}, set()),
    'identifier_composite_loud.py': (set(), {('CWE-328', 5), ('CWE-328', 10)}),
    'bool_nonstring.py': ({('CWE-704', 2), ('CWE-704', 8), ('CWE-704', 14), ('CWE-704', 18)},
                          set()),
    'bool_telemetry_label.py': ({('CWE-704', 9), ('CWE-704', 10), ('CWE-704', 19)}, set()),
    'decision_label_loud.py': (set(), {('CWE-704', 4)}),
    'bool_string_loud.py': (set(), {('CWE-704', 2)}),
    'existence_read.py': ({('CWE-704', 6), ('CWE-704', 11)}, set()),
    'existence_unbound_loud.py': (set(), {('CWE-704', 3), ('CWE-704', 11)}),
}


def scan_all(files):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        tracker = TT(files=dict(files), max_workers=1)
        _nodes, _rules, edges = tracker.analyze()
        return tracker, cli._findings_for(tracker, edges)


BASE_TRACKER, BASE_ROWS = scan_all(FIXTURES)


def basenames(rows):
    out = collections.defaultdict(set)
    for row in rows:
        out[os.path.basename(str(row['file']).replace('\\', '/'))].add((row['cwe'], int(row['line'])))
    return out


ROWS = basenames(BASE_ROWS)

ISOLATED = {module: set() for module in FIXTURES}
for _module in sorted(FIXTURES):
    _t, _rows = scan_all({'t6_isolated_%s' % _module: FIXTURES[_module]})
    ISOLATED[_module] = {(_row['cwe'], int(_row['line'])) for _row in _rows}


def dump_table():
    for module in sorted(FIXTURES):
        per_cwe = collections.defaultdict(set)
        for cwe, line in ISOLATED[module]:
            per_cwe[cwe].add(line)
        print('%-30s %s' % (module, {k: sorted(v) for k, v in sorted(per_cwe.items())}))
    print('rows=%d' % sum(len(v) for v in ISOLATED.values()))


def rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024.0 * 1024.0)
    except Exception:
        return 0.0


# ─── tier 1: the vocabulary the guards read ────────────────────────────────────────────────────
def tier1_predicates():
    checks = []

    def check(name, ok, detail=''):
        checks.append(name)
        if not ok:
            fail('predicate.%s' % name, detail or 'false')

    for name in ('_c862_base_name_is_a_scoped_endpoint',
                 '_c862_class_is_an_authorisation_component',
                 '_c209_payload_is_structured_envelope',
                 '_cwe338_draw_ships_a_duration',
                 '_cwe338_population_is_a_written_out_vocabulary',
                 '_cwe338_draw_is_clamped_by_a_declared_bound',
                 '_cwe338_join_formats_a_separated_identifier',
                 '_cwe338_draw_ships_a_registered_template_tag',
                 '_cwe338_shuffle_reorders_a_work_list',
                 '_cwe328_hash_input_is_written_out_identifiers',
                 '_cwe328_hasher_construction_has_no_input',
                 '_cwe328_name_only_says_it_is_a_digest',
                 '_c704_bool_feeds_telemetry_label',
                 '_c704_bool_operand_is_an_existence_read'):
        check('method_exists.' + name, hasattr(TT, name))

    check('862_dispatch_verbs_added',
          TASK14_DISPATCH_METHODS <= ast_scanner.CWE862_HTTP_DISPATCH_METHOD_NAMES,
          sorted(TASK14_DISPATCH_METHODS - ast_scanner.CWE862_HTTP_DISPATCH_METHOD_NAMES))
    check('862_authz_suffixes',
          ast_scanner.CWE862_AUTHZ_COMPONENT_SUFFIXES == TASK14_AUTHZ_SUFFIXES)
    check('862_verbs_are_verbs_not_models',
          not (TASK14_DISPATCH_METHODS & {'objects', 'get_or_create', 'filter'}))

    check('209_serializers_added', TASK14_SERIALIZERS <= ast_scanner.CWE209_PAYLOAD_SERIALIZERS)
    check('209_contract_attributes_added',
          TASK14_CONTRACT_ATTRS <= ast_scanner.CWE209_ERROR_CONTRACT_ATTRIBUTES,
          sorted(TASK14_CONTRACT_ATTRS - ast_scanner.CWE209_ERROR_CONTRACT_ATTRIBUTES))
    check('209_contract_never_a_raw_frame',
          not (ast_scanner.CWE209_ERROR_CONTRACT_ATTRIBUTES
               & ast_scanner.CWE209_RAW_TRACE_ATTRIBUTES))
    check('209_contract_never_a_traceback_label',
          not ({'traceback', 'stack', 'exc_info'} & ast_scanner.CWE209_ERROR_CONTRACT_ATTRIBUTES))

    check('338_display_markers_added',
          TASK14_NEW_DISPLAY_MARKERS <= ast_scanner.CWE338_DISPLAY_VALUE_MARKERS,
          sorted(TASK14_NEW_DISPLAY_MARKERS - ast_scanner.CWE338_DISPLAY_VALUE_MARKERS))
    check('338_new_markers_never_a_credential',
          not (TASK14_NEW_DISPLAY_MARKERS & ast_scanner.CWE338_SECURITY_NAME_WORDS),
          sorted(TASK14_NEW_DISPLAY_MARKERS & ast_scanner.CWE338_SECURITY_NAME_WORDS))
    check('338_stdlib_alphabet_added',
          ast_scanner.CWE338_STDLIB_ALPHABET_MEMBERS == TASK14_STDLIB_ALPHABET_MEMBERS)
    check('338_corpus_words_added',
          ast_scanner.CWE338_FILLER_CORPUS_MEMBERS == TASK14_FILLER_CORPUS_MEMBERS)
    check('338_alphabet_has_no_credential_word',
          not ({'letters', 'digits', 'hexdigits', 'words', 'sentences', 'paragraphs'}
               & ast_scanner.CWE338_SECURITY_NAME_WORDS))
    check('338_duration_callees', ast_scanner.CWE338_DURATION_CALLEES == {'timedelta',
                                                                         'relativedelta'})
    check('338_continuous_leaves_added',
          TASK14_CONTINUOUS_LEAVES == ast_scanner.CWE338_CONTINUOUS_DISTRIBUTION_LEAVES)
    check('338_continuous_leaves_reused_by_both_proofs',
          ast_scanner.CWE338_DURATION_EXTRA_LEAVES is ast_scanner.CWE338_CONTINUOUS_DISTRIBUTION_LEAVES
          and ast_scanner.CWE338_CONTINUOUS_DISTRIBUTION_LEAVES
          <= ast_scanner.CWE338_DISPLAY_VALUE_LEAVES)
    check('338_bounded_draw_leaves_are_draws',
          ast_scanner.CWE338_BOUNDED_DRAW_LEAVES == {'randint', 'randrange', 'uniform', 'random'})

    check('328_identifying_suffixes_added',
          {'id', 'slug', 'name'} <= ast_scanner.CWE328_IDENTIFYING_SUFFIX_WORDS)
    check('328_identifying_suffixes_never_a_credential',
          not (ast_scanner.CWE328_IDENTIFYING_SUFFIX_WORDS & ast_scanner.CWE338_SECURITY_NAME_WORDS),
          sorted(ast_scanner.CWE328_IDENTIFYING_SUFFIX_WORDS
                 & ast_scanner.CWE338_SECURITY_NAME_WORDS))
    check('328_separator_is_short', ast_scanner.CWE328_LITERAL_SEPARATOR_MAX_LENGTH == 3)
    check('328_digest_nouns_still_veto_named',
          'digest' in ast_scanner.CWE328_DIGEST_NOUN_WORDS
          and 'password' not in ast_scanner.CWE328_DIGEST_NOUN_WORDS)
    check('328_helper_name_proof_never_a_bare_noun',
          'CWE328_DIGEST_NOUN_WORDS'
          not in inspect.getsource(TT._cwe328_helper_name_is_a_content_digest),
          'a bare digest noun must not retire a hash: that is the shape of a password helper')

    check('704_existence_callees_added',
          {'get_one_or_none', 'get_object_or_none', 'first', 'last', 'filter', 'exclude', 'exists'}
          <= ast_scanner.CWE704_EXISTENCE_READ_CALLEES)
    check('704_existence_callees_refuse_value_reads',
          not ({'get', 'list', 'all', 'values_list'} & ast_scanner.CWE704_EXISTENCE_READ_CALLEES),
          sorted({'get', 'list', 'all', 'values_list'} & ast_scanner.CWE704_EXISTENCE_READ_CALLEES))
    check('704_telemetry_keywords',
          ast_scanner.CWE704_TELEMETRY_KEYWORDS == {'tags', 'extra', 'sample_data', 'attributes',
                                                    'contexts'})
    check('704_decision_labels_still_charge',
          any(word in ast_scanner.CWE704_DECISION_LABEL_WORDS
              for word in ('require_signup', 'allowed', 'is_admin', 'has_perm')))
    return checks


CRYPTO_LABELS = frozenset({'CWE-327', 'CWE-328'})


# ─── tier 2: every blessed row, against the shipped scan and against the isolated scan ─────────
def crypto_key(cwe, line):
    """One weak-hash sink is booked twice: the sink table calls `md5` CWE-327, the weak-hash pass
    calls the same node CWE-328, and which label survives `_remove_existing` depends on the scan
    context, so a shared scan can hold both while an isolated scan holds one. The row is the finding,
    the label is not: identity is the line for the crypto pair and the (cwe, line) for everything else.
    """
    return (line,) if cwe in CRYPTO_LABELS else (cwe, line)


def tier2_verdicts():
    checks = []
    for module, (quiet, loud) in BLESSED.items():
        shipped = {crypto_key(cwe, line) for cwe, line in ROWS.get(module, set())}
        alone = {crypto_key(cwe, line) for cwe, line in ISOLATED[module]}
        for cwe, line in sorted(quiet):
            checks.append('%s.quiet.%s:%d' % (module, cwe, line))
            if crypto_key(cwe, line) in shipped:
                fail('verdict.%s' % module, '%s:%d is still loud' % (cwe, line))
        for cwe, line in sorted(loud):
            checks.append('%s.loud.%s:%d' % (module, cwe, line))
            if crypto_key(cwe, line) not in shipped:
                fail('verdict.%s' % module, '%s:%d went quiet' % (cwe, line))
            if crypto_key(cwe, line) not in alone:
                fail('verdict.%s' % module, '%s:%d only exists in a shared scan' % (cwe, line))
        checks.append('%s.isolated_matches_shipped' % module)
        if alone != shipped:
            fail('verdict.%s' % module, 'isolated %s != shipped %s'
                 % (sorted(alone - shipped), sorted(shipped - alone)))
    return checks


# ─── tier 3: source laws -- the order of the proofs is what keeps a retirement fail-closed ──────
def tier3_laws():
    checks = []

    def law(name, ok, detail=''):
        checks.append(name)
        if not ok:
            fail('law.%s' % name, detail or 'false')

    def body(method):
        return inspect.getsource(method)

    draw = body(TT._cwe338_display_only_draw)
    law('338_credential_veto_precedes_the_new_arms',
        draw.index('_cwe338_name_is_security_named')
        < draw.index('_cwe338_population_is_a_written_out_vocabulary'))
    law('338_literal_code_guard_precedes_the_separator_proof',
        draw.index('feeds_a_string_join') < draw.index('_cwe338_join_formats_a_separated_identifier'))
    join_guard = draw[draw.index('if feeds_a_string_join and not ('):]
    join_guard = join_guard[:join_guard.index('):')]
    law('338_separator_proof_sits_inside_the_join_refusal',
        '_cwe338_join_ships_literal_sample_data' in join_guard
        and '_cwe338_draw_labels_a_literal_record' in join_guard
        and '_cwe338_join_formats_a_separated_identifier' in join_guard,
        'the separator proof must not be able to outvote the literal-code guard')
    for arm in ('_cwe338_draw_ships_a_duration', '_cwe338_population_is_a_written_out_vocabulary',
                '_cwe338_shuffle_reorders_a_work_list',
                '_cwe338_draw_is_clamped_by_a_declared_bound',
                '_cwe338_draw_ships_a_registered_template_tag'):
        law('338_arm_reached_from_the_display_proof.' + arm, arm in draw)
    # The loop-bound axis was withdrawn before this task and `cwe338_prng_context_probe.py` still pins it
    # loud (`for i in range(random.randint(1, 9))`, `range(random.choice(k))` -- a selection is not a
    # count). Re-adding an iteration-count proof here would re-light that tracked gate, so its absence
    # from the display proof is a law of this gate, not an accident.
    law('338_iteration_bound_axis_stays_withdrawn',
        '_cwe338_draw_is_an_iteration_count' not in draw
        and not hasattr(TT, '_cwe338_draw_is_an_iteration_count'),
        'the loop-bound suppression must stay out of the engine')

    gate = body(TT._cwe338_bounded_draw_is_a_sampling_gate)
    law('338_sampling_gate_needs_a_branch_test', 'parent.test is not gate' in gate,
        'TASK 14 FN heal: a comparison appended as data must not read as a sampling gate')

    duration = body(TT._cwe338_draw_ships_a_duration)
    law('338_duration_needs_a_time_argument',
        'CWE338_DURATION_CALLEES' in duration and 'CWE338_ARITHMETIC_WRAP_NODES' in duration)
    vocab = body(TT._cwe338_population_is_a_written_out_vocabulary)
    law('338_vocabulary_reads_the_dotted_path',
        'CWE338_STDLIB_ALPHABET_MEMBERS' in vocab and 'CWE338_FILLER_CORPUS_MEMBERS' in vocab
        and 'rsplit' in vocab)
    clamp = body(TT._cwe338_draw_is_clamped_by_a_declared_bound)
    law('338_clamp_needs_a_declared_bound', 'CWE338_CONTINUOUS_DISTRIBUTION_LEAVES' in clamp)
    tag = body(TT._cwe338_draw_ships_a_registered_template_tag)
    law('338_template_tag_needs_the_decorator', 'decorator_list' in tag)
    shuffle = body(TT._cwe338_shuffle_reorders_a_work_list)
    law('338_shuffle_needs_a_loop_over_the_same_name',
        'ordered_as_a_loop' in shuffle and 'ast.Return' in shuffle,
        'a permutation handed back to a caller is not a work order')
    sep = body(TT._cwe338_join_formats_a_separated_identifier)
    law('338_separator_join_needs_a_visible_separator',
        'separator.value.isalnum()' in sep and 'len(parts) < 3' in sep
        and "len(separator.value) != 1" in sep,
        'an empty separator is how an OTP is concatenated, and must not pass')

    non_cred = body(TT._cwe328_hash_input_is_non_credential)
    law('328_written_out_proof_runs_before_the_credential_veto',
        non_cred.index('_cwe328_hash_input_is_written_out_identifiers')
        < non_cred.index('_cwe328_input_is_credential_named'))
    written = body(TT._cwe328_hash_input_is_written_out_identifiers)
    law('328_written_out_needs_identifiers_on_every_side',
        'CWE328_IDENTIFYING_SUFFIX_WORDS' in written and '_cwe328_literal_is_a_separator' in written)
    law('328_written_out_keeps_its_own_veto',
        '_cwe328_input_is_credential_named' in written)
    law('328_digest_noun_only_lifts_the_noun_that_names_the_digest',
        'hits <= CWE328_DIGEST_NOUN_WORDS' in body(TT._cwe328_name_only_says_it_is_a_digest))
    construction = body(TT._cwe328_hasher_construction_has_no_input)
    law('328_bare_hasher_needs_no_argument',
        'node.args' in construction and 'node.keywords' in construction)
    law('328_literal_separator_is_non_alphanumeric',
        'isalnum' in body(TT._cwe328_literal_is_a_separator))

    dispatcher = body(TT._c209_dispatcher_reply)
    law('209_positional_argument_tried_alongside_the_resolved_payload',
        'resolved is not argument' in dispatcher
        and '_c209_payload_is_structured_envelope(argument)' in dispatcher)
    envelope = body(TT._c209_structured_error_envelope_only)
    law('209_arguments_are_read_alongside_a_dict_body',
        'payloads' in envelope and 'Attribute' in envelope and 'Call' in envelope)
    law('209_argument_never_tried_instead_of_the_payload',
        'payloads.append(payload)' in envelope)
    payload = body(TT._c209_payload_is_structured_envelope)
    law('209_serializer_proof_needs_one_argument',
        'CWE209_PAYLOAD_SERIALIZERS' in payload and 'len(' in payload)

    guarded = body(TT._c862_scope_is_guarded_or_off_http)
    law('862_authorisation_component_consulted', '_c862_class_is_an_authorisation_component'
        in guarded)
    law('862_scoped_base_is_an_authorisation_proof',
        '_c862_class_inherits_domain_scoped_endpoint' in guarded)
    law('862_opt_out_still_wins', '_c862_class_disables_permissions' in guarded)
    law('862_reachability_axis_untouched',
        '_c862_class_inherits_domain_scoped_endpoint'
        not in body(TT._c862_scope_is_http_entrypoint),
        'a domain endpoint IS reachable; only its authorisation is inherited')
    scoped = body(TT._c862_base_name_is_a_scoped_endpoint)
    law('862_scoped_base_name_is_read_as_segments', '_CWE338_NAME_SPLIT' in scoped
        or 'split' in scoped)

    existence = body(TT._c704_bool_operand_is_an_existence_read)
    law('704_existence_read_refuses_a_name_it_cannot_resolve',
        'return bindings > 0' in existence and 'isinstance(expr, ast.Name)' in existence)
    law('704_existence_read_needs_every_binding',
        existence.count('return False') >= 3,
        'one non-selector write must refuse the whole name')
    site = ast_scanner_source()
    law('704_existence_proof_is_the_last_of_the_three',
        site.index('_c704_bool_operand_is_nonstring(arg, scope)')
        < site.index('_c704_bool_operand_is_an_existence_read(arg)'))
    law('704_float_and_complex_still_charge',
        'NAN_UNVALIDATED_CONVERSION' in site and site.count('"float"') >= 1)

    own_source = open(os.path.abspath(__file__), encoding='utf-8').read()
    law('gate_never_execs_source', not re.search(r'\b(exec|compile)\s*\(', own_source),
        'aa_parity scans benchmark/; a live exec/compile would add a row to the frozen baseline')
    return checks


def ast_scanner_source():
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        return handle.read()


# ─── tier 4: falsifiers -- each removes exactly one proof and measures what comes back ──────────
_ORIG = {
    'scoped_base': TT._c862_base_name_is_a_scoped_endpoint,
    'authz_component': TT._c862_class_is_an_authorisation_component,
    'dispatch_verbs': ast_scanner.CWE862_HTTP_DISPATCH_METHOD_NAMES,
    'envelope_payload': TT._c209_payload_is_structured_envelope,
    'contract_attrs': ast_scanner.CWE209_ERROR_CONTRACT_ATTRIBUTES,
    'serializers': ast_scanner.CWE209_PAYLOAD_SERIALIZERS,
    'duration_arm': TT._cwe338_draw_ships_a_duration,
    'vocabulary_arm': TT._cwe338_population_is_a_written_out_vocabulary,
    'clamp_arm': TT._cwe338_draw_is_clamped_by_a_declared_bound,
    'separator_arm': TT._cwe338_join_formats_a_separated_identifier,
    'template_tag_arm': TT._cwe338_draw_ships_a_registered_template_tag,
    'shuffle_arm': TT._cwe338_shuffle_reorders_a_work_list,
    'display_markers': ast_scanner.CWE338_DISPLAY_VALUE_MARKERS,
    'alphabet_members': ast_scanner.CWE338_STDLIB_ALPHABET_MEMBERS,
    'filler_members': ast_scanner.CWE338_FILLER_CORPUS_MEMBERS,
    'sampling_gate_arm': TT._cwe338_bounded_draw_is_a_sampling_gate,
    'selects_literal_arm': TT._cwe338_draw_selects_a_literal_record,
    'labels_literal_arm': TT._cwe338_draw_labels_a_literal_record,
    'sample_data_arm': TT._cwe338_join_ships_literal_sample_data,
    'choice_set_arm': TT._cwe338_choices_call_is_a_django_choice_set,
    'continuous_leaves': ast_scanner.CWE338_CONTINUOUS_DISTRIBUTION_LEAVES,
    'written_out_arm': TT._cwe328_hash_input_is_written_out_identifiers,
    'bare_hasher_arm': TT._cwe328_hasher_construction_has_no_input,
    'identifying_suffixes': ast_scanner.CWE328_IDENTIFYING_SUFFIX_WORDS,
    'telemetry_label': TT._c704_bool_feeds_telemetry_label,
    'nonstring_proof': TT._c704_bool_operand_is_nonstring,
    'predicate_prefixes': ast_scanner.CLUSTER2_BOOL_PREDICATE_PREFIXES,
    'existence_arm': TT._c704_bool_operand_is_an_existence_read,
    'existence_callees': ast_scanner.CWE704_EXISTENCE_READ_CALLEES,
}


def _restore_all():
    TT._c862_base_name_is_a_scoped_endpoint = _ORIG['scoped_base']
    TT._c862_class_is_an_authorisation_component = _ORIG['authz_component']
    ast_scanner.CWE862_HTTP_DISPATCH_METHOD_NAMES = _ORIG['dispatch_verbs']
    TT._c209_payload_is_structured_envelope = _ORIG['envelope_payload']
    ast_scanner.CWE209_ERROR_CONTRACT_ATTRIBUTES = _ORIG['contract_attrs']
    ast_scanner.CWE209_PAYLOAD_SERIALIZERS = _ORIG['serializers']
    TT._cwe338_draw_ships_a_duration = _ORIG['duration_arm']
    TT._cwe338_population_is_a_written_out_vocabulary = _ORIG['vocabulary_arm']
    TT._cwe338_draw_is_clamped_by_a_declared_bound = _ORIG['clamp_arm']
    TT._cwe338_join_formats_a_separated_identifier = _ORIG['separator_arm']
    TT._cwe338_draw_ships_a_registered_template_tag = _ORIG['template_tag_arm']
    TT._cwe338_shuffle_reorders_a_work_list = _ORIG['shuffle_arm']
    ast_scanner.CWE338_DISPLAY_VALUE_MARKERS = _ORIG['display_markers']
    ast_scanner.CWE338_STDLIB_ALPHABET_MEMBERS = _ORIG['alphabet_members']
    ast_scanner.CWE338_FILLER_CORPUS_MEMBERS = _ORIG['filler_members']
    TT._cwe338_bounded_draw_is_a_sampling_gate = _ORIG['sampling_gate_arm']
    TT._cwe338_draw_selects_a_literal_record = _ORIG['selects_literal_arm']
    TT._cwe338_draw_labels_a_literal_record = _ORIG['labels_literal_arm']
    TT._cwe338_join_ships_literal_sample_data = _ORIG['sample_data_arm']
    TT._cwe338_choices_call_is_a_django_choice_set = _ORIG['choice_set_arm']
    ast_scanner.CWE338_CONTINUOUS_DISTRIBUTION_LEAVES = _ORIG['continuous_leaves']
    TT._cwe328_hash_input_is_written_out_identifiers = _ORIG['written_out_arm']
    TT._cwe328_hasher_construction_has_no_input = _ORIG['bare_hasher_arm']
    ast_scanner.CWE328_IDENTIFYING_SUFFIX_WORDS = _ORIG['identifying_suffixes']
    TT._c704_bool_feeds_telemetry_label = _ORIG['telemetry_label']
    TT._c704_bool_operand_is_nonstring = _ORIG['nonstring_proof']
    ast_scanner.CLUSTER2_BOOL_PREDICATE_PREFIXES = _ORIG['predicate_prefixes']
    TT._c704_bool_operand_is_an_existence_read = _ORIG['existence_arm']
    ast_scanner.CWE704_EXISTENCE_READ_CALLEES = _ORIG['existence_callees']


def _mute(method):
    """Replace an instance predicate with one that always refuses."""
    setattr(TT, method, lambda self, *args, **kwargs: False)


# Five of the new CWE-338 proofs are belt-and-braces: they overlap a proof that already fires on every
# fixture row, so muting any one of them -- or all five together -- measures nothing, and a falsifier
# built on a single redundant arm would be inert. What the family DOES have to answer for is the union: take
# all twelve arms and the three narrowed tables out at once and every display-only row the pocket retired
# comes back, while no credential-shaped fixture changes its mind. The per-arm attribution stays with the
# eight single-arm falsifiers and the call sites stay with tier 3.
# Measured: `duration_draw.py` and `sampling_gate_draw.py` stay quiet with the WHOLE family muted, so a
# pre-existing proof covers those two rows -- their arms are defence in depth, not the load-bearing reason,
# and the gate says so instead of claiming a gain it did not measure.
TASK14_DISPLAY_ARMS = (
    ('_cwe338_draw_ships_a_duration', 'duration_arm'),
    ('_cwe338_bounded_draw_is_a_sampling_gate', 'sampling_gate_arm'),
    ('_cwe338_draw_labels_a_literal_record', 'labels_literal_arm'),
    ('_cwe338_draw_selects_a_literal_record', 'selects_literal_arm'),
    ('_cwe338_join_ships_literal_sample_data', 'sample_data_arm'),
    ('_cwe338_population_is_a_written_out_vocabulary', 'vocabulary_arm'),
    ('_cwe338_draw_is_clamped_by_a_declared_bound', 'clamp_arm'),
    ('_cwe338_join_formats_a_separated_identifier', 'separator_arm'),
    ('_cwe338_draw_ships_a_registered_template_tag', 'template_tag_arm'),
    ('_cwe338_shuffle_reorders_a_work_list', 'shuffle_arm'),
    ('_cwe338_choices_call_is_a_django_choice_set', 'choice_set_arm'),
)

TASK14_CWE338_SCOPE = tuple(sorted(
    name for name, (quiet, loud) in BLESSED.items()
    if (quiet or loud) and all(cwe == 'CWE-338' for cwe, _ in quiet | loud)))


def _mute_display_arms_all():
    for method, _key in TASK14_DISPLAY_ARMS:
        setattr(TT, method, lambda *args, **kwargs: False)
    ast_scanner.CWE338_FILLER_CORPUS_MEMBERS = frozenset()
    ast_scanner.CWE338_STDLIB_ALPHABET_MEMBERS = frozenset()
    ast_scanner.CWE338_DISPLAY_VALUE_MARKERS = _ORIG['display_markers'] - TASK14_NEW_DISPLAY_MARKERS
    ast_scanner.CWE338_CONTINUOUS_DISTRIBUTION_LEAVES = frozenset()


def _restore_display_arms_all():
    for method, key in TASK14_DISPLAY_ARMS:
        setattr(TT, method, _ORIG[key])
    ast_scanner.CWE338_FILLER_CORPUS_MEMBERS = _ORIG['filler_members']
    ast_scanner.CWE338_STDLIB_ALPHABET_MEMBERS = _ORIG['alphabet_members']
    ast_scanner.CWE338_DISPLAY_VALUE_MARKERS = _ORIG['display_markers']
    ast_scanner.CWE338_CONTINUOUS_DISTRIBUTION_LEAVES = _ORIG['continuous_leaves']


MUTATIONS = {
    '338_display_family_all_muted': {
        'why': 'the whole display-only family goes at once: every row the pocket retired comes back and the '
               'credential-shaped fixtures still answer the same way',
        'apply': _mute_display_arms_all,
        'restore': _restore_display_arms_all,
        'gains': {'choice_set_draw.py': {('CWE-338', 2)},
                  'clamped_distribution_draw.py': {('CWE-338', 2)},
                  'separated_join_draw.py': {('CWE-338', 6), ('CWE-338', 7), ('CWE-338', 8)},
                  'shuffle_work_draw.py': {('CWE-338', 3), ('CWE-338', 9)},
                  'template_tag_draw.py': {('CWE-338', 10)},
                  'vocabulary_draw.py': {('CWE-338', 5)}},
        'losses': {},
    },
    '862_scoped_base_proof_disabled': {
        'why': 'a domain-scoped base stops answering for authorisation, so every endpoint that inherits '
               'its permission pass is charged again',
        'apply': lambda: _mute('_c862_base_name_is_a_scoped_endpoint'),
        'restore': lambda: setattr(TT, '_c862_base_name_is_a_scoped_endpoint', _ORIG['scoped_base']),
        'gains': {'scoped_base_endpoint.py': {('CWE-862', 8), ('CWE-862', 11)},
                  'scoped_mixin_endpoint.py': {('CWE-862', 6)}},
        'losses': {},
    },
    '862_authorisation_component_proof_disabled': {
        'why': 'the authentication backend / permission class stops being recognised as the mechanism, '
               'so a component is charged as if it were a view that forgot its guard',
        'apply': lambda: _mute('_c862_class_is_an_authorisation_component'),
        'restore': lambda: setattr(TT, '_c862_class_is_an_authorisation_component',
                                   _ORIG['authz_component']),
        'gains': {'authz_component.py': {('CWE-862', 6)}},
        'losses': {},
    },
    '862_verb_gate_emptied': {
        'why': 'REVERSE falsifier: with no verb names left, a handler the framework really calls is no '
               'longer an entrypoint, which is the false negative the verb table exists to prevent',
        'apply': lambda: setattr(ast_scanner, 'CWE862_HTTP_DISPATCH_METHOD_NAMES', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE862_HTTP_DISPATCH_METHOD_NAMES',
                                   _ORIG['dispatch_verbs']),
        'gains': {},
        'losses': {'verb_entrypoint_loud.py': {('CWE-862', 9)}},
    },
    '862_helper_named_as_a_verb': {
        'why': 'the verb table is the ONLY thing that keeps `relay_from_id(request, relay_id)` quiet: '
               'put its own name in the table and the helper is charged exactly like a view',
        'apply': lambda: setattr(ast_scanner, 'CWE862_HTTP_DISPATCH_METHOD_NAMES',
                                 _ORIG['dispatch_verbs'] | {'relay_from_id',
                                                            'promote_request_rpc_user'}),
        'restore': lambda: setattr(ast_scanner, 'CWE862_HTTP_DISPATCH_METHOD_NAMES',
                                   _ORIG['dispatch_verbs']),
        'gains': {'helper_not_entrypoint.py': {('CWE-862', 9)}},
        'losses': {},
    },
    '209_envelope_payload_proof_disabled': {
        'why': 'nothing a responder forwards counts as structured again, so every envelope that arrives '
               'already serialised is charged',
        'apply': lambda: _mute('_c209_payload_is_structured_envelope'),
        'restore': lambda: setattr(TT, '_c209_payload_is_structured_envelope',
                                   _ORIG['envelope_payload']),
        'gains': {'envelope_serializer.py': {('CWE-209', 8)},
                  'envelope_contract_attribute.py': {('CWE-209', 6)},
                  'dispatcher_dict_control.py': {('CWE-209', 6)},
                  'direct_serializer.py': {('CWE-209', 11)},
                  'direct_attribute.py': {('CWE-209', 9)}},
        'losses': {},
    },
    '209_contract_attributes_narrowed': {
        'why': "only this task's error-contract names are removed, so `Response(exc.field_errors)` is "
               'charged again while the raw-frame veto still holds the traceback rows',
        'apply': lambda: setattr(ast_scanner, 'CWE209_ERROR_CONTRACT_ATTRIBUTES',
                                 _ORIG['contract_attrs'] - TASK14_CONTRACT_ATTRS),
        'restore': lambda: setattr(ast_scanner, 'CWE209_ERROR_CONTRACT_ATTRIBUTES',
                                   _ORIG['contract_attrs']),
        'gains': {'envelope_contract_attribute.py': {('CWE-209', 6)},
                  'direct_attribute.py': {('CWE-209', 9)}},
        'losses': {},
    },
    '209_payload_serializers_emptied': {
        'why': 'a `json.dumps({...})` body is no longer read as an envelope, so the serialised reply is '
               'charged again',
        'apply': lambda: setattr(ast_scanner, 'CWE209_PAYLOAD_SERIALIZERS', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE209_PAYLOAD_SERIALIZERS', _ORIG['serializers']),
        'gains': {'envelope_serializer.py': {('CWE-209', 8)},
                  'direct_serializer.py': {('CWE-209', 11)}},
        'losses': {},
    },
    '338_vocabulary_arm_disabled': {
        'why': '`string.ascii_letters` and `loremipsum.words` stop being recognised as a published '
               'vocabulary, so a display alphabet is charged as a keyspace',
        'apply': lambda: _mute('_cwe338_population_is_a_written_out_vocabulary'),
        'restore': lambda: setattr(TT, '_cwe338_population_is_a_written_out_vocabulary',
                                   _ORIG['vocabulary_arm']),
        'gains': {'vocabulary_draw.py': {('CWE-338', 5)}},
        'losses': {},
    },
    '338_clamp_arm_disabled': {
        'why': 'a continuous distribution held under a declared bound is charged again',
        'apply': lambda: _mute('_cwe338_draw_is_clamped_by_a_declared_bound'),
        'restore': lambda: setattr(TT, '_cwe338_draw_is_clamped_by_a_declared_bound',
                                   _ORIG['clamp_arm']),
        'gains': {
                  'clamped_distribution_draw.py': {('CWE-338', 2)}},
        'losses': {},
    },
    '338_continuous_leaves_narrowed': {
        'why': 'removing the distribution leaves takes the clamp proof with it, and the `int(...)` loop '
               'bound goes back to being charged too',
        'apply': lambda: setattr(ast_scanner, 'CWE338_CONTINUOUS_DISTRIBUTION_LEAVES', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE338_CONTINUOUS_DISTRIBUTION_LEAVES',
                                   _ORIG['continuous_leaves']),
        'gains': {
                  'clamped_distribution_draw.py': {('CWE-338', 2)}},
        'losses': {},
    },
    '338_separator_join_arm_disabled': {
        'why': 'a draw whose value is one dotted field of an address stops being an identifier format',
        'apply': lambda: _mute('_cwe338_join_formats_a_separated_identifier'),
        'restore': lambda: setattr(TT, '_cwe338_join_formats_a_separated_identifier',
                                   _ORIG['separator_arm']),
        'gains': {
                  'separated_join_draw.py': {('CWE-338', 6), ('CWE-338', 7), ('CWE-338', 8)}},
        'losses': {},
    },
    '338_template_tag_arm_disabled': {
        'why': 'a registered template tag stops being read as display plumbing and is charged as a '
               'value mint',
        'apply': lambda: _mute('_cwe338_draw_ships_a_registered_template_tag'),
        'restore': lambda: setattr(TT, '_cwe338_draw_ships_a_registered_template_tag',
                                   _ORIG['template_tag_arm']),
        'gains': {
                  'template_tag_draw.py': {('CWE-338', 10)}},
        'losses': {},
    },
    '338_shuffle_arm_disabled': {
        'why': 'a permutation of work that already exists is charged as though it produced a value',
        'apply': lambda: _mute('_cwe338_shuffle_reorders_a_work_list'),
        'restore': lambda: setattr(TT, '_cwe338_shuffle_reorders_a_work_list', _ORIG['shuffle_arm']),
        'gains': {
                  'shuffle_work_draw.py': {('CWE-338', 3)}},
        'losses': {},
    },
    '338_choice_set_arm_disabled': {
        'why': '`.choices()` on a Django Choices class is read as drawing from a keyspace again',
        'apply': lambda: _mute('_cwe338_choices_call_is_a_django_choice_set'),
        'restore': lambda: setattr(TT, '_cwe338_choices_call_is_a_django_choice_set',
                                   _ORIG['choice_set_arm']),
        'gains': {
                  'choice_set_draw.py': {('CWE-338', 2)}},
        'losses': {},
    },
    '328_written_out_identifier_proof_disabled': {
        'why': 'a digest of a spelled-out composite address is charged as a password hash again',
        'apply': lambda: _mute('_cwe328_hash_input_is_written_out_identifiers'),
        'restore': lambda: setattr(TT, '_cwe328_hash_input_is_written_out_identifiers',
                                   _ORIG['written_out_arm']),
        'gains': {
                  'identifier_composite_digest.py': {('CWE-328', 5), ('CWE-328', 9), ('CWE-328', 14), ('CWE-328', 18)}},
        'losses': {},
    },
    '328_identifying_suffixes_narrowed': {
        'why': 'the id/slug/name/uuid axis goes, so a composite that identifies a row is no longer '
               'recognised -- and the credential-shaped fixture is untouched',
        'apply': lambda: setattr(ast_scanner, 'CWE328_IDENTIFYING_SUFFIX_WORDS', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE328_IDENTIFYING_SUFFIX_WORDS',
                                   _ORIG['identifying_suffixes']),
        'gains': {
                  'identifier_composite_digest.py': {('CWE-328', 18)}},
        'losses': {},
    },
    '328_bare_hasher_proof_disabled': {
        'why': 'a hasher constructed with no input is charged as though the constructor held a password',
        'apply': lambda: _mute('_cwe328_hasher_construction_has_no_input'),
        'restore': lambda: setattr(TT, '_cwe328_hasher_construction_has_no_input',
                                   _ORIG['bare_hasher_arm']),
        'gains': {
                  'bare_hasher_construction.py': {('CWE-328', 6), ('CWE-328', 13)}},
        'losses': {},
    },
    '704_nonstring_proof_disabled': {
        'why': 'the whole non-string family goes: a mapping, a queryset, a container constructor and a '
               'verdict-named callee are charged as string truthiness again',
        'apply': lambda: _mute('_c704_bool_operand_is_nonstring'),
        'restore': lambda: setattr(TT, '_c704_bool_operand_is_nonstring', _ORIG['nonstring_proof']),
        'gains': {
                  'bool_nonstring.py': {('CWE-704', 2), ('CWE-704', 18)}},
        'losses': {},
    },
    '704_predicate_prefixes_emptied': {
        'why': 'only the `is_`/`has_`/`check_` naming axis is removed, so a callee named for a verdict '
               'loses its exemption while the container proofs keep theirs',
        'apply': lambda: setattr(ast_scanner, 'CLUSTER2_BOOL_PREDICATE_PREFIXES', ()),
        'restore': lambda: setattr(ast_scanner, 'CLUSTER2_BOOL_PREDICATE_PREFIXES',
                                   _ORIG['predicate_prefixes']),
        'gains': {
                  'bool_nonstring.py': {('CWE-704', 18)}},
        'losses': {},
    },
    '704_telemetry_label_proof_disabled': {
        'why': 'a bool that only lands in a telemetry tag is charged as a decision again',
        'apply': lambda: _mute('_c704_bool_feeds_telemetry_label'),
        'restore': lambda: setattr(TT, '_c704_bool_feeds_telemetry_label', _ORIG['telemetry_label']),
        'gains': {
                  'bool_telemetry_label.py': {('CWE-704', 9), ('CWE-704', 10), ('CWE-704', 19)}},
        'losses': {},
    },
    '704_existence_read_proof_disabled': {
        'why': '`bool(row)` after a selector that answers "is it there?" is charged as string '
               'truthiness again',
        'apply': lambda: _mute('_c704_bool_operand_is_an_existence_read'),
        'restore': lambda: setattr(TT, '_c704_bool_operand_is_an_existence_read',
                                   _ORIG['existence_arm']),
        'gains': {
                  'existence_read.py': {('CWE-704', 6), ('CWE-704', 11)}},
        'losses': {},
    },
    '704_existence_callees_narrowed': {
        'why': 'this task\'s selector names go back out of the table, which is the measured state before '
               'the pocket was retired',
        'apply': lambda: setattr(ast_scanner, 'CWE704_EXISTENCE_READ_CALLEES',
                                 _ORIG['existence_callees'] - TASK14_EXISTENCE_READ_CALLEES),
        'restore': lambda: setattr(ast_scanner, 'CWE704_EXISTENCE_READ_CALLEES',
                                   _ORIG['existence_callees']),
        'gains': {
                  'existence_read.py': {('CWE-704', 6), ('CWE-704', 11)}},
        'losses': {},
    },
}

# Each falsifier re-scans only the fixtures its own proof governs, and re-scans them ONE AT A TIME. In a
# shared scan an imported name resolves once for the whole subset, so a neighbouring fixture's import
# table can hold a row quiet while the proof that would have charged it is gone -- the mutation then
# measures nothing and a live guard looks inert. Isolation is what makes `gains` a real measurement.
SCOPE = {
    '338_display_family_all_muted': TASK14_CWE338_SCOPE,
    '862_scoped_base_proof_disabled': ('scoped_base_endpoint.py', 'scoped_mixin_endpoint.py',
                                       'authz_component.py'),
    '862_authorisation_component_proof_disabled': ('authz_component.py', 'scoped_base_endpoint.py'),
    '862_verb_gate_emptied': ('verb_entrypoint_loud.py', 'dispatch_entrypoint_loud.py',
                              'generic_view_loud.py', 'helper_not_entrypoint.py',
                              'scoped_base_endpoint.py'),
    '862_helper_named_as_a_verb': ('helper_not_entrypoint.py',),
    '209_envelope_payload_proof_disabled': ('envelope_serializer.py', 'envelope_contract_attribute.py',
                                            'dispatcher_dict_control.py', 'direct_serializer.py',
                                            'direct_attribute.py', 'envelope_raw_frame_loud.py',
                                            'flask_tuple_reply_loud.py', 'wsgi_tuple_reply_loud.py'),
    '209_contract_attributes_narrowed': ('envelope_contract_attribute.py', 'direct_attribute.py',
                                         'envelope_raw_frame_loud.py'),
    '209_payload_serializers_emptied': ('envelope_serializer.py', 'direct_serializer.py',
                                        'flask_tuple_reply_loud.py'),
    '338_vocabulary_arm_disabled': ('vocabulary_draw.py', 'vocabulary_credential_loud.py'),
    '338_clamp_arm_disabled': ('clamped_distribution_draw.py', 'clamped_distribution_loud.py'),
    '338_continuous_leaves_narrowed': ('clamped_distribution_draw.py', 'clamped_distribution_loud.py',
                                       'loop_count_draw.py', 'duration_draw.py'),
    '338_separator_join_arm_disabled': ('separated_join_draw.py', 'separated_join_loud.py'),
    '338_template_tag_arm_disabled': ('template_tag_draw.py', 'template_tag_loud.py'),
    '338_shuffle_arm_disabled': ('shuffle_work_draw.py', 'shuffle_credential_loud.py'),
    '338_choice_set_arm_disabled': ('choice_set_draw.py', 'vocabulary_draw.py'),
    '328_written_out_identifier_proof_disabled': ('identifier_composite_digest.py',
                                                  'identifier_composite_loud.py', 'digest_noun_loud.py',
                                                  'bare_hasher_credential_loud.py'),
    '328_identifying_suffixes_narrowed': ('identifier_composite_digest.py',
                                          'identifier_composite_loud.py'),
    '328_bare_hasher_proof_disabled': ('bare_hasher_construction.py', 'bare_hasher_credential_loud.py'),
    '704_nonstring_proof_disabled': ('bool_nonstring.py', 'bool_telemetry_label.py',
                                     'decision_label_loud.py', 'bool_string_loud.py',
                                     'existence_read.py', 'existence_unbound_loud.py'),
    '704_predicate_prefixes_emptied': ('bool_nonstring.py',),
    '704_telemetry_label_proof_disabled': ('bool_telemetry_label.py', 'decision_label_loud.py'),
    '704_existence_read_proof_disabled': ('existence_read.py', 'existence_unbound_loud.py',
                                          'bool_nonstring.py'),
    '704_existence_callees_narrowed': ('existence_read.py', 'existence_unbound_loud.py'),
}

_RESTORED = []


def run_mutation(name):
    spec = MUTATIONS[name]
    scope = SCOPE[name]
    started = time.time()
    spec['apply']()
    try:
        got = {}
        for module in scope:
            _t, rows = scan_all({'t6_isolated_%s' % module: FIXTURES[module]})
            got[module] = {(row['cwe'], int(row['line'])) for row in rows}
    finally:
        spec['restore']()
    elapsed = time.time() - started
    appeared, vanished = {}, {}
    for module in scope:
        gained = got[module] - ISOLATED[module]
        lost = ISOLATED[module] - got[module]
        if gained:
            appeared[module] = gained
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


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == '--dump':
        dump_table()
        print('RSS=%.1f MB  setup=%.2fs' % (rss_mb(), time.time() - WORK_START))
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
    for name in sorted(MUTATIONS):
        times[name] = run_mutation(name)
    print('TIER 4: %d/%d falsifiers (%.2fs total, slowest %.2fs)'
          % (len(_RESTORED), len(MUTATIONS), sum(times.values()), max(times.values())))

    _restore_all()
    current = {
        'scoped_base': TT._c862_base_name_is_a_scoped_endpoint,
        'authz_component': TT._c862_class_is_an_authorisation_component,
        'dispatch_verbs': ast_scanner.CWE862_HTTP_DISPATCH_METHOD_NAMES,
        'envelope_payload': TT._c209_payload_is_structured_envelope,
        'contract_attrs': ast_scanner.CWE209_ERROR_CONTRACT_ATTRIBUTES,
        'serializers': ast_scanner.CWE209_PAYLOAD_SERIALIZERS,
        'duration_arm': TT._cwe338_draw_ships_a_duration,
        'vocabulary_arm': TT._cwe338_population_is_a_written_out_vocabulary,
            'clamp_arm': TT._cwe338_draw_is_clamped_by_a_declared_bound,
        'separator_arm': TT._cwe338_join_formats_a_separated_identifier,
        'template_tag_arm': TT._cwe338_draw_ships_a_registered_template_tag,
        'shuffle_arm': TT._cwe338_shuffle_reorders_a_work_list,
        'display_markers': ast_scanner.CWE338_DISPLAY_VALUE_MARKERS,
        'alphabet_members': ast_scanner.CWE338_STDLIB_ALPHABET_MEMBERS,
        'filler_members': ast_scanner.CWE338_FILLER_CORPUS_MEMBERS,
        'continuous_leaves': ast_scanner.CWE338_CONTINUOUS_DISTRIBUTION_LEAVES,
        'written_out_arm': TT._cwe328_hash_input_is_written_out_identifiers,
        'bare_hasher_arm': TT._cwe328_hasher_construction_has_no_input,
        'identifying_suffixes': ast_scanner.CWE328_IDENTIFYING_SUFFIX_WORDS,
        'telemetry_label': TT._c704_bool_feeds_telemetry_label,
        'nonstring_proof': TT._c704_bool_operand_is_nonstring,
        'predicate_prefixes': ast_scanner.CLUSTER2_BOOL_PREDICATE_PREFIXES,
        'sampling_gate_arm': TT._cwe338_bounded_draw_is_a_sampling_gate,
        'selects_literal_arm': TT._cwe338_draw_selects_a_literal_record,
        'labels_literal_arm': TT._cwe338_draw_labels_a_literal_record,
        'sample_data_arm': TT._cwe338_join_ships_literal_sample_data,
        'choice_set_arm': TT._cwe338_choices_call_is_a_django_choice_set,
        'existence_arm': TT._c704_bool_operand_is_an_existence_read,
        'existence_callees': ast_scanner.CWE704_EXISTENCE_READ_CALLEES,
    }
    for key, value in _ORIG.items():
        if current[key] is not value and current[key] != value:
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
