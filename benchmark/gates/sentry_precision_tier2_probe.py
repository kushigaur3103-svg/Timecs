"""Sentry precision, tier 2: the four provenance suppressions that retired the last ~380 FP families.

Why this gate exists, in one line: each of the four rules below decides *silence* from a fact about the
code -- a receiver's resolved type, the shape of an HTTP payload, the name a digest flows into, the
structure of a regex -- and every one of those facts can be read wrongly in a way that keeps the gate
green and deletes a true positive. `aa_parity` and `big8_ab` compare keys the engine still reports; they
cannot see a suppression that over-reaches into a row nobody blessed locally, and Sentry is not on this
machine. So the boundary of each veto is pinned here by a fixture, and each boundary is falsified from
both sides: the guard turned off must bring the quiet rows back, and the guard forced to answer "safe"
must take a loud row with it.

The four families, all measured on this checkout before and after:

* TIER 1 -- CWE-338 (`.choices` on a model/enum, and `random.random()` as a sampling threshold). The
  Django `Choices` *attribute* was already silent; what fired was the *call* form -- `w.choices(3)`,
  `ArtifactBundleIndexingState.choices(n)`, `channel.choices` read as a method call -- because
  `choices`, `sample`, `shuffle`
  and friends sit in the PRNG leaf table and matched any receiver. `_cwe338_receiver_is_foreign_object`
  now requires one fact about the object being called: its own name denotes a class THIS module
  declares (a bare name folding onto `Widget`, or a dotted path resolution left alone whose tail is
  such a class), and refuses the moment the draw's own naming vocabulary says secret. A fold is a
  rename, not an identity, so `rng` -> `global_rng`, `self.sub_model` -> the host class, an import
  whose qualified origin is all the source shows (`from scipy.stats import norm` ->
  `scipy.stats.norm.sample(size=8)`, which `mechanism_pitch_probe.py` locks loud), `store`,
  `get_rng()`, `self.choices(n)` and `random.*` are unproven or proven-random and stay reported --
  which is what the blessed Big-8 rows
  `values.append(rng.randint(0, vocab_size - 1))` / `values.append(rng.random() * scale)` depend on.
* TIER 2 -- CWE-209 (`Response({"detail": str(exc)}, status=400)`). `_c209_exposed_in_reply` asked only
  "does the reply carry the caught exception" and answered yes for DRF's documented error envelope.
  `_c209_structured_error_envelope_only` stands it down per reply, and only when every top-level key is
  a structured error label and no `traceback.format_*`, `sys.exc_info`, or raw-frame expression is
  anywhere in the body.
* TIER 3 -- CWE-328 (`etag`/`chunk_id`/`color_key`/`span_key` digests). The weak-hash branch consulted
  a statically `False` `usedforsecurity` and nothing else, while the CWE-327 sibling already honoured a
  non-crypto name. `_cwe328_hash_input_is_non_credential` wires that proof into CWE-328 with its own,
  wider vocabulary table -- wider must NOT mean shared, because `_is_exempt_cwe327` is also consulted on
  the CWE-338 path, and folding `blob`/`color` into the 327 table silences `blob = random.randbytes(16)`
  and `color_password = random.choice(alphabet)` (that mistake was caught by
  `benchmark/gates/cwe338_prng_context_probe.py` while this work was in progress, and
  `cwe327_table_absorbs_the_content_words` re-creates it here on purpose) -- and refuses the exemption
  whenever a security word names the bytes being hashed. The same helper answers for the three CWE-327
  registry sites, because a line retired under CWE-328 that stayed reported under CWE-327 was never
  retired at all. CWE-916 and CWE-759 are emitted by other rules and are pinned as collateral.
* TIER 4 -- CWE-1333 (`re.compile` of a safe constant). The emit gate already required a *static*
  pattern, so dynamic joins were never at risk; the FPs were inside `_regex_catastrophic_backtracking`,
  which flagged `^[a-z0-9]+(?:-[a-z0-9]+)*$` and `(?:foo|bar|baz)+/qux`. Two forced-boundary proofs
  exist: `_regex_head_delimited`, which credits the one mandatory character written *before* a repeat
  that the repeat body can never produce, and `_regex_branch_literals`, the prefix-free reading of an
  alternation of fixed literal words. A third clause drafted for this work, `_regex_leading_separator`
  (reading the body's own first token), was measured to change no verdict on any pattern this file
  enumerates -- the stream always sees that character one level up -- so it was deleted instead of kept
  as a clause no mutation can falsify. `(a+)+`, `(a*)*`, `(a|aa)+`, `(.+)+`, `(X+X)+` fail both remaining
  proofs and stay reported.

TIER 5 pins the vocabulary tables and the wiring in the source text, including the CWE-327/CWE-328 table
separation and the death of the redundant regex clause, so a later "tidy-up" that merges or resurrects
them has to break this gate on purpose.

TIER 6 is the falsification battery: 14 weakenings, each with the labels whose rows it owns, the labels
it must leave alone, and (for one refusal-only clause whose empty move-set is itself the measurement)
the position TIER 5 requires it to hold.
it must leave byte-identical, and any label whose *other-CWE* rows it is allowed to move. Every label is
compared against the baseline scan, not only the ones a mutation mentions: a declared row that does not
move is a decorative clause, and an undeclared row that moves is over-reach. TIER 7 is parity hygiene
(this file lives inside the scanned tree and must add no key) and TIER 8 the cost: peak RSS under 60 MB,
no corpus scan, every fixture compiled in memory.

Usage: python benchmark/gates/sentry_precision_tier2_probe.py [--mutate=NAME ...]
Exit 0 = every tier passes; 1 = a named failure; 2 = a mutation this file does not know.
"""
from __future__ import annotations

import ast
import contextlib
import ctypes
import inspect
import io
import os
import sys
import time
from ctypes import wintypes

_START = time.perf_counter()
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402

# The budget covers the gate's own work. Interpreter boot and importing the engine happen before this
# line, cost the gate nothing, and swing by 2-3x depending on what else the suite just left in the file
# cache -- pricing them would make a deterministic probe fail at random.
_BOOT = time.perf_counter()

_TT = ast_scanner.TaintTracker
BUDGET_SECONDS = 8.0
BUDGET_RSS_MB = 60.0
VIRTUAL_MODULE = 'sentry_precision_tier2_probe_fixture.py'

FAILURES = []

CWE338_MSG = 'CWE-338: %s'
CWE209_MSG = 'CWE-209: Detailed exception or stack trace exposed in response'
CWE328_MSG = 'CWE-328: WEAK_HASH'
CWE1333_MSG = 'CWE-1333: re.compile'


def fail(label, detail):
    FAILURES.append(label)
    print('  FAIL %s: %s' % (label, detail))


# --------------------------------------------------------------------------- fixtures
#
# Every source below is one virtual module, compiled in memory. Line numbers in the pins count from the
# first character of the string, so a reflow of a fixture moves a pin and the gate says so.

RANDOM_SPINE = 'import random\n\n'
DRF_SPINE = ('from rest_framework.response import Response\n'
             '\n'
             '\n'
             'class ErrorView:\n'
             '    def post(self, request):\n'
             '        try:\n'
             '            do_work(request.data)\n')
HASH_SPINE = 'import hashlib\n\n\ndef handler(cr, uid, name):\n    '

# ---- TIER 1: the quiet invariants -- target CWE reports nothing, and a named guard must own the silence.
QUIET = {
    'django_choices_tuple': ('CWE-338', 'foreign_receiver_proof_disabled', [
        'class UpdateChannel:\n'
        '    choices = (("unstable", "Unstable"), ("stable", "Stable"))\n'
        '\n'
        '\n'
        'def channel_labels(channel):\n'
        '    names = UpdateChannel.choices\n'
        '    for text, _label in channel.choices:\n'
        '        pass\n'
        '    return names\n',
        RANDOM_SPINE +
        'from sentry.conf.types.update_option_types import UpdateChannel\n'
        '\n'
        'def describe(value):\n'
        '    return dict(UpdateChannel.choices)[value]\n']),
    'model_class_member_call': ('CWE-338', 'foreign_receiver_proof_disabled', [
        'class ArtifactBundleIndexingState:\n'
        '    def choices(self, n):\n'
        '        return []\n'
        '\n'
        '\n'
        'def go(n):\n'
        '    return ArtifactBundleIndexingState.choices(n)\n',
        'class Widget:\n'
        '    def choices(self, n):\n'
        '        return []\n'
        '\n'
        '\n'
        'def draw(n):\n'
        '    widget = Widget()\n'
        '    return widget.choices(n)\n']),
    'probability_threshold_test': ('CWE-338', 'probability_threshold_veto_disabled', [
        RANDOM_SPINE +
        'def sample(rate):\n'
        '    if random.random() < rate:\n'
        '        return "hit"\n'
        '    return "miss"\n',
        RANDOM_SPINE +
        'def keep():\n'
        '    dropped = random.random() > 0.05\n'
        '    return dropped\n',
        RANDOM_SPINE +
        'def roll(scale):\n'
        '    while random.random() < scale:\n'
        '        return True\n'
        '    return False\n']),
    'drf_structured_error_envelope': ('CWE-209', 'structured_envelope_veto_disabled', [
        DRF_SPINE +
        '        except ValidationError as exc:\n'
        '            return Response({"detail": str(exc)}, status=400)\n',
        DRF_SPINE +
        '        except Exception as exc:\n'
        '            return Response({"error": str(exc), "code": "internal"}, status=500)\n',
        'from flask import jsonify\n'
        '\n'
        '\n'
        'def on_error(err):\n'
        '    try:\n'
        '        build()\n'
        '    except ValueError as exc:\n'
        '        return jsonify({"error": str(exc)}), 400\n']),
    'content_addressable_digest': ('CWE-328', 'content_hash_veto_disabled', [
        HASH_SPINE + 'etag = hashlib.md5(blob).hexdigest()\n    return etag\n',
        HASH_SPINE + 'chunk_id = hashlib.md5(raw).hexdigest()\n    return chunk_id\n',
        HASH_SPINE + 'color_key = hashlib.sha1(b"red").hexdigest()\n    return color_key\n',
        HASH_SPINE + 'span_lookup = hashlib.md5(payload_bytes).hexdigest()\n    return span_lookup\n',
        HASH_SPINE + 'blob_digest = hashlib.md5(raw).hexdigest()\n    return blob_digest\n',
        HASH_SPINE + 'checksum = hashlib.sha1(raw).hexdigest()\n    return checksum\n',
        HASH_SPINE + 'cache_key = hashlib.md5(repr(args)).hexdigest()\n    return cache_key\n',
        HASH_SPINE + 'fingerprint = hashlib.md5(path.encode()).hexdigest()\n    return fingerprint\n']),
    'usedforsecurity_keyword': ('CWE-328', 'content_hash_veto_disabled', [
        # Held by no single weakening of the name proof: this row is silenced by the `usedforsecurity`
        # disjunct that shipped long before this gate, which is why `content_hash_veto_disabled` must
        # leave it exactly as it is.
        HASH_SPINE + 'etag = hashlib.md5(blob, usedforsecurity=False).hexdigest()\n    return etag\n']),
    'separator_delimited_regex': ('CWE-1333', 'regex_head_boundary_disabled', [
        'import re\n'
        'SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")\n',
        'import re\n'
        'NUMBERED_RE = re.compile(r"(-\\d+)+")\n',
        'import re\n'
        'DOTTED_RE = re.compile(r"^\\d+(?:\\.\\d+){1,3}$")\n']),
    'prefix_free_alternation_regex': ('CWE-1333', 'regex_prefix_free_proof_disabled', [
        'import re\n'
        'WORDS_RE = re.compile(r"(?:foo|bar|baz)+/qux")\n',
        'import re\n'
        'MODE_RE = re.compile(r"(?:read|write|exec)+/once")\n']),
    'linear_literal_regex': ('CWE-1333', 'regex_head_boundary_disabled', [
        # Safe before this task and safe after it: pinned so the new head clause cannot widen into
        # the shapes that were never the problem.
        'import re\n'
        'EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")\n'
        'PHONE_RE = re.compile(r"^\\d{3}-\\d{2}-\\d{4}$")\n'
        'URL_RE = re.compile(r"^https?://(?:www\\.)?example\\.com/[a-z0-9-]+/?$")\n'
        'TAG_RE = re.compile(r"\\b(?:the|a|an)\\b")\n']),
}

# Labels whose silence this task did not buy: no clause added here moves them, so the weakening that
# comes nearest is required to leave them exactly as they are. Naming them prevents a fixture that
# "passes" because some unrelated rule happens to be switched off elsewhere.
PRE_EXISTING_QUIET = frozenset({'django_choices_tuple', 'linear_literal_regex',
                               'usedforsecurity_keyword'})

# ---- TIER 2: the loud invariants -- the exact target-CWE rows this source must produce.
LOUD = {
    'random_choice_token_mint': ('CWE-338', [
        (RANDOM_SPINE + 'import string\n'
                        '\n'
                        '\n'
                        'def mint():\n'
                        '    token = "".join(random.choice(string.ascii_letters) for _ in range(32))\n'
                        '    return token\n', ((7, CWE338_MSG % 'random.choice'),))]),
    'random_randint_session_key': ('CWE-338', [
        (RANDOM_SPINE + '\ndef make():\n    session_key = random.randint(0, 2 ** 53)\n'
                        '    return session_key\n', ((5, CWE338_MSG % 'random.randint'),))]),
    'random_module_choices': ('CWE-338', [
        (RANDOM_SPINE + '\ndef pick(population):\n    return random.choices(population, k=2)\n',
         ((5, CWE338_MSG % 'random.choices'),))]),
    'imported_choice_leaf': ('CWE-338', [
        ('from random import choice\n'
         '\n'
         '\n'
         'def pick(alphabet):\n    return choice(alphabet)\n',
         ((5, CWE338_MSG % 'random.choice'),))]),
    'random_instance_constructor': ('CWE-338', [
        (RANDOM_SPINE + '\ndef build(seed):\n    rng = random.Random(seed)\n'
                        '    return rng.random() * 4\n',
         ((5, CWE338_MSG % 'random.Random'), (6, CWE338_MSG % 'random.Random.random')))]),
    'random_instance_draw': ('CWE-338', [
        (RANDOM_SPINE + '\ndef draw(vocab_size):\n    rng = random.Random()\n'
                        '    return rng.randint(0, vocab_size - 1)\n',
         ((5, CWE338_MSG % 'random.Random'), (6, CWE338_MSG % 'random.Random.randint')))]),
    'getrandbits_and_randbytes': ('CWE-338', [
        (RANDOM_SPINE + '\ndef widen():\n    nonce = random.getrandbits(128)\n'
                        '    blob = random.randbytes(16)\n    return nonce, blob\n',
         ((5, CWE338_MSG % 'random.getrandbits'), (6, CWE338_MSG % 'random.randbytes')))]),
    'aliased_random_module_draw': ('CWE-338', [
        # `import random as rd` folds the receiver onto the module path, which is what the segment
        # allow-list reads; without that allow-list the alias looks like an arbitrary object.
        ('import random as rd\n'
         '\n'
         '\n'
         'def go(n):\n    return rd.choice(range(n))\n',
         ((5, CWE338_MSG % 'random.choice'),))]),
    'random_attribute_on_self': ('CWE-338', [
        ('import random\n'
         '\n'
         '\n'
         'class Roller:\n'
         '    def __init__(self):\n        self.random = random.Random()\n'
         '\n'
         '    def roll(self, n):\n        return self.random.randint(0, n)\n',
         ((6, CWE338_MSG % 'random.Random'), (9, CWE338_MSG % 'self.random.randint')))]),
    'traceback_in_drf_envelope': ('CWE-209', [
        ('import traceback\n'
         'from rest_framework.response import Response\n'
         '\n'
         '\n'
         'class ErrorView:\n'
         '    def post(self, request):\n'
         '        try:\n'
         '            do_work(request.data)\n'
         '        except Exception as exc:\n'
         '            return Response({"error": traceback.format_exc()}, status=500)\n',
         ((10, CWE209_MSG),))]),
    'format_exception_in_envelope': ('CWE-209', [
        ('import traceback\n'
         'from rest_framework.response import Response\n'
         '\n'
         '\n'
         'class ErrorView:\n'
         '    def post(self, request):\n'
         '        try:\n'
         '            do_work(request.data)\n'
         '        except Exception:\n'
         '            return Response({"detail": traceback.format_exception(*__import__("sys").exc_info())},\n'
         '                            status=500)\n', ((10, CWE209_MSG),))]),
    'raw_traceback_object_in_envelope': ('CWE-209', [
        (DRF_SPINE +
         '        except Exception as exc:\n'
         '            return Response({"error": exc.__traceback__.tb_frame}, status=500)\n',
         ((9, CWE209_MSG),))]),
    'password_weak_digest': ('CWE-328', [
        (HASH_SPINE + 'password_hash = hashlib.md5(password.encode()).hexdigest()\n'
                      '    return password_hash\n', ((5, CWE328_MSG),))]),
    'md5_of_password_literal': ('CWE-328', [
        ('import hashlib\n'
         '\n'
         '\n'
         'def sign(user):\n'
         '    return hashlib.md5(user.password.encode()).hexdigest()\n',
         ((5, CWE328_MSG),))]),
    'catastrophic_nested_quantifier': ('CWE-1333', [
        ('import re\n'
         'A = re.compile(r"(a+)+")\n', ((2, CWE1333_MSG),))]),
    'catastrophic_star_star': ('CWE-1333', [
        ('import re\n'
         'B = re.compile(r"(a*)*")\n', ((2, CWE1333_MSG),))]),
    'catastrophic_prefix_branch': ('CWE-1333', [
        ('import re\n'
         'C = re.compile(r"(a|aa)+")\n', ((2, CWE1333_MSG),))]),
    'catastrophic_dot_plus': ('CWE-1333', [
        ('import re\n'
         'D = re.compile(r"(.+)+")\n', ((2, CWE1333_MSG),))]),
    'catastrophic_overlap_run': ('CWE-1333', [
        ('import re\n'
         'E = re.compile(r"(X+X)+")\n', ((2, CWE1333_MSG),))]),
    'dynamic_join_regex': ('CWE-1333', [
        ('import re\n'
         '\n'
         '\n'
         'def build(missing_patterns):\n'
         '    return re.compile("|".join(rf"({pattern})" for pattern in missing_patterns))\n',
         ((5, CWE1333_MSG),))]),
}

# ---- TIER 3: right vocabulary, wrong provenance -- each veto must refuse, so the row stays reported.
PROVENANCE = {
    'unfoldable_receiver_names': ('CWE-338', [
        'def build(store, n):\n'
        '    return store.choices(n)\n'],
        ((2, CWE338_MSG % 'store.choices'),)),
    'self_member_call_unresolved': ('CWE-338', [
        'class Widget:\n'
        '    def choices(self, n):\n'
        '        return list(range(n))\n'
        '\n'
        '    def pick(self, n):\n'
        '        return self.choices(n)\n'],
        # `self` is the one receiver this proof cannot resolve, even though the class declares
        # `choices` two lines above: an unresolved receiver is not a proven foreign object, and the
        # blessed Big-8 draws are exactly the plain names (`rng`, `w`) this shape resembles.
        ((6, CWE338_MSG % 'self.choices'),)),
    'factory_call_receiver': ('CWE-338', [
        'import random\n'
        '\n'
        'def go():\n    return get_random().randint(0, 9)\n'],
        ((4, CWE338_MSG % 'randint'),)),
    'plain_name_rng_parameter': ('CWE-338', [
        'def ids(rng, vocab_size, total_dims):\n'
        '    values = []\n'
        '    for _ in range(total_dims):\n        values.append(rng.randint(0, vocab_size - 1))\n'
        '    return values\n'],
        ((4, CWE338_MSG % 'rng.randint'),)),
    'credential_named_choices_secret': ('CWE-338', [
        RANDOM_SPINE + '\ndef pick(alphabet):\n    widget_password = random.choice(alphabet)\n'
                       '    return widget_password\n'],
        ((5, CWE338_MSG % 'random.choice'),)),
    'threshold_with_security_operand': ('CWE-338', [
        RANDOM_SPINE + '\ndef sample(token_ttl):\n    if random.random() > token_ttl:\n'
                       '        return True\n    return False\n'],
        ((5, CWE338_MSG % 'random.random'),)),
    'checksum_of_a_token': ('CWE-328', [
        HASH_SPINE + 'token_checksum = hashlib.md5(token).hexdigest()\n    return token_checksum\n'],
        ((5, CWE328_MSG),)),
    'checksum_of_a_signature': ('CWE-328', [
        'import hashlib\n'
        '\n'
        '\n'
        'def store(payload, sign_key):\n'
        '    etag = hashlib.md5(sign_key).hexdigest()\n'
        '    return etag\n'],
        ((5, CWE328_MSG),)),
    'envelope_with_a_frame_key': ('CWE-209', [
        'import traceback\n'
        'from rest_framework.response import Response\n'
        '\n'
        '\n'
        'class ErrorView:\n'
        '    def post(self, request):\n'
        '        try:\n'
        '            do_work(request.data)\n'
        '        except Exception as exc:\n'
        '            return Response({"detail": str(exc), "stack": traceback.format_stack()},\n'
        '                            status=500)\n'],
        ((10, CWE209_MSG),)),
    'envelope_with_an_unlisted_key': ('CWE-209', [
        DRF_SPINE +
        '        except Exception as exc:\n'
        '            return Response({"environment": str(exc)}, status=500)\n'],
        ((9, CWE209_MSG),)),
    'regex_branch_that_shrinks': ('CWE-1333', [
        'import re\n'
        'F = re.compile(r"(a|b|ab)*")\n'],
        ((2, CWE1333_MSG),)),
}

# --------------------------------------------------------------------------- scan harness

SCANS = [0]


def probe_module_rows(source):
    """Every row for one in-memory module, through the real record path (`cli._findings_for`)."""
    SCANS[0] += 1
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        tracker = _TT(files={VIRTUAL_MODULE: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(int(r['line']), r['cwe'], r['message']) for r in rows})


def split_rows(rows, cwe):
    """(target-CWE rows, every other row) -- the two halves the falsification sweep compares apart."""
    return (tuple(r for r in rows if r[1] == cwe), tuple(r for r in rows if r[1] != cwe))


CASES = {}
for _label, (_cwe, _guard, _sources) in QUIET.items():
    CASES[_label] = (_cwe, list(_sources))
for _label, (_cwe, _shapes) in LOUD.items():
    CASES[_label] = (_cwe, [src for src, _pin in _shapes])
for _label, (_cwe, _sources, _pins) in PROVENANCE.items():
    CASES[_label] = (_cwe, list(_sources))
SOURCE_COUNT = sum(len(sources) for _cwe, sources in CASES.values())

_BASE = {label: [split_rows(probe_module_rows(src), cwe) for src in sources]
         for label, (cwe, sources) in CASES.items()}


def observe(label):
    """(target-CWE rows, other-CWE rows) per source of one label, in a single scan each."""
    cwe, sources = CASES[label]
    return [split_rows(probe_module_rows(src), cwe) for src in sources]


# --------------------------------------------------------------------------- mutations
#
# Each entry names the shipped clause it weakens, the labels whose rows that clause owns (`moves`), and
# the labels it must leave byte-identical (`holds`). Both lists are measured on this build with
# `--mutate=NAME`, so they are facts about the engine rather than intentions. Forcing a clause to answer
# "safe" is what proves the clause is the reason a row is missing -- a suppression nobody can turn off is
# a suppression that does not exist.

GUARD_METHODS = (
    '_cwe338_receiver_is_foreign_object',
    '_cwe338_probability_threshold_draw',
    '_cwe338_display_only_draw',
    '_c209_structured_error_envelope_only',
    '_cwe328_hash_input_is_non_credential',
    '_is_exempt_cwe327',
)
_ORIGINALS = {name: getattr(_TT, name) for name in GUARD_METHODS}
_MODULE_FUNCTIONS = ('_regex_head_delimited', '_regex_branch_literals')
_MODULE_ORIGINALS = {name: getattr(ast_scanner, name) for name in _MODULE_FUNCTIONS}
# A mutation that replaces a table has to hand it back: without this, the allow-list mutation below
# silently blinded every mutation the battery ran after it, and each of those reported two extra
# labels as "moved" for a reason that had nothing to do with the clause being weakened.
_MODULE_CONSTANTS = ('CWE338_RANDOM_SOURCE_SEGMENTS', 'CWE327_NON_CRYPTO_KEYWORDS',
                     'CWE328_CONTENT_HASH_KEYWORDS')
_CONSTANT_ORIGINALS = {name: getattr(ast_scanner, name) for name in _MODULE_CONSTANTS}


def _disable(name):
    return lambda: setattr(_TT, name, lambda self, *args, **kwargs: False)


def _answer(name, value):
    return lambda: setattr(_TT, name, lambda self, *args, **kwargs: value)


def _patch_function(name, value):
    return lambda: setattr(ast_scanner, name, lambda *args, **kwargs: value)


def _patch_constant(name, value):
    return lambda: setattr(ast_scanner, name, value)


def _float_draw_always_a_threshold(self, node, scope_id=''):
    """The threshold veto with its comparison and credential tests removed, its leaf test kept."""
    return isinstance(node.func, ast.Attribute) and node.func.attr == 'random'


def restore():
    for name, method in _ORIGINALS.items():
        setattr(_TT, name, method)
    for name, function in _MODULE_ORIGINALS.items():
        setattr(ast_scanner, name, function)
    for name, table in _CONSTANT_ORIGINALS.items():
        setattr(ast_scanner, name, table)


MUTATIONS = {
    'foreign_receiver_proof_disabled': {
        'what': 'answer "not proven foreign" for every receiver, so any `.choices(...)` call is a draw',
        'moves': ['model_class_member_call'],
        'holds': ['django_choices_tuple', 'probability_threshold_test', 'drf_structured_error_envelope',
                  'content_addressable_digest', 'separator_delimited_regex', 'random_module_choices',
                  'aliased_random_module_draw'],
        'apply': _disable('_cwe338_receiver_is_foreign_object'),
    },
    'foreign_receiver_proof_always_proves': {
        'what': 'answer "proven foreign" for every receiver -- the fail-closed half, deleted',
        'moves': ['random_module_choices', 'random_instance_draw', 'random_instance_constructor',
                  'getrandbits_and_randbytes', 'unfoldable_receiver_names',
                  'self_member_call_unresolved', 'factory_call_receiver', 'plain_name_rng_parameter',
                  'random_choice_token_mint', 'random_randint_session_key',
                  'credential_named_choices_secret', 'threshold_with_security_operand',
                  'aliased_random_module_draw', 'random_attribute_on_self'],
        'holds': ['django_choices_tuple', 'model_class_member_call', 'content_addressable_digest',
                  'traceback_in_drf_envelope', 'imported_choice_leaf', 'probability_threshold_test'],
        'apply': _answer('_cwe338_receiver_is_foreign_object', True),
    },
    'receiver_random_segments_blinded': {
        # Measured, and the measurement is the finding: emptying this allow-list moves no row of the 56
        # sources, because the declared-class test below it already refuses every receiver this table
        # would have refused first. It is a refusal, so it can only ever add a report -- the battery
        # does not claim a weakening nobody can falsify, and TIER 5 pins its position instead: it has
        # to stay the first answer, ahead of the identity test, for a folded path that passes through
        # `random`/`secrets` while also naming a class (`class Random:` + `rng = Random()`).
        'what': 'empty the allow-list, so a folded path through `random` reads as an ordinary object',
        'moves': [],
        'holds': ['django_choices_tuple', 'model_class_member_call', 'random_module_choices',
                  'imported_choice_leaf', 'content_addressable_digest', 'aliased_random_module_draw',
                  'random_attribute_on_self'],
        'apply': _patch_constant('CWE338_RANDOM_SOURCE_SEGMENTS', frozenset()),
    },
    'cwe327_table_absorbs_the_content_words': {
        # The merge that this file exists to prevent: `_is_exempt_cwe327` answers for the CWE-338 path
        # too, so a `blob`/`color` in the 327 table is a PRNG draw silenced by the name of the
        # variable that receives it. Measured on this build: `blob = random.randbytes(16)` goes quiet.
        'what': 'merge the two vocabulary tables, the tidy-up that reads a PRNG draw as a checksum',
        'moves': ['getrandbits_and_randbytes'],
        'holds': ['content_addressable_digest', 'password_weak_digest', 'checksum_of_a_token',
                  'model_class_member_call', 'drf_structured_error_envelope'],
        'apply': _patch_constant('CWE327_NON_CRYPTO_KEYWORDS',
                                 ast_scanner.CWE328_CONTENT_HASH_KEYWORDS),
    },
    'probability_threshold_veto_disabled': {
        'what': 'refuse the threshold reading, so `if random.random() < rate` is a secret draw again',
        'moves': ['probability_threshold_test'],
        'holds': ['django_choices_tuple', 'drf_structured_error_envelope',
                  'threshold_with_security_operand', 'random_instance_constructor'],
        'apply': _disable('_cwe338_probability_threshold_draw'),
    },
    'probability_threshold_veto_forced_on_every_float_draw': {
        'what': 'read every `X.random()` as a sampling test, comparison and credential names ignored',
        'moves': ['threshold_with_security_operand', 'random_instance_constructor'],
        'holds': ['probability_threshold_test', 'django_choices_tuple', 'imported_choice_leaf',
                  'credential_named_choices_secret', 'random_attribute_on_self'],
        'apply': lambda: setattr(_TT, '_cwe338_probability_threshold_draw',
                                 _float_draw_always_a_threshold),
    },
    'structured_envelope_veto_disabled': {
        'what': 'refuse the DRF envelope reading, so `{"detail": str(exc)}` is a stack exposure again',
        'moves': ['drf_structured_error_envelope'],
        'holds': ['content_addressable_digest', 'separator_delimited_regex',
                  'traceback_in_drf_envelope', 'envelope_with_a_frame_key', 'model_class_member_call'],
        'apply': _disable('_c209_structured_error_envelope_only'),
    },
    'structured_envelope_veto_always_accepts': {
        'what': 'call every reply a safe envelope -- the traceback and raw-frame guards, deleted',
        'moves': ['traceback_in_drf_envelope', 'format_exception_in_envelope',
                  'raw_traceback_object_in_envelope', 'envelope_with_a_frame_key',
                  'envelope_with_an_unlisted_key'],
        'holds': ['drf_structured_error_envelope', 'password_weak_digest', 'content_addressable_digest'],
        'apply': _answer('_c209_structured_error_envelope_only', True),
    },
    'content_hash_veto_disabled': {
        'what': 'refuse the non-crypto name proof, so every `etag`/`chunk_id` digest is a weak hash',
        'moves': ['content_addressable_digest'],
        # The same helper answers for the three CWE-327 registry sites (ast_scanner.py:13168, 13183,
        # 13195), so switching it off re-lights CWE-327 on those lines as well. Declared, not drift:
        # TIER 4 pins that routing, and every other label must keep its non-target rows identical.
        'collateral': ['content_addressable_digest'],
        'holds': ['usedforsecurity_keyword', 'password_weak_digest', 'checksum_of_a_token',
                  'probability_threshold_test', 'linear_literal_regex'],
        'apply': _disable('_cwe328_hash_input_is_non_credential'),
    },
    'content_hash_credential_arm_dropped': {
        'what': 'accept the name proof without reading what is being hashed',
        'moves': ['checksum_of_a_token', 'checksum_of_a_signature', 'password_weak_digest',
                  'md5_of_password_literal'],
        'holds': ['content_addressable_digest', 'usedforsecurity_keyword', 'random_attribute_on_self',
                  'traceback_in_drf_envelope'],
        'apply': _answer('_cwe328_hash_input_is_non_credential', True),
    },
    'regex_head_boundary_disabled': {
        'what': 'never credit a mandatory opening character, so `(-[a-z0-9]+)*` multiplies again',
        'moves': ['separator_delimited_regex'],
        'holds': ['linear_literal_regex', 'prefix_free_alternation_regex',
                  'catastrophic_nested_quantifier', 'dynamic_join_regex', 'content_addressable_digest'],
        'apply': _patch_function('_regex_head_delimited', False),
    },
    'regex_head_boundary_invented': {
        'what': 'credit every repeat with a disjoint opening character, boundaries asserted not read',
        'moves': ['catastrophic_nested_quantifier', 'catastrophic_star_star',
                  'catastrophic_dot_plus', 'catastrophic_overlap_run', 'catastrophic_prefix_branch',
                  'regex_branch_that_shrinks'],
        'holds': ['linear_literal_regex', 'prefix_free_alternation_regex', 'separator_delimited_regex',
                  'dynamic_join_regex', 'content_addressable_digest', 'traceback_in_drf_envelope'],
        'apply': _patch_function('_regex_head_delimited', True),
    },
    'regex_prefix_free_proof_disabled': {
        'what': 'refuse the prefix-free word reading, so `(?:foo|bar|baz)+` is catastrophic',
        'moves': ['prefix_free_alternation_regex'],
        'holds': ['catastrophic_prefix_branch', 'regex_branch_that_shrinks', 'linear_literal_regex',
                  'separator_delimited_regex'],
        'apply': _patch_function('_regex_branch_literals', None),
    },
    'regex_prefix_free_proof_overreaches': {
        'what': 'call every alternation prefix-free, including `(a|aa)` and `(a|b|ab)`',
        'moves': ['regex_branch_that_shrinks'],
        'holds': ['prefix_free_alternation_regex', 'catastrophic_prefix_branch', 'dynamic_join_regex',
                  'separator_delimited_regex'],
        'apply': _patch_function('_regex_branch_literals', ()),
    },
}


# --------------------------------------------------------------------------- tiers

def check_quiet():
    passed = 0
    for label, (cwe, guard, sources) in sorted(QUIET.items()):
        rows = [row for target, _others in _BASE[label] for row in target]
        if rows:
            fail('quiet.%s' % label, '%s still reports %d row(s) this task retired: %s'
                 % (cwe, len(rows), rows[:2]))
        elif guard not in MUTATIONS:
            fail('quiet.%s' % label, 'no mutation claims ownership of this silence')
        elif label in MUTATIONS[guard]['moves']:
            passed += 1
        elif label in PRE_EXISTING_QUIET and label in MUTATIONS[guard]['holds']:
            passed += 1  # bought before this task; the nearest clause must leave it untouched
        else:
            fail('quiet.%s' % label,
                 'guard %s neither moves this silence nor is required to hold it: the fixture is '
                 'quiet for a reason nobody has named' % guard)
    print('  quiet: %d/%d  (ownership re-checked as a real row move in TIER 6)'
          % (passed, len(QUIET)))
    return passed, len(QUIET)


def check_loud():
    passed = 0
    for label, (cwe, shapes) in sorted(LOUD.items()):
        clean = True
        observed = _BASE[label]
        for index, (_src, pin) in enumerate(shapes):
            got = [(line, message) for line, _c, message in observed[index][0]]
            if got != list(pin):
                fail('loud.%s' % label, 'source %d expected exactly %s, got %s' % (index, pin, got))
                clean = False
        passed += 1 if clean else 0
    print('  loud: %d/%d' % (passed, len(LOUD)))
    return passed, len(LOUD)


def check_provenance():
    passed = 0
    for label, (cwe, sources, pins) in sorted(PROVENANCE.items()):
        got = [(line, message) for line, _c, message in _BASE[label][0][0]]
        if got != list(pins):
            fail('provenance.%s' % label, 'expected %s, got %s' % (pins, got))
        else:
            passed += 1
    print('  provenance fail-closed: %d/%d' % (passed, len(PROVENANCE)))
    return passed, len(PROVENANCE)


def check_law_source():
    """TIER 5 -- the tables and the wiring, read out of the shipped file."""
    passed = 0
    if ast_scanner.CWE338_RANDOM_SOURCE_SEGMENTS != frozenset(
            {'random', 'Random', 'secrets', 'SystemRandom'}):
        fail('law.CWE338_RANDOM_SOURCE_SEGMENTS',
             'got %s' % sorted(ast_scanner.CWE338_RANDOM_SOURCE_SEGMENTS))
    elif ast_scanner.CWE338_PROBABILITY_DRAW_LEAVES != frozenset({'random'}):
        fail('law.only_the_float_draw_is_a_probability',
             'got %s' % sorted(ast_scanner.CWE338_PROBABILITY_DRAW_LEAVES))
    elif not {'detail', 'error'} <= set(ast_scanner.CWE209_STRUCTURED_ERROR_KEYS):
        fail('law.envelope_keys', 'detail/error must be listed, got %s'
             % sorted(ast_scanner.CWE209_STRUCTURED_ERROR_KEYS))
    elif ast_scanner.CWE209_STRUCTURED_ERROR_KEYS & {'traceback', 'stack', 'frames', 'env',
                                                     'environment', 'exception'}:
        fail('law.envelope_keys_refuse_trace_carriers',
             'got %s' % sorted(ast_scanner.CWE209_STRUCTURED_ERROR_KEYS))
    elif not {'chunk', 'blob', 'color', 'span'} <= set(ast_scanner.CWE328_CONTENT_HASH_KEYWORDS):
        fail('law.content_hash_vocabulary', 'got %s'
             % sorted(ast_scanner.CWE328_CONTENT_HASH_KEYWORDS))
    elif set(ast_scanner.CWE327_NON_CRYPTO_KEYWORDS) & {'chunk', 'blob', 'color', 'span'}:
        # The separation is load-bearing: `_is_exempt_cwe327` runs on the CWE-338 path too, so a merged
        # table would silence `blob = random.randbytes(16)` and `color_password = random.choice(...)`.
        fail('law.the_two_vocabulary_tables_stay_separate',
             'CWE327_NON_CRYPTO_KEYWORDS now carries %s'
             % sorted(set(ast_scanner.CWE327_NON_CRYPTO_KEYWORDS)
                      & {'chunk', 'blob', 'color', 'span'}))
    else:
        passed += 1

    with open(os.path.join(_ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        whole = handle.read()
    for needle, want, label in (
        ('self._cwe338_receiver_is_foreign_object(', 1, 'the receiver proof has one call site'),
        ('self._cwe338_probability_threshold_draw(', 1, 'the threshold proof has one call site'),
        ('self._c209_structured_error_envelope_only(', 2,
         'the envelope proof is asked for the written value and its folded alias'),
        ('self._cwe328_hash_input_is_non_credential(', 4,
         'one CWE-328 site plus the three CWE-327 registry sites, and nothing else'),
        ('if self._is_exempt_cwe327(node, scope_id, call_lineno):', 2,
         'the two exemptions that run before the CWE-338 block still read the narrow table'),
        ('head_delimited = _regex_head_delimited(previous_single_char, current_chars)', 1,
         'the head boundary is asked once, from the analyzer loop'),
        ('_regex_branch_literals(branches) is None', 1, 'the prefix-free proof is read from the branch list'),
        ('_regex_leading_separator', 0, 'the redundant body-head clause stays deleted'),
        ('if any(segment in CWE338_RANDOM_SOURCE_SEGMENTS for segment in segments + written):', 1,
         'the random-source refusal is read from the folded path and the written path together'),
        ('if segments[-1].endswith("Random") or written[-1].endswith("Random"):', 1,
         'a receiver named after a PRNG class is refused before its identity is asked'),
    ):
        got = whole.count(needle)
        if got != want:
            fail('law.%s' % label, 'found %d, want %d: %r' % (got, want, needle))
        else:
            passed += 1

    # The order is the point: a table that only ever answers "refuse" is worth nothing if the identity
    # test gets there first, so the two refusals have to sit ahead of both `names_declared_class` asks.
    refusals = (whole.index('if any(segment in CWE338_RANDOM_SOURCE_SEGMENTS'),
                whole.index('if segments[-1].endswith("Random")'))
    identity = (whole.index('if receiver_canon != receiver_name or not names_declared_class(written[-1]):'),
                whole.index('elif not names_declared_class(segments[-1]):'))
    if not (all(refusal < min(identity) for refusal in refusals)):
        fail('law.the_refusals_run_before_the_identity_test',
             'refusal offsets %s, identity offsets %s' % (refusals, identity))
    else:
        passed += 1
    proof = inspect.getsource(_TT._cwe338_receiver_is_foreign_object)
    if 'self.imports' in proof:
        fail('law.an_import_record_is_not_an_identity',
             'the receiver proof reads an import again -- `from scipy.stats import norm` folds to a '
             'qualified origin and `norm.sample()` is a draw that mechanism_pitch locks loud')
    else:
        passed += 1

    analyzer = inspect.getsource(ast_scanner._regex_catastrophic_backtracking)
    if analyzer.count('not head_delimited') != 2:
        fail('law.both_fire_tests_use_the_head_boundary',
             'found %d uses of `not head_delimited`, want 2' % analyzer.count('not head_delimited'))
    else:
        passed += 1
    helper = inspect.getsource(ast_scanner._regex_head_delimited)
    if 'previous_single_char is not None and current_chars is not None' not in helper:
        fail('law.the_head_boundary_reads_a_character_the_analyzer_actually_saw',
             'the helper no longer requires a mandatory preceding character')
    else:
        passed += 1
    verdict = inspect.getsource(ast_scanner._is_redos_vulnerable_pattern)
    if 'import regex' in verdict or 'regex.' in verdict:
        fail('law.the_verdict_still_never_imports_regex', 'the structural verdict gained a dependency')
    else:
        passed += 1
    print('  source law: %d/%d' % (passed, 16))
    return passed, 16


def check_verdict_table():
    """TIER 5b -- the structural verdict alone, no scan: every named shape, both directions."""
    catastrophic = [r'(a+)+', r'(a*)*', r'(a|aa)+', r'(.+)+', r'(X+X)+', r'(?:\d+)+', r'(\w+\s?)*',
                    r'(a|b|ab)*', r'(a+)(b+)+', r'^(a+)+$', r'([\w.]+)+@']
    linear = [r'^[a-z0-9]+(?:-[a-z0-9]+)*$', r'(?:foo|bar|baz)+/qux',
              r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', r'^\d{3}-\d{2}-\d{4}$',
              r'^https?://(?:www\.)?example\.com/[a-z0-9-]+/?$', r'\b(?:the|a|an)\b',
              r'[A-Za-z0-9_-]{1,64}', r'^(\d+,)*\d*$', r'(-\d+)+', r'(?:[a-z]+,)+', r'a{1,3}b+',
              r'^[a-f0-9]{32}$', r'(?:\w+-)+\w+$', r'^#[0-9a-fA-F]{3,8}$', r'^[+-]?\d+(\.\d+)?$',
              r'^[A-Z][a-z]+(?: [A-Z][a-z]+)*$']
    verdict = ast_scanner._is_redos_vulnerable_pattern
    missed = [p for p in catastrophic if not verdict(p)]
    stale = [p for p in linear if verdict(p)]
    if missed:
        fail('verdict.catastrophic_rows_went_quiet', '%s no longer multiply' % missed)
    if stale:
        fail('verdict.safe_literals_still_fire', '%s still read as catastrophic' % stale)
    print('  structural verdict: %d/%d catastrophic loud, %d/%d linear quiet'
          % (len(catastrophic) - len(missed), len(catastrophic), len(linear) - len(stale), len(linear)))
    return 1 if not missed and not stale else 0, 1


def run_falsification(name):
    """Weaken one clause; the set of labels whose rows move must equal the set it claims.

    Every label is compared, not just the ones the spec mentions: a clause that silences something
    outside its declared list is over-reaching, and a declared row that does not move is decorative.
    A label may also lose rows of a *different* CWE when the same helper answers for both sites
    (`content_hash_veto_disabled` re-lights CWE-327 as well as CWE-328), and that must be declared in
    `collateral` -- silence for any other label is drift.

    One spec declares an empty `moves` list, and that is a different claim, stated as such: the clause
    it weakens is a pure refusal (`CWE338_RANDOM_SOURCE_SEGMENTS`), so retiring it cannot re-light a
    row that the identity test below it has already refused. What is pinned for that clause is not a
    mover but its position -- TIER 5 requires the refusal to run first -- and the empty move-set is the
    measurement that says the ordering, not the table, is what keeps those receivers loud.

    Returns 1 when CAUGHT, 0 when MISSED, 2 when the mutation itself broke.
    """
    spec = MUTATIONS[name]
    restore()
    try:
        spec['apply']()
        moved, strayed, collateral = [], [], []
        for label in sorted(CASES):
            after = observe(label)
            target = [row for row, _ in after]
            others = [other for _, other in after]
            if target != [row for row, _ in _BASE[label]]:
                (moved if label in spec['moves'] else strayed).append(label)
            if others != [other for _, other in _BASE[label]] and label not in spec.get('collateral', ()):
                collateral.append((label, _BASE[label][0][1], others))
    except Exception as exc:
        restore()
        print('MUTATION ERROR: %s: %s' % (type(exc).__name__, exc))
        return 2
    finally:
        restore()
    caught = (sorted(moved) == sorted(spec['moves']) and not strayed and not collateral)
    print('MUTATION %s: %s' % (name, spec['what']))
    print('  rows moved: %s' % (', '.join(moved) or '-'))
    if sorted(spec['moves']) != sorted(moved):
        print('  claimed but did not move: %s'
              % ', '.join(sorted(set(spec['moves']) - set(moved))))
    if strayed:
        print('  moved without being claimed: %s' % ', '.join(strayed))
    if collateral:
        print('  collateral rows of another CWE changed: %s' % (collateral[:2],))
    print('FALSIFICATION VERDICT (%s): %s' % (name,
          'CAUGHT, surgical' if caught else
          'MISSED - this clause is decorative or over-reaching; its rows did not move as claimed'))
    return 1 if caught else 0


def check_battery():
    caught = 0
    for name in sorted(MUTATIONS):
        code = run_falsification(name)
        if code == 1:
            caught += 1
        elif code == 2:
            fail('battery.%s' % name, 'the mutation itself raised')
        else:
            fail('battery.%s' % name, 'not CAUGHT and surgical')
    print('  falsification battery: %d/%d CAUGHT' % (caught, len(MUTATIONS)))
    return caught, len(MUTATIONS)


def module_level_names(path):
    """Names this module binds at top level: defs, classes, assignments (imports are not callees)."""
    with open(path, encoding='utf-8') as handle:
        tree = ast.parse(handle.read(), filename=path)
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
    return names


def check_hygiene():
    """TIER 7 -- why this file is allowed to sit inside the scanned `benchmark/` tree.

    `aa_parity` scans all of `benchmark/` with cross-file taint and its blessed baseline holds not one
    `benchmark/gates/` key, so a gate file that itself reports a finding moves the parity key set and
    fails parity. The recorded hazard is a shared module-level callee name: written as `scan_rows`, this
    file's own helper resolves across the tree onto `gate_common.scan_rows`, which wraps `subprocess.run`,
    and parity counts CWE-78 at the call site here. Imports are excluded because sharing `os`/`sys` means
    nothing; sharing a callee name with the module holding the subprocess wrapper does.
    """
    common = os.path.join(_ROOT, 'benchmark', 'gates', 'gate_common.py')
    if not os.path.isfile(common):
        fail('hygiene.gate_common_missing', common)
        return False, False
    clash = sorted(module_level_names(common) & module_level_names(os.path.abspath(__file__)))
    if clash:
        fail('hygiene.name_clash',
             'module-level name(s) shared with gate_common: %s -- parity resolves callees across the '
             'tree and gate_common holds a subprocess wrapper' % ', '.join(clash))
        return False, False
    print('  disjoint from gate_common callees, so this file adds no parity key: 0 clashes')
    return True, True


def peak_rss_mb():
    """Peak working set with no third-party dependency: K32GetProcessMemoryInfo, else rusage."""
    if os.name == 'nt':
        class _Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                        ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaNonPagedPoolUsage', ctypes.c_size_t), ('PagefileUsage', ctypes.c_size_t),
                        ('PeakPagefileUsage', ctypes.c_size_t)]

        counters = _Counters()
        counters.cb = ctypes.sizeof(_Counters)
        try:
            getter = ctypes.WinDLL('kernel32').K32GetProcessMemoryInfo
            getter.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Counters), wintypes.DWORD]
            getter.restype = wintypes.BOOL
            if getter(wintypes.HANDLE(-1).value, ctypes.byref(counters), counters.cb):
                return counters.PeakWorkingSetSize / 1048576.0
        except (AttributeError, OSError):
            return None
        return None
    try:
        import resource
    except ImportError:
        return None
    used = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return used / 1048576.0 if sys.platform == 'darwin' else used / 1024.0


def check_budget(work_seconds, rss_mb):
    boot = _BOOT - _START
    print('  gate work %.2fs (budget %.1fs), peak RSS %s (budget %.0f MB), %d scans of %d virtual modules'
          % (work_seconds, BUDGET_SECONDS, 'not measurable' if rss_mb is None else '%.1f MB' % rss_mb,
             BUDGET_RSS_MB, SCANS[0], SOURCE_COUNT))
    print('  process total %.2fs = %.2fs interpreter boot + engine import (not charged to this gate)'
          ' + %.2fs work' % (boot + work_seconds, boot, work_seconds))
    work_ok = work_seconds < BUDGET_SECONDS
    if not work_ok:
        fail('budget.work', '%.2fs of gate work >= %.1fs' % (work_seconds, BUDGET_SECONDS))
    rss_ok = rss_mb is None or rss_mb < BUDGET_RSS_MB
    if rss_mb is not None and not rss_ok:
        fail('budget.rss', 'peak RSS %.1f MB >= %.0f MB' % (rss_mb, BUDGET_RSS_MB))
    return work_ok, rss_ok


# --------------------------------------------------------------------------- entry points

def main() -> int:
    print('TIER 1 - the quiet invariants (0 rows, and a named guard must own each silence):')
    quiet_n, quiet_total = check_quiet()
    print('TIER 2 - the loud invariants, pinned by line and message:')
    loud_n, loud_total = check_loud()
    print('TIER 3 - right vocabulary, wrong provenance (fail-closed):')
    prov_n, prov_total = check_provenance()
    print('TIER 4 - the shipped tables and the wiring, read from ast_scanner.py:')
    law_n, law_total = check_law_source()
    print('TIER 5 - the structural regex verdict, both directions:')
    verdict_n, verdict_total = check_verdict_table()
    print('TIER 6 - falsification battery + collateral sweep:')
    caught_n, caught_total = check_battery()
    print('TIER 7 - parity hygiene (this file must add no key to the scanned tree):')
    hygiene_n, hygiene_total = check_hygiene()
    work = time.perf_counter() - _BOOT
    print('TIER 8 - cost:')
    work_ok, rss_ok = check_budget(work, peak_rss_mb())

    mandated = quiet_n + loud_n
    print('\nMANDATED INVARIANTS: %d/%d (%d quiet, %d loud)'
          % (mandated, quiet_total + loud_total, quiet_n, loud_n))
    for label, ok in [('%d/%d quiet' % (quiet_n, quiet_total), quiet_n == quiet_total),
                      ('%d/%d loud' % (loud_n, loud_total), loud_n == loud_total),
                      ('%d/%d provenance' % (prov_n, prov_total), prov_n == prov_total),
                      ('%d/%d source law' % (law_n, law_total), law_n == law_total),
                      ('%d/%d verdict rows' % (verdict_n, verdict_total), verdict_n == verdict_total),
                      ('%d/%d mutations CAUGHT + surgical' % (caught_n, caught_total),
                       caught_n == caught_total),
                      ('adds no parity key (callees disjoint)', hygiene_n == hygiene_total),
                      ('gate work < %.1fs' % BUDGET_SECONDS, work_ok),
                      ('peak RSS < %.0f MB' % BUDGET_RSS_MB, rss_ok)]:
        print('  %-38s %s' % (label, 'OK' if ok else 'FAILED'))
    if FAILURES:
        print('FAILURES (%d): %s' % (len(FAILURES), ', '.join(FAILURES[:12])))
        print('VERDICT: FAIL')
        return 1
    print('VERDICT: PASS - Sentry tier-2 precision pinned: %d/%d mandated invariants across CWE-338, '
          'CWE-209, CWE-328 and CWE-1333, %d fail-closed provenance rows held loud by receiver/operand/'
          'key/branch proof alone, %d source-law assertions, the structural regex verdict table held in '
          'both directions, and all %d weakenings CAUGHT with no row of any other CWE moving that was '
          'not declared, in %.2fs of gate work under %.0f MB.'
          % (mandated, quiet_total + loud_total, prov_total, law_total, caught_total,
             work, BUDGET_RSS_MB))
    return 0


if __name__ == '__main__':
    wanted = [arg.split('=', 1)[1] for arg in sys.argv[1:] if arg.startswith('--mutate=')]
    if wanted:
        unknown = [name for name in wanted if name not in MUTATIONS]
        if unknown:
            print('BAD MUTATION: %s is not one of %s' % (unknown, sorted(MUTATIONS)))
            raise SystemExit(2)
        raise SystemExit(min(run_falsification(name) for name in wanted))
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
