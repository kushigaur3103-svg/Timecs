"""Gate #63: the six SaltStack v3000.1 false-positive factories, each retired on its own proof.

What this gate is for
---------------------
A Salt v3000.1 scan produced six clusters of findings reported because a NAME or a SHAPE looked
dangerous, not because a VALUE was. Four are retired here against rows this gate re-measures on every
run (F1 three, F2 two, F3 two, F6 five -- twelve booked retirements); the fifth turns out to be retired
one layer earlier than the mandate assumed, so it ships as a second proof that books no row; and the
sixth is already retired by clauses the engine ships and three other gates seal -- which this gate pins,
so the difference stays on the record instead of in a commit message.

  F1  DISK HANDLES. `fp_.read()` after `fp_ = salt.utils.files.fopen(path, "r")` was CWE-400 because
      the receiver test substring-matches `NETWORK_INPUT_KEYWORDS` over every segment of the binding,
      and `salt.utils.files.fopen` contains the segment `files`. The handle is the program's own
      filesystem, not an unbounded external input. The new clause proves the BINDING: every write to
      that name up to the read must land on an opener leaf (`open`, `io.open`, `codecs.open`, `fopen`,
      `Path(...).open`), the root must not be an HTTP or socket module, and the name must not itself
      spell a network object. No binding record at all -- a parameter, a global, a socket -- and the
      exemption is refused, so `request.read()` and `sock.read()` are untouched.
  F2  INTERNAL DICTS. `return {"success": False, "error": str(exc)}` was CWE-209 in a plain SDK helper.
      CWE-209 is about a detail reaching a REPLY, so a bare dict literal now needs web context: a route
      decorator, a web-shaped parameter (`request`/`req`/`environ`/`handler`/`ws`/`websocket`/`response`
      /`resp`) or a web framework import. `jsonify(...)` and every other reply constructor keep their
      own clause because the value stops being a plain dict.
  F3  OPTIONAL PARAMETERS. `def connect(host, user, password="")` is how a caller says "I will use a
      key". An empty default ships no credential unless the function itself treats empty as a value: a
      comparison against `""`, an assignment of `""` to a credential name, or a dict literal that puts
      `""` under a credential key.
  F4  CONSTANT PATTERNS. A regex the source wrote out is not a ReDoS unless its shape backtracks. The
      emit layer already parses the pattern (`_is_redos_vulnerable_pattern` via `re._parser`); this task
      adds the missing REGISTRATION-layer proof -- `CWE_1333_RULE.safety_filter`, a linear grammar over
      the pattern text that refuses a nested quantifier, an ambiguous alternation or a backreference.
      Honest bookkeeping: F4 retires zero arena rows, because the emit layer had already silenced every
      safe constant literal before this task. What it buys is that `re.compile` can never again register
      as a resource-exhaustion sink on a pattern the source proves harmless, and that the two layers can
      only disagree toward loud. That is why F4's falsifier flips predicates, not scan rows.
  F5  NON-SECURITY RANDOM. The mandate asks for a security-context veto on `random.shuffle(hosts)` and
      `random.randint(1, 5)`. Neither row is booked here: with the two shipped clauses switched off the
      engine still reports nothing for those shapes, because no sink is registered for a draw the code
      does not hand back. A new context veto cannot be added on top either:
      `cwe338_two_factor_probe`, `cwe338_void_seed_return_probe` and `cwe338_prng_context_probe` seal
      plain-named draws LOUD on purpose -- 5 of the 7 blessed Big-8 CWE-338 keys sit inside a discarded
      `ast.Expr` statement, and the engine's law is that void-ness is read off the CALLEE, never off a
      context. So F5 ships no clause; it pins the two callee proofs that do the work
      (`f5_duration_clause`, `f5_worklist_clause`) and the rows that must stay loud (`random.choice(pool)`,
      `random.getrandbits`, a shuffle whose result is returned, a `randrange` bounded by a caller).
  F6  PATHS IN CONFIG DOCUMENTS. `private_key = /etc/salt/pki/minion.pem` cleared every statistical
      floor in `scanners/secret_scanner.py` -- a path is long, mixed-class and high-entropy by
      construction -- while naming a file instead of carrying a secret. The refusal lives inside
      `_is_literal_credential`, which only the generic-assignment branch consults, so PEM blocks, vendor
      token shapes and DB URLs cannot be silenced by it. `path_refusal_blind` brings exactly the five
      path rows back, and `generic_gate_dead` proves the separation the other way: switch the predicate
      off and exactly the four literal-credential rows go quiet, while every self-proving shape stays.

How to read the tiers
---------------------
TIER 0 pins the vocabularies, because a clause is only as narrow as the words it reads. TIER 1 is the
retirements and controls: a row's shipped verdict, and its verdict with the owning clause reverted. A
retirement whose arm-off column is still quiet is not booked -- some older clause owns it. TIER 2 calls
the shipped predicates directly on parsed ASTs, which is how the fail-closed answers (an unbound
receiver, a computed pattern, a value that is not a dict) get proven without inventing a finding for
them. TIER 3 reads the shipped source and asks it to keep the shape each proof depends on. TIER 4 is the
falsifiers: one weakening per clause, and a witness must move.

Usage: python benchmark/gates/high_signal_fp_reduction_probe.py [--dump] [--mutate=<name>]
"""
from __future__ import annotations

import ast
import contextlib
import inspect
import io as _io
import os
import sys
import time

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
import rule_engine  # noqa: E402
from scanners import secret_scanner  # noqa: E402

T = ast_scanner.TaintTracker
OWNERS = {'T': T, 'rule_engine': rule_engine, 'secret_scanner': secret_scanner}

# Wide on purpose: this laptop also runs the arena, and a load spike is not a defect.
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


def scan_rows(files, state='ship'):
    """(basename, line, cwe) for an in-memory tree, or for a config document.

    The state belongs in the key. Two scans of identical source differ in the clauses that are
    installed while they run, and a cache keyed on the source alone hands an armed scan the shipped
    answer -- which then reads as "this clause changes nothing" for every clause in the file.
    """
    key = ('scan', state, _cache_key(files))
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


def loud(rows, name, cwe, line):
    return (name, line, cwe) in rows


CASES = []


def case(pocket, label, files, cwe, name, line, expect, arm, arm_expect, note=''):
    """expect / arm_expect: 'loud' or 'quiet', before and after the pocket's own clause.

    A retirement whose arm_expect is 'quiet' is reported as NOT BOOKED: the shipped engine never made
    that row, and an older clause -- not this task -- is why it stays silent.
    """
    CASES.append({'pocket': pocket, 'label': label, 'files': files, 'cwe': cwe, 'name': name,
                  'line': line, 'expect': expect, 'arm': arm, 'arm_expect': arm_expect,
                  'note': note})


# --------------------------------------------------------------------------- F1: disk handles
_DISK_READ = module(
    'import codecs',
    'import io',
    'from pathlib import Path',
    '',
    'import requests',
    'import salt.utils.files',
    '',
    '',
    'def read_roster(path):',
    '    fp_ = salt.utils.files.fopen(path, "r")',
    '    return fp_.read()',
    '',
    '',
    'def read_with(path):',
    '    with salt.utils.files.fopen(path) as fh:',
    '        return fh.read()',
    '',
    '',
    'def read_jinja(path):',
    '    raw = salt.utils.files.fopen(path)',
    '    return raw.read()',
    '',
    '',
    'def read_pathlib(path):',
    '    handle = Path(path).open()',
    '    return handle.read()',
    '',
    '',
    'def read_stdio(path):',
    '    stream = io.open(path)',
    '    return stream.read()',
    '',
    '',
    'def read_decode(path):',
    '    text = codecs.open(path, "r", "utf-8")',
    '    return text.read()',
    '',
    '',
    'def read_request(request):',
    '    return request.read()',
    '',
    '',
    'def read_conn(path):',
    '    conn = salt.utils.files.fopen(path)',
    '    return conn.read()',
    '',
    '',
    'class LocalHandle:',
    '    def open(self, path):',
    '        self.files = salt.utils.files.fopen(path)',
    '',
    '    def read(self):',
    '        return self.files.read()',
    '',
    '',
    'def fetch_read(url):',
    '    resp = requests.get(url)',
    '    return resp.raw.read()')

_F1 = {'disk_read.py': _DISK_READ}
case('F1', 'salt_fopen_bound', _F1, 'CWE-400', 'disk_read.py', at(_DISK_READ, 'def read_roster', 2),
     'quiet', 'disk_arm', 'loud', 'the binding to fopen is what retires this read')
case('F1', 'salt_fopen_with_statement', _F1, 'CWE-400', 'disk_read.py',
     at(_DISK_READ, 'def read_with', 2), 'quiet', 'disk_arm', 'loud',
     'a `with ... as` binding is a binding, and the clause reads it as one')
case('F1', 'salt_fopen_alias', _F1, 'CWE-400', 'disk_read.py', at(_DISK_READ, 'def read_jinja', 2),
     'quiet', 'disk_arm', 'loud', 'the name spells `raw`, but the record behind it is an opener')
case('F1', 'pathlib_open', _F1, 'CWE-400', 'disk_read.py', at(_DISK_READ, 'def read_pathlib', 2),
     'quiet', 'disk_arm', 'quiet', 'no sink is registered for this spelling, so nothing is booked here')
case('F1', 'io_open', _F1, 'CWE-400', 'disk_read.py', at(_DISK_READ, 'def read_stdio', 2),
     'quiet', 'disk_arm', 'quiet')
case('F1', 'codecs_open', _F1, 'CWE-400', 'disk_read.py', at(_DISK_READ, 'def read_decode', 2),
     'quiet', 'disk_arm', 'quiet')
case('F1', 'request_stream', _F1, 'CWE-400', 'disk_read.py', at(_DISK_READ, 'def read_request', 1),
     'loud', 'disk_arm', 'loud', 'a parameter is not a binding the clause can read')
case('F1', 'network_named_fopen_handle', _F1, 'CWE-400', 'disk_read.py',
     at(_DISK_READ, 'def read_conn', 2), 'loud', 'disk_arm', 'loud',
     'the name spells a socket, so an opener binding does not excuse the read')
case('F1', 'attribute_bound_handle', _F1, 'CWE-400', 'disk_read.py',
     at(_DISK_READ, '        return self.files.read()'), 'loud', 'disk_arm', 'loud',
     'an attribute receiver never reaches the vocabulary test')
case('F1', 'requests_raw_read', _F1, 'CWE-400', 'disk_read.py', at(_DISK_READ, 'def fetch_read', 2),
     'loud', 'disk_arm', 'loud', 'the same leaf shape, bound to an HTTP call instead of an opener')

# --------------------------------------------------------------------------- F2: internal dicts
_DICT_REPLY = module(
    'from flask import jsonify',
    '',
    '',
    'def api_call(payload):',
    '    try:',
    '        return dispatch(payload)',
    '    except Exception as exc:',
    '        return {"success": False, "error": str(exc)}',
    '',
    '',
    'def view_dict(request):',
    '    try:',
    '        return dispatch(request)',
    '    except Exception as exc:',
    '        return {"error": str(exc)}',
    '',
    '',
    'class Handler:',
    '    def handle_request(self, req):',
    '        try:',
    '            return self.dispatch(req)',
    '        except Exception as exc:',
    '            return {"error": str(exc)}',
    '',
    '',
    'def view_json(request):',
    '    try:',
    '        return dispatch(request)',
    '    except Exception as exc:',
    '        return jsonify({"error": str(exc)})')

_F2 = {'client.py': _DICT_REPLY}
case('F2', 'sdk_helper_plain_dict', _F2, 'CWE-209', 'client.py', at(_DICT_REPLY, 'def api_call', 4),
     'loud', 'dict_arm', 'loud', 'the module imports flask, so this dict sits in web context after all')
case('F2', 'view_dict_with_request_argument', _F2, 'CWE-209', 'client.py',
     at(_DICT_REPLY, 'def view_dict', 4), 'loud', 'dict_arm', 'loud',
     'the same dict under a `request` parameter is a reply body')
case('F2', 'web_framework_import', _F2, 'CWE-209', 'client.py',
     at(_DICT_REPLY, 'class Handler', 5), 'loud', 'dict_arm', 'loud',
     'flask imported at module level is web context for the whole file')
case('F2', 'reply_constructor_stays_a_reply', _F2, 'CWE-209', 'client.py',
     at(_DICT_REPLY, 'def view_json', 4), 'quiet', 'dict_arm', 'quiet',
     'silent under the structured-error envelope clause, and this clause never reads it')

# The same three helpers with no web framework in the file: this is the shape the clause was written
# for, and the measurement says the pipeline never registers it -- the exemption and the row are
# mutually exclusive, because web context is what makes the row.
_SDK_REPLY = module(
    'def api_call(payload):',
    '    try:',
    '        return dispatch(payload)',
    '    except Exception as exc:',
    '        return {"success": False, "error": str(exc)}',
    '',
    '',
    'def local_cfg(path):',
    '    try:',
    '        return load(path)',
    '    except OSError as exc:',
    '        return {"ok": False, "reason": str(exc)}')

_F2_SDK = {'salt_sdk.py': _SDK_REPLY}
case('F2', 'sdk_without_any_web_context', _F2_SDK, 'CWE-209', 'salt_sdk.py',
     at(_SDK_REPLY, 'def api_call', 4), 'quiet', 'dict_arm', 'loud',
     'the only thing that made this dict a reply was web context, and there is none')
case('F2', 'helper_dict_without_web_context', _F2_SDK, 'CWE-209', 'salt_sdk.py',
     at(_SDK_REPLY, 'def local_cfg', 4), 'quiet', 'dict_arm', 'loud',
     'an OSError read by another Python process is logging noise, not a stack disclosure')

# --------------------------------------------------------------------------- F3: optional parameters
_PASSWORD_DEFAULT = module(
    'import ssl',
    '',
    '',
    'def tls_connect(host, user, password=""):',
    '    ctx = ssl.SSLContext()',
    '    ctx.set_password(password)',
    '    return ctx',
    '',
    '',
    'def optional_token(host, user, password=""):',
    '    ctx = ssl.SSLContext()',
    '    ctx.set_password(password)',
    '    return ctx',
    '',
    '',
    'def key_or_password(host, user, password=""):',
    '    if password == "":',
    '        return key_auth(host, user)',
    '    ctx = ssl.SSLContext()',
    '    ctx.set_password(password)',
    '    return ctx',
    '',
    '',
    'def blank_then_use(host, user, password=""):',
    '    password = ""',
    '    ctx = ssl.SSLContext()',
    '    ctx.set_password(password)',
    '    return ctx',
    '',
    '',
    'def shipped_default(host, user, password=""):',
    '    ctx = ssl.SSLContext()',
    '    ctx.set_password(password)',
    '    return {"host": host, "password": ""}')

_F3 = {'net.py': _PASSWORD_DEFAULT}
case('F3', 'key_auth_signature', _F3, 'CWE-521', 'net.py', at(_PASSWORD_DEFAULT, 'def tls_connect'),
     'quiet', 'password_blind_arm', 'loud', 'an empty default is how the caller says "use the key"')
case('F3', 'empty_default_stored_on_a_context', _F3, 'CWE-521', 'net.py',
     at(_PASSWORD_DEFAULT, 'def optional_token'), 'quiet', 'password_blind_arm', 'loud',
     'forwarding the default to set_password ships nothing')
case('F3', 'function_compares_empty', _F3, 'CWE-521', 'net.py',
     at(_PASSWORD_DEFAULT, 'def key_or_password'), 'loud', 'password_arm', 'quiet',
     'the function treats empty as the credential itself -- the proof is what reports it')
case('F3', 'function_assigns_empty', _F3, 'CWE-521', 'net.py', at(_PASSWORD_DEFAULT, 'def blank_then_use'),
     'loud', 'password_arm', 'quiet', 'a blank assignment to the credential name is a shipped credential')
case('F3', 'function_ships_empty_in_a_dict', _F3, 'CWE-521', 'net.py',
     at(_PASSWORD_DEFAULT, 'def shipped_default'), 'loud', 'password_arm', 'quiet',
     'empty under a credential key in a returned dict is the shipped config')

# --------------------------------------------------------------------------- F4: constant patterns
_REDOS = module(
    'import re',
    '',
    '',
    'WORDS = re.compile(r"\\b\\w+\\b")',
    'KEYVAL = re.compile(r"^\\s*([A-Za-z0-9_.-]+)\\s*:\\s*(.*?)\\s*$")',
    'URLISH = re.compile(pattern=r"(https?|ftp)://[^\\s/$.?#].[^\\s]*")',
    'NAMED = re.compile(r"(?P<key>[a-zA-Z0-9_:-]+)\\s*=\\s*(?P<value>.*)")',
    '',
    '',
    'EVIL = re.compile(r"(a+)+$")',
    'NESTED = re.compile(r"^(\\s+.*\\s*)+$")',
    'ALT = re.compile(r"([,.]+|;)+")',
    'COUNTED = re.compile(r"(a{2,})+")',
    'STAR_STAR = re.compile(r"(a*)*b")',
    '',
    '',
    'def build_pattern(request):',
    '    return re.compile(request.args.get("p", ""))')

_F4 = {'patterns.py': _REDOS}
for _label, _needle, _note in (
        ('safe_word_boundary', 'WORDS =', 'the emit layer refused this literal before this task too'),
        ('safe_keyval', 'KEYVAL =', ''),
        ('safe_url_keyword_form', 'URLISH =', 'the keyword= spelling is read by both layers'),
        ('safe_named_group', 'NAMED =', '')):
    case('F4', _label, _F4, 'CWE-1333', 'patterns.py', at(_REDOS, _needle), 'quiet',
         'regex_removed_arm', 'quiet', _note)
for _label, _needle in (('nested_quantifier', 'EVIL ='), ('whitespace_nested', 'NESTED ='),
                        ('alternation_quantified', 'ALT ='), ('counted_group_repeated', 'COUNTED ='),
                        ('star_star_b', 'STAR_STAR ='), ('tainted_pattern', '    return re.compile(')):
    case('F4', _label, _F4, 'CWE-1333', 'patterns.py', at(_REDOS, _needle), 'loud', 'regex_removed_arm', 'loud')

# --------------------------------------------------------------------------- F5: non-security random
_PRNG = module(
    'import random',
    'import time',
    '',
    '',
    'def sleep_jitter(attempt):',
    '    time.sleep(random.uniform(1, 5))',
    '',
    '',
    'def retry_delay(attempt):',
    '    return random.randint(1, 5) * attempt',
    '',
    '',
    'def spread_hosts(hosts):',
    '    random.shuffle(hosts)',
    '    for host in hosts:',
    '        dispatch(host)',
    '',
    '',
    'def shuffle_and_return(tokens):',
    '    random.shuffle(tokens)',
    '    return tokens',
    '',
    '',
    'def pick_endpoint(endpoints):',
    '    return random.choice(endpoints)',
    '',
    '',
    'def sample_nonces(count):',
    '    return [random.getrandbits(64) for _ in range(count)]',
    '',
    '',
    'def bounded_by_caller(low, high):',
    '    return random.randrange(low, high)')

_F5 = {'backoff.py': _PRNG}
case('F5', 'uniform_feeds_a_pause', _F5, 'CWE-338', 'backoff.py',
     at(_PRNG, '    time.sleep(random.uniform'), 'quiet', 'duration_arm', 'quiet',
     'the shipped duration clause owns this row, and it was retired before this task')
case('F5', 'randint_in_a_delay_frame', _F5, 'CWE-338', 'backoff.py',
     at(_PRNG, '    return random.randint(1, 5)'), 'quiet', 'duration_arm', 'quiet')
case('F5', 'shuffle_then_walked_by_the_same_loop', _F5, 'CWE-338', 'backoff.py',
     at(_PRNG, '    random.shuffle(hosts)'), 'quiet', 'worklist_arm', 'quiet',
     'a permutation the code then iterates mints nothing, and that clause is sealed elsewhere')
case('F5', 'shuffle_result_is_returned', _F5, 'CWE-338', 'backoff.py',
     at(_PRNG, '    random.shuffle(tokens)'), 'loud', 'worklist_arm', 'loud',
     'credential vocabulary, and the draw result is the value handed back')
case('F5', 'choice_mints_a_value', _F5, 'CWE-338', 'backoff.py',
     at(_PRNG, '    return random.choice(endpoints)'), 'loud', 'duration_arm', 'loud',
     'sealed loud by cwe338_void_seed_return_probe: void-ness is read off the callee')
case('F5', 'getrandbits_mints_a_value', _F5, 'CWE-338', 'backoff.py',
     at(_PRNG, 'random.getrandbits(64)'), 'loud', 'duration_arm', 'loud')
case('F5', 'caller_bounded_randrange', _F5, 'CWE-338', 'backoff.py',
     at(_PRNG, '    return random.randrange(low, high)'), 'loud', 'duration_arm', 'loud',
     'an unbounded space the caller negotiated, so no clause here may silence it')

# --------------------------------------------------------------------------- F6: paths in documents
_MINION_CFG = module(
    '# minion configuration shipped with the image',
    'private_key: /etc/salt/pki/minion/minion_master.pem',
    'api_key: ~/salt-workspace/credentials-2fA9kZ7Qm.json',
    'DB_PASSWORD: C:\\salt\\conf\\pki\\mine.pem',
    'SECRET_KEY: ./deploy/svc-account_9Kz2Lm4Q.yaml',
    'auth_token: ../runner/token_cache.crt',
    '',
    'private_key: zQ7xW2mL9pK4vTr8nB3sY6hJ',
    'api_key: 9Kz2Lm4QpX7vTr8nB3sY6hJw',
    'SECRET_KEY: s3cr3t-rotated-value-Xk9m2',
    'DB_PASSWORD: R0ckets-alt-9Kz2Lm4QpX7vTr8',
    '',
    'aws_access_key_id: AKIAR3VQUZBH7TKQWM2D',
    'github_token: ghp_Xk9mQzR7vT2wL4pN8sY6hJb3cD5fKg1xZa9m',
    'stripe_key: sk_live_51HbF3kQzR7vT2wL4pN8sY6hJb3cD5fKg',
    'slack_hook: https://hooks.slack.com/services/T0A1B2C3D/B0E1F2G3H/x1y2z3a4b5c6',
    'db_url: postgres://saltuser:R0ckets-alt-9Kz2@db.internal:5432/salt',
    'ssl_key: |',
    '    -----BEGIN RSA PRIVATE KEY-----',
    '    MIIBOgIBAAJBAKj34GkxFhD90vcNLYL6jZx0oT9dXcQ7kZ4vBhE2mTgNcR1pS6uY',
    '    -----END RSA PRIVATE KEY-----')

_F6 = {'minion.cfg': _MINION_CFG}
_F6_PATHS = (('unix_path_prefix', 'private_key: /etc/'), ('home_relative_json_path', 'api_key: ~/'),
             ('windows_drive_path', 'DB_PASSWORD: C:'), ('dot_slash_yaml_path', 'SECRET_KEY: ./deploy/'),
             ('parent_relative_cert_path', 'auth_token: ..'))
for _label, _needle in _F6_PATHS:
    case('F6', _label, _F6, 'CWE-798', 'minion.cfg', at(_MINION_CFG, _needle), 'quiet',
         'path_arm', 'loud', 'a path names a file; the value it points at never reaches the report')
_F6_LITERALS = (('literal_private_key', 'private_key: zQ7x'), ('literal_api_key', 'api_key: 9Kz2'),
                ('literal_secret_key', 'SECRET_KEY: s3cr3t'),
                ('literal_db_password', 'DB_PASSWORD: R0ckets-alt-9Kz2Lm4QpX7vTr8'))
for _label, _needle in _F6_LITERALS:
    case('F6', _label, _F6, 'CWE-798', 'minion.cfg', at(_MINION_CFG, _needle), 'loud', 'path_arm',
         'loud', 'the same name with a real value is still a credential')
_F6_SHAPES = (('aws_key_id_shape', 'aws_access_key_id:'), ('github_token_shape', 'github_token:'),
              ('stripe_live_key_shape', 'stripe_key:'), ('slack_webhook_shape', 'slack_hook:'),
              ('service_url_password', 'db_url:'), ('pem_block', '-----BEGIN RSA PRIVATE KEY-----'))
for _label, _needle in _F6_SHAPES:
    case('F6', _label, _F6, 'CWE-798', 'minion.cfg', at(_MINION_CFG, _needle), 'loud',
         'generic_gate_arm', 'loud', 'a self-proving shape, gated by no lexical rule')

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
    # An exemption is reverted two ways: the clause switched off (the FP comes back) and the clause
    # blinded (everything is excused, so a row that should stay loud goes quiet).
    'disk_arm': (('T', '_c400_receiver_is_disk_handle', _never),),
    'disk_arm_all': (('T', '_c400_receiver_is_disk_handle', _always),),
    'dict_arm': (('T', '_c209_plain_dict_reply_without_web_context', _never),),
    'dict_arm_all': (('T', '_c209_plain_dict_reply_without_web_context', _always),),
    'password_arm': (('T', '_c521_function_ships_the_credential', _never),),
    'password_blind_arm': (('T', '_c521_function_ships_the_credential', _always),),
    # F4's clause is the grammar: the emit layer that owns the scan rows reads `re._parser`, so the
    # receipts for this pocket live in TIER 2, where the predicate is called directly.
    'regex_removed_arm': (('rule_engine', '_cwe1333_pattern_is_ambiguous', _always_static),),
    'regex_blind_arm': (('rule_engine', '_cwe1333_pattern_is_ambiguous', _never_static),),
    'duration_arm': (('T', '_cwe338_draw_ships_a_duration', _never),),
    'worklist_arm': (('T', '_cwe338_shuffle_reorders_a_work_list', _never),),
    'path_arm': (('secret_scanner', '_is_literal_credential', _always_static),),
    'generic_gate_arm': (('secret_scanner', '_is_literal_credential', _never_static),),
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


def _cache_key(files):
    return tuple(sorted(files.items()))


def case_rows(entry, state='ship'):
    key = ('rows', state, _cache_key(entry['files']))
    if key not in _CACHE:
        _CACHE[key] = _apply(() if state == 'ship' else ARMS[state],
                             lambda: scan_rows(entry['files'], state))
    return _CACHE[key]


def probe_value(name, state='ship'):
    key = ('probe', state, name)
    if key not in _CACHE:
        try:
            _CACHE[key] = _apply(() if state == 'ship' else ARMS[state], PROBES[name][1])
        except Exception as error:
            _CACHE[key] = f'error: {type(error).__name__}: {error}'
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
            control = entry['expect'] == 'loud' and arm == 'loud'
            receipt = 'BOOKED' if booked else ('CONTROL' if control else 'not booked')
            print(f'  {now:5s} arm={arm:5s} {receipt:11s} {entry["label"]:34s} {entry["note"][:44]}')
            if now != entry['expect']:
                failures.append(f'{pocket}/{entry["label"]}: shipped {now}, want {entry["expect"]}')
            if arm != entry['arm_expect']:
                failures.append(f'{pocket}/{entry["label"]}: arm-off {arm}, want {entry["arm_expect"]}')
    return failures


# --------------------------------------------------------------------------- TIER 2 predicates
class _Record:
    """One entry in `assignments_by_scope`, which is a (scope, name) -> records index."""

    def __init__(self, value_node, lineno, scope_id):
        self.node = value_node
        self.value_node = value_node
        self.lineno = lineno
        self.scope_id = scope_id


def _tracker(files):
    with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files=dict(files), max_workers=1)
        tracker.analyze()
    return tracker


def _call(source, index=-1):
    calls = [node for node in ast.walk(link(ast.parse(source))) if isinstance(node, ast.Call)]
    return calls[index]


PROBES = {}


def probe(name, description):
    def register(function):
        PROBES[name] = (description, function)
        return function
    return register


@probe('f1_opener_binding', 'a name bound to salt.utils.files.fopen is a disk handle')
def _(tracker=_tracker(_F1)):
    scope = 'disk_read.py:function:read_roster'
    opener = _Record(_call('salt.utils.files.fopen(path, "r")'), 2, scope)
    tracker.assignments_by_scope = {(scope, 'fp_'): [opener]}
    return tracker._c400_receiver_is_disk_handle(_call('fp_.read()').func.value, scope, 3) is True


@probe('f1_second_write', 'a later write that is not an opener refuses the exemption')
def _(tracker=_tracker(_F1)):
    scope = 'disk_read.py:function:read_roster'
    opener = _Record(_call('salt.utils.files.fopen(path, "r")'), 2, scope)
    other = _Record(ast.parse('other').body[0].value, 3, scope)
    tracker.assignments_by_scope = {(scope, 'fp_'): [opener, other]}
    return tracker._c400_receiver_is_disk_handle(_call('fp_.read()').func.value, scope, 4) is False


@probe('f1_unbound_receiver', 'a receiver with no binding record is never exempt')
def _(tracker=_tracker(_F1)):
    scope = 'disk_read.py:function:read_roster'
    tracker.assignments_by_scope = {}
    return tracker._c400_receiver_is_disk_handle(_call('sock.read()').func.value, scope, 3) is False


@probe('f1_network_name', 'a name that spells a network object is not a disk handle')
def _(tracker=_tracker(_F1)):
    scope = 'disk_read.py:function:read_roster'
    opener = _Record(_call('salt.utils.files.fopen(path, "r")'), 2, scope)
    tracker.assignments_by_scope = {(scope, 'result'): [opener]}
    return tracker._c400_receiver_is_disk_handle(_call('result.read()').func.value, scope, 3) is False


@probe('f1_http_binding', 'a receiver bound to requests.get is not an opener')
def _(tracker=_tracker(_F1)):
    scope = 'disk_read.py:function:read_roster'
    tracker.assignments_by_scope = {
        (scope, 'fp_'): [_Record(_call('requests.get(url)'), 2, scope)]}
    return tracker._c400_receiver_is_disk_handle(_call('fp_.read()').func.value, scope, 3) is False


@probe('f2_plain_dict_without_web', 'a bare dict in a web-less helper is exempt')
def _(tracker=_tracker(_F2)):
    func = link(ast.parse('def api_call(payload):\n    return {"error": str(exc)}\n')).body[0]
    return tracker._c209_plain_dict_reply_without_web_context(func.body[0].value) is True


@probe('f2_request_argument', 'the same dict under a request parameter is not exempt')
def _(tracker=_tracker(_F2)):
    func = link(ast.parse('def view(request):\n    return {"error": str(exc)}\n')).body[0]
    return tracker._c209_plain_dict_reply_without_web_context(func.body[0].value) is False


@probe('f2_reply_constructor', 'a dict containing a reply constructor is not a plain dict')
def _(tracker=_tracker(_F2)):
    func = link(ast.parse('def api(payload):\n    return {"e": jsonify(str(exc))}\n')).body[0]
    return tracker._c209_plain_dict_reply_without_web_context(func.body[0].value) is False


@probe('f2_not_a_dict', 'a value that is not a dict is never this clause')
def _(tracker=_tracker(_F2)):
    func = link(ast.parse('def api(payload):\n    return str(exc)\n')).body[0]
    return tracker._c209_plain_dict_reply_without_web_context(func.body[0].value) is False


@probe('f2_flask_import', 'a web framework import in the module defeats the exemption')
def _(tracker=_tracker(_F2)):
    tree = link(ast.parse('import tornado\n\n\ndef api(payload):\n    return {"e": str(exc)}\n'))
    return tracker._c209_plain_dict_reply_without_web_context(tree.body[1].body[0].value) is False


def _password_function(source):
    return ast.parse(source).body[0]


@probe('f3_unused_default', 'an empty default the body ignores ships nothing')
def _(tracker=_tracker(_F3)):
    func = _password_function('def c(host, password=""):\n    return key_auth(host)\n')
    return tracker._c521_function_ships_the_credential(func, 'password') is False


@probe('f3_compare', 'comparing the parameter against empty ships a credential')
def _(tracker=_tracker(_F3)):
    func = _password_function('def c(host, password=""):\n    if password == "":\n        return 1\n')
    return tracker._c521_function_ships_the_credential(func, 'password') is True


@probe('f3_assignment', 'assigning empty to the credential name ships it')
def _(tracker=_tracker(_F3)):
    func = _password_function('def c(host, password=""):\n    password = ""\n    return 1\n')
    return tracker._c521_function_ships_the_credential(func, 'password') is True


@probe('f3_dict_literal', 'a dict literal that puts empty under a credential key ships it')
def _(tracker=_tracker(_F3)):
    func = _password_function('def c(host, password=""):\n    return {"password": ""}\n')
    return tracker._c521_function_ships_the_credential(func, 'password') is True


@probe('f3_hand_back', 'handing the caller value back is not shipping a credential')
def _(tracker=_tracker(_F3)):
    func = _password_function('def c(host, password=""):\n    return password\n')
    return tracker._c521_function_ships_the_credential(func, 'password') is False


@probe('f4_safe_literal_exempt', 'a constant linear pattern is exempt at registration')
def _():
    return rule_engine._cwe1333_safety_filter(_call(r're.compile(r"\b\w+\b")'), 're.compile') is True


@probe('f4_keyword_form_exempt', 'the pattern= spelling is read too')
def _():
    return rule_engine._cwe1333_safety_filter(
        _call('re.compile(pattern=r"(abc)+")'), 're.compile') is True


@probe('f4_evil_literal_loud', 'a constant nested quantifier is never exempt')
def _():
    return rule_engine._cwe1333_safety_filter(_call(r're.compile(r"(a+)+")'), 're.compile') is False


@probe('f4_ambiguous_alternation_loud', 'an ambiguous alternation is never exempt')
def _():
    return rule_engine._cwe1333_safety_filter(_call(r're.compile(r"([,.]+|;)+")'),
                                              're.compile') is False


@probe('f4_computed_pattern_loud', 'a pattern the source computes is never exempt')
def _():
    return rule_engine._cwe1333_safety_filter(_call('re.compile(name)'), 're.compile') is False


@probe('f4_fstring_loud', 'an f-string is not a compile-time constant here')
def _():
    return rule_engine._cwe1333_safety_filter(_call('re.compile(f"{a}b")'), 're.compile') is False


@probe('f4_other_sink_untouched', 'a non-regex sink never sees this filter')
def _():
    return rule_engine._cwe1333_safety_filter(_call('zipfile.ZipFile("/tmp/x")'),
                                              'zipfile.ZipFile') is False


@probe('f4_registered_safe_sink_exempt', 'check_sink_safety exempts a safe constant re.compile')
def _(tracker=_tracker(_F4)):
    node = _call(r're.compile(r"\b\w+\b")')
    return tracker.check_sink_safety(node, 're.compile', 'patterns.py:global') is True


def _draw(source, leaf):
    """The draw call inside a fully parent-linked module, as the shipped clause sees it."""
    tree = link(ast.parse(source))
    return next(node for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == leaf)


@probe('f5_duration_clause', 'a draw that is only a timedelta magnitude is a duration')
def _(tracker=_tracker(_F5)):
    pause = tracker._cwe338_draw_ships_a_duration(_draw(
        'import random\nfrom datetime import timedelta\n\n\ndef f():\n'
        '    return timedelta(random.uniform(0, 60))\n', 'uniform'))
    keyed = tracker._cwe338_draw_ships_a_duration(_draw(
        'import random\nfrom datetime import timedelta\n\n\ndef f():\n'
        '    return timedelta(seconds=random.uniform(0, 60))\n', 'uniform'))
    named = tracker._cwe338_draw_ships_a_duration(_draw(
        'import random\nfrom datetime import timedelta\n\n\ndef f():\n'
        '    salt_window = timedelta(random.uniform(0, 60))\n    return salt_window\n', 'uniform'))
    return pause is True and keyed is False and named is False


@probe('f5_choice_not_a_duration', 'a draw that returns a value is not a pause')
def _(tracker=_tracker(_F5)):
    return tracker._cwe338_draw_ships_a_duration(_call('random.choice(endpoints)')) is False


@probe('f5_worklist_clause', 'a permutation the code then iterates mints nothing')
def _(tracker=_tracker(_F5)):
    yes = tracker._cwe338_shuffle_reorders_a_work_list(_draw(
        'import random\n\n\ndef spread(hosts):\n    random.shuffle(hosts)\n'
        '    for host in hosts:\n        dispatch(host)\n', 'shuffle'))
    returned = tracker._cwe338_shuffle_reorders_a_work_list(_draw(
        'import random\n\n\ndef spread(tokens):\n    random.shuffle(tokens)\n    return tokens\n',
        'shuffle'))
    return yes is True and returned is False


@probe('f6_path_refused', 'a filesystem path is not a literal credential')
def _():
    return all(secret_scanner._is_literal_credential(value) is False for value in (
        '/etc/salt/pki/minion/minion_master.pem', '~/salt/credentials-2fA9kZ7Qm.json',
        './deploy/svc-account_9Kz2Lm4Q.yaml', '../runner/token_cache.crt',
        'C:\\salt\\conf\\pki\\mine.pem'))


@probe('f6_literal_still_credential', 'a random literal under the same name still is one')
def _():
    return all(secret_scanner._is_literal_credential(value) for value in (
        'zQ7xW2mL9pK4vTr8nB3sY6hJ', 's3cr3t-rotated-value-Xk9m2', 'R0ckets-alt-9Kz2Lm4QpX7vTr8'))


@probe('f6_paths_cleared_the_old_floors', 'the path rows were FP for the statistical floors, not shape')
def _():
    return all(len(value) >= secret_scanner.MIN_GENERIC_LENGTH
               and secret_scanner._character_classes(value) >= 2
               and secret_scanner.shannon_entropy(value) >= secret_scanner.MIN_GENERIC_ENTROPY
               for value in ('/etc/salt/pki/minion/minion_master.pem',
                             '~/salt/credentials-2fA9kZ7Qm.json',
                             'C:\\salt\\conf\\pki\\mine.pem',
                             './deploy/svc-account_9Kz2Lm4Q.yaml',
                             '../runner/token_cache.crt'))


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
        print(f'  {"OK  " if ok else "FAIL"} {name:34s} {description}')
        if not ok:
            failures.append(f'predicate {name}: {description}')
    return failures


# --------------------------------------------------------------------------- TIER 3 source laws
LAWS = (
    ('F1 the exemption needs a binding record, and answers seen > 0',
     lambda: 'seen > 0' in inspect.getsource(T._c400_receiver_is_disk_handle)),
    ('F1 any write that is not an opener returns False',
     lambda: 'return False' in inspect.getsource(T._c400_receiver_is_disk_handle)),
    ('F1 the opener leaves are read off the last written segment, not a module whitelist',
     lambda: 'rsplit(".", 1)[-1]' in inspect.getsource(T._c400_value_is_local_opener)),
    ('F2 a reply constructor inside the value defeats the clause',
     lambda: 'RESPONSE_CONSTRUCTOR_NAMES' in inspect.getsource(
         T._c209_plain_dict_reply_without_web_context)),
    ('F2 a route decorator defeats the clause',
     lambda: '_c209_route_decorated' in inspect.getsource(T._c209_plain_dict_reply_without_web_context)),
    ('F4 the filter checks its own sink before anything else',
     lambda: (lambda src: src.index('_cwe1333_sink_matcher') < src.index('pattern = next(')
              and 'return False' in src[src.index('_cwe1333_sink_matcher'):src.index('pattern = next(')])(
         inspect.getsource(rule_engine._cwe1333_safety_filter))),
    ('F4 only a string constant is read',
     lambda: 'isinstance(pattern.value, str)' in inspect.getsource(
         rule_engine._cwe1333_safety_filter)),
    ('F4 a backreference is ambiguous',
     lambda: 'isdigit' in inspect.getsource(rule_engine._cwe1333_pattern_is_ambiguous)),
    ('F4 the rule registry carries the filter',
     lambda: rule_engine.CWE_1333_RULE.safety_filter is rule_engine._cwe1333_safety_filter),
    ('F5 no new context veto was added to the PRNG branch',
     lambda: not hasattr(T, '_c338_draw_is_plain_utility')),
    ('F6 the path rule lives in the generic gate only',
     lambda: 'CREDENTIAL_PATH_PREFIXES' in inspect.getsource(secret_scanner._is_literal_credential)),
    ('F6 exactly one branch calls the lexical gate',
     lambda: len([line for line in inspect.getsource(secret_scanner._iter_hits).splitlines()
                  if '_is_literal_credential' in line]) == 1),
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
    'disk_handle_removed': (
        'F1: the clause is switched off, so an opener-bound handle is an untrusted stream again',
        'disk_arm',
        ['salt_fopen_alias', 'salt_fopen_bound', 'salt_fopen_with_statement'],
        ['f1_opener_binding']),
    'disk_handle_blind': (
        'F1: everything is a disk handle, so HTTP and attribute-bound reads lose their row too',
        'disk_arm_all',
        ['attribute_bound_handle', 'network_named_fopen_handle', 'request_stream', 'requests_raw_read'],
        ['f1_http_binding', 'f1_network_name', 'f1_second_write', 'f1_unbound_receiver']),
    'dict_clause_removed': (
        'F2: the clause is switched off, so the non-web SDK dict is reported as a client reply',
        'dict_arm',
        ['helper_dict_without_web_context', 'sdk_without_any_web_context'],
        ['f2_plain_dict_without_web']),
    'dict_clause_blind': (
        'F2: every dict is treated as non-web, so the views that really are replies go quiet',
        'dict_arm_all',
        ['sdk_helper_plain_dict', 'view_dict_with_request_argument', 'web_framework_import'],
        ['f2_flask_import', 'f2_not_a_dict', 'f2_reply_constructor', 'f2_request_argument']),
    'password_blind': (
        'F3: any empty default at all counts as shipping a credential',
        'password_blind_arm',
        ['empty_default_stored_on_a_context', 'key_auth_signature'],
        ['f3_hand_back', 'f3_unused_default']),
    'password_dead': (
        'F3: the proof is switched off, and the three shapes it was reporting go quiet with it',
        'password_arm',
        ['function_assigns_empty', 'function_compares_empty', 'function_ships_empty_in_a_dict'],
        ['f3_assignment', 'f3_compare', 'f3_dict_literal']),
    'regex_grammar_blind': (
        'F4: the grammar calls every constant pattern linear',
        'regex_blind_arm',
        [],
        ['f4_ambiguous_alternation_loud', 'f4_evil_literal_loud']),
    'regex_clause_removed': (
        'F4: the grammar calls every constant pattern ambiguous, so it exempts nothing',
        'regex_removed_arm',
        [],
        ['f4_keyword_form_exempt', 'f4_registered_safe_sink_exempt', 'f4_safe_literal_exempt']),
    'duration_blind': (
        'F5: a draw that feeds a duration stops being recognised as one',
        'duration_arm',
        [],
        ['f5_duration_clause']),
    'worklist_blind': (
        'F5: a permutation the code then iterates stops being recognised',
        'worklist_arm',
        [],
        ['f5_worklist_clause']),
    'path_refusal_blind': (
        'F6: a filesystem path counts as a literal credential like any other value',
        'path_arm',
        ['dot_slash_yaml_path', 'home_relative_json_path', 'parent_relative_cert_path',
         'unix_path_prefix', 'windows_drive_path'],
        ['f6_path_refused']),
    'generic_gate_dead': (
        'F6: the lexical gate is switched off, which reaches the generic branch and nothing else',
        'generic_gate_arm',
        ['literal_api_key', 'literal_db_password', 'literal_private_key', 'literal_secret_key'],
        ['f6_literal_still_credential']),
}


def run_mutation(name):
    """Weaken one clause and report every row and predicate that moved.

    The baseline is read BEFORE the weakening is installed. Reading it afterwards compares the mutated
    gate with itself and reports every mutation as MISSED. `moved` is the full set of changes rather
    than a filtered one, so a clause that reaches into somebody else's pocket shows up as an extra
    label instead of passing unnoticed.
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
        print(f'  {"CAUGHT" if ok else "MISSED"} {name:24s} rows={moved} probes={flipped} '
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


def main():
    argv = sys.argv[1:]
    only = next((a.split('=', 1)[1] for a in argv if a.startswith('--mutate=')), None)
    if only and only not in MUTATIONS:
        print(f'unknown mutation {only}; known: {sorted(MUTATIONS)}')
        return 2
    if '--dump' in argv:
        dump()
        return 0
    started = time.perf_counter()
    failures = []
    if not only:
        failures += check_retirements()
        failures += check_predicates()
        failures += check_laws()
    failures += check_mutations(only)
    work = time.perf_counter() - started
    peak = rss_mb()
    total = len(CASES)
    booked = sum(1 for entry in CASES if entry['expect'] == 'quiet' and entry['arm_expect'] == 'loud')
    loud_cases = sum(1 for entry in CASES if entry['expect'] == 'loud')
    print(f'\ncases={total} booked_retirements={booked} expected_loud={loud_cases} '
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
