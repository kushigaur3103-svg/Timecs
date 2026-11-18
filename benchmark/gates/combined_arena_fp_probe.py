"""Gate #64 -- the five Airflow/Saltstack FP factories, each one held by its own falsifier.

What this task moved, measured against the commit it replaces rather than asserted:

  G1  CWE-601 INTERNAL `url_for`. The mandate expected 60+ Airflow rows on
      `redirect(url_for('Airflow.index'))`. Scanning the two named files says otherwise:
      `airflow/www/views.py` (26 rows) and `airflow/www_rbac/views.py` (42 rows) contain no such row,
      and both counts are identical before and after this change -- all seven corpus
      `redirect(url_for(...))` lines were already silent, and the 68 rows are `redirect(origin)` behind
      `get_safe_url(...)`, `redirect(request.referrer)` and `redirect(self.get_redirect())`, every one
      of which the mandate itself pins LOUD. They are silent because a fully literal redirect target is
      retired one clause earlier, by the dynamism gate, which is why `menu_redirect`,
      `external_redirect` and `named_endpoint_redirect` stay quiet under every arm. What was wrong sat
      on the other side: the shipped exemption excused *any* `url_for` call, so a redirect whose
      endpoint or query the client supplied reported nothing at its own line. The clause now has to
      earn the exemption twice -- a literal endpoint and no client data anywhere in the call -- so
      `reschedule_redirect` books the retirement (quiet shipped, loud with the exemption off) and
      `client_named_redirect`, `client_query_redirect` and `inline_client_endpoint_redirect` book the
      three false negatives it closes (loud shipped, quiet with the exemption blinded).
  G2  CWE-1333 AT THE EMIT LAYER. Already shipped: the emit pass resolves the pattern, refuses anything
      it cannot resolve to a string, and calls the structural verdict, so a linear constant compiles
      quiet while `^(a+)+$`, `(a|aa)+`, `(x+x+)+y` and a request-supplied pattern all stay loud. The
      verdict is asked for the `re.match`/`findall`/`sub` calls too, which is what books their safe rows
      here. One mandated condition is empty in practice: the shipped verdict never called a
      backreference pattern catastrophic -- `^(a)\1+$` and `^(a+)\1+$` both answer False -- so a
      backreference has nothing to be excused from, and `safe_backreference` is booked by blinding the
      verdict rather than by a name veto. Nothing new was written in this pocket.
  G3  CWE-400 DISK HANDLES. `_C400_LOCAL_OPENER_LEAVES` only knew `open`/`fopen`, so Salt's
      `salt.utils.files.flopen`, `safe_open` and `atomic_open` left `fh.read()` reported. Three rows,
      booked, and the network answers are controls: `urlopen(...).read()`, `resp.read()` after
      `requests.get`, `sock.makefile().read()`. The mandate's fourth loud shape, `self._content.read()`,
      emits no CWE-400 row in either state: an attribute receiver is not read as a stream by this
      emitter at all, so the widening neither creates it nor retires it -- it is kept as a case, not as
      a claim.
  G4  CWE-521 LOOKUP FALLBACK. `config.get("password", "")` was already excused when the mapping is a
      parameter or `self.x`, but Salt reads its loader-injected `__opts__`, which is neither, so
      `__opts__.get("passwd", "")` reported an empty default the module never shipped. The clause now
      asks whether this module writes that name in the first place, looked up per file rather than per
      scope, because the read is reported at module scope while a test's own `__opts__ = {...}` sits
      inside the function around it -- and a file that does write the name keeps reporting.
      `password = ""`, `{"password": ""}` and `if password == ""` are untouched controls, and
      `os.getenv("PASSWORD", "")` stays retired by the older lookup clause, not by this one.
  G5  TEST/DEFAULT CONFIG DOCUMENTS. The three cited Airflow rows -- `default_test.cfg:95,96`,
      `default_airflow.cfg:547,555`, `config.yml:1134,1146` -- are all the same value,
      `sqla+mysql://airflow:airflow@localhost:3306/airflow`, and all three are the service-URL rule
      rather than the generic-assignment rule the mandate described. Two of the three file names are
      not in the mandated test/default list either, so the deciding proof had to be the value: the
      password IS the username and the host is this machine, which is what a worked example looks like
      and not what a deployed credential looks like. The mandated placeholder tokens and the mandated
      document names ship as ordered -- the name rule reaching only the generic branch, where a key
      name is the only thing doing the identifying.

TIER 1 reads every case twice against one shared in-memory tree: a row's shipped verdict, and its
verdict with the owning clause reverted. A retirement whose arm-off column is still quiet is not booked
-- some older clause owns it. TIER 2 calls the shipped predicates directly. TIER 3 reads the shipped
source and asks it to keep the shape each proof depends on. TIER 4 is the falsifiers: one weakening per
clause, and a witness must move.

Usage: python benchmark/gates/combined_arena_fp_probe.py [--dump] [--mutate=<name>]
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
from scanners import secret_scanner  # noqa: E402

T = ast_scanner.TaintTracker
OWNERS = {'T': T, 'ast_scanner': ast_scanner, 'secret_scanner': secret_scanner}

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

    The state belongs in the key: two scans of identical source differ in the clauses installed while
    they run, and a cache keyed on the source alone hands an armed scan the shipped answer -- which
    then reads as "this clause changes nothing" for every clause in the file.
    """
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


def loud(rows, name, cwe, line):
    return (name, line, cwe) in rows


CASES = []


def case(pocket, label, files, cwe, name, line, expect, arm, arm_expect, note=''):
    """expect / arm_expect: 'loud' or 'quiet', before and after the pocket's own clause."""
    CASES.append({'pocket': pocket, 'label': label, 'files': files, 'cwe': cwe, 'name': name,
                  'line': line, 'expect': expect, 'arm': arm, 'arm_expect': arm_expect,
                  'note': note})


# --------------------------------------------------------------------------- G1: internal url_for
_URLFOR = module(
    'from flask import redirect, url_for, request',
    '',
    'def menu_redirect():',
    "    return redirect(url_for('Airflow.index'))",
    '',
    'def reschedule_redirect(task_id):',
    "    return redirect(url_for('TaskReschedule', id=task_id))",
    '',
    'def external_redirect():',
    "    return redirect(url_for('Airflow.index', _external=True))",
    '',
    'def named_endpoint_redirect():',
    "    return redirect(url_for('Airflow.index', token='literal'))",
    '',
    'def client_named_redirect():',
    "    endpoint = request.args['page']",
    '    return redirect(url_for(endpoint))',
    '',
    'def client_query_redirect():',
    "    nxt = request.args['next']",
    "    return redirect(url_for('Airflow.index', next=nxt))",
    '',
    'def inline_client_endpoint_redirect():',
    "    return redirect(url_for(request.values['page']))",
    '',
    'def referrer_redirect():',
    '    return redirect(request.referrer)',
    '',
    'def next_param_redirect():',
    "    return redirect(request.args.get('next'))",
    '',
    'def form_origin_redirect():',
    '    origin = get_safe_url(request.form.get("origin"))',
    '    return redirect(origin)',
    '',
)
_URLFOR_STATIC = ['menu_redirect', 'external_redirect', 'named_endpoint_redirect']
for _needle in _URLFOR_STATIC:
    case('G1', _needle, {'urlfor_views.py': _URLFOR}, 'CWE-601', 'urlfor_views.py',
         at(_URLFOR, f'def {_needle}(', 1), 'quiet', 'urlfor_blind_arm', 'quiet',
         'a fully literal target is retired by the dynamism gate, before any url_for clause')
case('G1', 'reschedule_redirect', {'urlfor_views.py': _URLFOR}, 'CWE-601', 'urlfor_views.py',
     at(_URLFOR, 'def reschedule_redirect(', 1), 'quiet', 'urlfor_off_arm', 'loud',
     'a route argument this application owns, not one the client filled in')
_URLFOR_CLIENT = ['client_named_redirect', 'client_query_redirect']
for _needle in _URLFOR_CLIENT:
    case('G1', _needle, {'urlfor_views.py': _URLFOR}, 'CWE-601', 'urlfor_views.py',
         at(_URLFOR, f'def {_needle}(', 2), 'loud', 'urlfor_blind_arm', 'quiet',
         'HEAD excused every url_for, so the client chose the destination')
case('G1', 'inline_client_endpoint_redirect', {'urlfor_views.py': _URLFOR}, 'CWE-601',
     'urlfor_views.py', at(_URLFOR, 'def inline_client_endpoint_redirect(', 1), 'loud',
     'urlfor_blind_arm', 'quiet', 'url_for(request.values[...]) picks the path')
for _needle, _offset, _note in [('referrer_redirect', 1, 'the request referrer is client data'),
                               ('next_param_redirect', 1, 'request.args.get(next)'),
                               ('form_origin_redirect', 2, 'get_safe_url is not this engines sanitizer')]:
    case('G1', _needle, {'urlfor_views.py': _URLFOR}, 'CWE-601', 'urlfor_views.py',
         at(_URLFOR, f'def {_needle}(', _offset), 'loud', 'urlfor_off_arm', 'loud', _note)

# --------------------------------------------------------------------------- G2: emit-layer regex
_REGEX = module(
    'import re',
    'from flask import request',
    '',
    'SEGMENT = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")',
    '',
    'VERSION = re.compile(r"^(a+)+$")',
    '',
    'BACKREF = re.compile(r"^(a)\\1+$")',
    '',
    'def match_grain(text):',
    '    return re.match(r"^\\d{4}\\.\\d+$", text)',
    '',
    'def find_versions(text):',
    '    return re.findall(r"[0-9]+\\.[0-9]+", text)',
    '',
    'def normalise(text):',
    '    return re.sub(r"\\s+", " ", text)',
    '',
    'def nested_quantifier(text):',
    '    return re.match(r"^(a+)+$", text)',
    '',
    'def overlapping_alternation(text):',
    '    return re.match(r"^(a|aa)+$", text)',
    '',
    'def adjacent_quantifiers(text):',
    '    return re.sub(r"(x+x+)+y", "", text)',
    '',
    'def client_pattern():',
    '    return re.compile(request.args["pattern"])',
    '',
    'def unprovable_pattern(text, pat):',
    '    return re.split(pat, text)',
    '',
)
case('G2', 'safe_segment', {'regex_grains.py': _REGEX}, 'CWE-1333', 'regex_grains.py',
     at(_REGEX, 'SEGMENT = '), 'quiet', 'redos_blind_arm', 'loud',
     'a linear constant is not a ReDoS')
case('G2', 'safe_backreference', {'regex_grains.py': _REGEX}, 'CWE-1333', 'regex_grains.py',
     at(_REGEX, 'BACKREF = '), 'quiet', 'redos_blind_arm', 'loud',
     'the shipped verdict calls no backreference pattern catastrophic, so nothing excuses it here')
case('G2', 'evil_compile', {'regex_grains.py': _REGEX}, 'CWE-1333', 'regex_grains.py',
     at(_REGEX, 'VERSION = '), 'loud', 'redos_blind_arm', 'loud', 'a catastrophic constant keeps its row')
for _needle in ['match_grain', 'find_versions', 'normalise']:
    case('G2', f'safe_{_needle}', {'regex_grains.py': _REGEX}, 'CWE-1333', 'regex_grains.py',
         at(_REGEX, f'def {_needle}(', 1), 'quiet', 'redos_blind_arm', 'loud',
         'a match/search/sub call is judged by the same verdict, not by the name of the call')
for _needle in ['nested_quantifier', 'overlapping_alternation', 'adjacent_quantifiers', 'client_pattern']:
    case('G2', _needle, {'regex_grains.py': _REGEX}, 'CWE-1333', 'regex_grains.py',
         at(_REGEX, f'def {_needle}(', 1), 'loud', 'redos_blind_arm', 'loud',
         'the structural verdict owns this row, not a name veto')
case('G2', 'unprovable_pattern', {'regex_grains.py': _REGEX}, 'CWE-1333', 'regex_grains.py',
     at(_REGEX, 'def unprovable_pattern(', 1), 'quiet', 'redos_blind_arm', 'quiet',
     'a pattern the emitter cannot resolve gets no verdict either way')

# --------------------------------------------------------------------------- G3: disk handle reads
_HANDLES = module(
    'import salt.utils.files as saltfiles',
    'import requests',
    'import socket',
    '',
    'def read_lock(path):',
    '    fh = saltfiles.flopen(path, "r")',
    '    return fh.read()',
    '',
    'def read_checked(path):',
    '    fh = saltfiles.safe_open(path, "r")',
    '    return fh.read()',
    '',
    'def read_atomic(path):',
    '    fh = saltfiles.atomic_open(path, "w")',
    '    return fh.read()',
    '',
    'def read_plain(path):',
    '    fp_ = saltfiles.fopen(path)',
    '    return fp_.read()',
    '',
    'def read_urlopen(url):',
    '    fh = urllib.request.urlopen(url)',
    '    return fh.read()',
    '',
    'def read_response(url):',
    '    resp = requests.get(url)',
    '    return resp.read()',
    '',
    'def read_socket(host, port):',
    '    sock = socket.socket()',
    '    fh = sock.makefile()',
    '    return fh.read()',
    '',
    'def read_attribute(body):',
    '    body.content = 1',
    '    return body.content.read()',
    '',
    'class Response:',
    '    def __init__(self, url):',
    '        self._content = requests.get(url).content',
    '',
    '    def take(self):',
    '        return self._content.read()',
    '',
)
for _needle in ['read_lock', 'read_checked', 'read_atomic']:
    case('G3', _needle, {'handles_grains.py': _HANDLES}, 'CWE-400', 'handles_grains.py',
         at(_HANDLES, f'def {_needle}(', 2), 'quiet', 'opener_narrow_arm', 'loud',
         'a sibling of fopen opens a file this program chose')
case('G3', 'read_plain', {'handles_grains.py': _HANDLES}, 'CWE-400', 'handles_grains.py',
     at(_HANDLES, 'def read_plain(', 2), 'quiet', 'opener_narrow_arm', 'quiet',
     'fopen was already in the set -- the older clause owns this row')
for _needle, _offset, _note in [
        ('read_urlopen', 2, 'the root blacklist keeps a URL open loud'),
        ('read_response', 2, 'requests.get names the receiver network-shaped'),
        ('read_socket', 3, 'makefile derives a stream, it does not open a path')]:
    case('G3', _needle, {'handles_grains.py': _HANDLES}, 'CWE-400', 'handles_grains.py',
         at(_HANDLES, f'def {_needle}(', _offset), 'loud', 'opener_off_arm', 'loud', _note)
for _needle, _offset, _note in [
        ('read_attribute', 2, 'an attribute receiver is never emitted as a CWE-400 read, in either state'),
        ('take', 1, 'the same for self._content: no row exists for this clause to retire')]:
    case('G3', _needle, {'handles_grains.py': _HANDLES}, 'CWE-400', 'handles_grains.py',
         at(_HANDLES, f'def {_needle}(', _offset), 'quiet', 'opener_off_arm', 'quiet', _note)

# --------------------------------------------------------------------------- G4: lookup fallbacks
# Three documents, because the clause asks a module-level question: a file that writes `__opts__`
# cannot be scored in the same tree as a file that never does.
_OPTS_CLEAN = module(
    'def minion_fallback():',
    '    return __opts__.get("passwd", "")',
    '',
)
_OPTS_WRITTEN = module(
    'def shipped_table_fallback():',
    '    __opts__ = {"passwd": "shipped-default"}',
    '    return __opts__.get("passwd", "")',
    '',
)
_LOOKUP = module(
    'import os',
    'import ssl',
    '',
    'def param_fallback(config):',
    '    return config.get("password", "")',
    '',
    'def self_fallback(self):',
    '    return self._context.get("password", "")',
    '',
    'def object_fallback(config):',
    '    return config.settings.get("password", "")',
    '',
    'def env_fallback():',
    '    return os.getenv("PASSWORD", "")',
    '',
    'def blank_then_use(host, user, password=""):',
    '    password = ""',
    '    ctx = ssl.SSLContext()',
    '    ctx.set_password(password)',
    '    return ctx',
    '',
    'def compares_empty(host, user, password=""):',
    '    if password == "":',
    '        return key_auth(host, user)',
    '    ctx = ssl.SSLContext()',
    '    ctx.set_password(password)',
    '    return ctx',
    '',
    'def ships_blank_dict(host, user, password=""):',
    '    ctx = ssl.SSLContext()',
    '    ctx.set_password(password)',
    '    return {"host": host, "password": ""}',
    '',
)
case('G4', 'minion_fallback', {'lookup_opts_clean.py': _OPTS_CLEAN}, 'CWE-521',
     'lookup_opts_clean.py', at(_OPTS_CLEAN, 'def minion_fallback(', 1), 'quiet',
     'lookup_off_arm', 'loud', 'the loader injects __opts__; this module never writes it')
case('G4', 'written_opts_fallback', {'lookup_opts_written.py': _OPTS_WRITTEN}, 'CWE-521',
     'lookup_opts_written.py', at(_OPTS_WRITTEN, 'def shipped_table_fallback(', 2), 'loud',
     'lookup_blind_arm', 'quiet', 'a module that writes the name ships that empty default itself')
for _needle, _note in [('param_fallback', 'the caller fills the mapping in'),
                       ('self_fallback', 'an attribute of the object, populated elsewhere')]:
    case('G4', _needle, {'lookup_config.py': _LOOKUP}, 'CWE-521', 'lookup_config.py',
         at(_LOOKUP, f'def {_needle}(', 1), 'quiet', 'lookup_off_arm', 'loud', _note)
case('G4', 'object_fallback', {'lookup_config.py': _LOOKUP}, 'CWE-521', 'lookup_config.py',
     at(_LOOKUP, 'def object_fallback(', 1), 'loud', 'lookup_off_arm', 'loud',
     'a mapping this scope cannot account for is not proven to be someone elses')
case('G4', 'env_fallback', {'lookup_config.py': _LOOKUP}, 'CWE-521', 'lookup_config.py',
     at(_LOOKUP, 'def env_fallback(', 1), 'quiet', 'lookup_off_arm', 'quiet',
     'an environment read is retired by the older lookup clause, not by this one')
for _needle, _offset, _note in [
        ('blank_then_use', 1, 'an empty assignment to the credential name is a shipped credential'),
        ('compares_empty', 0, 'a function that treats empty as the credential')]:
    case('G4', _needle, {'lookup_config.py': _LOOKUP}, 'CWE-521', 'lookup_config.py',
         at(_LOOKUP, f'def {_needle}(', _offset), 'loud', 'lookup_blind_arm', 'loud', _note)
case('G4', 'ships_blank_dict', {'lookup_config.py': _LOOKUP}, 'CWE-521', 'lookup_config.py',
     at(_LOOKUP, 'def ships_blank_dict(', 0), 'loud', 'lookup_blind_arm', 'loud',
     'a dict literal carrying the credential')

# --------------------------------------------------------------------------- G5: config documents
_AIRFLOW_BROKER = 'broker_url = sqla+mysql://airflow:airflow@localhost:3306/airflow\n'
_AIRFLOW_DOCS = {
    'default_test.cfg': _AIRFLOW_BROKER + 'result_backend = db+mysql://airflow:airflow@localhost:3306/airflow\n',
    'default_airflow.cfg': _AIRFLOW_BROKER,
    'config.yml': '      default: "sqla+mysql://airflow:airflow@localhost:3306/airflow"\n',
}
def _tag(name):
    return name.replace('.', '_')


for _name, _source in _AIRFLOW_DOCS.items():
    case('G5', f'dev_default_{_tag(_name)}', {_name: _source}, 'CWE-798', _name, 1, 'quiet',
         'dev_default_off_arm', 'loud', 'the password is the username, on localhost')
_TEST_DOC = {
    'service_test.cfg': 'api_key = R4ndomStr1ngVal7ue8Xq20000\n',
    'test_local.ini': 'secret_key = R4ndomStr1ngVal7ue8Xq20000\n',
}
for _name, _source in _TEST_DOC.items():
    case('G5', f'test_document_{_name.split(".")[0]}', {_name: _source}, 'CWE-798', _name, 1,
         'quiet', 'doc_name_off_arm', 'loud', 'the document calls itself a test fixture')
case('G5', 'temporary_key_placeholder',
     {'local_settings.cfg': 'api_key = temporary_key_rotation_seed_value\n'},
     'CWE-798', 'local_settings.cfg', 1, 'quiet', 'token_set_off_arm', 'loud',
     'the value names what it stands in for')
case('G5', 'replace_me_placeholder', {'local.conf': 'client_secret = replace_me_before_deploying_1\n'},
     'CWE-798', 'local.conf', 1, 'quiet', 'token_set_off_arm', 'loud', 'an instruction, not a credential')
case('G5', 'not_found_placeholder', {'salt_minion.cfg': 'secret_key = cryptography_not_found_value\n'},
     'CWE-798', 'salt_minion.cfg', 1, 'quiet', 'token_set_off_arm', 'loud',
     "Salt's own marker for storing nothing at all")
case('G5', 'boundary_secret_in_test_doc', {'service_test.cfg': 'api_key = R4ndomStr1ngVal7ue8Xq20000\n'},
     'CWE-798', 'service_test.cfg', 1, 'quiet', 'doc_name_off_arm', 'loud',
     'the cost of the name rule, stated as a case instead of hidden')
_PRODUCTION = {
    'digitalocean.conf': 'api_key = 9fD3qW7zXe1Lp0RtY4vB8nK2\n',
    'prod_broker.conf': 'broker_url = amqp://app:S3cr3tP4ssHostValue@mq.internal:5672/prod\n',
    'service_prod.cfg': 'api_key = R4ndomStr1ngVal7ue8Xq20000\n',
    'aws_credentials.cfg': 'aws_access_key_id = AKIAR3VQUZBH7TKQWM2D\n',
}
# The two generic keys move when the name rule is blinded -- that is the cost of the rule, kept as a
# case. The service URL and the vendor token do not, because the name rule never reaches their branch.
_PRODUCTION_LOUD = ('prod_broker', 'aws_credentials')
for _name, _source in _PRODUCTION.items():
    case('G5', f'production_{_name.split(".")[0]}', {_name: _source}, 'CWE-798', _name, 1,
         'loud', 'doc_name_blind_arm',
         'loud' if _name.split('.')[0] in _PRODUCTION_LOUD else 'quiet',
         'a value that proves its own shape' if _name.split('.')[0] in _PRODUCTION_LOUD
         else 'blinding the name rule is what silences a real key in a production document')
case('G5', 'prod_service_url_kept', {'prod_broker.conf': _PRODUCTION['prod_broker.conf']},
     'CWE-798', 'prod_broker.conf', 1, 'loud', 'dev_default_blind_arm', 'quiet',
     'blinding the dev-default proof is what silences a real broker password')
case('G5', 'pem_block_kept', {'server.cfg': 'private_key = -----BEGIN RSA PRIVATE KEY-----\n'},
     'CWE-798', 'server.cfg', 1, 'loud', 'token_set_off_arm', 'loud', 'a PEM header is self-proving')

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
    # G1: off = the exemption never applies, so internal routes are reported; blind = HEAD's answer,
    # so every url_for is excused and a client-named endpoint disappears.
    'urlfor_off_arm': (('T', '_c601_urlfor_builds_an_internal_route', _never),),
    'urlfor_blind_arm': (('T', '_c601_urlfor_builds_an_internal_route', _always),),
    # G2: the verdict function forced to always-vulnerable (safe rows loud) and never-vulnerable.
    'redos_blind_arm': (('ast_scanner', '_is_redos_vulnerable_pattern', _always_static),),
    'redos_removed_arm': (('ast_scanner', '_is_redos_vulnerable_pattern', _never_static),),
    # G3: the opener vocabulary wound back to what HEAD shipped, and forced to excuse everything.
    'opener_narrow_arm': (('T', '_C400_LOCAL_OPENER_LEAVES', frozenset({'open', 'fopen'})),),
    'opener_off_arm': (('T', '_c400_receiver_is_disk_handle', _never),),
    'opener_blind_arm': (('T', '_c400_receiver_is_disk_handle', _always),),
    # G4: the lookup exemption off, and forced onto every mapping.
    'lookup_off_arm': (('T', '_c521_lookup_default_is_absent_marker', _never),),
    'lookup_blind_arm': (('T', '_c521_lookup_default_is_absent_marker', _always),),
    # G5, one arm per shipped proof.
    'dev_default_off_arm': (('secret_scanner', '_service_credential_is_dev_default', _never_static),),
    'dev_default_blind_arm': (('secret_scanner', '_service_credential_is_dev_default', _always_static),),
    'doc_name_off_arm': (('secret_scanner', '_is_non_production_document', _never_static),),
    'doc_name_blind_arm': (('secret_scanner', '_is_non_production_document', _always_static),),
    'token_set_off_arm': (('secret_scanner', 'NON_SECRET_PLACEHOLDER_TOKENS', ()),),
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
            print(f'  {now:5s} arm={arm:5s} {receipt:11s} {entry["label"]:32s} {entry["note"][:46]}')
            if now != entry['expect']:
                failures.append(f'{pocket}/{entry["label"]}: shipped {now}, want {entry["expect"]}')
            if arm != entry['arm_expect']:
                failures.append(f'{pocket}/{entry["label"]}: arm-off {arm}, want {entry["arm_expect"]}')
    return failures


# --------------------------------------------------------------------------- TIER 2 predicates
def _tracker(files):
    with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files=dict(files), max_workers=1)
        tracker.analyze()
    return tracker


def _calls(source):
    return [node for node in ast.walk(link(ast.parse(source))) if isinstance(node, ast.Call)]


_TRACKER = _tracker({'urlfor_views.py': _URLFOR})
PROBES = {}


def probe(name, description):
    def register(function):
        PROBES[name] = (description, function)
        return function
    return register


def _urlfor_call(needle):
    """The `url_for(...)` call inside the named function of the G1 fixture."""
    tree = link(ast.parse(_URLFOR))
    for function in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        if function.name != needle:
            continue
        for call in [n for n in ast.walk(function) if isinstance(n, ast.Call)]:
            if (call.func.id if isinstance(call.func, ast.Name) else '') == 'url_for':
                return call
    raise AssertionError(f'no url_for call in {needle}')


@probe('g1_literal_endpoint_is_internal', 'a constant endpoint with no client data earns the exemption')
def _():
    internal = _TRACKER._c601_urlfor_builds_an_internal_route
    return (internal(_urlfor_call('menu_redirect'), []) is True
            and internal(_urlfor_call('menu_redirect'), [False, True]) is False)


@probe('g1_client_named_endpoint_is_not', 'an endpoint the request chose is not an internal route')
def _():
    return _TRACKER._c601_urlfor_builds_an_internal_route(
        _urlfor_call('client_named_redirect'), [False]) is False


@probe('g1_client_keyword_defeats_the_route', 'a client-supplied query argument cancels the exemption')
def _():
    internal = _TRACKER._c601_urlfor_builds_an_internal_route
    return (internal(_urlfor_call('client_query_redirect'), [False, False, True]) is False
            and internal(_urlfor_call('named_endpoint_redirect'), [False, False]) is True)


@probe('g1_subscript_endpoint_is_not_constant', 'url_for(request.values[...]) never reads as a literal')
def _():
    return _TRACKER._c601_urlfor_builds_an_internal_route(
        _urlfor_call('inline_client_endpoint_redirect'), [False]) is False


# Every fixture below is a module-level literal with a literal file name: `scan_rows` fed a
# dynamically built source is itself a CWE-78 parity key, and a gate must never add one.
_URLFOR_LITERAL = module('from flask import redirect, url_for, request', '',
                         'def target(token):',
                         "    return redirect(url_for('Airflow.index'))")
_URLFOR_CONSTANT_KWARG = module('from flask import redirect, url_for, request', '',
                                'def target(token):',
                                "    return redirect(url_for('Airflow.index', id=token))")
_URLFOR_CLIENT_KWARG = module('from flask import redirect, url_for, request', '',
                              'def target(token):',
                              "    return redirect(url_for('Airflow.index', id=request.args['id']))")
_URLFOR_NAME_ENDPOINT = module('from flask import redirect, url_for, request', '',
                               'def target(token):',
                               '    return redirect(url_for(token))')
_URLFOR_KWARGS_ENDPOINT = module('from flask import redirect, url_for, request', '',
                                 'def target(token):',
                                 "    return redirect(url_for('Airflow.index', **extra))")


@probe('g1_an_unexplainable_argument_is_client_data', 'the caller resolves arguments fail-closed')
def _():
    quiet = (
        loud(scan_rows({'urlfor_literal.py': _URLFOR_LITERAL}), 'urlfor_literal.py', 'CWE-601', 4),
        loud(scan_rows({'urlfor_kwarg.py': _URLFOR_CONSTANT_KWARG}),
             'urlfor_kwarg.py', 'CWE-601', 4))
    held = (
        loud(scan_rows({'urlfor_client_kwarg.py': _URLFOR_CLIENT_KWARG}),
             'urlfor_client_kwarg.py', 'CWE-601', 4),
        loud(scan_rows({'urlfor_name_endpoint.py': _URLFOR_NAME_ENDPOINT}),
             'urlfor_name_endpoint.py', 'CWE-601', 4),
        loud(scan_rows({'urlfor_kwargs_endpoint.py': _URLFOR_KWARGS_ENDPOINT}),
             'urlfor_kwargs_endpoint.py', 'CWE-601', 4))
    return not any(quiet) and all(held)


@probe('g2_safe_pattern_is_linear', 'four shipped Salt/Airflow constants answer not catastrophic')
def _():
    return all(ast_scanner._is_redos_vulnerable_pattern(pattern) is False
               for pattern in (r'^[a-z0-9]+(?:-[a-z0-9]+)*$', r'^\d{4}\.\d+$', r'\s+',
                               r'[0-9]+\.[0-9]+'))


@probe('g2_evil_patterns_stay_vulnerable', 'nested quantifiers and overlapping alternation answer catastrophic')
def _():
    return all(ast_scanner._is_redos_vulnerable_pattern(pattern) is True
               for pattern in (r'^(a+)+$', r'^(a|aa)+$', r'(x+x+)+y'))


@probe('g2_backreference_is_not_catastrophic_here', 'the verdict excuses no backreference, it never flags one')
def _():
    return all(ast_scanner._is_redos_vulnerable_pattern(pattern) is False
               for pattern in (r'^(a)\1+$', r'^(a+)\1+$'))


@probe('g3_opener_vocabulary_and_roots', 'flopen/safe_open/atomic_open open, urlopen/makefile do not')
def _():
    def opener(source):
        return T._c400_value_is_local_opener(_TRACKER, _calls(source)[-1])
    return (opener('fh = salt.utils.files.flopen(path)') is True
            and opener('fh = salt.utils.files.safe_open(path)') is True
            and opener('fh = salt.utils.files.atomic_open(path)') is True
            and opener('fh = urllib.request.urlopen(url)') is False
            and opener('fh = sock.makefile()') is False)


@probe('g4_empty_default_needs_an_unwritten_name', 'a dunder this module never writes is injected')
def _():
    def answers(source, module_name):
        tracker = _tracker({module_name: source})
        return tracker._c521_lookup_default_is_absent_marker(
            _calls(source)[-1], f'{module_name.rsplit(".", 1)[0]}:global')
    return (answers(_OPTS_CLEAN, 'lookup_opts_clean.py') is True
            and answers(_OPTS_WRITTEN, 'lookup_opts_written.py') is False)


@probe('g4_written_dunder_lookups_stay_loud', 'a mapping this scope owns is never treated as injected')
def _():
    rows = scan_rows({'lookup_config.py': _LOOKUP})
    return (loud(rows, 'lookup_config.py', 'CWE-521', at(_LOOKUP, 'def object_fallback(', 1)) is True
            and loud(rows, 'lookup_config.py', 'CWE-521', at(_LOOKUP, 'def param_fallback(', 1)) is False)


@probe('g3_attribute_receivers_emit_no_read_row', 'the mandated self._content.read() shape is never emitted')
def _():
    rows = scan_rows({'handles_grains.py': _HANDLES})
    return (loud(rows, 'handles_grains.py', 'CWE-400', at(_HANDLES, 'def take(', 1)) is False
            and loud(rows, 'handles_grains.py', 'CWE-400', at(_HANDLES, 'def read_response(', 2)) is True)


@probe('g5_dev_default_needs_both_halves', 'username == password on a loopback host, nothing else')
def _():
    check = secret_scanner._service_credential_is_dev_default
    return (check('sqla+mysql://airflow:airflow@localhost:3306/airflow') is True
            and check('mysql://airflow:airflow@[::1]/airflow') is True
            and check('amqp://app:S3cr3tP4ssHostValue@mq.internal:5672/prod') is False
            and check('postgres://airflow:otherpass@localhost/airflow') is False
            and check('redis://cache:cache@redis.example.com:6379/0') is False)


@probe('g5_document_names_are_specific', 'the listed test/default names only, never production ones')
def _():
    check = secret_scanner._is_non_production_document
    return (check('a/b/service_test.cfg') is True
            and check('test_local.ini') is True
            and check('default_test.properties') is True
            and check('default_airflow.cfg') is False
            and check('digitalocean.conf') is False)


@probe('g5_placeholder_tokens_do_not_reach_secrets', 'four instruction tokens refuse, a real key does not')
def _():
    check = secret_scanner.is_refused
    return (check('temporary_key_rotation_seed_value', named=True) is True
            and check('replace_me_before_deploying_1', named=True) is True
            and check('cryptography_not_found_value', named=True) is True
            and check('not_a_real_key_but_long_enough', named=True) is True
            and check('9fD3qW7zXe1Lp0RtY4vB8nK2', named=True) is False)


@probe('g5_generic_branch_is_the_only_one_gated', 'a path is not a credential, a random key is')
def _():
    from scanners.secret_scanner import _is_literal_credential
    return (_is_literal_credential('/etc/salt/pki/minion.pem') is False
            and _is_literal_credential('9fD3qW7zXe1Lp0RtY4vB8nK2') is True)


# --------------------------------------------------------------------------- TIER 3 source laws
LAWS = (
    ('G1 the emitter no longer excuses url_for unconditionally',
     lambda: '_urlfor_builds_an_internal_route(expr, scope_id, lineno)'
             in inspect.getsource(T._collect_phase8_structural_findings)
             and '{"get_full_path", "url_for"}'
             not in inspect.getsource(T._collect_phase8_structural_findings)),
    ('G1 the exemption has to read a constant first argument',
     lambda: 'isinstance(endpoint, ast.Constant)'
             in inspect.getsource(T._c601_urlfor_builds_an_internal_route)),
    ('G1 a client argument cancels the exemption',
     lambda: 'return not any(args_read_client_input)'
             in inspect.getsource(T._c601_urlfor_builds_an_internal_route)),
    ('G2 the emit layer resolves the pattern before judging it',
     lambda: 'if not isinstance(value, str):' in inspect.getsource(T._collect_phase9_structural_findings)
             and '_is_redos_vulnerable_pattern(value)' in inspect.getsource(
                 T._collect_phase9_structural_findings)),
    ('G3 the opener leaves are read off the last written segment',
     lambda: 'rsplit(".", 1)[-1]' in inspect.getsource(T._c400_value_is_local_opener)),
    ('G3 the network roots still answer False',
     lambda: '"urllib", "aiohttp", "httpx", "requests", "socket", "http"'
             in inspect.getsource(T._c400_value_is_local_opener)),
    ('G4 a written dunder keeps reporting',
     lambda: 'names_by_module' in inspect.getsource(T._c521_lookup_default_is_absent_marker)
             and 'self.assignments_by_scope.get((module_scope'
             not in inspect.getsource(T._c521_lookup_default_is_absent_marker)),
    ('G5 the document-name rule reaches only the generic branch',
     lambda: 'kind == "generic" and _is_non_production_document(file_path)'
             in inspect.getsource(secret_scanner.audit_secret_files)),
    ('G5 the dev-default proof needs the username and the host',
     lambda: 'user != password' in inspect.getsource(secret_scanner._service_credential_is_dev_default)
             and '_service_host(host) in LOCAL_SERVICE_HOSTS'
             in inspect.getsource(secret_scanner._service_credential_is_dev_default)),
    ('G5 the lexical gate is still called from one branch',
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
    'urlfor_exemption_removed': (
        'G1: the exemption is switched off, so the internal route it retires is reported again',
        'urlfor_off_arm',
        ['reschedule_redirect'],
        ['g1_client_keyword_defeats_the_route', 'g1_literal_endpoint_is_internal']),
    'urlfor_exemption_blinded': (
        'G1: HEAD answer, every url_for is excused, so the client-named destinations go quiet',
        'urlfor_blind_arm',
        ['client_named_redirect', 'client_query_redirect', 'inline_client_endpoint_redirect'],
        ['g1_client_keyword_defeats_the_route', 'g1_client_named_endpoint_is_not',
         'g1_literal_endpoint_is_internal', 'g1_subscript_endpoint_is_not_constant']),
    'redos_verdict_blinded': (
        'G2: every pattern is called catastrophic, so the linear constants and the calls go loud',
        'redos_blind_arm',
        ['safe_segment', 'safe_backreference', 'safe_match_grain', 'safe_find_versions',
         'safe_normalise'],
        ['g2_backreference_is_not_catastrophic_here', 'g2_safe_pattern_is_linear']),
    'redos_verdict_removed': (
        'G2: no pattern is ever catastrophic, so the ReDoS rows lose their finding',
        'redos_removed_arm',
        ['evil_compile', 'nested_quantifier', 'overlapping_alternation', 'adjacent_quantifiers'],
        ['g2_evil_patterns_stay_vulnerable']),
    'opener_set_wound_back': (
        'G3: the vocabulary loses flopen/safe_open/atomic_open, which is what HEAD shipped',
        'opener_narrow_arm',
        ['read_atomic', 'read_checked', 'read_lock'],
        ['g3_opener_vocabulary_and_roots']),
    'opener_exemption_blinded': (
        'G3: every receiver is a disk handle, so the network reads lose their row',
        'opener_blind_arm',
        ['read_urlopen', 'read_response', 'read_socket'],
        []),
    'lookup_exemption_removed': (
        'G4: no lookup default is ever an absent marker, so every mapping reports',
        'lookup_off_arm',
        ['minion_fallback', 'param_fallback', 'self_fallback'],
        ['g4_empty_default_needs_an_unwritten_name']),
    'lookup_exemption_blinded': (
        'G4: every mapping is treated as someone elses, so a shipped empty default goes quiet',
        'lookup_blind_arm',
        ['written_opts_fallback', 'object_fallback'],
        ['g4_empty_default_needs_an_unwritten_name']),
    'dev_default_proof_removed': (
        'G5: a worked-example broker stops being recognised, so the Airflow rows return',
        'dev_default_off_arm',
        ['dev_default_config_yml', 'dev_default_default_airflow_cfg', 'dev_default_default_test_cfg'],
        ['g5_dev_default_needs_both_halves']),
    'dev_default_proof_blinded': (
        'G5: every service URL is a dev default, so the production broker password goes quiet',
        'dev_default_blind_arm',
        ['production_prod_broker', 'prod_service_url_kept'],
        ['g5_dev_default_needs_both_halves']),
    'document_rule_removed': (
        'G5: the document name stops mattering, so the test-fixture keys report',
        'doc_name_off_arm',
        ['boundary_secret_in_test_doc', 'test_document_service_test', 'test_document_test_local'],
        ['g5_document_names_are_specific']),
    'document_rule_blinded': (
        'G5: every document is a test fixture, so the production keys go quiet with them',
        'doc_name_blind_arm',
        ['production_digitalocean', 'production_service_prod'],
        ['g5_document_names_are_specific']),
    'placeholder_tokens_removed': (
        'G5: the newer tokens stop refusing, so the instruction-shaped values report',
        'token_set_off_arm',
        ['not_found_placeholder', 'replace_me_placeholder', 'temporary_key_placeholder'],
        ['g5_placeholder_tokens_do_not_reach_secrets']),
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
        print(f'  {"OK  " if ok else "FAIL"} {name:38s} {description}')
        if not ok:
            failures.append(f'predicate {name}: {description}')
    return failures


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
        print(f'  {"CAUGHT" if ok else "MISSED"} {name:26s} rows={moved} probes={flipped} '
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
