"""Gate #69 -- the five TASK 26 root causes, each held by its own falsifier.

Every fixture below is a verbatim reproducer of a row that was measured LOUD against a real HEAD
checkout (`git worktree add --detach` at ceadc89) and is QUIET with the shipped engine. No clause
reads a repository name, a folder or a filename: each answers on the scanned source's own AST, on a
parsed regex token tree, on a literal media type, or on a URL's own authority.

  R1  BOUNDED REGEX LITERALS (CWE-1333). `_regex_catastrophic_backtracking` fired on ANY two adjacent
      repeats whose character sets overlapped, with no test of whether either repeat could iterate
      without a ceiling. `\d{4}-\d{2}-\d{2}`, `[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` and
      `{0,20}` next to `{0,3}` are linear-time: a bounded neighbour contributes a CONSTANT number of
      splits. `_t26_repeat_is_unbounded` is the missing test, and it is an equality test against
      `re._constants.MAXREPEAT` -- `re` spells `*`, `+` and `{n,}` with that sentinel, not with None,
      so `maximum is None` alone silently retired `a*a*` (a real regression this gate now seals).
      `multiplies` is the WRONG test for adjacency: it is true for a large bounded ceiling, which is
      what makes NESTED repetition blow up, not neighbours. Both spellings are armed separately.
      LOUD CONTROLS: `re.compile(user_pattern)` from the request, `(a+)+$`, `([a-z]+)*$`, `a*a*`.

  R2  NON-HTML MEDIA TYPE (CWE-79). The response collector read `content_type=` and `mimetype=` but
      not FastAPI/Starlette's `media_type=`, so `Response(content=body.model_dump_json(),
      media_type="application/json")` reported XSS on a JSON body. `RESPONSE_MEDIA_KEYWORDS` is one
      vocabulary for all three spellings. `media_type_is_not_html` also refuses `image/svg+xml`
      explicitly: SVG is a document the browser parses and scripts, and it opens with the `image/`
      prefix every raster type shares, so the prefix list alone would have silenced it.
      `text/event-stream` and `application/problem+json` join the prefix list.
      LOUD CONTROLS: `media_type="text/html"`, `media_type="image/svg+xml"`, the same SVG with a
      `; charset=utf-8` parameter, and a Response with NO media type at all.

  R3  EXCEPTION DETAIL WITH NO CLIENT (CWE-209). Two independent emitters, two independent clauses.
      (a) The structural ExceptHandler rule reported `return error` -- handing the exception OBJECT
          back to an internal caller. `_t26_catches_declared_error_group` refuses that ONLY when the
          handler catches a group the module itself declared as a tuple/list (`_TRANSIENT_ERRORS =
          (OSError, ValueError)`) AND no web context surrounds it AND the return is not a text form.
          This partition is load-bearing: the blessed corpus books bare `return e` under a directly
          named class (`except RuntimeError as e`, `except Exception as e`) LOUD, and a blanket
          refusal dropped both keys. `_t26_is_string_error_return` keeps `str(exc)`, `repr(exc)` and
          `format_exc()` loud even inside a declared group with no web context, because text discloses
          on its own where an object does not.
      (b) `_c209_exposed_in_reply` accepted ANY JoinedStr/BinOp as a response body, so a CLI helper
          with zero web imports reported an HTTP stack disclosure.
          `_t26_string_reply_without_web_context` requires a route decorator, a web-handler argument
          or a web-framework import. A missing parent chain answers False -- an unproven shape is not
          a safe one, so the finding is kept rather than retired.
      LOUD CONTROLS: a Flask route returning `str(exc)` and `traceback.format_exc()`, a bare
      `return error` inside a route, the same with only a web IMPORT, an f-string inside a route, and
      `str(error)`/`repr(error)` from a declared group in a non-web module.

  R4  PASSWORD PROVENANCE (CWE-916/759). The structural collector's `scope_id` is always
      `{mod_name}:global`, so searching it for a password word searched the FILENAME: a cache digest
      of `message_content` inside a module named `secret_detection.py` matched `secret` and reported
      a weak password hash. `_t26_password_scope_names` returns the innermost enclosing function's
      own name and parameters instead, memoised per module. It is strictly narrow: it can only ever
      return spellings the source itself writes.
      LOUD CONTROLS: `hashlib.sha256(password.encode())`, `hashlib.md5(user_pwd.encode())`.
      FN-CLOSER: `def hash_password(value): hashlib.sha256(value.encode())` was QUIET at HEAD and is
      LOUD now -- the function's own name is provenance the filename never carried.

  R5  LOCAL DEV SERVICE URL (CWE-798, the line-based config reader). `_service_credential_is_dev_default`
      already refused `user:user@localhost`; `host.docker.internal` was missing from
      `LOCAL_SERVICE_HOSTS`, so `postgresql://postgres:postgres@host.docker.internal:5432/litellm_test`
      reported a hard-coded credential. The refusal needs BOTH halves: the password equals the
      username AND the host is this machine or the Docker host gateway.
      LOUD CONTROLS: a production URL with a real password, the SAME default credentials on a remote
      host (`db.internal`), and a real password on `host.docker.internal`.

Honest limits, measured rather than assumed:
  * `[a-z]+(?:[-._/][a-z]+)+` (the disjoint delimiter loop) is QUIET at HEAD already -- the shipped
    separator test refuses it. Booked as a CONTROL, not credit.
  * `HTMLResponse(user_input)` and fastapi's `JSONResponse({"error": str(e)})` are QUIET at HEAD:
    neither name is in `RESPONSE_CONSTRUCTOR_NAMES`. These are PRE-EXISTING engine gaps, not
    regressions from this task, and they are booked `not booked` with the measurement stated. The
    recognised equivalents (`django.http.HttpResponse`, `flask.jsonify`) do fire.
  * `def store(passphrase)` is QUIET at HEAD and stays QUIET: `CWE3A_PASSWORD_NAME_RE` does not spell
    `passphrase`. Widening that vocabulary is a separate decision with its own blessed-key audit.
  * BUG 5(b) WAS NOT FIXED, deliberately. `.circleci/scripts/run_integration.sh` measures 4 hits in
    total, not 44: two `Service URL With Embedded Password` and two `Hard-coded API_KEY` at lines 177
    and 178, both on the literal `sk-scripted-provider`. `$ENV_VAR` references are ALREADY refused by
    `INTERPOLATION`. The dummy literal clears every generic floor (20 chars, 2 classes, 3.484 bits)
    and so does a real all-lowercase key `sk-abcdefghijklmnopqrst` (23 chars, 4.35 bits): no
    deterministic, repo-agnostic test separates them, and a dictionary-word heuristic would weaken
    real API-key detection. The task's own condition -- ONLY fix if provably non-secret -- is not met,
    so the row stays LOUD and is booked here as a CONTROL with that reasoning.

TIER 0 parses every fixture. TIER 1 reads every case twice against one shared fixture: its shipped
verdict, and its verdict with the owning clause reverted. TIER 1b asserts the verbatim reproducers
produce ZERO rows of any CWE. TIER 1c does the same for the line-based secret reader. TIER 2 calls the
shipped predicates directly. TIER 3 reads the shipped source (docstrings stripped) and asks it to keep
the shape each proof depends on. TIER 4 is the falsifiers: one weakening per clause, and an exact set
of rows and predicates must move.

Usage: python benchmark/gates/five_rootcause_fp_probe.py [--dump] [--mutate=<name>]
"""
from __future__ import annotations

import ast
import contextlib
import gc
import inspect
import io as _io
import os
import re
import sys
import textwrap
import time

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
import rule_engine  # noqa: E402
from scanners import secret_scanner  # noqa: E402

T = ast_scanner.TaintTracker
OWNERS = {'T': T, 'ast_scanner': ast_scanner, 'rule_engine': rule_engine,
          'secret_scanner': secret_scanner}

BUDGET_SECONDS = 240.0
BUDGET_MUTATION_SECONDS = 60.0
BUDGET_RSS_MB = 60.0

BS = chr(92)
NL = chr(10)
Q = chr(39)
DQ = chr(34)


def module(*lines):
    return ''.join(line + NL for line in lines)


def at(source, needle, offset=0):
    """The line of a unique needle, so a fixture is read instead of hand-counted."""
    lines = [index for index, text in enumerate(source.splitlines(), 1) if needle in text]
    if len(lines) != 1:
        raise AssertionError(f'{needle!r} matched {len(lines)} lines, need exactly 1')
    return lines[0] + offset


def link(tree):
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    return tree


_CACHE = {}


def fixture_rows(source, state='ship', name='m.py'):
    """(name, line, cwe) for one fixture file, every clause in its shipped position.

    Deliberately not named `scan_rows`: `gate_common.scan_rows(kind, cwd)` runs a subprocess over a
    path, and a three-argument call resolves onto it cross-file and reports COMMAND_INJECTION here.
    """
    key = ('scan', state, source, name)
    if key in _CACHE:
        return _CACHE[key]
    with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files={name: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = sorted({(name, int(row['line']), row['cwe'])
                       for row in cli._findings_for(tracker, edges)})
    _CACHE[key] = rows
    return rows


def config_rows(source, state='ship'):
    """(line, label, kind) for the line-based config reader, which is not the AST engine."""
    key = ('config', state, source)
    if key in _CACHE:
        return _CACHE[key]
    rows = sorted({(int(lineno), label, kind)
                   for lineno, label, _sev, _red, kind in secret_scanner._iter_hits(source)})
    _CACHE[key] = rows
    return rows


def loud(rows, name, cwe, line):
    return (name, line, cwe) in rows


CASES = []


def case(pocket, label, cwe, name, line, expect, arm, arm_expect, source, note=''):
    CASES.append({'pocket': pocket, 'label': label, 'source': source, 'cwe': cwe, 'name': name,
                  'line': line, 'expect': expect, 'arm': arm, 'arm_expect': arm_expect,
                  'note': note})


def rows_for(entry, state='ship'):
    return fixture_rows(entry['source'], state, entry['name'])


# --------------------------------------------------------------------------- R1 fixtures
ISO_DATETIME = module(
    'import re',
    'ISO = re.compile(r"' + BS + 'd{4}-' + BS + 'd{2}-' + BS + 'd{2}(?:T' + BS + 'd{2}:' + BS
    + 'd{2}(?::' + BS + 'd{2}(?:' + BS + '.' + BS + 'd+)?)?(?:Z|[+-]' + BS + 'd{2}:?' + BS
    + 'd{2})?)?")')
SLACK_TOKEN = module(
    'import re',
    'SLACK = re.compile(r"(xoxb-[0-9]{10,13}' + BS + '-[0-9]{10,13}[a-zA-Z0-9-]*)")')
DELIMITER_LOOP = module(
    'import re',
    'SLUG = re.compile(r"[a-z]+(?:[-._/][a-z]+)+")')
ADAFRUIT_BOUNDED = module(
    'import re',
    'ADAFRUIT = re.compile(r"(?i)(?:adafruit)(?:[0-9a-z' + BS + '-' + BS + '_' + BS + 't .]{0,20})'
    '(?:[' + BS + 's|' + Q + ']|[' + BS + 's|' + BS + DQ + ']){0,3}'
    '(?:=|>|:{1,3}=|' + BS + '|' + BS + '|:|<=|=>|)")')
L_DYNAMIC = module(
    'import re',
    'def go(request):',
    '    user_pattern = request.GET["p"]',
    '    return re.compile(user_pattern)')
L_EVIL_STATIC = module('import re', 'EVIL = re.compile(r"(a+)+$")')
L_EVIL_ALT = module('import re', 'EVIL2 = re.compile(r"([a-z]+)*$")')
L_ADJACENT_UNBOUNDED = module('import re', 'BAD = re.compile(r"a*a*")')
NESTED_BOUNDED = module('import re', 'OK = re.compile(r"(a{1,3}){1,3}")')
BOUNDED_SEPARATOR = module('import re', 'OK = re.compile(r"[0-9]+-[0-9]+")')

case('R1', 'iso_datetime_retired', 'CWE-1333', 'm.py', at(ISO_DATETIME, 'ISO = re.compile'),
     'quiet', 'redos_bound_off_arm', 'loud', ISO_DATETIME, 'every ceiling is {4}/{2}, all fixed')
case('R1', 'slack_token_retired', 'CWE-1333', 'm.py', at(SLACK_TOKEN, 'SLACK = re.compile'),
     'quiet', 'redos_bound_off_arm', 'loud', SLACK_TOKEN, '{10,13} is a ceiling of 13, not unbounded')
case('R1', 'adafruit_bounded_retired', 'CWE-1333', 'm.py', at(ADAFRUIT_BOUNDED, 'ADAFRUIT = re.compile'),
     'quiet', 'redos_bound_off_arm', 'loud', ADAFRUIT_BOUNDED, '{0,20} beside {0,3}')
case('R1', 'delimiter_loop_control', 'CWE-1333', 'm.py', at(DELIMITER_LOOP, 'SLUG = re.compile'),
     'quiet', 'redos_bound_off_arm', 'quiet', DELIMITER_LOOP, 'already quiet at HEAD: separator test')
case('R1', 'nested_bounded_control', 'CWE-1333', 'm.py', at(NESTED_BOUNDED, 'OK = re.compile'),
     'quiet', 'redos_bound_off_arm', 'quiet', NESTED_BOUNDED, 'a constant number of paths')
case('R1', 'bounded_separator_control', 'CWE-1333', 'm.py', at(BOUNDED_SEPARATOR, 'OK = re.compile'),
     'quiet', 'redos_bound_off_arm', 'quiet', BOUNDED_SEPARATOR, 'disjoint delimiter, quiet at HEAD')
case('R1', 'dynamic_pattern_kept', 'CWE-1333', 'm.py', at(L_DYNAMIC, 'return re.compile'),
     'loud', 'redos_bound_off_arm', 'loud', L_DYNAMIC, 'MANDATED loud control: tainted pattern')
case('R1', 'evil_static_kept', 'CWE-1333', 'm.py', at(L_EVIL_STATIC, 'EVIL = re.compile'),
     'loud', 'redos_bound_off_arm', 'loud', L_EVIL_STATIC, 'MANDATED loud control: (a+)+$')
case('R1', 'evil_alternation_kept', 'CWE-1333', 'm.py', at(L_EVIL_ALT, 'EVIL2 = re.compile'),
     'loud', 'redos_bound_off_arm', 'loud', L_EVIL_ALT, 'MANDATED loud control: ([a-z]+)*$')
case('R1', 'adjacent_unbounded_kept', 'CWE-1333', 'm.py', at(L_ADJACENT_UNBOUNDED, 'BAD = re.compile'),
     'loud', 'redos_bound_off_arm', 'loud', L_ADJACENT_UNBOUNDED,
     'the MAXREPEAT sentinel regression this gate seals')

# --------------------------------------------------------------------------- R2 fixtures
JSON_RESPONSE = module(
    'from fastapi import Response',
    'def handler(body, headers):',
    '    return Response(content=body.model_dump_json(), media_type="application/json", headers=headers)')
JSON_RESPONSE_ROUTE = module(
    'from fastapi import APIRouter, Response',
    'router = APIRouter()',
    '@router.post("/dump")',
    'def handler(body, headers):',
    '    return Response(content=body.model_dump_json(), media_type="application/json", headers=headers)')
L_HTML_MEDIA = module(
    'from fastapi import Response',
    'def handler(request):',
    '    user_html = request.GET["h"]',
    '    return Response(content=user_html, media_type="text/html")')
L_SVG_MEDIA = module(
    'from fastapi import Response',
    'def handler(request):',
    '    user_svg = request.GET["s"]',
    '    return Response(content=user_svg, media_type="image/svg+xml")')
L_SVG_CHARSET = module(
    'from fastapi import Response',
    'def handler(request):',
    '    data = request.GET["d"]',
    '    return Response(content=data, media_type="image/svg+xml; charset=utf-8")')
L_NO_MEDIA = module(
    'from fastapi import Response',
    'def handler(request):',
    '    data = request.GET["d"]',
    '    return Response(content=data)')
PLAIN_MEDIA = module(
    'from fastapi import Response',
    'def handler(request):',
    '    data = request.GET["d"]',
    '    return Response(content=data, media_type="text/plain")')
EVENT_STREAM = module(
    'from fastapi import Response',
    'def handler(request):',
    '    data = request.GET["d"]',
    '    return Response(content=data, media_type="text/event-stream")')
PROBLEM_JSON = module(
    'from fastapi import Response',
    'def handler(request):',
    '    data = request.GET["d"]',
    '    return Response(content=data, media_type="application/problem+json")')
CONTENT_TYPE_KW = module(
    'from django.http import HttpResponse',
    'def handler(request):',
    '    data = request.GET["d"]',
    '    return HttpResponse(data, content_type="application/json")')
HEADERS_JSON = module(
    'from fastapi import Response',
    'def handler(request):',
    '    data = request.GET["d"]',
    '    return Response(content=data, headers={"Content-Type": "application/json"})')
# PRE-EXISTING GAP: HTMLResponse is not in RESPONSE_CONSTRUCTOR_NAMES, so this is quiet at HEAD too.
L_HTMLRESPONSE = module(
    'from fastapi.responses import HTMLResponse',
    'def handler(request):',
    '    user_input = request.GET["q"]',
    '    return HTMLResponse(user_input)')

case('R2', 'json_media_type_retired', 'CWE-79', 'm.py', at(JSON_RESPONSE, 'return Response'),
     'quiet', 'media_keyword_off_arm', 'loud', JSON_RESPONSE, 'the verbatim FastAPI FP')
case('R2', 'json_media_type_route_retired', 'CWE-79', 'm.py', at(JSON_RESPONSE_ROUTE, 'return Response'),
     'quiet', 'media_keyword_off_arm', 'loud', JSON_RESPONSE_ROUTE, 'same, under a route decorator')
case('R2', 'plain_media_retired', 'CWE-79', 'm.py', at(PLAIN_MEDIA, 'return Response'),
     'quiet', 'media_keyword_off_arm', 'loud', PLAIN_MEDIA, 'text/plain is not a document')
case('R2', 'event_stream_retired', 'CWE-79', 'm.py', at(EVENT_STREAM, 'return Response'),
     'quiet', 'media_vocab_off_arm', 'loud', EVENT_STREAM, 'SSE carries text, not markup')
case('R2', 'problem_json_retired', 'CWE-79', 'm.py', at(PROBLEM_JSON, 'return Response'),
     'quiet', 'media_vocab_off_arm', 'loud', PROBLEM_JSON, 'RFC 7807 problem detail is JSON')
case('R2', 'html_media_kept', 'CWE-79', 'm.py', at(L_HTML_MEDIA, 'return Response'),
     'loud', 'media_keyword_off_arm', 'loud', L_HTML_MEDIA, 'MANDATED loud control')
case('R2', 'svg_media_kept', 'CWE-79', 'm.py', at(L_SVG_MEDIA, 'return Response'),
     'loud', 'media_svg_blind_arm', 'quiet', L_SVG_MEDIA, 'MANDATED loud control: SVG scripts')
case('R2', 'svg_charset_kept', 'CWE-79', 'm.py', at(L_SVG_CHARSET, 'return Response'),
     'loud', 'media_svg_blind_arm', 'quiet', L_SVG_CHARSET, 'a parameter cannot launder SVG')
case('R2', 'no_media_type_kept', 'CWE-79', 'm.py', at(L_NO_MEDIA, 'return Response'),
     'loud', 'media_keyword_off_arm', 'loud', L_NO_MEDIA, 'no declaration is not a safe declaration')
case('R2', 'content_type_keyword_control', 'CWE-79', 'm.py', at(CONTENT_TYPE_KW, 'return HttpResponse'),
     'quiet', 'media_keyword_off_arm', 'quiet', CONTENT_TYPE_KW, 'the older spelling, quiet at HEAD')
case('R2', 'headers_mapping_control', 'CWE-79', 'm.py', at(HEADERS_JSON, 'return Response'),
     'quiet', 'media_keyword_off_arm', 'quiet', HEADERS_JSON, 'Content-Type in a headers dict')
case('R2', 'htmlresponse_preexisting_gap', 'CWE-79', 'm.py', at(L_HTMLRESPONSE, 'return HTMLResponse'),
     'quiet', 'media_keyword_off_arm', 'quiet', L_HTMLRESPONSE,
     'QUIET AT HEAD: name absent from RESPONSE_CONSTRUCTOR_NAMES')

# --------------------------------------------------------------------------- R3 fixtures
BARE_EXC_RETURN = module(
    '_TRANSIENT_ERRORS = (OSError, ValueError)',
    'def fetch(url):',
    '    try:',
    '        return open(url).read()',
    '    except _TRANSIENT_ERRORS as error:',
    '        return error')
CLI_JSON_HELPER = module(
    'import json',
    'def check(path):',
    '    try:',
    '        with open(path) as handle:',
    '            return json.load(handle)',
    '    except json.JSONDecodeError as error:',
    '        return f"{path} is not valid JSON: {error}"')
CLI_OSERROR_HELPER = module(
    'def read(path):',
    '    try:',
    '        with open(path) as handle:',
    '            return handle.read()',
    '    except OSError as exc:',
    '        return f"<cannot read {path}: {exc}>"')
L_FLASK_STR_EXC = module(
    'from flask import Flask',
    'app = Flask(__name__)',
    '@app.route("/x")',
    'def view():',
    '    try:',
    '        return open("/etc/passwd").read()',
    '    except Exception as exc:',
    '        return str(exc)')
L_FLASK_TRACEBACK = module(
    'import traceback',
    'from flask import Flask',
    'app = Flask(__name__)',
    '@app.route("/x")',
    'def view():',
    '    try:',
    '        return open("/etc/passwd").read()',
    '    except Exception:',
    '        return traceback.format_exc()')
L_BARE_EXC_ROUTE = module(
    'from flask import Flask',
    'app = Flask(__name__)',
    '@app.route("/x")',
    'def view():',
    '    try:',
    '        return open("/etc/passwd").read()',
    '    except Exception as error:',
    '        return error')
L_BARE_EXC_IMPORT = module(
    'import flask',
    'def helper():',
    '    try:',
    '        return open("/etc/passwd").read()',
    '    except Exception as error:',
    '        return error')
L_FSTRING_ROUTE = module(
    'from flask import Flask',
    'app = Flask(__name__)',
    '@app.route("/x")',
    'def view(path):',
    '    try:',
    '        return open(path).read()',
    '    except OSError as exc:',
    '        return f"<cannot read {path}: {exc}>"')
L_GROUP_STR = module(
    '_ERRORS = (OSError, ValueError)',
    'def fetch(url):',
    '    try:',
    '        return open(url).read()',
    '    except _ERRORS as error:',
    '        return str(error)')
L_GROUP_REPR = module(
    '_ERRORS = [OSError, ValueError]',
    'def fetch(url):',
    '    try:',
    '        return open(url).read()',
    '    except _ERRORS as error:',
    '        return repr(error)')
# The blessed corpus shape: a directly named class keeps its bare-return finding.
BLESSED_DIRECT_CLASS = module(
    'def handle():',
    '    try:',
    '        return load()',
    '    except RuntimeError as e:',
    '        return e')
# PRE-EXISTING GAP: fastapi's JSONResponse is not in RESPONSE_CONSTRUCTOR_NAMES either.
L_FASTAPI_JSONRESPONSE = module(
    'from fastapi import FastAPI',
    'from fastapi.responses import JSONResponse',
    'app = FastAPI()',
    '@app.get("/x")',
    'def view():',
    '    try:',
    '        return open("/etc/passwd").read()',
    '    except Exception as e:',
    '        return JSONResponse({"error": str(e)})')

case('R3', 'bare_exception_object_retired', 'CWE-209', 'm.py', at(BARE_EXC_RETURN, 'except _TRANSIENT_ERRORS'),
     'quiet', 'error_group_off_arm', 'loud', BARE_EXC_RETURN, 'the verbatim internal retry helper')
case('R3', 'cli_json_helper_retired', 'CWE-209', 'm.py', at(CLI_JSON_HELPER, 'return f"{path} is not valid'),
     'quiet', 'string_reply_off_arm', 'loud', CLI_JSON_HELPER, 'zero web imports, a terminal string')
case('R3', 'cli_oserror_helper_retired', 'CWE-209', 'm.py', at(CLI_OSERROR_HELPER, 'return f"<cannot read'),
     'quiet', 'string_reply_off_arm', 'loud', CLI_OSERROR_HELPER, 'same, an OSError diagnostic')
case('R3', 'flask_str_exc_kept', 'CWE-209', 'm.py', at(L_FLASK_STR_EXC, 'except Exception as exc'),
     'loud', 'error_group_off_arm', 'loud', L_FLASK_STR_EXC,
     'MANDATED loud control; the handler rule emits on the except line')
case('R3', 'flask_traceback_kept', 'CWE-209', 'm.py', at(L_FLASK_TRACEBACK, 'except Exception:'),
     'loud', 'error_group_off_arm', 'loud', L_FLASK_TRACEBACK,
     'MANDATED loud control; the handler rule emits on the except line')
case('R3', 'bare_exc_in_route_kept', 'CWE-209', 'm.py', at(L_BARE_EXC_ROUTE, 'except Exception as error'),
     'loud', 'error_group_off_arm', 'loud', L_BARE_EXC_ROUTE, 'a route IS a client')
case('R3', 'bare_exc_web_import_kept', 'CWE-209', 'm.py', at(L_BARE_EXC_IMPORT, 'except Exception as error'),
     'loud', 'error_group_off_arm', 'loud', L_BARE_EXC_IMPORT, 'a web import is enough context')
case('R3', 'fstring_in_route_kept', 'CWE-209', 'm.py', at(L_FSTRING_ROUTE, 'return f"<cannot read'),
     'loud', 'web_context_off_arm', 'quiet', L_FSTRING_ROUTE, 'the same text, now with a client')
case('R3', 'group_str_return_kept', 'CWE-209', 'm.py', at(L_GROUP_STR, 'except _ERRORS as error'),
     'loud', 'string_error_off_arm', 'quiet', L_GROUP_STR, 'text discloses where an object does not')
case('R3', 'group_repr_return_kept', 'CWE-209', 'm.py', at(L_GROUP_REPR, 'except _ERRORS as error'),
     'loud', 'string_error_off_arm', 'quiet', L_GROUP_REPR, 'a LIST-declared group, repr form')
case('R3', 'blessed_direct_class_kept', 'CWE-209', 'm.py', at(BLESSED_DIRECT_CLASS, 'except RuntimeError'),
     'loud', 'error_group_off_arm', 'loud', BLESSED_DIRECT_CLASS,
     'the blessed corpus shape the partition protects')
case('R3', 'fastapi_jsonresponse_preexisting_gap', 'CWE-209', 'm.py',
     at(L_FASTAPI_JSONRESPONSE, 'return JSONResponse'),
     'quiet', 'error_group_off_arm', 'quiet', L_FASTAPI_JSONRESPONSE,
     'QUIET AT HEAD: name absent from RESPONSE_CONSTRUCTOR_NAMES')

# --------------------------------------------------------------------------- R4 fixtures
# Scanned under the filename that caused the bleed, so the fixture reproduces the row rather than
# describing it. The clause itself never reads this name.
MESSAGE_DIGEST = module(
    'import hashlib',
    'def cache_key(message_content):',
    '    digest = hashlib.sha256(message_content.encode()).digest()',
    '    return digest.hex()')
L_PASSWORD = module(
    'import hashlib',
    'def store(password):',
    '    return hashlib.sha256(password.encode()).hexdigest()')
L_USER_PWD_MD5 = module(
    'import hashlib',
    'def store(user_pwd):',
    '    return hashlib.md5(user_pwd.encode()).hexdigest()')
PW_FUNC_NAME = module(
    'import hashlib',
    'def hash_password(value):',
    '    return hashlib.sha256(value.encode()).hexdigest()')
PW_PARAM_NAME = module(
    'import hashlib',
    'def store(passphrase):',
    '    return hashlib.sha256(passphrase.encode()).hexdigest()')

case('R4', 'message_digest_916_retired', 'CWE-916', 'secret_detection.py',
     at(MESSAGE_DIGEST, 'digest = hashlib.sha256'), 'quiet', 'password_scope_off_arm', 'loud',
     MESSAGE_DIGEST, 'the verbatim cache/dedup digest')
case('R4', 'message_digest_759_retired', 'CWE-759', 'secret_detection.py',
     at(MESSAGE_DIGEST, 'digest = hashlib.sha256'), 'quiet', 'password_scope_off_arm', 'loud',
     MESSAGE_DIGEST, 'the salt co-fire on the same line')
case('R4', 'password_sha256_kept', 'CWE-916', 'secret_detection.py',
     at(L_PASSWORD, 'return hashlib.sha256'), 'loud', 'password_scope_off_arm', 'loud',
     L_PASSWORD, 'MANDATED loud control')
case('R4', 'password_md5_kept', 'CWE-916', 'secret_detection.py',
     at(L_USER_PWD_MD5, 'return hashlib.md5'), 'loud', 'password_scope_off_arm', 'loud',
     L_USER_PWD_MD5, 'MANDATED loud control')
case('R4', 'password_md5_328_kept', 'CWE-328', 'secret_detection.py',
     at(L_USER_PWD_MD5, 'return hashlib.md5'), 'loud', 'password_scope_off_arm', 'loud',
     L_USER_PWD_MD5, 'the weak-digest co-fire')
case('R4', 'function_name_provenance_closer', 'CWE-916', 'm.py',
     at(PW_FUNC_NAME, 'return hashlib.sha256'), 'loud', 'password_scope_blind_arm', 'quiet',
     PW_FUNC_NAME, 'FN-CLOSER: quiet at HEAD, the function name is provenance')
case('R4', 'passphrase_preexisting_gap', 'CWE-916', 'm.py',
     at(PW_PARAM_NAME, 'return hashlib.sha256'), 'quiet', 'password_scope_off_arm', 'quiet',
     PW_PARAM_NAME, 'QUIET AT HEAD: CWE3A_PASSWORD_NAME_RE does not spell passphrase')

# --------------------------------------------------------------------------- R5 fixtures
S_DOCKER_TEST = 'DATABASE_URL="postgresql://postgres:postgres@host.docker.internal:5432/litellm_test"' + NL
S_LOCALHOST = 'DATABASE_URL="postgresql://postgres:postgres@localhost:5432/app"' + NL
S_LOOPBACK = 'DATABASE_URL="mysql://root:root@127.0.0.1:3306/app"' + NL
S_IPV6 = 'DATABASE_URL="postgresql://admin:admin@[::1]:5432/app"' + NL
S_PROD = 'DATABASE_URL="postgresql://produser:S3cr3tP4ss!@db.prod.company.com:5432/app"' + NL
S_REMOTE_DEFAULT = 'DATABASE_URL="postgresql://postgres:postgres@db.internal:5432/app"' + NL
S_DOCKER_REAL = 'DATABASE_URL="postgresql://produser:S3cr3tP4ss!@host.docker.internal:5432/app"' + NL
S_REAL_KEY = 'OPENAI_API_KEY="sk-proj-abc123XYZdef456UVWghi789RSTjkl012MNO"' + NL
S_SCRIPTED = '      "GEMINI_API_KEY=sk-scripted-provider"' + NL
S_ENV_REF = 'LITELLM_MASTER_KEY="$LITELLM_MASTER_KEY"' + NL

CONFIG_CASES = [
    ('docker_test_url_retired', S_DOCKER_TEST, 0, 'local_hosts_off_arm', 1,
     'the verbatim Docker-internal test URL'),
    ('localhost_url_control', S_LOCALHOST, 0, 'local_hosts_off_arm', 0, 'already refused at HEAD'),
    ('loopback_url_control', S_LOOPBACK, 0, 'local_hosts_off_arm', 0, 'already refused at HEAD'),
    ('ipv6_url_control', S_IPV6, 0, 'local_hosts_off_arm', 0, 'already refused at HEAD'),
    ('prod_url_kept', S_PROD, 1, 'local_hosts_off_arm', 1, 'MANDATED loud control'),
    ('remote_default_creds_kept', S_REMOTE_DEFAULT, 1, 'local_hosts_off_arm', 1,
     'default creds on a REMOTE host are still a credential'),
    ('docker_real_password_kept', S_DOCKER_REAL, 1, 'local_hosts_off_arm', 1,
     'a real password on the Docker gateway is still a credential'),
    ('real_api_key_kept', S_REAL_KEY, 1, 'local_hosts_off_arm', 1, 'MANDATED: real key detection intact'),
    ('env_reference_control', S_ENV_REF, 0, 'local_hosts_off_arm', 0, 'INTERPOLATION already refuses it'),
    ('scripted_provider_not_retired', S_SCRIPTED, 1, 'local_hosts_off_arm', 1,
     'BUG 5(b) DECLINED: no deterministic test separates it from a real lowercase key'),
]

ZERO_ROW_FIXTURES = {
    'iso_datetime': ('m.py', ISO_DATETIME),
    'slack_token': ('m.py', SLACK_TOKEN),
    'delimiter_loop': ('m.py', DELIMITER_LOOP),
    'adafruit_bounded': ('m.py', ADAFRUIT_BOUNDED),
    'json_response': ('m.py', JSON_RESPONSE),
    'json_response_route': ('m.py', JSON_RESPONSE_ROUTE),
    'plain_media': ('m.py', PLAIN_MEDIA),
    'event_stream': ('m.py', EVENT_STREAM),
    'problem_json': ('m.py', PROBLEM_JSON),
    'bare_exc_return': ('m.py', BARE_EXC_RETURN),
    'cli_json_helper': ('m.py', CLI_JSON_HELPER),
    'cli_oserror_helper': ('m.py', CLI_OSERROR_HELPER),
    'message_digest': ('secret_detection.py', MESSAGE_DIGEST),
}


# --------------------------------------------------------------------------- TIER 4 arms
def _always_unbounded(maximum):
    """HEAD: adjacency never asked whether either repeat had a ceiling."""
    return True


def _multiplies_unbounded(maximum):
    """The WRONG test: a large bounded ceiling is not an unbounded one."""
    return maximum is None or maximum >= ast_scanner.REGEX_MULTIPLYING_BOUND


def _media_no_svg(text):
    """The shipped media test with the SVG exclusion removed, so `image/` covers image/svg+xml."""
    if not isinstance(text, str):
        return False
    lowered = text.strip().lower()
    if not lowered or 'html' in lowered:
        return False
    head = lowered.split(';', 1)[0].strip()
    return any(head.startswith(prefix) for prefix in ast_scanner._NON_HTML_MEDIA_PREFIXES)


_HEAD_MEDIA_PREFIXES = ('application/json', 'text/json', 'text/xml', 'application/xml',
                        'text/csv', 'application/octet-stream', 'application/pdf',
                        'application/postscript', 'text/plain',
                        'image/', 'font/', 'woff', 'video/', 'audio/')
_HEAD_LOCAL_HOSTS = frozenset({'localhost', '127.0.0.1', '0.0.0.0', '::1'})

ARMS = {
    'redos_bound_off_arm': (('ast_scanner', '_t26_repeat_is_unbounded', _always_unbounded),),
    'redos_bound_blind_arm': (('ast_scanner', '_t26_repeat_is_unbounded', _multiplies_unbounded),),
    'media_keyword_off_arm': (('ast_scanner', 'RESPONSE_MEDIA_KEYWORDS',
                               frozenset({'content_type', 'mimetype'})),),
    'media_svg_blind_arm': (('ast_scanner', 'media_type_is_not_html', _media_no_svg),),
    'media_vocab_off_arm': (('ast_scanner', '_NON_HTML_MEDIA_PREFIXES', _HEAD_MEDIA_PREFIXES),),
    'error_group_off_arm': (('T', '_t26_catches_declared_error_group',
                             staticmethod(lambda node, tree: False)),),
    'string_error_off_arm': (('T', '_t26_is_string_error_return',
                              lambda self, ret_node, handler_name: False),),
    'web_context_off_arm': (('T', '_c209_web_context_around', lambda self, value: False),),
    'string_reply_off_arm': (('T', '_t26_string_reply_without_web_context',
                              lambda self, value: False),),
    'password_scope_off_arm': (('ast_scanner', '_t26_password_scope_names',
                                lambda mod_name, functions, lineno, cache: {mod_name}),),
    'password_scope_blind_arm': (('ast_scanner', '_t26_password_scope_names',
                                  lambda mod_name, functions, lineno, cache: set()),),
    'local_hosts_off_arm': (('secret_scanner', 'LOCAL_SERVICE_HOSTS', _HEAD_LOCAL_HOSTS),),
}


def _apply(patches, function):
    saved = []
    try:
        for owner, attribute, replacement in patches:
            target = OWNERS[owner]
            if not hasattr(target, attribute):
                raise AssertionError(f'no such clause: {owner}.{attribute}')
            # getattr_static, not getattr: attribute access UNWRAPS a staticmethod into a plain
            # function, and restoring that plain function onto the class rebinds `self` and breaks
            # every later call. The descriptor itself has to be saved.
            saved.append((target, attribute, inspect.getattr_static(target, attribute)))
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


def config_case_rows(source, state='ship'):
    key = ('configrows', state, source)
    if key not in _CACHE:
        _CACHE[key] = _apply(() if state == 'ship' else ARMS[state],
                             lambda: config_rows(source, state))
    return _CACHE[key]


def _release():
    """Drop every weakened-state memo and collect, so the arms do not stack up scanners."""
    for key in [k for k in _CACHE if k[1] != 'ship']:
        del _CACHE[key]
    gc.collect()


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
            print(f'  {now:5s} arm={arm:5s} {receipt:11s} {entry["label"]:44s} {entry["note"][:44]}')
            if now != entry['expect']:
                failures.append(f'{pocket}/{entry["label"]}: shipped {now}, want {entry["expect"]}')
            if arm != entry['arm_expect']:
                failures.append(f'{pocket}/{entry["label"]}: arm-off {arm}, want {entry["arm_expect"]}')
    _release()
    return failures


def check_config_retirements():
    """TIER 1c -- the line-based config reader, which the AST harness cannot reach."""
    print('\nTIER 1c  R5 secret reader (line-based, not the AST engine)')
    failures = []
    for label, source, expect, arm, arm_expect, note in CONFIG_CASES:
        shipped = len(config_case_rows(source))
        reverted = len(config_case_rows(source, arm))
        booked = (expect, reverted) == (0, 1)
        receipt = 'BOOKED' if booked else ('CONTROL' if expect == reverted else 'not booked')
        print(f'  hits={shipped} arm={reverted} {receipt:11s} {label:38s} {note[:46]}')
        if shipped != expect:
            failures.append(f'R5/{label}: shipped {shipped} hits, want {expect}')
        if reverted != arm_expect:
            failures.append(f'R5/{label}: arm-off {reverted} hits, want {arm_expect}')
    _release()
    return failures


def check_fixtures_parse():
    """TIER 0 -- every fixture is valid Python.

    A fixture that does not parse yields ZERO rows, which reads exactly like a successful retirement.
    No quiet verdict in this gate is trusted until its source parses.
    """
    print('\nTIER 0  every fixture parses')
    sources = {entry['source'] for entry in CASES} | {src for _n, src in ZERO_ROW_FIXTURES.values()}
    failures = []
    for source in sorted(sources):
        try:
            ast.parse(source)
        except SyntaxError as error:
            failures.append(f'fixture does not parse: {error}: {source.splitlines()[:3]}')
    print(f'  {"OK  " if not failures else "FAIL"} {len(sources)} distinct fixture sources')
    return failures


def check_zero_rows():
    """TIER 1b -- the verbatim reproducers produce NO row at all, of any CWE."""
    print('\nTIER 1b  zero-row contract on every verbatim reproducer')
    failures = []
    for label, (name, source) in ZERO_ROW_FIXTURES.items():
        rows = fixture_rows(source, 'ship', name)
        print(f'  {"OK  " if not rows else "FAIL"} {label:38s} rows={len(rows)}')
        if rows:
            failures.append(f'{label}: {len(rows)} rows, want 0 -> {rows}')
    return failures


# --------------------------------------------------------------------------- TIER 2 predicates
_TRACKER = None


def tracker():
    global _TRACKER
    if _TRACKER is None:
        with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
            _TRACKER = T(files={'m.py': 'x = 1\n'}, max_workers=1)
    return _TRACKER


def _handler(source):
    """The first ExceptHandler and its MODULE: the group test reads module-level assignments."""
    tree = link(ast.parse(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            return node, tree
    raise AssertionError('no except handler in the fixture')


def _return_value(source, needle):
    line = at(source, needle)
    for node in ast.walk(link(ast.parse(source))):
        if isinstance(node, ast.Return) and node.lineno == line:
            return node
    raise AssertionError(f'no return on line {line}')


def _call_on(source, needle):
    line = at(source, needle)
    for node in ast.walk(link(ast.parse(source))):
        if isinstance(node, ast.Call) and node.lineno == line:
            return node
    raise AssertionError(f'no call on line {line}')


def _functions(source, mod_name='m'):
    """The (scope, node) pairs the structural collector hands the provenance helper."""
    tree = ast.parse(source)
    pairs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            pairs.append((f'{mod_name}:function:{node.name}', node))
    return {mod_name: pairs}


PROBES = {}


def probe(name, description):
    def register(function):
        PROBES[name] = (description, function)
        return function
    return register


@probe('c1333_unbounded_sentinel', 'MAXREPEAT and None are unbounded; a fixed ceiling never is')
def _():
    test = ast_scanner._t26_repeat_is_unbounded
    return (test(re._constants.MAXREPEAT) is True and test(None) is True
            and test(13) is False and test(20) is False and test(3) is False and test(1) is False)


@probe('c1333_bounded_literals_linear', 'the four verbatim literals are linear, the evil ones are not')
def _():
    test = ast_scanner._is_redos_vulnerable_pattern
    safe = [ISO_DATETIME, SLACK_TOKEN, ADAFRUIT_BOUNDED, DELIMITER_LOOP, NESTED_BOUNDED]
    evil = ['(a+)+$', '([a-z]+)*$', 'a*a*', '(a|aa)+$']
    literals = []
    for source in safe:
        node = _call_on(source, 're.compile')
        literals.append(node.args[0].value)
    return (all(test(text) is False for text in literals)
            and all(test(text) is True for text in evil))


@probe('c79_media_vocabulary', 'non-document types are refused, HTML and SVG are not')
def _():
    test = ast_scanner.media_type_is_not_html
    safe = ['application/json', 'text/plain', 'text/csv', 'application/octet-stream',
            'application/pdf', 'text/event-stream', 'application/problem+json', 'image/png',
            'image/jpeg', 'image/webp', 'application/json; charset=utf-8', 'TEXT/PLAIN']
    carrier = ['text/html', 'application/xhtml+xml', 'image/svg+xml',
               'image/svg+xml; charset=utf-8', '', None, 7, 'text/html; charset=utf-8']
    return (all(test(text) is True for text in safe)
            and all(test(text) is False for text in carrier))


@probe('c79_svg_is_a_document', 'the image/ prefix cannot silence an SVG carrier')
def _():
    return ('image/' in ast_scanner._NON_HTML_MEDIA_PREFIXES
            and ast_scanner.media_type_is_not_html('image/png') is True
            and ast_scanner.media_type_is_not_html('image/svg+xml') is False)


@probe('c79_media_keyword_vocabulary', 'all three framework spellings are one vocabulary')
def _():
    keywords = ast_scanner.RESPONSE_MEDIA_KEYWORDS
    if keywords != frozenset({'content_type', 'mimetype', 'media_type'}):
        return False
    test = ast_scanner._response_media_header_is_not_html
    for keyword in sorted(keywords):
        source = module('from fastapi import Response', 'def h(request):',
                        '    d = request.GET["d"]',
                        f'    return Response(content=d, {keyword}="application/json")')
        if test(_call_on(source, 'return Response'), {}, 'm:global', 4) is not True:
            return False
    html = module('from fastapi import Response', 'def h(request):',
                  '    d = request.GET["d"]',
                  '    return Response(content=d, media_type="text/html")')
    return test(_call_on(html, 'return Response'), {}, 'm:global', 4) is False


@probe('c209_declared_group', 'only a module-declared tuple/list aggregate is a group')
def _():
    test = T._t26_catches_declared_error_group
    yes, tree = _handler(BARE_EXC_RETURN)
    listed, ltree = _handler(L_GROUP_REPR)
    direct, dtree = _handler(BLESSED_DIRECT_CLASS)
    inline, itree = _handler(module('def f():', '    try:', '        pass',
                                    '    except (OSError, ValueError) as e:', '        return e'))
    unknown, utree = _handler(module('_ERRORS = (OSError,)', 'def f():', '    try:', '        pass',
                                     '    except _OTHER as e:', '        return e'))
    scalar, stree = _handler(module('_ERRORS = OSError', 'def f():', '    try:', '        pass',
                                    '    except _ERRORS as e:', '        return e'))
    return (test(yes, tree) is True and test(listed, ltree) is True
            and test(direct, dtree) is False and test(inline, itree) is False
            and test(unknown, utree) is False and test(scalar, stree) is False)


@probe('c209_string_forms', 'str/repr/format_exc are text; a bare object is not')
def _():
    test = tracker()._t26_is_string_error_return
    str_ret = _return_value(L_GROUP_STR, 'return str(error)')
    repr_ret = _return_value(L_GROUP_REPR, 'return repr(error)')
    bare_ret = _return_value(BARE_EXC_RETURN, 'return error')
    tb_ret = _return_value(L_FLASK_TRACEBACK, 'return traceback.format_exc')
    other_ret = _return_value(module('def f(e):', '    try:', '        pass',
                                     '    except OSError as e:', '        return str(value)'),
                              'return str(value)')
    return (test(str_ret, 'error') is True and test(repr_ret, 'error') is True
            and test(tb_ret, None) is True and test(bare_ret, 'error') is False
            and test(other_ret, 'e') is False and test(str_ret, None) is False)


@probe('c209_web_context', 'a route, a web argument or a web import is context; a CLI is not')
def _():
    test = tracker()._c209_web_context_around
    route = _return_value(L_FSTRING_ROUTE, 'return f"<cannot read')
    imported = _return_value(L_BARE_EXC_IMPORT, 'return error')
    cli = _return_value(CLI_OSERROR_HELPER, 'return f"<cannot read')
    argument = _return_value(module('def view(request):', '    try:', '        pass',
                                    '    except OSError as e:', '        return f"{e}"'),
                             'return f"{e}"')
    orphan = ast.Return(value=ast.Constant(value='x'))
    return (test(route) is True and test(imported) is True and test(argument) is True
            and test(cli) is False and test(orphan) is False)


@probe('c209_string_reply_needs_web', 'an f-string reply is refused only with no client anywhere')
def _():
    test = tracker()._t26_string_reply_without_web_context
    cli = _return_value(CLI_OSERROR_HELPER, 'return f"<cannot read')
    route = _return_value(L_FSTRING_ROUTE, 'return f"<cannot read')
    return (test(cli.value) is True and test(route.value) is False
            and test(ast.Constant(value='plain')) is False
            and test(ast.Dict(keys=[], values=[])) is False)


@probe('c916_scope_is_not_the_filename', 'the module name is never provenance; the function is')
def _():
    test = ast_scanner._t26_password_scope_names
    functions = _functions(PW_FUNC_NAME, 'secret_detection')
    names = test('secret_detection', functions, 3, {})
    return ('hash_password' in names and 'value' in names
            and 'secret_detection' not in names and 'secret' not in ' '.join(names))


@probe('c916_innermost_function_wins', 'the tightest enclosing span supplies the spellings')
def _():
    test = ast_scanner._t26_password_scope_names
    source = module('import hashlib', 'def outer(password):', '    def inner(message_content):',
                    '        return hashlib.sha256(message_content.encode()).hexdigest()',
                    '    return inner')
    functions = _functions(source)
    inner = test('m', functions, 4, {})
    outer = test('m', functions, 5, {})
    return ('inner' in inner and 'message_content' in inner and 'password' not in inner
            and 'outer' in outer and 'password' in outer)


@probe('c916_scope_memoised_per_module', 'the span table is built once and reused')
def _():
    test = ast_scanner._t26_password_scope_names
    functions = _functions(PW_FUNC_NAME)
    cache = {}
    first = test('m', functions, 3, cache)
    if 'm' not in cache:
        return False
    spans = cache['m']
    second = test('m', functions, 3, cache)
    return first == second and cache['m'] is spans


@probe('c798_local_hosts_vocabulary', 'the Docker gateway is local; a remote host is not')
def _():
    hosts = secret_scanner.LOCAL_SERVICE_HOSTS
    return ({'localhost', '127.0.0.1', '0.0.0.0', '::1', 'host.docker.internal'} <= hosts
            and 'db.internal' not in hosts and 'db.prod.company.com' not in hosts)


@probe('c798_dev_default_needs_both_halves', 'user==password AND a local host, never either alone')
def _():
    test = secret_scanner._service_credential_is_dev_default
    return (test('postgresql://postgres:postgres@host.docker.internal:5432/litellm_test') is True
            and test('postgresql://postgres:postgres@localhost:5432/app') is True
            and test('postgresql://admin:admin@[::1]:5432/app') is True
            and test('postgresql://postgres:postgres@db.internal:5432/app') is False
            and test('postgresql://produser:S3cr3tP4ss!@host.docker.internal:5432/app') is False
            and test('postgresql://produser:S3cr3tP4ss!@db.prod.company.com:5432/app') is False)


@probe('c798_real_key_detection_intact', 'a real key is still refused nothing, a dummy env ref is')
def _():
    refused = secret_scanner.is_refused
    return (refused('sk-proj-abc123XYZdef456UVWghi789RSTjkl012MNO', named=True) is False
            and refused('$LITELLM_MASTER_KEY', named=True) is True
            and refused('${API_KEY}', named=True) is True
            and refused('sk-scripted-provider', named=True) is False)


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
        print(f'  {"OK  " if ok else "FAIL"} {name:48s} {description}')
        if not ok:
            failures.append(f'predicate {name}: {description}')
    return failures


# --------------------------------------------------------------------------- TIER 3 shipped shapes
def _body_source(func):
    """The executable source of a clause, docstring stripped.

    A law that asks "does this clause read a filename?" must not be answered by the prose explaining
    which filename caused the bug. Only the code is read.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    node = tree.body[0]
    if (node.body and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)):
        node.body = node.body[1:]
    return ast.unparse(node)


_UNBOUNDED = _body_source(ast_scanner._t26_repeat_is_unbounded)
_REDOS = _body_source(ast_scanner._regex_catastrophic_backtracking)
_MEDIA = _body_source(ast_scanner.media_type_is_not_html)
_HEADER = _body_source(ast_scanner._response_media_header_is_not_html)
_SCOPE = _body_source(ast_scanner._t26_password_scope_names)
_GROUP = _body_source(T._t26_catches_declared_error_group)
_STRFORM = _body_source(T._t26_is_string_error_return)
_WEBCONTEXT = _body_source(T._c209_web_context_around)
_STRREPLY = _body_source(T._t26_string_reply_without_web_context)
_DEVDEFAULT = _body_source(secret_scanner._service_credential_is_dev_default)
_BATCH2 = _body_source(T._collect_batch2_structural_findings)
_BATCH3A = _body_source(T._collect_batch3a_structural_findings)
_REPLY = _body_source(T._c209_exposed_in_reply)

LAWS = (
    ('R1 the unbounded test is an equality against the MAXREPEAT sentinel, not a size comparison',
     lambda: 'maximum == re._constants.MAXREPEAT' in _UNBOUNDED
             and 'REGEX_MULTIPLYING_BOUND' not in _UNBOUNDED),
    ('R1 adjacency asks the unbounded test on BOTH neighbours, and nested repetition still multiplies',
     lambda: 'unbounded = _t26_repeat_is_unbounded(maximum)' in _REDOS
             and 'if unbounded and previous_repeat_unbounded' in _REDOS
             and 'if inside_repeat and multiplies' in _REDOS),
    ('R2 one keyword vocabulary covers all three framework spellings',
     lambda: ast_scanner.RESPONSE_MEDIA_KEYWORDS == frozenset({'content_type', 'mimetype', 'media_type'})
             and 'kw.arg in RESPONSE_MEDIA_KEYWORDS' in _HEADER),
    ('R2 SVG is excluded before the prefix list is consulted',
     lambda: "if 'svg' in lowered:" in _MEDIA
             and _MEDIA.index("'svg'") < _MEDIA.index('_NON_HTML_MEDIA_PREFIXES')
             and 'text/event-stream' in ast_scanner._NON_HTML_MEDIA_PREFIXES
             and 'application/problem+json' in ast_scanner._NON_HTML_MEDIA_PREFIXES),
    ('R3 the bare-object refusal needs all three halves: text form, web context, declared group',
     lambda: 'self._t26_is_string_error_return' in _BATCH2
             and 'self._c209_web_context_around(node)' in _BATCH2
             and 'not self._t26_catches_declared_error_group(node, tree)' in _BATCH2),
    ('R3 the group test reads a module-level tuple/list assignment and nothing else',
     lambda: 'isinstance(caught, ast.Name)' in _GROUP
             and 'isinstance(statement.value, (ast.Tuple, ast.List))' in _GROUP
             and 'for statement in tree.body' in _GROUP),
    ('R3 the text-form test names str/repr/format_exc and requires the handler binding',
     lambda: "fn in ('traceback.format_exc', 'format_exc')" in _STRFORM
             and "fn in ('str', 'repr')" in _STRFORM
             and 'value.args[0].id == handler_name' in _STRFORM),
    ('R3 an unproven parent chain keeps the finding rather than retiring it',
     lambda: 'if current is None:' in _WEBCONTEXT and 'return False' in _WEBCONTEXT
             and 'CWE209_WEB_FRAMEWORK_ROOTS' in _WEBCONTEXT
             and 'CWE209_WEB_CONTEXT_ARGUMENTS' in _WEBCONTEXT),
    ('R3 the string-reply refusal is gated on JoinedStr/BinOp and delegates to the web-context test',
     lambda: 'isinstance(value, (ast.JoinedStr, ast.BinOp))' in _STRREPLY
             and 'return not self._c209_web_context_around(value)' in _STRREPLY
             and 'if self._t26_string_reply_without_web_context(value):' in _REPLY),
    ('R4 provenance is the enclosing function, and the module name is only a cache key',
     lambda: 'CWE3A_PASSWORD_NAME_RE' not in _SCOPE
             and 'fnode.name' in _SCOPE and 'fnode.args' in _SCOPE
             and 'cache[mod_name] = spans' in _SCOPE
             and '_t26_password_scope_names(' in _BATCH3A
             and 'for scope_cand in (scope_id, name):' not in _BATCH3A),
    ('R5 the dev-default refusal needs the password to equal the username AND a local host',
     lambda: 'if not colon or user != password:' in _DEVDEFAULT
             and 'return _service_host(host) in LOCAL_SERVICE_HOSTS' in _DEVDEFAULT
             and 'host.docker.internal' in secret_scanner.LOCAL_SERVICE_HOSTS),
    ('no new clause reads a repository, a folder or a filename in its executable code',
     lambda: all(word not in _UNBOUNDED + _MEDIA + _HEADER + _SCOPE + _GROUP + _STRFORM
                 + _WEBCONTEXT + _STRREPLY + _DEVDEFAULT
                 for word in ('litellm', 'secret_detection', 'ansible', 'adafruit', 'xoxb',
                              'circleci', 'run_integration', 'tests/', 'examples/', 'docs/',
                              'os.path', 'file_path', '__file__'))),
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
_R1_BOOKED = ['iso_datetime_retired', 'slack_token_retired', 'adafruit_bounded_retired']
_R2_KEYWORD_BOOKED = ['json_media_type_retired', 'json_media_type_route_retired', 'plain_media_retired']
_R2_VOCAB_BOOKED = ['event_stream_retired', 'problem_json_retired']
_R2_SVG_KEPT = ['svg_media_kept', 'svg_charset_kept']
_R3_GROUP_BOOKED = ['bare_exception_object_retired']
_R3_STRING_KEPT = ['group_str_return_kept', 'group_repr_return_kept']
_R3_REPLY_BOOKED = ['cli_json_helper_retired', 'cli_oserror_helper_retired']
_R4_BOOKED = ['message_digest_916_retired', 'message_digest_759_retired']

MUTATIONS = {
    'r1_adjacency_bound_test_removed': (
        'R1: HEAD restored -- adjacency never asks for a ceiling, so the three bounded literals report',
        'redos_bound_off_arm', _R1_BOOKED,
        ['c1333_unbounded_sentinel', 'c1333_bounded_literals_linear']),
    'r1_adjacency_uses_multiplies': (
        'R1: the wrong test -- a large bounded ceiling counts as unbounded, so {10,13} reports again',
        'redos_bound_blind_arm', ['slack_token_retired'],
        ['c1333_unbounded_sentinel', 'c1333_bounded_literals_linear']),
    'r2_media_type_keyword_removed': (
        'R2: HEAD spelling restored -- media_type is unread, so all three FastAPI JSON/plain rows report',
        'media_keyword_off_arm', _R2_KEYWORD_BOOKED + _R2_VOCAB_BOOKED,
        ['c79_media_keyword_vocabulary']),
    'r2_svg_exclusion_removed': (
        'R2: the image/ prefix covers SVG, so both SVG carriers go quiet -- a real XSS hole',
        'media_svg_blind_arm', _R2_SVG_KEPT,
        ['c79_media_vocabulary', 'c79_svg_is_a_document']),
    'r2_media_vocabulary_reverted': (
        'R2: HEAD prefix list restored -- event-stream and problem+json report again',
        'media_vocab_off_arm', _R2_VOCAB_BOOKED, ['c79_media_vocabulary']),
    'r3_declared_group_test_removed': (
        'R3: no handler is a declared group, so the bare exception object reports again',
        'error_group_off_arm', _R3_GROUP_BOOKED, ['c209_declared_group']),
    'r3_text_form_test_removed': (
        'R3: str/repr are treated as objects, so both text disclosures inside a group go quiet',
        'string_error_off_arm', _R3_STRING_KEPT, ['c209_string_forms']),
    'r3_web_context_blinded': (
        'R3: no node ever has web context, so the route f-string goes quiet -- a real disclosure hole',
        'web_context_off_arm', ['fstring_in_route_kept'],
        ['c209_web_context', 'c209_string_reply_needs_web']),
    'r3_string_reply_refusal_removed': (
        'R3: HEAD restored -- any f-string is a response body, so both CLI helpers report again',
        'string_reply_off_arm', _R3_REPLY_BOOKED, ['c209_string_reply_needs_web']),
    'r4_filename_provenance_restored': (
        'R4: HEAD restored -- the module name is searched, so the digest reports and the closer goes quiet',
        'password_scope_off_arm', _R4_BOOKED + ['function_name_provenance_closer'],
        ['c916_scope_is_not_the_filename', 'c916_innermost_function_wins',
         'c916_scope_memoised_per_module']),
    'r4_function_provenance_blinded': (
        'R4: no scope spellings at all, so the function-name FN-closer goes quiet',
        'password_scope_blind_arm', ['function_name_provenance_closer'],
        ['c916_scope_is_not_the_filename', 'c916_innermost_function_wins',
         'c916_scope_memoised_per_module']),
    'r5_docker_gateway_removed': (
        'R5: HEAD host list restored -- the Docker-internal test URL reports a credential again',
        'local_hosts_off_arm', ['R5/docker_test_url_retired'],
        ['c798_local_hosts_vocabulary', 'c798_dev_default_needs_both_halves']),
}


def run_mutation(name):
    """Weaken one clause and report every row and predicate that moved.

    The baseline is read BEFORE the weakening is installed; reading it afterwards compares the
    mutated gate with itself and reports every mutation as MISSED.
    """
    description, state, expected_rows, expected_probes = MUTATIONS[name]
    moved = [entry['label'] for entry in CASES
             if loud(case_rows(entry), entry['name'], entry['cwe'], entry['line'])
             != loud(case_rows(entry, state), entry['name'], entry['cwe'], entry['line'])]
    moved += [f'R5/{label}' for label, source, _e, _a, _ae, _n in CONFIG_CASES
              if len(config_case_rows(source)) != len(config_case_rows(source, state))]
    flipped = [key for key in sorted(PROBES)
               if (probe_value(key) is True) != (probe_value(key, state) is True)]
    _release()
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
        print(f'  {"CAUGHT" if ok else "MISSED"} {name:40s} rows={len(moved)} probes={flipped} '
              f'({elapsed:.2f}s rss={rss_mb():.0f}MB)')
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
    for label, source, _e, _a, _ae, _n in CONFIG_CASES:
        print(f'\n=== R5 {label}')
        for row in config_case_rows(source):
            print('   ', row)


def main():
    argv = sys.argv[1:]
    only = next((a.split('=', 1)[1] for a in argv if a.startswith('--mutate=')), None)
    if only and only not in MUTATIONS:
        print(f'unknown mutation {only}; known: {sorted(MUTATIONS)}')
        return 2
    started = time.perf_counter()
    failures = []
    if '--dump' in argv:
        dump()
        return 0
    if not only:
        failures += check_fixtures_parse()
        failures += check_retirements()
        failures += check_config_retirements()
        failures += check_zero_rows()
        failures += check_predicates()
        failures += check_laws()
    failures += check_mutations(only)
    work = time.perf_counter() - started
    peak = rss_mb()
    total = len(CASES) + len(CONFIG_CASES)
    booked = sum(1 for entry in CASES if entry['expect'] == 'quiet' and entry['arm_expect'] == 'loud')
    booked += sum(1 for _l, _s, expect, _a, arm_expect, _n in CONFIG_CASES
                  if (expect, arm_expect) == (0, 1))
    loud_cases = sum(1 for entry in CASES if entry['expect'] == 'loud')
    print(f'\ncases={total} clause_retirements={booked} expected_loud={loud_cases} '
          f'zero_row_fixtures={len(ZERO_ROW_FIXTURES)} '
          f'probes={len(PROBES)} laws={len(LAWS)} '
          f'mutations={len(MUTATIONS) if not only else 1} '
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