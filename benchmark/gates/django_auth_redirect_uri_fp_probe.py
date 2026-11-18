"""Gate #66 -- three Django/Zulip framework FP factories, each one held by its own falsifier.

What this task moved, measured against the corpus and the fixtures rather than asserted:

  C1  VALIDATED REDIRECTS AND ANCHORED INTERNAL TEMPLATES (CWE-601). Zulip's `login_view` hands
      `next` to its own `get_safe_redirect_to(next, realm.url)` and redirects with the result, and the
      row survived because nothing proved the wrapper validates anything. The refusal now reads the
      wrapper's body in the same file: a call excuses the redirect only when the function that owns
      that name calls one of the five mandated validators on a parameter and returns something built
      from that same parameter. `def get_safe_redirect_to(url, host): return url` -- the name without
      the check -- stays loud, and so does a body that validates and then returns something else. The
      second half is the template: `redirect(f"/search/?q={request.GET['q']}")` cannot change origin,
      because the first literal chunk starts with exactly one `/` and everything the client controls
      sits behind `?` or `#`. A chained destination inside that query (`?next=`) keeps its row, which
      is the policy the `%`-format branch of the same-origin clause already applies, and so does
      client data in a path segment: `f"/users/{request.GET['u']}"` is the sibling of the mandated-loud
      `"/" + user_input`, and a rule that excuses one while refusing the other is a name game, not a
      proof.

  C2  EXPLICIT AUTH AND CSRF DECORATORS (CWE-862, CWE-352). `@csrf_exempt` on a view that is also
      `@require_post` or `@webhook_view('GCP')` reports a missing CSRF control that the framework
      enforces two lines away, and `@zulip_login_required` reports a view with no authorization at
      all. Both vocabularies are consulted, and in both cases the name alone is not the guard: the
      decorator has to be imported from a module that owns such a decorator (`zerver.decorator`,
      `django.contrib.auth.decorators`, `django.views.decorators.http`, ...). A locally defined
      `def require_post(view_func): return view_func`, a `zulip_login_required` imported from
      `zerver.types`, `@typed_endpoint` with no auth decorator and `@cache_page` all keep reporting.
      `@require_safe` deliberately is not in the CSRF set: a read-only guard says nothing about the
      state-changing case that the rule exists to protect.

  C3  STATIC CUSTOM URI SCHEMES (CWE-939). `urlopen(f"salt://states/{kind}.sls")` is an internal
      URI scheme a browser or transport cannot fetch, so the "arbitrary custom scheme handler" row is
      noise. The scheme is read off the constant prefix -- the head chunk of a template, the left side
      of a concatenation, or the literal itself -- and the row is refused only when that prefix
      resolves to a scheme that is not in the transportable set. `f"https://{request.GET['h']}/x"`,
      `f"ht{kind}ps://host/x"` (no scheme in the constant head) and `urlopen(req)` (no prefix to read
      at all) answer False and stay loud; the tainted-URL rows the sentry tiers pin keep reporting.

Corpus effect, measured on the 34 `.py` files of the local Zulip snapshot: 100 rows -> 91. CWE-601
22 -> 19 (`zerver/views/auth.py` 985/987/988, all three `get_safe_redirect_to`), CWE-352 10 -> 4
(`auth.py` 659/1127/1171, `zilencer/views.py` 139/182/216, and every one of those six goes loud again
when the import-home vocabulary is emptied, so none of them is bought with a name match). CWE-862 is
5 -> 5 and CWE-939 0 -> 0 on this snapshot: the two named files that carry them (`registration.py`,
`portico.py`, and the `zulip://` snippet cache) are not in the local copy, so those clauses are held by
the fixtures below and by the salt/sentry gates, not by a corpus delta. The same-function validator
refusal and the constant-literal scheme refusal were already shipped before this task; each is kept
here as a control so this gate cannot claim credit for an older proof.

TIER 1 reads every case twice against one shared fixture: its shipped verdict, and its verdict with the
owning clause reverted. A retirement whose arm column is still quiet is not booked -- some older clause
owns it; a row that goes quiet only when the clause is blinded is counted as an FN-CLOSER, because that
is the false negative the guard is there to prevent. TIER 2 calls the shipped predicates directly.
TIER 3 reads the shipped source and asks it to keep the shape each proof depends on. TIER 4 is the
falsifiers: one weakening per clause, and an exact set of rows and predicates must move.

Usage: python benchmark/gates/django_auth_redirect_uri_fp_probe.py [--dump] [--mutate=<name>]
"""
from __future__ import annotations

import ast
import contextlib
import inspect
import io as _io
import os
import re
import sys
import time

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402

T = ast_scanner.TaintTracker
OWNERS = {'T': T, 'ast_scanner': ast_scanner}

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


def scan_rows(source, state='ship'):
    """(basename, line, cwe) for one fixture file, every clause in its shipped position."""
    key = ('scan', state, source)
    if key in _CACHE:
        return _CACHE[key]
    with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files={'m.py': source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = sorted({('m.py', int(row['line']), row['cwe'])
                       for row in cli._findings_for(tracker, edges)})
    _CACHE[key] = rows
    return rows


def loud(rows, name, cwe, line):
    return (name, line, cwe) in rows


CASES = []


def case(pocket, label, cwe, name, line, expect, arm, arm_expect, source, note=''):
    """expect / arm_expect: 'loud' or 'quiet', before and after the pocket's own clause."""
    CASES.append({'pocket': pocket, 'label': label, 'source': source, 'cwe': cwe, 'name': name,
                  'line': line, 'expect': expect, 'arm': arm, 'arm_expect': arm_expect,
                  'note': note})


def rows_for(entry, state='ship'):
    return scan_rows(entry['source'], state)


# --------------------------------------------------------------------------- C1 fixtures: validated redirects
SAFE_WRAPPER = module(
    'from django.http import HttpResponseRedirect',
    'from django.utils.http import url_has_allowed_host_and_scheme',
    'from urllib.parse import urljoin',
    '',
    'def get_safe_redirect_to(url, redirect_host):',
    '    is_url_safe = url_has_allowed_host_and_scheme(url=url, allowed_hosts=None)',
    '    if is_url_safe:',
    '        return urljoin(redirect_host, url)',
    '    return redirect_host',
    '',
    'def login_view(request, next):',
    '    redirect_to = get_safe_redirect_to(next, request.user.realm.url)',
    '    return HttpResponseRedirect(redirect_to)',
)
INLINE_VALIDATED = module(
    'from django.shortcuts import redirect',
    'from django.utils.http import url_has_allowed_host_and_scheme',
    '',
    'def get_safe_redirect_to(url, redirect_host):',
    '    if url_has_allowed_host_and_scheme(url=url, allowed_hosts=None):',
    '        return url',
    '    return redirect_host',
    '',
    'def login_view(request, next):',
    '    return redirect(get_safe_redirect_to(next, "/"))',
)
NAME_ONLY_WRAPPER = module(
    'from django.http import HttpResponseRedirect',
    'from django.utils.http import url_has_allowed_host_and_scheme',
    '',
    'def get_safe_redirect_to(url, redirect_host):',
    '    return url',
    '',
    'def login_view(request, next):',
    '    redirect_to = get_safe_redirect_to(next, request.user.realm.url)',
    '    return HttpResponseRedirect(redirect_to)',
)
DISCARDED_VALIDATION = module(
    'from django.http import HttpResponseRedirect',
    'from django.utils.http import url_has_allowed_host_and_scheme',
    '',
    'def get_safe_redirect_to(url, redirect_host):',
    '    url_has_allowed_host_and_scheme(url=url, allowed_hosts=None)',
    '    return redirect_host',
    '',
    'def login_view(request, next):',
    '    redirect_to = get_safe_redirect_to(next, request.user.realm.url)',
    '    return HttpResponseRedirect(redirect_to)',
)
SAME_FUNCTION_VALIDATOR = module(
    'from django.shortcuts import redirect',
    'from django.utils.http import url_has_allowed_host_and_scheme',
    '',
    'def login_view(request, next_url):',
    '    if url_has_allowed_host_and_scheme(url=next_url, allowed_hosts=None):',
    '        return redirect(next_url)',
    '    return redirect("/")',
)
BARE_NEXT = module(
    'from django.shortcuts import redirect',
    '',
    'def go(request):',
    "    return redirect(request.GET.get('next'))",
)
PARAM_TARGET = module(
    'from django.http import HttpResponseRedirect',
    '',
    'def go(request, next_url):',
    '    return HttpResponseRedirect(next_url)',
)

# --------------------------------------------------------------------------- C1 fixtures: anchored templates
QUERY_TEMPLATE = module(
    'from django.shortcuts import redirect',
    '',
    'def go(request):',
    '    return redirect(f"/search/?q={request.GET[\'q\']}")',
)
FRAGMENT_TEMPLATE = module(
    'from django.shortcuts import redirect',
    '',
    'def go(request):',
    '    return redirect(f"/inbox/#panel/{request.GET[\'p\']}")',
)
CHAIN_KEY_TEMPLATE = module(
    'from django.shortcuts import redirect',
    '',
    'def go(request):',
    '    return redirect(f"/login/?next={request.GET[\'n\']}")',
)
PROTOCOL_RELATIVE_TEMPLATE = module(
    'from django.shortcuts import redirect',
    '',
    'def go(request, host):',
    '    return redirect(f"//{host}/x")',
)
PATH_TEMPLATE = module(
    'from django.shortcuts import redirect',
    '',
    'def go(request):',
    '    return redirect(f"/users/{request.GET[\'u\']}")',
)
SLASH_CONCAT = module(
    'from django.shortcuts import redirect',
    '',
    'def go(request):',
    "    return redirect('/' + request.GET['next'])",
)
ROUTE_PARAM_TEMPLATE = module(
    'from django.shortcuts import redirect',
    '',
    'def go(request, project_id):',
    '    return redirect(f"/taskManager/{project_id}/")',
)

# --------------------------------------------------------------------------- C2 fixtures: csrf decorators
EXEMPT_REQUIRE_POST = module(
    'from django.views.decorators.csrf import csrf_exempt',
    'from django.views.decorators.http import require_post',
    'from zerver.decorator import typed_endpoint',
    '',
    '@csrf_exempt',
    '@require_post',
    '@typed_endpoint',
    'def api_fetch(request, username, password):',
    '    return json_success(request)',
)
EXEMPT_WEBHOOK = module(
    'from django.views.decorators.csrf import csrf_exempt',
    'from zerver.decorator import webhook_view',
    '',
    '@csrf_exempt',
    "@webhook_view('GCP')",
    'def gcp_hook(request, payload):',
    '    return json_success(request)',
)
BARE_EXEMPT = module(
    'from django.views.decorators.csrf import csrf_exempt',
    '',
    '@csrf_exempt',
    'def upload_view(request):',
    "    if request.method == 'POST':",
    '        ProfileForm(request.POST).save()',
    "    return render(request, 'p.html')",
)
EXEMPT_REQUIRE_SAFE = module(
    'from django.views.decorators.csrf import csrf_exempt',
    'from django.views.decorators.http import require_safe',
    '',
    '@require_safe',
    '@csrf_exempt',
    'def settings_view(request):',
    '    return json_success(request)',
)
EXEMPT_LOCAL_LOOKALIKE = module(
    'from django.views.decorators.csrf import csrf_exempt',
    '',
    'def require_post(view_func):',
    '    return view_func',
    '',
    '@csrf_exempt',
    '@require_post',
    'def hook(request):',
    '    return json_success(request)',
)
POST_ROUTE_GUARDED = module(
    'from flask import Flask, request',
    'from zerver.decorator import require_post',
    '',
    'app = Flask(__name__)',
    '',
    "@app.route('/transfer', methods=['POST'])",
    '@require_post',
    'def transfer():',
    "    return request.form['amount']",
)
POST_ROUTE_PLAIN = module(
    'from flask import Flask, request',
    '',
    'app = Flask(__name__)',
    '',
    "@app.route('/transfer', methods=['POST'])",
    'def transfer():',
    "    return request.form['amount']",
)

# --------------------------------------------------------------------------- C2 fixtures: auth decorators
ZULIP_LOGIN_REQUIRED = module(
    'from zerver.decorator import zulip_login_required',
    '',
    '@zulip_login_required',
    'def note_edit(request, note_id):',
    '    note = Notes.objects.get(pk=note_id)',
    "    return render(request, 'n.html', {'note': note})",
)
REALM_ADMIN = module(
    'from zerver.decorator import require_realm_admin',
    '',
    '@require_realm_admin',
    'def note_edit(request, note_id):',
    '    note = Notes.objects.get(pk=note_id)',
    "    return render(request, 'n.html', {'note': note})",
)
REST_API_VIEW = module(
    'from zerver.decorator import authenticated_rest_api_view',
    '',
    '@authenticated_rest_api_view',
    'def note_edit(request, note_id):',
    '    note = Notes.objects.get(pk=note_id)',
    "    return render(request, 'n.html', {'note': note})",
)
GUARD_FROM_WRONG_HOME = module(
    'from zerver.types import zulip_login_required',
    '',
    '@zulip_login_required',
    'def note_edit(request, note_id):',
    '    note = Notes.objects.get(pk=note_id)',
    "    return render(request, 'n.html', {'note': note})",
)
TYPED_ENDPOINT_ONLY = module(
    'from zerver.types import typed_endpoint',
    '',
    '@typed_endpoint',
    'def note_edit(request, note_id):',
    '    note = Notes.objects.get(pk=note_id)',
    "    return render(request, 'n.html', {'note': note})",
)
CACHE_PAGE_ONLY = module(
    'from django.views.decorators.cache import cache_page',
    '',
    '@cache_page(60)',
    'def note_edit(request, note_id):',
    '    note = Notes.objects.get(pk=note_id)',
    "    return render(request, 'n.html', {'note': note})",
)
LOCAL_ADMIN_LOOKALIKE = module(
    'def require_realm_admin(view_func):',
    '    return view_func',
    '',
    '@require_realm_admin',
    'def note_edit(request, note_id):',
    '    note = Notes.objects.get(pk=note_id)',
    "    return render(request, 'n.html', {'note': note})",
)
UNDECORATED_VIEW = module(
    'def note_edit(request, note_id):',
    '    note = Notes.objects.get(pk=note_id)',
    "    return render(request, 'n.html', {'note': note})",
)

# --------------------------------------------------------------------------- C3 fixtures: uri schemes
TEMPLATE_SCHEME = module(
    'import urllib.request',
    '',
    'def load(request, key):',
    '    return urllib.request.urlopen(f"zulip://snippet/{key}")',
)
SALT_SCHEME = module(
    'import urllib.request',
    '',
    'def load(kind):',
    '    return urllib.request.urlopen(f"salt://states/{kind}.sls")',
)
CONSTANT_SCHEME = module(
    'import urllib.request',
    '',
    'def load(request):',
    '    return urllib.request.urlopen("zulip://snippet/1")',
)
TAINTED_URL = module(
    'import urllib.request',
    '',
    'def load(request):',
    "    return urllib.request.urlopen(request.GET['u'])",
)
HOST_TEMPLATE = module(
    'import urllib.request',
    '',
    'def load(request):',
    "    return urllib.request.urlopen(f\"https://{request.GET['h']}/x\")",
)
SPLIT_SCHEME = module(
    'import urllib.request',
    '',
    'def load(request, kind):',
    '    return urllib.request.urlopen(f"ht{kind}ps://host/x")',
)
UNRESOLVABLE_URL = module(
    'import urllib.request',
    '',
    'def load(request):',
    "    req = urllib.request.Request(request.GET['url'])",
    '    return urllib.request.urlopen(req)',
)

# --------------------------------------------------------------------------- C1: validated redirects
case('C1', 'validated_assignment_row_dropped', 'CWE-601', 'm.py',
     at(SAFE_WRAPPER, 'redirect_to = get_safe_redirect_to'), 'quiet', 'wrapper_off_arm', 'loud',
     SAFE_WRAPPER, 'the redirect feeds off this file s own validating wrapper')
case('C1', 'validated_response_row_dropped', 'CWE-601', 'm.py',
     at(SAFE_WRAPPER, 'return HttpResponseRedirect(redirect_to)'), 'quiet', 'wrapper_off_arm', 'loud',
     SAFE_WRAPPER, 'the second row of the same view is retired by the same proof')
case('C1', 'inline_validated_call_dropped', 'CWE-601', 'm.py',
     at(INLINE_VALIDATED, 'return redirect(get_safe_redirect_to'), 'quiet', 'wrapper_off_arm', 'loud',
     INLINE_VALIDATED, 'a wrapper called inside redirect() is the same proof')
case('C1', 'validator_vocabulary_owns_the_wrapper', 'CWE-601', 'm.py',
     at(SAFE_WRAPPER, 'redirect_to = get_safe_redirect_to'), 'quiet', 'validators_off_arm', 'loud',
     SAFE_WRAPPER, 'empty the validator names and the wrapper proves nothing again')
case('C1', 'name_only_wrapper_kept', 'CWE-601', 'm.py',
     at(NAME_ONLY_WRAPPER, 'redirect_to = get_safe_redirect_to'), 'loud', 'body_blind_arm', 'quiet',
     NAME_ONLY_WRAPPER, 'the safe-looking name with `return url` is the FN this rule prevents')
case('C1', 'discarded_validation_kept', 'CWE-601', 'm.py',
     at(DISCARDED_VALIDATION, 'redirect_to = get_safe_redirect_to'), 'loud', 'body_blind_arm', 'quiet',
     DISCARDED_VALIDATION, 'a body that validates and returns something else has proved nothing')
case('C1', 'same_function_validator_pre_existing', 'CWE-601', 'm.py',
     at(SAME_FUNCTION_VALIDATOR, 'return redirect(next_url)'), 'quiet', 'validators_off_arm', 'quiet',
     SAME_FUNCTION_VALIDATOR, 'HEAD already retired this row: the new clause owns no credit here')
case('C1', 'bare_next_kept', 'CWE-601', 'm.py', at(BARE_NEXT, 'request.GET.get'),
     'loud', 'wrapper_off_arm', 'loud', BARE_NEXT, 'the mandated loud case: nothing has checked next')
case('C1', 'parameter_target_kept', 'CWE-601', 'm.py', at(PARAM_TARGET, 'HttpResponseRedirect(next_url)'),
     'loud', 'wrapper_off_arm', 'loud', PARAM_TARGET, 'a destination that is only a parameter')

# --------------------------------------------------------------------------- C1: anchored internal templates
case('C1', 'query_data_template_dropped', 'CWE-601', 'm.py', at(QUERY_TEMPLATE, 'redirect(f"/search'),
     'quiet', 'template_off_arm', 'loud', QUERY_TEMPLATE,
     'client data behind the ? cannot move the destination off this origin')
case('C1', 'fragment_data_template_dropped', 'CWE-601', 'm.py', at(FRAGMENT_TEMPLATE, 'redirect(f"/inbox'),
     'quiet', 'template_off_arm', 'loud', FRAGMENT_TEMPLATE,
     'the fragment is read by no server and reaches no other host')
case('C1', 'route_parameter_template_pre_existing', 'CWE-601', 'm.py',
     at(ROUTE_PARAM_TEMPLATE, 'redirect(f"/taskManager'), 'quiet', 'template_off_arm', 'quiet',
     ROUTE_PARAM_TEMPLATE, 'clean path data: the older same-origin clause already excuses it')
case('C1', 'chained_destination_kept', 'CWE-601', 'm.py', at(CHAIN_KEY_TEMPLATE, 'redirect(f"/login'),
     'loud', 'template_blind_arm', 'quiet', CHAIN_KEY_TEMPLATE,
     '?next= carries a further destination, so the anchor stops proving the origin')
case('C1', 'chained_destination_not_this_clauses_credit', 'CWE-601', 'm.py',
     at(CHAIN_KEY_TEMPLATE, 'redirect(f"/login'), 'loud', 'template_off_arm', 'loud',
     CHAIN_KEY_TEMPLATE, 'the veto holds with the clause off too: nothing here was ever excused')
case('C1', 'protocol_relative_template_kept', 'CWE-601', 'm.py',
     at(PROTOCOL_RELATIVE_TEMPLATE, 'redirect(f"//'), 'loud', 'template_off_arm', 'loud',
     PROTOCOL_RELATIVE_TEMPLATE, '//host resolves against another origin')
case('C1', 'path_data_template_kept', 'CWE-601', 'm.py', at(PATH_TEMPLATE, 'redirect(f"/users'),
     'loud', 'template_blind_arm', 'quiet', PATH_TEMPLATE,
     'client data in the path is the sibling of the mandated-loud / + user_input')
case('C1', 'slash_concatenation_kept', 'CWE-601', 'm.py', at(SLASH_CONCAT, "redirect('/'"),
     'loud', 'template_off_arm', 'loud', SLASH_CONCAT, 'the literal loud case of the mandate')

# --------------------------------------------------------------------------- C2: csrf enforcing decorators
case('C2', 'exempt_with_require_post_dropped', 'CWE-352', 'm.py',
     at(EXEMPT_REQUIRE_POST, '@csrf_exempt'), 'quiet', 'csrf_off_arm', 'loud', EXEMPT_REQUIRE_POST,
     'a POST-only view cannot be reached by a cross-site form')
case('C2', 'exempt_with_webhook_view_dropped', 'CWE-352', 'm.py',
     at(EXEMPT_WEBHOOK, '@csrf_exempt'), 'quiet', 'csrf_off_arm', 'loud', EXEMPT_WEBHOOK,
     'webhook_view authenticates by shared secret and takes POST only')
case('C2', 'csrf_vocabulary_owns_the_guard', 'CWE-352', 'm.py',
     at(EXEMPT_REQUIRE_POST, '@csrf_exempt'), 'quiet', 'csrf_vocab_off_arm', 'loud',
     EXEMPT_REQUIRE_POST, 'empty the enforcing names and the decorator guards nothing')
case('C2', 'csrf_import_home_owns_the_guard', 'CWE-352', 'm.py',
     at(POST_ROUTE_GUARDED, 'def transfer'), 'quiet', 'provenance_off_arm', 'loud',
     POST_ROUTE_GUARDED, 'a guard name imported from anywhere is not a guard')
case('C2', 'guarded_post_route_vocabulary', 'CWE-352', 'm.py',
     at(POST_ROUTE_GUARDED, 'def transfer'), 'quiet', 'csrf_vocab_off_arm', 'loud',
     POST_ROUTE_GUARDED, 'the route decorator branch asks the same vocabulary')
case('C2', 'bare_exempt_kept', 'CWE-352', 'm.py', at(BARE_EXEMPT, '@csrf_exempt'),
     'loud', 'csrf_blind_arm', 'quiet', BARE_EXEMPT, 'exemption with no guard is the finding')
case('C2', 'plain_post_route_kept', 'CWE-352', 'm.py', at(POST_ROUTE_PLAIN, 'def transfer'),
     'loud', 'csrf_blind_arm', 'quiet', POST_ROUTE_PLAIN, 'the missing-protection branch is untouched')
case('C2', 'require_safe_is_not_a_csrf_guard', 'CWE-352', 'm.py',
     at(EXEMPT_REQUIRE_SAFE, '@csrf_exempt'), 'loud', 'csrf_off_arm', 'loud', EXEMPT_REQUIRE_SAFE,
     'a read-only guard says nothing about the state-changing case')
case('C2', 'locally_named_require_post_is_not_a_guard', 'CWE-352', 'm.py',
     at(EXEMPT_LOCAL_LOOKALIKE, '@csrf_exempt'), 'loud', 'csrf_off_arm', 'loud',
     EXEMPT_LOCAL_LOOKALIKE, 'the project s own one-line require_post enforces nothing')

# --------------------------------------------------------------------------- C2: auth enforcing decorators
case('C2', 'zulip_login_required_guards', 'CWE-862', 'm.py', at(ZULIP_LOGIN_REQUIRED, '@zulip_login_required'),
     'quiet', 'auth_vocab_off_arm', 'loud', ZULIP_LOGIN_REQUIRED, 'the view cannot be reached anonymous')
case('C2', 'require_realm_admin_guards', 'CWE-862', 'm.py', at(REALM_ADMIN, '@require_realm_admin'),
     'quiet', 'auth_vocab_off_arm', 'loud', REALM_ADMIN, 'an admin gate is the strongest auth decorator')
case('C2', 'authenticated_rest_api_view_guards', 'CWE-862', 'm.py', at(REST_API_VIEW, '@authenticated_rest_api_view'),
     'quiet', 'provenance_off_arm', 'loud', REST_API_VIEW, 'the name has to come from zerver.decorator')
case('C2', 'guard_from_wrong_home_kept', 'CWE-862', 'm.py', at(GUARD_FROM_WRONG_HOME, '@zulip_login_required'),
     'loud', 'auth_vocab_off_arm', 'loud', GUARD_FROM_WRONG_HOME,
     'the same name re-exported from a types module proves nothing')
case('C2', 'typed_endpoint_alone_kept', 'CWE-862', 'm.py', at(TYPED_ENDPOINT_ONLY, '@typed_endpoint'),
     'loud', 'auth_vocab_off_arm', 'loud', TYPED_ENDPOINT_ONLY,
     'a parameter parser is not an authentication decorator')
case('C2', 'cache_page_alone_kept', 'CWE-862', 'm.py', at(CACHE_PAGE_ONLY, '@cache_page(60)'),
     'loud', 'auth_vocab_off_arm', 'loud', CACHE_PAGE_ONLY, 'the mandated non-auth generic decorator')
case('C2', 'local_admin_lookalike_kept', 'CWE-862', 'm.py',
     at(LOCAL_ADMIN_LOOKALIKE, '@require_realm_admin'), 'loud', 'auth_vocab_off_arm', 'loud',
     LOCAL_ADMIN_LOOKALIKE, 'an identity decorator defined two lines above guards nothing')
case('C2', 'undecorated_view_kept', 'CWE-862', 'm.py', at(UNDECORATED_VIEW, 'def note_edit'),
     'loud', 'auth_vocab_off_arm', 'loud', UNDECORATED_VIEW, 'the population the rule exists for')

# --------------------------------------------------------------------------- C3: custom uri schemes
case('C3', 'template_scheme_dropped', 'CWE-939', 'm.py', at(TEMPLATE_SCHEME, 'urlopen(f"zulip'),
     'quiet', 'scheme_off_arm', 'loud', TEMPLATE_SCHEME,
     'the constant head of the template carries a scheme no transport can fetch')
case('C3', 'salt_template_scheme_dropped', 'CWE-939', 'm.py', at(SALT_SCHEME, 'urlopen(f"salt'),
     'quiet', 'scheme_off_arm', 'loud', SALT_SCHEME, 'the file-reader scheme behind the state name')
case('C3', 'constant_scheme_pre_existing', 'CWE-939', 'm.py', at(CONSTANT_SCHEME, 'urlopen("zulip'),
     'quiet', 'scheme_off_arm', 'quiet', CONSTANT_SCHEME,
     'HEAD already silenced a bare literal: no credit claimed for this row')
case('C3', 'tainted_url_kept', 'CWE-939', 'm.py', at(TAINTED_URL, "urlopen(request.GET"),
     'loud', 'scheme_blind_arm', 'quiet', TAINTED_URL, 'no constant prefix, no refusal')
case('C3', 'transportable_host_template_kept', 'CWE-939', 'm.py', at(HOST_TEMPLATE, 'urlopen(f"https'),
     'loud', 'scheme_blind_arm', 'quiet', HOST_TEMPLATE, 'https is exactly the fetchable case')
case('C3', 'split_scheme_kept', 'CWE-939', 'm.py', at(SPLIT_SCHEME, 'urlopen(f"ht'),
     'loud', 'scheme_blind_arm', 'quiet', SPLIT_SCHEME, 'ht + kind + ps:// has no scheme in its head')
case('C3', 'unresolvable_url_kept', 'CWE-939', 'm.py', at(UNRESOLVABLE_URL, 'urlopen(req)'),
     'loud', 'scheme_blind_arm', 'quiet', UNRESOLVABLE_URL,
     'the sentry-pinned Request(request.GET["url"]) shape stays loud')

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
    # C1a: off = HEAD (no wrapper proof at all); blind = every wrapper excuses every redirect.
    'wrapper_off_arm': (('ast_scanner', 'c601_call_is_safe_redirect_wrapper', _never_static),),
    'body_blind_arm': (('ast_scanner', 'c601_definition_validates_redirect', _always_static),),
    'validators_off_arm': (('ast_scanner', 'CWE601_REDIRECT_VALIDATOR_NAMES', frozenset()),),
    'wrappers_off_arm': (('ast_scanner', 'CWE601_SAFE_REDIRECT_WRAPPERS', frozenset()),),
    # C1b: off = HEAD (templates are never proven internal); blind = every leading slash is internal.
    'template_off_arm': (('T', '_c601_anchored_internal_template', _never),),
    'template_blind_arm': (('T', '_c601_anchored_internal_template', _always),),
    'chain_veto_off_arm': (('ast_scanner', 'CWE601_RELATIVE_CHAIN_KEYS', ()),),
    # C2a: off = no decorator carries a CSRF guard; blind = every exempt view is guarded.
    'csrf_off_arm': (('ast_scanner', 'view_carries_csrf_guard', _never_static),),
    'csrf_blind_arm': (('ast_scanner', 'view_carries_csrf_guard', _always_static),),
    'csrf_vocab_off_arm': (('ast_scanner', 'CSRF_ENFORCING_DECORATOR_NAMES', frozenset()),),
    # C2b: the shared import-home vocabulary and the auth names it gates.
    'auth_vocab_off_arm': (('ast_scanner', 'AUTH_ENFORCING_DECORATOR_NAMES', frozenset()),),
    'provenance_off_arm': (('ast_scanner', 'GUARD_DECORATOR_MODULE_HOME', frozenset()),),
    # C3: off = HEAD; blind = every scheme is unfetchable.
    'scheme_off_arm': (('ast_scanner', 'p3_scheme_is_unfetchable', _never_static),),
    'scheme_blind_arm': (('ast_scanner', 'p3_scheme_is_unfetchable', _always_static),),
    'scheme_head_off_arm': (('ast_scanner', 'p3_constant_url_prefix', _never_static),),
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
            print(f'  {now:5s} arm={arm:5s} {receipt:11s} {entry["label"]:40s} {entry["note"][:44]}')
            if now != entry['expect']:
                failures.append(f'{pocket}/{entry["label"]}: shipped {now}, want {entry["expect"]}')
            if arm != entry['arm_expect']:
                failures.append(f'{pocket}/{entry["label"]}: arm-off {arm}, want {entry["arm_expect"]}')
    return failures


# --------------------------------------------------------------------------- TIER 2 predicates
def _tree(source):
    return ast.parse(source)


def _def_named(source, name):
    for node in ast.walk(_tree(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f'no function {name}')


def _call_to(source, owner_name, leaf):
    """The first call to `leaf` inside `owner_name`, which is what the wrapper predicates read."""
    for node in ast.walk(_def_named(source, owner_name)):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, 'attr', '')
            if name == leaf:
                return node
    raise AssertionError(f'no {leaf} call inside {owner_name}')


def _arg_on_line(source, needle):
    """The first argument of the sink call on the fixture line that contains `needle`."""
    target = at(source, needle)
    for node in ast.walk(link(_tree(source))):
        if isinstance(node, ast.Call) and node.lineno == target and node.args:
            return node.args[0]
    raise AssertionError(f'no call argument on the {needle!r} line')


def _client(node):
    return 'request' in ast.dump(node)


def _clean(node):
    return False


PROBES = {}


def probe(name, description):
    def register(function):
        PROBES[name] = (description, function)
        return function
    return register


@probe('c1_validator_vocabulary', 'the five mandated validators and the one wrapper name they feed')
def _():
    return (ast_scanner.CWE601_REDIRECT_VALIDATOR_NAMES == frozenset({
                'url_has_allowed_host_and_scheme', 'is_safe_url', 'is_safe_redirect_url',
                'validate_redirect_url', 'is_relative_url'})
            and ast_scanner.CWE601_SAFE_REDIRECT_WRAPPERS == frozenset({
                'get_safe_redirect_to', 'safe_redirect_to', 'validated_redirect_to'}))


@probe('c1_wrapper_body_has_to_validate_a_parameter_and_return_it',
       'the checked wrapper excuses, the name-only and discarded-validation bodies do not')
def _():
    answer = ast_scanner.c601_call_is_safe_redirect_wrapper
    return (answer(_call_to(SAFE_WRAPPER, 'login_view', 'get_safe_redirect_to'), _tree(SAFE_WRAPPER))
            is True
            and answer(_call_to(INLINE_VALIDATED, 'login_view', 'get_safe_redirect_to'),
                       _tree(INLINE_VALIDATED)) is True
            and answer(_call_to(NAME_ONLY_WRAPPER, 'login_view', 'get_safe_redirect_to'),
                       _tree(NAME_ONLY_WRAPPER)) is False
            and answer(_call_to(DISCARDED_VALIDATION, 'login_view', 'get_safe_redirect_to'),
                       _tree(DISCARDED_VALIDATION)) is False)


@probe('c1_wrapper_must_be_defined_in_this_file',
       'an imported wrapper of the same name excuses nothing: its body is not in this tree')
def _():
    source = module(
        'from django.http import HttpResponseRedirect',
        'from zerver.lib.redirect import get_safe_redirect_to',
        '',
        'def login_view(request, next):',
        '    redirect_to = get_safe_redirect_to(next, request.user.realm.url)',
        '    return HttpResponseRedirect(redirect_to)',
    )
    return (ast_scanner.c601_call_is_safe_redirect_wrapper(
                _call_to(source, 'login_view', 'get_safe_redirect_to'), _tree(source)) is False
            and ast_scanner.c601_definition_validates_redirect(_def_named(NAME_ONLY_WRAPPER,
                                                                          'get_safe_redirect_to'))
            is False
            and ast_scanner.c601_definition_validates_redirect(ast.parse('x = 1').body[0]) is False)


@probe('c1_anchored_template_needs_query_or_fragment',
       'data behind ? or # is excused, data in the path and a chained destination are not')
def _():
    answer = T._c601_anchored_internal_template
    return (answer(None, _arg_on_line(QUERY_TEMPLATE, 'redirect(f"/search'), _client) is True
            and answer(None, _arg_on_line(FRAGMENT_TEMPLATE, 'redirect(f"/inbox'), _client) is True
            and answer(None, _arg_on_line(PATH_TEMPLATE, 'redirect(f"/users'), _client) is False
            and answer(None, _arg_on_line(CHAIN_KEY_TEMPLATE, 'redirect(f"/login'), _client) is False
            and answer(None, _arg_on_line(PROTOCOL_RELATIVE_TEMPLATE, 'redirect(f"//'), _clean) is False
            and answer(None, _arg_on_line(ROUTE_PARAM_TEMPLATE, 'redirect(f"/taskManager'),
                       _client) is True
            and answer(None, _arg_on_line(SLASH_CONCAT, "redirect('/'"), _client) is False)


@probe('c1_anchor_shape', 'one leading slash plus a path character, and no scheme, ever',
       )
def _():
    answer = T._c601_anchored_internal_template

    def template(text):
        return ast.parse(f'redirect(f"{text}")').body[0].value.args[0]

    return (answer(None, template('/a?x={v}'), _client) is True
            and answer(None, template('/a#x={v}'), _client) is True
            and answer(None, template('//a?x={v}'), _client) is False
            and answer(None, template('/?x={v}'), _client) is True
            and answer(None, template('/{v}?x={w}'), _client) is False
            and answer(None, template('/a?url={v}'), _client) is False
            and answer(None, ast.parse('redirect(target)').body[0].value.args[0], _client) is False)


@probe('c2_csrf_vocabulary', 'exactly the four enforcing decorators the mandate names',
       )
def _():
    return ast_scanner.CSRF_ENFORCING_DECORATOR_NAMES == frozenset({
        'csrf_protect', 'require_post', 'webhook_view', 'authenticated_rest_api_view'})


@probe('c2_auth_vocabulary', 'the eight enterprise auth decorators, and no generic ones')
def _():
    names = ast_scanner.AUTH_ENFORCING_DECORATOR_NAMES
    return names == frozenset({
        'zulip_login_required', 'authenticated_rest_api_view', 'authenticated_json_view',
        'authenticated_api_view', 'require_realm_admin', 'require_server_admin', 'human_users_only',
        'webhook_view'}) and not names & {'cache_page', 'typed_endpoint', 'require_safe', 'csrf_exempt'}


@probe('c2_guard_needs_its_import_home',
       'imported from zerver.decorator guards, defined two lines above does not')
def _():
    answer = ast_scanner.view_carries_csrf_guard
    return (answer(_def_named(EXEMPT_REQUIRE_POST, 'api_fetch'), _tree(EXEMPT_REQUIRE_POST)) is True
            and answer(_def_named(EXEMPT_WEBHOOK, 'gcp_hook'), _tree(EXEMPT_WEBHOOK)) is True
            and answer(_def_named(POST_ROUTE_GUARDED, 'transfer'), _tree(POST_ROUTE_GUARDED)) is True
            and answer(_def_named(EXEMPT_LOCAL_LOOKALIKE, 'hook'), _tree(EXEMPT_LOCAL_LOOKALIKE)) is False
            and answer(_def_named(EXEMPT_REQUIRE_SAFE, 'settings_view'),
                       _tree(EXEMPT_REQUIRE_SAFE)) is False
            and answer(_def_named(BARE_EXEMPT, 'upload_view'), _tree(BARE_EXEMPT)) is False)


@probe('c2_import_table_reads_this_modules_imports_only',
       'the home vocabulary is per-module, so a sibling file cannot guard this one')
def _():
    return (set(ast_scanner.guard_decorator_imports(_tree(EXEMPT_REQUIRE_POST)))
            == {'csrf_exempt', 'require_post', 'typed_endpoint'}
            and set(ast_scanner.guard_decorator_imports(_tree(GUARD_FROM_WRONG_HOME))) == set()
            and set(ast_scanner.guard_decorator_imports(_tree(LOCAL_ADMIN_LOOKALIKE))) == set()
            and 'zulip_login_required'
            in ast_scanner.guard_decorator_imports(_tree(ZULIP_LOGIN_REQUIRED)))


@probe('c3_scheme_refusal_needs_a_resolvable_constant_head',
       'custom schemes refuse, transportable and unreadable prefixes do not')
def _():
    answer = ast_scanner.p3_scheme_is_unfetchable
    return (answer(_arg_on_line(TEMPLATE_SCHEME, 'urlopen(f"zulip')) is True
            and answer(_arg_on_line(SALT_SCHEME, 'urlopen(f"salt')) is True
            and answer(_arg_on_line(CONSTANT_SCHEME, 'urlopen("zulip')) is True
            and answer(_arg_on_line(HOST_TEMPLATE, 'urlopen(f"https')) is False
            and answer(_arg_on_line(SPLIT_SCHEME, 'urlopen(f"ht')) is False
            and answer(_arg_on_line(TAINTED_URL, 'urlopen(request')) is False
            and answer(_arg_on_line(UNRESOLVABLE_URL, 'urlopen(req)')) is False)


@probe('c3_transportable_schemes_never_excused',
       'every scheme a client or transport can actually follow stays in the loud set')
def _():
    answer = ast_scanner.p3_scheme_is_unfetchable

    def literal(text):
        return ast.parse(f'urlopen("{text}")').body[0].value.args[0]

    return (ast_scanner.P3_TRANSPORTABLE_SCHEMES
            >= frozenset({'http', 'https', 'ftp', 'ftps', 'sftp', 'file', 'data'})
            and all(answer(literal(f'{scheme}://host/x')) is False
                    for scheme in sorted(ast_scanner.P3_TRANSPORTABLE_SCHEMES))
            and answer(literal('zulip://snippet/1')) is True
            and answer(literal('javascript:alert(1)')) is True)


@probe('c3_prefix_uses_the_left_side_of_a_concatenation',
       'the anchor of a built URL is read the same way a template head is')
def _():
    answer = ast_scanner.p3_constant_url_prefix
    return (answer(ast.parse('a + b').body[0].value) is None
            and answer(ast.parse('"zulip://x/" + key').body[0].value) == 'zulip://x/'
            and ast_scanner.p3_scheme_is_unfetchable(
                ast.parse('urljoin("zulip://h/", key)').body[0].value.args[0]) is True)


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
_PHASE8 = inspect.getsource(T._collect_phase8_structural_findings)
_CLUSTER2 = inspect.getsource(T._collect_cluster2_structural_findings)
_CLUSTER3 = inspect.getsource(T._collect_cluster3_structural_findings)
_BATCH3A = inspect.getsource(T._collect_batch3a_structural_findings)
_TEMPLATE = inspect.getsource(T._c601_anchored_internal_template)
_WRAPPER = inspect.getsource(ast_scanner.c601_call_is_safe_redirect_wrapper)
_BODY = inspect.getsource(ast_scanner.c601_definition_validates_redirect)
_AUTH_GUARD = inspect.getsource(ast_scanner.view_carries_csrf_guard)
_IMPORTS = inspect.getsource(ast_scanner.guard_decorator_imports)

LAWS = (
    ('C1 the phase-8 redirect proof asks the template and the wrapper',
     lambda: 'if _anchored_internal_template(target, scope_id, lineno):' in _PHASE8
             and 'if isinstance(target, ast.Call) and _safe_redirect_wrapper_call(target, scope_id):'
             in _PHASE8),
    ('C1 the wrapper arm only reads a call, never a bare name',
     lambda: 'isinstance(target, ast.Call)' in _PHASE8
             and 'return tree is not None and c601_call_is_safe_redirect_wrapper(call, tree)'
             in _PHASE8),
    ('C1 the wrapper has to be a top-level def of this module',
     lambda: 'for stmt in getattr(tree, "body", ()):' in _WRAPPER
             and 'isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))' in _WRAPPER
             and 'stmt.name == leaf' in _WRAPPER),
    ('C1 a body proves validation by parameter, not by variable name',
     lambda: 'if not validated:' in _BODY and 'name.id in validated' in _BODY
             and 'return False' in _BODY),
    ('C1 the cluster-2 source row keeps both refusals',
     lambda: '"redirect" not in scope_validators and \\' in _CLUSTER2
             and 'not c601_call_is_safe_redirect_wrapper(value_node, tree):' in _CLUSTER2),
    ('C2 the anchored template proves the anchor before it reads the holes',
     lambda: _TEMPLATE.find('anchor.startswith("/")') < _TEMPLATE.find('behind_query_or_fragment')
             and 'CWE601_RELATIVE_CHAIN_KEYS' in _TEMPLATE
             and 'FormattedValue' in _TEMPLATE),
    ('C2 the exempt-view emitter asks the csrf guard on the same view',
     lambda: 'csrf_guarded = view_carries_csrf_guard(node, tree)' in _CLUSTER3
             and 'and not csrf_guarded \\' in _CLUSTER3),
    ('C2 the batch-3a csrf branch asks the same predicate',
     lambda: 'has_csrf_protect_dec = view_carries_csrf_guard(node, tree)' in _BATCH3A
             and 'and not has_csrf_protect_dec \\' in _BATCH3A),
    ('C2 the auth guard keeps the pre-existing framework set first',
     lambda: 'if dec_name in FRAMEWORK_AUTH_DECORATORS:' in _BATCH3A
             and 'return (leaf in AUTH_ENFORCING_DECORATOR_NAMES' in _BATCH3A
             and 'and leaf in guard_decorator_imports(tree))' in _BATCH3A),
    ('C2 a guard name is read with its import home, in both predicates',
     lambda: 'leaf in imported' in _AUTH_GUARD and 'stmt.module or ""' in _IMPORTS
             and 'GUARD_DECORATOR_MODULE_HOME' in _IMPORTS),
    ('C2 the import table is memoised on the tree, not rebuilt per view',
     lambda: '_cached_guard_decorator_imports' in _IMPORTS),
    ('C3 the scheme refusal sits on the branch that cannot resolve a URL',
     lambda: 'if url_value is None and not p3_scheme_is_unfetchable(url_expr):' in _CLUSTER3),
    ('C3 the scheme test reads a prefix before it reads a scheme',
     lambda: 'if not prefix:' in inspect.getsource(ast_scanner.p3_scheme_is_unfetchable)
             and 'P3_SCHEME_PREFIX_RE.match(prefix)'
             in inspect.getsource(ast_scanner.p3_scheme_is_unfetchable)),
    ('C3 no clause reads a path, a module name or a file table',
     lambda: not re.search(r'self\.(files|current_file|path)|mod_name|filename',
                           _TEMPLATE + _WRAPPER + _BODY + _AUTH_GUARD + _IMPORTS)),
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
    'c1_wrapper_proof_removed': (
        'C1: the wrapper call is never inspected, which is what HEAD shipped -- validated redirects report',
        'wrapper_off_arm',
        ['validated_assignment_row_dropped', 'validated_response_row_dropped',
         'inline_validated_call_dropped', 'validator_vocabulary_owns_the_wrapper'],
        ['c1_wrapper_body_has_to_validate_a_parameter_and_return_it']),
    'c1_wrapper_body_blinded': (
        'C1: every wrapper body counts as a validation, so the name-only and discarded views go quiet',
        'body_blind_arm',
        ['name_only_wrapper_kept', 'discarded_validation_kept'],
        ['c1_wrapper_body_has_to_validate_a_parameter_and_return_it',
         'c1_wrapper_must_be_defined_in_this_file']),
    'c1_validator_vocabulary_emptied': (
        'C1: no name is a redirect validator, so the wrapper proves nothing and the rows return',
        'validators_off_arm',
        ['validated_assignment_row_dropped', 'validated_response_row_dropped',
         'inline_validated_call_dropped', 'validator_vocabulary_owns_the_wrapper'],
        ['c1_validator_vocabulary', 'c1_wrapper_body_has_to_validate_a_parameter_and_return_it']),
    'c1_wrapper_name_vocabulary_emptied': (
        'C1: no name is a safe-redirect wrapper, so the call is read as an ordinary destination',
        'wrappers_off_arm',
        ['validated_assignment_row_dropped', 'validated_response_row_dropped',
         'inline_validated_call_dropped', 'validator_vocabulary_owns_the_wrapper'],
        ['c1_validator_vocabulary', 'c1_wrapper_body_has_to_validate_a_parameter_and_return_it']),
    'c1_template_clause_removed': (
        'C1: a leading slash proves nothing, which is HEAD -- the query and fragment rows return',
        'template_off_arm',
        ['query_data_template_dropped', 'fragment_data_template_dropped'],
        ['c1_anchored_template_needs_query_or_fragment', 'c1_anchor_shape']),
    'c1_template_clause_blinded': (
        'C1: every anchored template is internal, so chained, protocol-relative and path data go quiet',
        'template_blind_arm',
        ['chained_destination_kept', 'chained_destination_not_this_clauses_credit',
         'protocol_relative_template_kept', 'path_data_template_kept', 'slash_concatenation_kept',
         'bare_next_kept', 'parameter_target_kept'],
        ['c1_anchored_template_needs_query_or_fragment', 'c1_anchor_shape']),
    'c1_chain_veto_removed': (
        'C1: the query stops carrying a further destination, so ?next= inside a template is excused',
        'chain_veto_off_arm',
        ['chained_destination_kept', 'chained_destination_not_this_clauses_credit'],
        ['c1_anchored_template_needs_query_or_fragment', 'c1_anchor_shape']),
    'c2_csrf_guard_ignored': (
        'C2: no decorator carries a CSRF guard, which is HEAD -- the five guarded rows report',
        'csrf_off_arm',
        ['exempt_with_require_post_dropped', 'exempt_with_webhook_view_dropped',
         'csrf_vocabulary_owns_the_guard', 'csrf_import_home_owns_the_guard',
         'guarded_post_route_vocabulary'],
        ['c2_guard_needs_its_import_home']),
    'c2_csrf_vocabulary_emptied': (
        'C2: no enforcing names, so require_post and webhook_view guard nothing again',
        'csrf_vocab_off_arm',
        ['exempt_with_require_post_dropped', 'exempt_with_webhook_view_dropped',
         'csrf_vocabulary_owns_the_guard', 'csrf_import_home_owns_the_guard',
         'guarded_post_route_vocabulary'],
        ['c2_csrf_vocabulary', 'c2_guard_needs_its_import_home']),
    'c2_guard_homes_emptied': (
        'C2: no module owns a guard, so every named decorator reports and the auth views return too',
        'provenance_off_arm',
        ['exempt_with_require_post_dropped', 'exempt_with_webhook_view_dropped',
         'csrf_vocabulary_owns_the_guard', 'csrf_import_home_owns_the_guard',
         'guarded_post_route_vocabulary', 'zulip_login_required_guards',
         'require_realm_admin_guards', 'authenticated_rest_api_view_guards'],
        ['c2_guard_needs_its_import_home', 'c2_import_table_reads_this_modules_imports_only']),
    'c2_csrf_guard_blinded': (
        'C2: every exempt view is treated as guarded, so the bare exemption loses its row',
        'csrf_blind_arm',
        ['bare_exempt_kept', 'plain_post_route_kept', 'require_safe_is_not_a_csrf_guard',
         'locally_named_require_post_is_not_a_guard'],
        ['c2_guard_needs_its_import_home']),
    'c2_auth_vocabulary_emptied': (
        'C2: none of the enterprise auth names guards a view, so the three guarded views report',
        'auth_vocab_off_arm',
        ['zulip_login_required_guards', 'require_realm_admin_guards',
         'authenticated_rest_api_view_guards'],
        ['c2_auth_vocabulary']),
    'c3_scheme_clause_removed': (
        'C3: no scheme is unfetchable, which is HEAD -- the two template rows report again',
        'scheme_off_arm',
        ['template_scheme_dropped', 'salt_template_scheme_dropped'],
        ['c3_scheme_refusal_needs_a_resolvable_constant_head',
         'c3_transportable_schemes_never_excused', 'c3_prefix_uses_the_left_side_of_a_concatenation']),
    'c3_scheme_clause_blinded': (
        'C3: every prefix is treated as an internal scheme, so the four real SSRF rows go quiet',
        'scheme_blind_arm',
        ['tainted_url_kept', 'transportable_host_template_kept', 'split_scheme_kept',
         'unresolvable_url_kept'],
        ['c3_scheme_refusal_needs_a_resolvable_constant_head',
         'c3_transportable_schemes_never_excused']),
    'c3_prefix_reader_removed': (
        'C3: the constant head stops resolving, so nothing has a scheme to check',
        'scheme_head_off_arm',
        ['template_scheme_dropped', 'salt_template_scheme_dropped'],
        ['c3_prefix_uses_the_left_side_of_a_concatenation',
         'c3_scheme_refusal_needs_a_resolvable_constant_head',
         'c3_transportable_schemes_never_excused']),
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
        print(f'  {"CAUGHT" if ok else "MISSED"} {name:34s} rows={moved} probes={flipped} '
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
    started = time.perf_counter()
    failures = []
    if '--dump' in argv:
        dump()
        return 0
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
