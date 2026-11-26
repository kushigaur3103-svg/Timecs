"""v3.3.2 arena FP fixes -- the exact shapes NetBox/LiteLLM/LangChain paid for, pinned in-memory.

One scan per shape through the real record path (TaintTracker + cli._findings_for), no tree walks,
no arena: the whole file runs in seconds and stays inside the laptop RAM budget.
"""
from __future__ import annotations

import contextlib
import io
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ast_scanner  # noqa: E402
import cli  # noqa: E402


def findings(source: str, cwe: str, name: str = "m.py"):
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={name: source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row["line"], row["message"]) for row in rows if row["cwe"] == cwe})


# ---------------------------------------------------------------- CWE-601: Django reverse() builders

REVERSE_ROUTE_OK = '''
from django.shortcuts import redirect
from django.urls import reverse
def job_view(request, job_id):
    return redirect(reverse('core:background_task', args=[job_id]))
'''

REVERSE_DYNAMIC_ENDPOINT = '''
from django.shortcuts import redirect
from django.urls import reverse
def view(request, view_name, next_page):
    return redirect(reverse(view_name, args=[next_page]))
'''

REVERSE_SELF_PK = '''
from django.http import HttpResponseRedirect
def view(request):
    return HttpResponseRedirect(reverse('home', args=[self.pk]))
'''


def test_reverse_with_literal_endpoint_and_route_param_is_clean():
    assert findings(REVERSE_ROUTE_OK, "CWE-601") == []


def test_reverse_with_dynamic_endpoint_still_reports():
    assert findings(REVERSE_DYNAMIC_ENDPOINT, "CWE-601") != []


def test_reverse_args_with_self_pk_stays_loud():
    assert findings(REVERSE_SELF_PK, "CWE-601") != []


# ---------------------------------------------------------------- CWE-601: source/sink rows

RAW_NEXT_TWO_ROWS = '''
from django.shortcuts import redirect
def v(request):
    next_url = request.GET.get('next')
    return redirect(next_url)
'''

HELPER_CALL_SINGLE_ROW = '''
from django.shortcuts import redirect
class V:
    def helper_view(self, request):
        return_url = self.get_return_url(request)
        return redirect(return_url)
'''


def test_two_line_open_redirect_keeps_source_and_sink_rows():
    rows = findings(RAW_NEXT_TWO_ROWS, "CWE-601")
    assert any(line == 4 for line, _ in rows), rows
    assert any(line == 5 for line, _ in rows), rows


def test_helper_call_site_emits_no_source_row():
    rows = findings(HELPER_CALL_SINGLE_ROW, "CWE-601")
    assert [line for line, _ in rows] == [6], rows


# ---------------------------------------------------------------- CWE-96: globals-only rule

ORDINARY_DICT_SUBSCRIPT = '''
def f(passed_params, chosen):
    optional_params = {}
    for k in chosen:
        optional_params[k] = passed_params[k]
    return optional_params
'''

LOCALS_MUTATION = '''
def f(name):
    # A dynamic namespace READ is the injection sink; the engine decided long ago that a
    # store into globals() is not reported (ast_scanner cluster1 rule B).
    return globals()[name]()
'''


def test_plain_dict_subscript_is_not_dangerous_globals_use():
    rows = findings(ORDINARY_DICT_SUBSCRIPT, "CWE-96")
    assert not any("DANGEROUS_GLOBALS_USE" in message for _, message in rows), rows


def test_dynamic_globals_read_still_reports():
    rows = findings(LOCALS_MUTATION, "CWE-96")
    assert any("DANGEROUS_GLOBALS_USE" in message for _, message in rows), rows


# ---------------------------------------------------------------- CWE-95: AST-only compile

COMPILE_TO_AST = '''
import ast
def parse(source):
    return compile(source, '<string>', 'exec', ast.PyCF_ONLY_AST)
'''

EVAL_STILL_REPORTS = '''
def run(payload):
    return eval(payload)
'''


def test_compile_to_ast_is_not_code_execution():
    assert findings(COMPILE_TO_AST, "CWE-95") == []


def test_eval_still_reports():
    assert findings(EVAL_STILL_REPORTS, "CWE-95") != []


# ---------------------------------------------------------------- CWE-434: receiver proof

LOCAL_SERIALIZATION_SAVE = '''
class Manager:
    def persist(self, path):
        return self.db.save(path)
'''


def test_self_db_save_is_not_file_upload():
    assert findings(LOCAL_SERIALIZATION_SAVE, "CWE-434") == []


# ---------------------------------------------------------------- CWE-79: content_type proof

DJANGO_YAML_RESPONSE = '''
from django.http import HttpResponse
def v(request):
    return HttpResponse(request.body, content_type="text/yaml")
'''

DJANGO_HTML_RESPONSE = '''
from django.http import HttpResponse
def v(request):
    return HttpResponse(request.body, content_type="text/html")
'''


def test_safe_yaml_content_type_is_not_stored_xss():
    assert findings(DJANGO_YAML_RESPONSE, "CWE-79") == []


def test_html_content_type_still_reports():
    assert findings(DJANGO_HTML_RESPONSE, "CWE-79") != []
