"""Regression gate for the Sentry suppression contract — `90b4654` plus the CWE-862 HTTP-entrypoint
clause and the `testutils/` + `fixtures/` walker prune, pinned row by row.

    python benchmark/gates/drf_snuba_scope_probe.py
    python benchmark/gates/drf_snuba_scope_probe.py --mutate=drf_envelope_guard_disabled

`90b4654` retired roughly 1,000 Sentry-shaped false positives with four AST guards, and **none of the
other 49 gates could have caught a regression**: no frozen corpus contains a `rest_framework` view, a
`snuba_sdk` query, a `@shared_task` worker or a Django migration, so the whole CWE-79 / CWE-95 /
CWE-862 triple was asserted only by a scratch A/B that no longer exists. This gate is the permanent
replacement for that A/B, and it holds the two clauses added after it to the same standard. Every
fixture is a virtual module handed to `TaintTracker(files={...})`, so nothing here touches the
filesystem, and no guard can pass by looking at a path — which is the rule the fixes themselves had to
respect ("NO PATH BLACKLISTING"). The one tier that must use real files, the walker prune, builds its
own three-file tree in a temp directory.

Tiers, and what each one can actually falsify:

* TIER 1 — the QUIET invariants (0 rows of the target CWE): the DRF JSON envelope, the `snuba_sdk`
  `Function`, background tasks, migrations, ORM scopes, permission-guarded views, and the internal
  `services/*/impl.py` + `models.py` + `utils` methods that no HTTP request can enter. Each is paired
  in TIER 5 with the mutation that brings its rows back, so a fixture that is merely empty for the
  wrong reason — an expression that never carried taint — cannot pass this gate.
* TIER 2 — the LOUD invariants, pinned by line *and* message. The DRF pair is the load-bearing half of
  the old contract: `Response({...})` is silent and `Response(..., content_type="text/html")` is not.
  The CWE-862 half is what stops the new entrypoint clause from over-reaching, and its shapes are chosen
  from the seven blessed corpus rows it must never swallow: six are plain statements at module scope,
  which report with no marker present, and one is a base-less `class DocumentView`, which reports on its
  name alone. A `*Endpoint` base and a `@app.route` decorator cover the two ways the same charge arrives
  in a file the corpus does not hold.
* TIER 3 — provenance fail-closed: the right **name** with the wrong **provenance** stays loud. A local
  `class Response`, `from myapp.api import Response`, a module-level `def Function`, a task that does
  take `request`, a class that is neither an ORM scope nor a view but declares `permission_classes`.
  This tier is what fails the day import provenance is replaced by a name blacklist.
* TIER 4 — walker scope: the same three-file tree scanned twice through `cli.main`, once as a user runs
  it and once with `--include-tests`, asserting `fixtures/` and `testutils/` disappear by default while
  the directory that was pointed at keeps its row.
* TIER 5 — falsification battery + collateral sweep: twelve in-memory weakenings, each of which must
  move every row its clause owns and must leave its neighbours byte-identical, including rows of every
  other CWE. A mutation that moves nothing is decorative and is reported as MISSED.
* TIER 6 — parity hygiene: `aa_parity` scans this whole `benchmark/` tree with cross-file taint and its
  blessed baseline holds no `benchmark/gates/` key, so a gate file must add nothing to it. Sharing a
  module-level callee name with `gate_common` — which wraps `subprocess.run` — is how writing this file
  naively broke parity, and the tier fails the day that happens again.
* TIER 7 — budget: < 3.0 s of gate work and < 60 MB peak RSS, both measured here rather than assumed.
  The 3.0 s is charged to this file's own scans (the virtual one-screen modules plus two walks of a
  three-file temp tree, no repository file) and deliberately starts after interpreter boot and the
  engine import: those swing 2-3x with whatever the previous gate left in the file cache, and charging
  them turned a deterministic probe into a random failure once the suite ran it after a 47-second
  neighbour. The total wall time is still printed.
"""

import ast
import contextlib
import ctypes
import io
import json
import os
import sys
import tempfile
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
BUDGET_SECONDS = 3.0
BUDGET_RSS_MB = 60.0
VIRTUAL_MODULE = 'drf_snuba_scope_probe_fixture.py'

FAILURES = []


def fail(label, detail):
    FAILURES.append(label)
    print('  FAIL %s: %s' % (label, detail))


# --------------------------------------------------------------------------- fixtures

DRF_VIEW_SPINE = ('from rest_framework.response import Response\n'
                  'from rest_framework.views import APIView\n'
                  '\n'
                  '\n'
                  'class SearchView(APIView):\n'
                  '    def get(self, request):\n'
                  '        query = request.GET.get("q")\n')

# ---- TIER 1: the quiet invariants -- the target CWE must report nothing, and a named guard must own it.
# `guard` names the mutation in TIER 4 that has to bring these rows back.
QUIET = {
    'drf_dict_payload': ('CWE-79', 'drf_envelope_guard_disabled', [
        DRF_VIEW_SPINE + '        return Response({"q": query, "page": 1})\n']),
    'drf_serializer_data': ('CWE-79', 'drf_envelope_guard_disabled', [
        'from rest_framework.response import Response\n'
        'from rest_framework.views import APIView\n'
        'from rest_framework import serializers\n'
        '\n'
        '\n'
        'class GroupSerializer(serializers.ModelSerializer):\n'
        '    name = serializers.CharField()\n'
        '\n'
        '\n'
        'class GroupView(APIView):\n'
        '    def get(self, request):\n'
        '        ser = GroupSerializer(instance=request.group)\n'
        '        return Response(ser.data)\n']),
    'snuba_sdk_function': ('CWE-95', 'snuba_function_guard_disabled', [
        'from snuba_sdk import Column, Function\n'
        '\n'
        '\n'
        'def build(request):\n'
        '    op = request.GET.get("op")\n'
        '    return Function(op, [Column("x")], "total")\n']),
    'celery_background_task': ('CWE-862', 'http_scope_clauses_disabled', [
        'from celery import shared_task\n'
        'from sentry.models import Group\n'
        '\n'
        '\n'
        '@shared_task\n'
        'def purge_group(group_id):\n'
        '    row = Group.objects.get(pk=group_id)\n'
        '    row.delete()\n'
        '    return row\n',
        'from sentry.tasks.base import instrumented_task\n'
        'from sentry.models import Group\n'
        '\n'
        '\n'
        '@instrumented_task(name="sentry.purge")\n'
        'def purge_queryset(queryset, *args, **kwargs):\n'
        '    row = queryset.query.get(pk=1)\n'
        '    return [row]\n']),
    'django_migration': ('CWE-862', 'http_scope_clauses_disabled', [
        'from django.db import migrations\n'
        'from sentry.models import Group\n'
        '\n'
        '\n'
        'class Migration(migrations.Migration):\n'
        '    dependencies = [("sentry", "0001_initial")]\n'
        '    operations = [migrations.RunPython(forwards)]\n'
        '\n'
        '\n'
        'def forwards(apps, schema_editor):\n'
        '    row = Group.objects.get(pk=1)\n'
        '    row.save()\n']),
    'orm_model_manager_queryset': ('CWE-862', 'http_scope_clauses_disabled', [
        'from django.db import models\n'
        '\n'
        '\n'
        'class Group(models.Model):\n'
        '    name = models.CharField(max_length=64)\n'
        '\n'
        '    def find(self, pk):\n'
        '        row = Group.objects.get(pk=pk)\n'
        '        return row\n'
        '\n'
        '\n'
        'class GroupManager(models.Manager):\n'
        '    def lookup(self, pk):\n'
        '        return self.get_queryset().get(pk=pk)\n'
        '\n'
        '\n'
        'class GroupQuerySet(models.QuerySet):\n'
        '    def lookup(self, pk):\n'
        '        return self.query.get(pk=pk)\n']),
    'drf_permission_classes': ('CWE-862', 'permission_guard_recognition_disabled', [
        'from rest_framework.permissions import IsAuthenticated\n'
        'from rest_framework.views import APIView\n'
        'from sentry.models import Document\n'
        '\n'
        '\n'
        'class GuardedView(APIView):\n'
        '    permission_classes = (IsAuthenticated,)\n'
        '\n'
        '    def get(self, request):\n'
        '        return Document.objects.get(pk=1)\n']),
    'inherited_permission_classes': ('CWE-862', 'permission_guard_recognition_disabled', [
        'from rest_framework.permissions import IsAuthenticated\n'
        'from rest_framework.views import APIView\n'
        'from sentry.models import Document\n'
        '\n'
        '\n'
        'class BaseView(APIView):\n'
        '    permission_classes = (IsAuthenticated,)\n'
        '\n'
        '\n'
        'class ChildView(BaseView):\n'
        '    def delete(self, request):\n'
        '        obj = Document.objects.get(pk=2)\n'
        '        obj.delete()\n']),
    # ---- the internal-service family: Sentry's remaining CWE-862 volume, retired at the scope level.
    'internal_service_impl_method': ('CWE-862', 'http_entrypoint_guard_disabled', [
        'from sentry.hybridcloud.services import BaseService\n'
        'from sentry.models import Server, Organization\n'
        '\n'
        '\n'
        'class HybridCloudService(BaseService):\n'
        '    def get_server(self, server_id):\n'
        '        row = Server.objects.get(pk=server_id)\n'
        '        return row\n'
        '\n'
        '    def sync_state(self, org_id):\n'
        '        return Organization.objects.get(id=org_id)\n']),
    'model_helper_class': ('CWE-862', 'http_entrypoint_guard_disabled', [
        'from sentry.models import DeployKey\n'
        '\n'
        '\n'
        'class DeployKeyStore:\n'
        '    def rotate_for(self, project_id):\n'
        '        return DeployKey.objects.get(project_id=project_id)\n']),
    'library_helper_function': ('CWE-862', 'http_entrypoint_guard_disabled', [
        'from sentry.models import Organization\n'
        '\n'
        '\n'
        'def resolve_organization(org_id):\n'
        '    return Organization.objects.get(pk=org_id)\n']),
}

# ---- TIER 2: the loud invariants -- each shape pins its exact (line, message).
LOUD = {
    'drf_html_content_type': ('CWE-79', [
        (DRF_VIEW_SPINE + '        return Response({"q": query}, content_type="text/html")\n',
         (8, 'CWE-79: HTML_RESPONSE_CONTAINER_BODY'))]),
    'drf_markup_payload': ('CWE-79', [
        (DRF_VIEW_SPINE + '        return Response("<div>" + query + "</div>")\n',
         (8, 'CWE-79: rest_framework.response.Response'))]),
    'django_http_response': ('CWE-79', [
        ('from django.http import HttpResponse\n'
         'import html\n'
         '\n'
         '\n'
         'def render(request):\n'
         '    query = request.GET.get("q")\n'
         '    return HttpResponse("<b>" + html.escape(query) + "</b>")\n',
         (7, 'CWE-79: django.http.HttpResponse'))]),
    'real_code_execution': ('CWE-95', [
        ('def build(request):\n'
         '    op = request.GET.get("op")\n'
         '    return Function(op)\n',
         (3, 'CWE-95: Function')),
        ('def build(request):\n'
         '    op = request.GET.get("op")\n'
         '    return eval(op)\n',
         (3, 'CWE-95: DYNAMIC_CODE_EXECUTION'))]),
    'request_param_veto': ('CWE-862', [
        ('from sentry.models import Group\n'
         '\n'
         '\n'
         'def delete_group(request, group_id):\n'
         '    row = Group.objects.get(pk=group_id)\n'
         '    row.delete()\n'
         '    return row\n',
         (4, 'CWE-862: MISSING_AUTHORIZATION'))]),
    'empty_permission_tuple': ('CWE-862', [
        ('from rest_framework.views import APIView\n'
         'from sentry.models import Document\n'
         '\n'
         '\n'
         'class HouseView(APIView):\n'
         '    permission_classes = ()\n'
         '\n'
         '    def get(self, request):\n'
         '        return Document.objects.get(pk=1)\n',
         (8, 'CWE-862: MISSING_AUTHORIZATION'))]),
    'allowany_permissions': ('CWE-862', [
        ('from rest_framework.permissions import AllowAny\n'
         'from rest_framework.views import APIView\n'
         'from sentry.models import Document\n'
         '\n'
         '\n'
         'class PublicView(APIView):\n'
         '    permission_classes = (AllowAny,)\n'
         '\n'
         '    def get(self, request):\n'
         '        return Document.objects.get(pk=1)\n',
         (9, 'CWE-862: MISSING_AUTHORIZATION'))]),
    # ---- the three marker families that keep a view loud when no parameter names a request: the class
    # `View`/`Endpoint` name, a view-shaped base, and a route decorator. Corpus CWE-862 lives in the
    # first two shapes, so a guard that read only `request` would drop those blessed rows here.
    'view_named_class_without_request': ('CWE-862', [
        ('from sentry.models import Document\n'
         '\n'
         '\n'
         'class DocumentView:\n'
         '    def view(self):\n'
         '        return Document.objects.get(pk=1)\n',
         (5, 'CWE-862: MISSING_AUTHORIZATION'))]),
    'view_shaped_base_without_request': ('CWE-862', [
        ('from sentry.web.api import Endpoint\n'
         'from sentry.models import Document\n'
         '\n'
         '\n'
         'class DocumentEndpoint(Endpoint):\n'
         '    def get(self):\n'
         '        return Document.objects.get(pk=1)\n',
         (6, 'CWE-862: MISSING_AUTHORIZATION'))]),
    'route_decorated_handler_without_request': ('CWE-862', [
        ('from sentry.web import app\n'
         'from sentry.models import Document\n'
         '\n'
         '\n'
         '@app.route("/documents/<int:pk>")\n'
         'def document_detail(pk):\n'
         '    return Document.objects.get(pk=pk)\n',
         # Annotated view: the row rides the decorator, which is where the route is declared.
         (5, 'CWE-862: MISSING_AUTHORIZATION'))]),
    'module_scope_flat_view_body': ('CWE-862', [
        # Six of the seven blessed corpus CWE-862 rows are plain statements at module scope. This is the
        # shape the entrypoint clause must never touch, and it reports with no marker present at all.
        ('from sentry.models import Document\n'
         '\n'
         '\n'
         'doc = Document.objects.get(id=request.GET["id"])\n',
         (4, 'CWE-862: MISSING_AUTHORIZATION'))]),
}

# ---- TIER 3: right name, wrong provenance -> the row stays reported.
PROVENANCE = {
    'locally_defined_response_class': ('CWE-79', [
        'class Response:\n'
        '    def __init__(self, payload):\n'
        '        self.payload = payload\n'
        '\n'
        '\n'
        'def render(request):\n'
        '    query = request.GET.get("q")\n'
        '    return Response("<div>" + query + "</div>")\n'],
        [(8, 'CWE-79: Response')]),
    'response_imported_from_another_module': ('CWE-79', [
        'from myapp.api import Response\n'
        '\n'
        '\n'
        'def render(request):\n'
        '    query = request.GET.get("q")\n'
        '    return Response({"q": query})\n'],
        [(6, 'CWE-79: HTML_RESPONSE_CONTAINER_BODY')]),
    'function_defined_in_this_module': ('CWE-95', [
        'def Function(body):\n'
        '    return body\n'
        '\n'
        '\n'
        'def build(request):\n'
        '    op = request.GET.get("op")\n'
        '    return Function(op)\n'],
        [(7, 'CWE-95: Function')]),
    'non_orm_class_declaring_a_handler_attribute': ('CWE-862', [
        # Not an ORM scope (no `models.Model` base) and not a `*View` name, so neither the off-HTTP veto
        # nor the class-name marker explains this row: what keeps it reported is that the class body
        # carries `permission_classes`, an attribute no code but a request dispatcher ever reads.
        'from sentry.models import Group\n'
        '\n'
        '\n'
        'class HouseService:\n'
        '    permission_classes = ()\n'
        '\n'
        '    def find(self, pk):\n'
        '        row = Group.objects.get(pk=pk)\n'
        '        return row\n'],
        [(7, 'CWE-862: MISSING_AUTHORIZATION')]),
    'task_that_takes_request': ('CWE-862', [
        'from celery import shared_task\n'
        'from sentry.models import Group\n'
        '\n'
        '\n'
        '@shared_task\n'
        'def purge(request, group_id):\n'
        '    row = Group.objects.get(pk=group_id)\n'
        '    return row\n'],
        [(5, 'CWE-862: MISSING_AUTHORIZATION')]),
}


# --------------------------------------------------------------------------- scanning

SCANS = [0]


def probe_module_rows(source):
    """Every row for one in-memory module, through the real record path (`cli._findings_for`)."""
    SCANS[0] += 1
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = _TT(files={VIRTUAL_MODULE: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(int(r['line']), r['cwe'], r['message']) for r in rows})


def split_rows(rows, cwe):
    """(target-CWE rows, every other row) -- the two halves TIER 4 compares separately."""
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
# the labels it must leave byte-identical (`holds`). Both lists were measured on this build, so they are
# facts about the engine rather than intentions. `None`-style answers disable a clause; `True` / `""`
# force the fail-closed answer that would let a suppression swallow more than it should.
GUARD_METHODS = (
    '_cwe79_sink_is_drf_json_envelope',
    '_drf_response_delivers_markup',
    '_js_code_exec_name_is_an_imported_python_symbol',
    '_module_symbol_paths',
    '_import_path_for_expr',
    '_c862_scope_is_guarded_or_off_http',
    '_c862_scope_is_http_entrypoint',
    '_class_declares_permission_guard',
    '_signature_takes_http_request',
    '_permission_value_declares_a_check',
)
_ORIGINALS = {name: getattr(_TT, name) for name in GUARD_METHODS}


def _disable(name):
    return lambda: setattr(_TT, name, lambda self, *args, **kwargs: False)


def _answer(name, value):
    return lambda: setattr(_TT, name, lambda self, *args, **kwargs: value)


def _combine(*appliers):
    """Fall through two clauses at once, for a silence no single clause owns any more.

    A background task, a migration and an ORM scope are now held quiet by the off-HTTP veto *and* by the
    HTTP-entrypoint requirement, in series: weakening either one leaves the other answering, so the rows
    only reappear when both do. That overlap is worth pinning rather than hiding, because it is the proof
    that neither clause is load-bearing alone -- deleting one still cannot resurrect a retired finding.
    """
    def apply():
        for applier in appliers:
            applier()
    return apply


MUTATIONS = {
    'drf_envelope_guard_disabled': {
        'what': 'make _cwe79_sink_is_drf_json_envelope always answer "not a DRF JSON envelope"',
        'moves': ['drf_dict_payload', 'drf_serializer_data'],
        'holds': ['django_http_response', 'snuba_sdk_function', 'empty_permission_tuple'],
        'apply': _disable('_cwe79_sink_is_drf_json_envelope'),
    },
    'drf_markup_detector_disabled': {
        'what': 'make _drf_response_delivers_markup blind to content_type and to markup in the payload',
        'moves': ['drf_html_content_type', 'drf_markup_payload'],
        'holds': ['drf_dict_payload', 'django_http_response'],
        'apply': _disable('_drf_response_delivers_markup'),
    },
    'snuba_function_guard_disabled': {
        'what': 'make the JS-only code-exec name refuse every import proof',
        'moves': ['snuba_sdk_function'],
        'holds': ['real_code_execution', 'drf_dict_payload'],
        'apply': _disable('_js_code_exec_name_is_an_imported_python_symbol'),
    },
    'import_alias_table_disabled': {
        'what': 'empty the per-module import alias table that every provenance proof reads',
        'moves': ['drf_dict_payload', 'snuba_sdk_function'],
        'holds': ['django_migration', 'allowany_permissions', 'celery_background_task',
                  'orm_model_manager_queryset'],
        'apply': _answer('_module_symbol_paths', {}),
    },
    'import_path_resolution_disabled': {
        'what': 'resolve no dotted path -- the fail-closed answer -- for any callee',
        'moves': ['drf_dict_payload'],
        'holds': ['snuba_sdk_function', 'django_migration', 'allowany_permissions',
                  'celery_background_task', 'orm_model_manager_queryset'],
        'apply': _answer('_import_path_for_expr', ''),
    },
    'off_http_scope_guard_disabled': {
        'what': 'make _c862_scope_is_guarded_or_off_http report every scope as on-HTTP and unguarded',
        'moves': ['drf_permission_classes', 'inherited_permission_classes'],
        'holds': ['request_param_veto', 'empty_permission_tuple', 'celery_background_task',
                  'django_migration', 'orm_model_manager_queryset'],
        'apply': _disable('_c862_scope_is_guarded_or_off_http'),
    },
    'http_scope_clauses_disabled': {
        'what': 'fall both on-HTTP clauses in series: no off-HTTP veto and every scope called an entrypoint',
        'moves': ['celery_background_task', 'django_migration', 'orm_model_manager_queryset',
                  'drf_permission_classes', 'inherited_permission_classes',
                  'internal_service_impl_method', 'model_helper_class', 'library_helper_function'],
        'holds': ['request_param_veto', 'empty_permission_tuple', 'view_named_class_without_request',
                  'django_http_response'],
        'apply': _combine(_disable('_c862_scope_is_guarded_or_off_http'),
                          _answer('_c862_scope_is_http_entrypoint', True)),
    },
    'permission_guard_recognition_disabled': {
        'what': 'stop recognising class-level permission_classes as an authorization guard',
        'moves': ['drf_permission_classes', 'inherited_permission_classes'],
        'holds': ['orm_model_manager_queryset', 'empty_permission_tuple'],
        'apply': _disable('_class_declares_permission_guard'),
    },
    'request_param_veto_always_fires': {
        'what': 'treat every scope as if it took an HTTP request, voiding all three off-HTTP vetoes',
        'moves': ['celery_background_task', 'django_migration', 'orm_model_manager_queryset'],
        'holds': ['inherited_permission_classes', 'request_param_veto'],
        'apply': _answer('_signature_takes_http_request', True),
    },
    'permission_value_always_declares_check': {
        'what': 'let `permission_classes = ()` and `(AllowAny,)` count as a guard',
        'moves': ['empty_permission_tuple', 'allowany_permissions',
                  'non_orm_class_declaring_a_handler_attribute'],
        'holds': ['drf_permission_classes', 'django_http_response', 'internal_service_impl_method'],
        'apply': _answer('_permission_value_declares_a_check', True),
    },
    'http_entrypoint_guard_disabled': {
        'what': 'treat every scope as reachable from an HTTP request, voiding the service/model/util veto',
        'moves': ['internal_service_impl_method', 'model_helper_class', 'library_helper_function'],
        'holds': ['celery_background_task', 'request_param_veto', 'view_named_class_without_request'],
        'apply': _answer('_c862_scope_is_http_entrypoint', True),
    },
    'http_entrypoint_markers_unreadable': {
        'what': 'answer "this scope is not an HTTP entrypoint" everywhere, the way a name blacklist would',
        'moves': ['request_param_veto', 'empty_permission_tuple', 'allowany_permissions',
                  'view_named_class_without_request', 'view_shaped_base_without_request',
                  'route_decorated_handler_without_request', 'module_scope_flat_view_body',
                  'non_orm_class_declaring_a_handler_attribute', 'task_that_takes_request'],
        'holds': ['internal_service_impl_method', 'model_helper_class', 'celery_background_task',
                  'drf_permission_classes', 'django_http_response'],
        'apply': _answer('_c862_scope_is_http_entrypoint', False),
    },
}


def restore():
    for name, method in _ORIGINALS.items():
        setattr(_TT, name, method)


# --------------------------------------------------------------------------- tiers

def check_quiet():
    passed = 0
    for label, (cwe, guard, sources) in sorted(QUIET.items()):
        rows = [row for obs in observe(label) for row in obs[0]]
        if rows:
            fail('quiet.%s' % label, '%s reported %d row(s) 90b4654 retired: %s' % (cwe, len(rows), rows[:2]))
        elif guard not in MUTATIONS:
            fail('quiet.%s' % label, 'no mutation claims ownership of this silence')
        elif label not in MUTATIONS[guard]['moves']:
            fail('quiet.%s' % label, 'guard %s does not pin this invariant' % guard)
        else:
            passed += 1
    print('  quiet: %d/%d  (each silence re-checked as guard-owned in TIER 5)' % (passed, len(QUIET)))
    return passed, len(QUIET)


def check_loud():
    passed = 0
    for label, (cwe, shapes) in sorted(LOUD.items()):
        clean = True
        observed = observe(label)
        for index, (_src, pin) in enumerate(shapes):
            got = [(line, message) for line, _c, message in observed[index][0]]
            if got != [pin]:
                fail('loud.%s' % label, 'expected exactly [%s], got %s' % (pin, got))
                clean = False
        passed += 1 if clean else 0
    print('  loud: %d/%d' % (passed, len(LOUD)))
    return passed, len(LOUD)


def check_provenance():
    passed = 0
    for label, (cwe, sources, pins) in sorted(PROVENANCE.items()):
        got = [(line, message) for line, _c, message in observe(label)[0][0]]
        if got != pins:
            fail('provenance.%s' % label, 'expected %s, got %s' % (pins, got))
        else:
            passed += 1
    print('  provenance fail-closed: %d/%d' % (passed, len(PROVENANCE)))
    return passed, len(PROVENANCE)


# --------------------------------------------------------------------------- walker scope
#
# `testutils/` and `fixtures/` hold code that is never deployed -- a project's own service test helpers
# and the sample trees its tests read. `cli.py` prunes both from a directory scan by default, the
# opt-out it has carried for `tests/` and `examples/` since `ad8acd4`: the set only ever applies to
# directories found *under* the scan root, a root named `fixtures` is always scanned, and
# `--include-tests` walks everything. That is also the only reason it is safe here -- 27 of the 425
# blessed parity keys live under `benchmark/fixtures/`, and `scan_child.py`, the wrapper those frozen
# corpora scan through, passes the flag. Asserted below anyway, because a prune that silently ate a
# blessed fixture is exactly how this tier could pass while the repository broke.

WALK_MODULES = ('views.py', os.path.join('fixtures', 'document_view.py'),
                os.path.join('testutils', 'documents.py'))
WALK_VIEW = ('from sentry.models import Document\n'
             '\n'
             '\n'
             'class DocumentView:\n'
             '    def get(self, request):\n'
             '        return Document.objects.get(pk=request.GET["pk"])\n')
WALK_KEY = (5, 'CWE-862')


def walk_cli_payload(argv, cwd):
    """One in-process CLI run over `cwd`, returning the JSON payload it printed."""
    SCANS[0] += 1
    out, err = io.StringIO(), io.StringIO()
    previous = os.getcwd()
    os.chdir(cwd)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main(argv)
    finally:
        os.chdir(previous)
    text = out.getvalue()
    start = text.find('{')
    if start < 0:
        raise AssertionError('the CLI printed no JSON (%s)' % err.getvalue()[-200:])
    return json.loads(text[start:])


def check_walk_scope():
    """TIER 4 -- the prune set itself, then the same tree scanned with and without `--include-tests`."""
    lost = {'testutils', 'fixtures'} - set(cli.NON_PRODUCTION_DIRS)
    if lost:
        fail('walk.set', 'cli.NON_PRODUCTION_DIRS no longer holds %s' % ', '.join(sorted(lost)))
        return 0, 3
    with tempfile.TemporaryDirectory() as tmp:
        for rel in WALK_MODULES:
            path = os.path.join(tmp, *rel.split(os.sep))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(WALK_VIEW)
        argv = ['scan', '.', '--format', 'json', '--workers', '1']
        default = walk_cli_payload(argv, tmp)
        included = walk_cli_payload(argv + ['--include-tests'], tmp)

    def reported(payload):
        return {os.path.normpath(f['file']).lower(): (int(f['line']), f['cwe'])
                for f in payload['findings'] if (int(f['line']), f['cwe']) == WALK_KEY}

    wanted = {os.path.normpath(rel).lower() for rel in WALK_MODULES}
    passed = 0
    if reported(included) and set(reported(included)) != wanted:
        fail('walk.include_tests', '--include-tests walked %s, expected all of %s'
             % (sorted(reported(included)), sorted(wanted)))
    else:
        passed += 1
    if set(reported(default)) != {os.path.normpath(WALK_MODULES[0]).lower()}:
        fail('walk.default_pruned', 'a default scan reported %s, expected only %s'
             % (sorted(reported(default)), WALK_MODULES[0]))
    else:
        passed += 1
    if reported(default).get(os.path.normpath(WALK_MODULES[0]).lower()) != WALK_KEY:
        fail('walk.root_still_scanned', 'the top-level view lost its row: %s' % reported(default))
    else:
        passed += 1
    print('  %d/%d: default scan prunes fixtures/ and testutils/, --include-tests reports all three,'
          ' the tree that was pointed at stays scanned' % (passed, 3))
    return passed, 3


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
    """TIER 5 -- why this file is allowed to exist inside `benchmark/` at all.

    `aa_parity` scans the whole `benchmark/` tree with cross-file taint, and its blessed baseline holds
    not one `benchmark/gates/` key: a gate file that *reports a finding* moves the parity key set and
    fails the gate. Writing this file the obvious way did exactly that -- a local `scan_rows` helper
    resolved across the tree onto `gate_common.scan_rows`, which wraps `subprocess.run`, and parity
    counted CWE-78 at this file's call site. Imports are excluded because sharing `os`/`sys` is
    meaningless; sharing a callee name with the module that holds the subprocess wrapper is not.
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


def run_falsification(name):
    """Weaken one clause; its owned rows must move, its neighbours and all other CWEs must not.

    Returns 1 when CAUGHT, 0 when MISSED (the clause is decorative), 2 when the mutation itself broke.
    """
    spec = MUTATIONS[name]
    restore()
    try:
        spec['apply']()
        moved, strayed, collateral = [], [], []
        for label in spec['moves'] + spec['holds']:
            after = observe(label)
            if after != _BASE[label]:
                (moved if label in spec['moves'] else strayed).append(label)
            for index, (_target, others) in enumerate(after):
                if others != _BASE[label][index][1]:
                    collateral.append((label, _BASE[label][index][1], others))
    except Exception as exc:
        restore()
        print('MUTATION ERROR: %s: %s' % (type(exc).__name__, exc))
        return 2
    finally:
        restore()
    caught = len(moved) == len(spec['moves']) and not strayed and not collateral
    print('MUTATION %s: %s' % (name, spec['what']))
    print('  owned rows moved: %s/%d (%s)' % (len(moved), len(spec['moves']), ', '.join(moved) or '-'))
    if strayed:
        print('  rows that must not move but did: %s' % ', '.join(strayed))
    if collateral:
        print('  collateral rows of another CWE changed: %s' % (collateral[:1],))
    print('FALSIFICATION VERDICT (%s): %s' % (name,
          'CAUGHT, surgical' if caught else
          'MISSED - this clause is decorative or over-reaching; its rows did not move as claimed'))
    return 1 if caught else 0


def check_battery():
    caught = 0
    for name in sorted(MUTATIONS):
        if run_falsification(name) == 1:
            caught += 1
    print('  battery: %d/%d weakenings CAUGHT and surgical' % (caught, len(MUTATIONS)))
    return caught, len(MUTATIONS)


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
    print('TIER 3 - right name, wrong provenance (fail-closed):')
    prov_n, prov_total = check_provenance()
    print('TIER 4 - walker scope: fixtures/ and testutils/ pruned by default, whole with --include-tests:')
    walk_n, walk_total = check_walk_scope()
    print('TIER 5 - falsification battery + collateral sweep:')
    caught_n, caught_total = check_battery()
    print('TIER 6 - parity hygiene (this file must add no key to the scanned tree):')
    hygiene_n, hygiene_total = check_hygiene()
    work = time.perf_counter() - _BOOT
    print('TIER 7 - cost:')
    work_ok, rss_ok = check_budget(work, peak_rss_mb())

    mandated = quiet_n + loud_n
    print('\nMANDATED INVARIANTS: %d/%d (%d quiet, %d loud)'
          % (mandated, quiet_total + loud_total, quiet_n, loud_n))
    for label, ok in [('%d/%d quiet' % (quiet_n, quiet_total), quiet_n == quiet_total),
                      ('%d/%d loud' % (loud_n, loud_total), loud_n == loud_total),
                      ('%d/%d provenance' % (prov_n, prov_total), prov_n == prov_total),
                      ('%d/%d walker scope' % (walk_n, walk_total), walk_n == walk_total),
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
    print('VERDICT: PASS - DRF/snuba/off-HTTP/HTTP-entrypoint suppressions pinned: '
          '%d/%d mandated invariants, %d provenance rows held loud by import proof alone, %d walker-scope '
          'assertions, all %d weakenings CAUGHT with zero collateral rows of any other CWE moved, in '
          '%.2fs of gate work under %.0f MB.'
          % (mandated, quiet_total + loud_total, prov_total, walk_total, caught_total, work, BUDGET_RSS_MB))
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
