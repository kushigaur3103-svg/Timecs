"""Arena FP clusters 1 and 2 (release 3.1.0): CWE-862 authorisation inheritance, CWE-601 internal URL producers.

Same contract as the other cluster files: every suppression is shown next to the loud row it must not
swallow, and every expectation here was read off the engine before it was written down. Two of the
shapes deliberately STAY reported, and the tests say so, because a test that only asserts silence is
how a false negative gets blessed.

Cluster 1 - CWE-862 `MISSING_AUTHORIZATION` (45 arena FPs). The rule charges an object fetch taken by a
client-supplied id in code a request enters. It was over-charging two proven cases:
  * a class-based view whose authorisation lives in a BASE (`LoginRequiredMixin`,
    `ObjectPermissionRequiredMixin`, `UserPassesTestMixin`, NetBox's `BaseObjectView`/`ObjectEditView`/
    `BulkDeleteView`) - the guard is inherited, not omitted;
  * a queryset already restricted to the authenticated principal (`filter(user=request.user)`), where
    the id can no longer name somebody else's row.

Cluster 2 - CWE-601 `OPEN_REDIRECT` (41 arena FPs). `redirect(x)` is only a finding when x can be an
off-site URL. Producers that answer from this application's own URLconf or from the object itself are
internal by construction: `reverse`/`reverse_lazy`, `resolve_url`, `obj.get_absolute_url()`, and a
same-file wrapper that provably runs `url_has_allowed_host_and_scheme` on its argument before returning
it.

Known limits, pinned rather than hidden: `self.get_return_url()` written as a METHOD still reports,
because the wrapper proof reads this file's module-level definitions and a method body reached through
`self` in another class is not proof this file can supply; and `resolve_url(request.GET["next"])` still
reports, because `resolve_url` echoes back whatever is not in its own URLconf.

Run it either way:
    python tests/test_arena_fp_clusters_1_2.py
    python -m pytest tests/test_arena_fp_clusters_1_2.py -q
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ast_scanner
from ast_scanner import TaintTracker

TRACKED = {"CWE-862", "CWE-601"}


def _findings(code: str, filename: str = "app/views.py"):
    tracker = TaintTracker(files={filename: code})
    _sources, sinks, _edges = tracker.analyze()
    return sorted({(sink.location.line_start, (sink.metadata or {}).get("cwe"))
                   for sink in sinks if (sink.metadata or {}).get("cwe") in TRACKED})


def _fires(code: str, line: int, cwe: str) -> None:
    got = _findings(code)
    assert (line, cwe) in got, f"expected {cwe} at line {line}, got {got}"


def _silent(code: str, line: int, cwe: str) -> None:
    got = _findings(code)
    assert (line, cwe) not in got, f"unexpected {cwe} at line {line}, got {got}"


def _absent(code: str, cwe: str, filename: str = "app/views.py") -> None:
    """For a fixture with exactly one candidate row: the rule never fires anywhere in it."""
    got = _findings(code, filename)
    assert all(found_cwe != cwe for _line, found_cwe in got), f"unexpected {cwe} in {got}"


# A view-shaped class over a bare `objects.get` -- the shape the NetBox/LiteLLM triage kept hitting. The
# bases are the only thing that varies between the loud and the quiet case.
_CBV = '''from django.views.generic import View


class DocView(%s):
    def get(self, request, pk):
        return Document.objects.get(pk=pk)
'''

# `redirect` fed by a value; the body is line 8.
_URL = '''from django.shortcuts import redirect, resolve_url
from django.utils.http import url_has_allowed_host_and_scheme


def view(request, obj):
    %s
'''

_SCOPED = '''from django.shortcuts import get_object_or_404


def view(request, doc_id, actor):
    %s
'''


# ─── Cluster 1a: the authorisation guard is inherited, not missing ────────────────────────────────

class TestCBVAuthorisationInheritance:
    def test_an_unguarded_class_view_is_the_loud_baseline(self):
        _fires(_CBV % "View", 5, "CWE-862")

    def test_login_required_mixin_silences_the_fetch(self):
        _silent(_CBV % "LoginRequiredMixin, View", 5, "CWE-862")

    def test_the_mixin_alone_is_enough(self):
        # No `View` in the bases: `DocView` names the class, the mixin proves the guard.
        _silent(_CBV % "LoginRequiredMixin", 5, "CWE-862")

    def test_permission_mixin_naming_convention_is_a_proof(self):
        _silent(_CBV % "ObjectPermissionRequiredMixin", 5, "CWE-862")

    def test_netbox_generic_views_are_a_proof(self):
        _silent(_CBV % "BaseObjectView", 5, "CWE-862")
        _silent(_CBV % "BulkDeleteView", 5, "CWE-862")

    def test_a_mixin_that_guards_nothing_is_not_a_proof(self):
        # `SerializerMixin` is a serialisation helper. Refusing it is what keeps the suffix honest: a
        # base merely ending in `Mixin` says nothing about who may act.
        _fires(_CBV % "SerializerMixin", 5, "CWE-862")

    def test_bare_framework_bases_are_never_a_proof(self):
        _fires(_CBV % "APIView", 5, "CWE-862")
        _fires(_CBV % "ViewSet", 5, "CWE-862")

    def test_opting_out_of_permissions_outranks_the_mixin(self):
        # `permission_classes = ()` is the author declaring that the inherited check does not run here.
        _fires('''from django.views.generic import View


class DocView(LoginRequiredMixin, View):
    permission_classes = ()

    def get(self, request, pk):
        return Document.objects.get(pk=pk)
''', 7, "CWE-862")

    def test_the_sentry_table_stays_free_of_generic_bases(self):
        # The corpus rows are written on `View`/`APIView`/`ViewSet` deliberately; if a future widening
        # ever put one of them in a table the engine trusts, every one of those rows goes quiet.
        generic = {"View", "APIView", "ViewSet", "GenericAPIView"}
        # `Endpoint` is tested too because the bare word names no domain, and `generic_endpoint.py`
        # is blessed LOUD for exactly that reason.
        assert not (ast_scanner.CWE862_DOMAIN_SCOPED_ENDPOINT_BASES & (generic | {"Endpoint"}))
        assert generic <= ast_scanner.CWE862_UNENFORCEABLE_BASE_NAMES


# ─── Cluster 1b: the queryset is already restricted to the caller's own rows ──────────────────────

class TestSubjectScopedQueryset:
    def test_filter_on_request_user_silences_the_id(self):
        _silent(_SCOPED % 'return get_object_or_404(Document.objects.filter(user=request.user), pk=doc_id)',
                4, "CWE-862")

    def test_owner_column_and_self_request_are_also_subjects(self):
        _silent(_SCOPED % 'return get_object_or_404(Document.objects.filter(owner=self.request.user), pk=doc_id)',
                4, "CWE-862")

    def test_an_arbitrary_owner_value_is_not_the_subject(self):
        # `user=actor` is whatever the caller chose -- the restriction proves nothing about WHO acted.
        _fires(_SCOPED % 'return get_object_or_404(Document.objects.filter(user=actor), pk=doc_id)',
               4, "CWE-862")

    def test_a_bare_fetch_still_reports(self):
        _fires(_SCOPED % "return get_object_or_404(Document, pk=doc_id)", 4, "CWE-862")


# ─── Cluster 1c: the blessed corpus rows must survive the two new proofs ─────────────────────────

def test_corpus_idor_rows_are_still_reported():
    corpus = ROOT / "benchmark" / "corpus" / "cwe_862_idor"
    checked = 0
    for name in ("test_v01_bad.py", "test_v02_bad.py", "test_v03_bad.py", "test_v04_bad.py",
                 "test_v05_bad.py", "test_v06_bad.py"):
        code = (corpus / name).read_text(encoding="utf-8")
        assert any(cwe == "CWE-862" for _line, cwe in _findings(code, name)), name
        checked += 1
    assert checked == 6


# ─── Cluster 2a: producers that answer from this application's own URLconf ────────────────────────

class TestInternalUrlProducers:
    def test_a_client_supplied_next_is_the_loud_baseline(self):
        _fires(_URL % 'return redirect(request.GET["next"])', 6, "CWE-601")

    def test_get_absolute_url_is_the_objects_own_page(self):
        _absent(_URL % "return redirect(obj.get_absolute_url())", "CWE-601")

    def test_reverse_of_a_named_route_is_internal(self):
        _absent(_URL % 'return redirect(reverse("home"))', "CWE-601")

    def test_resolve_url_of_a_name_or_an_object_is_internal(self):
        _absent(_URL % 'return redirect(resolve_url("home"))', "CWE-601")
        _absent(_URL % "return redirect(resolve_url(obj))", "CWE-601")

    def test_resolve_url_of_client_text_still_reports(self):
        # `resolve_url` falls through to whatever is not in the URLconf, so it cannot vouch for this one.
        _fires(_URL % 'return redirect(resolve_url(request.GET["next"]))', 6, "CWE-601")

    def test_an_explicit_validator_answered_before_the_redirect(self):
        _absent(_URL % 'return redirect(url_has_allowed_host_and_scheme(request.GET["next"], "x.com"))',
                "CWE-601")


# ─── Cluster 2b: a wrapper that proves it validates ──────────────────────────────────────────────

_WRAPPER = '''from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def get_return_url(next_url):
    if url_has_allowed_host_and_scheme(next_url, allowed_hosts=None):
        return next_url
    return "/"


def lookalike(next_url):
    return next_url


def view(request):
    return redirect(get_return_url(request.GET["next"]))


def other(request):
    return redirect(lookalike(request.GET["next"]))
'''


class TestValidatingRedirectWrapper:
    def test_a_wrapper_that_validates_its_argument_is_safe(self):
        assert (16, "CWE-601") not in _findings(_WRAPPER)

    def test_a_wrapper_with_the_same_name_that_validates_nothing_is_not(self):
        _fires(_WRAPPER, 20, "CWE-601")

    def test_a_zero_argument_return_url_method_is_internal(self):
        # `def get_return_url(self)` has no parameter a client could reach, so the destination is the
        # object's own page: the same proof `get_absolute_url` runs on, and the shape NetBox writes.
        _silent('''from django.shortcuts import redirect


class Wizard:
    def view(self, request):
        return redirect(self.get_return_url())
''', 6, "CWE-601")

    def test_a_return_url_method_handed_client_input_is_charged(self):
        # The excuse belongs to the zero-argument declaration. Pass it a request field and it is no
        # longer that method, so `unknown stays reported` resumes: the redirect is reported.
        _fires('''from django.shortcuts import redirect


class Wizard:
    def view(self, request):
        return redirect(self.get_return_url(request.GET["next"]))
''', 6, "CWE-601")


if __name__ == "__main__":
    tests = []
    for _name, _obj in sorted(globals().items()):
        if _name.startswith("Test") and isinstance(_obj, type):
            tests.extend((_name + "." + m, getattr(_obj, m))
                         for m in sorted(dir(_obj)) if m.startswith("test_") and callable(getattr(_obj, m)))
        elif _name.startswith("test_") and callable(_obj):
            tests.append((_name, _obj))
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {name}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
