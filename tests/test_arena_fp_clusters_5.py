"""Arena FP cluster 5 (release 3.1.0): CWE-79 / CWE-1336 response and template shapes.

Django's own escaping idiom is markup the author wrote with escaped holes around it. Before this
release the engine believed a sanitizer only when the response body *was* one call, so
`HttpResponse("<b>" + escape(name) + "</b>")` - straight from Django's security docs - was reported
as XSS. The rule now asks the question per substitution hole: a literal contributes no characters,
an escaping wrapper neutralises its argument, and the trust-me wrappers (`mark_safe`, `Markup`) are
walked through instead of believed, so `mark_safe(escape(x))` is silent while `mark_safe("<b>" + x)`
still reports. Every silent shape below is paired with the loud shape that keeps it honest.

Clusters:
  5a. CWE-79  - escape-wrapped response bodies, five spellings of the same Django idiom
  5b. CWE-79  - `@register.filter(is_safe=True)` has to contain real unsafe concatenation
  5c. CWE-1336/CWE-79 - a static template with a tainted context is one finding, not two
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ast_scanner
from ast_scanner import TaintTracker

PRE = ('from django.http import HttpResponse\n'
       'from django.utils.html import escape, format_html\n'
       'from django.utils.safestring import mark_safe\n'
       'from django.utils.http import urlencode\n'
       'from django import template\n'
       'register = template.Library()\n\n\n')


def _cwes_at(code: str, line: int) -> set[str]:
    tracker = TaintTracker(files={"snippet.py": code})
    _sources, sinks, _edges = tracker.analyze()
    return {(sink.metadata or {}).get("cwe") for sink in sinks
            if sink.location.line_start == line and (sink.metadata or {}).get("cwe")}


def _fires(code: str, line: int, expected_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert expected_cwe in cwes, f"Expected {expected_cwe} at line {line}, got {cwes}"


def _silent(code: str, line: int, retired_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert retired_cwe not in cwes, f"Unexpected {retired_cwe} at line {line}, got {cwes}"


def _absent(code: str, retired_cwe: str) -> None:
    tracker = TaintTracker(files={"snippet.py": code})
    _sources, sinks, _edges = tracker.analyze()
    fired = [(sink.location.line_start, (sink.metadata or {}).get("cwe")) for sink in sinks
             if (sink.metadata or {}).get("cwe") == retired_cwe]
    assert not fired, f"Unexpected {retired_cwe} at {fired}"


def _view(body: str) -> str:
    """A response view; `PRE` is eight lines, so the body lands on line 10."""
    return PRE + f"def view(request, name):\n    return {body}\n"


def _pipeline_cwes(code: str) -> set[str]:
    """The XSS-family CWEs the shipped CLI reports for one file - what SARIF triage counts.

    The collector layer and the response layer disagree on purpose: a page with a static template
    and a tainted context is one finding, and only the pipeline knows it.
    """
    import contextlib
    import io
    import json
    import tempfile

    import cli
    directory = Path(tempfile.mkdtemp(prefix="tcs_c5_"))
    (directory / "view.py").write_text(code, encoding="utf-8")
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        cli.main(["scan", str(directory), "--format", "json", "--workers", "1", "--include-tests"])
    payload = stdout.getvalue()
    data = json.loads(payload[payload.find("{"):])
    return {finding["cwe"] for finding in data["findings"]
            if finding["cwe"] in {"CWE-79", "CWE-1336"}}


# ─── 5a: the same escaping idiom, five ways to spell it ──────────────────────

class TestEscapedResponseBody:
    CONCAT = _view('HttpResponse("<b>" + escape(name) + "</b>")')
    FSTRING = _view('HttpResponse(f"<b>{escape(name)}</b>")')
    MARK_ESC = _view('HttpResponse(mark_safe(escape(name)))')
    PERCENT = _view('HttpResponse("<b>%s</b>" % escape(name))')
    FORMAT_HTML = _view('HttpResponse(format_html("<b>{}</b>", name))')

    def test_concatenated_escape_is_silent(self):
        _silent(self.CONCAT, 10, "CWE-79")

    def test_fstring_hole_inside_escape_is_silent(self):
        _silent(self.FSTRING, 10, "CWE-79")

    def test_mark_safe_of_an_escape_is_silent(self):
        _silent(self.MARK_ESC, 10, "CWE-79")

    def test_percent_format_of_an_escape_is_silent(self):
        _silent(self.PERCENT, 10, "CWE-79")

    def test_format_html_is_silent(self):
        _silent(self.FORMAT_HTML, 10, "CWE-79")

    def test_mark_safe_of_raw_concatenation_still_fires(self):
        _fires(_view('HttpResponse(mark_safe("<b>" + name + "</b>"))'), 10, "CWE-79")

    def test_raw_fstring_hole_still_fires(self):
        _fires(_view('HttpResponse(f"<b>{name}</b>")'), 10, "CWE-79")

    def test_raw_percent_operand_still_fires(self):
        _fires(_view('HttpResponse("<b>%s</b>" % name)'), 10, "CWE-79")

    def test_partly_escaped_ternary_still_fires(self):
        # The `else` branch reaches the page raw, so one escaped side is not enough.
        code = (PRE + 'def view(request, name, other):\n'
                '    return HttpResponse(f"<b>{escape(name) if other else name}</b>")\n')
        _fires(code, 10, "CWE-79")

    def test_escaped_name_bound_in_a_local_stays_silent(self):
        _absent(PRE + 'def view(request, name):\n    body = "<b>" + escape(name) + "</b>"\n'
                '    return HttpResponse(body)\n', "CWE-79")

    def test_unescaped_name_bound_in_a_local_still_fires(self):
        _fires(PRE + 'def view(request, name):\n    body = "<b>" + name + "</b>"\n'
               '    return HttpResponse(body)\n', 11, "CWE-79")


# ─── 5b: is_safe=True only switches auto-escaping off ────────────────────────

class TestTemplateFilterSafetyFlag:
    def test_raw_interpolation_in_an_is_safe_filter_fires(self):
        _fires(PRE + '@register.filter(is_safe=True)\ndef bold(usr):\n    return f"<b>{usr}</b>"\n',
               9, "CWE-79")

    def test_concatenated_argument_in_an_is_safe_filter_fires(self):
        _fires(PRE + '@register.filter(is_safe=True)\ndef hl(value, term):\n'
               '    return value.replace(term, "<b>" + term + "</b>")\n', 9, "CWE-79")

    def test_format_html_filter_is_silent(self):
        _silent(PRE + '@register.filter(is_safe=True)\ndef bold(usr):\n'
                '    return format_html("<b>{}</b>", usr)\n', 9, "CWE-79")

    def test_escape_wrapped_filter_is_silent(self):
        _silent(PRE + '@register.filter(is_safe=True)\ndef bold(usr):\n'
                '    return mark_safe(escape(usr))\n', 9, "CWE-79")

    def test_percent_encoded_filter_is_silent(self):
        _silent(PRE + '@register.filter(is_safe=True)\ndef link(value):\n'
                '    return "?" + urlencode({"a": value})\n', 9, "CWE-79")

    def test_an_undecorated_filter_never_takes_the_flag(self):
        _silent(PRE + 'def bold(usr):\n    return f"<b>{usr}</b>"\n', 9, "CWE-79")


# ─── 5c: a static template with a tainted context is one finding ─────────────

class TestStaticTemplateIsNotInjection:
    STATIC = ('import jinja2\nfrom django.http import HttpResponse\n\n\n'
              'def view(request, name):\n'
              '    t = jinja2.Template("Hello {{ name }}!")\n'
              '    return HttpResponse(t.render(name=request.GET["n"]))\n')
    INJECTED = ('import jinja2\n\n\ndef render_greeting(name):\n'
                '    template = jinja2.Template(f"Hello {name}!")\n'
                '    return template.render()\n')

    def test_static_template_tainted_context_is_not_1336(self):
        # Reported by the shipped pipeline, because the collector layer emits the pair and the
        # response layer is what decides a page has one vulnerability, not two.
        assert _pipeline_cwes(self.STATIC) == {"CWE-79"}

    def test_injected_template_source_is_still_1336(self):
        assert "CWE-1336" in _pipeline_cwes(self.INJECTED)

    def test_the_same_row_is_still_reported_as_xss(self):
        _fires(self.STATIC, 7, "CWE-79")

    def test_injected_template_source_still_fires_as_1336(self):
        _fires(self.INJECTED, 6, "CWE-1336")

    def test_corpus_injection_rows_are_still_reported(self):
        # The blessed pair: both CWEs on the dynamic-source lines, nothing added to the static ones.
        for stem, line in (("bad", 6), ("test_v01_bad", 4), ("test_v04_bad", 8), ("test_v05_bad", 8)):
            path = ROOT / "benchmark/corpus/cwe_1336_ssti" / f"{stem}.py"
            _fires(path.read_text(encoding="utf-8"), line, "CWE-1336")

    def test_corpus_xss_rows_survive_the_escaping_rule(self):
        for stem, line in (("bad", 6), ("test_v01_bad", 2), ("test_v02_bad", 2),
                           ("test_v03_bad", 3), ("test_v05_bad", 3)):
            path = ROOT / "benchmark/corpus/cwe_79_xss" / f"{stem}.py"
            _fires(path.read_text(encoding="utf-8"), line, "CWE-79")


# ─── Table contracts ─────────────────────────────────────────────────────────

class TestMarkupNeutraliserTables:
    def test_every_escaping_wrapper_neutralises(self):
        assert ast_scanner.XSS_ESCAPING_WRAPPERS <= ast_scanner.CWE79_MARKUP_NEUTRALIZERS

    def test_a_trust_me_wrapper_is_never_its_own_neutraliser(self):
        for wrapper in ast_scanner.XSS_SAFE_WRAPPERS:
            assert wrapper not in ast_scanner.CWE79_MARKUP_NEUTRALIZERS, wrapper
        assert "mark_safe" not in ast_scanner.CWE79_MARKUP_NEUTRALIZERS

    def test_transparent_set_is_the_lowered_trust_me_family_plus_markup(self):
        assert ast_scanner.CWE79_MARKUP_TRANSPARENT_WRAPPERS == (
            {w.lower() for w in ast_scanner.XSS_SAFE_WRAPPERS} | {"markup"})

    def test_escaping_and_trust_me_families_are_disjoint(self):
        assert not ({w.lower() for w in ast_scanner.XSS_SAFE_WRAPPERS}
                    & ast_scanner.XSS_ESCAPING_WRAPPERS)

    def test_the_fold_refuses_what_it_cannot_prove(self):
        import ast
        fold = ast_scanner._c79_markup_is_escaped_only
        for unsafe in ('name', 'user.name', 'parts["k"]', 'render_it(name)', 'mark_safe(name) '
                       'if x else name'):
            assert not fold(ast.parse(unsafe, mode="eval").body), unsafe
        for safe in ('"<b>"', 'f"<b>{escape(name)}</b>"', 'mark_safe(escape(name))',
                     '"<b>%s</b>" % escape(name)', 'escape(a) + escape(b)'):
            assert fold(ast.parse(safe, mode="eval").body), safe
