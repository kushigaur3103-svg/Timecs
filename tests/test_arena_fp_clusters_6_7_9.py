"""Arena FP clusters 6, 7 and 9 (release 3.1.0).

Proven from the timecs-vs-semgrep-vs-CodeQL SARIF triage:

  6. `CWE-798` fired on environment *indirection* (`api_key: os.environ/AZURE_KEY`), on a constant
     whose name says it stores an env-var name, and on a redaction stand-in.
  7. `CWE-532` / `CWE-312` fired on LLM token *counters* because a substring match on `token`
     cannot tell `completion_tokens` from `access_token`.
  9. `CWE-20` fired on the documented Django second-form idiom `SecondForm(request.POST)` read
     inside a validated-form scope.

Every case asserts the false shape stays SILENT and the true shape still FIRES.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import (  # noqa: E402
    CWE3A_SENSITIVE_VALUE_RE,
    LLM_TOKEN_METRIC_NAME_RE,
    SENSITIVE_NAME_EXEMPT_RE,
    TaintTracker,
)
from secret_scanner import scan_text  # noqa: E402

METRIC_NAMES = [
    "completion_tokens", "prompt_tokens", "max_output_tokens", "user_max_tokens",
    "output_cost_per_token", "cost_per_token", "token_buffer", "token_count",
    "input_tokens", "output_tokens", "total_tokens", "usage_tokens",
]
CREDENTIAL_NAMES = [
    "access_token", "api_token", "auth_token", "bearer_token", "refresh_token",
    "secret_token", "id_token", "jwt_token", "raw_token", "session_token",
    "token", "api_key", "password", "auth_tokens",
]


def _cwes_at(code: str, line: int) -> set:
    tracker = TaintTracker(files={"snippet.py": code})
    _, sinks, _ = tracker.analyze()
    found = set()
    for sink in sinks:
        meta = sink.metadata or {}
        cwe = meta.get("cwe")
        if cwe and sink.location.line_start == line:
            found.add(cwe)
    return found


class TestTokenMetricVocabulary:
    """Cluster 7: the qualifier table, tested directly so the contract cannot rot."""

    def test_metrics_are_exempt(self):
        for name in METRIC_NAMES:
            assert LLM_TOKEN_METRIC_NAME_RE.match(name), name
            assert SENSITIVE_NAME_EXEMPT_RE.search(name), name
            assert not CWE3A_SENSITIVE_VALUE_RE.match(name), name

    def test_credentials_are_never_exempt(self):
        for name in CREDENTIAL_NAMES:
            assert not LLM_TOKEN_METRIC_NAME_RE.match(name), name
            assert CWE3A_SENSITIVE_VALUE_RE.match(name), name


class TestLoggingTokenCounters:
    def test_token_counter_log_is_silent(self):
        code = 'import logging\nlogger = logging.getLogger(__name__)\n' \
               'logger.info(f"used {completion_tokens} of {max_output_tokens}")\n'
        assert "CWE-532" not in _cwes_at(code, 3)

    def test_streaming_chunk_log_is_silent(self):
        code = 'import logging\nlogger = logging.getLogger(__name__)\n' \
               'logger.debug(f"buffered {token_count} chunks")\n'
        assert "CWE-532" not in _cwes_at(code, 3)

    def test_real_token_log_still_fires(self):
        code = 'import logging\nlogger = logging.getLogger(__name__)\n' \
               'logger.info(f"key={api_token}")\n'
        assert "CWE-532" in _cwes_at(code, 3)


class TestEnvironmentIndirection:
    """Cluster 6: a pointer to a secret is not a secret."""

    def test_yaml_and_python_indirection_are_silent(self):
        for text, name in (
            ("api_key: os.environ/AZURE_KEY\n", "cfg.yaml"),
            ("# api_key: os.environ/AZURE_KEY\n", "cfg.yaml"),
            ("token: env:OPENAI_TOKEN\n", "cfg.yaml"),
            ('password: ${DB_PASSWORD}\n', "cfg.yaml"),
            ('OPENAI_API_KEY = "os.environ/OPENAI_API_KEY"\n', "p.py"),
            ('api_key = "scrubbed_by_provider_for_sensitive_keys"\n', "p.py"),
            ('MODEL_CREDENTIAL_ENV_NAME = "HUGGINGFACE_API_KEY"\n', "p.py"),
        ):
            assert scan_text(text, name) == [], (name, text)

    def test_pasted_secrets_still_fire(self):
        for text, name in (
            ("api_key: sk_live_51HqYbTn2eQ8vKx3mAbcd1234567\n", "cfg.yaml"),
            ('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG9xRq2pLmN"\n', "p.py"),
            ('api_key = "sk-proj-aB3dEfGhIjKlMnOpQrStUvWx"\n', "p.py"),
        ):
            assert scan_text(text, name), (name, text)

    def test_ast_credential_rule_follows_the_same_shape(self):
        assert "CWE-798" not in _cwes_at('api_key = "os.environ/OPENAI_API_KEY"\n', 1)
        assert "CWE-798" not in _cwes_at(
            'api_key = "scrubbed_by_provider_for_sensitive_keys"\n', 1)
        assert "CWE-798" in _cwes_at(
            'api_key = "sk_live_51HqYbTn2eQ8vKx3mAbcd1234567"\n', 1)


class TestDjangoSecondFormIdiom:
    """Cluster 9: `request.POST` handed to a Form constructor is re-validated by Django."""

    def test_second_form_constructor_is_silent(self):
        code = (
            'from django.shortcuts import render\n'
            'def view(request):\n'
            '    form_a = FormA(request.POST)\n'
            '    if form_a.is_valid():\n'
            '        form_b = FormB(request.POST, instance=form_a.instance)\n'
            '        return render(request, "b.html", {"form": form_b})\n'
        )
        assert "CWE-20" not in _cwes_at(code, 5)

    def test_keyword_form_data_is_silent(self):
        code = (
            'def view(request):\n'
            '    form_a = FormA(request.POST)\n'
            '    if form_a.is_valid():\n'
            '        form_b = FormB(data=request.POST)\n'
            '        return form_b\n'
        )
        assert "CWE-20" not in _cwes_at(code, 4)

    def test_raw_post_still_fires_when_read_directly(self):
        code = (
            'from django.shortcuts import redirect\n'
            'def view(request):\n'
            '    form = MyForm(request.POST)\n'
            '    if form.is_valid():\n'
            '        target = request.POST["next"]\n'
            '        return redirect(target)\n'
        )
        assert "CWE-20" in _cwes_at(code, 5)

    def test_raw_post_passed_to_a_non_form_still_fires(self):
        code = (
            'def view(request):\n'
            '    form = MyForm(request.POST)\n'
            '    if form.is_valid():\n'
            '        save_payload(request.POST)\n'
        )
        assert "CWE-20" in _cwes_at(code, 4)
