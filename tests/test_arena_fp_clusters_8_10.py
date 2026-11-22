"""Arena FP clusters 8 and 10 (release 3.1.0).

Every case here was measured against the engine before the rule was widened, and each one states
which false positive it retires and which true positive must survive it. A suppression that cannot
show its loud sibling is not a fix, it is a blindfold, so the silent shapes and the loud shapes sit
next to each other on purpose.

Clusters:
  8. CWE-117  - an audit line that names the authenticated subject, not client input
  9/10. CWE-319 - `self.create_connection(db_file)` is a storage helper, not a socket
      CWE-287  - `author` is a byline, `auth` is a credential
      CWE-95   - `x.eval(tree)` is a method, `eval(text)` is the builtin
      CWE-916  - sha256 of a secret is a cache key, sha256 of a password is a weak store
      CWE-96   - `globals().get(name, default)` asks whether something is present
      CWE-209  - exception text returned from a library method reaches a caller, not a client
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ast_scanner
from ast_scanner import TaintTracker


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


# A route so CWE-117 has a client to leak to; without it the same log line is already silent, which
# would let the test pass without the rule doing any work.
_ROUTE = '''import logging
log = logging.getLogger(__name__)


@blueprint.route("/x")
def view(request):
    %s
'''


# ─── Cluster 8: CWE-117 audit lines that name the authenticated subject ──────

class TestLogInjectionSubjectAudit:
    def test_request_user_audit_is_silent(self):
        # NetBox/DRF style audit trail: the value is the session-loaded user, never a request field.
        _silent(_ROUTE % 'log.info(f"User {request.user} acted")\n', 7, "CWE-117")

    def test_percent_style_subject_audit_is_silent(self):
        _silent(_ROUTE % 'log.info("User %s acted", request.user)\n', 7, "CWE-117")

    def test_identity_members_are_silent(self):
        _silent(_ROUTE % 'log.debug(f"{request.user.username} ({request.user.id}) signed in")\n',
                7, "CWE-117")

    def test_get_username_is_silent(self):
        _silent(_ROUTE % 'log.info(f"{request.user.get_username()} acted")\n', 7, "CWE-117")

    def test_one_client_hole_keeps_the_finding(self):
        # The subject is inert; the query is whatever the client typed. Both appear, so it stays loud.
        _fires(_ROUTE % 'log.info(f"User {request.user} typed {request.POST[q]}")\n',
               7, "CWE-117")

    def test_plain_client_input_still_fires(self):
        _fires(_ROUTE % 'log.info(f"bad login for {request.form[username]}")\n', 7, "CWE-117")


# ─── Cluster 10a: CWE-319, a helper that borrowed the socket verb ────────────

class TestCleartextSocketReceiver:
    SOCKET = ('import socket\n\n\ndef poll(host, port):\n'
              '    return socket.create_connection((host, port)).recv(1024)\n')
    HELPER = ('import sqlite3\n\n\nclass Store:\n'
              '    def create_connection(self, db_file):\n'
              '        return sqlite3.connect(db_file)\n\n'
              '    def open_db(self, name):\n        return self.create_connection(name)\n')

    def test_module_socket_call_fires(self):
        _fires(self.SOCKET, 5, "CWE-319")

    def test_instance_helper_method_is_silent(self):
        _silent(self.HELPER, 8, "CWE-319")

    def test_instance_receivers_are_named(self):
        assert ast_scanner.RAW_SOCKET_INSTANCE_RECEIVERS == frozenset({"self", "cls", "super"})


# ─── Cluster 10b: CWE-287, `author` is not `auth` ────────────────────────────

class TestAuthenticationNameBoundary:
    def test_author_compare_is_silent(self):
        _silent('def classify(item):\n    if item.author == "ai":\n        return 1\n    return 0\n',
                2, "CWE-287")

    def test_authentication_compare_still_fires(self):
        _fires('def check(authentication):\n    if authentication == "basic":\n        return 1\n'
               '    return 0\n', 2, "CWE-287")

    def test_byline_family_excluded_but_authorize_kept(self):
        credential = ast_scanner.CWE3A_PASSWORD_NAME_RE
        for name in ("author", "authors", "author_name", "authorship"):
            assert not credential.search(name), name
        for name in ("auth", "authentication", "is_authenticated", "auth_token", "oauth",
                     "authorized", "authorization"):
            assert credential.search(name), name


# ─── Cluster 10c: CWE-95, the builtin and the method are different verbs ─────

class TestEvalMethodVersusBuiltin:
    def test_expression_tree_eval_is_silent(self):
        _silent('class CS:\n    def eval(self, d):\n        return d\n\n\n'
                'def run(x, cs):\n    return CS().eval(x)\n', 7, "CWE-95")

    def test_unknown_receiver_eval_is_silent(self):
        _silent('def run(engine, x):\n    return engine.eval(x)\n', 2, "CWE-95")

    def test_builtin_eval_still_fires(self):
        _fires('def run(req):\n    return eval(req.GET["e"])\n', 2, "CWE-95")

    def test_proven_code_engine_still_fires(self):
        _fires('import numexpr\n\n\ndef run(x):\n    return numexpr.eval(x)\n', 5, "CWE-95")


# ─── Cluster 10d: CWE-916, a strong digest needs a password inside it ────────

class TestWeakPasswordHashContext:
    def test_secret_cache_key_is_silent(self):
        _silent('import hashlib\nSECRET_KEY = "x"\n'
                'DEPLOYMENT_ID = hashlib.sha256(SECRET_KEY.encode()).hexdigest()\n',
                3, "CWE-916")

    def test_sha256_of_password_still_fires(self):
        _fires('import hashlib\n\n\ndef hash_pw(password):\n'
               '    return hashlib.sha256(password.encode()).hexdigest()\n', 5, "CWE-916")

    def test_md5_of_a_secret_still_fires(self):
        # md5/sha1 are broken whatever they fold, so they keep the wider secret vocabulary.
        _fires('import hashlib\n\n\ndef sign(secret):\n'
               '    return hashlib.md5(secret.encode()).hexdigest()\n', 5, "CWE-916")

    def test_password_vocabulary_is_narrower_than_secret_vocabulary(self):
        password_only = ast_scanner.CWE3A_PASSWORD_ONLY_NAME_RE
        assert not password_only.search("credential_args")
        assert not password_only.search("SECRET_KEY")
        for name in ("password", "passwd", "pwd", "passphrase", "user_pass"):
            assert password_only.search(name), name


# ─── Cluster 10e: CWE-96, a probe with a fallback is not a dispatcher ────────

class TestGlobalsProbeVersusDispatch:
    def test_lookup_with_default_is_silent(self):
        _silent('def loader(name):\n    return globals().get(name, None)\n', 2, "CWE-96")

    def test_lookup_without_default_still_fires(self):
        _fires('def loader(name):\n    return globals().get(name)\n', 2, "CWE-96")


# ─── Cluster 4 (structural half): CWE-209 needs a client, not a caller ───────

class TestErrorExposureNeedsAClient:
    def test_library_method_detail_return_is_silent(self):
        # LangChain's tool contract: `repr(e)` goes back to the agent that called `_run`.
        _silent('class Tool:\n    def _run(self, query):\n        try:\n'
                '            return compute(query)\n        except Exception as e:\n'
                '            return repr(e)\n', 5, "CWE-209")

    def test_column_renderer_is_silent(self):
        _silent('class Table:\n    def render_cell(self, value):\n        try:\n'
                '            return fmt(value)\n        except ValueError as e:\n'
                '            return str(e)\n', 5, "CWE-209")

    def test_free_function_detail_still_fires(self):
        # The blessed corpus shape: nothing proves who prints it, so unknown stays reported. The rule
        # anchors the disclosure on the `except` line, which is where the handler starts.
        _fires('def handle():\n    try:\n        return load()\n'
               '    except Exception as e:\n        return str(e)\n', 4, "CWE-209")

    def test_view_handler_method_still_fires(self):
        _fires('from django.views.generic import View\n\n\nclass V(View):\n'
               '    def get(self, request):\n        try:\n            return ok()\n'
               '        except Exception as e:\n            return str(e)\n', 8, "CWE-209")

    def test_helper_refuses_an_http_looking_method(self):
        assert {"get", "post", "put", "patch", "delete", "head", "options"} <= \
            ast_scanner.TaintTracker.CWE209_HTTP_METHOD_NAMES
