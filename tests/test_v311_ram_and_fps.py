"""v3.1.1: the worker pool sized by the machine alone, and the false-positive clusters.

Written to the house idiom -- every case here was measured against the engine, and each suppression
is shown next to the true positive that must survive it. Nothing in this file scans a repository: the
engine is handed one in-memory snippet (or one tiny corpus fixture) per case, so the whole file runs
inside the laptop's memory headroom.

Part one is machine sizing, twice. `--workers auto` used to answer `os.cpu_count()` and hand that
number to the process pool, which bypassed the RAM governor entirely: a 4-core, 16 GB machine opened
five interpreters, each importing its own copy of the rule bank, and peak resident memory tripled
before a single file was read. It then acquired a cap of its own, 2 workers on any machine at or
below 16 GB, which threw away the governor's measurement on the CI runner it was written for; at
v3.1.1 the answer is the governor's again, and only the governor's. The second half of part one is
Phase 2, where the fan-out is decided inside the engine: a corpus is now collected across workers
that share the parent's trees by copy-on-write instead of a pool that pickles 2,700 abstract syntax
trees in and back out, and parsing stopped fanning out at all, because `ast.parse` in the parent
beats any number of workers that have to start up to do it.

Part two is the clusters observed on the LangChain corpus at v3.1.0, plus the one shape of cluster 3
that survived it:

  1. CWE-89   - one multi-line `cur.execute(...)` reported on both lines its query argument spans
  2. CWE-918/939 - the same `urlopen(req)` charged twice, once as SSRF and once as protocol access
  3. CWE-209  - `return e` / `return repr(e)` from a library method with no client to leak to
  4. CWE-434  - `model.save(Path(self.temp_dir.name, "model.bin"))`, a write no client chose
  5. CWE-798  - `_HUGGINGFACE_API_KEY_ENV_NAME = "HUGGINGFACE_API_KEY"`, a name, not a secret
  6. CWE-312  - `sys.stdout.write(token)` inside an LLM streaming callback
  7. CWE-287  - `if username == "" and password == "": auth = None`, which declines to authenticate
  8. CWE-209  - `return repr(e), []`, the tuple spelling of cluster 3 that survived it
"""

import ast
import contextlib
import io
import pickle
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ast_scanner
import cli
from ast_scanner import TaintTracker


def _rows(code: str, filename: str = "snippet.py") -> set:
    tracker = TaintTracker(files={filename: code})
    _sources, sinks, _edges = tracker.analyze()
    return {(sink.location.line_start, (sink.metadata or {}).get("cwe"))
            for sink in sinks if (sink.metadata or {}).get("cwe")}


def _cwes_at(code: str, line: int) -> set:
    return {cwe for (lineno, cwe) in _rows(code) if lineno == line}


def _count(code: str, cwe: str) -> int:
    return sum(1 for (_line, found) in _rows(code) if found == cwe)


def _fires(code: str, line: int, expected_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert expected_cwe in cwes, f"Expected {expected_cwe} at line {line}, got {cwes}"


def _silent(code: str, line: int, retired_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert retired_cwe not in cwes, f"Unexpected {retired_cwe} at line {line}, got {cwes}"


# ─── Part one: `--workers auto` is the RAM governor's answer, whole ──────────

class TestAutoWorkerRamScaling:
    """`auto` asks one machine question and takes its answer.

    v3.1.0 routed `auto` through `compute_safe_workers()` and then clipped the result to 2 workers on
    any machine with 16 GB or less installed -- a second, dumber governor that overrode a measurement
    the first one had already made, on the exact reason for making it. The clip is gone; these cases
    are what the flag answers now.
    """

    def _auto_with(self, monkeypatch, governor):
        import tcs.parallel_scanner

        monkeypatch.setattr(tcs.parallel_scanner, "compute_safe_workers", governor)
        return cli._auto_worker_count()

    def test_auto_is_used_for_the_auto_keyword(self, monkeypatch):
        # The bug was `return os.cpu_count()`; whatever the machine's core count is, the answer now
        # comes from the governor, so this test pins the wiring rather than a number.
        calls = []
        monkeypatch.setattr(cli, "_auto_worker_count", lambda: (calls.append(1), 2)[1])
        assert cli._parse_workers_arg("auto") == 2
        assert calls == [1]

    def test_the_governors_answer_is_the_answer(self, monkeypatch):
        # Every size the governor may return passes through untouched, including the ones a
        # small-machine cap used to clamp.
        for answer in (1, 2, 4, 6, 12):
            assert self._auto_with(monkeypatch, lambda a=answer: a) == answer

    def test_scaling_is_the_real_arithmetic_not_a_stub(self, monkeypatch):
        # The three machines in the release brief, run through `compute_safe_workers` itself: free
        # RAM is measured, the 900 MB floor decides the laptop, `WORKER_RAM_BUDGET_MB` divides what
        # is left, cores are held back by the platform's reservation, and `MAX_WORKERS_CEILING` is
        # the ceiling. The reservation is the one variable: Windows keeps `MIN_FREE_CORES` free for
        # DWM whatever the RAM says, a POSIX runner keeps one core once free RAM clears
        # `LARGE_MACHINE_FREE_RAM_MB`, and below that line POSIX pays the same tax as Windows.
        import types

        import tcs.parallel_analyzer
        import tcs.parallel_scanner as scanner

        def answer(cores, free_mb, os_name):
            monkeypatch.setattr(scanner, "os", types.SimpleNamespace(
                cpu_count=lambda: cores, name=os_name))
            monkeypatch.setattr(tcs.parallel_analyzer, "available_ram_mb", lambda: float(free_mb))
            return cli._auto_worker_count()

        big = scanner.LARGE_MACHINE_FREE_RAM_MB + 1
        assert answer(4, scanner.HARD_SAFETY_THRESHOLD_MB - 1, "posix") == 1
        assert answer(4, 13_000, "nt") == 4 - scanner.MIN_FREE_CORES
        assert answer(6, 13_000, "nt") == 4
        assert answer(16, 13_000, "nt") == scanner.MAX_WORKERS_CEILING
        assert answer(6, big, "posix") == 5, "one reserved core, four workers on a 6-vCPU runner"
        assert answer(6, 3_300, "posix") == answer(6, 3_300, "nt"), \
            "below the large-machine line POSIX pays the Windows reservation too"

    def test_the_small_machine_cap_is_gone(self, monkeypatch):
        assert not hasattr(cli, "AUTO_POOL_SMALL_MACHINE_WORKERS")
        assert not hasattr(cli, "AUTO_POOL_SMALL_MACHINE_TOTAL_MB")
        assert not hasattr(cli, "_total_ram_mb"), \
            "installed RAM was only ever read to clamp the governor's answer"

    def test_governor_refusal_stays_serial(self, monkeypatch):
        import tcs.parallel_scanner

        def explode():
            raise RuntimeError("no RAM reading")

        monkeypatch.setattr(tcs.parallel_scanner, "compute_safe_workers", explode)
        assert cli._auto_worker_count() == 1

    def test_explicit_worker_count_never_passes_through_the_governor(self, monkeypatch):
        # `--workers 3` is an instruction, not a default; it must not be clamped and it must not
        # consult the governor either.
        def forbidden():
            raise AssertionError("the governor must not be consulted for an explicit count")

        import tcs.parallel_scanner
        monkeypatch.setattr(tcs.parallel_scanner, "compute_safe_workers", forbidden)
        assert cli._parse_workers_arg("3") == 3
        assert cli._parse_workers_arg("1") == 1

    def test_one_is_still_one(self, monkeypatch):
        monkeypatch.setattr(cli, "_auto_worker_count", lambda: 99)
        assert cli._parse_workers_arg("auto") == 99


# ─── Part one b: the sink gate does not duplicate the rule bank by default ───

class TestSinkGateRamFloor:
    def test_thresholds_are_the_measured_ones(self):
        # 50,000 call sites is the point where a fan-out earns back a private copy of the bank, and
        # 4 GB free is what a doubled ~210 MB bank needs beside everything else the run holds.
        assert ast_scanner._SINK_GATE_MIN_CALLS == 50_000
        assert ast_scanner._SINK_GATE_MIN_FREE_RAM_MB == 4096

    def test_small_corpus_is_serial_before_anything_else_is_consulted(self):
        assert ast_scanner._sink_gate_worker_count(ast_scanner._SINK_GATE_MIN_CALLS - 1) == 1

    def test_gate_runs_serially_on_a_machine_without_fork(self):
        # Windows has no fork start method, so the serial gate was always the answer there; the call
        # count that would have fanned out on Linux must still not raise or hang here.
        workers = ast_scanner._sink_gate_worker_count(ast_scanner._SINK_GATE_MIN_CALLS * 4)
        assert workers >= 1


# ─── Part one c: the call-site index is released when the pass is over ───────

class TestCallSiteIndexRelease:
    def test_the_index_is_empty_once_analyze_returns(self):
        files = {"snippet.py": _MULTILINE_QUERY}
        tracker = TaintTracker(files=files)
        tracker.analyze()
        assert tracker.raw_calls == [], "one tuple per call site outlived the pass that needed it"
        # Raw text remains aliased only long enough for the CLI to freeze byte-exact reuse trees;
        # once released, trees and line-indexed source stay for reporters and repeat analyses.
        tracker.release_raw_sources()
        assert tracker.modules and tracker.files == {}
        assert tracker._module_source_text("snippet") == "\n".join(_MULTILINE_QUERY.splitlines())

    def test_a_second_pass_rebuilds_the_index_and_still_reports(self):
        # Phase 2 walks the trees, so releasing the raw source cannot starve a tracker asked to run
        # twice -- the CWE-89 row on the same snippet proves the call sites came back.
        tracker = TaintTracker(files={"snippet.py": _MULTILINE_QUERY})
        tracker.analyze()
        _sources, sinks, _edges = tracker.analyze()
        assert any((sink.metadata or {}).get("cwe") == "CWE-89" for sink in sinks), \
            "the second pass found no SQL execution, so the index was not rebuilt"


class TestV313MemoryAndIndexInvariants:
    def test_raw_source_is_released_but_lines_remain_exact(self):
        source = _MULTILINE_QUERY
        files = {"snippet.py": source}
        tracker = TaintTracker(files=files)
        assert tracker.files == files
        tracker.release_raw_sources()
        assert tracker.files == {}
        assert files == {}
        assert tracker._module_source_text("snippet") == "\n".join(source.splitlines())
        expected = "\n".join(source.splitlines()[7:10]).strip()
        assert tracker.get_source_snippet("snippet.py", 8, 10) == expected

    def test_cross_file_tree_reuse_preserves_byte_exact_source_after_release(self, monkeypatch):
        source = '''from sqlite3 import connect


def fetch(name):
    return connect("app.db").execute("SELECT * FROM users WHERE name = '" + name + "'")
'''
        files = {"cross_file.py": source}
        tracker = TaintTracker(files=files)
        monkeypatch.setattr(Path, "cwd", lambda: ROOT)
        monkeypatch.setattr(Path, "resolve", lambda self: ROOT / str(self))
        reuse = cli._cross_scan_reuse_trees(tracker, files)
        key = str(ROOT / "cross_file.py")
        assert reuse == {key: (source, tracker.modules["cross_file"])}
        tracker.release_raw_sources()
        assert reuse[key][0] == source
        assert reuse[key][1] is tracker.modules["cross_file"]

    def test_preorder_numbering_is_cached_on_the_tree(self, monkeypatch):
        tree = ast.parse("value = 1\n")
        nodes = ast_scanner._preorder_ast_nodes(tree)
        assert tree.__dict__["_cached_preorder_nodes"] is nodes

        def forbidden(_node):
            raise AssertionError("cached preorder numbering walked the tree again")

        monkeypatch.setattr(ast, "iter_child_nodes", forbidden)
        assert ast_scanner._preorder_ast_nodes(tree) is nodes

    def test_phase7_prunes_removed_sinks_without_rebuilding_the_location_index(self):
        source = '''from lxml import etree


def parse_xml(payload):
    etree.fromstring(payload, parser=etree.XMLParser(resolve_entities=False))
    return etree.fromstring(payload)
'''
        tracker = TaintTracker(files={"xml.py": source})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            tracker.analyze()
        phase7 = tracker._removal_profile.get("phase7", {})
        assert phase7.get("removed", 0) > 0, "the fixture never exercised a Phase 7 removal"
        assert "sink_loc_index" not in tracker._cache_profile, \
            "removing a sink forced a full Phase 7 location-index rebuild"
        cwe611 = [sink for sink in tracker.sinks
                  if (sink.metadata or {}).get("cwe") == "CWE-611"]
        assert len(cwe611) == 1 and cwe611[0].location.line_start == 6, \
            "pruning the safe XML call disturbed the independent unsafe call"

    def test_collector_cleanup_releases_every_module_cache_and_collects(self, monkeypatch):
        tracker = TaintTracker(files={"snippet.py": _MULTILINE_QUERY})
        tree = next(iter(tracker.modules.values()))
        cache_keys = ("_cached_reachable_nodes", "_cached_all_nodes", "_cached_preorder_nodes",
                      "_cached_node_buckets", "_cached_node_type_buckets",
                      "_cached_node_type_views")
        for key in cache_keys:
            tree.__dict__[key] = []
        collected = []
        monkeypatch.setattr(ast_scanner.gc, "collect", lambda: collected.append(True))
        tracker.release_collector_gate_scratch()
        assert all(key not in tree.__dict__ for key in cache_keys)
        assert collected == [True]

    def test_module_node_buckets_cache_one_ordered_pass_per_type_set(self):
        tree = ast.parse("x = 1\nimport os\ncall()\ny: int = 2\n")
        tracker = TaintTracker(files={"bucket.py": "unused"})
        requested = (ast.Assign, ast.AnnAssign, ast.Import, ast.Call)
        buckets = tracker._module_node_buckets(tree, requested)
        assert buckets[ast.Assign][0] is next(
            n for n in ast.walk(tree) if isinstance(n, ast.Assign))
        assert [type(n) for n in buckets[ast.Call]] == [ast.Call]
        assert tracker._module_node_buckets(tree, requested) is buckets
        assert tracker._module_node_buckets(tree, requested) is buckets

    def test_module_nodes_of_types_preserves_walk_order_and_caches_view(self):
        source = "import os\nx = 1\ny: int = 2\ncall()\nz = 3\n"
        tracker = TaintTracker(files={"view.py": source})
        tree = next(iter(tracker.modules.values()))
        requested = (ast.Assign, ast.AnnAssign, ast.Import, ast.Call)
        expected = [node for node in ast.walk(tree) if type(node) in requested]
        rows = tracker._module_nodes_of_types(tree, requested)
        assert [id(node) for node in rows] == [id(node) for node in expected]
        assert tracker._module_nodes_of_types(tree, requested) is rows
        tracker.release_collector_gate_scratch()
        assert "_cached_node_type_views" not in tree.__dict__

    def test_release_collector_gate_scratch_releases_type_buckets(self):
        tracker = TaintTracker(files={"bucket.py": "x = 1\ncall()\n"})
        tree = next(iter(tracker.modules.values()))
        tracker._module_node_buckets(tree, (ast.Assign, ast.Call))
        assert "_cached_node_type_buckets" in tree.__dict__
        tracker.release_collector_gate_scratch()
        assert "_cached_node_type_buckets" not in tree.__dict__


class TestPhase2SerialThreshold:
    def test_small_and_mid_corpus_uses_serial_phase2(self, monkeypatch):
        if not ast_scanner.PARALLEL_PARSING_AVAILABLE:
            pytest.skip("Phase 2 parallel transport is unavailable")
        parallel_analyzer = pytest.importorskip("tcs.parallel_analyzer")
        monkeypatch.setattr(parallel_analyzer, "compute_analysis_workers", lambda: 4)
        assert ast_scanner._phase2_worker_count(
            ast_scanner._PHASE2_PARALLEL_MIN_MODULES - 1) == 1
        assert ast_scanner._phase2_worker_count(
            ast_scanner._PHASE2_PARALLEL_MIN_MODULES) > 1


_MULTILINE_QUERY = '''import sqlite3


def fetch(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(
        f"SELECT * FROM users WHERE name = '{user_id}'"
    )
    return cur.fetchall()
'''

_SINGLE_LINE_QUERY = '''import sqlite3


def fetch(user_id):
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{user_id}'")
    return cur.fetchall()
'''

_TWO_STATEMENTS = '''import sqlite3


def fetch(user_id, role):
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(
        f"SELECT * FROM users WHERE name = '{user_id}'"
    )
    cur.execute(
        f"SELECT * FROM roles WHERE grantee = '{role}'"
    )
    return cur.fetchall()
'''


class TestSqlExecutionReportsOnce:
    def test_multiline_query_reports_once(self):
        assert _count(_MULTILINE_QUERY, "CWE-89") == 1, \
            f"one execute() emitted {_count(_MULTILINE_QUERY, 'CWE-89')} CWE-89 rows"

    def test_single_line_query_still_reports(self):
        _fires(_SINGLE_LINE_QUERY, 6, "CWE-89")
        assert _count(_SINGLE_LINE_QUERY, "CWE-89") == 1

    def test_collapse_is_per_call_not_per_file(self):
        # Two statements are two findings. A rule that reported once per file would pass the test
        # above by being a blindfold, and this is the case that tells the two apart.
        assert _count(_TWO_STATEMENTS, "CWE-89") == 2


# ─── Cluster 2: one fetch, one finding (CWE-918 and CWE-939 on one call) ─────

_ONE_URLLIB_FETCH = '''import os
import urllib.request

name = os.environ.get("CHARGE", "x")
resp = urllib.request.urlopen(f"https://api.stripe.com/v1/charges/{name}")
'''

_THREE_STATEMENT_FETCH = '''import os
import urllib.request

name = os.environ.get("CHARGE", "x")
req = urllib.request.Request("https://api.stripe.com/v1/charges/" + name)
urllib.request.urlopen(req)
'''


class TestUrllibFetchReportsOnce:
    def test_fetch_line_is_not_charged_twice(self):
        rows = _rows(_ONE_URLLIB_FETCH)
        assert (5, "CWE-918") in rows, "the SSRF finding itself must stay"
        assert "CWE-939" not in {cwe for (_line, cwe) in rows}, \
            "CWE-939 reported the same urlopen() call a second time"

    def test_the_two_statement_reading_still_reports_the_fetch(self):
        # `benchmark/corpus/cwe_522_basic_auth/test_v05_bad.py` is the sealed shape: `Request(...)`
        # on one line, `urlopen(req)` on the next, and the baseline books BOTH. The pin that protects
        # those keys is exercised by the fixture itself, so the merge cannot quietly eat them.
        fixture = ROOT / "benchmark" / "corpus" / "cwe_522_basic_auth" / "test_v05_bad.py"
        rows = _rows(fixture.read_text(encoding="utf-8"), filename=fixture.name)
        assert (5, "CWE-918") in rows, f"blessed SSRF row lost: {sorted(rows)}"
        assert (7, "CWE-939") in rows, f"blessed protocol row lost: {sorted(rows)}"

    def test_request_construction_line_keeps_its_own_finding(self):
        # The construction and the fetch are different statements, so they stay two findings; only a
        # second name for ONE call is a duplicate.
        rows = _rows(_THREE_STATEMENT_FETCH)
        assert any(_line == 5 and cwe == "CWE-918" for (_line, cwe) in rows)


# ─── Cluster 3: exception detail needs a client, not a caller ────────────────
_LIBRARY_METHOD_RETURN_E = '''class Loader:
    def load(self):
        try:
            return self._send()
        except Exception as e:
            return e
'''

_LIBRARY_METHOD_RETURN_REPR = '''class Loader:
    def load(self):
        try:
            return self._send()
        except Exception as e:
            return repr(e)
'''

_FREE_FUNCTION_DETAIL = '''def handle():
    try:
        return load()
    except Exception as e:
        return str(e)
'''

_VIEW_METHOD_DETAIL = '''from django.views.generic import View


class V(View):
    def get(self, request):
        try:
            return ok()
        except Exception as e:
            return str(e)
'''

# The chain shapes, numbered the way the engine reports them: the finding anchors on the `except`
# line, one above the `return`.
_METHOD_CLOSURE_RETURN_E = '''class RunnableConfigurableFields:
    def __init__(self, fields):
        def wrapper(*args, **kw):
            try:
                return go(*args, **kw)
            except Exception as e:
                return e
        return wrapper
'''

_MODULE_CLOSURE_RETURN_E = '''def configurable(fn):
    def wrapper(*args, **kw):
        try:
            return fn(*args, **kw)
        except Exception as e:
            return e
    return wrapper
'''

_SELF_NAMED_FREE_FUNCTION_CLOSURE_RETURN_E = '''def configurable(self, fn):
    def wrapper(*args, **kw):
        try:
            return fn(*args, **kw)
        except Exception as e:
            return e
    return wrapper
'''

_METHOD_CLOSURE_UNDER_POST = '''class Client:
    def post(self, url):
        def send():
            try:
                return dispatch(url)
            except Exception as e:
                return str(e)
        return send()
'''


class TestErrorExposureNeedsAClient:
    def test_bare_exception_object_from_a_method_is_silent(self):
        _silent(_LIBRARY_METHOD_RETURN_E, 5, "CWE-209")

    def test_repr_of_the_exception_from_a_method_is_silent(self):
        _silent(_LIBRARY_METHOD_RETURN_REPR, 5, "CWE-209")

    def test_free_function_detail_still_fires(self):
        # Nothing proves who prints it, so unknown stays reported -- the contract of
        # `tests/test_arena_fp_clusters_8_10.py`, restated here so the cluster cannot regress.
        _fires(_FREE_FUNCTION_DETAIL, 4, "CWE-209")

    def test_http_method_detail_still_fires(self):
        _fires(_VIEW_METHOD_DETAIL, 8, "CWE-209")

    def test_a_method_returns_a_closure_and_that_detail_is_silent(self):
        # LangChain's spelling: `RunnableConfigurableFields.__init__` builds a `wrapper` and hands the
        # caller that closure, so the `return e` is a frame deeper out but the receiver is the same --
        # whoever called the method. The proof is the enclosing chain, and the chain reaches `self`.
        _silent(_METHOD_CLOSURE_RETURN_E, 6, "CWE-209")

    def test_a_module_level_closure_detail_still_fires(self):
        # The chain rule is a proof, not a licence. `configurable(fn)` is a plain function; behind it
        # sits nothing but a caller that could be a view, so the bare `return e` stays reported.
        _fires(_MODULE_CLOSURE_RETURN_E, 5, "CWE-209")

    def test_a_self_named_free_function_closure_detail_still_fires(self):
        # A parameter spelled `self` is not method provenance; the outermost frame must sit in a class.
        _fires(_SELF_NAMED_FREE_FUNCTION_CLOSURE_RETURN_E, 5, "CWE-209")

    def test_a_closure_under_a_verb_named_method_still_fires(self):
        # The refusal set is consulted for every frame, not only the innermost, so a route handler's
        # helper keeps the finding its handler would have kept.
        _fires(_METHOD_CLOSURE_UNDER_POST, 6, "CWE-209")

    def test_the_chain_refusals_are_named(self):
        # The three markers that turn a library method back into a handler, read off the constants so
        # widening them is a decision someone has to make in this file's presence.
        assert {"request", "handler", "response"} <= ast_scanner.CWE209_WEB_CONTEXT_ARGUMENTS
        assert {"get", "post", "put", "patch", "delete"} <= \
            ast_scanner.TaintTracker.CWE209_HTTP_METHOD_NAMES


# ─── Cluster 4: a write into a directory the program created is not an upload ─

_SAVE_INTO_INSTANCE_TEMP_DIR = '''import tempfile
from pathlib import Path


class ModelStore:
    def __init__(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def store(self, model):
        path = Path(self.temp_dir.name, "model.bin")
        model.save(str(path))
'''

_SAVE_INTO_MODULE_TEMP_DIR = '''import os
import tempfile

import numpy as np

tmpdir = tempfile.mkdtemp()
np.save(os.path.join(tmpdir, "weights.npy"), [1, 2])
'''

_SAVE_WITHOUT_A_TEMP_DIR = '''def store(model, destination):
    model.save(destination)
'''

_SAVE_OF_AN_UPLOADED_FILE = '''from flask import request


def store(model):
    model.save(request.args["p"])
'''


class TestLocalSerializationIsNotAnUpload:
    def test_save_into_the_instance_temp_dir_is_silent(self):
        _silent(_SAVE_INTO_INSTANCE_TEMP_DIR, 11, "CWE-434")

    def test_save_into_a_module_level_temp_dir_is_silent(self):
        _silent(_SAVE_INTO_MODULE_TEMP_DIR, 7, "CWE-434")

    def test_an_unproven_destination_still_fires(self):
        # The exemption is a proof, not a guess: a destination that came in as a parameter is not
        # shown to be a temporary path, and the finding stands.
        _fires(_SAVE_WITHOUT_A_TEMP_DIR, 2, "CWE-434")

    def test_a_destination_read_from_the_request_always_fires(self):
        _fires(_SAVE_OF_AN_UPLOADED_FILE, 5, "CWE-434")


# ─── Cluster 5: an environment variable NAME is not a credential ─────────────

_ENV_NAME_CONSTANTS = '''import os

_HUGGINGFACE_API_KEY_ENV_NAME = "HUGGINGFACE_API_KEY"
DEFAULT_TOKEN_ENV_VAR = "OPENAI_API_KEY"
key = os.getenv(_HUGGINGFACE_API_KEY_ENV_NAME)
'''

_NAME_ASSIGNED_FROM_THE_ENVIRONMENT = '''import os

HUGGINGFACE_API_KEY = "HUGGINGFACE_API_KEY"
key = os.getenv(HUGGINGFACE_API_KEY)
'''

_A_REAL_KEY_IN_THE_SAME_NAME = '''import os

HUGGINGFACE_API_KEY = "hf_0123456789abcdef"
key = os.getenv(HUGGINGFACE_API_KEY)
'''

_REAL_SECRET_IN_A_KWARG_DEFAULT = '''def client(api_key: str = "sk_live_0123456789abcdef") -> None:
    pass
'''


class TestEnvVarNameplateIsNotASecret:
    # Measured at v3.1.0 and again here: CWE-798 charges a hardcoded secret only when the VALUE looks
    # like a credential, so an environment variable's NAME sitting in a secret-shaped variable was
    # never reported. No rule was widened for this cluster -- these cases are the lock that keeps it
    # that way, and the key-shaped value beside them is what proves the discriminator is real.
    def test_nameplate_constants_are_silent(self):
        rows = _rows(_ENV_NAME_CONSTANTS)
        assert "CWE-798" not in {cwe for (_line, cwe) in rows}, \
            f"an environment variable name was charged as a hardcoded credential: {sorted(rows)}"

    def test_a_name_that_is_its_own_env_var_is_silent(self):
        _silent(_NAME_ASSIGNED_FROM_THE_ENVIRONMENT, 3, "CWE-798")

    def test_the_same_name_holding_a_key_still_fires(self):
        _fires(_A_REAL_KEY_IN_THE_SAME_NAME, 3, "CWE-798")

    def test_a_value_that_is_a_key_still_fires(self):
        _fires(_REAL_SECRET_IN_A_KWARG_DEFAULT, 1, "CWE-798")


# ─── Cluster 6: a streamed chunk printed to the console is not a stored secret ─

_STREAMING_HANDLER = '''import sys


class TokenStreamingHandler:
    def on_llm_new_token(self, token, **kwargs):
        sys.stdout.write(token)
'''

_WRITING_AN_ACTUAL_CREDENTIAL = '''import sys


def debug(secret_token):
    sys.stdout.write(secret_token)
'''


class TestStreamedTokenIsNotACleartextSecret:
    def test_streaming_callback_write_is_silent(self):
        _silent(_STREAMING_HANDLER, 6, "CWE-312")

    def test_a_credential_named_parameter_still_fires(self):
        # Same statement, same rule, opposite answer: `secret_token` is not one of the chunk names,
        # which is what keeps this a suppression and not a mute button.
        _fires(_WRITING_AN_ACTUAL_CREDENTIAL, 5, "CWE-312")


# ─── Cluster 7: an empty-credential branch that switches authentication off ──

_EMPTY_CREDENTIALS_DISABLE_AUTH = '''def build_auth(username, password):
    if username == "" and password == "":
        auth = None
    else:
        auth = (username, password)
    return auth
'''

_EMPTY_CREDENTIALS_STILL_SEND_AUTH = '''def build_auth(username, password):
    if username == "" and password == "":
        auth = (username, password)
    return auth
'''

_HARDCODED_PASSWORD_COMPARE = '''def check(username, password):
    if username == "" and password == "admin123":
        return True
    return False
'''


class TestEmptyCredentialBranchDisablesAuthentication:
    def test_declining_to_authenticate_is_silent(self):
        _silent(_EMPTY_CREDENTIALS_DISABLE_AUTH, 2, "CWE-287")

    def test_an_empty_compare_that_still_builds_credentials_fires(self):
        # Without the `auth = None` the branch shape is a credential path, and the finding stands.
        _fires(_EMPTY_CREDENTIALS_STILL_SEND_AUTH, 2, "CWE-287")

    def test_a_non_empty_password_compare_fires(self):
        # Every blessed fixture in `benchmark/corpus/cwe_287_auth/` is this shape.
        _fires(_HARDCODED_PASSWORD_COMPARE, 2, "CWE-287")


# ─── Cluster 3b: a tuple return is the caller's convention, not a response ───

_TUPLE_DETAIL_LIBRARY_METHOD = '''class Loader:
    def load(self):
        try:
            return self._send()
        except Exception as e:
            return repr(e), []
'''

_TUPLE_DETAIL_FIRST_ELEMENT = '''class Runner:
    def run(self, cmd):
        try:
            return compute(cmd)
        except BaseException as e:
            return (None, str(e))
'''

_TUPLE_DETAIL_FREE_FUNCTION = '''def handle():
    try:
        return load()
    except Exception as e:
        return repr(e), []
'''

_TUPLE_DETAIL_IN_A_ROUTE_HANDLER = '''class Tool:
    @app.route("/run")
    def _run(self, query):
        try:
            return compute(query)
        except Exception as e:
            return repr(e), []
'''

_TUPLE_DETAIL_WITH_A_REQUEST_ARGUMENT = '''class Tool:
    def _run(self, request):
        try:
            return compute(request)
        except Exception as e:
            return repr(e), []
'''

_TUPLE_DETAIL_REPLY_CONSTRUCTOR = '''import flask


class Tool:
    def _run(self, query):
        try:
            return compute(query)
        except Exception as e:
            return flask.jsonify({"e": str(e)}), 500
'''


class TestTupleDetailStillNeedsAClient:
    """`return repr(e), []` is the shape that outlived cluster 3 at v3.1.0.

    The bare forms were already quiet, and so was the tuple one for the wrong reason until the
    clause below: `_is_bad_error_return` recognises a direct text return, a Tuple is not one, so the
    detail reached `_c209_exposed_in_reply` and the container -- the second element of a library's
    own calling convention -- read as an exposure. The cases after these are what keeps the
    exemption a proof rather than a mute button: same tuple, same rule, and a route decorator, a
    `request` parameter, or a reply constructor in the tuple puts the client back.
    """

    def test_tuple_detail_from_a_library_method_is_silent(self):
        _silent(_TUPLE_DETAIL_LIBRARY_METHOD, 6, "CWE-209")

    def test_tuple_detail_under_base_exception_is_silent(self):
        _silent(_TUPLE_DETAIL_FIRST_ELEMENT, 6, "CWE-209")

    def test_tuple_detail_from_a_free_function_still_fires(self):
        _fires(_TUPLE_DETAIL_FREE_FUNCTION, 5, "CWE-209")

    def test_tuple_detail_in_a_route_handler_still_fires(self):
        _fires(_TUPLE_DETAIL_IN_A_ROUTE_HANDLER, 7, "CWE-209")

    def test_tuple_detail_in_a_method_handed_a_request_still_fires(self):
        _fires(_TUPLE_DETAIL_WITH_A_REQUEST_ARGUMENT, 6, "CWE-209")

    def test_tuple_whose_element_builds_a_response_still_fires(self):
        _fires(_TUPLE_DETAIL_REPLY_CONSTRUCTOR, 9, "CWE-209")

    def test_the_blessed_corpus_rows_survive_the_clause(self):
        for name, line in (("test_v01_bad.py", 11), ("test_v03_bad.py", 7)):
            fixture = ROOT / "benchmark" / "corpus" / "cwe_200_info_exposure" / name
            _fires(fixture.read_text(encoding="utf-8"), line, "CWE-209")


# ─── Part two b: Phase 2 across workers, and parsing, without leaving a process ─

class _InlinePool:
    """A `ProcessPoolExecutor` that is really this process.

    The fan-out code decides the transport, orders the modules, grafts the state and re-issues the
    id series; the OS boundary it opens is the part a unit test has no business measuring, and a
    spawned worker imports the rule bank before reading a file -- which is the memory this release
    is trying not to spend. So the pool is replaced by a loop that calls the same worker functions,
    and everything above it runs for real.
    """

    def __init__(self, max_workers=None, initializer=None, initargs=(), mp_context=None, **_kw):
        self.max_workers = max_workers
        if initializer is not None:
            initializer(*initargs)

    def map(self, func, iterable, chunksize=1):
        return [func(item) for item in iterable]

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _BrokenPool(_InlinePool):
    def map(self, func, iterable, chunksize=1):
        raise RuntimeError("worker exited before it answered")


_MULTI_MODULE_CORPUS = {
    "repo/sql.py": '''import sqlite3


def fetch(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{user_id}'")
    return cur.fetchall()
''',
    "repo/fetch.py": '''import os
import urllib.request


def get(charge):
    name = os.environ.get("CHARGE", "x")
    return urllib.request.urlopen(f"https://api.stripe.com/v1/charges/{name}")
''',
    "repo/dead.py": '''import subprocess


def run(cmd):
    if False:
        subprocess.run(cmd, shell=True)
    return 1
''',
    "repo/auth.py": '''from flask import request


def login():
    pwd = request.form["password"]
    if pwd == "":
        return "anonymous"
    return "no"
''',
}


def _signature(tracker):
    """Everything a transport could get wrong: which nodes were found, where, and in what order.

    The ids are in here because the id series is derived from the order the modules were collected
    in; a fan-out that merged in completion order would shift every SNK- and SRC- number without
    changing a single finding.
    """
    return ([(node.id, node.symbol, node.operation, node.location.file, node.location.line_start)
             for node in tracker.sinks],
            [(node.id, node.symbol, node.location.file, node.location.line_start)
             for node in tracker.sources])


def _fork_reply(tracker, mod_name):
    """Ask a fork worker for one module the way the pool does, and hand back the reply it sends."""
    ast_scanner._PHASE2_SHARED_TRACKER = tracker
    try:
        return ast_scanner._phase2_module_fork_batch(mod_name)[1]
    finally:
        ast_scanner._PHASE2_SHARED_TRACKER = None


def _reachable(value):
    """Everything a reply carries -- containers, and the attributes of the records inside them.

    The attribute view is the engine's own `_phase2_object_members`, so a field the transport can
    reach is a field this check can reach, including the ones that live only in `__slots__`. AST
    nodes are leaves: reaching one is the failure this walk looks for, and walking its `.parent`
    chain would recreate the whole corpus in the test.
    """
    stack = [value]
    while stack:
        item = stack.pop()
        yield item
        if isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple, set, frozenset)):
            stack.extend(item)
        elif isinstance(item, (ast.AST, str, bytes, int, float, complex, bool)) or item is None:
            continue
        else:
            stack.extend(ast_scanner._phase2_object_members(item).values())


class TestPhase2TransportsAgree:
    def _analyze(self, monkeypatch, workers, *, fork, pool=_InlinePool):
        import concurrent.futures
        import multiprocessing

        def refuse(name="fork"):
            raise ValueError("no fork start method on this platform")

        monkeypatch.setattr(ast_scanner, "_phase2_worker_count", lambda count: workers)
        monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", pool)
        monkeypatch.setattr(multiprocessing, "get_context",
                            (lambda name="fork": object()) if fork else refuse)
        tracker = TaintTracker(files=dict(_MULTI_MODULE_CORPUS))
        with contextlib.redirect_stdout(io.StringIO()):
            tracker.analyze()
        return tracker

    def test_the_fanout_is_actually_taken(self, monkeypatch):
        # A guard that silently kept everything serial would make every parity test below pass
        # without a transport existing, so the dispatch is pinned before it is compared.
        opened = []

        class _RecordingPool(_InlinePool):
            def __init__(self, *args, **kwargs):
                opened.append(kwargs)
                super().__init__(*args, **kwargs)

        self._analyze(monkeypatch, workers=3, fork=True, pool=_RecordingPool)
        assert opened, "3 workers did not open a pool, so nothing above it was tested"
        assert opened[0]["mp_context"] is not None, \
            "a fork-capable machine fell back to the payload transport"

    def test_fork_warms_preorder_caches_and_freezes_after_collection(self, monkeypatch):
        events = []

        monkeypatch.setattr(ast_scanner.gc, "collect", lambda: events.append("collect"))
        monkeypatch.setattr(ast_scanner.gc, "freeze", lambda: events.append("freeze"))
        monkeypatch.setattr(ast_scanner.gc, "unfreeze", lambda: events.append("unfreeze"))

        class _RecordingPool(_InlinePool):
            def __init__(self, *args, **kwargs):
                assert events[-2:] == ["collect", "freeze"], \
                    "the fork pool opened without collect/freeze immediately before it"
                tracker = ast_scanner._PHASE2_SHARED_TRACKER
                assert tracker is not None
                assert all("_cached_preorder_nodes" in tree.__dict__
                           for tree in tracker.modules.values()), \
                    "a child would have to build its own preorder numbering"
                super().__init__(*args, **kwargs)

        self._analyze(monkeypatch, workers=3, fork=True, pool=_RecordingPool)
        assert events.index("freeze") < events.index("unfreeze"), \
            "the parent never unfroze its heap after the fork pool closed"

    def test_a_failed_fork_pool_still_unfreezes_the_parent(self, monkeypatch):
        events = []
        monkeypatch.setattr(ast_scanner.gc, "freeze", lambda: events.append("freeze"))
        monkeypatch.setattr(ast_scanner.gc, "unfreeze", lambda: events.append("unfreeze"))
        self._analyze(monkeypatch, workers=3, fork=True, pool=_BrokenPool)
        assert events == ["freeze", "unfreeze"]

    def test_the_fork_transport_matches_the_serial_loop(self, monkeypatch):
        assert _signature(self._analyze(monkeypatch, workers=1, fork=True)) == \
            _signature(self._analyze(monkeypatch, workers=3, fork=True))

    def test_the_payload_transport_matches_the_serial_loop(self, monkeypatch):
        assert _signature(self._analyze(monkeypatch, workers=1, fork=False)) == \
            _signature(self._analyze(monkeypatch, workers=3, fork=False))

    def test_the_two_transports_agree_with_each_other(self, monkeypatch):
        assert _signature(self._analyze(monkeypatch, workers=4, fork=True)) == \
            _signature(self._analyze(monkeypatch, workers=4, fork=False))

    def test_a_dead_branch_is_still_silent_after_the_graft(self, monkeypatch):
        sinks, _sources = _signature(self._analyze(monkeypatch, workers=3, fork=True))
        assert not any("subprocess" in symbol for (_id, symbol, *_rest) in sinks), \
            "the unreachable `if False:` body came back as a sink"

    def test_a_forked_worker_reads_the_parents_own_tree(self, monkeypatch):
        # Copy-on-write means no copy in either direction. The worker resolves the module name against
        # `_PHASE2_SHARED_TRACKER`, so it collects the identical tree the parent holds, and what comes
        # back is not that tree: `tree is None` is the reply saying "every node I found is a position
        # in the one you already have". A non-None tree here would mean an AST crossed the pipe.
        tracker = TaintTracker(files=dict(_MULTI_MODULE_CORPUS))
        mod_name = ast_scanner._phase2_ordered_modules(tracker)[0]
        tree_before = tracker.modules[mod_name]
        tree, _state = _fork_reply(tracker, mod_name)
        assert tree is None, "a tree was pickled out of the worker"
        assert tracker.modules[mod_name] is tree_before, "the parent's tree was replaced by its worker"

    def test_the_reply_carries_no_ast_node_at_all(self):
        # The payload a fork worker returns is what a real pipe would pickle, so this is the transport
        # measured rather than asserted: zero `ast.AST` objects reachable, markers present, and the
        # bytes round-trip. The tree a record used to drag back was the whole module, `.parent` links
        # included -- 1.23 GB of it on a 40,000-line corpus.
        tracker = TaintTracker(files=dict(_MULTI_MODULE_CORPUS))
        replies = [_fork_reply(tracker, mod) for mod in ast_scanner._phase2_ordered_modules(tracker)]
        assert all(_tree is None for _tree, _state in replies), "a tree was pickled out of a worker"
        numbered = [state for _tree, state in replies]
        assert any(any(isinstance(item, tuple) and len(item) == 2 and item[0] == "_TCS_AST_IDX_"
                       for item in _reachable(state)) for state in numbered), \
            "no node was numbered, so the transport was never exercised"
        for state in numbered:
            leaked = [item for item in _reachable(pickle.loads(pickle.dumps(state)))
                      if isinstance(item, ast.AST)]
            assert not leaked, f"{len(leaked)} AST nodes survived in the reply"

    def test_mapping_keys_sets_and_defaultdicts_keep_their_types(self):
        from collections import defaultdict

        tree = ast.parse("value = 1\n")
        node = tree.body[0]
        nodes = ast_scanner._preorder_ast_nodes(tree)
        numbered = ast_scanner._phase2_encode_state(
            {node: {node}, "default": defaultdict(list, {node: [node]})},
            {id(item): index for index, item in enumerate(nodes)})
        assert not any(isinstance(item, ast.AST) for item in _reachable(numbered))
        restored = ast_scanner._phase2_decode_state(pickle.loads(pickle.dumps(numbered)), nodes)
        key = next(item for item in restored if isinstance(item, ast.AST))
        assert key is node
        assert key in restored[key], "a set member was not restored as the parent's node"
        assert restored["default"].default_factory is list
        assert restored["default"][node][0] is node

    def test_the_graft_answers_every_number_with_the_parents_node(self):
        # Identity is the invariant the later phases lean on: `_sink_records_for_node` compares a
        # `record.node` against the tree in `tracker.modules` by `is`. Restoring by position has to put
        # back exactly that object, and it has to do it through the bytes a pool really sends.
        tracker = TaintTracker(files=dict(_MULTI_MODULE_CORPUS))
        trees = dict(tracker.modules)
        for mod_name in ast_scanner._phase2_ordered_modules(tracker):
            tree, state = _fork_reply(tracker, mod_name)
            ast_scanner._phase2_grant_fork(tracker, mod_name, tree, pickle.loads(pickle.dumps(state)))
        assert tracker.modules == trees, "a numbered reply replaced one of the parent's trees"
        positions = {id(node) for tree in trees.values() for node in ast.walk(tree)}
        nodes = [record.node for record in tracker.sink_records]
        for bucket in tracker.assignments_by_scope.values():
            nodes.extend(record.value_node for record in bucket)
        assert nodes, "nothing came back through the numbered transport, so nothing was checked"
        for node in nodes:
            assert id(node) in positions, "a grafted record points outside the parent's trees"

    def test_the_shared_tracker_is_released_when_the_round_fails(self, monkeypatch):
        # A worker that dies must not leave the engine holding a tracker through a module global, and
        # must not lose the pass: the caller falls back to serial collection.
        tracker = self._analyze(monkeypatch, workers=3, fork=True, pool=_BrokenPool)
        assert ast_scanner._PHASE2_SHARED_TRACKER is None
        assert _signature(tracker) == \
            _signature(self._analyze(monkeypatch, workers=1, fork=True))


class TestParsingStaysInProcess:
    def _files(self):
        # Past `BATCH_SIZE`, so the corpus reaches the inline parse loop instead of the sequential
        # short-circuit that guards tiny runs.
        import tcs.parallel_scanner as scanner

        count = scanner.BATCH_SIZE + 5
        return {f"/repo/m{i}.py": f"import os\n\nvalue = os.environ.get('K{i}', '{i}')\n"
                for i in range(count)}

    def test_a_four_worker_request_parses_inline_and_reports_that_it_did(self):
        import tcs.parallel_scanner as scanner

        files = self._files()
        modules, file_paths, skipped, stats = scanner.parse_files_parallel(files, 4)
        assert set(stats) == {"discovered", "parsed", "fast_path_skipped", "unparseable",
                              "parse_mode", "workers_initial", "workers_final", "governor_events"}
        assert stats["parse_mode"] == "inline"
        assert stats["workers_initial"] == 4, "the ledger must still show what was asked for"
        assert stats["workers_final"] == 1
        assert stats["governor_events"] == 0
        assert stats["discovered"] == len(modules) == len(file_paths) == len(files)
        assert not skipped

    def test_no_pool_is_constructed_for_parsing(self, monkeypatch):
        import tcs.parallel_scanner as scanner

        def forbidden(*_args, **_kwargs):
            raise AssertionError("parsing opened a process pool instead of parsing here")

        monkeypatch.setattr(scanner, "ProcessPoolExecutor", forbidden)
        files = self._files()
        modules, _paths, _skipped, stats = scanner.parse_files_parallel(files, 8)
        assert stats["parse_mode"] == "inline" and len(modules) == len(files)

    def test_the_trees_are_the_ones_the_sequential_parser_builds(self, monkeypatch):
        import tcs.parallel_scanner as scanner

        def forbidden(*_args, **_kwargs):
            raise AssertionError("the comparison must not be the only inline path left untested")

        files = self._files()
        monkeypatch.setattr(scanner, "ProcessPoolExecutor", forbidden)
        with_pool = scanner.parse_files_parallel(files, 4)
        without = scanner._parse_files_sequential(files)
        assert list(with_pool[0]) == list(without[0]), "module order drives the SNK- series"
        assert with_pool[2] == without[2]
        assert with_pool[3]["parsed"] == without[3]["parsed"]


# ─── The release number the banner and the package both have to say ─────────

class TestReleaseVersion:
    def test_pyproject_and_banner_agree_on_3_3_2(self):
        # Read as source, not imported: `banner` prefers the installed distribution's metadata when
        # one is present, so an import would test whichever wheel this machine happens to hold.
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        banner_src = (ROOT / "banner.py").read_text(encoding="utf-8")
        assert 'version = "3.3.2"' in pyproject
        assert 'VERSION = "3.3.2"' in banner_src, "the fallback must name the release it ships with"
        assert 'version = "3.2.0"' not in pyproject
