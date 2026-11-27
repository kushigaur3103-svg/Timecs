"""v3.3.3: debt baseline, --fail-on quality gate, SCA upgrade plan, wheel workflow pins.

Every scan runs over a tiny tmp tree with --workers 1, so the whole file stays inside the
laptop RAM budget and runs in seconds. No arena, no full-repo walk, no core-engine change.
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import cli  # noqa: E402
from scanners import sca_scanner  # noqa: E402

VULN = (
    "import os\n"
    "import subprocess\n"
    "\n"
    "user_input = os.sys.argv[1]\n"
    "subprocess.call(user_input, shell=True)\n"
)


def run_scan(argv):
    """One in-process CLI scan; returns (exit_code, stdout, stderr)."""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def scan_json(path, *extra):
    code, out, err = run_scan(["scan", str(path), "--format", "json", "--workers", "1",
                               "--min-confidence", "all", *extra])
    start = out.find("{")
    assert start >= 0, f"no JSON payload on stdout:\n{out[-500:]}"
    return code, json.loads(out[start:]), err


@pytest.fixture()
def vuln_tree(tmp_path):
    (tmp_path / "vuln.py").write_text(VULN, encoding="utf-8")
    return tmp_path


# ────────────────────────────────────────── 1. SonarQube-style debt baseline

class TestDebtBaseline:
    def test_write_baseline_is_portable_and_exits_zero(self, vuln_tree):
        baseline = vuln_tree / "tcs-baseline.json"
        code, _, err = run_scan(["scan", str(vuln_tree), "--workers", "1",
                                 "--min-confidence", "all",
                                 "--write-baseline", str(baseline)])
        assert code == 0
        assert baseline.is_file()
        raw = baseline.read_text(encoding="utf-8")
        data = json.loads(raw)
        assert data["version"] == 1
        assert data["fingerprints"], "a dirty tree must fingerprint something"
        for fingerprint in data["fingerprints"]:
            assert re.fullmatch(r"[0-9a-f]{64}", fingerprint)
        assert str(vuln_tree) not in raw, "absolute machine paths must never reach the baseline"
        assert "\\" not in raw, "fingerprints must be portable across Windows/Linux"
        assert "Baseline written" in err

    def test_baseline_survives_line_shift_and_catches_new_findings(self, vuln_tree):
        baseline = vuln_tree / "tcs-baseline.json"
        code, before, _ = scan_json(vuln_tree)
        assert code == 1 and before["findings"], "fixture must start dirty"
        original_count = len(before["findings"])

        code, _, _ = run_scan(["scan", str(vuln_tree), "--workers", "1",
                               "--min-confidence", "all",
                               "--write-baseline", str(baseline)])
        assert code == 0

        source = (vuln_tree / "vuln.py").read_text(encoding="utf-8")
        shifted = "\n\n\n" + source + "eval(user_input)\n"
        (vuln_tree / "vuln.py").write_text(shifted, encoding="utf-8")
        eval_line = len(shifted.splitlines())

        code, after, err = scan_json(vuln_tree, "--baseline", str(baseline))
        assert code == 1, "the newly added vulnerability must still gate the run"
        reported = after["findings"]
        assert reported, "the new eval() row must survive baseline suppression"
        assert all(row["line"] == eval_line for row in reported), (
            f"every surviving row belongs to the new vulnerability: {reported}")
        match = re.search(r"Note: Suppressed (\d+) baseline finding\(s\) from", err)
        assert match, f"the stderr note is missing: {err[-400:]}"
        assert int(match.group(1)) == original_count, (
            "the shifted rows are the same code and must all be suppressed")

    def test_missing_or_malformed_baseline_is_a_clean_error(self, vuln_tree):
        def scan(*extra):
            return run_scan(["scan", str(vuln_tree), "--format", "json", "--workers", "1",
                             "--min-confidence", "all", *extra])
        code, _, err = scan("--baseline", str(vuln_tree / "absent.json"))
        assert code == 2
        assert "Baseline file not found" in err
        bad = vuln_tree / "bad.json"
        bad.write_text('{"version": 7}', encoding="utf-8")
        code, _, err = scan("--baseline", str(bad))
        assert code == 2
        assert "Invalid baseline file" in err


# ────────────────────────────────────────── 2. SonarQube-style quality gate

SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class TestFailOnQualityGate:
    def test_budget_mode(self, vuln_tree):
        code, data, _ = scan_json(vuln_tree)
        assert code == 1 and data["findings"]
        code, _, _ = scan_json(vuln_tree, "--fail-on", "critical:100,high:100,medium:100,low:100")
        assert code == 0, "generous budgets must pass on any tree"
        code, _, _ = scan_json(vuln_tree, "--fail-on", "critical:0,high:0,medium:0,low:0")
        assert code == 1, "zero budgets must fail a dirty tree"

    def test_min_severity_mode(self, vuln_tree):
        code, data, _ = scan_json(vuln_tree)
        severities = {str(row["severity"]).upper() for row in data["findings"]}
        top = max(SEVERITY_ORDER.index(severity) for severity in severities)
        code, _, _ = scan_json(vuln_tree, "--fail-on", "low")
        assert code == 1, "any finding is at or above LOW"
        code, _, _ = scan_json(vuln_tree, "--fail-on", SEVERITY_ORDER[top].lower())
        assert code == 1, "the floor at the tree's own top severity must gate"
        if top + 1 < len(SEVERITY_ORDER):
            code, _, _ = scan_json(vuln_tree, "--fail-on", SEVERITY_ORDER[top + 1].lower())
            assert code == 0, "a floor strictly above every finding must pass"

    def test_invalid_spec_is_a_clean_cli_error(self, vuln_tree):
        for spec in ("banana", "critical:x", "high,,low", "critical:0,critical:1",
                     "critical:-1", "high,critical:0"):
            code, _, err = run_scan(["scan", str(vuln_tree), "--workers", "1",
                                     "--fail-on", spec])
            assert code == 2, spec
            assert "Invalid --fail-on spec" in err, spec

    def test_fail_on_critical_and_default_unchanged(self, vuln_tree):
        code_default, data, _ = scan_json(vuln_tree)
        severities = {str(row["severity"]).upper() for row in data["findings"]}
        expected = 1 if severities & {"CRITICAL", "HIGH"} else 0
        code, _, _ = scan_json(vuln_tree, "--fail-on-critical")
        assert code == expected, "--fail-on-critical semantics must not move"
        assert code_default == 1, "default: any finding exits 1"
        code, _, _ = scan_json(vuln_tree, "--fail-on-critical", "--fail-on",
                               "critical:100,high:100,medium:100,low:100")
        assert code == 0, "--fail-on is the explicit gate and wins when both are named"

    def test_clean_tree_exits_zero_under_every_gate(self, tmp_path):
        (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        code, data, _ = scan_json(tmp_path)
        assert code == 0 and not data["findings"]
        for spec in ("critical", "low", "critical:0,high:0"):
            code, _, _ = scan_json(tmp_path, "--fail-on", spec)
            assert code == 0, spec

    def test_yaml_policy_fail_on(self, vuln_tree, monkeypatch):
        (vuln_tree / ".tcs.yaml").write_text(
            'policy:\n  fail_on: "critical:100,high:100,medium:100,low:100"\n', encoding="utf-8")
        monkeypatch.chdir(vuln_tree)
        code, data, _ = scan_json(vuln_tree)
        assert data["findings"], "fixture must still be dirty"
        assert code == 0, "policy.fail_on from .tcs.yaml must gate the exit code"
        code, _, _ = scan_json(vuln_tree, "--fail-on", "low")
        assert code == 1, "an explicit CLI flag always overrides the yaml policy"


# ──────────────────────── 3. Snyk-style grouped SCA plan + monorepo reachability

def _build_monorepo(tmp_path):
    """requests==2.30.0 is a known-vulnerable pin in the offline advisory index. The OUTER
    importer ('aaa_tools/') sorts before the sub-package one, so repo-wide first-wins and
    sub-package preference pick different evidence and the polish is observable."""
    (tmp_path / "partners" / "pinecone").mkdir(parents=True)
    (tmp_path / "services" / "other").mkdir(parents=True)
    (tmp_path / "aaa_tools").mkdir(parents=True)
    (tmp_path / "partners" / "pinecone" / "requirements.txt").write_text(
        "requests==2.30.0\n", encoding="utf-8")
    (tmp_path / "services" / "other" / "requirements.txt").write_text(
        "requests==2.30.0\n", encoding="utf-8")
    (tmp_path / "partners" / "pinecone" / "app.py").write_text(
        "import requests\n\n\ndef get(url):\n    return requests.get(url)\n", encoding="utf-8")
    (tmp_path / "aaa_tools" / "check.py").write_text(
        "import requests\n\n\ndef ping(url):\n    return requests.head(url)\n", encoding="utf-8")
    return tmp_path


def _sca_finding(manifest):
    return {"file": manifest, "line": 1, "cwe": "CWE-1395", "severity": "HIGH",
            "category": sca_scanner.CATEGORY, "package": "requests", "ecosystem": "pypi",
            "spec": "==2.30.0", "cve": "CVE-2023-32681", "cves": ["CVE-2023-32681"],
            "fixed_version": "2.31.0", "summary": "proxy leak", "related_cwes": ["CWE-1395"],
            "reachability": "UNREACHABLE_MANIFEST_ONLY", "confidence": "LOW", "message": ""}


class TestScaUpgradePlan:
    def test_table_block_groups_manifests(self, tmp_path):
        _build_monorepo(tmp_path)
        code, out, _ = run_scan(["scan", str(tmp_path), "--workers", "1",
                                 "--min-confidence", "all"])
        assert "SCA UPGRADE PLAN" in out, out[-800:]
        plan_lines = [line for line in out.splitlines()
                      if line.strip().startswith("requests >= ")]
        assert len(plan_lines) == 1, f"one grouped row per package+version: {plan_lines}"
        assert "across 2 manifest(s)" in plan_lines[0], plan_lines[0]
        assert "fixes CVE-" in plan_lines[0], plan_lines[0]

    def test_json_carries_structured_plan(self, tmp_path):
        _build_monorepo(tmp_path)
        code, data, _ = scan_json(tmp_path)
        plan = data["sca_fix_plan"]
        assert isinstance(plan, list) and len(plan) == 1
        entry = plan[0]
        assert entry["package"] == "requests"
        assert entry["ecosystem"] == "pypi"
        assert entry["manifest_count"] == 2
        assert entry["cves"] == sorted(entry["cves"]) and entry["cves"]
        assert re.fullmatch(r"\d+(\.\d+)*", entry["fixed_version"])

    def test_no_sca_no_plan_block(self, vuln_tree):
        code, data, _ = scan_json(vuln_tree)
        assert data["sca_fix_plan"] == []
        code, out, _ = run_scan(["scan", str(vuln_tree), "--workers", "1",
                                 "--min-confidence", "all"])
        assert "SCA UPGRADE PLAN" not in out


class TestMonorepoReachability:
    def test_subpackage_evidence_prefers_own_subtree(self):
        finding = _sca_finding("partners/pinecone/requirements.txt")
        roots = {"requests": ("aaa_tools/check.py", 1)}
        hits = {"requests": [("aaa_tools/check.py", 1), ("partners/pinecone/app.py", 1)]}
        sca_scanner.tag_reachability([finding], roots, root_hits=hits)
        assert finding["reachability"] == "REACHABLE"
        assert finding["confidence"] == "HIGH"
        assert "partners/pinecone/app.py" in finding["message"], finding["message"]
        assert "aaa_tools" not in finding["message"]

    def test_without_root_hits_behaviour_is_unchanged(self):
        finding = _sca_finding("partners/pinecone/requirements.txt")
        sca_scanner.tag_reachability([finding], {"requests": ("aaa_tools/check.py", 1)})
        assert finding["reachability"] == "REACHABLE"
        assert "aaa_tools/check.py:1" in finding["message"], finding["message"]

    def test_root_manifest_falls_back_to_repo_wide_evidence(self):
        finding = _sca_finding("requirements.txt")
        roots = {"requests": ("aaa_tools/check.py", 1)}
        hits = {"requests": [("aaa_tools/check.py", 1), ("partners/pinecone/app.py", 1)]}
        sca_scanner.tag_reachability([finding], roots, root_hits=hits)
        assert finding["reachability"] == "REACHABLE"
        assert "aaa_tools/check.py:1" in finding["message"], finding["message"]

    def test_no_importer_stays_unreachable(self):
        finding = _sca_finding("partners/pinecone/requirements.txt")
        sca_scanner.tag_reachability([finding], {}, root_hits={})
        assert finding["reachability"] == "UNREACHABLE_MANIFEST_ONLY"
        assert finding["confidence"] == "LOW"

    def test_cli_end_to_end_prefers_subpackage_importer(self, tmp_path):
        _build_monorepo(tmp_path)
        code, data, _ = scan_json(tmp_path)
        rows = [row for row in data["findings"]
                if row.get("category") == sca_scanner.CATEGORY]
        assert rows, "the vulnerable pin must be reported"
        reachable = [row for row in rows if row.get("reachability") == "REACHABLE"]
        assert reachable, "the sub-package import proves reachability"
        for row in reachable:
            if row["file"].replace("\\", "/").startswith("partners/"):
                assert "partners/pinecone/app.py" in row["message"], row["message"]


# ────────────────────────────────────────── 4. wheel workflow pins

class TestWheelWorkflow:
    def test_yaml_is_valid_and_pins_python_315(self):
        import yaml
        path = ROOT / ".github" / "workflows" / "build_closed_wheel.yml"
        text = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        versions = None
        for job in doc["jobs"].values():
            matrix = (job.get("strategy") or {}).get("matrix") or {}
            if "python-version" in matrix:
                versions = matrix["python-version"]
        assert versions == ["3.11", "3.12", "3.13", "3.14", "3.15"]
        assert "cython>=3.3.0" in text
        assert '"cython>=3.0"' not in text
        assert "Verify exact 15 wheels before Official PyPI publish" in text
        assert 'test "$COUNT" -eq 15' in text
        assert "-eq 12" not in text
