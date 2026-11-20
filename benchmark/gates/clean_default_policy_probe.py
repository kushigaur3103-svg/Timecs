"""Gate #70 -- the clean default output policy: one report floor, three formats, zero detection loss.

TASK 27 added a discovery-and-report layer to `cli.py` (never to the engine). A plain `cli.py scan`
now holds back four kinds of row -- hygiene/audit CWEs, LOW severity, LOW/MEDIUM confidence, and
dormant manifest-only SCA -- while keeping HIGH-confidence CRITICAL/HIGH findings, the exploitable
MEDIUM allowlist (CWE-601/776/116/327) and every REACHABLE dependency advisory, but ONLY at HIGH
confidence (TASK 27.1 Fix 1). Flags come in two families (Fix 2): the FULL-LIFT flags
(--all/--audit-all/--include-tests/--min-confidence) bypass the clean-default floor entirely; the
COMPOSABLE flags (--include-hygiene/--include-unreachable/--min-severity) lift only their own
dimension and --include-vendor only widens discovery, so clean-default stays active for the rest.
The same options persist in the existing root `.tcs.yaml` under a `policy:` block (Fix 3), with
explicit CLI flags always winning and the banner naming `source=.tcs.yaml`. The terminal table, JSON
and SARIF are all built from the SAME filtered list, so they agree by construction. A directory walk
also prunes extra non-production trees, test/demo filenames and vendored/generated code -- but a path
named on the command line is always analysed in full.

The contract this gate locks, in ten tiers:

1. TRUTH TABLE -- `_clean_default_keep` over 36 synthetic rows: every keep/hold branch, the Fix 1
   confidence gate on the exploitable allowlist and reachable SCA (HIGH kept, LOW/MEDIUM held), the
   precedence overrides (unreachable beats exploitable; reachable beats hygiene at HIGH confidence),
   the missing-label defaults, and `_apply_clean_default` purity (subset, never mutation, order kept).
2. MODE + BANNER -- `_output_policy_mode` and the one-line ASCII `[INF] policy -> ...` announcement:
   full-lift flags are custom/full-audit, composable flags stay clean-default, and the banner names
   exactly which floors/blocks are holding rows back and which are showing them.
3. FLOORS + DISCOVERY HELPERS -- `_filter_by_severity`, `_discovery_prune_set`, the filename
   matchers and `_skip_nonprod_filenames` counters. scripts/, ci_cd/, packaging/ and setup.py are
   provably NOT in any prune set.
4. UNIFIED END-TO-END -- a real CLI run: a REACHABLE advisory is kept, a dormant one is held, default
   JSON == SARIF == table, the held row is still DETECTED under --all (display-only proof), metadata
   + banner + note are honest, full-lift flags restore the complete set and composable flags do NOT.
5. SINGLE FILE -- a test_*.py named on the command line is collected and parsed; the same file inside
   a directory walk is pruned by default and restored by --all (measured by discovered-file count).
6. DISCOVERY PRUNING -- a 19-file layout: the default walk discovers only the 5 production files;
   --include-tests discovers 15, --include-vendor 9, --all 19. No pruned path leaks into the report.
7. MUTATIONS -- decision points blinded in turn (keep, apply, unreachable, mode, exploitable
   allowlist, hygiene set, prune set, both filename matchers, severity floor, the Fix 1 confidence
   bypass, the Fix 2 composable-mode reclassification); each must move its own row, every patch restored.
8. ENGINE UNTOUCHED + BUDGET -- ast_scanner.py and scanners/ carry zero diff against HEAD; work and
   peak RSS stay inside the laptop budget.
9. COMPOSABLE -- in-memory isolation of each dimension (include-hygiene shows hygiene but still holds
   dormant SCA and LOW-conf; include-unreachable shows dormant but still holds hygiene; min-severity
   moves only the severity floor; include-vendor changes no finding filter) plus an end-to-end tree
   with a HIGH-confidence hygiene carrier proving the same through terminal/JSON/SARIF.
10. PERSISTENT .tcs.yaml -- a `policy:` block persists across runs with no CLI flag, names
   `source=.tcs.yaml` in the banner, is overridden by an explicit CLI flag, coexists with
   `exclude_paths`, leaves the no-file default byte-identical, and rejects unknown keys/values loudly.

Parity-clean by construction: every vulnerable artefact is a STRING constant written to a temporary
tree, every argv is a literal, and the truth table runs in memory. This file emits zero findings of
its own, so `aa_parity.py` (which scans benchmark/) stays at its frozen count.

Usage: python benchmark/gates/clean_default_policy_probe.py
"""
from __future__ import annotations

import contextlib
import inspect
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

START = time.time()
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import cli  # noqa: E402
import banner  # noqa: E402

BUDGET_SECONDS = 90.0
BUDGET_RSS_MB = 60.0

SCA = cli.SCA_CATEGORY
UNREACHABLE = cli.UNREACHABLE_SCA


def module(*lines):
    return "".join(line + "\n" for line in lines)


# ── vulnerable artefacts (STRING constants only; written to temp trees, never executed here) ──
# A confirmed source->sink flow: input() is USER_CONTROLLED, os.system is OS_COMMAND_EXECUTION, so
# this is a HIGH-confidence CWE-78 row the clean default keeps.
CMD_APP = module(
    "import os",
    "",
    "",
    "def run():",
    "    os.system(input())",
)
# Two vulnerable pins, only one of them imported: pyyaml becomes REACHABLE (kept), pillow stays
# UNREACHABLE_MANIFEST_ONLY (held). The SCA gate proves both pins and the import-name map.
TWO_PIN = "pyyaml==5.3.1\npillow==10.1.0\n"
IMPORTER = module(
    "import yaml",
    "",
    "",
    "def load(text):",
    "    return yaml.safe_load(text)",
)
UNIFIED_TREE = {"requirements.txt": TWO_PIN, "importer.py": IMPORTER, "app.py": CMD_APP}

# A HIGH-confidence hygiene carrier: hashlib.md5 is CWE-328 (MEDIUM severity, HIGH confidence), which
# the clean default holds back as hygiene/audit. --include-hygiene restores exactly this row while the
# dormant LOW-confidence advisory stays held -- the end-to-end proof that a composable flag lifts one
# dimension only. Written as a STRING constant, never executed in this process.
WEAK_HASH = module(
    "import hashlib",
    "",
    "",
    "def digest(data):",
    "    return hashlib.md5(data).hexdigest()",
)
# app.py CWE-78 CRITICAL/HIGH (always kept), h.py CWE-328 MEDIUM/HIGH (hygiene), requirements.txt a
# REACHABLE CWE-502 CRITICAL/HIGH (kept) and a dormant CWE-94 CRITICAL/LOW (held by reachability AND
# by the confidence floor, so --include-unreachable alone must NOT restore it).
COMPOSABLE_TREE = {"app.py": CMD_APP, "h.py": WEAK_HASH,
                   "requirements.txt": TWO_PIN, "importer.py": IMPORTER}

# The 19-file discovery layout. Every file carries the same loud carrier, so the discovered-file
# count is exactly the number of files the walk read, whatever the report policy then does.
PRODUCTION_FILES = ("app.py", "scripts/run.py", "ci_cd/deploy.py", "packaging/build.py", "setup.py")
NONPROD_DIR_FILES = ("docs/guide.py", "demos/demo_app.py", "migrations/0001.py",
                     "cookbook/recipe.py", "tutorials/tut.py", "tests/test_x.py")
NONPROD_NAME_FILES = ("test_unit.py", "helper_test.py", "conftest.py", "demo_show.py")
VENDOR_DIR_FILES = ("vendor/lib.py", "_vendor/lib2.py", "third_party/lib3.py")
VENDOR_NAME_FILES = ("api_pb2.py",)
LAYOUT_TREE = {name: CMD_APP for name in
               PRODUCTION_FILES + NONPROD_DIR_FILES + NONPROD_NAME_FILES
               + VENDOR_DIR_FILES + VENDOR_NAME_FILES}
PRUNED_SAMPLES = ("docs/guide.py", "vendor/lib.py", "test_unit.py", "api_pb2.py", "tests/test_x.py")


# ── CLI helpers (mirror the SCA gate: in-process main, constant argv, temp cwd) ──
def write_tree(root, files):
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


@contextlib.contextmanager
def chdir(path):
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def run_cli(argv, cwd, sarif_name=None):
    """Return (exit_code, stdout, stderr, sarif_path). stdout is the data pipe; stderr the UX."""
    full = list(argv)
    sarif_path = None
    if sarif_name:
        sarif_path = Path(cwd) / sarif_name
        full = full + ["--sarif", str(sarif_path)]
    out, err = io.StringIO(), io.StringIO()
    with chdir(cwd), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(full)
    return code, out.getvalue(), err.getvalue(), sarif_path


def json_payload(stdout):
    start = stdout.find("{")
    if start < 0:
        raise AssertionError(f"cli produced no JSON: {stdout[-300:]}")
    return json.loads(stdout[start:])


def keys_of(findings):
    return {(item["file"], item["line"], item["cwe"]) for item in findings}


def files_of(findings):
    return {item["file"] for item in findings}


def sarif_keys(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    results = document["runs"][0]["results"]
    out = set()
    for result in results:
        physical = result["locations"][0]["physicalLocation"]
        out.add((physical["artifactLocation"]["uri"],
                 physical["region"]["startLine"], result["ruleId"]))
    return out, len(results)


def table_rows(stdout):
    """Data rows of the ascii table: a leading cell that is the 1-based row index."""
    return sum(1 for line in stdout.splitlines() if re.match(r"^\|\s*\d+\s*\|", line))


def base_argv(*extra):
    return ["scan", ".", "--format", "json", "--workers", "1", *extra]


def discovered(payload):
    return payload["scope_breakdown"]["python"]["discovered"]


def advisory(findings, reachability):
    for item in findings:
        if item.get("category") == SCA and item.get("reachability") == reachability:
            return item
    return None


# ── tier 1: the keep/hold truth table ─────────────────────────────────────
def F(cwe, severity, confidence, category="Security", reachability=None):
    finding = {"file": "pkg/mod.py", "line": 7, "cwe": cwe, "severity": severity,
               "confidence": confidence, "category": category, "message": f"{cwe}: synthetic row"}
    if reachability is not None:
        finding["reachability"] = reachability
    return finding


TRUTH_TABLE = (
    # kept: HIGH-confidence CRITICAL/HIGH/MEDIUM severity, non-hygiene
    ("critical high-conf kept", F("CWE-78", "CRITICAL", "HIGH"), True),
    ("high high-conf kept", F("CWE-89", "HIGH", "HIGH"), True),
    ("medium-sev high-conf kept", F("CWE-22", "MEDIUM", "HIGH"), True),
    # Fix 1: the exploitable-MEDIUM allowlist must clear the CONFIDENCE floor. HIGH-confidence rows
    # are kept (and still bypass the severity floor); LOW/MEDIUM-confidence rows are held back exactly
    # like any other unconfirmed row -- a structural match is not a confirmed exploit.
    ("open redirect HIGH-conf kept", F("CWE-601", "MEDIUM", "HIGH"), True),
    ("open redirect MED-conf held", F("CWE-601", "MEDIUM", "MEDIUM"), False),
    ("xml entity HIGH-conf kept", F("CWE-776", "MEDIUM", "HIGH"), True),
    ("xml entity LOW-conf held", F("CWE-776", "MEDIUM", "LOW"), False),
    ("autoescape HIGH-conf kept bypasses sev", F("CWE-116", "LOW", "HIGH"), True),
    ("autoescape MED-conf held", F("CWE-116", "LOW", "MEDIUM"), False),
    ("insecure cipher HIGH-conf kept", F("CWE-327", "MEDIUM", "HIGH"), True),
    ("insecure cipher MED-conf held", F("CWE-327", "MEDIUM", "MEDIUM"), False),
    ("exploitable LOW-conf held", F("CWE-601", "LOW", "LOW"), False),
    # Fix 1: a REACHABLE advisory likewise needs HIGH confidence. At HIGH it bypasses severity and
    # hygiene; at LOW/MEDIUM it is held, so reachability alone never smuggles an unconfirmed row in.
    ("reachable sca HIGH-conf kept", F("CWE-502", "LOW", "HIGH", SCA, "REACHABLE"), True),
    ("reachable sca LOW-conf held", F("CWE-502", "LOW", "LOW", SCA, "REACHABLE"), False),
    ("reachable beats hygiene HIGH-conf", F("CWE-352", "LOW", "HIGH", SCA, "REACHABLE"), True),
    ("reachable hygiene LOW-conf held", F("CWE-352", "LOW", "LOW", SCA, "REACHABLE"), False),
    # held: severity floor
    ("low severity held", F("CWE-78", "LOW", "HIGH"), False),
    # held: confidence floor
    ("medium confidence held", F("CWE-78", "HIGH", "MEDIUM"), False),
    ("low confidence held", F("CWE-78", "CRITICAL", "LOW"), False),
    ("missing confidence defaults medium held", F("CWE-78", "HIGH", None), False),
    ("missing severity held", F("CWE-78", "", "HIGH"), False),
    # held: every hygiene/audit CWE, even at HIGH confidence and HIGH severity
    ("csrf held", F("CWE-352", "HIGH", "HIGH"), False),
    ("sri 353 held", F("CWE-353", "HIGH", "HIGH"), False),
    ("sri 829 held", F("CWE-829", "HIGH", "HIGH"), False),
    ("cookie 614 held", F("CWE-614", "HIGH", "HIGH"), False),
    ("cookie 1004 held", F("CWE-1004", "HIGH", "HIGH"), False),
    ("cookie 1275 held", F("CWE-1275", "HIGH", "HIGH"), False),
    ("unbounded 770 held", F("CWE-770", "HIGH", "HIGH"), False),
    ("exposure 200 held", F("CWE-200", "HIGH", "HIGH"), False),
    ("weak hash 328 held", F("CWE-328", "HIGH", "HIGH"), False),
    ("perms 276 held", F("CWE-276", "HIGH", "HIGH"), False),
    ("random 330 held", F("CWE-330", "HIGH", "HIGH"), False),
    ("default 1188 held", F("CWE-1188", "HIGH", "HIGH"), False),
    # held: dormant SCA, and unreachable beats the exploitable allowlist
    ("unreachable sca held", F("CWE-502", "CRITICAL", "HIGH", SCA, UNREACHABLE), False),
    ("unreachable beats exploitable", F("CWE-601", "HIGH", "HIGH", SCA, UNREACHABLE), False),
)


def check_truth_table():
    failures = []
    for label, finding, want in TRUTH_TABLE:
        got = cli._clean_default_keep(finding)
        if got is not want:
            failures.append(f"truth table {label}: keep={got}, expected {want}")
    rows = [dict(finding, line=index)
            for index, (_label, finding, _want) in enumerate(TRUTH_TABLE, 1)]
    snapshot = json.dumps(rows, sort_keys=True)
    kept, held = cli._apply_clean_default(rows)
    want_kept = [f for f, (_l, _f, w) in zip(rows, TRUTH_TABLE) if w]
    if keys_of(kept) != keys_of(want_kept):
        failures.append("_apply_clean_default kept the wrong set")
    if len(kept) + len(held) != len(rows):
        failures.append("_apply_clean_default lost or duplicated a row")
    if json.dumps(rows, sort_keys=True) != snapshot:
        failures.append("_apply_clean_default mutated its input")
    if [id(f) for f in kept] != [id(f) for f in rows if cli._clean_default_keep(f)]:
        failures.append("_apply_clean_default did not preserve emission order")
    return failures, len(TRUTH_TABLE)


# ── tier 2: mode selection and the ASCII banner ───────────────────────────
def args(**kw):
    base = dict(all=False, include_tests=False, include_vendor=False, include_hygiene=False,
                include_unreachable=False, audit_all=False, min_severity=None, min_confidence=None,
                format="table")
    base.update(kw)
    return types.SimpleNamespace(**base)


MODE_CASES = (
    ("no flag is clean-default", args(), "clean-default"),
    # full-lift flags bypass the clean-default floor (backward compatible with the frozen gates)
    ("include-tests is custom", args(include_tests=True), "custom"),
    ("audit-all is custom", args(audit_all=True), "custom"),
    ("min-confidence is custom", args(min_confidence="high"), "custom"),
    ("--all is full-audit", args(all=True), "full-audit"),
    ("--all wins over a named floor", args(all=True, min_confidence="high"), "full-audit"),
    # composable flags keep clean-default ACTIVE and lift only their own dimension (Fix 2)
    ("include-vendor stays clean-default", args(include_vendor=True), "clean-default"),
    ("include-hygiene stays clean-default", args(include_hygiene=True), "clean-default"),
    ("include-unreachable stays clean-default", args(include_unreachable=True), "clean-default"),
    ("min-severity stays clean-default", args(min_severity="low"), "clean-default"),
)


def check_mode_banner():
    failures = []
    for label, namespace, want in MODE_CASES:
        got = cli._output_policy_mode(namespace)
        if got != want:
            failures.append(f"mode {label}: {got}, expected {want}")
        text = cli._policy_banner(namespace)
        if not text.startswith("policy -> "):
            failures.append(f"banner {label} does not start with 'policy -> ': {text!r}")
        if not text.isascii():
            failures.append(f"banner {label} is not ASCII: {text!r}")
        if want not in text:
            failures.append(f"banner {label} does not name the mode {want}: {text!r}")
    if "min-confidence=high" not in cli._policy_banner(args(min_confidence="high")):
        failures.append("custom banner omits the named confidence floor")
    if "min-severity=low" not in cli._policy_banner(args(min_severity="low")):
        failures.append("clean-default banner omits the named severity floor")
    if "include-tests" not in cli._policy_banner(args(include_tests=True)):
        failures.append("custom banner omits the include-tests scope flag")
    # The banner must tell the truth about which dimension a composable flag lifted and which it kept.
    hyg = cli._policy_banner(args(include_hygiene=True))
    if "showing hygiene" not in hyg or "dormant-SCA" not in hyg:
        failures.append(f"include-hygiene banner must show hygiene and still hold dormant SCA: {hyg!r}")
    unr = cli._policy_banner(args(include_unreachable=True))
    if "showing dormant-SCA" not in unr or "holding back hygiene" not in unr:
        failures.append(f"include-unreachable banner must show dormant SCA and still hold hygiene: {unr!r}")
    if "min-severity=high" not in cli._policy_banner(args(min_severity="high")):
        failures.append("clean-default banner omits a raised severity floor")
    if "include-vendor" not in cli._policy_banner(args(include_vendor=True)):
        failures.append("clean-default banner omits the include-vendor discovery flag")
    # A .tcs.yaml-sourced option must be named in the banner; a CLI-only option must not claim a source.
    yaml_text = cli._policy_banner(args(include_hygiene=True, _yaml_policy_keys=("include_hygiene",)))
    if "source=.tcs.yaml" not in yaml_text or "include_hygiene" not in yaml_text:
        failures.append(f"banner does not name the .tcs.yaml source: {yaml_text!r}")
    if "source=.tcs.yaml" in cli._policy_banner(args(include_hygiene=True)):
        failures.append("a CLI-only flag must not claim a .tcs.yaml source")
    stream = io.StringIO()
    banner.badge("INF", cli._policy_banner(args()), stream=stream)
    line = stream.getvalue()
    if not line.startswith("[INF] policy -> clean-default"):
        failures.append(f"badge did not render '[INF] policy -> clean-default': {line!r}")
    if "\033[" in line:
        failures.append("badge emitted colour to a non-TTY stream")
    return failures, len(MODE_CASES)


# ── tier 3: severity floor and discovery helpers ──────────────────────────
def check_helpers():
    failures = []
    rows = [F("CWE-78", "CRITICAL", "HIGH"), F("CWE-89", "HIGH", "HIGH"),
            F("CWE-22", "MEDIUM", "HIGH"), F("CWE-352", "LOW", "HIGH")]
    for minimum, want in ((None, 4), ("low", 4), ("medium", 3), ("high", 2), ("critical", 1)):
        got = cli._filter_by_severity(rows, minimum)
        if len(got) != want:
            failures.append(f"_filter_by_severity({minimum}) kept {len(got)}, expected {want}")
    if cli._filter_by_severity(rows, None) is not rows:
        failures.append("_filter_by_severity(None) must return the list untouched")

    if cli._discovery_prune_set(False, False) is not None:
        failures.append("no opt-out must mean no prune set (None)")
    nonprod = cli._discovery_prune_set(True, False)
    vendor = cli._discovery_prune_set(False, True)
    both = cli._discovery_prune_set(True, True)
    for name in ("docs", "doc", "demos", "demo", "benchmarks", "tutorials", "migrations", "cookbook"):
        if name not in nonprod:
            failures.append(f"extra non-production dir {name} missing from the nonprod prune set")
    for name in ("tests", "testutils", "fixtures", "examples", "samples", "debug"):
        if name not in nonprod:
            failures.append(f"non-production dir {name} missing from the nonprod prune set")
    for name in ("vendor", "_vendor", "third_party"):
        if name not in vendor:
            failures.append(f"vendor dir {name} missing from the vendor prune set")
        if name in nonprod:
            failures.append(f"vendor dir {name} leaked into the nonprod-only prune set")
    for name in ("docs", "tests"):
        if name in vendor:
            failures.append(f"non-production dir {name} leaked into the vendor-only prune set")
    for name in ("scripts", "ci_cd", "packaging", "src", "lib", "app"):
        for label, prune in (("nonprod", nonprod), ("vendor", vendor), ("both", both)):
            if name in prune:
                failures.append(f"production dir {name} was pruned by the {label} set")
    for name in cli.IGNORED_DIRS:
        if name not in both:
            failures.append(f"ignored dir {name} missing from the combined prune set")

    for name in ("test_x.py", "x_test.py", "x_tests.py", "conftest.py", "demo_x.py",
                 "x_demo.py", "x_mock.py"):
        if not cli._is_nonprod_filename(name):
            failures.append(f"non-production filename {name} was not matched")
    for name in ("app.py", "setup.py", "scripts.py", "contest.py", "democracy.py", "x_pb2.py"):
        if cli._is_nonprod_filename(name):
            failures.append(f"production filename {name} was wrongly matched as non-production")
    if not cli._is_vendor_filename("api_pb2.py"):
        failures.append("api_pb2.py was not matched as generated")
    for name in ("app.py", "pb2.py", "x_pb2.pyi"):
        if cli._is_vendor_filename(name):
            failures.append(f"{name} was wrongly matched as generated protobuf")

    for stat in cli._SCOPE_STATS:
        cli._SCOPE_STATS[stat] = 0
    paths = [Path(n) for n in ("app.py", "test_x.py", "conftest.py", "api_pb2.py", "setup.py")]
    kept = cli._skip_nonprod_filenames(paths, True, True)
    if {p.name for p in kept} != {"app.py", "setup.py"}:
        failures.append(f"_skip_nonprod_filenames kept {[p.name for p in kept]}")
    if cli._SCOPE_STATS["skipped_filenames"] != 2:
        failures.append(f"skipped_filenames={cli._SCOPE_STATS['skipped_filenames']}, expected 2")
    if cli._SCOPE_STATS["vendor_files"] != 1:
        failures.append(f"vendor_files={cli._SCOPE_STATS['vendor_files']}, expected 1")
    for stat in cli._SCOPE_STATS:
        cli._SCOPE_STATS[stat] = 0
    if len(cli._skip_nonprod_filenames(paths, False, False)) != len(paths):
        failures.append("no opt-out must keep every filename")
    return failures


# ── tier 4: unified end-to-end ────────────────────────────────────────────
def check_unified():
    failures = []
    facts = {}
    with tempfile.TemporaryDirectory(prefix="tcs_policy_unified_") as tmp:
        tree = Path(tmp)
        write_tree(tree, UNIFIED_TREE)
        _code, full_out, _full_err, full_sarif = run_cli(base_argv("--all"), tree, "full.sarif")
        full = json_payload(full_out)
        full_findings = full["findings"]
        full_keys = keys_of(full_findings)
        reachable = advisory(full_findings, "REACHABLE")
        dormant = advisory(full_findings, UNREACHABLE)
        if reachable is None:
            failures.append("the imported pin produced no REACHABLE advisory to keep")
        if dormant is None:
            failures.append("the un-imported pin produced no UNREACHABLE advisory to hold back")
        if full["output_policy"] != "full-audit" or full["held_back_findings"] != 0:
            failures.append(f"--all metadata is {full['output_policy']}/{full['held_back_findings']}")
        if reachable is None or dormant is None:
            return failures, facts

        _code, def_out, def_err, def_sarif = run_cli(base_argv(), tree, "default.sarif")
        default = json_payload(def_out)
        def_findings = default["findings"]
        def_keys = keys_of(def_findings)
        want_keys = {(i["file"], i["line"], i["cwe"]) for i in full_findings
                     if cli._clean_default_keep(i)}
        facts["full"] = len(full_findings)
        facts["default"] = len(def_findings)
        if def_keys != want_keys:
            failures.append(f"default JSON {sorted(def_keys)} != clean-default keep of --all "
                            f"{sorted(want_keys)}")
        if (reachable["file"], reachable["line"], reachable["cwe"]) not in def_keys:
            failures.append("the REACHABLE advisory was wrongly held back by default")
        if (dormant["file"], dormant["line"], dormant["cwe"]) in def_keys:
            failures.append("the dormant advisory was NOT held back by default")
        if default["output_policy"] != "clean-default":
            failures.append(f"default output_policy is {default['output_policy']}")
        if default["held_back_findings"] != len(full_findings) - len(def_findings):
            failures.append("held_back_findings does not match the held set size")
        if default["confidence_filter"] is not None:
            failures.append("clean-default must not set an explicit confidence_filter")
        if not def_findings:
            failures.append("the default report held back everything, so keeping is unmeasured")

        # SARIF and the table are built from the same filtered list.
        s_keys, s_count = sarif_keys(def_sarif)
        if s_keys != def_keys or s_count != len(def_findings):
            failures.append(f"default SARIF {s_count} rows {sorted(s_keys)} != JSON {sorted(def_keys)}")
        fs_keys, fs_count = sarif_keys(full_sarif)
        if fs_keys != full_keys or fs_count != len(full_findings):
            failures.append("--all SARIF does not match --all JSON")
        _code, table_out, _table_err, _t = run_cli(
            ["scan", ".", "--format", "table", "--workers", "1"], tree)
        if table_rows(table_out) != len(def_findings):
            failures.append(f"default table shows {table_rows(table_out)} rows, "
                            f"JSON shows {len(def_findings)}")
        if "policy -> clean-default" not in def_err:
            failures.append("the scan-start policy banner is missing from stderr")
        if "Held back" not in def_err or "--all" not in def_err:
            failures.append("the clean-default held-back note is missing or does not name --all")

        # Full-lift flags bypass the clean-default floor entirely: the complete emission set returns.
        for flag in ("--include-tests", "--audit-all", "--min-confidence"):
            extra = [flag, "low"] if flag == "--min-confidence" else [flag]
            _code, out, _err, _s = run_cli(base_argv(*extra), tree)
            payload = json_payload(out)
            if payload["output_policy"] not in ("custom", "full-audit"):
                failures.append(f"{flag} did not switch to a full-lift mode")
            if keys_of(payload["findings"]) != full_keys:
                failures.append(f"{flag} did not restore the complete emission set")
        # Composable flags keep clean-default ACTIVE. On this tree the only held row is a dormant
        # LOW-confidence advisory, so lifting hygiene / unreachable / vendor / the severity floor must
        # NOT smuggle it back in -- that accidental full-floor lift is exactly the Fix 2 regression.
        for extra in (["--include-hygiene"], ["--include-unreachable"], ["--include-vendor"],
                      ["--min-severity", "low"]):
            _code, out, err, _s = run_cli(base_argv(*extra), tree)
            payload = json_payload(out)
            if payload["output_policy"] != "clean-default":
                failures.append(f"{extra[0]} wrongly left clean-default mode")
            if keys_of(payload["findings"]) != def_keys:
                failures.append(f"{extra[0]} accidentally changed the held set on the unified tree")
            if "policy -> clean-default" not in err:
                failures.append(f"{extra[0]} banner does not announce clean-default")
        _code, out, _err, _s = run_cli(base_argv("--all"), tree)
        if keys_of(json_payload(out)["findings"]) != full_keys:
            failures.append("--all did not restore the complete emission set")
    return failures, facts


# ── tier 5: a test_*.py named on the command line is never pruned ─────────
def check_single_file():
    failures = []
    with tempfile.TemporaryDirectory(prefix="tcs_policy_single_") as tmp:
        tree = Path(tmp)
        # app.py is a production control so the walk always has one file to read; test_vuln.py is
        # the filename a default walk prunes but a command-line path never does.
        write_tree(tree, {"test_vuln.py": CMD_APP, "app.py": CMD_APP})
        _code, dir_out, _err, _s = run_cli(base_argv(), tree)
        dir_payload = json_payload(dir_out)
        if discovered(dir_payload) != 1:
            failures.append(f"a directory walk discovered {discovered(dir_payload)} file(s); "
                            "test_vuln.py should be pruned by filename, leaving only app.py")
        if any(item["file"] == "test_vuln.py" for item in dir_payload["findings"]):
            failures.append("test_vuln.py leaked into the default directory report")
        _code, file_out, _err, _s = run_cli(
            ["scan", "test_vuln.py", "--format", "json", "--workers", "1"], tree)
        file_payload = json_payload(file_out)
        if discovered(file_payload) != 1:
            failures.append(f"a test_*.py named on the command line discovered "
                            f"{discovered(file_payload)} file(s), expected 1 (never pruned)")
        _code, all_out, _err, _s = run_cli(base_argv("--all"), tree)
        if discovered(json_payload(all_out)) != 2:
            failures.append("--all did not restore test_vuln.py to the directory walk")
    return failures


# ── tier 6: discovery pruning over the 19-file layout ─────────────────────
def check_discovery():
    failures = []
    facts = {}
    production = set(PRODUCTION_FILES)
    with tempfile.TemporaryDirectory(prefix="tcs_policy_layout_") as tmp:
        tree = Path(tmp)
        write_tree(tree, LAYOUT_TREE)
        expectations = (
            ("default", base_argv(), 5),
            ("include-tests", base_argv("--include-tests"), 15),
            ("include-vendor", base_argv("--include-vendor"), 9),
            ("all", base_argv("--all"), 19),
        )
        for label, argv, want in expectations:
            _code, out, _err, _s = run_cli(argv, tree)
            payload = json_payload(out)
            got = discovered(payload)
            facts[label] = got
            if got != want:
                failures.append(f"{label} discovered {got} python file(s), expected {want}")
        _code, out, _err, _s = run_cli(base_argv(), tree)
        default_files = files_of(json_payload(out)["findings"])
        # Whatever the report keeps, it must never name a pruned path, and any production row it
        # does keep must be one of the five production files.
        for name in PRUNED_SAMPLES:
            if name in default_files:
                failures.append(f"pruned path {name} leaked into the default report")
        if not default_files <= production:
            failures.append(f"default report named non-production files {sorted(default_files - production)}")
        # Under full audit every one of the 19 files is loud, so the layout itself is proven real.
        _code, all_out, _err, _s = run_cli(base_argv("--all"), tree)
        all_files = files_of(json_payload(all_out)["findings"])
        if len(all_files) != 19:
            failures.append(f"--all reported {len(all_files)} distinct files, expected 19 "
                            "(a fixture file is silent, so the layout is unmeasured)")
        for name in PRODUCTION_FILES:
            if name not in all_files:
                failures.append(f"production file {name} is silent under --all")
    return failures, facts


# ── tier 7: mutations ─────────────────────────────────────────────────────
def _const(value):
    return lambda *a, **k: value


def unified_pair():
    with tempfile.TemporaryDirectory(prefix="tcs_policy_mut_") as tmp:
        tree = Path(tmp)
        write_tree(tree, UNIFIED_TREE)
        _code, d_out, _err, _s = run_cli(base_argv(), tree)
        _code, f_out, _err, _s = run_cli(base_argv("--all"), tree)
        return keys_of(json_payload(d_out)["findings"]), keys_of(json_payload(f_out)["findings"])


def _default_equals_full():
    default_keys, full_keys = unified_pair()
    return bool(full_keys) and default_keys == full_keys


def default_layout_discovered():
    with tempfile.TemporaryDirectory(prefix="tcs_policy_mutl_") as tmp:
        tree = Path(tmp)
        write_tree(tree, LAYOUT_TREE)
        _code, out, _err, _s = run_cli(base_argv(), tree)
        return discovered(json_payload(out))


def _exploitable_case():
    # LOW severity, HIGH confidence: kept ONLY because the exploitable allowlist bypasses the
    # severity floor. Emptying the allowlist must drop it to the normal floors (which hold LOW sev).
    return cli._clean_default_keep(F("CWE-116", "LOW", "HIGH"))


def _fix1_conf_bypass_case():
    # A MEDIUM-confidence exploitable row must be HELD (Fix 1). The pre-fix bug returned True for the
    # allowlist before the confidence floor, so this probe flips to True only under that regression.
    return cli._clean_default_keep(F("CWE-601", "MEDIUM", "MEDIUM")) is True


def _composable_mode_case():
    # include-hygiene must stay clean-default (Fix 2). The old code switched any opt-in flag to
    # custom, lifting every floor; this probe flips to True only under that regression.
    return cli._output_policy_mode(args(include_hygiene=True)) == "custom"


def _buggy_keep_no_conf_gate(finding, *a, **k):
    """The pre-Fix-1 logic, restored as a mutation: allowlist/reachable return True before confidence."""
    cwe = str(finding.get("cwe", ""))
    if cli._is_unreachable_sca(finding):
        return False
    if cwe in cli.EXPLOITABLE_MEDIUM_CWES or cli._is_reachable_sca(finding):
        return True
    if cwe in cli.HYGIENE_AUDIT_CWES:
        return False
    severity = str(finding.get("severity", "")).upper()
    confidence = str(finding.get("confidence") or "MEDIUM").upper()
    if cli.SEVERITY_ORDER.get(severity, 0) < cli.SEVERITY_ORDER[cli.CLEAN_DEFAULT_MIN_SEVERITY]:
        return False
    if cli.CONFIDENCE_ORDER.get(confidence, 2) < cli.CONFIDENCE_ORDER[cli.CLEAN_DEFAULT_MIN_CONFIDENCE]:
        return False
    return True


def _old_mode_composable_is_custom(a):
    """The pre-Fix-2 mode rule, restored as a mutation: every opt-in flag becomes custom."""
    if getattr(a, "all", False):
        return "full-audit"
    if any((getattr(a, "include_tests", False), getattr(a, "include_vendor", False),
            getattr(a, "include_hygiene", False), getattr(a, "include_unreachable", False),
            getattr(a, "audit_all", False), getattr(a, "min_severity", None) is not None,
            getattr(a, "min_confidence", None) is not None)):
        return "custom"
    return "clean-default"


def _unreachable_case():
    # HIGH/HIGH so the ONLY thing holding this row is its dormant reachability, not a floor.
    return cli._clean_default_keep(F("CWE-502", "CRITICAL", "HIGH", SCA, UNREACHABLE))


def _hygiene_case():
    return cli._clean_default_keep(F("CWE-352", "HIGH", "HIGH"))


def _severity_floor_case():
    rows = [F("CWE-78", "LOW", "HIGH"), F("CWE-89", "HIGH", "HIGH")]
    return len(cli._filter_by_severity(rows, "high"))


MUTATIONS = {
    "keep_always_true": (((cli, "_clean_default_keep", _const(True)),), _default_equals_full),
    "apply_never_holds": (((cli, "_apply_clean_default", lambda fs, *a, **k: (fs, [])),),
                          _default_equals_full),
    "unreachable_blind": (((cli, "_is_unreachable_sca", _const(False)),),
                          lambda: _unreachable_case() is True),
    "mode_always_full": (((cli, "_output_policy_mode", _const("full-audit")),), _default_equals_full),
    "exploitable_allowlist_emptied": (((cli, "EXPLOITABLE_MEDIUM_CWES", frozenset()),),
                                      lambda: _exploitable_case() is False),
    "hygiene_set_emptied": (((cli, "HYGIENE_AUDIT_CWES", frozenset()),),
                            lambda: _hygiene_case() is True),
    "prune_set_blind": (((cli, "_discovery_prune_set", _const(None)),),
                        lambda: default_layout_discovered() > 5),
    "nonprod_filename_blind": (((cli, "_is_nonprod_filename", _const(False)),),
                               lambda: default_layout_discovered() > 5),
    "vendor_filename_blind": (((cli, "_is_vendor_filename", _const(False)),),
                              lambda: default_layout_discovered() > 5),
    "severity_floor_blind": (((cli, "_filter_by_severity", lambda fs, m: fs),),
                             lambda: _severity_floor_case() == 2),
    "fix1_exploitable_conf_bypass": (((cli, "_clean_default_keep", _buggy_keep_no_conf_gate),),
                                     _fix1_conf_bypass_case),
    "fix2_composable_mode_reverted": (((cli, "_output_policy_mode", _old_mode_composable_is_custom),),
                                      _composable_mode_case),
}


def run_mutations():
    failures = []
    caught = 0
    for name, (patches, probe) in sorted(MUTATIONS.items()):
        saved = [(mod, attribute, inspect.getattr_static(mod, attribute))
                 for mod, attribute, _replacement in patches]
        try:
            for mod, attribute, replacement in patches:
                setattr(mod, attribute, replacement)
            seen = bool(probe())
        finally:
            for mod, attribute, original in saved:
                setattr(mod, attribute, original)
            for mod, attribute, original in saved:
                if inspect.getattr_static(mod, attribute) is not original:
                    failures.append(f"{name}: {mod.__name__}.{attribute} was not restored")
        if seen:
            caught += 1
        else:
            failures.append(f"{name}: blinding it changed nothing, so it is not what decides the row")
    return failures, caught


# ── tier 8: the engine is untouched, and the budget ───────────────────────
def check_engine_untouched():
    failures = []
    diff_state = "git unavailable"
    try:
        proc = subprocess.run(["git", "diff", "--exit-code", "HEAD", "--",
                               "ast_scanner.py", "scanners"],
                              cwd=str(REPO_ROOT), capture_output=True, encoding="utf-8",
                              errors="replace", timeout=120)
        diff_state = "clean" if proc.returncode == 0 else "dirty"
        if proc.returncode != 0:
            failures.append("ast_scanner.py / scanners/ carry a diff against HEAD:\n"
                            + proc.stdout[-600:])
    except (OSError, subprocess.SubprocessError):
        pass
    return failures, diff_state


def peak_rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1048576.0
    except Exception:
        return 0.0


# ── tier 9: composable flags lift one dimension only ──────────────────────
def check_composable():
    failures = []
    facts = {}
    # In-memory isolation: every row sits at a known confidence/severity so exactly one named block
    # decides it. This proves the dimension lift without depending on the engine's label choices.
    hyg = F("CWE-352", "HIGH", "HIGH")
    dormant = F("CWE-502", "CRITICAL", "HIGH", SCA, UNREACHABLE)
    reachable = F("CWE-502", "CRITICAL", "HIGH", SCA, "REACHABLE")
    lowconf = F("CWE-78", "CRITICAL", "MEDIUM")
    lowsev = F("CWE-78", "LOW", "HIGH")
    normal = F("CWE-78", "CRITICAL", "HIGH")
    medsev = F("CWE-22", "MEDIUM", "HIGH")
    rows = [hyg, dormant, reachable, lowconf, lowsev, normal, medsev]
    labels = ["hygiene", "dormant", "reachable", "lowconf", "lowsev", "normal", "medsev"]
    index_by_id = {id(row): lab for row, lab in zip(rows, labels)}
    snapshot = json.dumps(rows, sort_keys=True)

    def kept_labels(namespace):
        kept, held = cli._apply_clean_default(rows, namespace)
        if len(kept) + len(held) != len(rows):
            failures.append("composable apply lost or duplicated a row")
        return {index_by_id[id(row)] for row in kept}

    cases = (
        ("default", args(), {"reachable", "normal", "medsev"}),
        ("include-hygiene", args(include_hygiene=True),
         {"hygiene", "reachable", "normal", "medsev"}),
        ("include-unreachable", args(include_unreachable=True),
         {"dormant", "reachable", "normal", "medsev"}),
        ("hygiene+unreachable", args(include_hygiene=True, include_unreachable=True),
         {"hygiene", "dormant", "reachable", "normal", "medsev"}),
        ("min-severity=low", args(min_severity="low"),
         {"reachable", "normal", "medsev", "lowsev"}),
        ("min-severity=high", args(min_severity="high"), {"reachable", "normal"}),
        ("include-vendor", args(include_vendor=True), {"reachable", "normal", "medsev"}),
    )
    for label, namespace, want in cases:
        got = kept_labels(namespace)
        facts[label] = len(got)
        if got != want:
            failures.append(f"composable {label}: kept {sorted(got)}, expected {sorted(want)}")
    if json.dumps(rows, sort_keys=True) != snapshot:
        failures.append("composable apply mutated its input")

    # End-to-end through the real CLI: a HIGH-confidence hygiene carrier (CWE-328 MEDIUM/HIGH) and a
    # dormant LOW-confidence advisory. include-hygiene restores the hygiene row only; the dormant row
    # stays held under every composable flag because its confidence floor is never lifted.
    with tempfile.TemporaryDirectory(prefix="tcs_policy_composable_") as tmp:
        tree = Path(tmp)
        write_tree(tree, COMPOSABLE_TREE)

        def run(extra, sarif_name=None):
            _code, out, err, sarif = run_cli(base_argv(*extra), tree, sarif_name)
            return json_payload(out), err, sarif

        full, _err, _s = run(["--all"])
        full_keys = keys_of(full["findings"])
        if len(full_keys) != 4:
            failures.append(f"composable tree --all produced {len(full_keys)} rows, expected 4")
        default, def_err, def_sarif = run([], "comp_default.sarif")
        def_keys = keys_of(default["findings"])
        if len(def_keys) != 2:
            failures.append(f"composable tree default produced {len(def_keys)} rows, expected 2")

        hyg_payload, hyg_err, hyg_sarif = run(["--include-hygiene"], "comp_hyg.sarif")
        hyg_keys = keys_of(hyg_payload["findings"])
        facts["e2e_default"] = len(def_keys)
        facts["e2e_hygiene"] = len(hyg_keys)
        if hyg_payload["output_policy"] != "clean-default":
            failures.append("include-hygiene left clean-default mode end-to-end")
        if len(hyg_keys) != 3 or not any(cwe == "CWE-328" for _f, _l, cwe in hyg_keys):
            failures.append(f"include-hygiene did not restore exactly the hygiene row: {sorted(hyg_keys)}")
        if any(cwe == "CWE-94" for _f, _l, cwe in hyg_keys):
            failures.append("include-hygiene accidentally restored the dormant advisory")
        # terminal/JSON/SARIF agree for the composable run too
        s_keys, s_count = sarif_keys(hyg_sarif)
        if s_keys != hyg_keys or s_count != len(hyg_keys):
            failures.append("include-hygiene SARIF disagrees with JSON")
        _code, table_out, _te, _ts = run_cli(
            ["scan", ".", "--format", "table", "--workers", "1", "--include-hygiene"], tree)
        if table_rows(table_out) != len(hyg_keys):
            failures.append("include-hygiene table disagrees with JSON")
        if "showing hygiene" not in hyg_err or "source=.tcs.yaml" in hyg_err:
            failures.append(f"include-hygiene CLI banner is wrong: {hyg_err!r}")

        for extra, want_n in ((["--include-unreachable"], 2), (["--include-vendor"], 2),
                              (["--min-severity", "low"], 2),
                              (["--include-hygiene", "--min-severity", "high"], 2),
                              (["--include-hygiene", "--min-severity", "medium"], 3)):
            payload, err, _s = run(extra)
            got = keys_of(payload["findings"])
            if payload["output_policy"] != "clean-default":
                failures.append(f"{extra} left clean-default mode end-to-end")
            if len(got) != want_n:
                failures.append(f"{extra} produced {len(got)} rows, expected {want_n}")
            if any(cwe == "CWE-94" for _f, _l, cwe in got):
                failures.append(f"{extra} accidentally restored the dormant LOW-confidence advisory")
    return failures, facts


# ── tier 10: persistent policy in the existing .tcs.yaml ──────────────────
def check_yaml_policy():
    failures = []
    facts = {}
    with tempfile.TemporaryDirectory(prefix="tcs_policy_yaml_") as tmp:
        tree = Path(tmp)
        write_tree(tree, COMPOSABLE_TREE)
        config = tree / ".tcs.yaml"

        def run(extra, sarif_name=None):
            _code, out, err, sarif = run_cli(base_argv(*extra), tree, sarif_name)
            return _code, json_payload(out), err, sarif

        def set_yaml(text):
            config.write_text(text, encoding="utf-8")

        # 1. A composable policy key persists with NO CLI flag and restores exactly its dimension.
        set_yaml("policy:\n  include_hygiene: true\n")
        _code, payload, err, _s = run([])
        facts["yaml_hygiene"] = len(payload["findings"])
        if payload["output_policy"] != "clean-default":
            failures.append("yaml include_hygiene did not stay clean-default")
        if len(payload["findings"]) != 3:
            failures.append(f"yaml include_hygiene kept {len(payload['findings'])}, expected 3")
        if "source=.tcs.yaml" not in err or "include_hygiene" not in err:
            failures.append(f"yaml banner does not name the source: {err!r}")
        if "showing hygiene" not in err:
            failures.append("yaml include_hygiene banner does not show the lifted dimension")

        # 2. An explicit CLI flag overrides the yaml value (min-severity high -> medium).
        set_yaml("policy:\n  include_hygiene: true\n  min_severity: high\n")
        _code, base, base_err, _s = run([])
        if len(base["findings"]) != 2:
            failures.append(f"yaml min_severity=high should hold the MEDIUM hygiene row: {len(base['findings'])}")
        _code, over, over_err, _s = run(["--min-severity", "medium"])
        if len(over["findings"]) != 3:
            failures.append(f"CLI --min-severity medium did not override yaml high: {len(over['findings'])}")
        if "min-severity=medium" not in over_err:
            failures.append("override banner does not name the CLI severity floor")
        if "min_severity" in over_err.split("source=.tcs.yaml:")[-1]:
            failures.append("an explicit CLI flag must not be credited to .tcs.yaml")

        # 3. A full-lift policy key (min_confidence) restores the dormant LOW-confidence advisory.
        set_yaml("policy:\n  min_confidence: low\n")
        _code, payload, err, _s = run([])
        facts["yaml_min_confidence"] = len(payload["findings"])
        if payload["output_policy"] != "custom":
            failures.append("yaml min_confidence did not switch to custom (full-lift)")
        if len(payload["findings"]) != 4:
            failures.append(f"yaml min_confidence=low kept {len(payload['findings'])}, expected 4")
        if "source=.tcs.yaml" not in err or "min_confidence" not in err:
            failures.append(f"yaml min_confidence banner does not name the source: {err!r}")

        # 4. CLI --min-confidence high overrides yaml low: the dormant LOW row is held again.
        _code, over, over_err, _s = run(["--min-confidence", "high"])
        if len(over["findings"]) != 3:
            failures.append(f"CLI --min-confidence high did not override yaml low: {len(over['findings'])}")
        if "min-confidence=high" not in over_err or "source=.tcs.yaml" in over_err:
            failures.append(f"override banner wrong: {over_err!r}")

        # 5. yaml all:true is full-audit and names the source.
        set_yaml("policy:\n  all: true\n")
        _code, payload, err, _s = run([])
        if payload["output_policy"] != "full-audit" or len(payload["findings"]) != 4:
            failures.append("yaml all:true is not full-audit with the complete set")
        if "source=.tcs.yaml" not in err or "all" not in err:
            failures.append(f"yaml all banner does not name the source: {err!r}")

        # 6. CLI --all overrides a yaml composable key and claims no yaml source.
        set_yaml("policy:\n  include_hygiene: true\n")
        _code, payload, err, _s = run(["--all"])
        if payload["output_policy"] != "full-audit" or len(payload["findings"]) != 4:
            failures.append("CLI --all did not override the yaml policy")
        if "source=.tcs.yaml" in err:
            failures.append("CLI --all must not credit .tcs.yaml")

        # 7. A yaml with no policy block leaves the default byte-identical (no source, 2 rows).
        set_yaml("exclude_paths: []\n")
        _code, payload, err, _s = run([])
        if payload["output_policy"] != "clean-default" or len(payload["findings"]) != 2:
            failures.append("a policy-free .tcs.yaml changed the default report")
        if "source=.tcs.yaml" in err:
            failures.append("a policy-free .tcs.yaml must not claim a policy source")

        # 8. Policy coexists with real exclusions: excluding h.py removes the hygiene row even though
        #    include_hygiene is set, proving load_config still parses exclude_paths alongside policy.
        set_yaml('exclude_paths: ["h.py"]\npolicy:\n  include_hygiene: true\n')
        _code, payload, _err, _s = run([])
        if any(f == "h.py" for f, _l, _c in keys_of(payload["findings"])):
            failures.append("exclude_paths stopped working once a policy block was present")
        if len(payload["findings"]) != 2:
            failures.append(f"exclusion+policy kept {len(payload['findings'])}, expected 2")

        # 9. Unknown keys and bad values fail loudly rather than silently misreporting coverage.
        for bad in ("policy:\n  bogus_key: true\n", "policy:\n  min_severity: ultra\n",
                    "policy:\n  include_hygiene: yes-please\n"):
            set_yaml(bad)
            code, _out, _err, _s = run_cli(base_argv(), tree)
            if code == 0:
                failures.append(f"malformed policy accepted silently: {bad!r}")

        # 10. No file at all is the byte-identical default.
        config.unlink()
        _code, payload, err, _s = run([])
        if payload["output_policy"] != "clean-default" or len(payload["findings"]) != 2:
            failures.append("removing .tcs.yaml did not restore the default report")
        if "source=.tcs.yaml" in err:
            failures.append("no .tcs.yaml must not claim a source")
    return failures, facts


def main():
    failures = []

    truth_failures, truth_n = check_truth_table()
    failures += truth_failures
    print(f"TIER 1 - keep/hold truth table over {truth_n} synthetic rows: "
          f"{len(truth_failures)} failure(s)")

    mode_failures, mode_n = check_mode_banner()
    failures += mode_failures
    print(f"TIER 2 - mode + ASCII banner over {mode_n} flag shapes: {len(mode_failures)} failure(s)")

    helper_failures = check_helpers()
    failures += helper_failures
    print(f"TIER 3 - severity floor + discovery helpers: {len(helper_failures)} failure(s)")

    unified_failures, unified = check_unified()
    failures += unified_failures
    print(f"TIER 4 - unified terminal/JSON/SARIF: full={unified.get('full')} "
          f"default={unified.get('default')} {len(unified_failures)} failure(s)")

    single_failures = check_single_file()
    failures += single_failures
    print(f"TIER 5 - single test_*.py collected, dir-pruned, --all restored: "
          f"{len(single_failures)} failure(s)")

    discovery_failures, discovery = check_discovery()
    failures += discovery_failures
    print(f"TIER 6 - discovery pruning: default={discovery.get('default')} "
          f"include-tests={discovery.get('include-tests')} "
          f"include-vendor={discovery.get('include-vendor')} all={discovery.get('all')} "
          f"{len(discovery_failures)} failure(s)")

    mutation_failures, caught = run_mutations()
    failures += mutation_failures
    print(f"TIER 7 - {caught}/{len(MUTATIONS)} mutations caught")

    engine_failures, diff_state = check_engine_untouched()
    failures += engine_failures
    print(f"TIER 8 - engine diff={diff_state}, {len(engine_failures)} failure(s)")

    composable_failures, composable = check_composable()
    failures += composable_failures
    print(f"TIER 9 - composable flags lift one dimension: in-memory 7 cases, "
          f"e2e default={composable.get('e2e_default')} hygiene={composable.get('e2e_hygiene')} "
          f"{len(composable_failures)} failure(s)")

    yaml_failures, yaml_facts = check_yaml_policy()
    failures += yaml_failures
    print(f"TIER 10 - persistent .tcs.yaml policy: hygiene={yaml_facts.get('yaml_hygiene')} "
          f"min_confidence={yaml_facts.get('yaml_min_confidence')} "
          f"{len(yaml_failures)} failure(s)")

    for item in failures:
        print(f"  !! {item}")

    elapsed = time.time() - START
    rss = peak_rss_mb()
    print(f"BUDGET - work={elapsed:.2f}s (budget {BUDGET_SECONDS}s) "
          f"peak_rss={rss:.1f}MB (budget {BUDGET_RSS_MB}MB)")
    if failures:
        print("VERDICT: FAIL - the clean default policy hid a keeper, leaked a held row, broke "
              "format agreement, pruned a production path, mis-handled a composable flag or "
              ".tcs.yaml policy, or touched the engine. Fix the cause.")
        return 1
    if elapsed > BUDGET_SECONDS or rss > BUDGET_RSS_MB:
        print("VERDICT: FAIL - budget blown, and a lock that is slow or heavy never runs.")
        return 1
    print(f"VERDICT: PASS - {truth_n}-row truth table exact (Fix 1 confidence gate), {mode_n} modes "
          f"announced in ASCII, terminal/JSON/SARIF agree (full={unified.get('full')} "
          f"default={unified.get('default')}), single test_*.py collected, discovery "
          f"{discovery.get('default')}/{discovery.get('include-tests')}/"
          f"{discovery.get('include-vendor')}/{discovery.get('all')}, composable flags lift one "
          f"dimension (e2e hygiene={composable.get('e2e_hygiene')}), .tcs.yaml policy persists + "
          f"CLI overrides, {caught}/{len(MUTATIONS)} mutations caught, engine diff={diff_state}, "
          f"peak RSS {rss:.1f}MB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())