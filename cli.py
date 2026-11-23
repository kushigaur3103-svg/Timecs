"""Standalone command-line interface for the TimeCodeSecurity AST scanner."""

import argparse
import ast
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import subprocess
import time
import traceback
from typing import Optional
import banner
from cross_file_engine import CrossFileTaintEngine
from ast_scanner import TaintTracker, PARSER_MODES, DEFAULT_PARSER_MODE
from ci_reporter import sanitize_symbol_display
from diff_scan import changed_line_intervals, resolve_repo_root
from html_auditor import audit_templates, is_template_path
from iac_auditor import audit_iac_files
from scanners import (
    audit_sca_files,
    audit_secret_files,
    audit_security_files,
    build_sbom,
    collect_components,
    is_container_path,
    is_kubernetes_manifest,
    is_manifest_path,
    is_secret_path,
    is_terraform_path,
    is_workflow_yaml_path,
    tag_reachability,
)
from rule_engine import get_rule
from suppression_resolver import resolve_line_suppressions
import tcs_config
from tcs_config import load_config
from remediation.patch_engine import RemediationEngine
from sarif_adapter import bound_sarif_document
from sarif_exporter import atomic_write_text

try:
    from js_scanner import (
        has_js_ts_files,
        js_ts_available,
        run_js_ts_scan_isolated,
        warn_js_ts_unavailable,
    )
    _JS_TS_SCANNER_AVAILABLE = True
except ImportError:
    _JS_TS_SCANNER_AVAILABLE = False

    def js_ts_available() -> bool:
        return False

    def run_js_ts_scan_isolated(target, base_dir=None, skipped_files=None):
        return []

    def has_js_ts_files(target_path) -> bool:
        return False

    def warn_js_ts_unavailable() -> None:
        print("[TimeCodeSecurity-JS] WARNING: js_scanner is not importable; JS/TS scanning is disabled.",
              file=sys.stderr)


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}

# Directories that hold sample, fixture and harness code rather than shipped product code. A
# directory scan prunes these before descending; `--include-tests` turns that off, and a path named
# on the command line is always walked in full. This is a discovery-scope choice, not a suppression:
# nothing is filtered out of the emission set, so every finding in a scanned file is still reported.
# The cost is stated plainly because it is real -- `benchmark/gates/workflow_controls_probe.py` names
# `examples/app.py` and `tests/fixture.py` among the trees a hardcoded secret is classically committed
# in, and `fixtures/` is where this repository keeps 27 of its own blessed detection cases, so a default
# directory scan no longer sees a CWE-798 sitting in any of them and needs `--include-tests` to find it.
# That is why the skip is always announced in the report, why the confidence-floor note and this one are
# printed even when nothing else is, and why the gates that prove per-rule or per-directory behaviour
# pass `--include-tests` (or name the directory on the command line) instead of losing their assertions.
# `debug/` joins the list for the same reason `examples/` and `samples/` are on it: a tree of preview
# and demo views -- Sentry's `src/sentry/web/frontend/debug/` renders sample mail and component
# payloads for local development -- whose findings describe developer tooling, not shipped surface.
# Name the directory or pass `--include-tests` and every row inside it is still reported, which is the
# pair `benchmark/gates/sentry_tier3_precision_probe.py` locks.
NON_PRODUCTION_DIRS = frozenset({"tests", "test", "__tests__", "testutils",
                                 "fixtures", "examples", "example", "samples", "debug"})
# What the current scan pruned, so the report can say so instead of looking like a clean tree.
_SCOPE_STATS = {"skipped_dirs": 0, "skipped_files": 0, "skipped_filenames": 0,
                "vendor_dirs": 0, "vendor_files": 0}

# Jinja interpolation tokens in a *path*, as opposed to its content: Salt formulae ship files like
# `templates/{{module_name}}.py`, and that name alone guarantees `ast.parse` raises SyntaxError.
TEMPLATE_INTERPOLATION_TOKENS = ("{{", "}}")

# One flush per file is blocking pipe/disk I/O: a 2,819-file run paid 2,819 of those to say "I am
# still here". Progress now logs every Nth file, and the in-flight name is kept in
# `_PARTIAL["current_file"]` so a kill still reports where the scan was stuck.
PROGRESS_FILE_EVERY = 250

# Every finding belongs to exactly one analysis scope: template, container and CI/IaC paths are
# routed to their auditors, everything else is Python. --scope selects which collectors run.
SCOPE_ORDER = ("python", "docker", "iac", "sca", "secrets", "html")
SCOPE_LABELS = {"python": "Python Code", "docker": "Container/Config",
                "iac": "CI/CD & IaC", "sca": "Dependencies (SCA)",
                "secrets": "Config & Env Secrets", "html": "HTML Templates"}

# Confidence is a display label, never a detection decision: `--min-confidence` hides rows
# from the report, the engine still emits every finding it emitted before.
CONFIDENCE_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
# Sinks whose finding is a heuristic over an in-process comparison rather than data arriving
# at a dangerous operation: CWE-208 reports `token == expected`, where both operands are
# already local values, so the shape alone cannot prove an attacker reaches it.
LOW_CONFIDENCE_SINK_TYPES = frozenset({"TIMING_ATTACK"})

# ── Clean default output policy ────────────────────────────────────────────────────────────────
# A discovery-and-report layer, never a detection decision: the engine still emits every finding it
# emitted before, and `--all` (or any single opt-in flag) restores the complete set across the terminal
# table, JSON and SARIF alike. In clean-default mode the report holds back four kinds of row -- hygiene
# /audit-tier CWEs, LOW severity, LOW/MEDIUM confidence, and dormant manifest-only SCA advisories --
# while keeping HIGH-confidence CRITICAL/HIGH findings and the exploitable-MEDIUM allowlist below.
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# Hygiene (CSRF / subresource integrity / cookie configuration) and the noisy MEDIUM audit tier: real
# but low-signal in a default report, held back until --include-hygiene / --all asks for them.
HYGIENE_AUDIT_CWES = frozenset({
    "CWE-352", "CWE-353", "CWE-829",
    "CWE-614", "CWE-1004", "CWE-1275",
    "CWE-770", "CWE-200", "CWE-328", "CWE-276", "CWE-330", "CWE-1188",
})
# Exploitable findings that survive every default floor: open redirect, XML entity expansion, disabled
# template autoescape, insecure cipher mode, and any REACHABLE dependency advisory.
EXPLOITABLE_MEDIUM_CWES = frozenset({"CWE-601", "CWE-776", "CWE-116", "CWE-327"})
SCA_CATEGORY = "SCA_VULNERABLE_DEPENDENCY"
UNREACHABLE_SCA = "UNREACHABLE_MANIFEST_ONLY"
CLEAN_DEFAULT_MIN_SEVERITY = "MEDIUM"
CLEAN_DEFAULT_MIN_CONFIDENCE = "HIGH"
# Extra non-production directories a default walk prunes. Kept separate from NON_PRODUCTION_DIRS so the
# engine's cross-file vocabulary mirror stays exact (zulip gate c1 pins cli == symbol_indexer); this is
# a CLI discovery choice only. scripts/, ci_cd/, packaging/ and setup.py are deliberately NOT here.
EXTRA_NON_PRODUCTION_DIRS = frozenset({"cookbook", "docs", "doc", "demos", "demo",
                                       "benchmarks", "tutorials", "migrations"})
# Third-party vendored / auto-generated trees, opt back in with --include-vendor.
VENDOR_DIRS = frozenset({"vendor", "_vendor", "third_party"})
# Non-production filenames skipped inside an otherwise-production tree, and the auto-generated protobuf
# suffix. A file named on the command line is never skipped -- only a directory walk applies these.
NON_PRODUCTION_FILENAMES = ("test_*.py", "*_test.py", "*_tests.py", "conftest.py",
                            "demo_*.py", "*_demo.py", "*_mock.py")
VENDOR_FILENAMES = ("*_pb2.py",)

# ── Persistent policy in the existing root `.tcs.yaml` ───────────────────────────────────────────
# Snyk-style: the same optional `.tcs.yaml` that carries `exclude_paths`/`rules` may also carry a
# `policy:` block naming the report options below. cli.py owns that block; tcs_config owns the
# exclusions. The strict loader is taught to accept (and ignore) `policy` so one file carries both
# without editing tcs_config -- every other unknown top-level key is still rejected loudly. Explicit
# CLI flags always win; with no `.tcs.yaml` (or no policy block) behaviour is byte-identical to before.
YAML_POLICY_BOOL_KEYS = ("all", "include_hygiene", "include_tests", "include_vendor",
                         "include_unreachable")
YAML_POLICY_SEVERITY_VALUES = ("low", "medium", "high", "critical")
YAML_POLICY_CONFIDENCE_VALUES = ("low", "medium", "high", "all")
YAML_POLICY_KEYS = frozenset(YAML_POLICY_BOOL_KEYS) | {"min_severity", "min_confidence"}
# argparse defaults: an attribute sitting at its default was NOT named on the command line, so a
# `.tcs.yaml` value may fill it. A non-default value is an explicit CLI flag and always overrides.
_POLICY_ARG_DEFAULTS = {"all": False, "include_hygiene": False, "include_tests": False,
                        "include_vendor": False, "include_unreachable": False, "audit_all": False,
                        "min_severity": None, "min_confidence": None}
# tcs_config._ALLOWED_TOP_LEVEL natively allows "policy" in tcs_config.py.


def _read_yaml_policy(directory=None):
    """The validated `policy:` block from the working directory's `.tcs.yaml`, or {} when absent.

    Reads the same file `load_config` reads. A malformed block raises ValueError -- a policy the user
    wrote but the scanner silently ignored would misreport coverage, the same harm as a missed finding.
    """
    base = Path(directory) if directory is not None else Path.cwd()
    path = base / tcs_config.CONFIG_FILENAME
    if not path.is_file():
        return {}
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(f"{tcs_config.CONFIG_FILENAME} present but PyYAML is not installed") from exc
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid {tcs_config.CONFIG_FILENAME}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"Invalid {tcs_config.CONFIG_FILENAME}: top level must be a mapping")
    block = data.get("policy")
    if block is None:
        return {}
    if not isinstance(block, dict):
        raise ValueError(f"Invalid {tcs_config.CONFIG_FILENAME}: policy must be a mapping")
    unknown = sorted(set(block) - YAML_POLICY_KEYS)
    if unknown:
        raise ValueError(f"Invalid {tcs_config.CONFIG_FILENAME}: unknown policy key(s) {unknown}")
    out = {}
    for key in YAML_POLICY_BOOL_KEYS:
        if key in block:
            if not isinstance(block[key], bool):
                raise ValueError(f"Invalid {tcs_config.CONFIG_FILENAME}: policy.{key} must be true/false")
            out[key] = block[key]
    if "min_severity" in block:
        value = str(block["min_severity"]).lower()
        if value not in YAML_POLICY_SEVERITY_VALUES:
            raise ValueError(f"Invalid {tcs_config.CONFIG_FILENAME}: policy.min_severity must be one of "
                             f"{list(YAML_POLICY_SEVERITY_VALUES)}")
        out["min_severity"] = value
    if "min_confidence" in block:
        value = str(block["min_confidence"]).lower()
        if value not in YAML_POLICY_CONFIDENCE_VALUES:
            raise ValueError(f"Invalid {tcs_config.CONFIG_FILENAME}: policy.min_confidence must be one of "
                             f"{list(YAML_POLICY_CONFIDENCE_VALUES)}")
        out["min_confidence"] = value
    return out


def _apply_yaml_policy(args):
    """Fill policy attributes the CLI did NOT name from `.tcs.yaml`, recording the active source keys.

    Precedence: an explicit CLI flag (a non-default value) always wins. `all: true` from the file
    expands like `--all` but still yields to any sub-flag the CLI named explicitly.
    """
    args._yaml_policy_keys = ()
    policy = _read_yaml_policy()
    if not policy:
        return
    explicit = {key for key, default in _POLICY_ARG_DEFAULTS.items()
                if getattr(args, key, default) != default}
    applied = []
    if policy.get("all") is True and "all" not in explicit:
        args.all = True
        applied.append("all")
        for attr, value in (("include_hygiene", True), ("include_tests", True),
                            ("include_vendor", True), ("include_unreachable", True),
                            ("min_severity", "low"), ("min_confidence", "low")):
            if attr not in explicit:
                setattr(args, attr, value)
        args._yaml_policy_keys = tuple(applied)
        return
    for key in YAML_POLICY_BOOL_KEYS + ("min_severity", "min_confidence"):
        if key in policy and key not in explicit and policy[key]:
            setattr(args, key, policy[key])
            applied.append(key)
    args._yaml_policy_keys = tuple(applied)


def _scope_of(path, aux_scopes=None):
    """Scope of one finding's file.

    ``aux_scopes`` is the discovery map for auxiliary documents. It is the authority for a
    Kubernetes workload manifest, which can sit at any path and is only recognisable from its
    content; every other family is decidable from the path alone.
    """
    key = str(path)
    if aux_scopes and key in aux_scopes:
        return aux_scopes[key]
    lowered = key.lower()
    if is_template_path(lowered):
        return "html"
    if is_container_path(lowered):
        return "docker"
    if is_workflow_yaml_path(lowered) or is_terraform_path(lowered):
        return "iac"
    if is_manifest_path(lowered):
        return "sca"
    if is_secret_path(lowered):
        return "secrets"
    return "python"


def _file_key(path, cwd):
    try:
        return path.resolve().relative_to(cwd).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _parse_exclude_patterns(raw):
    if not raw:
        return None
    return [p.strip() for p in raw.split(",") if p.strip()] or None


def _is_excluded(path, root, exclude_patterns):
    """True when `path` matches any exclude pattern.

    Patterns are matched three ways because users write all three: a bare directory
    name (`tests`), a filename glob (`test_*.py`) and a rooted relative glob
    (`contrib/*/tests/*`). Matching only the basename or only the full relative path
    silently keeps nested hits, which is how `--exclude tests` used to survive
    `django/contrib/auth/tests/models.py`.

    Relative paths are normalised to POSIX before fnmatch, whose separator handling
    is not portable: on Windows `str(Path.relative_to())` yields backslashes, so a
    pattern containing `/` could never match.
    """
    if not exclude_patterns:
        return False
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    rel_posix = rel.as_posix()
    name = path.name
    parts = rel.parts
    for pattern in exclude_patterns:
        if fnmatch.fnmatchcase(rel_posix, pattern):
            return True
        if fnmatch.fnmatchcase(name, pattern):
            return True
        if any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
    return False


def _is_template_interpolated(path, root):
    """True when a path *component* carries a Jinja interpolation token.

    Salt formulae ship files named `templates/{{module_name}}.py`: the name is a render-time
    placeholder, so the bytes on disk are pre-render scaffolding and `ast.parse` on them usually
    raises SyntaxError. Only components of the path are inspected, never file content, so a normal
    module that merely uses `{{` inside a string is never mistaken for one.
    """
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(token in part for part in parts for token in TEMPLATE_INTERPOLATION_TOKENS)


def _parses_as_python(source):
    """True when `ast.parse` accepts the text -- the gate that keeps a template file scannable.

    A Jinja-named path alone is not proof of junk: measured on this repo, `templates/{{x}}.py`
    holding `import os; os.system(p)` parses fine and reports CWE-78. Dropping on the path alone
    would have turned that real finding into a false negative, so the skip requires the content to
    be unparseable as well. One extra parse per interpolated-path file, nothing else pays for it.
    """
    try:
        ast.parse(source)
        return True
    except (SyntaxError, ValueError):
        return False


def _progress(message):
    """Emit one progress line on stderr so a stalled scan names the file it stuck on.

    stderr keeps stdout parsable (`--format json` consumers read stdout only) and
    flush=True means the line lands even if the process is killed mid-file.
    Callers throttle *how often* this runs (PROGRESS_FILE_EVERY); the in-flight file name
    lives in `_PARTIAL["current_file"]` so the throttled gap stays diagnosable.
    """
    print(f"[progress] {message}", file=sys.stderr, flush=True)


def _ux_enabled(args):
    """True only for a human watching a terminal, never for a data pipe or a log.

    `--format json` is an absolute veto: that stdout is parsed by every benchmark and CI job, so
    the styled UX stays off even when TIMECS_FORCE_BANNER asks for it. Otherwise a real TTY turns
    it on, and the env var exists so a test can drive the same code path over a pipe.
    """
    if getattr(args, "format", "table") == "json":
        return False
    if os.environ.get("TIMECS_FORCE_BANNER") == "1":
        return True
    try:
        return bool(sys.stderr.isatty())
    except (AttributeError, ValueError):
        return False


class _StageClock:
    """Phase-1 outer instrumentation: disjoint end-to-end stage clocks, stderr only.

    Each `mark()` closes the stage that was open since the previous mark, so the stage
    seconds are disjoint by construction and sum to TOTAL (modulo the final report call).
    Engine-internal lines (`[PROFILE] Phase n ...`, `[PROFILE] CrossEngine ...`, collector
    profiles) are NESTED inside these stages and must never be added to them. Worker-pool
    time is included in the stage that owns the pool (Parse), not per core.

    Nothing here feeds a finding, a suppression, the JSON schema, or the exit code;
    `duration_ms` keeps its original semantics (started after file collection). RSS sampling
    uses the already-optional psutil: without it the report says RSS=unavailable.
    """

    def __init__(self, label):
        try:
            import psutil
            self._rss_fn = psutil.Process().memory_info
        except Exception:
            self._rss_fn = None
        self.label = label
        self.t_start = time.perf_counter()
        self.t_mark = self.t_start
        self.rows = []
        self.peak_rss_mb = 0.0

    def mark(self, stage):
        now = time.perf_counter()
        rss_mb = 0.0
        if self._rss_fn is not None:
            try:
                rss_mb = self._rss_fn().rss / (1024 ** 2)
            except Exception:
                rss_mb = 0.0
        self.peak_rss_mb = max(self.peak_rss_mb, rss_mb)
        self.rows.append((stage, now - self.t_mark, rss_mb))
        self.t_mark = now

    def report(self):
        total = time.perf_counter() - self.t_start
        parts = " ".join(f"{name}={secs:.2f}s" for name, secs, _ in self.rows)
        rss_note = (f" peakRSS_parent={self.peak_rss_mb:.0f}MB"
                    if self._rss_fn is not None else " RSS=unavailable(psutil missing)")
        print(f"TimeCodeSecurity [PROFILE] Outer({self.label}): {parts} TOTAL={total:.2f}s{rss_note}",
              file=sys.stderr, flush=True)


def _iter_tree_files(root, prune_dirs=None, count_pruned=False):
    """Yield the real files under `root`, never following a symlink.

    Traversal guard (CWE-59): `Path.rglob` semantics are version dependent — Python
    3.13+ follows symlinked directories by default, so one link back into an ancestor
    makes the crawl loop. os.walk with followlinks=False plus explicit symlink pruning
    keeps discovery inside the real tree. Ignored directories are pruned before
    descending, so `node_modules` is never walked just to be filtered out again.

    `prune_dirs` replaces the prune set for one walk; `count_pruned` only ever comes from a requested
    scope narrowing, and records how many directories and Python files it held back so the report can
    name them. Three things keep a file in scope whatever the set says: a file named directly (no
    directory walk happens at all), a directory named as the scan root -- which is why
    `cli.py scan tests/` still walks it -- and `--include-tests`, which passes no set at all.
    """
    skip = IGNORED_DIRS if prune_dirs is None else prune_dirs
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for name in sorted(dirnames):
            if name in skip:
                if count_pruned and name not in IGNORED_DIRS:
                    held = sum(
                        1 for _root, _dirs, _files in os.walk(os.path.join(dirpath, name))
                        for _name in _files if _name.lower().endswith(".py"))
                    if name in VENDOR_DIRS:
                        _SCOPE_STATS["vendor_dirs"] += 1
                        _SCOPE_STATS["vendor_files"] += held
                    else:
                        _SCOPE_STATS["skipped_dirs"] += 1
                        _SCOPE_STATS["skipped_files"] += held
                continue
            if os.path.islink(os.path.join(dirpath, name)):
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if os.path.islink(path):
                continue
            yield path


def _collect_files(scan_path, exclude_patterns=None, config_excludes=None,
                   skip_non_production=False, skip_vendor=False):
    """Collect Python files from scan path, optionally excluding by glob patterns.

    Args:
        scan_path: Path object (file or directory)
        exclude_patterns: List of glob patterns to exclude (e.g., ['tests', 'test_*'])
        config_excludes: Optional callable taking a CWD-relative POSIX path and returning
            True when `.tcs.yaml` excludes it. A file named on the command line is never
            dropped, matching how a tree walk treats `--exclude`.
        skip_non_production: Prune `NON_PRODUCTION_DIRS` from the tree walk only. A path named
            on the command line is scanned in full either way, same contract as `--exclude`.

    Phase-1 instrumentation only: the enumerate/read split names the cold-tree serial
    read cost that the pre-existing `duration_ms` anchor cannot see (it starts later).
    """
    _t_enum0 = time.perf_counter()
    cwd = Path.cwd().resolve()
    if not scan_path.exists():
        raise FileNotFoundError(f"Path does not exist: {scan_path}")
    is_tree = scan_path.is_dir()
    prune = _discovery_prune_set(skip_non_production, skip_vendor)
    if scan_path.is_file():
        if scan_path.suffix.lower() != ".py":
            raise ValueError(f"Expected a Python file: {scan_path}")
        paths = [scan_path]
    elif is_tree:
        paths = sorted(
            path for path in _iter_tree_files(scan_path, prune,
                                              skip_non_production or skip_vendor)
            if path.suffix.lower() == ".py"
            and not any(part in IGNORED_DIRS for part in path.parts)
            and not _is_excluded(path, scan_path, exclude_patterns)
            and not (config_excludes and config_excludes(_file_key(path, cwd)))
        )
        paths = _skip_nonprod_filenames(paths, skip_non_production, skip_vendor)
    else:
        raise ValueError(f"Path is not a regular file or directory: {scan_path}")

    if not paths:
        scope_note = non_production_scope_note()
        if scope_note:
            # The tree holds nothing but pruned non-production code: say so rather than letting the
            # caller read "No Python files found" as an empty directory.
            print(scope_note, file=sys.stderr)
        raise ValueError(f"No Python files found: {scan_path}")

    _t_enum = time.perf_counter()
    files = {}
    skipped = 0
    templated = 0
    total_chars = 0
    total = len(paths)
    _progress(f"discovered {total} python file(s) under {scan_path}")
    for index, path in enumerate(paths, 1):
        _PARTIAL["current_file"] = str(path)
        if index == 1 or index == total or index % PROGRESS_FILE_EVERY == 0:
            _progress(f"reading python ({index}/{total}) {path}")
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            # A single unreadable file must not abort the scan of the whole tree.
            skipped += 1
            print(f"Warning: skipping unreadable file {path}: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            continue
        # Only a tree walk drops files; a file named on the command line is always analysed.
        if is_tree and _is_template_interpolated(path, scan_path) and not _parses_as_python(source):
            templated += 1
            continue
        total_chars += len(source)
        files[_file_key(path, cwd)] = source
    _t_reads = time.perf_counter()
    if templated:
        _progress(f"skipped {templated} unparseable Jinja-interpolated file(s) under {scan_path}")
    if skipped:
        print(f"Warning: skipped {skipped} of {len(paths)} Python files; "
              f"{len(files)} scanned.", file=sys.stderr)
    print(f"TimeCodeSecurity [PROFILE] CollectFiles: enumerate={_t_enum - _t_enum0:.2f}s "
          f"(paths={total}), serial_read={_t_reads - _t_enum:.2f}s "
          f"(kept={len(files)}, chars={total_chars}, unreadable={skipped}, jinja_skipped={templated})",
          file=sys.stderr)
    _PARTIAL["current_file"] = None
    return files


AUX_YAML_SUFFIXES = (".yml", ".yaml")


def _collect_auxiliary_files(scan_path, exclude_patterns=None, config_excludes=None,
                             skip_non_production=False, skip_vendor=False):
    """Collect non-Python artefacts in one walk.

    Returns ``(templates, security documents, manifests, secret documents, scope map)``.
    Keys match _collect_files so findings share a single path namespace, and
    `--exclude` applies here too: a template under an excluded directory is just as
    out of scope as a .py file under it. `config_excludes` carries the same contract
    as in _collect_files, as does `skip_non_production` -- a template inside a skipped
    `examples/` tree is out of scope for exactly the same reason.

    The scope map carries each auxiliary document's key to its scope ("docker" for images and
    compose, "iac" for workflows, Kubernetes and Terraform, "sca" for dependency manifests and
    lockfiles, "secrets" for config and env documents). It exists because a Kubernetes manifest
    is recognised from content, not from its path, so the bucketing decision has to survive the
    walk for `_scope_of` to report it honestly.
    """
    cwd = Path.cwd().resolve()
    if not scan_path.exists():
        raise FileNotFoundError(f"Path does not exist: {scan_path}")

    prune = _discovery_prune_set(skip_non_production, skip_vendor)
    if scan_path.is_file():
        paths = [scan_path]
    elif scan_path.is_dir():
        # count_pruned stays off here: the note reports python files held back, and the Python
        # collection below walks the same tree -- counting twice would double the figure.
        paths = sorted(
            path for path in _iter_tree_files(scan_path, prune, False)
            if not any(part in IGNORED_DIRS for part in path.parts)
            and not _is_excluded(path, scan_path, exclude_patterns)
            and not (config_excludes and config_excludes(_file_key(path, cwd)))
        )
    else:
        return {}, {}, {}, {}, {}

    templates = {}
    iac = {}
    manifests = {}
    secrets = {}
    aux_scopes = {}
    buckets = {}
    skipped = 0
    for path in paths:
        relative = str(path).replace("\\", "/")
        if is_template_path(relative):
            buckets[path] = (templates, "html")
        elif is_container_path(relative):
            buckets[path] = (iac, "docker")
        elif is_workflow_yaml_path(relative) or is_terraform_path(relative):
            buckets[path] = (iac, "iac")
        elif is_manifest_path(relative):
            buckets[path] = (manifests, "sca")
        elif relative.lower().endswith(AUX_YAML_SUFFIXES):
            # Scope undecided until the content is read: a Kubernetes workload manifest belongs
            # to IaC, and only a YAML document that is not one falls through to the secret reader.
            buckets[path] = (iac, None)
        elif is_secret_path(relative):
            buckets[path] = (secrets, "secrets")

    total = len(buckets)
    _progress(f"discovered {total} template/IaC file(s) under {scan_path}")
    for index, (path, (bucket, scope)) in enumerate(buckets.items(), 1):
        _PARTIAL["current_file"] = str(path)
        if index == 1 or index == total or index % PROGRESS_FILE_EVERY == 0:
            _progress(f"reading auxiliary ({index}/{total}) {path}")
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # Same contract as _collect_files above: one unreadable template or IaC file is a
            # local fault, so it is reported and skipped. Re-raising here used to abort the whole
            # tree scan and exit 2, losing every Python finding in the repository.
            skipped += 1
            print(f"Warning: skipping unreadable auxiliary file {path}: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        if scope is None:
            if is_kubernetes_manifest(source):
                scope = "iac"
            elif is_secret_path(str(path).replace("\\", "/")):
                bucket, scope = secrets, "secrets"
            else:
                continue
        key = _file_key(path, cwd)
        bucket[key] = source
        if bucket is not templates:
            aux_scopes[key] = scope
    if skipped:
        print(f"Warning: skipped {skipped} of {total} auxiliary files; "
              f"{len(templates) + len(iac) + len(manifests) + len(secrets)} scanned.",
              file=sys.stderr)
    _PARTIAL["current_file"] = None
    return templates, iac, manifests, secrets, aux_scopes


def _imported_roots(tracker):
    """Top-level import roots across the Python files the engine already parsed.

    Reuses the ``tracker.modules`` trees instead of re-reading or re-parsing anything, so the
    reachability proof never adds a second AST pass to a scan. A tree that is not a stdlib AST
    (the opt-in tree-sitter reader) is parsed from the engine's own source snapshot. The first
    importer wins, which makes the evidence deterministic regardless of module iteration order.
    """
    roots = {}
    if tracker is None:
        return roots
    paths = getattr(tracker, "file_paths", {}) or {}
    sources = getattr(tracker, "files", {}) or {}
    for module, tree in (getattr(tracker, "modules", {}) or {}).items():
        if not isinstance(tree, ast.AST):
            source = sources.get(paths.get(module))
            if not source:
                continue
            try:
                tree = ast.parse(source)
            except (SyntaxError, ValueError):
                continue
        path = str(paths.get(module, module))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # A relative import names this project's own module, not a distribution.
                if node.level or not node.module:
                    continue
                names = [node.module]
            else:
                continue
            for name in names:
                root = name.split(".", 1)[0]
                if root and root not in roots:
                    roots[root] = (path, node.lineno)
    return roots


def _merge_findings(*finding_groups):
    """Merge auditor findings with AST findings in a deterministic order."""
    seen = set()
    unique = []
    for group in finding_groups:
        for item in group:
            identity = (item["file"], item["line"], item["cwe"], item.get("category"))
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(item)
    return sorted(unique, key=lambda entry: (entry["file"], entry["line"], entry["cwe"]))


# Several CWEs describe one *attribute* of the same defect: a single weak-digest call can
# be simultaneously a broken algorithm (327/328) and a storage-strength failure (759/916),
# and one set_cookie() can lack Secure (614), HttpOnly (1004) and SameSite (1275). Reporting
# every attribute as its own alert multiplies the count without adding an actionable site.
# An unbounded `f.read()` is the same case from the other direction: the rule engine calls it
# CWE-400 and the structural batch calls the identical call node CWE-770, so one sink is
# counted as two findings.
# The families below collapse to one finding per (file, line); the surviving CWEs are kept
# in `consolidated_from` so nothing is lost. This is presentation-only: the engine still emits
# every CWE, which is what the benchmark scores per rule.
FAMILY_PRIORITY = {
    "CRYPTO_HASH": ("CWE-327", "CWE-916", "CWE-759", "CWE-328"),
    "INSECURE_COOKIE": ("CWE-614", "CWE-1004", "CWE-1275"),
    "RESOURCE_EXHAUSTION": ("CWE-770", "CWE-400"),
}
FAMILY_OF_CWE = {
    cwe: family for family, members in FAMILY_PRIORITY.items() for cwe in members
}
COOKIE_FLAG_BY_CWE = {"CWE-614": "Secure", "CWE-1004": "HttpOnly", "CWE-1275": "SameSite"}
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _family_message(family, primary, members_by_cwe):
    """Alert text naming what the collapsed CWEs actually proved."""
    if family == "INSECURE_COOKIE":
        flags = [COOKIE_FLAG_BY_CWE[cwe] for cwe in FAMILY_PRIORITY[family] if cwe in members_by_cwe]
        return f"{primary}: Insecure Cookie Configuration (Missing {', '.join(flags)})"
    source = members_by_cwe[primary][0]["message"]
    operation = source.split(":", 1)[1].strip() if ":" in source else source
    secondaries = [cwe for cwe in FAMILY_PRIORITY[family] if cwe in members_by_cwe and cwe != primary]
    suffix = f" (consolidated: {', '.join(secondaries)})" if secondaries else ""
    return f"{primary}: {operation}{suffix}"


def _consolidate_family(family, group):
    members_by_cwe = {}
    for finding in group:
        members_by_cwe.setdefault(finding["cwe"], []).append(finding)
    priority = FAMILY_PRIORITY[family]
    primary = next(cwe for cwe in priority if cwe in members_by_cwe)
    representative = members_by_cwe[primary][0]
    consolidated = []
    for cwe in priority:
        consolidated.extend(member for member in members_by_cwe.get(cwe, []) if member is not representative)
    return {
        **representative,
        "cwe": primary,
        "line": min(member["line"] for member in group),
        "severity": max(
            (member["severity"] for member in group),
            key=lambda value: SEVERITY_RANK.get(value, 0),
        ),
        "confidence": max(
            (member.get("confidence", "MEDIUM") for member in group),
            key=lambda value: CONFIDENCE_ORDER.get(value, 0),
        ),
        "message": _family_message(family, primary, members_by_cwe),
        "consolidated_from": [f"{member['cwe']}@{member['line']}" for member in consolidated],
    }


def consolidate_findings(findings):
    """Collapse same-site CWE families into one finding, preserving scan order."""
    buckets = {}
    for finding in findings:
        family = FAMILY_OF_CWE.get(finding["cwe"])
        if family:
            buckets.setdefault((family, finding["file"], finding["line"]), []).append(finding)

    emitted = set()
    consolidated = []
    for finding in findings:
        family = FAMILY_OF_CWE.get(finding["cwe"])
        if not family:
            consolidated.append(finding)
            continue
        key = (family, finding["file"], finding["line"])
        if key in emitted:
            continue
        emitted.add(key)
        consolidated.append(_consolidate_family(family, buckets[key]))
    return sorted(consolidated, key=lambda item: (item["file"], item["line"], item["cwe"]))


def _findings_for(tracker, edges):
    sinks = {sink.id: sink for sink in tracker.sinks}
    by_identity = {}
    for edge in edges:
        sink = sinks.get(edge.target_id)
        if sink is None:
            continue
        cwe = sink.metadata.get("cwe")
        if not cwe and edge.proof_graph is not None:
            cwe = edge.proof_graph.cwe
        cwe = cwe or "UNKNOWN_CWE"
        rule = get_rule(cwe)
        confidence_label = "CONFIRMED" if edge.kind == "CONFIRMED_DATA_FLOW" else "POTENTIAL"
        severity = rule.get_severity(confidence_label).upper() if rule else "HIGH"
        # HIGH follows the engine's own CONFIRMED label. Phase collectors record a sink with a
        # synthetic source id (`OS_COMMAND_EXECUTION`, `WEAK_HASH_ALGORITHM`) and still say
        # CONFIRMED, so this over-claims rather than under-claims: a `--min-confidence high`
        # run may show a pattern row, but it can never hide a traced flow behind a filter.
        sink_type = sink.metadata.get("sink_type") or sink.metadata.get("category")
        if sink_type in LOW_CONFIDENCE_SINK_TYPES:
            confidence = "LOW"
        elif edge.kind == "CONFIRMED_DATA_FLOW":
            confidence = "HIGH"
        else:
            confidence = "MEDIUM"
        location = sink.location
        file_path = location.file.replace("\\", "/")
        finding = {
            "file": file_path,
            "line": location.line_start,
            "cwe": cwe,
            "severity": severity,
            "confidence": confidence,
            "category": sink.metadata.get("category") or (rule.category if rule else "Security"),
            "message": sink.metadata.get("message") or \
                f"{cwe}: {sink.metadata.get('operation') or sanitize_symbol_display(sink.symbol)}",
        }
        # Triage-only shape label (CWE-611 today). It rides beside the message, never inside it,
        # so the canonical keys the baselines compare cannot move because of it.
        xml_input = sink.metadata.get("xml_input")
        if xml_input:
            finding["xml_input"] = xml_input
        identity = (finding["file"], finding["line"], finding["cwe"])
        existing = by_identity.get(identity)
        if existing is None:
            by_identity[identity] = finding
        elif CONFIDENCE_ORDER[confidence] > CONFIDENCE_ORDER[existing["confidence"]]:
            # One site can be reached by several edges; the loudest label wins so a
            # confidence filter can never hide a confirmed flow behind a weaker edge.
            existing["confidence"] = confidence
    return sorted(by_identity.values(),
                  key=lambda item: (item["file"], item["line"], item["cwe"]))


def _parse_line_ranges(spec):
    """Parse a --lines value like '4-5' or '4-5,10' into inclusive (start, end) ranges.

    Returns None when the spec is empty/absent, meaning a full-file scan.
    Raises ValueError on malformed input so the CLI can report it cleanly.
    """
    if not spec:
        return None
    ranges = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        bounds = part.split("-", 1)
        try:
            start = int(bounds[0].strip())
            end = int(bounds[1].strip()) if len(bounds) > 1 else start
        except ValueError as exc:
            raise ValueError(f"Invalid --lines range {part!r}; expected START[-END]") from exc
        if start < 1 or end < start:
            raise ValueError(f"Invalid --lines range {part!r}; lines must be positive and ordered")
        ranges.append((start, end))
    return ranges or None


def _in_line_ranges(line, ranges):
    return ranges is None or any(start <= line <= end for start, end in ranges)


def _scope_findings_to_lines(findings, ranges):
    """Keep findings whose sink line intersects the requested ranges.

    Findings without a usable line number are kept: dropping them would turn an
    incremental scan into a false-negative source.
    """
    if ranges is None:
        return findings
    scoped = []
    for finding in findings:
        line = finding.get("line")
        if not isinstance(line, int):
            scoped.append(finding)
            continue
        if _in_line_ranges(line, ranges):
            scoped.append(finding)
    return scoped


def _apply_inline_suppressions(findings, sources):
    """Drop findings named by a `# tcs: ignore[CWE-XXX]` comment on the finding's own line.

    `sources` maps every scanned path to its text (Python, templates and IaC alike).
    A finding whose file is absent from that map is kept: an unreadable source can
    never suppress anything.
    """
    if not findings or not sources:
        return findings
    resolve_line_suppressions(findings, sources)
    return [finding for finding in findings if not finding.get("suppressed")]


def _scope_findings_to_diff(findings, intervals, repo_root):
    """Keep findings reported on added/modified lines of the working tree versus a ref.

    `intervals` is keyed by repo-relative paths; findings carry CWD-relative keys, so both
    sides are mapped through `_file_key`. A finding without a usable line number in a
    changed file is kept, mirroring `_scope_findings_to_lines`.
    """
    cwd = Path.cwd().resolve()
    changed = {}
    for rel_path, spans in intervals.items():
        try:
            changed[_file_key((repo_root / rel_path).resolve(), cwd)] = spans
        except OSError:
            continue
    kept = []
    for finding in findings:
        spans = changed.get(finding.get("file"))
        if spans is None:
            continue
        line = finding.get("line")
        if not isinstance(line, int) or any(start <= line <= end for start, end in spans):
            kept.append(finding)
    return kept


def _filter_by_confidence(findings, minimum):
    """Hide findings below `minimum` from the report; detection itself is untouched."""
    if not minimum:
        return findings
    floor = CONFIDENCE_ORDER[minimum.upper()]
    return [
        finding for finding in findings
        if CONFIDENCE_ORDER.get(str(finding.get("confidence") or "MEDIUM").upper(), 2) >= floor
    ]


# The floor a plain `cli.py scan` table starts at when nobody asked for one. It is a reading order for
# a person, not a detection decision, so it is applied to the table only and always announced.
TABLE_DEFAULT_CONFIDENCE = "high"


def _split_by_table_default(findings):
    """Return (rows a default table shows, rows it hides) at `TABLE_DEFAULT_CONFIDENCE`."""
    floor = CONFIDENCE_ORDER[TABLE_DEFAULT_CONFIDENCE.upper()]
    visible, hidden = [], []
    for finding in findings:
        label = str(finding.get("confidence") or "MEDIUM").upper()
        (visible if CONFIDENCE_ORDER.get(label, 2) >= floor else hidden).append(finding)
    return visible, hidden


def _is_nonprod_filename(name):
    return any(fnmatch.fnmatch(name, pattern) for pattern in NON_PRODUCTION_FILENAMES)


def _is_vendor_filename(name):
    return any(fnmatch.fnmatch(name, pattern) for pattern in VENDOR_FILENAMES)


def _discovery_prune_set(skip_non_production, skip_vendor):
    """The directory prune set for one walk: ignored trees, plus the opt-out scopes asked for."""
    if not (skip_non_production or skip_vendor):
        return None
    prune = set(IGNORED_DIRS)
    if skip_non_production:
        prune |= NON_PRODUCTION_DIRS | EXTRA_NON_PRODUCTION_DIRS
    if skip_vendor:
        prune |= VENDOR_DIRS
    return prune


def _skip_nonprod_filenames(paths, skip_non_production, skip_vendor):
    """Drop test/demo and generated-protobuf filenames from a walk, counting what was held back."""
    kept = []
    for path in paths:
        if skip_non_production and _is_nonprod_filename(path.name):
            _SCOPE_STATS["skipped_filenames"] += 1
        elif skip_vendor and _is_vendor_filename(path.name):
            _SCOPE_STATS["vendor_files"] += 1
        else:
            kept.append(path)
    return kept


def _filter_by_severity(findings, minimum):
    """Hide findings below `minimum` severity from the report; detection itself is untouched."""
    if not minimum:
        return findings
    floor = SEVERITY_ORDER[minimum.upper()]
    return [finding for finding in findings
            if SEVERITY_ORDER.get(str(finding.get("severity", "")).upper(), 0) >= floor]


def _is_sca_finding(finding):
    return finding.get("category") == SCA_CATEGORY or "reachability" in finding


def _is_unreachable_sca(finding):
    return _is_sca_finding(finding) and finding.get("reachability") == UNREACHABLE_SCA


def _is_reachable_sca(finding):
    return _is_sca_finding(finding) and finding.get("reachability") == "REACHABLE"


def _clean_default_keep(finding, hold_hygiene=True, hold_unreachable=True,
                        min_severity=CLEAN_DEFAULT_MIN_SEVERITY,
                        min_confidence=CLEAN_DEFAULT_MIN_CONFIDENCE):
    """True when a finding survives the clean-default report floor. Detection is never consulted.

    The four dimensions are parameterised so one composable opt-in flag lifts only its own block
    while the rest stay held. The exploitable-MEDIUM allowlist and reachable SCA must still clear the
    confidence floor: a structural (LOW/MEDIUM confidence) open redirect, cipher-mode row or reachable
    advisory is not a confirmed exploit, so it is held back exactly like any other unconfirmed row.
    """
    cwe = str(finding.get("cwe", ""))
    severity = str(finding.get("severity", "")).upper()
    confidence = str(finding.get("confidence") or "MEDIUM").upper()
    sev_floor = SEVERITY_ORDER[str(min_severity).upper()]
    conf_floor = CONFIDENCE_ORDER[str(min_confidence).upper()]
    conf_ok = CONFIDENCE_ORDER.get(confidence, 2) >= conf_floor
    if hold_unreachable and _is_unreachable_sca(finding):
        return False
    if conf_ok and sev_floor <= SEVERITY_ORDER["HIGH"] and (
            cwe in EXPLOITABLE_MEDIUM_CWES or _is_reachable_sca(finding)):
        return True
    if hold_hygiene and cwe in HYGIENE_AUDIT_CWES:
        return False
    if SEVERITY_ORDER.get(severity, 0) < sev_floor:
        return False
    if not conf_ok:
        return False
    return True


def _apply_clean_default(findings, args=None):
    """Split the emission set into (kept, held-back) under the clean-default report policy.

    Composable opt-in flags lift only their own dimension: --include-hygiene shows hygiene rows,
    --include-unreachable shows dormant SCA, --min-severity moves the severity floor. The HIGH
    confidence floor stays put unless a full-lift flag (--min-confidence/--all/...) switched mode.
    """
    hold_hygiene = not bool(getattr(args, "include_hygiene", False))
    hold_unreachable = not bool(getattr(args, "include_unreachable", False))
    min_severity = getattr(args, "min_severity", None) or CLEAN_DEFAULT_MIN_SEVERITY
    kept, held = [], []
    for finding in findings:
        (kept if _clean_default_keep(finding, hold_hygiene=hold_hygiene,
                                     hold_unreachable=hold_unreachable,
                                     min_severity=min_severity,
                                     min_confidence=CLEAN_DEFAULT_MIN_CONFIDENCE) else held).append(finding)
    return kept, held


def _output_policy_mode(args):
    """clean-default, custom (a full-lift flag), or full-audit (--all).

    Only the full-lift flags -- --include-tests, --audit-all, --min-confidence -- bypass the
    clean-default floor entirely, which is what keeps scan_child / aa_parity / big8 /
    confidence_label / sca_reachability byte-identical. The composable flags -- --include-hygiene,
    --include-unreachable, --include-vendor, --min-severity -- keep clean-default ACTIVE and lift
    only their own dimension, so they remain in clean-default mode.
    """
    if getattr(args, "all", False):
        return "full-audit"
    if any((getattr(args, "include_tests", False),
            getattr(args, "audit_all", False),
            getattr(args, "min_confidence", None) is not None)):
        return "custom"
    return "clean-default"


def _policy_banner(args):
    """The one-line `[INF] policy -> ...` announcement printed at scan start (ASCII only).

    Names exactly which floors and blocks are holding rows back and which are showing them, so a
    composable flag or a `.tcs.yaml` policy never silently widens or narrows the report. When the
    active options came from `.tcs.yaml`, the source is named so the reader knows why.
    """
    mode = _output_policy_mode(args)
    source = getattr(args, "_yaml_policy_keys", ()) or ()
    suffix = (" (source=.tcs.yaml: %s)" % ", ".join(source)) if source else ""
    if mode == "full-audit":
        detail = ("full-audit (--all): every finding -- hygiene, dormant SCA, all severities "
                  "and confidences shown")
    elif mode == "custom":
        parts = []
        if getattr(args, "min_confidence", None):
            parts.append("min-confidence=%s" % args.min_confidence)
        if getattr(args, "min_severity", None):
            parts.append("min-severity=%s" % args.min_severity)
        for flag, label in (("include_tests", "include-tests"), ("audit_all", "audit-all")):
            if getattr(args, flag, False):
                parts.append(label)
        detail = ("custom (%s): clean-default floors lifted, only the named floors apply"
                  % ", ".join(parts))
    else:
        hold_hygiene = not bool(getattr(args, "include_hygiene", False))
        hold_unreachable = not bool(getattr(args, "include_unreachable", False))
        sev = (getattr(args, "min_severity", None) or CLEAN_DEFAULT_MIN_SEVERITY).lower()
        blocks, shown = [], []
        (blocks if hold_hygiene else shown).append("hygiene")
        (blocks if hold_unreachable else shown).append("dormant-SCA")
        detail = ("clean-default: floors min-severity=%s/min-confidence=high; holding back %s"
                  % (sev, "+".join(blocks) if blocks else "no extra blocks"))
        if shown:
            detail += "; showing %s" % "+".join(shown)
        detail += ("; keeping HIGH-confidence CRITICAL/HIGH + exploitable MEDIUM"
                   " (pass --all for the full audit)")
        if getattr(args, "include_vendor", False):
            detail += "; include-vendor"
    return "policy -> %s%s" % (detail, suffix)


def clean_default_note(held) -> str:
    """One line naming what the clean-default report policy held back, so a short report is honest."""
    if not held:
        return ""
    noun = "finding" if len(held) == 1 else "findings"
    return (f"Note: Held back {len(held)} hygiene/low-severity/low-confidence/dormant-SCA {noun} "
            f"by the clean default policy; pass --all to show all.")


def vendor_scope_note() -> str:
    """Name the vendored/generated trees a directory walk held back, and the way back in."""
    dirs = _SCOPE_STATS["vendor_dirs"]
    files = _SCOPE_STATS["vendor_files"]
    if not dirs and not files:
        return ""
    return (f"Note: Held back {files} python file(s) in {dirs} vendored/generated "
            f"director{'y' if dirs == 1 else 'ies'} (vendor/, _vendor/, third_party/, *_pb2.py); "
            f"pass --include-vendor to scan them.")


def non_production_scope_note() -> str:
    """Name the scope a directory walk narrowed by default.

    Held-back files are invisible to the report, which is the one way a scope choice can be mistaken
    for a clean tree -- and a hardcoded secret in `tests/fixture.py` or `examples/app.py` is exactly
    the finding that lives there. So the count is always stated when the walk pruned anything, and the
    way back is named. A path given on the command line is always walked in full, which is why this
    note never appears for `scan tests/`.
    """
    dirs = _SCOPE_STATS["skipped_dirs"]
    names = _SCOPE_STATS["skipped_filenames"]
    if not dirs and not names:
        return ""
    files = _SCOPE_STATS["skipped_files"] + names
    return (f"Note: Held back {files} python file(s) in {dirs} non-production "
            f"director{'y' if dirs == 1 else 'ies'} (tests/, testutils/, fixtures/, "
            f"examples/, samples/, debug/, docs/, demos/, benchmarks/, migrations/, "
            f"cookbook/, tutorials/) and test_*/demo_*/conftest filenames; "
            f"pass --include-tests to scan them.")


def table_default_note(hidden) -> str:
    """One line naming what the default table floor hid, so a short table is never read as a clean scan.

    A CRITICAL-severity row can sit under the floor when its flow was matched structurally rather than
    traced, so the count of hidden criticals is called out separately: that is the case where a reader
    would otherwise conclude the scan had nothing dangerous in it.
    """
    if not hidden:
        return ""
    counts = {}
    for finding in hidden:
        label = str(finding.get("confidence") or "MEDIUM").upper()
        counts[label] = counts.get(label, 0) + 1
    parts = [f"{counts[label]} {label}" for label in ("HIGH", "MEDIUM", "LOW") if counts.get(label)]
    critical = sum(1 for finding in hidden if finding.get("severity") == "CRITICAL")
    tail = ", all CRITICAL severity" if critical == len(hidden) else ""
    if 0 < critical < len(hidden):
        tail = f", {critical} of them CRITICAL severity"
    noun = "finding" if len(hidden) == 1 else "findings"
    return (f"Note: {' and '.join(parts)} {noun} hidden by the default table filter{tail} "
            "(pass --min-confidence all to view all findings).")


def _apply_config_filters(findings, config, path_excludes, scan_root=None, aux_scopes=None):
    """Apply root `.tcs.yaml` to findings: path exclusions and per-rule path overrides.

    `path_excludes` is False when the user named a single file on the command line --
    then only the rule-level overrides apply, because an explicitly named file is
    always analysed (same contract as `--exclude`).

    `scan_root` is the path the user named, as seen from the working directory: collected
    keys carry it as a prefix, and `TcsConfig` needs it to honour an anchored pattern such
    as `docs/**` when the scan is aimed at a subdirectory instead of the repository root.

    `aux_scopes` is the container/CI-IaC discovery map. Per-rule overrides are a *Python* noise
    policy -- the shipped CWE-78 globs name CI scripts and example trees, where shell-by-design
    is not injection -- and `**/.github/**` over a workflow YAML would delete the GHA injection
    rule at its only source. Those documents answer to their own structural falsifiers instead.
    A global `exclude_paths` entry still never-reads them, and templates are unaffected.
    """
    if config is None:
        return findings
    security_docs = aux_scopes or {}
    kept = []
    for finding in findings:
        path_key = str(finding.get("file", ""))
        if path_excludes and config.excludes_path(path_key, scan_root):
            continue
        if path_key not in security_docs and config.rule_excluded(
                str(finding.get("cwe", "")), path_key, scan_root):
            continue
        kept.append(finding)
    return kept


def _statement_span(source_code, line_number):
    """Return the (start, end) line span of the smallest statement covering line_number.

    Falls back to (line_number, line_number) when the source is unparseable or no
    statement covers the requested line.
    """
    try:
        tree = ast.parse(source_code)
    except (SyntaxError, ValueError, RecursionError):
        return line_number, line_number

    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.stmt)
        and getattr(node, "lineno", 0)
        and node.lineno <= line_number <= (node.end_lineno or node.lineno)
    ]
    if not candidates:
        return line_number, line_number

    stmt = min(candidates, key=lambda n: (n.end_lineno or n.lineno) - n.lineno)
    return stmt.lineno, (stmt.end_lineno or stmt.lineno)


def _generate_autofix(finding, source_code, file_path, engine=None):
    """
    Generate an autofix object for a finding by running the RemediationEngine.
    
    Returns a dict with autofix schema or None if no deterministic fix is available.
    
    Autofix schema:
    {
        "type": "ast_patch",
        "description": str,
        "replacement_text": str,
        "range": {
            "start_line": int,
            "start_col": int,
            "end_line": int,
            "end_col": int
        },
        "diff": str (optional),
        "verification_passed": bool
    }
    """
    if engine is None:
        engine = RemediationEngine()
    
    # Map CLI finding to remediation engine format
    remediation_finding = {
        "id": f"TimeCodeSecurity-{finding['cwe'].replace('-', '')}-{finding['line']}",
        "cwe": finding["cwe"],
        "line_number": finding["line"],
        "file": finding["file"],
        "code_snippet": "",  # Will be extracted from source
    }
    
    try:
        record = engine.remediate(remediation_finding, source_code, file_path)
    except Exception:
        # If remediation fails entirely, return None
        return None
    
    # Only attach autofix for successful patches
    if record.patch_status.value != "SUCCESS":
        return None
    
    # The autofix replaces the whole original statement, so derive the range from
    # the statement span in the UNPATCHED source. The snippet's own line count is
    # not used: a multi-line replacement still overwrites a single-line statement.
    stmt_start, stmt_end = _statement_span(source_code, record.line_number)
    start_line = stmt_start
    end_line = stmt_end

    source_lines = source_code.split("\n")
    if 0 < end_line <= len(source_lines):
        end_col = len(source_lines[end_line - 1].rstrip("\r"))
    else:
        end_col = 0

    autofix = {
        "type": "ast_patch",
        "description": f"Apply {record.remediation_rule.value} transformation for {record.cwe}",
        "replacement_text": record.patched_code_snippet,
        "range": {
            "start_line": start_line,
            "start_col": 0,
            "end_line": end_line,
            "end_col": end_col
        },
        "diff": record.unified_diff,
        "verification_passed": record.verification_passed
    }
    
    return autofix


def _attach_autofixes(findings, source_cache, autofix_engine=None):
    """
    Attach autofix objects to findings where deterministic fixes are available.
    
    Args:
        findings: List of finding dicts
        source_cache: Dict mapping file paths to source code strings
        autofix_engine: Optional RemediationEngine instance
    
    Returns:
        List of findings with autofix objects attached where applicable
    """
    if autofix_engine is None:
        autofix_engine = RemediationEngine()
    
    enhanced_findings = []
    for finding in findings:
        file_path = finding["file"]
        source_code = source_cache.get(file_path)
        
        if source_code:
            autofix = _generate_autofix(finding, source_code, file_path, autofix_engine)
            if autofix:
                finding_copy = finding.copy()
                finding_copy["autofix"] = autofix
                enhanced_findings.append(finding_copy)
            else:
                enhanced_findings.append(finding)
        else:
            enhanced_findings.append(finding)
    
    return enhanced_findings


def _ascii_table(findings):
    headers = ("#", "File", "Line", "CWE", "Severity", "Category")
    max_widths = (3, 15, 4, 8, 8, 22)
    rows = [
        (str(index), item["file"], str(item["line"]), item["cwe"], item["severity"], item["category"].replace("_", " "))
        for index, item in enumerate(findings, 1)
    ]
    widths = [
        min(max_widths[index], max([len(headers[index])] + [len(row[index]) for row in rows]))
        for index in range(len(headers))
    ]

    def fit(value, width, keep_end=False):
        if len(value) <= width:
            return value.ljust(width)
        if keep_end:
            return "..." + value[-(width - 3):]
        return value[:width - 3] + "..."

    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    lines = [border, "| " + " | ".join(headers[i].ljust(widths[i]) for i in range(len(headers))) + " |", border]
    for row in rows:
        cells = [fit(row[index], widths[index], keep_end=index == 1) for index in range(len(headers))]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append(border)
    return "\n".join(lines)


def _sarif_tags(cwe, related):
    """Tag list for one rule/result: its own CWE plus any secondary CWEs it stands for.

    A deduplicated, order-preserving list, so the same set of secondary ids always renders the
    same bytes and a CWE that already appears as the primary id is never repeated.
    """
    tags = ["security", str(cwe).lower()]
    for related_cwe in related or ():
        tag = str(related_cwe).lower()
        if tag not in tags:
            tags.append(tag)
    return tags


def _sarif_rule(cwe, category, severity, related=()):
    """Build one driver rule carrying the same required members the SARIF adapter emits."""
    digits = re.search(r"\d+", str(cwe))
    rule_meta = get_rule(cwe)
    short = str(category).replace("_", " ")
    return {
        "id": cwe,
        "name": str(cwe).replace("-", "_"),
        "shortDescription": {"text": short},
        "fullDescription": {"text": rule_meta.name if rule_meta else short},
        "helpUri": (
            f"https://cwe.mitre.org/data/definitions/{digits.group()}.html"
            if digits else "https://cwe.mitre.org/data/definitions/index.html"
        ),
        "defaultConfiguration": {
            "level": "error" if severity in ("CRITICAL", "HIGH") else "warning"
        },
        "properties": {"tags": _sarif_tags(cwe, related)},
    }


def _sarif_uri(path, cwd):
    """Normalize a filesystem path into a valid SARIF artifactLocation URI."""
    resolved = Path(str(path).replace("\\", "/")).resolve()
    try:
        return resolved.relative_to(cwd).as_posix()
    except ValueError:
        return resolved.as_uri()


def _sarif_code_flows(flow_trace, cwd):
    """Wrap a cross-file trace in SARIF codeFlows/threadFlows for GHAS and VS Code viewers."""
    locations = []
    for step, hop in enumerate(flow_trace, 1):
        locations.append({
            "location": {
                "message": {"text": f"{hop['role']} : {hop['label']}"},
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(hop["file"], cwd)},
                    "region": {"startLine": max(1, hop["line"]), "startColumn": 1},
                },
            },
            "executionOrder": step,
            "importance": "essential",
        })
    return [{
        "message": {"text": "Cross-file taint execution path"},
        "threadFlows": [{"locations": locations}],
    }]


def _sarif_document(findings, cwd, execution_successful=True):
    """Build the SARIF 2.1.0 run for `findings`.

    `execution_successful` mirrors reality: the crash and timeout-flush callers pass False, because
    their JSON siblings already report `status: incomplete` / `status: partial`, and both already
    exit non-zero -- claiming a successful run in the artefact would contradict them.
    """
    rules = []
    rule_indexes = {}
    # Rules are keyed by CWE alone, so the secondary ids of *every* finding carrying that CWE
    # are unioned up front. Reading only the first-seen finding would drop a later finding's
    # related CWEs and leave the rule under-indexed.
    related_by_cwe = {}
    for finding in findings:
        for related_cwe in finding.get("related_cwes") or ():
            collected = related_by_cwe.setdefault(finding["cwe"], [])
            if related_cwe not in collected:
                collected.append(related_cwe)
    for finding in findings:
        cwe = finding["cwe"]
        if cwe in rule_indexes:
            continue
        rule_indexes[cwe] = len(rules)
        rules.append(_sarif_rule(cwe, finding["category"], finding["severity"],
                                 related_by_cwe.get(cwe)))

    level_by_severity = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "UNKNOWN": "note"}
    results = []
    for finding in findings:
        result = {
            "ruleId": finding["cwe"],
            "ruleIndex": rule_indexes[finding["cwe"]],
            "level": level_by_severity.get(finding["severity"], "warning"),
            "message": {"text": finding["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(finding["file"], cwd)},
                    "region": {"startLine": max(1, finding["line"]), "startColumn": 1},
                }
            }],
        }
        # Mirrors the rule tag list so a reader that only walks results still sees the
        # secondary CWE. Emitted only when a finding actually carries one, which keeps the
        # bytes of every existing finding identical.
        properties = {}
        related = finding.get("related_cwes")
        if related:
            properties["tags"] = _sarif_tags(finding["cwe"], related)
        # CWE-611 triage hint: which syntactic shape the parser argument had. It exists only
        # here, never in the message, so SARIF text consumers keep reading the same sentence.
        xml_input = finding.get("xml_input")
        if xml_input:
            properties["xml_input"] = xml_input
        if properties:
            result["properties"] = properties
        flow_trace = finding.get("flow_trace")
        if flow_trace:
            result["codeFlows"] = _sarif_code_flows(flow_trace, cwd)
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "TimeCodeSecurity", "rules": rules}},
            "results": results,
            "invocations": [{"executionSuccessful": bool(execution_successful)}],
        }],
    }


def _scope_breakdown(findings, aux_scopes=None):
    counts = {scope: 0 for scope in SCOPE_ORDER}
    for finding in findings:
        counts[_scope_of(finding["file"], aux_scopes)] += 1
    return counts


def _print_summary(file_count, duration_ms, findings, file_counts=None,
                   discovered_files=None, fast_path_skipped_files=0,
                   unparseable_files=0, parse_governor=None, aux_scopes=None):
    counts = {severity: 0 for severity in SEVERITIES}
    scope_counts = _scope_breakdown(findings, aux_scopes)
    for finding in findings:
        severity = finding["severity"]
        counts[severity if severity in counts else "UNKNOWN"] += 1
    if discovered_files is not None:
        print(f"\nTotal discovered files: {discovered_files}")
    print(f"Total scanned files: {file_count}")
    if file_counts:
        print("Files scanned by scope: " + ", ".join(
            f"{SCOPE_LABELS[scope]}: {file_counts[scope]}" for scope in SCOPE_ORDER
        ))
        skipped = discovered_files - file_count if discovered_files is not None else 0
        if skipped:
            print(f"Files not scanned: {skipped} "
                  f"({fast_path_skipped_files} fast-path skipped, "
                  f"{unparseable_files} unparseable)")
    if parse_governor:
        workers = parse_governor.get("workers_final", parse_governor.get("workers_used"))
        print(f"Parser: {parse_governor.get('parse_mode', 'unknown')} mode, "
              f"{workers} worker(s), "
              f"{parse_governor.get('governor_events', 0)} governor reduction(s)")
        if parse_governor.get("execution_mode") == "serial_fallback":
            # A degraded run must announce itself on stdout: the reason, and the fact that
            # coverage did not shrink. Silent serial re-parsing would look like a normal scan.
            print(f"[!] EXECUTION MODE: serial_fallback - the parallel parse pool failed "
                  f"({parse_governor.get('parallel_fallback_reason')}). All "
                  f"{file_count} scanned file(s) were re-parsed serially; coverage unchanged, "
                  f"scan slower.")
    print(f"Scan duration: {duration_ms:.2f} ms")
    print("Findings by severity: " + ", ".join(f"{severity.title()}: {counts[severity]}" for severity in SEVERITIES))
    print("Findings by scope: " + ", ".join(
        f"{SCOPE_LABELS[scope]}: {scope_counts[scope]}" for scope in SCOPE_ORDER
    ))


def _cross_trace_report(findings, cwd):
    """Render the multi-hop attack path for every cross-file finding, or '' if none."""
    traced = [
        (index, finding)
        for index, finding in enumerate(findings, 1)
        if finding.get("category") == "cross_file" and finding.get("flow_trace")
    ]
    if not traced:
        return ""

    rule = "-" * 80
    lines = ["", rule, "        TIMECODESECURITY - CROSS-FILE EXPLOIT CHAINS", rule]
    for index, finding in traced:
        rule_meta = get_rule(finding["cwe"])
        label = (rule_meta.category if rule_meta else finding.get("category", "")).replace("_", " ").upper()
        lines.append(f"[TRACE] Finding #{index}: {finding['cwe']} ({label})")
        for step, hop in enumerate(finding["flow_trace"], 1):
            location = _file_key(Path(hop["file"]), cwd)
            lines.append(f"  {step}. {hop['role'].ljust(7)}: {location}:{hop['line']} ({hop['label']})")
        lines.append(rule)
    return "\n".join(lines)



class CrossFinding(dict):
    """Hybrid finding: acts as dict and object simultaneously."""
    def __init__(self, cwe, file_path, lineno, message, severity="HIGH", flow_trace=None,
                 confidence="HIGH"):
        super().__init__(
            cwe=cwe,
            rule_id=cwe,
            severity="HIGH",
            confidence=confidence,
            file_path=file_path,
            file=file_path,
            path=file_path,
            lineno=lineno,
            line=lineno,
            message=message,
            desc=message,
            description=message,
            category="cross_file",
            flow_trace=flow_trace or [],
        )
        self.category = "cross_file"
        self.confidence = confidence
        self.flow_trace = flow_trace or []
        self.cwe = cwe
        self.rule_id = cwe
        self.severity = "HIGH"
        self.file_path = file_path
        self.file = file_path
        self.path = file_path
        self.lineno = lineno
        self.line = lineno
        self.message = message
        self.desc = message
        self.description = message

def _cross_scan_reuse_trees(tracker):
    """The scanner's already-parsed ASTs, offered to the cross-file indexer for a second use.

    Reuse preconditions, each one checked before this dict is handed over:
    - parser mode is not `treesitter`: the engine reparses with the built-in `ast` module and
      a treesitter-produced tree is not what `GlobalSymbolIndex._index_file` walks;
    - files the scanner skipped (unparseable), recovered (block-pass substituted) or rescued
      are excluded - the engine's own disk parse would build a *different* tree for them,
      and the baseline behaviour for those files is the fresh parse, not the scanner's one;
    - the indexer still re-reads every path and reuses its tree only when the on-disk source
      equals the scanner's snapshot byte-for-byte, so a file changed mid-scan falls back.

    Returns None when nothing qualifies; the engine then behaves exactly as before.
    """
    if tracker is None or not getattr(tracker, "modules", None):
        return None
    if getattr(tracker, "execution_mode", None) == "treesitter":
        return None
    cwd = Path.cwd()
    excluded = (set(tracker.skipped_files) | set(tracker.recovered_files)
                | set(tracker.rescued_files))
    reuse = {}
    for mod, tree in tracker.modules.items():
        key = tracker.file_paths.get(mod)
        if key is None or key in excluded or tree is None:
            continue
        try:
            source = tracker.files[key]
            reuse[str((cwd / key).resolve())] = (source, tree)
        except (KeyError, OSError):
            continue
    return reuse or None


def _run_cross_scan(target_path, reuse_trees=None):
    """Executes CrossFileTaintEngine. Returns (findings, engine).

    An engine failure is fatal rather than empty: swallowing the exception made a broken
    cross-file analysis indistinguishable from a clean scan, silently dropping both the
    cross-file findings and the sanitizer suppression that depends on the engine.
    """
    try:
        engine = CrossFileTaintEngine(target_path, reuse_trees=reuse_trees)
        raw_findings = engine.run()
    except Exception as exc:
        print(f"[FATAL] CrossFileTaintEngine crashed: {exc}", file=sys.stderr)
        traceback.print_exc()
        raise SystemExit(1)

    results = []
    for cf in raw_findings:
        msg = f"Cross-file leak: {cf.caller_func} flows into {cf.callee_func} ({cf.callee_sink_name}) at {cf.callee_file}:{cf.callee_sink_lineno}"
        results.append(CrossFinding(
            cwe=cf.cwe,
            file_path=cf.caller_file,
            lineno=cf.caller_lineno,
            message=msg,
            severity="HIGH",
            flow_trace=[
                {"role": hop.role, "file": hop.file_path, "line": hop.lineno, "label": hop.label}
                for hop in getattr(cf, "flow_trace", None) or []
            ],
        ))
    return results, engine


def _suppress_cross_file_sanitized(findings, engine):
    """Drop single-file findings whose tainted arguments a cross-file sanitizer neutralized.

    The AST scanner has no visibility into callee contracts, so `cmd = format_command(x)`
    followed by `os.system(cmd)` is reported as injectable even when the helper escapes its
    argument. Cross-file findings are left untouched: that engine already honours contracts.

    A failure here is fatal, not ignored: returning the findings unchanged would silently
    re-introduce every sanitizer false positive and still report a successful scan.
    """
    try:
        sanitized_sites = {
            (_normalize_compare_path(file_path), lineno)
            for file_path, lineno in engine.sanitized_sink_locations()
        }
    except Exception as exc:
        print(f"[FATAL] CrossFileTaintEngine sanitizer analysis crashed: {exc}", file=sys.stderr)
        traceback.print_exc()
        raise SystemExit(1)
    if not sanitized_sites:
        return findings

    kept = []
    for finding in findings:
        if finding.get("category") == "cross_file":
            kept.append(finding)
            continue
        identity = (_normalize_compare_path(finding["file"]), finding["line"])
        if identity in sanitized_sites:
            continue
        kept.append(finding)
    return kept

def _js_ts_findings(path):
    """Map the isolated tree-sitter JS/TS findings onto this module's finding shape."""
    mapped = []
    for finding in run_js_ts_scan_isolated(path, base_dir=Path.cwd().resolve()):
        mapped.append({
            "file": str(finding.get("file", "")).replace("\\", "/"),
            "line": finding.get("line_number") or 1,
            "cwe": finding.get("cwe") or "UNKNOWN_CWE",
            "severity": str(finding.get("severity") or "HIGH").upper(),
            "confidence": "MEDIUM",
            "category": finding.get("category") or "Security",
            "message": finding.get("message") or "",
        })
    return sorted(mapped, key=lambda item: (item["file"], item["line"], item["cwe"]))


def _scan_failure(args, exc):
    """A crashed scan still owes CI parsable artefacts, then reports exit 2.

    Without this the process dies on a traceback: stdout JSON stays empty (0-byte file
    after redirection) and the SARIF target never exists, which GitHub's uploader
    reports as an unrelated failure.
    """
    message = f"{type(exc).__name__}: {exc}"
    print(f"[FATAL] TimeCodeSecurity scan aborted: {message}", file=sys.stderr)
    if getattr(args, "format", "") == "json":
        print(json.dumps({
            "scope": getattr(args, "scope", "all"),
            "status": "incomplete",
            "error": message,
            "total_discovered_files": 0,
            "scanned_files": 0,
            "fast_path_skipped_files": 0,
            "unparseable_files": 0,
            "findings": [],
        }, indent=2))
    if getattr(args, "sarif", None):
        try:
            document = bound_sarif_document(
                _sarif_document([], Path.cwd().resolve(), execution_successful=False))
            atomic_write_text(Path(args.sarif), json.dumps(document, indent=2) + "\n")
        except OSError as write_exc:
            print(f"Error writing fallback SARIF file: {write_exc}", file=sys.stderr)
    return 2


# A runner that kills the process at a step timeout leaves no SARIF at all, and the referee can only
# report that as "0 findings" - indistinguishable from a clean scan. The handlers below turn that
# truncation into a real (partial) report: whatever the scan already holds gets written to the
# requested --sarif / --format json targets. Two limits are stated plainly: findings the engine has
# not produced yet cannot be flushed, and GitHub's own step timeout does not reliably signal child
# processes, so a caller must bound the run with `timeout --signal=TERM` to actually reach this path.
_PARTIAL = {
    "args": None,
    "findings": [],
    "tracker": None,
    "files": None,
    "written": False,
    "current_file": None,
    "t0": None,
}


def _partial_findings():
    """Findings as far as the scan has got: stage list first, live tracker index second."""
    findings = list(_PARTIAL["findings"])
    if findings:
        return findings
    tracker = _PARTIAL["tracker"]
    if tracker is None:
        return []
    try:
        return _findings_for(tracker, list(tracker.edges))
    except Exception as exc:
        # A half-built index must not hide the artefact: report an empty partial run instead.
        print(f"[warning] Partial index unreadable: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return []


def _print_termination_telemetry():
    """Say where the scan stopped, on stderr, before the partial payload is emitted.

    A partial SARIF/JSON file only carries the findings that existed at the moment of the
    kill; it cannot say how far the engine had got. Without this line a timeout at file 3 of
    9,000 and a timeout inside the final cascade look identical to whoever reads the artefact.
    Everything here is observational: it writes to stderr and never touches the JSON shape or
    the SARIF document.
    """
    tracker = _PARTIAL["tracker"]
    point = None
    if tracker is not None:
        try:
            point = tracker.termination_checkpoint()
        except Exception as exc:
            print(f"[telemetry] Checkpoint unavailable: {type(exc).__name__}: {exc}",
                  file=sys.stderr, flush=True)
    if point is None:
        print("[telemetry] Active phase: pre-analysis (discovery/parse), analyze() not started",
              file=sys.stderr, flush=True)
    else:
        print(f"[telemetry] Active phase: {point['phase']}", file=sys.stderr, flush=True)
        profile = point.get("collector_profile_s") or {}
        if profile:
            ordered = sorted(profile.items(), key=lambda kv: (-kv[1], kv[0]))
            print("[telemetry] Collector timings so far (s): "
                  + " ".join(f"{name}={secs:.2f}" for name, secs in ordered),
                  file=sys.stderr, flush=True)
    t0 = _PARTIAL.get("t0")
    if t0 is not None:
        line = f"[telemetry] Elapsed since scan start: {time.perf_counter() - t0:.2f}s"
        if point is not None and point.get("analyze_elapsed_s") is not None:
            line += f" (analyze(): {point['analyze_elapsed_s']:.2f}s)"
        print(line, file=sys.stderr, flush=True)


def _flush_partial(reason):
    """Serialize the current scan state into the requested artefacts, once."""
    args = _PARTIAL["args"]
    if args is None or _PARTIAL["written"]:
        return []
    _PARTIAL["written"] = True
    # Telemetry first: stdout carries the JSON payload, so the checkpoint has to be on stderr
    # and flushed before it, or a consumer piping stdout never sees it in order.
    _print_termination_telemetry()
    findings = _partial_findings()
    files = _PARTIAL["files"] or {}
    if getattr(args, "format", "") == "json":
        print(json.dumps({
            "scope": getattr(args, "scope", "all"),
            "status": "partial",
            "terminated_by": reason,
            "total_discovered_files": len(files),
            "scanned_files": len(files),
            "findings": findings,
        }, indent=2), flush=True)
    if getattr(args, "sarif", None):
        try:
            document = bound_sarif_document(
                _sarif_document(findings, Path.cwd().resolve(), execution_successful=False))
            atomic_write_text(Path(args.sarif), json.dumps(document, indent=2) + "\n")
        except OSError as exc:
            print(f"[warning] Partial SARIF write failed: {exc}", file=sys.stderr, flush=True)
            return findings
    print("[warning] Caught termination signal; flushed partial findings to SARIF",
          file=sys.stderr, flush=True)
    return findings


def _install_partial_flush(args):
    """Arm SIGTERM/SIGINT for this scan run, then let the caller work normally."""
    _PARTIAL.update({"args": args, "findings": [], "tracker": None, "files": None,
                     "written": False, "current_file": None, "t0": time.perf_counter()})

    def _handle(signum, _frame):
        reason = signal.Signals(signum).name
        # Progress lines are throttled to one per PROGRESS_FILE_EVERY files, so the file the scan
        # is actually inside comes from _PARTIAL["current_file"] rather than the last log line.
        current = _PARTIAL["current_file"]
        where = f" while reading {current}" if current else " mid-scan"
        print(f"[warning] Caught {reason}{where}; flushing what is known so far",
              file=sys.stderr, flush=True)
        _flush_partial(reason)
        # 128 + signum is the shell convention for "died of that signal": 143 SIGTERM, 130 SIGINT.
        raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handle)
        except (AttributeError, OSError, ValueError):
            # No such signal on this platform, or not the main thread.
            pass


def _parse_parser_arg(parser_str: Optional[str]) -> str:
    """Normalise --parser into one of PARSER_MODES. Anything unexpected is the default, never a crash.

    argparse restricts the choices for a real command line; this exists for callers that build an args
    namespace themselves, where `getattr(args, "parser", None)` comes back None.
    """
    if isinstance(parser_str, str) and parser_str.strip().lower() in PARSER_MODES:
        return parser_str.strip().lower()
    return DEFAULT_PARSER_MODE


def _auto_worker_count() -> int:
    """Default pool size for `--workers auto`: the hardware governor's answer and nothing after it.

    Two faults made `auto` the most expensive setting in the product. It returned `os.cpu_count()`,
    so it never asked the governor that budgets RAM per worker, and a worker here was not cheap --
    each one was a fresh interpreter that imported its own copy of the rule bank, so a 4-core laptop
    opened 5 processes and roughly 1 GB of peak RSS before it had read a single file. The pool is
    now governed by measurement alone: `tcs.parallel_scanner.compute_safe_workers()` reads free RAM,
    forces 1 worker below `HARD_SAFETY_THRESHOLD_MB` (900 MB, the laptop case), divides what is left
    by `WORKER_RAM_BUDGET_MB`, and holds a free-core reservation, so the same flag answers 1 on a
    machine that cannot afford a second interpreter and scales up to `MAX_WORKERS_CEILING` on a cloud
    runner. The cap that used to sit on top of that answer -- 2 workers on any machine at or below
    16 GB -- was a second, dumber governor: it overrode a measurement the first one had already made
    and cost a 16 GB runner half the pool it had RAM for. An explicit `--workers N` never comes
    through here, so a user who wants a different pool still has it.
    """
    try:
        from tcs.parallel_scanner import compute_safe_workers
        return max(1, int(compute_safe_workers()))
    except Exception as exc:
        print(f"TimeCodeSecurity [WORKERS] --workers auto: governor unavailable "
              f"({type(exc).__name__}: {exc}); staying serial rather than guessing a pool size.",
              file=sys.stderr)
        return 1


def _parse_workers_arg(workers_str: Optional[str]) -> int:
    """Normalise --workers into a pool size.

    Args:
        workers_str: String value from CLI ('1', '2', '4', '8', 'auto', or None)

    Returns:
        Integer worker count. `None` and `'auto'` are the RAM-governed default
        (`_auto_worker_count`); a number is honoured as given, because an explicit request is the
        user overriding the governor on a machine the governor cannot see.
    """
    if workers_str is None:
        workers_str = "auto"

    workers_str = workers_str.strip().lower()

    if workers_str == "auto":
        return _auto_worker_count()

    try:
        n = int(workers_str)
        if n < 1:
            print("Warning: --workers must be >= 1, using 1", file=sys.stderr)
            return 1
        if n > 64:
            print(f"Warning: --workers={n} is excessive, capping at 32", file=sys.stderr)
            return 32
        return n
    except ValueError:
        print(f"Warning: invalid --workers value '{workers_str}', using auto-detect", file=sys.stderr)
        return _auto_worker_count()


def _maybe_warn_js_ts(args):
    """Warn about a missing JS/TS grammar only when JS/TS was actually part of this run.

    Pure-Python scans used to inherit an import-time warning from js_scanner that the user could
    do nothing with. The grammar is already imported fine in most runs, so that case costs one
    boolean; only a broken install pays the (early-exit) tree walk that decides whether the
    target holds any JS/TS file.
    """
    if _JS_TS_SCANNER_AVAILABLE and js_ts_available():
        return
    if not getattr(args, "include_js", False) and not has_js_ts_files(args.path):
        return
    warn_js_ts_unavailable()


def _scan(args):
    scope = args.scope
    # Phase-1 outer clock: anchored at the earliest scan entry point, i.e. BEFORE
    # `_maybe_warn_js_ts`, auxiliary collection and `_collect_files`. The pre-existing
    # `started`/`duration_ms` anchor (after file collection) is left untouched so the
    # JSON schema keeps its documented meaning; Outer(...) TOTAL is the wider boundary.
    _clock = _StageClock("scan")
    _install_partial_flush(args)
    _maybe_warn_js_ts(args)
    
    # Parse workers argument and pass to TaintTracker
    workers = _parse_workers_arg(getattr(args, "workers", None))
    ux = _ux_enabled(args)
    if ux:
        banner.print_banner(args.path, scope=scope, workers=workers, stream=sys.stderr)
    # The output policy is announced on every scan, TTY or not, so a reader always knows whether
    # clean-default, custom or full-audit mode produced the report. stderr keeps stdout a data pipe.
    banner.badge("INF", _policy_banner(args), stream=sys.stderr)

    try:
        line_ranges = _parse_line_ranges(getattr(args, "lines", None))
        exclude_patterns = _parse_exclude_patterns(getattr(args, "exclude", None))
        # Root configuration is optional and read from the working directory only, so a
        # checkout without `.tcs.yaml` keeps the byte-identical default scan.
        config = load_config()
        # Collected keys are spelled relative to the working directory, so the root is
        # resolved once here and reused by every `.tcs.yaml` match below.
        _config_root = _file_key(args.path, Path.cwd().resolve())
        config_excludes = (
            (lambda key: config.excludes_path(key, _config_root))
            if config is not None else None
        )
        tree_scan = args.path.is_dir()
        # Pruning non-production trees is the default for a directory walk; `--include-tests` (or
        # `--all`) opts back in, and `--skip-non-production` is accepted but no longer changes anything.
        # Only a walk prunes: a file or directory named on the command line is analysed in full.
        skip_non_production = tree_scan and not bool(getattr(args, "include_tests", False)) \
            and not bool(getattr(args, "all", False))
        skip_vendor = tree_scan and not bool(getattr(args, "include_vendor", False)) \
            and not bool(getattr(args, "all", False))
        for _stat in _SCOPE_STATS:
            _SCOPE_STATS[_stat] = 0
        templates, iac, manifests, secrets, aux_scopes = _collect_auxiliary_files(
            args.path, exclude_patterns, config_excludes, skip_non_production, skip_vendor)
        if scope not in ("all", "html"):
            templates = {}
        if scope not in ("all", "sca"):
            manifests = {}
        if scope not in ("all", "secrets"):
            secrets = {}
        if scope in ("docker", "iac"):
            iac = {key: source for key, source in iac.items() if aux_scopes.get(key) == scope}
        elif scope != "all":
            iac = {}
        aux_scopes = {key: value for key, value in aux_scopes.items()
                      if scope == "all" or value == scope}
        _clock.mark("AuxCollect")
        tracker = None
        files = {}
        if scope in ("all", "python"):
            try:
                files = _collect_files(args.path, exclude_patterns=exclude_patterns,
                                       config_excludes=config_excludes,
                                       skip_non_production=skip_non_production,
                                       skip_vendor=skip_vendor)
            except ValueError:
                if not templates and not iac and not manifests and not secrets:
                    raise
        _clock.mark("CollectPy")
        if ux:
            auxiliary = len(templates) + len(iac) + len(manifests) + len(secrets)
            banner.print_phase(1, 4, "discovery", stream=sys.stderr)
            banner.print_step(1, "files discovered",
                              f"{len(files)} python, {auxiliary} auxiliary", stream=sys.stderr)

        # TimeCodeSecurity: Capture pre-scan memory stats
        try:
            import psutil
            mem_before = psutil.virtual_memory()
            available_ram_before_gb = mem_before.available / (1024 ** 3)
            rss_before_mb = psutil.Process().memory_info().rss / (1024 ** 2)
        except ImportError:
            available_ram_before_gb = 0
            rss_before_mb = 0
        
        if ux:
            banner.print_phase(2, 4, "analysis", stream=sys.stderr)
            for worker_id in range(workers if files else 0):
                banner.print_worker(worker_id, "ready", stream=sys.stderr)
        started = time.perf_counter()
        if files:
            _PARTIAL["files"] = files
            _parser_mode = _parse_parser_arg(getattr(args, "parser", None))
            # Default mode keeps the progress line byte-for-byte as it was; a chosen mode names itself,
            # because "with 8 worker(s)" is not what `treesitter` is doing (it runs single-process).
            _progress(f"parsing {len(files)} python file(s) with {workers} worker(s)"
                      + ("" if _parser_mode == DEFAULT_PARSER_MODE else f", parser={_parser_mode}"))
            tracker = TaintTracker(
                files=files,
                max_workers=workers,
                parser_mode=_parser_mode,
                audit_all=getattr(args, "audit_all", False),
            )
            _PARTIAL["tracker"] = tracker
            _clock.mark("Parse+Init")
            for fpath, reason in sorted(tracker.skipped_files.items()):
                print(f"Warning: skipping unparseable file {fpath}: {reason}", file=sys.stderr)
            _, _, edges = tracker.analyze()
            _clock.mark("Analyze")
            ast_findings = _findings_for(tracker, edges)
            _clock.mark("ASTFindings")
            _progress(f"parsed + traced, {len(ast_findings)} AST finding(s) so far")
        else:
            ast_findings = []
            _clock.mark("Parse+Init")
            _clock.mark("Analyze")
            _clock.mark("ASTFindings")
        if ux:
            banner.print_step(2, "ast findings", f"{len(ast_findings)} row(s)", stream=sys.stderr)
        aux_file_counts = {"docker": 0, "iac": 0, "sca": 0, "secrets": 0}
        for aux_scope in aux_scopes.values():
            aux_file_counts[aux_scope] += 1
        file_counts = {
            "python": len(tracker.modules) if tracker else 0,
            "docker": aux_file_counts["docker"],
            "iac": aux_file_counts["iac"],
            "sca": aux_file_counts["sca"],
            "secrets": aux_file_counts["secrets"],
            "html": len(templates),
        }
        scanned_files = sum(file_counts.values())
        parse_stats = getattr(tracker, "parse_stats", None) or {}
        python_discovered = parse_stats.get("discovered", len(files))
        fast_path_skipped_files = parse_stats.get("fast_path_skipped", 0)
        unparseable_files = parse_stats.get(
            "unparseable", len(tracker.skipped_files) if tracker else 0)
        scope_breakdown = {
            "python": {
                "discovered": python_discovered,
                "scanned": file_counts["python"],
                "fast_path_skipped": fast_path_skipped_files,
                "unparseable": unparseable_files,
            },
            "docker": {
                "discovered": aux_file_counts["docker"],
                "scanned": file_counts["docker"],
            },
            "iac": {
                "discovered": aux_file_counts["iac"],
                "scanned": file_counts["iac"],
            },
            "sca": {
                "discovered": aux_file_counts["sca"],
                "scanned": file_counts["sca"],
            },
            "secrets": {
                "discovered": aux_file_counts["secrets"],
                "scanned": file_counts["secrets"],
            },
            "html": {
                "discovered": len(templates),
                "scanned": file_counts["html"],
            },
        }
        total_discovered_files = sum(bucket["discovered"] for bucket in scope_breakdown.values())
        parse_governor = {
            key: parse_stats[key]
            for key in ("parse_mode", "workers_used", "workers_initial",
                        "workers_final", "governor_events",
                        "execution_mode", "parallel_fallback_reason",
                        # Phase 3: which reader was allowed, and how many modules it actually produced
                        # (a shadow run can be checked against those two numbers instead of a log).
                        "parser_mode", "parsed_by_packer")
            if key in parse_stats
        }
        # The engine attribute is the authority; parse_stats carries it only when a tracker ran.
        parse_governor.setdefault("execution_mode", getattr(tracker, "execution_mode", "not_started"))
        parse_governor.setdefault("parallel_fallback_reason",
                                  getattr(tracker, "parallel_fallback_reason", None))
        # The legacy auditor keeps owning every CWE-1357 row and the Dockerfile CWE-250/CWE-269
        # pair, byte-identical. The modular scanners add the container and CI/IaC rule families on
        # top and are handed the legacy rows so one root-user defect is never booked twice.
        legacy_iac = audit_iac_files(iac, audit_all=getattr(args, "audit_all", False))
        sca_findings = audit_sca_files(manifests)
        if sca_findings:
            # The import walk is paid for only when a vulnerable pin exists, so a Python-only tree
            # -- every latency gate's workload -- does no extra work at all.
            tag_reachability(sca_findings, _imported_roots(tracker))
        findings = _merge_findings(
            ast_findings,
            audit_templates(templates),
            legacy_iac,
            audit_security_files(iac, legacy_findings=legacy_iac),
            sca_findings,
            audit_secret_files(secrets),
        )
        findings = consolidate_findings(findings)
        # Template/IaC auditors report a structural match and no data-flow provenance, which
        # is exactly MEDIUM; AST findings arrive with their own label.
        for finding in findings:
            finding.setdefault("confidence", "MEDIUM")
        _clock.mark("Merge+Consolidate")
        _PARTIAL["findings"] = findings
        if scope in ("all", "python"):
            cross_findings, cross_engine = _run_cross_scan(
                args.path, reuse_trees=_cross_scan_reuse_trees(tracker))
            _clock.mark("CrossScan")
            findings = _suppress_cross_file_sanitized(findings, cross_engine)
            _clock.mark("Suppression")
            findings.extend(cross_findings)
            _PARTIAL["findings"] = findings
        else:
            _clock.mark("CrossScan")
            _clock.mark("Suppression")
        if ux:
            banner.print_phase(3, 4, "correlation", stream=sys.stderr)
            banner.print_step(3, "cross-file + suppression", f"{len(findings)} row(s)",
                              stream=sys.stderr)

        # Incremental scan: keep only diagnostics intersecting the modified lines.
        # Applied before autofix generation so patching work is scoped too.
        findings = _scope_findings_to_lines(findings, line_ranges)

        # Opt-in tree-sitter JS/TS pass. Off by default: the grammar is a native
        # extension whose access violation takes the whole process down.
        if getattr(args, "include_js", False) and _JS_TS_SCANNER_AVAILABLE and js_ts_available():
            findings = _merge_findings(findings, _js_ts_findings(args.path))

        # Root `.tcs.yaml`: path exclusions and per-rule path overrides from the working
        # directory. Applied after every producer so cross-file and JS rows obey it too.
        findings = _apply_config_filters(findings, config, path_excludes=tree_scan,
                                         scan_root=_config_root, aux_scopes=aux_scopes)
        findings = _apply_inline_suppressions(
            findings, {**files, **templates, **iac, **manifests, **secrets})

        # --diff narrows *reporting* to added/modified lines. The analysis above already
        # saw the whole tree, so cross-file context is never truncated.
        diff_ref = getattr(args, "diff", None)
        if diff_ref:
            _diff_repo_root = resolve_repo_root()
            findings = _scope_findings_to_diff(
                findings, changed_line_intervals(_diff_repo_root, diff_ref), _diff_repo_root)

        # Display-only output policy; the engine's emission set is already final. The explicit
        # --min-confidence floor stays the single confidence call site; the clean-default policy is a
        # separate report layer that runs only when no opt-in flag asked for a wider or narrower view.
        requested_minimum = getattr(args, "min_confidence", None)
        confidence_minimum = None if requested_minimum in (None, "all") else requested_minimum
        findings = _filter_by_confidence(findings, confidence_minimum)
        policy_mode = _output_policy_mode(args)
        held_back = []
        if policy_mode == "clean-default":
            findings, held_back = _apply_clean_default(findings, args)
        else:
            findings = _filter_by_severity(findings, getattr(args, "min_severity", None))
        # In clean-default and full-audit modes the table shows exactly what JSON and SARIF show, so the
        # three formats agree. The legacy high table floor survives only in custom mode, where a caller
        # opted into a wider emission set but named no confidence level for the human-readable table.
        hidden_rows = []
        display_rows = findings
        if (policy_mode == "custom" and requested_minimum is None
                and getattr(args, "format", "table") == "table"):
            display_rows, hidden_rows = _split_by_table_default(findings)
        _PARTIAL["findings"] = findings

        # Generate autofix suggestions if requested (JSON only)
        if args.with_autofix and args.format == "json" and files:
            # Build source cache from scanned files
            source_cache = {}
            for file_path in files:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        source_cache[file_path.replace("\\", "/")] = f.read()
                except (OSError, UnicodeDecodeError):
                    pass
            
            # Attach autofixes where deterministic fixes are available
            autofix_engine = RemediationEngine()
            findings = _attach_autofixes(findings, source_cache, autofix_engine)
        _clock.mark("LineScope+JS+Autofix")
        
        duration_ms = (time.perf_counter() - started) * 1000
        
        # TimeCodeSecurity: Capture post-scan memory stats
        try:
            import psutil
            mem_after = psutil.virtual_memory()
            available_ram_after_gb = mem_after.available / (1024 ** 3)
            rss_after_mb = psutil.Process().memory_info().rss / (1024 ** 2)
            peak_rss_mb = rss_after_mb
            available_ram_gb = min(available_ram_before_gb, available_ram_after_gb)
        except ImportError:
            peak_rss_mb = 0
            available_ram_gb = 0
    except (OSError, ValueError) as exc:
        return _scan_failure(args, exc)

    if ux:
        banner.print_phase(4, 4, "reporting", stream=sys.stderr)
    if args.format == "json":
        print(json.dumps({
            "scope": scope,
            "line_filter": [list(r) for r in line_ranges] if line_ranges else None,
            "diff_ref": diff_ref,
            "confidence_filter": confidence_minimum,
            "output_policy": policy_mode,
            "held_back_findings": len(held_back),
            "total_discovered_files": total_discovered_files,
            "scanned_files": scanned_files,
            "scanned_files_by_scope": file_counts,
            "fast_path_skipped_files": fast_path_skipped_files,
            "unparseable_files": unparseable_files,
            "scope_breakdown": scope_breakdown,
            "parse_governor": parse_governor,
            "execution_mode": parse_governor.get("execution_mode", "not_started"),
            "parallel_fallback_reason": parse_governor.get("parallel_fallback_reason"),
            "duration_ms": round(duration_ms, 2),
            "findings_by_scope": _scope_breakdown(findings, aux_scopes),
            "findings": findings,
        }, indent=2))
        # A scope note belongs on stderr for a machine run: the payload and its keys stay exactly
        # as they are, so nothing that parses this output changes behaviour.
        scope_note = non_production_scope_note()
        if scope_note:
            print(scope_note, file=sys.stderr)
        policy_note = clean_default_note(held_back)
        if policy_note:
            print(policy_note, file=sys.stderr)
        vendor_note = vendor_scope_note()
        if vendor_note:
            print(vendor_note, file=sys.stderr)
    else:
        if display_rows:
            print(_ascii_table(display_rows))
        elif hidden_rows:
            print(f"[+] No findings at the default {TABLE_DEFAULT_CONFIDENCE.upper()} confidence "
                  f"floor; {len(hidden_rows)} row(s) are held back, listed in the note below.")
        elif held_back:
            print(f"[+] No findings at the clean default policy floor; {len(held_back)} row(s) are "
                  f"held back, listed in the note below (pass --all to show all).")
        else:
            if _SCOPE_STATS["skipped_files"] or _SCOPE_STATS["skipped_filenames"]:
                # Nothing was reported, but the walk did not read everything: "Clean scan!" over a
                # tree whose tests/ and examples/ were pruned would be the most misleading line
                # this tool can print.
                held_files = _SCOPE_STATS["skipped_files"] + _SCOPE_STATS["skipped_filenames"]
                print(f"[+] No findings in the {scanned_files} file(s) that were read; "
                      f"{held_files} non-production file(s) were held back -- see the note below.")
            else:
                print("[+] No vulnerabilities found. Clean scan!")
        note = table_default_note(hidden_rows)
        if note:
            print(note)
        scope_note = non_production_scope_note()
        if scope_note:
            print(scope_note)
        policy_note = clean_default_note(held_back)
        if policy_note:
            print(policy_note)
        vendor_note = vendor_scope_note()
        if vendor_note:
            print(vendor_note)
        _print_summary(scanned_files, duration_ms, display_rows, file_counts,
                       discovered_files=total_discovered_files,
                       fast_path_skipped_files=fast_path_skipped_files,
                       unparseable_files=unparseable_files,
                       parse_governor=parse_governor, aux_scopes=aux_scopes)
        traces = _cross_trace_report(findings, Path.cwd().resolve())
        if traces:
            print(traces)
    _clock.mark("StdoutOutput")

    if args.sarif:
        try:
            document = bound_sarif_document(_sarif_document(findings, Path.cwd().resolve()))
            sarif_path = Path(args.sarif)
            atomic_write_text(sarif_path, json.dumps(document, indent=2) + "\n")
            sarif_size_mb = sarif_path.stat().st_size / (1024 ** 2) if sarif_path.exists() else 0
        except OSError as exc:
            print(f"Error writing SARIF file: {exc}", file=sys.stderr)
            return 2
    else:
        sarif_size_mb = 0
    _clock.mark("SARIFDump")

    sbom_path_text = getattr(args, "sbom", None)
    if sbom_path_text:
        try:
            document = build_sbom(collect_components(manifests), findings,
                                  root_name=Path(args.path).resolve().name or "target")
            sbom_path = Path(sbom_path_text)
            atomic_write_text(sbom_path, json.dumps(document, indent=2) + "\n")
        except OSError as exc:
            print(f"Error writing SBOM file: {exc}", file=sys.stderr)
            return 2
    _clock.mark("SBOMDump")
    
    # TimeCodeSecurity: Print performance metrics to stderr
    if files and tracker:
        try:
            from tcs.parallel_scanner import HARD_SAFETY_THRESHOLD_MB

            print("\n" + "="*70, file=sys.stderr)
            print("TimeCodeSecurity - Performance Metrics", file=sys.stderr)
            print("="*70, file=sys.stderr)
            print(f"Wall-Clock Scan Time:     {duration_ms/1000:.2f}s ({duration_ms:.0f}ms)", file=sys.stderr)
            print(f"Parser Mode:              {parse_governor.get('parse_mode', 'unknown')}"
                  f"  (execution: {parse_governor.get('execution_mode', 'unknown')})", file=sys.stderr)
            print(f"Worker Count Utilized:    {parse_governor.get('workers_final', parse_governor.get('workers_used', 'n/a'))}"
                  f" (governor start: {parse_governor.get('workers_initial', parse_governor.get('workers_used', 'n/a'))}, "
                  f"reductions: {parse_governor.get('governor_events', 0)})", file=sys.stderr)
            print(f"Governor RAM Floor:       {HARD_SAFETY_THRESHOLD_MB} MB", file=sys.stderr)
            print(f"Peak Memory RSS:          {peak_rss_mb:.1f} MB", file=sys.stderr)
            print(f"Available RAM (min):      {available_ram_gb:.2f} GB", file=sys.stderr)
            print(f"Total Findings:           {len(findings)}", file=sys.stderr)
            if args.sarif:
                print(f"SARIF File Size:          {sarif_size_mb:.2f} MB {'✓' if sarif_size_mb < 10 else '⚠ EXCEEDS 10 MB'}", file=sys.stderr)
            print(f"Files Discovered:         {total_discovered_files} "
                  f"(python: {python_discovered}, docker: {aux_file_counts['docker']}, "
                  f"iac: {aux_file_counts['iac']}, sca: {aux_file_counts['sca']}, "
                  f"secrets: {aux_file_counts['secrets']}, "
                  f"html: {len(templates)})", file=sys.stderr)
            print(f"Files Scanned:            {scanned_files} "
                  f"(python: {file_counts['python']}, docker: {file_counts['docker']}, "
                  f"iac: {file_counts['iac']}, sca: {file_counts['sca']}, "
                  f"secrets: {file_counts['secrets']}, "
                  f"html: {file_counts['html']})", file=sys.stderr)
            print(f"Zero-Risk Fast-Path Skip: {fast_path_skipped_files} skipped", file=sys.stderr)
            print(f"Unparseable Files:        {unparseable_files} skipped", file=sys.stderr)
            print("="*70, file=sys.stderr)
        except ImportError:
            pass  # Parallel scanner not available, skip metrics

    _clock.mark("MetricsBlock")
    # Outer TOTAL spans the whole scan command: entry (before auxiliary/python collection)
    # to just before exit-code computation. Stages before `started` (AuxCollect, CollectPy)
    # are inside TOTAL but NOT inside duration_ms - that is the CLI-vs-UI boundary gap.
    _clock.report()
    if ux:
        banner.print_completion(duration_ms / 1000, len(findings),
                                sarif_path=str(args.sarif) if args.sarif else None,
                                sbom_path=sbom_path_text or None, stream=sys.stderr)

    # Exit-code parity with `tcs_cli.py`: a scan that finds something exits 1, so CI can gate
    # on either entry point. 2 stays reserved for an internal error (see the crash handler).
    # `--fail-on-critical` narrows what blocks: only Critical/High findings count.
    if args.fail_on_critical:
        blocking = [item for item in findings if item["severity"] in ("CRITICAL", "HIGH")]
    else:
        blocking = findings
    return 1 if blocking else 0


def _normalize_compare_path(value):
    return os.path.normcase(str(Path(value).resolve()))


def _normalize_cwes(value):
    if isinstance(value, dict):
        value = value.get("id", "")
    values = value if isinstance(value, list) else [value]
    cwes = set()
    for item in values:
        if isinstance(item, dict):
            item = item.get("id", "")
        text = str(item or "").upper()
        cwes.update(f"CWE-{number}" for number in re.findall(r"\bCWE[-_ ]?(\d+)\b", text))
        if text.isdigit():
            cwes.add(f"CWE-{text}")
    return sorted(cwes) if cwes else ["UNKNOWN_CWE"]


def _competitor_findings(tool, data):
    findings = []
    if tool == "semgrep":
        for item in data.get("results", []):
            metadata = item.get("extra", {}).get("metadata", {})
            cwes = _normalize_cwes(metadata.get("cwe"))
            if cwes == ["UNKNOWN_CWE"]:
                cwes = _normalize_cwes(item.get("check_id", ""))
            path = item.get("path", "")
            line = item.get("start", {}).get("line", 0)
            rule = item.get("check_id", "")
            message = item.get("extra", {}).get("message", "")
            for cwe in cwes:
                findings.append({"file": _normalize_compare_path(path), "line": line, "cwe": cwe, "rule": rule, "message": message})
    else:
        for item in data.get("results", []):
            cwes = _normalize_cwes(item.get("issue_cwe"))
            path = item.get("filename", "")
            line = item.get("line_number", 0)
            rule = item.get("test_id", "")
            message = item.get("issue_text", "")
            for cwe in cwes:
                findings.append({"file": _normalize_compare_path(path), "line": line, "cwe": cwe, "rule": rule, "message": message})
    return findings


def _run_competitor(tool, scan_path):
    executable = shutil.which(tool)
    if executable is None:
        print(f"Error: {tool} is not installed or not available on PATH.", file=sys.stderr)
        return None, None, 127
    if tool == "semgrep":
        command = [executable, "scan", "--json", "--config", "auto", str(scan_path)]
    else:
        command = [executable, "-r", "-f", "json", str(scan_path)]

    started = time.perf_counter()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    except OSError as exc:
        print(f"Error: unable to run {tool}: {exc}", file=sys.stderr)
        return None, None, 2
    duration_ms = (time.perf_counter() - started) * 1000
    try:
        data = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        detail = completed.stderr.strip() or completed.stdout.strip() or f"process exited with status {completed.returncode}"
        print(f"Error: {tool} did not return valid JSON: {detail}", file=sys.stderr)
        return None, None, 2
    return _competitor_findings(tool, data), duration_ms, 0


def _compare_findings(tcs_findings, competitor_findings, tolerance):
    matched = []
    matched_tcs = set()
    competitor_only = []
    for competitor in competitor_findings:
        candidates = [
            (index, finding) for index, finding in enumerate(tcs_findings)
            if finding["_normalized_file"] == competitor["file"]
            and finding["cwe"] == competitor["cwe"]
            and abs(finding["line"] - competitor["line"]) <= tolerance
        ]
        if candidates:
            tcs_index, finding = min(candidates, key=lambda pair: abs(pair[1]["line"] - competitor["line"]))
            matched_tcs.add(tcs_index)
            matched.append({"cwe": competitor["cwe"], "file": finding["file"], "tcs_line": finding["line"], "competitor_line": competitor["line"], "rule": competitor["rule"]})
        else:
            competitor_only.append(competitor)

    tcs_only = [finding for index, finding in enumerate(tcs_findings) if index not in matched_tcs]
    return matched, tcs_only, competitor_only


def _cwe_breakdown(matched, tcs_only, competitor_only):
    cwes = sorted({item["cwe"] for item in matched + tcs_only + competitor_only})
    return [
        {
            "cwe": cwe,
            "both": sum(item["cwe"] == cwe for item in matched),
            "tcs_only": sum(item["cwe"] == cwe for item in tcs_only),
            "competitor_only": sum(item["cwe"] == cwe for item in competitor_only),
        }
        for cwe in cwes
    ]


def _print_compare_scoreboard(tool, tcs_ms, competitor_ms, matched, tcs_only, competitor_only, breakdown):
    summary_rows = [
        ("Execution speed", f"TimeCodeSecurity {tcs_ms:.2f} ms vs {tool.title()} {competitor_ms:.2f} ms"),
        ("Matched Findings (both)", str(len(matched))),
        ("TimeCodeSecurity Exclusive Findings", str(len(tcs_only))),
        (f"{tool.title()} Only Findings", str(len(competitor_only))),
    ]
    summary_headers = ("Metric", "Result")
    summary_widths = [max(len(summary_headers[index]), *(len(row[index]) for row in summary_rows)) for index in range(len(summary_headers))]
    summary_border = "+" + "+".join("-" * (width + 2) for width in summary_widths) + "+"
    print("Comparison Scoreboard")
    print(summary_border)
    print("| " + " | ".join(summary_headers[index].ljust(summary_widths[index]) for index in range(len(summary_headers))) + " |")
    print(summary_border)
    for row in summary_rows:
        print("| " + " | ".join(row[index].ljust(summary_widths[index]) for index in range(len(summary_headers))) + " |")
    print(summary_border)
    rows = [(item["cwe"], str(item["both"]), str(item["tcs_only"]), str(item["competitor_only"])) for item in breakdown]
    headers = ("CWE", "Both", "TimeCodeSecurity only", f"{tool.title()} only")
    widths = [max(len(headers[index]), *(len(row[index]) for row in rows)) for index in range(len(headers))]
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    print("\nCWE Breakdown")
    print(border)
    print("| " + " | ".join(headers[index].ljust(widths[index]) for index in range(len(headers))) + " |")
    print(border)
    for row in rows:
        print("| " + " | ".join(row[index].ljust(widths[index]) for index in range(len(headers))) + " |")
    print(border)


def _compare(args):
    try:
        exclude_patterns = _parse_exclude_patterns(getattr(args, "exclude", None))
        templates, iac, manifests, secrets, _aux_scopes = _collect_auxiliary_files(
            args.path, exclude_patterns)

        try:
            files = _collect_files(args.path, exclude_patterns=exclude_patterns)
        except ValueError:
            if not templates and not iac and not manifests and not secrets:
                raise
            files = {}
        started = time.perf_counter()
        if files:
            tracker = TaintTracker(files=files)
            _, _, edges = tracker.analyze()
            ast_findings = _findings_for(tracker, edges)
        else:
            ast_findings = []
            tracker = None
        legacy_iac = audit_iac_files(iac)
        sca_findings = audit_sca_files(manifests)
        if sca_findings:
            tag_reachability(sca_findings, _imported_roots(tracker))
        tcs_findings = _merge_findings(ast_findings, audit_templates(templates), legacy_iac,
                                       audit_security_files(iac, legacy_findings=legacy_iac),
                                       sca_findings, audit_secret_files(secrets))
        tcs_ms = (time.perf_counter() - started) * 1000
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    for finding in tcs_findings:
        finding["_normalized_file"] = _normalize_compare_path(finding["file"])
    competitor_findings, competitor_ms, status = _run_competitor(args.vs, args.path)
    if status:
        return status

    matched, tcs_only, competitor_only = _compare_findings(tcs_findings, competitor_findings, args.tolerance)
    breakdown = _cwe_breakdown(matched, tcs_only, competitor_only)
    _print_compare_scoreboard(args.vs, tcs_ms, competitor_ms, matched, tcs_only, competitor_only, breakdown)

    report = {
        "competitor": args.vs,
        "tolerance": args.tolerance,
        "execution_ms": {"tcs": round(tcs_ms, 2), "competitor": round(competitor_ms, 2)},
        "counts": {"both": len(matched), "tcs_only": len(tcs_only), "competitor_only": len(competitor_only)},
        "cwe_breakdown": breakdown,
        "matched": matched,
        "tcs_exclusive": [{key: value for key, value in item.items() if not key.startswith("_")} for item in tcs_only],
        "competitor_only_findings": competitor_only,
    }
    if args.output_json:
        try:
            atomic_write_text(Path(args.output_json), json.dumps(report, indent=2) + "\n")
        except OSError as exc:
            print(f"Error writing comparison report: {exc}", file=sys.stderr)
            return 2
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cli.py", description="Standalone TimeCodeSecurity scanner")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="Scan a Python file or directory", epilog="Persistent policy: save defaults under a policy: block in root .tcs.yaml (CLI flags always override).")
    scan_parser.add_argument("path", type=Path, help="Python file or directory to scan")
    scan_parser.add_argument("--sarif", metavar="OUTPUT_PATH", help="Write findings as SARIF 2.1.0 JSON")
    scan_parser.add_argument("--sbom", metavar="OUTPUT_PATH",
                             help="Write the dependency inventory and its advisories as a "
                                  "CycloneDX 1.5 JSON SBOM (stdout output is unchanged)")
    scan_parser.add_argument("--fail-on-critical", action="store_true", help="Only exit 1 on a Critical or High finding (default: any finding exits 1, matching tcs_cli.py)")
    scan_parser.add_argument("--format", choices=("table", "json"), default="table", help="Output format (default: table)")
    scan_parser.add_argument(
        "--scope", choices=("all", "python", "docker", "iac", "sca", "secrets", "html"),
        default="all",
        help="Limit analysis to Python code, container images/compose, CI-CD & IaC "
             "(workflows, Kubernetes, Terraform), dependency manifests/lockfiles (SCA), "
             "config/env documents carrying credentials, "
             "or HTML templates (default: all)",
    )
    scan_parser.add_argument(
        "--with-autofix", action="store_true", default=False,
        help="Include deterministic autofix suggestions in JSON output (only for supported CWEs)",
    )
    scan_parser.add_argument(
        "--lines", metavar="START[-END][,START[-END]...]", default=None,
        help="Incremental scan: restrict findings to the given 1-indexed line ranges, e.g. --lines 4-5",
    )
    scan_parser.add_argument(
        "--diff", nargs="?", const="HEAD", default=None, metavar="REF",
        help="Report only findings on lines added or modified in the working tree versus REF "
             "(default REF: HEAD). The whole tree is still analysed, so cross-file context is "
             "never truncated. Requires a git repository",
    )
    scan_parser.add_argument(
        "--min-confidence", choices=("all", "low", "medium", "high"), default=None,
        help="Only show findings at or above this confidence level: high = an explicit "
             "source->sink flow, medium = pattern/structural match, low = heuristic comparison. "
             "`all` shows every finding. Default: clean-default starts at high across terminal, "
             "JSON and SARIF; naming a level lifts clean-default report floors. Detection is unchanged",
    )
    scan_parser.add_argument(
        "--include-js", dest="include_js", action="store_true", default=False,
        help="Also run the tree-sitter JS/TS scanner (CWE-79/CWE-95 in .js/.jsx/.ts/.tsx). "
             "Off by default so the analysis stays scoped to Python",
    )
    scan_parser.add_argument(
        "--workers", type=str, default="auto",
        help="Number of parallel worker processes for scanning. Use integer (1-64) or 'auto' (default: auto = all available CPU cores via os.cpu_count())",
    )
    scan_parser.add_argument(
        "--exclude", type=str, default=None,
        help="Comma-separated glob patterns to exclude from scanning (e.g., tests,test_*,*_test.py,migrations)",
    )
    scan_parser.add_argument(
        "--include-tests", action="store_true",
        help="Scan non-production trees (tests/, docs/, demos/, examples/, samples/, cookbook/, benchmarks/, tutorials/, migrations/) and test/demo filenames (test_*.py, *_test.py, conftest.py, demo_*.py, *_mock.py) too, and lift clean-default report floors. Directory walks "
             "prune those trees before descending by default, which is where fixtures and samples "
             "live -- and also where a hardcoded secret is classically committed, so use this flag "
             "for a full-coverage sweep. A file or directory named on the command line is always "
             "scanned in full, with or without it.",
    )
    scan_parser.add_argument(
        "--skip-non-production", action="store_true",
        help="Accepted for compatibility with scripts written before skipping became the default; "
             "it now asks for what already happens and changes nothing.",
    )
    scan_parser.add_argument(
        "--parser", choices=PARSER_MODES, default=DEFAULT_PARSER_MODE,
        help="Which reader builds the ASTs. 'hybrid' (default) = native ast.parse, with the "
             "tree-sitter rescue shield only on a file that raises SyntaxError; 'treesitter' = the "
             "tolerant tree-sitter CST reader for every file, single-process, CPython still catches "
             "what it declines; 'ast' = native ast.parse and the block-level sweep, tree-sitter "
             "never invoked",
    )
    scan_parser.add_argument(
        "--audit-all", action="store_true", default=False,
        help="Emit speculative POTENTIAL findings and non-actionable IaC notes",
    )
    scan_parser.add_argument(
        "--include-hygiene", action="store_true", default=False,
        help="Show hygiene/audit-tier findings (CSRF, SRI, cookie configuration, weak hash, "
             "diagnostic exposure, unbounded allocation, insecure umask/UUID1, mutable default) "
             "that the clean default report holds back. Detection is unchanged",
    )
    scan_parser.add_argument(
        "--include-unreachable", action="store_true", default=False,
        help="Lift the dormant dependency reachability block (UNREACHABLE_MANIFEST_ONLY) in clean-default "
             "mode. Confidence floor stays high; pass --min-confidence low or --all for LOW-confidence dormant advisories",
    )
    scan_parser.add_argument(
        "--include-vendor", action="store_true", default=False,
        help="Scan vendor/, _vendor/, third_party/ and *_pb2.py too. A directory walk prunes those "
             "vendored/auto-generated trees by default; a path named on the command line is always "
             "scanned in full",
    )
    scan_parser.add_argument(
        "--min-severity", choices=("low", "medium", "high", "critical"), default=None,
        help="Only show findings at or above this severity. Default: the clean default report starts "
             "at medium (LOW held back); naming a level keeps clean-default active for other dimensions. Detection is unchanged",
    )
    scan_parser.add_argument(
        "--all", action="store_true", default=False,
        help="Full audit: --include-hygiene --include-tests --include-vendor --include-unreachable "
             "--min-severity low --min-confidence low. Restores the complete emission set across "
             "terminal, JSON and SARIF",
    )
    compare_parser = commands.add_parser("compare", help="Compare TimeCodeSecurity findings with Semgrep or Bandit")
    compare_parser.add_argument("path", type=Path, help="Python file or directory to compare")
    compare_parser.add_argument("--vs", choices=("semgrep", "bandit"), default="semgrep", help="Competitor scanner (default: semgrep)")
    compare_parser.add_argument("--tolerance", type=int, default=5, help="Maximum line distance for a match (default: 5)")
    compare_parser.add_argument("--output-json", metavar="REPORT_PATH", help="Write detailed comparison report as JSON")
    args = parser.parse_args(argv)
    args._yaml_policy_keys = ()
    if getattr(args, "all", False):
        # CLI --all is the strongest explicit signal: it overrides any `.tcs.yaml` policy and keeps
        # the byte-identical full expansion below.
        args.include_hygiene = True
        args.include_tests = True
        args.include_vendor = True
        args.include_unreachable = True
        args.min_severity = "low"
        args.min_confidence = "low"
    if args.command == "scan":
        try:
            if not getattr(args, "all", False):
                _apply_yaml_policy(args)
            return _scan(args)
        except Exception as exc:
            # Anything unhandled is an internal error: emit the fallback artefacts and
            # exit 2 instead of dying on a traceback with an empty report.
            traceback.print_exc()
            return _scan_failure(args, exc)
    if args.tolerance < 0:
        parser.error("--tolerance must be zero or greater")
    return _compare(args)


if __name__ == "__main__":
    sys.exit(main())
