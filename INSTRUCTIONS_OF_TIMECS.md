# TimeCodeSecurity (`timecs`) - CLI and Policy Guide

## 1. Default Scan (Clean-Default Mode)

Run a standard scan on your project (use `timecs` if installed, or `python cli.py` from the repo):

    timecs scan .
    python cli.py scan .

By default, TimeCodeSecurity runs in clean-default mode so terminal tables, JSON, and SARIF reports stay focused on actionable vulnerabilities (all three formats always agree):
- Shown by default: HIGH-confidence CRITICAL and HIGH findings, HIGH-confidence exploitable MEDIUM CWEs (CWE-601, CWE-776, CWE-116, CWE-327), and HIGH-confidence REACHABLE SCA dependency advisories.
- Held back by default (still detected by the engine; zero engine FN):
  - Hygiene and noisy audit-tier CWEs: CWE-352, CWE-353, CWE-829, CWE-614, CWE-1004, CWE-1275, CWE-770, CWE-200, CWE-328, CWE-276, CWE-330, CWE-1188.
  - LOW severity findings (default min-severity is medium).
  - LOW and MEDIUM confidence findings (default min-confidence is high).
  - Dormant manifest-only SCA advisories (UNREACHABLE_MANIFEST_ONLY).
  - During directory walks: non-production folders (tests/, cookbook/, docs/, doc/, demos/, demo/, examples/, samples/, benchmarks/, tutorials/, migrations/, fixtures/, debug/), non-production filenames (test_*.py, *_test.py, *_tests.py, conftest.py, demo_*.py, *_demo.py, *_mock.py), and vendored/generated code (vendor/, _vendor/, third_party/, *_pb2.py).
- Single-file rule: if you pass a specific file path directly on the command line (for example, `timecs scan tests/test_app.py`), it is always scanned in full even without `--include-tests`.
- Every scan prints a one-line policy banner on stderr starting with: `[INF] policy -> ...`

## 2. Opt-In CLI Flags (8 Policy Commands)

### A. 4 `--include-*` Flags (Restore Hidden Categories)
- `--include-hygiene`: restores hygiene and noisy audit-tier CWEs (stays in clean-default mode; still respects active severity/confidence floors).
- `--include-tests`: includes non-production folders and test/demo filenames during directory walks, and lifts clean-default report floors.
- `--include-vendor`: includes third-party vendored folders (`vendor/`, `_vendor/`, `third_party/`) and `*_pb2.py` files during directory walks (discovery-only; report filters stay clean-default).
- `--include-unreachable`: lifts the dormant-SCA reachability block (`UNREACHABLE_MANIFEST_ONLY`). Note: stays in clean-default mode with `min-confidence=high`, so to see LOW-confidence dormant advisories, pass `--include-unreachable --min-confidence low` or `--all`.

### B. 4 Filter and Master Flags
- `--min-severity <low|medium|high|critical>`: sets the minimum severity floor (stays in clean-default mode; `--min-severity critical` keeps only CRITICAL).
- `--min-confidence <low|medium|high|all>`: sets the minimum confidence floor and lifts clean-default report floors.
- `--all`: master full-audit switch. Enables all 4 `--include-*` flags plus `--min-severity low` and `--min-confidence low`.
- `--audit-all`: legacy full-audit switch kept for backward compatibility (lifts clean-default report floors).

## 3. Ready-to-Use Examples

    # Default clean scan (back to normal clean mode)
    timecs scan .

    # Hygiene only (on top of clean-default)
    timecs scan . --include-hygiene

    # Hygiene + vendored code
    timecs scan . --include-hygiene --include-vendor

    # Dormant (unreachable) SCA including LOW-confidence advisories
    timecs scan . --include-unreachable --min-confidence low

    # Only CRITICAL findings
    timecs scan . --min-severity critical

    # Full audit (no report filters)
    timecs scan . --all

## 4. Persistent Policy in `.tcs.yaml`

Save policy options in the repository root `.tcs.yaml` under a `policy:` block (alongside existing `exclude_paths` and `rules`):

    policy:
      all: false
      include_hygiene: true
      include_tests: false
      include_vendor: false
      include_unreachable: false
      min_severity: medium
      min_confidence: high

- Precedence: explicit CLI flags always override `.tcs.yaml` values.
- Visibility: when `.tcs.yaml` activates any policy option, the banner prints `(source=.tcs.yaml: ...)`.
- Reset: remove the `policy:` block (or delete `.tcs.yaml`) to return to byte-identical clean-default mode.

## 5. Debt Baseline, Quality Gates & SCA Upgrade Plan (v3.3.3)

- Baseline: timecs scan . --write-baseline .tcs-baseline.json and timecs scan . --baseline .tcs-baseline.json
- Quality Gate: timecs scan . --fail-on high or timecs scan . --fail-on critical:0,high:5 (also in .tcs.yaml policy.fail_on)
- SCA & Wheels: Grouped SCA UPGRADE PLAN in output; binary wheels support Python 3.11-3.15
