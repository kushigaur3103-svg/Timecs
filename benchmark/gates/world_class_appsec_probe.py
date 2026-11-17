"""Gate #61 -- world-class AppSec completion: config secrets, the 96-CVE vault, CycloneDX 1.5.

TASK 18 added three capabilities beside the Python AST engine, and this gate locks all three:

* `scanners/secret_scanner.py` -- credentials in `.env`, INI, CFG, CONF, TOML, JSON, YAML and shell
  documents. Vendor shapes are proof on their own; a generic sensitive name additionally needs a
  literal of >= 16 characters, >= 2 character classes and Shannon entropy >= 3.3.
* `scanners/cve_index.py` -- the offline advisory vault grown to 96 CVEs over 55 packages, with
  per-branch `[introduced, fixed)` records so a patched maintenance branch is never condemned by
  the newest headline fix.
* `scanners/sbom.py` + `cli.py --sbom` -- a CycloneDX 1.5 JSON bill of materials built from the
  same manifest parse the audit used, with every `affects.ref` resolving to a listed component.

The contract, in ten tiers:

0. ISOLATION LAWS -- the new modules import nothing but the stdlib and their own package, and the
   CLI merge site still calls each producer exactly once.
1. SECRET BAD CASES -- every vendor family, every generic sensitive name and every service-URL
   scheme fires at the exact line, in all eleven document formats, with the exact CWE, severity
   and category. No finding ever carries the credential it found.
2. SECRET REFUSALS -- the zero-FP contract: interpolation, empty, null/boolean, a 40-hex commit
   SHA with no credential name, every placeholder word, low entropy, a single character class, a
   short value, an innocuous name, and every lockfile/template path. Each refusal is paired with
   a loud twin in the same call shape, so a quiet tree cannot hide a reader that never ran.
3. CVE VAULT -- the size band, every CVE the task names, parseable and ordered intervals, 30
   loud/quiet twins across the new packages, and 9 partial-immunity pins proving that fixing one
   advisory does not silence the next.
4. REACHABILITY -- the new distribution/import mappings proven through the real CLI: an imported
   vulnerable pin is REACHABLE/HIGH, the same pin in a dormant project is not.
5. SBOM -- CycloneDX 1.5 schema validity, referential integrity, and the semantics that make it
   honest: a range inventories version-less, an npm scope is percent-encoded, and the remedy for
   `ws 7.5.9` is 7.5.10 rather than 8.17.1.
6. CLI WIRING -- `--sbom` writes a document and changes nothing on stdout; the `secrets` scope is
   isolated in both directions; a Kubernetes YAML stays IaC even when it carries a credential;
   inline directives and global exclusions still hold.
7. PYTHON UNCHANGED -- a mixed tree with the secret reader on and off produces byte-identical
   `.py` rows, and `ast_scanner.py` / `iac_auditor.py` carry zero diff against HEAD.
8. MUTATIONS -- every decision point is blinded in turn and its own rows must move. The falsifier
   direction is measured too: removing the refusal must make the safe documents loud.
9. BUDGET -- work and peak RSS, because a lock that is slow or heavy never runs on this laptop.

Usage: python benchmark/gates/world_class_appsec_probe.py [--dump]
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
from pathlib import Path

START = time.time()
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import cli  # noqa: E402
from scanners import cve_index as CI  # noqa: E402
from scanners import sbom as SB  # noqa: E402
from scanners import sca_scanner as SCA  # noqa: E402
from scanners import secret_scanner as SS  # noqa: E402

BUDGET_SECONDS = 60.0
BUDGET_RSS_MB = 60.0

CATEGORY = "HARDCODED_SECRET_CONFIG"
SCA_CATEGORY = "SCA_VULNERABLE_DEPENDENCY"
NEW_MODULES = ("secret_scanner.py", "sbom.py")
FORBIDDEN_IMPORTS = ("ast_scanner", "cli", "iac_auditor", "cross_file_engine", "yaml", "psutil",
                     "requests", "urllib", "http", "socket", "osv_client", "manifest_parser",
                     "version_matcher", "packaging", "tomllib")
MERGE_CONTRACT = (
    ("cli.py", "audit_secret_files(secrets)"),
    ("cli.py", "build_sbom(collect_components(manifests), findings,"),
    ("cli.py", '"secrets"'),
    ("scanners/secret_scanner.py", "MIN_GENERIC_ENTROPY = 3.3"),
    ("scanners/secret_scanner.py", "MIN_GENERIC_LENGTH = 16"),
    ("scanners/sbom.py", 'SPEC_VERSION = "1.5"'),
    ("scanners/sca_scanner.py", "def collect_components("),
)


def module(*lines):
    return "".join(line + "\n" for line in lines)


def pin(source, needle):
    """The one line carrying `needle`. An ambiguous pin is a broken fixture, not a verdict."""
    hits = [index for index, line in enumerate(source.splitlines(), 1) if needle in line]
    if len(hits) != 1:
        raise AssertionError(f"pin {needle!r} matched {len(hits)} lines, expected exactly 1")
    return hits[0]


def secret_rows(findings):
    return {(item["file"], item["line"], item["cwe"], item["category"],
             item["secret_type"], item["severity"]) for item in findings}


def sca_rows(payload):
    return [item for item in payload["findings"] if item.get("category") == SCA_CATEGORY]


def cat_rows(payload):
    return [item for item in payload["findings"] if item.get("category") == CATEGORY]


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


def run_cli(argv, cwd):
    out, err = io.StringIO(), io.StringIO()
    with chdir(cwd), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    text = out.getvalue()
    start = text.find("{")
    if start < 0:
        raise AssertionError(f"cli produced no JSON (exit {code}): {text[-400:]} | "
                             f"{err.getvalue()[-400:]}")
    return code, json.loads(text[start:])


BASE_ARGV = ["scan", ".", "--format", "json", "--workers", "1", "--include-tests"]


# ── tier 1: credentials that must be loud ─────────────────────────────────
# Values are chosen to carry no placeholder word, so the refusal list cannot mute a true positive.
BAD_ENV = module(
    "# production environment",
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REALKEY",
    "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    "GH_FINE=github_pat_11ABCDEFG0abcdefghij_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    "GH_OAUTH=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    "STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    "SLACK_TOKEN=xoxb-QRSTUVWXYZ-9876543210",
    "SLACK_HOOK=https://hooks.slack.com/services/T0ABCDEFG/B0ABCDEFG/ZYXWVUTSRQPONMLKJIHGFEDCBA",
    "API_KEY=Zx9Qm2Vb7Lp4Rt8Yw1Nc",
    "SECRET_KEY=aB3dE6gH9jK2mN5pQ8rS",
    "AUTH_TOKEN=Qw7Er2Ty9Ui4Op6As8Df",
    "ACCESS_TOKEN=Mn3Bv6Cx9Zl2Kj5Hg8Fd",
    "CLIENT_SECRET=Po9Iu6Yt3Rw8Eq5Za2Xs",
    "DB_PASSWORD=Tk8Vn2Qp5Rw9Zx3Lm7Yb",
    "PRIVATE_KEY=Hj4Kl7Mn1Bv6Cx9Zq2Ws",
)
BAD_SHELL = module(
    "#!/bin/sh",
    "export PEM='-----BEGIN RSA PRIVATE KEY-----'",
    "export OPENSSH='-----BEGIN OPENSSH PRIVATE KEY-----'",
    "export EC='-----BEGIN EC PRIVATE KEY-----'",
    "export DSA='-----BEGIN DSA PRIVATE KEY-----'",
    "export PGP='-----BEGIN PGP PRIVATE KEY-----'",
    "export BARE='-----BEGIN PRIVATE KEY-----'",
)
BAD_URLS = module(
    "services:",
    "  pg: postgres://admin:Tr0ub4dorXyz@db.internal:5432/app",
    "  pg2: postgresql://admin:Tr0ub4dorXyz@db.internal:5432/app",
    "  my: mysql://admin:Tr0ub4dorXyz@db.internal:3306/app",
    "  mongo: mongodb://admin:Tr0ub4dorXyz@db.internal:27017/app",
    "  cache: redis://admin:Tr0ub4dorXyz@db.internal:6379",
    "  queue: amqp://admin:Tr0ub4dorXyz@db.internal:5672",
)
GENERIC_VALUE = "Zx9Qm2Vb7Lp4Rt8Yw1Nc"
BAD_INI = module("[svc]", "STRIPE_SECRET_KEY = " + GENERIC_VALUE)
BAD_CFG = module("[svc]", "API_KEY: " + GENERIC_VALUE)
BAD_CONF = module("API_KEY=" + GENERIC_VALUE)
BAD_TOML = module("[svc]", 'API_KEY = "' + GENERIC_VALUE + '"')
BAD_JSON = module("{", '  "API_KEY": "' + GENERIC_VALUE + '",',
                  '  "PEM": "-----BEGIN PRIVATE KEY-----"', "}")
BAD_YAML = module("svc:", "  API_KEY: " + GENERIC_VALUE)
BAD_DOTENV_PROD = module("API_KEY=" + GENERIC_VALUE)
BAD_DOTENV_SUFFIX = module("API_KEY=" + GENERIC_VALUE)

BAD_SECRET_FILES = {
    ".env": BAD_ENV,
    "deploy.sh": BAD_SHELL,
    "svc.yaml": BAD_URLS,
    "settings.ini": BAD_INI,
    "app.cfg": BAD_CFG,
    "service.conf": BAD_CONF,
    "config.toml": BAD_TOML,
    "settings.json": BAD_JSON,
    "config.yml": BAD_YAML,
    ".env.production": BAD_DOTENV_PROD,
    "app.env": BAD_DOTENV_SUFFIX,
}
# Every credential the fixtures carry. None of them may survive into a finding: a report is a
# shared artefact, and re-publishing the secret moves the leak instead of reporting it.
RAW_CREDENTIALS = (
    "AKIAIOSFODNN7REALKEY",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    "github_pat_11ABCDEFG0abcdefghij_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    "xoxb-QRSTUVWXYZ-9876543210",
    "https://hooks.slack.com/services/T0ABCDEFG/B0ABCDEFG/ZYXWVUTSRQPONMLKJIHGFEDCBA",
    "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----",
    "Tr0ub4dorXyz", GENERIC_VALUE, "aB3dE6gH9jK2mN5pQ8rS", "Qw7Er2Ty9Ui4Op6As8Df",
    "Mn3Bv6Cx9Zl2Kj5Hg8Fd", "Po9Iu6Yt3Rw8Eq5Za2Xs", "Tk8Vn2Qp5Rw9Zx3Lm7Yb",
    "Hj4Kl7Mn1Bv6Cx9Zq2Ws",
)


def expected_secret_rows():
    want = set()
    add = want.add
    env = ".env"
    for needle, label, severity in (
            ("AWS_ACCESS_KEY_ID=", "AWS Access Key ID", "HIGH"),
            ("GITHUB_TOKEN=", "GitHub Personal Access Token", "HIGH"),
            ("GH_FINE=", "GitHub Fine-Grained Token", "HIGH"),
            ("GH_OAUTH=", "GitHub OAuth Token", "HIGH"),
            ("STRIPE_KEY=", "Stripe Live Secret Key", "CRITICAL"),
            ("SLACK_TOKEN=", "Slack Token", "HIGH"),
            ("SLACK_HOOK=", "Slack Incoming Webhook", "HIGH"),
            ("API_KEY=", "Hard-coded API_KEY", "HIGH"),
            ("SECRET_KEY=", "Hard-coded SECRET_KEY", "HIGH"),
            ("AUTH_TOKEN=", "Hard-coded AUTH_TOKEN", "HIGH"),
            ("ACCESS_TOKEN=", "Hard-coded ACCESS_TOKEN", "HIGH"),
            ("CLIENT_SECRET=", "Hard-coded CLIENT_SECRET", "HIGH"),
            ("DB_PASSWORD=", "Hard-coded DB_PASSWORD", "HIGH"),
            ("PRIVATE_KEY=", "Hard-coded PRIVATE_KEY", "HIGH")):
        add((env, pin(BAD_ENV, needle), "CWE-798", CATEGORY, label, severity))
    for needle in ("BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH", "BEGIN EC ", "BEGIN DSA",
                   "BEGIN PGP", "export BARE="):
        add(("deploy.sh", pin(BAD_SHELL, needle), "CWE-798", CATEGORY,
             "PEM Private Key", "CRITICAL"))
    for needle in ("  pg:", "  pg2:", "  my:", "  mongo:", "  cache:", "  queue:"):
        add(("svc.yaml", pin(BAD_URLS, needle), "CWE-798", CATEGORY,
             "Service URL With Embedded Password", "HIGH"))
    add(("settings.ini", pin(BAD_INI, "STRIPE_SECRET_KEY"), "CWE-798", CATEGORY,
         "Hard-coded SECRET_KEY", "HIGH"))
    for path, source in (("app.cfg", BAD_CFG), ("service.conf", BAD_CONF),
                         ("config.toml", BAD_TOML), ("config.yml", BAD_YAML),
                         (".env.production", BAD_DOTENV_PROD), ("app.env", BAD_DOTENV_SUFFIX)):
        add((path, pin(source, "API_KEY"), "CWE-798", CATEGORY, "Hard-coded API_KEY", "HIGH"))
    add(("settings.json", pin(BAD_JSON, '"API_KEY"'), "CWE-798", CATEGORY,
         "Hard-coded API_KEY", "HIGH"))
    add(("settings.json", pin(BAD_JSON, '"PEM"'), "CWE-798", CATEGORY,
         "PEM Private Key", "CRITICAL"))
    return want


def check_secret_bad():
    failures = []
    found = SS.audit_secret_files(BAD_SECRET_FILES)
    want, got = expected_secret_rows(), secret_rows(found)
    for row in sorted(want - got):
        failures.append(f"missing secret row {row}")
    for row in sorted(got - want):
        failures.append(f"unexpected secret row {row}")
    serialized = json.dumps(found)
    for value in RAW_CREDENTIALS:
        if value in serialized:
            failures.append(f"a finding re-published the credential {value[:6]}...: redaction failed")
    for item in found:
        if item.get("confidence") != "HIGH":
            failures.append(f"{item['file']}:{item['line']} confidence is "
                            f"{item.get('confidence')!r}, a proven literal is HIGH")
        if not item.get("evidence") or "*" not in item["evidence"]:
            failures.append(f"{item['file']}:{item['line']} carries no redacted evidence")
        if item["secret_kind"] not in ("vendor", "generic", "service_url"):
            failures.append(f"unknown secret_kind {item['secret_kind']!r}")
    return failures, len(want), len(got)


# ── tier 2: the zero-FP refusal contract ──────────────────────────────────
COMMIT_SHA = "3f9a1c7e5b2d8046a1c9e7f3b5d208164a7c9e3f"
LOUD_URL = "postgres://admin:Tr0ub4dorXyz@db.internal:5432/app"
# (label, quiet line, loud twin line). The twin changes exactly the property under test.
REFUSALS = (
    ("interp_braces", "API_KEY=${API_KEY}", "API_KEY=" + GENERIC_VALUE),
    ("interp_bare", "API_KEY=$API_KEY", "API_KEY=" + GENERIC_VALUE),
    ("interp_shell", "API_KEY=${SECRET_KEY:-fallback}", "API_KEY=" + GENERIC_VALUE),
    ("empty_quotes", 'API_KEY=""', "API_KEY=" + GENERIC_VALUE),
    ("empty_single", "API_KEY=''", "API_KEY=" + GENERIC_VALUE),
    ("empty_bare", "API_KEY=", "API_KEY=" + GENERIC_VALUE),
    ("null_literal", "API_KEY=null", "API_KEY=" + GENERIC_VALUE),
    ("none_literal", "API_KEY=None", "API_KEY=" + GENERIC_VALUE),
    ("true_literal", "API_KEY=true", "API_KEY=" + GENERIC_VALUE),
    ("false_literal", "API_KEY=false", "API_KEY=" + GENERIC_VALUE),
    ("yaml_nil", "API_KEY=~", "API_KEY=" + GENERIC_VALUE),
    ("undefined", "API_KEY=undefined", "API_KEY=" + GENERIC_VALUE),
    ("commit_sha_unnamed", "COMMIT=" + COMMIT_SHA, "API_KEY=" + COMMIT_SHA),
    ("ph_example", "API_KEY=exampleexampleexample", "API_KEY=" + GENERIC_VALUE),
    ("ph_changeme", "API_KEY=changeme1234567890", "API_KEY=" + GENERIC_VALUE),
    ("ph_placeholder", "API_KEY=placeholder_value_1", "API_KEY=" + GENERIC_VALUE),
    ("ph_dummy", "API_KEY=dummy_dummy_dummy", "API_KEY=" + GENERIC_VALUE),
    ("ph_test", "API_KEY=test_test_test_test", "API_KEY=" + GENERIC_VALUE),
    ("ph_sample", "API_KEY=sample_sample_sample", "API_KEY=" + GENERIC_VALUE),
    ("ph_your", "API_KEY=your_api_key_here", "API_KEY=" + GENERIC_VALUE),
    ("ph_xxxx", "API_KEY=xxxxxxxxxxxxxxxx", "API_KEY=" + GENERIC_VALUE),
    ("ph_digits", "API_KEY=1234561234561234", "API_KEY=" + GENERIC_VALUE),
    ("ph_password", "DB_PASSWORD=passwordpassword", "DB_PASSWORD=Tk8Vn2Qp5Rw9Zx3Lm7Yb"),
    ("ph_secret", "CLIENT_SECRET=secretsecretsecret", "CLIENT_SECRET=Po9Iu6Yt3Rw8Eq5Za2Xs"),
    ("low_entropy", "API_KEY=aaaaaaaaaaaaaaaaaaaa", "API_KEY=" + GENERIC_VALUE),
    ("single_class", "API_KEY=abcdefghijklmnopqrst", "API_KEY=" + GENERIC_VALUE),
    ("fifteen_chars", "API_KEY=Zx9Qm2Vb7Lp4Rt8", "API_KEY=Zx9Qm2Vb7Lp4Rt8Y"),
    ("innocuous_name", "AWS_REGION=" + GENERIC_VALUE, "API_KEY=" + GENERIC_VALUE),
    ("innocuous_level", "LOG_LEVEL=" + GENERIC_VALUE, "API_KEY=" + GENERIC_VALUE),
    ("aws_docs_example", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
     "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REALKEY"),
    ("url_placeholder", "DB_URL=postgres://admin:changeme@db.internal:5432/app",
     "DB_URL=" + LOUD_URL),
    ("url_interpolation", "DB_URL=postgres://admin:${PG_PASS}@db.internal:5432/app",
     "DB_URL=" + LOUD_URL),
    ("url_short_password", "DB_URL=postgres://admin:abc@db.internal:5432/app",
     "DB_URL=" + LOUD_URL),
    ("url_no_password", "DB_URL=postgres://db.internal:5432/app", "DB_URL=" + LOUD_URL),
    ("url_empty_password", "DB_URL=postgres://admin:@db.internal:5432/app", "DB_URL=" + LOUD_URL),
)
REFUSAL_FILES = {f"r{index:02d}.env": module(quiet)
                 for index, (_label, quiet, _loud) in enumerate(REFUSALS)}
TWIN_FILES = {f"r{index:02d}.env": module(loud)
              for index, (_label, _quiet, loud) in enumerate(REFUSALS)}
# A real credential in a document that exists to hold fake values, or in a resolved dependency
# graph, is still not a finding: the path refusal is part of the contract, not a courtesy.
REFUSED_PATHS = (
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "poetry.lock", "pipfile.lock",
    "cargo.lock", "gemfile.lock", "composer.lock", "pnpm-lock.yaml",
    ".env.example", ".env.sample", "config.template", "settings.sample", "app.example",
)
REFUSED_PATH_FILES = {path: module("API_KEY=" + GENERIC_VALUE) for path in REFUSED_PATHS}
# Three values that every OTHER rule admits -- vendor shape, a 6+ character URL password, and a
# generic literal clearing both the length and the entropy floor. Only `is_refused` holds them
# quiet, so blinding it must turn all three loud, one per detection family.
REFUSAL_PROOF_FILES = {
    "proof_vendor.env": module("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
    "proof_url.env": module("DB_URL=postgres://admin:changeme@db.internal:5432/app"),
    "proof_generic.env": module("API_KEY=changeme1234567890"),
}


def check_secret_refusals():
    failures = []
    leaked = SS.audit_secret_files(REFUSAL_FILES)
    for item in leaked:
        failures.append(f"a refused value went loud: {item['file']} {item['secret_type']}")
    for index, (label, quiet, loud) in enumerate(REFUSALS):
        twins = SS.audit_secret_files({f"r{index:02d}.env": module(loud)})
        if not twins:
            failures.append(f"{label}: the loud twin {loud!r} is quiet too, so the refusal "
                            f"cannot be told from a reader that never ran")
    path_leaks = SS.audit_secret_files(REFUSED_PATH_FILES)
    for item in path_leaks:
        failures.append(f"a lockfile/template path was read: {item['file']}")
    proof_leaks = SS.audit_secret_files(REFUSAL_PROOF_FILES)
    if proof_leaks:
        failures.append(f"a refusal-only proof value went loud: "
                        f"{sorted(item['file'] for item in proof_leaks)}")
    for path in REFUSED_PATHS:
        if SS.is_secret_path(path):
            failures.append(f"is_secret_path claims the refused path {path}")
    for path in (".env", ".env.local", ".env.production", "app.env", "a.ini", "a.cfg", "a.conf",
                 "a.toml", "a.json", "a.yaml", "a.yml", "a.sh"):
        if not SS.is_secret_path(path):
            failures.append(f"is_secret_path refuses the owned format {path}")
    for path in ("main.py", "README.md", "Dockerfile", "notes.txt"):
        if SS.is_secret_path(path):
            failures.append(f"is_secret_path claims a document it does not own: {path}")
    # The two independent generic floors, measured on the value alone.
    if SS.shannon_entropy("abcdefghijklmnopqrst") < SS.MIN_GENERIC_ENTROPY:
        failures.append("the single-class fixture no longer clears the entropy floor, so tier 2 "
                        "would not be testing the character-class rule")
    if SS._character_classes("abcdefghijklmnopqrst") != 1:
        failures.append("the single-class fixture spans more than one class")
    if SS._character_classes(GENERIC_VALUE) < 2:
        failures.append("the loud generic fixture spans fewer than two classes")
    if not SS.is_refused(COMMIT_SHA) or SS.is_refused(COMMIT_SHA, named=True):
        failures.append("the commit-SHA refusal is not name-conditional")
    return failures, len(REFUSALS), len(REFUSED_PATHS)


# ── tier 3: the expanded offline vault ────────────────────────────────────
REQUIRED_CVES = {
    "fastapi": ("CVE-2024-24762",), "gunicorn": ("CVE-2024-1135", "CVE-2024-6827"),
    "tornado": ("CVE-2023-28370", "CVE-2024-52804"), "celery": ("CVE-2021-23727",),
    "sqlalchemy": ("CVE-2019-7164",), "lxml": ("CVE-2021-43818", "CVE-2022-2309"),
    "pyjwt": ("CVE-2022-29217",), "python-jose": ("CVE-2024-33663", "CVE-2024-33664"),
    "authlib": ("CVE-2024-37568",), "ecdsa": ("CVE-2024-23342",),
    "pycryptodome": ("CVE-2023-52323",), "gitpython": ("CVE-2023-40590", "CVE-2024-22190"),
    "ansible": ("CVE-2023-5764",), "mlflow": ("CVE-2024-27132", "CVE-2024-37059"),
    "gradio": ("CVE-2024-4325", "CVE-2024-47872"),
    "langchain": ("CVE-2023-46229", "CVE-2024-28088"),
    "transformers": ("CVE-2024-3568", "CVE-2024-11392"),
    "torch": ("CVE-2024-31580", "CVE-2024-5480"), "numpy": ("CVE-2021-41496",),
    "setuptools": ("CVE-2022-40897", "CVE-2024-6345"), "pip": ("CVE-2023-5752",),
    "urllib3": ("CVE-2023-43804",), "requests": ("CVE-2024-35195",),
    "django": ("CVE-2024-39329", "CVE-2024-45230"), "jinja2": ("CVE-2024-34064",),
    "werkzeug": ("CVE-2024-49767",), "aiohttp": ("CVE-2024-30251", "CVE-2024-52304"),
    "next": ("CVE-2024-34351", "CVE-2024-46982"),
    "vite": ("CVE-2024-23331", "CVE-2024-45812"), "webpack": ("CVE-2023-28154",),
    "tar": ("CVE-2024-28863",), "ws": ("CVE-2024-37890",),
    "node-forge": ("CVE-2022-24771",), "qs": ("CVE-2022-24999",),
    "semver": ("CVE-2022-25883",), "got": ("CVE-2022-33987",),
}
# (ecosystem, package, loud pin, quiet pin). The quiet pin is at or above every fix the loud
# pin was vulnerable to, so the pair proves the interval arithmetic rather than a name match.
VAULT_TWINS = (
    ("pypi", "fastapi", "0.109.0", "0.109.1"), ("pypi", "gunicorn", "21.2.0", "22.0.0"),
    ("pypi", "tornado", "6.3.1", "6.4.2"), ("pypi", "celery", "5.2.1", "5.2.2"),
    ("pypi", "sqlalchemy", "1.2.17", "1.2.18"), ("pypi", "lxml", "4.6.4", "4.9.1"),
    ("pypi", "pyjwt", "2.3.0", "2.4.0"), ("pypi", "python-jose", "3.3.0", "3.4.0"),
    ("pypi", "authlib", "1.3.0", "1.3.1"), ("pypi", "ecdsa", "0.18.0", "0.19.0"),
    ("pypi", "pycryptodome", "3.19.0", "3.19.1"), ("pypi", "gitpython", "3.1.30", "3.1.41"),
    ("pypi", "ansible", "8.5.0", "8.6.0"), ("pypi", "mlflow", "2.10.0", "2.12.1"),
    ("pypi", "gradio", "4.30.0", "5.0.0"), ("pypi", "langchain", "0.0.300", "0.1.11"),
    ("pypi", "transformers", "4.37.0", "4.48.0"), ("pypi", "torch", "2.1.0", "2.2.0"),
    ("pypi", "numpy", "1.21.0", "1.22.0"), ("pypi", "setuptools", "65.5.0", "70.0.0"),
    ("pypi", "pip", "23.2.1", "23.3"),
    ("npm", "next", "13.3.0", "14.2.10"), ("npm", "vite", "5.0.11", "5.4.6"),
    ("npm", "webpack", "5.75.0", "5.76.0"), ("npm", "tar", "6.2.0", "6.2.1"),
    ("npm", "ws", "7.5.9", "7.5.10"), ("npm", "node-forge", "1.2.1", "1.3.0"),
    ("npm", "qs", "6.9.6", "6.9.7"), ("npm", "semver", "7.5.1", "7.5.2"),
    ("npm", "got", "11.8.3", "11.8.5"),
)
# A pin that fixes the first advisory but not the second: the matcher must keep the second loud.
PARTIAL_IMMUNITY = (
    ("pypi", "tornado", "6.3.2", ("CVE-2024-52804",)),
    ("pypi", "langchain", "0.0.325", ("CVE-2024-28088",)),
    ("pypi", "gitpython", "3.1.35", ("CVE-2024-22190",)),
    ("pypi", "lxml", "4.6.5", ("CVE-2022-2309",)),
    ("pypi", "mlflow", "2.11.0", ("CVE-2024-37059",)),
    ("pypi", "gradio", "4.31.4", ("CVE-2024-47872",)),
    ("pypi", "setuptools", "65.5.1", ("CVE-2024-6345",)),
    ("pypi", "transformers", "4.38.0", ("CVE-2024-11392",)),
    ("npm", "next", "13.5.7", ("CVE-2024-34351",)),
)
IMPORT_MAP = (
    ("pyjwt", ("jwt",)), ("python-jose", ("jose",)), ("gitpython", ("git",)),
    ("pycryptodome", ("Crypto",)), ("scikit-learn", ("sklearn",)), ("pyyaml", ("yaml",)),
    ("pillow", ("PIL",)), ("beautifulsoup4", ("bs4",)), ("python-dateutil", ("dateutil",)),
    ("lxml", ("lxml",)), ("sqlalchemy", ("sqlalchemy",)), ("ecdsa", ("ecdsa",)),
    ("authlib", ("authlib",)), ("mlflow", ("mlflow",)), ("gradio", ("gradio",)),
    ("langchain", ("langchain",)), ("transformers", ("transformers",)), ("torch", ("torch",)),
    ("numpy", ("numpy",)), ("setuptools", ("setuptools",)), ("pip", ("pip",)),
    ("ansible", ("ansible",)), ("celery", ("celery",)), ("tornado", ("tornado",)),
    ("gunicorn", ("gunicorn",)), ("fastapi", ("fastapi",)),
)


def manifest_for(ecosystem, package, version):
    if ecosystem == "pypi":
        return {"requirements.txt": module(f"{package}=={version}")}
    return {"package.json": '{"dependencies": {"%s": "%s"}}' % (package, version)}


def check_vault():
    failures = []
    facts = {}
    distinct, packages, records = set(), set(), 0
    for ecosystem, table in (("pypi", CI.PYPI_ADVISORIES), ("npm", CI.NPM_ADVISORIES)):
        for package, advisories in table.items():
            packages.add((ecosystem, package))
            for advisory in advisories:
                records += 1
                distinct.add(advisory[0])
                cve, cwe, severity, fixed, introduced, summary = advisory
                if not re.match(r"^CVE-\d{4}-\d+$", cve):
                    failures.append(f"{package}: malformed CVE id {cve!r}")
                if not re.match(r"^CWE-\d+$", cwe):
                    failures.append(f"{package}/{cve}: malformed root CWE {cwe!r}")
                if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    failures.append(f"{package}/{cve}: unknown severity {severity!r}")
                if not summary:
                    failures.append(f"{package}/{cve}: no advisory summary")
                fixed_key = CI.parse_version(fixed)
                if fixed_key is None:
                    failures.append(f"{package}/{cve}: unparseable fix {fixed!r}")
                    continue
                if introduced:
                    introduced_key = CI.parse_version(introduced)
                    if introduced_key is None:
                        failures.append(f"{package}/{cve}: unparseable introduced {introduced!r}")
                    elif CI.compare_versions(introduced_key, fixed_key) >= 0:
                        failures.append(f"{package}/{cve}: introduced {introduced} is not below "
                                        f"fixed {fixed}, so the interval is empty")
    facts["cves"], facts["packages"], facts["records"] = len(distinct), len(packages), records
    if not 85 <= len(distinct) <= 100:
        failures.append(f"the vault holds {len(distinct)} CVEs, outside the 85-100 band")
    if len(packages) < 45:
        failures.append(f"the vault covers {len(packages)} packages, fewer than 45")
    for package, cves in sorted(REQUIRED_CVES.items()):
        ecosystem = "npm" if package in CI.NPM_ADVISORIES else "pypi"
        have = {item[0] for item in CI.advisories_for(ecosystem, package)}
        for cve in cves:
            if cve not in have:
                failures.append(f"the task's {package} advisory {cve} is not in the vault")
    for dist, expected in IMPORT_MAP:
        got = CI.import_roots_for(dist)
        if got != expected:
            failures.append(f"import map {dist} -> {got}, expected {expected}")
    for ecosystem, package, loud, quiet in VAULT_TWINS:
        loud_rows = SCA.audit_sca_files(manifest_for(ecosystem, package, loud))
        if len(loud_rows) != 1:
            failures.append(f"{package}=={loud} produced {len(loud_rows)} rows, expected 1")
            continue
        if not loud_rows[0]["cves"]:
            failures.append(f"{package}=={loud} is loud with no CVE")
        quiet_rows = SCA.audit_sca_files(manifest_for(ecosystem, package, quiet))
        if quiet_rows:
            failures.append(f"{package}=={quiet} is at or above the fix but still loud: "
                            f"{[item['cves'] for item in quiet_rows]}")
    for ecosystem, package, version, expected in PARTIAL_IMMUNITY:
        rows = SCA.audit_sca_files(manifest_for(ecosystem, package, version))
        got = tuple(rows[0]["cves"]) if len(rows) == 1 else ()
        if got != tuple(sorted(expected)):
            failures.append(f"{package}=={version} carries {got}, expected "
                            f"{tuple(sorted(expected))}: one fix must not silence the next")
    # A multi-branch advisory: every patched branch is quiet, every branch below its own fix loud.
    for quiet, loud in (("5.2.4", "5.2.3"), ("6.2.3", "6.2.2"), ("7.5.10", "7.5.9"),
                        ("8.17.1", "8.17.0")):
        if SCA.audit_sca_files(manifest_for("npm", "ws", quiet)):
            failures.append(f"ws {quiet} is a patched branch but went loud")
        if not SCA.audit_sca_files(manifest_for("npm", "ws", loud)):
            failures.append(f"ws {loud} is below its branch fix but stayed quiet")
    return failures, facts


# ── tier 4: reachability on the new distribution/import mappings ──────────
REACH_CASES = (
    ("pyjwt", "2.3.0", "jwt", module("import jwt", "", "", "def decode(token):",
                                    "    return jwt.decode(token, options={'verify': False})")),
    ("gitpython", "3.1.30", "git", module("import git", "", "", "def clone(url):",
                                         "    return git.Repo.clone_from(url, '/tmp/x')")),
    ("pycryptodome", "3.19.0", "Crypto", module("from Crypto.Cipher import AES", "", "",
                                                "def cipher(key):", "    return AES.new(key)")),
    ("python-jose", "3.3.0", "jose", module("from jose import jwt", "", "", "def sign(payload):",
                                            "    return jwt.encode(payload, 'k')")),
)
DORMANT_APP = module("import json", "", "", "def load(text):", "    return json.loads(text)")
NOT_PROOF_APP = module("import json", "", "", "def load(text):",
                       "    # jwt is mentioned here but never imported",
                       "    return json.loads(text)")


def check_reachability():
    failures = []
    facts = {}
    with tempfile.TemporaryDirectory(prefix="tcs_t18_reach_") as tmp:
        root = Path(tmp)
        for package, version, _root_name, app in REACH_CASES:
            loud_tree = root / (package + "_loud")
            quiet_tree = root / (package + "_quiet")
            false_tree = root / (package + "_false")
            write_tree(loud_tree, {"requirements.txt": module(f"{package}=={version}"),
                                   "app.py": app})
            write_tree(quiet_tree, {"requirements.txt": module(f"{package}=={version}"),
                                    "app.py": DORMANT_APP})
            write_tree(false_tree, {"requirements.txt": module(f"{package}=={version}"),
                                    "app.py": NOT_PROOF_APP})
            for label, tree, want in (("loud", loud_tree, ("REACHABLE", "HIGH")),
                                      ("quiet", quiet_tree, ("UNREACHABLE_MANIFEST_ONLY", "LOW")),
                                      ("false", false_tree, ("UNREACHABLE_MANIFEST_ONLY", "LOW"))):
                _code, payload = run_cli(BASE_ARGV, tree)
                rows = sca_rows(payload)
                if len(rows) != 1:
                    failures.append(f"{package}/{label}: {len(rows)} SCA rows, expected 1")
                    continue
                got = (rows[0]["reachability"], rows[0]["confidence"])
                facts[f"{package}_{label}"] = got
                if got != want:
                    failures.append(f"{package}/{label}: reachability {got}, expected {want}")
    return failures, facts


# ── tier 5: CycloneDX 1.5 ─────────────────────────────────────────────────
SBOM_FILES = {
    "requirements.txt": module("pyyaml==5.3.1", "requests>=2.0", "pyjwt==2.4.0"),
    "package.json": '{"dependencies": {"ws": "7.5.9", "lodash": "^4.17.20", '
                    '"@scope/pkg": "1.0.0", "next": "14.2.10"}}',
}
UUID_RE = re.compile(r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
STAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
# An npm scope is a purl namespace segment, so `pkg:npm/%40scope/pkg@1.0.0` carries two slashes.
PURL_RE = re.compile(r"^pkg:(pypi|npm)/(?:[^/@\s]+/)?[^/@\s]+(?:@[^/@\s]+)?$")
SEVERITY_WORDS = ("critical", "high", "medium", "low", "none", "unknown")
REACH_WORDS = ("REACHABLE", "UNREACHABLE_MANIFEST_ONLY")


def validate_cyclonedx(doc):
    """Schema and referential integrity, checked as data rather than trusted from the builder."""
    failures = []
    if doc.get("bomFormat") != "CycloneDX":
        failures.append(f"bomFormat is {doc.get('bomFormat')!r}")
    if doc.get("specVersion") != "1.5":
        failures.append(f"specVersion is {doc.get('specVersion')!r}")
    if not UUID_RE.match(str(doc.get("serialNumber", ""))):
        failures.append(f"serialNumber {doc.get('serialNumber')!r} is not a urn:uuid")
    if not isinstance(doc.get("version"), int) or doc["version"] < 1:
        failures.append(f"version is {doc.get('version')!r}, not a positive integer")
    metadata = doc.get("metadata") or {}
    if not STAMP_RE.match(str(metadata.get("timestamp", ""))):
        failures.append(f"metadata.timestamp {metadata.get('timestamp')!r} is not UTC ISO-8601")
    tools = metadata.get("tools") or []
    if not tools or not all(item.get("name") for item in tools):
        failures.append("metadata.tools names no tool")
    root = metadata.get("component") or {}
    if root.get("type") != "application" or not root.get("bom-ref") or not root.get("name"):
        failures.append(f"metadata.component is not a named application: {root}")
    components = doc.get("components")
    if not isinstance(components, list):
        failures.append("components is not a list")
        return failures
    refs = set()
    for item in components:
        ref = item.get("bom-ref")
        if item.get("type") != "library":
            failures.append(f"component {ref} type is {item.get('type')!r}")
        if not ref or ref != item.get("purl"):
            failures.append(f"component bom-ref {ref!r} does not equal its purl {item.get('purl')!r}")
        if ref in refs:
            failures.append(f"duplicate component bom-ref {ref}")
        refs.add(ref)
        if not PURL_RE.match(str(item.get("purl", ""))):
            failures.append(f"malformed purl {item.get('purl')!r}")
        if not item.get("name"):
            failures.append(f"component {ref} has no name")
        if "version" in item and not item["version"]:
            failures.append(f"component {ref} carries an empty version instead of omitting it")
        if not any(prop.get("name") == "tcs:manifest" for prop in item.get("properties") or []):
            failures.append(f"component {ref} carries no manifest provenance")
    root_ref = root.get("bom-ref")
    known = refs | {root_ref}
    for item in doc.get("vulnerabilities") or []:
        cve = item.get("id")
        if not re.match(r"^CVE-\d{4}-\d+$", str(cve)):
            failures.append(f"vulnerability id {cve!r} is not a CVE")
        source = item.get("source") or {}
        if source.get("name") != "NVD" or not str(source.get("url", "")).endswith(str(cve)):
            failures.append(f"{cve}: source is not an NVD detail link: {source}")
        cwes = item.get("cwes")
        if not isinstance(cwes, list) or not cwes or not all(
                isinstance(number, int) and number > 0 for number in cwes):
            failures.append(f"{cve}: cwes {cwes!r} is not a non-empty list of integers")
        ratings = item.get("ratings") or []
        if not ratings or any(rate.get("severity") not in SEVERITY_WORDS for rate in ratings):
            failures.append(f"{cve}: ratings {ratings!r} carry no valid severity")
        affects = item.get("affects") or []
        if not affects:
            failures.append(f"{cve}: affects nothing")
        for affect in affects:
            if affect.get("ref") not in refs:
                failures.append(f"{cve}: affects.ref {affect.get('ref')!r} is not a component")
        properties = {prop["name"]: prop["value"] for prop in item.get("properties") or []}
        if properties.get("tcs:reachability") not in REACH_WORDS:
            failures.append(f"{cve}: reachability property is "
                            f"{properties.get('tcs:reachability')!r}")
        if not item.get("description"):
            failures.append(f"{cve}: no description")
    for dependency in doc.get("dependencies") or []:
        if dependency.get("ref") not in known:
            failures.append(f"dependencies.ref {dependency.get('ref')!r} resolves to nothing")
        for child in dependency.get("dependsOn") or []:
            if child not in refs:
                failures.append(f"dependsOn {child!r} is not a component")
    if root_ref not in {item.get("ref") for item in doc.get("dependencies") or []}:
        failures.append("the root component has no dependencies entry")
    if json.loads(json.dumps(doc)) != doc:
        failures.append("the document does not survive a JSON round trip")
    return failures


def check_sbom():
    failures = []
    facts = {}
    components = SCA.collect_components(SBOM_FILES)
    findings = SCA.audit_sca_files(SBOM_FILES)
    doc = SB.build_sbom(components, findings, root_name="demo")
    failures += validate_cyclonedx(doc)
    by_purl = {item["purl"]: item for item in doc["components"]}
    facts["components"] = len(by_purl)
    facts["vulnerabilities"] = len(doc["vulnerabilities"])
    # An exact pin carries its version; a range does not invent one.
    for purl, version in (("pkg:pypi/pyyaml@5.3.1", "5.3.1"), ("pkg:npm/ws@7.5.9", "7.5.9"),
                          ("pkg:npm/%40scope/pkg@1.0.0", "1.0.0")):
        if purl not in by_purl:
            failures.append(f"missing component {purl}")
        elif by_purl[purl].get("version") != version:
            failures.append(f"{purl} version is {by_purl[purl].get('version')!r}")
    for purl in ("pkg:pypi/requests", "pkg:npm/lodash"):
        if purl not in by_purl:
            failures.append(f"a range spec was not inventoried as {purl}")
        elif "version" in by_purl[purl]:
            failures.append(f"{purl} invented a version for a range spec")
    if "pkg:npm/@scope/pkg@1.0.0" in by_purl:
        failures.append("an npm scope was not percent-encoded in the purl")
    # A patched pin is inventoried but never condemned.
    if "pkg:pypi/pyjwt@2.4.0" not in by_purl:
        failures.append("a patched pin was dropped from the inventory")
    if "pkg:npm/next@14.2.10" not in by_purl:
        failures.append("a patched npm pin was dropped from the inventory")
    condemned = {item["id"] for item in doc["vulnerabilities"]}
    facts["cves"] = sorted(condemned)
    for finding in findings:
        for cve in finding["cves"]:
            if cve not in condemned:
                failures.append(f"{cve} is in the report but not in the SBOM")
    if any(cve in condemned for cve in ("CVE-2022-29217", "CVE-2024-34351", "CVE-2024-46982")):
        failures.append(f"a patched pin was condemned: {sorted(condemned)}")
    # The remedy is the nearest fix on the component's own branch, not the newest fix anywhere.
    ws = [item for item in doc["vulnerabilities"] if item["id"] == "CVE-2024-37890"]
    if len(ws) != 1:
        failures.append(f"expected one ws vulnerability, got {len(ws)}")
    else:
        properties = {prop["name"]: prop["value"] for prop in ws[0]["properties"]}
        facts["ws_fix"] = properties.get("tcs:fixed_version")
        if properties.get("tcs:fixed_version") != "7.5.10":
            failures.append(f"ws 7.5.9 remedy is {properties.get('tcs:fixed_version')!r}, "
                            f"expected the 7.x branch fix 7.5.10")
        if ws[0]["affects"] != [{"ref": "pkg:npm/ws@7.5.9"}]:
            failures.append(f"ws vulnerability affects {ws[0]['affects']}")
    pyyaml = [item for item in doc["vulnerabilities"] if item["id"] == "CVE-2020-14343"]
    if not pyyaml or 502 not in pyyaml[0]["cwes"]:
        failures.append("the pyyaml vulnerability lost its root CWE-502")
    # Reachability travels as a property and upgrades when the import proof arrives.
    before = {item["id"]: {prop["name"]: prop["value"] for prop in item["properties"]}
              ["tcs:reachability"] for item in doc["vulnerabilities"]}
    SCA.tag_reachability(findings, {"yaml": ("app.py", 1)})
    after_doc = SB.build_sbom(components, findings, root_name="demo")
    after = {item["id"]: {prop["name"]: prop["value"] for prop in item["properties"]}
             ["tcs:reachability"] for item in after_doc["vulnerabilities"]}
    facts["reach_before"] = before.get("CVE-2020-14343")
    facts["reach_after"] = after.get("CVE-2020-14343")
    if before.get("CVE-2020-14343") != "UNREACHABLE_MANIFEST_ONLY":
        failures.append("an unproven pin was exported as reachable")
    if after.get("CVE-2020-14343") != "REACHABLE":
        failures.append("the import proof did not reach the SBOM")
    if after.get("CVE-2024-37890") != "UNREACHABLE_MANIFEST_ONLY":
        failures.append("an npm pin was upgraded by a Python import proof")
    failures += validate_cyclonedx(after_doc)
    # One component per coordinate, even when two manifests declare it.
    doubled = SB.build_sbom(SCA.collect_components({"requirements.txt": module("pyyaml==5.3.1"),
                                                    "pyproject.toml": module(
                                                        "[project]", 'name = "d"',
                                                        "dependencies = [", '  "pyyaml==5.3.1",',
                                                        "]")}), [], root_name="demo")
    if len(doubled["components"]) != 1:
        failures.append(f"the same coordinate was listed {len(doubled['components'])} times")
    elif len([prop for prop in doubled["components"][0]["properties"]
              if prop["name"] == "tcs:manifest"]) != 2:
        failures.append("a coordinate declared twice lost one manifest provenance line")
    # A finding whose component the inventory missed must still resolve, never dangle.
    orphan = SB.build_sbom([], findings, root_name="demo")
    failures += validate_cyclonedx(orphan)
    if not orphan["components"]:
        failures.append("an empty inventory dropped the affected components entirely")
    return failures, facts


# ── tier 6: CLI wiring ────────────────────────────────────────────────────
K8S_WITH_CREDENTIAL = module(
    "apiVersion: v1",
    "kind: Pod",
    "metadata:",
    "  name: demo",
    "spec:",
    "  containers:",
    "    - name: app",
    "      image: nginx:1.25",
    "      env:",
    "        - name: API_KEY",
    "          value: " + GENERIC_VALUE,
)
PLAIN_CONFIG = module("database:", "  host: localhost", "  privileged: true")
WIRE_FILES = {
    ".env": BAD_ENV,
    "requirements.txt": module("pyyaml==5.3.1"),
    "package.json": '{"dependencies": {"lodash": "4.17.20"}}',
    "app.py": module("import hashlib", "import yaml", "", "", "def load(text):",
                     "    return yaml.safe_load(text)", "", "", "def digest(text):",
                     "    return hashlib.md5(text).hexdigest()"),
    "Dockerfile": module("FROM python:3.12-slim", "USER 1000", "CMD [\"python\"]"),
    "k8s/pod.yaml": K8S_WITH_CREDENTIAL,
    "config/settings.yaml": PLAIN_CONFIG,
}
FORMAT_FILES = {
    ".env": BAD_DOTENV_PROD, ".env.production": BAD_DOTENV_PROD, "app.env": BAD_DOTENV_SUFFIX,
    "settings.ini": BAD_INI, "app.cfg": BAD_CFG, "service.conf": BAD_CONF,
    "config.toml": BAD_TOML, "settings.json": BAD_JSON, "config.yaml": BAD_YAML,
    "config.yml": BAD_YAML, "deploy.sh": module("export API_KEY=" + GENERIC_VALUE),
    "yarn.lock": module("API_KEY=" + GENERIC_VALUE),
    "Cargo.lock": module("API_KEY=" + GENERIC_VALUE),
    "pnpm-lock.yaml": module("API_KEY: " + GENERIC_VALUE),
    ".env.example": module("API_KEY=" + GENERIC_VALUE),
    "config.template": module("API_KEY=" + GENERIC_VALUE),
}


def check_wiring():
    failures = []
    facts = {}
    with tempfile.TemporaryDirectory(prefix="tcs_t18_wire_") as tmp:
        # The SBOM and the format corpus are SIBLINGS of the scanned tree. Written inside it they
        # would themselves be discovered as config documents and inflate every later count.
        root = Path(tmp)
        tree = root / "main"
        format_tree = root / "formats"
        write_tree(tree, WIRE_FILES)
        _code, payload = run_cli(BASE_ARGV, tree)
        facts["files"] = payload["scanned_files_by_scope"]
        facts["scopes"] = payload["findings_by_scope"]
        if set(payload["findings_by_scope"]) != set(cli.SCOPE_ORDER):
            failures.append("findings_by_scope keys drifted from SCOPE_ORDER")
        if "secrets" not in cli.SCOPE_ORDER:
            failures.append("SCOPE_ORDER has no secrets bucket")
        want_files = {"python": 1, "docker": 1, "iac": 1, "sca": 2, "secrets": 2, "html": 0}
        if payload["scanned_files_by_scope"] != want_files:
            failures.append(f"discovery is {payload['scanned_files_by_scope']}, expected "
                            f"{want_files}: a Kubernetes YAML must stay IaC and a plain config "
                            f"YAML must fall through to the secret reader")
        if payload["scope_breakdown"]["secrets"] != {"discovered": 2, "scanned": 2}:
            failures.append(f"secrets scope_breakdown is {payload['scope_breakdown']['secrets']}")
        rows = cat_rows(payload)
        if len(rows) != 14:
            failures.append(f"the mixed tree emitted {len(rows)} secret rows, expected the 14 "
                            f"from .env alone")
        if any(item["file"] != ".env" for item in rows):
            failures.append(f"a credential outside .env was reported: "
                            f"{sorted({item['file'] for item in rows})}")
        if any(item["file"] == "k8s/pod.yaml" for item in rows):
            failures.append("a Kubernetes manifest was read as a config secret document")
        # --sbom writes a document and leaves stdout exactly as it was.
        sbom_path = root / "bom.json"
        _code, with_sbom = run_cli(BASE_ARGV + ["--sbom", str(sbom_path)], tree)
        if not sbom_path.is_file():
            failures.append("--sbom wrote no file")
        else:
            document = json.loads(sbom_path.read_text(encoding="utf-8"))
            failures += validate_cyclonedx(document)
            facts["sbom_components"] = len(document["components"])
            facts["sbom_vulns"] = len(document["vulnerabilities"])
            if len(document["components"]) != 2:
                failures.append(f"the CLI SBOM lists {len(document['components'])} components, "
                                f"expected the 2 manifest pins")
            if not document["vulnerabilities"]:
                failures.append("the CLI SBOM carries no vulnerability for a vulnerable pin")
            if not any(item["id"] == "CVE-2020-14343" for item in document["vulnerabilities"]):
                failures.append("the CLI SBOM lost the pyyaml advisory")
            reach = [item for item in document["vulnerabilities"]
                     if item["id"] == "CVE-2020-14343"]
            if reach:
                properties = {prop["name"]: prop["value"] for prop in reach[0]["properties"]}
                facts["cli_reach"] = properties.get("tcs:reachability")
                if properties.get("tcs:reachability") != "REACHABLE":
                    failures.append("the CLI SBOM did not carry the import proof")
        # `duration_ms` is a wall-clock measurement and differs between any two runs; every other
        # field, findings included, must be byte-identical with and without --sbom.
        steady = lambda doc: {k: v for k, v in doc.items() if k != "duration_ms"}
        if steady(with_sbom) != steady(payload):
            differing = sorted(key for key in set(with_sbom) | set(payload)
                               if key != "duration_ms"
                               and with_sbom.get(key) != payload.get(key))
            failures.append(f"--sbom changed the stdout payload on {differing}")
        # Scope isolation, both directions.
        _code, only = run_cli(BASE_ARGV + ["--scope", "secrets"], tree)
        facts["secrets_only_files"] = only["scanned_files_by_scope"]
        if only["scanned_files_by_scope"]["python"] != 0:
            failures.append("--scope secrets still scanned Python files")
        if only["scanned_files_by_scope"]["sca"] != 0:
            failures.append("--scope secrets still audited manifests")
        if only["scanned_files_by_scope"]["secrets"] != 2:
            failures.append("--scope secrets did not read both config documents")
        if only["scope"] != "secrets":
            failures.append(f"--scope secrets payload says {only['scope']!r}")
        if len(cat_rows(only)) != 14:
            failures.append(f"--scope secrets emitted {len(cat_rows(only))} rows, expected 14")
        if sca_rows(only):
            failures.append("--scope secrets emitted SCA rows")
        for scope in ("python", "sca", "docker", "iac"):
            _code, scoped = run_cli(BASE_ARGV + ["--scope", scope], tree)
            if cat_rows(scoped):
                failures.append(f"--scope {scope} emitted config secret rows")
            if scoped["scanned_files_by_scope"]["secrets"] != 0:
                failures.append(f"--scope {scope} still counted config documents")
        # Every owned format is discovered, and every refused path is not.
        write_tree(format_tree, FORMAT_FILES)
        _code, formats = run_cli(BASE_ARGV, format_tree)
        facts["format_files"] = formats["scanned_files_by_scope"]
        if formats["scanned_files_by_scope"]["secrets"] != 11:
            failures.append(f"discovered {formats['scanned_files_by_scope']['secrets']} config "
                            f"documents, expected 11 formats")
        if len(cat_rows(formats)) != 12:
            failures.append(f"the format tree emitted {len(cat_rows(formats))} rows, expected 12")
        # An inline directive on the config line itself, in the engine's own syntax.
        suppressed_env = BAD_ENV.replace("API_KEY=" + GENERIC_VALUE,
                                         "API_KEY=" + GENERIC_VALUE + "  # tcs: ignore[CWE-798]")
        write_tree(tree, {".env": suppressed_env})
        _code, suppressed = run_cli(BASE_ARGV, tree)
        facts["inline_suppressed"] = not any(
            item["file"] == ".env" and item["secret_type"] == "Hard-coded API_KEY"
            for item in cat_rows(suppressed))
        if not facts["inline_suppressed"]:
            failures.append("a `# tcs: ignore[CWE-798]` directive on the config line did not "
                            "suppress the secret row")
        if len(cat_rows(suppressed)) != 13:
            failures.append(f"the inline directive silenced {14 - len(cat_rows(suppressed))} "
                            f"rows, expected exactly 1")
        # A global exclude_paths entry is a never-read rule and must hold for config documents.
        (tree / ".tcs.yaml").write_text('exclude_paths:\n  - ".env"\n', encoding="utf-8")
        _code, excluded = run_cli(BASE_ARGV, tree)
        if any(item["file"] == ".env" for item in cat_rows(excluded)):
            failures.append("a globally excluded config document was still audited")
        (tree / ".tcs.yaml").unlink()
        write_tree(tree, {".env": BAD_ENV})
    return failures, facts


# ── tier 7: the Python engine is untouched ────────────────────────────────
def check_engine_unchanged():
    failures = []
    with tempfile.TemporaryDirectory(prefix="tcs_t18_py_") as tmp:
        tree = Path(tmp)
        write_tree(tree, WIRE_FILES)
        _code, enabled = run_cli(BASE_ARGV, tree)
        original = inspect.getattr_static(cli, "audit_secret_files")
        try:
            cli.audit_secret_files = lambda files: []
            _code, disabled = run_cli(BASE_ARGV, tree)
        finally:
            cli.audit_secret_files = original
        py_on = sorted(json.dumps(item, sort_keys=True) for item in enabled["findings"]
                       if item["file"].endswith(".py"))
        py_off = sorted(json.dumps(item, sort_keys=True) for item in disabled["findings"]
                        if item["file"].endswith(".py"))
        if py_on != py_off:
            failures.append(f"the secret reader changed Python findings: "
                            f"only-on={sorted(set(py_on) - set(py_off))} "
                            f"only-off={sorted(set(py_off) - set(py_on))}")
        for field in ("scanned_files_by_scope", "scope_breakdown"):
            left = {key: value for key, value in enabled[field].items() if key == "python"}
            right = {key: value for key, value in disabled[field].items() if key == "python"}
            if left != right:
                failures.append(f"the secret reader changed {field} for Python: {left} vs {right}")
        if cat_rows(disabled):
            failures.append("blinding audit_secret_files left config secret rows in the payload")
        count = len(py_on)
    diff_state = "git unavailable"
    try:
        proc = subprocess.run(["git", "diff", "--exit-code", "HEAD", "--",
                               "ast_scanner.py", "iac_auditor.py"],
                              cwd=str(REPO_ROOT), capture_output=True, encoding="utf-8",
                              errors="replace", timeout=120)
        diff_state = "clean" if proc.returncode == 0 else "dirty"
        if proc.returncode != 0:
            failures.append("ast_scanner.py / iac_auditor.py carry a diff against HEAD:\n"
                            + proc.stdout[-600:])
    except (OSError, subprocess.SubprocessError):
        pass
    return failures, count, diff_state


# ── tier 0: isolation laws ────────────────────────────────────────────────
def check_laws():
    failures = []
    package = REPO_ROOT / "scanners"
    for name in NEW_MODULES:
        path = package / name
        if not path.is_file():
            failures.append(f"scanners/{name} is missing")
            continue
        source = path.read_text(encoding="utf-8")
        for line in source.splitlines():
            stripped = line.strip()
            if not (stripped.startswith("import ") or stripped.startswith("from ")):
                continue
            if stripped.startswith("from .") or stripped.startswith("from __future__"):
                continue
            root = re.split(r"[.\s]", stripped.split()[1])[0]
            if root in FORBIDDEN_IMPORTS:
                failures.append(f"scanners/{name} imports {root}: the package must stay "
                                f"stdlib-only and isolated from the Python engine ({stripped})")
    for relative, needle in MERGE_CONTRACT:
        if needle not in (REPO_ROOT / relative).read_text(encoding="utf-8"):
            failures.append(f"{relative} lost the merge contract clause {needle!r}")
    return failures


# ── tier 8: mutations ─────────────────────────────────────────────────────
def _const(value):
    return lambda *args, **kwargs: value


NEVER_MATCHES = re.compile(r"a^")


def _no_version_proof(ecosystem, package, lower, upper, inclusive):
    """The falsifier direction: every advisory for the package, whatever the pin says."""
    return CI.advisories_for(ecosystem, package)


def _kinds(findings, kind):
    return [item for item in findings if item["secret_kind"] == kind]


def _sbom_document():
    return SB.build_sbom(SCA.collect_components(SBOM_FILES), SCA.audit_sca_files(SBOM_FILES),
                         root_name="demo")


def _reach_findings():
    found = SCA.audit_sca_files({"requirements.txt": module("pyjwt==2.3.0")})
    SCA.tag_reachability(found, {"jwt": ("app.py", 1)})
    return found


def _secrets_scope_blind():
    with tempfile.TemporaryDirectory(prefix="tcs_t18_mut_") as tmp:
        tree = Path(tmp)
        write_tree(tree, {".env": BAD_ENV, "app.py": DORMANT_APP})
        _code, payload = run_cli(BASE_ARGV, tree)
    return payload["scanned_files_by_scope"]["secrets"] == 0 and not cat_rows(payload)


PATCHED_FILES = {"requirements.txt": module("pyjwt==2.4.0", "fastapi==0.109.1",
                                            "gitpython==3.1.41"),
                 "package.json": '{"dependencies": {"ws": "7.5.10", "next": "14.2.10"}}'}

# name -> (patches, experiment). The experiment runs inside the patch and returns True when the
# blinded decision point is provably what decided the rows.
MUTATIONS = {
    "vendor_patterns_blind": (
        ((SS, "VENDOR_PATTERNS", ()),),
        lambda: not _kinds(SS.audit_secret_files(BAD_SECRET_FILES), "vendor")),
    "service_url_blind": (
        ((SS, "SERVICE_URL", NEVER_MATCHES),),
        lambda: not _kinds(SS.audit_secret_files(BAD_SECRET_FILES), "service_url")),
    "assignment_blind": (
        ((SS, "ASSIGNMENT", NEVER_MATCHES),),
        lambda: not _kinds(SS.audit_secret_files(BAD_SECRET_FILES), "generic")),
    "entropy_floor_raised": (
        ((SS, "MIN_GENERIC_ENTROPY", 99.0),),
        lambda: not _kinds(SS.audit_secret_files(BAD_SECRET_FILES), "generic")),
    "length_floor_raised": (
        ((SS, "MIN_GENERIC_LENGTH", 999),),
        lambda: not _kinds(SS.audit_secret_files(BAD_SECRET_FILES), "generic")),
    "entropy_blind": (
        ((SS, "shannon_entropy", _const(0.0)),),
        lambda: not _kinds(SS.audit_secret_files(BAD_SECRET_FILES), "generic")),
    "character_classes_blind": (
        ((SS, "_character_classes", _const(1)),),
        lambda: not _kinds(SS.audit_secret_files(BAD_SECRET_FILES), "generic")),
    "sensitive_names_blind": (
        ((SS, "SENSITIVE_NAMES", ()),),
        lambda: not _kinds(SS.audit_secret_files(BAD_SECRET_FILES), "generic")),
    "refusal_removed": (
        ((SS, "is_refused", _const(False)),),
        lambda: {item["secret_kind"] for item in SS.audit_secret_files(REFUSAL_PROOF_FILES)}
                == {"vendor", "service_url", "generic"}),
    "path_refusal_removed": (
        ((SS, "is_secret_path", _const(True)),),
        lambda: len(SS.audit_secret_files(REFUSED_PATH_FILES)) >= len(REFUSED_PATHS)),
    # build_sbom synthesises a component for an advisory with no inventory entry, so blinding the
    # inventory cannot empty `components`. What must vanish are the pins no advisory names.
    "components_blind": (
        ((SCA, "collect_components", _const([])),),
        lambda: not ({"pkg:pypi/requests", "pkg:npm/lodash"}
                     & {item["purl"] for item in _sbom_document()["components"]})),
    "pinned_version_blind": (
        ((SCA, "pinned_version_text", _const(None)),),
        lambda: all("version" not in item for item in _sbom_document()["components"])),
    "purl_shape_blind": (
        ((SB, "component_purl", lambda eco, name, version=None: "pkg:broken/" + name),),
        lambda: not any(str(item["purl"]).startswith(("pkg:pypi/", "pkg:npm/"))
                        for item in _sbom_document()["components"])),
    "sbom_advisory_facts_blind": (
        ((SB, "_advisory_facts", _const(([], "unknown", "", ""))),),
        lambda: all(not item["cwes"] for item in _sbom_document()["vulnerabilities"])),
    "version_proof_removed": (
        ((SCA, "matching_advisories", _no_version_proof),),
        lambda: len(SCA.audit_sca_files(PATCHED_FILES)) >= 5),
    "reachability_upgrade_blind": (
        ((SCA, "tag_reachability", lambda findings, roots: findings),),
        lambda: all(item["confidence"] == "LOW" for item in _reach_findings())),
    "secrets_scope_blind": (
        ((cli, "is_secret_path", _const(False)),),
        _secrets_scope_blind),
}


def run_mutations():
    failures = []
    caught = 0
    for name, (patches, experiment) in sorted(MUTATIONS.items()):
        saved = [(mod, attribute, inspect.getattr_static(mod, attribute))
                 for mod, attribute, _replacement in patches]
        try:
            for mod, attribute, replacement in patches:
                setattr(mod, attribute, replacement)
            seen = bool(experiment())
        finally:
            for mod, attribute, original in saved:
                setattr(mod, attribute, original)
            for mod, attribute, original in saved:
                if inspect.getattr_static(mod, attribute) is not original:
                    failures.append(f"{name}: {mod.__name__}.{attribute} was not restored")
        if seen:
            caught += 1
        else:
            failures.append(f"{name}: blinding it changed nothing, so it is not what decides "
                            f"the row")
    return failures, caught


def peak_rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1048576.0
    except Exception:
        return 0.0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--dump":
        for item in SS.audit_secret_files(BAD_SECRET_FILES):
            print(f"  {item['file']}:{item['line']} {item['secret_type']} "
                  f"{item['severity']} {item['evidence']}")
        return 0

    failures = []
    law_failures = check_laws()
    failures += law_failures
    print(f"TIER 0 - isolation laws over {len(NEW_MODULES)} new modules: "
          f"{len(law_failures)} failure(s)")

    bad_failures, want, got = check_secret_bad()
    failures += bad_failures
    print(f"TIER 1 - config secrets: {want} expected rows, {got} emitted, "
          f"{len(bad_failures)} failure(s)")

    refusal_failures, refusals, paths = check_secret_refusals()
    failures += refusal_failures
    print(f"TIER 2 - zero-FP refusals over {refusals} values and {paths} refused paths: "
          f"{len(refusal_failures)} failure(s)")

    vault_failures, vault = check_vault()
    failures += vault_failures
    print(f"TIER 3 - vault: {vault.get('cves')} CVEs / {vault.get('packages')} packages / "
          f"{vault.get('records')} interval records, {len(VAULT_TWINS)} twins, "
          f"{len(PARTIAL_IMMUNITY)} partial-immunity pins, {len(vault_failures)} failure(s)")

    reach_failures, reach = check_reachability()
    failures += reach_failures
    print(f"TIER 4 - reachability on {len(REACH_CASES)} new import mappings through the real "
          f"CLI: {len(reach_failures)} failure(s)")

    sbom_failures, sbom_facts = check_sbom()
    failures += sbom_failures
    print(f"TIER 5 - CycloneDX 1.5: {sbom_facts.get('components')} components, "
          f"{sbom_facts.get('vulnerabilities')} vulnerabilities, ws fix="
          f"{sbom_facts.get('ws_fix')}, reach {sbom_facts.get('reach_before')} -> "
          f"{sbom_facts.get('reach_after')}, {len(sbom_failures)} failure(s)")

    wire_failures, facts = check_wiring()
    failures += wire_failures
    print(f"TIER 6 - CLI wiring: files={facts.get('files')} formats="
          f"{facts.get('format_files')} sbom={sbom_facts and facts.get('sbom_components')}/"
          f"{facts.get('sbom_vulns')} inline_suppressed={facts.get('inline_suppressed')} "
          f"{len(wire_failures)} failure(s)")

    engine_failures, py_rows, diff_state = check_engine_unchanged()
    failures += engine_failures
    print(f"TIER 7 - Python differential: {py_rows} row(s) byte-identical with the secret reader "
          f"on and off, engine diff={diff_state}, {len(engine_failures)} failure(s)")

    mutation_failures, caught = run_mutations()
    failures += mutation_failures
    print(f"TIER 8 - {caught}/{len(MUTATIONS)} mutations caught")

    for item in failures:
        print(f"  !! {item}")

    elapsed = time.time() - START
    rss = peak_rss_mb()
    print(f"TIER 9 - work={elapsed:.2f}s (budget {BUDGET_SECONDS}s) "
          f"peak_rss={rss:.1f}MB (budget {BUDGET_RSS_MB}MB)")
    if failures:
        print("VERDICT: FAIL - a credential was missed or re-published, a refused value went "
              "loud, the vault lost an advisory or condemned a patched pin, the SBOM stopped "
              "being valid CycloneDX, or the Python engine moved. Fix the cause; never blind "
              "a rule.")
        return 1
    if elapsed > BUDGET_SECONDS or rss > BUDGET_RSS_MB:
        print("VERDICT: FAIL - budget blown, and a lock that is slow or heavy never runs.")
        return 1
    print(f"VERDICT: PASS - {want} exact credential rows across 11 formats with no secret "
          f"re-published, {refusals} refusals and {paths} refused paths quiet beside loud twins, "
          f"{vault.get('cves')} CVEs over {vault.get('packages')} packages with "
          f"{len(VAULT_TWINS)} sound twins, reachability proven on {len(REACH_CASES)} new "
          f"mappings, a valid CycloneDX 1.5 document, {py_rows} Python row(s) unchanged, engine "
          f"diff={diff_state}, {caught}/{len(MUTATIONS)} mutations caught, peak RSS {rss:.1f}MB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())