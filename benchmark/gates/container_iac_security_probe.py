"""Gate #59 -- modular container and CI/IaC security scanners, and the Python engine untouched.

TASK 16 added two isolated stdlib-only scanners beside the Python AST engine:

* `scanners/container_scanner.py` -- CWE-250 CONTAINER_ROOT_USER, CWE-798
  CONTAINER_HARDCODED_SECRET, CWE-829 CONTAINER_UNTRUSTED_OR_UNPINNED_IMAGE over `Dockerfile*`
  and `docker-compose*.yml|yaml`.
* `scanners/iac_scanner.py` -- CWE-78 GHA_SCRIPT_INJECTION, CWE-269
  GHA_EXCESSIVE_PERMISSIONS_OR_PWN_REQUEST, CWE-250 K8S_PRIVILEGED_CONTAINER and CWE-732
  IAC_PUBLIC_EXPOSURE over `.github/workflows/*.yml`, Kubernetes workload manifests and `*.tf`.

The contract this gate locks, in eight tiers:

0. ISOLATION LAWS -- the package imports nothing but the stdlib and its own modules, never
   `ast_scanner`, never `cli`, never PyYAML, and never re-emits CWE-1357. `iac_auditor` keeps
   owning the legacy rows and does not import the package back.
1. BAD CASES -- every one of the seven rules fires on a real vulnerable artefact, at the exact
   line, with the exact category. Line numbers are pinned by substring, never counted by hand.
2. SAFE CASES AND FALSIFIERS -- the task's own falsifiers stay quiet: `USER 1000`, a digest-pinned
   `FROM`, `COPY` instead of `ADD`, `$VAR` / empty / placeholder credentials, an expression routed
   through step `env:` and quoted `"$VAR"`, `privileged: false` / `runAsNonRoot: true`,
   `acl = "private"` and `10.0.0.0/8`. A plain config YAML carrying `privileged: true` is NOT a
   Kubernetes manifest and must not be swept in. Every safe document is paired with its vulnerable
   twin in the same call shape, so a quiet tree cannot hide a rule that simply never ran.
3. LEGACY IDENTITY AND DEDUPE -- every CWE-1357 row is byte-identical to `iac_auditor`'s own, and
   a Dockerfile the legacy auditor already booked CWE-250 on carries exactly ONE CWE-250, not two.
4. PYTHON UNCHANGED -- the same mixed tree scanned through the real CLI with the new scanners
   enabled and disabled produces byte-identical rows on every `.py` file. This is the zero-breakage
   mandate measured as behaviour, not as a source hash that a later legitimate engine edit would
   trip over.
5. CLI WIRING -- discovery, the `docker` / `iac` scope split and `--scope` isolation.
6. NOISE POLICY -- a Python-oriented `rules.CWE-78.exclude` glob (`**/.github/**`) cannot delete
   the GHA injection rule at its only source, while the very same glob still mutes a Python CI
   script. Both halves are measured against a config-free scan of the same tree.
7. MUTATIONS -- each rule is blinded in turn and its own bad row must disappear. A rule whose
   absence this gate cannot see is not locked by it.
8. BUDGET -- work and peak RSS, because a lock that is slow or heavy never runs on this laptop.

Usage: python benchmark/gates/container_iac_security_probe.py [--dump]
"""
from __future__ import annotations

import contextlib
import inspect
import io
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

START = time.time()
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import cli  # noqa: E402
import iac_auditor  # noqa: E402
import scanners  # noqa: E402
from scanners import container_scanner as CS  # noqa: E402
from scanners import iac_scanner as IS  # noqa: E402

BUDGET_SECONDS = 25.0
BUDGET_RSS_MB = 60.0

DIGEST = "0123456789abcdef" * 4
SHA = "a" * 40


def module(*lines):
    return "".join(line + "\n" for line in lines)


def pin(source, needle):
    """The one line carrying `needle`. An ambiguous pin is a broken fixture, not a verdict."""
    hits = [index for index, line in enumerate(source.splitlines(), 1) if needle in line]
    if len(hits) != 1:
        raise AssertionError(f"pin {needle!r} matched {len(hits)} lines, expected exactly 1")
    return hits[0]


def pin_raw(source, raw):
    """The one line equal to `raw`, indentation included. Separates a workflow-level key from a
    job-level one, where a substring pin would match both."""
    hits = [index for index, line in enumerate(source.splitlines(), 1) if line == raw]
    if len(hits) != 1:
        raise AssertionError(f"pin_raw {raw!r} matched {len(hits)} lines, expected exactly 1")
    return hits[0]


# ── vulnerable artefacts ──────────────────────────────────────────────────
BAD_DOCKERFILE = module(
    "FROM python:3.11-slim AS builder",
    "RUN pip wheel --no-deps -w /wheels .",
    "",
    "FROM python:latest",
    "ENV DB_PASSWORD=Sup3rS3cret!",
    'ARG API_KEY="sk-live-abcdef123456"',
    "ADD https://example.com/app.tar.gz /tmp/app.tar.gz",
    "COPY --from=builder /wheels /wheels",
    "USER root",
    'CMD ["python", "-m", "app"]',
)
# No CMD and no ENTRYPOINT: the legacy auditor reports nothing here because the image executes
# nothing of its own, so this file is the end-to-end carrier for the NEW root-user rule.
BAD_RUNTIME_DOCKERFILE = module(
    "FROM ubuntu:latest",
    "ENV SERVICE_PASSWORD=hunter2literal",
    "RUN apt-get update",
)
BAD_COMPOSE = module(
    "services:",
    "  web:",
    "    image: nginx:latest",
    "    privileged: true",
    "    environment:",
    '      DB_PASSWORD: "Sup3rS3cret!"',
    "      API_KEY: ${API_KEY}",
    "  db:",
    "    image: postgres:15",
    '    user: "0"',
    "    environment:",
    "      - POSTGRES_PASSWORD=changeme",
    "      - AUTH_TOKEN=literal-token-value",
)
BAD_WORKFLOW = module(
    "name: ci",
    "on:",
    "  - pull_request_target",
    "  - issues",
    "permissions: write-all",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    permissions: write-all",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "        with:",
    "          ref: ${{ github.event.pull_request.head.sha }}",
    "      - name: greet",
    '        run: echo "${{ github.event.issue.title }}"',
    "      - name: safe",
    "        env:",
    "          TITLE: ${{ github.event.pull_request.title }}",
    '        run: echo "$TITLE"',
    "      - uses: someorg/some-action@main",
)
BAD_K8S = module(
    "apiVersion: v1",
    "kind: Pod",
    "metadata:",
    "  name: risky",
    "spec:",
    "  hostNetwork: true",
    "  containers:",
    "    - name: app",
    "      image: nginx",
    "      securityContext:",
    "        privileged: true",
    "        allowPrivilegeEscalation: true",
    "        runAsUser: 0",
)
BAD_TF = module(
    'resource "aws_s3_bucket" "public" {',
    '  bucket = "my-bucket"',
    '  acl    = "public-read"',
    "}",
    "",
    'resource "aws_security_group" "open" {',
    '  name = "open"',
    "  ingress {",
    "    from_port   = 22",
    "    to_port     = 22",
    '    protocol    = "tcp"',
    '    cidr_blocks = ["0.0.0.0/0"]',
    "  }",
    "}",
)

# ── safe artefacts and falsifiers ─────────────────────────────────────────
SAFE_DOCKERFILE = module(
    f"FROM python:3.11-slim@sha256:{DIGEST}",
    'ENV DB_PASSWORD=""',
    "ENV API_KEY=${API_KEY}",
    "ARG SECRET=changeme",
    "COPY app.py /app/app.py",
    "USER 1000",
    'CMD ["python", "/app/app.py"]',
)
SAFE_COMPOSE = module(
    "services:",
    "  web:",
    "    image: nginx:1.25",
    "    privileged: false",
    "    user: appuser",
    "    environment:",
    '      DB_PASSWORD: ""',
    "      API_KEY: ${API_KEY}",
    "      SECRET: placeholder",
    "      AUTH_TOKEN: your_token_here",
)
SAFE_WORKFLOW = module(
    "name: safe",
    "on:",
    "  - pull_request",
    "permissions:",
    "  contents: read",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    f"      - uses: actions/checkout@{SHA}",
    "      - name: greet",
    "        env:",
    "          TITLE: ${{ github.event.pull_request.title }}",
    '        run: echo "$TITLE"',
)
SAFE_K8S = module(
    "apiVersion: apps/v1",
    "kind: Deployment",
    "metadata:",
    "  name: safe",
    "spec:",
    "  template:",
    "    spec:",
    "      containers:",
    "        - name: app",
    "          image: nginx",
    "          securityContext:",
    "            privileged: false",
    "            allowPrivilegeEscalation: false",
    "            runAsNonRoot: true",
    "            runAsUser: 1000",
)
SAFE_TF = module(
    'resource "aws_s3_bucket" "private" {',
    '  bucket = "my-bucket"',
    '  acl    = "private"',
    "}",
    "",
    'resource "aws_security_group" "internal" {',
    '  name = "internal"',
    "  ingress {",
    "    from_port   = 22",
    "    to_port     = 22",
    '    protocol    = "tcp"',
    '    cidr_blocks = ["10.0.0.0/8"]',
    "  }",
    "}",
)
# Not a manifest: no apiVersion/kind at the root. `privileged: true` here is an ordinary config
# key, and a scanner that swept every YAML would report it as a Kubernetes privilege.
PLAIN_YAML = module(
    "database:",
    "  host: localhost",
    "  privileged: true",
)
PYTHON_CARRIER = module(
    "import hashlib",
    "",
    "",
    "def digest(data):",
    "    return hashlib.md5(data).hexdigest()",
)
# A Python CI script: the shipped-style CWE-78 glob is *about* this file, and tier 6 proves the
# glob still mutes it while the workflow YAML beside it stays loud.
PYTHON_CI_SCRIPT = module(
    "import os",
    "import subprocess",
    "",
    "",
    "def deploy(name):",
    '    subprocess.call("echo " + name, shell=True)',
    "",
    "",
    'deploy(os.environ["USER_INPUT"])',
)

BAD_FILES = {
    "Dockerfile": BAD_DOCKERFILE,
    "runtime/Dockerfile": BAD_RUNTIME_DOCKERFILE,
    "docker-compose.yml": BAD_COMPOSE,
    ".github/workflows/ci.yml": BAD_WORKFLOW,
    "k8s/pod.yaml": BAD_K8S,
    "main.tf": BAD_TF,
}
SAFE_FILES = {
    "safe/Dockerfile": SAFE_DOCKERFILE,
    "safe/docker-compose.yml": SAFE_COMPOSE,
    ".github/workflows/safe.yml": SAFE_WORKFLOW,
    "k8s/safe.yaml": SAFE_K8S,
    "safe.tf": SAFE_TF,
    "config/settings.yaml": PLAIN_YAML,
}
MIXED_FILES = dict(BAD_FILES, **SAFE_FILES)
MIXED_FILES["app.py"] = PYTHON_CARRIER

# Each safe document beside its vulnerable twin, at the same path, in the same call shape.
TWINS = (
    ("Dockerfile", BAD_DOCKERFILE, SAFE_DOCKERFILE),
    ("docker-compose.yml", BAD_COMPOSE, SAFE_COMPOSE),
    (".github/workflows/ci.yml", BAD_WORKFLOW, SAFE_WORKFLOW),
    ("k8s/pod.yaml", BAD_K8S, SAFE_K8S),
    ("main.tf", BAD_TF, SAFE_TF),
)


def rows_of(findings):
    return {(item["file"], item["line"], item["cwe"], item["category"]) for item in findings}


def aux_scan(files, audit_all=False):
    """Exactly what the CLI merge site does: legacy first, then the modular scanners."""
    legacy = iac_auditor.audit_iac_files(files, audit_all=audit_all)
    fresh = scanners.audit_security_files(files, legacy_findings=legacy)
    return legacy, fresh


# ── tier 0: isolation laws ────────────────────────────────────────────────
SCANNER_MODULES = ("__init__.py", "container_scanner.py", "iac_scanner.py", "yaml_lite.py")
FORBIDDEN_IMPORTS = ("ast_scanner", "cli", "iac_auditor", "cross_file_engine", "yaml", "psutil")
MERGE_CONTRACT = (
    ("cli.py", "audit_iac_files(iac, audit_all="),
    ("cli.py", "audit_security_files(iac, legacy_findings=legacy_iac)"),
    ("scanners/__init__.py", "already_root_reported"),
    ("scanners/__init__.py", 'item.get("cwe") == "CWE-250"'),
)


def check_laws():
    failures = []
    package = REPO_ROOT / "scanners"
    for name in SCANNER_MODULES:
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
                failures.append(f"scanners/{name} imports {root}: the package must stay stdlib-only "
                                f"and isolated from the Python engine ({stripped})")
        if '"cwe": "CWE-1357"' in source or "'cwe': 'CWE-1357'" in source:
            failures.append(f"scanners/{name} re-emits CWE-1357, which iac_auditor solely owns")
    if "scanners" in (REPO_ROOT / "iac_auditor.py").read_text(encoding="utf-8"):
        failures.append("iac_auditor.py references the new package; the legacy auditor must stay "
                        "independent so its CWE-1357 rows cannot drift")
    for relative, needle in MERGE_CONTRACT:
        if needle not in (REPO_ROOT / relative).read_text(encoding="utf-8"):
            failures.append(f"{relative} lost the merge contract clause {needle!r}")
    return failures


# ── tier 1: bad cases ─────────────────────────────────────────────────────
def expected_bad():
    want = set()
    add = want.add
    # Category labels only. A local named `secret` holding a string literal is itself a CWE-798
    # finding, and this gate lives inside the parity scan root -- the fixture must not bless itself.
    cat_798 = "CONTAINER_HARDCODED_SECRET"
    cat_829 = "CONTAINER_UNTRUSTED_OR_UNPINNED_IMAGE"
    cat_250 = "CONTAINER_ROOT_USER"
    cat_269 = "GHA_EXCESSIVE_PERMISSIONS_OR_PWN_REQUEST"
    add(("Dockerfile", pin(BAD_DOCKERFILE, "ENV DB_PASSWORD="), "CWE-798", cat_798))
    add(("Dockerfile", pin(BAD_DOCKERFILE, "ARG API_KEY="), "CWE-798", cat_798))
    add(("Dockerfile", pin(BAD_DOCKERFILE, "FROM python:latest"), "CWE-829", cat_829))
    add(("Dockerfile", pin(BAD_DOCKERFILE, "ADD https://"), "CWE-829", cat_829))
    ubuntu = pin(BAD_RUNTIME_DOCKERFILE, "FROM ubuntu:latest")
    add(("runtime/Dockerfile", ubuntu, "CWE-250", cat_250))
    add(("runtime/Dockerfile", ubuntu, "CWE-829", cat_829))
    add(("runtime/Dockerfile", pin(BAD_RUNTIME_DOCKERFILE, "ENV SERVICE_PASSWORD="), "CWE-798", cat_798))
    add(("docker-compose.yml", pin(BAD_COMPOSE, "privileged: true"), "CWE-250", cat_250))
    add(("docker-compose.yml", pin(BAD_COMPOSE, 'user: "0"'), "CWE-250", cat_250))
    add(("docker-compose.yml", pin(BAD_COMPOSE, "DB_PASSWORD:"), "CWE-798", cat_798))
    add(("docker-compose.yml", pin(BAD_COMPOSE, "AUTH_TOKEN=literal"), "CWE-798", cat_798))
    ci = ".github/workflows/ci.yml"
    add((ci, pin_raw(BAD_WORKFLOW, "permissions: write-all"), "CWE-269", cat_269))
    add((ci, pin_raw(BAD_WORKFLOW, "    permissions: write-all"), "CWE-269", cat_269))
    add((ci, pin(BAD_WORKFLOW, "head.sha"), "CWE-269", cat_269))
    add((ci, pin(BAD_WORKFLOW, 'run: echo "${{ github.event.issue.title }}"'), "CWE-78",
         "GHA_SCRIPT_INJECTION"))
    for needle in ("hostNetwork: true", "privileged: true", "allowPrivilegeEscalation: true",
                   "runAsUser: 0"):
        add(("k8s/pod.yaml", pin(BAD_K8S, needle), "CWE-250", "K8S_PRIVILEGED_CONTAINER"))
    add(("main.tf", pin(BAD_TF, 'acl    = "public-read"'), "CWE-732", "IAC_PUBLIC_EXPOSURE"))
    add(("main.tf", pin(BAD_TF, 'cidr_blocks = ["0.0.0.0/0"]'), "CWE-732", "IAC_PUBLIC_EXPOSURE"))
    return want


def check_bad():
    failures = []
    _legacy, fresh = aux_scan(BAD_FILES)
    got = rows_of(fresh)
    want = expected_bad()
    for row in sorted(want - got):
        failures.append(f"BAD missing {row[0]}:{row[1]} {row[2]} {row[3]}")
    for row in sorted(got - want):
        failures.append(f"BAD invented {row[0]}:{row[1]} {row[2]} {row[3]}")
    # The builder stage is pinned and named, the COPY is local: neither may be reported.
    for needle in ("FROM python:3.11-slim AS builder", "COPY --from=builder"):
        line = pin(BAD_DOCKERFILE, needle)
        if any(row[0] == "Dockerfile" and row[1] == line for row in got):
            failures.append(f"BAD reported the safe shape {needle!r}")
    return failures, len(want), len(got)


# ── tier 2: safe cases and falsifiers ─────────────────────────────────────
def check_safe():
    failures = []
    legacy, fresh = aux_scan(SAFE_FILES)
    if fresh:
        failures.append(f"SAFE tree is not quiet: {sorted(rows_of(fresh))}")
    if legacy:
        failures.append(f"SAFE tree drew legacy rows: {sorted(rows_of(legacy))}")
    for name, bad, safe in TWINS:
        _legacy, loud = aux_scan({name: bad})
        _legacy, quiet = aux_scan({name: safe})
        if not loud:
            failures.append(f"the {name} twin's vulnerable arm is quiet, so its safe arm proves nothing")
        if quiet:
            failures.append(f"the {name} twin's safe arm is loud: {sorted(rows_of(quiet))}")
    if IS.is_kubernetes_manifest(PLAIN_YAML):
        failures.append("a plain config YAML was claimed as a Kubernetes manifest")
    if not IS.is_kubernetes_manifest(BAD_K8S):
        failures.append("the vulnerable Pod manifest stopped being recognised as Kubernetes")
    return failures


# ── tier 3: legacy identity and the one-defect-one-row dedupe ─────────────
def check_legacy():
    failures = []
    legacy, fresh = aux_scan(BAD_FILES)
    if legacy != iac_auditor.audit_iac_files(BAD_FILES):
        failures.append("audit_iac_files changed shape when called through the merge site")
    unpinned = [item for item in legacy if item["cwe"] == "CWE-1357"]
    if not unpinned:
        failures.append("the bad workflow drew no CWE-1357 row, so legacy identity is unmeasured")
    for item in unpinned:
        if item.get("related_cwes") != ["CWE-353"]:
            failures.append(f"CWE-1357 lost its CWE-353 metadata: {item}")
        if "also CWE-353" not in item["message"]:
            failures.append(f"CWE-1357 lost the CWE-353 mention in its message: {item['message']}")
        if item not in iac_auditor.audit_workflow(item["file"], BAD_FILES[item["file"]]):
            failures.append(f"CWE-1357 row is not byte-identical to iac_auditor's own: {item}")
    if any(item["cwe"] == "CWE-1357" for item in fresh):
        failures.append("the modular scanners emitted CWE-1357, doubling the legacy rule")
    root_rows = [item for item in legacy + fresh
                 if item["file"] == "Dockerfile" and item["cwe"] == "CWE-250"]
    if len(root_rows) != 1:
        failures.append(f"Dockerfile carries {len(root_rows)} CWE-250 rows, expected exactly 1: "
                        f"{[(r['line'], r['category']) for r in root_rows]}")
    elif root_rows[0]["category"] != "EXECUTION_WITH_UNNECESSARY_PRIVILEGES":
        failures.append("the surviving CWE-250 is not the legacy row, so the legacy message changed")
    doubled = CS.audit_container_files(BAD_FILES)
    twice = [item for item in doubled + legacy
             if item["file"] == "Dockerfile" and item["cwe"] == "CWE-250"]
    if len(twice) != 2:
        failures.append(f"dropping already_root_reported produced {len(twice)} CWE-250 rows, "
                        "expected 2 -- the dedupe mutation would be unmeasurable")
    return failures, len(unpinned)


# ── CLI helpers ───────────────────────────────────────────────────────────
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


def python_rows(payload):
    return {json.dumps(item, sort_keys=True) for item in payload["findings"]
            if str(item["file"]).endswith(".py")}


def key_set(payload):
    return {(item["file"], item["line"], item["cwe"]) for item in payload["findings"]}


# ── tier 4: the Python engine is untouched ────────────────────────────────
def check_python_unchanged():
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_tree(root, MIXED_FILES)
        _code, enabled = run_cli(BASE_ARGV, root)
        original = cli.audit_security_files
        cli.audit_security_files = lambda files, legacy_findings=(): []
        try:
            _code, disabled = run_cli(BASE_ARGV, root)
        finally:
            cli.audit_security_files = original
        if cli.audit_security_files is not original:
            failures.append("audit_security_files was not restored after the differential")
    on, off = python_rows(enabled), python_rows(disabled)
    if not off:
        failures.append("the Python carrier drew no finding, so the differential measures nothing")
    for row in sorted(on - off):
        failures.append(f"Python row appeared with the scanners on: {row}")
    for row in sorted(off - on):
        failures.append(f"Python row disappeared with the scanners on: {row}")
    for key in ("scanned_files_by_scope", "scope_breakdown"):
        if enabled[key]["python"] != disabled[key]["python"]:
            failures.append(f"{key} python bucket moved: {enabled[key]['python']} != "
                            f"{disabled[key]['python']}")
    if enabled["parse_governor"] != disabled["parse_governor"]:
        failures.append("the parse governor changed, so the Python parse path was disturbed")
    legacy, _fresh = aux_scan(MIXED_FILES)
    merged = {(item["file"], item["line"], item["cwe"]): item for item in enabled["findings"]}
    for item in legacy:
        key = (item["file"], item["line"], item["cwe"])
        got = merged.get(key)
        if got is None:
            failures.append(f"legacy row vanished from the CLI report: {key}")
            continue
        for field, value in item.items():
            if got.get(field) != value:
                failures.append(f"legacy row {key} field {field!r} changed: "
                                f"{got.get(field)!r} != {value!r}")
    return failures, len(off)


# ── tier 5: discovery, scopes and --scope isolation ───────────────────────
def aux_scope_map():
    scopes = {}
    for path, source in MIXED_FILES.items():
        if CS.is_container_path(path):
            scopes[path] = "docker"
        elif (IS.is_workflow_yaml_path(path) or IS.is_terraform_path(path)
              or IS.is_kubernetes_manifest(source)):
            scopes[path] = "iac"
    return scopes


def check_cli_wiring():
    failures = []
    facts = {}
    scopes = aux_scope_map()
    docker_paths = {p for p, s in scopes.items() if s == "docker"}
    iac_paths = {p for p, s in scopes.items() if s == "iac"}
    py_paths = {p for p in MIXED_FILES if p.endswith(".py")}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_tree(root, MIXED_FILES)
        _code, payload = run_cli(BASE_ARGV, root)
        findings = payload["findings"]
        facts["scopes"] = payload["findings_by_scope"]
        facts["files"] = payload["scanned_files_by_scope"]
        if set(payload["findings_by_scope"]) != set(cli.SCOPE_ORDER):
            failures.append(f"findings_by_scope keys {sorted(payload['findings_by_scope'])} != "
                            f"{sorted(cli.SCOPE_ORDER)}")
        for name in ("docker", "iac", "python"):
            if payload["findings_by_scope"][name] <= 0:
                failures.append(f"the {name} scope reported nothing over a tree that carries it")
        if payload["scanned_files_by_scope"]["docker"] != len(docker_paths):
            failures.append(f"docker discovered {payload['scanned_files_by_scope']['docker']} != "
                            f"{len(docker_paths)} container documents")
        if payload["scanned_files_by_scope"]["iac"] != len(iac_paths):
            failures.append(f"iac discovered {payload['scanned_files_by_scope']['iac']} != "
                            f"{len(iac_paths)} CI/IaC documents")
        for item in findings:
            path = item["file"]
            if path.endswith(".py"):
                continue
            if path not in scopes:
                failures.append(f"a document outside the auxiliary families was reported: {item}")
                continue
            if cli._scope_of(path, scopes) != scopes[path]:
                failures.append(f"_scope_of mis-bucketed {path}")
        if any(item["file"] == "config/settings.yaml" for item in findings):
            failures.append("a plain config YAML produced a finding")
        for scope, allowed in (("docker", docker_paths), ("iac", iac_paths), ("python", py_paths)):
            _code, scoped = run_cli(BASE_ARGV + ["--scope", scope], root)
            seen = {item["file"] for item in scoped["findings"]}
            if seen - allowed:
                failures.append(f"--scope {scope} reported outside its family: {sorted(seen - allowed)}")
            if not seen:
                failures.append(f"--scope {scope} reported nothing at all")
            if scoped["scope"] != scope:
                failures.append(f"--scope {scope} payload says {scoped['scope']!r}")
    return failures, facts


# ── tier 6: the noise policy cannot delete a sole-source IaC rule ─────────
CONFIG_TEXT = module(
    "rules:",
    "  CWE-78:",
    "    exclude:",
    '      - "**/.github/**"',
    '      - "**/scripts/**"',
)
GHA_KEY = (".github/workflows/ci.yml",
           pin(BAD_WORKFLOW, 'run: echo "${{ github.event.issue.title }}"'), "CWE-78")


def check_noise_policy():
    failures = []
    facts = {}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_tree(root, dict(MIXED_FILES, **{"scripts/deploy.py": PYTHON_CI_SCRIPT}))
        _code, unconfigured = run_cli(BASE_ARGV, root)
        bare = key_set(unconfigured)
        python78 = {row for row in bare if row[0] == "scripts/deploy.py" and row[2] == "CWE-78"}
        if not python78:
            failures.append("the Python CI script drew no CWE-78 row, so the glob's Python half "
                            "is unmeasurable")
        if GHA_KEY not in bare:
            failures.append("the GHA injection row is absent even without a config")
        (root / ".tcs.yaml").write_text(CONFIG_TEXT, encoding="utf-8")
        _code, configured = run_cli(BASE_ARGV, root)
        keys = key_set(configured)
        facts["gha_under_config"] = GHA_KEY in keys
        facts["python78_muted"] = len(python78 - keys)
        if GHA_KEY not in keys:
            failures.append("a Python-oriented CWE-78 `**/.github/**` glob deleted the GHA "
                            "injection rule at its only source")
        if python78 & keys:
            failures.append("the same glob stopped muting a Python CI script, so the exemption "
                            f"became a whole-policy bypass: {sorted(python78 & keys)}")
        original = cli._apply_config_filters

        def blind(findings, config, path_excludes, scan_root=None, aux_scopes=None):
            return original(findings, config, path_excludes, scan_root, aux_scopes=None)

        cli._apply_config_filters = blind
        try:
            _code, blinded = run_cli(BASE_ARGV, root)
        finally:
            cli._apply_config_filters = original
        if cli._apply_config_filters is not original:
            failures.append("_apply_config_filters was not restored")
        facts["gha_blinded"] = GHA_KEY in key_set(blinded)
        if GHA_KEY in key_set(blinded):
            failures.append("blinding the auxiliary exemption changed nothing, so the exemption "
                            "is not what keeps the GHA rule alive")
    return failures, facts


# ── tier 7: mutations ─────────────────────────────────────────────────────
def _const(value):
    return lambda *args, **kwargs: value


MUTATIONS = {
    "container_root_user_blind": (
        "CWE-250 CONTAINER_ROOT_USER stops being decided",
        ((CS, "_dockerfile_root_user", _const([])),),
        ("runtime/Dockerfile", "CWE-250", "CONTAINER_ROOT_USER")),
    "container_secret_blind": (
        "a literal credential stops counting as a secret",
        ((CS, "_value_is_a_hardcoded_secret", _const(False)),),
        ("Dockerfile", "CWE-798", "CONTAINER_HARDCODED_SECRET")),
    "container_image_blind": (
        "CWE-829 stops being decided",
        ((CS, "_dockerfile_images", _const([])),),
        ("Dockerfile", "CWE-829", "CONTAINER_UNTRUSTED_OR_UNPINNED_IMAGE")),
    "compose_rules_blind": (
        "compose services stop being audited",
        ((CS, "_compose_rules", _const([])),),
        ("docker-compose.yml", "CWE-250", "CONTAINER_ROOT_USER")),
    "gha_injection_blind": (
        "CWE-78 GHA_SCRIPT_INJECTION stops being decided",
        ((IS, "_gha_script_injection", _const([])),),
        (".github/workflows/ci.yml", "CWE-78", "GHA_SCRIPT_INJECTION")),
    "gha_permissions_blind": (
        "CWE-269 stops being decided",
        ((IS, "_gha_permissions", _const([])),),
        (".github/workflows/ci.yml", "CWE-269", "GHA_EXCESSIVE_PERMISSIONS_OR_PWN_REQUEST")),
    "kubernetes_privileges_blind": (
        "CWE-250 K8S_PRIVILEGED_CONTAINER stops being decided",
        ((IS, "_kubernetes_privileges", _const([])),),
        ("k8s/pod.yaml", "CWE-250", "K8S_PRIVILEGED_CONTAINER")),
    "terraform_exposure_blind": (
        "CWE-732 IAC_PUBLIC_EXPOSURE stops being decided",
        ((IS, "_terraform_exposure", _const([])),),
        ("main.tf", "CWE-732", "IAC_PUBLIC_EXPOSURE")),
    "kubernetes_sniff_blind": (
        "discovery stops recognising a workload manifest",
        ((IS, "is_kubernetes_manifest", _const(False)),),
        ("k8s/pod.yaml", "CWE-250", "K8S_PRIVILEGED_CONTAINER")),
    "placeholder_proof_blind": (
        "an obvious placeholder starts counting as a real credential",
        ((CS, "_value_is_a_hardcoded_secret", _const(True)),),
        None),
}


def run_mutations():
    failures = []
    caught = 0
    _legacy, baseline = aux_scan(BAD_FILES)
    base_rows = rows_of(baseline)
    for name, (description, patches, watched) in sorted(MUTATIONS.items()):
        saved = [(mod, attribute, inspect.getattr_static(mod, attribute))
                 for mod, attribute, _replacement in patches]
        try:
            for mod, attribute, replacement in patches:
                setattr(mod, attribute, replacement)
            _legacy, mutated = aux_scan(BAD_FILES)
            mutated_rows = rows_of(mutated)
            if watched is None:
                # The falsifier direction: a safe value must become loud, proving the placeholder
                # proof is what keeps `changeme` quiet rather than the rule never running.
                line = pin(BAD_COMPOSE, "POSTGRES_PASSWORD=changeme")
                victim = ("docker-compose.yml", line, "CWE-798", "CONTAINER_HARDCODED_SECRET")
                seen = victim in mutated_rows
            else:
                victims = [row for row in base_rows
                           if row[0] == watched[0] and row[2] == watched[1] and row[3] == watched[2]]
                if not victims:
                    failures.append(f"{name}: the baseline carries no {watched} row to lose")
                    continue
                seen = any(row in mutated_rows for row in victims)
        finally:
            for mod, attribute, original in saved:
                setattr(mod, attribute, original)
            for mod, attribute, original in saved:
                if inspect.getattr_static(mod, attribute) is not original:
                    failures.append(f"{name}: {mod.__name__}.{attribute} was not restored")
        if watched is None:
            if not seen:
                failures.append(f"{name}: blinding the placeholder proof did not make "
                                "`POSTGRES_PASSWORD=changeme` loud, so the falsifier is unmeasured")
            else:
                caught += 1
        elif seen:
            failures.append(f"{name}: {description}, yet {watched} stayed loud -- the gate "
                            "cannot see this rule's absence")
        else:
            caught += 1
    return failures, caught, len(base_rows)


def peak_rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1048576.0
    except Exception:
        return 0.0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--dump":
        legacy, fresh = aux_scan(MIXED_FILES)
        for label, group in (("legacy", legacy), ("modular", fresh)):
            print(f"{label}: {len(group)}")
            for item in group:
                print(f"  {item['file']}:{item['line']} {item['cwe']} {item['category']}")
        return 0

    failures = check_laws()
    print(f"TIER 0 - isolation laws over {len(SCANNER_MODULES)} modules: {len(failures)} failure(s)")

    bad_failures, want, got = check_bad()
    failures += bad_failures
    print(f"TIER 1 - bad cases: {want} expected rows, {got} emitted, {len(bad_failures)} failure(s)")

    safe_failures = check_safe()
    failures += safe_failures
    print(f"TIER 2 - safe cases and falsifiers over {len(SAFE_FILES)} documents + {len(TWINS)} twins: "
          f"{len(safe_failures)} failure(s)")

    legacy_failures, unpinned = check_legacy()
    failures += legacy_failures
    print(f"TIER 3 - legacy identity ({unpinned} CWE-1357 row(s)) and one-defect-one-row dedupe: "
          f"{len(legacy_failures)} failure(s)")

    python_failures, python_count = check_python_unchanged()
    failures += python_failures
    print(f"TIER 4 - Python differential through the real CLI: {python_count} row(s) byte-identical "
          f"with the scanners on and off, {len(python_failures)} failure(s)")

    wiring_failures, facts = check_cli_wiring()
    failures += wiring_failures
    print(f"TIER 5 - CLI wiring: files={facts.get('files')} findings={facts.get('scopes')} "
          f"{len(wiring_failures)} failure(s)")

    policy_failures, policy = check_noise_policy()
    failures += policy_failures
    print(f"TIER 6 - noise policy: gha_alive_under_config={policy.get('gha_under_config')} "
          f"python78_muted={policy.get('python78_muted')} "
          f"gha_alive_when_blinded={policy.get('gha_blinded')} "
          f"{len(policy_failures)} failure(s)")

    mutation_failures, caught, base_rows = run_mutations()
    failures += mutation_failures
    print(f"TIER 7 - {caught}/{len(MUTATIONS)} mutations caught over {base_rows} baseline rows")

    for item in failures:
        print(f"  !! {item}")

    elapsed = time.time() - START
    rss = peak_rss_mb()
    print(f"TIER 8 - work={elapsed:.2f}s (budget {BUDGET_SECONDS}s) "
          f"peak_rss={rss:.1f}MB (budget {BUDGET_RSS_MB}MB)")
    if failures:
        print("VERDICT: FAIL - a container/IaC rule lost a true positive, a falsifier went loud, "
              "a legacy row drifted, or the Python engine moved. Fix the cause; never blind a rule.")
        return 1
    if elapsed > BUDGET_SECONDS or rss > BUDGET_RSS_MB:
        print("VERDICT: FAIL - budget blown, and a lock that is slow or heavy never runs.")
        return 1
    print(f"VERDICT: PASS - 7 rule families loud on {want} exact rows, every safe twin quiet, "
          f"{unpinned} CWE-1357 row(s) byte-identical, one CWE-250 per root-user defect, "
          f"{python_count} Python row(s) unchanged, {caught}/{len(MUTATIONS)} mutations caught, "
          f"peak RSS {rss:.1f}MB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())