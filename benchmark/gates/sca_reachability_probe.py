"""Gate #60 -- SCA dependency audit and import reachability, and the Python engine untouched.

TASK 17 added a software-composition scanner beside the Python AST engine:

* `scanners/cve_index.py` -- a curated OFFLINE advisory table with exact `fixed` and `introduced`
  versions, plus the version arithmetic and the interval matcher.
* `scanners/sca_scanner.py` -- line-by-line readers for `requirements*.txt`, `pyproject.toml`,
  `poetry.lock`, `package.json` and `package-lock.json`, and the reachability label.

The contract this gate locks, in nine tiers:

0. ISOLATION LAWS -- the two new modules import nothing but the stdlib and their own package,
   never `ast_scanner`, never `cli`, never a network client. An offline index that can reach the
   network is not an offline index.
1. BAD CASES -- every manifest family fires on a real vulnerable pin, at the exact line, with the
   exact root CWE and the exact CVE set. Lines are pinned by substring, never counted by hand.
2. PATCHED AND UNPROVABLE -- the task's own falsifier: a pin at or above `fixed_version` is 100%
   quiet in all five families. So is every spec that does not prove a vulnerable version: `*`,
   `latest`, `>=` with no ceiling, an editable install, a VCS URL, a comment, a bare name.
3. INTERVAL SOUNDNESS -- the zero-FP argument itself. `lodash ^4.17.20` allows the patched
   4.17.21 and must be quiet; `pyyaml <5.4` allows the patched 5.3.1 and must carry only the one
   advisory that 5.3.1 does not fix; a multi-range advisory must not condemn a patched branch.
   Every quiet case is paired with a loud twin in the same call shape, so a quiet tree cannot
   hide a matcher that simply never ran.
4. REACHABILITY -- the same vulnerable `pyyaml==5.3.1` in two projects, one importing `yaml` and
   one not, through the real CLI: REACHABLE/HIGH versus UNREACHABLE_MANIFEST_ONLY/LOW. Import
   aliases, `from` imports and the distribution/import name map are proven; a relative import and
   a string that merely mentions an import are not, which is what makes this an AST proof.
5. PYTHON UNCHANGED -- a mixed tree scanned with the SCA scanner enabled and disabled produces
   byte-identical rows on every `.py` file, and `ast_scanner.py` / `iac_auditor.py` carry zero diff.
6. CLI WIRING -- discovery, the `sca` scope bucket, `--scope` isolation in both directions, and
   the fact that a manifest-only scan cannot prove reachability and must not claim HIGH.
7. MUTATIONS -- each reader, the matcher, the version parser and the reachability upgrade are
   blinded in turn and their own rows must disappear. The falsifier direction is measured too:
   removing the version proof must make a PATCHED pin loud.
8. BUDGET -- work and peak RSS, because a lock that is slow or heavy never runs on this laptop.

Usage: python benchmark/gates/sca_reachability_probe.py [--dump]
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
import scanners  # noqa: E402
from scanners import cve_index as CI  # noqa: E402
from scanners import sca_scanner as SCA  # noqa: E402

BUDGET_SECONDS = 30.0
BUDGET_RSS_MB = 60.0

CATEGORY = "SCA_VULNERABLE_DEPENDENCY"


def module(*lines):
    return "".join(line + "\n" for line in lines)


def pin(source, needle):
    """The one line carrying `needle`. An ambiguous pin is a broken fixture, not a verdict."""
    hits = [index for index, line in enumerate(source.splitlines(), 1) if needle in line]
    if len(hits) != 1:
        raise AssertionError(f"pin {needle!r} matched {len(hits)} lines, expected exactly 1")
    return hits[0]


def rows_of(findings):
    return {(item["file"], item["line"], item["cwe"], item["category"]) for item in findings}


def sca_scan(files, roots=None):
    """Exactly what the CLI merge site does: audit the manifests, then prove reachability."""
    found = SCA.audit_sca_files(files)
    if roots is not None:
        SCA.tag_reachability(found, roots)
    return found


# ── vulnerable artefacts ──────────────────────────────────────────────────
BAD_REQUIREMENTS = module(
    "# production pins",
    "pyyaml==5.3.1",
    "requests==2.30.0",
    "urllib3==2.0.6",
    "django==4.2.10",
    "jinja2==3.1.2",
    "cryptography==42.0.3",
    "pillow==10.1.0",
    "werkzeug==3.0.2",
    "aiohttp==3.9.2",
    "starlette==0.36.1",
    "paramiko==3.3.1",
    "sqlparse==0.4.4",
    "certifi==2023.7.21",
    "flask==2.3.1",
    "pyjwt==2.3.0",
)
BAD_PYPROJECT = module(
    "[project]",
    'name = "demo"',
    'version = "1.0.0"',
    "dependencies = [",
    '  "pyyaml==5.3.1",',
    '  "pillow==10.1.0",',
    '  "sqlparse==0.4.4",',
    "]",
    "",
    "[tool.poetry.dependencies]",
    'python = "^3.10"',
    'paramiko = "3.3.1"',
    'starlette = {version = "0.36.1", optional = true}',
)
BAD_POETRY_LOCK = module(
    "[[package]]",
    'name = "pyyaml"',
    'version = "5.3.1"',
    'description = "YAML parser"',
    'category = "main"',
    "optional = false",
    "",
    "[[package]]",
    'name = "certifi"',
    'version = "2023.7.21"',
    "",
    "[[package]]",
    'name = "requests"',
    'version = "2.31.0"',
)
BAD_PACKAGE_JSON = module(
    "{",
    '  "name": "demo",',
    '  "version": "1.0.0",',
    '  "dependencies": {',
    '    "lodash": "4.17.20",',
    '    "axios": "1.6.0",',
    '    "express": "4.19.1",',
    '    "jsonwebtoken": "8.5.1"',
    "  }",
    "}",
)
BAD_PACKAGE_LOCK = module(
    "{",
    '  "name": "demo",',
    '  "lockfileVersion": 3,',
    '  "packages": {',
    '    "": {"name": "demo", "version": "1.0.0"},',
    '    "node_modules/lodash": {',
    '      "version": "4.17.20"',
    "    },",
    '    "node_modules/axios": {',
    '      "version": "1.7.3"',
    "    }",
    "  }",
    "}",
)
BAD_FILES = {
    "requirements.txt": BAD_REQUIREMENTS,
    "pyproject.toml": BAD_PYPROJECT,
    "poetry.lock": BAD_POETRY_LOCK,
    "package.json": BAD_PACKAGE_JSON,
    "package-lock.json": BAD_PACKAGE_LOCK,
}

# ── patched artefacts: the task's falsifier, one per family ───────────────
SAFE_REQUIREMENTS = module(
    "# every pin at or above its fix",
    "pyyaml==6.0.1",
    "requests==2.32.4",
    "urllib3==2.2.2",
    "django==4.2.16",
    "jinja2==3.1.6",
    "cryptography==42.0.4",
    "pillow==10.3.0",
    "werkzeug==3.0.6",
    "aiohttp==3.10.11",
    "starlette==0.36.2",
    "paramiko==3.4.0",
    "sqlparse==0.5.0",
    "certifi==2024.7.4",
    "flask==2.3.2",
    "pyjwt==2.4.0",
)
SAFE_PYPROJECT = module(
    "[project]",
    'name = "demo"',
    "dependencies = [",
    '  "pyyaml==6.0.1",',
    '  "pillow==10.3.0",',
    "]",
    "",
    "[tool.poetry.dependencies]",
    'python = "^3.10"',
    'paramiko = "3.4.0"',
)
SAFE_POETRY_LOCK = module(
    "[[package]]",
    'name = "pyyaml"',
    'version = "6.0.1"',
    "",
    "[[package]]",
    'name = "certifi"',
    'version = "2024.7.4"',
)
SAFE_PACKAGE_JSON = module(
    "{",
    '  "dependencies": {',
    '    "lodash": "4.17.21",',
    '    "axios": "1.8.2",',
    '    "express": "4.21.0",',
    '    "jsonwebtoken": "9.0.0"',
    "  }",
    "}",
)
SAFE_PACKAGE_LOCK = module(
    "{",
    '  "lockfileVersion": 3,',
    '  "packages": {',
    '    "": {"name": "demo"},',
    '    "node_modules/lodash": {"version": "4.17.21"},',
    '    "node_modules/axios": {"version": "1.8.2"}',
    "  }",
    "}",
)
SAFE_FILES = {
    "requirements.txt": SAFE_REQUIREMENTS,
    "pyproject.toml": SAFE_PYPROJECT,
    "poetry.lock": SAFE_POETRY_LOCK,
    "package.json": SAFE_PACKAGE_JSON,
    "package-lock.json": SAFE_PACKAGE_LOCK,
}

# Specs that prove nothing. Each one allows a patched release, so each must be quiet -- and each
# is paired with a pinned twin of the SAME package that is loud, so quiet cannot mean "never ran".
UNPROVABLE = (
    ("requirements.txt", "pyyaml\n", "pyyaml==5.3.1\n"),
    ("requirements.txt", "pyyaml>=5.0\n", "pyyaml==5.3.1\n"),
    ("requirements.txt", "pyyaml*\n", "pyyaml==5.3.1\n"),
    ("requirements.txt", "# pyyaml==5.3.1\n", "pyyaml==5.3.1\n"),
    ("requirements.txt", "-e git+https://example.com/x#egg=pyyaml\n", "pyyaml==5.3.1\n"),
    ("requirements.txt", "-r other.txt\n", "pyyaml==5.3.1\n"),
    ("requirements.txt", "pyyaml @ https://example.com/p.whl\n", "pyyaml==5.3.1\n"),
    ("package.json", '{\n "dependencies": {"lodash": "*"}\n}\n',
     '{\n "dependencies": {"lodash": "4.17.20"}\n}\n'),
    ("package.json", '{\n "dependencies": {"lodash": "latest"}\n}\n',
     '{\n "dependencies": {"lodash": "4.17.20"}\n}\n'),
    ("package.json", '{\n "dependencies": {"axios": ">=1.0.0"}\n}\n',
     '{\n "dependencies": {"axios": "1.6.0"}\n}\n'),
    ("package.json", '{\n "dependencies": {"axios": "workspace:*"}\n}\n',
     '{\n "dependencies": {"axios": "1.6.0"}\n}\n'),
    ("pyproject.toml", '[tool.poetry.dependencies]\npyyaml = "*"\n',
     '[tool.poetry.dependencies]\npyyaml = "5.3.1"\n'),
    ("poetry.lock", '[[package]]\nname = "pyyaml"\nversion = "6.0.1"\n',
     '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n'),
)

# (label, quiet spec, loud spec) for the interval proof. The quiet arm is quiet because a patched
# release is INSIDE the interval, not because the package is unknown.
INTERVAL_TWINS = (
    ("lodash caret allows the fix", '{"dependencies": {"lodash": "^4.17.20"}}',
     '{"dependencies": {"lodash": "4.17.20"}}', "package.json"),
    ("lodash pinned at the fix", '{"dependencies": {"lodash": "4.17.21"}}',
     '{"dependencies": {"lodash": "4.17.20"}}', "package.json"),
    ("express tilde at the fix", '{"dependencies": {"express": "~4.21.0"}}',
     '{"dependencies": {"express": "4.19.1"}}', "package.json"),
    ("pyyaml at 5.4", "pyyaml==5.4\n", "pyyaml==5.3.1\n", "requirements.txt"),
    ("django patched 3.2 branch", "django==3.2.25\n", "django==3.2.24\n", "requirements.txt"),
    ("django patched 5.0 branch", "django==5.0.9\n", "django==5.0.2\n", "requirements.txt"),
    ("urllib3 patched 1.x branch", "urllib3==1.26.19\n", "urllib3==1.26.17\n", "requirements.txt"),
    ("flask below the 2.2 branch", "flask==2.1.0\n", "flask==2.2.4\n", "requirements.txt"),
    ("aiohttp at every fix", "aiohttp==3.10.11\n", "aiohttp==3.9.2\n", "requirements.txt"),
    ("npm partial <= refused", '{"dependencies": {"axios": "<=1.6"}}',
     '{"dependencies": {"axios": "1.6.0"}}', "package.json"),
)

# ── reachability carriers ─────────────────────────────────────────────────
PINNED_PYYAML = "pyyaml==5.3.1\n"
IMPORTING_APP = module(
    "import yaml",
    "",
    "",
    "def load(text):",
    "    return yaml.safe_load(text)",
)
DORMANT_APP = module(
    "import os",
    "",
    "",
    "def where():",
    "    return os.getcwd()",
)
# A string that merely mentions an import, and a relative import of a local module: neither is an
# import of the distribution, and a grep-based reachability check would wrongly call both proof.
NOT_PROOF_APP = module(
    "from . import yaml",
    "",
    "NOTE = 'import yaml'",
    "",
    "",
    "def load(text):",
    "    return text",
)
NAME_MAP_CASES = (
    ("pillow==10.1.0\n", "from PIL import Image\n", "PIL"),
    ("pyjwt==2.3.0\n", "import jwt\n", "jwt"),
    ("beautifulsoup4==4.12.0\n", "import bs4\n", "bs4"),
    ("scikit-learn==1.3.0\n", "import sklearn\n", "sklearn"),
    ("python-dateutil==2.8.2\n", "import dateutil\n", "dateutil"),
    ("pyyaml==5.3.1\n", "import yaml as y\n", "yaml"),
    ("pyyaml==5.3.1\n", "from yaml import safe_load\n", "yaml"),
)
# Packages with no advisory in the index: an import of these proves nothing about a CVE, and the
# scanner must not invent one.
UNINDEXED = ("beautifulsoup4==4.12.0\n", "scikit-learn==1.3.0\n", "python-dateutil==2.8.2\n")

PYTHON_CARRIER = module(
    "import hashlib",
    "",
    "",
    "def digest(data):",
    "    return hashlib.md5(data).hexdigest()",
)
MIXED_FILES = {
    "requirements.txt": BAD_REQUIREMENTS,
    "package.json": BAD_PACKAGE_JSON,
    "app.py": PYTHON_CARRIER,
    "loader.py": IMPORTING_APP,
}


# ── tier 0: isolation laws ────────────────────────────────────────────────
NEW_MODULES = ("cve_index.py", "sca_scanner.py")
FORBIDDEN_IMPORTS = ("ast_scanner", "cli", "iac_auditor", "cross_file_engine", "yaml", "psutil",
                     "requests", "urllib", "http", "socket", "osv_client", "manifest_parser",
                     "version_matcher", "packaging", "tomllib")
MERGE_CONTRACT = (
    ("cli.py", "audit_sca_files(manifests)"),
    ("cli.py", "tag_reachability(sca_findings, _imported_roots(tracker))"),
    ("cli.py", "if sca_findings:"),
    ("scanners/sca_scanner.py", "UNREACHABLE_MANIFEST_ONLY"),
    ("scanners/cve_index.py", "if upper is None:"),
)


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
                failures.append(f"scanners/{name} imports {root}: the index must stay offline and "
                                f"stdlib-only, isolated from the Python engine ({stripped})")
    for name in ("ast_scanner.py", "iac_auditor.py"):
        source = (REPO_ROOT / name).read_text(encoding="utf-8")
        for needle in ("sca_scanner", "cve_index", "audit_sca_files", "from scanners"):
            if needle in source:
                failures.append(f"{name} references {needle!r}: the Python engine must stay untouched")
    for relative, needle in MERGE_CONTRACT:
        if needle not in (REPO_ROOT / relative).read_text(encoding="utf-8"):
            failures.append(f"{relative} lost the merge contract clause {needle!r}")
    return failures


# ── tier 1: bad cases ─────────────────────────────────────────────────────
def expected_bad():
    want = set()
    add = want.add
    req = "requirements.txt"
    for needle, cwe in (
        ("pyyaml==5.3.1", "CWE-502"),
        ("requests==2.30.0", "CWE-200"),
        ("urllib3==2.0.6", "CWE-200"),
        ("django==4.2.10", "CWE-1333"),
        ("jinja2==3.1.2", "CWE-79"),
        ("cryptography==42.0.3", "CWE-476"),
        ("pillow==10.1.0", "CWE-94"),
        ("werkzeug==3.0.2", "CWE-352"),
        ("aiohttp==3.9.2", "CWE-22"),
        ("starlette==0.36.1", "CWE-1333"),
        ("paramiko==3.3.1", "CWE-326"),
        ("sqlparse==0.4.4", "CWE-1333"),
        ("certifi==2023.7.21", "CWE-295"),
        ("flask==2.3.1", "CWE-200"),
        ("pyjwt==2.3.0", "CWE-347"),
    ):
        add((req, pin(BAD_REQUIREMENTS, needle), cwe, CATEGORY))
    add(("pyproject.toml", pin(BAD_PYPROJECT, '"pyyaml==5.3.1"'), "CWE-502", CATEGORY))
    add(("pyproject.toml", pin(BAD_PYPROJECT, '"pillow==10.1.0"'), "CWE-94", CATEGORY))
    add(("pyproject.toml", pin(BAD_PYPROJECT, '"sqlparse==0.4.4"'), "CWE-1333", CATEGORY))
    add(("pyproject.toml", pin(BAD_PYPROJECT, 'paramiko = "3.3.1"'), "CWE-326", CATEGORY))
    add(("pyproject.toml", pin(BAD_PYPROJECT, 'starlette = {version'), "CWE-1333", CATEGORY))
    add(("poetry.lock", pin(BAD_POETRY_LOCK, 'name = "pyyaml"'), "CWE-502", CATEGORY))
    add(("poetry.lock", pin(BAD_POETRY_LOCK, 'name = "certifi"'), "CWE-295", CATEGORY))
    add(("poetry.lock", pin(BAD_POETRY_LOCK, 'name = "requests"'), "CWE-295", CATEGORY))
    add(("package.json", pin(BAD_PACKAGE_JSON, '"lodash": "4.17.20"'), "CWE-78", CATEGORY))
    add(("package.json", pin(BAD_PACKAGE_JSON, '"axios": "1.6.0"'), "CWE-918", CATEGORY))
    add(("package.json", pin(BAD_PACKAGE_JSON, '"express": "4.19.1"'), "CWE-601", CATEGORY))
    add(("package.json", pin(BAD_PACKAGE_JSON, '"jsonwebtoken": "8.5.1"'), "CWE-20", CATEGORY))
    add(("package-lock.json", pin(BAD_PACKAGE_LOCK, '"node_modules/lodash"'), "CWE-78", CATEGORY))
    add(("package-lock.json", pin(BAD_PACKAGE_LOCK, '"node_modules/axios"'), "CWE-918", CATEGORY))
    return want


def check_bad():
    failures = []
    found = sca_scan(BAD_FILES)
    got = rows_of(found)
    want = expected_bad()
    for row in sorted(want - got):
        failures.append(f"BAD missing {row[0]}:{row[1]} {row[2]}")
    for row in sorted(got - want):
        failures.append(f"BAD invented {row[0]}:{row[1]} {row[2]}")
    by_key = {(item["file"], item["line"]): item for item in found}
    expectations = (
        ("requirements.txt", pin(BAD_REQUIREMENTS, "pyyaml==5.3.1"), ["CVE-2020-14343"], "5.4"),
        ("requirements.txt", pin(BAD_REQUIREMENTS, "pillow==10.1.0"),
         ["CVE-2023-50447", "CVE-2024-28219"], "10.3.0"),
        ("requirements.txt", pin(BAD_REQUIREMENTS, "jinja2==3.1.2"),
         ["CVE-2024-22195", "CVE-2024-34064", "CVE-2024-56201", "CVE-2025-27516"], "3.1.6"),
        ("requirements.txt", pin(BAD_REQUIREMENTS, "requests==2.30.0"),
         ["CVE-2023-32681", "CVE-2024-35195", "CVE-2024-47081"], "2.32.4"),
        ("package.json", pin(BAD_PACKAGE_JSON, '"axios": "1.6.0"'),
         ["CVE-2024-39338", "CVE-2025-27152"], "1.8.2"),
        ("package-lock.json", pin(BAD_PACKAGE_LOCK, '"node_modules/axios"'),
         ["CVE-2024-39338", "CVE-2025-27152"], "1.8.2"),
    )
    for name, line, cves, fixed in expectations:
        item = by_key.get((name, line))
        if item is None:
            failures.append(f"BAD no row at {name}:{line} to check the CVE set on")
            continue
        if item["cves"] != cves:
            failures.append(f"{name}:{line} carries {item['cves']}, expected {cves}")
        if item["fixed_version"] != fixed:
            failures.append(f"{name}:{line} upgrade target is {item['fixed_version']}, expected {fixed}")
        if item.get("related_cwes") != ["CWE-1395"]:
            failures.append(f"{name}:{line} lost its CWE-1395 component metadata")
        if item["confidence"] != "LOW" or item["reachability"] != "UNREACHABLE_MANIFEST_ONLY":
            failures.append(f"{name}:{line} claimed reachability without an import proof")
    return failures, len(want), len(got)


# ── tier 2: patched and unprovable ────────────────────────────────────────
def check_safe():
    failures = []
    loud = sca_scan(SAFE_FILES)
    if loud:
        failures.append(f"PATCHED tree is not quiet: {sorted(rows_of(loud))}")
    for name, quiet, twin in UNPROVABLE:
        if sca_scan({name: quiet}):
            failures.append(f"UNPROVABLE {name} {quiet.strip()!r} was reported")
        if not sca_scan({name: twin}):
            failures.append(f"UNPROVABLE {name} twin {twin.strip()!r} is quiet, so the quiet arm "
                            "proves nothing")
    for source in UNINDEXED:
        if sca_scan({"requirements.txt": source}):
            failures.append(f"a package with no advisory was reported: {source.strip()!r}")
    # An environment marker does not unpin the version: the pin is exact whenever the marker
    # holds, so dropping it would be a false negative, not a false-positive reduction.
    marked = sca_scan({"requirements.txt": "pyyaml==5.3.1 ; python_version < '3.9'\n"})
    if len(marked) != 1 or marked[0]["cves"] != ["CVE-2020-14343"]:
        failures.append(f"a marker-qualified exact pin was dropped: {[i['cves'] for i in marked]}")
    return failures


# ── tier 3: interval soundness ────────────────────────────────────────────
def check_intervals():
    failures = []
    for label, quiet, loud, name in INTERVAL_TWINS:
        if sca_scan({name: quiet}):
            failures.append(f"INTERVAL {label}: {quiet.strip()!r} allows a patched release but was reported")
        if not sca_scan({name: loud}):
            failures.append(f"INTERVAL {label}: the loud twin {loud.strip()!r} is quiet, so the "
                            "matcher never ran")
    # `pyyaml <5.4` allows 5.3.1, which fixes CVE-2020-1747 but not CVE-2020-14343.
    partial = sca_scan({"requirements.txt": "pyyaml<5.4\n"})
    if len(partial) != 1 or partial[0]["cves"] != ["CVE-2020-14343"]:
        failures.append(f"pyyaml<5.4 carried {[i['cves'] for i in partial]}, expected only "
                        "CVE-2020-14343 -- the advisory 5.3.1 already fixes was condemned")
    both = sca_scan({"requirements.txt": "pyyaml==5.3\n"})
    if len(both) != 1 or both[0]["cves"] != ["CVE-2020-14343", "CVE-2020-1747"]:
        failures.append(f"pyyaml==5.3 carried {[i['cves'] for i in both]}, expected both advisories")
    elif both[0]["fixed_version"] != "5.4":
        failures.append("the aggregate upgrade target is not the highest fix across advisories")
    # `introduced` is a real bound: aiohttp 3.8.6 predates the follow_redirects defect, so that one
    # advisory must stay out even though three others with no introduction do condemn the release.
    old = sca_scan({"requirements.txt": "aiohttp==3.8.6\n"})
    if len(old) != 1 or "CVE-2024-23334" in old[0]["cves"] or "CVE-2024-23829" not in old[0]["cves"]:
        failures.append(f"aiohttp==3.8.6 carried {[i['cves'] for i in old]}: the introduced bound "
                        "let CVE-2024-23334 condemn a release that predates it")
    # The clean single-advisory form of the same proof: next 13.3.0 predates Server Actions, so
    # only the cache-poisoning advisory, whose range starts at 13.0.0, may condemn it.
    early = sca_scan({"package.json": '{"dependencies": {"next": "13.3.0"}}'})
    if len(early) != 1 or early[0]["cves"] != ["CVE-2024-46982"]:
        failures.append(f"next 13.3.0 carried {[i['cves'] for i in early]}, expected only "
                        "CVE-2024-46982 -- the introduced bound is not being honoured")
    # A branch fix is not the newest fix: ws 7.5.10 patches the 7.x branch and must be quiet even
    # though 8.17.1 is the headline number for the same CVE.
    for quiet, loud in (("7.5.10", "7.5.9"), ("6.2.3", "6.2.2"), ("8.17.1", "8.17.0")):
        spec = '{"dependencies": {"ws": "%s"}}'
        if sca_scan({"package.json": spec % quiet}):
            failures.append(f"ws {quiet} is patched on its own branch but was reported")
        if not sca_scan({"package.json": spec % loud}):
            failures.append(f"ws {loud} is vulnerable on its own branch but stayed quiet")
    # A tilde that stops below one fix still allows the other defect: partial immunity is not immunity.
    tilde = sca_scan({"package.json": '{"dependencies": {"express": "~4.19.1"}}'})
    if len(tilde) != 1 or tilde[0]["cves"] != ["CVE-2024-43796"]:
        failures.append(f"express ~4.19.1 carried {[i['cves'] for i in tilde]}, expected only "
                        "CVE-2024-43796")
    elif tilde[0]["fixed_version"] != "4.21.0":
        failures.append("express ~4.19.1 upgrade target is not the remaining fix 4.21.0")
    ordering = (("5.3.1", "5.4", -1), ("6.0.1", "5.4", 1), ("1.0rc1", "1.0", -1),
                ("1.0", "1.0.post1", -1), ("1.2", "1.2.0", 0), ("2023.7.22", "2023.7.22", 0),
                ("4.17.20", "4.17.21", -1), ("1.26.9", "1.26.18", -1))
    for left, right, expected in ordering:
        got = CI.compare_versions(CI.parse_version(left), CI.parse_version(right))
        if got != expected:
            failures.append(f"version order {left} vs {right} gave {got}, expected {expected}")
    for spelling in ("*", "latest", "", "1.2.3+local", "1!2.0", "abc"):
        if CI.parse_version(spelling) is not None:
            failures.append(f"parse_version guessed at {spelling!r} instead of refusing it")
    return failures


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


def sca_rows(payload):
    return [item for item in payload["findings"] if item.get("category") == CATEGORY]


# ── tier 4: reachability through the real CLI ─────────────────────────────
def check_reachability():
    failures = []
    facts = {}
    # The distribution -> import namespace map is data, so it is checked as data too: a package
    # with no advisory in the index still has to map correctly the day one is added.
    for dist, expected in (("pyyaml", ("yaml",)), ("pillow", ("PIL",)),
                           ("beautifulsoup4", ("bs4",)), ("pyjwt", ("jwt",)),
                           ("python-jose", ("jose",)), ("scikit-learn", ("sklearn",)),
                           ("python-dateutil", ("dateutil",)), ("requests", ("requests",))):
        got = CI.import_roots_for(dist)
        if got != expected:
            failures.append(f"import map {dist} -> {got}, expected {expected}")
    with tempfile.TemporaryDirectory(prefix="tcs_sca_reach_") as tmp:
        root = Path(tmp)
        loud_tree, quiet_tree, false_tree = root / "loud", root / "quiet", root / "false"
        for tree, app in ((loud_tree, IMPORTING_APP), (quiet_tree, DORMANT_APP),
                          (false_tree, NOT_PROOF_APP)):
            write_tree(tree, {"requirements.txt": PINNED_PYYAML, "app.py": app})
        payloads = {}
        for label, tree in (("loud", loud_tree), ("quiet", quiet_tree), ("false", false_tree)):
            _code, payload = run_cli(["scan", ".", "--format", "json", "--workers", "1",
                                      "--include-tests"], tree)
            rows = sca_rows(payload)
            if len(rows) != 1:
                failures.append(f"{label}: expected exactly 1 SCA row, got {len(rows)}")
                continue
            payloads[label] = rows[0]
        if "loud" in payloads:
            item = payloads["loud"]
            facts["loud"] = (item["reachability"], item["confidence"])
            if item["reachability"] != "REACHABLE" or item["confidence"] != "HIGH":
                failures.append(f"importing project is {item['reachability']}/{item['confidence']}, "
                                "expected REACHABLE/HIGH")
            if "app.py:1" not in item["message"]:
                failures.append(f"REACHABLE row carries no import evidence: {item['message']}")
        for label in ("quiet", "false"):
            if label not in payloads:
                continue
            item = payloads[label]
            facts[label] = (item["reachability"], item["confidence"])
            if item["reachability"] != "UNREACHABLE_MANIFEST_ONLY" or item["confidence"] != "LOW":
                failures.append(f"{label} project is {item['reachability']}/{item['confidence']}, "
                                "expected UNREACHABLE_MANIFEST_ONLY/LOW")
        if "loud" in payloads and "quiet" in payloads:
            loud, quiet = payloads["loud"], payloads["quiet"]
            for field in ("file", "line", "cwe", "cves", "package", "fixed_version", "severity"):
                if loud[field] != quiet[field]:
                    failures.append(f"reachability changed the detection field {field}: "
                                    f"{loud[field]!r} vs {quiet[field]!r}")
        # The distribution -> import namespace map, each with a loud and a dormant arm.
        for spec, importer, root_name in NAME_MAP_CASES:
            if spec in UNINDEXED:
                continue
            with tempfile.TemporaryDirectory(prefix="tcs_sca_map_") as inner:
                tree = Path(inner)
                write_tree(tree, {"requirements.txt": spec, "use.py": importer})
                _code, payload = run_cli(["scan", ".", "--format", "json", "--workers", "1",
                                          "--include-tests"], tree)
                rows = sca_rows(payload)
                if not rows:
                    failures.append(f"name map {spec.strip()} produced no row to label")
                    continue
                if rows[0]["reachability"] != "REACHABLE":
                    failures.append(f"{spec.strip()} imported as {root_name} was not REACHABLE")
                write_tree(tree, {"use.py": DORMANT_APP})
                _code, payload = run_cli(["scan", ".", "--format", "json", "--workers", "1",
                                          "--include-tests"], tree)
                rows = sca_rows(payload)
                if rows and rows[0]["reachability"] != "UNREACHABLE_MANIFEST_ONLY":
                    failures.append(f"{spec.strip()} stayed REACHABLE after the import was removed")
    return failures, facts


# ── tier 5: the Python engine is unchanged ────────────────────────────────
def check_engine_unchanged():
    failures = []
    with tempfile.TemporaryDirectory(prefix="tcs_sca_diff_") as tmp:
        tree = Path(tmp)
        write_tree(tree, MIXED_FILES)
        argv = ["scan", ".", "--format", "json", "--workers", "1", "--include-tests"]
        _code, enabled = run_cli(argv, tree)
        original = cli.audit_sca_files
        cli.audit_sca_files = lambda files: []
        try:
            _code, disabled = run_cli(argv, tree)
        finally:
            cli.audit_sca_files = original
        if cli.audit_sca_files is not original:
            failures.append("cli.audit_sca_files was not restored")
        py_on = sorted(json.dumps(item, sort_keys=True) for item in enabled["findings"]
                       if item["file"].endswith(".py"))
        py_off = sorted(json.dumps(item, sort_keys=True) for item in disabled["findings"]
                        if item["file"].endswith(".py"))
        if not py_on:
            failures.append("the mixed tree carries no Python row, so the differential is unmeasured")
        if py_on != py_off:
            failures.append(f"SCA changed Python findings: only-on={sorted(set(py_on) - set(py_off))} "
                            f"only-off={sorted(set(py_off) - set(py_on))}")
        for field in ("scanned_files_by_scope", "scope_breakdown", "parse_governor"):
            left, right = enabled[field], disabled[field]
            if field == "scanned_files_by_scope":
                left = {k: v for k, v in left.items() if k == "python"}
                right = {k: v for k, v in right.items() if k == "python"}
            elif field == "scope_breakdown":
                left, right = left["python"], right["python"]
            if left != right:
                failures.append(f"SCA changed {field} for Python: {left} vs {right}")
        if sca_rows(disabled):
            failures.append("blinding audit_sca_files left SCA rows in the payload")
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


# ── tier 6: CLI wiring ────────────────────────────────────────────────────
def check_wiring():
    failures = []
    facts = {}
    with tempfile.TemporaryDirectory(prefix="tcs_sca_wire_") as tmp:
        tree = Path(tmp)
        write_tree(tree, MIXED_FILES)
        argv = ["scan", ".", "--format", "json", "--workers", "1", "--include-tests"]
        _code, payload = run_cli(argv, tree)
        facts["files"] = payload["scanned_files_by_scope"]
        facts["scopes"] = payload["findings_by_scope"]
        if set(payload["findings_by_scope"]) != set(cli.SCOPE_ORDER):
            failures.append("findings_by_scope keys drifted from SCOPE_ORDER")
        if "sca" not in cli.SCOPE_ORDER:
            failures.append("SCOPE_ORDER has no sca bucket")
        if payload["scanned_files_by_scope"]["sca"] != 2:
            failures.append(f"expected 2 manifests discovered, got {payload['scanned_files_by_scope']}")
        if payload["scope_breakdown"]["sca"] != {"discovered": 2, "scanned": 2}:
            failures.append(f"sca scope_breakdown is {payload['scope_breakdown']['sca']}")
        rows = sca_rows(payload)
        expected_mixed = len(sca_scan({"requirements.txt": BAD_REQUIREMENTS,
                                       "package.json": BAD_PACKAGE_JSON}))
        if len(rows) != expected_mixed:
            failures.append(f"mixed tree emitted {len(rows)} SCA rows, expected {expected_mixed}")
        for item in rows:
            if cli._scope_of(item["file"], {}) != "sca":
                failures.append(f"{item['file']} is not routed to the sca scope")
        reachable = [item for item in rows if item["reachability"] == "REACHABLE"]
        if len(reachable) != 1 or reachable[0]["package"] != "pyyaml":
            failures.append(f"expected exactly the imported pyyaml pin to be REACHABLE, got "
                            f"{[(i['package'], i['reachability']) for i in rows]}")
        _code, only = run_cli(argv + ["--scope", "sca"], tree)
        facts["sca_only_files"] = only["scanned_files_by_scope"]
        if only["scanned_files_by_scope"]["python"] != 0:
            failures.append("--scope sca still scanned Python files")
        if any(not item["file"].endswith((".txt", ".json", ".toml", ".lock"))
               for item in only["findings"]):
            failures.append("--scope sca emitted a non-manifest finding")
        if not sca_rows(only):
            failures.append("--scope sca emitted no SCA row at all")
        if any(item["reachability"] != "UNREACHABLE_MANIFEST_ONLY" for item in sca_rows(only)):
            failures.append("--scope sca claimed REACHABLE with no Python tree parsed")
        _code, py_only = run_cli(argv + ["--scope", "python"], tree)
        if sca_rows(py_only):
            failures.append("--scope python emitted SCA rows")
        if py_only["scanned_files_by_scope"]["sca"] != 0:
            failures.append("--scope python still counted manifests")
        # A global exclude_paths entry is a never-read rule and must still hold for manifests.
        (tree / ".tcs.yaml").write_text('exclude_paths:\n  - "package.json"\n', encoding="utf-8")
        _code, excluded = run_cli(argv, tree)
        if any(item["file"] == "package.json" for item in sca_rows(excluded)):
            failures.append("a globally excluded manifest was still audited")
        if not any(item["file"] == "requirements.txt" for item in sca_rows(excluded)):
            failures.append("the global exclude silenced a manifest it does not name")
        (tree / ".tcs.yaml").unlink()
        # An inline suppression on the manifest line itself, in the engine's own directive syntax.
        write_tree(tree, {"requirements.txt": "pyyaml==5.3.1  # tcs: ignore[CWE-502]\n"})
        _code, suppressed = run_cli(argv, tree)
        facts["inline_suppressed"] = not any(
            item["file"] == "requirements.txt" and item["package"] == "pyyaml"
            for item in sca_rows(suppressed))
        if not facts["inline_suppressed"]:
            failures.append("a `# tcs: ignore[CWE-502]` directive on the manifest line did not "
                            "suppress the SCA row")
        if not any(item["file"] == "package.json" for item in sca_rows(suppressed)):
            failures.append("the inline directive silenced a manifest it was not written on")
    return failures, facts


# ── tier 7: mutations ─────────────────────────────────────────────────────
def _const(value):
    return lambda *args, **kwargs: value


def _no_version_proof(ecosystem, package, lower, upper, inclusive):
    """The falsifier direction: every advisory for the package, whatever the pin says."""
    return CI.advisories_for(ecosystem, package)


def _blinded_parsers(kind):
    """`audit_sca_files` dispatches through `_PARSERS`, so the table is the decision point."""
    blinded = dict(SCA._PARSERS)
    blinded[kind] = _const([])
    return blinded


MUTATIONS = {
    "requirements_reader_blind": (
        ((SCA, "_PARSERS", _blinded_parsers("requirements")),),
        ("requirements.txt", "CWE-502")),
    "pyproject_reader_blind": (
        ((SCA, "_PARSERS", _blinded_parsers("pyproject")),),
        ("pyproject.toml", "CWE-502")),
    "poetry_lock_reader_blind": (
        ((SCA, "_PARSERS", _blinded_parsers("poetry_lock")),),
        ("poetry.lock", "CWE-502")),
    "package_json_reader_blind": (
        ((SCA, "_PARSERS", _blinded_parsers("package_json")),),
        ("package.json", "CWE-78")),
    "package_lock_reader_blind": (
        ((SCA, "_PARSERS", _blinded_parsers("package_lock")),),
        ("package-lock.json", "CWE-78")),
    "matcher_blind": (
        ((SCA, "matching_advisories", _const(())),),
        ("requirements.txt", "CWE-502")),
    "version_parser_blind": (
        ((SCA, "parse_version", _const(None)),),
        ("requirements.txt", "CWE-502")),
    "python_bounds_blind": (
        ((SCA, "_python_bounds", _const(SCA.UNBOUNDED)),),
        ("requirements.txt", "CWE-502")),
    "npm_bounds_blind": (
        ((SCA, "_npm_bounds", _const(SCA.UNBOUNDED)),),
        ("package.json", "CWE-78")),
    "manifest_path_blind": (
        ((cli, "is_manifest_path", _const(False)),),
        None),
    "reachability_upgrade_blind": (
        ((SCA, "tag_reachability", lambda findings, roots: findings),),
        None),
    "version_proof_removed": (
        ((SCA, "matching_advisories", _no_version_proof),),
        None),
}


def run_mutations():
    failures = []
    caught = 0
    baseline = sca_scan(BAD_FILES)
    base_rows = rows_of(baseline)
    for name, (patches, watched) in sorted(MUTATIONS.items()):
        saved = [(mod, attribute, inspect.getattr_static(mod, attribute))
                 for mod, attribute, _replacement in patches]
        try:
            for mod, attribute, replacement in patches:
                setattr(mod, attribute, replacement)
            if name == "manifest_path_blind":
                with tempfile.TemporaryDirectory(prefix="tcs_sca_mut_") as inner:
                    tree = Path(inner)
                    write_tree(tree, MIXED_FILES)
                    _code, payload = run_cli(["scan", ".", "--format", "json", "--workers", "1",
                                              "--include-tests"], tree)
                seen = (payload["scanned_files_by_scope"]["sca"] == 0 and not sca_rows(payload))
            elif name == "reachability_upgrade_blind":
                mutated = sca_scan({"requirements.txt": PINNED_PYYAML},
                                   {"yaml": ("app.py", 1)})
                seen = bool(mutated) and all(item["confidence"] == "LOW" for item in mutated)
            elif name == "version_proof_removed":
                mutated = sca_scan(SAFE_FILES)
                seen = len(rows_of(mutated)) >= 15
            else:
                mutated = sca_scan(BAD_FILES)
                mutated_rows = rows_of(mutated)
                victims = [row for row in base_rows
                           if row[0] == watched[0] and row[2] == watched[1]]
                if not victims:
                    failures.append(f"{name}: the baseline carries no {watched} row to lose")
                    continue
                seen = not any(row in mutated_rows for row in victims)
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
    return failures, caught, len(base_rows)


def peak_rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1048576.0
    except Exception:
        return 0.0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--dump":
        for item in sca_scan(BAD_FILES):
            print(f"  {item['file']}:{item['line']} {item['cwe']} {item['package']} "
                  f"{item['cves']} fix>={item['fixed_version']}")
        return 0

    failures = []
    law_failures = check_laws()
    failures += law_failures
    print(f"TIER 0 - isolation laws over {len(NEW_MODULES)} new modules: {len(law_failures)} failure(s)")

    bad_failures, want, got = check_bad()
    failures += bad_failures
    print(f"TIER 1 - bad cases: {want} expected rows, {got} emitted, {len(bad_failures)} failure(s)")

    safe_failures = check_safe()
    failures += safe_failures
    print(f"TIER 2 - patched + unprovable over {len(SAFE_FILES)} families and {len(UNPROVABLE)} "
          f"unprovable specs: {len(safe_failures)} failure(s)")

    interval_failures = check_intervals()
    failures += interval_failures
    print(f"TIER 3 - interval soundness over {len(INTERVAL_TWINS)} twins: "
          f"{len(interval_failures)} failure(s)")

    reach_failures, reach = check_reachability()
    failures += reach_failures
    print(f"TIER 4 - reachability through the real CLI: loud={reach.get('loud')} "
          f"quiet={reach.get('quiet')} false_proof={reach.get('false')} "
          f"{len(reach_failures)} failure(s)")

    engine_failures, py_rows, diff_state = check_engine_unchanged()
    failures += engine_failures
    print(f"TIER 5 - Python differential: {py_rows} row(s) byte-identical with SCA on and off, "
          f"engine diff={diff_state}, {len(engine_failures)} failure(s)")

    wire_failures, facts = check_wiring()
    failures += wire_failures
    print(f"TIER 6 - CLI wiring: files={facts.get('files')} findings={facts.get('scopes')} "
          f"inline_suppressed={facts.get('inline_suppressed')} {len(wire_failures)} failure(s)")

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
        print("VERDICT: FAIL - an SCA rule lost a true positive, a patched or unprovable pin went "
              "loud, reachability was claimed without proof, or the Python engine moved. Fix the "
              "cause; never blind a rule.")
        return 1
    if elapsed > BUDGET_SECONDS or rss > BUDGET_RSS_MB:
        print("VERDICT: FAIL - budget blown, and a lock that is slow or heavy never runs.")
        return 1
    print(f"VERDICT: PASS - 5 manifest families loud on {want} exact rows, every patched and "
          f"unprovable pin quiet, {len(INTERVAL_TWINS)} interval twins sound, reachability proven "
          f"both ways, {py_rows} Python row(s) unchanged, engine diff={diff_state}, "
          f"{caught}/{len(MUTATIONS)} mutations caught, peak RSS {rss:.1f}MB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())