"""Software composition analysis -- manifests and lockfiles, stdlib only, fully offline.

Five manifest families are read line by line: ``requirements*.txt``, ``pyproject.toml``,
``poetry.lock``, ``package.json`` and ``package-lock.json``. Each yields dependencies carrying
the *interval* of versions its spec allows, not a guessed resolved version.

That interval is the whole zero-false-positive argument. `cve_index.matching_advisories` reports
an advisory only when every version inside the interval is vulnerable, so an unbounded spec
(``requests>=2.0``, ``*``, ``latest``, a VCS URL, an editable install) is quiet by construction:
it allows a patched release, and nothing has been proven. A pinned ``==5.3.1`` is an interval of
one version, which is why lockfiles and pinned requirements are the loud, high-signal case.

Reachability is a second, separate proof. A vulnerable pin that no scanned Python file imports is
dormant manifest noise, so it is labelled ``UNREACHABLE_MANIFEST_ONLY`` at ``LOW`` confidence and
the default table floor hides it; one that production code imports is ``REACHABLE`` at ``HIGH``.
The label never changes whether a finding is emitted -- only how loudly it is presented.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .cve_index import (
    VersionKey,
    compare_versions,
    import_roots_for,
    matching_advisories,
    normalize_package_name,
    parse_version,
)

__all__ = ["is_manifest_path", "audit_sca_files", "tag_reachability", "collect_components",
           "pinned_version_text", "CATEGORY"]

CATEGORY = "SCA_VULNERABLE_DEPENDENCY"
UNBOUNDED: Tuple[Optional[VersionKey], Optional[VersionKey], bool] = (None, None, True)
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
FINAL_RANK = 4

# A dependency: which registry, its name, the spec as written, the line it sits on, and the
# interval that spec allows. `upper_inclusive` distinguishes <=1.2.3 from <1.2.3.
Dependency = Tuple[str, str, str, int, Optional[VersionKey], Optional[VersionKey], bool]

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_PY_CLAUSE_RE = re.compile(r"^(===|==|!=|~=|<=|>=|<|>)\s*(.+)$")
_TOML_KEY_RE = re.compile(r'^\s*(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9_.-]+))\s*=\s*(.*)$')
_TOML_TABLE_RE = re.compile(r"^\s*\[\[?([^\]]+)\]?\]\s*$")
_POETRY_VERSION_RE = re.compile(r'version\s*=\s*"([^"]*)"')
_LOCK_NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
_LOCK_VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"')
_NPM_PREFIXES = ("workspace:", "file:", "link:", "portal:", "git:", "git+", "github:",
                 "http:", "https:", "npm:", "patch:")


def is_manifest_path(path: str) -> bool:
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name in ("pyproject.toml", "poetry.lock", "package.json", "package-lock.json"):
        return True
    return name.startswith("requirements") and name.endswith(".txt")


def _manifest_kind(path: str) -> Optional[str]:
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name == "pyproject.toml":
        return "pyproject"
    if name == "poetry.lock":
        return "poetry_lock"
    if name == "package-lock.json":
        return "package_lock"
    if name == "package.json":
        return "package_json"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "requirements"
    return None


# ── version intervals ─────────────────────────────────────────────────────
def _padded(parts: Sequence[int]) -> VersionKey:
    filled = tuple(parts) + (0,) * (3 - len(parts))
    return (filled, FINAL_RANK, 0)


def _bump(parts: Sequence[int], index: int) -> VersionKey:
    """The exclusive upper bound of a prefix: 1.2 -> 1.3.0, 1 -> 2.0.0."""
    filled = list(parts) + [0] * (index + 1 - len(parts))
    filled[index] += 1
    for position in range(index + 1, len(filled)):
        filled[position] = 0
    return (tuple(filled), FINAL_RANK, 0)


def _intersect(clauses: Sequence[Tuple[Optional[VersionKey], Optional[VersionKey], bool]]
               ) -> Tuple[Optional[VersionKey], Optional[VersionKey], bool]:
    lower: Optional[VersionKey] = None
    upper: Optional[VersionKey] = None
    inclusive = True
    for lo, hi, hi_inclusive in clauses:
        if lo is not None and (lower is None or compare_versions(lo, lower) > 0):
            lower = lo
        if hi is None:
            continue
        if upper is None:
            upper, inclusive = hi, hi_inclusive
            continue
        order = compare_versions(hi, upper)
        if order < 0:
            upper, inclusive = hi, hi_inclusive
        elif order == 0:
            inclusive = inclusive and hi_inclusive
    return (lower, upper, inclusive)


def _python_clause(clause: str) -> Optional[Tuple[Optional[VersionKey], Optional[VersionKey], bool]]:
    match = _PY_CLAUSE_RE.match(clause)
    if not match:
        key = parse_version(clause)
        return (key, key, True) if key is not None else None
    operator, value = match.group(1), match.group(2).strip()
    if operator == "!=":
        # An exclusion removes one version; it never bounds the interval from either side.
        return UNBOUNDED
    if value.endswith(".*"):
        if operator not in ("==", "==="):
            return None
        base = parse_version(value[:-2])
        if base is None:
            return None
        return (base, _bump(base[0], len(base[0]) - 1), False)
    key = parse_version(value)
    if key is None:
        return None
    if operator in ("==", "==="):
        return (key, key, True)
    if operator == "<=":
        return (None, key, True)
    if operator == "<":
        return (None, key, False)
    if operator in (">=", ">"):
        return (key, None, True)
    if operator == "~=":
        # PEP 440 compatible release: ~=X.Y.Z means >=X.Y.Z, ==X.Y.*
        if len(key[0]) < 2:
            return None
        return (key, _bump(key[0], len(key[0]) - 2), False)
    return None


def _python_bounds(spec: str) -> Tuple[Optional[VersionKey], Optional[VersionKey], bool]:
    text = str(spec).split(";", 1)[0].strip()
    if not text or text == "*":
        return UNBOUNDED
    clauses = []
    for clause in text.split(","):
        clause = clause.strip()
        if not clause:
            continue
        parsed = _python_clause(clause)
        if parsed is None:
            # One unrecognised clause makes the whole spec unresolvable. Widening it to "anything"
            # would be a guess, and a guess is how a dependency scanner invents a finding.
            return UNBOUNDED
        clauses.append(parsed)
    return _intersect(clauses) if clauses else UNBOUNDED


def _npm_parts(token: str) -> Optional[List[int]]:
    base = token.split("-", 1)[0].split("+", 1)[0]
    pieces = base.split(".")
    if len(pieces) > 3:
        return None
    parts: List[int] = []
    for piece in pieces:
        if piece in ("x", "X", "*"):
            break
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    return parts or None


def _npm_comparator(token: str) -> Optional[Tuple[Optional[VersionKey], Optional[VersionKey], bool]]:
    token = token.strip()
    if not token or token in ("*", "x", "X", "latest"):
        return UNBOUNDED
    if token.startswith("^"):
        parts = _npm_parts(token[1:])
        if not parts:
            return None
        # Caret pins the leftmost non-zero component; an all-zero prefix pins the last one given.
        index = next((i for i, part in enumerate(parts) if part != 0), len(parts) - 1)
        return (parse_version(token[1:]), _bump(parts, index), False)
    if token.startswith("~"):
        value = token[1:].lstrip(">").strip()
        parts = _npm_parts(value)
        if not parts:
            return None
        return (parse_version(value), _bump(parts, 1 if len(parts) >= 2 else 0), False)
    for operator in (">=", "<=", ">", "<", "="):
        if not token.startswith(operator):
            continue
        value = token[len(operator):].strip()
        key = parse_version(value)
        if key is None:
            return None
        # npm reads a partial `<=1.2` as <1.3.0 and `=1.2` as 1.2.x. Treating either as the
        # single version 1.2.0 would narrow the interval and could condemn a patched release.
        if operator in ("<=", "=") and len(key[0]) < 3:
            return None
        if operator in (">=", ">"):
            return (key, None, True)
        if operator == "<=":
            return (None, key, True)
        if operator == "<":
            return (None, key, False)
        return (key, key, True)
    parts = _npm_parts(token)
    if not parts:
        return None
    if len(parts) == 3:
        key = parse_version(token)
        return (key, key, True) if key is not None else None
    return (_padded(parts), _bump(parts, len(parts) - 1), False)


def _npm_branch(text: str) -> Optional[Tuple[Optional[VersionKey], Optional[VersionKey], bool]]:
    if not text:
        return UNBOUNDED
    hyphen = re.split(r"\s+-\s+", text)
    if len(hyphen) == 2:
        low = parse_version(hyphen[0].strip())
        high_parts = _npm_parts(hyphen[1].strip())
        if low is None or not high_parts:
            return None
        high = (parse_version(hyphen[1].strip()) if len(high_parts) == 3
                else _bump(high_parts, len(high_parts) - 1))
        return (low, high, len(high_parts) == 3)
    clauses = []
    for token in text.split():
        parsed = _npm_comparator(token)
        if parsed is None:
            return None
        clauses.append(parsed)
    return _intersect(clauses) if clauses else UNBOUNDED


def _npm_bounds(spec: str) -> Tuple[Optional[VersionKey], Optional[VersionKey], bool]:
    text = str(spec).strip()
    if not text or text.startswith(_NPM_PREFIXES):
        return UNBOUNDED
    branches = []
    for branch in text.split("||"):
        parsed = _npm_branch(branch.strip())
        if parsed is None:
            return UNBOUNDED
        branches.append(parsed)
    if not branches:
        return UNBOUNDED
    # A union is bounded above only when every branch is, and its bound is the widest one.
    lower = None
    upper = None
    inclusive = False
    for lo, hi, hi_inclusive in branches:
        if lo is not None and (lower is None or compare_versions(lo, lower) < 0):
            lower = lo
        if hi is None:
            return (lower, None, True)
        if upper is None:
            upper, inclusive = hi, hi_inclusive
            continue
        order = compare_versions(hi, upper)
        if order > 0:
            upper, inclusive = hi, hi_inclusive
        elif order == 0:
            inclusive = inclusive or hi_inclusive
    return (lower, upper, inclusive)


def _exact(version: str) -> Tuple[Optional[VersionKey], Optional[VersionKey], bool]:
    key = parse_version(version)
    return (key, key, True) if key is not None else UNBOUNDED


# ── requirements*.txt ─────────────────────────────────────────────────────
def _requirements(source: str) -> List[Dependency]:
    out: List[Dependency] = []
    pending = ""
    start = 0
    for lineno, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if not pending:
            start = lineno
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        text = (pending + line).strip()
        pending = ""
        text = text.split(" #", 1)[0].split(" --", 1)[0].split(";", 1)[0].strip()
        if not text or text.startswith(("-", ".", "/")) or "://" in text or "@" in text:
            # -e / -r / --index-url, a local path, a direct URL reference: no pinned version.
            continue
        match = _REQ_NAME_RE.match(text)
        if not match:
            continue
        name, spec = match.group(1), match.group(3).strip()
        if spec.startswith("(") and spec.endswith(")"):
            spec = spec[1:-1].strip()
        if not spec:
            continue
        lower, upper, inclusive = _python_bounds(spec)
        out.append(("pypi", normalize_package_name(name), spec, start, lower, upper, inclusive))
    return out


# ── pyproject.toml ────────────────────────────────────────────────────────
def _strip_toml_comment(text: str) -> str:
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index].rstrip()
    return text.rstrip()


def _toml_string(value: str) -> Optional[str]:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return None


def _pyproject(source: str) -> List[Dependency]:
    """Read the two dependency shapes the task names, keeping each entry's own line number.

    A line reader rather than tomllib: tomllib arrives in 3.11 and this project supports 3.10,
    and a parsed TOML document has thrown away the line numbers a finding has to point at.
    """
    out: List[Dependency] = []
    lines = source.splitlines()
    table = ""
    index = 0
    while index < len(lines):
        raw = _strip_toml_comment(lines[index])
        lineno = index + 1
        index += 1
        header = _TOML_TABLE_RE.match(raw)
        if header:
            table = header.group(1).strip().strip('"').strip("'")
            continue
        entry = _TOML_KEY_RE.match(raw)
        if not entry:
            continue
        key = entry.group(1) or entry.group(2) or entry.group(3)
        value = entry.group(4).strip()
        if table == "project" and key == "dependencies":
            body = value
            while body.count("[") > body.count("]") and index < len(lines):
                body += " " + _strip_toml_comment(lines[index])
                index += 1
            for element in re.findall(r'"([^"]*)"|\'([^\']*)\'', body):
                text = (element[0] or element[1]).strip()
                if not text:
                    continue
                # An array element is a quoted literal on its own line, not a JSON key: it has
                # no colon, so the key locator below would never match it.
                found = next((i for i, raw in enumerate(lines, 1)
                              if '"' + text + '"' in raw or "'" + text + "'" in raw), 1)
                match = _REQ_NAME_RE.match(text)
                if not match:
                    continue
                spec = match.group(3).strip()
                if not spec:
                    continue
                lower, upper, inclusive = _python_bounds(spec)
                out.append(("pypi", normalize_package_name(match.group(1)), spec,
                            found, lower, upper, inclusive))
        elif table == "tool.poetry.dependencies" and key.lower() != "python":
            body = value
            while body.count("{") > body.count("}") and index < len(lines):
                body += " " + _strip_toml_comment(lines[index])
                index += 1
            if body.startswith("{"):
                version = _POETRY_VERSION_RE.search(body)
                if not version:
                    continue
                spec = version.group(1)
            else:
                spec = _toml_string(body)
                if spec is None:
                    continue
            lower, upper, inclusive = _python_bounds(spec)
            out.append(("pypi", normalize_package_name(key), spec, lineno, lower, upper, inclusive))
    return out


# ── poetry.lock ───────────────────────────────────────────────────────────
def _poetry_lock(source: str) -> List[Dependency]:
    out: List[Dependency] = []
    name: Optional[str] = None
    version: Optional[str] = None
    lineno = 1

    def flush() -> None:
        if not name or not version:
            return
        lower, upper, inclusive = _exact(version)
        out.append(("pypi", normalize_package_name(name), version, lineno, lower, upper, inclusive))

    for index, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if line == "[[package]]":
            flush()
            name = version = None
            lineno = index
            continue
        hit = _LOCK_NAME_RE.match(line)
        if hit:
            name = hit.group(1)
            lineno = index
            continue
        hit = _LOCK_VERSION_RE.match(line)
        if hit:
            version = hit.group(1)
    flush()
    return out


# ── package.json / package-lock.json ──────────────────────────────────────
def _locate(lines: Sequence[str], key: str, hint: Optional[str], cursor: int) -> int:
    """Line of a JSON key, disambiguated by a value that must sit at or just below it.

    A lockfile repeats a bare package name at every nesting level, so the version is what tells
    two entries apart. The cursor keeps successive lookups in document order.
    """
    needle = '"' + key + '"'
    for index in range(cursor, len(lines)):
        text = lines[index]
        if needle not in text or ":" not in text:
            continue
        if hint is None or hint in text:
            return index + 1
        if any(hint in ahead for ahead in lines[index + 1:index + 9]):
            return index + 1
    return cursor + 1 if cursor < len(lines) else 1


def _npm_dependency(name: str, spec: str, lineno: int) -> Optional[Dependency]:
    normalized = normalize_package_name(name)
    if not normalized:
        return None
    lower, upper, inclusive = _npm_bounds(spec)
    return ("npm", normalized, spec, lineno, lower, upper, inclusive)


def _package_json(source: str) -> List[Dependency]:
    try:
        document = json.loads(source)
    except ValueError:
        return []
    if not isinstance(document, dict):
        return []
    lines = source.splitlines()
    out: List[Dependency] = []
    cursor = 0
    for section in ("dependencies", "devDependencies"):
        entries = document.get(section)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            if not isinstance(spec, str):
                continue
            lineno = _locate(lines, str(name), spec, cursor)
            cursor = lineno
            dependency = _npm_dependency(str(name), spec, lineno)
            if dependency is not None:
                out.append(dependency)
    return out


def _package_lock(source: str) -> List[Dependency]:
    try:
        document = json.loads(source)
    except ValueError:
        return []
    if not isinstance(document, dict):
        return []
    lines = source.splitlines()
    out: List[Dependency] = []
    cursor = 0
    packages = document.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict) or entry.get("link"):
                continue
            version = entry.get("version")
            if not isinstance(version, str):
                continue
            name = str(key).rsplit("node_modules/", 1)[-1]
            lineno = _locate(lines, str(key), '"version": "%s"' % version, cursor)
            if lineno <= cursor:
                lineno = _locate(lines, str(key), version, cursor)
            cursor = lineno
            dependency = _npm_dependency(name, version, lineno)
            if dependency is not None:
                out.append(dependency)
        return out

    def walk(entries: Any, depth: int) -> None:
        nonlocal cursor
        if not isinstance(entries, dict) or depth > 12:
            return
        for name, entry in entries.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str):
                lineno = _locate(lines, str(name), '"version": "%s"' % version, cursor)
                if lineno <= cursor:
                    lineno = _locate(lines, str(name), version, cursor)
                cursor = lineno
                dependency = _npm_dependency(str(name), version, lineno)
                if dependency is not None:
                    out.append(dependency)
            walk(entry.get("dependencies"), depth + 1)

    walk(document.get("dependencies"), 0)
    return out


# The readers inventory every declared dependency, including a spec with no ceiling. Whether a
# finding exists is `matching_advisories`' decision alone, so the audit and the SBOM share one parse.
_PARSERS = {
    "requirements": _requirements,
    "pyproject": _pyproject,
    "poetry_lock": _poetry_lock,
    "package_json": _package_json,
    "package_lock": _package_lock,
}

_VERSION_TOKEN = re.compile(
    r"\d+(?:\.\d+)*(?:[-.]?(?:a|b|c|rc|alpha|beta|pre|preview|dev|post|rev|r)[-.\d]*)?",
    re.IGNORECASE)


def pinned_version_text(spec: str, lower: Optional[VersionKey], upper: Optional[VersionKey],
                        upper_inclusive: bool) -> Optional[str]:
    """The one version a spec allows, in its own spelling, or None when it allows a range.

    An SBOM component may carry a version only when the manifest proves exactly one. `^4.17.20`
    and `~=5.3.1` allow many, so they inventory as version-less coordinates rather than as a
    guess at whichever release the resolver happened to pick.
    """
    if lower is None or upper is None or not upper_inclusive:
        return None
    if compare_versions(lower, upper) != 0:
        return None
    match = _VERSION_TOKEN.search(spec)
    return match.group(0) if match else None


def collect_components(files: Dict[str, str]) -> List[Dict[str, Any]]:
    """Every declared dependency in the manifests, vulnerable or not, for the SBOM inventory."""
    out: List[Dict[str, Any]] = []
    for file_path in sorted(files):
        kind = _manifest_kind(file_path)
        if kind is None:
            continue
        for ecosystem, name, spec, lineno, lower, upper, inclusive in _PARSERS[kind](files[file_path]):
            out.append({
                "ecosystem": ecosystem,
                "name": name,
                "version": pinned_version_text(spec, lower, upper, inclusive),
                "spec": spec,
                "file": file_path,
                "line": max(1, int(lineno)),
            })
    return out


# ── findings ──────────────────────────────────────────────────────────────
def _describe(finding: Dict[str, Any], evidence: Optional[Tuple[str, str, int]]) -> str:
    cves = ", ".join(finding["cves"])
    head = (f"{finding['cwe']}: {finding['package']} {finding['spec']} allows only versions below"
            f" the fix for {cves} (fixed in {finding['fixed_version']}). {finding['summary']}")
    if evidence is not None:
        return head + (f" REACHABLE: production code imports it as {evidence[0]} at"
                       f" {evidence[1]}:{evidence[2]}, so the vulnerable release is actually"
                       f" loaded. Upgrade to {finding['package']}>={finding['fixed_version']}.")
    return head + (" UNREACHABLE_MANIFEST_ONLY: no scanned Python file imports it, so this is a"
                   " dormant pin rather than a live exposure. It is hidden by the default table"
                   " confidence floor; pass --min-confidence low to list it.")


def audit_sca_files(files: Dict[str, str]) -> List[Dict[str, Any]]:
    """Audit manifests against the offline index. Reachability starts unproven, therefore LOW."""
    findings: List[Dict[str, Any]] = []
    for file_path in sorted(files):
        kind = _manifest_kind(file_path)
        if kind is None:
            continue
        for ecosystem, name, spec, lineno, lower, upper, inclusive in _PARSERS[kind](files[file_path]):
            matched = matching_advisories(ecosystem, name, lower, upper, inclusive)
            if not matched:
                continue
            ordered = sorted(matched, key=lambda item: (-SEVERITY_RANK.get(item[2], 0), item[0]))
            primary = ordered[0]
            # One pin can carry several advisories with different fixes; the upgrade target is the
            # highest of them, compared as versions rather than as tuples of unequal length.
            target = primary
            for item in ordered:
                candidate, current = parse_version(item[3]), parse_version(target[3])
                if candidate is not None and (current is None
                                              or compare_versions(candidate, current) > 0):
                    target = item
            finding: Dict[str, Any] = {
                "file": file_path,
                "line": max(1, int(lineno)),
                "cwe": primary[1],
                "severity": primary[2],
                "category": CATEGORY,
                "package": name,
                "ecosystem": ecosystem,
                "spec": spec,
                "cve": primary[0],
                "cves": sorted({item[0] for item in matched}),
                "fixed_version": target[3],
                "summary": primary[5],
                "related_cwes": ["CWE-1395"],
                "reachability": "UNREACHABLE_MANIFEST_ONLY",
                "confidence": "LOW",
            }
            finding["message"] = _describe(finding, None)
            findings.append(finding)
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["cwe"]))


def tag_reachability(findings: List[Dict[str, Any]],
                     imported_roots: Dict[str, Tuple[str, int]]) -> List[Dict[str, Any]]:
    """Upgrade a finding to REACHABLE/HIGH when an actual import proves the dependency is loaded.

    ``imported_roots`` maps a top-level import root to the first (file, line) that imports it.
    Only an upgrade ever happens here: without proof a finding keeps its conservative LOW label,
    so the reachability pass can never manufacture confidence. An npm dependency has no Python
    import proof available and therefore stays LOW.
    """
    for finding in findings:
        if finding.get("category") != CATEGORY or finding.get("ecosystem") != "pypi":
            continue
        evidence = None
        for root in import_roots_for(finding["package"]):
            hit = imported_roots.get(root.split(".", 1)[0])
            if hit is not None:
                evidence = (root, hit[0], hit[1])
                break
        if evidence is None:
            continue
        finding["reachability"] = "REACHABLE"
        finding["confidence"] = "HIGH"
        finding["message"] = _describe(finding, evidence)
    return findings