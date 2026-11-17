"""Container security scanner -- Dockerfiles and docker-compose, stdlib only.

Three rules, each decided from parsed instructions or parsed YAML nodes rather than a whole-file
pattern sweep:

* CWE-250 ``CONTAINER_ROOT_USER`` -- the image's FINAL stage runs as UID 0. Intermediate builder
  stages are not the shipped image, and ``FROM scratch`` has no user at all, so neither is reported.
* CWE-798 ``CONTAINER_HARDCODED_SECRET`` -- an ``ENV``/``ARG`` (or a compose ``environment:`` entry)
  writes a literal into a credential-named key. An empty value, a ``$VAR`` reference and an obvious
  placeholder are not secrets: they are the absence of one.
* CWE-829 ``CONTAINER_UNTRUSTED_OR_UNPINNED_IMAGE`` -- ``ADD`` fetches a remote URL with no checksum,
  or ``FROM`` names an image by ``:latest`` or by no reference at all. ``COPY`` moves a local file and
  a digest-pinned or local stage reference is immutable, so neither is reported.

The legacy ``iac_auditor.audit_dockerfile`` keeps its own CWE-250/CWE-269 rows untouched. This module
takes ``already_root_reported`` so one defect is not booked twice on one file.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import yaml_lite

__all__ = ["is_container_path", "is_dockerfile_name", "is_compose_path", "audit_container_files"]

COMPOSE_SUFFIXES = (".yml", ".yaml")
ROOT_USER_VALUES = frozenset({"root", "0", "root:root", "0:0", "root:0", "0:root"})
SECRET_KEY_WORDS = frozenset({
    "PASSWORD", "PASSWD", "SECRET", "API_KEY", "PRIVATE_KEY",
    "AWS_SECRET_ACCESS_KEY", "AUTH_TOKEN", "ACCESS_TOKEN",
})
PLACEHOLDER_VALUES = frozenset({"changeme", "example", "dummy", "placeholder", "none", "null", ""})
CONTINUATION = "\\"

_DIGEST_RE = re.compile(r"@sha256:[0-9a-fA-F]{64}\s*$")
_REMOTE_ADD_RE = re.compile(r"^https?://", re.IGNORECASE)
_KEY_SPLIT_RE = re.compile(r"[^0-9A-Za-z]+")


def is_dockerfile_name(path: str) -> bool:
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.startswith("dockerfile") or name.endswith(".dockerfile")


def is_compose_path(path: str) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    return name.startswith("docker-compose") and name.endswith(COMPOSE_SUFFIXES)


def is_container_path(path: str) -> bool:
    return is_dockerfile_name(path) or is_compose_path(path)


# ── Dockerfile instructions ───────────────────────────────────────────────
def _instructions(source: str) -> List[Tuple[int, str, str]]:
    """[(start_line, KEYWORD, arguments)] honouring backslash continuations."""
    out: List[Tuple[int, str, str]] = []
    logical: List[str] = []
    start = 0
    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = raw.strip()
        if not logical:
            if not line or line.startswith("#"):
                continue
            start = lineno
        elif not line or line.startswith("#"):
            out.append(_split(start, logical))
            logical = []
            continue
        if line.endswith(CONTINUATION) and not line.endswith("\\\\"):
            logical.append(line[:-1].strip())
            continue
        logical.append(line)
        out.append(_split(start, logical))
        logical = []
    if logical:
        out.append(_split(start, logical))
    return [(line, kw, args) for line, kw, args in out if kw]


def _split(start: int, logical: Sequence[str]) -> Tuple[int, str, str]:
    text = " ".join(logical)
    keyword, _, arguments = text.partition(" ")
    return start, keyword.strip().upper(), arguments.strip()


def _from_target(arguments: str) -> Tuple[str, Optional[str]]:
    """(image_reference, stage_alias) for a FROM instruction, skipping ``--flag=`` options."""
    alias = None
    tokens = arguments.split()
    kept: List[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.lower() == "as" and index + 1 < len(tokens):
            alias = tokens[index + 1].lower()
            break
        if token.startswith("--"):
            index += 1
            continue
        kept.append(token)
        index += 1
    return (kept[0] if kept else ""), alias


def _image_is_pinned(reference: str) -> bool:
    if _DIGEST_RE.search(reference):
        return True
    name, separator, tag = reference.rpartition(":")
    if not separator or not name:
        return False
    return bool(tag) and tag.lower() != "latest"


def _stages(instructions: Sequence[Tuple[int, str, str]]) -> List[List[Tuple[int, str, str]]]:
    stages: List[List[Tuple[int, str, str]]] = []
    for entry in instructions:
        if entry[1] == "FROM":
            stages.append([entry])
        elif stages:
            stages[-1].append(entry)
    return stages


# ── shared value proofs ───────────────────────────────────────────────────
def _key_is_sensitive(key: str) -> bool:
    normalized = "_".join(part for part in _KEY_SPLIT_RE.split(str(key).upper()) if part)
    if normalized in SECRET_KEY_WORDS:
        return True
    return any(normalized.endswith("_" + word) for word in SECRET_KEY_WORDS)


def _value_is_a_hardcoded_secret(value: str) -> bool:
    """A non-empty literal that is neither a variable reference nor an obvious placeholder."""
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1].strip()
    if not text or "$" in text:
        return False
    lowered = text.lower()
    if lowered in PLACEHOLDER_VALUES:
        return False
    if lowered.startswith(("your_", "your-", "<", "{{")):
        return False
    return True


def _finding(file_path: str, line: int, cwe: str, category: str, severity: str, message: str) -> Dict[str, Any]:
    return {
        "file": file_path,
        "line": max(1, int(line)),
        "cwe": cwe,
        "severity": severity,
        "category": category,
        "message": f"{cwe}: {message}",
    }


# ── Dockerfile rules ──────────────────────────────────────────────────────
def _dockerfile_root_user(file_path: str, instructions: Sequence[Tuple[int, str, str]]) -> List[Dict[str, Any]]:
    stages = _stages(instructions)
    if not stages:
        return []
    final = stages[-1]
    from_line, _kw, from_args = final[0]
    reference, _alias = _from_target(from_args)
    if reference.lower() == "scratch":
        return []
    users = [entry for entry in final if entry[1] == "USER"]
    if users:
        user_line, _kw, user_args = users[-1]
        value = user_args.split()[0].lower() if user_args.split() else ""
        if value not in ROOT_USER_VALUES:
            return []
        return [_finding(
            file_path, user_line, "CWE-250", "CONTAINER_ROOT_USER", "HIGH",
            f"Final stage sets USER {value}: the container process runs as UID 0, so a container"
            " escape inherits root on the host. Set USER to a non-root account or a numeric UID"
            " above 0")]
    return [_finding(
        file_path, from_line, "CWE-250", "CONTAINER_ROOT_USER", "HIGH",
        f"Final stage FROM {reference} declares no USER instruction, so the image runs as root."
        " Add USER <non-root> after the final FROM so a container escape does not inherit UID 0")]


def _dockerfile_secrets(file_path: str, instructions: Sequence[Tuple[int, str, str]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for line, keyword, arguments in instructions:
        if keyword not in ("ENV", "ARG"):
            continue
        for key, value in _env_pairs(keyword, arguments):
            if _key_is_sensitive(key) and _value_is_a_hardcoded_secret(value):
                findings.append(_finding(
                    file_path, line, "CWE-798", "CONTAINER_HARDCODED_SECRET", "HIGH",
                    f"{keyword} {key} embeds a literal credential in the image layer history."
                    " Read it from a build secret or the runtime environment instead of baking it"
                    " into the image"))
    return findings


def _env_pairs(keyword: str, arguments: str) -> List[Tuple[str, str]]:
    """ENV/ARG assignments: ``K=V K2=V2`` and the legacy ``ENV K V`` single-pair form."""
    text = arguments.strip()
    if not text:
        return []
    if "=" not in text.split()[0]:
        if keyword == "ENV":
            key, _, value = text.partition(" ")
            return [(key.strip(), value.strip())] if key.strip() else []
        return [(text.split()[0], "")]
    pairs: List[Tuple[str, str]] = []
    for match in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s]*)", text):
        pairs.append((match.group(1), match.group(2)))
    return pairs


def _dockerfile_images(file_path: str, instructions: Sequence[Tuple[int, str, str]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    aliases: Set[str] = set()
    for line, keyword, arguments in instructions:
        if keyword == "ADD":
            for token in arguments.split():
                if _REMOTE_ADD_RE.match(token.strip("\"'")):
                    findings.append(_finding(
                        file_path, line, "CWE-829", "CONTAINER_UNTRUSTED_OR_UNPINNED_IMAGE", "HIGH",
                        f"ADD fetches {token} over the network with no checksum verification, so a"
                        " compromised or spoofed endpoint changes the image silently. Download with"
                        " a verified digest, or COPY a file already in the build context"))
                    break
        elif keyword == "FROM":
            reference, alias = _from_target(arguments)
            if alias:
                aliases.add(alias)
            bare = reference.split("@", 1)[0].rpartition(":")[0] or reference
            if not reference or reference.lower() == "scratch":
                continue
            if bare.lower() in aliases and "@" not in reference and ":" not in reference:
                continue
            if _image_is_pinned(reference):
                continue
            findings.append(_finding(
                file_path, line, "CWE-829", "CONTAINER_UNTRUSTED_OR_UNPINNED_IMAGE", "HIGH",
                f"FROM {reference} is not pinned to an immutable digest, so the base image can"
                " change under the build without any edit here. Reference it by @sha256:<digest>"))
    return findings


# ── docker-compose rules ──────────────────────────────────────────────────
def _compose_services(root: Any) -> Iterable[Tuple[str, int, Any]]:
    services = yaml_lite.get(root, "services")
    if isinstance(services, yaml_lite.Mapping):
        for name, lineno, value in services.items:
            yield name, lineno, value
        return
    if isinstance(root, yaml_lite.Mapping):
        for name, lineno, value in root.items:
            if isinstance(value, yaml_lite.Mapping) and (
                    yaml_lite.get(value, "image") is not None
                    or yaml_lite.get(value, "build") is not None):
                yield name, lineno, value


def _environment_entries(node: Any) -> Iterable[Tuple[str, int, str]]:
    if isinstance(node, yaml_lite.Mapping):
        for key, lineno, value in node.items:
            yield key, lineno, yaml_lite.scalar_text(value)
    elif isinstance(node, yaml_lite.Sequence):
        for lineno, value in node.items:
            text = yaml_lite.scalar_text(value)
            key, separator, val = text.partition("=")
            if separator:
                yield key.strip(), lineno, val.strip()


def _compose_rules(file_path: str, root: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for name, _lineno, service in _compose_services(root):
        if not isinstance(service, yaml_lite.Mapping):
            continue
        privileged = yaml_lite.get(service, "privileged")
        if isinstance(privileged, yaml_lite.Scalar) and privileged.text.strip().lower() == "true":
            findings.append(_finding(
                file_path, privileged.lineno, "CWE-250", "CONTAINER_ROOT_USER", "HIGH",
                f"Service {name} sets privileged: true, which grants every capability and device"
                " on the host. Drop privileged and add only the capabilities the service needs"))
        user = yaml_lite.get(service, "user")
        if isinstance(user, yaml_lite.Scalar):
            value = user.text.strip().strip("'\"").lower()
            if value in ROOT_USER_VALUES:
                findings.append(_finding(
                    file_path, user.lineno, "CWE-250", "CONTAINER_ROOT_USER", "HIGH",
                    f"Service {name} runs as user {value}: the container process holds UID 0."
                    " Set user to a non-root account or a numeric UID above 0"))
        for key, lineno, value in _environment_entries(yaml_lite.get(service, "environment")):
            if _key_is_sensitive(key) and _value_is_a_hardcoded_secret(value):
                findings.append(_finding(
                    file_path, lineno, "CWE-798", "CONTAINER_HARDCODED_SECRET", "HIGH",
                    f"Service {name} sets {key} to a literal credential in a file that is normally"
                    " committed. Reference an environment variable or a secrets file instead"))
    return findings


def audit_container_files(files: Dict[str, str],
                          already_root_reported: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """Audit Dockerfiles and compose documents. ``already_root_reported`` names files whose CWE-250
    the legacy Dockerfile auditor already booked, so one defect is not reported twice."""
    skip_root: Set[str] = set(already_root_reported or ())
    findings: List[Dict[str, Any]] = []
    for file_path in sorted(files):
        if is_dockerfile_name(file_path):
            instructions = _instructions(files[file_path])
            if not instructions:
                continue
            if file_path not in skip_root:
                findings.extend(_dockerfile_root_user(file_path, instructions))
            findings.extend(_dockerfile_secrets(file_path, instructions))
            findings.extend(_dockerfile_images(file_path, instructions))
        elif is_compose_path(file_path):
            findings.extend(_compose_rules(file_path, yaml_lite.parse(files[file_path])))
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["cwe"]))