"""Hard-coded secrets in configuration, environment and shell documents -- stdlib only.

The Python engine already owns hard-coded credentials inside `.py` source. This reader owns the
documents around it: `.env`, `*.ini`, `*.cfg`, `*.conf`, `*.toml`, `*.json`, `*.yaml`, `*.yml` and
`*.sh`, where a credential is not an expression the AST can reason about but a literal sitting in
a config file that ships with the image.

Precision is the whole design. Two families are detected:

* Vendor shapes -- an AWS key ID, a GitHub token, a Stripe live key, a Slack token or webhook, a
  PEM private-key header, a service URL carrying a password. These are recognisable on their own,
  so no entropy argument is needed: the prefix IS the proof.
* Generic sensitive assignments -- `API_KEY`, `SECRET_KEY`, `AUTH_TOKEN`, `ACCESS_TOKEN`,
  `CLIENT_SECRET`, `DB_PASSWORD`, `PRIVATE_KEY` (also under a vendor prefix, e.g.
  `STRIPE_SECRET_KEY`). A name alone is not a secret, so the value must additionally be a literal
  of at least 16 characters spanning at least two character classes with Shannon entropy >= 3.3.

Everything else is refused, and the refusals are the reason this reader can be loud by default:
shell interpolation (`${VAR}`, `$VAR`), empty and boolean/null literals, a 40-character hex string
with no credential name (a git commit SHA), and any value carrying a placeholder word. A template
or example document is never read at all -- `.env.example` exists to hold fake values.

Statistics alone cannot tell a credential from a sentence about a credential, so a generic
assignment must also pass a lexical test (`_is_literal_credential`): it may carry no space or tab,
and it may not be wrapped in a macro or reference marker. The bug this closes is Home Assistant's
`strings.json` localisation catalogues, whose UI labels sit under real sensitive names and clear
every statistical floor -- `"access_token": "Personal Access Token (PAT)"` measures 3.78 bits per
character over 27, and `"api_key": "[%key:common::config_flow::data::api_key%]"` (4.14 over 42) is a
reference to a string stored elsewhere, not the string itself. Both gates apply to the generic
branch only: a PEM header contains spaces by definition, and a URL password may legitimately carry
one, so those families keep their own proof and gain no new way to go quiet.

The matched secret is never copied into a finding. Reports, SARIF and logs are shared artefacts;
a scanner that re-publishes the credential it found has moved the leak rather than reported it.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

__all__ = ["is_secret_path", "audit_secret_files", "CATEGORY"]

CATEGORY = "HARDCODED_SECRET_CONFIG"

CONFIG_SUFFIXES = (".ini", ".cfg", ".conf", ".toml", ".json", ".yaml", ".yml", ".sh")
# A lockfile is a resolved dependency graph, not a credential store, and the SCA scanner owns it.
LOCKFILE_NAMES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "poetry.lock", "pipfile.lock",
    "cargo.lock", "gemfile.lock", "composer.lock", "pnpm-lock.yaml",
})
# These documents exist to carry fake values. Reading them would report the documentation.
TEMPLATE_SUFFIXES = (".example", ".sample", ".template")

# (label, pattern, severity). The pattern matches the credential itself, not the assignment.
VENDOR_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]", str], ...] = (
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "HIGH"),
    ("GitHub Personal Access Token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "HIGH"),
    ("GitHub Fine-Grained Token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"), "HIGH"),
    ("GitHub OAuth Token", re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "HIGH"),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}"), "CRITICAL"),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "HIGH"),
    ("Slack Incoming Webhook",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), "HIGH"),
    ("PEM Private Key",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "CRITICAL"),
)

SERVICE_URL = re.compile(
    r"(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:\s]+:([^@\s]{6,})@[^/\s]+")

SENSITIVE_NAMES = ("API_KEY", "SECRET_KEY", "AUTH_TOKEN", "ACCESS_TOKEN",
                   "CLIENT_SECRET", "DB_PASSWORD", "PRIVATE_KEY")
# One assignment shape covers dotenv/ini/shell (`K=v`), YAML (`K: v`), TOML (`K = v`) and
# JSON (`"K": "v"`): the optional closing quote after the key is what makes JSON fit.
ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*"""
    r"""(?P<value>"[^"]*"|'[^']*'|[^\s,;#}\]]+)""")

PLACEHOLDER_WORDS = ("example", "changeme", "placeholder", "dummy", "test", "sample",
                     "your_", "xxxx", "123456", "password", "secret")
# Four tokens that say what a value is *for* instead of carrying one. Kept apart from
# PLACEHOLDER_WORDS so this reader's newer refusal can be measured without moving the older one.
NON_SECRET_PLACEHOLDER_TOKENS = ("temporary_key", "replace_me", "not_found", "not_a_real_key")
# `user:user@localhost` proves a developer default rather than a deployed credential: the secret and
# its own username are the same dictionary word, and the host is this machine, so no deployment can
# be relying on it. Airflow ships exactly this pair in `default_airflow.cfg`, `default_test.cfg` and
# the documentation template `config.yml`, all three of which describe a broker URL rather than
# configure one.
LOCAL_SERVICE_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})
# A document whose own name declares it a test fixture or the shipped default of a product. Only the
# generic-assignment branch consults this: a vendor token, a PEM block or a service URL proves itself
# by shape and cannot be silenced by the name of the file it sits in.
NON_PRODUCTION_CONFIG_SUFFIXES = ("_test.cfg", "_test.ini", "_test.conf")
NON_PRODUCTION_CONFIG_PREFIXES = ("test_", "default_test.")
NON_PRODUCTION_CONFIG_EXTENSIONS = (".cfg", ".ini", ".conf", ".yml", ".yaml", ".env", ".properties")
NULL_LITERALS = frozenset({"null", "none", "true", "false", "~", "nil", "undefined"})
INTERPOLATION = re.compile(r"\$(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)")
COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")
MIN_GENERIC_LENGTH = 16
MIN_GENERIC_ENTROPY = 3.3
# The lexical floor for a *literal* credential, sitting under a sensitive name. Prose says what a
# credential is; a macro reference says where one lives. Neither is a secret, and no length,
# character-class or entropy threshold can separate them from one -- only shape can.
PROSE_CHARACTERS = (" ", "\t")
# A filesystem path says where a credential is kept, not what it is. `private_key = /etc/salt/pki/
# minion.pem` and `api_key: ~/credentials.json` clear every statistical floor -- a path is long, spans
# several character classes and is high-entropy by construction -- while shipping no secret at all; the
# file it names is the artefact an operator protects and rotates.
CREDENTIAL_PATH_PREFIXES = ("/", "./", "../", "~/")
CREDENTIAL_PATH_SUFFIXES = (".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".pub", ".json",
                            ".yaml", ".yml", ".conf", ".cfg", ".ini", ".env")
WINDOWS_DRIVE_PATH = re.compile(r"[A-Za-z]:[\\/].*")
# The closing marker is optional in every pattern below because ASSIGNMENT's unquoted alternative
# stops before `]`, `}` and `)`: `api_key: [%key:common::config_flow::data::api_key%]` arrives here
# as `[%key:common::config_flow::data::api_key%`. A reference is a reference either way.
REFERENCE_WRAPPERS = (
    # Home Assistant localisation catalogues (and Jinja/Template Toolkit references): the whole
    # value is `[%key:section::name%]`, a pointer into a string table.
    re.compile(r"\[\%.*\%\]?"),
    re.compile(r"\{\{.*\}\}?"),   # {{ expression }}
    re.compile(r"\{%.*%\}?"),     # {% statement %}
    re.compile(r"\$\{.*\}?"),     # ${VAR}
    re.compile(r"\$\(.*\)?"),     # $(command)
    re.compile(r"\<.*\>?"),       # <value supplied somewhere else>
)


def _is_literal_credential(value: str) -> bool:
    """False when the value is prose, a pointer, or a filesystem path rather than a secret itself.

    Gated on the generic-assignment branch only, by design: `-----BEGIN RSA PRIVATE KEY-----`
    carries spaces and `VENDOR_PATTERNS` / `SERVICE_URL` prove their own shapes, so this rule must
    never be able to silence them. A generic assignment is the one place where the name, not the
    value, did the identifying -- which is exactly where a UI label can impersonate a credential.
    """
    if not value:
        return False
    if any(char in value for char in PROSE_CHARACTERS):
        return False
    if any(pattern.fullmatch(value) for pattern in REFERENCE_WRAPPERS):
        return False
    if value.startswith(CREDENTIAL_PATH_PREFIXES) or WINDOWS_DRIVE_PATH.fullmatch(value):
        return False
    if value.lower().endswith(CREDENTIAL_PATH_SUFFIXES):
        return False
    return True


def _service_host(authority: str) -> str:
    """The bare host of an already-split `host` or `host:port`, IPv6 included."""
    host = authority.lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    head, separator, tail = host.rpartition(":")
    if separator and tail.isdigit():
        return head
    return host


def _service_credential_is_dev_default(url: str) -> bool:
    """True for `scheme://user:user@localhost/db`: the password is the username, on this machine.

    `sqla+mysql://airflow:airflow@localhost:3306/airflow` is a worked example of a broker URL, not a
    credential a deployment relies on -- and a deployment that really does run it that way is guarding
    the word `airflow`, which is not a secret worth rotating. `postgres://app:S3cr3tP4ss@db.internal
    /prod` fails both halves, so a production service URL cannot be silenced here.
    """
    _scheme, separator, rest = url.partition("://")
    if not separator:
        return False
    authority = rest.split("/", 1)[0]
    userinfo, at, host = authority.rpartition("@")
    if not at:
        return False
    user, colon, password = userinfo.partition(":")
    if not colon or user != password:
        return False
    return _service_host(host) in LOCAL_SERVICE_HOSTS


def _is_non_production_document(path: str) -> bool:
    """True when a config document's own name says it is a test fixture or a shipped default.

    Scoped to the generic-assignment branch by the caller: those are the hits identified by the key
    name alone, which is exactly where a template's `api_key = REPLACE_ME_NOW` can impersonate a
    credential. A value that proves its own shape is never reached by this rule.
    """
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(NON_PRODUCTION_CONFIG_SUFFIXES):
        return True
    if name.startswith(NON_PRODUCTION_CONFIG_PREFIXES):
        return name.endswith(NON_PRODUCTION_CONFIG_EXTENSIONS)
    return False


API_SPEC_NAME_MARKS = ("openapi", "swagger")
API_SPEC_VERSION_HEAD_BYTES = 512
API_SPEC_PATH_SCAN_BYTES = 65536
API_SPEC_VERSION_RE = re.compile(r"^(?:openapi|swagger)\s*:", re.MULTILINE)
API_SPEC_PATHS_RE = re.compile(r"^paths\s*:", re.MULTILINE)


def _is_api_specification_document(path: str, text: str) -> bool:
    """True for an OpenAPI/Swagger contract -- a description of an API, not a deployment of one.

    Zulip's whole public surface is written twice: once in code and once in
    `zerver/openapi/zulip.yaml`, which spells out every parameter, every example payload and every
    sample credential a client might send. Those strings are documentation that ships to the world
    on purpose, and the point of writing them is that they are not secrets. Five CWE-798 rows came
    from key names alone.

    Two independent ways to know it: the file's own name, or the two keys only a specification
    carries -- a version declaration in the first lines and a top-level `paths:` map. The cheap
    checks are bounded (`API_SPEC_*` below) so a large config file is never re-scanned for shape.
    """
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith((".yml", ".yaml", ".json")) and any(mark in name for mark in API_SPEC_NAME_MARKS):
        return True
    if not text:
        return False
    head = text[:API_SPEC_VERSION_HEAD_BYTES]
    if not API_SPEC_VERSION_RE.search(head):
        return False
    return bool(API_SPEC_PATHS_RE.search(text[:API_SPEC_PATH_SCAN_BYTES]))


def is_secret_path(path: str) -> bool:
    """True for a config/env/shell document this reader owns, by name alone."""
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name in LOCKFILE_NAMES or name.endswith(TEMPLATE_SUFFIXES):
        return False
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return True
    return name.endswith(CONFIG_SUFFIXES)


def shannon_entropy(text: str) -> float:
    """Bits per character. A repeated or single-class string cannot reach the generic floor."""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _character_classes(text: str) -> int:
    present = 0
    for probe in (str.islower, str.isupper, str.isdigit):
        if any(probe(char) for char in text):
            present += 1
    if any(not char.isalnum() for char in text):
        present += 1
    return present


def _unquote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1]
    return text.strip()


def is_refused(value: str, named: bool = False) -> bool:
    """The zero-FP contract: a value that is not a credential, whatever its shape.

    `named` says a credential name or a password position already identified this value, which is
    what separates a 40-hex secret from a 40-hex git commit SHA.
    """
    text = _unquote(value)
    if not text:
        return True
    lowered = text.lower()
    if lowered in NULL_LITERALS:
        return True
    if INTERPOLATION.search(text):
        return True
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return True
    if any(token in lowered for token in NON_SECRET_PLACEHOLDER_TOKENS):
        return True
    if not named and len(text) == 40 and COMMIT_SHA.fullmatch(text):
        return True
    return False


def _sensitive_name(key: str) -> Optional[str]:
    """The sensitive name a config key carries, exactly or under a vendor prefix."""
    normalized = key.upper().replace("-", "_").replace(".", "_")
    for name in SENSITIVE_NAMES:
        if normalized == name or normalized.endswith("_" + name):
            return name
    return None


def _redact(text: str) -> str:
    """Enough to locate the credential in the file, never enough to use it."""
    if len(text) <= 8:
        return "*" * len(text)
    return text[:4] + "*" * 8 + text[-2:]


def _iter_hits(source: str) -> Iterator[Tuple[int, str, str, str, str]]:
    """(lineno, label, severity, redacted, kind) for every credential the line proves."""
    for lineno, line in enumerate(source.splitlines(), start=1):
        if not line.strip():
            continue
        for label, pattern, severity in VENDOR_PATTERNS:
            match = pattern.search(line)
            if match and not is_refused(match.group(0), named=True):
                yield lineno, label, severity, _redact(match.group(0)), "vendor"
        for match in SERVICE_URL.finditer(line):
            if is_refused(match.group(1), named=True):
                continue
            if _service_credential_is_dev_default(match.group(0)):
                continue
            yield (lineno, "Service URL With Embedded Password", "HIGH",
                   _redact(match.group(1)), "service_url")
        for match in ASSIGNMENT.finditer(line):
            name = _sensitive_name(match.group("key"))
            if name is None:
                continue
            value = _unquote(match.group("value"))
            if is_refused(value, named=True):
                continue
            if not _is_literal_credential(value):
                continue
            if len(value) < MIN_GENERIC_LENGTH or _character_classes(value) < 2:
                continue
            if shannon_entropy(value) < MIN_GENERIC_ENTROPY:
                continue
            yield (lineno, f"Hard-coded {name}", "HIGH", _redact(value), "generic")


def audit_secret_files(files: Dict[str, str]) -> List[Dict[str, Any]]:
    """One finding per (document, line, credential family), in source order."""
    findings: List[Dict[str, Any]] = []
    for file_path in sorted(files):
        # The refusal is enforced here as well as at discovery, so a caller that hands over a
        # lockfile or a `.env.example` cannot make this reader report the documentation.
        if not is_secret_path(file_path):
            continue
        seen = set()
        # Both refusals are about the *document*, so they are answered once per file, not once per
        # hit: a name that says test fixture, and a shape that says API specification.
        generic_candidate_refused = (_is_non_production_document(file_path)
                                     or _is_api_specification_document(file_path,
                                                                       files[file_path]))
        for lineno, label, severity, redacted, kind in _iter_hits(files[file_path]):
            # A document that names itself a test fixture or the shipped default carries no deployed
            # credential, and the key name is the *only* thing that identified a generic hit -- so
            # `api_key = REPLACE_WITH_YOUR_KEY` in `service_test.cfg` is the one place the document's
            # own name is evidence. Vendor tokens and service URLs prove their shape and never reach
            # this clause.
            if kind == "generic" and generic_candidate_refused:
                continue
            # A line can satisfy two shapes at once -- a service URL whose password is also a
            # sensitive assignment. One credential is one finding, so the first shape wins.
            key = (lineno, label)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "file": file_path,
                "line": lineno,
                "cwe": "CWE-798",
                "severity": severity,
                "category": CATEGORY,
                "confidence": "HIGH",
                "secret_type": label,
                "secret_kind": kind,
                "evidence": redacted,
                "message": (f"{label} hard-coded in {file_path}:{lineno} "
                            f"(value {redacted}). Move it to a secret manager or an environment "
                            f"variable supplied at runtime, and rotate it: a credential committed "
                            f"to a config file is already exposed."),
            })
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["secret_type"]))