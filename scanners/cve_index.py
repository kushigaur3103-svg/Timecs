"""Curated offline advisory index for the SCA scanner -- compact stdlib data, no network.

Every record is a real published advisory with an exact `fixed` version, and where the vulnerable
range does not start at zero, an exact `introduced` version too. That second bound is what keeps
this index honest: `django < 4.2.11` written naively would also condemn 3.2.25, which is patched.
A record therefore describes the half-open interval ``[introduced, fixed)``.

The matcher in `matching_advisories` is deliberately stricter than a typical SCA resolver. It
answers "is EVERY version this manifest allows vulnerable?", not "is SOME version vulnerable?".
A spec with no upper bound (`requests>=2.0`, `*`, `latest`) allows a patched release, so it is
quiet. Guessing a resolved version is how a dependency scanner manufactures false positives.

Version order follows PEP 440 / semver closely enough to be exact on release numbers and on
pre/post releases: ``1.0rc1 < 1.0 < 1.0.post1``. A spelling this reader cannot represent returns
None, and an unresolvable version is never guessed at -- the dependency stays quiet.
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

__all__ = ["normalize_package_name", "parse_version", "compare_versions",
           "advisories_for", "matching_advisories", "VersionKey"]

# (release components, stage rank, stage number). Final releases rank 4, so a pre-release sorts
# below its own release and a post-release above it.
VersionKey = Tuple[Tuple[int, ...], int, int]

# (cve, cwe, severity, fixed, introduced, summary)
Advisory = Tuple[str, str, str, str, Optional[str], str]

PYPI_ADVISORIES: Dict[str, Tuple[Advisory, ...]] = {
    "pyyaml": (
        ("CVE-2020-1747", "CWE-502", "CRITICAL", "5.3.1", None,
         "full_load deserializes untrusted YAML into arbitrary Python objects"),
        ("CVE-2020-14343", "CWE-502", "CRITICAL", "5.4", None,
         "full_load still executes arbitrary Python constructors from untrusted YAML"),
    ),
    "requests": (
        ("CVE-2023-32681", "CWE-200", "MEDIUM", "2.31.0", None,
         "Proxy-Authorization header is leaked to the destination host on a redirect"),
        ("CVE-2024-35195", "CWE-295", "MEDIUM", "2.32.0", None,
         "a Session keeps verify=False for later requests to the same host after the first"),
    ),
    "urllib3": (
        ("CVE-2023-43804", "CWE-200", "MEDIUM", "1.26.17", None,
         "Cookie header is not stripped on a cross-origin redirect"),
        ("CVE-2023-43804", "CWE-200", "MEDIUM", "2.0.6", "2.0.0",
         "Cookie header is not stripped on a cross-origin redirect"),
        ("CVE-2023-45803", "CWE-200", "MEDIUM", "1.26.18", None,
         "request body is not stripped after a 303 redirect changes the method to GET"),
        ("CVE-2023-45803", "CWE-200", "MEDIUM", "2.0.7", "2.0.0",
         "request body is not stripped after a 303 redirect changes the method to GET"),
    ),
    "django": (
        ("CVE-2022-28346", "CWE-89", "HIGH", "2.2.28", "2.2",
         "SQL injection through a crafted column alias in QuerySet.annotate/aggregate"),
        ("CVE-2022-28346", "CWE-89", "HIGH", "3.2.13", "3.0",
         "SQL injection through a crafted column alias in QuerySet.annotate/aggregate"),
        ("CVE-2022-28346", "CWE-89", "HIGH", "4.0.4", "4.0",
         "SQL injection through a crafted column alias in QuerySet.annotate/aggregate"),
        ("CVE-2024-27351", "CWE-1333", "HIGH", "3.2.25", "3.2",
         "regular-expression denial of service in django.utils.text.Truncator"),
        ("CVE-2024-27351", "CWE-1333", "HIGH", "4.2.11", "4.0",
         "regular-expression denial of service in django.utils.text.Truncator"),
        ("CVE-2024-27351", "CWE-1333", "HIGH", "5.0.3", "5.0",
         "regular-expression denial of service in django.utils.text.Truncator"),
    ),
    "flask": (
        ("CVE-2023-30861", "CWE-200", "HIGH", "2.2.5", "2.2.0",
         "a cached redirect response can carry another client's session cookie"),
        ("CVE-2023-30861", "CWE-200", "HIGH", "2.3.2", "2.3.0",
         "a cached redirect response can carry another client's session cookie"),
    ),
    "jinja2": (
        ("CVE-2024-22195", "CWE-79", "MEDIUM", "3.1.3", None,
         "the xmlattr filter accepts keys with spaces, enabling attribute-injection XSS"),
        ("CVE-2024-34064", "CWE-79", "MEDIUM", "3.1.4", None,
         "the xmlattr filter accepts keys with whitespace, enabling attribute-injection XSS"),
    ),
    "cryptography": (
        ("CVE-2023-49083", "CWE-476", "HIGH", "41.0.6", None,
         "NULL dereference when loading a PKCS#7 certificate with no certificates"),
        ("CVE-2024-26130", "CWE-476", "HIGH", "42.0.4", None,
         "NULL dereference in pkcs12.serialize_key_and_certificates with a NULL key"),
    ),
    "pillow": (
        ("CVE-2023-50447", "CWE-94", "CRITICAL", "10.2.0", None,
         "PIL.ImageMath.eval executes arbitrary Python expressions from untrusted input"),
        ("CVE-2024-28219", "CWE-120", "HIGH", "10.3.0", None,
         "buffer overflow in _imagingcms when processing a crafted ICC profile"),
    ),
    "werkzeug": (
        ("CVE-2023-46136", "CWE-400", "HIGH", "2.3.8", "2.0.0",
         "multipart parsing accepts unbounded leading whitespace, exhausting CPU"),
        ("CVE-2023-46136", "CWE-400", "HIGH", "3.0.1", "3.0.0",
         "multipart parsing accepts unbounded leading whitespace, exhausting CPU"),
        ("CVE-2024-34069", "CWE-352", "HIGH", "3.0.3", None,
         "the interactive debugger can be driven cross-site, executing code on the host"),
    ),
    "aiohttp": (
        ("CVE-2024-23334", "CWE-22", "HIGH", "3.9.4", "3.9.0",
         "static routes with follow_symlinks allow traversal outside the root directory"),
        ("CVE-2024-23829", "CWE-444", "MEDIUM", "3.9.2", None,
         "the HTTP parser accepts malformed headers, enabling request smuggling"),
    ),
    "starlette": (
        ("CVE-2024-24762", "CWE-1333", "HIGH", "0.36.2", None,
         "multipart form parsing is quadratic in the number of parts, exhausting CPU"),
    ),
    "paramiko": (
        ("CVE-2023-48795", "CWE-326", "MEDIUM", "3.4.0", None,
         "Terrapin prefix truncation lets an on-path attacker strip SSH extension negotiation"),
    ),
    "sqlparse": (
        ("CVE-2024-4340", "CWE-1333", "HIGH", "0.5.0", None,
         "the regular expression behind sqlparse.format is quadratic on crafted SQL"),
    ),
    "certifi": (
        ("CVE-2023-37920", "CWE-295", "HIGH", "2023.7.22", None,
         "the trust store still carries the e-Tugra root certificate, which must be distrusted"),
    ),
    "pyjwt": (
        ("CVE-2022-29217", "CWE-347", "CRITICAL", "2.4.0", None,
         "algorithm confusion lets an HMAC key verify a token signed as RSA"),
    ),
}

NPM_ADVISORIES: Dict[str, Tuple[Advisory, ...]] = {
    "lodash": (
        ("CVE-2021-23337", "CWE-78", "HIGH", "4.17.21", None,
         "the template helper passes untrusted options into a shell command"),
    ),
    "axios": (
        ("CVE-2023-45857", "CWE-200", "MEDIUM", "1.6.0", None,
         "the XSRF-TOKEN header is sent to a third-party host on a cross-origin request"),
        ("CVE-2024-39338", "CWE-918", "HIGH", "1.7.4", None,
         "an absolute URL bypasses the configured proxy and baseURL, enabling SSRF"),
    ),
    "express": (
        ("CVE-2024-29041", "CWE-601", "MEDIUM", "4.19.2", None,
         "a malformed URL passed to response.redirect escapes the intended host"),
        ("CVE-2024-43796", "CWE-79", "MEDIUM", "4.21.0", None,
         "response.redirect interpolates untrusted input into the HTML body, enabling XSS"),
    ),
    "jsonwebtoken": (
        ("CVE-2022-23529", "CWE-20", "CRITICAL", "9.0.0", None,
         "the secretOrPublicKey callback can be driven to forge tokens across key types"),
    ),
}

_INDEXES = {"pypi": PYPI_ADVISORIES, "npm": NPM_ADVISORIES}

# Distribution names whose import namespace is not the distribution name. Everything absent here
# imports under its own normalized name with '-' turned into '_'.
DIST_TO_IMPORTS: Dict[str, Tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "pillow": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "pyjwt": ("jwt",),
    "python-jose": ("jose",),
    "scikit-learn": ("sklearn",),
    "python-dateutil": ("dateutil",),
    "attrs": ("attr", "attrs"),
    "opencv-python": ("cv2",),
    "mysqlclient": ("MySQLdb",),
    "pypdf2": ("PyPDF2",),
    "protobuf": ("google",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "python-multipart": ("multipart",),
    "python-dotenv": ("dotenv",),
    "typing-extensions": ("typing_extensions",),
}

_NAME_SPLIT_RE = re.compile(r"[-_.]+")
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$", re.IGNORECASE)
_STAGE_RE = re.compile(r"([a-z]+)[\-_.]?(\d*)")
_PRE_RANK = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2,
             "c": 3, "rc": 3, "pre": 3, "preview": 3}
_POST_RANK = {"post": 5, "rev": 5, "r": 5}
_FINAL_RANK = 4


def normalize_package_name(name: str) -> str:
    """PEP 503 normalization, which npm's registry spelling also satisfies."""
    return _NAME_SPLIT_RE.sub("-", str(name).strip().lower())


def parse_version(text: Optional[str]) -> Optional[VersionKey]:
    """A comparable version key, or None for a spelling this reader refuses to guess at."""
    if text is None:
        return None
    spelling = str(text).strip().lstrip("=").strip()
    if not spelling:
        return None
    # An epoch reorders every comparison that follows it, and a local label is build metadata.
    # Neither is modelled here, so both make the version unresolvable rather than comparable.
    if "!" in spelling or "+" in spelling:
        return None
    match = _VERSION_RE.match(spelling)
    if not match:
        return None
    release = tuple(int(part) for part in match.group(1).split("."))
    rest = match.group(2).strip().lower().lstrip("-_.")
    if not rest:
        return (release, _FINAL_RANK, 0)
    stage = _STAGE_RE.match(rest)
    if not stage:
        return None
    word, number = stage.group(1), stage.group(2)
    if word in _PRE_RANK:
        return (release, _PRE_RANK[word], int(number or 0))
    if word in _POST_RANK:
        return (release, _POST_RANK[word], int(number or 0))
    return None


def compare_versions(left: VersionKey, right: VersionKey) -> int:
    """-1 / 0 / 1. Release tuples are zero-padded, so 1.2 and 1.2.0 are the same version."""
    width = max(len(left[0]), len(right[0]))
    a = (left[0] + (0,) * (width - len(left[0])), left[1], left[2])
    b = (right[0] + (0,) * (width - len(right[0])), right[1], right[2])
    return (a > b) - (a < b)


def advisories_for(ecosystem: str, package: str) -> Tuple[Advisory, ...]:
    index = _INDEXES.get(ecosystem)
    if not index:
        return ()
    return index.get(normalize_package_name(package), ())


def import_roots_for(package: str) -> Tuple[str, ...]:
    normalized = normalize_package_name(package)
    curated = DIST_TO_IMPORTS.get(normalized)
    if curated:
        return curated
    return (normalized.replace("-", "_"),)


def matching_advisories(ecosystem: str, package: str, lower: Optional[VersionKey],
                        upper: Optional[VersionKey], upper_inclusive: bool) -> Tuple[Advisory, ...]:
    """Advisories that EVERY version allowed by the spec is vulnerable to.

    `lower`/`upper` are the spec's bounds, None meaning unbounded on that side. An unbounded
    upper side allows a patched release, so nothing is provable and the result is empty. A
    bounded spec whose lower side is below an advisory's `introduced` also allows a release
    that predates the defect, so that advisory is skipped too.
    """
    if upper is None:
        return ()
    matched = []
    for advisory in advisories_for(ecosystem, package):
        fixed = parse_version(advisory[3])
        if fixed is None:
            continue
        introduced = parse_version(advisory[4]) if advisory[4] else None
        if introduced is not None:
            if lower is None or compare_versions(lower, introduced) < 0:
                continue
        order = compare_versions(upper, fixed)
        if order < 0 or (order == 0 and not upper_inclusive):
            matched.append(advisory)
    return tuple(matched)