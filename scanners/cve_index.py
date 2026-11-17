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

A package with several supported branches carries one record per branch, because a single fix
version cannot describe them: `ws` fixed 8.17.1, 7.5.10, 6.2.3 and 5.2.4 for the same defect, and
a pin on the 7.x branch is patched at 7.5.10 even though that is far below 8.17.1.
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
        ("CVE-2024-47081", "CWE-200", "MEDIUM", "2.32.4", None,
         "a .netrc credential is sent to a third-party host reached through a redirect"),
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
        ("CVE-2024-37891", "CWE-200", "MEDIUM", "1.26.19", None,
         "Proxy-Authorization is not stripped when a redirect leaves the proxy"),
        ("CVE-2024-37891", "CWE-200", "MEDIUM", "2.2.2", "2.0.0",
         "Proxy-Authorization is not stripped when a redirect leaves the proxy"),
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
        ("CVE-2024-39329", "CWE-208", "MEDIUM", "4.2.15", "4.2",
         "the authentication backend's timing differs for an existing and an absent user"),
        ("CVE-2024-39329", "CWE-208", "MEDIUM", "5.0.8", "5.0",
         "the authentication backend's timing differs for an existing and an absent user"),
        ("CVE-2024-45230", "CWE-1333", "HIGH", "4.2.16", "4.2",
         "urlize is quadratic on crafted input, exhausting CPU"),
        ("CVE-2024-45230", "CWE-1333", "HIGH", "5.0.9", "5.0",
         "urlize is quadratic on crafted input, exhausting CPU"),
        ("CVE-2024-45230", "CWE-1333", "HIGH", "5.1.1", "5.1",
         "urlize is quadratic on crafted input, exhausting CPU"),
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
        ("CVE-2024-56201", "CWE-79", "MEDIUM", "3.1.5", None,
         "a crafted template filename escapes the sandbox and executes Python"),
        ("CVE-2025-27516", "CWE-79", "MEDIUM", "3.1.6", None,
         "the |attr filter escapes the sandbox through a crafted attribute name"),
    ),
    "cryptography": (
        ("CVE-2023-49083", "CWE-476", "HIGH", "41.0.6", None,
         "NULL dereference when loading a PKCS#7 certificate with no certificates"),
        ("CVE-2024-26130", "CWE-476", "HIGH", "42.0.4", None,
         "NULL dereference in pkcs12.serialize_key_and_certificates with a NULL key"),
        ("CVE-2023-50782", "CWE-208", "HIGH", "41.0.6", None,
         "Bleichenbacher timing oracle in the PKCS#1 v1.5 decryption path"),
        ("CVE-2024-0727", "CWE-476", "MEDIUM", "42.0.2", None,
         "NULL dereference when processing a crafted PKCS#12 file"),
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
        ("CVE-2024-49767", "CWE-400", "HIGH", "3.0.6", None,
         "multipart form parsing consumes unbounded resources on a crafted body"),
    ),
    "aiohttp": (
        ("CVE-2024-23334", "CWE-22", "HIGH", "3.9.4", "3.9.0",
         "static routes with follow_symlinks allow traversal outside the root directory"),
        ("CVE-2024-23829", "CWE-444", "MEDIUM", "3.9.2", None,
         "the HTTP parser accepts malformed headers, enabling request smuggling"),
        ("CVE-2024-30251", "CWE-400", "HIGH", "3.9.4", None,
         "a crafted multipart body is parsed without a size limit, exhausting memory"),
        ("CVE-2024-52304", "CWE-444", "HIGH", "3.10.11", None,
         "a chunked trailer section is accepted without validation, enabling request smuggling"),
    ),
    "starlette": (
        ("CVE-2024-24762", "CWE-1333", "HIGH", "0.36.2", None,
         "multipart form parsing is quadratic in the number of parts, exhausting CPU"),
        ("CVE-2023-29159", "CWE-22", "HIGH", "0.27.0", None,
         "StaticFiles follows a crafted path outside the configured directory"),
        ("CVE-2023-30798", "CWE-400", "HIGH", "0.27.0", None,
         "multipart form parsing accepts unbounded parts, exhausting CPU"),
    ),
    "paramiko": (
        ("CVE-2023-48795", "CWE-326", "MEDIUM", "3.4.0", None,
         "Terrapin prefix truncation lets an on-path attacker strip SSH extension negotiation"),
        ("CVE-2022-24302", "CWE-362", "MEDIUM", "2.10.1", None,
         "a race between key file creation and permission write exposes the private key"),
    ),
    "sqlparse": (
        ("CVE-2024-4340", "CWE-1333", "HIGH", "0.5.0", None,
         "the regular expression behind sqlparse.format is quadratic on crafted SQL"),
        ("CVE-2023-30608", "CWE-1333", "MEDIUM", "0.4.4", None,
         "the regular expression behind sqlparse.split is quadratic on crafted SQL"),
    ),
    "certifi": (
        ("CVE-2023-37920", "CWE-295", "HIGH", "2023.7.22", None,
         "the trust store still carries the e-Tugra root certificate, which must be distrusted"),
        ("CVE-2024-39689", "CWE-295", "HIGH", "2024.7.4", None,
         "the trust store still carries the GLOBALTRUST roots, which must be distrusted"),
    ),
    "pyjwt": (
        ("CVE-2022-29217", "CWE-347", "CRITICAL", "2.4.0", None,
         "algorithm confusion lets an HMAC key verify a token signed as RSA"),
    ),
    "fastapi": (
        ("CVE-2024-24762", "CWE-1333", "HIGH", "0.109.1", None,
         "the bundled python-multipart parser is quadratic in the number of form parts"),
    ),
    "gunicorn": (
        ("CVE-2024-1135", "CWE-444", "HIGH", "22.0.0", None,
         "a crafted Transfer-Encoding header splits one request into two"),
        ("CVE-2024-6827", "CWE-444", "HIGH", "22.0.0", None,
         "a malformed Transfer-Encoding header is accepted, enabling request smuggling"),
    ),
    "tornado": (
        ("CVE-2023-28370", "CWE-601", "MEDIUM", "6.3.2", None,
         "a crafted redirect target escapes the intended host"),
        ("CVE-2024-52804", "CWE-1333", "HIGH", "6.4.2", None,
         "cookie parsing is quadratic in the number of cookies, exhausting CPU"),
    ),
    "celery": (
        ("CVE-2021-23727", "CWE-78", "HIGH", "5.2.2", None,
         "a crafted task argument reaches a shell command in the worker"),
    ),
    "sqlalchemy": (
        ("CVE-2019-7164", "CWE-89", "HIGH", "1.2.18", None,
         "a crafted column expression in order_by is interpolated into SQL"),
    ),
    "lxml": (
        ("CVE-2021-43818", "CWE-79", "HIGH", "4.6.5", None,
         "lxml.html.clean leaves a crafted SVG/CSS construct that executes script"),
        ("CVE-2022-2309", "CWE-476", "MEDIUM", "4.9.1", None,
         "NULL dereference in the iterwalk/iterparse error path crashes the process"),
    ),
    "python-jose": (
        ("CVE-2024-33663", "CWE-347", "HIGH", "3.4.0", None,
         "algorithm confusion lets an ECDSA token be verified with the wrong key type"),
        ("CVE-2024-33664", "CWE-400", "MEDIUM", "3.4.0", None,
         "a crafted JWE body decompresses without a bound, exhausting memory"),
    ),
    "authlib": (
        ("CVE-2024-37568", "CWE-347", "CRITICAL", "1.3.1", None,
         "a JWS with an unsupported algorithm is accepted without verifying its signature"),
    ),
    "ecdsa": (
        ("CVE-2024-23342", "CWE-208", "MEDIUM", "0.19.0", None,
         "Minerva timing leakage in scalar multiplication recovers the private nonce"),
    ),
    "pycryptodome": (
        ("CVE-2023-52323", "CWE-208", "MEDIUM", "3.19.1", None,
         "a side channel in the RSA OAEP decryption path leaks plaintext"),
    ),
    "gitpython": (
        ("CVE-2023-40590", "CWE-426", "HIGH", "3.1.35", None,
         "an untrusted search path on Windows lets a planted git executable run"),
        ("CVE-2024-22190", "CWE-426", "CRITICAL", "3.1.41", None,
         "an untrusted search path lets a planted executable run arbitrary code"),
    ),
    "ansible": (
        ("CVE-2023-5764", "CWE-94", "HIGH", "8.6.0", None,
         "a templated variable marked unsafe is still evaluated, executing attacker code"),
    ),
    "mlflow": (
        ("CVE-2024-27132", "CWE-79", "HIGH", "2.11.0", None,
         "a crafted recipe name is rendered without escaping, enabling stored XSS"),
        ("CVE-2024-37059", "CWE-22", "HIGH", "2.12.1", None,
         "a crafted artifact path reads an arbitrary file from the tracking server"),
    ),
    "gradio": (
        ("CVE-2024-4325", "CWE-22", "HIGH", "4.31.4", None,
         "a crafted component upload path writes outside the intended directory"),
        ("CVE-2024-47872", "CWE-79", "HIGH", "5.0.0", None,
         "a crafted component value is rendered without escaping, enabling stored XSS"),
    ),
    "langchain": (
        ("CVE-2023-46229", "CWE-918", "HIGH", "0.0.325", None,
         "the recursive URL loader follows an attacker-supplied internal address"),
        ("CVE-2024-28088", "CWE-22", "HIGH", "0.1.11", None,
         "a crafted document path traverses outside the configured loader root"),
    ),
    "transformers": (
        ("CVE-2024-3568", "CWE-502", "CRITICAL", "4.38.0", None,
         "a crafted checkpoint is unpickled, executing arbitrary code on load"),
        ("CVE-2024-11392", "CWE-502", "CRITICAL", "4.48.0", None,
         "a crafted model file is deserialized without a safe loader, executing code"),
    ),
    "torch": (
        ("CVE-2024-31580", "CWE-122", "HIGH", "2.2.0", None,
         "a crafted tensor shape overflows a heap buffer in the JIT runtime"),
        ("CVE-2024-5480", "CWE-502", "CRITICAL", "2.2.0", None,
         "torch.distributed.rpc unpickles an untrusted argument, executing arbitrary code"),
    ),
    "numpy": (
        ("CVE-2021-41496", "CWE-120", "HIGH", "1.22.0", None,
         "a crafted array argument overflows a buffer in array_from_pyobj"),
    ),
    "setuptools": (
        ("CVE-2022-40897", "CWE-1333", "HIGH", "65.5.1", None,
         "the regular expression behind package_index is quadratic on a crafted HTML page"),
        ("CVE-2024-6345", "CWE-94", "CRITICAL", "70.0.0", None,
         "the download helpers pass an attacker-supplied URL to a shell, executing code"),
    ),
    "pip": (
        ("CVE-2023-5752", "CWE-78", "HIGH", "23.3", None,
         "a crafted Mercurial revision is interpolated into a shell command"),
    ),
}

NPM_ADVISORIES: Dict[str, Tuple[Advisory, ...]] = {
    "lodash": (
        ("CVE-2021-23337", "CWE-78", "HIGH", "4.17.21", None,
         "the template helper passes untrusted options into a shell command"),
        ("CVE-2020-8203", "CWE-1321", "HIGH", "4.17.20", None,
         "zipObjectDeep pollutes Object.prototype through a crafted path"),
    ),
    "axios": (
        ("CVE-2023-45857", "CWE-200", "MEDIUM", "1.6.0", None,
         "the XSRF-TOKEN header is sent to a third-party host on a cross-origin request"),
        ("CVE-2024-39338", "CWE-918", "HIGH", "1.7.4", None,
         "an absolute URL bypasses the configured proxy and baseURL, enabling SSRF"),
        ("CVE-2025-27152", "CWE-918", "HIGH", "1.8.2", None,
         "an absolute URL overrides baseURL and reaches an attacker-chosen host"),
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
    "next": (
        ("CVE-2024-34351", "CWE-918", "HIGH", "14.1.1", "13.4.0",
         "a Server Action redirect follows an attacker-supplied Host header, enabling SSRF"),
        ("CVE-2024-46982", "CWE-400", "HIGH", "13.5.7", "13.0.0",
         "a crafted request poisons the App Router cache, denying service to other users"),
        ("CVE-2024-46982", "CWE-400", "HIGH", "14.2.10", "14.0.0",
         "a crafted request poisons the App Router cache, denying service to other users"),
    ),
    "vite": (
        ("CVE-2024-23331", "CWE-22", "HIGH", "4.5.2", "4.0.0",
         "the dev server serves a crafted path outside the project root"),
        ("CVE-2024-23331", "CWE-22", "HIGH", "5.0.12", "5.0.0",
         "the dev server serves a crafted path outside the project root"),
        ("CVE-2024-45812", "CWE-79", "HIGH", "4.5.5", "4.0.0",
         "DOM clobbering through a crafted element id executes script in the dev server"),
        ("CVE-2024-45812", "CWE-79", "HIGH", "5.3.6", "5.0.0",
         "DOM clobbering through a crafted element id executes script in the dev server"),
        ("CVE-2024-45812", "CWE-79", "HIGH", "5.4.6", "5.4.0",
         "DOM clobbering through a crafted element id executes script in the dev server"),
    ),
    "webpack": (
        ("CVE-2023-28154", "CWE-94", "CRITICAL", "5.76.0", None,
         "the cross-realm object access in the runtime lets a crafted module execute code"),
    ),
    "tar": (
        ("CVE-2024-28863", "CWE-400", "MEDIUM", "6.2.1", None,
         "a crafted archive creates unbounded entries, exhausting memory during extraction"),
    ),
    "ws": (
        ("CVE-2024-37890", "CWE-400", "HIGH", "5.2.4", "5.0.0",
         "a request with many HTTP headers exhausts memory during the upgrade handshake"),
        ("CVE-2024-37890", "CWE-400", "HIGH", "6.2.3", "6.0.0",
         "a request with many HTTP headers exhausts memory during the upgrade handshake"),
        ("CVE-2024-37890", "CWE-400", "HIGH", "7.5.10", "7.0.0",
         "a request with many HTTP headers exhausts memory during the upgrade handshake"),
        ("CVE-2024-37890", "CWE-400", "HIGH", "8.17.1", "8.0.0",
         "a request with many HTTP headers exhausts memory during the upgrade handshake"),
    ),
    "node-forge": (
        ("CVE-2022-24771", "CWE-347", "HIGH", "1.3.0", None,
         "a crafted RSA signature with a malformed DigestInfo is accepted as valid"),
    ),
    "qs": (
        ("CVE-2022-24999", "CWE-1321", "HIGH", "6.5.3", "6.5.0",
         "a crafted query string pollutes Object.prototype through the parser"),
        ("CVE-2022-24999", "CWE-1321", "HIGH", "6.9.7", "6.9.0",
         "a crafted query string pollutes Object.prototype through the parser"),
        ("CVE-2022-24999", "CWE-1321", "HIGH", "6.10.3", "6.10.0",
         "a crafted query string pollutes Object.prototype through the parser"),
    ),
    "semver": (
        ("CVE-2022-25883", "CWE-1333", "HIGH", "5.7.2", "5.0.0",
         "the regular expression behind range parsing is quadratic on a crafted version"),
        ("CVE-2022-25883", "CWE-1333", "HIGH", "6.3.1", "6.0.0",
         "the regular expression behind range parsing is quadratic on a crafted version"),
        ("CVE-2022-25883", "CWE-1333", "HIGH", "7.5.2", "7.0.0",
         "the regular expression behind range parsing is quadratic on a crafted version"),
    ),
    "got": (
        ("CVE-2022-33987", "CWE-918", "HIGH", "11.8.5", "11.0.0",
         "a crafted redirect target is followed to an internal address, enabling SSRF"),
        ("CVE-2022-33987", "CWE-918", "HIGH", "12.1.0", "12.0.0",
         "a crafted redirect target is followed to an internal address, enabling SSRF"),
    ),
    "minimist": (
        ("CVE-2021-44906", "CWE-1321", "CRITICAL", "1.2.6", None,
         "a crafted argument pollutes Object.prototype through the parser"),
    ),
    "cookie": (
        ("CVE-2024-47764", "CWE-20", "HIGH", "0.7.0", None,
         "a crafted cookie name or value is accepted without validation, enabling injection"),
    ),
    "body-parser": (
        ("CVE-2024-45590", "CWE-400", "HIGH", "1.20.3", None,
         "a crafted urlencoded body is parsed without a bound, exhausting CPU"),
    ),
    "send": (
        ("CVE-2024-43799", "CWE-79", "MEDIUM", "0.19.0", None,
         "a crafted redirect target is interpolated into the HTML body, enabling XSS"),
    ),
    "serve-static": (
        ("CVE-2024-43800", "CWE-79", "MEDIUM", "1.16.0", None,
         "a crafted redirect target is interpolated into the HTML body, enabling XSS"),
    ),
    "ejs": (
        ("CVE-2022-29078", "CWE-94", "CRITICAL", "3.1.7", None,
         "a crafted render option reaches the template compiler, executing arbitrary code"),
    ),
    "handlebars": (
        ("CVE-2021-23369", "CWE-94", "CRITICAL", "4.7.7", None,
         "a crafted template bypasses the prototype access guard, executing arbitrary code"),
    ),
}

_INDEXES = {"pypi": PYPI_ADVISORIES, "npm": NPM_ADVISORIES}

# Distribution names whose import namespace is not the distribution name. Everything absent here
# imports under its own normalized name with '-' turned into '_'.
DIST_TO_IMPORTS: Dict[str, Tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "pillow": ("PIL",),
    "pillow-simd": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "pyjwt": ("jwt",),
    "python-jose": ("jose",),
    "scikit-learn": ("sklearn",),
    "python-dateutil": ("dateutil",),
    "attrs": ("attr", "attrs"),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "mysqlclient": ("MySQLdb",),
    "mysql-connector-python": ("mysql",),
    "pypdf2": ("PyPDF2",),
    "protobuf": ("google",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "python-multipart": ("multipart",),
    "python-dotenv": ("dotenv",),
    "typing-extensions": ("typing_extensions",),
    "gitpython": ("git",),
    "pyopenssl": ("OpenSSL",),
    "psycopg2-binary": ("psycopg2",),
    "pyzmq": ("zmq",),
    "discord.py": ("discord",),
    "python-telegram-bot": ("telegram",),
    "python-gitlab": ("gitlab",),
    "tensorflow-cpu": ("tensorflow",),
    "ruamel.yaml": ("ruamel",),
    "msgpack-python": ("msgpack",),
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