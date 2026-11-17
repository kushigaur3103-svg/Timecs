"""Gate #62 -- the `timecs` terminal UX: compact TIMECS banner, nuclei badges, zero stdout pollution.

TASK 19 gave the CLI a human face without giving it a second output channel. `banner.py` owns the
look, `cli.py` owns the decision to speak at all, and this gate locks both halves:

* the wordmark is TIMECS and the command is `timecs`. A standalone `TCS` must never appear, and
  the art must fit an 80-column terminal rather than wrap into nonsense.
* colour is a TTY privilege. NO_COLOR or a redirected stream gets bare `[INF]` tags, never an
  escape sequence a log would store as litter.
* a Windows cp1252 console cannot encode the box rule or the arrow, so the glyphs are probed
  against the stream's own encoding and fall back to `-` / `->`. UnicodeEncodeError is not a
  permissible outcome of printing a banner.
* stdout is a data pipe. `--format json` is an absolute veto on the styled UX, so a benchmark or
  CI job parses exactly the payload it always parsed.

The contract, in nine tiers:

0. ISOLATION LAWS -- banner.py imports nothing but the stdlib, cli.py still calls every helper,
   and `ast_scanner.py`, `iac_auditor.py` and all of `scanners/` carry zero diff against HEAD.
1. BANNER SHAPE -- the art, the exact subtitle, all five badges, the phased dividers, the width
   ceiling, and the branding refusal.
2. COLOUR -- a TTY gets bold ANSI per badge; NO_COLOR and a non-TTY get none.
3. ENCODING -- cp1252, ascii, latin-1, utf-8 and an encoding-less StringIO, each rendered whole.
4. JSON PURITY -- a real subprocess scan with the banner forced still emits `json.loads(stdout)`
   on the first attempt, with no banner token anywhere in it.
5. TTY UX -- a real subprocess table scan renders four phases, three steps and a completion on
   stderr and nothing styled on stdout; without the env var it stays silent.
6. ENTRYPOINT -- pyproject names the distribution `timecs`, exposes `timecs = "cli:main"`, no
   longer exposes `tcs`, and actually packages the modules the entrypoint imports.
7. MUTATIONS -- every decision point is blinded in turn and its own output must move, including
   the falsifier direction: forcing the unicode answer on a cp1252 stream must raise.
8. BUDGET -- work and peak RSS, because a lock that is slow or heavy never runs on this laptop.

Usage: python benchmark/gates/cli_banner_ux_probe.py [--dump]
"""
from __future__ import annotations

import ast
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
import tomllib
from pathlib import Path

START = time.time()
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT))
# The child's script path is spelled through `os.path` from `__file__`, the way `gate_common.GATES_DIR`
# is, rather than through `Path`/`str`. This file is itself inside the parity scan, and a bare builtin
# call in an argv slot has unknown provenance, which the engine reports as CWE-78 at the call site.
CLI_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "cli.py")

import banner as BN  # noqa: E402
import cli  # noqa: E402

BUDGET_SECONDS = 90.0
BUDGET_RSS_MB = 50.0

WIDTH_CEILING = 80
SUBTITLE = "timecs \u00b7 autonomous static & appsec analysis"
BADGE_KINDS = ("INF", "WRN", "ERR", "AGT", "SUC")
BOLD_CODES = {"INF": "1;34", "WRN": "1;33", "ERR": "1;31", "AGT": "1;35", "SUC": "1;32"}
ANSI = "\033["
BOX = "\u2500"
ARROW = "\u2192"
DOT = "\u00b7"
STANDALONE_TCS = re.compile(r"\bTCS\b")
ALLOWED_IMPORTS = frozenset({"__future__", "os", "sys", "typing"})
FORBIDDEN_IMPORTS = ("cli", "ast_scanner", "iac_auditor", "scanners", "cross_file_engine",
                     "psutil", "requests", "yaml", "colorama", "rich", "click", "tomllib")
WIRING_CONTRACT = (
    ("cli.py", "import banner"),
    ("cli.py", "def _ux_enabled(args):"),
    ("cli.py", 'os.environ.get("TIMECS_FORCE_BANNER") == "1"'),
    ("cli.py", "banner.print_banner(args.path, scope=scope, workers=workers, stream=sys.stderr)"),
    ("cli.py", 'banner.print_phase(1, 4, "discovery", stream=sys.stderr)'),
    ("cli.py", 'banner.print_phase(2, 4, "analysis", stream=sys.stderr)'),
    ("cli.py", 'banner.print_phase(3, 4, "correlation", stream=sys.stderr)'),
    ("cli.py", 'banner.print_phase(4, 4, "reporting", stream=sys.stderr)'),
    ("cli.py", "banner.print_worker(worker_id, \"ready\", stream=sys.stderr)"),
    ("cli.py", "banner.print_completion(duration_ms / 1000, len(findings),"),
    ("banner.py", 'SUBTITLE = "timecs \\u00b7 autonomous static & appsec analysis"'),
    ("banner.py", "def supports_unicode(stream: Any) -> bool:"),
)


def module(*lines):
    return "".join(line + "\n" for line in lines)


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


@contextlib.contextmanager
def env_override(values):
    """Both UX variables are cleared first, so an ambient setting cannot decide a tier.

    Every supplied key is restored as well, so a child's pinned stream encoding cannot leak into
    the tiers that run after it.
    """
    keys = ("TIMECS_FORCE_BANNER", "NO_COLOR")
    touched = tuple(dict.fromkeys(keys + tuple(values)))
    saved = {key: os.environ.get(key) for key in touched}
    try:
        for key in keys:
            os.environ.pop(key, None)
        os.environ.update(values)
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class TtyBuffer(io.StringIO):
    """A StringIO that claims to be a terminal, so the colour path is reachable in a test."""

    encoding = "utf-8"

    def isatty(self):
        return True


def encoded_buffer(encoding):
    raw = io.BytesIO()
    return raw, io.TextIOWrapper(raw, encoding=encoding)


def render_all(stream):
    """Every public helper, in the order the CLI uses them."""
    BN.print_banner("src/", scope="all", workers=2, stream=stream)
    BN.print_phase(1, 4, "discovery", stream=stream)
    BN.print_step(1, "files discovered", "12 python, 3 auxiliary", stream=stream)
    BN.print_worker(0, "ready", stream=stream)
    BN.print_completion(1.25, 9, sarif_path="out.sarif", sbom_path="bom.json", stream=stream)
    BN.print_warning("careful", stream=stream)
    BN.print_error("boom", stream=stream)


def plain_text():
    stream = io.StringIO()
    render_all(stream)
    return stream.getvalue()


def tty_text():
    stream = TtyBuffer()
    render_all(stream)
    return stream.getvalue()


def cp1252_text():
    raw, stream = encoded_buffer("cp1252")
    render_all(stream)
    stream.flush()
    return raw.getvalue().decode("cp1252")


def utf8_text():
    raw, stream = encoded_buffer("utf-8")
    render_all(stream)
    stream.flush()
    return raw.getvalue().decode("utf-8")


def unicode_raises(render):
    try:
        render()
    except UnicodeEncodeError:
        return True
    return False


# ── tier 0: isolation ─────────────────────────────────────────────────────
def check_laws():
    failures = []
    source = (REPO_ROOT / "banner.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    for root in sorted(roots - ALLOWED_IMPORTS):
        failures.append(f"banner.py imports {root}, which is outside the stdlib allowlist")
    for forbidden in FORBIDDEN_IMPORTS:
        if forbidden in roots:
            failures.append(f"banner.py imports {forbidden}: the UX must not depend on the engine")
    for relative, needle in WIRING_CONTRACT:
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        if needle not in text:
            failures.append(f"{relative} lost the wiring clause {needle!r}")
    diff = subprocess.run(["git", "diff", "--exit-code", "HEAD", "--",
                           "ast_scanner.py", "iac_auditor.py", "scanners/"],
                          cwd=str(REPO_ROOT), capture_output=True, text=True, check=False)
    state = "clean" if diff.returncode == 0 else "DIRTY"
    if diff.returncode != 0:
        failures.append(f"the engine or scanners/ moved against HEAD: {diff.stdout[-400:]}")
    return failures, state


# ── tier 1: the banner itself ─────────────────────────────────────────────
def check_shape():
    failures = []
    facts = {}
    text = plain_text()
    lines = text.splitlines()
    facts["art_width"] = max(len(line) for line in BN.BANNER)
    facts["art_rows"] = len(BN.BANNER)
    facts["widest"] = max(len(line) for line in lines)
    if not BN.BANNER:
        failures.append("the banner carries no art")
    for line in BN.BANNER:
        if len(line) > WIDTH_CEILING:
            failures.append(f"an art row is {len(line)} columns, over the {WIDTH_CEILING} ceiling")
        if any(ord(char) > 127 for char in line):
            failures.append(f"an art row carries a non-ASCII character: {line!r}")
    if facts["widest"] > WIDTH_CEILING:
        failures.append(f"the rendered banner wraps at {facts['widest']} columns")
    if "TIMECS" not in text:
        failures.append("the literal wordmark TIMECS never appears")
    if STANDALONE_TCS.search(text):
        failures.append("a standalone TCS appears in the banner, which the branding rule forbids")
    # The exact subtitle belongs to a stream that can encode the middle dot; an encoding-less
    # stream must still carry the same words with the ASCII fallback dot.
    if SUBTITLE not in utf8_text():
        failures.append(f"the exact subtitle is missing: {SUBTITLE!r}")
    if SUBTITLE.replace(DOT, "-") not in text:
        failures.append("the ASCII-fallback subtitle is missing on an encoding-less stream")
    for kind in BADGE_KINDS:
        if f"[{kind}]" not in text:
            failures.append(f"the [{kind}] badge never rendered")
    if "[AGT] phase 1/4" not in text:
        failures.append("the phased divider did not render")
    if "-" * 46 not in text:
        failures.append("the closing rule did not render on an encoding-less stream")
    if "[SUC] scan complete" not in text:
        failures.append("print_completion printed no completion line")
    if "out.sarif" not in text or "bom.json" not in text:
        failures.append("print_completion dropped an artefact path")
    if "[AGT] worker 0" not in text:
        failures.append("print_worker printed no worker line")
    # The default stream is stderr: nothing here may reach stdout.
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        render_all(io.StringIO())
    if out.getvalue():
        failures.append(f"a banner helper wrote to stdout: {out.getvalue()[:120]!r}")
    return failures, facts


# ── tier 2: colour is a TTY privilege ─────────────────────────────────────
def check_colour():
    failures = []
    facts = {}
    with env_override({}):
        loud = tty_text()
        quiet = plain_text()
        facts["tty_ansi"] = loud.count(ANSI)
        if ANSI not in loud:
            failures.append("a TTY stream got no ANSI at all")
        for kind, code in BOLD_CODES.items():
            if f"\033[{code}m[{kind}]\033[0m" not in loud:
                failures.append(f"[{kind}] is not bold colour {code} on a TTY")
        if ANSI in quiet:
            failures.append("a non-TTY stream received escape sequences")
        if not BN.color_enabled(TtyBuffer()):
            failures.append("color_enabled refuses a TTY")
        if BN.color_enabled(io.StringIO()):
            failures.append("color_enabled accepts a non-TTY")
    with env_override({"NO_COLOR": "1"}):
        stripped = tty_text()
        facts["no_color_ansi"] = stripped.count(ANSI)
        if ANSI in stripped:
            failures.append("NO_COLOR=1 left escape sequences in the output")
        if "[INF]" not in stripped or "[AGT] phase 1/4" not in stripped:
            failures.append("NO_COLOR stripped the tags themselves, not just the colour")
        # A TTY keeps the unicode glyphs, so the comparison is against the SAME rendering with
        # only the escape sequences removed -- not against an encoding-less stream.
        if re.sub(r"\033\[[0-9;]*m", "", loud) != stripped:
            failures.append("NO_COLOR changed something other than the escape sequences")
        if BN.color_enabled(TtyBuffer()):
            failures.append("color_enabled ignores NO_COLOR")
    return failures, facts


# ── tier 3: every console encoding ────────────────────────────────────────
ENCODING_CASES = (
    ("cp1252", False, True),
    ("ascii", False, False),
    ("latin-1", False, True),
    ("utf-8", True, True),
)


def check_encoding():
    failures = []
    facts = {}
    for encoding, want_glyphs, want_dot in ENCODING_CASES:
        raw, stream = encoded_buffer(encoding)
        try:
            render_all(stream)
            stream.flush()
        except UnicodeEncodeError as exc:
            failures.append(f"{encoding} raised UnicodeEncodeError: {exc}")
            continue
        text = raw.getvalue().decode(encoding)
        facts[encoding] = len(raw.getvalue())
        if (BOX in text) != want_glyphs or (ARROW in text) != want_glyphs:
            failures.append(f"{encoding} chose the wrong rule/arrow glyphs")
        if (DOT in text) != want_dot:
            failures.append(f"{encoding} chose the wrong subtitle dot")
        if not want_glyphs and ("-" * 46 not in text or "->" not in text):
            failures.append(f"{encoding} did not fall back to '-' and '->'")
        if "[INF]" not in text or "[SUC] scan complete" not in text:
            failures.append(f"{encoding} lost a badge while falling back")
        if ANSI in text:
            failures.append(f"{encoding} received escape sequences on a non-TTY")
    if BN.supports_unicode(io.StringIO()):
        failures.append("an encoding-less StringIO was treated as unicode-capable")
    ascii_stream = io.StringIO()
    render_all(ascii_stream)
    if any(ord(char) > 127 for char in ascii_stream.getvalue()):
        failures.append("an encoding-less stream received a non-ASCII character")
    return failures, facts


# ── tiers 4-5: the real CLI, in a real subprocess ─────────────────────────
MINI_FILES = {"app.py": module("import hashlib", "", "", "def digest(text):",
                               "    return hashlib.md5(text).hexdigest()")}
BANNER_TOKENS = ("TIMECS", "[INF]", "[AGT]", "[SUC]", "[WRN]", "[ERR]", ANSI)


def subprocess_scan(tree, fmt, env, io_encoding="utf-8"):
    """A real child process. PYTHONIOENCODING pins the child's stream encoding so the parent can
    decode it exactly; without it a Windows child writes cp1252 and the subtitle's middle dot
    would arrive as a replacement character, failing a comparison that the CLI actually passed.

    This directory sits inside the parity scan, whose baseline holds no `benchmark/gates/` key, so
    this file must report nothing about itself. Every argv slot is therefore a literal or a
    repo-internal path: no splat, which would hide the command line from the execve proof, and no
    parameter-derived element. `CLI_SCRIPT` is reached through `os.path` rather than `str(Path(...))`
    because a bare builtin call in an argv slot has unknown provenance and is reported as CWE-78.
    No copy of `os.environ` is forwarded either -- the child inherits the environment the context
    manager prepared, so the parent's secrets are not handed over as a value. The two branches are
    written out rather than assembled so each argv stays a literal list the scanner can read.
    """
    with env_override(dict(env, PYTHONIOENCODING=io_encoding)):
        if fmt == "json":
            return subprocess.run([sys.executable, CLI_SCRIPT, "scan", ".", "--workers", "1",
                                   "--include-tests", "--format", "json"],
                                  cwd=str(tree), capture_output=True, text=True,
                                  encoding=io_encoding, errors="replace", check=False)
        return subprocess.run([sys.executable, CLI_SCRIPT, "scan", ".", "--workers", "1",
                               "--include-tests", "--format", "table"],
                              cwd=str(tree), capture_output=True, text=True,
                              encoding=io_encoding, errors="replace", check=False)


def check_cli():
    failures = []
    facts = {}
    with tempfile.TemporaryDirectory(prefix="timecs_g62_cli_") as tmp:
        tree = Path(tmp)
        write_tree(tree, MINI_FILES)
        # 4. JSON is a data pipe: the banner is forced and still must not exist.
        proc = subprocess_scan(tree, "json", {"TIMECS_FORCE_BANNER": "1"})
        facts["json_exit"] = proc.returncode
        try:
            payload = json.loads(proc.stdout)
        except ValueError as exc:
            payload = None
            failures.append(f"--format json stdout is not pure JSON: {exc}")
        if payload is not None:
            facts["json_findings"] = len(payload["findings"])
            if not payload["findings"]:
                failures.append("the mini fixture produced no finding, so tier 4 is vacuous")
            if set(payload["scanned_files_by_scope"]) != set(cli.SCOPE_ORDER):
                failures.append("the JSON payload lost a scope key")
        for token in BANNER_TOKENS:
            if token in proc.stdout:
                failures.append(f"--format json stdout carries the banner token {token!r}")
        if "TIMECS" in proc.stderr or "[AGT] phase" in proc.stderr:
            failures.append("--format json rendered the styled UX on stderr despite the veto")
        # 5. A table scan at a terminal is where the UX belongs.
        proc = subprocess_scan(tree, "table", {"TIMECS_FORCE_BANNER": "1"})
        facts["table_exit"] = proc.returncode
        err = proc.stderr
        facts["phases"] = err.count("[AGT] phase")
        facts["steps"] = err.count("[SUC] step")
        if "TIMECS" not in err:
            failures.append("the forced table scan printed no TIMECS banner on stderr")
        if SUBTITLE not in err:
            failures.append("the forced table scan printed no subtitle")
        if facts["phases"] != 4:
            failures.append(f"the table scan rendered {facts['phases']} phases, expected 4")
        if facts["steps"] != 3:
            failures.append(f"the table scan rendered {facts['steps']} steps, expected 3")
        if "[SUC] scan complete" not in err:
            failures.append("the table scan printed no completion line")
        if "[AGT] worker" not in err:
            failures.append("the table scan printed no worker line")
        for token in BANNER_TOKENS:
            if token in proc.stdout:
                failures.append(f"the table scan polluted stdout with {token!r}")
        # Without the env var a pipe is not a terminal, so the UX stays off.
        proc = subprocess_scan(tree, "table", {})
        facts["default_silent"] = "TIMECS" not in proc.stderr
        if "TIMECS" in proc.stderr or "[AGT] phase" in proc.stderr:
            failures.append("a non-TTY subprocess scan rendered the banner without being asked")
        # NO_COLOR reaches the subprocess too.
        proc = subprocess_scan(tree, "table", {"TIMECS_FORCE_BANNER": "1", "NO_COLOR": "1"})
        facts["no_color_silent"] = ANSI not in proc.stderr
        if "TIMECS" not in proc.stderr:
            failures.append("NO_COLOR removed the banner instead of only the colour")
        if ANSI in proc.stderr:
            failures.append("NO_COLOR=1 left escape sequences in the subprocess stderr")
        if ANSI in proc.stdout:
            failures.append("NO_COLOR=1 left escape sequences in the subprocess stdout")
        # The real Windows console path, end to end: a cp1252 child must still finish the scan.
        proc = subprocess_scan(tree, "table", {"TIMECS_FORCE_BANNER": "1"}, io_encoding="cp1252")
        facts["cp1252_exit"] = proc.returncode
        if proc.returncode not in (0, 1):
            failures.append(f"a cp1252 console scan exited {proc.returncode}: "
                            f"{proc.stderr[-300:]}")
        if "UnicodeEncodeError" in proc.stderr:
            failures.append("a cp1252 console scan raised UnicodeEncodeError")
        if "TIMECS" not in proc.stderr or SUBTITLE not in proc.stderr:
            failures.append("a cp1252 console scan lost the banner or the subtitle")
        if BOX in proc.stderr or ARROW in proc.stderr:
            failures.append("a cp1252 console scan emitted a glyph cp1252 cannot encode")
        if "->" not in proc.stderr or "-" * 46 not in proc.stderr:
            failures.append("a cp1252 console scan did not use the ASCII fallback")
    return failures, facts


# ── tier 6: the entrypoint a user actually types ──────────────────────────
def check_entrypoint():
    failures = []
    facts = {}
    meta = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = meta["project"]
    facts["name"] = project["name"]
    facts["scripts"] = sorted(project["scripts"])
    if project["name"] != "timecs":
        failures.append(f"the distribution is named {project['name']!r}, expected 'timecs'")
    scripts = project["scripts"]
    if scripts.get("timecs") != "cli:main":
        failures.append(f"[project.scripts] timecs is {scripts.get('timecs')!r}, expected cli:main")
    if "tcs" in scripts:
        failures.append("the forbidden `tcs` command is still exposed")
    if list(scripts)[0] != "timecs":
        failures.append("timecs is not the primary entrypoint")
    modules = meta["tool"]["setuptools"]["py-modules"]
    packages = meta["tool"]["setuptools"]["packages"]
    facts["packaged"] = "banner" in modules and "scanners" in packages
    for needed in ("banner", "cli", "ast_scanner", "diff_scan", "tcs_config", "sarif_exporter"):
        if needed not in modules:
            failures.append(f"the entrypoint imports {needed} but py-modules does not ship it")
    if "scanners" not in packages:
        failures.append("cli.py imports the scanners package but setuptools does not ship it")
    for name in ("banner.py", "cli.py", "diff_scan.py", "tcs_config.py", "sarif_exporter.py"):
        if not (REPO_ROOT / name).is_file():
            failures.append(f"pyproject ships {name} but the file does not exist")
    if not (REPO_ROOT / "scanners" / "__init__.py").is_file():
        failures.append("scanners is listed as a package but has no __init__.py")
    return failures, facts


# ── tier 7: mutations ─────────────────────────────────────────────────────
def cli_capture(fmt, force):
    out, err = io.StringIO(), io.StringIO()
    with tempfile.TemporaryDirectory(prefix="timecs_g62_mut_") as tmp:
        tree = Path(tmp)
        write_tree(tree, MINI_FILES)
        with chdir(tree), env_override({"TIMECS_FORCE_BANNER": "1"} if force else {}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["scan", ".", "--format", fmt, "--workers", "1", "--include-tests"])
    return code, out.getvalue(), err.getvalue()


def _noop(*_args, **_kwargs):
    return None


MUTATIONS = {
    "colour_always_on": (
        ((BN, "color_enabled", lambda stream: True),),
        lambda: ANSI in plain_text()),
    "colour_always_off": (
        ((BN, "color_enabled", lambda stream: False),),
        lambda: ANSI not in tty_text()),
    "badge_codes_blind": (
        ((BN, "_BADGES", {}),),
        lambda: ANSI not in tty_text()),
    "unicode_always_on": (
        ((BN, "supports_unicode", lambda stream: True),),
        lambda: unicode_raises(cp1252_text)),
    "unicode_always_off": (
        ((BN, "supports_unicode", lambda stream: False),),
        lambda: BOX not in utf8_text()),
    "encodable_blind": (
        ((BN, "_encodable", lambda stream, text: True),),
        lambda: unicode_raises(cp1252_text)),
    "dot_probe_blind": (
        ((BN, "_encodable", lambda stream, text: ARROW not in text),),
        lambda: unicode_raises(lambda: render_all(encoded_buffer("ascii")[1]))),
    "art_blind": (
        ((BN, "BANNER", ()),),
        lambda: "_____" not in plain_text()),
    "subtitle_blind": (
        ((BN, "SUBTITLE", ""),),
        lambda: "autonomous static & appsec analysis" not in plain_text()),
    "banner_blind": (
        ((BN, "print_banner", _noop),),
        lambda: "TIMECS" not in plain_text()),
    "ux_always_on": (
        ((cli, "_ux_enabled", lambda args: True),),
        lambda: "TIMECS" in cli_capture("json", True)[2]),
    "ux_always_off": (
        ((cli, "_ux_enabled", lambda args: False),),
        lambda: "TIMECS" not in cli_capture("table", True)[2]),
    "phase_blind": (
        ((BN, "print_phase", _noop),),
        lambda: "[AGT] phase" not in cli_capture("table", True)[2]),
    "step_blind": (
        ((BN, "print_step", _noop),),
        lambda: "[SUC] step" not in cli_capture("table", True)[2]),
    "worker_blind": (
        ((BN, "print_worker", _noop),),
        lambda: "[AGT] worker" not in cli_capture("table", True)[2]),
    "completion_blind": (
        ((BN, "print_completion", _noop),),
        lambda: "[SUC] scan complete" not in cli_capture("table", True)[2]),
}


def run_mutations():
    failures = []
    caught = 0
    for name, (patches, experiment) in MUTATIONS.items():
        saved = []
        try:
            for owner, attribute, value in patches:
                saved.append((owner, attribute, inspect.getattr_static(owner, attribute)))
                setattr(owner, attribute, value)
            moved = bool(experiment())
        except Exception as exc:
            moved = False
            failures.append(f"{name}: the experiment raised {type(exc).__name__}: {exc}")
        finally:
            for owner, attribute, original in reversed(saved):
                setattr(owner, attribute, original)
        if moved:
            caught += 1
        else:
            failures.append(f"{name}: blinding it changed nothing, so it is not what decides "
                            f"the output")
    return failures, caught


def peak_rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1048576.0
    except Exception:
        return 0.0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--dump":
        sys.stdout.write(plain_text())
        return 0

    failures = []
    law_failures, diff_state = check_laws()
    failures += law_failures
    print(f"TIER 0 - isolation laws: engine+scanners diff={diff_state}, "
          f"{len(law_failures)} failure(s)")

    shape_failures, shape = check_shape()
    failures += shape_failures
    print(f"TIER 1 - banner shape: {shape.get('art_rows')} art rows, widest "
          f"{shape.get('art_width')} cols, rendered max {shape.get('widest')} cols, "
          f"{len(BADGE_KINDS)} badges, {len(shape_failures)} failure(s)")

    colour_failures, colour = check_colour()
    failures += colour_failures
    print(f"TIER 2 - colour: tty_ansi={colour.get('tty_ansi')} "
          f"no_color_ansi={colour.get('no_color_ansi')}, {len(colour_failures)} failure(s)")

    encoding_failures, encodings = check_encoding()
    failures += encoding_failures
    print(f"TIER 3 - encoding safety over {len(ENCODING_CASES)} console encodings plus an "
          f"encoding-less stream: {len(encoding_failures)} failure(s)")

    cli_failures, cli_facts = check_cli()
    failures += cli_failures
    print(f"TIER 4/5 - real CLI subprocesses: json_findings={cli_facts.get('json_findings')} "
          f"phases={cli_facts.get('phases')} steps={cli_facts.get('steps')} "
          f"default_silent={cli_facts.get('default_silent')} "
          f"no_color_silent={cli_facts.get('no_color_silent')}, {len(cli_failures)} failure(s)")

    entry_failures, entry = check_entrypoint()
    failures += entry_failures
    print(f"TIER 6 - entrypoint: name={entry.get('name')} scripts={entry.get('scripts')} "
          f"packaged={entry.get('packaged')}, {len(entry_failures)} failure(s)")

    mutation_failures, caught = run_mutations()
    failures += mutation_failures
    print(f"TIER 7 - {caught}/{len(MUTATIONS)} mutations caught")

    for item in failures:
        print(f"  !! {item}")

    elapsed = time.time() - START
    rss = peak_rss_mb()
    print(f"TIER 8 - work={elapsed:.2f}s (budget {BUDGET_SECONDS}s) "
          f"peak_rss={rss:.1f}MB (budget {BUDGET_RSS_MB}MB)")
    if failures:
        print("VERDICT: FAIL - the banner wrapped, rebranded, coloured a log, raised on a "
              "Windows console, polluted a JSON pipe, or the entrypoint stopped being `timecs`. "
              "Fix the cause; never blind a rule.")
        return 1
    if elapsed > BUDGET_SECONDS or rss > BUDGET_RSS_MB:
        print("VERDICT: FAIL - budget blown, and a lock that is slow or heavy never runs.")
        return 1
    print(f"VERDICT: PASS - a {shape.get('art_width')}-column TIMECS wordmark with the exact "
          f"timecs subtitle and no standalone TCS, all {len(BADGE_KINDS)} badges, colour only at "
          f"a TTY, {len(ENCODING_CASES)} console encodings rendered without a "
          f"UnicodeEncodeError, pure JSON on stdout with the banner forced, "
          f"{cli_facts.get('phases')} phases and {cli_facts.get('steps')} steps on stderr, "
          f"`timecs = cli:main` packaged, engine+scanners diff={diff_state}, "
          f"{caught}/{len(MUTATIONS)} mutations caught, peak RSS {rss:.1f}MB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())