"""Nuclei-style terminal UX for the timecs CLI -- stdlib only, stderr only.

stdout is a data pipe: `--format json` consumers parse it, so every line this module produces
goes to stderr, exactly as nuclei and ripgrep do. The caller decides *whether* to speak (a TTY,
or TIMECS_FORCE_BANNER for a deterministic test); this module only decides *how* to speak.

Two refusals make the output safe on any terminal:

* Colour is emitted only when the stream is a TTY and NO_COLOR is unset. A redirected log or a
  CI capture gets the bare `[INF]` tag, never an escape sequence it would store as litter.
* Every non-ASCII glyph is probed against the stream's own encoding before it is chosen. Windows
  consoles still default to cp1252, which cannot encode the box-drawing rule or the arrow, so
  those fall back to `-` and `->`. The probe covers exactly the characters about to be written,
  which is what makes a UnicodeEncodeError unreachable from here.

The wordmark is TIMECS and the command is `timecs`; the art is 46 columns so it never wraps on
an 80-column terminal.
"""

from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Optional

__all__ = ["VERSION", "BANNER", "SUBTITLE", "badge", "color_enabled", "supports_unicode",
           "print_banner", "print_phase", "print_step", "print_worker", "print_completion",
           "print_warning", "print_error"]

# The installed distribution owns the number it reports: the wheel writes it from `pyproject.toml`,
# so the banner can never drift from the artifact a user ran. A bare source checkout has no
# metadata, and falls back to the release this tree is preparing.
try:
    VERSION = version("timecs")
except PackageNotFoundError:
    VERSION = "3.3.0"

# Six letters, five rows, one space between glyphs: 46 columns at its widest.
BANNER = (
    " _____   ___   __  __   _____    ____   ____ ",
    "|_   _| |_ _| |  \\/  | | ____|  / ___| / ___|",
    "  | |    | |  | |\\/| | |  _|   | |     \\___ \\",
    "  | |    | |  | |  | | | |___  | |___   ___) |",
    "  |_|   |___| |_|  |_| |_____|  \\____| |____/",
)
SUBTITLE = "timecs \u00b7 autonomous static & appsec analysis"

_RESET = "\033[0m"
_BADGES = {"INF": "\033[1;34m", "WRN": "\033[1;33m", "ERR": "\033[1;31m",
           "AGT": "\033[1;35m", "SUC": "\033[1;32m"}
_RULE = "\u2500"
_ARROW = "\u2192"
_DOT = "\u00b7"


def color_enabled(stream: Any) -> bool:
    """Colour is for a human watching a terminal, not for a log file or a CI capture."""
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def _encodable(stream: Any, text: str) -> bool:
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return False
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def supports_unicode(stream: Any) -> bool:
    """True when this stream's own encoding can carry the rule and the arrow."""
    return _encodable(stream, _RULE + _ARROW)


def _glyphs(stream: Any) -> tuple:
    """The three non-ASCII characters this module can emit, each probed against the stream.

    Probing exactly what is about to be written is what makes a UnicodeEncodeError unreachable:
    a cp1252 console gets `-` and `->`, and a stream that cannot even carry the middle dot gets
    an ASCII subtitle rather than an exception halfway through the banner.
    """
    rule, arrow = (_RULE, _ARROW) if supports_unicode(stream) else ("-", "->")
    dot = _DOT if _encodable(stream, _DOT) else "-"
    return rule, arrow, dot


def _write(line: str, stream: Any) -> None:
    stream.write(line + "\n")
    stream.flush()


def badge(kind: str, message: str, stream: Any = sys.stderr) -> None:
    """One `[KIND] message` line. KIND is INF, WRN, ERR, AGT or SUC."""
    tag = "[%s]" % kind
    code = _BADGES.get(kind)
    if code and color_enabled(stream):
        tag = code + tag + _RESET
    _write("%s %s" % (tag, message), stream)


def print_banner(target_path: Any, scope: str = "all", workers: int = 2,
                 version: str = VERSION, stream: Any = sys.stderr) -> None:
    rule, arrow, dot = _glyphs(stream)
    for line in BANNER:
        _write(line, stream)
    _write(SUBTITLE.replace(_DOT, dot), stream)
    badge("INF", "TIMECS %s" % version, stream)
    badge("INF", "target %s %s" % (arrow, target_path), stream)
    badge("INF", "scope %s %s" % (arrow, scope), stream)
    badge("INF", "workers %s %s" % (arrow, workers), stream)
    _write(rule * 46, stream)


def print_phase(current: int, total: int, title: str, stream: Any = sys.stderr) -> None:
    rule, _arrow, _dot = _glyphs(stream)
    badge("AGT", "phase %d/%d %s %s" % (current, total, rule * 6, title), stream)


def print_step(step_num: int, title: str, details: str, stream: Any = sys.stderr) -> None:
    _rule, arrow, _dot = _glyphs(stream)
    badge("SUC", "step %d %s %s: %s" % (step_num, arrow, title, details), stream)


def print_worker(worker_id: Any, status: str, stream: Any = sys.stderr) -> None:
    _rule, arrow, _dot = _glyphs(stream)
    badge("AGT", "worker %s %s %s" % (worker_id, arrow, status), stream)


def print_completion(duration_s: float, total_findings: int, sarif_path: Optional[str] = None,
                     sbom_path: Optional[str] = None, stream: Any = sys.stderr) -> None:
    _rule, arrow, _dot = _glyphs(stream)
    badge("SUC", "scan complete %s %d finding(s) in %.2fs" % (arrow, total_findings, duration_s),
          stream)
    if sarif_path:
        badge("INF", "sarif %s %s" % (arrow, sarif_path), stream)
    if sbom_path:
        badge("INF", "sbom %s %s" % (arrow, sbom_path), stream)


def print_warning(message: str, stream: Any = sys.stderr) -> None:
    badge("WRN", message, stream)


def print_error(message: str, stream: Any = sys.stderr) -> None:
    badge("ERR", message, stream)