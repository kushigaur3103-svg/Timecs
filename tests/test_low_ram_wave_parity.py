from __future__ import annotations

import ast
import dataclasses
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmark" / "corpus"


def _canonical(value):
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__name__,
            tuple(
                (field.name, _canonical(getattr(value, field.name)))
                for field in dataclasses.fields(value)
            ),
        )
    if isinstance(value, ast.AST):
        return (
            "AST",
            type(value).__name__,
            getattr(value, "lineno", None),
            getattr(value, "col_offset", None),
        )
    if isinstance(value, dict):
        return tuple(sorted((str(k), _canonical(v)) for k, v in value.items()))
    if isinstance(value, (set, frozenset)):
        return tuple(sorted(map(str, value)))
    if isinstance(value, (list, tuple)):
        return tuple(_canonical(item) for item in value)
    return value


def _load_corpus():
    paths = sorted(CORPUS.rglob("*.py"), key=lambda path: path.relative_to(ROOT).as_posix())
    assert len(paths) >= 28, "the low-RAM parity corpus must contain at least 28 files"
    return {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in paths[:28]
    }


def test_low_ram_wave_output_exactly_matches_single_pass():
    from ast_scanner import TaintTracker

    files = _load_corpus()
    normal = TaintTracker(files=dict(files), audit_all=True)
    expected = _canonical(normal.analyze())

    wave = TaintTracker(files=dict(files), audit_all=True, low_ram_wave_size=5)
    actual = _canonical(wave.analyze())

    assert actual == expected
    assert wave.execution_mode == "wave"
    assert wave.analyzed_module_count == 28
    assert wave.modules == {}
    assert wave._wave_store.active == {}


def test_cli_selects_wave_only_below_safety_floor():
    from cli import _low_ram_wave_size

    assert _low_ram_wave_size(351, 899) == 350
    assert _low_ram_wave_size(351, 900) is None
    assert _low_ram_wave_size(350, 899) is None


@pytest.mark.parametrize("wave_size", [1, 5, 28])
def test_low_ram_wave_size_preserves_findings(wave_size):
    from ast_scanner import TaintTracker

    files = _load_corpus()
    normal = TaintTracker(files=dict(files), audit_all=True)
    expected = _canonical(normal.analyze())
    wave = TaintTracker(files=dict(files), audit_all=True, low_ram_wave_size=wave_size)
    assert _canonical(wave.analyze()) == expected
    assert wave.modules == {}
