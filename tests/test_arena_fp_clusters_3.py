"""Arena FP cluster 3 (release 3.1.0): CWE-89 rows that have no hole for input.

Triage across the three arenas kept landing on the same two shapes, and neither one is injectable SQL:

  1. a statement assembled only from literals, where a variable decides WHICH literal runs
     (`col = "id" if flag else "name"` then `execute("SELECT " + col + " FROM users")`). The dataflow
     graph is right that `flag` reaches the query -- and irrelevant, because no character of the
     statement comes from it. The condition is a chooser, not a payload.
  2. `session.execute(select(Relay).where(Relay.id == pk))` -- a Core/ORM statement OBJECT. There is no
     SQL text at the call at all; the dialect compiles the tree afterwards and every value inside it
     leaves as a bound parameter.

Both are read off the construction, never off a name or a path. The refusals are the contract: a hole
that a parameter, a call, an attribute or a `text()`/`RawSQL()` template can fill stays reported, and a
function that merely shares the spelling `text` is not the SQLAlchemy wrapper.

Run it either way:
    python tests/test_arena_fp_clusters_3.py
    python -m pytest tests/test_arena_fp_clusters_3.py -q
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ast_scanner
from ast_scanner import TaintTracker


def _cwes_at(code: str, line: int, filename: str = "app/svc.py") -> set:
    tracker = TaintTracker(files={filename: code})
    _sources, sinks, _edges = tracker.analyze()
    return {(sink.location.line_start, (sink.metadata or {}).get("cwe"))
            for sink in sinks if (sink.metadata or {}).get("cwe")}


def _fires(code: str, line: int, cwe: str = "CWE-89") -> None:
    got = _cwes_at(code, line)
    assert (line, cwe) in got, f"expected {cwe} at line {line}, got {sorted(got)}"


def _silent(code: str, line: int, cwe: str = "CWE-89") -> None:
    got = _cwes_at(code, line)
    assert (line, cwe) not in got, f"unexpected {cwe} at line {line}, got {sorted(got)}"


# ─── Shape 1: the literal-only statement ───────────────────────────────────────────────────────────

CURSOR_TERNARY = '''def query(conn, flag):
    col = "id" if flag else "name"
    cursor = conn.cursor()
    cursor.execute(%s)
'''

HOOK_TERNARY = '''def query(hook, flag):
    col = "id" if flag else "name"
    hook.get_records(%s)
'''

TEXT_TERNARY = '''from sqlalchemy import text


def run(engine, flag):
    tbl = "relay" if flag else "device"
    engine.execute(%s)
'''


class TestClosedLiteralTernary:
    def test_a_parameter_in_the_statement_is_the_loud_baseline(self):
        _fires('def query(conn, order):\n    cursor = conn.cursor()\n'
               '    cursor.execute("SELECT " + order + " FROM users")\n', 3)

    def test_a_ternary_of_two_literals_is_silent_through_every_spelling(self):
        _silent(CURSOR_TERNARY % '"SELECT " + col + " FROM users"', 4)
        _silent(CURSOR_TERNARY % 'f"SELECT {col} FROM users"', 4)
        _silent(CURSOR_TERNARY % '"SELECT %s FROM users" % (col,)', 4)

    def test_the_spelling_is_still_assembled_from_literals_when_a_name_holds_it(self):
        _silent('import sqlite3\n\n\ndef query(conn, flag):\n    col = "id" if flag else "name"\n'
                '    sql = "SELECT " + col + " FROM users"\n    cursor = conn.cursor()\n'
                '    cursor.execute(sql)\n', 8)

    def test_a_query_handed_to_a_hook_is_judged_the_same_way(self):
        _silent(HOOK_TERNARY % 'f"SELECT {col} FROM users"', 3)
        _fires(HOOK_TERNARY % 'f"SELECT {order} FROM users"'.replace("flag", "order"), 3)

    def test_the_raw_sql_wrapper_is_transparent(self):
        _silent(TEXT_TERNARY % 'text(f"TRUNCATE {tbl}")', 6)
        _silent('import sqlalchemy as sa\n\n\ndef run(engine, flag):\n'
                '    tbl = "relay" if flag else "device"\n    engine.execute(sa.text(f"TRUNCATE {tbl}"))\n', 6)

    def test_a_wrapper_named_text_that_is_not_sqlalchemy_is_not_transparent(self):
        # `def text(s): return open(s).read()` returns whatever the file holds -- the spelling proves
        # nothing about the value, so the redirect stays charged.
        _fires('def text(s):\n    return open(s).read()\n\n\ndef run(engine, order):\n'
               '    engine.execute(text(order))\n', 6)

    def test_a_hole_filled_by_a_parameter_stays_reported(self):
        _fires('def query(conn, order):\n    cursor = conn.cursor()\n'
               '    cursor.execute(f"SELECT {order} FROM users")\n', 3)
        _fires('def query(conn, order):\n    cursor = conn.cursor()\n'
               '    cursor.execute("SELECT %s FROM users" % (order,))\n', 3)
        _fires(TEXT_TERNARY % 'text("SELECT id FROM t ORDER BY " + order)', 6)

    def test_the_blessed_both_branches_with_input_still_reports(self):
        # benchmark/corpus/cwe_89_sqli/test_v05_bad.py: an `if` picks the table, but `uid` is inside
        # BOTH strings -- a chooser over tainted text is not a chooser over literals.
        _fires('import sqlite3\n\n\ndef get_entity(uid, is_admin):\n    conn = sqlite3.connect("app.db")\n'
               '    cursor = conn.cursor()\n    if is_admin:\n'
               '        q = f"SELECT * FROM admins WHERE id = {uid}"\n    else:\n'
               '        q = f"SELECT * FROM users WHERE id = {uid}"\n    cursor.execute(q)\n'
               '    return cursor.fetchall()\n', 11)


# ─── Shape 2: a statement object, not a statement ─────────────────────────────────────────────────

class TestSqlAlchemyStatementObjects:
    def test_select_is_not_sql_text(self):
        _silent('from sqlalchemy import select\nfrom models import Relay\n\n\ndef list_relays(session, pk):\n'
                '    return session.execute(select(Relay).where(Relay.id == pk)).all()\n', 6)

    def test_insert_update_and_delete_are_not_sql_text(self):
        _silent('from sqlalchemy import insert\nfrom models import Relay\n\n\ndef add(session, values):\n'
                '    return session.execute(insert(Relay).values(**values))\n', 6)
        _silent('from sqlalchemy import delete, update\nfrom models import Relay\n\n\n'
                'def bump(session, pk):\n'
                '    session.execute(update(Relay).where(Relay.id == pk).values(name="x"))\n'
                '    session.execute(delete(Relay).where(Relay.id == pk))\n', 6)

    def test_a_statement_held_in_a_name_is_still_a_statement(self):
        _silent('from sqlalchemy import select\nfrom models import Relay\n\n\ndef go(session, pk):\n'
                '    stmt = select(Relay).where(Relay.id == pk)\n    return session.execute(stmt)\n', 7)

    def test_raw_sql_inside_the_structure_voids_the_proof(self):
        _fires('from sqlalchemy import select, text\nfrom models import Relay\n\n\ndef go(session, order):\n'
               '    return session.execute(select(Relay).where(text("name = " + order)))\n', 6)

    def test_an_unknown_callable_is_not_a_statement_object(self):
        _fires('def go(session, builder, pk):\n    return session.execute(builder(pk))\n', 2)

    def test_the_tables_hold_their_ground(self):
        # `text` must stay a refusal, not a constructor: treating it as structure would excuse every
        # raw-SQL template the driver is handed.
        assert "text" in ast_scanner.CWE89_RAW_SQL_WRAPPERS
        assert not (ast_scanner.CWE89_STATEMENT_CONSTRUCTORS & ast_scanner.CWE89_RAW_SQL_WRAPPERS)
        assert {"select", "insert", "update", "delete"} <= ast_scanner.CWE89_STATEMENT_CONSTRUCTORS


# ─── The safe spellings the rule already got right (non-regression) ────────────────────────────────

class TestBindParametersStayQuiet:
    def test_a_parameterised_statement_has_no_hole(self):
        _silent('def safe(cursor, name):\n'
                '    cursor.execute("SELECT id FROM t WHERE name = %s", (name,))\n', 2)

    def test_a_self_contained_probe_statement_has_no_hole(self):
        _silent('def probe(cursor):\n    cursor.execute("SELECT current_database()")\n', 2)
        _silent('import psycopg2\n\n\ndef probe(conn):\n    cur = conn.cursor()\n'
                '    cur.execute("SELECT version()")\n', 6)


def test_corpus_sqli_rows_are_still_reported():
    corpus = ROOT / "benchmark" / "corpus" / "cwe_89_sqli"
    loud = ("bad.py", "test_v01_bad.py", "test_v02_bad.py", "test_v03_bad.py",
            "test_v04_bad.py", "test_v05_bad.py")
    quiet = tuple(n.replace("_bad.py", "_good.py") for n in loud if n != "bad.py") + ("good.py",)
    for name in loud:
        code = (corpus / name).read_text(encoding="utf-8")
        assert any(cwe == "CWE-89" for _line, cwe in _cwes_at(code, 0, name)), name
    for name in quiet:
        code = (corpus / name).read_text(encoding="utf-8")
        assert not [1 for line, cwe in _cwes_at(code, 0, name) if cwe == "CWE-89"], name


if __name__ == "__main__":
    tests = []
    for _name, _obj in sorted(globals().items()):
        if _name.startswith("Test") and isinstance(_obj, type):
            tests.extend((_name + "." + m, getattr(_obj, m))
                         for m in sorted(dir(_obj)) if m.startswith("test_") and callable(getattr(_obj, m)))
        elif _name.startswith("test_") and callable(_obj):
            tests.append((_name, _obj))
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {name}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
