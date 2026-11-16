"""Gate #58: the seven Home Assistant Core (2023.11.0) false-positive pockets, retired on proof.

What this gate is for
---------------------
HA Core 2023.11.0 produced 485 findings; 130-ish of them were shapes the engine reported because a
NAME looked dangerous, not because a value was. This task retired seven of those pockets, and every
one of them is a rule about DATAFLOW, so each needs its own witnesses: a fixture that must go quiet,
a fixture that must stay loud for the reason the mandate names, and a weakening that proves the clause
is what is holding the line.

  P1  ATTRIBUTION. A CWE-89 repair used to run inside the per-module loop, so every module claimed
      every registry record and the alphabetically first file stamped OTHER files' callee line numbers
      onto its own path. 21 rows landed on `homeassistant/__main__.py` at lines 416..2562 (a 300-line
      file), and `benchmark/corpus/cwe_1004_cookies/test_v01_bad.py` -- two lines, no SQL -- came to
      own line 6 of a SQL fixture. The owner is now read off the record. A finding that names a line
      past the end of the file it names cannot be a finding about that file, so TIER 3 forbids that
      shape structurally and forbids writing one `(file, line, cwe)` triple twice. The fixture pair is
      `cross_file/case_04_aliased_import_sqli`: the row belongs to the callee that holds the AST node,
      and it belongs there only while a caller really supplies the statement (TIER 4b cuts that taint
      and the row goes quiet).
  P2  INTERNAL MAINTENANCE SQL. `PRAGMA`/`VACUUM`/`ANALYZE`/`REINDEX`/`CREATE INDEX`/`DROP INDEX`/
      `ALTER TABLE`/`sqlite_master` templates whose holes are table names read out of a module-level
      collection, SQLAlchemy `Table`/`Column` metadata attributes, or bound-parameter placeholders.
      The retirement is refused the moment any hole can be fed from `conf`/`config`/`request`/
      `options`/`environ`/`argv`, which is why `components/sql/*` stays CRITICAL.
  P3  SHUFFLE MODE. `random.shuffle(x)` permutes a deck; `client.shuffle(flag)` cannot -- the argument
      is a `bool`, so the call sets a media player's shuffle MODE and mints nothing. The receiver is
      checked first, so a real `random`/`SystemRandom`/`np.random` shuffle never matches, and the arm
      is read AFTER the credential veto, so `random.shuffle(tokens)` stays loud.
      The pocket's second clause is a REFUSAL, not an exemption: `randrange(AID_MIN, AID_MAX)`
      allocates a HomeKit accessory id, and `min`/`max` there bound an ID SPACE instead of naming the
      statistics columns they spell in `{"min": mean - random() * max_diff}`. TIER 2 pins that row
      loud, TIER 4 blinds the refusal, and TIER 4b renames the bounds to `min_value`/`max_value` to
      show the same display-table entry still retires a genuine statistics draw.
  P4  TIMING-SCAN STRUCTURAL FIELDS. CWE-208 fires when a secret-ish name is compared with `==`. A
      comparison against an enum member (`token_type == models.TOKEN_TYPE_SYSTEM`) or against
      `os.path.basename(...) == "secrets.yaml"` compares a structural field or a filename, not a
      secret; a comparison of two credential-named values still reports.
  P5  ABSENT PASSWORD. `""` is how a schema says "not set". `vol.Optional(CONF_PASSWORD, default="")`
      and `self.config.get("password", "")` are unset markers. The engine writes CWE-521 for an empty
      hardcoded credential and for nothing else -- `"admin"`, `"1234"` and `"password"` were measured
      to produce no CWE-521 row at all -- so what this pocket has to protect is the SCOPE: a blank
      constant that is not sitting in a schema `default=` stays reported, and TIER 4b turns the schema
      keyword off to show that is what holds it.
  P6  CONTENT-ADDRESSED DIGESTS. `md5` of a backup slug or of an e-mail for Gravatar addresses a
      thing in a listing. `md5(password)` is still CWE-328: the credential veto runs before the
      vocabulary is ever consulted.
  P7  REPOSITORY-SCOPED ENUMERATION. `Path("homeassistant/components").iterdir()`,
      `integration.path.glob("**/*.py")`: the repository picked every byte, so there is no traversal.
      A pattern the engine cannot read, a parameter root, or any module that touches `os.environ` /
      `sys.argv` / a request stays loud.

How to read the tiers
---------------------
TIER 0 pins the tables (a clause is only as narrow as its vocabulary) and asks the maintenance-shape
regex to read the statements the mandate names and to refuse the ones it does not. TIER 1 is the
retirements: quiet as shipped, loud with its own arm reverted -- a row that is quiet for someone
else's reason cannot be booked here, so the arm-off column is the receipt. TIER 2 is the controls:
loud under BOTH arms, which is the zero-FN mandate for this pocket. TIER 3 asks the shipped source to
keep the shape the fix depends on, and measures the two attribution laws over every fixture in the
file. TIER 4 blinds one engine clause at a time and names the rows that move, with the baseline read
BEFORE the weakening is installed. TIER 4b works from the other side: it edits one premise out of a
fixture -- puts the taint back, moves the value out of the schema, turns `glob` into `walk` -- and the
row has to cross to the other side. A clause that only a fixture can falsify is falsified there.
TIER 5 is the work and RSS budget.

    python benchmark/gates/homeassistant_fp_retirement_probe.py
    python benchmark/gates/homeassistant_fp_retirement_probe.py --mutate=maintenance_blind
    python benchmark/gates/homeassistant_fp_retirement_probe.py --dump
"""
from __future__ import annotations

import ast
import contextlib
import inspect
import io as _io
import os
import sys
import time

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402

T = ast_scanner.TaintTracker

BUDGET_SECONDS = 90.0
BUDGET_MUTATION_SECONDS = 20.0
BUDGET_RSS_MB = 90.0


def module(*lines):
    return ''.join(line + '\n' for line in lines)


def pin(source, needle):
    """The line a fixture's sink lives on, read off the source instead of counted by hand."""
    lines = [index for index, text in enumerate(source.splitlines(), 1) if needle in text]
    if len(lines) != 1:
        raise AssertionError(f'{needle!r} pinned {len(lines)} lines, need exactly 1')
    return lines[0]


def scan(files):
    """Rows as (file basename, line, cwe, severity) for an in-memory tree."""
    with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files=dict(files), max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(os.path.basename(row['file']), int(row['line']), row['cwe']) for row in rows})


def hits(found, name, cwe, line):
    return [row for row in found if row == (name, line, cwe)]


CASES = {}


def case(pocket, label, files, cwe, name, line, expect, note='', mode='arms'):
    """expect: 'quiet' (this pocket retired it) or 'loud' (this pocket must not touch it).

    mode: 'arms' reverts this pocket's helpers to answer the reinstatement. 'absent' asks for no arm
    receipt at all -- the row must simply not be booked, because the call site is not a sink and no
    clause of this pocket is what keeps it quiet.
    """
    CASES.setdefault(pocket, []).append(
        {'label': label, 'files': files, 'cwe': cwe, 'name': name, 'line': line,
         'expect': expect, 'note': note, 'mode': mode})
    return files


# --------------------------------------------------------------------------- P1: attribution
# `benchmark/fixtures/cross_file/case_04_aliased_import_sqli`, the pair whose blessed key the phantom
# displaced. The sink is in `repo04.py` and the taint is in `caller04.py`, so the repair loop has to
# name an owner, and `caller04` sorts first: pointing the resolver at "the alphabetically first module"
# reproduces HEAD exactly -- the row leaves the file that holds the AST node and lands six lines deep in
# a five-line file, which is the shape TIER 3 forbids structurally.
_CALLER04 = module(
    'from repo04 import exec_query as run_q',
    '',
    '',
    'def report_view(request):',
    '    statement = request.GET.get("sql")',
    '    return run_q(statement)')
_REPO04 = module(
    'import sqlite3',
    '',
    '',
    'def exec_query(statement):',
    '    connection = sqlite3.connect("reporting.db")',
    '    return connection.cursor().execute(statement)')
_CROSS = {'caller04.py': _CALLER04, 'repo04.py': _REPO04}
case('P1', 'sql_module_owns_its_own_line', _CROSS, 'CWE-89',
     'repo04.py', pin(_REPO04, 'connection.cursor().execute'), 'loud',
     'the true positive the phantom displaced: the callee file, the callee line')
case('P1', 'caller_file_has_no_row_of_its_own', _CROSS, 'CWE-89',
     'caller04.py', pin(_CALLER04, 'return run_q(statement)'), 'quiet',
     'HEAD wrote exactly this row; the call site is not a sink, so nothing may be booked here',
     mode='absent')

# --------------------------------------------------------------------------- P2: maintenance SQL
# Every fixture here is the real HA shape, trimmed to the statements that decide it. `components/sql`
# itself cannot be reproduced synthetically -- a config read that crosses a sessionmaker does not book
# on its own -- so the taint veto is witnessed by three tainted sinks below, and the two named
# `components/sql` files stay witnessed by `aa_parity` (their blessed keys) and by the arena run.
_CONSTRAINTS = '''"""Recorder schema migration: rebuild a table's foreign keys."""
import logging

from sqlalchemy import AddConstraint, DropConstraint, ForeignKeyConstraint, Table, MetaData

TABLE_STATES = "states"

_LOGGER = logging.getLogger(__name__)


def _restrict_delete_rule(session_maker, alters, states_key_constraints):
    for alter in alters:
        with session_scope(session=session_maker()) as session:
            try:
                connection = session.connection()
                connection.execute(DropConstraint(alter["old_fk"]))
                for fkc in states_key_constraints:
                    if fkc.column_keys == alter["columns"]:
                        connection.execute(AddConstraint(fkc))
            except Exception:
                _LOGGER.exception("Could not update foreign options in %s table", TABLE_STATES)


def _drop_foreign_key_constraints(session_maker, engine, table, columns):
    inspector = sqlalchemy.inspect(engine)
    drops = []
    for foreign_key in inspector.get_foreign_keys(table):
        if foreign_key["name"] and foreign_key["constrained_columns"] == columns:
            drops.append(ForeignKeyConstraint((), (), name=foreign_key["name"]))
    old_table = Table(table, MetaData(), *drops)
    for drop in drops:
        with session_scope(session=session_maker()) as session:
            connection = session.connection()
            connection.execute(DropConstraint(drop))
'''

_STATISTICS = '''"""Recorder statistics housekeeping."""
from sqlalchemy import text

STATISTICS_TABLES = ("statistics", "statistics_short_term")


def _reset_start_times(instance, session_scope):
    for table in STATISTICS_TABLES:
        with session_scope(session=instance.get_session()) as session:
            session.connection().execute(
                text(f"update {table} set start = NULL, created = NULL, last_reset = NULL;")
            )
'''

_CATALOG = '''"""Recorder index housekeeping: sqlite_master is SQLite\'s own catalog."""
import sqlite3

TABLES = ("events", "states", "recorder")


def _unused_indexes(connection):
    """Each table\'s own index names, read out of the catalog."""
    for table in TABLES:
        connection.execute(
            f"SELECT name FROM sqlite_master WHERE type=\'index\' AND tbl_name=\'{table}\'"
        )
'''

_PURGE_TAINTED = '''"""Recorder purge: a DELETE-FROM-shaped template whose value the caller supplies."""
import sqlite3


def purge_runs(connection, user_input):
    """Drop the runs a request names."""
    cursor = connection.cursor()
    cursor.execute(f"DELETE FROM recorder_runs WHERE run_id = {user_input['run_id']}")
    connection.commit()
'''

_REQUEST_JSON = '''"""A web handler that runs what the request body asked for."""
import sqlite3
from aiohttp import web


async def handle(request):
    payload = await request.json()
    connection = sqlite3.connect("db.sqlite3")
    connection.execute(f"SELECT * FROM events WHERE run_id = '{payload["id"]}'")
    return web.Response(text="ok")
'''

_CURSOR_PERCENT = '''"""A cursor fed by a caller-supplied argument."""
import MySQLdb


def fetch(connection, user_query):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM t WHERE q = %s" % (user_query,))
    return cursor
'''

case('P2', 'drop_constraint_is_metadata', {'migration.py': _CONSTRAINTS}, 'CWE-89',
     'migration.py', pin(_CONSTRAINTS, 'connection.execute(DropConstraint(alter'), 'quiet',
     'a DropConstraint built from Table/Column metadata')
case('P2', 'add_constraint_is_metadata', {'migration.py': _CONSTRAINTS}, 'CWE-89',
     'migration.py', pin(_CONSTRAINTS, 'connection.execute(AddConstraint(fkc'), 'quiet',
     'the sibling statement on the same object')
case('P2', 'update_set_over_a_table_tuple', {'statistics.py': _STATISTICS}, 'CWE-89',
     'statistics.py', pin(_STATISTICS, 'update {table} set start'), 'quiet',
     'the hole is a table name read out of a module-level collection')
case('P2', 'catalog_probe_of_its_own_indexes', {'recorder.py': _CATALOG}, 'CWE-89',
     'recorder.py', pin(_CATALOG, 'FROM sqlite_master'), 'quiet',
     'SQLite keeps its own schema in sqlite_master; the hole is a name from a module tuple')
case('P2', 'delete_from_with_request_input', {'purge.py': _PURGE_TAINTED}, 'CWE-89',
     'purge.py', pin(_PURGE_TAINTED, 'DELETE FROM recorder_runs'), 'loud',
     'maintenance SHAPE plus real taint: the taint half must win')
case('P2', 'request_json_into_execute', {'handler.py': _REQUEST_JSON}, 'CWE-89',
     'handler.py', pin(_REQUEST_JSON, 'connection.execute(f"SELECT'), 'loud',
     'the body of an HTTP request, straight into execute()')
case('P2', 'percent_format_of_an_argument', {'store.py': _CURSOR_PERCENT}, 'CWE-89',
     'store.py', pin(_CURSOR_PERCENT, 'cursor.execute("SELECT * FROM t WHERE q'), 'loud',
     'a function parameter is an external source whatever the template looks like')

# --------------------------------------------------------------------------- P3: shuffle mode
_SHUFFLE_MODE = module(
    'import random',
    '',
    '',
    'class SpotifyMediaEntity:',
    '    def __init__(self, client):',
    '        self.client = client',
    '',
    '    def shuffle(self, shuffle: bool):',
    '        return self.client.shuffle(shuffle)',
    '',
    '',
    'class DeckGame:',
    '    def deal(self, tokens):',
    '        random.shuffle(tokens)',
    '        return tokens')
case('P3', 'client_shuffle_takes_a_bool', {'media_player.py': _SHUFFLE_MODE}, 'CWE-338',
     'media_player.py', pin(_SHUFFLE_MODE, 'self.client.shuffle(shuffle)'), 'quiet')
case('P3', 'real_random_shuffle_of_named_values', {'media_player.py': _SHUFFLE_MODE}, 'CWE-338',
     'media_player.py', pin(_SHUFFLE_MODE, 'random.shuffle(tokens)'), 'loud',
     'receiver is random AND the list is credential-named')

# The second zero-FN control the mandate names: `homeassistant/components/homekit/aidmanager.py:58`.
# Its bounds spell `min`/`max`, the same two segments the display table reads as statistics columns in
# `{"min": mean - random() * max_diff}` -- but here they bound an ID SPACE, and the value drawn is the
# accessory id a HomeKit pairing is addressed by. The statistics twin below is the same table entry
# doing its job, so the guard that separates them cannot be a blanket refusal of `min`/`max`.
_AID_SPACE = module(
    'import random',
    '',
    'AID_MIN = 1',
    'AID_MAX = 2147483647',
    '',
    '',
    'def _generate_aids(unique_id, entity_id):',
    '    for _ in range(5):',
    '        yield random.randrange(AID_MIN, AID_MAX)',
    '',
    '',
    'def _statistics_record(mean, max_diff):',
    '    return {"min": mean - random.random() * max_diff,',
    '            "max": mean + random.random() * max_diff}')
case('P3', 'accessory_id_space_stays_loud', {'aidmanager.py': _AID_SPACE}, 'CWE-338',
     'aidmanager.py', pin(_AID_SPACE, 'yield random.randrange('), 'loud',
     'min/max bound an ID space, not a statistics column')

# The statistics words also spell a FUNCTION'S FRAME, and a frame is not a value. `minimum` as a
# parameter of `def draw_a_bound(minimum)` names what the caller hands in; `self._minimum` names a
# field of the record the sensor reads. Only the second is evidence that the draw produces a display
# statistic, so the first stays reported and the second retires. This is what keeps the clamp clause's
# row (`max(random.normalvariate(mu, sigma), minimum)`) and the shuffle clause's row
# (`def spread_the_hosts(hosts)`) owned by those clauses instead of answered twice -- the sentry
# tier-6 gate pins both sides of that ownership with its own falsifiers.
_FRAME_BOUNDS = module(
    'import random',
    '',
    '',
    'class RandomSensor:',
    '    def native_value(self):',
    '        return random.randrange(self._minimum, self._maximum + 1)',
    '',
    '',
    'def draw_a_bound(minimum):',
    '    return random.randrange(minimum)')
case('P3', 'attribute_bounds_are_record_fields', {'sensor.py': _FRAME_BOUNDS}, 'CWE-338',
     'sensor.py', pin(_FRAME_BOUNDS, 'randrange(self._minimum'), 'quiet',
     'the random sensor gauge twin: fields of the configured entity, not caller parameters',
     mode='absent')
case('P3', 'parameter_bound_is_not_a_record_column', {'sensor.py': _FRAME_BOUNDS}, 'CWE-338',
     'sensor.py', pin(_FRAME_BOUNDS, 'def draw_a_bound(minimum):') + 1, 'loud',
     'a bare parameter names the frame, so no display evidence exists and the draw stays reported')

# --------------------------------------------------------------------------- P4: structural compares
_AUTH_TYPES = '''"""Home Assistant auth: refresh token type gates."""
from homeassistant.auth import models


class Auth:
    def async_create_refresh_token(self, user, client_id=None, client_name=None,
                                   token_type=None):
        """Create a new refresh token for a user."""
        if not user.is_active:
            raise ValueError("User is not active")

        if token_type is None:
            if user.system_generated:
                token_type = models.TOKEN_TYPE_SYSTEM
            else:
                token_type = models.TOKEN_TYPE_NORMAL

        if user.system_generated != (token_type == models.TOKEN_TYPE_SYSTEM):
            raise ValueError("System generated users can only have system type refresh tokens")

        if token_type == models.TOKEN_TYPE_NORMAL and client_id is None:
            raise ValueError("Client is required to generate a refresh token.")

        if (
            token_type == models.TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN
            and client_name is None
        ):
            raise ValueError("Client_name is required for long-lived access token")

        for token in user.refresh_tokens.values():
            if token.token_type == models.TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN:
                raise ValueError(f"{client_name} already exists")
        return models.RefreshToken
'''

_LOADER_FILTER = '''"""YAML includes that skip the secrets file."""
import os

SECRET_YAML = "secrets.yaml"


def _find_files(loc, pattern):
    return []


def include_dir_named_yaml(loader, node):
    """Load each yaml file in a directory as a named dict."""
    mapping = {}
    loc = os.path.join(os.path.dirname(loader.get_name()), node.value)
    for fname in _find_files(loc, "*.yaml"):
        filename = os.path.splitext(os.path.basename(fname))[0]
        if os.path.basename(fname) == SECRET_YAML:
            continue
        mapping[filename] = loader.construct_mapping(node)
    return mapping
'''

_KEY_COMPARE = '''"""A client that authenticates by comparing keys."""
import os


def authorized(payload):
    """Compare the key the request carried with the key in the environment."""
    api_key = os.environ["API_KEY"]
    if payload["api_key"] == api_key:
        return True
    return False
'''

case('P4', 'system_generated_xor_enum_member', {'auth.py': _AUTH_TYPES}, 'CWE-208',
     'auth.py', pin(_AUTH_TYPES, 'user.system_generated != (token_type'), 'quiet',
     'a token TYPE, compared to an enum member')
case('P4', 'enum_member_and_client_id', {'auth.py': _AUTH_TYPES}, 'CWE-208',
     'auth.py', pin(_AUTH_TYPES, 'if token_type == models.TOKEN_TYPE_NORMAL and'), 'quiet',
     'the same field against the same vocabulary')
case('P4', 'multiline_enum_guard', {'auth.py': _AUTH_TYPES}, 'CWE-208',
     'auth.py', pin(_AUTH_TYPES, '            token_type == models'), 'quiet',
     'a compare split across lines still compares a type, not a secret')
case('P4', 'loop_target_enum_member', {'auth.py': _AUTH_TYPES}, 'CWE-208',
     'auth.py', pin(_AUTH_TYPES, 'if token.token_type == models.TOKEN_TYPE_LONG_LIVED'), 'quiet',
     'reached through a loop variable')
case('P4', 'basename_equal_to_a_yaml_name', {'loader.py': _LOADER_FILTER}, 'CWE-208',
     'loader.py', pin(_LOADER_FILTER, 'if os.path.basename(fname) == SECRET_YAML'), 'quiet',
     'a filename filter, the shape the mandate names')
case('P4', 'two_credential_named_values', {'client.py': _KEY_COMPARE}, 'CWE-208',
     'client.py', pin(_KEY_COMPARE, 'payload["api_key"] == api_key'), 'loud',
     'the actual timing oracle this pocket must never touch')

# --------------------------------------------------------------------------- P5: absent password
_SCHEMA = '''"""Solax config flow: an empty default means the field is unset."""
import voluptuous as vol

import homeassistant.helpers.config_validation as cv

CONF_PASSWORD = "password"
DEFAULT_PORT = 80
DEFAULT_PASSWORD = ""

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("host"): cv.string,
        vol.Optional("port", default=DEFAULT_PORT): cv.port,
        vol.Optional(CONF_PASSWORD, default=DEFAULT_PASSWORD): cv.string,
    }
)
'''

_BLANK_NO_SCHEMA = '''"""An empty password outside a schema is still a hardcoded credential."""
PASSWORD = ""
'''

case('P5', 'schema_default_empty_string', {'config_flow.py': _SCHEMA}, 'CWE-521',
     'config_flow.py', pin(_SCHEMA, 'DEFAULT_PASSWORD = ""'), 'quiet',
     'the field is unset, which is what an empty default means in a schema')
case('P5', 'blank_constant_outside_a_schema', {'plain.py': _BLANK_NO_SCHEMA}, 'CWE-521',
     'plain.py', pin(_BLANK_NO_SCHEMA, 'PASSWORD = ""'), 'loud',
     'no schema, no default keyword: the retirement does not reach it')

# --------------------------------------------------------------------------- P6: content digests
_SLUG = module(
    'import hashlib',
    'import uuid',
    '',
    '',
    'def _generate_slug(name, date):',
    '    return hashlib.md5(f"{date} - {name}".encode()).hexdigest()[:8]',
    '',
    '',
    'def get_gravatar_for_email(email):',
    '    return hashlib.md5(email.encode()).hexdigest()',
    '',
    '',
    'def hash_password(password):',
    '    return hashlib.md5(password.encode()).hexdigest()')
case('P6', 'backup_slug_digest', {'backup.py': _SLUG}, 'CWE-328',
     'backup.py', pin(_SLUG, 'md5(f"{date}'), 'quiet')
case('P6', 'gravatar_digest', {'backup.py': _SLUG}, 'CWE-328',
     'backup.py', pin(_SLUG, 'md5(email.encode'), 'quiet')
case('P6', 'md5_of_a_password', {'backup.py': _SLUG}, 'CWE-328',
     'backup.py', pin(_SLUG, 'md5(password.encode'), 'loud')

# --------------------------------------------------------------------------- P7: repo enumeration
_COLLECTOR = '''"""script/hassfest/dependencies.py, reduced to the collector walk."""
from __future__ import annotations

import ast
from pathlib import Path

from .model import Integration


class ImportCollector(ast.NodeVisitor):
    """Collect all integrations referenced."""

    def __init__(self, integration: Integration) -> None:
        """Initialize the import collector."""
        self.integration = integration
        self.referenced: dict[Path, str] = {}

    def collect(self) -> None:
        """Collect imports from a source file."""
        for fil in self.integration.path.glob("**/*.py"):
            if not fil.is_file():
                continue
            self.referenced[fil] = fil.name
            self.visit(ast.parse(fil.read_text()))

    def visit(self, tree) -> None:
        """Walk a parsed file."""
        return None
'''

_ENV_ROOT = '''"""The same read with a root the operator supplies: loud."""
import json
import os
import pathlib

TARGET = os.environ["TARGET"]


def read_target():
    """Read the file named in the environment."""
    path = pathlib.Path(TARGET)
    return json.loads(path.read_text())
'''

case('P7', 'glob_over_the_integration_folder', {'dependencies.py': _COLLECTOR}, 'CWE-22',
     'dependencies.py', pin(_COLLECTOR, 'self.visit(ast.parse(fil.read_text'), 'quiet',
     'the repository enumerated its own files; no byte of the path is caller-chosen')
case('P7', 'path_from_environ', {'reader.py': _ENV_ROOT}, 'CWE-22',
     'reader.py', pin(_ENV_ROOT, 'return json.loads(path.read_text'), 'loud',
     'the environment chose this path, so traversal is real')


# --------------------------------------------------------------------------- the arms
# Every helper a pocket wired into the engine. The sweep reverts all of them together, because a row
# that comes back when a clause is removed is evidence the clause is what silenced it; a row that only
# comes back when two are removed would be evidence of nothing.
ARMS = {
    'P1': ('_c89_record_owner_module',),
    'P2': ('_c89_statement_is_internal_maintenance', '_c89_registry_sink_is_internal'),
    'P3': ('_cwe338_shuffle_moves_a_flag',),
    'P4': ('_c208_compare_is_structural_field', '_c208_compare_is_a_filename_or_tag_filter'),
    'P5': ('_c521_empty_constant_is_a_schema_default', '_c521_lookup_default_is_absent_marker'),
    'P6': ('_cwe328_hash_input_is_non_credential',
           '_cwe328_enclosing_helper_is_content_addressed'),
    'P7': ('_c22_path_is_repo_internal_enumeration',),
}

_ALL_ARMS = sorted({name for names in ARMS.values() for name in names})
_ORIG = {name: getattr(T, name) for name in _ALL_ARMS if hasattr(T, name)}
_MISSING_ARMS = [name for name in _ALL_ARMS if name not in _ORIG]
if _MISSING_ARMS:
    raise AssertionError(f'arms point at helpers the engine no longer has: {_MISSING_ARMS}')


@contextlib.contextmanager
def arms_off(pocket):
    names = ARMS[pocket]
    # getattr_static, not getattr: a staticmethod read through getattr comes back as a bare function,
    # and putting that back with setattr turns it into an instance method -- every later call then
    # passes self where the clause expects its first argument. The descriptor is what must be restored.
    saved = {name: inspect.getattr_static(T, name) for name in names}
    for name in names:
        setattr(T, name, lambda *args, **kwargs: False)
    try:
        yield
    finally:
        for name, original in saved.items():
            setattr(T, name, original)
        for name, original in saved.items():
            if inspect.getattr_static(T, name) is not original:
                raise AssertionError(f'{name} was not restored')


def run_case(entry):
    return scan(entry['files'])


def table(name):
    """A pocket vocabulary, wherever it lives: some are class attributes, some are module level."""
    if hasattr(T, name):
        return getattr(T, name)
    if hasattr(ast_scanner, name):
        return getattr(ast_scanner, name)
    raise AssertionError(f'neither TaintTracker nor ast_scanner defines {name}')


def check_tables():
    failures = []
    print('\nTIER 0  the vocabularies are as narrow as the mandate says')
    shape = table('CWE89_MAINTENANCE_SHAPE_RE').match
    for statement in ('PRAGMA integrity_check', 'VACUUM', 'ANALYZE states', 'REINDEX',
                      'CREATE INDEX idx_states_created ON states (created)',
                      'CREATE UNIQUE INDEX IF NOT EXISTS i ON t (c)',
                      'DROP INDEX idx_states_created', 'DROP TABLE states',
                      'ALTER TABLE states ADD COLUMN new_col INTEGER',
                      'OPTIMIZE TABLE states',
                      "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name= X ",
                      "SELECT name FROM sqlite_temp_master WHERE type='index'",
                      'UPDATE statistics SET start = NULL',
                      'DELETE FROM recorder_runs',
                      'INSERT INTO archive SELECT * FROM states'):
        if not shape(statement):
            failures.append(f'P2 maintenance shape no longer reads {statement!r}')
    for statement in ('SELECT * FROM users WHERE id = X ',
                      'SELECT * FROM states LIMIT 1; DROP TABLE states',
                      'SELECT password FROM users ORDER BY created',
                      'EXECUTE something'):
        if shape(statement):
            failures.append(f'P2 maintenance shape must not read {statement!r}')
    for word in ('conf', 'config', 'user_input', 'request', 'options', 'argv', 'environ'):
        if word not in table('CWE89_EXTERNAL_SOURCE_WORDS'):
            failures.append(f'P2 external source word {word} missing')
    for word in ('glob', 'rglob', 'iterdir'):
        if word not in table('CWE22_TEMP_ROOT_ENUMERATION_LEAVES'):
            failures.append(f'P7 enumerator {word} missing')
    for word in ('listdir', 'scandir', 'walk'):
        if word in table('CWE22_TEMP_ROOT_ENUMERATION_LEAVES'):
            failures.append(f'P7 {word} must NOT be an enumerator')
    for word in ('slug', 'gravatar'):
        if word not in table('CWE328_CONTENT_HASH_KEYWORDS'):
            failures.append(f'P6 vocabulary lost {word}')
    for word in ('password', 'secret', 'token'):
        if word in table('CWE328_CONTENT_HASH_KEYWORDS'):
            failures.append(f'P6 {word} must NOT be a content-hash word')
    for word in ('DropConstraint', 'AddConstraint', 'Table', 'Column', 'text'):
        if word not in table('CWE89_STATEMENT_CONSTRUCT_LEAVES'):
            failures.append(f'P2 statement-construct leaf {word} missing')
    for word in ('table_name', 'index_name', 'constraint_name'):
        if word not in table('CWE89_METADATA_ATTRIBUTE_WORDS'):
            failures.append(f'P2 metadata attribute {word} missing')
    for word in ('query', 'statement'):
        if word in table('CWE89_METADATA_ATTRIBUTE_WORDS'):
            failures.append(f'P2 {word} is the ordinary name for an internal SQL value, not metadata')
    for suffix in ('_type', '_status', '_version'):
        if suffix not in table('CWE208_STRUCTURAL_SUFFIXES'):
            failures.append(f'P4 structural suffix {suffix} missing')
    for word in ('token', 'secret', 'password', 'hmac', 'signature'):
        if word not in table('CWE208_CREDENTIAL_SUFFIXES'):
            failures.append(f'P4 credential suffix {word} missing')
    for leaf in ('optional', 'required', 'schema'):
        if leaf not in table('CWE521_SCHEMA_CALL_LEAVES'):
            failures.append(f'P5 schema call leaf {leaf} missing')
    for leaf in ('execute', 'format'):
        if leaf in table('CWE521_SCHEMA_CALL_LEAVES'):
            failures.append(f'P5 {leaf} must NOT be a schema call leaf')
    for word in ('default', 'value'):
        if word not in table('CWE521_SCHEMA_DEFAULT_KEYWORDS'):
            failures.append(f'P5 default keyword {word} missing')
    for leaf in ('Path', 'PurePath'):
        if leaf not in table('C22_REPO_ROOT_CONSTRUCTORS'):
            failures.append(f'P7 repo-root constructor {leaf} missing')
    for word in ('aid', 'uuid', 'guid', 'serial', 'identifier'):
        if word not in table('CWE338_IDENTIFIER_SPACE_WORDS'):
            failures.append(f'P3 identifier-space word {word} missing')
    for word in ('min', 'max', 'mean', 'sum', 'value', 'data', 'id', 'index'):
        if word in table('CWE338_IDENTIFIER_SPACE_WORDS'):
            failures.append(f'P3 {word} is a display or container word, not an identifier space')
    for word in ('min', 'max', 'minimum', 'maximum', 'mean', 'sum', 'noise'):
        if word not in table('CWE338_DISPLAY_VALUE_MARKERS'):
            failures.append(f'P3 display marker {word} missing')
    statistics = table('CWE338_RECORD_STATISTIC_MARKERS')
    if not statistics <= table('CWE338_DISPLAY_VALUE_MARKERS'):
        failures.append('P3 the record-statistic family must be part of the display table, not beside it')
    for word in ('min', 'max', 'minimum', 'maximum', 'spread'):
        if word not in statistics:
            failures.append(f'P3 frame-ambiguous statistic {word} missing from the narrowed family')
    for word in ('host', 'hosts', 'color', 'delay', 'jitter', 'interval'):
        if word in statistics:
            failures.append(f'P3 {word} is an older display word and must not be frame-narrowed')
    print(f'  tables checked, failures={len(failures)}')
    return failures


def check_retirements():
    failures = []
    print('\nTIER 1  retirements (quiet shipped, loud with this pocket\'s arm reverted)')
    for pocket in sorted(CASES):
        for entry in CASES[pocket]:
            if entry['expect'] != 'quiet':
                continue
            shipped = hits(run_case(entry), entry['name'], entry['cwe'], entry['line'])
            if entry['mode'] == 'absent':
                reverted = None
                ok = not shipped
            else:
                with arms_off(pocket):
                    reverted = hits(run_case(entry), entry['name'], entry['cwe'], entry['line'])
                ok = not shipped and bool(reverted)
            print(f'  {"OK " if ok else "FAIL"} {pocket} {entry["label"]:42s} '
                  f'shipped={len(shipped)} arm_off={"n/a" if reverted is None else len(reverted)}')
            if not ok:
                failures.append(f'{pocket}/{entry["label"]}: shipped={shipped} arm_off={reverted}')
    return failures


def check_controls():
    failures = []
    print('\nTIER 2  controls (loud under BOTH arms -- the zero-FN mandate)')
    for pocket in sorted(CASES):
        for entry in CASES[pocket]:
            if entry['expect'] != 'loud':
                continue
            shipped = hits(run_case(entry), entry['name'], entry['cwe'], entry['line'])
            with arms_off(pocket):
                reverted = hits(run_case(entry), entry['name'], entry['cwe'], entry['line'])
            ok = bool(shipped) and bool(reverted)
            print(f'  {"OK " if ok else "FAIL"} {pocket} {entry["label"]:42s} '
                  f'shipped={len(shipped)} arm_off={len(reverted)}  {entry["note"]}')
            if not ok:
                failures.append(f'{pocket}/{entry["label"]}: shipped={shipped} arm_off={reverted}')
    return failures


def check_attribution_law():
    """No CWE-89 row may point past the end of the file it names, and no site may be written twice."""
    failures = []
    print('\nTIER 3  attribution law + source shape')
    for pocket in sorted(CASES):
        for entry in CASES[pocket]:
            lengths = {name: len(source.splitlines()) for name, source in entry['files'].items()}
            for name, line, cwe in run_case(entry):
                if cwe != 'CWE-89' or name not in lengths:
                    continue
                if line > lengths[name]:
                    failures.append(f'{pocket}/{entry["label"]}: {name}:{line} is past EOF '
                                    f'({lengths[name]} lines)')
    for entry in (e for entries in CASES.values() for e in entries):
        triples = [(name, line, cwe) for name, line, cwe in run_case(entry)]
        if len(set(triples)) != len(triples):
            failures.append(f'{entry["label"]}: a (file, line, cwe) triple was written twice')
    laws = (
        ('_c89_record_owner_module', 'by_file.get', 'P1 reads the owner off the record\'s own file'),
        ('_c89_template_is_maintenance', 'CWE89_MAINTENANCE_SHAPE_RE',
         'P2 requires a maintenance shape before anything else'),
        ('_c89_template_is_maintenance', '_c89_hole_is_internal',
         'P2 asks every interpolation hole separately'),
        ('_c89_hole_is_internal', '_c89_parameter_callers_are_internal',
         'P2 resolves a parameter to its callers instead of trusting its name'),
        ('_c89_hole_is_internal', 'CWE89_METADATA_ATTRIBUTE_WORDS',
         'P2 reads Table/Column metadata through a fixed vocabulary'),
        ('_c89_expression_rides_an_external_source', 'CWE89_EXTERNAL_SOURCE_WORDS',
         'P2 keeps an external-source veto on the callee proof'),
        ('_cwe338_shuffle_moves_a_flag', 'node.func.attr != "shuffle"',
         'P3 asks only shuffle calls'),
        ('_cwe338_shuffle_moves_a_flag', 'systemrandom',
         'P3 refuses a real PRNG receiver'),
        ('_cwe338_draw_allocates_an_identifier', 'CWE338_IDENTIFIER_SPACE_WORDS',
         'P3 refuses an identifier space through a fixed vocabulary'),
        ('_cwe338_draw_allocates_an_identifier', '_CWE338_NAME_SPLIT',
         'P3 matches whole name segments, not substrings'),
        ('_c208_compare_is_structural_field', 'CWE208_CREDENTIAL_SUFFIXES',
         'P4 refuses credential-shaped names'),
        ('_c208_compare_is_structural_field', 'CWE208_STRUCTURAL_SUFFIXES',
         'P4 needs a structural suffix on the compared field'),
        ('_c521_read_is_a_schema_default', 'CWE521_SCHEMA_DEFAULT_KEYWORDS',
         'P5 requires the read to sit in a default keyword'),
        ('_c521_read_is_a_schema_default', 'CWE521_SCHEMA_CALL_LEAVES',
         'P5 requires a schema call around that keyword'),
        ('_c521_empty_constant_is_a_schema_default', ':global',
         'P5 only answers for a module-level constant'),
        ('_cwe328_hash_input_is_non_credential', 'CWE328_CONTENT_HASH_KEYWORDS',
         'P6 consults a content-address vocabulary, not a blanket exemption'),
        ('_c22_enumeration_is_repository_scoped', 'CWE22_TEMP_ROOT_ENUMERATION_LEAVES',
         'P7 enumerates only through glob/rglob/iterdir'),
        ('_c22_enumeration_is_repository_scoped', '_c22_literal_glob_pattern',
         'P7 requires a pattern the file itself wrote'),
        ('_c22_root_is_repository_constant', 'C22_REPO_ROOT_CONSTRUCTORS',
         'P7 proves the root is constructed from literals'),
        ('_c22_root_is_repository_constant', '__file__',
         'P7 accepts a root anchored on the file itself'),
        ('_c22_literal_glob_pattern', '..', 'P7 refuses a traversal-bearing pattern'),
    )
    for method, needle, description in laws:
        source = inspect.getsource(getattr(T, method))
        if needle not in source:
            failures.append(f'source law: {description} ({method} no longer says {needle!r})')
    collector = inspect.getsource(T._collect_cwe89_driver_querybuilder_findings)
    if 'self._c89_record_owner_module(' not in collector:
        failures.append('source law: the P1 repair loop no longer resolves the record owner')
    if 'for record in repair_candidates:' not in collector or \
            collector.index('for record in repair_candidates:') > \
            collector.index('for mod_name, tree in self.modules.items():'):
        failures.append('source law: the P1 repair loop must run once, before the module loop')
    display = inspect.getsource(T._cwe338_display_only_draw)
    refusal = 'self._cwe338_draw_allocates_an_identifier(names)'
    if refusal not in display or 'CWE338_DISPLAY_VALUE_MARKERS' not in display or \
            display.index(refusal) > display.index('CWE338_DISPLAY_VALUE_MARKERS'):
        failures.append('source law: the id-space refusal must be read before the display-marker table')
    if 'self._cwe338_frame_and_operation_names(node)' not in display or \
            'statistic_only' not in display or 'name not in frame' not in display or \
            'CWE338_RECORD_STATISTIC_MARKERS' not in display:
        failures.append('source law: the marker loop must refuse frame names and enclosing callees '
                        'for the record-statistic family only')
    frame_source = inspect.getsource(T._cwe338_frame_and_operation_names)
    if 'posonlyargs' not in frame_source or 'kwonlyargs' not in frame_source or \
            'vararg' not in frame_source or 'kwarg' not in frame_source:
        failures.append('source law: the frame must cover every parameter spelling, not just args')
    print(f'  source laws={len(laws) + 5}, failures={len(failures)}')
    return failures


# --------------------------------------------------------------------------- TIER 4: falsifiers
def _always_true(*args, **kwargs):
    return True


def _always_false(*args, **kwargs):
    return False


def _empty_frame(*args, **kwargs):
    return set()


MUTATIONS = {
    'maintenance_blind': (
        'P2: every registry CWE-89 sink counts as internal maintenance',
        (('_c89_statement_is_internal_maintenance', _always_true),
         ('_c89_registry_sink_is_internal', _always_true)),
        [('P2', 'delete_from_with_request_input'), ('P2', 'request_json_into_execute')]),
    'structural_field_blind': (
        'P4: any == is a structural field compare',
        (('_c208_compare_is_structural_field', _always_true),
         ('_c208_compare_is_a_filename_or_tag_filter', _always_true)),
        [('P4', 'two_credential_named_values')]),
    'schema_default_blind': (
        'P5: any empty-string password is a schema default',
        (('_c521_empty_constant_is_a_schema_default', _always_true),
         ('_c521_lookup_default_is_absent_marker', _always_true)),
        [('P5', 'blank_constant_outside_a_schema')]),
    'content_digest_blind': (
        'P6: every weak digest is content addressing, credential input or not',
        (('_cwe328_hash_input_is_non_credential', _always_true),
         ('_cwe328_enclosing_helper_is_content_addressed', _always_true)),
        [('P6', 'md5_of_a_password')]),
    'repo_enumeration_blind': (
        'P7: any path is repository-internal',
        (('_c22_path_is_repo_internal_enumeration', _always_true),),
        [('P7', 'path_from_environ')]),
    'identifier_space_blind': (
        'P3: an id space\'s bounds count as display statistics',
        (('_cwe338_draw_allocates_an_identifier', _always_false),),
        [('P3', 'accessory_id_space_stays_loud')]),
    'frame_narrowing_blind': (
        'P3: a parameter name counts as a record column',
        (('_cwe338_frame_and_operation_names', _empty_frame),),
        [('P3', 'parameter_bound_is_not_a_record_column')]),
}


def entry_for(pocket, label):
    for entry in CASES[pocket]:
        if entry['label'] == label:
            return entry
    raise AssertionError(f'no case {pocket}/{label}')


def run_mutation(name):
    """Weaken one clause and report the rows that moved.

    The baseline is read BEFORE the weakening is installed. Reading it afterwards compares the mutated
    engine with itself and reports every mutation as MISSED.

    A clause is load-bearing in two directions, and this gate uses both: blinding a guard silences a
    row that must stay loud (a control goes quiet), and it can also put a row back where the guard
    retired it. The watched rows decide the direction, and they must all sit on the same side of the
    baseline -- a mix would let one row cancel another and still report a move.
    """
    description, patches, watched = MUTATIONS[name]
    entries = [entry_for(pocket, label) for pocket, label in watched]
    missing = [attribute for attribute, _ in patches if not hasattr(T, attribute)]
    if missing:
        return description, [label for _, label in watched], [], f'no such clause: {missing}'
    was_loud = [bool(hits(scan(entry['files']), entry['name'], entry['cwe'], entry['line']))
                for entry in entries]
    if any(was_loud) and not all(was_loud):
        return (description, [label for _, label in watched], [],
                'the watched rows sit on both sides of the baseline; split this falsifier')
    saved = {attribute: inspect.getattr_static(T, attribute) for attribute, _ in patches}
    try:
        for attribute, replacement in patches:
            setattr(T, attribute, replacement)
        now_loud = [bool(hits(scan(entry['files']), entry['name'], entry['cwe'], entry['line']))
                    for entry in entries]
    finally:
        for attribute, original in saved.items():
            setattr(T, attribute, original)
        for attribute, original in saved.items():
            if inspect.getattr_static(T, attribute) is not original:
                raise AssertionError(f'{attribute} was not restored')
    moved = [entry['label'] for entry, was, now in zip(entries, was_loud, now_loud) if was != now]
    return description, [label for _, label in watched], moved, None


# A fixture-level weakening asks the question an engine patch cannot: put the dangerous byte back into
# the same source text and the row has to come back. Each pair below is the smallest edit that breaks
# one clause's premise, and each was measured to move exactly the named row.
SOURCE_WEAKENINGS = (
    ('P1', 'the caller stops supplying the statement', 'sql_module_owns_its_own_line', _CROSS,
     'caller04.py', 'connection.cursor().execute(statement)',
     '    statement = request.GET.get("sql")', '    statement = "SELECT 1"'),
    ('P2', 'a hole the caller fills', 'update_set_over_a_table_tuple', _STATISTICS, 'statistics.py',
     'update {table} set start', "last_reset = NULL;\"",
     "last_reset = NULL where id = {user_input['id']};\""),
    ('P4', 'the compared name is a credential', 'multiline_enum_guard', _AUTH_TYPES, 'auth.py',
     '            token_type == models.TOKEN_TYPE_LONG_LIVED',
     'token_type == models.TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN\n            and client_name',
     'token_type == credential.refresh_token_id\n            and client_name'),
    ('P5', 'the value leaves the schema', 'schema_default_empty_string', _SCHEMA, 'config_flow.py',
     'DEFAULT_PASSWORD = ""', 'vol.Optional(CONF_PASSWORD, default=DEFAULT_PASSWORD)',
     'send_state(hass, DEFAULT_PASSWORD)'),
    ('P5', 'the keyword is not a default', 'schema_default_empty_string', _SCHEMA, 'config_flow.py',
     'DEFAULT_PASSWORD = ""', 'vol.Optional(CONF_PASSWORD, default=DEFAULT_PASSWORD)',
     'vol.Optional(CONF_PASSWORD, description=DEFAULT_PASSWORD)'),
    ('P3', 'the receiver is a PRNG', 'client_shuffle_takes_a_bool', _SHUFFLE_MODE,
     'media_player.py', 'self.client.shuffle(shuffle)', '        return self.client.shuffle(shuffle)',
     '        return random.shuffle(shuffle)'),
    ('P3', 'the bounds stop naming an id space', 'accessory_id_space_stays_loud', _AID_SPACE,
     'aidmanager.py', 'yield random.randrange(',
     'AID_MIN = 1\n'
     'AID_MAX = 2147483647\n'
     '\n'
     '\n'
     'def _generate_aids(unique_id, entity_id):\n'
     '    for _ in range(5):\n'
     '        yield random.randrange(AID_MIN, AID_MAX)',
     'MIN_VALUE = 1\n'
     'MAX_VALUE = 2147483647\n'
     '\n'
     '\n'
     'def _draw_a_statistic():\n'
     '    for _ in range(5):\n'
     '        yield random.randrange(MIN_VALUE, MAX_VALUE)'),
    ('P7', 'the folder is not enumerated', 'glob_over_the_integration_folder', _COLLECTOR,
     'dependencies.py', 'self.visit(ast.parse(fil.read_text', 'glob("**/*.py")',
     'walk("**/*.py")'),
    ('P7', 'the pattern is not a literal', 'glob_over_the_integration_folder', _COLLECTOR,
     'dependencies.py', 'self.visit(ast.parse(fil.read_text', 'glob("**/*.py")',
     'glob(self.pattern)'),
)


def check_source_weakenings():
    """Each weakening edits one clause's premise out of a fixture; the row must cross to the other side.

    A row the pocket retired comes back, and a row the pocket was told not to touch goes quiet when the
    taint it was kept for disappears. Which direction applies is the fixture's own `expect`.
    """
    failures = []
    print('\nTIER 4b  fixture weakenings (edit one premise, the row crosses)')
    for pocket, label, case_label, source, name, needle, before, after in SOURCE_WEAKENINGS:
        files = dict(source) if isinstance(source, dict) else {name: source}
        entry = entry_for(pocket, case_label)
        if before not in files[name] or files[name].count(before) != 1:
            failures.append(f'{pocket}/{label}: {before!r} matches {files[name].count(before)} times')
            print(f'  FAIL   {pocket} {label:34s} needle is not unique')
            continue
        row_file = entry['name']
        if row_file not in files:
            failures.append(f'{pocket}/{label}: {row_file} is not in this fixture')
            print(f'  FAIL   {pocket} {label:34s} the row is in another file')
            continue
        line = pin(files[row_file], needle)
        weakened = {key: (text.replace(before, after, 1) if key == name else text)
                    for key, text in files.items()}
        base = hits(scan(files), row_file, entry['cwe'], line)
        moved = hits(scan(weakened), row_file, entry['cwe'], line)
        want_moved = entry['expect'] == 'loud'
        ok = bool(moved) != bool(base) and bool(moved) is not want_moved
        print(f'  {"OK " if ok else "FAIL"} {pocket} {label:34s} base={len(base)} '
              f'weakened={len(moved)}')
        if not ok:
            failures.append(f'{pocket}/{label}: base={base} weakened={moved}')
    return failures


def check_mutations(only=None):
    failures = []
    print('\nTIER 4  falsifiers (one weakening per clause)')
    for name in sorted(MUTATIONS):
        if only and name != only:
            continue
        started = time.perf_counter()
        description, expected, moved, error = run_mutation(name)
        elapsed = time.perf_counter() - started
        if error:
            failures.append(f'{name}: {error}')
            print(f'  ERROR  {name:28s} {error}')
            continue
        ok = sorted(moved) == sorted(expected)
        print(f'  {"CAUGHT" if ok else "MISSED"} {name:28s} moved={moved} ({elapsed:.2f}s)')
        if not ok:
            failures.append(f'{name}: expected {sorted(expected)} moved {sorted(moved)}')
        if elapsed > BUDGET_MUTATION_SECONDS:
            failures.append(f'{name}: took {elapsed:.2f}s (budget {BUDGET_MUTATION_SECONDS}s)')
    return failures


def dump():
    for pocket in sorted(CASES):
        for entry in CASES[pocket]:
            print(f'\n=== {pocket} {entry["label"]} expect={entry["expect"]}')
            for row in run_case(entry):
                print('   ', row)


def rss_mb():
    try:
        import ctypes
    except ImportError:
        return None
    if sys.platform != 'win32':
        return None

    class Counter(ctypes.Structure):
        _fields_ = [('cb', ctypes.c_uint32),
                    ('PeakWorkingSetSize', ctypes.c_size_t),
                    ('WorkingSetSize', ctypes.c_size_t),
                    ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                    ('PagefileUsage', ctypes.c_size_t),
                    ('PeakPagefileUsage', ctypes.c_size_t)]

    counter = Counter()
    counter.cb = ctypes.sizeof(counter)
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    if not ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counter), counter.cb):
        return None
    return counter.PeakWorkingSetSize / 1048576.0


def main():
    argv = sys.argv[1:]
    only = next((a.split('=', 1)[1] for a in argv if a.startswith('--mutate=')), None)
    if only and only not in MUTATIONS:
        print(f'unknown mutation {only}; known: {sorted(MUTATIONS)}')
        return 2
    if '--dump' in argv:
        dump()
        return 0
    started = time.perf_counter()
    failures = []
    if not only:
        failures += check_tables()
        failures += check_retirements()
        failures += check_controls()
        failures += check_attribution_law()
        failures += check_source_weakenings()
    failures += check_mutations(only)
    work = time.perf_counter() - started
    peak = rss_mb()
    total = sum(len(entries) for entries in CASES.values())
    quiet = sum(1 for entries in CASES.values() for e in entries if e['expect'] == 'quiet')
    print(f'\ncases={total} retired={quiet} held_loud={total - quiet} '
          f'mutations={len(MUTATIONS) if not only else 1} '
          f'work={work:.2f}s (budget {BUDGET_SECONDS}s) peak_rss='
          + ('n/a' if peak is None else f'{peak:.1f} MB') + f' (budget {BUDGET_RSS_MB:.0f} MB)')
    if work > BUDGET_SECONDS:
        failures.append(f'work {work:.2f}s over budget')
    if peak is not None and peak > BUDGET_RSS_MB:
        failures.append(f'peak RSS {peak:.1f} MB over budget')
    for failure in failures:
        print(f'  FAILURE {failure}')
    print('VERDICT: ' + ('PASS' if not failures else 'FAIL'))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
