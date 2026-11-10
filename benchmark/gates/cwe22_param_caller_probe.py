"""Slice G truth table: when the callers of a path parameter prove the path, and when they don't.

Why this gate exists
--------------------
Slice G claims two CWE-22 prunings: (1) `open(path_param)` inside a library helper is retired when
**every** in-repo call site hands that parameter a whole-location literal, a `tempfile` root or a hub
cache resolver (`PROVEN_SAFE_PARAM_SINK`), and (2) `open(self.<x>_file)` is retired when the field's
writes prove a root the program created. Both were specified as reaching zero true positives, so the
burden of proof is not the count of rows they silence but the count of blessed rows they touch: **0 of
the 24** (8 parity + 16 Big-8). TIER 2 asks the shipped predicate about those 24 lines directly, and
TIER 1 pins the population so an empty question cannot masquerade as a zero answer.

The premise numbers in the mandate did not survive measurement, and the deltas are the useful part:
the arena holds 148 domain-1 and 138 domain-2 CWE-22 rows, not 93 and ~118. The 24 blessed keys are
also split 8/16 across the two baselines, not 24 inside Big-8.

What it actually retired, measured on the audited arena (transformers v4.38.0, 2,847 modules, 325
chunks) rather than on intent: 1,421 CWE-22-class records were put to the funnel, 50 of them answered
SAFE, and the reported-row diff is **RETIRED=1, ADDED=0** (CWE-22 605 -> 604, all-CWE 1603 -> 1602).
So the claimed ~210-row yield is one row, because the shapes the mandate lists are already retired by
clauses that shipped earlier -- `scratch/_G_seal_compare.py` ran all 35 fixtures against
`git show HEAD:ast_scanner.py` and 11 of them were quiet at HEAD, 7 of those under the *prohibited*
name/path shield `_c22_is_test_suite_or_cached_path`. Those 11 sit in `PREVIOUSLY_QUIET_ROWS` with
`hits == 0`, so no future revision can book them as a Slice G win. The refusals are where the 210 went:
447 records have no enclosing parameter list (the sink is not in a helper), 320 have no in-module call
site, 207 reach the origin proof and fail it (`name_unbound:vocab_file` 25, `attr:args.*` 30+,
`call:os.getcwd` 6), 172 name a parameter that is not in the path at all, and 144 are self-fields with
no temp root behind the write.

The first two of those buckets -- 767 of the 1,421 asks -- are decided by the O(1) per-module presence
facts in `_c22_slice_g_module_facts` rather than by building the scope binding table, and that is what
made the rule free: measured against `git show HEAD:ast_scanner.py` in one interleaved loop
(`scratch/_G_slice_clock.py`, 6 pairs, order-rotating, gc-collected legs of the three Big-8 modules that
hold all 16 blessed keys) the working arm comes out at live/head median 0.997x, with a `head/stub` NULL
arm of 1.003x on the same legs -- so the two arms are not separable, and the honest claim is the median
plus the band, never a single pair (one pair read 1.12x, and the null arm read 1.06x in the same round).
An earlier revision of the funnel cost ~4% because it asked the deep proofs for every record; both new
facts are pinned by their own mutations (`module_tempfile_witness_blind`, `module_call_sites_blind`),
because a guard that moves no row is a guard that was never load-bearing.

Two things this file learned about its own harness, both pinned so they cannot come back. First, the
census is taken at the funnel: an earlier revision re-derived the target expression the way the
cascade does, and the copy drifted -- the cascade reads `tekken_path.read_bytes()` and
`extractor.extract()` off `node.func.value`, not off `node.args`, so 3 of the 16 blessed Big-8 lines
looked unasked. `observe_asks` now wraps the shipped method and lets the engine call it, so `asked` is
what the engine asked and cannot be a mirror. Second, a gate that reads files with a helper's return
value or a `*split('/')` splat becomes a CWE-22 finding itself, because parity scans
`benchmark/gates/`: this file briefly turned 425 into 427 with two rows of its own. `check_blessed_reach`
now uses the same ROOT-anchored, single-write, `os.path.exists`-guarded `with open(...)` shape the
sibling probes use.

What makes this a proof and not a guess
---------------------------------------
The rule never reads a file name, a directory name, a function name or a variable name. `Rung 2` of
the Both-And ladder is machine-checked here: TIER 5 walks the source of the deciding method and
refuses any `tests/`, `examples/`, `corpus`, `convert_` or `test_` token in it.

Domain 1 is a **positive** proof about values, and it fails closed in six distinct ways, each pinned
by a fixture that stays loud:

  * no call site in the file at all -> refused (`no_call_site_in_file`). A helper whose callers live in
    another module is the same case, which is why `modeling_utils.py`, `trainer.py` and every converter
    entry point cannot be silenced from inside their own file;
  * a `*args` or `**kwargs` splat at any site -> refused (`caller_splats_positional`,
    `caller_splats_keyword`): the value is whatever the caller's caller had;
  * any binding that is not proven -> refused, because the answer is the conjunction over **every**
    value the name can hold (`one_caller_passes_request`, `parameter_rebound_locally`);
  * a literal must name the *whole location* -- absolute, or a drive root -- because a relative
    `"release.txt"` resolves against whatever directory the process was launched in
    (`caller_passes_relative_literal`); `parity benchmark/corpus/cwe_937_insecure_protocol/test_v06_bad.py:6`
    is exactly that shape and is a blessed key, which is what this clause was measured against;
  * `..` voids either spelling (`caller_passes_escape_literal`, `dotdot_leaf_only`);
  * a subscript is an element somebody put in a container (`paths[0]` is accepted only because the
    list literal itself is proven), an unimported `hf_hub_download` has no witnessed root
    (`hub_resolver_without_import`), and a join whose receiver is a foreign object stays loud
    (`caller_passes_foreign_receiver_join`, `join_carries_a_tainted_segment`).

Domain 2 reuses the teardown proof the engine already ships (`_c22_path_is_proven_temp_root`) and adds
only a `self`/`cls` gate in front of it, asked at the read instead of only at the delete. It takes
*every* write the field has, so a second write from `request` voids it
(`self_field_second_write_from_request`) and an unwritten field voids it (`self_field_never_written`).

One deciding site
-----------------
The measured reason the first wiring shipped nothing: CWE-22 `open()` rows arrive through three
different registrants, and two of them -- the Phase-5 synthetic-source branches -- append an edge and
`continue` **before** the exemption disjunction, while the parameter collector retires rows even
earlier. So a proof placed in the disjunction, or in the collector, is blind to the rows it was written
for. Rung 4 of the ladder says unify the funnel: `_c22_slice_g_proves_safe_sink`
(ast_scanner.py:8348) is consulted **once**, at the head of the graph-evaluation cascade, before any
synthetic-source branch, and TIER 5 asserts both halves of that -- exactly one consult site in the
engine, and a strictly earlier line than every `p3_source_id` / `p4_source_id` / `p5_source_id`
short-circuit.

Usage
-----
    python benchmark/gates/cwe22_param_caller_probe.py
    python benchmark/gates/cwe22_param_caller_probe.py --mutate=<name>

Nine weakenings are pinned below, each one clause of the shipped proof or one of its two presence
facts, and each must move the row that clause decides -- measured 9/9 CAUGHT at exit 1, per Harness
Law 8. The tripwires are line-scoped:
a fixture module carries other CWE-22 rows that belong to other clauses, and a whole-file "did anything
disappear" test reports a working mutation as decorative (it did, twice, before the line was pinned).
"""
from __future__ import annotations

import ast
import contextlib
import io as _io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)
sys.path.insert(0, GATES_DIR)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys  # noqa: E402

# The blessed CWE-22 population, measured out of the frozen baselines this file refuses to re-bless.
CWE22_LOCKED = {'parity': 8, 'big8': 16}
BASELINE_TOTALS = {'parity': 425, 'big8': 119}


def is_cwe22_record(meta) -> bool:
    return (meta.get('cwe') == 'CWE-22'
            or meta.get('sink_type') in ('PATH_TRAVERSAL', 'FILE_ACCESS')
            or meta.get('operation') == 'FILE_ACCESS')


def scan_source(source, module='m.py'):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-22'})


def observe_asks(source, module='m.py'):
    """Scan one module and record every question the shipped funnel was actually asked.

    The census is taken by wrapping `_c22_slice_g_proves_safe_sink` and letting the engine's own
    cascade call it, so `asked` counts exactly the lines the engine derived a target expression for
    and `hits` counts exactly the lines it answered SAFE on. This file used to re-derive the target
    itself, and the copy drifted: the cascade reads `tekken_path.read_bytes()` and
    `extractor.extract()` off `node.func.value`, not off `node.args`, so three blessed Big-8 lines
    looked unasked. Rule 15.5 rung 4 -- one funnel, one answer, and the gate stands at the funnel.
    """
    log = []
    original = ast_scanner.TaintTracker._c22_slice_g_proves_safe_sink

    def spy(self, record, target_expr):
        answer = original(self, record, target_expr)
        log.append((record.lineno, dict(record.security_node.metadata),
                    target_expr is not None, answer))
        return answer

    ast_scanner.TaintTracker._c22_slice_g_proves_safe_sink = spy
    try:
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
            tracker.analyze()
    finally:
        ast_scanner.TaintTracker._c22_slice_g_proves_safe_sink = original
    return log


def c22_asks(log):
    """The CWE-22 lines the funnel was asked about, and the lines it answered SAFE on."""
    asked, hits = set(), set()
    for lineno, metadata, has_target, answer in log:
        if is_cwe22_record(metadata) and has_target:
            asked.add(lineno)
            if answer:
                hits.add(lineno)
    return asked, hits


def slice_g_hits(source, module='m.py'):
    """``(asked, hits)`` for one module.

    `asked` is the census size, so a scan that resolved no target expression reports 0 and the tier
    fails rather than certifying an unasked question.
    """
    asked, hits = c22_asks(observe_asks(source, module))
    return len(asked), len(hits)


# --------------------------------------------------------------------------- fixtures
# Built by explicit concatenation, one source line per term, per the harness laws.
#
# The three tables below are separated by MEASUREMENT, not by intention. `scratch/_G_seal_compare.py`
# ran every one of these fixtures against `git show HEAD:ast_scanner.py` and against the working copy,
# and 12 of the shapes the mandate calls Slice G's were already quiet at HEAD -- retired by the
# cascade's `_is_self_described`, by `_c22_path_is_internal_repo_anchor`, or by the legacy
# name/path shield `_c22_is_test_suite_or_cached_path`. A gate that booked those as wins would be
# advertising coverage it did not add, so they sit in `PREVIOUSLY_QUIET_ROWS` and are asserted with
# `hits == 0`: quiet, and NOT because of this rule.

HELP = (
    'def read_sidecar(sidecar_path):\n'
    + '    with open(sidecar_path, "rb") as handle:\n'
    + '        return handle.read()\n')

# The open() taint requirement (`cwe22_open_taint_probe`) retires an unproven `open()` in a module
# that declares no entrypoint. A refused row below must still be a live finding for this gate to be
# able to refuse it, so those carriers append an argv read. Appended, never prepended: no sink line
# moves, and the caller-closure proof is still the only thing that can answer SAFE.
ENTRY = 'import sys\nprint(sys.argv[1])\n'

# Rows this rule retires and nothing else does: loud at HEAD, quiet now, and the deciding method
# answers SAFE on the record.
EARNED_ROWS = {
    'caller_param_gets_tempfile_join': (
        'import os, tempfile\n'
        + 'def write_state(state_path):\n'
        + '    with open(state_path, "w") as handle:\n'
        + '        handle.write("x")\n'
        + 'write_state(os.path.join(tempfile.mkdtemp(), "state.json"))\n'),
    'self_field_joined_onto_temp_root_in_setup': (
        'import os, tempfile\n'
        + 'class Reader:\n'
        + '    def setUp(self):\n'
        + '        self.tmpdirname = tempfile.mkdtemp()\n'
        + '        self.reader_config_file = os.path.join(self.tmpdirname, "reader_config.json")\n'
        + '    def write(self):\n'
        + '        with open(self.reader_config_file, "w", encoding="utf-8") as fp:\n'
        + '            fp.write("{}")\n'),
    'self_field_paired_with_a_literal_segment': (
        'import tempfile\n'
        + 'class Reader:\n'
        + '    def setUp(self):\n'
        + '        self.working_blob = tempfile.NamedTemporaryFile(delete=False).name\n'
        + '    def write(self):\n'
        + '        with open(self.working_blob, "w") as fp:\n'
        + '            fp.write("x")\n'),
}

# Rows the rule is asked about and refuses. Loud at HEAD, loud now, and the deciding method answers
# SAFE on none of them.
REFUSED_ROWS = {
    'no_call_site_in_file': HELP + ENTRY,
    'caller_passes_unbound_name': HELP + 'read_sidecar(external_path)\n',
    'caller_splats_positional': (
        'def read_pair(sidecar_path, other_path):\n'
        + '    with open(sidecar_path, "rb") as handle:\n'
        + '        return handle.read()\n'
        + 'values = ("/opt/a.bin", "/opt/b.bin")\n'
        + 'read_pair(*values)\n'),
    'caller_splats_keyword': HELP + 'options = {"sidecar_path": "/opt/a.bin"}\n' + 'read_sidecar(**options)\n',
    'one_caller_passes_request': (
        'import os\n' + HELP
        + 'def view(request):\n'
        + '    read_sidecar("/opt/fixed.bin")\n'
        + '    return read_sidecar(request.args["f"])\n'),
    'parameter_rebound_locally': (
        'def read_sidecar(sidecar_path):\n'
        + '    sidecar_path = request.args["f"]\n'
        + '    with open(sidecar_path, "rb") as handle:\n'
        + '        return handle.read()\n'
        + 'read_sidecar("/opt/a.bin")\n'),
    'caller_passes_relative_literal': (
        'def download_file(server, filename):\n'
        + '    with open(filename, "wb") as handle:\n'
        + '        handle.write("x")\n'
        + 'download_file("ftp.example.org", "release.txt")\n'),
    'temp_root_with_an_escape_segment': (
        'import os, tempfile\n'
        + 'def write_state(state_path):\n'
        + '    with open(state_path, "w") as handle:\n'
        + '        handle.write("x")\n'
        + 'write_state(os.path.join(tempfile.mkdtemp(), "..", "escape.txt"))\n'),
    'hub_resolver_without_import_witness': HELP + 'read_sidecar(hf_hub_download("org/model", "weights.bin"))\n',
    'caller_passes_foreign_receiver_join': (
        HELP + 'def view(request):\n'
        + '    read_sidecar(request.holder.join("/opt/a.bin"))\n'),
    'join_carries_a_tainted_segment': (
        'import os, tempfile\n' + HELP
        + 'def view(request):\n'
        + '    read_sidecar(os.path.join(tempfile.mkdtemp(), request.args["f"]))\n'),
    'tainted_open_is_not_a_helper_call': (
        'def view(request):\n'
        + '    with open(request.args["f"], "rb") as handle:\n'
        + '        return handle.read()\n'),
    # A `request` name anywhere in the module poisons the binding table itself, so every refusal that
    # needs to isolate ONE clause of the origin proof is written without it -- these two shapes are
    # decided by the shipped clauses, not by the module-level poison.
    'one_site_proven_one_site_unbound': (
        'import os, tempfile\n'
        + 'def write_state(state_path):\n'
        + '    with open(state_path, "w") as handle:\n'
        + '        handle.write("x")\n'
        + 'write_state(os.path.join(tempfile.mkdtemp(), "state.json"))\n'
        + 'write_state(sidecar_argument_name)\n'),
    'proven_root_with_unproven_segment': (
        'import os, tempfile\n'
        + 'def write_state(state_path):\n'
        + '    with open(state_path, "w") as handle:\n'
        + '        handle.write("x")\n'
        + 'write_state(os.path.join(tempfile.mkdtemp(), sidecar_argument_name))\n'),
    # The helper IS called in the file, so the cheap call-site index lets the question through, and the
    # answer comes back from the parameter level: `mode` is in the path and no call site ever supplies it.
    # Absence of a value is not proof of one, and this is the row that pins the difference.
    'unpassed_param_inside_a_proven_root': (
        'import os, tempfile\n'
        + 'def read_state(state_path, mode):\n'
        + '    with open(os.path.join(state_path, mode)) as handle:\n'
        + '        return handle.read()\n'
        + 'read_state(tempfile.mkdtemp())\n'),
    'self_field_never_written': (
        'class Reader:\n'
        + '    def read(self):\n'
        + '        with open(self.vocab_file) as handle:\n'
        + '            return handle.read()\n'
        + ENTRY),
    'self_field_second_write_from_request': (
        'import os, tempfile\n'
        + 'class Reader:\n'
        + '    def setUp(self):\n'
        + '        self.csv_file = tempfile.mkdtemp()\n'
        + '    def load(self, request):\n'
        + '        self.csv_file = request.args["f"]\n'
        + '    def read(self):\n'
        + '        with open(self.csv_file) as handle:\n'
        + '            return handle.read()\n'),
    'self_field_holds_parsed_command_line': (
        'import argparse\n'
        + 'class Runner:\n'
        + '    def __init__(self):\n'
        + '        self.args = argparse.ArgumentParser().parse_args()\n'
        + '    def read(self):\n'
        + '        with open(self.args.csv_file) as handle:\n'
        + '            return handle.read()\n'),
    'self_field_from_loop': (
        'class Reader:\n'
        + '    def run(self, candidates):\n'
        + '        for self.csv_file in candidates:\n'
        + '            pass\n'
        + '    def read(self):\n'
        + '        with open(self.csv_file) as handle:\n'
        + '            return handle.read()\n'
        + ENTRY),
    'self_field_is_request_upload': (
        'class Reader:\n'
        + '    def load(self, request):\n'
        + '        self.csv_file = request.files["f"].filename\n'
        + '    def read(self):\n'
        + '        with open(self.csv_file) as handle:\n'
        + '            return handle.read()\n'),
    'self_field_escape_segment': (
        'import os, tempfile\n'
        + 'class Reader:\n'
        + '    def setUp(self):\n'
        + '        self.tmpdirname = tempfile.mkdtemp()\n'
        + '        self.reader_config_file = os.path.join(self.tmpdirname, "..", "escape.json")\n'
        + '    def write(self):\n'
        + '        with open(self.reader_config_file, "w") as fp:\n'
        + '            fp.write("{}")\n'
        + ENTRY),
}

# Quiet at HEAD and quiet now -- retired by a clause that shipped earlier. Kept in the gate so the
# overlap is on the record, and asserted as `hits == 0` so none of them can be re-booked as a Slice G
# win without failing this file.
PREVIOUSLY_QUIET_ROWS = {
    'caller_passes_absolute_literal': (
        'import os\n' + HELP
        + 'read_sidecar(os.path.join("/opt/models/roberta", "sidecar.bin"))\n'),
    'caller_passes_bare_absolute_literal': HELP + 'read_sidecar("/opt/models/roberta/sidecar.bin")\n',
    'caller_passes_module_constant_absolute': (
        'ASSET = "/opt/models/roberta/config.json"\n' + HELP + 'read_sidecar(ASSET)\n'),
    'caller_passes_subscript_of_proven_list': (
        HELP + 'paths = ["/opt/a.bin", "/opt/b.bin"]\n' + 'read_sidecar(paths[0])\n'),
    'caller_passes_named_tempfile_name': (
        'import tempfile\n'
        + 'def read_dump(dump_path):\n'
        + '    with open(dump_path, "rb") as handle:\n'
        + '        return handle.read()\n'
        + 'handle = tempfile.NamedTemporaryFile()\n'
        + 'read_dump(handle.name)\n'),
    'bare_import_mkdtemp_is_not_tempfile': (
        'from tempfile import mkdtemp\n'
        + 'import os\n' + HELP
        + 'read_sidecar(mkdtemp())\n'),
    'caller_passes_escape_literal': HELP + 'read_sidecar("/opt/models/../etc/passwd")\n',
    'dotdot_leaf_only': HELP + 'read_sidecar("../secrets/ids.csv")\n',
    'self_field_from_mkdtemp_in_setup': (
        'import os, tempfile\n'
        + 'class Reader:\n'
        + '    def setUp(self):\n'
        + '        self.tmpdirname = tempfile.mkdtemp()\n'
        + '    def read(self):\n'
        + '        with open(os.path.join(self.tmpdirname, "state.json")) as handle:\n'
        + '            return handle.read()\n'),
    'self_field_from_named_tempfile': (
        'import tempfile\n'
        + 'class Reader:\n'
        + '    def __init__(self):\n'
        + '        self.dump_file = tempfile.NamedTemporaryFile().name\n'
        + '    def read(self):\n'
        + '        with open(self.dump_file, "rb") as handle:\n'
        + '            return handle.read()\n'),
    'self_field_is_save_pretrained_target': (
        'import os, tempfile\n'
        + 'class Exporter:\n'
        + '    def setUp(self):\n'
        + '        self.export_dir = tempfile.mkdtemp()\n'
        + '    def run(self, model):\n'
        + '        model.save_pretrained(self.export_dir)\n'
        + '        with open(os.path.join(self.export_dir, "config.json")) as handle:\n'
        + '            return handle.read()\n'),
}

# --------------------------------------------------------------------------- origin table
# The value-level question, asked on the expression a caller would hand over.

def _expr_of(source):
    """The first argument of the last call expression in `source` -- what a caller would hand over."""
    for node in reversed(ast.parse(source).body):
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and call.args:
                return call.args[0]
    return None


ORIGIN_PROVEN = {
    'abs_literal': 'read("/opt/models/a.bin")\n',
    'win_drive_literal': 'read("C:/models/a.bin")\n',
    'tempfile_root': 'import tempfile\nread(tempfile.mkdtemp())\n',
    'tempfile_name_attr': 'import tempfile\nread(tempfile.NamedTemporaryFile().name)\n',
    'hub_resolver': 'import huggingface_hub\nread(huggingface_hub.hf_hub_download("o", "f"))\n',
    'join_of_root_and_literal': (
        'import os, tempfile\nread(os.path.join(tempfile.mkdtemp(), "a.json"))\n'),
    'path_object': 'import pathlib\nread(pathlib.Path("/opt/models/a.bin"))\n',
}

ORIGIN_REFUSED = {
    'relative_literal': 'read("release.txt")\n',
    'escape_literal': 'read("/opt/../etc/passwd")\n',
    'dotdot_leaf': 'read("../secrets/ids.csv")\n',
    'bare_name_no_binding': 'read(external_path)\n',
    'unimported_helper': 'read(mkdtemp())\n',
    'unimported_hub': 'read(hf_hub_download("o", "f"))\n',
    'request_subscript': 'read(request.args["f"])\n',
    'foreign_join_receiver': 'read(holder.join("/opt/a.bin"))\n',
    'splat_into_join': 'import os\nread(os.path.join(*parts))\n',
    'self_attribute': 'class C:\n    def r(self):\n        read(self.csv_file)\n',
}


# --------------------------------------------------------------------------- tiers

def check_floors():
    """TIER 1: the blessed CWE-22 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-22'}
        print(f'  {kind:7s} total={len(rows)} (want {BASELINE_TOTALS[kind]})  '
              f'CWE-22={len(keys)} (want {CWE22_LOCKED[kind]})')
        if len(rows) != BASELINE_TOTALS[kind]:
            failures.append((kind, 'baseline total', BASELINE_TOTALS[kind], len(rows)))
        if len(keys) != CWE22_LOCKED[kind]:
            failures.append((kind, 'CWE-22 population', CWE22_LOCKED[kind], len(keys)))
    return failures


def check_blessed_reach():
    """TIER 2: Slice G asked about the 24 blessed CWE-22 lines -- the answer must be 0 of 24."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        wanted = sorted((row for row in rows if row[2] == 'CWE-22'), key=lambda r: (str(r[0]), r[1]))
        by_file = {}
        for row in wanted:
            by_file.setdefault(str(row[0]), set()).add(int(row[1]))
        asked = hits = 0
        for file_field, lines in sorted(by_file.items()):
            # The read shape the sibling probes use, for a reason: parity scans `benchmark/gates/`, so
            # a helper's return value, a `*file_field.split('/')` splat or a twice-written name makes
            # the harness ITSELF a CWE-22 key -- which is exactly how this file came to add two rows of
            # its own to the 425. ROOT-anchored, single write, `os.path.exists` guard, `with` block.
            relative = (file_field if kind == 'parity' else os.path.join(
                'benchmark_gates_data', 'corpus_big8', os.path.basename(file_field)))
            path = os.path.abspath(os.path.join(ROOT, relative))
            if not os.path.exists(path):
                failures.append((kind, 'blessed fixture file is not in the tree', file_field))
                continue
            with open(path, encoding='utf-8', errors='replace') as handle:
                source = handle.read()
            module = os.path.basename(file_field)
            asked_here, hits_here = c22_asks([entry for entry in observe_asks(source, module)
                                              if entry[0] in lines])
            asked += len(asked_here)
            for line in sorted(hits_here):
                hits += 1
                failures.append((kind, 'blessed line answered SAFE', file_field, line))
            still = {row[0] for row in scan_source(source, module)}
            for line in sorted(lines):
                if line not in still:
                    failures.append((kind, 'blessed line no longer reported', file_field, line))
        print(f'  {kind:7s} blessed_lines={len(wanted)} asked={asked} answered_safe={hits}')
        if asked != len(wanted):
            failures.append((kind, 'census asked', len(wanted), asked))
    return failures


def check_shapes():
    """TIER 3: findings plus deciding-method census, so a win is attributed to the right rule."""
    failures = []
    earned = refused = inherited = 0
    for label, source in sorted(EARNED_ROWS.items()):
        rows, (asked, hits) = scan_source(source), slice_g_hits(source)
        if rows:
            failures.append(('earned', label, 'still reported', rows[:2]))
        elif not hits:
            failures.append(('earned', label, 'quiet but Slice G answered SAFE on 0 of', asked))
        else:
            earned += 1
    for label, source in sorted(REFUSED_ROWS.items()):
        rows, (asked, hits) = scan_source(source), slice_g_hits(source)
        if not rows:
            failures.append(('refused', label, 'no CWE-22 row reported', asked))
        elif hits:
            failures.append(('refused', label, 'Slice G answered SAFE on', hits))
        else:
            refused += 1
    inherited = overlap = 0
    for label, source in sorted(PREVIOUSLY_QUIET_ROWS.items()):
        rows, (asked, hits) = scan_source(source), slice_g_hits(source)
        if rows:
            failures.append(('inherited', label, 'now reported', rows[:2]))
            continue
        inherited += 1
        # Redundant coverage, measured rather than claimed: this rule can answer SAFE on a row an
        # earlier clause already retired, and such a row is never booked as a Slice G win.
        overlap += 1 if hits else 0
    print(f'  fixtures={len(EARNED_ROWS) + len(REFUSED_ROWS) + len(PREVIOUSLY_QUIET_ROWS)} '
          f'earned={earned} refused={refused} already_quiet_not_claimed={inherited} '
          f'overlap_with_earlier_clauses={overlap}')
    return failures


def check_origins():
    """TIER 4: the value-level proof, asserted expression by expression."""
    failures = []
    proven = refused = 0
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': 'x = 1\n'}, audit_all=True)

    def ask(source):
        tree = ast.parse(source)
        expr = _expr_of(source)
        if expr is None:
            return None
        return tracker._c22_value_is_proven_path_origin(tree, expr, 'm')

    for label, source in sorted(ORIGIN_PROVEN.items()):
        if not ask(source):
            failures.append(('proven', label, 'refused'))
        else:
            proven += 1
    for label, source in sorted(ORIGIN_REFUSED.items()):
        if ask(source):
            failures.append(('refused', label, 'accepted'))
        else:
            refused += 1
    print(f'  origins={len(ORIGIN_PROVEN) + len(ORIGIN_REFUSED)} proven={proven} refused={refused}')
    return failures


def check_wiring():
    """TIER 5: one deciding site, earlier than every synthetic-source branch, no name tables."""
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        lines = handle.read().splitlines()
    consults = [index + 1 for index, text in enumerate(lines)
                if '_c22_slice_g_proves_safe_sink(' in text]
    definition = [index + 1 for index, text in enumerate(lines)
                  if 'def _c22_slice_g_proves_safe_sink(' in text]
    print(f'  definition={definition} consults={consults}')
    if len(definition) != 1:
        failures.append(('deciding method is not defined exactly once', definition))
        return failures
    call_sites = [number for number in consults if number != definition[0]]
    if len(call_sites) != 1:
        failures.append(('Slice G must be consulted from exactly one place (the unified funnel)',
                         call_sites))
        return failures
    consult = call_sites[0]
    heads = [number for number, text in enumerate(lines, 1)
             if text.strip() == 'for record in self.sink_records:' and number < consult]
    if not heads:
        failures.append(('the consult site is not inside the sink-record cascade', consult))
        return failures
    loop_head = max(heads)
    # The synthetic-source branches each append an edge and `continue` inside this same loop, so a
    # consult line after the first of them would be blind to every record they retire early.
    branches = [number for number, text in enumerate(lines, 1)
                if number > loop_head and text.strip().startswith('if p')
                and '_source_id:' in text]
    print(f'  cascade_loop={loop_head} first_synthetic_branch={min(branches) if branches else None} '
          f'consult={consult}')
    if branches and min(branches) < consult:
        failures.append(('the consult site sits after a synthetic-source short-circuit',
                         (consult, min(branches))))
    body = ast.parse('\n'.join(lines)).body
    method = None
    for top in body:
        if isinstance(top, ast.ClassDef):
            for item in top.body:
                if isinstance(item, ast.FunctionDef) and item.name == '_c22_slice_g_proves_safe_sink':
                    method = item
    if method is None:
        failures.append(('the deciding method is not a TaintTracker method', None))
        return failures
    segment = '\n'.join(lines[method.lineno - 1:method.end_lineno])
    cluster = [item for top in body if isinstance(top, ast.ClassDef) for item in top.body
               if isinstance(item, ast.FunctionDef) and item.name == '_c22_slice_g_proves_safe_sink'
               or isinstance(item, ast.FunctionDef) and item.name.startswith('_c22_slice_g_')
               or isinstance(item, ast.FunctionDef) and item.name == '_c22_enclosing_function']
    print(f'  token-scanned Slice G methods={[item.name for item in cluster]}')
    banned = ('tests/', 'examples/', 'corpus', 'convert_', 'test_', 'fn_lower',
              'file_paths.get', 'location.file')
    for item in cluster:
        head = item.body[0] if item.body else None
        start = item.lineno - 1
        if (isinstance(head, ast.Expr) and isinstance(head.value, ast.Constant)
                and isinstance(head.value.value, str)):
            # Docstring prose is exempt: it names the shapes a rule refuses, honestly, and `convert_*`
            # appears there for the same reason it must never appear in the code. The scan is of the
            # executable lines of every method in the cluster.
            start = head.end_lineno
        segment = '\n'.join(lines[start:item.end_lineno])
        for token in banned:
            if token in segment:
                failures.append(('name/path token inside Slice G code', item.name, token))
    return failures


# --------------------------------------------------------------------------- mutations
# Each entry weakens one clause of the shipped proof, in memory only, and must move a pinned row.

ALL_ROWS = {}
ALL_ROWS.update(EARNED_ROWS)
ALL_ROWS.update(REFUSED_ROWS)
ALL_ROWS.update(PREVIOUSLY_QUIET_ROWS)


def _row_moved(label, line, must_become_quiet):
    """True when THE LINE this clause owns flipped in the direction the weakening would buy.

    Line-scoped rather than file-scoped on purpose: a fixture module carries other CWE-22 rows that
    belong to other clauses (the caller-side row of a helper, for instance), and a whole-file
    "did anything disappear" test would report a passing mutation as decorative. Harness Law 8 asks
    the tripwire to move, so the tripwire is the row the weakened clause actually decides.
    """
    lines = {row_line for row_line, _message in scan_source(ALL_ROWS[label])}
    return (line in lines) != must_become_quiet


def _literal_becomes_any_string(expr):
    return isinstance(expr, ast.Constant) and isinstance(expr.value, str) and bool(expr.value)


def _anchor_literal_accepts_everything(self, expr, allow_literal=False):
    return isinstance(expr, ast.Constant) and isinstance(expr.value, str) and bool(expr.value)


def _callers_accept_no_bindings(self, tree, node, expr, params, mod_name):
    names = [sub.id for sub in ast.walk(expr)
             if isinstance(sub, ast.Name) and sub.id in params]
    if not names:
        return False
    for param in dict.fromkeys(names):
        found = self._c22_bound_values(tree, node, param)
        if not found or not found[1]:
            continue
        if not all(self._c22_value_is_proven_path_origin(tree, cand, mod_name)
                   for cand in found[1]):
            return False
    return True


def _callers_take_any_binding(self, tree, node, expr, params, mod_name):
    names = [sub.id for sub in ast.walk(expr)
             if isinstance(sub, ast.Name) and sub.id in params]
    if not names:
        return False
    for param in dict.fromkeys(names):
        found = self._c22_bound_values(tree, node, param)
        if not found or not found[1]:
            return False
        # `any` instead of `all`: one proven call site buys silence for the whole parameter.
        if not any(self._c22_value_is_proven_path_origin(tree, cand, mod_name)
                   for cand in found[1]):
            return False
    return True


def _chain_right_side_never_checked(self, tree, expr, mod_name, depth=0, seen=None,
                                    allow_literal=False):
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Div, ast.Add, ast.Mod)):
        return _ORIGIN(self, tree, expr.left, mod_name, depth + 1, seen, allow_literal)
    if isinstance(expr, ast.Call) and len(expr.args) > 1:
        return _ORIGIN(self, tree, expr.args[0], mod_name, depth + 1, seen, allow_literal)
    return _ORIGIN(self, tree, expr, mod_name, depth, seen, allow_literal)


def _domain2_clause_removed(self, expr, scope_id, lineno):
    return False


def _facts_blind_tempfile_witness(self, tree):
    called, _witness = _FACTS(self, tree)
    return (called, False)


def _facts_blind_call_sites(self, tree):
    _called, witness = _FACTS(self, tree)
    return (frozenset(), witness)


_ORIGIN = ast_scanner.TaintTracker._c22_value_is_proven_path_origin
_PARAM = ast_scanner.TaintTracker._c22_param_callers_prove_safe
_SELF = ast_scanner.TaintTracker._c22_self_attribute_is_temp_sink
_WHOLE = ast_scanner.TaintTracker._c22_literal_names_whole_location
_ANCHOR = ast_scanner.TaintTracker._c22_anchor_literal_ok
_SLICE = ast_scanner.TaintTracker._c22_slice_g_proves_safe_sink
_FACTS = ast_scanner.TaintTracker._c22_slice_g_module_facts

MUTATIONS = {
    'literal_accepts_relative_path': {
        'what': 'any non-empty string literal names the whole location',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_literal_names_whole_location',
                                 staticmethod(_literal_becomes_any_string)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_literal_names_whole_location',
                                   _WHOLE),
        'moves': [('caller_passes_relative_literal', 2, True)],
    },
    'anchor_literal_ignores_dotdot': {
        'what': 'the `..` veto is dropped from a literal segment inside a proven root',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_anchor_literal_ok',
                                 _anchor_literal_accepts_everything),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_anchor_literal_ok', _ANCHOR),
        'moves': [('temp_root_with_an_escape_segment', 3, True), ('self_field_escape_segment', 7, True)],
    },
    'callers_accept_no_bindings': {
        'what': 'a parameter with no in-file binding counts as proven (absence, not proof)',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_param_callers_prove_safe',
                                 _callers_accept_no_bindings),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_param_callers_prove_safe',
                                   _PARAM),
        'moves': [('unpassed_param_inside_a_proven_root', 3, True)],
    },
    'callers_accept_any_binding': {
        'what': 'one proven call site buys silence for a parameter another site taints',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_param_callers_prove_safe',
                                 _callers_take_any_binding),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_param_callers_prove_safe',
                                   _PARAM),
        'moves': [('one_site_proven_one_site_unbound', 3, True)],
    },
    'domain2_clause_removed': {
        'what': 'the self-attribute temp-root proof always answers False',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_self_attribute_is_temp_sink',
                                 _domain2_clause_removed),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_self_attribute_is_temp_sink',
                                   _SELF),
        'moves': [('self_field_joined_onto_temp_root_in_setup', 7, False)],
    },
    'module_tempfile_witness_blind': {
        'what': 'the per-module `tempfile` presence fact is forced False, blinding domain 2',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_slice_g_module_facts',
                                 _facts_blind_tempfile_witness),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_slice_g_module_facts', _FACTS),
        'moves': [('self_field_joined_onto_temp_root_in_setup', 7, False),
                  ('self_field_paired_with_a_literal_segment', 6, False)],
    },
    'module_call_sites_blind': {
        'what': 'the per-module bare call-site index is forced empty, so domain 1 refuses everything',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_slice_g_module_facts',
                                 _facts_blind_call_sites),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_slice_g_module_facts', _FACTS),
        'moves': [('caller_param_gets_tempfile_join', 3, False)],
    },
    'deciding_site_never_prunes': {
        'what': 'the funnel is asked but its answer is discarded',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_slice_g_proves_safe_sink',
                                 lambda self, record, target_expr: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_slice_g_proves_safe_sink',
                                   _SLICE),
        'moves': [('caller_param_gets_tempfile_join', 3, False),
                  ('self_field_paired_with_a_literal_segment', 6, False)],
    },
    'chain_right_side_never_checked': {
        'what': 'only the first component of a join or operator chain is proved',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_value_is_proven_path_origin',
                                 _chain_right_side_never_checked),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_value_is_proven_path_origin',
                                   _ORIGIN),
        'moves': [('proven_root_with_unproven_segment', 3, True),
                  ('temp_root_with_an_escape_segment', 3, True)],
    },
}


def run_mutation(name):
    """Apply one in-memory weakening and check that the rows it should break actually move."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print('  rows that must move: '
          + ', '.join(f'{label}:{line}' for label, line, _ in spec['moves']))
    try:
        spec['apply']()
        outcomes = [(f'{label}:{line}', _row_moved(label, line, expected))
                    for label, line, expected in spec['moves']]
    except Exception as exc:
        print('MUTATION ERROR: ' + type(exc).__name__ + ': ' + str(exc))
        print(f'\nFALSIFICATION VERDICT ({name}): ERROR - the mutation is broken, '
              'so it proves nothing either way (exit 2, not a pass)')
        return 2
    finally:
        spec['restore']()
    moved = [label for label, did_move in outcomes if did_move]
    for label, did_move in outcomes:
        print(f"  {label:42s} {'MOVED' if did_move else 'unchanged'}")
    caught = len(moved) == len(outcomes)
    print('FALSIFICATION VERDICT (' + name + '): '
          + (f'CAUGHT on all {len(moved)} pinned row(s)' if caught else
             'MISSED - this clause is decorative; the row it guards did not move'))
    return 1 if caught else 0


def main() -> int:
    print('TIER 1 - blessed CWE-22 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the 24 blessed lines, asked about directly:')
    failures += check_blessed_reach()
    print('TIER 3 - findings truth table:')
    failures += check_shapes()
    print('TIER 4 - the value-level origin proof, expression by expression:')
    failures += check_origins()
    print('TIER 5 - one deciding site, earlier than every synthetic-source branch:')
    failures += check_wiring()
    for item in failures[:12]:
        print(f'  !! {item}')
    print(f'\nfixtures={len(EARNED_ROWS) + len(REFUSED_ROWS) + len(PREVIOUSLY_QUIET_ROWS)} '
          f'earned={len(EARNED_ROWS)} refused={len(REFUSED_ROWS)} '
          f'already_quiet_not_claimed={len(PREVIOUSLY_QUIET_ROWS)} '
          f'origins={len(ORIGIN_PROVEN) + len(ORIGIN_REFUSED)} '
          f'locked_cwe22={sum(CWE22_LOCKED.values())} failures={len(failures)}')
    if failures:
        print('VERDICT: FAIL - Slice G no longer matches its measured evidence. Either a blessed '
              'CWE-22 key was answered SAFE, an earned shape stopped being retired, a refused shape '
              '(relative literal, `..` segment, splat, unbound name, unproven second write, foreign '
              'join receiver, unwritten self field) bought silence, or an inherited row was booked as '
              'a win. Restore the answer; never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - 0 of {sum(CWE22_LOCKED.values())} blessed CWE-22 keys answered SAFE, '
          f'{len(EARNED_ROWS)} shapes retired by this rule alone, '
          f'{len(REFUSED_ROWS)} refused shapes still loud, '
          f'{len(PREVIOUSLY_QUIET_ROWS)} inherited rows not claimed, '
          f'{len(ORIGIN_REFUSED)} origin refusals held, one deciding site confirmed.')
    return 0


if __name__ == '__main__':
    wanted = [arg.split('=', 1)[1] for arg in sys.argv[1:] if arg.startswith('--mutate=')]
    if wanted:
        unknown = [name for name in wanted if name not in MUTATIONS]
        if unknown:
            print(f'BAD MUTATION: {unknown} is not one of {sorted(MUTATIONS)}')
            sys.exit(1)
        sys.exit(run_mutation(wanted[0]))
    sys.exit(main())
