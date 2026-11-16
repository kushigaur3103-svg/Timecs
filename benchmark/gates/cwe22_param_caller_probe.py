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

What the owed rule now decides on top of Slice G
------------------------------------------------
Slice G answers one question -- *is this path proven safe?* -- and this file used to treat the answer
`no` as a finding. `TaintTracker._c22_open_sink_owes_proven_taint` (ast_scanner.py:8707) answers a
different question about the same record -- *has anybody actually shown that an untrusted value reaches
this argument?* -- and since this round it is asked of every CWE-22 filesystem sink the funnel reaches,
not only of `open()` in a module that declares an entrypoint. When it answers True, the phase-11
registry sink, the phase-5 and phase-4 short-circuits and the subtract-only `ProvenanceState.UNKNOWN`
prune arm all decline to emit. The sentence the mandate retired is the one this file was built on:
"refused to certify" never meant "untrusted", and a package's own code is not a finding just because the
engine could not prove the variable holding its path was chosen by somebody safe.

Fifteen rows went quiet, and the attribution is measured three times rather than assumed. First through
the sanctioned harness: `scratch/_c22_r3_engines.py --diff` (HEAD's snapshot
`scratch/_c22_r2_head_ast_scanner.py` and the live engine, in separate processes, because one process
would let the first arm's import tables answer for the second) is run over every fixture in this file by
`scratch/_c22_r3_paramcaller_engines_diff.py`, and twelve of the fifteen print `head-only
(SUPERSUCCEEDED by this round)` with no `live-only` row anywhere. The other three print "quiet under both
arms" there and are not: the harness builds `TaintTracker(files=..., max_workers=1)` while this file and
both frozen baselines build `TaintTracker(files=..., audit_all=True)`, and
`scratch/_c22_r3_paramcaller_gatedriver.py` -- plus the `--audit` mode of the script above -- runs the
same two engines under *both* drivers side by side. Under the driver this gate actually uses, all three
(`no_call_site_in_file`, `caller_splats_keyword`, `self_field_is_request_upload`) are loud at HEAD and
quiet now, so they are supersessions too, and the disagreement is printed rather than hidden. Third,
`scratch/_c22_r3_paramcaller_owes_probe.py` re-scans the live engine with the owed rule pinned to False,
i.e. with the retired fallback restored and Slice G's answer once again the only thing that can prune a
row. For all fifteen, HEAD's line set and the pinned-False line set agree to the line -- the exact
tuples TIER 3 asserts -- so none of them is a row some earlier clause had already retired, which is
what the same columns show for the 11 `PREVIOUSLY_QUIET_ROWS` and the 3 `EARNED_ROWS`: empty at HEAD,
empty now, empty with the fallback pinned back on, and therefore claiming nothing this round.

Twelve of the fifteen are re-filed, because their proposition *is* the retired equation: the value the
funnel refused to certify is a bare name, a splat, an unimported resolver, an unpassed parameter or a
temp root with no operator in it, and the mandate says a library row like that is silence, not a
finding. `parity benchmark/corpus/cwe_937_insecure_protocol/test_v06_bad.py:6` is the proof that the
re-filing is the intended reading and not a convenient one: `caller_passes_relative_literal` is that
blessed key's own shape, and the shipped table `CWE22_OPEN_TAINT_KEEP_LOUD` keeps it with the comment
"the bless, not the dataflow, is what keeps the row". `no_call_site_in_file` is the same admission for
the two `modeling_utils.py` keys. One row is earned back instead: an unimported `hf_hub_download` is
still no witnessed root, but `hub_resolver_without_import_witness` now hands that resolver a filename
read from `os.environ`, which is the mandate's condition (a) in plain words, so the sink reports (lines 3
and 5) while the funnel still refuses (asked 2, hits 0). Round 5 moved that carrier off `sys.argv` for the
same reason it moved the rule: a standalone script's own command line is the process owner's invocation,
so an argv-fed sink there is retired, while an environment read stays an untrusted root.

Two rows are neither, and this file refuses to book them. `self_field_holds_parsed_command_line` writes
`self.args = argparse.ArgumentParser().parse_args()` and then opens `self.args.csv_file`;
`self_field_is_request_upload` writes `self.csv_file = request.files["f"].filename` and then opens
`self.csv_file`. Both fields *are* written from a recognised root, which is the mandate's condition (b)
in plain words, so their silence is not the mandate's answer.
`scratch/_c22_r3_paramcaller_fn_predicate.py` asks the shipped predicate the questions that separate a
blind walk from an absent root, and both rows answer False on the sink argument, True on the write's
right-hand side, and True on the identical root travelling through a local name instead of an attribute;
the walk grid in `scratch/_c22_walk_resolution_grid.py` records the same split for
`obj.path = sys.argv[1]` then `open(obj.path)`. The engine knows the root and knows the hop; it loses
the thread at the attribute. TIER 6 pins that asymmetry, books the pair as a candidate false negative
rather than as a reduction in findings, and fails the moment the walk learns to follow the hop -- the
point at which they must be re-filed into the loud table, not silently re-counted.

Everything that moved is still asked. The census in `observe_asks` is taken at the funnel and does not
care whether the row is emitted, so each re-filed row still proves the clause that refused to certify it
(`asked >= 1`, `hits == 0`), and each still proves, with the fallback pinned back on, that the silence
came from the owed rule and from nothing else.

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

Domain 1 is a **positive** proof about values, and it fails closed in six distinct ways. The rows below
are the ones that still arrive as findings, each because a resolved origin really does reach the sink:

  * any binding that is not proven -> refused, because the answer is the conjunction over **every**
    value the name can hold, and it stays loud while it does (`one_caller_passes_request`,
    `parameter_rebound_locally`);
  * a tainted segment inside a proven root -> refused and loud (`join_carries_a_tainted_segment`), and a
    join whose receiver is a foreign object is refused and loud for the same reason
    (`caller_passes_foreign_receiver_join`);
  * a path argument the operator chose -> refused and loud, which is what
    `hub_resolver_without_import_witness` now spells: the resolver is still unimported, so the witnessed
    root the clause wants is still missing, and `os.environ` is still what makes the row a finding;
  * a `request` write into a `self` field that the sink reads in the same frame -> refused and loud
    (`self_field_second_write_from_request`), and a `with open(request.args[...])` that is not a helper
    call at all -> refused and loud (`tainted_open_is_not_a_helper_call`).

The other refusals that moved -- no call site in the file, a `*args`/`**kwargs` splat at any site, a
literal that is not a whole location, an unbound name, a parameter no call site ever supplies, a segment
a proven root does not cover, a `..` inside a root that does, a loop target and an unwritten field -- are
all still refused by the funnel, and all of them used to be *reported* because nothing proved them safe.
Under the owed rule they are silent, because none of them contains a resolved origin anywhere, and that
is the mandate's answer rather than this file's: `caller_passes_relative_literal` is the blessed parity
key's own shape, `no_call_site_in_file` is the blessed `modeling_utils.py` shape, and the shipped tables
`CWE22_OPEN_TAINT_KEEP_LOUD` and `CWE22_ENTRYPOINT_KEEP_LOUD` are what keep the real keys loud.
Those twelve rows live in `SILENT_REFUSED_ROWS`, are asserted with the census they were asserted with
before, and are booked as a win with the fallback pinned back on: `no_call_site_in_file` asked=1 hits=0
with the sink silent, and reported at line 2 the moment the requirement is withdrawn. Their sources are
the ones this file used to shout about, byte for byte -- `scratch/_c22_r3_paramcaller_seal_check.py`
loads HEAD's copy of the gate and this one together and fails on any fixture that vanished, any `moves`
pin that moved, any floor that lowered, and any source that changed except the one declared re-spelling.

Domain 2 reuses the teardown proof the engine already ships (`_c22_path_is_proven_temp_root`) and adds
only a `self`/`cls` gate in front of it, asked at the read instead of only at the delete. It takes
*every* write the field has, so a second write from `request` voids it
(`self_field_second_write_from_request`, still loud) and an unwritten field voids it
(`self_field_never_written`, now silent at line 3 under the blanket arm and booked as a win: a field
nobody ever writes is the mandate's "unproven bare attribute" with no argument to make). The two rows
whose fields *are* written from a recognised root are in `ATTR_HOP_BLIND_ROWS` and are not booked at all.

One deciding site
-----------------
The measured reason the first wiring shipped nothing: CWE-22 `open()` rows arrive through three
different registrants, and two of them -- the Phase-5 synthetic-source branches -- append an edge and
`continue` **before** the exemption disjunction, while the parameter collector retires rows even
earlier. So a proof placed in the disjunction, or in the collector, is blind to the rows it was written
for. Rung 4 of the ladder says unify the funnel: `_c22_slice_g_proves_safe_sink`
(ast_scanner.py:9648) is consulted **once**, at the head of the graph-evaluation cascade, before any
synthetic-source branch, and TIER 5 asserts both halves of that -- exactly one consult site in the
engine (line 29825), and a strictly earlier line than every `p3_source_id` / `p4_source_id` /
`p5_source_id` short-circuit. The owed rule is consulted from one place too, two statements later at
ast_scanner.py:29850, and its answer is read by four emitters -- the phase-11 registry sink at 29856,
the phase-5 short-circuit at 29922, the phase-4 short-circuit at 29997 and the UNKNOWN prune arm at
30130 -- which is why a row can now be refused by the funnel and still be silent, and why the tripwires
below had to move.

Usage
-----
    python benchmark/gates/cwe22_param_caller_probe.py
    python benchmark/gates/cwe22_param_caller_probe.py --mutate=<name>

Nine weakenings are pinned below, each one clause of the shipped proof or one of its two presence
facts, and each must move the row that clause decides -- measured 9/9 CAUGHT at exit 1, per Harness
Law 8. The tripwires are line-scoped:
a fixture module carries other CWE-22 rows that belong to other clauses, and a whole-file "did anything
disappear" test reports a working mutation as decorative (it did, twice, before the line was pinned).
They are also, since this round, evaluated with the retired fallback pinned back on
(`retired_blanket_restored`), and that is not a shortcut -- it is the only world in which they can still
be honest. Four of the nine (`domain2_clause_removed`, `module_tempfile_witness_blind`,
`module_call_sites_blind`, `deciding_site_never_prunes`) are pinned to `EARNED_ROWS`, whose rows are now
silent twice over: Slice G retires them and the owed rule would have retired them anyway, so a
weakening of the clause buys no *new* silence and the shipped arm reads them as decorative. Five more
(`literal_accepts_relative_path`, `anchor_literal_ignores_dotdot`, `callers_accept_no_bindings`,
`callers_accept_any_binding`, `chain_right_side_never_checked`) are pinned to rows that are already
silent, so on the shipped arm they read CAUGHT for the worst possible reason -- the line was missing
before the mutation ran and is missing after it. With the fallback restored, Slice G's answer is again
the only thing that can prune the row, every one of these nine flips for the reason its clause decides,
and the same arm is the one that books the twelve re-filed rows as a win.
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
BASELINE_TOTALS = {'parity': 424, 'big8': 119}


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


# --------------------------------------------------------------------------- the retired blanket, on tap
OWED = ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint


@contextlib.contextmanager
def retired_blanket_restored():
    """Run the shipped engine with this round's requirement withdrawn, i.e. in HEAD's world.

    `_c22_open_sink_owes_proven_taint` (ast_scanner.py:8707) pinned to False is exactly the retired
    policy: the phase-11 registry sink, the phase-5 and phase-4 short-circuits and the subtract-only
    `ProvenanceState.UNKNOWN` arm all emit again on the bare "the funnel refused to certify this"
    fallback, and Slice G's answer is once more the only thing in the engine that can prune a row. Two
    jobs for one arm. First, it books the win honestly: a re-filed row that is silent now and loud here
    is silent BECAUSE of the owed rule and not because of some clause this file happens to like -- the
    attribution `scratch/_c22_r3_paramcaller_owes_probe.py` measured, asserted per fixture in TIER 3.
    Second, it makes the tripwires observable again: on the shipped arm a weakening of a Slice G clause
    that guards an already-silent row buys nothing new and reads decorative, while in this world the
    clause is the last thing standing between the row and the record. Mutation results are measured
    here, which is the only way all nine keep meaning what Harness Law 8 asks them to mean.
    """
    ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = (
        lambda self, record, sink: False)
    try:
        yield
    finally:
        ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = OWED


def row_lines(rows):
    """The sorted line numbers of a `scan_source` result; message text is not evidence."""
    return sorted({line for line, _message in rows})


def blanket_rows(source, module='m.py'):
    """The CWE-22 lines one fixture reported with the retired generic fallback still in force."""
    with retired_blanket_restored():
        return row_lines(scan_source(source, module))


def walk_reaches(source, sink_arg, write_target=None, module='m.py'):
    """Ask the shipped reachability walk about a fixture's sink argument, and about the value written.

    Everything is read off the tree the engine itself analysed, with the engine's own assignment map,
    operator facts and command-parameter table (`_memo_assignment_map`, `_c22_operator_facts_on`,
    `_c22_cli_command_params`) and the enclosing-def name the walk wants as its owner, so the answer is
    the shipped one and not a re-derivation -- the mistake the census used to make, see the harness-laws
    paragraph of this file's docstring. Returns ``(sink, write)``, either `None` when the fixture has no
    such expression, because a gate may not assert against an expression it failed to find.
    """
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
        tracker.analyze()
    tree = tracker.modules.get(os.path.splitext(module)[0])
    if tree is None:
        candidates = [value for value in tracker.modules.values() if value is not None]
        tree = candidates[0] if candidates else None
    if tree is None:
        return (None, None)
    table = tracker._memo_assignment_map(tree)
    _guarded, argparse_names = tracker._c22_operator_facts_on(tree)
    command_params = tracker._c22_cli_command_params(tree)
    open_args, assigned = {}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'open':
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                if arg is not None:
                    open_args.setdefault(ast.unparse(arg), arg)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                assigned[ast.unparse(target)] = node.value

    def ask(expr):
        if expr is None:
            return None
        owner = tracker._c22_enclosing_def_name(tree, getattr(expr, 'lineno', 0))
        return bool(tracker._c22_value_reaches_operator(tree, table, expr, argparse_names,
                                                        command_params, owner))

    return (ask(open_args.get(sink_arg)),
            ask(assigned.get(write_target)) if write_target is not None else None)


# --------------------------------------------------------------------------- fixtures
# Built by explicit concatenation, one source line per term, per the harness laws.
#
# The tables below are separated by MEASUREMENT, not by intention. `scratch/_G_seal_compare.py` ran
# every one of these fixtures against `git show HEAD:ast_scanner.py` and against the working copy, and
# 12 of the shapes the mandate calls Slice G's were already quiet at HEAD -- retired by the cascade's
# `_is_self_described`, by `_c22_path_is_internal_repo_anchor`, or by the legacy name/path shield
# `_c22_is_test_suite_or_cached_path`. A gate that booked those as wins would be advertising coverage it
# did not add, so they sit in `PREVIOUSLY_QUIET_ROWS` and are asserted with `hits == 0`: quiet, and NOT
# because of this rule. This round moved a second population, and it is measured the same way --
# `scratch/_c22_r3_paramcaller_gatedriver.py` for HEAD versus live under both drivers, and
# `scratch/_c22_r3_paramcaller_owes_probe.py` for live with the owed rule pinned to each answer. Those
# two columns are what separate `SILENT_REFUSED_ROWS` (refused and retired, and the retirement is this
# round's) from `ATTR_HOP_BLIND_ROWS` (refused and retired, and the retirement is a bug).

HELP = (
    'def read_sidecar(sidecar_path):\n'
    + '    with open(sidecar_path, "rb") as handle:\n'
    + '        return handle.read()\n')

# The open() taint requirement (`cwe22_open_taint_probe`) retired an unproven `open()` in a module that
# declared no entrypoint, so a refused carrier used to append an argv read simply to keep the row alive
# for the gate to be able to refuse it. The generalised requirement takes that service away: an argv
# read that never reaches the sink argument keeps nothing loud now, and the rows whose carrier is this
# one are re-filed in `SILENT_REFUSED_ROWS` with the fallback arm doing the work the read used to do.
# Appended, never prepended: no sink line moves, and the caller-closure proof is still the only thing
# that can answer SAFE.
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

# Rows the funnel refuses AND the engine still reports, because a resolved operator/remote origin really
# does reach the sink argument. Loud at HEAD, loud now, `asked > 0` and `hits == 0` on every one: the
# clause still refuses to certify them, and the owed rule is the thing that keeps them on the record.
# `hub_resolver_without_import_witness` is the one re-filed row this round EARNED back: an unimported
# `hf_hub_download` is still no witnessed root -- the resolver filename now comes out of `os.environ`,
# which is the mandate's condition (a) spelled literally, so the sink reports at 3 and 5 while the
# funnel still refuses (asked 2, hits 0). Round 5 moved that carrier off `sys.argv`: a standalone
# script's own command line is the process owner's invocation, so the demotion retires an argv-fed
# sink there, while an environment read stays an untrusted root. The proposition is the missing
# import witness, not the spelling of the root, so it survives the move unchanged.
REFUSED_ROWS = {
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
    'hub_resolver_without_import_witness': (
        'import os, sys\n' + HELP
        + 'read_sidecar(hf_hub_download("org/model", os.environ["SIDECAR"]))\n'),
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
}

# The twelve refusals this round retired, measured rather than asserted: `asked` unchanged, `hits` still
# 0, the sink now silent, and exactly the line set the pinned-False arm prints
# (`scratch/_c22_r3_paramcaller_owes_probe.py`, and `scratch/_c22_r3_paramcaller_gatedriver.py` for the
# same lines under HEAD). Their proposition IS the retired equation "not certified, therefore reported":
# a bare name, a splat, a module with no call site, a relative literal, an unpassed parameter, a segment
# a proven root does not cover, a `..` inside one that does, a loop target and an unwritten field. None of
# them contains a resolved origin anywhere, so under the mandate they are silence, not findings. The
# blanketed line tuple is the booked win: withdraw the requirement and the row comes back at that line.
# Sources are byte-identical to the versions this file used to assert loudly, `ENTRY` carriers included.
SILENT_REFUSED_ROWS = {
    # A `request` name anywhere in the module poisons the binding table itself, so every refusal that
    # needs to isolate ONE clause of the origin proof is written without it -- these two shapes are
    # decided by the shipped clauses, not by the module-level poison.
    'no_call_site_in_file': (HELP + ENTRY, (2,)),
    'caller_passes_unbound_name': (HELP + 'read_sidecar(external_path)\n', (2, 4)),
    'caller_splats_positional': (
        'def read_pair(sidecar_path, other_path):\n'
        + '    with open(sidecar_path, "rb") as handle:\n'
        + '        return handle.read()\n'
        + 'values = ("/opt/a.bin", "/opt/b.bin")\n'
        + 'read_pair(*values)\n', (2, 5)),
    'caller_splats_keyword': (
        HELP + 'options = {"sidecar_path": "/opt/a.bin"}\n' + 'read_sidecar(**options)\n', (2,)),
    'caller_passes_relative_literal': (
        'def download_file(server, filename):\n'
        + '    with open(filename, "wb") as handle:\n'
        + '        handle.write("x")\n'
        + 'download_file("ftp.example.org", "release.txt")\n', (2,)),
    'temp_root_with_an_escape_segment': (
        'import os, tempfile\n'
        + 'def write_state(state_path):\n'
        + '    with open(state_path, "w") as handle:\n'
        + '        handle.write("x")\n'
        + 'write_state(os.path.join(tempfile.mkdtemp(), "..", "escape.txt"))\n', (3,)),
    'one_site_proven_one_site_unbound': (
        'import os, tempfile\n'
        + 'def write_state(state_path):\n'
        + '    with open(state_path, "w") as handle:\n'
        + '        handle.write("x")\n'
        + 'write_state(os.path.join(tempfile.mkdtemp(), "state.json"))\n'
        + 'write_state(sidecar_argument_name)\n', (3, 6)),
    'proven_root_with_unproven_segment': (
        'import os, tempfile\n'
        + 'def write_state(state_path):\n'
        + '    with open(state_path, "w") as handle:\n'
        + '        handle.write("x")\n'
        + 'write_state(os.path.join(tempfile.mkdtemp(), sidecar_argument_name))\n', (3, 5)),
    # The helper IS called in the file, so the cheap call-site index lets the question through, and the
    # answer comes back from the parameter level: `mode` is in the path and no call site ever supplies it.
    # Absence of a value is not proof of one, and this is the row that pinned the difference; now the
    # absence is also proof of nothing dangerous, so the row is silent and the clause is still asked.
    'unpassed_param_inside_a_proven_root': (
        'import os, tempfile\n'
        + 'def read_state(state_path, mode):\n'
        + '    with open(os.path.join(state_path, mode)) as handle:\n'
        + '        return handle.read()\n'
        + 'read_state(tempfile.mkdtemp())\n', (3,)),
    'self_field_never_written': (
        'class Reader:\n'
        + '    def read(self):\n'
        + '        with open(self.vocab_file) as handle:\n'
        + '            return handle.read()\n'
        + ENTRY, (3,)),
    'self_field_from_loop': (
        'class Reader:\n'
        + '    def run(self, candidates):\n'
        + '        for self.csv_file in candidates:\n'
        + '            pass\n'
        + '    def read(self):\n'
        + '        with open(self.csv_file) as handle:\n'
        + '            return handle.read()\n'
        + ENTRY, (6,)),
    'self_field_escape_segment': (
        'import os, tempfile\n'
        + 'class Reader:\n'
        + '    def setUp(self):\n'
        + '        self.tmpdirname = tempfile.mkdtemp()\n'
        + '        self.reader_config_file = os.path.join(self.tmpdirname, "..", "escape.json")\n'
        + '    def write(self):\n'
        + '        with open(self.reader_config_file, "w") as fp:\n'
        + '            fp.write("{}")\n'
        + ENTRY, (7,)),
}

# The two refusals this round silenced that the mandate does NOT license: the field is written from a
# recognised root (`parse_args()` namespace, `request.files[...].filename`), which is condition (b) --
# "a tainted parameter within the caller chain" -- in plain words. They are not booked as wins and not
# re-spelled away. TIER 6 pins them as a candidate engine false negative: the walk answers True on the
# write's right-hand side and False on the very same value one attribute-hop later, while the identical
# root travelling through a LOCAL name answers True at its sink. A fixture per bucket, source unchanged.
ATTR_HOP_BLIND_ROWS = {
    # label: (source, silent sink line, sink argument, the write whose value carries the root)
    'self_field_holds_parsed_command_line': (
        'import argparse\n'
        + 'class Runner:\n'
        + '    def __init__(self):\n'
        + '        self.args = argparse.ArgumentParser().parse_args()\n'
        + '    def read(self):\n'
        + '        with open(self.args.csv_file) as handle:\n'
        + '            return handle.read()\n', 6, 'self.args.csv_file', 'self.args'),
    'self_field_is_request_upload': (
        'class Reader:\n'
        + '    def load(self, request):\n'
        + '        self.csv_file = request.files["f"].filename\n'
        + '    def read(self):\n'
        + '        with open(self.csv_file) as handle:\n'
        + '            return handle.read()\n', 5, 'self.csv_file', 'self.csv_file'),
}

# The same two roots one hop shorter, through a local written and read in the same frame: the walk does
# resolve these at the sink argument, which is the evidence that the pair above is a blind attribute hop
# and not an unrecognised root. `scratch/_c22_r3_paramcaller_fn_predicate.py` and
# `scratch/_c22_walk_resolution_grid.py` measured the split; TIER 6 re-measures it here.
ATTR_HOP_CONTROLS = {
    'parsed_command_line_in_local': (
        'import argparse\n'
        + 'def read():\n'
        + '    options = argparse.ArgumentParser().parse_args()\n'
        + '    where = options.csv_file\n'
        + '    with open(where) as handle:\n'
        + '        return handle.read()\n', 'where'),
    'request_upload_in_local': (
        'def read(request):\n'
        + '    where = request.files["f"].filename\n'
        + '    with open(where) as handle:\n'
        + '        return handle.read()\n', 'where'),
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

# Every fixture, counted once, in whichever bucket its MEASUREMENT put it. The number is 35 before and
# after this round's re-filing: nothing was deleted, four buckets now say what the four mechanisms are.
FIXTURE_TABLES = (EARNED_ROWS, REFUSED_ROWS, SILENT_REFUSED_ROWS, ATTR_HOP_BLIND_ROWS,
                  PREVIOUSLY_QUIET_ROWS)


def fixture_count():
    return sum(len(table) for table in FIXTURE_TABLES)


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
    silent = 0
    for label, (source, booked) in sorted(SILENT_REFUSED_ROWS.items()):
        rows, (asked, hits) = scan_source(source), slice_g_hits(source)
        loud = blanket_rows(source)
        print(f'  re-filed {label:36s} asked={asked} hits={hits} live={row_lines(rows)} '
              f'blanket={loud}')
        if rows:
            # The sink has acquired a resolved origin in its own arguments. That is a finding, so the row
            # belongs back in `REFUSED_ROWS` -- it must not be quietly dropped from this table.
            failures.append(('re-filed', label, 'reported again; move it to REFUSED_ROWS', rows[:2]))
        elif hits:
            # Then the silence is Slice G's, not the owed rule's, and the row is an earned retirement.
            failures.append(('re-filed', label, 'quiet because Slice G answered SAFE; re-book it in '
                             'EARNED_ROWS instead of claiming the fallback', hits))
        elif asked < 1:
            failures.append(('re-filed', label, 'the funnel was never asked about it', asked))
        elif loud != sorted(booked):
            failures.append(('re-filed', label, 'the withdrawn requirement does not bring the booked '
                             'line set back; the silence is not this rule\'s', sorted(booked), loud))
        else:
            silent += 1
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
    print(f'  fixtures={fixture_count()} '
          f'earned={earned} refused={refused} refiled_silent={silent} '
          f'attr_hop_blind={len(ATTR_HOP_BLIND_ROWS)} already_quiet_not_claimed={inherited} '
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


def check_attr_hop_blind():
    """TIER 6: the two fields written from a recognised root that went quiet anyway -- booked as a bug.

    The mandate's condition (b) is "a tainted parameter within the caller chain", and `self.args` set
    from `parse_args()` and `self.csv_file` set from `request.files[...].filename` both satisfy it
    literally. Their silence is therefore not the mandate's answer and this file declines to count it as
    a reduction in findings. What TIER 6 pins is the asymmetry that makes it a blind hop rather than an
    absent root, measured by the shipped walk on the shipped tree:

      * the sink argument, reached through the attribute, answers False;
      * the value WRITTEN into that attribute, in the same file, answers True -- the root is recognised;
      * the same root travelling one hop shorter, into a local name read in the same frame, answers True
        at ITS sink argument, so the walk does follow a hop and does not do it across an attribute;
      * the pinned-False arm still reports the sink at the booked line, so the row is this round's loss
        and not something an earlier clause had already retired.

    Every one of those four is a re-filing instruction in the other direction if it changes: loud at the
    sink means the pair belongs in `REFUSED_ROWS`, quiet in the blanket arm means it belongs in
    `SILENT_REFUSED_ROWS`, and a write that no longer resolves means the silence was the mandate's after
    all. None of the four lets the row be re-counted as a win without moving tables.
    """
    failures = []
    for label, (source, sink_line, sink_arg, write_target) in sorted(ATTR_HOP_BLIND_ROWS.items()):
        rows, (asked, hits) = scan_source(source), slice_g_hits(source)
        lines, booked = row_lines(rows), blanket_rows(source)
        sink_reach, write_reach = walk_reaches(source, sink_arg, write_target)
        print(f'  {label:36s} asked={asked} hits={hits} live={lines} blanket={booked} '
              f'walk(sink `{sink_arg}`)={sink_reach} walk(write of `{write_target}`)={write_reach}')
        if sink_line in lines:
            failures.append((label, 'the walk now follows the attribute hop; this is a finding, '
                             're-file it into REFUSED_ROWS', lines))
        elif booked != [sink_line]:
            failures.append((label, 'the pinned-False arm is not loud at the booked line either, so '
                             'this silence predates the round and belongs in SILENT_REFUSED_ROWS',
                             booked))
        elif hits:
            failures.append((label, 'Slice G answered SAFE here; a booked win, not a false negative',
                             hits))
        elif asked < 1:
            failures.append((label, 'the funnel was never asked about it', asked))
        if sink_reach is not False:
            failures.append((label, 'the sink argument now resolves on its own; re-measure this tier',
                             sink_reach))
        if write_reach is not True:
            failures.append((label, 'the write stopped carrying a recognised root, so the mandate '
                             'does license the silence; re-file into SILENT_REFUSED_ROWS',
                             write_reach))
    for label, (source, sink_arg) in sorted(ATTR_HOP_CONTROLS.items()):
        control_reach, _unused = walk_reaches(source, sink_arg)
        print(f'  control {label:29s} walk(sink `{sink_arg}`)={control_reach} '
              f'live={row_lines(scan_source(source))}')
        if control_reach is not True:
            failures.append((label, 'the local-hop control no longer resolves, so the attribute pair is '
                             'not a blind hop and the FN claim is void', control_reach))
    return failures


# --------------------------------------------------------------------------- mutations
# Each entry weakens one clause of the shipped proof, in memory only, and must move a pinned row.

ALL_ROWS = {}
ALL_ROWS.update(EARNED_ROWS)
ALL_ROWS.update(REFUSED_ROWS)
ALL_ROWS.update({label: source for label, (source, *_booked) in SILENT_REFUSED_ROWS.items()})
ALL_ROWS.update({label: source for label, (source, *_rest) in ATTR_HOP_BLIND_ROWS.items()})
ALL_ROWS.update(PREVIOUSLY_QUIET_ROWS)


def _row_moved(label, line, must_become_quiet):
    """True when THE LINE this clause owns flipped in the direction the weakening would buy.

    Line-scoped rather than file-scoped on purpose: a fixture module carries other CWE-22 rows that
    belong to other clauses (the caller-side row of a helper, for instance), and a whole-file
    "did anything disappear" test would report a passing mutation as decorative. Harness Law 8 asks
    the tripwire to move, so the tripwire is the row the weakened clause actually decides.

    Measured with the retired generic fallback restored, and that is load-bearing rather than
    convenient. On the shipped arm four of the nine pins sit on `EARNED_ROWS` lines that are silent
    twice over -- Slice G retires them and, once Slice G is weakened, the owed rule would retire them
    again for want of a resolved origin -- so the weakening buys no NEW silence and the tripwire reads
    decorative; five more sit on lines this round already retired, so they read CAUGHT for the worst
    possible reason, missing before the mutation and missing after it. In the blanket world Slice G's
    answer is the only thing that can prune a row, so each of the nine flips for exactly the clause it
    is pinned to, and the nine `moves` tuples below keep their original line numbers unchanged.
    """
    lines = set(blanket_rows(ALL_ROWS[label]))
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
    print('  arm: the generic fallback is restored (`_c22_open_sink_owes_proven_taint` pinned False), '
          'so Slice G\'s clause is the last thing that can prune the row')
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
    print('TIER 6 - the two root-written self fields: booked as a candidate engine false negative:')
    failures += check_attr_hop_blind()
    for item in failures[:24]:
        print(f'  !! {item}')
    print(f'\nfixtures={fixture_count()} '
          f'earned={len(EARNED_ROWS)} refused={len(REFUSED_ROWS)} '
          f'refiled_silent={len(SILENT_REFUSED_ROWS)} '
          f'attr_hop_not_booked={len(ATTR_HOP_BLIND_ROWS)} '
          f'already_quiet_not_claimed={len(PREVIOUSLY_QUIET_ROWS)} '
          f'origins={len(ORIGIN_PROVEN) + len(ORIGIN_REFUSED)} '
          f'locked_cwe22={sum(CWE22_LOCKED.values())} failures={len(failures)}')
    if failures:
        print('VERDICT: FAIL - Slice G and the owed rule no longer match their measured evidence. '
              'Either a blessed CWE-22 key was answered SAFE, an earned shape stopped being retired, a '
              'refused shape (tainted second write, `..` segment inside a proven root, splat, unbound '
              'name, foreign join receiver, argv-chosen hub filename) bought silence, a re-filed row '
              'came back or lost its blanket-arm lines, an inherited row was booked as a win, or the '
              'attribute-hop false negative changed shape without changing tables. Restore the answer; '
              'never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - 0 of {sum(CWE22_LOCKED.values())} blessed CWE-22 keys answered SAFE, '
          f'{len(EARNED_ROWS)} shapes retired by this rule alone, '
          f'{len(REFUSED_ROWS)} refused shapes still loud, '
          f'{len(SILENT_REFUSED_ROWS)} refusals re-filed as silence and booked only against the '
          f'withdrawn fallback, {len(ATTR_HOP_BLIND_ROWS)} root-written fields refused and NOT booked, '
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
