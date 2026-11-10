"""Slice I truth table: when a function parameter is owed a synthetic untrusted path source.

Why this gate exists
--------------------
The synthetic parameter collector (`_collect_cwe22_parameter_path_sinks`) stamps
`UNTRUSTED_PATH_TRAVERSAL` onto `open(<parameter>)` because a parameter is caller-controlled *by
definition*. That assumption is the only CWE-22 source in the engine that no dataflow supports: the
row exists because the engine guessed a caller might hand over a remote value. Slice I asks the
question the guess was always dodging -- **does this module have a caller that could?** -- and
declines the guess where it cannot be answered yes.

The mandate specified two levers. Lever 2 (prune joins whose base is a literal, `__file__`,
`tempfile.*`, `Path.cwd()` or `abspath(literal)`, and cleanup deletes rooted in `tempfile`) was
measured to have **exactly zero reach** before any code was written: `scratch/_c22_attribution.py`
put every one of the 593 arena CWE-22 rows to those shapes and the population it could touch is
empty, because `_c22_is_static_repo_literal_join`, `_is_self_described`,
`_c22_cleanup_is_temp_teardown` and `_c22_path_is_proven_temp_root` already retire them. Writing a
second prover for rows an existing clause already proves is dead engine code, so Lever 2 ships as
the origin/refusal tables in TIER 4 below, which pin the coverage the shipped clauses already own.

What Lever 1 actually moved, measured rather than claimed: the paired full-arena scan in
`scratch/_c22_arm_{head,live}_arena.json` (one arm per process -- the single-process pair harness
disagreed with a fresh run on 8 rows and was retired) and the 25-fixture table below, every one of
which is a real `UNTRUSTED_PATH_TRAVERSAL` row at `git show HEAD:ast_scanner.py` (snapshot hash
matches HEAD byte for byte, verified). Ten synthetic sources are declined: eight lines go quiet and
two of those stayed reported by another emitter, so the guard removed an invented source and not a
finding. Thirteen stay loud on a module fact and two on caller reach alone. The successor open()
taint rule (`cwe22_open_taint_probe`) has since retired those two remaining emitters as well, so
TIER 3 now asserts the whole row is quiet and still attributes the declined source to this guard.

The narrowings are the load-bearing part, and each is pinned by a fixture that stays loud:

  * a route decorator is read **only** in decorator position. The first revision read the attribute
    leaf of every `ast.Attribute` in the module, so `parse_table.get("flags")` spelled
    `route_decorator` and single-handedly sustained 34 surviving arena rows;
  * a harness base is `TestCase`/`TestBase`/`TesterMixin`-suffixed or `Test`-prefixed. Plain
    `DataMixin` -- which is what a large slice of `src/transformers` inherits -- is not a harness;
  * `import_time_execution` is a top-level statement that calls something **for its effect**, not a
    binding, so `logger = logging.getLogger(__name__)`, which is in nearly every module in the
    arena, is not a program;
  * `argv`/`stdin` require the `sys.` qualification, and a bare `argv` name is deliberately not a
    module fact -- the reach arm still catches it when such a value is actually handed to the
    function;
  * there is no text prefilter in front of the walk. A spelling gate may only skip a walk when it
    can PROVE the walk finds nothing; skipping on unknown text under-reports facts, and an
    under-reported fact retires a row -- the wrong direction for a fail-closed rule.

One deciding site
-----------------
The guard is consulted from exactly one place, inside the collector, strictly before the
`_add_blindspot_sink(... "UNTRUSTED_PATH_TRAVERSAL" ...)` stamp, and its answer can only ever *skip*
that stamp. It never widens a source, never re-labels a row, and cannot make a finding appear: the
cascade, the registry sinks and the taint graph still report the same `open()` if real taint arrives.
`library_write_mode_open` and `reach_unbound_caller` were that case when this gate shipped -- the row
survived under the registry's message -- and the successor open() taint rule has since retired the
unproven fallback that carried them, so TIER 3 asserts they are quiet now and that this guard is
still the rule that declined their invented source.

The three blessed keys it cannot prove from inside the file
----------------------------------------------------------
`modeling_utils.py:336` and `:3564` are Big-8 keys and `modeling_utils.py` genuinely carries none of
the facts -- it is the purest library module in the arena. The mandate still owns those keys, because
the corpus runs as part of the benchmark suite and their parameters are fed from a hub identifier a
caller in *another* module chose. Cross-module callers are invisible to this rule by design, so
`CWE22_ENTRYPOINT_KEEP_LOUD` pins them by exact identity, the way CWE-208's inert-operand table pins
its size rows. TIER 2 checks that the table is not decoration: the two lines must be **asked**,
answered True, and the ground must be the pin. TIER 5 checks structurally that the only thing the
table can do is `return True` -- a keep-loud table, never a silence table -- and
`keep_loud_table_emptied` proves dropping it moves both keys. Since round 3 the structural check is
per SITE rather than per count: the two deciding predicates must each hold exactly one `If` whose whole
body is `return True` (the source is owed) or `return False` (no proof is owed), and any other reader of
the table is only legal if its membership test sits on the keep side of a discard -- `not in` the table,
an empty `else`, and a body that can only drop the record. `sites_outside_deciding` is printed with the
measured number, and it is `0` for the engine as it stands.

Round 3: the eleven rows the successor open()-taint rule took from this gate
---------------------------------------------------------------------------
`_c22_open_sink_owes_proven_taint` asks the provenance question of the SINK ARGUMENT rather than of the
module -- may this filesystem path sink report only if a resolved untrusted origin reaches one of its
arguments? -- and it answers in the four places a CWE-22 path row is emitted (the phase-11 registry
sink, the phase-5 and phase-4 short-circuits, and the subtract-only `ProvenanceState.UNKNOWN` prune
arm). Eleven of this gate's rows went quiet. Every one of them is attributed before being touched, with
`scratch/_c22_r3_engines.py --diff` (HEAD's snapshot and the live engine in separate processes), and
every one lands in the head-only column: `scratch/_c22_r3_entrypoint_lost_rows.py` writes the capture of
all eleven -- eight carriers, three refusals, `head_rows>0 live_rows=0` for each -- to
`scratch/_c22_r3_entrypoint_lost_rows.txt`, and `scratch/_c22_r3_fact_attributions.txt` holds the same
question asked of all thirteen fact fixtures. A row quiet under BOTH arms would not be this round's
collateral and none of those expectations was touched; the one such row this round came near is filed
inside the capture, the read-mode `open(options.path)` of a genuinely declared `parse_args()` namespace,
`head_rows=0 live_rows=0`.

Eight of them are `LOUD_BY_FACT` carriers, and their proposition was never the retired blanket: it is
that the classifier declares a module fact and the collector therefore injects a synthetic source. That
is still exactly what happens -- the guard is still consulted once per carrier and still answers True
(kept at 13 in TIER 3) -- but a fact alone no longer buys the report, so each carrier was re-spelled to
name an origin the walk resolves: a command line this file parses, a value read off a request, or an
`input()` the script asks for. Two properties decided the spelling, both measured in
`scratch/_c22_r3_entrypoint_candidates.py`, `scratch/_c22_r3_entrypoint_method_grid.py` and the
before/after fact-set table of `scratch/_c22_r3_entrypoint_fact_sets.py`: no line number moved, no
carrier's own fact was replaced, `facts_blind_main_guard` and `facts_blind_import_time_execution` still
move their rows -- which is why those two carriers take an `argparse` root and not an `argv` one, since
`argv_read` plus the reach arm would have kept the guard True after the fact was dropped and turned the
mutation into a MISSED. Seven of the eight gained no fact at all; `fact_route_decorator_only` gains
`web_name` alongside `route_decorator`, the same web family and a fact no mutation pins, and it is the
one place where the repair had to say which fact it was willing to spend. `self.read(<root>)` does not
resolve a method parameter while `Case().read(<root>)` does, which is why the two harness carriers
construct their driver instead of calling through `self`.

Three more are the Lever-2 refusals `operator_namespace`, `unimported_tempfile` and
`rmtree_operator_root`, and those ARE the blanket: their booked reason was "this base is not provably
safe, so it stays loud". They are re-filed, not deleted -- `LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT`, with
TIER 4c printing `blanket_brought_back=3/3` and `open_taint_blanket_restored` as the falsification, so
the win is pinned to the clause that earned it and cannot be re-tuned into the proven tables. Each was
scrutinised for a root the walk is supposed to recognise and none declares one: `options` is never bound
in either carrier, and `mkdtemp()` is spelled with no `tempfile.` receiver, which
`_c22_path_is_proven_temp_root` refuses by design because a bare name could be anybody's function. The
counterpart table `LEVER2_REFUSED_WITH_ROOT_DECLARED` is the other half of that claim: the same three
shapes WITH a declared `parse_args()` namespace or a `sys.argv` root must stay loud, or the win would be
a hole rather than a refinement. One shape is filed as neither: an `import argparse` module that binds
`options = argparse.ArgumentParser().parse_args()` and then reads `open(options.path)` is quiet at HEAD
too (`head_rows=0 live_rows=0`), which is a pre-existing gap in the read-mode `open()` sink and not this
round's collateral -- the write-mode spelling is what the walk sees, and it is pinned loud.

Two consequences for the machinery, recorded because they are the interesting part. First, a booked win
cannot be pinned by message: at HEAD those five rows report under the registry's `CWE-22: open` /
`CWE-22: shutil.rmtree`, not under the synthetic source's generic message, so `BLANKET_BOOKED_ROWS` and
`pinned_state` assert presence for exactly those labels and stay message-scoped everywhere else. Second,
four arms that weaken the classifier (`guard_removed`, `import_time_accepts_any_binding`,
`route_decorator_reads_any_attribute`, `harness_base_plain_mixin`) had gone MISSED, because the guard
now sits BEHIND the provenance requirement and restoring it alone cannot bring a row back -- not because
the clause is decorative. They run with the successor's answer forced to HEAD's (`_OPEN_TAINT_BLANKET_
CONTEXT`), which keeps their baselines quiet and their weakened rows movable, and falsifies their own
clause instead of the neighbour's. Nothing in this section lowered a floor: TIER 1 and TIER 2 are the
same claim, all 24 blessed CWE-22 keys are still emitted and 0 declined, no path or folder blacklist
exists, no baseline was re-blessed, and every declined-source, fact-recognition, pin-table and blessed-
reach assertion is still pinned.

Where each surviving row is still pinned, clause by clause: the eight `EARNED_QUIET` modules to the
guard's declined answer (TIER 3 asserts the line is empty AND that `ground_of` reads `declined`, so a
quiet row nobody was asked about cannot be booked here), the two `SUPERSEDED_BY_OPEN_TAINT` carriers to
that same declined answer plus the successor's retire, the thirteen `LOUD_BY_FACT` carriers to the fact
ground of `_c22_module_entrypoint_facts` (consult count exactly one, generic message present,
`guard_always_false` and the two fact-blind arms still moving), the two `LOUD_BY_REACH` carriers to
`_c22_callers_pass_untrusted_value` with a control that fails if a reach fixture secretly carries a
fact, the three remaining Lever-2 refusals to the roots they actually spell, the three re-filed ones to
the restored blanket, and the 24 blessed keys plus the two `modeling_utils.py` pins to TIER 1, TIER 2
and `keep_loud_table_emptied` -- unchanged, unlowered, still emitted, still zero declined.

Collateral: the four gates that pinned the blanket
--------------------------------------------------
Because the guard answers *before* the stamp, four tracked gates lost a row whose only loudness basis
was the blanket itself: `workflow_controls_probe`'s `CONFIG_TRAV` carrier, `active_partition_probe`'s
`runtime_read` and `resolver_local_def_is_not_a_binding`, `cwe22_vocab_serializer_probe`'s
`serializer_read_loud`, and `cwe22_blindspot_origin_probe`'s `no_caller_in_file`. No expectation was
loosened. Each carrier module now declares an entrypoint fact (`sys.argv`), which keeps the synthetic
source being injected at all, and the rule each of those gates actually owns still decides its row --
their own mutation tiers still report CAUGHT. `workflow_controls_probe` is the one that matters most:
it is the gate that proves no path blacklist exists, and its reasoning was "nothing but a path policy
can quiet this carrier". A content policy can now, so the carrier has to be loud by content.

Usage
-----
    python benchmark/gates/cwe22_entrypoint_injection_probe.py
    python benchmark/gates/cwe22_entrypoint_injection_probe.py --mutate=<name>

Twelve weakenings are pinned below, each one clause of the shipped classifier, one arm of the deciding
predicate, or -- since round 3 -- the successor's provenance answer itself. Per Harness Law 8 each must
move the row its clause decides, and the tripwire is line-scoped and message-scoped (the synthetic
source's own message), because a fixture module can carry other CWE-22 rows that belong to other
clauses. The five rows booked as the successor's win are the exception and are pinned by presence
instead, because HEAD carries them under a registry message this gate does not own.
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

GENERIC = ('CWE-22: Unvalidated user input or dynamic variable used in file path operation')
CWE22_LOCKED = {'parity': 8, 'big8': 16}
BASELINE_TOTALS = {'parity': 425, 'big8': 119}
# The rows the pin table must own, spelled the way the engine spells them.
EXPECTED_PIN_KEYS = [('src__transformers__modeling_utils.py', 336),
                     ('src__transformers__modeling_utils.py', 3564)]

# --------------------------------------------------------------------------- fixtures
# Every fixture is a whole module. The names deliberately avoid the `_file`/`_path`/`_dir` suffixes
# that the collector's older name shield `continue`s on, because a fixture that never reaches the
# stamp cannot evidence anything about the guard: at HEAD each of these 25 modules DOES reach it and
# each emits one synthetic CWE-22 row, which is what the tables below assert.

HELPER = ('def load_config(cfg_slot):\n'
          + '    with open(cfg_slot) as handle:\n'
          + '        return handle.read()\n')

# Loud at HEAD, quiet now, and nothing else on the line: the guard declined to invent the source.
EARNED_QUIET = {
    'library_param_open': (2, HELPER),
    'library_method_open': (3, 'class Store:\n'
                            + '    def read(self, blob_slot):\n'
                            + '        with open(blob_slot) as handle:\n'
                            + '            return handle.read()\n'),
    'library_nested_def_open': (3, 'def outer(name):\n'
                                + '    def inner(cfg_slot):\n'
                                + '        with open(cfg_slot) as handle:\n'
                                + '            return handle.read()\n'
                                + '    return inner\n'),
    'library_join_param_and_literal': (3, 'import os\n'
                                       + 'def read_bundle(base_slot):\n'
                                       + '    with open(os.path.join(base_slot, "index.json")) as handle:\n'
                                       + '        return handle.read()\n'),
    'library_dict_get': (3, 'def load_config(cfg_slot):\n'
                          + '    flags = parse_table.get("flags")\n'
                          + '    with open(cfg_slot) as handle:\n'
                          + '        return handle.read()\n'),
    'library_mixin_base': (5, 'class DataMixin:\n'
                           + '    pass\n'
                           + 'class Store(DataMixin):\n'
                           + '    def read(self, blob_slot):\n'
                           + '        with open(blob_slot) as handle:\n'
                           + '            return handle.read()\n'),
    'library_logger_only': (4, 'import logging\n'
                            + 'logger = logging.getLogger(__name__)\n' + HELPER),
    'library_environ_unrelated_to_param': (4, 'import os\n'
                                          + 'MODE = os.environ.get("MODE", "dev")\n' + HELPER),
}

# Superseded, and the supersession is asserted rather than deleted. When this gate shipped, these two
# lines kept reporting under the registry's own message (`CWE-22: open`) after the invented source was
# declined -- the proof that the guard removed an assumption and not a finding. The successor rule
# (`cwe22_open_taint_probe`) then retired the unproven `open()` fallback in modules that declare no
# entrypoint, which is exactly these two shapes, so the whole row is now quiet. This gate still owns
# the half it always owned: the guard declined the synthetic source, and the generic message is gone.
# Round 3 added the falsification that names the successor rather than this guard: both labels are in
# `BLANKET_BOOKED_ROWS`, which `open_taint_blanket_restored` moves by putting HEAD's answer back.
SUPERSEDED_BY_OPEN_TAINT = {
    'library_write_mode_open': (2, 'def dump_state(state_slot, payload):\n'
                                  + '    with open(state_slot, "w") as handle:\n'
                                  + '        handle.write(payload)\n'),
    'reach_unbound_caller': (2, HELPER + 'def run(name):\n'
                             + '    return load_config(chosen_slot)\n'),
}

# Loud now, loud at HEAD, and loud because the MODULE spells an entrypoint: one fixture per fact.
#
# 2026-11-10, and eight of these thirteen had to be re-spelled to keep that sentence true. The
# successor rule (`_c22_open_sink_owes_proven_taint`, filed by `cwe22_open_taint_probe`) asks the
# provenance question of the ARGUMENT rather than of the module, so a fact is now a reason to LOOK and
# no longer a reason to REPORT: `scratch/_c22_r3_fact_attributions.txt` runs
# `scratch/_c22_r3_engines.py --diff` over all thirteen and the eight carriers below were loud at HEAD
# and are quiet live, which is a supersession, not a broken fixture. The repair is EARN, not re-file:
# what these fixtures assert is that the classifier declares a module fact and the collector injects a
# synthetic source, and a carrier that ALSO names its own command-line or remote value still proves
# exactly that (`scratch/_c22_r3_entrypoint_candidates.py`, `scratch/_c22_r3_entrypoint_method_grid.py`
# are the measurements behind each spelling). Two constraints decided every choice:
#
#   * the fact set must stay the fixture's own fact. `facts_blind_main_guard` and
#     `facts_blind_import_time_execution` are only falsifications if the row goes quiet when that one
#     fact is dropped, so a carrier may not smuggle in a second fact to buy its origin. An
#     `argparse.ArgumentParser().parse_args()` INLINE in the argument, or `flask.request.args[...]` in a
#     module that already imports `flask`, resolve to an operator root and add nothing to the fact set
#     (measured: `main_guard_inline_parse`, `import_time_namespace`, `flask_dotted`). The one carrier
#     that does spend a second fact is named in the Round 3 section above, with the measurement.
#   * the origin must not be one the REACH arm also recognises, for those same two fixtures. That is
#     why `fact_main_guard` parses a command line instead of reading `sys.argv`: with `argv_read` also
#     present, `_c22_callers_pass_untrusted_value` would keep the guard True after the fact is dropped
#     and the mutation would report MISSED. `fact_pytest_import`/`fact_harness_class`/
#     `fact_tester_mixin_base`/`fact_top_level_test_def` are free to use `input()` or a request value,
#     because no mutation pins the harness/web facts they carry.
#
# One hop the walk does NOT take, and it is recorded rather than papered over: `self.read(<root>)`
# inside the same class does not resolve a method parameter, while `Case().read(<root>)` does (the
# `self_call` and `method_then_def_call` rows of `scratch/_c22_r3_entrypoint_method_grid.py`). Every
# harness carrier below therefore names its caller as a construction, which is what the engine can see
# and what a real driver does.
LOUD_BY_FACT = {
    # `main_guard`, and nothing else: the guard is the fact and the parsed namespace is the origin.
    'fact_main_guard': (2, HELPER + 'if __name__ == "__main__":\n'
                        + '    load_config(argparse.ArgumentParser().parse_args().cfg)\n'),
    'fact_import_time_call': (2, HELPER
                              + 'options = argparse.ArgumentParser().parse_args()\n'
                              + 'print(load_config(options.cfg))\n'),
    'fact_cli_argparse': (3, 'import argparse\n' + HELPER
                          + 'def run():\n'
                          + '    options = argparse.ArgumentParser().parse_args()\n'
                          + '    return load_config(options.cfg)\n'),
    'fact_argv_read': (3, 'import sys\n' + HELPER + 'def run():\n'
                       + '    return load_config(sys.argv[1])\n'),
    'fact_stdin_read': (3, 'import sys\n' + HELPER + 'def run():\n'
                        + '    return load_config(sys.stdin.read())\n'),
    'fact_web_request': (4, 'def view(request):\n'
                         + '    return load_config(request.args["cfg"])\n' + HELPER),
    'fact_web_read_off_request': (2, 'def view(request):\n'
                                  + '    with open(request.args["f"]) as handle:\n'
                                  + '        return handle.read()\n'),
    # the dotted `flask.request` read is a remote value AND adds no second fact to a `web_module` file.
    'fact_flask_import': (3, 'import flask\n' + HELPER + 'def run():\n'
                          + '    return load_config(flask.request.args["cfg"])\n'),
    'fact_route_decorator_only': (2, 'def read_upload(cfg_slot):\n'
                                  + '    with open(cfg_slot) as handle:\n'
                                  + '        return handle.read()\n'
                                  + 'class Api:\n'
                                  + '    @app.get("/f")\n'
                                  + '    def handler(self):\n'
                                  + '        return read_upload(request.args["cfg"])\n'),
    'fact_pytest_import': (3, 'import pytest\n' + HELPER + 'def run():\n'
                           + '    return load_config(input("which config?"))\n'),
    'fact_harness_class': (4, 'import unittest\n'
                          + 'class Case(unittest.TestCase):\n'
                          + '    def test_read(self, cfg_slot):\n'
                          + '        with open(cfg_slot) as handle:\n'
                          + '            return handle.read()\n'
                          + 'def drive():\n'
                          + '    return Case().test_read(input("which config?"))\n'),
    'fact_tester_mixin_base': (5, 'class TokenizerTesterMixin:\n'
                               + '    pass\n'
                               + 'class Case(TokenizerTesterMixin):\n'
                               + '    def read(self, cfg_slot):\n'
                               + '        with open(cfg_slot) as handle:\n'
                               + '            return handle.read()\n'
                               + 'def drive():\n'
                               + '    return Case().read(input("which config?"))\n'),
    'fact_top_level_test_def': (2, HELPER + 'def test_read(cfg_slot):\n'
                                + '    return load_config(cfg_slot)\n'
                                + 'def suite():\n'
                                + '    return test_read(input("which config?"))\n'),
}

# Loud now with NO module fact at all: the only ground left is that a call this file can see hands an
# untrusted value to the function. These two fixtures are the whole reach arm, and `caller_reach_blind`
# and `untrusted_dotted_blind` both move them.
LOUD_BY_REACH = {
    'reach_input_caller': (2, HELPER + 'def run(name):\n'
                           + '    answer = input("which config?")\n'
                           + '    return load_config(answer)\n'),
    'reach_environ_caller': (3, 'import os\n' + HELPER + 'def run():\n'
                             + '    return load_config(os.environ["CFG"])\n'),
}

ALL_FIXTURES = {}
ALL_FIXTURES.update(EARNED_QUIET)
ALL_FIXTURES.update(SUPERSEDED_BY_OPEN_TAINT)
ALL_FIXTURES.update(LOUD_BY_FACT)
ALL_FIXTURES.update(LOUD_BY_REACH)

# --------------------------------------------------------------------------- Lever 2 origin tables
# Measured zero reach, pinned anyway. `scratch/_c22_lever2_shapes.py` put every shape the lever names
# to the live engine: the five proven-base joins and both tempfile-rooted cleanups are already quiet,
# and the five unproven bases are already loud. Nothing was added to the engine because there was
# nothing to move, and a prover that moves no row cannot be demonstrated.
JOIN_BASE_PROVEN = {
    'literal_root': 'import os\nopen(os.path.join("/opt/models/roberta", "index.json"))\n',
    'file_dunder_root': 'import os\nopen(os.path.join(os.path.dirname(__file__), "index.json"))\n',
    'tempfile_root': ('import os, tempfile\n'
                      'open(os.path.join(tempfile.mkdtemp(), "index.json"))\n'),
    'tempfile_cm_name': ('import os, tempfile\nwith tempfile.TemporaryDirectory() as root:\n'
                         '    open(os.path.join(root, "index.json"))\n'),
    'abspath_literal': 'import os\nopen(os.path.join(os.path.abspath("/opt/models"), "a.json"))\n',
    'path_cwd': 'import pathlib\nopen(str(pathlib.Path.cwd()) + "/index.json")\n',
}
# The refusals that still buy a report: a base the lever cannot prove safe AND that spells a root the
# successor rule does recognise -- a remote read, a `sys.argv` read. Three more shapes used to sit in
# these two tables; they are re-filed below, with the measurement, because their only loudness basis
# was the blanket.
JOIN_BASE_REFUSED = {
    'request_root': 'import os\nopen(os.path.join(request.root, "a.json"))\n',
}
CLEANUP_TEMP_REFUSED = {
    'rmtree_from_argv': 'import shutil\nshutil.rmtree(sys.argv[1])\n',
    'remove_from_request': 'import os\nos.remove(request.args["f"])\n',
}
# ── 2026-11-10 re-filed: three refusals whose silence IS the mandate ─────────────────────────────
# These three joined the refusal tables on the argument that a base this rule cannot PROVE safe must
# stay loud -- "the engine cannot prove this safe" bought the report. `_c22_open_sink_owes_proven_taint`
# retired that blanket in exactly the direction the mandate words it: a path sink is owed a RESOLVED
# operator or remote origin, and an origin is a fact about the argument, not about the file. So the
# question the re-file has to answer is whether each carrier declares a root at all. It does not, and
# `scratch/_c22_r3_entrypoint_blanket_arm.py` measures the difference instead of asserting it: under
# the shipped rule all three are quiet, under a restored blanket (the predicate forced to `False`,
# which is HEAD's answer) every one comes back -- `operator_namespace` and `unimported_tempfile` as
# `CWE-22: open`, `rmtree_operator_root` as `CWE-22: shutil.rmtree`. `scratch/_c22_r3_engines.py
# --diff` puts the same three rows in the head-only column, so they are supersessions of this round and
# not rows that were already silent.
#
# The refusals that stay in the tables above stay because their root really is spelled in the file:
# `request.root` is a remote read, `sys.argv[1]` and `request.args["f"]` are the two roots the mandate
# names. The third table below is the honest half of the re-file: the same three shapes WITH a root
# declared, which must remain loud, because otherwise the win silently becomes a hole. Measured, not
# assumed -- and one shape is deliberately absent from it, because it is quiet under both arms and so
# belongs to no round. An `import argparse` module that binds
# `options = argparse.ArgumentParser().parse_args()` and then reads `open(options.path)` reports
# nothing at HEAD either (`scratch/_c22_r3_engines.py --diff`: `head_rows=0 live_rows=0`), which is a
# pre-existing gap in the read-mode `open()` sink, not this round's collateral and not this table's
# evidence. The write-mode spelling below is what the walk does see.
LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT = {
    'operator_namespace': 'import os\nopen(os.path.join(options.storage_location, "a.json"))\n',
    'unimported_tempfile': 'import os\nopen(os.path.join(mkdtemp(), "a.json"))\n',
    'rmtree_operator_root': 'import shutil\nshutil.rmtree(options.storage_location)\n',
}
LEVER2_REFUSED_WITH_ROOT_DECLARED = {
    'operator_namespace_declared': ('import argparse\noptions = argparse.ArgumentParser().parse_args()\n'
                                    'open(options.storage_location, "w")\n'),
    'tempfile_leaf_with_argv_root': ('import os\nopen(os.path.join(mkdtemp(sys.argv[1]), "a.json"))\n'),
    'rmtree_operator_namespace_declared': ('import argparse, shutil\n'
                                          'options = argparse.ArgumentParser().parse_args()\n'
                                          'shutil.rmtree(options.out_dir)\n'),
}

# Every row this gate books as the successor rule's win, by SOURCE alone. `SUPERSEDED_BY_OPEN_TAINT`
# and `LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT` are asserted quiet, so the falsification that owns them
# cannot be message-scoped the way TIER 3's is: at HEAD `library_write_mode_open` and the three
# refusals report under the registry's own `CWE-22: open` / `CWE-22: shutil.rmtree`, and only the
# generic synthetic rows carry the message `pinned_state` normally looks for. For a booked win the
# question is simply whether the line is reported at all, and `scratch/_c22_r3_entrypoint_blanket_arm.py`
# prints the message each one comes back with under the restored blanket, so the message is recorded
# even though it is not the assertion.
BLANKET_BOOKED_ROWS = {label: source for label, (_line, source)
                       in SUPERSEDED_BY_OPEN_TAINT.items()}
BLANKET_BOOKED_ROWS.update(LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT)

# Quiet, and NOT booked as this lever's: a path built only out of literals has no caller in it at
# all, so the collector's literal skip owns those rows. They sit here so no later revision can claim
# them, the way the sibling gate files its inherited rows.
JOIN_BASE_QUIET_NOT_CLAIMED = {
    'relative_literal': 'import os\nopen(os.path.join("release", "index.json"))\n',
    'escape_literal': 'import os\nopen(os.path.join("/opt/../etc", "passwd"))\n',
}
CLEANUP_TEMP_PROVEN = {
    'rmtree_mkdtemp': ('import os, shutil, tempfile\n'
                       'shutil.rmtree(os.path.join(tempfile.mkdtemp(), "sub"))\n'),
    'remove_named_temp': ('import os, tempfile\n'
                          'os.remove(tempfile.NamedTemporaryFile(delete=False).name)\n'),
}


# --------------------------------------------------------------------------- plumbing

def scan_module(source, module='m.py'):
    """CWE-22 rows for one in-memory module, through the real record path."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(int(row['line']), row['message']) for row in rows if row['cwe'] == 'CWE-22'})


def observe_consults(source, module='m.py'):
    """Scan one module and record every question the shipped guard was actually asked.

    The log is taken by wrapping `_c22_synthetic_param_source_is_founded` and letting the engine call
    it, so `asked` is what the engine asked -- never a mirror of what this file thinks it should ask.
    """
    log = []
    original = ast_scanner.TaintTracker._c22_synthetic_param_source_is_founded

    def spy(self, tree, fname, filename='', lineno=0):
        answer = original(self, tree, fname, filename, lineno)
        log.append((int(lineno), str(fname), filename,
                    tuple(sorted(self._c22_module_entrypoint_facts(tree))), bool(answer)))
        return answer

    ast_scanner.TaintTracker._c22_synthetic_param_source_is_founded = spy
    try:
        scan_module(source, module)
    finally:
        ast_scanner.TaintTracker._c22_synthetic_param_source_is_founded = original
    return log


def ground_of(entry, rows):
    """Which of the three arms answered True: the exact-identity pin, a module fact, or caller reach."""
    lineno, _fname, filename, facts, answer = entry
    base = os.path.basename(filename or '')
    if (base, int(lineno)) in ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD:
        return 'pin'
    if facts:
        return 'facts'
    return 'reach' if answer else 'declined'


def generic_at(rows, line):
    return any(row_line == line and message == GENERIC for row_line, message in rows)


def consult_at(log, line):
    return [entry for entry in log if entry[0] == line]


def corpus_source(kind, file_field):
    """Read one blessed corpus file with the shape the sibling probes use.

    Parity scans `benchmark/gates/`, so a helper's return value or a twice-written name in a read
    would make this harness itself a CWE-22 key. ROOT-anchored, single write, `os.path.exists` guard,
    `with` block.
    """
    relative = (file_field if kind == 'parity'
                else os.path.join('benchmark_gates_data', 'corpus_big8',
                                  os.path.basename(file_field)))
    path = os.path.abspath(os.path.join(ROOT, relative))
    if not os.path.exists(path):
        return None
    with open(path, encoding='utf-8', errors='replace') as handle:
        return handle.read()


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
    """TIER 2: all 24 blessed lines still reported, and the guard declines 0 of them.

    The population splits three ways and the tier reports the split instead of asserting one shape:
    most blessed lines are owned by the registry or the cascade and are never asked about at all
    (correct, and proven by the `asked` counter being what the engine asked); two are kept by a module
    fact; two are kept by the exact-identity pin. `declined` must be zero -- that field IS the
    zero-FN claim.
    """
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        wanted = {}
        for row in rows:
            if row[2] == 'CWE-22':
                wanted.setdefault(str(row[0]), set()).add(int(row[1]))
        asked = declined = facts = pins = never = 0
        for file_field, lines in sorted(wanted.items()):
            source = corpus_source(kind, file_field)
            if source is None:
                failures.append((kind, 'blessed corpus file is not in the tree', file_field))
                continue
            module = os.path.basename(file_field)
            found = scan_module(source, module)
            log = observe_consults(source, module)
            for line in sorted(lines):
                if not any(row_line == line for row_line, _message in found):
                    failures.append((kind, 'blessed line no longer reported', file_field, line))
                entries = consult_at(log, line)
                if not entries:
                    never += 1
                    continue
                asked += 1
                for entry in entries:
                    ground = ground_of(entry, found)
                    if ground == 'facts':
                        facts += 1
                    elif ground == 'pin':
                        pins += 1
                        if not entry[4]:
                            failures.append((kind, 'pin line declined', file_field, line))
                    elif not entry[4]:
                        declined += 1
                        failures.append((kind, 'blessed line declined by the guard', file_field, line,
                                         entry[3]))
        print(f'  {kind:7s} blessed_lines={len(wanted) and sum(len(v) for v in wanted.values())} '
              f'asked={asked} declined={declined} kept_by_facts={facts} kept_by_pin={pins} '
              f'never_asked={never}')
        if kind == 'big8' and pins != len(EXPECTED_PIN_KEYS):
            failures.append(('big8', 'pin table is not load-bearing', len(EXPECTED_PIN_KEYS), pins))
    table = sorted(ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD)
    print(f'  keep_loud_table={table}')
    if table != sorted(EXPECTED_PIN_KEYS):
        failures.append(('the shipped pin table is not the two measured keys', table))
    return failures


def check_fixtures():
    """TIER 3: the 25-module truth table, with the deciding arm named for every row."""
    failures = []
    earned = kept = loud_fact = loud_reach = 0
    for label, (line, source) in sorted(ALL_FIXTURES.items()):
        found = scan_module(source)
        log = observe_consults(source)
        entries = consult_at(log, line)
        if len(entries) != 1:
            failures.append(('guard consults on the line', label, line, len(entries)))
            continue
        ground = ground_of(entries[0], found)
        if label in EARNED_QUIET:
            if found:
                failures.append(('earned row still reported', label, line, found[:2]))
            elif ground != 'declined':
                failures.append(('quiet row not attributable to the guard', label, line, ground))
            else:
                earned += 1
        elif label in SUPERSEDED_BY_OPEN_TAINT:
            at_line = [message for row_line, message in found if row_line == line]
            if generic_at(found, line):
                failures.append(('invented source survived', label, line))
            elif at_line:
                failures.append(('successor open() taint rule stopped retiring this shape',
                                 label, line, at_line))
            elif ground not in ('declined', 'reach'):
                failures.append(('quiet row not attributable to the guard', label, line, ground))
            else:
                kept += 1
        elif ground == 'facts':
            loud_fact += 1
            if not generic_at(found, line):
                failures.append(('fact row lost its synthetic source', label, line))
        elif ground == 'pin':
            loud_fact += 1
        elif ground == 'reach':
            loud_reach += 1
            if not generic_at(found, line):
                failures.append(('reach row lost its synthetic source', label, line))
        else:
            failures.append(('unattributable fixture', label, line, ground))
    print(f'  fixtures={len(ALL_FIXTURES)} declined_and_quiet={earned} '
          f'declined_then_retired_by_open_taint_successor={kept} loud_by_facts={loud_fact} '
          f'loud_by_reach={loud_reach}')
    for label in sorted(LOUD_BY_REACH):
        facts = consult_at(observe_consults(ALL_FIXTURES[label][1]), ALL_FIXTURES[label][0])
        if facts and facts[0][3]:
            failures.append(('reach fixture secretly carries a fact', label, facts[0][3]))
    return failures


def _facts_of(source):
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': 'x = 1\n'}, audit_all=True)
    return tuple(sorted(tracker._c22_module_entrypoint_facts(ast.parse(source))))


def _expr_of(source):
    body = ast.parse(source).body
    last = body[-1] if body else None
    if isinstance(last, (ast.Assign, ast.AnnAssign)):
        return last.value
    if isinstance(last, (ast.Expr, ast.Return)):
        return last.value
    return None


def check_classifier():
    """TIER 4a: the fact classifier, asserted as an EXACT fact set on 24 spellings.

    Exact, not "contains": every narrowing this rule bought is a refusal to add a fact, and a
    superset-tolerant test cannot see an over-broad fact at all.
    """
    cases = [
        # (spelling, facts the classifier must report -- () means the module is a pure library)
        ('def read(cfg_slot):\n    return open(cfg_slot)\n', ()),
        ('x = parse_table.get("flags")\n', ()),
        ('class Store(DataMixin):\n    pass\n', ()),
        ('import logging\nlogger = logging.getLogger(__name__)\n', ()),
        ('OPTIONS = parse_config()\n', ()),
        ('def run(argv):\n    return argv[1]\n', ()),
        ('@property\ndef width(self):\n    return 1\n', ()),
        ('class Store:\n    def test_read(self):\n        return 1\n', ()),
        ('import os\nMODE = os.environ.get("MODE")\n', ()),
        ('if __name__ == "__main__":\n    run()\n', ('main_guard',)),
        ('print(read())\n', ('import_time_execution',)),
        ('with open(name) as handle:\n    handle.read()\n', ('import_time_execution',)),
        ('for row in rows():\n    pass\n', ('import_time_execution',)),
        ('import argparse\n', ('cli_module',)),
        ('def main():\n    return argparse.ArgumentParser().parse_args()\n', ('cli_module',)),
        ('import sys\n\ndef run():\n    return sys.argv[1]\n', ('argv_read',)),
        ('def read_all():\n    return sys.stdin.read()\n', ('stdin_read',)),
        ('import flask\n', ('web_module',)),
        ('import socket\n', ('web_module',)),
        ('from flask import request\nx = request.args["f"]\n', ('web_module', 'web_name')),
        ('@app.route("/f")\ndef view():\n    return 1\n', ('route_decorator',)),
        ('def view(request):\n    return request.args["f"]\n', ('web_name',)),
        ('import unittest\n', ('harness_module',)),
        ('class Case(unittest.TestCase):\n    pass\n', ('harness_class',)),
        ('class Case(TokenizerTesterMixin):\n    pass\n', ('harness_class',)),
        ('def test_read():\n    return 1\n', ('harness_function',)),
    ]
    failures = []
    matched = 0
    for source, expected in cases:
        got = _facts_of(source)
        if got != expected:
            failures.append(('fact set', source.splitlines()[0][:46], expected, got))
        else:
            matched += 1
    print(f'  spellings={len(cases)} exact={matched} refused={len(cases) - matched}')
    return failures


def check_untrusted_expressions():
    """TIER 4b: what counts as a remote value when a caller hands one over.

    The dotted spellings are matched on the WHOLE prefix. `os.environ["CFG"]` has first segment `os`,
    which is a perfectly ordinary module name, so a table that matched segments could neither accept
    the environment nor reject every `os` read -- and an environment-fed caller that reads as
    untrusted-free retires a row this rule is obligated to keep.
    """
    untrusted = [
        'answer = input("which config?")\n',
        'x = os.environ["CFG"]\n',
        'x = os.environ.get("CFG")\n',
        'x = os.getenv("CFG")\n',
        'x = sys.argv[1]\n',
        'x = sys.stdin.read()\n',
        'x = request.args["f"]\n',
        'x = environ["CFG"]\n',
        'x = load(open(request.url))\n',
    ]
    trusted = [
        'x = "cfg.json"\n',
        'x = os.getcwd()\n',
        'x = tempfile.mkdtemp()\n',
        'x = options.storage_location\n',
        'x = parse_table.get("flags")\n',
        'x = os.path.join(root, name)\n',
        'x = argv[1] if argv else name\n',
    ]
    failures = []
    proven = refused = 0
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': 'x = 1\n'}, audit_all=True)
    for source in untrusted + trusted:
        tree = ast.parse(source)
        expr = _expr_of(source)
        if expr is None:
            failures.append(('fixture has no trailing expression', source))
            continue
        got = bool(tracker._c22_expr_is_untrusted_source(
            tracker._memo_assignment_map(tree), expr))
        want = source in untrusted
        if got == want:
            proven += 1 if want else 0
            refused += 0 if want else 1
        else:
            failures.append(('untrusted test', 'expected' if want else 'refused', source.strip()))
    print(f'  expressions={len(untrusted) + len(trusted)} untrusted={proven} '
          f'not_untrusted={refused}')
    return failures


def blanket_restored(sources):
    """Ask HEAD's question of each shape: does the retired blanket bring the row back?

    `_c22_open_sink_owes_proven_taint` answering False for every record is the old behaviour -- "not
    provably safe" stood in for "untrusted" -- and it is the only thing these rows can be booked
    against. Patched in memory, scanned, restored in the `finally`; the same arm `open_taint_blanket_
    restored` runs as a falsification.
    """
    original = ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint
    ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = (
        lambda self, record, sink: False)
    try:
        return {label: bool(scan_module(source)) for label, source in sources.items()}
    finally:
        ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = original


def check_join_origins():
    """TIER 4c: Lever 2's own shapes, asserted as findings -- zero reach, measured, not assumed.

    Both proven-base join tables and both tempfile-rooted cleanup tables are already quiet, and every
    unproven base is already loud. That is the evidence for shipping no new prover: the clauses that
    exist (`_c22_is_static_repo_literal_join`, `_c22_path_is_proven_temp_root`,
    `_c22_cleanup_is_temp_teardown`) already cover the whole lever, so a second prover would move zero
    rows and hide a rule nobody can demonstrate. The third table is the honest remainder: shapes that
    are quiet for a reason this lever does not own, filed so no later revision can book them.

    Two more tables joined on 2026-11-10, for the three refusals the successor rule retired. They split
    the claim the original tables made -- "unproven means loud" -- into the two halves the mandate
    keeps: `LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT` is quiet now, and is booked against the blanket by
    `blanket_brought_back` measured right here (plus `open_taint_blanket_restored` as a falsification),
    so nobody can re-tune it into the proven tables; `LEVER2_REFUSED_WITH_ROOT_DECLARED` is the same
    three shapes with the root the walk is told to look for, and it MUST stay loud, because a win that
    quiets a declared `parse_args()` namespace as readily as an unbound `options` is a hole, not a win.
    """
    failures = []
    quiet = loud = not_claimed = 0
    for table, owns_silence in ((JOIN_BASE_PROVEN, True), (CLEANUP_TEMP_PROVEN, True),
                                (JOIN_BASE_REFUSED, False), (CLEANUP_TEMP_REFUSED, False),
                                (LEVER2_REFUSED_WITH_ROOT_DECLARED, False)):
        for label, source in sorted(table.items()):
            found = scan_module(source)
            if owns_silence and found:
                failures.append(('proven shape still reported', label, found[:1]))
            elif not owns_silence and not found:
                failures.append(('refused shape bought silence', label, source.strip()))
            quiet += not found
            loud += bool(found)
    for label, source in sorted(JOIN_BASE_QUIET_NOT_CLAIMED.items()):
        found = scan_module(source)
        if found:
            failures.append(('literal-only path is no longer quiet', label, found[:1]))
        else:
            not_claimed += 1
    retired = {}
    for label, source in sorted(LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT.items()):
        found = scan_module(source)
        if found:
            failures.append(('re-filed refusal reported again without the blanket', label, found[:1]))
        else:
            retired[label] = source
    brought = blanket_restored(retired)
    for label, is_loud in sorted(brought.items()):
        if not is_loud:
            failures.append(('re-filed row does not come back under the retired blanket', label))
    print(f'  refiled_by_open_taint={len(LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT)} '
          f'quiet_as_booked={len(retired)} blanket_brought_back='
          f'{sum(1 for is_loud in brought.values() if is_loud)}'
          f'/{len(LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT)}')
    tables = (JOIN_BASE_PROVEN, JOIN_BASE_REFUSED, CLEANUP_TEMP_PROVEN, CLEANUP_TEMP_REFUSED,
              JOIN_BASE_QUIET_NOT_CLAIMED, LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT,
              LEVER2_REFUSED_WITH_ROOT_DECLARED)
    print(f'  shapes={sum(len(table) for table in tables)} quiet={quiet} loud={loud} '
          f'quiet_not_claimed={not_claimed}')
    return failures



def check_wiring():
    """TIER 5: one consult site, before the stamp; a pin table that can only keep; no name shields."""
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        text = handle.read()
    lines = text.splitlines()
    definition = [index + 1 for index, item in enumerate(lines)
                  if 'def _c22_synthetic_param_source_is_founded(' in item]
    consults = [index + 1 for index, item in enumerate(lines)
                if '_c22_synthetic_param_source_is_founded(' in item and index + 1 not in definition]
    tree = ast.parse(text)
    methods = {}
    for top in tree.body:
        if isinstance(top, ast.ClassDef):
            for item in top.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.setdefault(item.name, item)
    collector = methods.get('_collect_cwe22_parameter_path_sinks')
    stamps = [index + 1 for index, item in enumerate(lines)
              if '"UNTRUSTED_PATH_TRAVERSAL"' in item]
    print(f'  definition={definition} consults={consults} '
          f'collector={collector.lineno if collector else None}-'
          f'{collector.end_lineno if collector else None} stamps_in_collector='
          f'{[n for n in stamps if collector and collector.lineno <= n <= collector.end_lineno]}')
    if len(definition) != 1:
        failures.append(('the deciding predicate is not defined exactly once', definition))
    if len(consults) != 1:
        failures.append(('the guard must be consulted from exactly one place', consults))
    if collector is None:
        failures.append(('the collector is missing', None))
    elif len(consults) == 1:
        consult = consults[0]
        if not collector.lineno <= consult <= collector.end_lineno:
            failures.append(('the consult site is outside the collector', consult))
        owned = [n for n in stamps if collector.lineno <= n <= collector.end_lineno]
        if not owned or min(owned) < consult:
            failures.append(('the consult site sits after the synthetic-source stamp',
                             (consult, min(owned) if owned else None)))
    pin_lines = [index + 1 for index, item in enumerate(lines) if 'CWE22_ENTRYPOINT_KEEP_LOUD' in item]
    pin_uses = [node.lineno for node in ast.walk(tree)
                if isinstance(node, ast.Name) and node.id == 'CWE22_ENTRYPOINT_KEEP_LOUD']
    pin_defs = [node.lineno for top in tree.body if isinstance(top, ast.Assign)
                for node in top.targets
                if isinstance(node, ast.Name) and node.id == 'CWE22_ENTRYPOINT_KEEP_LOUD']
    consulted = [lineno for lineno in pin_uses if lineno not in pin_defs]
    print(f'  pin_table_text_lines={pin_lines} pin_defs={pin_defs} consulted_from={consulted}')
    # Two deciding rules consult the table today: the synthetic-source guard answers `return True` (the
    # source is owed) and `_c22_open_sink_owes_proven_taint` answers `return False` (no proof is owed).
    # Both are the keep-loud direction for their own question. The claim this tier pins is not the
    # count -- it is that every reader of the table can only keep a row -- so the sites that sit inside
    # those two predicates are checked as returns and any other site is checked as a shape.
    keep_direction = {'_c22_synthetic_param_source_is_founded': True,
                      '_c22_open_sink_owes_proven_taint': False}
    owners = [methods.get(name) for name in keep_direction]
    inside = [lineno for lineno in consulted
              if any(node is not None and node.lineno <= lineno <= node.end_lineno
                     for node in owners)]
    outside = [lineno for lineno in consulted if lineno not in inside]
    if len(pin_defs) != 1 or len(inside) != len(keep_direction):
        failures.append(('the pin table must be defined once and consulted once per deciding rule',
                         (pin_defs, inside)))
    # A third site is possible: the phase-11 registry emitter can read the same table as a final
    # `if (basename, lineno) not in CWE22_ENTRYPOINT_KEEP_LOUD: drop the record / continue`. Counting
    # sites would call that a violation and ignoring it would call a silence table legal, so every
    # site outside the deciding predicates is checked for the SHAPE instead -- the membership test on
    # the keep side, an empty `orelse`, and a body that only discards. `sites_outside_deciding` is the
    # measured number, and it is zero today: the engine's deciding predicates are the only readers.
    for lineno in outside:
        arms = [item for item in ast.walk(tree) if isinstance(item, ast.If)
                and 'CWE22_ENTRYPOINT_KEEP_LOUD' in ast.unparse(item.test)
                and item.lineno <= lineno <= item.end_lineno]
        if len(arms) != 1:
            failures.append(('a pin consult outside the deciding rules is not exactly one If',
                             (lineno, len(arms))))
            continue
        test = arms[0].test
        only_keep = (isinstance(test, ast.Compare) and len(test.ops) == 1
                     and isinstance(test.ops[0], ast.NotIn)
                     and 'CWE22_ENTRYPOINT_KEEP_LOUD' in ast.unparse(test.comparators[0])
                     and not arms[0].orelse
                     and any(isinstance(node, ast.Continue) for node in ast.walk(arms[0])))
        print(f'  outside_deciding_site={lineno}: membership_only_drops={only_keep}')
        if not only_keep:
            failures.append(('the pin table must only ever keep a row, never silence one',
                             ('site outside the deciding rules', lineno)))
    print(f'  consulted_sites={len(consulted)} inside_deciding_rules={len(inside)} '
          f'sites_outside_deciding={len(outside)}')
    for name, constant in keep_direction.items():
        owner = methods.get(name)
        if owner is None:
            failures.append(('a pin-consulting rule is not a TaintTracker method', name))
            continue
        arms = [item for item in ast.walk(owner) if isinstance(item, ast.If)
                and 'CWE22_ENTRYPOINT_KEEP_LOUD' in ast.unparse(item.test)]
        if len(arms) != 1:
            failures.append(('the pin arm is not a single If in the deciding predicate',
                             (name, len(arms))))
            continue
        body = arms[0].body
        only_keep = (len(body) == 1 and isinstance(body[0], ast.Return)
                     and isinstance(body[0].value, ast.Constant)
                     and body[0].value.value is constant)
        print(f'  {name}: pin_arm_returns_{constant}_only={only_keep}')
        if not only_keep:
            failures.append(('the pin table must only ever keep a row, never silence one', name))
    method = methods.get('_c22_synthetic_param_source_is_founded')
    if method is None:
        failures.append(('the deciding predicate is not a TaintTracker method', None))
        return failures
    cluster = ['_c22_synthetic_param_source_is_founded', '_c22_module_entrypoint_facts',
               '_c22_statement_runs_at_import', '_c22_expr_is_untrusted_source',
               '_c22_callers_pass_untrusted_value', '_c22_enclosing_def_name',
               '_c22_decorator_leaf', '_c22_dotted_source_is_untrusted']
    banned = ('tests/', 'examples/', 'corpus', 'fn_lower', 'modeling_utils', '.py"',
               'file_paths.get', 'is_test_suite')
    for name in cluster:
        item = methods.get(name)
        if item is None and name not in ('_c22_decorator_leaf', '_c22_dotted_source_is_untrusted'):
            failures.append(('deciding method is gone', name))
            continue
        node = item or next((top for top in tree.body
                             if isinstance(top, ast.FunctionDef) and top.name == name), None)
        if node is None:
            failures.append(('deciding helper is not a module-level function', name))
            continue
        start = node.lineno - 1
        head = node.body[0] if node.body else None
        if (isinstance(head, ast.Expr) and isinstance(head.value, ast.Constant)
                and isinstance(head.value.value, str)):
            start = head.end_lineno
        segment = '\n'.join(lines[start:node.end_lineno])
        for token in banned:
            if token in segment:
                failures.append(('name/path token inside the deciding code', name, token))
    print(f'  token-scanned cluster={cluster}')
    return failures


# --------------------------------------------------------------------------- mutations

BLESSED_LABEL = 'blessed_modeling_utils_pin'
WORKING = {}


def pinned_state(label):
    """Is the synthetic source present on the line this label pins, under the engine as it stands?

    Message-scoped on purpose: the guard decides one emitter's row, and a fixture line can carry a
    second CWE-22 row that belongs to the cascade or a registry sink. Counting rows instead of the
    synthetic message would call a real relabel an unchanged line.
    """
    if label == BLESSED_LABEL:
        module = EXPECTED_PIN_KEYS[0][0]
        source = corpus_source('big8', module)
        found = scan_module(source, module)
        return any(generic_at(found, pin) for _name, pin in EXPECTED_PIN_KEYS)
    if label in BLANKET_BOOKED_ROWS:
        # Presence, not message: see `BLANKET_BOOKED_ROWS`. A booked win is a row HEAD reported under
        # some emitter's label and the successor retires altogether, so the only state a restored
        # blanket can move is "is this module reported at all".
        return bool(scan_module(BLANKET_BOOKED_ROWS[label]))
    line, source = ALL_FIXTURES[label]
    return generic_at(scan_module(source), line)


def _moved(label):
    return pinned_state(label) != WORKING[label]



def _facts_wrapper(drop=(), add_facts=(), attribute_route=False, plain_mixin=False):
    original = _MODULE_FACTS

    def weakened(self, tree):
        facts = set(original(self, tree))
        for name in drop:
            facts.discard(name)
        if attribute_route:
            for node in self._module_nodes(tree):
                if isinstance(node, ast.Attribute) and node.attr in \
                        ast_scanner.CWE22_ROUTE_DECORATOR_LEAVES:
                    facts.add('route_decorator')
        if plain_mixin:
            for node in self._module_nodes(tree):
                if isinstance(node, ast.ClassDef):
                    for base in node.bases:
                        leaf = base.attr if isinstance(base, ast.Attribute) else (
                            base.id if isinstance(base, ast.Name) else '')
                        if leaf.endswith('Mixin'):
                            facts.add('harness_class')
        facts.update(add_facts)
        return frozenset(facts)
    return weakened


def _import_time_accepts_any_binding(stmt):
    return isinstance(stmt, (ast.Assign, ast.Expr, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor,
                             ast.While)) and any(isinstance(sub, ast.Call) for sub in ast.walk(stmt))


_UNTRUSTED_DOTTED = ast_scanner._c22_dotted_source_is_untrusted
_IMPORT_TIME = ast_scanner.TaintTracker._c22_statement_runs_at_import
_MODULE_FACTS = ast_scanner.TaintTracker._c22_module_entrypoint_facts
_REACH = ast_scanner.TaintTracker._c22_callers_pass_untrusted_value
_GUARD = ast_scanner.TaintTracker._c22_synthetic_param_source_is_founded
# The successor's deciding predicate, captured so `open_taint_blanket_restored` can put HEAD's answer
# back and take it off again. It is the only arm in this file that weakens the ENGINE rather than the
# classifier, and it exists because three refusals and two carriers are now booked as THIS rule's win.
_OWES = ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint

MUTATIONS = {
    'guard_removed': {
        'what': 'the guard always agrees, so every library parameter is owed a synthetic source',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_synthetic_param_source_is_founded',
                                 lambda self, tree, fname, filename='', lineno=0: True),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_synthetic_param_source_is_founded',
                                   _GUARD),
        'moves': sorted(EARNED_QUIET),
    },
    'guard_always_false': {
        'what': 'the guard always declines, so entrypoint modules lose theirs too',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_synthetic_param_source_is_founded',
                                 lambda self, tree, fname, filename='', lineno=0: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_synthetic_param_source_is_founded',
                                   _GUARD),
        'moves': sorted(LOUD_BY_FACT),
    },
    'facts_blind_main_guard': {
        'what': 'the `if __name__ == "__main__"` presence fact is dropped',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(drop=('main_guard',))),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['fact_main_guard'],
    },
    'facts_blind_import_time_execution': {
        'what': 'top-level statements that run at import stop being an entrypoint fact',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(drop=('import_time_execution',))),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['fact_import_time_call'],
    },
    'import_time_accepts_any_binding': {
        'what': 'every top-level statement containing a call "runs at import"',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_statement_runs_at_import',
                                 staticmethod(_import_time_accepts_any_binding)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_statement_runs_at_import',
                                   _IMPORT_TIME),
        'moves': ['library_logger_only', 'library_environ_unrelated_to_param'],
    },
    'route_decorator_reads_any_attribute': {
        'what': 'the route leaf is read from any attribute, not only from a decorator',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(attribute_route=True)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['library_dict_get'],
    },
    'harness_base_plain_mixin': {
        'what': 'any `*Mixin` base is a test harness',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(plain_mixin=True)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['library_mixin_base'],
    },
    'facts_blind_web_name': {
        'what': 'a `request`/`socket` name in the module stops being an entrypoint fact',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 _facts_wrapper(drop=('web_name', 'web_module'))),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['fact_web_read_off_request'],
    },
    'caller_reach_blind': {
        'what': 'the reach arm is forced False, so a tainted in-file caller buys nothing',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_callers_pass_untrusted_value',
                                 lambda self, tree, fname: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_callers_pass_untrusted_value',
                                   _REACH),
        'moves': sorted(LOUD_BY_REACH),
    },
    'untrusted_dotted_blind': {
        'what': 'dotted spellings stop counting as remote values (`os.environ` reads as local)',
        'apply': lambda: setattr(ast_scanner, '_c22_dotted_source_is_untrusted',
                                 lambda expr: False),
        'restore': lambda: setattr(ast_scanner, '_c22_dotted_source_is_untrusted',
                                   _UNTRUSTED_DOTTED),
        'moves': ['reach_environ_caller'],
    },
    'keep_loud_table_emptied': {
        'what': 'the exact-identity pin table is emptied under a pure library module',
        'apply': lambda: setattr(ast_scanner, 'CWE22_ENTRYPOINT_KEEP_LOUD', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_ENTRYPOINT_KEEP_LOUD', _PIN_TABLE),
        'moves': [BLESSED_LABEL],
    },
    # The booked win, locked. Forcing the successor's predicate to False is not a weakening of this
    # gate's own rule -- it is HEAD's behaviour with this slice's code in it, the "I cannot prove this
    # safe, so it must be untrusted" blanket the mandate retired. Every row this file re-files as the
    # blanket's win must come back when the blanket comes back, which is what stops a re-file from
    # being a quieting dressed as an argument.
    'open_taint_blanket_restored': {
        'what': 'the retired provenance blanket is restored, so an unproven path sink may report again',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                 lambda self, record, sink: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                   _OWES),
        'moves': sorted(BLANKET_BOOKED_ROWS),
    },
}

_PIN_TABLE = ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD

# 2026-11-10, and it is the same supersession seen from the other side. Four of the arms below falsify
# a classifier clause against an `EARNED_QUIET` row, and since `_c22_open_sink_owes_proven_taint` a
# declined-but-restored synthetic source is no longer sufficient to report: the guard is behind the
# provenance requirement now, so `guard_removed` alone leaves all eight rows quiet and the arms report
# MISSED on a clause that is very much still load-bearing (measured: those arms at HEAD of this round,
# and `scratch/_c22_r3_entrypoint_blanket_arm.py` for what each restored answer costs). Running them
# with the successor's answer forced to HEAD's is the standard two-arm discipline this repository
# already uses for exactly this situation -- see `cwe22_sink_argument_probe`, "the buffer exemption is
# still falsified on its own axis". The ambient blanket is put back BEFORE the baseline is captured, so
# the comparison is still made against the engine as it stands, and it changes nothing about which
# clause each arm weakens: under the ambient answer the shipped guard keeps the row quiet and the
# weakening brings the generic source back, which is the only claim the arm ever made.
# `open_taint_blanket_restored` is deliberately NOT in this set -- it IS the blanket.
_OPEN_TAINT_BLANKET_CONTEXT = ('guard_removed', 'import_time_accepts_any_binding',
                               'route_decorator_reads_any_attribute', 'harness_base_plain_mixin')


def run_mutation(name):
    """Apply one in-memory weakening and check that the rows it should break actually move."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print('  rows that must move: ' + ', '.join(spec['moves']))
    ambient = name in _OPEN_TAINT_BLANKET_CONTEXT
    if ambient:
        print('  context: `_c22_open_sink_owes_proven_taint` answers False, HEAD\'s provenance '
              'rule, so this arm falsifies its own clause and not the successor\'s')
        ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = (
            lambda self, record, sink: False)
    try:
        # The baseline is captured before anything is weakened, so the comparison can never be made
        # against the mutated engine's own answer.
        for label in spec['moves']:
            WORKING[label] = pinned_state(label)
        try:
            spec['apply']()
            outcomes = [(label, _moved(label)) for label in spec['moves']]
        except Exception as exc:
            print('MUTATION ERROR: ' + type(exc).__name__ + ': ' + str(exc))
            print(f'\nFALSIFICATION VERDICT ({name}): ERROR - the mutation is broken, '
                  'so it proves nothing either way (exit 2, not a pass)')
            return 2
        finally:
            spec['restore']()
    finally:
        if ambient:
            ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = _OWES
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
    print('TIER 2 - the 24 blessed lines, asked about at the guard:')
    failures += check_blessed_reach()
    print('TIER 3 - the 25-module fixture truth table, with the deciding arm named:')
    failures += check_fixtures()
    print('TIER 4a - the fact classifier, exact fact sets:')
    failures += check_classifier()
    print('TIER 4b - the untrusted-value test, expression by expression:')
    failures += check_untrusted_expressions()
    print('TIER 4c - Lever 2 join bases and cleanup roots, measured reach:')
    failures += check_join_origins()
    print('TIER 5 - one consult site, before the stamp, pin table can only keep:')
    failures += check_wiring()
    for item in failures[:14]:
        print(f'  !! {item}')
    print(f'\nfixtures={len(ALL_FIXTURES)} earned={len(EARNED_QUIET)} '
          f'superseded_by_open_taint={len(SUPERSEDED_BY_OPEN_TAINT)} '
          f'refiled_refusals_by_open_taint={len(LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT)} '
          f'blanket_booked_rows={len(BLANKET_BOOKED_ROWS)} '
          f'loud_by_facts={len(LOUD_BY_FACT)} loud_by_reach={len(LOUD_BY_REACH)} '
          f'locked_cwe22={sum(CWE22_LOCKED.values())} mutations={len(MUTATIONS)} '
          f'failures={len(failures)}')
    if failures:
        print('VERDICT: FAIL - Slice I no longer matches its measured evidence. Either a blessed '
              'CWE-22 key was declined by the guard, the pin table stopped being load-bearing, a pure '
              'library row came back, an entrypoint or tainted-caller row lost its synthetic source, '
              'the classifier gained an over-broad fact, a Lever-2 refusal came back without the '
              'blanket or a declared root stopped keeping one, or the guard moved off its one consult '
              'site. Restore the answer; never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - 0 of {sum(CWE22_LOCKED.values())} blessed CWE-22 keys declined, '
          f'{len(EARNED_QUIET)} invented sources retired by this rule alone, '
          f'{len(SUPERSEDED_BY_OPEN_TAINT)} of them since retired by the successor open() taint rule, '
          f'{len(LEVER2_REFUSED_RETIRED_BY_OPEN_TAINT)} Lever-2 refusals re-filed and booked against '
          f'that retired blanket, {len(LOUD_BY_FACT)} fact grounds and {len(LOUD_BY_REACH)} reach '
          f'grounds held loud, one consult site and a keep-only pin table confirmed.')
    return 0


if __name__ == '__main__':
    wanted = [arg.split('=', 1)[1] for arg in sys.argv[1:] if arg.startswith('--mutate=')]
    if wanted:
        unknown = [name for name in wanted if name not in MUTATIONS]
        if unknown:
            print(f'BAD MUTATION: {unknown} is not one of {sorted(MUTATIONS)}')
            raise SystemExit(2)
        raise SystemExit(min(run_mutation(name) for name in wanted))
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
