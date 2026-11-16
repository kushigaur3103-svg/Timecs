"""Slice J truth table: when an `open()` in a library module owes a resolved untrusted origin.

Why this gate exists
--------------------
Two mechanisms reported `CWE-22: open` with no taint flow at all. Phase 11 adopts the registry `open`
sink and stamps a synthetic `UNTRUSTED_PATH_TRAVERSAL` -- and its only gate was `_is_safe_path`, so
"not provably safe" was being used as "untrusted". The funnel's `ProvenanceState.UNKNOWN` arm then
appended a 0.50 edge for whatever survived. At HEAD (the d0ef933 engine, snapshotted in
`scratch/_c22_open_head_ast_scanner.py`) the CWE-22 universe holds 359 rows carrying the registry
`open` message and 91 carrying the synthetic generic message, and not one of the 359 is there because
a source was proven -- they are there because nothing ruled the argument out. That is the fallback the
mandate named.

The first revision therefore asked the same question the synthetic-source guard asks -- can this module
be handed a remote value? -- and where the answer was no, the `open()` had to produce a *resolved*
origin instead of borrowing one. Measured, not claimed: the paired full-arena scan
(`scratch/_c22_pair_base_all.json` / `scratch/_c22_pair_live_all.json`, one arm per process, the
candidate arm loaded from `scratch/_c22_open_committed_ast_scanner.py` so nothing the other session
has in this worktree can help or hurt the number) moves **585 -> 481 CWE-22 lines and the whole arena
population 1559 -> 1455 findings: 104 tuples retired, 0 appeared, 0 message churn on surviving lines,
and every per-CWE delta except CWE-22 is zero.** The retired set is 102 `CWE-22: open` rows plus one
`os.open` and one `display.Image.open` -- both reached by the open-family leaf rule, both in modules
that declare no entrypoint -- and **zero** of the 91 generic synthetic rows, which belong to the
sibling gate and stay exactly where they were.
`scratch/_c22_open_retired_split.py` attributes the
retired sinks: 59 of them were carrying a synthetic `p5` `UNTRUSTED_PATH_TRAVERSAL` stamp and 33 were
carried by the UNKNOWN arm alone, and once the stamp is refused 46 resolve to an internal value while
46 come back UNKNOWN with nothing behind them.

The second revision replaced both halves of that basis, and it is the rule this gate now tests
-------------------------------------------------------------------------------------------
The module question was the wrong question in the one direction a precision rule is not allowed to be
wrong in. "This module declares `__main__`" is a fact about the *file*; the mandate is a fact about the
*argument* -- whether a value the operator or the network controls demonstrably reaches this sink. A
module that declares an entrypoint and calls its helper with a compile-time literal was being handed an
assumed-remote value anyway, and a pure library helper that reads `os.environ["CFG"]` two lines below
its definition was being refused one. So the blanket is gone from both sides: `_c22_open_sink_owes_
proven_taint` no longer consults `_c22_module_entrypoint_facts` as a gate, it ends with
`return not self._c22_path_sink_reaches_operator(node, tree)`, and the module facts survive only as
inputs to the walk -- they are how an argparse namespace gets named, never a reason to skip looking.
The scope generalised at the same time: the `FILE_OPEN_FUNCS` test inside the rule was deleted, because
`shutil.rmtree(self.hparams.output_dir)`, `save_json(self.metrics, path)` and a repo helper called with
a bare variable are the same assumption in a different verb. The retired set is now attributed by
clause in the tiers below and by family in `scratch/_c22_r3_floor_census.py`.

The generic emitter is the second half. Round 1 left the 91 `CWE-22: Unvalidated user input or dynamic
variable used in file path operation` rows exactly where they were and told the sibling gate about
them; the mandate then named that emitter as the thing to retire, so the phase-4 short-circuit -- where
that key is stamped onto an adopted or freshly created sink -- is now gated on the same one flag. That
is why this file, and not `cwe22_sink_argument_probe.py`, is where the vocabulary's reach is tested:
all three synthetic arms and the UNKNOWN arm read `c22_open_owes_taint`, and an emitter gated in one
place only and tested in another is a rule nobody can falsify.

What is left, attributed row by row
-----------------------------------
The two dumps the perf work produced (`scratch/_c22_r3_rows_head_final.json` and
`scratch/_c22_r3_rows_final.json`, both regenerated per arm in a fresh process by
`scratch/_c22_universe_arm.py`) are what these numbers come from. In the raw universe the mandate counted,
this round moves **481 -> 144 CWE-22 rows** and the whole arena population **1455 -> 1118 findings**:
338 tuples retired, **1 appeared**, and 0 new message wordings on any line HEAD already reported (the
diff over the two dumps is CWE-22 only -- no other CWE family gained or lost a row). By family, live
against head: `CWE-22: open` 71 against 257, the generic dynamic-variable key 19 against 91, other
filesystem sinks 14 against 33, `os.remove`/`unlink` 9 against 26, `shutil.move`/`copy` 5 against 25,
serializer/helper writers 7 against 19, `shutil.rmtree` 7 against 18, and the archive family
**12 against 12, nothing quieted**.

The one appearing row is `src/transformers/modeling_utils.py:538`, and a retirement rule that adds a
finding has to explain itself: line 538 is `with open(checkpoint_file) as f` inside `load_state_dict`,
whose `checkpoint_file` is a caller-supplied path, and HEAD never reported it. Refusing the synthetic
short-circuit sent that record to the provenance walk, which resolved `param:checkpoint_file` and
produced a CONFIRMED edge; HEAD's cheap arm had pruned the sink without ever walking it. The same file
shows the other direction -- HEAD's `CWE-22: open` row at line 350 sits inside `shard_checkpoint`, a
function with no `open(` call anywhere in its body (350 is a docstring line), and this round retires it.
In the exclusion-configured view a normal scan emits, the pre-bound build measured **258 -> 52** CWE-22
and 658 -> 452 findings total; the bound returns about ten rows there as well and that view has not been
re-measured for this build, so treat 144/1118 as the number this commit ships and 52 as the last measured
configured figure.

Two of those populations are the mandate's own preservation arms and both are arithmetic, not editorial:
the sacred floor is 8 rows at the three sink spellings the mandate names (`zipfile.ZipFile.extractall`
4/4, `tarfile.open` 2/2, `tar_file.extractall` 2/2 -- the prose said six, the arena holds eight) plus 3
`.extract` marker rows, and the 24 blessed CWE-22 keys (16 Big-8 + 8 parity) live outside this arena and
stay 100% emitted, 8 of the Big-8 ones and 1 parity key by the exact-identity pin because their caller is
in another module. A single-digit floor would have to delete those, and the mandate forbids both the
deletion and the other instrument that could reach them -- a path blacklist -- so **the floor is ~35
rows of preserved findings before a single survivor is counted**.

`scratch/_c22_r3_survivor_attribution.py` then answers the only question left: not how many survive, but
**why**, line by line. It walks the arena with the candidate engine, spies the one owed predicate, and
re-derives which arm answered from the shipped helpers -- so the classification is the engine's own
logic, cross-checked by a mismatch counter that must stay at zero. It reads the engine's
`_c22_reach_declines` counter as a delta around each consult, because a walk that ran out of
`CWE22_REACH_VISIT_LIMIT` answers the same True a found root answers and the two must not be merged: a
row held loud because the proof was declined is not a row an operator value reached. All 144 lines land
in five populations:

  * **102 refused:operator_reaches_argument** -- a CLI, `os.environ` or argparse-namespace value
    demonstrably reaches one of the sink's arguments, which is the mandate's condition (a) met on its
    face, module by module, with no entrypoint blanket anywhere in the decision;
  * **16 owed:proof_produced_for_the_sinking_argument** -- the rule demanded a resolved origin and got
    one, and the rows it got one for are CLI command modules (`commands/add_new_model_like.py` carries
    most of the printed sample) rather than library helpers that merely mention one;
  * **14 declined:graph_wider_than_bound** -- loud because the width bound declined to ask, which is
    what the 10 rows this build gives back against the unbounded rule are;
  * **11 refused by the sacred floor** -- 6 `refused:archive_module` and 5 `refused:extract_marker`,
    the whole archive consult population, none quieted (the family split above counts 12 archive-worded
    rows because one of them is held loud by an operator value rather than by the floor arm);
  * **1 never_asked** -- a row another emitter proves on its own flow.

The same run counts the consults the rule *did* retire: 1041 sinks answered `owed:no_resolved_origin`
across the arena, against 159 operator-reachable, 19 too-wide-to-ask, 11 archive, 5 extraction and 1
module-tree-less refusal. That is the shape of the win -- the requirement now applies to everything the
fallback used to cover and is withdrawn only where the mandate, a proof or the width bound says it must
be.

Cost, measured against a control rather than against a hope (round 2)
--------------------------------------------------------------------
`scratch/_c22_open_cost_probe.py` runs three arms in one process, alternating which goes first: HEAD,
this engine, and a control that loads THIS engine with the answer forced to False, which is HEAD's
behaviour with this slice's code in it. The control is what makes the number honest: it does strictly
less work than the shipped rule (it asks the 746 questions and prunes nothing, so it carries all 586
rows) and it measured *higher* than the candidate -- median 36.4s / 90.5 MB against the candidate's
35.6s / 90.0 MB and HEAD's 35.1s / 88.9 MB, with the same process reaching 128 MB on its third arm.
The gap attributable to this slice is therefore ~+0.5s (+1.4%) on the CWE-22 universe and ~1.01x on
the full arena (201.8s -> 203.6s), and `memo_builds=244` in both arms shows the assignment map is not
involved. Absolute RSS is not a usable ceiling on this box: HEAD itself measured 88.9 to 97.7 MB
across runs of the same engine.

Round 3 spends more than that, and where it spends it is not where the profiler said
-----------------------------------------------------------------------------------
The requirement's price is not the reachability walk. Timed without a profiler over the arena's first
40 groups (`scratch/_c22_r3_cost_timers.py`), `_c22_path_sink_reaches_operator` is 1.6s of a 63.8s scan
-- 2.5%. The seconds go to `resolve_path_provenance`, which the walk's answer unlocks on every record
that used to take a synthetic short-circuit. The concentration is extreme: one transformers CLI module
spends 30.1s of its 31.7s scan in there, because 16 top-level resolutions expand to 67,921 nested
provenance frames and 716,891 `resolve_expression` calls (`scratch/_c22_r3_onefile_prof.py`).
`scratch/_c22_r3_cost_split.py` blamed 81s of a 90s delta on `_c22_enclosing_def_name` and its 41,231
module scans; the guard that removes those lookups bought 11s when measured without a profiler, so the
attribution is withdrawn and no latency claim in this round rests on cProfile.

Two ways to pay less were built, measured, and rejected.

  * A per-resolution WORK CAP (2,000 frames; an exhausted walk returns the same `UNKNOWN`/`depth_guard`
    value the existing depth guard returns). It worked on time -- 64.8s to 44.1s per 40 groups -- and it
    took four findings with it: `src/transformers/commands/add_new_model_like.py` lines 521, 1194, 1269
    and 1461, each of which the uncapped walk reports as TAINTED at confidence 1.00
    (`scratch/_c22_r3_cap_rows.py`, `scratch/_c22_r3_cap_probe.py`). The mechanism is worth recording
    because it is HEAD's, not this round's: a cut walk's edge carries `source_id="UNKNOWN"`, and no
    finding materialises from that edge. So "a cut walk is kept loud by
    `_c22_unknown_origin_keeps_the_row`" is true of the flow graph and false of the report, which also
    means the depth guard's own comment -- "can never be reported as proven-clean" -- does not hold at
    the layer that prints. Reverted; the cap is not in the engine.
  * Narrowing the population another way. Path blacklists are forbidden by contract 3, and the arena
    offers no textual door worth opening: 2,847 files, 815 with a filesystem sink, 3 mentioning `click`
    and none spelling a decorator (`scratch/_c22_r3_root_token_skip.py`).

What ships instead bounds the PROOF, not the walk
-------------------------------------------------
`CWE22_REACH_VISIT_LIMIT` gives each sink's reachability consult a node budget -- `ast.walk` steps plus
the bindings it dereferences. A graph wider than the budget makes `_c22_path_sink_reaches_operator`
answer True, which is the same answer a found operator root gives: the record keeps HEAD's synthetic
source and never enters `resolve_path_provenance`. The direction is the whole safety argument, and it is
the difference between this and the cap above -- a decline can only ever keep a row LOUD, so no
suppression is bought with an unfinished proof. `_c22_reach_declines` counts the declines so the
scorecard can tell them apart from real roots instead of silently merging them.

At 4,000 nodes the arena gives back ten of the 134 CWE-22 lines (144) and 10 of the 1,108 rows (1,118),
and both numbers were bit-stable across three runs; `scratch/_c22_r3_reach_limit.py` is the knee-finder
that chose it. Tighter budgets were measured and are worse, not better -- 1,500 and 800 nodes give back
6 and 9 more lines in the first 40 groups and buy no time (43.7s / 43.9s / 44.6s), because the seconds
live in the few widest graphs that 4,000 already declines.

    python scratch/_c22_r3_reach_limit.py 40 4000 1500 800

The latency has to be read as a distribution, not a number, on this box. `scratch/_c22_universe_arm.py`
run alternately on the two engines over the whole 2,847-file arena gave HEAD 240.5s / 243.4s / 369.8s
and this engine 251.4s / 266.3s / 279.2s -- a median ratio of 1.09x against 2.29x before the bound, with
one pair reading 0.68x and another 1.15x while the engine being timed did not change between its own
runs by anything but the OS. Peak RSS followed the same spread (HEAD 85.4-100.8 MB, this engine
83.8-89.4 MB), so HEAD itself crossed the 90 MB line on a run where this engine did not. What is not
noise is the shape: the unbounded rule measured 551.7s against that same HEAD 240.5s, so the bound is
worth ~2x on the arena and it is the reason the ratio is at parity rather than past it.

The committed engine was also verified away from this worktree, because the worktree is shared with
another session's CWE-117 edits and a gate result there cannot be attributed to this commit alone. A
fresh `git worktree` at the commit -- whose `ast_scanner.py` is byte-identical to
`scratch/_c22_open_committed_ast_scanner.py`, which is what every scan above loaded -- gives big8
119/119, parity 425/425, cross-file F1 1.0000 and 42/42 tracked gates. One of those 42 initially
failed only because `cwe22_vocab_serializer_probe` reads its corpus from the gitignored legacy
`scratch/_p3_big/` path, which a fresh worktree does not have; with that directory present it passes.
In this worktree, with the CWE-117 edits in it, the same sweep is 43/43.

Round 3 was verified the same way, on its own checkout: engine 30,421 lines in the worktree and 30,421
in the commit blob, then big8 119/119 (`MISSING=0 NEW=0`, 119 pinned keys), parity 425/425
(`MISSING=0 NEW=0`), cross-file F1 1.0000 with TP=12 / FP=0 / FN=0 and exact-set match YES, and
`SCORECARD: 42/42 PASSED`. 42 rather than 43 for the same reason as last round -- the 43rd gate here is
another session's untracked CWE-117/CWE-208 table probe, which is not in this commit and was not
sneaked in beside it. `python scratch/_c22_r3_fresh_verify.py <commit>` reproduces it.

    python scratch/_c22_r3_fresh_verify.py de07d5f

That harness is worth one confession, because it changes what a green log means. Until this round it
reported a clean run while executing no gates at all: `run()` answers `(code, out)`, and the
`if run([...worktree add...])` guard tested the tuple, which is truthy even when the code is 0 -- so the
script printed `-> exit=0` for the checkout and then returned 1 before the first gate. A second bug sat
behind it: the blob comparison used `text=True` with no encoding, which on this box decodes the engine as
cp1252, kills the reader thread on a UTF-8 continuation byte, and leaves `stdout` as `None` -- an error
that looks like a broken checkout rather than a decode failure. Both are fixed in the harness, and the
numbers above are from the fixed run: a `(code, out)` unpack at the guard and explicit
`encoding='utf-8'` plus `PYTHONIOENCODING` on every child. Neither bug touched the engine or any gate;
they only made the wrapper that runs them lie about having run.

Round 4 breaks the cycle the bound was braking, and the floor it reaches is not the one asked for
----------------------------------------------------------------------------------------------
The round-3 bound left 14 rows loud because their reach walk hit `CWE22_REACH_VISIT_LIMIT` and declined.
The mandate read those declines as a cycle and asked for an intra-traversal visited set. The walk already
had one -- `seen`, an ANCESTRY set -- and that is exactly why it exploded: an ancestry set stops a cycle
but lets the same node be re-walked once per path that reaches it, so a name with dozens of assignments
re-walks its whole subtree once per binding per path. `scratch/_c22_r4_root_kind.py` and a synthetic
12-name cycle measure the shape: 602 budget-exhausted entries over 21 DISTINCT nodes. The fix is a second
set, `done`, that memoises nodes whose exploration COMPLETED with no root, so each is walked once per
consult instead of once per path. It is keyed by the depth budget the answer was proven under (`6 -
depth`): a False proven with `r` levels left is a False with fewer, never with more, so a depth-truncated
answer is only reused where the truncation is at least as early. An in-progress ancestor is never
memoised (it may still find a root on a branch this path could not take) and a budget exhaustion answers
True, so no cut-short walk ever writes a False. The synthetic cycle collapses 602 entries to 62, same
answer; 13 of the 14 arena declines finish, and the one that does not (`modeling_utils.py:3957`, a
blessed-key module) is genuine breadth, not a cycle.

    python scratch/_c22_universe_arm.py head scratch/_c22_r4_rows_head.json all scratch/_c22_r4_head_ast_scanner.py
    python scratch/_c22_universe_arm.py head scratch/_c22_r4_rows_cand.json all scratch/_c22_r4_candidate_ast_scanner.py
    python scratch/_c22_r4_row_diff.py scratch/_c22_r4_rows_head.json scratch/_c22_r4_rows_cand.json

Measured on the whole 2,847-file arena, one process per arm: CWE-22 144 -> 135 (9 retired, 0 appeared),
total 1118 -> 1109, elapsed 283.0s -> 270.1s (0.95x -- the memo pays for itself because it collapses
re-exploration in every walk, not only the declining ones), peak RSS 83.8 -> 85.2 MB. All four protected
CLI rows (`add_new_model_like.py:521/1194/1269/1461`) and all eleven sacred archive/extraction rows are
loud in BOTH arms; big8 119/119, parity 425/425, cross-file F1 1.0000, 43/43 gates.

The second lever the mandate asked for -- prune pseudo-entrypoint reachability on private helpers -- has
no sound target in this arena, and the census is why. `scratch/_c22_r4_survivor_detail.py` dumps all 144
survivors with the innermost def, the module's entrypoint facts and the call edges out of the entrypoint:
of the 116 non-sacred refusals, 90 are PUBLIC defs (57 of them inside `main()` called DIRECTLY by the
`if __name__` block), 7 are module-level, and only 5 are private helpers -- 3 `_download` reached through
a real 3-hop caller chain, 2 `_resumable_file_manager` which are aliased closures (`temp_file_manager =
_resumable_file_manager`), not dead code. The mechanism probe re-asks every refusal with the command-param
table emptied and with the binding hop disabled: ZERO rows depend on the click/command-param blanket the
lever names, 92 roots are real assignment/call-site dataflow ending at a CLI or web root, and 7 are
demonstrated argument roots. So the "module-wide reachability assumption" the lever would prune is not
load-bearing for any surviving row; what keeps them loud is condition (a)/(b) of the original mandate --
a direct CLI argument or a tainted parameter in the entrypoint's caller chain. Withdrawing those refusals
because an edge is not *direct* would discard demonstrated dataflow and silence genuine remote-download
paths (`_download` writes the file `urllib.request.urlopen(url)` returns), which is TP loss, not FP
reduction. The lever is therefore not shipped, and the sound floor under the zero-FN shield is 135, not
the ~35 the arithmetic of the mandate assumed. The 90 public CLI rows are the reason: they cannot be
retired without dropping a finding the shield obligates this engine to keep.

SUPERSEDED, one clause of it: "they cannot be retired" was true of a rule that asked only whether an
operator value reaches the sink. Round 5 asks a second question -- whose operator -- and 44 of the 135
retire on the differential below. The rest of the paragraph stands: the 11 sacred rows, the pins and the
remote-download chains are still not reachable.

Round 5 asks the other half of condition (a), and the floor it reaches is 91
---------------------------------------------------------------------------
Rounds 3 and 4 kept `open(args.output_dir)` loud because a value the operator controls demonstrably
reaches the argument. That is condition (a) read as "an operator value gets here", and the round-4
census is the objection to it: of the 116 non-sacred refusals, 57 sit inside a `main()` that the module's
own `if __name__` block calls, in a file the operator started, from a repository the operator installed.
For that shape the operator is not an attacker -- the operator is the process owner, and a finding that
calls a shell flag a remote vector is the FP the mandate named.

"What is a local program" cannot be answered by the module (that blanket was deleted in round 2), by the
path (`tests/`, `examples/` are forbidden by contract 3), or by an import (`examples/pytorch/.../run_glue.py`
imports `datasets`; so does a web service). So the question is asked of the ARGUMENT, by differential, in
`_c22_sink_root_is_only_the_local_command_line`: run the shipped walk once as written, then again with the
parsed-command-line recognitions switched off -- the argparse namespace table, the `@click` parameter
table, the `parse_args()`/`click.prompt()` operator leaf, and the `sys.argv` / bare `argv` spellings at
the source door (`CWE22_LOCAL_COMMAND_LINE_SPOTS` / `..._NAMES`). Every other door stays open in the
blinded walk: an environment read, a stdin read, an `input()` prompt, a web request, a socket, an
`urlopen`. A row is retired when the first walk finds a root and the second finds none, which is the
statement "nothing but this program's own command line makes this path attacker-chosen" -- and a decline
in the second walk answers True, so the width bound can cost a retirement and can never buy one. The
first walk is re-asked inside the predicate rather than trusted from the funnel, because a rule whose
soundness depends on where it was called from is a rule a later emitter can call from anywhere
(`requirement_always_refused` is what falsifies that premise).

Two refusals bound where the rule does not reach: a harness fact (a `unittest`/`pytest`/`nose`/`absl`
import, a `*TestCase` base, a top-level `def test_`), because a suite is handed paths by whatever runs
it, so its CLI rows keep the standard argument-taint reading -- in this arena that clause holds exactly
one row loud, `utils/add_pipeline_model_mapping_to_test.py:288`, and `local_cli_harness_guard_off` is the
mutation that says so; the blessed keys do not depend on it, because the shield and the two pin tables
refuse those bytes a clause earlier. `TIER 3` proves both halves on the same bytes:
`demoted_local_command_line=8/8` and `same_bytes_under_the_shield=8/8`, one file scanned as `m.py`
(quiet) and as `benchmark/corpus/m.py` (loud).

The argv door is the half that an arena run was needed to find. The first build of this rule reached 68
retirements and stopped: 17 rows survived with `argv_read` in their module facts and a blinded walk that
still found a root. The reason is a SECOND binding of the same name. `run_glue.py:227-234` parses
`training_args` twice -- `parser.parse_json_file(json_file=os.path.abspath(sys.argv[1]))` when the script
gets one `.json` argument, `parser.parse_args_into_dataclasses()` otherwise -- and the assignment map keeps
both, so a walk that consults `training_args` consults the `sys.argv` spelling too. The first blinding
switched off the namespace table, the `@click` table and the `parse_args()`-shaped leaf, and left the
SOURCE DOOR wide open, where `sys.argv` lives. `scratch/_c22_r5_gap.py` on that build's rows file prints
all 17 refusals: 16 `CLI_only` (14 under `examples/**`, 1 `tests/sagemaker/**`, 1
`utils/download_glue_data.py:53`, whose `main(sys.argv[1:])` is the command line handed to a parameter)
plus `utils/notification_service.py:771`, whose root is `arguments = sys.argv[1:][0]` nine hundred lines
earlier and which the census files as unclassified because the hop is a call argument, not a namespace.
Blinding `CWE22_LOCAL_COMMAND_LINE_SPOTS` / `..._NAMES` at the door took all 17: 67 -> 50 rows, 0 appeared.
Every count in this paragraph is the PRE-SOUNDNESS-FIX build's; the shipped floor is 91, and the 41
retirements between the two are the price of the three false negatives named below.

The environment door is left open on purpose. The census prices the choice as far as it can see: exactly
one survivor, `.circleci/create_circleci_config.py:175`, is `OTHER_LOCAL_only` with an environment read as
its only non-command-line root, so closing that door too would retire at least one further row. The
mandate names argv, argparse and click, and an environment variable is written by whoever installed the
service -- a wider audience than the one shell -- which is exception (b) read conservatively. The final
census prices the same choice from the other side: 7 of the 91 survivors refuse at
`unclassified_call:os.getenv` (`examples/research_projects/lxmert/utils.py:364/397` and the `visual_bert`
twins, among them), and environment-fed module constants sit behind more -- `TRANSFORMERS_CACHE` is
`os.getenv("TRANSFORMERS_CACHE", ...)` at `examples/research_projects/lxmert/utils.py:74`, and
`old_default_cache_path` hangs off `torch_cache_home = os.getenv("TORCH_HOME", ...)` at
`src/transformers/utils/hub.py:84`. So one row understates the price rather than setting it, which is a
reason to leave the door open, not to close it.

    python scratch/_c22_r5_build_candidate.py
    bash scratch/_c22_r5_final_chain.sh
    bash scratch/_c22_r5_rss_remeasure.sh
    python scratch/_c22_r5_final_census.py scratch/_c22_r5f1_rows_cand.json

Measured on the whole 2,847-file arena (325 chunks), one process per arm, on the FINAL engine: CWE-22
135 -> 91, total 1109 -> 1065 findings (contract 3's ceiling is 1,602). 44 rows removed, 0 added, every
removed row CWE-22, 0 message churn on any surviving key. The retirement set is byte-identical in all
FIVE pairs that ran these bytes (f1, f2, g1, g2, g3 -- HEAD sorted-rows sha `f7b9b8d0d4261324`, candidate
`3bbaafd2a4702d89`), so it is a rule and not a race.

The 41 retirements this engine does NOT take, and why that is the sound number
------------------------------------------------------------------------------
An earlier build of this rule reached 85 retirements and a floor of 50. That build was UNSOUND, and the
three false negatives it carried are the reason the shipped floor is 91. All three were the same defect:
an early `return True` in the resolved-origin walk that trusted the blinded reach walk to cover a shape
the reach walk never reads. The reach walk resolves NAMES to their bindings; it does not read a callee's
body and it does not look inside a call's arguments. So "the blinding will find the remote root in there"
was false every time it was assumed:

  * **the local-def arm** -- `_c22_call_is_classified_path_call` accepted any function the file defines.
    `def hf_hub_download(repo, name): return requests.get(repo).text` then handed a remote payload to
    `open()` while every argument still spelled the command line, and the row went quiet
    (`scratch/_c22_r5_localdef_probe.py`). The arm is deleted and `_c22_defined_callable_names` with it;
    an unanalysed body is an unknown wrapper, exactly like an imported name no table covers.
  * **the container-reshaper early return** -- `zip`, `list`, `str` and friends returned True without
    descending, so `open(zip(request.args['a'], args.out)[0])` went quiet. 3 of 7 probe shapes hid a
    remote root; now 0 of 7 (`scratch/_c22_r5_reshape_probe.py`). They stay CLASSIFIED as path calls --
    they hand back elements of what they were given -- but the walk descends into their arguments, and
    the descent is load-bearing (`c22_local_cli_reshaper_descent_is_load_bearing`).
  * **the file-parser leaf** -- `CWE22_OPERATOR_ROOT_CALLS` returned True at `parse_json_file` /
    `parse_yaml_file`, skipping the check that table's own comment demands: a config file is "not a trust
    root on its own ... so the chain only clears when the file argument is itself operator-supplied".
    `cfg = parse_json_file(root)` with `root` handed `requests.get(...).text` went quiet
    (`scratch/_c22_r5_parseleaf_probe.py`). The early return is narrowed to `CWE22_OPERATOR_PROGRAM_CALLS`
    (the four `parse_args*` spellings) plus the interactive calls, and the file parsers fall through to
    the descent (`c22_local_cli_file_parser_descent_is_load_bearing`).

Each was found by building a shape where a remote root hides behind the early return and then running a
DEMOTION-OFF attribution arm to prove the demotion owned the silence before changing anything. Reasoning
alone was wrong all three times. The same discipline separates this round's regressions from inherited
reach-walk gaps: `scratch/_c22_r5_tolerant_arms_probe.py` reports 0 holes and 3 gaps that are quiet with
the demotion disabled too (deep chains past the depth budget, an imported constant), so they are charged
to HEAD and not hidden here. The price is 41 retirements -- 85 -> 44 -- and it is paid in full: the rows
that came back are `os.remove`, `pickle_save`, `read_lines`, `add_chinese_references` and
`sort_auto_mapping` sinks whose chains run through a local def or a reshaper. A retirement that hides a
remote root is not a proven retirement, and contract 1 outranks contract 3.

Peak RSS, three fresh same-window pairs, per-chunk traced (`scratch/_c22_r5g{1,2,3}_arm_{head,cand}.log`):
HEAD 81.1 / 82.5 / 88.0 MB, candidate 88.1 / 83.1 / 80.9 MB. Candidate max 88.1 MB, HEAD max 88.0 MB --
both under contract 4's 90 MB line, and the candidate is the LOWER peak in 2 of the 3 pairs. An earlier
pair read 118.4 / 123.6 MB with BOTH arms over the line; that was investigated rather than booked, and it
did not reproduce: the universe was identical (2,847 files, 325 chunks), four orphaned python processes
held 29 MB, and the box was at 82.4% memory. Absolute peak on this box is a property of the window, not
of the engine -- the same HEAD bytes have peaked at 76.3, 88.8, 101.5, 101.9 and 103.1 MB in five
full-arena runs, and the committed sibling gate books a parent peak of 96.6 / 159.8 MB of its own
(`cwe79_latency_gates_probe.py:39`). The rule's own cost is measured rather than inferred:
`scratch/_c22_r5_rss_attrib.py` attributes the arena's largest single-file transient
(`tests/models/markuplm/test_tokenization_markuplm.py`, 216 KB) to the pre-existing per-module analysis,
with the demotion predicate consulted ZERO times in that stretch, plus a steady +1.8 MB for the two facts
it caches on the trees it is asked about.

Latency, the same three pairs, candidate first / HEAD first / candidate first: 242.9 vs 245.7s (0.989x),
261.0 vs 275.6s (0.947x), 279.7 vs 276.9s (1.010x). Pooled 783.6 / 798.2 = 0.9817x, geometric mean
0.9816x. The mandate's <=1.05x holds in 3 of 3 pairs and the pooled ratio is under 1.0x; the strict
per-pair <=1.0x of contract 4 CANNOT be certified from wall time here -- pair 3 came in at 1.010x, and
identical HEAD bytes spanned 238.6-383.4s across windows, a spread larger than the effect being measured.
Counted rather than inferred, the added work is 90 predicate consults per 60 chunks at 2.2 ms each and
0.16% of that arm's wall (`scratch/_c22_r5_pred_counts.log`), and over the arena's tail 35 consults at
3.0 ms and 0.06% (`scratch/_c22_r5_pred_counts_tail.log`).

Nothing else moved: all 11 sacred archive/extraction rows and all four protected
`add_new_model_like.py:521/1194/1269/1461` rows loud in both arms, 43/43 tracked gates, big8 119/119,
parity 425/425, cross-file precision 100.00% / recall 100.00% / F1 1.0000.

The 44 are not examples-only noise, which is what makes the claim safe rather than convenient. By area,
counted off the two rows files at exact (path, line, cwe, message) identity: 27 under `src/`, 12 under
`examples/**`, 5 `utils/**`, over 28 distinct files. All 27 `src/` rows are `convert_*` /
`checkpoint_reshaping_*` weight-import scripts spread over 19 files --
`.../llama/convert_llama_weights_to_hf.py`, `.../mistral/convert_mistral_weights_to_hf.py`,
`.../whisper/convert_openai_to_hf.py` and sixteen more of the same shape -- each carrying `main_guard` +
`cli_module` and a path handed to it by `--model_path`. No library runtime module is touched: `trainer.py`,
`modeling_utils.py` and the generation stack declare no main guard, so the rule never asks them. By
message: 36 `open`, 2 generic "unvalidated user input or dynamic variable used in a file path operation",
and one apiece of `shutil.rmtree`, `gzip.open`, `os.unlink`, `compress_file`, `shutil.copytree` and
`clean_doctest_list` -- the mandate's own list of "standard file I/O", reached through the sink vocabulary
rather than a name test.

91 is not the ~11-15 the mandate's arithmetic expected, and `scratch/_c22_r5_final_census.py` names the
refusal that keeps EVERY one of the 91 loud (attributed=91 of 91, `scratch/_c22_r5f_census.log`). The
census mirrors the demotion's refusal ladder in order and labels each surviving row by the first clause
that stops it:

  * **11 the sacred floor** -- 6 `SACRED_archive_constructor` + 5 `SACRED_archive_extraction`, all loud,
    none quieted. This is the mandate's target and it is intact;
  * **35 `unclassified_call:<leaf>`** -- the resolved-origin walk refuses at a call no table classifies.
    Named leaves, with counts: `os.getenv` 7, `get_git_info` 4, `Config.load_yaml` 2, `datasets.map` 2,
    `variation.replace` 2, `aws_model_maps.keys` 2, `glob.glob` 2, `os.listdir` 2, and one apiece of
    `os.getcwd`, `predict_dataset.remove_columns`, `pop`, `get_model_files`, `tokenizer.save_pretrained`,
    `hf_hub_download`, `test_dataset.remove_columns`, `to_create.items`, `get_tasks`, `artifacts.items`,
    `retrieve_available_artifacts`, `sort_auto_mapping`. These are the next sound lever, and they are not
    one lever: dict views (`.keys`/`.items`/`pop`), `str.replace` and filesystem enumeration
    (`glob.glob`/`os.listdir`/`os.getcwd`) are reshapers or local-only reads a table could carry, while
    `hf_hub_download`, `get_git_info` and the `datasets` transforms are remote fetches or unanalysed
    bodies that MUST stay refused. `os.getenv` is the clearest case of a refusal that buys nothing:
    classifying it would let the chain resolve and the blinded walk would then find the environment root
    and keep the row loud anyway;
  * **11 `no_operator_root_reaches`** -- the positive half asked inside the predicate found no root at
    all, so there is nothing for the differential to retire. These are the round-3/4 proven-taint rows
    (`add_new_model_like.py:521/885/927/1194` among them);
  * **10 `no_entrypoint_fact`** -- a pure library module nobody in the file hands a value to is not a
    program, so its path was not chosen at a command line this file owns
    (`feature_extraction_utils.py:524`, `image_processing_utils.py:362`, `modeling_utils.py:3957`, ...);
  * **9 `unresolved_other`** -- the chain is refused at a non-call link;
  * **8 `dishonest_namespace`** -- `args` 6, `training_args` 2: a holder read that fails the all-bindings
    namespace proof, i.e. the name was rebound to something that is not a parsed command line. This is
    the soundness conjunct doing its job, not a gap;
  * **3 `harness_module`** -- `tests/test_pipeline_mixin.py:113`,
    `tests/utils/test_add_new_model_like.py:94`, `utils/add_pipeline_model_mapping_to_test.py:288`. A
    suite is handed paths by whatever runs it, so its CLI rows keep the standard argument-taint reading;
  * **3 `record_not_reproduced_solo`** -- the row does not reappear when its file is scanned alone, so
    the census cannot attribute it and says so rather than guessing;
  * **1 `remote_or_other_root_survives_blinding`** -- `.circleci/create_circleci_config.py:175`, whose
    only non-command-line root is an environment read.

So the mandate's premise -- "the 124 surviving non-sacred rows are pure FPs caused by local CLI flags" --
is not what the arena measures. 44 of the 124 were CLI-only and are retired; the other 80 are rows whose
root is not this program's command line, or whose chain the engine cannot resolve soundly. Collapsing to
~11 would mean retiring 11 rows that carry a real proof, 10 library rows with no entrypoint, 8 dishonest
namespace reads and 35 unclassified calls -- of which the remote fetches and unanalysed bodies are FN
loss, not FP reduction. The honest next step is the named subset of the 35 that is genuinely a reshaper
or a local-only read, priced and probed one table entry at a time, not a wider blanket.

Mandate item 3 -- "for paths that exceed visit limits, resolve deterministically to SAFE" -- is the one
specification item deliberately not shipped. It is a single row in this arena (`DECLINED_at_bound`), and
its cost is the design of the bound: `CWE22_REACH_VISIT_LIMIT` answers True on exhaustion precisely so a
walk that ran out of budget can never be read as a clean proof. Turning the decline into SAFE makes every
future budget exhaustion a suppression, and `scratch/_c22_r4_*` measured that the declines are genuine
breadth (one `modeling_utils.py:3957` consult that no memo can shorten). One FP is not worth an
instrument that can silently grow.

One deciding site, and it can only subtract
------------------------------------------
`c22_open_owes_taint` is computed once per funnel record, strictly before any collector's synthetic
source can attach an edge -- the same placement discipline the CWE-78 execve guard uses, for the same
reason: a future emitter cannot register an `open()` finding that escapes the answer. The flag does
not resolve anything itself. It removes the right to short-circuit (both synthetic arms) and then
declines at the UNKNOWN arm, where it **only ever removes a sink**. A TAINTED answer, a STATIC answer
and any resolution that is cut short fall through to exactly the answer they already had, so no row
can appear and no message can change. TIER 5 pins that shape structurally: one assignment, two gated
short-circuits, a prune arm containing no `edges.append`.

What refuses the requirement -- and why each refusal is load-bearing
-------------------------------------------------------------------
Every refusal is in the keep-loud direction, and every one is falsified below by a mutation that
must move the rows it guards:

  * **a node that is not a call** -- `with` targets, cascade messages and attribute-only records keep
    the answer they always had. The second revision's scope is sink *calls*; widening it to every
    record that carries a CWE-22 label reached shapes no sink vocabulary owns, and the arena rows that
    proved it are the ones `cwe22_sink_argument_probe.py` still pins;
  * **an archive constructor or extraction** -- `tarfile.open` shares the `open` leaf with the builtin,
    and Zip-Slip is a finding about the archive, not about who chose the path. Pinned at the predicate
    for both the dotted and the `import tarfile as tf` spelling (a leaf-name test would miss the alias),
    and for the `extractall`/`extract` marker too: once the rule stopped testing for an open-family
    leaf, `extractall` was inside its scope, so this is the arm that keeps the floor loud rather than a
    side effect of the rule looking elsewhere. `archive_table_emptied` and
    `requirement_always_applied` are what falsify the two halves;
  * **an argument that demonstrably carries an operator value** -- `open(args.csv_file)` in a script,
    `shutil.rmtree(options.out_dir)` after a real `parse_args()`, `open(os.environ["CFG"])`. This
    replaces the entrypoint-declaration blanket, and it is asked in every module rather than only in
    the ones that declare facts: the mandate's condition (a) is a property of the value, and the
    measured rows each recognition arm decides are the `LOUD_BY_TRACE_*` tiers below;
  * **the exact-identity pins** -- 8 of the 16 Big-8 CWE-22 keys and 1 of the 8 parity keys are harness
    or library rows whose caller lives in another module, which no intra-file proof can ever see, and
    the frozen baselines own them. The harness rows are kept by pinning, never by a blanket: a
    declaration that happens to be load-bearing is a rule, and a basename that happens to be load-
    bearing is a debt, so `open_pin_table_emptied` names every row that dies with the table and
    `scratch/_c22_pin_bearing.py` proves the table carries no decorative entry;
  * **three UNKNOWN flavours that are not "nothing reached here"** -- a walk cut short by the depth or
    cycle guard, a walk that landed on a directory enumeration, and a walk that landed on an
    untrusted-source spelling. The last of these was found by this gate, not by the arena:
    `open(os.environ["CFG"])` and `chosen = os.environ["CFG"]; open(chosen)` answer UNKNOWN because the
    resolver gives up on a subscript, so a rule that demanded the TAINTED label would have retired a
    real operator-controlled path. Condition (a) of the mandate is met on its face there.

Collateral: the gates whose carriers were the blanket
---------------------------------------------
Because this rule answers before the synthetic arms, tracked gates lost carriers whose only loudness
basis was the fallback itself. Each was repaired one of two ways, and neither is a loosened expectation.

**Earned** -- the fixture is re-spelled so a resolved origin genuinely reaches a sink argument, and the
proposition it asserts keeps its original words: `mechanism_pitch_probe`'s `param_path_open` now calls
its helper with `read_it(sys.argv[1])`, `workflow_controls_probe`'s `CONFIG_TRAV` with
`load(sys.argv[1])`, `cwe117_cwe22_unknown_source_probe`'s writer with `save(sys.argv[1], ...)`,
`cwe22_sink_argument_probe`'s two buffer rows through a caller that hands in a request value,
`active_partition_probe`'s resolver and runtime-mode carriers with argv-fed call sites, and
`cwe22_value_origin_probe`'s carriers with `sys.argv[2]` in the argument *beside* the path -- the reach
test is argument-wide and therefore fail-closed, which is precisely why naming a CLI value somewhere in
the file buys nothing.

**Re-filed** -- the fixture's proposition IS the retired blanket, so there is nothing to earn without
deleting what the row claims: those rows move to their measured quiet value inside a named table
(`BLANKET_RETIRED_ROWS`, `C22_BLANKET_RETIREMENT`, `SILENT_REFUSED_ROWS`, `REFILED_QUIET`) and the win
is locked by a mutation that hands the retired blanket back
(`_c22_open_sink_owes_proven_taint` -> False), which must move exactly those rows and no others. Both
directions are asserted, not argued: a booked row that does not come back under the restored blanket was
credited to the wrong clause, and an unbooked quiet row that does come back means a supersession landed
in that table unfiled. This is how `cwe22_repo_anchor_path_probe` re-files `kwargs_slot` (1 of its 42
shapes, with its anchor veto re-pinned at the predicate so the guard still loses its tripwire),
`cwe22_pil_tempfile_probe` three seal rows plus the bare-import pair, `cwe22_param_caller_probe` twelve
of fifteen refusals, `cwe22_blindspot_origin_probe` the splat / `**kwargs` / no-caller / skipped-arg
shapes, and `active_partition_probe` five blanket spellings.

Which of the two applies was decided by measurement, not by preference:
`scratch/_c22_walk_resolution_grid.py` enumerates the origin spellings the shipped walk does resolve
(`sys.argv`/`os.environ` inline and through one assignment, `os.path.join("/srv", sys.argv[1])`, module
constants and rebinds, a helper parameter called with argv, `shutil.rmtree(options.out_dir)` after a
real `argparse` namespace) and the shapes it does not (an empty `**kwargs` slot no caller fills, a splat,
a skipped positional, a `self.` field written in another frame, an f-string into a local). A row whose
only missing proof is a spelling the walk cannot see is a re-filing; a row that was only ever loud
because nobody asked can be earned. Nothing was deleted, no blessed-key check moved, and no path or
folder was blacklisted -- `scratch/_c22_r3_seal_remeasure.py` and `scratch/_c22_r3_engines.py --diff`
produce the per-row evidence each of those tables now asserts.

Two real bugs surfaced on the way and are fixed in the gates, not excused: `cwe22_sink_argument_probe`
appended `.py` to a label that already ended in `.py`, so it scanned `test_v06_bad.py.py` -- harmless
while its shapes were loud on their own and a lost blessed key the moment a rule keeps a row by exact
identity, because `CWE22_OPEN_TAINT_KEEP_LOUD` is keyed on `basename(file)`.

Usage
-----
    python benchmark/gates/cwe22_open_taint_probe.py
    python benchmark/gates/cwe22_open_taint_probe.py --mutate=<name>

Twenty-one weakenings are pinned below, four of them added by the local-command-line rule. Per Harness
Law 8 each must move the row its clause decides,
and the rows each one claims were read off `scratch/_c22_blind_matrix.py` and
`scratch/_c22_flavour_only.py` rather than off a theory of which clause ought to decide: two of the
engine's remote-source arms are the same predicate, so a blind that switches it off moves rows the
walk and the exemption each guard on their own, and a blind that switches off only one of them moves
neither. The tripwire is line-scoped and message-scoped, because a fixture line can carry a CWE-22 row
that belongs to another emitter.
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
OPEN_MSG = 'CWE-22: open'
CWE22_LOCKED = {'parity': 8, 'big8': 16}
BASELINE_TOTALS = {'parity': 424, 'big8': 119}
# Every identity the rule is allowed to keep loud by pinning rather than by proving. Spelled out here
# because a pin is a suspension of the rule, and a suspension nobody can count is a rule that has been
# quietly deleted; `open_pin_table_emptied` and `check_blessed_loud` are what make each row below earn
# its place. The `vendor/...` and leaf spellings are not duplicates -- `active_partition_probe` tier 9
# re-vendors blessed lines under paths where the corpus-name shield cannot reach, so the same key has
# to be pinned under every basename the scans actually carry.
EXPECTED_OPEN_PINS = [
    # The two `open()` rows this rule met first, in both their corpus and leaf spellings.
    ('src__transformers__trainer.py', 4301), ('trainer.py', 4301),
    ('modeling_utils.py', 336), ('modeling_utils.py', 3564),
    # Harness rows: the path names a fixture directory the runner chose two frames above the sink, so
    # condition (b) has no in-file call site to trace. Eight keys, three files.
    ('tests__generation__test_utils.py', 5537), ('tests__generation__test_utils.py', 5539),
    ('tests__generation__test_utils.py', 5565),
    ('tests__models__markuplm__test_tokenization_markuplm.py', 73),
    ('tests__models__markuplm__test_tokenization_markuplm.py', 75),
    ('tests__models__markuplm__test_tokenization_markuplm.py', 77),
    ('tests__test_tokenization_mistral_common.py', 263),
    ('tests__test_tokenization_mistral_common.py', 274),
    ('tests__test_tokenization_mistral_common.py', 280),
    # A read of a file located by `inspect.getfile(...)`.
    ('tests__test_modeling_common.py', 1279),
    # Library deletes whose target is an entry of a directory listing or a weight map: a resolved
    # origin, but one the resolver gives up on at the subscript.
    ('src__transformers__modeling_utils.py', 3494), ('src__transformers__trainer.py', 2008),
    # The vendored spellings of every row above that tier 9 re-vendors.
    ('tok.py', 73), ('tok.py', 75), ('tok.py', 77),
    ('tok.py', 263), ('tok.py', 274), ('tok.py', 280),
    ('modeling_utils.py', 3494), ('trainer.py', 2008),
    ('test_utils.py', 5537), ('test_utils.py', 5539), ('test_utils.py', 5565),
    ('modeling_common.py', 1279),
    # The three parity CWE-22 keys the generic-fallback retirement reaches: two corpus rows whose
    # only call site passes a compile-time literal, and the harness's own corpus read, whose path
    # crosses a method on a class declared in another module.
    ('test_v06_bad.py', 6), ('test_v06_good.py', 7), ('runner.py', 105),
]
# The blessed rows the leaf spellings exist for: `active_partition_probe` re-vendors every blessed
# line under `vendor/...`, where the corpus-name shield cannot help.
VENDORED_BLESSED = [('src__transformers__trainer.py', 'vendor/transformers/trainer.py', 4301),
                    ('src__transformers__modeling_utils.py',
                     'vendor/transformers/modeling_utils.py', 336)]

READ = '    with open({arg}) as handle:\n        return handle.read()\n'
WRITE = '    with open({arg}, "w") as handle:\n        handle.write(payload)\n'
PURE = 'src/library.py'


def module(*lines):
    return ''.join(line + '\n' for line in lines)


# A 56-deep aliasing chain, written so every name is assigned before it is read: the resolver walks
# it until the depth guard stops it, which is the only spelling that reaches `depth_guard` in a
# single function.
DEPTH_CHAIN = (module('def load(payload):',
                      *('    p%d = p%d' % (i, i + 1) for i in range(55, -1, -1)),
                      '    with open(p0, "w") as handle:', '        handle.write(payload)'))

# --------------------------------------------------------------------------- earned: loud at baseline, quiet now
# The first six were measured against `git show d0ef933:ast_scanner.py`, the snapshot Slice J shipped
# from (`scratch/_c22_open_taint_measure.py`). The rest are this round's, measured against the
# committed engine by `scratch/_c22_gate_refile.py`, which prints `head=` and `live=` for every label
# from the two engines side by side: `RETIRED` means a row existed at HEAD and does not exist now, and
# nothing in that class is filed here unless it printed RETIRED. Three groups, because the mandate
# retired them for three different reasons: the sink family was never open(), the module fact was
# standing in for a value, and the generic emitter invented the value outright.
EARNED_QUIET = {
    'write_mode_param': (2, module('def dump(slot, payload):', WRITE.format(arg='slot'))),
    'append_mode_param': (2, module('def dump(slot, payload):',
                                    '    with open(slot, "a") as handle:',
                                    '        handle.write(payload)')),
    'aliased_param': (3, module('def dump(slot, payload):',
                                 '    chosen = slot', WRITE.format(arg='chosen'))),
    'join_with_param_base': (3, module('import os', 'def dump(slot, payload):',
                                       WRITE.format(arg='os.path.join(slot, "index.json")'))),
    'operator_namespace': (2, module('def dump(options, payload):',
                                     WRITE.format(arg='options.output_dir'))),
    'module_global_from_opaque_call': (3, module('def dump(payload):',
                                                 '    CHOSEN = resolve_target()',
                                                 WRITE.format(arg='CHOSEN'))),
    # Morcha 2 item 1: the same assumption in a different verb. These two rows are the whole reason
    # `REFUSED_NOT_OPEN_FAMILY` used to exist -- the scope used to stop at `open()`, so a delete was
    # never asked and always reported.
    'delete_os_remove': (3, module('import os', 'def clean(slot):', '    os.remove(slot)')),
    'delete_shutil_rmtree': (3, module('import shutil', 'def clean(slot):',
                                       '    shutil.rmtree(slot)')),
    # Morcha 1's own item: a module-level fact is not a value. All three of these were refused at HEAD
    # because the module declared something; the question is now asked of the argument, and the
    # argument is an unfilled parameter. The rows that keep their finding are in `LOUD_BY_TRACE_*`.
    'fact_main_guard': (2, module('def dump(slot, payload):', WRITE.format(arg='slot'),
                                  'if __name__ == "__main__":', '    dump("cfg.json", "x")')),
    'fact_cli_argparse': (3, module('import argparse', 'def dump(slot, payload):',
                                    WRITE.format(arg='slot'),
                                    'options = argparse.ArgumentParser().parse_args()')),
    'fact_harness_class': (4, module('import unittest', 'class Case(unittest.TestCase):',
                                     '    def test_dump(self, slot, payload):',
                                     '        with open(slot, "w") as handle:',
                                     '            handle.write(payload)')),
    # Morcha 2 item 2: the generic dynamic-variable emitter. This is the exact spelling of the three
    # parity keys the engine had to be pinned for (`benchmark/corpus/cwe_937_insecure_protocol/
    # test_v06_bad.py:6` and `:7` good, and `benchmark/runner.py:105`) -- a web framework or an
    # import-time call somewhere in the module, and a helper parameter nobody in the file fills with a
    # import-time call somewhere in the module, and a helper parameter nobody in the file fills with
    # a request value.
    'generic_fallback_uncalled_helper': (4, module('from flask import request', 'import os',
                                                   'def read_doc(path):',
                                                   '    with open(path, "r", encoding="utf-8") as handle:',
                                                   '        return handle.read()',
                                                   'def other(key):',
                                                   '    return request.args.get(key)')),
}

# --------------------------------------------------------------------------- kept: condition (a) met
# The four spellings below read a source the engine already trusts by name -- `sys.argv`, a web
# request, `input()`, `os.getenv` -- so each is loud with or without the argument-wide trace and with
# or without the UNKNOWN exemption (measured: `trace_blind` and `flavour_blind` each leave all six
# standing, `scratch/_c22_trace_arms2.py`). They are filed where a row's contract is "loud, and not
# booked as an UNKNOWN flavour", and each one's refusal is pinned at the predicate in
# `CONSULT_PINNED`. Claiming them for the trace would credit a clause that is not load-bearing.
LOUD_BY_PROVEN_TAINT = {
    'input_direct': (2, module('def load():', READ.format(arg='input("path? ")'))),
    'input_local': (3, module('def load():', '    chosen = input("path? ")',
                              READ.format(arg='chosen'))),
    'getenv_call': (3, module('import os', 'def load():', READ.format(arg='os.getenv("CFG")'))),
    'request_inline': (3, module('from flask import request', 'def view():',
                                 READ.format(arg='request.args["f"]'))),
    'request_into_helper': (3, module('from flask import request', 'def load(slot):',
                                      READ.format(arg='slot'),
                                      'def view():', '    return load(request.args["f"])')),
}

# --------------------------------------------------------------------------- kept: the three UNKNOWN flavours
LOUD_BY_CUT_SHORT = {
    'circular_self_alias': (3, module('def dump(slot, payload):', '    slot = slot',
                                       WRITE.format(arg='slot'))),
    'depth_guard_chain': (58, DEPTH_CHAIN),
}
LOUD_BY_DIRENT = {
    'glob_multi_component': (4, module('import glob', 'def h():',
                                        '    for p in glob.glob("/srv/*/*"):', '        open(p)')),
    'iglob_component': (4, module('import glob', 'def h():',
                                   '    for p in glob.iglob("/srv/*"):', '        open(p)')),
    'glob_write_mode': (4, module('import glob', 'def h():', '    for p in glob.glob("/srv/*/*"):',
                                   '        with open(p, "w") as handle:',
                                   '            handle.write("x")')),
    # The flavour arm reaches the generalized sinks too: the verb here is a delete and the path names a
    # directory entry, so this is the mirror image of `delete_os_remove` in `EARNED_QUIET` -- the same
    # sink family, and the only thing that differs is that something really did name the path. Measured
    # as the delete shape that the dirent flavour actually still decides (`scratch/_c22_flavour_rows.py`
    # prints `owed=True flavours=['dirent'] row=(4, 'CWE-22: os.remove')`); the `os.scandir` spelling
    # with `entry.path` is not one of them -- the attribute of a loop target is never resolved to the
    # enumeration, so that shape owes its proof and goes quiet, which is the same answer
    # `scandir_path_removed` gets in that measurement.
    'glob_removed': (4, module('import glob', 'def clean():', '    for p in glob.glob("/srv/*/*"):',
                               '        os.remove(p)')),
}
LOUD_BY_UNTRUSTED_ORIGIN = {
    # Each shape below was measured (`scratch/_c22_flavour_only.py`) to move when ONLY this clause is
    # switched off: the sink still owes its proof, because the argument-wide walk stops at the helper
    # call / the concatenation / the subscript and does not climb through them, and the provenance
    # resolver does land on the environment read. The inline spellings of the same value --
    # `open(os.environ["CFG"])` and one local binding away -- are refused a requirement outright, so
    # they are filed with the trace (`LOUD_BY_TRACE_AND_FLAVOUR`) and may not be booked here.
    'helper_returns_environ': (5, module('import os', 'def pick():', '    return os.environ["CFG"]',
                                         'def load():', READ.format(arg='pick()'))),
    'helper_returns_argv': (5, module('import sys', 'def pick():', '    return sys.argv[1]',
                                      'def load():', READ.format(arg='pick()'))),
    'concat_environ': (3, module('import os', 'def load():',
                                 READ.format(arg='"/srv/" + os.environ["CFG"]'))),
    'list_index_environ': (4, module('import os', 'def load():',
                                     '    paths = [os.environ["CFG"]]',
                                     READ.format(arg='paths[0]'))),
}

# --------------------------------------------------------------------------- refused: the argument traces
# The mandate's condition (a) and (b) asked of the arguments rather than of the module, and each table
# below is one recognition arm with a mutation that moves exactly its own rows (`operator_root_calls_blind`,
# `cli_command_params_blind`, `caller_hop_blind`, `trace_remote_arm_blind`). Every one of these shapes
# sits in a module whose own facts cannot answer for it -- `fact_main_guard`, `fact_cli_argparse` and
# `fact_harness_class` below are the same modules with the value removed -- so a row here is loud
# because a specific command-line or remote value was found in a specific argument.
#
# Round 5 changed what a command-line row costs. `QUIET_BY_LOCAL_COMMAND_LINE` holds the six shapes
# that used to be booked here: the walk still finds their root, which is why they still answer
# `owed=False`, but a second, command-line-blinded walk shows that root is the ONLY root, and the sink
# is then removed. The two tables below keep the arms' evidence alive by putting a refusal between the
# demotion and the row, so each arm is still measured to decide a finding rather than merely an answer.
QUIET_BY_LOCAL_COMMAND_LINE = {
    'argparse_field_direct': (3, module('import argparse', 'def dump(options, payload):',
                                         WRITE.format(arg='options.output_dir'),
                                         'options = argparse.ArgumentParser().parse_args()',
                                         'dump(options, "x")')),
    'argparse_field_one_hop': (3, module('import argparse', 'def dump(slot, payload):',
                                         WRITE.format(arg='slot'),
                                         'options = argparse.ArgumentParser().parse_args()',
                                         'dump(options.output_dir, "x")')),
    'argparse_via_caller_namespace': (3, module('import argparse', 'def load(slot):',
                                                READ.format(arg='slot'),
                                                'options = argparse.ArgumentParser().parse_args()',
                                                'load(options.path)')),
    # Morcha 2 item 1's own evidence: a delete, kept loud by nothing but the command line behind it.
    # Round 5 retired it -- the operator who typed `--output-dir` is the process owner, not a remote
    # caller -- and `c22_local_cli_demoted_refused` is what proves the delete is still in scope.
    'rmtree_argparse_one_hop': (4, module('import argparse', 'import shutil', 'def clean(slot):',
                                          '    shutil.rmtree(slot)',
                                          'options = argparse.ArgumentParser().parse_args()',
                                          'clean(options.output_dir)')),
    'click_option_direct': (5, module('import click', '@click.command()',
                                      '@click.option("--model_dir")', 'def cli(model_dir):',
                                      '    with open(model_dir, "w") as handle:',
                                      '        handle.write("x")')),
    'click_option_into_helper': (3, module('import click', 'def run(slot):',
                                           '    with open(slot, "w") as handle:',
                                           '        handle.write("x")',
                                           '@click.command()', '@click.option("--model_dir")',
                                           'def cli(model_dir):', '    run(model_dir)')),
    # The two rows the mandate's own words put in this class -- "an argument originating from sys.argv,
    # argparse, or click does NOT constitute an untrusted path traversal source for standard file I/O
    # (open, save_json, shutil.rmtree, os.remove)". They used to be filed as proven taint, and the
    # `proven_argv_direct` / `proven_copy_argv` refusal pins still book the ANSWER the owed rule gives
    # for them, so nothing here says the walk stopped recognising a command line: it says the command
    # line alone is no longer enough to call a local program's own path attacker-chosen. In the arena
    # the shipped rule retires 44 rows -- 27 `src/`, 12 `examples/**`, 5 `utils/**` over 28 files
    # (`scratch/_c22_r5f1_rows_{head,cand}.json`, exact-row diff), so this class is not examples-only.
    'argv_direct': (3, module('import sys', 'def load():', READ.format(arg='sys.argv[1]'))),
    'copy_from_argv': (4, module('import sys', 'import shutil', 'def ship(dst):',
                                 '    shutil.copy(sys.argv[1], dst)')),
}
LOUD_BY_TRACE_COMMAND_LINE = {
    # The same bytes as `argparse_field_direct`, plus one `import unittest` (and the sink line that
    # shift takes it to 4). Nothing about the value changed -- the harness fact is what stands between
    # this row and the demotion, because a test suite is handed paths by whatever runs it, not by the
    # person at the terminal. `local_cli_harness_guard_off` is the falsification.
    'harness_argparse_direct': (4, module('import argparse', 'import unittest',
                                          'def dump(options, payload):',
                                          WRITE.format(arg='options.output_dir'),
                                          'options = argparse.ArgumentParser().parse_args()',
                                          'dump(options, "x")')),
}
LOUD_BY_TRACE_COMMAND_DECORATOR = {
    # The command-decorated parameter in a harness module: the arm is still what makes the row loud,
    # and the harness fact is still what stops the demotion from taking it back down.
    'harness_click_direct': (6, module('import click', 'import unittest', '@click.command()',
                                       '@click.option("--model_dir")', 'def cli(model_dir):',
                                       '    with open(model_dir, "w") as handle:',
                                       '        handle.write("x")')),
}
LOUD_BY_TRACE_REMOTE_HOP = {
    'caller_passes_environ': (3, module('import os', 'def read_doc(path):',
                                        '    with open(path, "r", encoding="utf-8") as handle:',
                                        '        return handle.read()',
                                        'def load():', '    return read_doc(os.environ["CFG"])')),
}
# --------------------------------------------------------------------------- kept loud twice over
# These three are refused by the walk (so they belong with the trace tables) and would also be saved
# by the UNKNOWN exemption if the walk were switched off, because the flavour's predicate is the same
# `_c22_expr_is_untrusted_source` the walk calls. Measured in `scratch/_c22_blind_matrix.py`: blinding
# `_c22_path_sink_reaches_operator` leaves all three LOUD and owed (the flavour picks them up), and
# blinding the flavour alone leaves them LOUD and refused, so no single-clause blind may claim them
# except the shared predicate itself. That is why they are not in `LOUD_BY_TRACE_SOLO`, whose rows move
# for the trace alone, and why `whole_trace_blind` does not list them.
LOUD_BY_TRACE_AND_FLAVOUR = {
    'environ_inline': (3, module('import os', 'def load():', READ.format(arg='os.environ["CFG"]'))),
    'environ_local': (4, module('import os', 'def load():', '    chosen = os.environ["CFG"]',
                                READ.format(arg='chosen'))),
    'environ_write_mode': (4, module('import os', 'def dump():', '    chosen = os.environ["CFG"]',
                                     WRITE.format(arg='chosen'))),
}

# --------------------------------------------------------------------------- refused: the rule never attaches
REFUSED_BY_ARCHIVE = {
    'tarfile_open_dotted': (4, module('import tarfile', 'def unpack(slot, dest):',
                                      '    with tarfile.open(slot) as archive:',
                                      '        archive.extractall(dest)')),
    'tarfile_open_alias': (4, module('import tarfile as tf', 'def unpack(slot, dest):',
                                     '    with tf.open(slot) as archive:',
                                     '        archive.extractall(dest)')),
    'zipfile_extractall': (4, module('import zipfile', 'def unpack(slot, dest):',
                                     '    with zipfile.ZipFile(slot) as archive:',
                                     '        archive.extractall(dest)')),
}
# --------------------------------------------------------------------------- owed, and never reported
# These four verbs never produced a row at either baseline, so this rule cannot book them as
# retirements; what they prove is the *scope*, at the predicate -- the requirement attaches to a
# delete, a move, a copy and a repo helper writer exactly as it attaches to `open()`. `consult_owed`
# reads the answer the shipped rule gives for each line.
SCOPE_NON_OPEN_SINKS = {
    'scope_shutil_copy': (3, module('import shutil', 'def ship(src, dst):',
                                    '    shutil.copy(src, dst)')),
    'scope_shutil_move': (3, module('import shutil', 'def ship(src, dst):',
                                    '    shutil.move(src, dst)')),
    'scope_shutil_copytree': (3, module('import shutil', 'def ship(src, dst):',
                                        '    shutil.copytree(src, dst)')),
    'scope_os_rmdir': (3, module('import os', 'def clean(slot):', '    os.rmdir(slot)')),
}

# A `with`-target, a cascade message and an attribute-only record are not calls, so the requirement
# must refuse them and no message-shaped record can be moved by this rule. That refusal is decided at
# the predicate, on a record built around a non-call node, in TIER 4a.

# --------------------------------------------------------------------------- quiet, and NOT this rule's
# Quiet at HEAD and quiet now: an older clause already proved these clean, so this slice may not book
# them. Filed here so a later revision cannot claim them, the way the sibling gate files its
# inherited rows. `self_field` above was moved out of this table when it measured as earned.
QUIET_BY_OTHER_CLAUSE = {
    'readonly_param_open': module('def load(slot):', READ.format(arg='slot')),
    'gzip_read_param': module('import gzip', 'def load(slot):',
                              '    with gzip.open(slot) as handle:', '        return handle.read()'),
    'gzip_write_param': module('import gzip', 'def dump(slot, payload):',
                               '    with gzip.open(slot, "wb") as handle:',
                               '        handle.write(payload)'),
    'runtime_mode_flag': module('def dump(slot, mode, payload):',
                                '    with open(slot, mode) as handle:',
                                '        handle.write(payload)'),
    'self_field_write': module('class Store:', '    def dump(self, payload):',
                               '        with open(self.out_slot, "w") as handle:',
                               '            handle.write(payload)'),
    'literal_path': module('def dump(payload):', WRITE.format(arg='"/var/log/app.out"')),
    'tempfile_root': module('import os, tempfile', 'def dump(payload):',
                            '    root = tempfile.mkdtemp()',
                            WRITE.format(arg='os.path.join(root, "a.json")')),
    # Opened and never extracted. Measured zero arena reach -- `grep -r "tarfile.open"` over the
    # corpus finds no such call, and the shape reports nothing at HEAD either -- so nothing in the
    # engine today demonstrates the archive exemption with a finding. It is pinned instead at the
    # predicate (the consult table below) and by the two-module cap, exactly the way the sibling gate
    # files a lever it measured as empty rather than pretending the row exists.
    'tarfile_open_no_extract': module('import tarfile', 'def inspect(slot):',
                                      '    with tarfile.open(slot) as archive:',
                                      '        return archive.getnames()'),
}

# The archive exemption's own evidence, read off what the engine answers rather than off a finding:
# the predicate must refuse to require a proof from `tarfile.open` in the dotted AND the aliased
# spelling, on a module that really registers the sink. `archive_table_emptied` flips both.
CONSULT_PINNED = {'archive_tarfile_dotted': ('tarfile_open_dotted', 3),
                  'archive_tarfile_alias': ('tarfile_open_alias', 3),
                  # A web handler's `open(request.args["f"])`, an `open(sys.argv[1])` and a
                  # `shutil.copy(sys.argv[1], dst)` are refused even though their rows would survive
                  # without the refusal, so the refusal is pinned on the answer rather than on the
                  # finding. The copy row is the one that says the rule declines the same argument it
                  # requires of a delete two tables below.
                  'proven_request_inline': ('request_inline', 3),
                  'proven_request_helper': ('request_into_helper', 3),
                  'proven_argv_direct': ('argv_direct', 3),
                  'proven_copy_argv': ('copy_from_argv', 4)}

ALL_FIXTURES = {}
for _table in (EARNED_QUIET, LOUD_BY_PROVEN_TAINT, LOUD_BY_CUT_SHORT, LOUD_BY_DIRENT,
               LOUD_BY_UNTRUSTED_ORIGIN, LOUD_BY_TRACE_COMMAND_LINE,
               LOUD_BY_TRACE_COMMAND_DECORATOR, LOUD_BY_TRACE_REMOTE_HOP,
               LOUD_BY_TRACE_AND_FLAVOUR, SCOPE_NON_OPEN_SINKS, REFUSED_BY_ARCHIVE,
               QUIET_BY_LOCAL_COMMAND_LINE):
    ALL_FIXTURES.update(_table)
for _label, _source in QUIET_BY_OTHER_CLAUSE.items():
    ALL_FIXTURES[_label] = (None, _source)

FLAVOUR_TABLES = {'cut_short': LOUD_BY_CUT_SHORT, 'dirent': LOUD_BY_DIRENT,
                  'untrusted_origin': LOUD_BY_UNTRUSTED_ORIGIN}
# One entry per recognition arm, so a row can be booked against the arm that actually decided it and
# `check_fixtures` can blind that one arm and demand the row move. The two remote entries read the same
# predicate -- one hop away in a caller, and in the argument itself -- and are kept apart because only
# the first of them is decided by that arm alone.
TRACE_TABLES = {'parse_args namespace': LOUD_BY_TRACE_COMMAND_LINE,
                'command decorator': LOUD_BY_TRACE_COMMAND_DECORATOR,
                'remote value one hop away': LOUD_BY_TRACE_REMOTE_HOP,
                'remote value in the argument': LOUD_BY_TRACE_AND_FLAVOUR}
# name -> (the one engine attribute that arm reads, the value that switches it off). The first is a
# module-level table on `ast_scanner`, the others are methods on the tracker, so a row filed under one
# of these names is a claim about that spelling alone.
TRACE_ARMS = {
    'parse_args namespace': ('CWE22_OPERATOR_ROOT_CALLS', frozenset()),
    'command decorator': ('_c22_cli_command_params', lambda self, tree: {}),
    'remote value one hop away': ('_c22_expr_is_untrusted_source',
                                  lambda self, table, expr, depth=0, cli_blind=False: False),
    'remote value in the argument': ('_c22_expr_is_untrusted_source',
                                     lambda self, table, expr, depth=0, cli_blind=False: False),
}
TRACE_ARM_ATTRIBUTES = {'CWE22_OPERATOR_ROOT_CALLS'}
LOUD_BY_FLAVOUR = {label: name for name, table in FLAVOUR_TABLES.items() for label in table}
LOUD_BY_TRACE = {label: name for name, table in TRACE_TABLES.items() for label in table}
# The rows the argument walk decides on its own: switching `_c22_path_sink_reaches_operator` off makes
# every one of them owe its proof and go quiet. `LOUD_BY_TRACE_AND_FLAVOUR` is deliberately absent --
# those rows are owed after the same blind and stay loud on the flavour, so a mutation that claimed
# them would be claiming a clause that is not load-bearing.
# A row filed under a trace arm that survives the whole walk going dark is loud twice over and may not
# be booked against the walk alone. Measured under `whole_trace_blind`
# (`scratch/_c22_r5_moves_matrix.py`), not inferred from the fixture's comment.
LOUD_TWICE_OVER = set()
LOUD_BY_TRACE_SOLO = {label: name for name, table in TRACE_TABLES.items() for label in table
                      if name != 'remote value in the argument' and label not in LOUD_TWICE_OVER}
# `shielded_<fixture>`: the same bytes as a demoted row filed under a path the frozen-corpus shield
# recognises. These are not extra fixtures -- `check_fixtures` proves the shield on the demoted
# fixtures themselves -- they exist so `pinned_state` can answer "is this shape still loud when nothing
# but the shield stands between it and the demotion". Once a row is retired by this rule an arm blind
# can no longer move the finding (there is no finding), and the shielded spelling is the only
# finding-level witness left that the arm still decides that shape of argument.
SHIELDED_LOUD = {f'shielded_{label}': (label, line)
                 for label, (line, _source) in sorted(QUIET_BY_LOCAL_COMMAND_LINE.items())}
# Which shielded shape each arm blind is measured to witness
# (`scratch/_c22_r5_moves_matrix.py`, one line per blind). These are the demoted fixtures whose root the
# named arm is the only thing recognising: every argparse row needs `parse_args()`, all but the
# decorator-direct row reach their sink through a call site, and the two `sys.argv` rows are the only
# ones whose root is also a remote-classified name. The sets are spelled out rather than derived from
# the fixtures because the arm a shape belongs to is a fact about the engine, not about the table it is
# filed in.
SHIELDED_BY_ARGPARSE_ARM = {'argparse_field_direct', 'argparse_field_one_hop',
                            'argparse_via_caller_namespace', 'rmtree_argparse_one_hop'}
SHIELDED_BY_CLICK_ARM = {'click_option_direct', 'click_option_into_helper'}
SHIELDED_BY_CALL_HOP = (SHIELDED_BY_ARGPARSE_ARM | SHIELDED_BY_CLICK_ARM) - {'click_option_direct'}
SHIELDED_BY_REMOTE_ARM = {'argv_direct', 'copy_from_argv'}
SHIELDED_BY_WHOLE_WALK = set(QUIET_BY_LOCAL_COMMAND_LINE) - SHIELDED_BY_REMOTE_ARM


def _shielded(names):
    """`shielded_x` for every fixture name in `names`, sorted."""
    return sorted(f'shielded_{name}' for name in names)
SCOPE_OWED = set(SCOPE_NON_OPEN_SINKS)
# The archive table is the only refusal this rule still books by finding. The module-fact table is
# gone: since the mandate stopped letting a declaration stand in for a value, a fact is an input to
# the argument walk and never a refusal of its own, so those fixtures are either `LOUD_BY_TRACE_*`
# (the value really was there) or `EARNED_QUIET` (it was not).
REFUSED_TABLES = {'archive': REFUSED_BY_ARCHIVE}
LOADED_REFUSALS = {label: name for name, table in REFUSED_TABLES.items() for label in table}
# The refusal pins split by the clause they record. A mutation that switches a refusal off moves the
# pinned answer even where the finding itself survives on a different clause, and the `moves` lists
# below claim those answers too, because the answer is what the pin is a claim about.
ARCHIVE_PINS = sorted(name for name in CONSULT_PINNED if name.startswith('archive_'))
PROVEN_PINS = sorted(name for name in CONSULT_PINNED if name.startswith('proven_'))


# --------------------------------------------------------------------------- plumbing

def scan_module(source, module_name='m.py'):
    """CWE-22 rows for one in-memory module, through the real record path."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module_name: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(int(row['line']), row['message']) for row in rows if row['cwe'] == 'CWE-22'})


def observe(source, module_name='m.py'):
    """Scan once and record what the shipped rule actually asked and actually answered.

    Both logs come from wrapping the shipped methods and letting the engine call them, so `owed` is
    what the engine asked -- never a mirror of what this file thinks it should ask.

    Round 5 added a third answer to the same record: `demote`, what
    `_c22_sink_root_is_only_the_local_command_line` said about that sink. It is booked on the consult
    entry rather than in a list of its own because the two answers are one question -- the demotion is
    only ever asked after a `owed=False`, and a row that is quiet because it OWED a proof is a
    different fact from a row that was loud and then had its sink removed.
    """
    consults, keeps = [], []
    owed_original = ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint
    keeps_original = ast_scanner.TaintTracker._c22_unknown_origin_keeps_the_row
    demote_original = ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line
    demote_answers = []

    def demote_spy(self, record, sink):
        answer = demote_original(self, record, sink)
        demote_answers.append((int(record.lineno), bool(answer)))
        return answer

    def owed_spy(self, record, sink):
        answer = owed_original(self, record, sink)
        tree = self.modules.get(ast_scanner.scope_module(record.scope_id))
        facts = sorted(self._c22_module_entrypoint_facts(tree)) if tree is not None else []
        base = os.path.basename(self.file_paths.get(ast_scanner.scope_module(record.scope_id), ''))
        pin = (base, int(record.lineno or 0))
        consults.append({
            'line': int(record.lineno), 'symbol': str(sink.symbol), 'owed': answer,
            'facts': tuple(facts),
            'demote': 'never' if answer else 'asked',
            'pin': 'open' if pin in ast_scanner.CWE22_OPEN_TAINT_KEEP_LOUD else (
                'entrypoint' if pin in ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD else '')})
        return answer

    def keeps_spy(self, prov, record):
        answer = keeps_original(self, prov, record)
        flavours = sorted(name for name, test in (
            ('cut_short', self._c22_trace_is_cut_short(prov.source_trace)),
            ('dirent', self._c22_trace_enumerates_directory(prov.source_trace)),
            ('untrusted_origin', self._c22_origin_is_untrusted_source(
                getattr(prov, 'origin_node', None), record))) if test)
        keeps.append({'line': int(record.lineno), 'state': prov.state.name,
                      'answer': answer, 'flavours': flavours})
        return answer

    ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = owed_spy
    ast_scanner.TaintTracker._c22_unknown_origin_keeps_the_row = keeps_spy
    ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = demote_spy
    try:
        found = scan_module(source, module_name)
    finally:
        ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = owed_original
        ast_scanner.TaintTracker._c22_unknown_origin_keeps_the_row = keeps_original
        ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = demote_original
    for entry in consults:
        answers = [answer for line, answer in demote_answers if line == entry['line']]
        if answers:
            entry['demote'] = 'yes' if any(answers) else 'no'
    return found, consults, keeps


def rows_at(found, line):
    return [message for row_line, message in found if row_line == line]


def corpus_source(kind, file_field):
    """Read one blessed corpus file the way the sibling probes do.

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


def check_blessed_loud():
    """TIER 2: all 24 blessed CWE-22 lines still reported, and the pin is load-bearing.

    The claim this tier owns is the zero-FN claim of the whole slice: this rule declines 0 blessed
    rows. `refused` counts blessed lines the predicate was asked about and answered False -- correct,
    because a blessed key is either a harness/entrypoint module, an archive sink, or a pinned identity.
    `declined` (asked, answered True, and then the row vanished) must be zero.
    """
    failures = []
    asked = declined = refused = never = pinned = 0
    big8_pinned = 0
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        wanted = {}
        for row in rows:
            if row[2] == 'CWE-22':
                wanted.setdefault(str(row[0]), set()).add(int(row[1]))
        for file_field, lines in sorted(wanted.items()):
            source = corpus_source(kind, file_field)
            if source is None:
                failures.append((kind, 'blessed corpus file is not in the tree', file_field))
                continue
            module_name = os.path.basename(file_field)
            found, consults, _keeps = observe(source, module_name)
            for line in sorted(lines):
                if not rows_at(found, line):
                    failures.append((kind, 'blessed line no longer reported', file_field, line))
                entries = [entry for entry in consults if entry['line'] == line]
                if not entries:
                    never += 1
                    continue
                asked += 1
                for entry in entries:
                    if entry['owed']:
                        declined += 1
                        failures.append((kind, 'blessed open() owed a proof it cannot produce',
                                         file_field, line))
                    else:
                        refused += 1
                    if entry['pin']:
                        pinned += 1
                        if entry['pin'] == 'open':
                            expected = (os.path.basename(file_field), line)
                            if expected not in ast_scanner.CWE22_OPEN_TAINT_KEEP_LOUD:
                                failures.append(('pin spelled wrong', expected))
        print(f'  {kind:7s} blessed_lines={sum(len(v) for v in wanted.values())}')
        if kind == 'big8':
            big8_pinned = pinned
    print(f'  asked={asked} refused={refused} declined={declined} never_asked={never} '
          f'kept_by_pin={pinned}')
    if declined:
        failures.append(('the rule declined a blessed row', declined))
    if big8_pinned < 1:
        failures.append(('the pin tables are not load-bearing on any blessed line', big8_pinned))
    table = sorted(ast_scanner.CWE22_OPEN_TAINT_KEEP_LOUD)
    print(f'  open_pin_table={table}')
    if table != sorted(EXPECTED_OPEN_PINS):
        failures.append(('the shipped open() pin table is not the four measured identities', table))
    return failures


def check_vendored_pins():
    """TIER 2b: the leaf spellings, under the `vendor/...` keys another gate re-vendors them with.

    `active_partition_probe` re-vendors every blessed line under a path the corpus-name shield cannot
    match, and when this rule shipped those rows went silent there. The two leaf entries in the pin
    table are what keeps them loud, and this tier is where that is proven rather than inherited:
    `open_pin_table_emptied` moves exactly these two rows and nothing else can.
    """
    failures = []
    for file_field, vendor_name, line in VENDORED_BLESSED:
        source = corpus_source('big8', file_field)
        if source is None:
            failures.append(('blessed corpus file is not in the tree', file_field))
            continue
        found = scan_module(source, vendor_name)
        if not rows_at(found, line):
            failures.append(('vendored blessed line no longer reported', vendor_name, line))
        _found, consults, _keeps = observe(source, vendor_name)
        entries = [entry for entry in consults if entry['line'] == line]
        if not entries or not all(not entry['owed'] for entry in entries):
            failures.append(('vendored line was owed a proof', vendor_name, line))
    print(f'  vendored_pin_rows_loud={len(VENDORED_BLESSED)} names={[v for _f, v, _l in VENDORED_BLESSED]}')
    return failures


def check_fixtures():
    """TIER 3: the fixture truth table, with the deciding clause named for every row.

    Every row is filed against the clause that was measured to decide it, which is why there are two
    remote-source tables: the walk refuses the requirement when it finds an environment read, and the
    UNKNOWN exemption saves the row when the walk cannot follow the value. A shape saved by both is
    booked with the walk and left out of the walk-only mutation.
    """
    failures = []
    earned = tainted = flavour = refused_rows = not_claimed = traced = scoped = 0
    demoted = shielded_loud = 0
    for label, (line, source) in sorted(ALL_FIXTURES.items()):
        found, consults, keeps = observe(source)
        if label in QUIET_BY_OTHER_CLAUSE:
            if found:
                failures.append(('shape this rule does not own came back', label, found[:2]))
            else:
                not_claimed += 1
            continue
        at = rows_at(found, line)
        entries = [entry for entry in consults if entry['line'] == line]
        if len(entries) != 1:
            failures.append(('consults on the pinned line', label, line, len(entries)))
            continue
        entry = entries[0]
        # One claim for the whole table, asked before the category split: the demotion may only ever
        # take a row this file files as demoted. A `yes` on any other row would mean two categories
        # describe the same sink, and the row's loudness would then be an accident of branch order.
        if label not in QUIET_BY_LOCAL_COMMAND_LINE and entry['demote'] == 'yes':
            failures.append(('the local-command-line demotion claimed a row filed loud', label, line))
        if label in QUIET_BY_LOCAL_COMMAND_LINE:
            at = rows_at(found, line)
            if at:
                failures.append(('local-command-line row was not demoted', label, line, at[:1]))
            elif entry['owed']:
                failures.append(('row went quiet by OWING a proof, not by this rule', label, line))
            else:
                demoted += 1
            # The same bytes under a name the frozen-corpus shield knows. This is the half of the
            # claim that keeps the shield honest: the demotion is what retired the row, and the shield
            # is what refuses to let it happen to a benchmark corpus file -- so a blessed key cannot be
            # retired by this rule even if its own module spells no harness fact.
            shielded, _sc, _sk = observe(source, f'benchmark/corpus/{label}.py')
            if not rows_at(shielded, line):
                failures.append(('shielded spelling of a demoted row went quiet too', label, line))
            else:
                shielded_loud += 1
            continue
        keep = [item for item in keeps if item['line'] == line]
        if label in EARNED_QUIET:
            if found:
                failures.append(('earned row still reported', label, line, found[:2]))
            elif not entry['owed']:
                failures.append(('quiet row was never owed a proof', label, line))
            else:
                earned += 1
        elif label in LOUD_BY_PROVEN_TAINT:
            if not at:
                failures.append(('proven-taint row went silent', label, line))
            elif entry['owed'] and keep and keep[0]['answer']:
                failures.append(('proven-taint row booked as an UNKNOWN flavour', label, keep))
            else:
                tainted += 1
        elif label in LOUD_BY_FLAVOUR:
            want = LOUD_BY_FLAVOUR[label]
            if not at:
                failures.append(('flavour row went silent', label, line))
            elif not entry['owed']:
                failures.append(('flavour row was refused, not exempted', label, line))
            elif not keep or keep[0]['flavours'] != [want]:
                failures.append(('flavour row decided by the wrong clause', label, line,
                                 keep[0]['flavours'] if keep else None))
            else:
                flavour += 1
        elif label in LOUD_BY_TRACE:
            if not at:
                failures.append(('operator-trace row went silent', label, line))
            elif entry['owed']:
                failures.append(('trace row reported while owing a proof', label, line))
            else:
                traced += 1
        elif label in SCOPE_OWED:
            if found:
                failures.append(('scope fixture reported a finding', label, line, found[:2]))
            elif not entry['owed']:
                failures.append(('the requirement did not attach to this sink family', label, line))
            else:
                scoped += 1
        elif label in LOADED_REFUSALS:
            if not at:
                failures.append(('refused row lost its finding', label, line, found[:2]))
            elif entry['owed']:
                failures.append(('refusal clause did not refuse', label, line))
            else:
                refused_rows += 1
        else:
            failures.append(('unattributable fixture', label))
    print(f'  fixtures={len(ALL_FIXTURES)} retired_by_this_rule={earned} '
          f'loud_by_proven_taint={tainted} loud_by_unknown_flavour={flavour} '
          f'loud_by_operator_trace={traced} attached_never_reported={scoped} '
          f'refused={refused_rows} quiet_not_claimed={not_claimed} '
          f'demoted_local_command_line={demoted}/{len(QUIET_BY_LOCAL_COMMAND_LINE)} '
          f'same_bytes_under_the_shield={shielded_loud}/{len(QUIET_BY_LOCAL_COMMAND_LINE)}')
    consult_refused = 0
    for name, (label, line) in sorted(CONSULT_PINNED.items()):
        _found, consults, _keeps = observe(ALL_FIXTURES[label][1])
        entries = [entry for entry in consults if entry['line'] == line]
        if not entries or any(entry['owed'] for entry in entries):
            failures.append(('the refusal clause did not refuse the consult', name, line))
        else:
            consult_refused += 1
    print(f'  consult_refusals={consult_refused}/{len(CONSULT_PINNED)}')
    # The trace fixtures are attributed to an arm, not to "some refusal happened". Each arm below is
    # switched off on its own and the row is asked again: if the named arm really is what kept the row,
    # taking it away makes the sink owe its proof again. An arm that is credited with rows it does not
    # decide is the failure mode the module-fact table used to hide.
    for table_name, (arm_key, blind) in sorted(TRACE_ARMS.items()):
        decided = 0
        target = ast_scanner if arm_key in TRACE_ARM_ATTRIBUTES else ast_scanner.TaintTracker
        for label in sorted(TRACE_TABLES[table_name]):
            line, source = ALL_FIXTURES[label]
            original = getattr(target, arm_key)
            try:
                setattr(target, arm_key, blind)
                _found, consults, _keeps = observe(source)
            finally:
                setattr(target, arm_key, original)
            entries = [entry for entry in consults if entry['line'] == line]
            if not entries or not all(entry['owed'] for entry in entries):
                failures.append(('the named arm does not decide this row', table_name, label, line))
            else:
                decided += 1
        print(f'  arm {table_name:28s} decides {decided}/{len(TRACE_TABLES[table_name])} row(s)')
    return failures


def check_open_family_scope():
    """TIER 4a: which call the requirement attaches to, decided on the node rather than the label.

    The predicate is called with a synthetic record and sink so the scoping table is exact: the same
    dotted leaf must answer the same way whether it arrives spelled out or through an import binding.

    The vocabulary inverted when the mandate's requirement moved from `open()` to the filesystem sink
    families. Deletion, copy, move, rename, fd-wrapping, serialization and a handle write are all
    *inside* the scope now -- that is Morcha 2 item 1, and `delete_os_remove` in `EARNED_QUIET` is what
    it cost at HEAD -- so a verb may no longer be a reason to refuse. Two things still refuse: the two
    archive families, which the sacred floor puts beyond any provenance argument, and a record whose
    node is not a call at all, which is what keeps `with`-targets and cascade messages out of reach.
    """
    attaches = [
        'open(slot)', 'open(slot, "w")', 'builtins.open(slot)', 'io.open(slot)',
        'codecs.open(slot)', 'gzip.open(slot, "wb")',
        'os.remove(slot)', 'os.unlink(slot)', 'os.rmdir(slot)', 'os.rename(slot, other)',
        'os.fdopen(fd, "w")', 'shutil.rmtree(slot)', 'shutil.copy(src, dst)',
        'shutil.move(src, dst)', 'shutil.copytree(src, dst)', 'json.dump(data, handle)',
        'handle.write(payload)', 'helper.save(payload, slot)',
    ]
    refuses = [
        'tarfile.open(slot)', 'zipfile.ZipFile(slot)', 'archive.extractall(dest)',
        'archive.extract(member)',
    ]
    failures = []
    matched = 0
    for spelling in attaches + refuses:
        source = module('def f(slot, other, fd, handle, data, dest, archive, src, dst, member,'
                        ' payload):', f'    {spelling}')
        tree = ast.parse(source)
        call = [node for node in ast.walk(tree) if isinstance(node, ast.Call)][0]
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={PURE: source}, audit_all=True)
        symbol = dotted_name_or(call)
        sink = ast_scanner.SecurityNode(
            'S-1', ast_scanner.NodeType.SINK, symbol, 'FILE_ACCESS',
            ast_scanner.CodeLocation(PURE, call.lineno, call.lineno))
        record = ast_scanner.SinkRecord(call, sink, call.lineno,
                                        f'{next(iter(tracker.modules))}:function:f')
        got = bool(tracker._c22_open_sink_owes_proven_taint(record, sink))
        want = spelling in attaches
        if got == want:
            matched += 1
        else:
            failures.append(('sink-family scope', 'attaches' if want else 'refuses', spelling, got))
    # The non-call half of `refuses`, on the two record shapes the funnel really builds: a `with`
    # target name and a bare attribute. Both must answer False, or a message-shaped record could be
    # silenced by a rule that only ever speaks about calls.
    non_call = module('def f(slot):', '    with open(slot) as handle:', '        return handle.read()')
    target_tree = ast.parse(non_call)
    name_node = [node for node in ast.walk(target_tree)
                 if isinstance(node, ast.Name) and node.id == 'handle'][0]
    attr_node = [node for node in ast.walk(target_tree) if isinstance(node, ast.Attribute)][0]
    for node, shape in [(name_node, 'with-target name'), (attr_node, 'attribute read')]:
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={PURE: non_call}, audit_all=True)
        sink = ast_scanner.SecurityNode(
            'S-2', ast_scanner.NodeType.SINK, ast.unparse(node), 'FILE_ACCESS',
            ast_scanner.CodeLocation(PURE, node.lineno, node.lineno))
        record = ast_scanner.SinkRecord(node, sink, node.lineno,
                                        f'{next(iter(tracker.modules))}:function:f')
        if bool(tracker._c22_open_sink_owes_proven_taint(record, sink)):
            failures.append(('sink-family scope', 'refuses', shape, True))
        else:
            matched += 1
    print(f'  spellings={len(attaches) + len(refuses) + 2} exact={matched} '
          f'wrong={len(attaches) + len(refuses) + 2 - matched} '
          f'(attaches={len(attaches)} refuses={len(refuses) + 2})')
    if ast_scanner.CWE22_ARCHIVE_CONSTRUCTOR_MODULES != frozenset({'tarfile', 'zipfile'}):
        failures.append(('the archive module table grew past the two Zip-Slip families',
                         sorted(ast_scanner.CWE22_ARCHIVE_CONSTRUCTOR_MODULES)))
    if not ast_scanner.CWE22_DIRECTORY_ENUMERATION_LEAVES <= frozenset({
            'glob', 'iglob', 'listdir', 'scandir', 'walk', 'iterdir'}):
        failures.append(('the enumeration leaf table grew past the six directory readers',
                         sorted(ast_scanner.CWE22_DIRECTORY_ENUMERATION_LEAVES)))
    return failures


def dotted_name_or(call):
    node = call.func
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return '.'.join(reversed(parts)) or 'call'


def check_trace_flavours():
    """TIER 4b: the three UNKNOWN flavours, label by label, plus the shapes that are not flavours.

    `UNKNOWN` is not one thing, and this is the only tier that can say which spellings mean "nothing
    reached here" and which do not. An arbitrary `opaque_call:` is deliberately on the refusing side:
    it is the difference between "the file system named this path" and "somebody's function did".
    """
    cut_short = [('depth_guard',), ('circular_node',), ('circular:slot',), ('circular:p0',)]
    dirent = [('opaque_call:glob.glob()', 'src/library.py:p'),
              ('opaque_call:glob.iglob()',), ('opaque_call:os.listdir()',),
              ('opaque_call:os.scandir()',), ('opaque_call:Path.iterdir()',),
              ('file:x', 'opaque_call:walk()')]
    untrusted = ['x = os.environ["CFG"]\n', 'x = os.environ.get("CFG")\n',
                 'x = os.getenv("CFG")\n', 'x = sys.argv[1]\n', 'x = sys.stdin.read()\n',
                 'x = environ["CFG"]\n', 'x = request.args["f"]\n']
    # `argv[1] if argv else other` is the sibling gate's measured refusal too: the predicate walks
    # names, attributes, subscripts, calls and concatenations, and an `IfExp` is none of those, so
    # the ternary reads as an ordinary local. Filing it on the refusing side here keeps the two gates
    # from disagreeing about the same expression.
    not_untrusted = ['x = "cfg.json"\n', 'x = os.getcwd()\n', 'x = tempfile.mkdtemp()\n',
                     'x = parse_table.get("flags")\n', 'x = os.path.join(root, name)\n',
                     'x = resolve_target()\n', 'x = argv[1] if argv else other\n']
    neither = [('subscript',), ('unknown_expr',), ('opaque_call:resolve_target()',),
               ('opaque_call:json.load()',), ('[join_internal]',), (), None,
               ('unbound_param:slot',), ('SRC-001',)]
    failures = []
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'src/library.py': 'x = 1\n'}, audit_all=True)
    for trace in cut_short + dirent + neither:
        got_cut = ast_scanner.TaintTracker._c22_trace_is_cut_short(trace)
        got_dirent = ast_scanner.TaintTracker._c22_trace_enumerates_directory(trace)
        want = 'cut_short' if trace in cut_short else ('dirent' if trace in dirent else '')
        if bool(got_cut) + bool(got_dirent) != bool(want) or (want and not (
                got_cut if want == 'cut_short' else got_dirent)):
            failures.append(('trace flavour', want or 'neither', trace, got_cut, got_dirent))
    proven = refused = 0
    for source in untrusted + not_untrusted:
        tree = ast.parse(source)
        expr = tree.body[-1].value
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={PURE: source}, audit_all=True)
        record = ast_scanner.SinkRecord(expr, _sink_for(expr), 1,
                                        f'{next(iter(tracker.modules))}:global')
        got = bool(tracker._c22_origin_is_untrusted_source(expr, record))
        want = source in untrusted
        proven += got and want
        refused += (not got) and (not want)
        if got != want:
            failures.append(('untrusted origin flavour', 'expected' if want else 'refused',
                             source.strip(), got))
    print(f'  traces={len(cut_short) + len(dirent) + len(neither)} '
          f'origins={len(untrusted) + len(not_untrusted)} untrusted={proven} '
          f'not_untrusted={refused}')
    return failures


def _sink_for(node):
    return ast_scanner.SecurityNode('S-1', ast_scanner.NodeType.SINK, 'open', 'FILE_ACCESS',
                                    ast_scanner.CodeLocation(PURE, node.lineno, node.lineno))


def check_wiring():
    """TIER 5: one flag per record, three short-circuits gated, a prune arm that can only subtract.

    The count of gated arms is the whole point of the structural tier. A CWE-22 sink can become a
    finding without resolving anything in three different ways -- the phase-11 adoption, the phase-5
    registry stamp, and the phase-4 stamp the generic dynamic-variable emitter leaves behind -- and
    each of them used to answer for itself. Pinning the number, rather than the line numbers, is what
    stops a fourth invented source from joining them unnoticed: when the flag is read at a fifth
    place, this tier asks what it guards.
    """
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        text = handle.read()
    lines = text.splitlines()
    tree = ast.parse(text)
    methods = {}
    for top in tree.body:
        if isinstance(top, ast.ClassDef):
            for item in top.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.setdefault(item.name, item)
    assignment = [index + 1 for index, item in enumerate(lines)
                  if item.strip().startswith('c22_open_owes_taint =')]
    consults = [index + 1 for index, item in enumerate(lines)
                if 'c22_open_owes_taint' in item and not item.strip().startswith('c22_open_owes_taint =')]
    gated = [index + 1 for index, item in enumerate(lines)
             if 'and not c22_open_owes_taint' in item]
    print(f'  assignment={assignment} consults={consults} gated_short_circuits={gated}')
    if len(assignment) != 1:
        failures.append(('the flag must be computed exactly once per record', assignment))
    if len(gated) != 3:
        failures.append(('every synthetic short-circuit must be gated by the flag', gated))
    if len(consults) != 5:
        failures.append(('the flag is read at an unexpected number of places', consults))
    # Round 5's fourth reader. It is not a short-circuit and it must never be: the arm that consumes
    # `c22_local_cli_only` may only take a sink away, so the count of `gated` above stays three and
    # this arm is pinned to the same subtract-only shape as the UNKNOWN prune below.
    local_flag = [index + 1 for index, item in enumerate(lines)
                  if item.strip().startswith('c22_local_cli_only =')]
    local_arms = [index + 1 for index, item in enumerate(lines)
                  if 'if c22_local_cli_only' in item]
    print(f'  local_cli_flag={local_flag} local_cli_arms={local_arms}')
    if len(local_flag) != 1 or len(local_arms) != 1:
        failures.append(('the local-command-line flag must be computed once and acted on once',
                         (local_flag, local_arms)))
    else:
        node_index = local_arms[0] - 1
        arm_lines = lines[node_index:node_index + 5]
        arm_text = '\n'.join(arm_lines)
        if ('self.sinks.remove(sink)' not in arm_text or 'continue' not in arm_text
                or 'edges.append' in arm_text):
            failures.append(('the local-command-line arm must only remove a sink and continue',
                             arm_text[:160]))
    # The prune arm: removes the sink, continues, and appends nothing. Anything else in it could
    # make a finding appear, which is the property this whole design is built on.
    arm = next((node for node in ast.walk(tree) if isinstance(node, ast.If)
                and 'c22_open_owes_taint' in ast.unparse(node.test)
                and '_c22_unknown_origin_keeps_the_row' in ast.unparse(node.test)), None)
    if arm is None:
        failures.append(('the UNKNOWN-arm prune is no longer an If on the flag and the flavour test',))
    else:
        body_text = ast.unparse(arm)
        appends = [node for node in arm.body if isinstance(node, ast.Expr)
                   and isinstance(node.value, ast.Call)
                   and 'edges.append' in ast.unparse(node.value)]
        has_remove = 'self.sinks.remove(sink)' in body_text
        has_continue = any(isinstance(node, ast.Continue) for node in arm.body)
        removes_only = bool(ast.unparse(arm.body))
        print(f'  prune_arm={arm.lineno} removes={has_remove} continues={has_continue} '
              f'appends={len(appends)}')
        if not (has_remove and has_continue and not appends and removes_only):
            failures.append(('the prune arm must only remove a sink and continue', arm.lineno))
    for name in ('_c22_open_sink_owes_proven_taint', '_c22_unknown_origin_keeps_the_row',
                 '_c22_trace_is_cut_short', '_c22_trace_enumerates_directory',
                 '_c22_origin_is_untrusted_source', '_c22_path_sink_reaches_operator',
                 '_c22_value_reaches_operator', '_c22_cli_command_params',
                 '_c22_sink_root_is_only_the_local_command_line'):
        if name not in methods:
            failures.append(('deciding method is gone', name))
    # Pin tables: each membership test may only answer in the keep direction. Round 5 added a second
    # reader of both tables -- the local-command-line rule, which refuses its own demotion for a pinned
    # identity -- so the count is two and BOTH arms have to be `return False`. A table that could end a
    # row from one place and start one from another is the same bug in a new coat.
    for table, constant in (('CWE22_OPEN_TAINT_KEEP_LOUD', False),
                            ('CWE22_ENTRYPOINT_KEEP_LOUD', False)):
        defs = [node.lineno for top in tree.body if isinstance(top, ast.Assign)
                for node in top.targets
                if isinstance(node, ast.Name) and node.id == table]
        uses = [node.lineno for node in ast.walk(tree)
                if isinstance(node, ast.Name) and node.id == table]
        consulted = [lineno for lineno in uses if lineno not in defs]
        print(f'  {table}: defs={defs} consulted_from={consulted}')
        if len(defs) != 1:
            failures.append(('pin table must be defined exactly once', table, defs))
        if table == 'CWE22_OPEN_TAINT_KEEP_LOUD' and len(consulted) != 2:
            failures.append(('the open() pin table must be consulted from the owed rule and the '
                             'local-command-line rule and nowhere else', consulted))
        for owner_name in ('_c22_open_sink_owes_proven_taint',
                           '_c22_sink_root_is_only_the_local_command_line'):
            owner = methods.get(owner_name)
            if owner is None:
                continue
            arms = [item for item in ast.walk(owner) if isinstance(item, ast.If)
                    and table in ast.unparse(item.test)]
            if table != 'CWE22_OPEN_TAINT_KEEP_LOUD':
                continue
            if len(arms) != 1:
                failures.append(('the open() pin arm is not a single If', owner_name, len(arms)))
            else:
                body = arms[0].body
                keep_only = (len(body) == 1 and isinstance(body[0], ast.Return)
                             and isinstance(body[0].value, ast.Constant)
                             and body[0].value.value is constant)
                print(f'  {owner_name} open_pin_arm_returns_False_only={keep_only}')
                if not keep_only:
                    failures.append(('the pin table must only ever refuse the requirement, '
                                     'never mandate a silence', owner_name, table))
    # Morcha 1's own prohibition, read off the syntax. A module-level declaration may not decide the
    # requirement in either direction: `if self._c22_module_entrypoint_facts(tree)` inside the owed
    # rule is the blanket the mandate retired, and the only legal place for a fact is as an input to
    # the argument walk. Zero calls from this method is the whole claim.
    owner = methods.get('_c22_open_sink_owes_proven_taint')
    fact_calls = [item.lineno for item in ast.walk(owner) if isinstance(item, ast.Call)
                  and '_c22_module_entrypoint_facts' in ast.unparse(item.func)]
    print(f'  owed_rule_consults_module_facts_at={fact_calls}')
    if fact_calls:
        failures.append(('a module-level fact is deciding the requirement again', fact_calls))
    # The one legal place a fact may now decide something: the local-command-line rule, where a harness
    # fact or the absence of every fact can only block a subtraction. Read off the syntax -- the facts
    # call must sit in an `If` whose whole body is `return False`.
    demoter = methods.get('_c22_sink_root_is_only_the_local_command_line')
    if demoter is not None:
        fact_arms = [item for item in ast.walk(demoter) if isinstance(item, ast.Call)
                     and '_c22_module_entrypoint_facts' in ast.unparse(item.func)]
        guarded = []
        for call in fact_arms:
            holder = next((node for node in ast.walk(demoter) if isinstance(node, ast.If)
                           and any(child is call for child in ast.walk(node.test))), None)
            if holder is not None and len(holder.body) == 1 and isinstance(holder.body[0], ast.Return)\
                    and isinstance(holder.body[0].value, ast.Constant)\
                    and holder.body[0].value.value is False:
                guarded.append(holder.lineno)
        print(f'  local_cli_fact_calls={len(fact_arms)} refusal_guards={guarded}')
        if len(fact_arms) != 1 or len(guarded) != 1:
            failures.append(('a module fact may only block the demotion, from one guarded If',
                             (fact_arms, guarded)))
    cluster = ['_c22_open_sink_owes_proven_taint', '_c22_unknown_origin_keeps_the_row',
               '_c22_trace_is_cut_short', '_c22_trace_enumerates_directory',
               '_c22_origin_is_untrusted_source', '_c22_module_entrypoint_facts',
               '_c22_path_sink_reaches_operator', '_c22_value_reaches_operator',
               '_c22_cli_command_params']
    banned = ('tests/', 'examples/', 'docs/', 'corpus', 'vendor/', 'fn_lower', '.py"',
              'is_test_suite', 'src/transformers')
    # Round 5's predicate is scanned for the token the contract actually forbids -- a folder name used
    # as a suppression -- and not for `corpus`/`fn_lower`, because its frozen-corpus shield is a
    # KEEP-LOUD refusal on the same tokens the sibling exemptions already use, and a tier that called
    # that illegal would be asking this rule to be weaker than the one it sits next to. The
    # subtract-only shape of the arm is what stops the shield from being a blacklist: nothing that
    # reaches it can be silenced by a path.
    banned_local = ('tests/', 'examples/', 'docs/', 'vendor/', '.py"', 'is_test_suite',
                    'src/transformers')
    scanned = [(name, banned) for name in cluster]
    scanned.append(('_c22_sink_root_is_only_the_local_command_line', banned_local))
    for name, tokens in scanned:
        item = methods.get(name)
        if item is None:
            failures.append(('deciding method is not a TaintTracker method', name))
            continue
        start = item.lineno - 1
        head = item.body[0] if item.body else None
        if (isinstance(head, ast.Expr) and isinstance(head.value, ast.Constant)
                and isinstance(head.value.value, str)):
            start = head.end_lineno
        segment = '\n'.join(lines[start:item.end_lineno])
        for token in tokens:
            if token in segment:
                failures.append(('name/path token inside the deciding code', name, token))
    print(f'  token-scanned cluster={cluster} + local-command-line rule')
    return failures


# --------------------------------------------------------------------------- mutations

BLESSED_CORPUS_LABEL = 'blessed_trainer_corpus'
BLESSED_VENDORED_LABEL = 'blessed_trainer_vendored'
BLESSED_ENTRYPOINT_LABEL = 'blessed_modeling_utils_pin'
WORKING = {}


def pinned_state(label):
    """Is the row this label pins present under the engine as it stands?

    Message-scoped on purpose: this rule decides one emitter's row, and a fixture line can carry a
    second CWE-22 row that belongs to the cascade or a registry sink. Counting rows instead of the
    measured message would call a real relabel an unchanged line.
    """
    if label == BLESSED_CORPUS_LABEL:
        source = corpus_source('big8', 'src__transformers__trainer.py')
        return any(message for line, message in scan_module(
            source, 'src__transformers__trainer.py') if line == 4301)
    if label == BLESSED_VENDORED_LABEL:
        source = corpus_source('big8', 'src__transformers__trainer.py')
        return any(message for line, message in scan_module(
            source, 'vendor/transformers/trainer.py') if line == 4301)
    if label == BLESSED_ENTRYPOINT_LABEL:
        source = corpus_source('big8', 'src__transformers__modeling_utils.py')
        found = scan_module(source, 'src__transformers__modeling_utils.py')
        return any(line in (336, 3564) for line, _message in found)
    if label in SHIELDED_LOUD:
        fixture, line = SHIELDED_LOUD[label]
        source = ALL_FIXTURES[fixture][1]
        found = scan_module(source, f'benchmark/corpus/{fixture}.py')
        return bool(rows_at(found, line))
    if label in CONSULT_PINNED:
        fixture, line = CONSULT_PINNED[label]
        _found, consults, _keeps = observe(ALL_FIXTURES[fixture][1])
        entries = [entry for entry in consults if entry['line'] == line]
        return bool(entries) and not any(entry['owed'] for entry in entries)
    line, source = ALL_FIXTURES[label]
    if line is None:
        return bool(scan_module(source))
    return bool(rows_at(scan_module(source), line))


def _moved(label):
    return pinned_state(label) != WORKING[label]


def _every_sink_owes(self, record, sink):
    """The refusal clauses switched off one by one, so the scope table is shown to be load-bearing.

    Treated here as `requirement_always_applied`: the predicate is forced True for every sink, so
    deletes, archive constructors, harness modules and pinned blessed rows all lose the answer that
    keeps them loud.
    """
    return True


_OPEN_PIN = ast_scanner.CWE22_OPEN_TAINT_KEEP_LOUD
_ENTRYPOINT_PIN = ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD
_ARCHIVE_MODULES = ast_scanner.CWE22_ARCHIVE_CONSTRUCTOR_MODULES
_OWEs = ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint
_KEEPS = ast_scanner.TaintTracker._c22_unknown_origin_keeps_the_row
_CUT = ast_scanner.TaintTracker.__dict__['_c22_trace_is_cut_short'].__func__
_DIRENT = ast_scanner.TaintTracker.__dict__['_c22_trace_enumerates_directory'].__func__
_MODULE_FACTS_BLANKET = ('fact_main_guard', 'fact_cli_argparse', 'fact_harness_class',
                         'generic_fallback_uncalled_helper')
FACT_ONLY_EARNED = set(_MODULE_FACTS_BLANKET)

MUTATIONS = {
    'requirement_always_refused': {
        'what': 'no open() ever owes a proof, so the unproven fallback reports whatever it used to',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                 lambda self, record, sink: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                   _OWEs),
        'moves': sorted(EARNED_QUIET) + ['self_field_write'],
        # `self_field_write` is the honest extra: it is quiet at HEAD and quiet here because an older
        # clause already proved it clean, and switching the requirement off brings it back anyway. That
        # is the flag's other half -- `owed=False` is not merely HEAD's behaviour, it re-attaches the
        # synthetic short-circuit the older clause then has to beat.
    },
    'requirement_always_applied': {
        'what': 'every sink owes a proof, so the archive and operator-trace refusals are gone',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                 _every_sink_owes),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                   _OWEs),
        'moves': ['tarfile_open_dotted', 'tarfile_open_alias', 'zipfile_extractall',
                  BLESSED_CORPUS_LABEL, BLESSED_VENDORED_LABEL, BLESSED_ENTRYPOINT_LABEL,
                  'argv_direct', 'copy_from_argv']
        + ARCHIVE_PINS + sorted(LOUD_BY_TRACE_SOLO) + PROVEN_PINS
        + _shielded(SHIELDED_BY_WHOLE_WALK),
        # Two additions the round-5 population makes, both measured. The `modeling_utils` pin moves
        # here because the pin is consulted by the owed rule, so forcing the requirement on takes the
        # pin's answer away with it. The six shielded shapes and the two argv fixtures move in OPPOSITE
        # directions: the shielded rows lose the finding the shield was protecting, and the two argv
        # rows -- demoted at baseline -- come back loud, because `owed=True` means the funnel never asks
        # the demotion at all and the UNKNOWN untrusted-origin flavour then saves them.
    },
    'archive_table_emptied': {
        'what': 'the archive module table is emptied, so `tarfile.open` is judged as a plain open()',
        'apply': lambda: setattr(ast_scanner, 'CWE22_ARCHIVE_CONSTRUCTOR_MODULES', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_ARCHIVE_CONSTRUCTOR_MODULES',
                                   _ARCHIVE_MODULES),
        'moves': ['archive_tarfile_dotted', 'archive_tarfile_alias'],
    },
    'module_fact_blanket_returns': {
        'what': 'the retired blanket comes back: a module-level fact alone refuses the requirement',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                 _fact_blanket_owes),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                   _OWEs),
        'moves': sorted(FACT_ONLY_EARNED),
    },
    'whole_trace_blind': {
        'what': 'the argument-wide operator walk finds nothing anywhere, so every trace row owes again',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_sink_reaches_operator',
                                 lambda self, node, tree, cli_blind=False: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_sink_reaches_operator',
                                   _REACHES),
        # Only the rows the walk decides alone. The three inline-environment rows owe their proof again
        # under this blind and stay loud on the UNKNOWN exemption, so they are not claimed here
        # (`scratch/_c22_blind_matrix.py`, column `trace`). The four `proven_*` answers are claimed:
        # taking the walk away makes a `sys.argv`/`request` argument owe its proof again even though
        # the row itself survives on its TAINTED answer. Round 5 adds the two demoted argv rows, which
        # come back LOUD because a blind walk kills the demotion's positive half before it can act, and
        # the six shielded spellings, which go quiet for the same reason the unshielded trace rows do.
        # `harness_argparse_direct` is in the claim because the walk is the only thing keeping it loud;
        # `LOUD_TWICE_OVER` is what a fixture that survived this blind would have to be moved to, and
        # after the round-5 line-number fix nothing in the table needs it.
        'moves': sorted(LOUD_BY_TRACE_SOLO) + PROVEN_PINS + ['argv_direct', 'copy_from_argv']
        + _shielded(SHIELDED_BY_WHOLE_WALK),
    },
    # One mutation per recognition arm, each with exactly the rows that arm was measured to decide
    # (`scratch/_c22_blind_matrix.py`, `scratch/_c22_flavour_only.py`, `scratch/_c22_r5_moves_matrix.py`).
    # Round 5 changed what each of these arms can still be credited with: the plain command-line shapes
    # are retired now, so a blind cannot move a finding that is not there, and the arm's evidence for
    # those shapes is its SHIELDED spelling -- the same bytes under `benchmark/corpus/`, where the
    # corpus shield refuses the demotion and the row is loud for the arm's own reason. An arm that
    # decides nothing in either spelling would be a decorative claim, and the measured `moves=` line in
    # `scratch/_c22_r5_moves_matrix.py` is what says it is not.
    'operator_root_calls_blind': {
        'what': 'a namespace built by `parse_args()` stops being recognized as a command-line root',
        'apply': lambda: setattr(ast_scanner, 'CWE22_OPERATOR_ROOT_CALLS', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_OPERATOR_ROOT_CALLS', _ROOT_CALLS),
        'moves': sorted(LOUD_BY_TRACE_COMMAND_LINE) + _shielded(SHIELDED_BY_ARGPARSE_ARM),
    },
    'cli_command_params_blind': {
        'what': 'the `@click.option`/`argument` decorator table is emptied, so typed text has no root',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_cli_command_params',
                                 lambda self, tree: {}),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_cli_command_params',
                                   _CLI_PARAMS),
        'moves': sorted(LOUD_BY_TRACE_COMMAND_DECORATOR) + _shielded(SHIELDED_BY_CLICK_ARM),
    },
    # ------------------------------------------------------------------ round 5, the local-command-line rule
    # Three mutations, one per thing the new clause can be wrong about. `local_cli_demotion_off` asks
    # whether the rule earns its retirements at all; `cli_blind_is_noop` asks whether the SECOND walk is
    # what earns them, or whether any root near a command line would do; `local_cli_harness_guard_off`
    # asks whether the harness exception is load-bearing, because a rule that demotes a test suite is
    # the one way this slice could ever reach a benchmark key.
    'local_cli_demotion_off': {
        'what': 'the local-command-line rule is switched off, so every retired row comes back',
        'apply': lambda: setattr(ast_scanner.TaintTracker,
                                 '_c22_sink_root_is_only_the_local_command_line',
                                 lambda self, record, sink: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker,
                                   '_c22_sink_root_is_only_the_local_command_line', _DEMOTE),
        'moves': sorted(QUIET_BY_LOCAL_COMMAND_LINE),
    },
    'cli_blind_is_noop': {
        'what': 'the second walk runs unblinded, so "the command line was the root" degrades to '
               '"some root happened to be nearby"',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_sink_reaches_operator',
                                 lambda self, node, tree, cli_blind=False: _REACHES(self, node, tree)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_sink_reaches_operator',
                                   _REACHES),
        'moves': sorted(QUIET_BY_LOCAL_COMMAND_LINE),
    },
    'local_cli_harness_guard_off': {
        'what': 'the harness facts stop refusing the demotion, so a test suite loses its CLI rows',
        'apply': lambda: setattr(ast_scanner, 'CWE22_HARNESS_FACTS', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_HARNESS_FACTS', _HARNESS_FACTS),
        'moves': sorted(LOUD_BY_TRACE_COMMAND_LINE) + sorted(LOUD_BY_TRACE_COMMAND_DECORATOR),
    },
    'local_cli_demote_on_any_root': {
        'what': 'the differential is dropped: any row the unblinded walk refused to owe gets demoted, '
               'whether its root was the command line or a socket reading the command line',
        'apply': lambda: setattr(ast_scanner.TaintTracker,
                                 '_c22_sink_root_is_only_the_local_command_line',
                                 _demote_without_the_second_walk),
        'restore': lambda: setattr(ast_scanner.TaintTracker,
                                   '_c22_sink_root_is_only_the_local_command_line', _DEMOTE),
        # Measured: the rows a web-request root was saving -- the only shapes whose module really does
        # spell a caller-fed fact (the flask import) AND whose surviving root is remote. Claiming the
        # demoted fixtures here would be wrong: they are already quiet, so nothing moves.
        'moves': ['request_inline', 'request_into_helper'],
    },
    'caller_hop_blind': {
        'what': 'the call-site table is emptied, so a value a caller hands over is invisible',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_param_proofs',
                                 lambda self, tree: {}),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_param_proofs', _PARAM_PROOFS),
        # The command-line rows plus the two shapes that reach the walk through the same call-site
        # table: an `os.environ` value handed to a helper (`caller_passes_environ`, measured quiet
        # under this blind in `scratch/_c22_moves_matrix.py`), and the refusal answer for the same
        # one-hop spelling, `proven_request_helper`. Round 5 dropped `click_option_into_helper` and the
        # three retired argparse rows from this list -- they are quiet now, and a blind cannot move a row
        # that is already gone -- and put their shielded spellings in instead, which is the same five
        # shapes with the corpus shield standing where the demotion used to stand.
        'moves': (sorted(LOUD_BY_TRACE_COMMAND_LINE) + ['caller_passes_environ',
                                                        'proven_request_helper']
                  + _shielded(SHIELDED_BY_CALL_HOP)),
    },
    'trace_remote_arm_blind': {
        'what': 'the remote-source predicate is switched off inside the walk, env/argv/request gone',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_expr_is_untrusted_source',
                                 lambda self, table, expr, depth=0, cli_blind=False: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_expr_is_untrusted_source',
                                   _UNTRUSTED),
        # Everything this one predicate decides, in all three of the places it is read: the walk's
        # remote arm (the hop row and the three rows the walk refuses), the `untrusted_origin`
        # exemption (which calls the same predicate, so the four flavour-only rows move here as well as
        # under their own blind), and the provenance classifier that labels `sys.argv` and
        # `os.getenv` TAINTED. `getenv_call` itself was measured to stand under this blind -- its row
        # is kept by the `os.getenv` sink rule, not by this predicate -- so it is not claimed.
        # `argv_direct` and `copy_from_argv` used to be claimed here; round 5 retired them (see
        # `QUIET_BY_LOCAL_COMMAND_LINE`), so this blind now moves nothing that is not already quiet --
        # except their own shielded spellings, which are the two rows that still show the remote-name
        # arm recognising a command line read.
        'moves': (sorted(LOUD_BY_TRACE_REMOTE_HOP) + sorted(LOUD_BY_TRACE_AND_FLAVOUR)
                  + sorted(LOUD_BY_UNTRUSTED_ORIGIN) + PROVEN_PINS
                  + _shielded(SHIELDED_BY_REMOTE_ARM)),
    },
    'open_pin_table_emptied': {
        'what': 'the exact-identity open() pin is emptied, so the cross-module blessed row is declined',
        'apply': lambda: setattr(ast_scanner, 'CWE22_OPEN_TAINT_KEEP_LOUD', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_OPEN_TAINT_KEEP_LOUD', _OPEN_PIN),
        'moves': [BLESSED_CORPUS_LABEL, BLESSED_VENDORED_LABEL],
    },
    'entrypoint_pin_emptied': {
        'what': 'the sibling gate keeps the two `modeling_utils.py` keys and this rule stops honoring it',
        'apply': lambda: setattr(ast_scanner, 'CWE22_ENTRYPOINT_KEEP_LOUD', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_ENTRYPOINT_KEEP_LOUD', _ENTRYPOINT_PIN),
        'moves': [BLESSED_ENTRYPOINT_LABEL],
    },
    'cut_short_flavour_blind': {
        'what': 'a walk stopped by the depth or cycle guard starts reading as proven-clean',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_is_cut_short',
                                 staticmethod(lambda trace: False)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_is_cut_short',
                                   staticmethod(_CUT)),
        'moves': sorted(LOUD_BY_CUT_SHORT),
    },
    'dirent_flavour_blind': {
        'what': 'a path named by a directory listing stops being an origin',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_enumerates_directory',
                                 staticmethod(lambda trace: False)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_enumerates_directory',
                                   staticmethod(_DIRENT)),
        'moves': sorted(LOUD_BY_DIRENT),
    },
    'dirent_any_opaque_call': {
        'what': 'every opaque callee counts as an enumeration, so the leaf table stops deciding',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_enumerates_directory',
                                 staticmethod(lambda trace: any(
                                     str(step).startswith('opaque_call:') for step in trace or ()))),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_enumerates_directory',
                                   staticmethod(_DIRENT)),
        'moves': ['module_global_from_opaque_call'],
    },
    'untrusted_origin_flavour_blind': {
        'what': 'an environment-supplied subscript reads as unproven, retiring a real finding',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_origin_is_untrusted_source',
                                 lambda self, origin, record: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_origin_is_untrusted_source',
                                   _ORIGIN),
        'moves': sorted(LOUD_BY_UNTRUSTED_ORIGIN),
    },
    'flavours_all_declined': {
        'what': 'the whole UNKNOWN exemption is switched off, so every owed row is pruned',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_unknown_origin_keeps_the_row',
                                 lambda self, prov, record: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_unknown_origin_keeps_the_row',
                                   _KEEPS),
        'moves': sorted(LOUD_BY_CUT_SHORT) + sorted(LOUD_BY_DIRENT)
        + sorted(LOUD_BY_UNTRUSTED_ORIGIN),
    },
    'flavours_all_accepted': {
        'what': 'every UNKNOWN answer counts as a risk, so nothing this rule owns is ever retired',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_unknown_origin_keeps_the_row',
                                 lambda self, prov, record: True),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_unknown_origin_keeps_the_row',
                                   _KEEPS),
        # `self_field_write` is booked here as well as under `requirement_always_refused`: an
        # `open(self.out_slot)` resolves to an UNKNOWN origin, so a blanket "UNKNOWN is a risk" reports
        # a row that two independent clauses -- the self-field rule and this requirement -- prove clean.
        'moves': ['module_global_from_opaque_call', 'self_field_write'],
    },
}

_ORIGIN = ast_scanner.TaintTracker._c22_origin_is_untrusted_source
_REACHES = ast_scanner.TaintTracker._c22_path_sink_reaches_operator
_DEMOTE = ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line
_HARNESS_FACTS = ast_scanner.CWE22_HARNESS_FACTS
_CLI_PARAMS = ast_scanner.TaintTracker._c22_cli_command_params
_PARAM_PROOFS = ast_scanner.TaintTracker._c22_param_proofs
_UNTRUSTED = ast_scanner.TaintTracker._c22_expr_is_untrusted_source
_ROOT_CALLS = ast_scanner.CWE22_OPERATOR_ROOT_CALLS

# The four retired rows whose modules really do declare a fact, so a declaration -- never a value -- is
# the only thing that ever kept them loud. Measured one by one: `scratch/_c22_gate_refile.py` prints
# the fact tuple the engine saw on each consult, and these are the four that came back non-empty.
FACT_ONLY_EARNED = {'fact_main_guard', 'fact_cli_argparse', 'fact_harness_class',
                    'generic_fallback_uncalled_helper'}


def _demote_without_the_second_walk(self, record, sink):
    """Every refusal the demotion asks, with the differential itself switched off.

    The blinded call answers "no root" and the unblinded call is left exactly as the engine wrote it, so
    the row still owes nothing for the right reason -- it is only the SECOND question that stops being
    asked. This is the shape of the rule if it had been written as "a command-line root was seen", which
    is what the mandate's prose could be read to mean, and it is the reason the differential is there
    instead: under it, a web request read two lines from an `argparse` namespace is retired too.
    """
    original = ast_scanner.TaintTracker._c22_path_sink_reaches_operator

    def forced(_self, node, tree, cli_blind=False):
        return False if cli_blind else original(_self, node, tree, cli_blind)

    ast_scanner.TaintTracker._c22_path_sink_reaches_operator = forced
    try:
        return _DEMOTE(self, record, sink)
    finally:
        ast_scanner.TaintTracker._c22_path_sink_reaches_operator = original


def _fact_blanket_owes(self, record, sink):
    """The retired shape of the rule: ask the module, never the argument."""
    tree = self.modules.get(ast_scanner.scope_module(record.scope_id))
    if tree is not None and self._c22_module_entrypoint_facts(tree):
        return False
    return _OWEs(self, record, sink)


def run_mutation(name):
    """Apply one in-memory weakening and check that the rows it should break actually move."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print('  rows that must move: ' + ', '.join(spec['moves']))
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
    moved = [label for label, did_move in outcomes if did_move]
    for label, did_move in outcomes:
        print(f"  {label:38s} {'MOVED' if did_move else 'unchanged'}")
    caught = len(moved) == len(outcomes)
    print('FALSIFICATION VERDICT (' + name + '): '
          + (f'CAUGHT on all {len(moved)} pinned row(s)' if caught else
             'MISSED - this clause is decorative; the row it guards did not move'))
    return 1 if caught else 0


def main() -> int:
    print('TIER 1 - blessed CWE-22 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the 24 blessed lines, asked about by the open() rule:')
    failures += check_blessed_loud()
    print('TIER 2b - the leaf spellings under the vendored keys:')
    failures += check_vendored_pins()
    print('TIER 3 - the fixture truth table, with the deciding clause named:')
    failures += check_fixtures()
    print('TIER 4a - which call the requirement attaches to:')
    failures += check_open_family_scope()
    print('TIER 4b - the three UNKNOWN flavours, label by label:')
    failures += check_trace_flavours()
    print('TIER 5 - one flag per record, three short-circuits gated, two subtract-only arms:')
    failures += check_wiring()
    for item in failures[:14]:
        print(f'  !! {item}')
    print(f'\nfixtures={len(ALL_FIXTURES)} earned={len(EARNED_QUIET)} '
          f'loud_by_proven_taint={len(LOUD_BY_PROVEN_TAINT)} '
          f'loud_by_flavour={sum(len(t) for t in FLAVOUR_TABLES.values())} '
          f'refused={sum(len(t) for t in REFUSED_TABLES.values())} '
          f'quiet_not_claimed={len(QUIET_BY_OTHER_CLAUSE)} '
          f'locked_cwe22={sum(CWE22_LOCKED.values())} mutations={len(MUTATIONS)} '
          f'failures={len(failures)}')
    if failures:
        print('VERDICT: FAIL - Slice J no longer matches its measured evidence. Either a blessed '
              'CWE-22 key was owed a proof it cannot produce, the open() pin table stopped being '
              'load-bearing in one of its two spellings, a retired shape came back, a refusal clause '
              'let an archive, operator-reachable or pinned row go quiet, an UNKNOWN flavour was '
              'reclassified, or the flag moved off its single computation site and gained an arm that '
              'can add a finding. Restore the answer; never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - 0 of {sum(CWE22_LOCKED.values())} blessed CWE-22 keys owed a proof they '
          f'cannot produce, {len(EARNED_QUIET)} unproven filesystem fallbacks retired by this rule '
          f'alone, '
          f'{len(LOUD_BY_PROVEN_TAINT)} proven-taint rows and '
          f'{sum(len(t) for t in FLAVOUR_TABLES.values())} UNKNOWN-flavour rows held loud by the '
          f'clause that names them, {sum(len(t) for t in REFUSED_TABLES.values())} archive-floor rows '
          f'refused the requirement outright with the pin table load-bearing in both spellings, one '
          f'flag per record and a prune arm that can only subtract.')
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
