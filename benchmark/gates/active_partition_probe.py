"""Active-partitioning lock: the slices shipped under the updated Zero-FN Shield.

The mandate asked for three filters. Two of them already existed in the engine, so the work was to
find the population that is still loud, prove a value-domain slice that no blessed key shares, and
ship that slice -- not to re-add a rule that was already there. Everything below is measured on this
checkout, and every conjunct has a mutation that moves it.

Slice A -- CWE-22, a read-only open whose path is a compile-time string literal
------------------------------------------------------------------------------
`_sink_context_exempt` already exempted read-only opens inside a test tree (ast_scanner.py:7431-7452
before this change). The 35 arena sites that are still registered are the NON-test ones, so the new
proof carries no path test at all: a path written in the source text has no runtime component an
attacker could steer. The observable is `sink_records`, exactly as the mandate named it -- these rows
never reached a finding on either arm, so a finding count is the one instrument that cannot see the
win. Measured per fixture, CWE-22 records only:
    literal read 0, literal 'rb' 0, literal with a runtime mode 1, literal write 1, runtime read 1.
A mode that is not a literal stays registered: `open(p, mode_var)` could be 'w' at runtime, and the
default-is-read argument only applies when no mode was passed at all.

`TaintTracker._c22_open_sink_owes_proven_taint` (this round) decides a second question on top of that:
whether a registered CWE-22 path sink may EMIT at all. It does not ask what the retired blanket asked
("can I prove this safe?") but what the mandate asks ("does a value the operator or the network
controls demonstrably reach one of these arguments?"). `runtime_read` is the row that shows the two
questions are not the same. With a bare parameter as the path the fixture was loud on the blanket's
say-so; round 3 re-earned it loud because the argument carries the command line itself
(`open(os.path.join(sys.argv[1], filename))`), measured `[2]` and 1 `sink_record` by
`scratch/_c22_r3_partition_measure.py`. Round 5 then retired that report: the command-line half of
condition (a) is exactly what the local-command-line demotion removes for standard file I/O, so the row
is re-filed in `C22_LOCAL_CLI_RETIREMENT` at its measured live value (quiet, still 1 `sink_record`)
with HEAD's `[2]` beside it, and `c22_local_cli_runtime_read_restored` brings it back. M17 runs with the
demotion ambient-disabled so the blanket arm still measures the blanket alone. The same statement with
no value reaching it -- a `def f(filename)` nobody in the file calls with argv, beside a module-level
`print(sys.argv[1])` -- is `scratch/_c22_r3_engines.py --diff`
head-only at line 2 and silent live; that row is booked in C22_BLANKET_RETIREMENT at its measured
value (quiet, still 1 `sink_record`) with HEAD's line kept beside it, and the mutation
`c22_open_taint_blanket_restored` brings it back. The two rows still separate the two rules: one is
quiet because no root reaches it, the other because the only root that reaches it is the operator's own
command line. The literal rows are untouched by all of this: they
never reached a finding on either arm, so the owed rule is never asked about them.

Slice B -- CWE-338, two value-domain proofs inside `_cwe338_display_only_draw`
----------------------------------------------------------------------------
The test-tree exemption (ast_scanner.py:7453-7465) already covers test files; the arena rows that
remain live in `src/` and `examples/`. Two shapes there are provably not credentials:
  * `random.uniform(0, 1)` -- two literal bounds, so the value domain is the closed unit interval.
    36 arena rows are exactly `dropout_probability = random.uniform(0, 1)`. The other three arena
    `uniform` rows carry runtime bounds and stay loud.
  * `for index in random.sample(range(len(dataset)), 3)` -- the population is a container's length,
    so the draw returns POSITIONS, and the loop consumes them as indices. 21 arena rows. A code or
    OTP generator draws from a literal alphabet (`range(10)`), never from a dataset's length, and
    that fixture stays loud.
Both proofs sit AFTER the credential and `.join` vetoes, so a security-named destination still wins.
0 of the 16 blessed CWE-338 keys is a `uniform` call or a `sample(range(len(...)))` loop.

The veto hole this exposed, and its measured-free fix
----------------------------------------------------
`random.sample(range(len(passwords)), 3)` was loud on HEAD and went quiet under the first draft of
Slice B: CWE338_SECURITY_NAME_WORDS carried a plural for every member of its family except `password`
and `seed`, and a container name is exactly where the plural appears. Adding `passwords` and `seeds`
restores the veto. Measured before adding: 0 arena CWE-338 rows and 0 of the 16 blessed keys contain
either word; the 20 `seeds` occurrences in the arena are comments plus one literal `SEEDS = [...]`
parametrisation list, never a draw destination. So the completion re-loudens nothing that is quiet.

Slice C -- CWE-208, the constant-integer partition is already shipped, and is defended twice
-------------------------------------------------------------------------------------------
`_compares_two_secrets` refuses any `ast.Constant` operand (ast_scanner.py:8561) and
`_c208_is_unit_test_assertion` refuses a test assertion without credential provenance
(ast_scanner.py:8512). Measured: 0 of the 118 arena CWE-208 rows is an equality against an integer
literal -- the only four rows with an int operand are a `< 1` tensor metric and three
`len(token_ids) > 0` guards beside `token_ids[-1] == self.eos_token_id`, which the mandate keeps loud.
So there is no new predicate here and nothing to suppress; what this gate adds is the lock, plus the
proof that the partition is load-bearing: blinding the Constant refusal alone already re-loudens a
credential-named `secret_size == 2`, blinding both guards keeps it loud, and `batch_size == 2` stays
quiet under both because the credential-name axis is a third, independent guard.

Slice D -- CWE-22, the path a hub cache resolver built is not a path the caller chose
-------------------------------------------------------------------------------------
`_c22_is_hub_cache_read` exempts an `open()` whose path argument IS the return value of
`hf_hub_download` / `cached_download`, in read mode, when the name is bound -- either the module
carries `from huggingface_hub import <name>`, or the call uses the qualified
`huggingface_hub.<name>` spelling. Three conjuncts, each with its own mutation:
  * the argument must be the resolver call itself: `os.path.join(root_dir, hf_hub_download(...))`
    is attacker-prefixed and stays loud, which is the fixture `resolver_join_prefix_stays_loud`;
  * a same-named local `def hf_hub_download` proves nothing, so `resolver_local_def_is_not_a_binding`
    stays loud -- the proof is the import, never the leaf spelling;
  * a non-literal or writing mode is unknown, so both stay registered.
Measured over the arena CI rows the current engine still emits: 52 rows in 48 converter scripts
match, and 0 of the 24 blessed CWE-22 keys (8 parity + 16 Big-8) match in any spelling.

The owed rule asks these fixtures a second, independent question, and the four rows this tier pins
LOUD now answer it with a value rather than with a module-level fact: each sink has a call site that
hands `get_labels` a `sys.argv` value, so `_c22_path_sink_reaches_operator` finds the command line in
the arguments and the only thing left that could silence the row is the conjunct the fixture is about.
What each surviving row still proves is unchanged and measured: the attacker prefix in
`resolver_join_prefix_stays_loud` ([4]), the missing import in `resolver_local_def_is_not_a_binding`
([4]), the writing mode in `resolver_write_mode_stays_loud` ([3]), the runtime mode in
`resolver_runtime_mode_stays_loud` ([3], 2 `sink_records` now that the mode value itself is argv). In
the OLD spelling -- no call site, only `import sys` + `print(sys.argv[1])` at module level -- all four
lines were the retired blanket's answer: `scratch/_c22_r3_engines.py --diff` reports every one of them
head-only and nothing live, so each is booked in C22_BLANKET_RETIREMENT at its measured live value
(quiet, 1 `sink_record`) with HEAD's line kept beside it for the restoration mutation. The two quiet
fixtures register nothing and stay quiet; `resolver_bare_import_read` is spelled with the argv call
site precisely so the two hub mutations still have a row they can re-loud -- blinding
`_c22_is_hub_cache_read` gives `[3]` there, and blinding the import-binding reads (the
`_c22_module_hub_resolvers` table AND the canonical spelling a bare leaf inherits from
`from huggingface_hub import ...`) gives `[3]` for the bare spelling while the qualified
`huggingface_hub.hf_hub_download` spelling stays quiet, because that one needs no binding table.

Refused, with its numbers -- CWE-117, the numeric-format-spec proof
--------------------------------------------------------------------
`format(v, ",")` raises on a `str`, so an f-string field carrying a `,` (or `d`/`.3f`/`%`) spec is
CPython-proven numeric and cannot smuggle the newline CWE-117 is about. Elegant, and still wrong:
it yields 3 arena rows and, on the pinned Big-8 corpus, deletes 8 CWE-117 rows out of 29 --
1602/1603/1604/1605/1607/1608/1610/1611 in `src/transformers/trainer.py`, every one of them a blessed
key and not one an FP. Tier 8 pins all eight loud and the mutation installs the predicate to prove
the refusal is load-bearing.

Slice E -- CWE-22/770, the path a program's own command line chose is not a path a caller chose
----------------------------------------------------------------------------------------------
One blessed CWE-22 key can sit in the same origin class (`function_parameter`, 52 arena rows vs 3
blessed) as hundreds of false alarms, and the answer to that is not to leave the whole class loud:
it is to add the AST conditions that no blessed key satisfies. The condition here is a positive
presence proof, twice over -- the file BOTH parses its own command line (`parse_args`) AND runs under
`if __name__ == "__main__":`, and the `open()`'s path argument walks back to an argparse leaf with
nothing untrusted joined in. A library module has neither fact, so the same taint shape there stays
loud. Measured on the CI arena rows the engine still emitted: 14 rows match, all `models/*/convert_*`
checkpoint scripts, and the predicate silences all 14 at registration; over the whole arena this slice
alone removes 81 rows (1873 -> 1792) with 0 rows added -- the same 325 chunks with the proof blinded
emit 1873 rows in 219.79 s against 1792 rows in 204.39 s with it, so the walk costs nothing it does not
pay back. Muting a CWE-22 row un-masks the `f.read()` underneath it -- which is why the same proof is
wired into the CWE-770 unbounded-read branch too.

The trust is on the *binding*, never on the spelling of a variable, and that is what the last nine
fixtures pin. A name is resolved through the enclosing callables innermost-first, so a converter's
local `args = chkpt["cfg"]["model"]` may not poison the module's `args = parser.parse_args()` (the
arena's biogpt/fsmt/gptsan/megatron rows are exactly that shape), and equally the module's parse may
not vouch for a handler whose parameter merely shares the name, a loop target, a lambda argument, a
nested tuple rebind like `head, (args, tail) = split_request(body())`, or a field somebody wrote
into. A namespace handed to a function is still a namespace -- `convert(args)` stays quiet while
`convert(os.environ['P'])` and `args.dest = fetch_payload()` stay loud -- and a name called `argv`
that came off a socket proves nothing. Mutants M6/M7/M8 blind the binding proof, the scope split and
the write veto one at a time, and each moves only the fixtures that depend on it.

Reach on the baseline is 0, and tier 9 proves that with two different instruments.
---------------------------------------------------------------------------------
Twenty-two of the 24 blessed CWE-22 lines are re-spelled under `vendor/...` keys and stay loud there:
the frozen keys live under paths containing `src__`/`tests__`, every CWE-22 exemption sits behind
`not is_protected`, so a green parity run says nothing about this predicate and the tier reads the SAME
bytes where the shield cannot help. The two `cwe_937_insecure_protocol/test_v06_*` parity keys do not
survive that re-spelling, and what keeps them on their own baseline names is a keep-loud mechanism, not
a suppression: their `filename` is called only with literals, no CLI/remote value reaches the `open()`
anywhere in the module, and `_c22_path_sink_reaches_operator` therefore cannot answer the mandate's
question -- `scratch/_c22_r3_engines.py --diff` on those exact bytes reports the sink line head-only,
which is the definition of this round's supersession. The engine keeps them through
`CWE22_OPEN_TAINT_KEEP_LOUD`, an exact `(os.path.basename(file), lineno)` identity table, which is the
instrument the operating contract sanctions for a TP that overlaps a new suppression ("pin those exact
K nodes LOUD via fail-closed guard or exact AST identity (`KEEP_LOUD_EXCEPTION`)"); it can only ADD a
finding, never take one away, so renaming the module drops the pin and silences nothing by itself. A
path/folder blacklist is the forbidden instrument precisely because it does the opposite.
So the property this tier owns -- that no *suppression* is name-based -- moved to a carrier that earns
its loudness from a resolved origin instead of inheriting a pin. `C22_NAME_BLIND_CARRIER` scans one
byte-for-byte module under five names, `vendor/proto/v06bad.py` and `vendor/proto/v06good.py` among
them: with `load(os.environ['PATH_IN'])` present the open reports `[5, 8]` and 2 `sink_records` under
EVERY name, and the same statement without a resolved origin is quiet ([], 1 record) under EVERY name.
Loudness and silence are both name-invariant for anything the owed rule decides; the only name
dependence left in the engine points the keep-loud way. The mutation
`c22_name_scoped_suppression_would_move_the_tier` installs the forbidden instrument -- owe the proof
only when the path contains `vendor/proto` -- and the carrier's rows split by name, which is exactly
what the tier would see. Called directly on the corpus, the predicate fires on 0 of the 19 `open()`
nodes that sit on a blessed line; the other 5 keys are `os.remove`/`shutil.rmtree`/`Path.read_bytes`/
`.extract()` sinks, and forcing the predicate True on them is the mutation that shows the tier can move.

Round 5 -- the local command line is the operator, and the retirement needs a resolved binding
----------------------------------------------------------------------------------------------
`_c22_sink_root_is_only_the_local_command_line` retires a path sink whose only resolved root is this
program's own command line: `--output_dir` in a local CLI tool is the invocation, not an attack vector.
It is a differential -- the reach walk answers True, and the same walk with the four local-command-line
recognitions blinded answers False -- and it refuses archive extraction, the frozen-corpus shield, both
keep-loud pin tables, harness modules and modules with no caller-fed fact.

The differential alone was UNSOUND, and this gate is what caught it. `_c22_path_sink_reaches_operator`
is a presence walk over ANY binding: `_c22_bound_values` returns every assignment a name ever had and
one root among them answers True, and `_c22_expr_is_untrusted_source` credits bare `argv` by spelling.
Both are sound for the question round 3 asked of them, where True only ever keeps a row loud. Asked in
the silencing direction they retire five shapes Slice E already refuses -- `args = fetch_from_socket()`
after a parse, `args.dest = fetch_payload()`, `for args in scan_roots()`,
`head, (args, tail) = split_request(body())`, and `argv = read_socket()` -- because a blinded False
means "the walk found no root", never "the only root is the command line". Measured before the fix:
all five answered `reach=True blind=False demote=True` and went quiet
(`scratch/_c22_r5_partition_lab.py`).

The repair is a conjunct, not a loosened assertion: `_c22_cli_retirement_is_proven` walks the argument's
VALUE CHAIN (`_c22_value_origin_is_resolved`) and asks that every link be resolved, so a retirement now
needs a resolved binding. It refuses at exactly two shapes -- a call the engine cannot classify as a path
call (unknown wrapper, a bare path name with no import witness, a bare `mkdtemp`, an unqualified hub
resolver, a function this file defines), and a command-line credit the value did not earn (a holder read
failing the all-bindings namespace proof, a bare `argv` or click parameter rebound to something else).
Everything else it is deliberately tolerant of: an unbound name, an imported constant, a cycle, the
depth budget, a `BoolOp`, a loop target over `zip`. That tolerance is what the objective costs --
demanding a POSITIVE proof of every leaf instead was measured to hand back 79 of the 85 arena
retirements, because the engine cannot resolve imported constants or `pathlib.Path` at all. All five
borrowed-authority rows came back with no carrier re-spelled.
`c22_local_cli_binding_proof_is_load_bearing` hands the proof back as a constant True
and must re-silence all five; M6 now runs with the demotion ambient-disabled so it measures the binding
proof alone rather than two clauses at once.

The local-def refusal is itself a caught false negative, not a design choice. The first cut classified
any function the module defines, on the argument that "its body is in the tree the blinded walk reads".
That argument is false: the walk resolves NAMES to bindings and never reads a callee's body, so
`def hf_hub_download(repo, name): return requests.get(repo).text` handed a remote payload to `open()`
while every argument still spelled the command line, and the row went QUIET
(`scratch/_c22_r5_localdef_probe.py`, four shapes, all silent with the arm in and all loud with it out).
Removing the arm closed that hole and restored slice D's `resolver_local_def_is_not_a_binding` veto at
its asserted `[4]` with no re-file at all.

Two more early returns of exactly that class went the same way, each measured before it was removed.
Stopping at a `CWE22_PURE_CONTAINER_RESHAPE` leaf hid `zip(requests.get(...).text, tasks)`,
`list(urlopen(root).read())` and `str(requests.get(root).text)` -- the walk resolves a loop target or a
subscript to the reshaper CALL and never looks inside its arguments
(`scratch/_c22_r5_reshape_probe.py`, 3 of 7 quiet with the early return, 0 of 7 without). Stopping at any
`CWE22_OPERATOR_ROOT_CALLS` leaf hid `parse_json_file(root)` and `parse_yaml_file(root)` when `root` was
handed `requests.get(...).text`: that set is the program parsers PLUS the file parsers, and the file
parsers' own table comment says they are not a trust root on their own, so the walk must descend into
the file argument (`scratch/_c22_r5_parseleaf_probe.py`). `C22_LOCAL_CLI_FN_SHIELDS` pins all seven
rows loud, and M6e/M6f hand each early return back and must re-hide exactly its own rows. The remaining
tolerant arms -- the depth budget, the cycle guard, an unbound name -- were audited the same way
(`scratch/_c22_r5_tolerant_arms_probe.py`): the cycle and self-referential shapes stay loud, and the
three deep-chain/imported-constant shapes are quiet with the demotion DISABLED too, so they are
inherited reach-walk gaps rather than this round's false negatives.

Three rows could not come back, and all three are re-filed rather than re-blessed.
`no_main_guard_stays_loud` contradicts round 5 head-on: the main guard decides whether a module is a
PROGRAM, never who typed argv, so `C22_RETIRED_BY_LOCAL_CLI` books its measured live value ([], 0
registered, 2 records) with the pre-demotion answer beside it, and
`c22_local_cli_no_main_guard_restored` must bring `[9]` / 2 / 2 back with the demotion off.
`runtime_read` is the same supersession one tier earlier -- round 3 re-earned it on "the command line is
IN the argument", which is the half of condition (a) round 5 removes -- and
`C22_LOCAL_CLI_RETIREMENT` books it with `c22_local_cli_runtime_read_restored` bringing `[2]` / 1 back.
`tempfile_leaf_with_argv_root` is re-filed in `cwe22_entrypoint_injection_probe.py`: `from tempfile
import mkdtemp` then bare `mkdtemp()` is a call the engine cannot classify, by its own documented
doctrine that a bare name could be anybody's function.

The one row the conjunct does not restore is the carrier itself: `load(sys.argv[1])` really is a
command-line-only root, so it is retired under every name. It is booked in `C22_NAME_BLIND_RETIRED` at
its measured live value ([], 2 records, name-invariant) with the pre-demotion answer beside it, and
`c22_local_cli_demotion_restored` must bring `[5, 8]` / 2 back under all five names while the earned
environ carrier does not move. The earned carrier moved to `os.environ['PATH_IN']` because a quiet
carrier cannot show that a name failed to silence an earned row; the proposition -- one answer under
five names -- keeps its words.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
GATES_DIR = os.path.join(ROOT, 'benchmark', 'gates')
BIG8_CORPUS = os.path.join(ROOT, 'benchmark_gates_data', 'corpus_big8')
CORPUS_DIR = os.path.join(ROOT, 'benchmark', 'corpus')
BENCHMARK_DIR = os.path.join(ROOT, 'benchmark')
MODELING_COMMON = 'tests__test_modeling_common.py'
GENERATION_UTILS = 'tests__generation__test_utils.py'
WHISPER = 'tests__models__whisper__test_modeling_whisper.py'

import cli  # noqa: E402
import ast_scanner  # noqa: E402


def scan(files: dict, cwe: str) -> tuple:
    """One in-process scan: (loud lines, registered sinks, sink_records) for one CWE."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files=files, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
        registered = sum(1 for sink in tracker.sinks if (sink.metadata or {}).get('cwe') == cwe)
        records = sum(1 for record in tracker.sink_records
                      if (record.security_node.metadata or {}).get('cwe') == cwe)
    loud = sorted(int(row['line']) for row in rows if row['cwe'] == cwe)
    return loud, registered, records


# Slice A fixtures: (source path, source, expected loud lines, expected CWE-22 sink_records).
C22_FIXTURES = {
    'literal_read': ('src/m.py',
                     "def f():\n"
                     + "    with open('vocab.json') as h:\n"
                     + "        return h.read()\n", [], 0),
    'literal_read_rb': ('src/m.py',
                        "def f():\n"
                        + "    with open('vocab.json', 'rb') as h:\n"
                        + "        return h.read()\n", [], 0),
    'literal_runtime_mode': ('src/m.py',
                             "def f(mode_var):\n"
                             + "    with open('vocab.json', mode_var) as h:\n"
                             + "        return h.read()\n", [], 1),
    'literal_write': ('src/m.py',
                      "def f():\n"
                      + "    with open('vocab.json', 'w') as h:\n"
                      + "        h.write('x')\n", [], 1),
    # `runtime_read` left this table for `C22_LOCAL_CLI_RETIREMENT` below: round 5 demotes the very
    # root its loudness was earned from, and the proposition it used to assert -- "the command line is
    # IN the argument" -- is the half of round 3's condition (a) that the mandate retires.
}

# ── Round 5 re-filed: the slice A row whose REPORT the local-command-line demotion retires ──────────
# `runtime_read` was EARNED loud in round 3, not inherited: the blanket used to read an unproven
# runtime path as untrusted, and when that blanket was retired the row was re-earned on the ground
# that `sys.argv[1]` is IN the argument -- round 3's condition (a), "a direct command-line or remote
# root". Round 5 splits condition (a) in two and keeps only the remote half for standard file I/O:
# in a local CLI program the operator who typed `--output_dir` is the process owner, not a remote
# attacker. So the ground this row was re-earned on is the ground the mandate removes, and the row is
# re-filed rather than deleted -- its bytes are unchanged, its registration is unchanged (1
# sink_record: the demotion removes the sink, never the record), and
# `c22_local_cli_runtime_read_restored` hands the demotion back and must bring [2] / 1 back.
#
# The sibling `runtime_read_unproven` in C22_BLANKET_RETIREMENT is the same statement WITHOUT the argv
# value, and it stays there: it is quiet under the retired blanket and the demotion never claimed it,
# so the two rows still separate the two rules exactly as they did before.
C22_LOCAL_CLI_RETIREMENT = {
    'runtime_read_was_loud': ('src/m.py',
                              "def f(filename):\n"
                              + "    with open(os.path.join(sys.argv[1], filename)) as h:\n"
                              + "        return h.read()\n"
                              + "import os\n"
                              + "import sys\n", [], 1, 2),
    # The control for the two remote-config shields below: the SAME parser pointed at a file the
    # operator chose. Its silence is the retirement working, not a hole -- the file argument resolves
    # to `sys.argv[1]`, so the chain clears exactly as `CWE22_OPERATOR_FILE_PARSERS`' comment requires.
    'parse_json_file_operator_cfg': ('src/m.py',
                                     "import sys\n"
                                     + "from transformers.utils import parse_json_file\n"
                                     + "def run(root):\n"
                                     + "    cfg = parse_json_file(root)\n"
                                     + "    with open(cfg['out'], 'w') as h:\n"
                                     + "        h.write('x')\n"
                                     + "run(sys.argv[1])\n", [], 1, 5),
}

# ── Round 5: the two false negatives the resolved-origin proof caught, pinned LOUD ─────────────────
# Both were introduced by an early `return True` that trusted the blinded reach walk to cover a shape
# it does not cover, and both were measured rather than reasoned about. The walk resolves NAMES to
# their bindings; it never reads a callee's body and never looks inside a call's arguments. So:
#
#   * a function this module DEFINES is an unknown wrapper. `def hf_hub_download(repo, name): return
#     requests.get(repo).text` hands a remote payload to `open()` while every argument still spells the
#     command line. Classifying local defs retired it (`scratch/_c22_r5_localdef_probe.py`).
#   * a container reshaper must be DESCENDED into, not stopped at. `zip(requests.get(...).text, tasks)`,
#     `list(urlopen(root).read())` and `str(requests.get(root).text)` all went quiet when the walk
#     returned True at the reshaper, and all seven shapes are loud with the whole demotion disabled --
#     so the demotion owned those silences (`scratch/_c22_r5_reshape_probe.py`).
#
# Every row here declares a CLI fact, so the demotion is reachable and the silence would be its doing.
# Three mutations hand the three early returns back, and each must re-hide exactly its own rows:
# `c22_local_cli_unclassified_call_refusal_is_load_bearing` forces the classifier to True (all seven go
# quiet), `c22_local_cli_reshaper_descent_is_load_bearing` stops the walk at a reshaper (the three
# reshaper rows go quiet, the rest stay loud), and
# `c22_local_cli_file_parser_descent_is_load_bearing` stops it at any root-call leaf (the two
# remote-config rows go quiet, the operator-pointed control stays quiet). A refusal nobody can falsify
# is a decoration.
C22_LOCAL_CLI_FN_SHIELDS = {
    'local_def_fetches_remote': ('src/m.py',
                                 "import requests\n"
                                 + "def hf_hub_download(repo, name):\n"
                                 + "    return requests.get(repo).text\n"
                                 + "def get_labels(repo_id, filename):\n"
                                 + "    with open(hf_hub_download(repo_id, filename), 'r') as h:\n"
                                 + "        return h.read()\n"
                                 + "import sys\n"
                                 + "print(get_labels(sys.argv[1], sys.argv[2]))\n", [5]),
    'local_def_reads_socket': ('src/m.py',
                               "import socket\n"
                               + "def resolve(repo, name):\n"
                               + "    s = socket.socket()\n"
                               + "    return s.recv(4096).decode()\n"
                               + "def get_labels(repo_id, filename):\n"
                               + "    with open(resolve(repo_id, filename), 'r') as h:\n"
                               + "        return h.read()\n"
                               + "import sys\n"
                               + "print(get_labels(sys.argv[1], sys.argv[2]))\n", [6]),
    'zip_hides_request': ('src/m.py',
                          "import sys, requests\n"
                          + "def run(tasks):\n"
                          + "    for payload, task in zip(requests.get(sys.argv[1]).text, tasks):\n"
                          + "        with open(payload) as h:\n"
                          + "            h.read()\n"
                          + "run(sys.argv[2])\n", [4]),
    'list_hides_urlopen': ('src/m.py',
                           "import sys\n"
                           + "from urllib.request import urlopen\n"
                           + "def run(root):\n"
                           + "    parts = list(urlopen(root).read())\n"
                           + "    with open(parts[0]) as h:\n"
                           + "        h.read()\n"
                           + "run(sys.argv[1])\n", [5]),
    'str_hides_request': ('src/m.py',
                          "import sys, requests\n"
                          + "def run(root):\n"
                          + "    name = str(requests.get(root).text)\n"
                          + "    with open(name) as h:\n"
                          + "        h.read()\n"
                          + "run(sys.argv[1])\n", [4]),
    # A config file the NETWORK chose is not the operator's. `CWE22_OPERATOR_FILE_PARSERS`' own table
    # comment says the chain only clears when the file argument is itself operator-supplied, and the
    # parse-leaf early return skipped that check -- both rows went quiet until the leaf was made to
    # descend (`scratch/_c22_r5_parseleaf_probe.py`). The operator-pointed twin is the control, booked
    # in C22_LOCAL_CLI_RETIREMENT: it must STAY quiet, or the fix is a blanket rather than a proof.
    'parse_json_file_remote_cfg': ('src/m.py',
                                   "import sys\n"
                                   + "from transformers.utils import parse_json_file\n"
                                   + "def run(root):\n"
                                   + "    cfg = parse_json_file(root)\n"
                                   + "    with open(cfg['out'], 'w') as h:\n"
                                   + "        h.write('x')\n"
                                   + "import requests\n"
                                   + "run(requests.get(sys.argv[1]).text)\n", [5]),
    'parse_yaml_file_remote_cfg': ('src/m.py',
                                   "import sys\n"
                                   + "from transformers.utils import parse_yaml_file\n"
                                   + "def run(root):\n"
                                   + "    cfg = parse_yaml_file(root)\n"
                                   + "    with open(cfg['out'], 'w') as h:\n"
                                   + "        h.write('x')\n"
                                   + "import requests\n"
                                   + "run(requests.get(sys.argv[1]).text)\n", [5]),
}

# Slice D fixtures: the hub cache-resolver origin proof. (path, source, loud lines, sink_records).
# Every quiet row must register nothing, and every veto row must still register and still shout.
C22_RESOLVER_FIXTURES = {
    # The quiet fixtures stay quiet and register nothing. `resolver_bare_import_read` does carry the
    # argv call site now, so that the two hub mutations have a row they can re-loud: with the resolved
    # origin in the file, blinding the resolver proof or its import binding gives [3] (measured,
    # scratch/_c22_r3_partition_measure.py --mut=resolver / --mut=bindings) instead of nothing at all.
    'resolver_bare_import_read': ('src/convert_x_to_pytorch.py',
                                  "from huggingface_hub import hf_hub_download\n"
                                  + "def get_labels(repo_id, filename):\n"
                                  + "    with open(hf_hub_download(repo_id, filename), \"r\") as h:\n"
                                  + "        return h.read()\n"
                                  + "import sys\n"
                                  + "print(get_labels(sys.argv[1], sys.argv[2]))\n", [], 0),
    'resolver_qualified_read': ('src/convert_x_to_pytorch.py',
                                "import huggingface_hub\n"
                                + "def get_labels(repo_id, filename):\n"
                                + "    with open(huggingface_hub.hf_hub_download(repo_id, filename)) as h:\n"
                                + "        return h.read()\n"
                                # The qualified spelling is recognised without any binding table, so
                                # this one must stay quiet and register nothing even when the bare
                                # twin goes loud under the binding mutation. No argv call site here:
                                # its silence is what the mutation has to leave alone.
                                + "import sys\n"
                                + "print(sys.argv[1])\n", [], 0),
    'resolver_cached_download_read': ('src/convert_x_to_pytorch.py',
                                      "from huggingface_hub import cached_download, hf_hub_url\n"
                                      + "def get_labels(repo_id, filename):\n"
                                      + "    with open(cached_download(hf_hub_url(repo_id, filename)), \"r\") as h:\n"
                                      + "        return h.read()\n", [], 0),
    # The four veto fixtures keep their exact asserted lines -- [4], [4], [3], [3] -- and each now
    # earns that loudness from a command-line value reaching the arguments
    # (`_c22_path_sink_reaches_operator`), which is what the mandate requires now that the retired
    # blanket no longer answers "unproven" with "untrusted". What each row still proves is the hub
    # conjunct named in its own comment, and the sink still registers.
    'resolver_local_def_is_not_a_binding': ('src/convert_x_to_pytorch.py',
                                            "def hf_hub_download(repo, name):\n"
                                            + "    return repo\n"
                                            + "def get_labels(repo_id, filename):\n"
                                            + "    with open(hf_hub_download(repo_id, filename), \"r\") as h:\n"
                                            + "        return h.read()\n"
                                            + "import sys\n"
                                            # The leaf spelling is what a same-named local `def` cannot
                                            # vouch for; the argv call site is what makes the row's
                                            # loudness something the engine earned rather than assumed.
                                            + "print(get_labels(sys.argv[1], sys.argv[2]))\n", [4], 1),
    'resolver_join_prefix_stays_loud': ('src/convert_x_to_pytorch.py',
                                        "from huggingface_hub import hf_hub_download\n"
                                        + "import os\n"
                                        + "def get_labels(root_dir, repo_id, filename):\n"
                                        + "    with open(os.path.join(root_dir, hf_hub_download(repo_id, filename)), \"r\") as h:\n"
                                        + "        return h.read()\n"
                                        + "import sys\n"
                                        # `root_dir` is handed a value the operator typed, so the
                                        # attacker prefix is a real prefix of a real untrusted path:
                                        # the join refusal is the only veto left standing here.
                                        + "print(get_labels(sys.argv[1], sys.argv[2], sys.argv[3]))\n",
                                        [4], 1),
    'resolver_write_mode_stays_loud': ('src/convert_x_to_pytorch.py',
                                       "from huggingface_hub import hf_hub_download\n"
                                       + "def get_labels(repo_id, filename):\n"
                                       + "    with open(hf_hub_download(repo_id, filename), \"w\") as h:\n"
                                       + "        h.write(\"x\")\n"
                                       + "import sys\n"
                                       # Write mode is never a cache read, so the mode veto keeps the
                                       # sink even though the origin is the resolver's own.
                                       + "print(get_labels(sys.argv[1], sys.argv[2]))\n", [3], 1),
    'resolver_runtime_mode_stays_loud': ('src/convert_x_to_pytorch.py',
                                         "from huggingface_hub import hf_hub_download\n"
                                         + "def get_labels(repo_id, filename, stream_mode):\n"
                                         + "    with open(hf_hub_download(repo_id, filename), stream_mode) as h:\n"
                                         + "        return h.read()\n"
                                         + "import sys\n"
                                         # A mode that is not a literal could be 'w' at runtime, and
                                         # here it is exactly the value the operator typed, which is
                                         # why this row registers twice now: the open() and the argv
                                         # value that decides its mode.
                                         + "mode_var = sys.argv[1]\n"
                                         + "print(get_labels('bert-base/rag', 'labels.txt', mode_var))\n",
                                         [3], 2),
}

# The five rows this round's supersession actually retired, spelled exactly as they were asserted on
# HEAD and restated at the value the live engine prints for them. `scratch/_c22_r3_engines.py --diff`
# reported every one of them head-only (HEAD reports the line, live reports nothing), so each is a
# genuine supersession and not a row this round never touched; and each fixture's proposition here IS
# the retired blanket -- "a filesystem sink I cannot prove safe is untrusted" -- which is why the row
# stays in the gate as a measured quiet instead of being deleted with the blanket that made it loud.
# The last element is the line HEAD printed for it, which is what
# `c22_open_taint_blanket_restored` has to bring back.
C22_BLANKET_RETIREMENT = {
    'runtime_read_unproven': ('src/m.py',
                              "def f(filename):\n"
                              + "    with open(filename) as h:\n"
                              + "        return h.read()\n"
                              + "import sys\n"
                              + "print(sys.argv[1])\n", [], 1, 2),
    'resolver_local_def_unproven': ('src/convert_x_to_pytorch.py',
                                    "def hf_hub_download(repo, name):\n"
                                    + "    return repo\n"
                                    + "def get_labels(repo_id, filename):\n"
                                    + "    with open(hf_hub_download(repo_id, filename), \"r\") as h:\n"
                                    + "        return h.read()\n"
                                    + "import sys\n"
                                    + "print(sys.argv[1])\n", [], 1, 4),
    'resolver_join_prefix_unproven': ('src/convert_x_to_pytorch.py',
                                      "from huggingface_hub import hf_hub_download\n"
                                      + "import os\n"
                                      + "def get_labels(root_dir, repo_id, filename):\n"
                                      + "    with open(os.path.join(root_dir, hf_hub_download(repo_id, filename)), \"r\") as h:\n"
                                      + "        return h.read()\n"
                                      + "import sys\n"
                                      + "print(sys.argv[1])\n", [], 1, 4),
    'resolver_write_mode_unproven': ('src/convert_x_to_pytorch.py',
                                     "from huggingface_hub import hf_hub_download\n"
                                     + "def get_labels(repo_id, filename):\n"
                                     + "    with open(hf_hub_download(repo_id, filename), \"w\") as h:\n"
                                     + "        h.write(\"x\")\n"
                                     + "import sys\n"
                                     + "print(sys.argv[1])\n", [], 1, 3),
    'resolver_runtime_mode_unproven': ('src/convert_x_to_pytorch.py',
                                       "from huggingface_hub import hf_hub_download\n"
                                       + "def get_labels(repo_id, filename, stream_mode):\n"
                                       + "    with open(hf_hub_download(repo_id, filename), stream_mode) as h:\n"
                                       + "        return h.read()\n"
                                       + "import sys\n"
                                       + "print(sys.argv[1])\n", [], 1, 3),
}

# Slice E fixtures: the operator-program proof. Each entry is (path, source, CWE, loud lines,
# CWE sink_records) and every expectation is the number the working-copy engine printed for that
# exact string -- see scratch/_slice_e5.py. Quiet rows must register nothing new, loud rows must
# still register, and no expectation here is a wildcard.
OP_ARGV = ("import argparse\n"
           + "import os\n"
           + "import shutil\n"
           + "\n"
           + "parser = argparse.ArgumentParser()\n")
OP_WRITE = ("\n"
            + "\n"
            + "def convert(out_path):\n"
            + "    with open(out_path, 'w') as h:\n"
            + "        h.write('x')\n"
            + "\n")
OP_MAIN = ("\n"
           + "if __name__ == '__main__':\n"
           + "    args = parser.parse_args()\n")

C22_OPERATOR_FIXTURES = {
    # The two presence facts and a walkable chain: quiet.
    'operator_positional_call': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN
                                 + "    convert(args.checkpoint)\n", 'CWE-22', [], 1),
    'operator_keyword_call': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN
                              + "    convert(out_path=args.checkpoint)\n", 'CWE-22', [], 1),
    'operator_assigned_local': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN
                                + "    path = args.checkpoint\n    convert(path)\n", 'CWE-22', [], 1),
    'operator_rmtree_built_dir': ('src/m.py', OP_ARGV
                                  + "\n\ndef convert(out_dir):\n"
                                  + "    tmp = os.path.join(out_dir, 'tmp')\n"
                                  + "    shutil.rmtree(tmp)\n"
                                  + "\n" + OP_MAIN + "    convert(args.model_dir)\n",
                                  'CWE-22', [], 1),
    # Every one of these is an absence or an unresolvable value: loud, and still registered.
    # `no_main_guard_stays_loud` left this table for `C22_RETIRED_BY_LOCAL_CLI` below: round 5's
    # local-command-line demotion retires its report, and the reason it used to be loud -- Slice E's
    # proof needs BOTH presence facts -- is still asserted, by M1 with the demotion ambient-disabled.
    # ── 2026-11-10 supersession: three rows this tier used to pin LOUD on "unknown is loud" ──────
    # The sink-generalisation slice ended the entrypoint blanket: a `main_guard` module no longer
    # lends a proof to a sink it cannot connect to a command line, and an ABSENCE of a caller is now
    # answered the way the mandate words it -- "must NOT emit on unproven bare variables or attributes
    # unless an active, resolved untrusted taint source reaches the path argument". So `convert` never
    # called, a `**opts` splat, and a lambda parameter that shadows the parsed namespace are three
    # spellings of the same thing: the file cannot show who hands the value over, and showing is what
    # is now required. They are renamed rather than re-tuned, and the reason stays in this file: the
    # rows are quiet BECAUSE the proof is unanswerable, which is the opposite of the old answer and
    # must not be mistaken for a fixture that stopped mattering. `unknown_call`, `unknown_wrap`,
    # `unbound_wrapper`, `holder_*` and `*_shadows`-with-a-real-caller all still resolve to a typed
    # command line and stay loud for the original reason.
    'uncalled_function_now_unproven': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN, 'CWE-22', [], 1),
    'unknown_call_stays_loud': ('src/m.py', OP_ARGV
                                + "\n\ndef convert(out_path):\n"
                                + "    with open(fetch_root(out_path), 'w') as h:\n"
                                + "        h.write('x')\n"
                                + "\n" + OP_MAIN + "    convert(args.checkpoint)\n",
                                'CWE-22', [9], 1),
    'unknown_wrap_stays_loud': ('src/m.py', OP_ARGV
                                + "\n\ndef convert(out_path):\n"
                                + "    with open(resolve(out_path), 'w') as h:\n"
                                + "        h.write('x')\n"
                                + "\n" + OP_MAIN + "    convert(args.checkpoint)\n",
                                'CWE-22', [9], 1),
    'unbound_wrapper_stays_loud': ('src/m.py', OP_ARGV
                                   + "\n\ndef convert(out_path):\n"
                                   + "    with open(removeprefix(out_path, \"pre\"), 'w') as h:\n"
                                   + "        h.write('x')\n"
                                   + "\n" + OP_MAIN + "    convert(args.checkpoint)\n",
                                   'CWE-22', [9], 1),
    'environ_value_stays_loud': ('src/m.py', OP_ARGV
                                 + "\ndef convert_gin(gin_file):\n"
                                 + "    with open(gin_file, 'r') as f:\n"
                                 + "        raw = f.read()\n    return raw\n"
                                 + "\n\ndef run():\n    convert_gin(os.environ.get('GIN_FILE'))\n"
                                 + "\n" + OP_MAIN + "    run()\n", 'CWE-22', [8, 14], 2),
    'splat_call_now_unproven': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN
                                + "    opts = {'out_path': args.checkpoint}\n    convert(**opts)\n",
                                'CWE-22', [], 2),
    'environ_rmtree_stays_loud': ('src/m.py', OP_ARGV
                                  + "\ndef convert(out_dir):\n"
                                  + "    tmp = os.path.join(out_dir, 'tmp')\n"
                                  + "    shutil.rmtree(tmp)\n"
                                  + "\n\ndef run():\n    convert(os.environ.get('D'))\n"
                                  + "\n" + OP_MAIN + "    run()\n", 'CWE-22', [9], 1),
    # The holder has to still be a parsed command line in the scope that reads it. Each row below is
    # a way the trust could be borrowed without being earned, and the last two are the shapes the CI
    # arena's converter scripts actually use, so they must stay quiet for the right reason.
    'holder_rebound_stays_loud': ('src/m.py', OP_ARGV + OP_WRITE
                                  + "\nargs = parser.parse_args()\nargs = fetch_from_socket()\n"
                                  + "convert(args.dest)\n" + OP_MAIN, 'CWE-22', [9, 15], 2),
    'holder_is_param_stays_loud': ('src/m.py', OP_ARGV
                                   + "\nargs = parser.parse_args()\n\n\ndef convert(args):\n"
                                   + "    with open(args.dest, 'w') as h:\n        h.write('x')\n"
                                   + "\n\nconvert(os.environ['P'])\n" + OP_MAIN, 'CWE-22', [11], 1),
    'holder_field_written_stays_loud': ('src/m.py', OP_ARGV
                                        + "\nargs = parser.parse_args()\n"
                                        + "args.dest = fetch_payload()\n"
                                        + "with open(args.dest, 'w') as h:\n    h.write('x')\n"
                                        + OP_MAIN, 'CWE-22', [9], 1),
    'loop_target_shadows_stays_loud': ('src/m.py', OP_ARGV
                                       + "\nargs = parser.parse_args()\n"
                                       + "for args in scan_roots():\n"
                                       + "    with open(args.dest, 'w') as h:\n        h.write('x')\n"
                                       + OP_MAIN, 'CWE-22', [9], 1),
    'lambda_param_shadow_now_unproven': ('src/m.py', OP_ARGV
                                         + "\nargs = parser.parse_args()\n"
                                         + "write = lambda args: open(args.dest, 'w')\n"
                                         + OP_MAIN, 'CWE-22', [], 1),
    'nested_tuple_rebind_stays_loud': ('src/m.py', OP_ARGV
                                       + "\nargs = parser.parse_args()\n"
                                       + "head, (args, tail) = split_request(body())\n"
                                       + "with open(args.dest, 'w') as h:\n    h.write('x')\n"
                                       + OP_MAIN, 'CWE-22', [9], 1),
    'argv_from_socket_stays_loud': ('src/m.py', OP_ARGV
                                    + "\nargv = read_socket()\n"
                                    + "with open(argv.out, 'w') as h:\n    h.write('x')\n"
                                    + OP_MAIN, 'CWE-22', [8], 1),
    'namespace_handoff_quiet': ('src/m.py', OP_ARGV
                                + "\nargs = parser.parse_args()\n\n\ndef convert(args):\n"
                                + "    with open(args.dest, 'w') as h:\n        h.write('x')\n"
                                + "\n\nconvert(args)\n" + OP_MAIN, 'CWE-22', [], 0),
    'other_scope_local_quiet': ('src/m.py', OP_ARGV + OP_WRITE
                                + "\n\ndef peek(chkpt):\n    args = chkpt[\"cfg\"]\n"
                                + "    return args\n" + OP_MAIN + "    convert(args.checkpoint)\n",
                                'CWE-22', [], 1),
}

# ── Round 5 re-filed: the one Slice E row whose REPORT the local-command-line demotion retires ──────
# `no_main_guard_stays_loud` was loud because Slice E's operator-program proof demands BOTH presence
# facts, and this module has no `if __name__ == '__main__':`. That proposition is untouched and M1
# still falsifies it -- with the demotion ambient-disabled, forcing the guard fact at the tree-level
# source still turns [9] into []. What moved is only the report: the value reaching the sink is
# `args.checkpoint`, `args` is bound to this program's own `parser.parse_args()`, and the mandate says
# the operator who typed that command line is the process owner, not a remote attacker. The main guard
# decides whether a module is a PROGRAM; it does not decide who typed the argv that `parse_args()`
# read, and round 5's question is the second one.
#
# Re-filed, not re-blessed: the row is asserted at its measured live value ([], 0 registered, 2
# sink_records -- the demotion removes the sink, never the record), and
# `c22_local_cli_no_main_guard_restored` hands the retired rule back and must restore
# [9] / 2 registered / 2 records. The source is the same bytes the table above used to carry.
C22_RETIRED_BY_LOCAL_CLI = {
    'no_main_guard_was_loud': ('src/m.py', OP_ARGV + OP_WRITE
                               + "\nargs = parser.parse_args()\nconvert(args.checkpoint)\n",
                               'CWE-22', [], 0, 2, [9], 2),
}

# The `f.read()` under a muted operator-program open(): the CWE-22 row is gone, so the unbounded
# read is only quiet because the same proof is wired into the CWE-770 branch.
C770_OPERATOR_READ = ('src/m.py',
                      "import argparse\n"
                      + "import os\n"
                      + "import regex as re\n"
                      + "import shutil\n"
                      + "\n"
                      + "parser = argparse.ArgumentParser()\n"
                      + "\n\ndef convert_gin(gin_file):\n"
                      + "    with open(gin_file, 'r') as f:\n"
                      + "        raw = f.read()\n"
                      + "    return re.findall(r'(.*) = ([0-9.]*)', raw)\n"
                      + "\n" + OP_MAIN + "    convert_gin(args.gin_file)\n",
                      'CWE-770', [], 0)

# Slice F: the same two presence facts, applied to CWE-117. Every fixture is a HYBRID module -- it
# parses its own command line under `if __name__ == '__main__':` and also holds a `request`-shaped
# client value, because a log call only registers when the file has real client data somewhere. The
# client line (12) is therefore loud in all of them; what the slice decides is only the second line.
# Expectations are the numbers the working-copy engine printed for these exact strings.
C117_HEAD = ("import argparse\n"
             + "import logging\n"
             + "import os\n"
             + "import sys\n"
             + "\n"
             + "logger = logging.getLogger(__name__)\n"
             + "parser = argparse.ArgumentParser()\n")
C117_CLIENT = ("\n"
               + "\ndef handle(request):\n"
               + "    payload = request.args.get('q')\n"
               + "    logger.info(f'query = {payload}')\n")
C117_MAIN = ("\n"
             + "if __name__ == '__main__':\n"
             + "    args = parser.parse_args()\n")
C117_JSON_ARGV_MAIN = ("\n"
                       + "if __name__ == '__main__':\n"
                       + "    args = parser.parse_json_file(json_file=os.path.abspath(sys.argv[1]))\n")
C117_JSON_UNKNOWN_MAIN = ("\n"
                          + "if __name__ == '__main__':\n"
                          + "    args = parser.parse_json_file(json_file=fetch_path())\n")


def c117_case(body, main=C117_MAIN, head=C117_HEAD):
    return head + C117_CLIENT + body + main


C117_OPERATOR_FIXTURES = {
    # The logged text is this program's own argv, or a value CPython forces to have no line break.
    'argv_field_quiet': ('src/m.py', c117_case(
        "\n\ndef show():\n    logger.info(f'root = {args.model_dir}')\n"),
        'CWE-117', [12], 1),
    'numeric_local_quiet': ('src/m.py', c117_case(
        "\n\ndef report():\n    total = len(items) * 2\n"
        + "    logger.info(f'total = {total}')\n"),
        'CWE-117', [12], 1),
    'sealed_builtin_quiet': ('src/m.py', c117_case(
        "\n\ndef report(request_count):\n    logger.info(f'n = {len(request_count)}')\n"),
        'CWE-117', [12], 1),
    'json_config_from_argv_quiet': ('src/m.py', c117_case(
        "\n\ndef show():\n    logger.info(f'cfg = {args.train_file}')\n",
        main=C117_JSON_ARGV_MAIN),
        'CWE-117', [12], 1),
    # One unprovable field in the line and the whole line is reported again: the rule is every value,
    # not any value, and `str()`/a client payload/rebinding refuse.
    'client_text_stays_loud': ('src/m.py', c117_case(
        "\n\ndef other(request):\n    logger.info(f'e = {request.headers}')\n"),
        'CWE-117', [12, 16], 2),
    'mixed_client_and_argv_stays_loud': ('src/m.py', c117_case(
        "\n\ndef show():\n    logger.info(f'mix = {args.model_dir} {query}')\n"),
        'CWE-117', [12, 16], 2),
    'rebound_client_stays_loud': ('src/m.py', c117_case(
        "\n\ndef report():\n    total = len(items) * 2\n    total = query\n"
        + "    logger.info(f'total = {total}')\n"),
        'CWE-117', [12, 18], 2),
    # The newline-in-a-literal refusal and the shadowed-builtin refusal are predicate-level facts: a
    # log line whose only unproven value is a literal cannot register a CWE-117 sink at all (measured
    # 1 record, [12] loud), so pinning them as sink fixtures would be vacuous. They live in
    # C117_VALUE_PROOFS below, which asks `_c22_value_is_newline_free` the question directly.
    # A config file is only as trusted as the path it was read from.
    'json_config_from_unknown_stays_loud': ('src/m.py', c117_case(
        "\n\ndef show():\n    logger.info(f'cfg = {args.train_file}')\n",
        main=C117_JSON_UNKNOWN_MAIN),
        'CWE-117', [12, 16], 2),
    # Two functions that spell the same local the same way are two different proofs: the small one
    # binds an arithmetic value, the big one binds the request, and the value cache has to answer each
    # occurrence on its own.
    'same_name_two_scopes_split': ('src/m.py', c117_case(
        "\n\ndef small():\n    total = len(items) * 2\n"
        + "    logger.info(f'total = {total}')\n"
        + "\n\ndef big(request):\n    total = request.headers\n"
        + "    logger.info(f'total = {total}')\n"),
        'CWE-117', [12, 22], 2),
    # And a module that does not both parse its own command line and run as a program keeps all of it.
    'no_main_guard_stays_loud': ('src/m.py', c117_case(
        "\n\ndef report():\n    total = len(items) * 2\n"
        + "    logger.info(f'total = {total}')\n", main="\n\nreport()\n"),
        'CWE-117', [12, 17], 2),
    'no_parse_stays_loud': ('src/m.py', C117_HEAD.replace(
        "parser = argparse.ArgumentParser()\n", "") + C117_CLIENT
        + "\n\ndef report():\n    total = len(items) * 2\n"
        + "    logger.info(f'total = {total}')\n"
        + "\nif __name__ == '__main__':\n    report()\n",
        'CWE-117', [11, 16], 2),
}

# Tier 9: the frozen blessed CWE-22 keys, scanned under a key that the engine's corpus-name shield
# cannot see (`src__`/`tests__`/`corpus_big8`/`_p3_big` all make every CWE-22 exemption inert, so a
# green parity run is not the reach proof). Lines are the keys themselves, from the frozen .keys.
# Twenty-two of the 24 move to `vendor/...`. The two `cwe_937_insecure_protocol` parity keys do not,
# and they are in BLESSED_C22_BASELINE_NAME below rather than dropped: their loudness on the live
# engine is the exact-identity pin `CWE22_OPEN_TAINT_KEEP_LOUD`, which is keyed on the basename the
# baseline owns, so re-spelling the module as `vendor/proto/v06bad.py` does not lose a finding to a
# name -- it loses the identity the contract sanctions for a blessed TP.
BLESSED_C22_REACH = {
    'src__transformers__modeling_utils.py': ('vendor/transformers/modeling_utils.py',
                                             (336, 3494, 3564)),
    'src__transformers__trainer.py': ('vendor/transformers/trainer.py', (2008, 4301)),
    'tests__generation__test_utils.py': ('vendor/generation/test_utils.py', (5537, 5539, 5565)),
    'tests__models__markuplm__test_tokenization_markuplm.py': ('vendor/markuplm/tok.py',
                                                               (73, 75, 77, 138)),
    'tests__test_modeling_common.py': ('vendor/base/modeling_common.py', (1279,)),
    'tests__test_tokenization_mistral_common.py': ('vendor/mistral/tok.py', (263, 274, 280)),
    'cwe_22_traversal/bad.py': ('vendor/trav/bad.py', (5,)),
    'cwe_22_traversal/test_v01_bad.py': ('vendor/trav/v01.py', (5,)),
    'cwe_22_traversal/test_v02_bad.py': ('vendor/trav/v02.py', (8,)),
    'cwe_22_traversal/test_v03_bad.py': ('vendor/trav/v03.py', (5,)),
    'cwe_22_traversal/test_v05_bad.py': ('vendor/trav/v05.py', (8,)),
    'runner.py': ('vendor/runner.py', (105,)),
}

# The two parity CWE-22 keys, scanned under the exact frozen key string the parity baseline itself
# uses. This is a blessed-key check and stays: dropping either line is the immediate hard rollback the
# Zero-FN shield names. What is NOT asserted here any more is the renamed copy -- that the same bytes
# under `vendor/proto/v06bad.py` report -- because the live engine only keeps those two lines loud
# through `CWE22_OPEN_TAINT_KEEP_LOUD`, whose identity is `(basename(file), lineno)`. Renaming the
# module drops the pin, and what remains is the owed rule's own answer: `download_file` is called in
# this file only with the literals `"ftp.debian.org"`/`"release.txt"`, no CLI/remote value reaches
# `open(filename, "wb")`, so there is no resolved origin to report and the row is quiet. That quiet is
# `_c22_open_sink_owes_proven_taint` refusing an assumption, measured head-only for both files by
# `scratch/_c22_r3_engines.py --file`; it is not a suppression, and no folder or module name silences
# anything anywhere in this engine -- the carrier tier below is what proves that.
BLESSED_C22_BASELINE_NAME = {
    'cwe_937_insecure_protocol/test_v06_bad.py': (
        'benchmark/corpus/cwe_937_insecure_protocol/test_v06_bad.py', (6,)),
    'cwe_937_insecure_protocol/test_v06_good.py': (
        'benchmark/corpus/cwe_937_insecure_protocol/test_v06_good.py', (7,)),
}

# The carrier the name-blindness property now rides on: one module, five different names, and a
# loudness that comes from a resolved origin instead of from an identity pin. Both spellings are
# measured on the shipped bytes: with `load(os.environ['PATH_IN'])` in the file the row is [5, 8] / 2
# sink_records under EVERY name, and without it [] / 1 sink_record under EVERY name. The names include
# the two `vendor/proto/...` spellings the v06 parity bytes lost their pin under, so the same keys that
# made the corpus rows name-sensitive are shown to make an earned row and an unearned row
# name-invariant -- which is the only direction a suppression is allowed to go.
#
# Round 5 moved the earned carrier off `sys.argv[1]`. The local-command-line demotion retires a sink
# whose only resolved root is this program's own command line, so `load(sys.argv[1])` is now [] / 2
# under every one of these names -- still name-invariant, but quiet, and a quiet carrier cannot show
# that a name failed to silence an earned row. `os.environ` is a resolved origin the demotion's blinded
# walk still sees, so the loudness is earned exactly as before and the proposition keeps its words. The
# argv spelling is kept beside it as a measured retirement: it must be [] / 2 under every name, and
# `c22_local_cli_demotion_restored` hands the rule back and must return [5, 8] / 2 under every name.
CARRIER_OPEN_ENV = ("import os\nimport sys\n\ndef load(path):\n    with open(path) as h:\n"
                    "        return h.read()\n\nload(os.environ['PATH_IN'])\n")
CARRIER_OPEN_ARGV = ("import os\nimport sys\n\ndef load(path):\n    with open(path) as h:\n"
                     "        return h.read()\n\nload(sys.argv[1])\n")
CARRIER_OPEN_UNPROVEN = ("import os\nimport sys\n\ndef load(path):\n    with open(path) as h:\n"
                         "        return h.read()\n")
NAME_BLIND_KEYS = ('vendor/proto/v06bad.py', 'vendor/proto/v06good.py',
                   'src/convert_x_to_pytorch.py', 'tools/one.py', 'm.py')
C22_NAME_BLIND_CARRIER = (
    ('carrier_open_env', CARRIER_OPEN_ENV, [5, 8], 2),
    ('carrier_open_unproven', CARRIER_OPEN_UNPROVEN, [], 1),
)
# The spelling round 5 retired, at its measured live value under every name. `HEAD` here is the
# pre-demotion answer, which is what the restoration mutation has to bring back.
C22_NAME_BLIND_RETIRED = (
    ('carrier_open_argv', CARRIER_OPEN_ARGV, [], 2, [5, 8]),
)
# The single line tier 10's forced-True mutant must silence, and the file it is read from.
REACH_MUTATION_LEAF = 'tests__test_modeling_common.py'
REACH_MUTATION_KEY = 'vendor/base/modeling_common.py'
REACH_MUTATION_LINE = 1279

UNIFORM_UNIT = ("import random\n"
                + "class A:\n"
                + "    def __call__(self, hidden_states, deterministic=True):\n"
                + "        dropout_probability = random.uniform(0, 1)\n"
                + "        if not deterministic and dropout_probability < self.dropout:\n"
                + "            hidden_states = dropout(hidden_states)\n"
                + "        return hidden_states\n")
SAMPLE_INDEX = ("import random\n"
                + "def log_examples(train_dataset, logger):\n"
                + "    for index in random.sample(range(len(train_dataset)), 3):\n"
                + "        logger.info(train_dataset[index])\n")

# Slice B fixtures: (path, source, expected loud lines). Quiet rows must also register no sink.
C338_FIXTURES = {
    'uniform_unit_quiet': ('src/transformers/models/m.py', UNIFORM_UNIT, []),
    'sample_index_quiet': ('examples/run_qa.py', SAMPLE_INDEX, []),
    'uniform_runtime_bounds_loud': ('src/m.py',
                                    "import random\n"
                                    + "def f(self):\n"
                                    + "    aspect = random.uniform(self.lo, self.hi)\n"
                                    + "    return aspect\n", [3]),
    'sample_literal_alphabet_loud': ('src/m.py',
                                     "import random\n"
                                     + "def f():\n"
                                     + "    for i in random.sample(range(10), 6):\n"
                                     + "        print(i)\n", [3]),
    'uniform_credential_veto_loud': ('src/m.py',
                                     "import random\n"
                                     + "def f():\n"
                                     + "    secrets = random.uniform(0, 1)\n"
                                     + "    return secrets\n", [3]),
    'sample_passwords_veto_loud': ('examples/m.py',
                                   "import random\n"
                                   + "def f(passwords):\n"
                                   + "    for index in random.sample(range(len(passwords)), 3):\n"
                                   + "        print(index)\n", [3]),
    'sample_seeds_veto_loud': ('examples/m.py',
                               "import random\n"
                               + "def f(seeds):\n"
                               + "    for index in random.sample(range(len(seeds)), 3):\n"
                               + "        print(index)\n", [3]),
    'blessed_scale_loud': ('tests/test_modeling_common.py',
                           "def f(rng, values, scale):\n"
                           + "    values.append(rng.random() * scale)\n", [2]),
    'blessed_vocab_loud': ('tests/test_modeling_common.py',
                           "def f(rng, values, vocab_size):\n"
                           + "    values.append(rng.randint(0, vocab_size - 1))\n", [2]),
}

# Slice C fixtures: the partition is pre-existing, so these pin behaviour rather than a new predicate.
C208_FIXTURES = {
    'test_credential_int_quiet': ('tests/test_m.py',
                                  "def f(secret_size):\n"
                                  + "    assert secret_size == 2\n", []),
    'test_plain_int_quiet': ('tests/test_m.py',
                             "import unittest\n"
                             + "class T(unittest.TestCase):\n"
                             + "    def test_a(self):\n"
                             + "        batch_size = 2\n"
                             + "        assert batch_size == 2\n", []),
    'token_constant_loud': ('src/m.py',
                            "def f(input_ids, bos_token_id):\n"
                            + "    if input_ids == bos_token_id:\n"
                            + "        return 1\n", [2]),
}


def check_baseline_domain() -> list:
    """Only the two frozen key files are read here, each with its join written at the open site.

    Opening a per-key corpus path from a loop variable is itself a variable-derived path, and the
    engine reports it -- that is how an earlier draft of this gate added a NEW parity key. The
    behavioural half of the domain proof lives in check_blessed_lines_stay_loud instead.
    """
    failures = []
    expected = {'parity_before.keys': (424, 9), 'big8_before.keys': (119, 7)}
    for keys_name, (total_rows, c338_rows) in expected.items():
        with open(os.path.join(GATES_DIR, keys_name), encoding='utf-8') as handle:
            text = handle.read()
        rows = []
        for line in text.splitlines():
            entry = line.strip()
            if entry.startswith('('):
                row = ast.literal_eval(entry)
                if len(row) >= 3:
                    rows.append(row)
                    if row[2] == 'CWE-338':
                        c338_rows -= 1
        if len(rows) != total_rows:
            failures.append(f'{keys_name}: {len(rows)} keys, expected {total_rows}')
        if c338_rows:
            failures.append(f'{keys_name}: the CWE-338 key census moved, so the value-domain proof '
                            'is no longer over the frozen baseline')
        print(f'  tier1 {keys_name}: {len(rows)} keys, CWE-338 census intact')
    return failures


def check_slice_a() -> list:
    failures = []
    for name, (path, source, expected_loud, expected_records) in sorted(C22_FIXTURES.items()):
        loud, _registered, records = scan({path: source}, 'CWE-22')
        if loud != expected_loud:
            failures.append(f'{name}: CWE-22 lines {loud}, expected {expected_loud}')
        if records != expected_records:
            failures.append(f'{name}: {records} CWE-22 sink_records, expected {expected_records}; '
                            'the registration prune is the whole yield of this slice')
    print('  tier2 slice A fixtures checked:', len(C22_FIXTURES))
    for name, (path, source, expected_loud, expected_records, head_line) in sorted(
            C22_LOCAL_CLI_RETIREMENT.items()):
        loud, _registered, records = scan({path: source}, 'CWE-22')
        if loud != expected_loud:
            failures.append(f'{name}: CWE-22 lines {loud}, expected {expected_loud} (HEAD line '
                            f'{head_line}); the local-command-line demotion is off, so a CLI-rooted '
                            'path sink is being reported as untrusted again')
        if records != expected_records:
            failures.append(f'{name}: {records} CWE-22 sink_records, expected {expected_records} '
                            '(the demotion removes the sink, not the record)')
    print('  tier2b slice A reports retired by the local CLI rule:',
          len(C22_LOCAL_CLI_RETIREMENT))
    for name, (path, source, expected_loud) in sorted(C22_LOCAL_CLI_FN_SHIELDS.items()):
        loud, _registered, _records = scan({path: source}, 'CWE-22')
        if loud != expected_loud:
            failures.append(f'{name}: CWE-22 lines {loud}, expected {expected_loud}; a remote root is '
                            'hiding behind an unanalysed call or a container reshaper, which is the '
                            'false negative the resolved-origin proof exists to refuse')
    print('  tier2c remote roots the CLI demotion must not hide:',
          len(C22_LOCAL_CLI_FN_SHIELDS))
    return failures


def check_slice_b() -> list:
    failures = []
    for name, (path, source, expected) in sorted(C338_FIXTURES.items()):
        loud, registered, _records = scan({path: source}, 'CWE-338')
        if loud != expected:
            failures.append(f'{name}: CWE-338 lines {loud}, expected {expected}')
        if expected and not registered:
            failures.append(f'{name}: reported but no sink registered, so the census is not the '
                            'census being asserted')
        if not expected and registered:
            failures.append(f'{name}: quiet but {registered} sink(s) still registered; the prune '
                            'moved back to emission and the cascade is paying for it again')
    print('  tier3 slice B fixtures checked:', len(C338_FIXTURES))
    return failures


def check_slice_c() -> list:
    failures = []
    for name, (path, source, expected) in sorted(C208_FIXTURES.items()):
        loud, _registered, _records = scan({path: source}, 'CWE-208')
        if loud != expected:
            failures.append(f'{name}: CWE-208 lines {loud}, expected {expected}')
    print('  tier4 slice C fixtures checked:', len(C208_FIXTURES))
    return failures


def check_slice_d() -> list:
    failures = []
    for name, (path, source, expected, expected_records) in sorted(C22_RESOLVER_FIXTURES.items()):
        loud, _registered, records = scan({path: source}, 'CWE-22')
        if loud != expected:
            failures.append(f'{name}: CWE-22 lines {loud}, expected {expected}')
        if records != expected_records:
            failures.append(f'{name}: CWE-22 sink_records {records}, expected {expected_records} '
                            '(the mandate is registration, not emission)')
    print('  tier5 slice D fixtures checked:', len(C22_RESOLVER_FIXTURES))
    return failures


def check_blanket_retirement() -> list:
    """The five rows the open() taint requirement retired, restated at their measured live values.

    Each of these spells the retired blanket's own proposition -- an unproven filesystem sink treated
    as untrusted -- and `scratch/_c22_r3_engines.py --diff` printed each asserted line head-only and
    nothing live, so the row belongs in this gate as a measured silence, not as a deleted assertion.
    The registration is untouched (1 `sink_record` apiece): what this round changed is emission, which
    is exactly what the subtract-only `ProvenanceState.UNKNOWN` prune arm and the phase-4/phase-5
    short-circuits were written to do. `c22_open_taint_blanket_restored` is the mutation that proves
    the retirement is the thing that silenced them, by restoring the blanket and bringing each HEAD
    line back.
    """
    failures = []
    for name, (path, source, expected_loud, expected_records, head_line) in sorted(
            C22_BLANKET_RETIREMENT.items()):
        loud, _registered, records = scan({path: source}, 'CWE-22')
        if loud != expected_loud:
            failures.append(f'{name}: CWE-22 lines {loud}, expected {expected_loud} (HEAD line '
                            f'{head_line}); the retired blanket is back, so an unproven filesystem '
                            'sink is being reported as untrusted again')
        if records != expected_records:
            failures.append(f'{name}: {records} CWE-22 sink_records, expected {expected_records} '
                            '(the requirement is subtract-only: the sink still registers)')
    print('  tier5b open() taint retirement pinned:', len(C22_BLANKET_RETIREMENT),
          'unproven rows quiet, each still registering 1 sink_record')
    return failures


TRAINER_LEAF = 'src__transformers__trainer.py'
TRAINER_KEY = 'scratch/_p3_big/' + TRAINER_LEAF
BLESSED_C117_TRAINER = (1602, 1603, 1604, 1605, 1607, 1608, 1610, 1611)
# Filled by the shipped arm below; the mutation compares against it instead of a hand-typed count.
SHIPPED_TRAINER_LOUD = []


def trainer_rows() -> list:
    """One scan of the corpus file the numeric-spec slice would hit, on the repo-relative key.

    Two halves are load-bearing and both were measured. The bytes come from the tracked corpus copy
    (`verify_corpus` hashes it against the pinned value and `scratch/_p3_big/` is git-ignored, so CI
    has nothing else to read -- here they are byte-identical, 233,460 bytes). The key is the baseline
    spelling: with an absolute key the same source yields 12 CWE-117 rows instead of 29 and loses
    blessed lines 1605 and 1607, because `scope_module`/`file_paths` resolve through the
    repo-relative POSIX spelling the frozen `.keys` files themselves use.
    """
    with open(os.path.join(BIG8_CORPUS, TRAINER_LEAF), encoding='utf-8', errors='replace') as handle:
        src = handle.read()
    return scan({TRAINER_KEY: src}, 'CWE-117')


def check_refused_value_slice() -> list:
    """The numeric-format-spec exemption was measured and refused; this tier keeps it refused.

    `format(value, ",")` raises on a `str`, so a `,`-spec field is CPython-proven numeric and
    cannot carry the newline CWE-117 is about. It is still the right answer nowhere: measured over
    the live arena rows it yields 3 rows, and on this corpus the same predicate deletes 8 of the 29
    CWE-117 rows -- all eight are blessed keys (1602, 1603, 1604, 1605, 1607, 1608, 1610, 1611, the
    memory-stat block of `src/transformers/trainer.py`) and not one of them is an FP. 3 FPs for 8
    TPs is the trade the doctrine forbids, so the predicate stays out of the engine and all eight
    rows must be reported.
    """
    failures = []
    global SHIPPED_TRAINER_LOUD
    loud, _registered, _records = trainer_rows()
    SHIPPED_TRAINER_LOUD = list(loud)
    for line in BLESSED_C117_TRAINER:
        if line not in loud:
            failures.append(f'trainer.py:{line} went silent; it is one of the 8 blessed CWE-117 keys '
                            'the numeric-format-spec refusal exists to protect')
    print('  tier8 refused value slice pinned: 8 blessed CWE-117 lines loud '
          f'({len(loud)} CWE-117 rows in the trainer corpus)')
    return failures


def check_slice_e() -> list:
    failures = []
    rows = dict(C22_OPERATOR_FIXTURES)
    rows['operator_program_read'] = C770_OPERATOR_READ
    for name, (path, source, cwe, expected, expected_records) in sorted(rows.items()):
        loud, _registered, records = scan({path: source}, cwe)
        if loud != expected:
            failures.append(f'{name}: {cwe} lines {loud}, expected {expected}')
        if records != expected_records:
            failures.append(f'{name}: {records} {cwe} sink_records, expected {expected_records} '
                            '(the mandate is registration, not emission)')
    print('  tier10 slice E fixtures checked:', len(rows))
    for name, (path, source, cwe, expected, registered, records,
               _head_lines, _head_registered) in sorted(C22_RETIRED_BY_LOCAL_CLI.items()):
        loud, reg, rec = scan({path: source}, cwe)
        if loud != expected:
            failures.append(f'{name}: {cwe} lines {loud}, expected {expected} '
                            '(retired by the local-command-line demotion)')
        if reg != registered or rec != records:
            failures.append(f'{name}: {reg} registered / {rec} sink_records, expected '
                            f'{registered} / {records} (the demotion removes the sink, not the record)')
    print('  tier10b slice E reports retired by the local CLI rule:',
          len(C22_RETIRED_BY_LOCAL_CLI))
    return failures


def newline_free_proof(source: str, hole: str):
    """Ask `_c22_value_is_newline_free` the question it answers, on one f-string hole."""
    tracker = ast_scanner.TaintTracker(files={'src/m.py': source}, max_workers=1)
    mod = next(iter(tracker.file_paths), None)
    tree = tracker.modules.get(mod)
    if tree is None:
        return None
    shadowed = tracker._shadowed_names_in_tree(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.FormattedValue) and ast.unparse(node.value) == hole:
            return tracker._c22_value_is_newline_free(tree, node.value, shadowed)
    return None


def bound_value_probe(source: str, expr: str, names: list) -> list:
    """Ask `_c22_bound_values` the same node under each spelling in `names`, answers unparsed.

    The scope cache keys on (expression, name), so the question this answers is whether the name half
    of that key is real: `args.model_dir` is one node, and the namespace proof and the value chain ask
    it about two different things.
    """
    tracker = ast_scanner.TaintTracker(files={'src/m.py': source}, max_workers=1)
    mod = next(iter(tracker.file_paths), None)
    tree = tracker.modules.get(mod)
    if tree is None:
        return []
    target = None
    for node in ast.walk(tree):
        if ast.unparse(node) == expr and isinstance(node, (ast.Attribute, ast.Name)):
            target = node
            break
    if target is None:
        return []
    out = []
    for name in names:
        found = tracker._c22_bound_values(tree, target, name)
        out.append(None if found is None
                   else tuple(ast.unparse(v) if v is not None else 'None' for v in found[1]))
    return out


# (name, module source, the f-string hole to prove, expectation). `LOG_HEAD` is a module that is NOT
# an operator program: these rows pin the value proof alone, exactly as the arm composes it.
C117_VALUE_PROOFS = (
    ('literal_with_line_break', C117_HEAD + "label = 'a\\nb'\n"
     + "logger.info(f'v = {label}')\n", 'label', False),
    ('literal_without_line_break', C117_HEAD + "label = 'a b'\n"
     + "logger.info(f'v = {label}')\n", 'label', True),
    ('arithmetic_over_sealed_builtin', C117_HEAD + "total = len(items) * 2\n"
     + "logger.info(f'v = {total}')\n", 'total', True),
    ('shadowed_builtin_is_not_sealed', C117_HEAD + "\ndef len(value):\n    return 'a\\nb'\n"
     + "total = len(items) * 2\nlogger.info(f'v = {total}')\n", 'total', False),
    ('comparison_yields_a_bool', C117_HEAD + "enabled = count == 2\n"
     + "logger.info(f'v = {enabled}')\n", 'enabled', True),
    ('attribute_type_is_unknown', C117_HEAD + "logger.info(f'v = {cfg.name}')\n", 'cfg.name', False),
    ('rebound_to_unknown', C117_HEAD + "total = len(items)\ntotal = fetch()\n"
     + "logger.info(f'v = {total}')\n", 'total', False),
)


def check_slice_f() -> list:
    failures = []
    for name, (path, source, cwe, expected, expected_records) in sorted(
            C117_OPERATOR_FIXTURES.items()):
        loud, registered, records = scan({path: source}, cwe)
        if loud != expected:
            failures.append(f'{name}: {cwe} lines {loud}, expected {expected}')
        if records != expected_records:
            failures.append(f'{name}: {records} {cwe} sink_records, expected {expected_records} '
                            f'(registered={registered}; the mandate is registration, not emission)')
    print('  tier11 slice F fixtures checked:', len(C117_OPERATOR_FIXTURES))
    proofs = 0
    for name, source, hole, expected in C117_VALUE_PROOFS:
        got = newline_free_proof(source, hole)
        proofs += 1
        if got is None:
            failures.append(f'{name}: no f-string hole {hole} reached the proof (harness defect)')
        elif got is not expected:
            failures.append(f'{name}: _c22_value_is_newline_free({hole}) = {got}, '
                            f'expected {expected}')
    print('  tier11 slice F value proofs checked:', proofs)
    return failures


def _reach_row(leaf: str, entry: tuple, src: str) -> list:
    """One blessed file, scanned under the key the corpus-name shield cannot see."""
    key, lines = entry
    loud, _registered, _records = scan({key: src}, 'CWE-22')
    gone = [line for line in lines if line not in loud]
    if gone:
        return [f'{leaf}:{gone} went silent under the non-corpus key {key}; with the shield blind '
                'this line is loud only because a resolved origin reaches the sink or because '
                'CWE22_OPEN_TAINT_KEEP_LOUD names this exact (basename, lineno), and a blessed key '
                'that drops is the immediate hard rollback the Zero-FN shield mandates']
    return []


def _baseline_name_row(leaf: str, src: str) -> list:
    """One parity corpus file, scanned under the frozen baseline key that names it.

    This is a blessed-key check and stays untouched by the re-spelling above: `test_v06_bad.py:6` and
    `test_v06_good.py:7` must be emitted, and on the live engine the mechanism that emits them is the
    exact-identity pin, which is keyed on the basename the baseline itself uses. The renamed copy of
    the same bytes is NOT asserted loud anywhere in this gate -- the pin does not reach it, and the
    owed rule declines it because the file calls its parameter only with literals -- and the silence
    that produces is measured and explained in `check_name_blind_partition`, which owns the direction
    a name is allowed to influence.
    """
    key, lines = BLESSED_C22_BASELINE_NAME[leaf]
    loud, _registered, _records = scan({key: src}, 'CWE-22')
    gone = [line for line in lines if line not in loud]
    if gone:
        return [f'{leaf}:{gone} went silent under its own frozen key {key}; the exact-identity '
                'keep-loud pin is the sanctioned mechanism for a blessed CWE-22 key whose caller is '
                'in another module, and losing it is a zero-FN breach']
    return []


def check_name_blind_partition() -> list:
    """No suppression in this engine is keyed on a module or folder name -- measured on one carrier.

    Tier 9's corpus-name arm can only show that a KEEP-LOUD pin is scoped to the identity it names:
    `CWE22_OPEN_TAINT_KEEP_LOUD` matches `(os.path.basename(file), lineno)`, so `test_v06_bad.py`
    keeps its blessed line 6 and `vendor/proto/v06bad.py` does not. That table only ever ADDS a
    finding -- `_c22_open_sink_owes_proven_taint` returns False for a pinned identity and nothing else
    -- which is the instrument AGENTS.md sanctions ("pin those exact K nodes LOUD via fail-closed
    guard or exact AST identity (`KEEP_LOUD_EXCEPTION`)") for a true positive that overlaps the new
    requirement; a path/folder blacklist is the forbidden instrument because it subtracts.

    What must not move with a name is therefore the SILENCE, and it is measured here on bytes whose
    loudness is earned rather than pinned. With `load(os.environ['PATH_IN'])` in the module the open
    reports `[5, 8]` with 2 `sink_records` under every key in `NAME_BLIND_KEYS`, and the same statement
    with no resolved origin is `[]` with 1 `sink_record` under every one of those keys -- including the
    two `vendor/proto/...` names under which the v06 parity bytes lost their pin. If a name ever decided
    whether a sink owes its proof, these rows would split, and the mutation
    `c22_name_scoped_suppression_would_move_the_tier` installs exactly such a blacklist to show this
    tier would see it.

    Round 5 retired the argv spelling of this carrier, and the retirement is measured here too rather
    than deleted: `load(sys.argv[1])` is `[]` / 2 under every one of the same five names, because the
    only resolved root reaching that open is this program's own command line. Name-invariance is the
    proposition, so a retired carrier still has to satisfy it -- and `c22_local_cli_demotion_restored`
    hands the rule back and must return `[5, 8]` / 2 under every name, which is what keeps the
    retirement from being a row this tier simply stopped looking at.
    """
    failures = []
    for name, source, expected_loud, expected_records in C22_NAME_BLIND_CARRIER:
        for key in NAME_BLIND_KEYS:
            loud, _registered, records = scan({key: source}, 'CWE-22')
            if loud != expected_loud or records != expected_records:
                failures.append(
                    f'{name}@{key}: CWE-22 lines {loud} / {records} sink_records, expected '
                    f'{expected_loud} / {expected_records}; a module name changed the answer, so a '
                    'name -- not the resolved origin -- is deciding whether this sink owes its proof')
    for name, source, expected_loud, expected_records, _restored in C22_NAME_BLIND_RETIRED:
        for key in NAME_BLIND_KEYS:
            loud, _registered, records = scan({key: source}, 'CWE-22')
            if loud != expected_loud or records != expected_records:
                failures.append(
                    f'{name}@{key}: CWE-22 lines {loud} / {records} sink_records, expected '
                    f'{expected_loud} / {expected_records}; the retired local-command-line carrier '
                    'moved, so either the demotion stopped being name-invariant or a name bought '
                    'silence that the resolved origin did not')
    print(f'  tier9b name-blind carrier: {len(C22_NAME_BLIND_CARRIER)} spellings x '
          f'{len(NAME_BLIND_KEYS)} module names, one answer each; '
          f'{len(C22_NAME_BLIND_RETIRED)} retired spelling x {len(NAME_BLIND_KEYS)} names')
    return failures


def check_operator_reach() -> list:
    """All 24 blessed CWE-22 keys re-scanned where the corpus-name shield cannot protect them.

    Every CWE-22 exemption in `_sink_context_exempt` sits behind `not is_protected`, and the frozen
    keys live under names carrying `src__`/`tests__`/`corpus_big8`, so parity would stay green even
    if this predicate reached a true positive. These are the same bytes under `vendor/...` keys,
    where the shield is blind and the shape has to stand on its own merits. Each path is a literal
    join at its own `open`: a corpus path resolved from a loop variable is itself a variable-derived
    path, and the engine reports it -- that is how this tier gained a NEW parity key.

    Twenty-two of the 24 blessed lines live here. The two `cwe_937_insecure_protocol` parity keys are
    read under their own frozen baseline names by `_baseline_name_row` at the bottom of this tier,
    because what keeps those two lines on the live engine is the exact-identity pin and a pin travels
    with the identity it names, not with the bytes; `check_name_blind_partition` owns the claim that
    no suppression travels with a name.
    """
    failures = []
    with open(os.path.join(BIG8_CORPUS, 'src__transformers__modeling_utils.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('src/transformers/modeling_utils.py',
                                   BLESSED_C22_REACH['src__transformers__modeling_utils.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'src__transformers__trainer.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('src/transformers/trainer.py',
                                   BLESSED_C22_REACH['src__transformers__trainer.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'tests__generation__test_utils.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('tests/generation/test_utils.py',
                                   BLESSED_C22_REACH['tests__generation__test_utils.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'tests__models__markuplm__test_tokenization_markuplm.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('tests/models/markuplm/test_tokenization_markuplm.py',
                                   BLESSED_C22_REACH['tests__models__markuplm__test_tokenization_markuplm.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'tests__test_modeling_common.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('tests/test_modeling_common.py',
                                   BLESSED_C22_REACH['tests__test_modeling_common.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'tests__test_tokenization_mistral_common.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('tests/test_tokenization_mistral_common.py',
                                   BLESSED_C22_REACH['tests__test_tokenization_mistral_common.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/bad.py'], handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/test_v01_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/test_v01_bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/test_v01_bad.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/test_v02_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/test_v02_bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/test_v02_bad.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/test_v03_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/test_v03_bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/test_v03_bad.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/test_v05_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/test_v05_bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/test_v05_bad.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_937_insecure_protocol/test_v06_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_baseline_name_row('cwe_937_insecure_protocol/test_v06_bad.py',
                                           handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_937_insecure_protocol/test_v06_good.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_baseline_name_row('cwe_937_insecure_protocol/test_v06_good.py',
                                           handle.read()))
    with open(os.path.join(BENCHMARK_DIR, 'runner.py'), encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('benchmark/runner.py', BLESSED_C22_REACH['runner.py'],
                                   handle.read()))
    blind = sum(len(lines) for _key, lines in BLESSED_C22_REACH.values())
    pinned = sum(len(lines) for _leaf, (_key, lines) in BLESSED_C22_BASELINE_NAME.items())
    total = blind + pinned
    if blind != 22:
        failures.append(f'the shield-blind arm pins {blind} blessed CWE-22 lines, expected 22 -- a '
                        'vendor key moved between the two tables without this tier agreeing to it')
    if pinned != 2:
        failures.append(f'the exact-identity arm pins {pinned} blessed CWE-22 parity keys, expected 2 '
                        '-- the two cwe_937_insecure_protocol lines are the contract-pinned set and '
                        'neither may be dropped from the reach census')
    if total != 24:
        failures.append(f'the reach tier pins {total} blessed CWE-22 keys, expected 24 -- a key was '
                        'added to or dropped from the frozen baseline without updating this table')
    print(f'  tier9 blessed CWE-22 keys loud: {blind} with the corpus-name shield removed, '
          f'{pinned} parity keys under the baseline name their pin names (24 total)')
    return failures


def check_blessed_lines_stay_loud() -> list:
    """The blessed lines a widened value-domain proof could actually reach, re-scanned loud."""
    failures = []
    with open(os.path.join(BIG8_CORPUS, MODELING_COMMON), encoding='utf-8', errors='replace') as handle:
        common_src = handle.read()
    loud, _reg, _rec = scan({os.path.join(BIG8_CORPUS, MODELING_COMMON): common_src}, 'CWE-338')
    for line in (6606, 6698, 6722):
        if line not in loud:
            failures.append(f'{MODELING_COMMON}:{line} went silent; it is a blessed CWE-338 key')
    loud22, _r2, _c2 = scan({os.path.join(BIG8_CORPUS, MODELING_COMMON): common_src}, 'CWE-22')
    if 1279 not in loud22:
        failures.append(f'{MODELING_COMMON}:1279 went silent; the mandate names it as the read-only '
                        'test open that must stay loud, and its path is a runtime name')
    with open(os.path.join(BIG8_CORPUS, GENERATION_UTILS), encoding='utf-8', errors='replace') as handle:
        gen_src = handle.read()
    loud_gen, _rg, _rc = scan({os.path.join(BIG8_CORPUS, GENERATION_UTILS): gen_src}, 'CWE-338')
    for line in (3352, 3367, 3384):
        if line not in loud_gen:
            failures.append(f'{GENERATION_UTILS}:{line} went silent; it is a blessed CWE-338 key')
    with open(os.path.join(BIG8_CORPUS, WHISPER), encoding='utf-8', errors='replace') as handle:
        whisper_src = handle.read()
    loud_wh, _rw, _rcw = scan({os.path.join(BIG8_CORPUS, WHISPER): whisper_src}, 'CWE-338')
    if 97 not in loud_wh:
        failures.append(f'{WHISPER}:97 went silent; it is a blessed CWE-338 key')
    print('  tier6 blessed lines re-scanned loud: 8')
    return failures


def check_source_shape() -> list:
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        source = handle.read()
    spellings = ('def _c22_is_literal_readonly_open',
                     'def _c22_is_hub_cache_read',
                     # This round's rule and the two tables that answer it: the requirement itself,
                     # the argument-wide reachability question that retires the blanket, the phase-11
                     # site that asks it, and the exact-identity keep-loud pins the contract sanctions
                     # for a blessed key whose caller is not in the file. Every one of the four
                     # emitters has to keep asking -- the registry sink, the two short-circuits and
                     # the subtract-only UNKNOWN prune arm -- or the blanket is back under a new name.
                     'def _c22_open_sink_owes_proven_taint',
                     'def _c22_path_sink_reaches_operator',
                     'and self._c22_open_sink_owes_proven_taint(record, sink))',
                     'return not self._c22_path_sink_reaches_operator(node, tree)',
                     'CWE22_OPEN_TAINT_KEEP_LOUD = frozenset',
                     'CWE22_ENTRYPOINT_KEEP_LOUD = frozenset',
                     'if identity in CWE22_OPEN_TAINT_KEEP_LOUD or identity in '
                     'CWE22_ENTRYPOINT_KEEP_LOUD:',
                     '("test_v06_bad.py", 6),',
                     '("test_v06_good.py", 7),',
                     'def _c22_is_operator_program_open',
                     'def _c22_path_is_operator_supplied',
                     'def _c770_read_comes_from_operator_program',
                     'CWE22_OPERATOR_PROGRAM_CALLS = frozenset',
                     'isinstance(a, ast.Starred) for a in site.args',
                     # The value chain resolves names through the scope that owns them, so the scope
                     # tables and the namespace proof have to stay in the engine.
                     'def _c22_target_names',
                     'def _c22_scope_binds',
                     'def _c22_bound_values',
                     'def _c22_is_namespace_root',
                     'if (owner, field) in mutated or ("", field) in mutated:',
                     'stack.append((child, owner if decorators and child in decorators else inner))',
                     # Slice F: the arm, the two proofs it composes, and the file-parser trust rule
                     # that only clears when the file argument itself is operator-supplied.
                     'def _cwe117_message_is_operator_sealed',
                     'def _c22_value_is_newline_free',
                     'def _cwe117_logged_values',
                     'def _c22_operator_facts_on',
                     'CWE22_OPERATOR_FILE_PARSERS = frozenset',
                     'CWE22_OPERATOR_ROOT_CALLS = CWE22_OPERATOR_PROGRAM_CALLS | CWE22_OPERATOR_FILE_PARSERS',
                     'or (tree is not None and self._cwe117_message_is_operator_sealed(',
                     'if self._cwe117_message_is_sealed(node, shadowed, tree):',
                     # The two caches are pure, so their keys are the whole contract: one answer per
                     # (tree, expression, name) and one verdict per (tree, log statement).
                     'def _c22_bound_values_on',
                     'key = (id(node), name)',
                     'cache = tree.__dict__.get("_c117_operator_sealed")',
                     'cache[id(node)] = verdict',
                     # The facts pass reads the module's own cached node list and is only entered when
                     # the source could hold either fact, so it never costs a second traversal.
                     'def _c22_operator_facts_build',
                     'def _module_text_for',
                     'CWE22_OPERATOR_FACT_TOKENS = ("__name__", "parse_")',
                     'if text and not all(tok in text for tok in CWE22_OPERATOR_FACT_TOKENS):',
                     'for n in self._module_nodes(tree):',
                     # Every address that can register the row has to ask the new proof.
                     'if not is_protected and self._c22_is_operator_program_open(node, mod_name):',
                     'if self._c22_is_operator_program_open(node, mod_name):',
                     'and not self._c22_is_operator_program_open(node, mod_name):',
                     'and not self._c22_path_is_operator_supplied(path_expr, mod_name):',
                     'and not self._c770_read_comes_from_operator_program(node, mod_name)',
                     'CWE22_HUB_CACHE_RESOLVERS = frozenset',
                     'leaf == "uniform" and len(node.args) == 2',
                     'loop.iter is node',
                     '"passwords", "seeds",')
    for spelling in spellings:
        if spelling not in source:
            failures.append(f'the shipped proof is gone from the engine: {spelling}')
    retired = ('_C338_BLESSED_LINES_SHIELD', '_C338_BLESSED_LINES', 'is_test_or_eval',
               # A file-wide name table cannot tell a converter's local from the module's command
               # line, so it must not come back: the scope-keyed table is the shipped proof.
               'def _c22_assign_map', 'argparse_names:\n                return True',
               # The collector consulted the seal without a tree, so the operator-program arm could
               # not reach the path that records most of the arena's log sinks.
               'if self._cwe117_message_is_sealed(node, shadowed):\n',
               # The facts pass once did its own whole-tree walk, so every module that ever logged
               # paid a traversal the collector had already done.
               'for n in ast.walk(tree):\n                if (isinstance(n, ast.If)',
               # The blanket this round retired, in the two shapes it had: "the module declares an
               # entrypoint, therefore the sink owes nothing" and its mirror, "the module declares
               # nothing, therefore the sink is untrusted". Neither may come back -- the mandate's
               # question is about the ARGUMENT, and `_c22_path_sink_reaches_operator` is the only
               # form allowed to answer it. Measured absent from the working copy by
               # scratch/_c22_r3_partition_measure.py's --mut=blanket arm: with the requirement forced
               # off, the five C22_BLANKET_RETIREMENT rows come back.
               'owed = bool(self._c22_module_entrypoint_facts',
               'CWE22_OPEN_TAINT_REQUIRES_ENTRYPOINT')
    for marker in retired:
        if marker in source:
            failures.append(f'a retired name/line shield is back in the engine: {marker}')
    print(f'  tier7 source spellings checked: {len(spellings)} present, '
          f'{len(retired)} retired markers absent')
    return failures


def run_mutations() -> list:
    """Every conjunct must move under its own mutation, and the engine must come back identical."""
    results = []

    shipped_literal = ast_scanner.TaintTracker._c22_is_literal_readonly_open
    ast_scanner.TaintTracker._c22_is_literal_readonly_open = lambda self, node: False
    try:
        _loud, _reg, records = scan({'src/m.py': C22_FIXTURES['literal_read'][1]}, 'CWE-22')
        results.append(('c22_literal_proof_blinded', records == 1))
    finally:
        ast_scanner.TaintTracker._c22_is_literal_readonly_open = shipped_literal

    # Both hub mutations ride on `resolver_bare_import_read`, which is why that quiet fixture carries
    # the argv call site: with the proof or the binding blinded the sink registers, and an unproven
    # open() in a module nobody hands a value to is no longer enough to emit. Re-anchored this round
    # (measured [3] / 1 sink_record for the bare spelling under each mutant, [] for the qualified
    # spelling under the binding mutant) -- before the earning, neither mutant moved at all.
    shipped_resolver = ast_scanner.TaintTracker._c22_is_hub_cache_read
    ast_scanner.TaintTracker._c22_is_hub_cache_read = lambda self, node, mod_name='': False
    try:
        loud, _reg, records = scan(
            {'src/convert_x_to_pytorch.py': C22_RESOLVER_FIXTURES['resolver_bare_import_read'][1]},
            'CWE-22')
        results.append(('c22_hub_resolver_proof_blinded', loud == [3] and records == 1))
    finally:
        ast_scanner.TaintTracker._c22_is_hub_cache_read = shipped_resolver

    shipped_bindings = ast_scanner.TaintTracker._c22_module_hub_resolvers
    ast_scanner.TaintTracker._c22_module_hub_resolvers = lambda self, mod_name: frozenset()
    try:
        loud_bare, _r1, _c1 = scan(
            {'src/convert_x_to_pytorch.py': C22_RESOLVER_FIXTURES['resolver_bare_import_read'][1]},
            'CWE-22')
        loud_qual, _r2, _c2 = scan(
            {'src/convert_x_to_pytorch.py': C22_RESOLVER_FIXTURES['resolver_qualified_read'][1]},
            'CWE-22')
        results.append(('c22_hub_import_binding_is_load_bearing',
                        loud_bare == [3] and loud_qual == []))
    finally:
        ast_scanner.TaintTracker._c22_module_hub_resolvers = shipped_bindings

    shipped_display = ast_scanner.TaintTracker._cwe338_display_only_draw



    def blind_leaf(leaf_name):
        def mutant(self, node, scope_id=''):
            leaf = (node.func.attr if isinstance(node.func, ast.Attribute)
                    else (node.func.id if isinstance(node.func, ast.Name) else ''))
            if leaf == leaf_name:
                return False
            return shipped_display(self, node, scope_id)
        return mutant

    ast_scanner.TaintTracker._cwe338_display_only_draw = blind_leaf('uniform')
    try:
        loud, _r, _c = scan({'src/transformers/models/m.py': UNIFORM_UNIT}, 'CWE-338')
        results.append(('c338_uniform_proof_blinded', loud == [4]))
    finally:
        ast_scanner.TaintTracker._cwe338_display_only_draw = shipped_display

    ast_scanner.TaintTracker._cwe338_display_only_draw = blind_leaf('sample')
    try:
        loud, _r, _c = scan({'examples/run_qa.py': SAMPLE_INDEX}, 'CWE-338')
        results.append(('c338_sample_proof_blinded', loud == [3]))
    finally:
        ast_scanner.TaintTracker._cwe338_display_only_draw = shipped_display

    shipped_words = ast_scanner.CWE338_SECURITY_NAME_WORDS
    ast_scanner.CWE338_SECURITY_NAME_WORDS = frozenset(shipped_words - {'passwords'})
    try:
        loud, _r, _c = scan({'examples/m.py': C338_FIXTURES['sample_passwords_veto_loud'][1]}, 'CWE-338')
        results.append(('plural_veto_completion_is_load_bearing', loud == []))
    finally:
        ast_scanner.CWE338_SECURITY_NAME_WORDS = shipped_words

    shipped_secrets = ast_scanner.TaintTracker._compares_two_secrets
    shipped_assertion = ast_scanner.TaintTracker._c208_is_unit_test_assertion

    def without_constant_refusal(self, node, file_path=''):
        operands = [node.left] + list(node.comparators)
        if any(isinstance(o, ast.Constant) for o in operands):
            return not self._c208_is_tensor_dimension_compare(node, file_path)
        return shipped_secrets(self, node, file_path)

    ast_scanner.TaintTracker._compares_two_secrets = without_constant_refusal
    try:
        loud, _r, _c = scan({'tests/test_m.py': C208_FIXTURES['test_credential_int_quiet'][1]}, 'CWE-208')
        loud_plain, _rp, _cp = scan({'tests/test_m.py': C208_FIXTURES['test_plain_int_quiet'][1]}, 'CWE-208')
        results.append(('c208_constant_refusal_is_load_bearing', loud == [2] and loud_plain == []))
    finally:
        ast_scanner.TaintTracker._compares_two_secrets = shipped_secrets

    ast_scanner.TaintTracker._compares_two_secrets = without_constant_refusal
    ast_scanner.TaintTracker._c208_is_unit_test_assertion = lambda self, node, file_path='': False
    try:
        loud, _r, _c = scan({'tests/test_m.py': C208_FIXTURES['test_credential_int_quiet'][1]}, 'CWE-208')
        loud_plain, _rp, _cp = scan({'tests/test_m.py': C208_FIXTURES['test_plain_int_quiet'][1]}, 'CWE-208')
        results.append(('c208_both_guards_blinded_moves_the_tier', loud == [2] and loud_plain == []))
    finally:
        ast_scanner.TaintTracker._compares_two_secrets = shipped_secrets
        ast_scanner.TaintTracker._c208_is_unit_test_assertion = shipped_assertion

    shipped_exempt = ast_scanner.TaintTracker._sink_context_exempt

    def with_numeric_spec_exemption(self, cwe_id, node, scope_id):
        if cwe_id == 'CWE-117' and node.args and isinstance(node.args[0], ast.JoinedStr):
            fields = [v for v in node.args[0].values if isinstance(v, ast.FormattedValue)]
            if fields and all(
                    getattr(v.format_spec, 'values', None)
                    and isinstance(v.format_spec.values[0], ast.Constant)
                    and ',' in str(v.format_spec.values[0].value) for v in fields):
                return True
        return shipped_exempt(self, cwe_id, node, scope_id)

    ast_scanner.TaintTracker._sink_context_exempt = with_numeric_spec_exemption
    try:
        loud_mut, _r, _c = trainer_rows()
        silenced = [line for line in BLESSED_C117_TRAINER if line not in loud_mut]
        # The mutant has to remove exactly the blessed block and nothing else: on this corpus the
        # predicate's yield is 8 rows, all 8 are true positives, so 0 FPs is the whole story.
        results.append(('c117_numeric_spec_refusal_is_load_bearing',
                        len(silenced) == len(BLESSED_C117_TRAINER)
                        and bool(SHIPPED_TRAINER_LOUD)
                        and len(SHIPPED_TRAINER_LOUD) - len(loud_mut) == len(silenced)))
    finally:
        ast_scanner.TaintTracker._sink_context_exempt = shipped_exempt

    shipped_facts = ast_scanner.TaintTracker._c22_operator_facts
    shipped_facts_on = ast_scanner.TaintTracker._c22_operator_facts_on
    shipped_facts_build = ast_scanner.TaintTracker._c22_operator_facts_build
    shipped_open_pred = ast_scanner.TaintTracker._c22_is_operator_program_open
    shipped_expr_pred = ast_scanner.TaintTracker._c22_path_is_operator_supplied
    shipped_path_names = ast_scanner.TaintTracker._c22_module_path_names
    shipped_c770_read = ast_scanner.TaintTracker._c770_read_comes_from_operator_program
    shipped_ns_root = ast_scanner.TaintTracker._c22_is_namespace_root
    shipped_scope_binds = ast_scanner.TaintTracker._c22_scope_binds

    # M1: the `__main__` guard conjunct is the fact that separates a program from a library. The
    # mutant forces it at the tree-level fact source and keeps the names the file really parsed, so
    # it tests the conjunct and not the token screen that reads the same two facts. It runs with the
    # round-5 demotion ambient-disabled: that rule retires this carrier's report at baseline, so
    # without the ambient answer the row would already be quiet and the mutant would measure nothing.
    shipped_demotion = ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line
    ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = (
        lambda self, record, sink: False)
    ast_scanner.TaintTracker._c22_operator_facts_on = lambda self, tree: (
        True, shipped_facts_build(self, tree)[1])
    try:
        loud, _r, _c = scan({'src/m.py': C22_RETIRED_BY_LOCAL_CLI['no_main_guard_was_loud'][1]},
                            'CWE-22')
        results.append(('c22_main_guard_conjunct_is_load_bearing', loud == []))
    finally:
        ast_scanner.TaintTracker._c22_operator_facts_on = shipped_facts_on
        ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = shipped_demotion

    # M2: presence facts with the value chain dropped -- the Rung-1 form the doctrine forbids. Every
    # fixture below is an absence or an unresolvable value, and only the two environ-rooted rows,
    # whose own argument the chain does resolve, survive the mutant.
    def presence_only(self, node, mod_name):
        if not isinstance(node, ast.Call):
            return False
        if (ast_scanner.dotted_name(node.func) or '') not in ast_scanner.FILE_OPEN_FUNCS:
            return False
        guarded, names = shipped_facts(self, mod_name)
        return bool(guarded and names)

    def presence_only_expr(self, expr, mod_name):
        guarded, names = shipped_facts(self, mod_name)
        return bool(guarded and names and expr is not None)

    ast_scanner.TaintTracker._c22_is_operator_program_open = presence_only
    ast_scanner.TaintTracker._c22_path_is_operator_supplied = presence_only_expr
    try:
        quiet_rows = []
        # `uncalled_function` and `splat_call` left this list on 2026-11-10: the sink-generalisation
        # slice made them quiet without any mutation, so they can no longer demonstrate that the value
        # chain is load-bearing. The two converter shapes below still are.
        for name in ('unknown_call_stays_loud', 'unknown_wrap_stays_loud'):
            loud, _r, _c = scan({'src/m.py': C22_OPERATOR_FIXTURES[name][1]}, 'CWE-22')
            quiet_rows.append(loud == [])
        env_loud, _re, _ce = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['environ_value_stays_loud'][1]}, 'CWE-22')
        env_rm_loud, _rm, _cm = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['environ_rmtree_stays_loud'][1]}, 'CWE-22')
        results.append(('c22_value_chain_is_load_bearing',
                        all(quiet_rows) and env_loud == [14] and env_rm_loud == [9]))
    finally:
        ast_scanner.TaintTracker._c22_is_operator_program_open = shipped_open_pred
        ast_scanner.TaintTracker._c22_path_is_operator_supplied = shipped_expr_pred

    # M3: a bare wrapper name proves nothing until the import binding is there.
    ast_scanner.TaintTracker._c22_module_path_names = lambda self, tree: frozenset({'removeprefix'})
    try:
        loud, _r, _c = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['unbound_wrapper_stays_loud'][1]}, 'CWE-22')
        results.append(('c22_wrapper_binding_is_load_bearing', loud == []))
    finally:
        ast_scanner.TaintTracker._c22_module_path_names = shipped_path_names

    # M4: the CWE-770 unbounded read only stays quiet because the open underneath it was proven.
    ast_scanner.TaintTracker._c770_read_comes_from_operator_program = (
        lambda self, node, mod_name: False)
    try:
        loud, _r, _c = scan({C770_OPERATOR_READ[0]: C770_OPERATOR_READ[1]}, 'CWE-770')
        results.append(('c770_operator_program_read_is_load_bearing', loud == [11]))
    finally:
        ast_scanner.TaintTracker._c770_read_comes_from_operator_program = shipped_c770_read

    # M5: tier 9 has to be about this predicate, not about a line that no exemption could reach.
    ast_scanner.TaintTracker._c22_is_operator_program_open = lambda self, node, mod_name: True
    ast_scanner.TaintTracker._c22_path_is_operator_supplied = lambda self, expr, mod_name: True
    try:
        with open(os.path.join(BIG8_CORPUS, REACH_MUTATION_LEAF),
                  encoding='utf-8', errors='replace') as handle:
            common_src = handle.read()
        loud, _r, _c = scan({REACH_MUTATION_KEY: common_src}, 'CWE-22')
        results.append(('c22_operator_reach_tier_moves_when_forced',
                        REACH_MUTATION_LINE not in loud))
    finally:
        ast_scanner.TaintTracker._c22_is_operator_program_open = shipped_open_pred
        ast_scanner.TaintTracker._c22_path_is_operator_supplied = shipped_expr_pred

    # M6: the holder trust is a proof about the binding, not about the spelling of the name. Reduced
    # to "this name is fed a parse_args() somewhere" it silences every borrowed-authority fixture at
    # once -- exactly the false negative the scope tables exist to prevent.
    #
    # Round 5 added a second rule that reads the same binding proof, so this arm runs with the
    # local-command-line demotion ambient-disabled: otherwise the demotion retires the rebound row's
    # call-site record too and the arm measures two clauses at once. With the successor off, the
    # booked answer is exactly the one this mutation was written against -- four borrowed fixtures
    # quiet, `holder_rebound` down to [15].
    shipped_demotion = ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line
    ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = (
        lambda self, record, sink: False)
    ast_scanner.TaintTracker._c22_is_namespace_root = (
        lambda self, tree, node, name, argparse_names, path=None, seen=None: name in argparse_names)
    try:
        borrowed = []
        # `lambda_param_shadows` left this list with the same supersession: it is quiet at baseline
        # now, and a fixture that is already silent cannot show that the binding proof is load-bearing.
        for fixture in ('holder_is_param_stays_loud', 'holder_field_written_stays_loud',
                        'loop_target_shadows_stays_loud',
                        'nested_tuple_rebind_stays_loud'):
            loud, _r, _c = scan({'src/m.py': C22_OPERATOR_FIXTURES[fixture][1]}, 'CWE-22')
            borrowed.append(loud == [])
        rebound, _r2, _c2 = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['holder_rebound_stays_loud'][1]}, 'CWE-22')
        results.append(('c22_namespace_binding_proof_is_load_bearing',
                        all(borrowed) and rebound == [15]))
    finally:
        ast_scanner.TaintTracker._c22_is_namespace_root = shipped_ns_root
        ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = shipped_demotion

    # M6b: the demotion's own binding conjunct. `_c22_path_sink_reaches_operator` is a presence walk
    # over ANY binding, so on its own it credits `args = parser.parse_args()` even after
    # `args = fetch_from_socket()`, and credits bare `argv` even when it is bound to `read_socket()`.
    # Handing the resolved-origin proof back as a constant True restores exactly that unsound reading,
    # and every borrowed-authority fixture the proof keeps loud must go quiet under it. This is the
    # mutation that proves the proof is load-bearing rather than decorative: without it the
    # demotion is a false negative on five shapes Slice E already refuses.
    shipped_leaves = ast_scanner.TaintTracker._c22_cli_retirement_is_proven
    ast_scanner.TaintTracker._c22_cli_retirement_is_proven = (
        lambda self, node, tree: True)
    try:
        unsound = []
        for fixture in ('holder_rebound_stays_loud', 'holder_field_written_stays_loud',
                        'loop_target_shadows_stays_loud', 'nested_tuple_rebind_stays_loud',
                        'argv_from_socket_stays_loud'):
            loud, _r, _c = scan({'src/m.py': C22_OPERATOR_FIXTURES[fixture][1]}, 'CWE-22')
            unsound.append(loud == [])
        results.append(('c22_local_cli_binding_proof_is_load_bearing', all(unsound)))
    finally:
        ast_scanner.TaintTracker._c22_cli_retirement_is_proven = shipped_leaves

    # M6e: the two early returns the resolved-origin proof had to give up. Each trusted the blinded
    # reach walk to cover a shape it does not cover -- a callee's body, and the inside of a call's
    # arguments -- and each was measured to hide a remote root (`C22_LOCAL_CLI_FN_SHIELDS`). Forcing
    # the classifier to True restores the local-def arm and hides all five. Stopping the walk at a
    # container reshaper restores the other and hides exactly the three reshaper rows, leaving the two
    # local-def rows loud -- the refusals are independent, and each arm names its own rows.
    shipped_classifier = ast_scanner.TaintTracker._c22_call_is_classified_path_call
    ast_scanner.TaintTracker._c22_call_is_classified_path_call = lambda self, tree, call: True
    try:
        hidden = []
        for _name, (path, source, _expected) in sorted(C22_LOCAL_CLI_FN_SHIELDS.items()):
            loud, _r, _c = scan({path: source}, 'CWE-22')
            hidden.append(loud == [])
        results.append(('c22_local_cli_unclassified_call_refusal_is_load_bearing', all(hidden)))
    finally:
        ast_scanner.TaintTracker._c22_call_is_classified_path_call = shipped_classifier

    shipped_origin = ast_scanner.TaintTracker._c22_value_origin_is_resolved

    def reshaper_stop(self, tree, expr, argparse_names, cli_names, depth=0, seen=None):
        if isinstance(expr, ast.Call):
            leaf = (ast_scanner.dotted_name(expr.func) or "").rsplit(".", 1)[-1]
            if leaf in ast_scanner.CWE22_PURE_CONTAINER_RESHAPE:
                return True
        return shipped_origin(self, tree, expr, argparse_names, cli_names, depth, seen)

    reshaper_rows = ('zip_hides_request', 'list_hides_urlopen', 'str_hides_request')
    ast_scanner.TaintTracker._c22_value_origin_is_resolved = reshaper_stop
    try:
        hidden = []
        held = []
        for name, (path, source, expected) in sorted(C22_LOCAL_CLI_FN_SHIELDS.items()):
            loud, _r, _c = scan({path: source}, 'CWE-22')
            if name in reshaper_rows:
                hidden.append(loud == [])
            else:
                held.append(loud == expected)
        results.append(('c22_local_cli_reshaper_descent_is_load_bearing',
                        all(hidden) and all(held)))
    finally:
        ast_scanner.TaintTracker._c22_value_origin_is_resolved = shipped_origin

    # M6f: the third early return of the same class. `CWE22_OPERATOR_ROOT_CALLS` is the program parsers
    # PLUS the file parsers, and the file parsers are not a trust root on their own -- their own table
    # comment says the chain only clears when the file argument is operator-supplied. Stopping at any
    # root-call leaf skips that check, so a config file the network chose is credited to the operator.
    # Restoring the stop must re-silence both remote-config shields and leave the operator-pointed
    # control quiet, which is what separates this refusal from a blanket.
    shipped_origin_f = ast_scanner.TaintTracker._c22_value_origin_is_resolved

    def parseleaf_stop(self, tree, expr, argparse_names, cli_names, depth=0, seen=None):
        if isinstance(expr, ast.Call):
            leaf = (ast_scanner.dotted_name(expr.func) or "").rsplit(".", 1)[-1]
            if leaf in ast_scanner.CWE22_OPERATOR_ROOT_CALLS:
                return True
        return shipped_origin_f(self, tree, expr, argparse_names, cli_names, depth, seen)

    ast_scanner.TaintTracker._c22_value_origin_is_resolved = parseleaf_stop
    try:
        hidden = []
        for name in ('parse_json_file_remote_cfg', 'parse_yaml_file_remote_cfg'):
            path, source, _expected = C22_LOCAL_CLI_FN_SHIELDS[name]
            loud, _r, _c = scan({path: source}, 'CWE-22')
            hidden.append(loud == [])
        control_path, control_src, control_live, _rec, _head = (
            C22_LOCAL_CLI_RETIREMENT['parse_json_file_operator_cfg'])
        control_loud, _r, _c = scan({control_path: control_src}, 'CWE-22')
        results.append(('c22_local_cli_file_parser_descent_is_load_bearing',
                        all(hidden) and control_loud == control_live))
    finally:
        ast_scanner.TaintTracker._c22_value_origin_is_resolved = shipped_origin_f

    # M6d: the row round 5 re-filed out of tier 10. Handing the demotion back must restore
    # `no_main_guard`'s report at exactly the answer the fixture used to carry -- [9] loud, 2
    # registered, 2 sink_records -- so the retirement is provably the demotion's doing and not a
    # silently weakened Slice E. The proposition Slice E asserted is measured separately by M1,
    # which forces the guard fact with the demotion off.
    ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = (
        lambda self, record, sink: False)
    try:
        restored_rows = []
        for _key, (path, source, cwe, _live_loud, _live_reg, sink_records,
                   head_loud, head_registered) in sorted(C22_RETIRED_BY_LOCAL_CLI.items()):
            loud, registered, records = scan({path: source}, cwe)
            restored_rows.append(loud == head_loud and registered == head_registered
                                 and records == sink_records)
        results.append(('c22_local_cli_no_main_guard_restored', all(restored_rows)))
    finally:
        ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = shipped_demotion

    # M6c: the retirement itself, on the carrier tier 9b books. With the demotion off, the argv
    # spelling must report [5, 8] with 2 sink_records under EVERY name in NAME_BLIND_KEYS -- the
    # answer it had before round 5 -- and the earned environ carrier must not move, because its
    # loudness comes from a root the demotion never claimed.
    ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = (
        lambda self, record, sink: False)
    try:
        restored = []
        for _name, source, _quiet, expected_records, head_lines in C22_NAME_BLIND_RETIRED:
            for key in NAME_BLIND_KEYS:
                loud, _r, records = scan({key: source}, 'CWE-22')
                restored.append(loud == head_lines and records == expected_records)
        earned_still = []
        for _name, source, expected_loud, expected_records in C22_NAME_BLIND_CARRIER:
            loud, _r, records = scan({'m.py': source}, 'CWE-22')
            earned_still.append(loud == expected_loud and records == expected_records)
        results.append(('c22_local_cli_demotion_restored',
                        all(restored) and all(earned_still)))
    finally:
        ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = shipped_demotion

    # M7: mixing scopes lets one function's `args = chkpt["cfg"]` poison a different function's
    # command line. The merged table has to move the converter-shaped fixture and nothing else.
    def merged_scopes(self, tree):
        binds, mutated = shipped_scope_binds(self, tree)
        flat = {}
        for (_owner, bound), values in binds.items():
            flat.setdefault(('', bound), []).extend(values)
        return flat, mutated

    ast_scanner.TaintTracker._c22_scope_binds = merged_scopes
    try:
        peek_loud, _r, _c = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['other_scope_local_quiet'][1]}, 'CWE-22')
        handoff, _r2, _c2 = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['namespace_handoff_quiet'][1]}, 'CWE-22')
        positional, _r3, _c3 = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['operator_positional_call'][1]}, 'CWE-22')
        results.append(('c22_scope_separation_is_load_bearing',
                        peek_loud == [9] and handoff == [] and positional == []))
    finally:
        ast_scanner.TaintTracker._c22_scope_binds = shipped_scope_binds

    # M8: the write veto is per field, so blinding it must quiet the written field and leave the
    # never-written reads alone.
    ast_scanner.TaintTracker._c22_scope_binds = (
        lambda self, tree: (shipped_scope_binds(self, tree)[0], frozenset()))
    try:
        written, _r, _c = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['holder_field_written_stays_loud'][1]}, 'CWE-22')
        nested, _r2, _c2 = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['nested_tuple_rebind_stays_loud'][1]}, 'CWE-22')
        results.append(('c22_field_mutation_veto_is_load_bearing',
                        written == [] and nested == [9]))
    finally:
        ast_scanner.TaintTracker._c22_scope_binds = shipped_scope_binds

    # M9: slice F's arm is what quiets the operator-program log lines. Remove the arm and every one
    # of the four quiet fixtures registers its second sink again.
    shipped_c117_arm = ast_scanner.TaintTracker._cwe117_message_is_operator_sealed
    ast_scanner.TaintTracker._cwe117_message_is_operator_sealed = (
        lambda self, node, tree, shadowed: False)
    try:
        moved = []
        for fixture in ('argv_field_quiet', 'numeric_local_quiet',
                        'json_config_from_argv_quiet'):
            loud, _r, records = scan(
                {'src/m.py': C117_OPERATOR_FIXTURES[fixture][1]}, 'CWE-117')
            moved.append(records == 2 and len(loud) == 2)
        held = []
        for fixture in ('client_text_stays_loud', 'mixed_client_and_argv_stays_loud',
                        'rebound_client_stays_loud', 'json_config_from_unknown_stays_loud'):
            loud, _r, records = scan(
                {'src/m.py': C117_OPERATOR_FIXTURES[fixture][1]}, 'CWE-117')
            held.append(records == 2 and len(loud) == 2)
        results.append(('c117_operator_program_arm_is_load_bearing',
                        all(moved) and all(held)))
    finally:
        ast_scanner.TaintTracker._cwe117_message_is_operator_sealed = shipped_c117_arm

    # M10: the newline-free proof is a separate arm from the argv proof. Blinding it must quiet
    # nothing and re-loud exactly the two numeric fixtures, while the argv fixture stays quiet.
    shipped_newline_free = ast_scanner.TaintTracker._c22_value_is_newline_free
    ast_scanner.TaintTracker._c22_value_is_newline_free = (
        lambda self, tree, expr, shadowed, depth=0, seen=None: False)
    try:
        numeric, _r, _c = scan(
            {'src/m.py': C117_OPERATOR_FIXTURES['numeric_local_quiet'][1]}, 'CWE-117')
        argv, _r3, _c3 = scan(
            {'src/m.py': C117_OPERATOR_FIXTURES['argv_field_quiet'][1]}, 'CWE-117')
        results.append(('c117_newline_free_proof_is_load_bearing',
                        len(numeric) == 2 and argv == [12]))
    finally:
        ast_scanner.TaintTracker._c22_value_is_newline_free = shipped_newline_free

    # M10b: the same proof asserted the other way. If every value were newline-free, the literal
    # carrying a real line break and the shadowed `len` would both clear, and the two fixtures that
    # depend on refusing them would go quiet.
    ast_scanner.TaintTracker._c22_value_is_newline_free = (
        lambda self, tree, expr, shadowed, depth=0, seen=None: True)
    try:
        flipped = [newline_free_proof(source, hole) for _n, source, hole, _e in C117_VALUE_PROOFS]
        moved = [got is True and expected is False
                 for (_n, _s, _h, expected), got in zip(C117_VALUE_PROOFS, flipped)]
        results.append(('c117_value_proof_refusals_are_load_bearing',
                        any(moved) and all(flipped)))
    finally:
        ast_scanner.TaintTracker._c22_value_is_newline_free = shipped_newline_free

    # M11: a config namespace parsed from a file is trusted only as far as the file argument is.
    # Admitting `parse_json_file` as a root on sight quiets the fixture whose file came from an
    # unknown call -- the exact false negative the recursive proof exists to stop.
    shipped_program_calls = ast_scanner.CWE22_OPERATOR_PROGRAM_CALLS
    ast_scanner.CWE22_OPERATOR_PROGRAM_CALLS = ast_scanner.CWE22_OPERATOR_ROOT_CALLS
    try:
        unknown, _r, records = scan(
            {'src/m.py': C117_OPERATOR_FIXTURES['json_config_from_unknown_stays_loud'][1]},
            'CWE-117')
        results.append(('c117_json_file_argument_proof_is_load_bearing',
                        records == 1 or len(unknown) < 2))
    finally:
        ast_scanner.CWE22_OPERATOR_PROGRAM_CALLS = shipped_program_calls

    # M12: the rule is every logged value, not any. Feeding the proof only the first value quiets a
    # line that still interpolates a client payload.
    shipped_logged_values = ast_scanner.TaintTracker._cwe117_logged_values
    ast_scanner.TaintTracker._cwe117_logged_values = (
        lambda self, node: shipped_logged_values(self, node)[:1])
    try:
        mixed, _r, records = scan(
            {'src/m.py': C117_OPERATOR_FIXTURES['mixed_client_and_argv_stays_loud'][1]},
            'CWE-117')
        results.append(('c117_every_value_rule_is_load_bearing', records == 1 or len(mixed) < 2))
    finally:
        ast_scanner.TaintTracker._cwe117_logged_values = shipped_logged_values

    # M17: the retirement itself. `_c22_open_sink_owes_proven_taint` answering False is the retired
    # blanket in its modern clothing -- "a filesystem sink owes no proof of an untrusted origin" -- and
    # restoring it must bring back exactly the five lines HEAD printed for C22_BLANKET_RETIREMENT and
    # not one of the earned fixtures, whose loudness comes from a value in the argument and would be
    # loud under either answer. That asymmetry is the booked win, measured by
    # scratch/_c22_r3_partition_measure.py --mut=blanket.
    #
    # Round 5 added a second retirement that reads the same rows, so this arm runs with the
    # local-command-line demotion ambient-disabled: `runtime_read` is re-filed in
    # C22_LOCAL_CLI_RETIREMENT because the demotion owns its silence now, and leaving the demotion on
    # would make this arm measure two clauses at once instead of the blanket it was written against.
    shipped_owed = ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint
    shipped_demotion_m17 = ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line
    ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = lambda self, record, sink: False
    ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = (
        lambda self, record, sink: False)
    try:
        revived = []
        for _name, (path, source, _expected, _records, head_line) in sorted(
                C22_BLANKET_RETIREMENT.items()):
            loud, _r, _c = scan({path: source}, 'CWE-22')
            revived.append(loud == [head_line])
        earned = []
        for _name, (path, source, expected, _records) in sorted(C22_RESOLVER_FIXTURES.items()):
            if not expected:
                continue
            loud, _r, _c = scan({path: source}, 'CWE-22')
            earned.append(loud == expected)
        literal_read, _lr, _lc = scan(
            {'src/m.py': C22_LOCAL_CLI_RETIREMENT['runtime_read_was_loud'][1]}, 'CWE-22')
        results.append(('c22_open_taint_blanket_restored',
                        all(revived) and all(earned) and literal_read == [2]))
    finally:
        ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = shipped_owed
        ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = shipped_demotion_m17

    # M17b: the slice A row round 5 re-filed. Handing the demotion back must restore `runtime_read`'s
    # report at exactly the answer the fixture used to carry -- [2] loud, 1 sink_record -- so the
    # retirement is provably the demotion's doing and not a weakened round-3 condition (a).
    ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = (
        lambda self, record, sink: False)
    try:
        cli_restored = []
        for _name, (path, source, _live, sink_records, head_line) in sorted(
                C22_LOCAL_CLI_RETIREMENT.items()):
            loud, _r, records = scan({path: source}, 'CWE-22')
            cli_restored.append(loud == [head_line] and records == sink_records)
        results.append(('c22_local_cli_runtime_read_restored', all(cli_restored)))
    finally:
        ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = shipped_demotion_m17

    # M18: tier 9b is the instrument that would catch a folder blacklist, so a blacklist has to be
    # able to move it. Owing the proof only under one path prefix silences the earned carrier's open()
    # under exactly those two names, which is the forbidden direction; the shipped engine answers the
    # same question from the argument and the carrier is [5, 8] everywhere.
    def name_scoped_owe(self, record, sink):
        path = (self.file_paths.get(ast_scanner.scope_module(record.scope_id), '') or '').replace(
            os.sep, '/')
        if path.startswith('vendor/proto/'):
            return True
        return shipped_owed(self, record, sink)

    ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = name_scoped_owe
    try:
        blinded = {}
        for name, source, expected_loud, _records in C22_NAME_BLIND_CARRIER:
            blinded[name] = [scan({key: source}, 'CWE-22')[0] for key in NAME_BLIND_KEYS]
    finally:
        ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = shipped_owed
    results.append(('c22_name_scoped_suppression_would_move_the_tier',
                    blinded['carrier_open_env'] != [C22_NAME_BLIND_CARRIER[0][2]]
                    and blinded['carrier_open_unproven'] == [C22_NAME_BLIND_CARRIER[1][2]] * 5))

    # M13/M14: the two value caches move no finding row on their own -- they are pure caching -- so
    # each key half has to be shown load-bearing separately. Dropping the expression from the scope
    # key hands `small()`'s arithmetic binding to `big()`, which reads the request, and line 22 of the
    # split fixture goes quiet (measured [12] against the shipped [12, 22]). Dropping the name hands
    # the namespace's own binding to the `args.model_dir` question asked about the same node.
    shipped_bound = ast_scanner.TaintTracker._c22_bound_values
    shipped_bound_on = ast_scanner.TaintTracker._c22_bound_values_on

    def bound_by_name_only(self, tree, node, name):
        cache = tree.__dict__.get('_c22_bound_values')
        if cache is None:
            cache = tree.__dict__['_c22_bound_values'] = {}
        key = ('', name)
        if key not in cache:
            cache[key] = shipped_bound_on(self, tree, node, name)
        return cache[key]

    def bound_by_node_only(self, tree, node, name):
        cache = tree.__dict__.get('_c22_bound_values')
        if cache is None:
            cache = tree.__dict__['_c22_bound_values'] = {}
        key = (id(node),)
        if key not in cache:
            cache[key] = shipped_bound_on(self, tree, node, name)
        return cache[key]

    split_source = C117_OPERATOR_FIXTURES['same_name_two_scopes_split'][1]
    argv_source = C117_OPERATOR_FIXTURES['argv_field_quiet'][1]
    clean_split = scan({'src/m.py': split_source}, 'CWE-117')[0]
    clean_argv = scan({'src/m.py': argv_source}, 'CWE-117')[0]
    ast_scanner.TaintTracker._c22_bound_values = bound_by_name_only
    try:
        name_only = scan({'src/m.py': split_source}, 'CWE-117')[0]
    finally:
        ast_scanner.TaintTracker._c22_bound_values = shipped_bound
    results.append(('c22_bound_value_cache_scope_key_is_load_bearing',
                    clean_split == [12, 22] and name_only == [12]))

    spellings = ['args', 'args.model_dir']
    split_answers = bound_value_probe(argv_source, 'args.model_dir', spellings)
    ast_scanner.TaintTracker._c22_bound_values = bound_by_node_only
    try:
        collapsed = bound_value_probe(argv_source, 'args.model_dir', spellings)
    finally:
        ast_scanner.TaintTracker._c22_bound_values = shipped_bound
    results.append(('c22_bound_value_cache_name_key_is_load_bearing',
                    len(split_answers) == 2 and split_answers[0] != split_answers[1]
                    and collapsed[0] == collapsed[1]))

    # M15: the arm caches its own verdict per log statement. A cache that answers every later
    # statement with the first verdict would quiet the request line behind the arithmetic line.
    def sticky_arm(self, node, tree, shadowed):
        store = getattr(sticky_arm, 'store', None)
        if store is None:
            store = sticky_arm.store = {}
        if store:
            return store['verdict']
        verdict = shipped_c117_arm(self, node, tree, shadowed)
        store['verdict'] = verdict
        return verdict

    sticky_arm.store = {}
    ast_scanner.TaintTracker._cwe117_message_is_operator_sealed = sticky_arm
    try:
        sticky = scan({'src/m.py': split_source}, 'CWE-117')[0]
    finally:
        ast_scanner.TaintTracker._cwe117_message_is_operator_sealed = shipped_c117_arm
    results.append(('c117_verdict_cache_key_is_load_bearing', sticky != clean_split))

    # M16: the facts screen may only ever decline a module that provably holds neither fact. Tightening
    # the tokens to one root spelling hides the namespaces of every file that spells it differently,
    # so both fixture sets must come back loud; switching the screen off entirely must change nothing,
    # which is the exact statement that it is a fast path and not a filter.
    shipped_tokens = ast_scanner.CWE22_OPERATOR_FACT_TOKENS
    ast_scanner.CWE22_OPERATOR_FACT_TOKENS = ('__name__', 'parse_args_into_dataclasses')
    try:
        strict_argv = scan({'src/m.py': argv_source}, 'CWE-117')[0]
        strict_split = scan({'src/m.py': split_source}, 'CWE-117')[0]
    finally:
        ast_scanner.CWE22_OPERATOR_FACT_TOKENS = shipped_tokens
    ast_scanner.CWE22_OPERATOR_FACT_TOKENS = ()
    try:
        unshielded_argv = scan({'src/m.py': argv_source}, 'CWE-117')[0]
        unshielded_split = scan({'src/m.py': split_source}, 'CWE-117')[0]
    finally:
        ast_scanner.CWE22_OPERATOR_FACT_TOKENS = shipped_tokens
    results.append(('c22_operator_fact_screen_is_superset_only',
                    strict_argv != clean_argv and strict_split != clean_split
                    and unshielded_argv == clean_argv and unshielded_split == clean_split))

    restored = (ast_scanner.TaintTracker._c22_is_literal_readonly_open is shipped_literal
                and ast_scanner.TaintTracker._c22_is_hub_cache_read is shipped_resolver
                and ast_scanner.TaintTracker._c22_module_hub_resolvers is shipped_bindings
                and ast_scanner.TaintTracker._cwe338_display_only_draw is shipped_display
                and ast_scanner.CWE338_SECURITY_NAME_WORDS is shipped_words
                and ast_scanner.TaintTracker._compares_two_secrets is shipped_secrets
                and ast_scanner.TaintTracker._sink_context_exempt is shipped_exempt
                and ast_scanner.TaintTracker._c22_operator_facts is shipped_facts
                and ast_scanner.TaintTracker._c22_operator_facts_on is shipped_facts_on
                and ast_scanner.TaintTracker._c22_operator_facts_build is shipped_facts_build
                and ast_scanner.CWE22_OPERATOR_FACT_TOKENS == ('__name__', 'parse_')
                and ast_scanner.TaintTracker._c22_is_operator_program_open is shipped_open_pred
                and ast_scanner.TaintTracker._c22_path_is_operator_supplied is shipped_expr_pred
                and ast_scanner.TaintTracker._c22_module_path_names is shipped_path_names
                and ast_scanner.TaintTracker._c22_is_namespace_root is shipped_ns_root
                and ast_scanner.TaintTracker._c22_scope_binds is shipped_scope_binds
                and ast_scanner.TaintTracker._c770_read_comes_from_operator_program is shipped_c770_read
                and ast_scanner.TaintTracker._c208_is_unit_test_assertion is shipped_assertion
                and ast_scanner.TaintTracker._cwe117_message_is_operator_sealed is shipped_c117_arm
                and ast_scanner.TaintTracker._c22_value_is_newline_free is shipped_newline_free
                and ast_scanner.TaintTracker._cwe117_logged_values is shipped_logged_values
                and ast_scanner.TaintTracker._c22_bound_values is shipped_bound
                and ast_scanner.TaintTracker._c22_bound_values_on is shipped_bound_on
                and ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint is shipped_owed
                and ast_scanner.CWE22_OPERATOR_PROGRAM_CALLS is shipped_program_calls)
    results.append(('engine_restored_after_mutation', restored))
    for name, ok in results:
        print(f'  {"ok " if ok else "FAIL"} mutation {name} -> '
              f'{"moves the tier" if ok else "does not move"}')
    return [name for name, ok in results if not ok]


def main() -> int:
    failures = []
    for check in (check_baseline_domain, check_slice_a, check_slice_b, check_slice_c,
                   check_slice_d, check_blanket_retirement, check_slice_e, check_slice_f,
                   check_operator_reach, check_name_blind_partition,
                   check_blessed_lines_stay_loud, check_source_shape,
                   check_refused_value_slice):
        failures.extend(check())
    failures.extend(run_mutations())
    if failures:
        print('VERDICT: FAIL - ' + '; '.join(str(f) for f in failures))
        return 1
    print('VERDICT: PASS - the literal read-only open, the hub cache-resolver read and the '
          'operator-program open/delete never register, every CWE-22 path sink that does register '
          'owes a resolved CLI/remote origin unless the exact-identity keep-loud pin names it, the '
          'five rows the retired blanket used to emit are quiet at their measured registrations while '
          'restoring the blanket brings all five back, the 22 shield-blind blessed CWE-22 keys and '
          'the 2 pinned parity keys stay loud on the names that carry them while one earned carrier '
          'answers identically under five module names, the two CWE-338 value domains are quiet while '
          'every credential veto and all 8 blessed lines stay loud, the CWE-208 constant partition '
          'holds under two independent guards, the refused CWE-117 numeric-spec slice keeps all 8 '
          'trainer keys loud, the CWE-117 operator-program arm quiets only argv and newline-free log '
          'values, and every conjunct moves under its own mutation.')
    return 0


if __name__ == '__main__':
    sys.exit(main())