"""Fail-loud lock: the CWE-22 framework vocabulary-serializer registration prune.

    python benchmark/gates/cwe22_vocab_serializer_probe.py

The arena (2,847 py files under `scratch/target_arena`) reported **138 CWE-22 rows whose innermost
enclosing def is `save_vocabulary`**, spread over 93 tokenizer files, of which 133 are write-mode
`open()` calls and 5 are not. They are the single largest identically-shaped CWE-22 block in the
tree: a serializer writing the tokenizer's own artifact into the destination directory it was handed
(`os.path.join(save_directory, "vocab.txt")`) is not a path an attacker chose.

The exemption is a conjunction of three positive facts and two fail-closed vetoes, and every one of
them is pinned by a mutation below:

| fact / veto                              | what the code asks                          | mutation that proves it bites |
|------------------------------------------|---------------------------------------------|-------------------------------|
| declared serializer contract             | innermost def name is in the pinned frozenset | `widened_serializer_vocabulary` |
| the sink emits                           | mode string contains a write flag            | `mode_set_refuses_writes`       |
| the module proves no source at all       | no untrusted name / import / argv-environ     | `untrusted_vocabulary_emptied`  |
| the sink is dropped before registration  | `self.sinks` never receives it                | `shipped_predicate_blinded`     |

**`save_pretrained` is refused by measurement, not by taste.** Two of the sixteen blessed Big-8
CWE-22 keys live inside it (`scratch/_p3_big/src__transformers__modeling_utils.py:3494` and `:3564`),
so the exemption may never fold into `CWE434_FRAMEWORK_SERIALIZER_METHODS`, which contains that name.
TIER 2 refuses it independently over the frozen baselines: no blessed key in either baseline resolves
to a def in the exemption set.

The 5 non-write rows and everything under a protected corpus root stay loud on purpose -- the rule is
allowed to trade arena volume, never a true positive. Measured, and recorded because it changes what
a mutation may claim: widening the write-flag tuple leaves the read-mode fixture loud anyway, so that
row is owned by a second CWE-22 emitter this exemption never spoke to. The write flags are therefore
pinned by *narrowing* them (`mode_set_refuses_writes`), which is the direction the exempted
population actually depends on.

Round 3 retired the assumption this gate's four booked rows were resting on. `_c22_open_sink_owes_proven_taint`
(`ast_scanner.py:8691`) refuses to let a CWE-22 path sink emit at all unless a resolved operator/remote
value reaches one of ITS arguments, and it is asked after the exemption, including at the registry sink
factory. Attribution is `scratch/_c22_r3_sliceh_attrib.py`, which drives `scratch/_c22_r3_engines.py --diff`
(HEAD's engine snapshot and the live engine in separate processes): `serializer_read_loud`,
`pretrained_write_loud`, `serializer_write_with_argv_source_loud` (its round-3 name; re-filed as
`serializer_write_with_argv_source_quiet` in round 5, below) and `serializer_write_with_http_source_loud`
are each `head_rows=1, live_rows=0` -- genuine supersessions -- while `serializer_write_quiet` is QUIET UNDER
BOTH ARMS and keeps its empty booking, so it was never this round's collateral.

No row was re-filed in round 3. Each superseded row named its root somewhere that does not reach the sink:
the two rows at 7 carry no root whatsoever (`open(vocab_file, ...)` over a `save_directory` join nobody hands
the command line to), and the argv/http rows at 12 spelled theirs inside a `picked_directory()` that no
call site ever calls. `scratch/_c22_r3_sliceh_earn.py` measured the carriers, and all four were earnable,
so all four were earned at their new lines. Two carriers, and the choice between them is a table lookup:
a module-level operator read with its value in the NON-path argument, which is condition (a) of the mandate
without disturbing the exemption's third fact -- `_c22_module_proves_no_untrusted_source`
(`ast_scanner.py:8287`) only vetoes source NAMES, `argv`/`environ` attributes and web imports -- used by
`serializer_read_loud` (10), `pretrained_write_loud` (10) and `serializer_cli_encoding_write_quiet` (still 0
registered, still quiet); and the root written into the join itself,
`os.path.join(save_directory, sys.argv[1])` / `request.args["filename"]`, for the two source-table rows (8),
where the row is loud because the operator really did name the file and the exemption is refused twice over.

Round 5 moves the first carrier and re-files one row of the second, and both moves are the same rule. The
local-command-line demotion retires a path sink whose only resolved root is this program's own command line,
so `argparse.ArgumentParser().parse_args()` -- round 3's carrier, chosen precisely because the walk saw it
and the veto did not -- stopped buying liveness: the exempted write went quiet for a reason this gate does
not own, and `shipped_predicate_blinded` / `mode_set_refuses_writes` had no finding left to move. The
replacement is `stdin_encoding = sys.stdin.readline()` with `encoding=stdin_encoding`, which is the one
spelling that satisfies both halves at once and is measured rather than argued
(`scratch/_c22_r5_carrier_lab.py roots`: loud, survives the blinding, no demotion), because the veto walks
for `Attribute.attr in ("argv", "environ")` and `stdin` is not one of them. All three fixtures keep their
lines and their verdicts, and the registration census is unchanged. The argv source-table row is RE-FILED
as `serializer_write_with_argv_source_quiet` with its spelling kept byte-for-byte: its proposition -- a root
spelled in an argument is recognised by `_c22_expr_is_untrusted_source` even with the module veto emptied --
is still carried verbatim by its http twin, and the new `local_cli_demotion_off` arm hands the retired
blanket back at [8] with registration 1, so the re-filing is locked rather than deleted.

Two of those fixtures used to be anchors, and their arms moved rather than went quiet. Under a blinded
exemption or a narrowed write-flag tuple the shipped `serializer_write_quiet` still only changes
`registered` (0 -> 1, the census TIER 3 asserts) and never a finding, because the sink is now refused at
emission whatever the exemption answers; `serializer_cli_encoding_write_quiet` is the same exempted write
with provenance, and it is where those two arms now book their row back at 10.
`untrusted_vocabulary_emptied` moved to the new `serializer_write_from_stdin_loud` (7 -> quiet) because a
root written directly into a sink argument is recognised by `_c22_expr_is_untrusted_source` as well as by
the module veto, so emptying only the module tables cannot silence the argv/http rows -- measured in the
`veto_emptied` column, where both stay loud at 8 while the stdin row, whose loudness rests on the table
alone, goes quiet. Every arm below therefore states the value it must produce, not merely "different".

Reported upward, not booked: `scratch/_c22_r3_sliceh_walk.py` traces `_c22_value_reaches_operator`
argument by argument, and for `os.path.join(picked_directory(), "vocab.txt")` over a helper that returns
`sys.argv[1]` every depth answers False -- a called in-file helper whose `return` is the command line is
not resolved, while the identical shape written into the join directly answers True at depth 0. The engine
therefore still owes that hop; the fixtures use the spelling it does resolve, and nothing quiet depends on
the unresolved one.
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
GATES_DIR = os.path.join(ROOT, 'benchmark', 'gates')
BIG8_CORPUS = os.path.join(ROOT, 'benchmark_gates_data', 'corpus_big8')

import cli  # noqa: E402
import ast_scanner  # noqa: E402

MARKUPLM = 'tests__models__markuplm__test_tokenization_markuplm.py'
MODELING_COMMON = 'tests__test_modeling_common.py'
P3_MODELING_UTILS = os.path.join('scratch', '_p3_big', 'src__transformers__modeling_utils.py')
P3_TEST_UTILS = os.path.join('scratch', '_p3_big', 'tests__generation__test_utils.py')

# (fixture name, source, expected loud lines) -- expectations measured against the shipped engine, in
# `scratch/_c22_r3_sliceh_earn.py`, which prints both censuses (findings and registered CWE-22 sinks) for
# every fixture under every arm below.
def vocab_body(method_name: str, last_line_mode: str, join_tail: str = '"vocab.txt"',
               header: str = 'import os\n') -> str:
    return (header
            + "\n"
            + "\n"
            + "class SlowTokenizer:\n"
            + "    def " + method_name + "(self, save_directory, filename_prefix=None):\n"
            + "        vocab_file = os.path.join(save_directory, " + join_tail + ")\n"
            + "        with open(vocab_file, " + last_line_mode + ") as writer:\n"
            + "            writer.write(\"a b c\")\n"
            + "        return (vocab_file,)\n")

# The open() taint requirement (`cwe22_open_taint_probe`) retires an unproven `open()` in a module
# that declares no entrypoint, which would quiet every carrier here for a reason this gate does not
# own -- and would leave its mutations nothing to move. A `__main__` guard declares an entrypoint
# WITHOUT spelling an untrusted source, which matters here: the exemption's own veto refuses a module
# that names argv/environ/request, so an argv tail would make the exempted write loud for the wrong
# reason. Appended, so every line number below is the line the carrier was measured at.
ENTRY_TAIL = 'if __name__ == "__main__":\n    pass\n'

# Round 5's carrier for the three stdin-shaped fixtures: two module-level lines, then the body, so the
# `open` that used to sit at 7 sits at 10. Round 3 used `argparse.ArgumentParser().parse_args()` here,
# and the reason it had to be argparse is the reason it can no longer be: the exemption's third fact
# refuses a module that names argv/environ/request, so the carrier needed a root the walk recognises
# but the veto does not. The local-command-line demotion now blinds exactly that root -- a standalone
# script's own command line is the process owner's invocation -- which left the exempted write quiet
# for a reason this gate does not own and its mutations nothing to move. `sys.stdin.readline()` is the
# one spelling that satisfies both halves at once, and it is measured, not argued: the veto walks for
# `Name.id` in `CWE22_UNTRUSTED_SOURCE_NAMES`, an `ImportFrom` in `CWE22_UNTRUSTED_IMPORT_MODULES`, and
# `Attribute.attr` in `("argv", "environ")` -- `stdin` is in none of the three, while
# `_c22_expr_is_untrusted_source` does recognise it and the blinding leaves it alone
# (`scratch/_c22_r5_carrier_lab.py roots`: loud, blind=True, demote=False). So an exempted serializer
# write stays exempted (`serializer_cli_encoding_write_quiet` registers 0) while the row still owes
# nothing to the provenance rule. The value goes in the NON-path argument on purpose: the destination
# is still the framework's own `save_directory`, so the only thing being proved is provenance, not a
# traversal.
STDIN_NS = 'import sys\nstdin_encoding = sys.stdin.readline()\n'

FIXTURES = {
    # Quiet under HEAD and quiet under live: the exemption's own row, unchanged by this round.
    'serializer_write_quiet': (vocab_body('save_vocabulary', '"w", encoding="utf-8"') + ENTRY_TAIL, []),
    # The exempted write WITH provenance. Shipped it is still exempted (0 registered, no finding), which
    # is what makes `shipped_predicate_blinded` and `mode_set_refuses_writes` move a FINDING at 10
    # instead of only moving a census.
    'serializer_cli_encoding_write_quiet': (
        STDIN_NS + '\n' + vocab_body('save_vocabulary', '"w", encoding=stdin_encoding') + ENTRY_TAIL, []),
    # Read mode: the exemption demands a write flag, so this row is owned by the second emitter and stays
    # loud under `flags=('a',)` -- measured. EARNed at 10; at HEAD it was loud at 7 with no provenance.
    'serializer_read_loud': (
        STDIN_NS + '\n' + vocab_body('save_vocabulary', 'encoding=stdin_encoding') + ENTRY_TAIL, [10]),
    # `save_pretrained` is outside the exemption vocabulary, so the same carrier stays loud at 10 and
    # `widened_serializer_vocabulary` is what silences it. Stdin rather than argv, because a vetoed
    # module would stay loud even when the widened set exempted it and the arm would move nothing.
    'pretrained_write_loud': (
        STDIN_NS + '\n' + vocab_body('save_pretrained', '"w", encoding=stdin_encoding') + ENTRY_TAIL, [10]),
    # A serializer module that reads its filename from stdin: the veto's third fact fails, the value
    # reaches, and the row is loud at 7 -- and this is the only loudness here that depends on the source
    # TABLE alone, so it is the fixture `untrusted_vocabulary_emptied` now moves (measured quiet).
    'serializer_write_from_stdin_loud': (
        vocab_body('save_vocabulary', '"w", encoding="utf-8"', 'input()') + ENTRY_TAIL, [7]),
    # The two roots the retired blanket used only to declare. Each is now in the sink's own path, so the
    # row is loud because the operator named the file (condition (a) at depth 0 in
    # `scratch/_c22_r3_sliceh_walk.py`); both stay loud at 8 even with the module veto emptied, because a
    # root spelled in an argument is also recognised by `_c22_expr_is_untrusted_source`.
    'serializer_write_with_http_source_loud': (
        vocab_body('save_vocabulary', '"w", encoding="utf-8"', 'request.args["filename"]',
                   'from flask import request\nimport os\n'), [8]),
    # RE-FILED by round 5, not earned: the root IS this program's own command line, spelled in the
    # sink's path argument, which is exactly the shape the local-command-line demotion retires. The
    # proposition it used to carry -- a root in an argument is recognised by
    # `_c22_expr_is_untrusted_source` even with the module veto emptied -- is still carried verbatim by
    # its http twin above, so nothing is lost by booking this one as a measured quiet. The spelling is
    # kept byte-for-byte and `local_cli_demotion_off` hands the retired blanket back at [8], which is
    # what makes this a re-filing with a lock rather than a deleted expectation.
    'serializer_write_with_argv_source_quiet': (
        vocab_body('save_vocabulary', '"w", encoding="utf-8"', 'sys.argv[1]',
                   'import os\nimport sys\n'), []),
}


def scan_files(files: dict) -> list:
    """One in-process scan, returning (line, cwe) for CWE-22 plus the registered CWE-22 sink count."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files=files, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
        registered = sum(1 for sink in tracker.sinks
                         if (sink.metadata or {}).get("cwe") == "CWE-22")
    loud = sorted(int(row["line"]) for row in rows if row["cwe"] == "CWE-22")
    return loud, registered


def check_fixtures() -> list:
    failures = []
    for name, (source, expected) in sorted(FIXTURES.items()):
        loud, _registered = scan_files({'pkg/' + name + '.py': source})
        if loud != expected:
            failures.append(f'{name}: CWE-22 lines reported {loud}, expected {expected}')
    print('  tier2 fixtures checked:', len(FIXTURES))
    return failures


def check_registration_prune() -> list:
    """The mandate is registration, not emission: the exempted sink must never enter `self.sinks`.

    Both exempted carriers are counted, and the second one is the case round 3 made this tier worth
    writing: a serializer write whose CLI value is resolved could be quiet because the owed rule refused
    it, so `serializer_cli_encoding_write_quiet` has to be in this census at 0 (the exemption really did
    drop it before registration) and not only at "no finding" in TIER 2. `serializer_read_loud` is the
    reported side of the same count, so the census being asserted is the census being used.
    """
    failures = []
    for fixture in ('serializer_write_quiet', 'serializer_cli_encoding_write_quiet'):
        _loud, registered = scan_files({'pkg/prune_proof.py': FIXTURES[fixture][0]})
        if registered:
            failures.append(f'the exempted serializer write {fixture} registered {registered} CWE-22 '
                            'sink(s); the prune moved back to emission and the cascade is paying for '
                            'it again')
    _loud2, registered_loud = scan_files({'pkg/prune_proof_loud.py': FIXTURES['serializer_read_loud'][0]})
    if not registered_loud:
        failures.append('no CWE-22 sink registered even for a row that is reported, so the census '
                        'being asserted is not the census being used')
    print('  tier3 registered CWE-22 sinks: exempted=0 (both carriers), reported>=1')
    return failures


def check_baseline_domain() -> list:
    """The exemption's vocabulary, measured against the two frozen baselines.

    Reads only `.keys` files, and only with a literal join at each `open` site: this repository
    scans its own tooling, so a helper here that opened a path handed to it would add a CWE-22 row
    to parity (measured -- it did, on the first version of this file). The per-key half of the
    domain proof is behavioural and lives in `check_blessed_lines_stay_loud`, which re-scans the ten
    blessed CWE-22 keys that a widened serializer set could actually reach.
    """
    failures = []
    exempt = set(ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS)
    if exempt != {'save_vocabulary', '_save_vocabulary'}:
        failures.append(f'the exemption vocabulary is {sorted(exempt)}, not the measured two-name '
                        'set; every extra name is a serializer whose blessed keys were never counted')
    expected = {'parity_before.keys': (424, 8), 'big8_before.keys': (119, 16)}
    for keys_name, (total_rows, c22_rows) in expected.items():
        with open(os.path.join(GATES_DIR, keys_name), encoding='utf-8') as handle:
            text = handle.read()
        rows = []
        for line in text.splitlines():
            entry = line.strip()
            if entry.startswith('('):
                row = ast.literal_eval(entry)
                if len(row) >= 3:
                    rows.append(row)
                    if row[2] == 'CWE-22':
                        c22_rows -= 1
        if len(rows) != total_rows:
            failures.append(f'{keys_name}: {len(rows)} keys, expected {total_rows}')
        if c22_rows:
            failures.append(f'{keys_name}: the CWE-22 key census moved, so the domain proof below '
                            'is no longer over the frozen baseline')
        print(f'  tier1 {keys_name}: {len(rows)} keys, blessed CWE-22 keys still inside the '
              'exemption vocabulary')
    return failures


def check_blessed_lines_stay_loud() -> list:
    failures = []
    with open(os.path.join(BIG8_CORPUS, MARKUPLM), encoding='utf-8') as handle:
        markuplm_src = handle.read()
    loud, _reg = scan_files({os.path.join(BIG8_CORPUS, MARKUPLM): markuplm_src})
    for line in (73, 75, 77, 138):
        if line not in loud:
            failures.append(f'{MARKUPLM}:{line} went silent; it is a blessed Big-8 CWE-22 key and '
                            'the exemption reached a protected corpus root')
    with open(os.path.join(BIG8_CORPUS, MODELING_COMMON), encoding='utf-8') as handle:
        common_src = handle.read()
    loud2, _reg2 = scan_files({os.path.join(BIG8_CORPUS, MODELING_COMMON): common_src})
    if 1279 not in loud2:
        failures.append(f'{MODELING_COMMON}:1279 (open over inspect.getfile) went silent, so the '
                        'read-only test-fixture carve-out lost its reflection proof')
    # Both reads write their join at the `open` site (Harness Law 1) because these two files carry
    # the refusal proof: `save_pretrained` owns two blessed keys and the write-mode test opens own
    # three more, so if either goes quiet the exemption widened.
    with open(os.path.join(ROOT, 'scratch', '_p3_big', 'src__transformers__modeling_utils.py'),
              encoding='utf-8', errors='replace') as handle:
        utils_src = handle.read()
    loud_utils, _reg = scan_files({P3_MODELING_UTILS: utils_src})
    for line in (3494, 3564):
        if line not in loud_utils:
            failures.append(f'{P3_MODELING_UTILS}:{line} went silent; it is a blessed CWE-22 key '
                            'inside save_pretrained, so the exemption set widened past its pin')
    with open(os.path.join(ROOT, 'scratch', '_p3_big', 'tests__generation__test_utils.py'),
              encoding='utf-8', errors='replace') as handle:
        utils_test_src = handle.read()
    loud_tests, _reg = scan_files({P3_TEST_UTILS: utils_test_src})
    for line in (5537, 5539, 5565):
        if line not in loud_tests:
            failures.append(f'{P3_TEST_UTILS}:{line} went silent; it is a blessed write-mode test '
                            'open, refused by the write-flag conjunct')
    print('  tier4 blessed Big-8 CWE-22 lines re-scanned loud: 10')
    return failures


def run_mutations() -> list:
    """TIER 5: prove every conjunct bites. A lock that passes on a blinded engine is not a lock.

    Round 3 moved two anchors, and it moved them for a reason this tier has to state rather than absorb.
    On the shipped `serializer_write_quiet` a blinded exemption or a narrowed write-flag tuple changes
    `registered` (0 -> 1, the census TIER 3 asserts) and changes no finding, because the owed rule now
    refuses to emit an unproven `open()` whatever the exemption answers -- measured in the
    `predicate_blinded` and `flags=(a,)` columns of `scratch/_c22_r3_sliceh_earn.py` (row R9). Those two
    arms therefore moved to `serializer_cli_encoding_write_quiet`, the same exempted write with a
    resolved CLI value in its non-path argument, where the booked row comes back at 10 while the shipped
    carrier keeps registering 0. `untrusted_vocabulary_emptied` moved to `serializer_write_from_stdin_loud`
    because a root written into a sink argument is recognised by `_c22_expr_is_untrusted_source` as well
    as by the module veto, so the argv/http rows stay loud at 8 with both tables emptied; the stdin row's
    loudness rests on the table alone, and emptying it exempts the write. `widened_serializer_vocabulary`
    kept its fixture and its mechanism, only not its line: 10 instead of 7.

    Each observation below is a measured value, both censuses, not merely "different" -- and each arm
    must still move at least one booked finding, or it is a mutation that stopped moving.
    """
    results = []
    shipped = ast_scanner.TaintTracker._c22_is_framework_vocab_serializer_write
    demotion = ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line
    names = ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS
    flags = ast_scanner.CWE22_SERIALIZER_WRITE_FLAGS
    source_names = ast_scanner.CWE22_UNTRUSTED_SOURCE_NAMES
    import_names = ast_scanner.CWE22_UNTRUSTED_IMPORT_MODULES

    def mutate(predicate=None, exempt=None, write_flags=None, empty_veto=False, demotion_off=False):
        if predicate is not None:
            ast_scanner.TaintTracker._c22_is_framework_vocab_serializer_write = predicate
        if exempt is not None:
            ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS = exempt
        if write_flags is not None:
            ast_scanner.CWE22_SERIALIZER_WRITE_FLAGS = write_flags
        if empty_veto:
            ast_scanner.CWE22_UNTRUSTED_SOURCE_NAMES = frozenset()
            ast_scanner.CWE22_UNTRUSTED_IMPORT_MODULES = frozenset()
        if demotion_off:
            ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = (
                lambda self, record, sink: False)

    def restore():
        ast_scanner.TaintTracker._c22_is_framework_vocab_serializer_write = shipped
        ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line = demotion
        ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS = names
        ast_scanner.CWE22_SERIALIZER_WRITE_FLAGS = flags
        ast_scanner.CWE22_UNTRUSTED_SOURCE_NAMES = source_names
        ast_scanner.CWE22_UNTRUSTED_IMPORT_MODULES = import_names

    # (arm label, mutation, [(fixture, loud lines | None, registered count | None)]) -- `None` in the
    # loud slot means "this arm does not change that fixture's finding", which is its own assertion: the
    # read-mode row stays loud under a narrowed flag set, and a widened vocabulary does not reach stdin.
    arms = [
        ('shipped_predicate_blinded',
         {'predicate': lambda self, node, mod_name: False},
         [('serializer_cli_encoding_write_quiet', [10], 1), ('serializer_write_quiet', None, 1),
          ('serializer_read_loud', [10], 1)]),
        ('widened_serializer_vocabulary',
         {'exempt': frozenset(names) | {'save_pretrained'}},
         [('pretrained_write_loud', [], 0), ('serializer_cli_encoding_write_quiet', None, 0),
          ('serializer_write_from_stdin_loud', None, 1)]),
        ('mode_set_refuses_writes',
         {'write_flags': ('a',)},
         [('serializer_cli_encoding_write_quiet', [10], 1), ('serializer_write_quiet', None, 1),
          ('serializer_read_loud', [10], 1), ('serializer_write_from_stdin_loud', None, 1)]),
        ('untrusted_vocabulary_emptied',
         {'empty_veto': True},
         [('serializer_write_from_stdin_loud', [], 0), ('serializer_cli_encoding_write_quiet', None, 0),
          ('serializer_write_with_http_source_loud', None, 1),
          ('serializer_write_with_argv_source_quiet', None, 0)]),
        # Round 5's own lock inside this gate: the re-filed argv row is quiet BECAUSE the demotion
        # retired it, so handing that rule back must restore the finding and its registration.
        ('local_cli_demotion_off',
         {'demotion_off': True},
         [('serializer_write_with_argv_source_quiet', [8], 1),
          ('serializer_cli_encoding_write_quiet', None, 0),
          ('serializer_write_with_http_source_loud', None, 1)]),
    ]
    detail = {}
    for label, kwargs, rows in arms:
        mutate(**kwargs)
        seen = []
        try:
            for fixture, want_loud, want_registered in rows:
                loud, registered = scan_files({'pkg/' + fixture + '.py': FIXTURES[fixture][0]})
                want_loud = FIXTURES[fixture][1] if want_loud is None else want_loud
                booked = FIXTURES[fixture][1]
                wrong = (loud != want_loud or (want_registered is not None
                                               and registered != want_registered))
                seen.append((fixture, wrong, loud != booked))
        finally:
            restore()
        moved = any(m for _f, _wrong, m in seen)
        bad = [f for f, wrong, _m in seen if wrong]
        results.append((label, moved and not bad))
        for fixture in bad:
            print(f'     ! {label} on {fixture} answered something other than the measured booking')
        if not moved:
            print(f'     ! {label} moved no booked finding')
    restored_ok = (ast_scanner.TaintTracker._c22_is_framework_vocab_serializer_write is shipped
                   and ast_scanner.TaintTracker._c22_sink_root_is_only_the_local_command_line is demotion
                   and ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS is names
                   and ast_scanner.CWE22_SERIALIZER_WRITE_FLAGS is flags
                   and ast_scanner.CWE22_UNTRUSTED_SOURCE_NAMES is source_names
                   and ast_scanner.CWE22_UNTRUSTED_IMPORT_MODULES is import_names)
    results.append(('engine_restored_after_mutation', restored_ok))
    failures = [name for name, ok in results if not ok]
    for name, ok in results:
        print(f'  {"ok " if ok else "FAIL"} mutation {name} -> '
              f'{"moves the tier" if ok else "does not move"}')
    return failures


def check_source_shape() -> list:
    """TIER 6: three engine addresses can register this CWE-22 row, and all three must ask.

    They all reach the same callee, so blinding that callee (TIER 5) is the behavioural proof that
    the conjunction is load-bearing; this tier is the cheaper lock against one address being deleted
    while the fixtures still pass because another address happened to be the one being exercised.
    """
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        source = handle.read()
    addresses = {
        'blindspot parameter collector':
            'if self._c22_is_framework_vocab_serializer_write(node, mod_name):\n                continue',
        'phase-5 FILE_WRITE collector':
            'and not self._c22_is_framework_vocab_serializer_write(node, mod_name) \\',
        'registry sink factory':
            'self._c22_is_framework_vocab_serializer_write(\n                node, self._scope_module(scope_id)):',
    }
    for label, spelling in sorted(addresses.items()):
        if source.count(spelling) != 1:
            failures.append(f'{label} no longer asks the shared exemption exactly once '
                            '(spelling changed or the address was dropped), so a fourth emitter can '
                            'quiet the same row without a lock')
    if 'frozenset({"save_vocabulary", "_save_vocabulary"})' not in source:
        failures.append('the pinned serializer vocabulary changed spelling, so the save_pretrained '
                        'refusal is no longer the measured two-name set')
    if 'CWE22_SERIALIZER_WRITE_FLAGS' not in source:
        failures.append('the write-mode proof no longer reads its pinned flag tuple, so '
                        'mode_set_refuses_writes above is testing nothing')
    print('  tier6 exemption addresses checked:', len(addresses))
    return failures


def main() -> int:
    failures = []
    for stage in (check_baseline_domain, check_fixtures, check_registration_prune,
                  check_blessed_lines_stay_loud, check_source_shape):
        stage_failures = stage()
        failures += stage_failures
        if stage_failures:
            for item in stage_failures:
                print(f'  FAIL {stage.__name__}: {item}')
    mutation_failures = run_mutations()
    if mutation_failures:
        failures.append('mutations that the tiers must catch did not move: ' + ', '.join(mutation_failures))
    exempt_count = len(ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS)
    verdict = ('PASS' if not failures else 'FAIL')
    print(f'VERDICT: {verdict} - CWE-22 vocabulary-serializer prune holds its {exempt_count}-name '
          'domain, keeps the 5 non-write and every protected-root row loud on an EARNed origin, drops '
          'the exempted sink before registration, and every conjunct moves under its own mutation.')
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
