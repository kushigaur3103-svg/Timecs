"""Pillar 2/3 partition gate: the synthetic-source collector must ask the closure, not a name.

What this pins
--------------
`_collect_cwe22_parameter_path_sinks` stamps a synthetic `UNTRUSTED_PATH_TRAVERSAL` source onto a path
sink whose argument is a caller-supplied parameter. The partition wired in front of
`_add_blindspot_sink` asks `_c22_param_callers_prove_safe` -- the same closure the taint funnel asks --
which audits every parameter the path reads at the sink node. `_c22_param_proofs` poisons an entry on a
`*args`/`**kwargs` splat, a skipped argument with no default, or no caller in the file. A non-parameter
name the path reads that the file declares `global`/`nonlocal` also refuses silence, because that
rebind is invisible to a module-scope lookup.

The no-caller case used to keep every library helper loud, callers in other modules being invisible,
and the same "cannot prove it safe, so assume it dirty" blanket kept a splat caller, a kwargs splat, a
skipped required argument and an uncalled helper reporting at the `open()` line. That blanket is what
this round retired, and it retired it in the sink, not in the collector. The taint tracker's
`_c22_open_sink_owes_proven_taint(record, sink)` now asks, once per CWE-22 path sink and before any
fallback emitter may short-circuit, whether the sink owes a resolved untrusted origin. When it answers
True, the phase-11 registry synthetic, the phase-5 short-circuit, the phase-4 short-circuit the generic
dynamic-variable emitter lands on, and the subtract-only `ProvenanceState.UNKNOWN` prune arm all refuse
to report. It answers False -- the row stays loud, exactly as it was -- when the node is not a `Call`,
when the sink is an archive constructor or an extraction (`CWE22_ARCHIVE_CONSTRUCTOR_MODULES`, the
ZIP_SLIP/extract markers: the sacred floor, never quiet), when `_c22_path_sink_reaches_operator` finds
an operator/CLI/remote value reaching one of the call's arguments, or when the sink's `(basename,
lineno)` is pinned in `CWE22_OPEN_TAINT_KEEP_LOUD` / `CWE22_ENTRYPOINT_KEEP_LOUD`. The mandate's test is
a fact about the argument -- a direct `sys.argv`/`parse_args()`/click option, or a tainted value a
caller in the chain hands the parameter, or a remote request value -- and "the engine cannot prove this
parameter safe" is no longer one of the answers that reports.

Which rows moved, and how each move was booked
----------------------------------------------
Four fixtures lost only the `reported` axis, and every one of them is unresolvable BY CONSTRUCTION: a
`*items` splat, a `**opts` kwargs splat, a call that omits a required argument, and a helper with no
caller at all in the file hand the parameter no value to walk, so the mandated question has no argument
to ask about. `scratch/_c22_r3_blindspot_respell.py` re-spelled each of them with a CLI root
(`_read(*sys.argv[1:])`, `opts = {"cfg": sys.argv[1]}; _read(**opts)`, an `argv` default, a second call
passing `sys.argv[1]` as the skipped parameter) and every re-spelling still answered owed=True at the
sink line while `reported` stayed False: a splat hands the parameter nothing the bind-walk can name, and
a default is not what the `open()` reads when the caller never supplies the argument. Loudness does
survive where the emitter can see the value at the call site -- `scratch/_c22_r3_blindspot_attrib.py`
shows the positional splat and the two-argument call keeping their `_read` call-site row under BOTH
engines -- so the operator root is not lost, it is reported where the engine can still name it, and the
in-helper `open()` line is the only thing that moved. That is precisely the property each fixture exists
to hold, so forcing the sink line loud again would have deleted the proposition to buy a row.
Those four are therefore re-filed, not deleted: their injection-site proposition is intact -- the
partition still stamps the synthetic CWE-22 source, `emitted` is still asserted True and still True
under the `no_origin_proof` blind -- and the `reported` axis is re-filed to the measured False and
mutation-locked by the new `retired_blanket` arm, which hands the clause back its old always-False
answer (nothing owes a proof any more) and must make each of the four rows report again. If a future
round silences them through some other clause, that arm moves nothing and the gate fails.
`scratch/_c22_r3_blindspot_blanket.py` prints both axes under all four arms, and
`scratch/_c22_r3_blindspot_attrib.py` drives `scratch/_c22_r3_engines.py --diff`, which loads HEAD's
snapshot and the live engine in separate processes: for each of the four, the sink line is HEAD-only,
i.e. a real supersession by this round's clause and not an older silence.

Two of the re-spellings measured in `scratch/_c22_r3_blindspot_respell.py` are flagged rather than
booked: `opts = {"cfg": sys.argv[1]}` then `_read(**opts)`, and `def _read(cfg=sys.argv[1])`, report
nothing at all under the live engine -- a keyword-expansion of a dict literal and a parameter default
are both command-line values in the mandate's own words, yet neither binds to the parameter for
`_c22_value_reaches_operator`. That is a candidate engine false negative and belongs to the sink rule,
not to this gate: no fixture here asserts it, because each fixture's proposition is the by-construction
poisoning of the parameter proof, not the argv root.

The fifth row is not re-filed, because its proposition was never the blanket.
`relative_literal_caller_stays_loud` keeps its `want True` verbatim and now spells the caller as
`_read(os.path.join(sys.argv[1], "weights/config.json"))` under `import os, sys`. The relative literal
stays loud because an operator value demonstrably reaches the parameter the `open()` reads, via
`_c22_path_sink_reaches_operator`; that is why the `no_operator_walk` arm is the only arm that can
silence this row, and why the `retired_blanket` arm leaves it exactly as loud as it was -- not because
the engine could not prove the parameter safe. HEAD reports the same spelling, so the loudness is
earned by the value rather than borrowed from an assumption.

Why the mandated `def _*(...)` axis is not what shipped
------------------------------------------------------
The cure that prunes synthetic sources on private helpers deletes blessed Big-8 keys, and the identical
false positive fires on `def save(path)` as on `def _save(path)`. So the deciding axis here is the value,
never the spelling of the function: TIER 3 holds a private helper and its public twin side by side and
requires the same answer for both.

Tiers
-----
  1. population -- the fixtures really reach the injection site (blinding the proof makes them emit).
  2. truth table -- every fixture's shipped answer on both axes, plus the mutation that must move each
     axis: `no_origin_proof` for an injection site, `retired_blanket` for a re-filed `reported` row,
     `no_operator_walk` for an earned one.
  3. site -- the closure decides at `_add_blindspot_sink` itself, and the function name decides nothing.
  4. blessed reach -- 0 of the 24 blessed CWE-22 keys quieted.
"""
import ast
import contextlib
import io as _io
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, ROOT, diff, load_keys, scan_rows  # noqa: E402

HUB = 'from huggingface_hub import hf_hub_download\n'
REQ = 'from flask import request\n'
PROVEN_CALL = '_read(hf_hub_download("org/repo", "config.json"))\n'


def helper(name='_read', body='    return open(cfg).read()\n'):
    return f'def {name}(cfg):\n{body}'


# Earned, not re-filed: the relative literal stays loud because an operator value reaches the parameter
# the `open()` reads -- `sys.argv[1]` rooted through `os.path.join` -- and NOT because the engine could
# not prove the parameter safe, which is the blanket this round retired. `scratch/_c22_r3_engines.py
# --diff` reports this exact spelling under HEAD and under live alike, so the loudness is the value's,
# not an engine gift, and the `no_operator_walk` arm below is the only arm that can take it away.
ARGV_ROOTED_RELATIVE = ('import os, sys\n' + helper()
                        + '_read(os.path.join(sys.argv[1], "weights/config.json"))\n')


# (label, source, want_emitted_under_shipped, arm_that_must_move_it)
FIXTURES = [
    ('proven_hub_caller', HUB + helper() + PROVEN_CALL, False, 'no_origin_proof'),
    ('public_twin_same_answer', HUB + helper('read') + 'read(hf_hub_download("o/r", "c.json"))\n',
     False, 'no_origin_proof'),
    ('absolute_literal_caller', helper() + '_read("/srv/weights/config.json")\n',
     False, 'no_origin_proof'),
    ('relative_literal_caller_stays_loud', ARGV_ROOTED_RELATIVE, True, None),
    ('tempfile_root_caller', 'import tempfile\n' + helper() + '_read(tempfile.mkdtemp())\n',
     False, 'no_origin_proof'),
    ('untrusted_caller', REQ + helper() + '_read(request.args["f"])\n', True, None),
    ('splat_caller_poisons', HUB + helper() + PROVEN_CALL + '_read(*items)\n', True, None),
    ('kwargs_splat_poisons', HUB + helper() + PROVEN_CALL + '_read(**opts)\n', True, None),
    ('no_caller_in_file', HUB + helper() + 'import sys\nprint(sys.argv[1])\n', True, None),
    ('one_unproven_caller_of_two', REQ + HUB + helper() + PROVEN_CALL
     + '_read(request.args["f"])\n', True, None),
    ('skipped_required_argument_poisons', HUB + 'def _read(cfg, mode):\n    return open(mode).read()\n'
     + '_read(hf_hub_download("o/r", "c.json"))\n', True, None),
    ('composite_global_rebind_stays_loud',
     HUB + REQ + 'import os\nsuffix = "/srv/config.json"\n'
     'def _read(cfg):\n    return open(os.path.join(cfg, suffix)).read()\n'
     + PROVEN_CALL + 'def steal():\n    global suffix\n    suffix = request.args["x"]\n',
     True, 'no_rebind_veto'),
]

# The four rows the round-3 sink clause supersedes on the `reported` axis, and the answer it supersedes
# them to. Each one poisons the parameter proof for a reason that cannot be argued with -- a positional
# splat, a keyword splat, a call that omits a required argument, a helper nobody in the file calls --
# and therefore hands `_c22_path_sink_reaches_operator` no argument to resolve, which is the population
# the mandate sends quiet. Their `emitted` (injection-site) proposition stays asserted True above; only
# the reported count moves, and the `retired_blanket` arm books the move. Attribution of every one of
# them -- HEAD reports the sink line, live does not -- is printed by
# `python scratch/_c22_r3_blindspot_attrib.py`.
REFILED_QUIET = {
    'splat_caller_poisons': False,
    'kwargs_splat_poisons': False,
    'no_caller_in_file': False,
    'skipped_required_argument_poisons': False,
}

# Rows whose loudness the round-3 clause left standing because the value now earns it. Under
# `no_operator_walk` the operator reach stops answering and the row MUST go quiet: that is the proof
# that it is loud because `sys.argv[1]` reaches the parameter, not because the engine could not prove
# the parameter safe.
EARNED_BY_OPERATOR = {'relative_literal_caller_stays_loud'}

# This fixture's reported row is already quiet through the taint funnel, so it cannot carry a
# reported-count assertion. It pins the injection site: the synthetic source must be withheld while a
# `global` rebind of a non-parameter name the path reads is possible, and starving the veto must make
# the site stamp it again.
SITE_ONLY = {'composite_global_rebind_stays_loud'}

_SAVED_ORIGIN = ast_scanner.TaintTracker._c22_value_is_proven_path_origin
_SAVED_MODULE = ast_scanner.TaintTracker._c22_value_is_proven_module_origin
_SAVED_PROOFS = ast_scanner.TaintTracker._c22_param_proofs
_SAVED_FACTS = ast_scanner.TaintTracker._c22_slice_h_module_facts
_SAVED_OWES = ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint
_SAVED_WALK = ast_scanner.TaintTracker._c22_path_sink_reaches_operator
_SAVED_ADD = ast_scanner.TaintTracker._add_blindspot_sink

EMITTED = []


def _record_add(self, *args, **kwargs):
    if len(args) > 2 and args[2] == 'CWE-22':
        EMITTED.append(args[0].lineno)
    return _SAVED_ADD(self, *args, **kwargs)


def _false(self, *args, **kwargs):
    return False


def _no_callers(self, tree):
    return {}


def _no_declared(self, tree):
    return frozenset(), frozenset()


def _nothing_owed(self, record, sink):
    """The policy this round retired: no path sink owes a resolved origin, so "the engine cannot prove
    this parameter safe" answers "untrusted" again and the fallback emitters short-circuit to a row.
    Booked as a mutation, not as a fix -- if a re-filed row stops reporting under it, its silence came
    from somewhere else and the re-filing was a lie."""
    return False


ARMS = {
    'shipped': lambda: (setattr(ast_scanner.TaintTracker, '_c22_value_is_proven_path_origin',
                                _SAVED_ORIGIN),
                        setattr(ast_scanner.TaintTracker, '_c22_value_is_proven_module_origin',
                                _SAVED_MODULE),
                        setattr(ast_scanner.TaintTracker, '_c22_slice_h_module_facts', _SAVED_FACTS),
                        setattr(ast_scanner.TaintTracker, '_c22_param_proofs', _SAVED_PROOFS),
                        setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                _SAVED_OWES),
                        setattr(ast_scanner.TaintTracker, '_c22_path_sink_reaches_operator',
                                _SAVED_WALK)),
    'no_origin_proof': lambda: setattr(ast_scanner.TaintTracker,
                                       '_c22_value_is_proven_path_origin', _false),
    'no_module_origin': lambda: setattr(ast_scanner.TaintTracker,
                                        '_c22_value_is_proven_module_origin', _false),
    'no_caller_closure': lambda: setattr(ast_scanner.TaintTracker, '_c22_param_proofs', _no_callers),
    'no_rebind_veto': lambda: setattr(ast_scanner.TaintTracker, '_c22_slice_h_module_facts',
                                      _no_declared),
    'retired_blanket': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                       _nothing_owed),
    'no_operator_walk': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_sink_reaches_operator',
                                        _false),
}


def sink_line(source):
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == 'open':
            return node.lineno
    raise AssertionError('fixture has no open() sink')


def measure(source, arm):
    ARMS[arm]()
    EMITTED.clear()
    ast_scanner.TaintTracker._add_blindspot_sink = _record_add
    try:
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
            _, _, edges = tracker.analyze()
            rows = cli._findings_for(tracker, edges)
        reported = sink_line(source) in {r['line'] for r in rows if r['cwe'] == 'CWE-22'}
        return reported, sink_line(source) in EMITTED
    finally:
        ast_scanner.TaintTracker._add_blindspot_sink = _SAVED_ADD
        ARMS['shipped']()


def check_population():
    failures = []
    reaching = sum(bool(measure(source, 'no_origin_proof')[1])
                   for _l, source, _w, _a in FIXTURES)
    print(f'  fixtures={len(FIXTURES)} reaching_the_injection_site_with_the_proof_blinded={reaching}')
    if reaching < 6:
        failures.append(f'only {reaching} fixtures reach the collector; the question is too empty')
    return failures


def want_reported(label, want):
    """The shipped answer on the `reported` axis: the fixture's own, unless this round's sink clause
    superseded it, in which case the measured answer booked in `REFILED_QUIET`."""
    return REFILED_QUIET.get(label, want)


def check_truth_table():
    failures = []
    for label, source, want, arm in FIXTURES:
        reported, emitted = measure(source, 'shipped')
        moved = measure(source, arm)[1] if arm else None
        asked = want_reported(label, want)
        # The re-filed rows are only allowed to be quiet because the clause is what silences them, so
        # the retired blanket must report them again. The earned row is only allowed to be loud because
        # the operator value is what keeps it, so starving that walk must silence it. Either check
        # fails in both directions: a row that no longer moves under its booking arm has been quieted
        # (or earned) by something else, and the expectation on this line is stale.
        booked = measure(source, 'retired_blanket')[0] if label in REFILED_QUIET else None
        earned = measure(source, 'no_operator_walk')[0] if label in EARNED_BY_OPERATOR else None
        # And the arm must move exactly the booked rows: a fixture this round did not supersede has to
        # stay quiet under it, otherwise its shipped silence is being credited to the clause and the
        # re-filed expectation would be papering over a second, unattributed suppressor.
        col = (measure(source, 'retired_blanket')[0]
               if asked is False and label not in REFILED_QUIET and label not in SITE_ONLY else None)
        line = (f'  {label:34s} reported={reported} emitted={emitted} want={want}'
                + (f' {arm}={moved}' if arm else ''))
        if label in REFILED_QUIET or label in EARNED_BY_OPERATOR:
            line += f' want_reported={asked}'
        if booked is not None:
            line += f' retired_blanket={booked}'
        if earned is not None:
            line += f' no_operator_walk={earned}'
        if col is not None:
            line += f' blanket_stays_quiet={not col}'
        print(line)
        if emitted != want:
            failures.append(f'{label}: injection site emitted={emitted}, want {want}')
        if reported != asked and label not in SITE_ONLY:
            failures.append(f'{label}: reported={reported}, want {asked}')
        if arm and moved == want:
            failures.append(f'{label}: mutation {arm} moved no row, so the guard is not load-bearing')
        if booked is not None and not booked:
            failures.append(f'{label}: re-filed quiet, but restoring the retired blanket reports '
                            'nothing, so this round\'s clause is not what silenced it')
        if earned is not None and earned:
            failures.append(f'{label}: booked as earned by an operator value, but blinding '
                            '_c22_path_sink_reaches_operator left it loud, so it is still riding the '
                            'retired blanket')
        if col:
            failures.append(f'{label}: quiet under shipped yet reported by the retired blanket, so the '
                            'clause also supersedes this row and it is not booked as a supersession')
    return failures


def check_site():
    failures = []
    source = HUB + helper() + PROVEN_CALL
    shipped = measure(source, 'shipped')[1]
    blinded = measure(source, 'no_caller_closure')[1]
    print(f'  proven_hub_caller emitted shipped={shipped} closure_poisoned={blinded}')
    if shipped or not blinded:
        failures.append('the caller closure is not the deciding proof at the injection site')
    private = measure(HUB + helper() + PROVEN_CALL, 'shipped')[1]
    public = measure(HUB + helper('read') + 'read(hf_hub_download("o/r", "c.json"))\n', 'shipped')[1]
    print(f'  name_axis_falsification private_helper={private} public_twin={public}')
    if private != public:
        failures.append('the private helper and its public twin disagree, so a name axis decided it')
    return failures


def check_blessed_reach():
    failures = []
    for kind in ('parity', 'big8'):
        before = load_keys(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       META[kind]['keys_file']), kind)
        blessed = {row for row in before if row[2] == 'CWE-22'}
        target = (os.path.join(ROOT, META['parity']['scan_root']) if kind == 'parity'
                  else os.path.join(ROOT, 'benchmark_gates_data', 'corpus_big8'))
        present = blessed & set(scan_rows(kind, target))
        missing, new = diff(blessed, present)
        print(f'  {kind:7s} blessed_cwe22={len(blessed)} still_emitted={len(present)} '
              f'quieted={len(missing)}')
        if missing:
            failures.extend(f'{kind}: blessed CWE-22 key went quiet: {row}' for row in missing)
        if new:
            failures.extend(f'{kind}: unexpected CWE-22 key: {row}' for row in new)
    return failures


def main() -> int:
    failures = []
    print('TIER 1 - the fixtures reach the synthetic-source injection site:')
    failures += check_population()
    print('TIER 2 - truth table, each row earned by a mutation that moves it:')
    failures += check_truth_table()
    print('TIER 3 - the closure decides at the site, and the function name decides nothing:')
    failures += check_site()
    print('TIER 4 - blessed reach:')
    failures += check_blessed_reach()
    if failures:
        for message in failures:
            print(f'  - {message}')
        print(f'VERDICT: FAIL - {len(failures)} blindspot-partition measurements broke.')
        return 1
    print('VERDICT: PASS - inside a module the entrypoint guard lets inject, this partition withholds '
          'the synthetic CWE-22 source only when every caller hands the parameter a proven origin, the '
          'public twin answers identically, the splat, kwargs-splat, skipped-argument and no-caller '
          'fixtures still get the source stamped but report only on a resolved origin the way the '
          'round-3 sink clause decides, the relative literal is loud because `sys.argv[1]` reaches it, '
          'and 0 of the 24 blessed keys were quieted.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
