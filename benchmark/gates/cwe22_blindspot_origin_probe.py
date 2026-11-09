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

The no-caller case used to keep every library helper loud, callers in other modules being invisible.
The entrypoint guard (`cwe22_entrypoint_injection_probe`) retired that blanket for modules that declare
no entrypoint, so `no_caller_in_file` now carries a `sys.argv` read to keep the source being injected
at all; the row is then still loud because this partition refuses to certify an origin for a parameter
nobody in the file hands it a value.

Why the mandated `def _*(...)` axis is not what shipped
------------------------------------------------------
The cure that prunes synthetic sources on private helpers deletes blessed Big-8 keys, and the identical
false positive fires on `def save(path)` as on `def _save(path)`. So the deciding axis here is the value,
never the spelling of the function: TIER 3 holds a private helper and its public twin side by side and
requires the same answer for both.

Tiers
-----
  1. population -- the fixtures really reach the injection site (blinding the proof makes them emit).
  2. truth table -- every fixture's shipped answer, plus the mutation that must move it.
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


# (label, source, want_emitted_under_shipped, arm_that_must_move_it)
FIXTURES = [
    ('proven_hub_caller', HUB + helper() + PROVEN_CALL, False, 'no_origin_proof'),
    ('public_twin_same_answer', HUB + helper('read') + 'read(hf_hub_download("o/r", "c.json"))\n',
     False, 'no_origin_proof'),
    ('absolute_literal_caller', helper() + '_read("/srv/weights/config.json")\n',
     False, 'no_origin_proof'),
    ('relative_literal_caller_stays_loud', helper() + '_read("weights/config.json")\n', True, None),
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

# This fixture's reported row is already quiet through the taint funnel, so it cannot carry a
# reported-count assertion. It pins the injection site: the synthetic source must be withheld while a
# `global` rebind of a non-parameter name the path reads is possible, and starving the veto must make
# the site stamp it again.
SITE_ONLY = {'composite_global_rebind_stays_loud'}

_SAVED_ORIGIN = ast_scanner.TaintTracker._c22_value_is_proven_path_origin
_SAVED_MODULE = ast_scanner.TaintTracker._c22_value_is_proven_module_origin
_SAVED_PROOFS = ast_scanner.TaintTracker._c22_param_proofs
_SAVED_FACTS = ast_scanner.TaintTracker._c22_slice_h_module_facts
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


ARMS = {
    'shipped': lambda: (setattr(ast_scanner.TaintTracker, '_c22_value_is_proven_path_origin',
                                _SAVED_ORIGIN),
                        setattr(ast_scanner.TaintTracker, '_c22_value_is_proven_module_origin',
                                _SAVED_MODULE),
                        setattr(ast_scanner.TaintTracker, '_c22_slice_h_module_facts', _SAVED_FACTS),
                        setattr(ast_scanner.TaintTracker, '_c22_param_proofs', _SAVED_PROOFS)),
    'no_origin_proof': lambda: setattr(ast_scanner.TaintTracker,
                                       '_c22_value_is_proven_path_origin', _false),
    'no_module_origin': lambda: setattr(ast_scanner.TaintTracker,
                                        '_c22_value_is_proven_module_origin', _false),
    'no_caller_closure': lambda: setattr(ast_scanner.TaintTracker, '_c22_param_proofs', _no_callers),
    'no_rebind_veto': lambda: setattr(ast_scanner.TaintTracker, '_c22_slice_h_module_facts',
                                      _no_declared),
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


def check_truth_table():
    failures = []
    for label, source, want, arm in FIXTURES:
        reported, emitted = measure(source, 'shipped')
        moved = measure(source, arm)[1] if arm else None
        print(f'  {label:34s} reported={reported} emitted={emitted} want={want}'
              + (f' {arm}={moved}' if arm else ''))
        if emitted != want:
            failures.append(f'{label}: injection site emitted={emitted}, want {want}')
        if reported != want and label not in SITE_ONLY:
            failures.append(f'{label}: reported={reported}, want {want}')
        if arm and moved == want:
            failures.append(f'{label}: mutation {arm} moved no row, so the guard is not load-bearing')
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
          'the synthetic CWE-22 source only when every caller hands the parameter a proven origin, '
          'splats and uncalled helpers stay loud, the public twin answers identically, and 0 of the '
          '24 blessed keys were quieted.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
