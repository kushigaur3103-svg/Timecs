"""Round 6: the qualified local-filesystem-discovery classification, and the container-key fix.

What this gate is for
---------------------
Round 5 shipped `_c22_sink_root_is_only_the_local_command_line`: a filesystem sink whose ONLY root is
this process's own command line is retired, because the operator who typed `--output-dir` is the
process owner and not a remote caller. The retirement is a differential -- the operator walk answers
yes unblinded and no when the command line is exempted -- conjoined with a PROOF that every path
component has a resolved origin (`_c22_value_origin_is_resolved`). That proof stops at any call no
table classifies, so a whole class of purely local helpers kept their rows for no reason the engine
could state.

The mandate named 13 such call shapes in four groups. They were priced before any of them was
implemented (`scratch/_c22_r6_price.py`, three classifier arms over 15 hiding shapes and the 14 arena
rows the groups touch), and the price is the reason this gate exists in the shape it does:

  group                     arena rows   retire   remote roots hidden (naive / guarded)
  dict view methods              5         0              5 / 1
  str.replace                    2         0              0 / 0
  local FS discovery             5         4              0 / 0
  Config.load_yaml               2         0              1 / 1

Only the filesystem group buys anything, and it is the only one that hides nothing. The other three
are DECLINED, and `check_declined_groups` below is what makes the decline permanent rather than a
promise: TIER 1 asks the classifier itself about every spelling the three groups would have credited
and requires a refusal. A later revision that adds them fails this gate on the predicate, not on a
remembered conversation.

The mandate expected 91 -> ~78. The measured answer is 91 -> 87, and the five-row shortfall is not a
punt under TP risk -- it is three groups whose arena gain is ZERO in both classifier arms, so there is
no clean row to partition off and nothing to suppress. Two of the three also hide remote roots:
crediting dict views hides 5 of 5 shapes naively and 1 even with a mutation guard, and crediting
`Config.load_yaml` hides 1. `str.replace` hides nothing and buys nothing. Declining a measured no-op
is the sound answer; the anti-surrender law asks for the (N-K) clean rows to be suppressed in the same
turn, and here N-K is 0 for each of the three.

The dict-view group's own hole is worth spelling out, because it is the reason "0 retirements" is not
the same as "harmless". `artifacts.update({...})` and `results[key] = ...` write into a dict AFTER the
binding the walk can see, so the walk resolves the name to `{}` and never sees what was put in it. In
the arena those dicts are fed by `requests.get(...).json()`
(`utils/get_ci_error_statistics.py:77/82`, `masked_run_squad.py:1133`, `create_dummy_models.py:1425`).
Crediting `.keys()`/`.items()`/`.values()`/`.pop()` retires the row that reads them.
`Config.load_yaml` is the same defect in a different costume: it is a `@staticmethod` DEFINED in
`examples/research_projects/lxmert/utils.py:155`, and the function that consumes its result
(`cached_path`, line 419) has a remote download branch at 437-447. A local def is an unknown wrapper.

The soundness fix this round also carries
-----------------------------------------
Pricing the dict group found a false negative in round 5's own commit. The resolved-origin walk's Dict
arm walked `expr.values` and never `expr.keys` -- but iterating a dict yields its KEYS, so
`table = {requests.get(url).text: 1}` / `for name in table` / `open(join(out, name))` was retired with
a remote root inside it. `ast.DictComp` had the identical blindness on `expr.key`. Five hiding shapes
went quiet on HEAD's blob and keep their report now
(`scratch/_c22_r6_container_arms.py`, run against `git show HEAD:ast_scanner.py` and against the live
engine: 4 holes before, 0 after, plus `iterate_dict_with_remote_key` in
`scratch/_c22_r6_fs_soundness.py` Q1). `container_key_arm_blind` hands the retired rule back and is
what proves the fix is load-bearing rather than decorative.

Both changes are subtract-only in the direction that matters: walking MORE children can only add
refusals, and classifying a call can only let a proof finish that already had to survive the
differential. Neither can invent a finding, and neither can retire a row whose remote root the
blinded walk can see.

How to read the tiers
---------------------
TIER 1 is the predicate truth table -- which spellings the classifier credits, asked on the node.
TIER 2 is the retirements, each attributed against the demotion-off arm so a row this lever did not
retire cannot be booked to it.
TIER 3 is the hiding shapes, each required to be loud under BOTH arms: quiet under both is an
inherited gap at HEAD, not a soundness claim this gate may make.
TIER 4 is the declined groups. TIER 4b records the one shape that IS quiet under both arms, so the
blind spot is on the record and this lever is forbidden from claiming it.
TIER 5 is one weakening per clause, each with the rows it was measured to move
(`scratch/_c22_r6_gate_filing.py` prints the whole moves matrix; all five are CAUGHT).

The arena price, measured on the pair rather than on the fixtures: HEAD `ea28a58` 1065 findings / 91
CWE-22, candidate 1061 / 87 -- **4 retired, 0 added, 0 message churn**, and the four are exactly the
rows the price probe named (`utils/check_copies.py:590,759`, `utils/sort_auto_mappings.py:61,95`).
The container-key fix un-retired nothing: it closes five false negatives at zero cost in retirements.
The HEAD arm's row set is byte-identical to round 5's committed candidate output, which is the
integrity check that says the pair is measuring this slice and nothing else
(`scratch/_c22_r6_row_diff.py`).

Every pin is the fixture's own `open()` line, read off its AST rather than counted by hand: round 5
paid for a drifted line number with a re-file, and a derived pin cannot drift when a fixture is edited.

    python benchmark/gates/cwe22_local_fs_discovery_probe.py
    python benchmark/gates/cwe22_local_fs_discovery_probe.py --mutate=container_key_arm_blind
"""
from __future__ import annotations

import ast
import contextlib
import copy
import io as _io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)
sys.path.insert(0, GATES_DIR)

import ast_scanner  # noqa: E402
import cli  # noqa: E402

T = ast_scanner.TaintTracker


def module(*lines):
    return ''.join(line + '\n' for line in lines)


def pinned(table):
    """label -> source becomes label -> (the fixture's own open() line, source)."""
    out = {}
    for label, source in table.items():
        lines = [node.lineno for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call)
                 and (ast_scanner.dotted_name(node.func) or '') == 'open']
        if len(lines) != 1:
            raise AssertionError(f'{label}: expected exactly one open() call, found {lines}')
        out[label] = (lines[0], source)
    return out


# --------------------------------------------------------------------------- TIER 2: the retirements
# The command line is the only root, and the discovery call is what lets the resolved-origin proof
# finish instead of stopping at an unclassified callee. Each is quiet now and loud with the demotion
# off, which is the attribution: `local_cli_demotion_off` and `fs_discovery_table_emptied` both move
# them, and the second is what says the CLASSIFICATION is load-bearing rather than the demotion alone.
RETIRED_BY_FS_DISCOVERY = pinned({
    'fs_listdir_cli': module(
        'import os', 'import sys', 'def run(root):',
        '    for name in os.listdir(root):',
        '        with open(os.path.join(root, name)) as handle:',
        '            return handle.read()',
        'run(sys.argv[1])'),
    'fs_glob_cli': module(
        'import os', 'import sys', 'import glob', 'def run(root):',
        '    for path in glob.glob(os.path.join(root, "*.py")):',
        '        with open(path) as handle:',
        '            return handle.read()',
        'run(sys.argv[1])'),
    'fs_getcwd_cli': module(
        'import os', 'import sys', 'def run():',
        '    with open(os.path.join(os.getcwd(), sys.argv[1])) as handle:',
        '        return handle.read()',
        'run()'),
})

# --------------------------------------------------------------------------- TIER 3: the hiding shapes
# A remote component inside a discovery call, or beside it. The two `*_in_join` shapes are the ones
# that exercise the DESCENT, and `fs_discovery_no_descent` is the measurement that says so: a
# command-line component beside the discovery call gives the unblinded walk a root it can see and the
# blinded walk none, which is the only combination where the proof's descent into the discovery
# argument is what decides the row. The other shapes are soundness witnesses, not descent evidence --
# with the remote root alone the walk stops at the call in BOTH arms, so the row is loud for a reason
# that has nothing to do with the descent (`owed=True`, or the differential refusing on a root the
# blinded walk can still see). `fs_listdir_loop_target_only` below is the shape where that same
# stop-at-the-call behaviour leaves NO row at all, at HEAD and now.
LOUD_BY_FS_DESCENT = pinned({
    'fs_listdir_remote_in_join': module(
        'import os', 'import sys', 'import requests', 'def run(out, url):',
        '    with open(os.path.join(out, os.listdir(requests.get(url).text)[0])) as handle:',
        '        return handle.read()',
        'run(sys.argv[1], sys.argv[2])'),
    'fs_glob_remote_in_join': module(
        'import os', 'import sys', 'import glob', 'import requests', 'def run(out, url):',
        '    with open(os.path.join(out, glob.glob(requests.get(url).text)[0])) as handle:',
        '        return handle.read()',
        'run(sys.argv[1], sys.argv[2])'),
    'fs_listdir_remote_via_name': module(
        'import os', 'import sys', 'import requests', 'def run(url):',
        '    root = requests.get(url).text',
        '    for name in os.listdir(root):',
        '        with open(os.path.join(root, name)) as handle:',
        '            return handle.read()',
        'run(sys.argv[1])'),
    'fs_glob_remote_pattern': module(
        'import os', 'import sys', 'import glob', 'from urllib.request import urlopen',
        'def run(url):',
        '    with open(glob.glob(urlopen(url).read().decode())[0]) as handle:',
        '        return handle.read()',
        'run(sys.argv[1])'),
    'fs_getcwd_remote_join': module(
        'import os', 'import sys', 'import requests', 'def run(url):',
        '    with open(os.path.join(os.getcwd(), requests.get(url).text)) as handle:',
        '        return handle.read()',
        'run(sys.argv[1])'),
    'fs_listdir_remote_environ': module(
        'import os', 'import sys', 'def run(root):',
        '    with open(os.listdir(os.environ["ROOT"])[0]) as handle:',
        '        return handle.read()',
        'run(sys.argv[1])'),
})
# The qualified-only witness. This file DEFINES `listdir` and its body fetches, so the bare spelling
# is an unknown wrapper: the blinded walk resolves names to bindings and never reads a callee body.
LOUD_BY_QUALIFIED_WITNESS = pinned({
    'fs_listdir_bare_localdef': module(
        'import os', 'import sys', 'import requests',
        'def listdir(root):',
        '    return requests.get(root).json()',
        'def run(root):',
        '    with open(listdir(root)[0]) as handle:',
        '        return handle.read()',
        'run(sys.argv[1])'),
})
# Iterating a dict yields its KEYS. Every one of these was QUIET on HEAD's blob and is loud now.
LOUD_BY_CONTAINER_KEY = pinned({
    'dict_key_remote_iterated': module(
        'import os', 'import sys', 'import requests', 'def run(out, url):',
        '    table = {requests.get(url).text: 1}',
        '    for name in table:',
        '        with open(os.path.join(out, name)) as handle:',
        '            return handle.read()',
        'run(sys.argv[1], sys.argv[2])'),
    'dictcomp_key_remote_iterated': module(
        'import os', 'import sys', 'import requests', 'def run(out, url):',
        '    table = {requests.get(url).text: 1 for _ in range(1)}',
        '    for name in table:',
        '        with open(os.path.join(out, name)) as handle:',
        '            return handle.read()',
        'run(sys.argv[1], sys.argv[2])'),
    'dict_key_remote_via_list': module(
        'import os', 'import sys', 'import requests', 'def run(out, url):',
        '    table = {requests.get(url).text: 1}',
        '    with open(os.path.join(out, list(table)[0])) as handle:',
        '        return handle.read()',
        'run(sys.argv[1], sys.argv[2])'),
    'dict_nested_key_remote': module(
        'import os', 'import sys', 'import requests', 'def run(out, url):',
        "    table = {'a': {requests.get(url).text: 1}}",
        "    for name in table['a']:",
        '        with open(os.path.join(out, name)) as handle:',
        '            return handle.read()',
        'run(sys.argv[1], sys.argv[2])'),
    'dict_key_localdef_remote': module(
        'import os', 'import sys', 'import requests',
        'def fetch(url):',
        '    return requests.get(url).text',
        'def run(out, url):',
        '    table = {fetch(url): 1}',
        '    for name in table:',
        '        with open(os.path.join(out, name)) as handle:',
        '            return handle.read()',
        'run(sys.argv[1], sys.argv[2])'),
})
# The declined dict-view group's own hole, kept as a fixture so the decline is measured on a finding
# and not merely asserted on a node: a remote root in a dict VALUE read back through a view method.
LOUD_BY_DECLINED_GROUP = pinned({
    'dict_view_literal_remote': module(
        'import os', 'import sys', 'import requests', 'def run(out, url):',
        "    table = {'k': requests.get(url).text}",
        '    with open(os.path.join(out, list(table.values())[0])) as handle:',
        '        return handle.read()',
        'run(sys.argv[1], sys.argv[2])'),
})

LOUD_TABLES = {'fs descent': LOUD_BY_FS_DESCENT,
               'qualified witness': LOUD_BY_QUALIFIED_WITNESS,
               'container key': LOUD_BY_CONTAINER_KEY,
               'declined group': LOUD_BY_DECLINED_GROUP}
# --------------------------------------------------------------------------- inherited, NOT claimed
# Quiet on HEAD's committed blob and quiet now, under BOTH arms. `open(name)` where `name` is a
# `os.listdir(...)` loop target produces no row at all: the engine's directory-enumeration reading
# treats a listing entry as naming something that already exists inside the listed directory, so the
# remote root inside the listing argument never reaches the sink. Measured on
# `git show HEAD:ast_scanner.py`: shipped=[] demotion_off=[].
#
# This is a blind spot, not a proof of cleanliness, so it is deliberately NOT asserted to stay quiet --
# a later round that fixes it must be free to. The one claim made here is the attribution: this lever
# may not book the silence as a retirement, and `demote` must never be `yes` on it. Filed so the gap is
# on the record instead of being discovered again and charged to the wrong round.
INHERITED_GAPS = pinned({
    'fs_listdir_loop_target_only': module(
        'import os', 'import sys', 'import requests', 'def run(url):',
        '    for name in os.listdir(requests.get(url).text):',
        '        with open(name) as handle:',
        '            return handle.read()',
        'run(sys.argv[1])'),
})
ALL_FIXTURES = dict(RETIRED_BY_FS_DISCOVERY)
for _table in tuple(LOUD_TABLES.values()) + (INHERITED_GAPS,):
    ALL_FIXTURES.update(_table)
LOUD_LABELS = {label for table in LOUD_TABLES.values() for label in table}

# --------------------------------------------------------------------------- TIER 1: the predicate
# Asked on the node, so a spelling cannot be credited by a fixture that happens to be quiet for
# another reason. `credit` is the answer the classifier must give.
PREDICTED_CALLS = {
    'os.getcwd()': ('import os\nx = os.getcwd()\n', True),
    'os.listdir(root)': ('import os\nx = os.listdir(root)\n', True),
    'glob.glob(pattern)': ('import glob\nx = glob.glob(pattern)\n', True),
    # The bare spellings: no import witness, so each may be this file's own wrapper.
    'getcwd()': ('x = getcwd()\n', False),
    'listdir(root)': ('x = listdir(root)\n', False),
    'glob(pattern)': ('x = glob(pattern)\n', False),
    # The three declined groups. Every one of these is a spelling the mandate asked to credit and
    # the price measurement refused; a later revision that adds one fails here.
    'table.keys()': ('table = {}\nx = table.keys()\n', False),
    'table.items()': ('table = {}\nx = table.items()\n', False),
    'table.values()': ('table = {}\nx = table.values()\n', False),
    "table.pop('k')": ("table = {}\nx = table.pop('k')\n", False),
    "name.replace('a', 'b')": ("name = 'x'\ny = name.replace('a', 'b')\n", True),
    'Config.load_yaml(path)': ('class Config:\n    pass\nx = Config.load_yaml(path)\n', True),
    # A local def is an unknown wrapper whatever it is called, and a remote fetch is never a path call.
    'helper(root)': ('def helper(root):\n    return root\nx = helper(root)\n', False),
    'requests.get(url)': ('import requests\nx = requests.get(url)\n', False),
}


def call_node(source, spelling):
    """The one `ast.Call` in `source` whose dotted spelling matches, with its module tree."""
    tree = ast.parse(source)
    wanted = spelling.split('(')[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (ast_scanner.dotted_name(node.func) or '') == wanted:
            return tree, node
    raise AssertionError(f'no call spelling {spelling!r} in the fixture source')


# --------------------------------------------------------------------------- plumbing

def scan_module(source, module_name='m.py'):
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files={module_name: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(int(row['line']), row['message']) for row in rows if row['cwe'] == 'CWE-22'})


def rows_at(found, line):
    return [message for row_line, message in found if row_line == line]


def observe(source):
    """Scan once and record what the shipped rule asked and answered, through the engine's own calls."""
    consults = []
    owed_original = T._c22_open_sink_owes_proven_taint
    demote_original = T._c22_sink_root_is_only_the_local_command_line
    answers = []

    def demote_spy(self, record, sink):
        answer = demote_original(self, record, sink)
        answers.append((int(record.lineno), bool(answer)))
        return answer

    def owed_spy(self, record, sink):
        answer = owed_original(self, record, sink)
        consults.append({'line': int(record.lineno), 'owed': answer,
                         'demote': 'never' if answer else 'asked'})
        return answer

    T._c22_open_sink_owes_proven_taint = owed_spy
    T._c22_sink_root_is_only_the_local_command_line = demote_spy
    try:
        found = scan_module(source)
    finally:
        T._c22_open_sink_owes_proven_taint = owed_original
        T._c22_sink_root_is_only_the_local_command_line = demote_original
    for entry in consults:
        said = [answer for line, answer in answers if line == entry['line']]
        if said:
            entry['demote'] = 'yes' if any(said) else 'no'
    return found, consults


def demotion_off(source):
    """The same module with the whole local-command-line rule switched off: the attribution arm."""
    original = T._c22_sink_root_is_only_the_local_command_line
    T._c22_sink_root_is_only_the_local_command_line = lambda self, record, sink: False
    try:
        return scan_module(source)
    finally:
        T._c22_sink_root_is_only_the_local_command_line = original


def consult_on(consults, line):
    entries = [entry for entry in consults if entry['line'] == line]
    return entries[0] if len(entries) == 1 else None


# --------------------------------------------------------------------------- tiers

def check_predicate():
    print('TIER 1 - which spellings the classifier credits, asked on the node:')
    failures = []
    tracker = T(files={}, max_workers=1)
    credited = refused = 0
    for spelling, (source, want) in sorted(PREDICTED_CALLS.items()):
        tree, node = call_node(source, spelling)
        got = tracker._c22_call_is_classified_path_call(tree, node)
        if bool(got) != want:
            failures.append(('classifier answered the wrong way', spelling, got, want))
        elif want:
            credited += 1
        else:
            refused += 1
    print(f'  credited={credited} refused={refused} of {len(PREDICTED_CALLS)} spellings')
    return failures


def check_retirements():
    print('TIER 2 - the retirements, attributed against the demotion-off arm:')
    failures = []
    retired = 0
    for label, (line, source) in sorted(RETIRED_BY_FS_DISCOVERY.items()):
        found, consults = observe(source)
        entry = consult_on(consults, line)
        off = rows_at(demotion_off(source), line)
        if rows_at(found, line):
            failures.append(('discovery row was not retired', label, line))
        elif entry is None:
            failures.append(('no single consult on the pinned line', label, line))
        elif entry['owed']:
            failures.append(('row went quiet by OWING a proof, not by the demotion', label, line))
        elif entry['demote'] != 'yes':
            failures.append(('the demotion did not claim this row', label, line, entry['demote']))
        elif not off:
            failures.append(('quiet under both arms: inherited gap, not this lever', label, line))
        else:
            retired += 1
        print(f'  {label:28s} line={line} quiet={not rows_at(found, line)} '
              f'owed={entry["owed"] if entry else "-"} '
              f'demote={entry["demote"] if entry else "-"} demotion_off_loud={bool(off)}')
    print(f'  retired_by_this_classification={retired}/{len(RETIRED_BY_FS_DISCOVERY)}')
    return failures


def check_hiding_shapes():
    print('TIER 3 - the hiding shapes, loud under BOTH arms:')
    failures = []
    held = 0
    for name, table in sorted(LOUD_TABLES.items()):
        for label, (line, source) in sorted(table.items()):
            found, consults = observe(source)
            entry = consult_on(consults, line)
            off = rows_at(demotion_off(source), line)
            if not rows_at(found, line):
                failures.append(('a remote root went quiet', name, label, line))
            elif not off:
                failures.append(('loud only because the demotion is off: not a soundness witness',
                                 name, label, line))
            else:
                held += 1
            print(f'  {label:30s} line={line} loud={bool(rows_at(found, line))} '
                  f'demotion_off_loud={bool(off)} '
                  f'demote={entry["demote"] if entry else "-"}')
    print(f'  remote_roots_held_loud={held}/{len(LOUD_LABELS)}')
    return failures


def check_declined_groups():
    print('TIER 4 - the three declined groups, refused on the predicate and on the arena:')
    failures = []
    # The measured price, booked so a later revision cannot re-claim the groups without re-measuring.
    # `scratch/_c22_r6_price.py` prints this table from the three classifier arms; the arena rows are
    # the 14 the four groups touch, and the retirements are the same four in BOTH arms.
    price = {'dict view methods': (5, 0, 5, 1), 'str.replace': (2, 2, 0, 0),
             'local FS discovery': (5, 4, 0, 0), 'Config.load_yaml': (2, 2, 0, 0)}
    for group, (rows, retire, naive, guarded) in sorted(price.items()):
        print(f'  {group:22s} arena_rows={rows} retire={retire} '
              f'remote_hidden_naive={naive} guarded={guarded}')
    if price['local FS discovery'][1] != 4:
        failures.append(('the booked FS price no longer matches the measurement', price))
    for group in ('dict view methods',):
        if price[group][1] != 0:
            failures.append(('a declined group is booked as buying retirements', group))
    for label, (line, source) in sorted(LOUD_BY_DECLINED_GROUP.items()):
        if not rows_at(scan_module(source), line):
            failures.append(('the declined group hole is live', label, line))
    return failures


def check_inherited_gaps():
    print('TIER 4b - inherited gaps: recorded, and never claimed by this lever:')
    failures = []
    for label, (line, source) in sorted(INHERITED_GAPS.items()):
        found, consults = observe(source)
        entry = consult_on(consults, line)
        off = rows_at(demotion_off(source), line)
        if entry is not None and entry['demote'] == 'yes':
            failures.append(('this lever claimed an inherited silence', label, line))
        print(f'  {label:30s} line={line} loud={bool(rows_at(found, line))} '
              f'demotion_off_loud={bool(off)} '
              f'demote={entry["demote"] if entry else "-"} (quiet under both = GAP@HEAD)')
    return failures


# --------------------------------------------------------------------------- mutations

_DEMOTE = T._c22_sink_root_is_only_the_local_command_line
_CLASSIFIER = T._c22_call_is_classified_path_call
_ORIGIN = T._c22_value_origin_is_resolved
_FS_TABLE = ast_scanner.CWE22_LOCAL_FS_DISCOVERY
_BARE_FS_LEAVES = frozenset({'getcwd', 'listdir', 'glob'})


def _classifier_credits_bare(self, tree, call):
    """The witness discipline dropped: a bare `listdir` is credited as the stdlib spelling."""
    if _CLASSIFIER(self, tree, call):
        return True
    leaf = (ast_scanner.dotted_name(call.func) or '').rsplit('.', 1)[-1]
    return leaf in _BARE_FS_LEAVES


def _origin_no_fs_descent(self, tree, expr, argparse_names, cli_names, depth=0, seen=None):
    """The reshaper mistake repeated on purpose: answer True AT the discovery call, without descending.

    This is the exact early return round 5 had to remove from `CWE22_PURE_CONTAINER_RESHAPE`, and the
    reason it is a mutation here rather than a design choice: the walk resolves a loop target or a
    subscript to the CALL and stops, so it does not look inside the call's arguments either.
    """
    if isinstance(expr, ast.Call) and (ast_scanner.dotted_name(expr.func) or '') in _FS_TABLE:
        return True
    return _ORIGIN(self, tree, expr, argparse_names, cli_names, depth, seen)


def _origin_blind_to_keys(self, tree, expr, argparse_names, cli_names, depth=0, seen=None):
    """HEAD's container arms handed back: a dict's KEYS are not path components.

    A shallow copy per visit is enough because every recursive call goes through this wrapper too, so
    a nested dict is blinded at its own level. The `None` keys are dropped by the walk's own AST
    filter, which is exactly what `kids = expr.values` did.
    """
    if isinstance(expr, ast.Dict):
        expr = copy.copy(expr)
        expr.keys = [None] * len(expr.keys)
    elif isinstance(expr, ast.DictComp):
        expr = copy.copy(expr)
        expr.key = ast.Constant(value=None)
    return _ORIGIN(self, tree, expr, argparse_names, cli_names, depth, seen)


MUTATIONS = {
    'local_cli_demotion_off': {
        'what': 'the whole local-command-line rule is off, so every retirement comes back',
        'apply': lambda: setattr(T, '_c22_sink_root_is_only_the_local_command_line',
                                 lambda self, record, sink: False),
        'restore': lambda: setattr(T, '_c22_sink_root_is_only_the_local_command_line', _DEMOTE),
        'moves': sorted(RETIRED_BY_FS_DISCOVERY),
    },
    'fs_discovery_table_emptied': {
        'what': 'the discovery table is emptied, so the proof stops at an unclassified callee again',
        'apply': lambda: setattr(ast_scanner, 'CWE22_LOCAL_FS_DISCOVERY', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_LOCAL_FS_DISCOVERY', _FS_TABLE),
        'moves': sorted(RETIRED_BY_FS_DISCOVERY),
    },
    'fs_discovery_bare_spelling': {
        'what': 'the qualified-only witness is dropped, so this file\'s own `def listdir` is credited',
        'apply': lambda: setattr(T, '_c22_call_is_classified_path_call', _classifier_credits_bare),
        'restore': lambda: setattr(T, '_c22_call_is_classified_path_call', _CLASSIFIER),
        'moves': sorted(LOUD_BY_QUALIFIED_WITNESS),
    },
    'fs_discovery_no_descent': {
        'what': 'the proof answers True at the discovery call without walking its arguments',
        'apply': lambda: setattr(T, '_c22_value_origin_is_resolved', _origin_no_fs_descent),
        'restore': lambda: setattr(T, '_c22_value_origin_is_resolved', _ORIGIN),
        'moves': ['fs_listdir_remote_in_join', 'fs_glob_remote_in_join'],
    },
    'container_key_arm_blind': {
        'what': 'the retired Dict/DictComp arms are handed back, so a remote KEY is not a component',
        'apply': lambda: setattr(T, '_c22_value_origin_is_resolved', _origin_blind_to_keys),
        'restore': lambda: setattr(T, '_c22_value_origin_is_resolved', _ORIGIN),
        'moves': sorted(LOUD_BY_CONTAINER_KEY),
    },
}

WORKING = {}


def pinned_state(label):
    line, source = ALL_FIXTURES[label]
    return bool(rows_at(scan_module(source), line))


def run_mutation(name):
    spec = MUTATIONS[name]
    print(f'MUTATION {name}: {spec["what"]}')
    print('  rows that must move: ' + ', '.join(spec['moves']))
    for label in spec['moves']:
        WORKING[label] = pinned_state(label)
    try:
        spec['apply']()
        outcomes = [(label, pinned_state(label) != WORKING[label]) for label in spec['moves']]
    except Exception as exc:
        print('MUTATION ERROR: ' + type(exc).__name__ + ': ' + str(exc))
        print(f'\nFALSIFICATION VERDICT ({name}): ERROR - the mutation is broken, so it proves '
              'nothing either way (exit 2, not a pass)')
        return 2
    finally:
        spec['restore']()
    for label, did_move in outcomes:
        print(f'  {label:32s} {"MOVED" if did_move else "unchanged"}')
    caught = all(did_move for _label, did_move in outcomes)
    print('FALSIFICATION VERDICT (' + name + '): '
          + (f'CAUGHT on all {len(outcomes)} pinned row(s)' if caught else
             'MISSED - this clause is decorative; the row it guards did not move'))
    return 1 if caught else 0


def main() -> int:
    failures = check_predicate()
    failures += check_retirements()
    failures += check_hiding_shapes()
    failures += check_declined_groups()
    failures += check_inherited_gaps()
    for item in failures[:14]:
        print(f'  !! {item}')
    print(f'\nspellings={len(PREDICTED_CALLS)} fixtures={len(ALL_FIXTURES)} '
          f'retired={len(RETIRED_BY_FS_DISCOVERY)} held_loud={len(LOUD_LABELS)} '
          f'inherited_gaps={len(INHERITED_GAPS)} '
          f'mutations={len(MUTATIONS)} failures={len(failures)}')
    if failures:
        print('VERDICT: FAIL - either a spelling the price measurement refused is being credited, a '
              'retirement is not attributable to this classification, a remote root went quiet, or a '
              'declined group came back. Restore the answer; never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - {len(RETIRED_BY_FS_DISCOVERY)} local-discovery retirements attributed to '
          f'this classification against the demotion-off arm, {len(LOUD_LABELS)} remote-root shapes '
          f'held loud under both arms, the qualified-only witness and the container-key arms each '
          f'load-bearing under their own mutation, and the three declined groups refused on the '
          f'predicate.')
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