"""Round 7: the booked declines of the mandate's Lever C and Lever D, with the rows they would hide.

Why this gate exists
--------------------
The round-7 mandate asked for two rules that are unsound as written, and the arena was measured before
anything was implemented:

  LEVER C -- "in pure library modules where NO entrypoint exists and NO tainted caller reaches the
             function, suppress fallback synthetic CWE-22 alarms on unproven bare variables."
  LEVER D -- "if a reach-walk finishes deterministically with NO active untrusted root found, do not
             emit the fail-loud fallback. Mark SAFE."

Both mistake an ABSENCE for a PROOF.

  * "No entrypoint in this file" is not "no attacker". A library's caller is the entrypoint, and the
    engine cannot see it from here. `AudioClassificationPipeline.preprocess(self, inputs)` opens
    `inputs` in the `else` branch of a `startswith("http")` test: a remote user of a pipeline service
    chooses that string, and the module has no `__main__`, no CLI and no web route of its own.
    `feature_extraction_utils.py:524` and `image_processing_utils.py:362` are the same story one level
    up -- `is_remote_url(...) -> download_url(...)` feeding `open(resolved_..._file)`.
  * The reach walk is a PRESENCE walk over ANY binding. It resolves NAMES to bindings and never reads
    a callee's body, so "the walk found no root" is not "no root exists". The decisive fixture here is
    `interactive_global_rebound`, the arena's own `add_new_model_like.py` shape: a module that DOES
    guard itself as a program, where `global REPO_PATH; REPO_PATH = Path(self.path_to_repo)` inside a
    method carries an `input()` prompt into a helper's parameter. The walk answers False on
    `open(module_file)` while the row is LOUD, so Lever D would silence a value a person typed at a
    prompt -- and Lever C would not, because this module owns an entrypoint. That separation is what
    makes the two declines independent measurements rather than one argument told twice.

What is shipped instead is the ONE provably-local row of Lever C's ten:
`integration_utils.py:800`, a `for` target over `Path(temp_dir).glob("*")` inside
`with tempfile.TemporaryDirectory() as temp_dir`. That is a positive proof about the value, not an
absence about the module, and it is gated by `cwe22_temp_root_enumeration_probe.py`.

How this gate books a decline
-----------------------------
TIER 1 pins the shapes the two levers would silence and requires every one of them LOUD.
TIER 1b books the shapes that are ALREADY quiet at HEAD. They are not witnesses and are never claimed:
a fixture that is quiet under both arms cannot show that a lever hides anything. Three of the
mandate's own examples land here, which is why the arena was measured before the levers were priced.
TIER 2 is the control: a LOUD program that owns an entrypoint AND whose root the walk really does
find. Neither lever's condition holds on it, so neither mutation may move it -- otherwise the
mutation is a kill switch rather than the rule.
TIER 3 asks the engine's own predicates on every witness, so the gate verifies the PREMISE each lever
would act on (no entrypoint fact for C, a False reach walk for D) instead of asserting it in prose.
TIER 4 implements each lever AS A MUTATION, wired into the engine's own exemption disjunction
(`_is_self_described` for C, `_c22_cleanup_is_temp_teardown` for D, which is the predicate there that
receives the sink call node), and requires the mutation to move exactly the rows that lever names.

The fixtures are in-memory and faithful to the arena lines named above; no corpus file is read, so
this gate runs on a fresh checkout. Every pin is read off the fixture's own AST.

    python benchmark/gates/cwe22_no_entrypoint_decline_probe.py
    python benchmark/gates/cwe22_no_entrypoint_decline_probe.py --mutate=lever_c_no_entrypoint_is_safe
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

T = ast_scanner.TaintTracker


def module(*lines):
    return ''.join(line + '\n' for line in lines)


def pinned(table, spelling):
    """label -> source becomes label -> (the fixture's own sink line, source)."""
    out = {}
    for label, source in table.items():
        lines = [node.lineno for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call)
                 and (ast_scanner.dotted_name(node.func) or '') == spelling]
        if len(lines) != 1:
            raise AssertionError(f'{label}: expected exactly one {spelling}() call, found {lines}')
        out[label] = (lines[0], source)
    return out


# --------------------------------------------------------------------------- TIER 1: what must stay loud
# audio_classification.py:154 and automatic_speech_recognition.py:358. A public pipeline API: the
# caller's string is opened unless it spells a URL, and the module owns no entrypoint at all.
PIPELINE_OPEN_INPUTS = module(
    'import requests',
    'class AudioClassificationPipeline:',
    '    def preprocess(self, inputs):',
    '        if isinstance(inputs, str):',
    '            if inputs.startswith("http://") or inputs.startswith("https://"):',
    '                inputs = requests.get(inputs).content',
    '            else:',
    '                with open(inputs, "rb") as handle:',
    '                    inputs = handle.read()',
    '        return inputs',
)

# feature_extraction_utils.py:524, image_processing_utils.py:362. One branch downloads from a URL the
# caller supplied; the resolved path is opened. No entrypoint, and a remote root one branch away.
LIBRARY_REMOTE_BRANCH = module(
    'import os',
    'import json',
    'CONFIG_NAME = "preprocessor_config.json"',
    'def is_remote_url(path):',
    '    return path.startswith("http")',
    'def download_url(url):',
    '    return url',
    'def cached_file(name, filename, **kwargs):',
    '    return os.path.join(name, filename)',
    'class FeatureExtractionMixin:',
    '    @classmethod',
    '    def get_dict(cls, pretrained_model_name_or_path, **kwargs):',
    '        pretrained_model_name_or_path = str(pretrained_model_name_or_path)',
    '        if os.path.isfile(pretrained_model_name_or_path):',
    '            resolved = pretrained_model_name_or_path',
    '        elif is_remote_url(pretrained_model_name_or_path):',
    '            resolved = download_url(pretrained_model_name_or_path)',
    '        else:',
    '            resolved = cached_file(pretrained_model_name_or_path, CONFIG_NAME)',
    '        with open(resolved, "r", encoding="utf-8") as reader:',
    '            text = reader.read()',
    '        return json.loads(text)',
)

# modeling_utils.py:3957's verb, but not its loudness: `shutil.move` over a caller-supplied folder.
# Quiet because `_c22_open_sink_owes_proven_taint` is True and `_c22_synthetic_param_source_is_founded`
# is False -- and it stays quiet when an in-file caller hands it `request.json()["folder"]` or
# `os.environ["OFFLOAD"]`, so the silence is not about entrypoints at all.
LIBRARY_OFFLOAD_MOVE = module(
    'import os',
    'import shutil',
    'class PreTrainedModel:',
    '    base_model_prefix = "model"',
    '    @classmethod',
    '    def load_offloaded(cls, offload_folder, offload_index, model, model_to_load):',
    '        if offload_index is not None and len(offload_index) > 0:',
    '            if model != model_to_load:',
    '                prefix = cls.base_model_prefix',
    '                for weight_name in offload_index:',
    '                    shutil.move(',
    '                        os.path.join(offload_folder, f"{weight_name}.dat"),',
    '                        os.path.join(offload_folder, f"{prefix}.{weight_name}.dat"),',
    '                    )',
)

# The global-rebind shape with a LITERAL module-level binding. Quiet because the walk resolves
# `CONFIG_PATH` to `Path("config.json")`, a constant the program chose, so the row never existed.
# The witness above anchors the same global to `__file__` instead, which is what the arena does.
REMOTE_GLOBAL_REBOUND = module(
    'import requests',
    'from pathlib import Path',
    'CONFIG_PATH = Path("config.json")',
    'class Loader:',
    '    def __init__(self, url):',
    '        self.url = url',
    '    def run(self):',
    '        global CONFIG_PATH',
    '        CONFIG_PATH = Path(requests.get(self.url).text)',
    'def load():',
    '    with open(CONFIG_PATH, "r", encoding="utf-8") as handle:',
    '        return handle.read()',
)

# add_new_model_like.py:521 / :885 / :927 / :1194, the arena's eleven `no_operator_root_reaches` rows.
# `global REPO_PATH; REPO_PATH = Path(self.path_to_repo)` inside a method, where path_to_repo is the
# CLI's or `get_user_input()`'s, feeding a helper parameter that is opened one hop away. This module
# OWNS a main guard, so Lever C's condition is false here and Lever D's is true: the walk cannot see
# the rebound global, and the fail-loud fallback is the only thing keeping the row.
INTERACTIVE_GLOBAL_REBOUND = module(
    'from pathlib import Path',
    'REPO_PATH = Path(__file__).parent',
    'def get_user_input():',
    '    return input("repo: ")',
    'def duplicate_module(module_file):',
    '    with open(module_file, "r", encoding="utf-8") as handle:',
    '        return handle.read()',
    'class NewModelLike:',
    '    def __init__(self, path_to_repo=None):',
    '        if path_to_repo is None:',
    '            path_to_repo = get_user_input()',
    '        self.path_to_repo = path_to_repo',
    '    def run(self):',
    '        global REPO_PATH',
    '        REPO_PATH = Path(self.path_to_repo)',
    '        duplicate_module(REPO_PATH / "models" / "auto.py")',
    'def main():',
    '    NewModelLike().run()',
    'if __name__ == "__main__":',
    '    main()',
)

LOUD = {}
LOUD.update(pinned({'pipeline_open_inputs': PIPELINE_OPEN_INPUTS}, 'open'))
LOUD.update(pinned({'library_remote_branch': LIBRARY_REMOTE_BRANCH}, 'open'))
LOUD.update(pinned({'interactive_global_rebound': INTERACTIVE_GLOBAL_REBOUND}, 'open'))

# The premise each lever acts on, pinned per witness: (module has an entrypoint fact, walk finds a
# root). C fires where the first is False; D fires where the second is False. TIER 3 measures both.
PREMISE = {
    'pipeline_open_inputs': (False, False),
    'library_remote_branch': (False, False),
    'interactive_global_rebound': (True, False),
}
LEVER_C_ROWS = tuple(sorted(label for label, (entry, _) in PREMISE.items() if not entry))
LEVER_D_ROWS = tuple(sorted(label for label, (_, reach) in PREMISE.items() if not reach))

# --------------------------------------------------------------------------- TIER 2: the control
# A LOUD program that owns an entrypoint AND whose root the walk finds. `input()` is an interactive
# remote root and `requests.get` is a network one, so neither lever's condition holds. If a mutation
# moves this row it is a kill switch, and the decline it "proves" is worthless.
CONTROL_REMOTE_PROGRAM = module(
    'import requests',
    'def main():',
    '    url = input("url: ")',
    '    path = requests.get(url).json()["path"]',
    '    with open(path, "r", encoding="utf-8") as handle:',
    '        return handle.read()',
    'if __name__ == "__main__":',
    '    main()',
)
CONTROL = pinned({'control_remote_program': CONTROL_REMOTE_PROGRAM}, 'open')
CONTROL_PREMISE = {'control_remote_program': (True, True)}

# --------------------------------------------------------------------------- TIER 1b: already quiet at HEAD
# Booked so nobody reads these silences as a lever effect, and so nobody "repairs" the gate by
# claiming them. Each reason below was measured on this fixture at HEAD, not inferred.

# The same arena shape driven from argparse instead of a prompt. Quiet because the local-CLI
# retirement (`_c22_sink_root_is_only_the_local_command_line`) already decided the only root is this
# program's own command line. The prompt-driven witness above is the one that survives that rule,
# because `input()` is not the invocation.
ARENA_CLI_GLOBAL_REBOUND = module(
    'import argparse',
    'from pathlib import Path',
    'REPO_PATH = Path(__file__).parent',
    'def duplicate_module(module_file):',
    '    with open(module_file, "r", encoding="utf-8") as handle:',
    '        return handle.read()',
    'class NewModelLike:',
    '    def __init__(self, path_to_repo=None):',
    '        self.path_to_repo = path_to_repo',
    '    def run(self):',
    '        global REPO_PATH',
    '        REPO_PATH = Path(self.path_to_repo)',
    '        duplicate_module(REPO_PATH / "models" / "auto.py")',
    'def main():',
    '    parser = argparse.ArgumentParser()',
    '    parser.add_argument("--path-to-repo")',
    '    args = parser.parse_args()',
    '    NewModelLike(args.path_to_repo).run()',
    'if __name__ == "__main__":',
    '    main()',
)

# A main-guard program opening its own `--output-dir` in WRITE mode. Quiet twice over: `open(out, "w")`
# produces no CWE-22 sink record at all, and a read-mode version is retired by the local-CLI rule.
CONTROL_CLI_PROGRAM = module(
    'import argparse',
    'import os',
    'def main():',
    '    parser = argparse.ArgumentParser()',
    '    parser.add_argument("--output-dir")',
    '    args = parser.parse_args()',
    '    out = os.path.join(args.output_dir, "eval.txt")',
    '    with open(out, "w") as handle:',
    '        handle.write("x")',
    'if __name__ == "__main__":',
    '    main()',
)

INHERITED_QUIET = {}
INHERITED_QUIET.update(pinned({'library_offload_move': LIBRARY_OFFLOAD_MOVE}, 'shutil.move'))
INHERITED_QUIET.update(pinned({'remote_global_rebound': REMOTE_GLOBAL_REBOUND}, 'open'))
INHERITED_QUIET.update(pinned({'arena_cli_global_rebound': ARENA_CLI_GLOBAL_REBOUND}, 'open'))
INHERITED_QUIET.update(pinned({'control_cli_program': CONTROL_CLI_PROGRAM}, 'open'))


def scan(source, module_name='m.py'):
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files={module_name: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    found = sorted({(int(row['line']), row['message']) for row in rows if row['cwe'] == 'CWE-22'})
    return tracker, found


def scan_module(source, module_name='m.py'):
    return scan(source, module_name)[1]


def rows_at(found, line):
    return [message for row_line, message in found if row_line == line]


def premise_of(tracker, line):
    """(module has an entrypoint fact, the reach walk finds a root) for the CWE-22 record at `line`."""
    record = next((r for r in tracker.sink_records
                   if int(r.lineno) == line
                   and (r.security_node.metadata or {}).get('cwe') == 'CWE-22'), None)
    if record is None:
        raise AssertionError(f'no CWE-22 sink record at line {line}')
    tree = tracker.modules.get(ast_scanner.scope_module(record.scope_id))
    if tree is None:
        raise AssertionError(f'no tree for {record.scope_id}')
    return (bool(tracker._c22_module_entrypoint_facts(tree)),
            bool(tracker._c22_path_sink_reaches_operator(record.node, tree)))


def check_loud():
    failures = []
    print('\nTIER 1  the rows the two levers would silence (every one must be LOUD)')
    for label, (line, source) in sorted(LOUD.items()):
        found = rows_at(scan_module(source), line)
        ok = bool(found)
        levers = ('C' if label in LEVER_C_ROWS else '-') + ('D' if label in LEVER_D_ROWS else '-')
        print(f'  {"OK " if ok else "FAIL"} {label:28s} levers={levers} line={line:3d} rows={len(found)}')
        if not ok:
            failures.append(f'{label}: expected loud, rows={found}')

    print('\nTIER 1b  already quiet at HEAD (booked, never claimed as a lever effect)')
    for label, (line, source) in sorted(INHERITED_QUIET.items()):
        found = rows_at(scan_module(source), line)
        ok = not found
        print(f'  {"OK " if ok else "FAIL"} {label:28s} line={line:3d} rows={len(found)}')
        if not ok:
            failures.append(f'{label}: expected inherited-quiet, rows={found}')

    print('\nTIER 2  the control (LOUD, and neither lever\'s condition holds on it)')
    for label, (line, source) in sorted(CONTROL.items()):
        found = rows_at(scan_module(source), line)
        ok = bool(found)
        print(f'  {"OK " if ok else "FAIL"} {label:28s} levers=-- line={line:3d} rows={len(found)}')
        if not ok:
            failures.append(f'{label}: expected loud, rows={found}')
    return failures


def check_premises():
    failures = []
    print('\nTIER 3  the engine\'s own predicates on every witness (the premise each lever acts on)')
    tables = dict(LOUD)
    tables.update(CONTROL)
    for label, (line, source) in sorted(tables.items()):
        want = PREMISE.get(label) or CONTROL_PREMISE[label]
        tracker, _ = scan(source)
        try:
            got = premise_of(tracker, line)
        except AssertionError as exc:
            failures.append(f'{label}: {exc}')
            print(f'  FAIL {label:28s} {exc}')
            continue
        ok = got == want
        print(f'  {"OK " if ok else "FAIL"} {label:28s} entrypoint={got[0]} walk_finds_root={got[1]} '
              f'(pinned {want[0]}, {want[1]})')
        if not ok:
            failures.append(f'{label}: premise {got} != pinned {want}')
    return failures


# --------------------------------------------------------------------------- TIER 4: the levers as mutations
_SELF_DESCRIBED = T._is_self_described
_TEARDOWN = T._c22_cleanup_is_temp_teardown


def _lever_c_no_entrypoint_is_safe(self, expr, scope_id='', lineno=0, depth=0):
    """Lever C as written: a module with no entrypoint fact has no attacker, so its path is safe."""
    tree = self.modules.get(ast_scanner.scope_module(scope_id))
    if tree is not None and not self._c22_module_entrypoint_facts(tree):
        return True
    return _SELF_DESCRIBED(self, expr, scope_id, lineno, depth)


def _lever_d_no_root_is_safe(self, call_node, path_expr, scope_id='', lineno=0):
    """Lever D as written: the reach walk found no root, so mark the sink SAFE."""
    tree = self.modules.get(ast_scanner.scope_module(scope_id))
    if tree is not None and isinstance(call_node, ast.Call) \
            and not self._c22_path_sink_reaches_operator(call_node, tree):
        return True
    return _TEARDOWN(self, call_node, path_expr, scope_id, lineno)


MUTATIONS = {
    'lever_c_no_entrypoint_is_safe': (
        'no entrypoint in this module is treated as proof that no attacker reaches it',
        '_is_self_described', _lever_c_no_entrypoint_is_safe, LEVER_C_ROWS),
    'lever_d_no_root_is_safe': (
        'a reach walk that found no root is treated as proof that none exists',
        '_c22_cleanup_is_temp_teardown', _lever_d_no_root_is_safe, LEVER_D_ROWS),
}


def run_mutation(name):
    description, attribute, replacement, expected = MUTATIONS[name]
    tables = dict(LOUD)
    tables.update(CONTROL)
    # The baseline is read BEFORE the lever is installed: reading it afterwards compares the mutated
    # engine with itself and reports every mutation as MISSED.
    before = {label: bool(rows_at(scan_module(tables[label][1]), tables[label][0]))
              for label in tables}
    original = getattr(T, attribute)
    setattr(T, attribute, replacement)
    try:
        after = {label: bool(rows_at(scan_module(tables[label][1]), tables[label][0]))
                 for label in tables}
    finally:
        setattr(T, attribute, original)
    moved = sorted(label for label in tables if after[label] != before[label])
    return description, expected, moved, before, after


def check_mutations(only=None):
    failures = []
    print('\nTIER 4  each lever implemented as a mutation (it must hide exactly its own rows)')
    for name in sorted(MUTATIONS):
        if only and name != only:
            continue
        description, expected, moved, before, after = run_mutation(name)
        ok = moved == sorted(expected)
        print(f'  {"CAUGHT" if ok else "MISSED"} {name:32s} moved={moved}')
        if not ok:
            failures.append(f'{name}: expected {sorted(expected)} moved {moved}')
        if not all(before.values()):
            failures.append(f'{name}: baseline was not loud on every fixture: {before}')
        held = sorted(label for label in CONTROL if after[label])
        if len(held) != len(CONTROL):
            failures.append(f'{name}: the control moved, so this is a kill switch: held={held}')
    return failures


def main():
    only = next((a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--mutate=')), None)
    if only and only not in MUTATIONS:
        print(f'unknown mutation {only}; known: {sorted(MUTATIONS)}')
        return 2
    failures = [] if only else check_loud()
    failures += [] if only else check_premises()
    failures += check_mutations(only)
    print(f'\npinned_loud={len(LOUD)} inherited_quiet={len(INHERITED_QUIET)} control={len(CONTROL)} '
          f'lever_c_rows={len(LEVER_C_ROWS)} lever_d_rows={len(LEVER_D_ROWS)} '
          f'mutations={len(MUTATIONS) if not only else 1} failures={len(failures)}')
    for failure in failures:
        print(f'  FAILURE {failure}')
    print('VERDICT: ' + ('PASS' if not failures else 'FAIL'))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())