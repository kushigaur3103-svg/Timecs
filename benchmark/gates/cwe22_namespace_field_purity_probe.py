"""Round 7 Lever B: a written namespace field is still the invocation when every write is pure.

What this gate is for
---------------------
`_c22_is_namespace_root` decides whether `args` holds THIS program's parsed command line in the scope
reading it. Round 5 made that decision carry a field-level refusal: if anybody writes `args.dest`,
the field no longer holds only what the operator typed, so trust in it ends. That refusal is correct
for `args.dest = payload()` and wrong for `args.task_name = args.task_name.lower()`, which hands back
the same characters in a different case.

The cost was measured before anything was implemented (`scratch/_c22_r7_lever_b_why.py`, which mirrors
the proof and prints the DECIDING refusal for each row instead of a bare False). Of the 8 arena rows
labelled `dishonest_namespace`, six were refused by the field-write rule and every one of those six
writes is a pure transform:

  rows  write                                                    file:line of the write
   3    args.task_name = args.task_name.lower()                   run_glue_with_pabee.py:647
                                                                 run_glue_deebert.py:599
                                                                 masked_run_glue.py:854
   1    args.summaries_output_dir = args.documents_dir            run_summarization.py:323
   2    training_args.output_dir = Path(training_args.output_dir) run_clm.py:265, run_mlm.py:271

All six go quiet on the live engine. The remaining two (`finetune_rag.py:704,710`) are refused for a
different reason -- `args` is bound to `args = args or parser.parse_args()`, an `ast.BoolOp` the
candidate loop does not handle -- and they are DECLINED here rather than half-fixed.

The six are charged, not assumed: `scratch/_c22_r7_b_attrib.py` scans each of the eight files solo
under HEAD's committed blob and under the candidate, one process per arm, and prints EVERY CWE-22 row
of the file so a row that merely moved line shows up as churn. Measured: HEAD loud on all eight,
candidate loud on exactly the two BoolOp rows, six retired, zero added, zero moved
(`scratch/_c22_r7_b_head.log`, `scratch/_c22_r7_b_live.log`).

Three fixture-fidelity traps this gate had to climb out of, all of which read as PASS-shaped silence
rather than as an error, and all of which are now commented at the site they bit:

  * `_c22_operator_facts_on` declines to walk a module whose text never spells `__name__`. A fixture
    that calls `main()` bare gets `argparse_names=frozenset()`, and then EVERY tier measures nothing:
    all retirements read as failures and all mutations read as MISSED. Hence `GUARD`.
  * `_c22_operator_facts_build` registers a namespace only from `name = <Call>`. The BoolOp assignment
    does not name `args` at all, so the declined fixture needs a second function that parses into
    `args` -- exactly as the arena file does at finetune_rag.py:814.
  * A sibling copy read in the SAME scope that wrote it is quiet under both arms, because the walk
    resolves the field to the written value and reaches the unmutated sibling on its own. The arena
    row is cross-scope, so the fixture has to be too: `cross_scope_sibling_copy`, which
    `purity_sibling_write_refused` moves.

Attribution is `purity_off`, NOT `demotion_off`. These rows are retired by the open-taint requirement
once the namespace proof can finish, so switching the round-5 demotion off does not bring them back;
measured, demotion_off is 0 on all five. Two further shapes (`constant_write`, `sibling_field_copy`)
are quiet under BOTH arms and are booked in TIER 1b as inherited, because claiming them would inflate
the scorecard with rows this refinement never moved.

Why the proof is co-inductive, and why that is sound
----------------------------------------------------
`args.task_name = args.task_name.lower()` reads the field it writes, so proving the write needs the
field. The base case is the parse itself, which the candidate loop checks separately and which this
refinement does not touch; the step is a CLOSED syntactic whitelist. A field already being judged
answers True, and because EVERY write must pass, a single `args.x = payload()` anywhere in the same
scope refuses the field for every read of it. `purity_any_write` swaps `all` for `any` and is CAUGHT
on exactly that shape, which is what says the conjunction is load-bearing.

The whitelist credits no call the engine cannot see inside. A method must run on the field itself or
on a sibling field of the SAME namespace that also passes, and every argument must be a constant --
so `args.x.replace("a", requests.get(url).text)` is refused on the argument, not on the method name.
`purity_nonconstant_arg` removes that requirement and is CAUGHT. A cast must be one of four spellings
with exactly one positional argument, so `Path(args.x, requests.get(url).text)` is refused on arity.

How to read the tiers
---------------------
TIER 1 is the retirements, attributed against a purity-off arm so a row this refinement did not retire
cannot be booked to it. TIER 1b books the shapes that were already quiet.
TIER 2 is the hiding shapes, each required to be loud under BOTH arms.
TIER 3 is the declined BoolOp binding, asked on the PROOF rather than on a row, because the fixture is
quiet under both arms for reasons of its own and "still loud" would be a false claim.
TIER 4 is one weakening per clause, each with the rows it was measured to move.

Every pin is the fixture's own `open()` line, read off its AST rather than counted by hand: a wrong
pin reads as "no consult" and silently voids the whole measurement, which is a mistake this repo has
already paid for twice.

    python benchmark/gates/cwe22_namespace_field_purity_probe.py
    python benchmark/gates/cwe22_namespace_field_purity_probe.py --mutate=purity_any_write
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


def pinned(table, spelling='open'):
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


HEAD = ('import argparse', 'import os', 'from pathlib import Path', 'import requests')
# The program guard is not decoration. `_c22_operator_facts_on` declines to walk a module whose text
# does not spell `__name__`, so a fixture that calls `main()` bare gets argparse_names=frozenset() and
# every tier below silently measures nothing. Measured: without the guard all 6 retirements read as
# failures and all 6 mutations read as MISSED.
GUARD = ('if __name__ == "__main__":', '    main()')


def cli_main(*body):
    """A program whose only root is its own command line, with `body` inside main()."""
    return module(*HEAD,
                  'def main():',
                  '    parser = argparse.ArgumentParser()',
                  '    parser.add_argument("--task-name")',
                  '    parser.add_argument("--output-dir")',
                  '    parser.add_argument("--documents-dir")',
                  '    args = parser.parse_args()',
                  *('    ' + line for line in body),
                  *GUARD)


# --------------------------------------------------------------------------- TIER 1: the retirements
RETIRED_BY_FIELD_PURITY = pinned({
    'lower_same_field': cli_main(
        'args.task_name = args.task_name.lower()',
        'out = os.path.join(args.output_dir, args.task_name, "eval.txt")',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'path_cast_same_field': cli_main(
        'args.output_dir = Path(args.output_dir)',
        'out = os.path.join(args.output_dir, "eval.txt")',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'strip_constant_args': cli_main(
        'args.task_name = args.task_name.replace("-", "_")',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    # The arena shape: the write is in main(), the read is in a helper that receives the namespace.
    'cross_scope_lower': module(
        *HEAD,
        'def evaluate(args, prefix):',
        '    out = os.path.join(args.output_dir, prefix, "eval.txt")',
        '    with open(out, "w") as handle:',
        '        handle.write("x")',
        'def main():',
        '    parser = argparse.ArgumentParser()',
        '    parser.add_argument("--task-name")',
        '    parser.add_argument("--output-dir")',
        '    args = parser.parse_args()',
        '    args.task_name = args.task_name.lower()',
        '    evaluate(args, args.task_name)',
        *GUARD),
    # bertabs/run_summarization.py:122 -- the write is conditional and in main(), the read is in a
    # helper. The conditional is not decoration either: it is the arena's own shape.
    'cross_scope_sibling_copy': module(
        *HEAD,
        'def evaluate(args):',
        '    out = os.path.join(args.output_dir, "eval.txt")',
        '    with open(out, "w") as handle:',
        '        handle.write("x")',
        'def main():',
        '    parser = argparse.ArgumentParser()',
        '    parser.add_argument("--task-name")',
        '    parser.add_argument("--output-dir")',
        '    parser.add_argument("--documents-dir")',
        '    args = parser.parse_args()',
        '    if not args.output_dir:',
        '        args.output_dir = args.documents_dir',
        '    evaluate(args)',
        *GUARD),
})

# Quiet under BOTH arms, so this lever may not claim them. Measured, not assumed: the open-taint
# requirement already retires these shapes without any field-purity credit, and booking them as
# retirements would inflate the scorecard with rows the refinement never moved.
INHERITED_QUIET = pinned({
    'constant_write': cli_main(
        'args.task_name = "fixed"',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    # The same-scope sibling copy is NOT the arena shape and cannot stand in for it. Reading
    # `args.task_name` in the scope that wrote it resolves to the written value, so the walk reaches
    # the unmutated `args.documents_dir` on its own and the mutated-field refusal never decides
    # anything -- measured quiet under both arms. `cross_scope_sibling_copy` above is the shape that
    # does decide, because a helper reads the field through the parameter proof instead.
    'sibling_field_copy': cli_main(
        'args.task_name = args.documents_dir',
        'out = os.path.join(args.task_name, "eval.txt")',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
})

# --------------------------------------------------------------------------- TIER 2: the hiding shapes
# Every one of these writes something the operator did not type into the field, or writes it through
# a shape the whitelist cannot see inside. Each must stay loud with the refinement ON and OFF.
LOUD_BY_WRITE_PAYLOAD = pinned({
    'write_unclassified_call': cli_main(
        'args.task_name = payload()',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'write_remote_text': cli_main(
        'args.task_name = requests.get("http://evil/x").text',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'replace_remote_argument': cli_main(
        'args.task_name = args.task_name.replace("-", requests.get("http://evil/x").text)',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'replace_keyword_argument': cli_main(
        'args.task_name = args.task_name.replace(old="-", new=requests.get("http://e").text)',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'binop_not_whitelisted': cli_main(
        'args.task_name = args.task_name + payload()',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'other_holder_field': cli_main(
        'other = payload()',
        'args.task_name = other.task_name',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'cast_two_args': cli_main(
        'args.task_name = Path(args.task_name, requests.get("http://evil/x").text)',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'cast_not_in_table': cli_main(
        'args.task_name = Wrapper(args.task_name)',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    'method_not_in_table': cli_main(
        'args.task_name = args.task_name.format(payload())',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    # One pure write and one payload write in the SAME scope: `all` must refuse the field.
    'mixed_writes_same_scope': cli_main(
        'args.task_name = args.task_name.lower()',
        'args.task_name = payload()',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
    # A pure write in main() and a payload write at module scope: both scopes are consulted.
    'module_scope_payload': module(
        *HEAD,
        'def main():',
        '    parser = argparse.ArgumentParser()',
        '    parser.add_argument("--task-name")',
        '    parser.add_argument("--output-dir")',
        '    args = parser.parse_args()',
        '    args.task_name = args.task_name.lower()',
        '    out = os.path.join(args.output_dir, args.task_name)',
        '    with open(out, "w") as handle:',
        '        handle.write("x")',
        'args = None',
        'args.task_name = payload()',
        *GUARD),
    'sibling_field_is_poisoned': cli_main(
        'args.documents_dir = payload()',
        'args.task_name = args.documents_dir',
        'out = os.path.join(args.output_dir, args.task_name)',
        'with open(out, "w") as handle:',
        '    handle.write("x")'),
})

# --------------------------------------------------------------------------- TIER 3: the decline
# `args = args or parser.parse_args()` binds the holder to an ast.BoolOp. The candidate loop handles
# ast.Call and ast.Name only, so it refuses. Crediting it needs the self-referential arm judged
# against the PARAMETER's incoming values rather than against the local binding it is part of, which
# is a different proof from this one. Declined, and booked here so the refusal is on the record.
DECLINED_BOOLUP = pinned({
    'declined_boolop_binding': module(
        *HEAD,
        'import shutil',
        'def main(args=None):',
        '    parser = argparse.ArgumentParser()',
        '    parser.add_argument("--shard-dir")',
        '    parser.add_argument("--output-dir")',
        '    args = args or parser.parse_args()',
        '    shutil.rmtree(args.shard_dir)',
        # `_c22_operator_facts_build` registers a namespace only from `name = <Call>`, so the BoolOp
        # assignment above does not name `args` at all. The arena file establishes it elsewhere
        # (finetune_rag.py:814) and this fixture mirrors that, otherwise the shape is not the one
        # being declined -- it is a file with no namespace, which proves nothing.
        'def other():',
        '    parser = argparse.ArgumentParser()',
        '    args = parser.parse_args()',
        '    return args',
        *GUARD),
}, spelling='shutil.rmtree')


def scan_module(source, module_name='m.py'):
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files={module_name: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(int(row['line']), row['message']) for row in rows if row['cwe'] == 'CWE-22'})


def rows_at(found, line):
    return [message for row_line, message in found if row_line == line]


def demotion_off(source):
    original = T._c22_sink_root_is_only_the_local_command_line
    T._c22_sink_root_is_only_the_local_command_line = lambda self, record, sink: False
    try:
        return scan_module(source)
    finally:
        T._c22_sink_root_is_only_the_local_command_line = original


def purity_off(source):
    """The round-6 behaviour: any write into the field ends trust, whatever it writes."""
    original = T._c22_namespace_field_write_is_pure
    T._c22_namespace_field_write_is_pure = lambda *a, **k: False
    try:
        return scan_module(source)
    finally:
        T._c22_namespace_field_write_is_pure = original


# --------------------------------------------------------------------------- tiers
def check_retirements():
    failures = []
    print('TIER 1  retirements (quiet shipped, loud with the purity refinement reverted)')
    for label, (line, source) in sorted(RETIRED_BY_FIELD_PURITY.items()):
        shipped = rows_at(scan_module(source), line)
        no_purity = rows_at(purity_off(source), line)
        no_demote = rows_at(demotion_off(source), line)
        # `purity_off` is the attribution arm, not `demotion_off`: these rows are retired by the
        # open-taint requirement once the namespace proof can finish, so switching the round-5
        # demotion off does not bring them back. Measured -- demotion_off is 0 on all four.
        ok = not shipped and bool(no_purity)
        print(f'  {"OK " if ok else "FAIL"} {label:26s} line={line:3d} '
              f'shipped={len(shipped)} purity_off={len(no_purity)} '
              f'demotion_off={len(no_demote)}')
        if not ok:
            failures.append(f'{label}: shipped={shipped} purity_off={no_purity}')
    return failures


def check_inherited_quiet():
    failures = []
    print('\nTIER 1b  already quiet at HEAD (this lever must not claim them)')
    for label, (line, source) in sorted(INHERITED_QUIET.items()):
        shipped = rows_at(scan_module(source), line)
        no_purity = rows_at(purity_off(source), line)
        ok = not shipped and not no_purity
        print(f'  {"OK " if ok else "FAIL"} {label:26s} line={line:3d} '
              f'shipped={len(shipped)} purity_off={len(no_purity)}')
        if not ok:
            failures.append(f'{label}: shipped={shipped} purity_off={no_purity}')
    return failures


def check_hiding_shapes():
    failures = []
    print('\nTIER 2  hiding shapes (loud under BOTH arms)')
    for label, (line, source) in sorted(LOUD_BY_WRITE_PAYLOAD.items()):
        shipped = rows_at(scan_module(source), line)
        no_purity = rows_at(purity_off(source), line)
        ok = bool(shipped) and bool(no_purity)
        print(f'  {"OK " if ok else "FAIL"} {label:26s} line={line:3d} '
              f'shipped={len(shipped)} purity_off={len(no_purity)}')
        if not ok:
            failures.append(f'{label}: shipped={shipped} purity_off={no_purity}')
    return failures


def check_declined():
    """The BoolOp binding is refused by the PROOF, asked on the node.

    A row-level check cannot book this decline: the fixture is quiet under both arms because the
    open-taint requirement retires it for its own reasons, so "still loud" would be a false claim.
    The predicate is the thing this lever declines to change, so the predicate is what is asked --
    and it is asked again with purity forced True, which is what proves no amount of field-purity
    credit can retire a holder bound to `args or parser.parse_args()`.
    """
    failures = []
    print('\nTIER 3  declined BoolOp binding (asked on the proof, not on a row)')
    for label, (line, source) in sorted(DECLINED_BOOLUP.items()):
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = T(files={'m.py': source}, max_workers=1)
            tracker.analyze()
        tree = next(iter(tracker.modules.values()))
        _guarded, argparse_names = tracker._c22_operator_facts_on(tree)
        target = next((n for n in ast.walk(tree)
                       if isinstance(n, ast.Attribute)
                       and (ast_scanner.dotted_name(n) or '') == 'args.shard_dir'), None)
        if target is None or 'args' not in argparse_names:
            failures.append(f'{label}: fixture does not establish the shape '
                            f'(target={target is not None}, names={sorted(argparse_names)})')
            continue
        shipped = tracker._c22_is_namespace_root(tree, target, 'args', argparse_names,
                                                 'args.shard_dir')
        original = T._c22_namespace_field_write_is_pure
        T._c22_namespace_field_write_is_pure = lambda *a, **k: True
        try:
            forced = tracker._c22_is_namespace_root(tree, target, 'args', argparse_names,
                                                    'args.shard_dir')
        finally:
            T._c22_namespace_field_write_is_pure = original
        ok = shipped is False and forced is False
        print(f'  {"OK " if ok else "FAIL"} {label:26s} '
              f'namespace_root={shipped} with_purity_forced_true={forced}')
        if not ok:
            failures.append(f'{label}: namespace_root={shipped} forced={forced}')
    return failures


def check_tables():
    failures = []
    print('\nTIER 0  whitelist is closed')
    for name in ('lower', 'upper', 'strip', 'replace'):
        if name not in ast_scanner.CWE22_NAMESPACE_PURE_FIELD_METHODS:
            failures.append(f'method {name} missing from the purity table')
    for name in ('format', 'join', 'encode', 'decode', 'get', 'read'):
        if name in ast_scanner.CWE22_NAMESPACE_PURE_FIELD_METHODS:
            failures.append(f'method {name} must NOT be in the purity table')
    for name in ('Path', 'str'):
        if name not in ast_scanner.CWE22_NAMESPACE_PURE_FIELD_CASTS:
            failures.append(f'cast {name} missing from the purity table')
    for name in ('Wrapper', 'open', 'eval', 'loads'):
        if name in ast_scanner.CWE22_NAMESPACE_PURE_FIELD_CASTS:
            failures.append(f'cast {name} must NOT be in the purity table')
    print(f'  methods={len(ast_scanner.CWE22_NAMESPACE_PURE_FIELD_METHODS)} '
          f'casts={len(ast_scanner.CWE22_NAMESPACE_PURE_FIELD_CASTS)} '
          f'failures={len(failures)}')
    return failures


# --------------------------------------------------------------------------- TIER 4: mutations
def _purity_blanket_true(self, tree, owner, field, argparse_names, pending=frozenset()):
    return True


def _purity_any_write(self, tree, owner, field, argparse_names, pending=frozenset()):
    holder = field.split('.', 1)[0]
    if holder not in argparse_names:
        return False
    key = (owner, field)
    if key in pending:
        return True
    writes = self._c22_scope_binds(tree)[0]
    values = list(writes.get(key) or []) + list(writes.get(('', field)) or [])
    if not values:
        return False
    pending = pending | {key, ('', field)}
    return any(self._c22_namespace_write_value_is_pure(tree, owner, holder, value,
                                                       argparse_names, pending)
               for value in values)


def _value_nonconstant_arg(self, tree, owner, holder, expr, argparse_names, pending):
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) \
            and expr.func.attr in ast_scanner.CWE22_NAMESPACE_PURE_FIELD_METHODS:
        return _VALUE(self, tree, owner, holder, expr.func.value, argparse_names, pending)
    return _VALUE(self, tree, owner, holder, expr, argparse_names, pending)


def _value_other_holder(self, tree, owner, holder, expr, argparse_names, pending):
    if isinstance(expr, ast.Attribute):
        ref = ast_scanner.dotted_name(expr) or ''
        mutated = self._c22_scope_binds(tree)[1]
        if (owner, ref) not in mutated and ('', ref) not in mutated:
            return True
        return self._c22_namespace_field_write_is_pure(tree, owner, ref, argparse_names, pending)
    return _VALUE(self, tree, owner, holder, expr, argparse_names, pending)


def _value_sibling_write_refused(self, tree, owner, holder, expr, argparse_names, pending):
    """An unmutated sibling field must prove its own writes instead of counting as operator text."""
    if isinstance(expr, ast.Attribute):
        if (ast_scanner.dotted_name(expr.value) or '') != holder:
            return False
        return self._c22_namespace_field_write_is_pure(
            tree, owner, ast_scanner.dotted_name(expr) or '', argparse_names, pending)
    return _VALUE(self, tree, owner, holder, expr, argparse_names, pending)


def _value_module_scope_ignored(self, tree, owner, field, argparse_names, pending=frozenset()):
    holder = field.split('.', 1)[0]
    if holder not in argparse_names:
        return False
    key = (owner, field)
    if key in pending:
        return True
    writes = self._c22_scope_binds(tree)[0]
    values = list(writes.get(key) or [])
    if not values:
        return False
    pending = pending | {key}
    return all(self._c22_namespace_write_value_is_pure(tree, owner, holder, value,
                                                       argparse_names, pending)
               for value in values)


_PURITY = T._c22_namespace_field_write_is_pure
_VALUE = T._c22_namespace_write_value_is_pure

MUTATIONS = {
    'purity_blanket_true': (
        'every written field keeps trust, whatever was written',
        '_c22_namespace_field_write_is_pure', _purity_blanket_true,
        ('write_unclassified_call', 'write_remote_text', 'binop_not_whitelisted')),
    'purity_any_write': (
        'one pure write is enough, instead of every write',
        '_c22_namespace_field_write_is_pure', _purity_any_write,
        ('mixed_writes_same_scope',)),
    'purity_nonconstant_arg': (
        'a whitelisted method may take a non-constant argument',
        '_c22_namespace_write_value_is_pure', _value_nonconstant_arg,
        ('replace_remote_argument', 'replace_keyword_argument')),
    'purity_other_holder': (
        'a field of ANY holder counts, not only the same namespace',
        '_c22_namespace_write_value_is_pure', _value_other_holder,
        ('other_holder_field',)),
    'purity_sibling_write_refused': (
        'a copy of an unmutated sibling field no longer counts as operator text',
        '_c22_namespace_write_value_is_pure', _value_sibling_write_refused,
        ('cross_scope_sibling_copy',)),
    'purity_module_scope_ignored': (
        'only the owning scope is consulted, not module scope',
        '_c22_namespace_field_write_is_pure', _value_module_scope_ignored,
        ('module_scope_payload',)),
    'purity_off': (
        'the whole refinement reverted to the round-6 blanket refusal',
        '_c22_namespace_field_write_is_pure', lambda *a, **k: False,
        tuple(sorted(RETIRED_BY_FIELD_PURITY))),
}


def run_mutation(name):
    description, attribute, replacement, expected = MUTATIONS[name]
    tables = dict(RETIRED_BY_FIELD_PURITY)
    tables.update(LOUD_BY_WRITE_PAYLOAD)
    # The baseline is read BEFORE the weakening is installed. Reading it afterwards would compare the
    # mutated engine with itself and report every mutation as MISSED.
    before = {label: bool(rows_at(scan_module(tables[label][1]), tables[label][0]))
              for label in expected}
    original = getattr(T, attribute)
    setattr(T, attribute, replacement)
    try:
        moved = [label for label in expected
                 if bool(rows_at(scan_module(tables[label][1]), tables[label][0])) != before[label]]
    finally:
        setattr(T, attribute, original)
    caught = sorted(moved) == sorted(expected)
    print(f'  {"CAUGHT" if caught else "MISSED"} {name:28s} moved={sorted(moved)}')
    if not caught:
        print(f'         expected={sorted(expected)}')
    return caught, description


def main() -> int:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    only = next((a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--mutate=')), None)
    if only:
        if only not in MUTATIONS:
            print(f'unknown mutation {only!r}; have {sorted(MUTATIONS)}')
            return 2
        caught, description = run_mutation(only)
        print(f'\n{only}: {description}')
        print('VERDICT:', 'PASS - mutation caught' if caught else 'FAIL - mutation survived')
        return 0 if caught else 1

    failures = []
    failures += check_tables()
    failures += check_retirements()
    failures += check_inherited_quiet()
    failures += check_hiding_shapes()
    failures += check_declined()

    print('\nTIER 4  mutations (one weakening per clause)')
    missed = []
    for name in MUTATIONS:
        caught, _description = run_mutation(name)
        if not caught:
            missed.append(name)
    failures += [f'mutation survived: {name}' for name in missed]

    print(f'\nretired={len(RETIRED_BY_FIELD_PURITY)} '
          f'held_loud={len(LOUD_BY_WRITE_PAYLOAD)} inherited_quiet={len(INHERITED_QUIET)} '
          f'declined={len(DECLINED_BOOLUP)} '
          f'mutations={len(MUTATIONS)} failures={len(failures)}')
    for failure in failures:
        print('  FAILURE:', failure)
    print('VERDICT:', 'PASS' if not failures else 'FAIL')
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())