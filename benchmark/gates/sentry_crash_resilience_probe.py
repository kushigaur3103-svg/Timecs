"""Crash-resilience lock for the provenance helpers added in `c7f4b75..3a0e7d8`.

    python benchmark/gates/sentry_crash_resilience_probe.py
    python benchmark/gates/sentry_crash_resilience_probe.py --dump
    python benchmark/gates/sentry_crash_resilience_probe.py --mutation <name>

WHY THIS GATE EXISTS
`cli.py scan target_arena/ --scope all --format json --sarif benchmark_results/tcs.sarif` walked
clean on `c7f4b75` (exit 1, 997 findings) and ABORTED on `3a0e7d8` with `Process exit: 2` and 0
findings. Reproduced locally, without Sentry: `_c862_scope_is_http_entrypoint` read
`dotted_name(base).rsplit(".", 1)[-1]`, and `dotted_name` is declared `-> Optional[str]`. Sentry
writes `class Future(Generic[T])` and `@REGISTRY["route"]`, whose `Subscript`/`Starred`/`Call` nodes
it cannot name, so `None.rsplit` raised `AttributeError: 'NoneType' object has no attribute
'rsplit'` inside `_collect_batch3a_structural_findings`. The exception escaped the scan,
`_scan_failure` wrote an empty artefact, and every finding already earned was thrown away. A crash
is not a conservative answer -- it costs 100% of recall and looks like a clean tree.

WHAT IS LOCKED
TIER 1  every helper the range added, called DIRECTLY on the malformed and unusual AST shapes the
        brief names -- `usedforsecurity=` with empty `args`, `{**unpack}` (a `None` entry in
        `ast.Dict.keys`), non-`Constant` and empty dicts, `bytes` and invalid regex patterns, chained
        `Compare` with two comparators, `def g(a="x", /)`, a `defaults` list LONGER than the parameter
        list, a default with no parameter at all, unnameable bases and decorators, non-AST inputs.
        Each must ANSWER, with its documented type, without raising.
TIER 2  the pre-fix expression is replayed on the very nodes TIER 1 hands over and MUST raise. That is
        what separates a load-bearing battery from decoration: fixtures that never crashed would pass
        forever while the bug stayed live.
TIER 3  the shipped verdicts, read out of one shared scan (`--dump` reprints them): `Generic[T]`
        beside `APIView` still charges CWE-862 -- an unnameable item skips ONE loop iteration, it does
        not abandon the walk -- while `class Plain(Generic[T])` with no marker stays quiet, and every
        other blessed and quiet line holds.
TIER 4  the user-facing contract itself: `cli.main([...])` over a temp tree that includes nested
        `testutils/` and `fixtures/` directories exits 1, NEVER 2, prints no `[FATAL]` line, and leaves
        a SARIF whose `executionSuccessful` is true with results in it.
TIER 5  source laws, so the fix cannot rot into a local patch: no unguarded `dotted_name(...)`
        dereference anywhere in `ast_scanner.py` (that one regex IS the defect class); both CWE-862
        name reads carry the `or ""` fold; the sre walkers are reachable only through
        `_is_redos_vulnerable_pattern`, which is where the blanket `except Exception` lives; the PEP
        570 alignment refuses a negative offset; the collector memo is only ever rebound by the pair
        of functions that bracket the collector phase (it is unbounded and per-node, and the laptop has
        600 MB, so its lifetime is a memory law, not a style choice); and no rule suppresses by path --
        the one basename read in the guard family is the CWE-208 KEEP_LOUD pin, whose only answer is
        to force a row loud, which is the opposite of a blacklist.
TIER 6  budgets -- a crash lock that is slow or heavy never gets run.

Falsification: `--mutation <name>` changes what the shipped pipeline reads -- the name a node resolves
to, the base list a walk is handed, a method bound on `TaintTracker` -- and exits 1 when the mutation
fails to move the row or the guard it claims. No mutation recompiles engine source: `aa_parity` scans
this directory, so a live `exec(compile(text))` in a gate is a CWE-95 row the engine is right to
report, and the frozen 425-key parity baseline is not this gate's to move.
"""
from __future__ import annotations

import ast
import collections
import contextlib
import inspect
import io
import json
import os
import re
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402

TT = ast_scanner.TaintTracker
START = time.time()
BUDGET_SECONDS = 2.0
BUDGET_RSS_MB = 60.0
MARKERS = ("token", "secret", "signature", "hmac", "api_key", "auth_token")
SCANNER_PATH = os.path.join(ROOT, 'ast_scanner.py')

# ─── fixtures: the shapes that killed the scan, plus the neighbours they came with ─────────────
GEN_VIEW = '''from typing import Generic, TypeVar
from rest_framework.views import APIView
T = TypeVar("T")
class Future(Generic[T], APIView):
    def get(self, request):
        return Group.objects.get(id=request.GET["id"])
class Plain(Generic[T]):
    def build(self):
        return Group.objects.get(id=1)
class Later(Generic[T], APIView):
    def post(self, form):
        return Group.objects.get(id=1)
'''
SUB_DECORATOR = '''REGISTRY = {}
@REGISTRY["route"]
def handler(user_input):
    import subprocess
    subprocess.run("tail -f " + user_input, shell=True)
'''
STAR_BASE = '''bases = ()
class Mixin(*bases):
    permission_classes = []
    def run(self, request):
        import os
        return os.system("rm -rf " + request.path)
'''
HASHLIB_KW = '''import hashlib
def etag(body):
    return hashlib.md5(body, usedforsecurity=False).hexdigest()
def sig(body, api_key):
    return hashlib.md5(api_key + body).hexdigest()
def flag_only(data):
    return hashlib.new("md5", usedforsecurity=False)
def no_args():
    return hashlib.md5(usedforsecurity=False)
'''
BYTES_REGEX = '''import re
BYTE = re.compile(rb"(?P<x>a+)+")
BROKEN = re.compile(r"(?P")
def m(s):
    return re.match(r"(a+)+b", s)
def n(s):
    return re.fullmatch(rb"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", s)
'''
PEP570 = '''def f(a, /, b=1, *, c=2):
    return open(a).read()
def g(a="x", /):
    return open(a).read()
def h(self, path, /, *, mode="r"):
    return open(path, mode).read()
def kwonly(*, a=1):
    return a
def star(a, *rest, b=2):
    return a
'''
DRF_ENV = '''from rest_framework.response import Response
def h(request, exc):
    err = {"status": 500}
    return Response({**err, "detail": str(exc)})
def h2(request, exc):
    return Response({**{}, "detail": str(exc)})
def h3(request, exc):
    return Response({"traceback": str(exc)})
'''
YAML_LOADER = '''import yaml
class _Safe(yaml.SafeLoader):
    pass
class _Starred(*bases):
    pass
def a(body):
    return yaml.load(body, Loader=_Safe)
def b(body):
    return yaml.load(body, Loader=yaml.UnsafeLoader)
'''
TIMING = '''def check(api_key, incoming_api_key, user_api_key_dict, d, tok_a, tokenizer, text):
    if api_key == incoming_api_key:
        return True
    if user_api_key_dict.user_role != "PROXY_ADMIN":
        return False
    if d[a:b] == api_key:
        return True
    if tok_a == tokenizer.encode(text):
        return True
    return api_key == None
'''
RANDOM_CHAIN = '''import random
rate = 0.5
def keep():
    return 0.1 < random.random() < 0.9
def one():
    return random.random() < rate
def bare():
    return random.random()
def tied():
    return random.random() == random.random() == 1
class Widget:
    def choices(self, k):
        return random.choices([1, 2, 3], k=k)
'''
NESTED_DIR = '''import random
REGISTRY = {}
@REGISTRY["route"]
def view_marker_after_unnameable():
    return Group.objects.get(id=1)
def plain_view():
    return random.random()
'''
FIXTURES = {
    'gen_view.py': GEN_VIEW,
    'sub_decorator.py': SUB_DECORATOR,
    'star_base.py': STAR_BASE,
    'hashlib_kw.py': HASHLIB_KW,
    'bytes_regex.py': BYTES_REGEX,
    'pep570.py': PEP570,
    'drf_env.py': DRF_ENV,
    'yaml_loader.py': YAML_LOADER,
    'timing.py': TIMING,
    'random_chain.py': RANDOM_CHAIN,
    'testutils/nested.py': NESTED_DIR,
}

# Read out of the shared scan (`--dump` prints it) and frozen. `loud` must be reported, `quiet` must
# not: the quiet CWE-862 lines are exactly what a widened fold would light up, and the loud ones are
# what an abandon-the-loop "fix" would drop.
BLESSED = {
    'gen_view.py': {'loud': {'CWE-862': [5, 11]}, 'quiet': {'CWE-862': [8]}},
    'sub_decorator.py': {'loud': {'CWE-78': [5]}, 'quiet': {'CWE-862': [3]}},
    'star_base.py': {'loud': {'CWE-78': [6]}, 'quiet': {'CWE-862': [5]}},
    'hashlib_kw.py': {'loud': {'CWE-328': [5]}, 'quiet': {'CWE-328': [3, 7, 9]}},
    'bytes_regex.py': {'loud': {'CWE-1333': [5]}, 'quiet': {'CWE-1333': [2, 3, 7]}},
    'pep570.py': {'loud': {}, 'quiet': {'CWE-22': [2, 4, 6]}},
    'drf_env.py': {'loud': {}, 'quiet': {'CWE-209': [5, 7]}},
    'yaml_loader.py': {'loud': {'CWE-502': [9]}, 'quiet': {'CWE-502': [7]}},
    'timing.py': {'loud': {'CWE-208': [2, 6, 8]}, 'quiet': {'CWE-208': [4]}},
    'random_chain.py': {'loud': {'CWE-338': [4, 8, 10, 13]}, 'quiet': {'CWE-338': [6]}},
    'testutils/nested.py': {'loud': {}, 'quiet': {'CWE-862': [4], 'CWE-338': [7]}},
}


def scan_all(files):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        tracker = TT(files=dict(files), max_workers=1)
        _nodes, _rules, edges = tracker.analyze()
        return tracker, cli._findings_for(tracker, edges)


SHARED, SHARED_ROWS = scan_all(FIXTURES)
# Parent links, exactly as the engine's parse sets them (ast_scanner.py:5718-5720). Without them the
# scope walk stops at `func is None` and never reaches the decorator/base loops this gate is about.
PARSED = {}
for _name, _source in FIXTURES.items():
    _tree = ast.parse(_source)
    for _node in ast.walk(_tree):
        for _child in ast.iter_child_nodes(_node):
            _child.parent = _node
    PARSED[_name] = _tree


def basenames(rows):
    out = collections.defaultdict(lambda: collections.defaultdict(set))
    for row in rows:
        out[os.path.basename(str(row['file']).replace('\\', '/'))][row['cwe']].add(int(row['line']))
    return out


def calls(tree):
    return sorted([n for n in ast.walk(tree) if isinstance(n, ast.Call)],
                  key=lambda c: (c.lineno, c.col_offset))


def classes(tree):
    return [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]


def _brief(args):
    text = repr(args[0]) if len(args) == 1 else repr(args)
    return text if len(text) <= 44 else text[:41] + '...'


# ─── TIER 1: the helpers answer, they do not raise ────────────────────────────────────────────
def battery():
    """(label, callable, args, allowed result types) over every node shape the brief names."""
    eng = SHARED
    out = []
    for name in ('gen_view.py', 'sub_decorator.py', 'star_base.py', 'testutils/nested.py'):
        for call in calls(PARSED[name]):
            out.append(('c862_entrypoint', eng._c862_scope_is_http_entrypoint, (call,), (bool,)))
            out.append(('c862_guarded_or_off_http', eng._c862_scope_is_guarded_or_off_http,
                        (call, name), (bool,)))
    for tree in PARSED.values():
        for cls in classes(tree):
            out.append(('c862_is_background_task', eng._c862_is_background_task, (cls, 'm'),
                        (bool,)))
            out.append(('c862_orm_scope', eng._class_is_orm_scope, (cls, 'm'), (bool,)))
            out.append(('c862_permission_guard', eng._class_declares_permission_guard, (cls, 'm'),
                        (bool,)))
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            out.append(('c862_is_background_task_fn', eng._c862_is_background_task, (fn, 'm'),
                        (bool,)))
    for junk in (None, '', 7, ast.Constant(1)):
        out.append(('c862_helpers_non_ast', eng._c862_scope_is_http_entrypoint, (junk,), (bool,)))
    payloads = [n for n in ast.walk(PARSED['drf_env.py']) if isinstance(n, ast.Dict)]
    payloads += [ast.Dict(keys=[], values=[]),
                 ast.Dict(keys=[None], values=[ast.Constant(1)]),
                 ast.Dict(keys=[ast.Constant(1)], values=[]),
                 ast.Dict(keys=[None, ast.Constant(1)], values=[None, None])]
    for payload in payloads:
        out.append(('c209_envelope_None_key', eng._c209_structured_error_envelope_only,
                    (payload,), (bool,)))
        out.append(('c209_members', eng._c209_members, (payload,), (list,)))
    for junk in (None, '', 7, [1, 2], ast.Constant(1)):
        out.append(('c209_envelope_non_dict', eng._c209_structured_error_envelope_only, (junk,),
                    (bool,)))
        out.append(('c209_members_non_dict', eng._c209_members, (junk,), (list,)))
    for call in calls(PARSED['hashlib_kw.py']):
        out.append(('c328_hash_input', eng._cwe328_hash_input_is_non_credential,
                    (call, '', call.lineno), (bool,)))
        out.append(('c327_exempt', eng._is_exempt_cwe327, (call, '', call.lineno), (bool,)))
    for not_a_call in (ast.Name(id='x'), ast.Constant(1), ast.Dict(keys=[], values=[]), None):
        out.append(('c327_exempt_non_call', eng._is_exempt_cwe327, (not_a_call, '', 1), (bool,)))
        out.append(('c328_hash_input_non_call', eng._cwe328_hash_input_is_non_credential,
                    (not_a_call, '', 1), (bool,)))
    for call in calls(PARSED['random_chain.py']):
        out.append(('c338_probability_draw', eng._cwe338_probability_threshold_draw, (call, ''),
                    (bool,)))
        out.append(('c338_display_only', eng._cwe338_display_only_draw, (call, ''), (bool,)))
    first_draw = calls(PARSED['random_chain.py'])[0]
    for receiver in ('', 'rng', 'self.sub_model', 'scipy.stats.norm', 'random', '/', 'a/b'):
        out.append(('c338_foreign_receiver', eng._cwe338_receiver_is_foreign_object,
                    (receiver, receiver, first_draw, ''), (bool,)))
    for node in [n for n in ast.walk(PARSED['timing.py']) if isinstance(n, ast.Compare)]:
        out.append(('c208_operand_provenance', eng._c208_compared_operand_is_secret_named,
                    (node, MARKERS, 'timing.py'), (bool,)))
    values = [n for n in ast.walk(PARSED['timing.py'])
              if isinstance(n, (ast.Attribute, ast.Subscript, ast.Call, ast.Name, ast.Constant,
                                ast.List, ast.Tuple))]
    values += [None, ast.Slice(lower=ast.Constant(1), upper=None, step=None),
               ast.Dict(keys=[None], values=[ast.Constant(1)]),
               ast.Starred(value=ast.Name(id='x'), ctx=ast.Load()),
               ast.DictComp(key=ast.Name(id='a'), value=ast.Name(id='b'),
                            generators=[ast.comprehension(target=ast.Name(id='a'),
                                                           iter=ast.Name(id='b'), ifs=[],
                                                           is_async=0)])]
    for value in values:
        out.append(('c208_value_naming', eng._c208_value_is_secret_named, (value, MARKERS),
                    (bool,)))
    for name in ('_Safe', '_Starred', 'Missing', '', 'yaml', 'object', 'None', 'Loader'):
        out.append(('c502_local_loader', eng._c502_local_safe_loader_class, (name, 'm'), (bool,)))
    out.append(('c502_missing_module', eng._c502_local_safe_loader_class,
                ('_Safe', 'no_such_module'), (bool,)))
    out.append(('c502_non_module', eng._c502_local_safe_loader_class, ('_Safe', None), (bool,)))
    for tree_name in ('pep570.py', 'gen_view.py', 'hashlib_kw.py', 'random_chain.py'):
        out.append(('c22_param_proofs', eng._c22_param_proofs, (PARSED[tree_name],), (dict,)))
    broken = ast.parse('def ok(a):\n    return a\n').body[0]
    broken.args.posonlyargs = [ast.arg(arg='a', annotation=None)]
    broken.args.args = []
    broken.args.defaults = [ast.Constant(1), ast.Constant(2), ast.Constant(3)]
    out.append(('c22_defaults_longer_than_params', eng._c22_param_proofs,
                (ast.Module(body=[broken], type_ignores=[]),), (dict,)))
    empty = ast.parse('def ok():\n    return 1\n').body[0]
    empty.args.posonlyargs = []
    empty.args.defaults = [ast.Constant(1)]
    out.append(('c22_default_without_param', eng._c22_param_proofs,
                (ast.Module(body=[empty], type_ignores=[]),), (dict,)))
    for pattern in (b'(?P<x>a+)+', '', None, 7, '(?P', '(a+)+b', '[', '((((a+)+)+)+',
                    '(?P<n>' + 'a' * 120 + ')+)*', 'a{0,}', rb'(?P<x>a+)+'):
        out.append(('redos_entry_never_raises', ast_scanner._is_redos_vulnerable_pattern,
                    (pattern,), (bool,)))
    for tokens in ([], [(None, None)], [({'a'},)], [('x',)], 'not-a-tree', [(1, 2, 3)],
                   [(), (3, 'x')]):
        out.append(('regex_branch_literals_malformed', ast_scanner._regex_branch_literals,
                    (tokens,), (type(None),)))
    return out


def check_battery():
    failures = []
    seen = collections.Counter()
    raised = []
    for label, fn, args, expect in battery():
        seen[label] += 1
        try:
            answer = fn(*args)
        except Exception as exc:
            raised.append('%s(%s) raised %s: %s' % (label, _brief(args), type(exc).__name__, exc))
            continue
        if not isinstance(answer, expect):
            failures.append('%s answered %s, expected %s'
                            % (label, type(answer).__name__,
                               '/'.join(t.__name__ for t in expect)))
    if raised:
        failures.append('%d helper call(s) aborted the scan instead of refusing: %s'
                        % (len(raised), ' | '.join(raised[:5])))
    if len(seen) < 24:
        failures.append('battery covers %d predicate groups; the range added 16 helpers and every '
                        'one of them must be asked here' % len(seen))
    return failures, seen, len(raised)


# ─── TIER 2: the pre-fix expression must still be able to kill a scan ─────────────────────────
def check_prefix_is_live():
    raised = 0
    for source in (GEN_VIEW, STAR_BASE, SUB_DECORATOR):
        tree = ast.parse(source)
        for cls in classes(tree):
            for base in cls.bases:
                try:
                    ast_scanner.dotted_name(base).rsplit('.', 1)[-1]
                except AttributeError:
                    raised += 1
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for dec in fn.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                try:
                    ast_scanner.dotted_name(target).rsplit('.', 1)[-1]
                except AttributeError:
                    raised += 1
    if raised < 3:
        return (['the pre-fix expression raised %d times (<3): the fixtures no longer contain an '
                 'unnameable base or decorator, so the guard is untested and this gate is '
                 'decoration' % raised], raised)
    return [], raised


# ─── TIER 3: shipped verdicts ────────────────────────────────────────────────────────────────
def check_blessed_rows(rows=None):
    failures = []
    by = basenames(rows if rows is not None else SHARED_ROWS)
    for module, spec in BLESSED.items():
        got = by.get(module, {})
        for cwe, lines in spec['loud'].items():
            missing = [n for n in lines if n not in got.get(cwe, set())]
            if missing:
                failures.append('%s lost %s on line %s (has %s) -- an unnameable item must skip ONE '
                                'loop iteration, not abandon the walk: bailing out is the same abort '
                                'wearing a try/except' % (module, cwe, missing,
                                                          sorted(got.get(cwe, set()))))
        for cwe, lines in spec['quiet'].items():
            extra = [n for n in lines if n in got.get(cwe, set())]
            if extra:
                failures.append('%s grew %s on line %s -- an unnameable node answered as though it '
                                'were a marker, which widens the rule' % (module, cwe, extra))
    return failures, by


# ─── TIER 4: the CLI contract, exit code and artefacts ────────────────────────────────────────
def check_cli_contract():
    failures = []
    workdir = tempfile.mkdtemp(prefix='tcs_crash_gate_')
    try:
        tree = os.path.join(workdir, 'arena')
        os.makedirs(os.path.join(tree, 'testutils', 'fixtures'), exist_ok=True)
        for name, source in FIXTURES.items():
            path = os.path.join(tree, name.replace('/', os.sep))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            io.open(path, 'w', encoding='utf-8').write(source)
        sarif = os.path.join(workdir, 'tcs.sarif')
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = cli.main(['scan', tree, '--scope', 'all', '--format', 'json',
                             '--sarif', sarif])
        text = buf.getvalue()
        facts = {'exit': code, 'sarif_results': 0, 'note': ''}
        if code == 2:
            failures.append('cli.main returned 2 -- the exact abort the brief is about. Tail: %s'
                            % [ln for ln in text.splitlines() if ln.strip()][-3:])
        if '[FATAL]' in text:
            failures.append('report carries a [FATAL] line: %s' % text.strip().splitlines()[:2])
        if not os.path.exists(sarif):
            failures.append('no SARIF written -- a crashed scan leaves CI an uploader and nothing '
                            'to upload')
        else:
            doc = json.load(io.open(sarif, encoding='utf-8'))
            run = (doc.get('runs') or [{}])[0]
            results = run.get('results') or []
            facts['sarif_results'] = len(results)
            if run.get('properties', {}).get('executionSuccessful') is False:
                failures.append('SARIF says executionSuccessful=false -- the abort profile')
            if not results:
                failures.append('SARIF has zero results over a tree that carries findings')
        note = next((ln for ln in text.splitlines() if 'Held back' in ln), '')
        facts['note'] = note
        if 'testutils/' not in note or 'fixtures/' not in note:
            failures.append('the held-back note stopped naming testutils/ and fixtures/, so the '
                            'prune list added in f0b9400 is no longer exercised here: %r' % note)
        return failures, facts
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)


# ─── TIER 5: source laws ─────────────────────────────────────────────────────────────────────
REGEX_HELPERS = ('_regex_first_chars', '_regex_trailing_separator', '_regex_branch_literals',
                 '_regex_catastrophic_backtracking')
HELPERS_THAT_MUST_EXIST = (
    '_c862_scope_is_http_entrypoint', '_c862_scope_is_guarded_or_off_http',
    '_c862_is_background_task', '_class_is_orm_scope', '_class_declares_permission_guard',
    '_c209_structured_error_envelope_only', '_c209_members', '_is_exempt_cwe327',
    '_cwe328_hash_input_is_non_credential', '_cwe338_probability_threshold_draw',
    '_cwe338_display_only_draw', '_cwe338_receiver_is_foreign_object',
    '_c208_compared_operand_is_secret_named', '_c208_value_is_secret_named',
    '_c502_local_safe_loader_class', '_c22_param_proofs',
)


def check_laws(src):
    failures = []
    lines = src.splitlines()
    # (a) the whole defect class, in one regex: an unguarded dereference of an Optional[str].
    bad = re.findall(r'dotted_name\([^()\n]*\)\s*\.\s*(?:rsplit|split|lower|endswith|startswith)',
                     src)
    if bad:
        failures.append('unguarded dotted_name(...) dereference x%d: %s -- the result is '
                        'Optional[str] and `None.rsplit` aborts the scan' % (len(bad), bad[:3]))
    # (b) the crash site itself carries the fold, on the same line as the dereference. One line
    # reads a decorator's leaf, the other a class base's; losing either re-opens exit 2.
    entry_src = inspect.getsource(TT._c862_scope_is_http_entrypoint)
    folds = len(re.findall(r'\(dotted_name\([^)]*\)\s+or\s+""\)', entry_src))
    if folds < 2:
        failures.append('_c862_scope_is_http_entrypoint folds `or ""` %d times (<2): one of the two '
                        'leaf reads -- the decorator at ast_scanner.py:13805 or the class base at '
                        ':13811 -- lost its guard' % folds)
    # (c) the sre walkers are reachable only inside the regex block, which ends with the guard.
    block_start = min(src.index('def ' + h) for h in REGEX_HELPERS)
    entry_at = src.index('def _is_redos_vulnerable_pattern')
    block_end = src.index('\n# ', entry_at) if '\n# ' in src[entry_at:] else len(src)
    offset_of = [0]
    for line in lines:
        offset_of.append(offset_of[-1] + len(line) + 1)
    for helper in REGEX_HELPERS:
        for i, line in enumerate(lines, 1):
            if not re.search(r'\b%s\(' % helper, line):
                continue
            if 'def ' + helper in line:
                continue
            if not (block_start <= offset_of[i - 1] <= block_end):
                failures.append('%s is called on line %d, outside the block whose entry point holds '
                                'the blanket except' % (helper, i))
    entry_body = src[entry_at:block_end]
    if 'except Exception' not in entry_body:
        failures.append('_is_redos_vulnerable_pattern lost its blanket except -- `re.error` and '
                        'ValueError from a malformed literal pattern would abort the scan again')
    if 'isinstance(pattern_str, str)' not in entry_body:
        failures.append('_is_redos_vulnerable_pattern no longer refuses a non-str pattern (bytes '
                        'literals such as rb"(?P<x>a+)+" reach it)')
    # (d) PEP 570: the alignment refuses a negative offset instead of indexing with one.
    c22 = inspect.getsource(TT._c22_param_proofs)
    if 'offset >= 0' not in c22 or 'posonlyargs' not in c22:
        failures.append('_c22_param_proofs lost the PEP 570 guard (`posonlyargs + args` and '
                        '`offset >= 0`) -- `def g(a="x", /)` and an over-long defaults list crash on '
                        'exactly that')
    # (e) the collector memo is only ever rebound by the pair that brackets the collector phase.
    # Both rebinding lines sit inside methods, so the owner is the nearest `def` at any indent.
    owner, owners_of = '<module>', {}
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith('def '):
            owner = stripped[4:].split('(')[0].strip()
        owners_of[i] = owner
    memo_writes = [i for i, line in enumerate(lines, 1)
                   if re.match(r'\s*_DOTTED_NAME_MEMO\s*=', line)]
    bracket = ('_begin_collector_memos', 'release_collector_memos')
    if [owners_of.get(i) for i in memo_writes] != list(bracket):
        failures.append('_DOTTED_NAME_MEMO is rebound on lines %s inside %s; only the phase-bracket '
                        'pair %s may rebind it -- the memo is unbounded and keyed per node, and a '
                        'rebinding that outlives one phase leaks entries across scans and costs RAM '
                        'this engine does not have' % (memo_writes,
                                                       [owners_of.get(i) for i in memo_writes],
                                                       list(bracket)))
    if re.search(r'_DOTTED_NAME_MEMO\s*[\[.]\s*(?!get)', src) or \
            re.search(r'_DOTTED_NAME_MEMO\.(?:pop|clear|update|setdefault)', src):
        failures.append('something mutates _DOTTED_NAME_MEMO other than rebinding it -- entries '
                        'written outside the bracketing pair never get dropped')
    if src.count('self._collector_dotted_name_memo') < 2:
        failures.append('the memo is no longer also held on the tracker: release_collector_memos '
                        'would drop the global while the per-tracker dict stayed alive')
    # (f) nothing in the guard family suppresses by path. Directory names are banned outright; a
    # basename read is tolerated only where it is the KEEP_LOUD pin, i.e. where its one and only
    # effect is to force a row LOUD. A pin can widen a finding, a blacklist can only hide one, and
    # hiding is what the contract forbids.
    for fname in ('_c862_scope_is_http_entrypoint', '_c862_scope_is_guarded_or_off_http',
                  '_c862_is_background_task', '_class_is_orm_scope',
                  '_c209_structured_error_envelope_only',
                  '_cwe328_hash_input_is_non_credential', '_c502_local_safe_loader_class',
                  '_c208_compared_operand_is_secret_named'):
        text = inspect.getsource(getattr(TT, fname))
        for token in ('"testutils"', '"fixtures"', '"tests"', '"examples"', '"docs"',
                      'file_path.endswith', '.startswith("tests'):
            if token in text:
                failures.append('%s matches the path token %s -- path blacklisting is banned by the '
                                'contract' % (fname, token))
        if 'basename(' not in text and 'os.path' not in text:
            continue
        if fname != '_c208_compared_operand_is_secret_named':
            failures.append('%s reads a filesystem path -- only the CWE-208 pin table is allowed to, '
                            'and only to promote' % fname)
            continue
        if 'CWE208_TIMING_OPERAND_KEEP_LOUD' not in text:
            failures.append('_c208_compared_operand_is_secret_named reads a path but no longer consults '
                            'the KEEP_LOUD table -- that read is now a blacklist')
            continue
        body = text.splitlines()
        hits = [i for i, line in enumerate(body) if 'basename(' in line or 'os.path' in line]
        after = next((body[j].strip() for i in hits for j in range(i + 1, len(body))
                      if body[j].strip().startswith('return')), '')
        if after != 'return True':
            failures.append('the path pin in _c208_compared_operand_is_secret_named answers %r, not '
                            '`return True` -- a basename that can quiet a row is path blacklisting '
                            'wearing a lookup table' % after)
    # (g) a helper that was deleted would silently leave the battery.
    for name in HELPERS_THAT_MUST_EXIST:
        if not hasattr(TT, name):
            failures.append('TaintTracker lost %s: the range added it, and this gate has to be told '
                            'when it goes' % name)
    return failures


# ─── mutations: change what the shipped pipeline reads, never recompile it ─────────────────────
# aa_parity scans this directory, so a live `exec(compile(text))` here is a CWE-95 row the engine is
# right to report -- and the frozen 425-key baseline is not this gate's to move. No mutation below
# recompiles engine source. Each one changes something the shipped code reads: the name a node
# resolves to, a marker table, a method bound on TaintTracker, or the source handed to the walk.
def _with_naming(shim, files):
    """Rescan `files` with `ast_scanner.dotted_name` swapped for `shim` (the predicate reads it live)."""
    if not hasattr(ast_scanner, 'dotted_name'):
        raise AssertionError('ast_scanner lost dotted_name -- the mutation no longer reaches anything')
    saved = ast_scanner.dotted_name
    ast_scanner.dotted_name = shim
    try:
        return basenames(scan_all(files)[1])
    finally:
        ast_scanner.dotted_name = saved


def _with_bindings(items, files):
    """Rescan `files` with TaintTracker methods swapped for hand-written replacements."""
    for name, _fn in items:
        if not hasattr(TT, name):
            raise AssertionError('TaintTracker has no %s -- the shipped code moved and this mutation '
                                 'would test nothing' % name)
    saved = {name: getattr(TT, name) for name, _ in items}
    for name, fn in items:
        setattr(TT, name, fn)
    try:
        return basenames(scan_all(files)[1])
    finally:
        for name, fn in saved.items():
            setattr(TT, name, fn)


def _lost_and_lit(by, cwe):
    """Blessed rows this scan stops reporting, and blessed quiet rows it starts reporting."""
    lost = [(module, line) for module, spec in BLESSED.items()
            for line in spec['loud'].get(cwe, [])
            if line not in by.get(module, {}).get(cwe, set())]
    lit = [(module, line) for module, spec in BLESSED.items()
           for line in spec['quiet'].get(cwe, [])
           if line in by.get(module, {}).get(cwe, set())]
    return lost, lit


def _scope_nodes(call):
    """The decorator and base nodes the shipped predicate reads for this call.

    Only the parent walk is copied, from ast_scanner.py:13785-13795 -- the first enclosing function
    and every enclosing class. The replay then applies the one pre-fix expression to those nodes.
    """
    func, classes_ = None, []
    current = getattr(call, 'parent', None)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if func is None:
                func = current
        elif isinstance(current, ast.ClassDef):
            classes_.append(current)
        current = getattr(current, 'parent', None)
    if func is None:
        return []
    nodes = [d.func if isinstance(d, ast.Call) else d for d in func.decorator_list]
    for cls in classes_:
        nodes += list(cls.bases)
    return nodes


MUTATIONS = {
    'unguarded_deref': '''Re-apply the shipped read without the fold -- `dotted_name(node).rsplit(
        ".", 1)[-1]`, exactly the expression that aborted `c7f4b75..3a0e7d8` -- to the decorator and
        base nodes the predicate walks, over the parent-linked trees the scan charged. It must raise,
        and the shipped helper must not: the fixtures still carry unnameable nodes, and the fold is the
        only thing standing between that read and a dead scan. Measured 6 of 8 nodes.''',
    'treat_unnameable_as_marker': '''Answer an unnameable node with a real marker instead of the empty
        string the fold chooses, by patching the naming layer. `route` is a member of
        CWE862_HTTP_ROUTE_DECORATORS, `APIView` passes the view-suffix test on a class base; measured
        `route` lights nothing -- no fixture holds an ORM fetch under a bare subscript decorator, which
        is why the read is pinned at the naming layer rather than left to one accidental shape -- while
        `APIView` lights gen_view.py:8, the plain `class Plain(Generic[T])` that is not a view. An
        unnameable node is the absence of evidence, not evidence.''',
    'base_unnameable_abandons_the_loop': '''Cut every enclosing class at its first unnameable base,
        which is the base list a `break` there would leave the walk to read, then call the shipped
        predicate unchanged. `class Later(Generic[T], APIView)` never reaches `APIView` and gen_view.py:11
        -- whose only HTTP marker is that second base, since `post(self, form)` takes no request -- goes
        quiet. The crash is gone and the finding dropped anyway. `Future.get` stays loud here, which is
        exactly why a partial check reads as a pass.''',
    'c862_guarded_helper_never_charges': '''Bind the sibling predicate to answer True before it reads a
        thing -- "a permission class declares this, or no HTTP caller reaches it" -- which is the
        conjunct `not scope_is_guarded_or_off_http` at ast_scanner.py:24028. Both blessed CWE-862 rows
        in gen_view.py vanish, so the helper is live in the shipped pipeline and this gate is not
        watching a dead branch.''',
    'pep570_posonly_default_without_parameter': '''Align defaults against `posonlyargs + args` with no
        offset test, replayed here in four lines. On a signature with zero positional names and one
        default -- which only a hand-built tree can carry, because `ast.parse` refuses `def f(a=1, /)` --
        `pos[offset + idx]` indexes an empty list and raises IndexError, the second crash the range
        introduced. The shipped helper runs on the same corrupted tree and raises nothing.''',
}


def run_mutation(name):
    if name == 'unguarded_deref':
        # The pre-fix expression, `dotted_name(<node>).rsplit(".", 1)[-1]`, replayed over exactly the
        # nodes the shipped predicate reads. Nothing is recompiled: the claim is about that one read,
        # and if the replay stops raising, the fixtures stopped carrying an unnameable node.
        raised = reached = shipped_crashes = 0
        for tree in SHARED.modules.values():
            for call in calls(tree):
                nodes = _scope_nodes(call)
                reached += len(nodes)
                for node in nodes:
                    if ast_scanner.dotted_name(node) is None:
                        try:
                            ast_scanner.dotted_name(node).rsplit('.', 1)[-1]
                        except AttributeError:
                            raised += 1
                try:
                    TT._c862_scope_is_http_entrypoint(SHARED, call)
                except Exception:
                    shipped_crashes += 1
        print('mutation %s: the un-folded read raised AttributeError on %d of %d decorator/base nodes '
              'the predicate walks; the shipped helper raised on 0 calls (got %d)'
              % (name, raised, reached, shipped_crashes))
        return 0 if raised >= 1 and shipped_crashes == 0 else 1
    if name == 'treat_unnameable_as_marker':
        # Fold at the naming layer instead of `or ""`: `route` is a member of
        # CWE862_HTTP_ROUTE_DECORATORS and `APIView` satisfies the view-suffix test on a base, so each
        # variant turns one of the two reads' absence-of-evidence into evidence.
        orig = ast_scanner.dotted_name
        reports = []
        for sentinel in ('route', 'APIView'):
            def shim(node, _orig=orig, _sentinel=sentinel):
                named = _orig(node)
                return _sentinel if named is None else named
            by = _with_naming(shim, FIXTURES)
            lost, lit = _lost_and_lit(by, 'CWE-862')
            reports.append((sentinel, lit))
        lit_any = [(sentinel, rows) for sentinel, rows in reports if rows]
        print('mutation %s: unnameable-as-marker per sentinel: %s -- the shipped scan reports none '
              'of these quiet lines' % (name, [(s, rows) for s, rows in reports]))
        return 0 if lit_any else 1
    if name == 'base_unnameable_abandons_the_loop':
        shipped = TT._c862_scope_is_http_entrypoint

        def bail_at_first_unnameable(self, call):
            """The walk's own view of each enclosing class, cut where a `break` would happen."""
            saved = []
            current = getattr(call, 'parent', None)
            while current is not None:
                if isinstance(current, ast.ClassDef):
                    keep = []
                    for base in current.bases:
                        if ast_scanner.dotted_name(base) is None:
                            break
                        keep.append(base)
                    saved.append((current, current.bases))
                    current.bases = keep
                current = getattr(current, 'parent', None)
            try:
                return shipped(self, call)
            finally:
                for cls, bases in saved:
                    cls.bases = bases
        by = _with_bindings([('_c862_scope_is_http_entrypoint', bail_at_first_unnameable)], FIXTURES)
        lost, lit = _lost_and_lit(by, 'CWE-862')
        print('mutation %s: rows lost when the base walk stops at the first unnameable base: %s'
              % (name, lost))
        return 0 if lost else 1
    if name == 'c862_guarded_helper_never_charges':
        # The charge needs `not scope_is_guarded_or_off_http`, so the mutant that silences it is the
        # predicate answering True before it reads anything: "a permission class declares this, or no
        # HTTP caller reaches it". Bound, not recompiled -- the shipped sibling is what disappears.
        by = _with_bindings([('_c862_scope_is_guarded_or_off_http',
                              lambda self, call, mod_name: True)], FIXTURES)
        lost, lit = _lost_and_lit(by, 'CWE-862')
        print('mutation %s: charged rows lost when the sibling always claims a guard: %s'
              % (name, lost))
        return 0 if len(lost) >= 1 else 1
    if name == 'pep570_posonly_default_without_parameter':
        tree = ast.parse('def f(*, c=2):\n    return c\n')
        fn = tree.body[0]
        # A signature no parser can produce: one default, zero positional names. `pos[offset + idx]`
        # then indexes an empty list -- IndexError, the second crash the range could have introduced.
        # Only a hand-corrupted tree reaches this, which is why the guard is proved on a node, not a
        # file: `ast.parse` refuses `def f(a=1, /)` outright.
        fn.args.kwonlyargs = []
        fn.args.kw_defaults = []
        fn.args.defaults = [ast.Constant(value=1)]
        for p in ast.walk(tree):
            for child in ast.iter_child_nodes(p):
                child.parent = p
        # The mutant's arithmetic, replayed here in four lines: align defaults with no offset test.
        raised = None
        try:
            pos = [a.arg for a in list(fn.args.posonlyargs) + list(fn.args.args)]
            for idx, _d in enumerate(list(fn.args.defaults)):
                pos[len(pos) - len(fn.args.defaults) + idx] = _d
        except IndexError as exc:
            raised = exc
        shipped = None
        try:
            TT._c22_param_proofs(SHARED, tree)
        except Exception as exc:
            shipped = exc
        print('mutation %s: alignment without the offset test raised %s on a 0-name/1-default '
              'signature; the shipped helper raised %s (must be nothing)'
              % (name, type(raised).__name__ if raised else 'nothing',
                 type(shipped).__name__ if shipped else 'nothing'))
        return 0 if isinstance(raised, IndexError) and shipped is None else 1
    print('unknown mutation %r; known: %s' % (name, sorted(MUTATIONS)))
    return 2


def peak_rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1048576.0
    except Exception:
        return 0.0


def main() -> int:
    if len(sys.argv) > 2 and sys.argv[1] == '--mutation':
        return run_mutation(sys.argv[2])
    if len(sys.argv) > 2 and sys.argv[1] == '--mutation-spec':
        text = MUTATIONS.get(sys.argv[2])
        if text is None:
            print('unknown mutation %r' % sys.argv[2])
            return 2
        print('%s: %s' % (sys.argv[2], ' '.join(text.split())))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == '--dump':
        by = basenames(SHARED_ROWS)
        for module in FIXTURES:
            print('%-22s %s' % (module,
                                {k: sorted(v) for k, v in sorted(by.get(module, {}).items())}))
        return 0
    src = io.open(SCANNER_PATH, encoding='utf-8').read()
    failures, seen, raised = check_battery()
    print('TIER 1 - %d direct helper claims over %d predicate groups, raising=%d:'
          % (sum(seen.values()), len(seen), raised))
    for name in sorted(seen):
        print('    %-42s %3d shapes' % (name, seen[name]))
    prefix_failures, live = check_prefix_is_live()
    print('TIER 2 - pre-fix `dotted_name(node).rsplit(...)` raises x%d on the same fixtures (>=3 '
          'needed)' % live)
    failures += prefix_failures
    row_failures, by = check_blessed_rows()
    print('TIER 3 - shared scan over %d modules, rows=%d' % (len(FIXTURES), len(SHARED_ROWS)))
    failures += row_failures
    cli_failures, facts = check_cli_contract()
    print('TIER 4 - cli.main exit=%s, sarif results=%d, held-back note=%s'
          % (facts['exit'], facts['sarif_results'], facts['note'][:70]))
    failures += cli_failures
    law_failures = check_laws(src)
    print('TIER 5 - unguarded dotted_name dereferences=%d, fold sites=%d, helpers required=%d, '
          'all present=%s' % (
              len(re.findall(r'dotted_name\([^()\n]*\)\s*\.\s*(?:rsplit|split|lower|endswith)',
                             src)),
              len([ln for ln in src.splitlines()
                   if re.search(r'\(dotted_name\([^)]*\)\s+or\s+""\)', ln)]),
              len(HELPERS_THAT_MUST_EXIST),
              all(hasattr(TT, n) for n in HELPERS_THAT_MUST_EXIST)))
    failures += law_failures
    for item in failures:
        print('  !! %s' % item)
    elapsed = time.time() - START
    rss = peak_rss_mb()
    print('TIER 6 - elapsed=%.2fs (budget %.1fs)  peak_rss=%.1fMB (budget %.1fMB)'
          % (elapsed, BUDGET_SECONDS, rss, BUDGET_RSS_MB))
    if failures:
        print('VERDICT: FAIL - a provenance helper can abort the scan again, or the guard lost a '
              'finding. Harden the site; never wrap the caller in silence.')
        return 1
    if elapsed > BUDGET_SECONDS or rss > BUDGET_RSS_MB:
        print('VERDICT: FAIL - budget blown, and a crash lock that is slow or heavy never runs.')
        return 1
    print('VERDICT: PASS - %d malformed/unusual nodes answered without raising, the pre-fix shape '
          'still raises x%d, %d blessed lines held and %d quiet lines stayed quiet over %d modules, '
          'cli.main exits %s (never 2) with %d SARIF results.'
          % (sum(seen.values()), live,
             sum(len(v) for spec in BLESSED.values() for v in spec['loud'].values()),
             sum(len(v) for spec in BLESSED.values() for v in spec['quiet'].values()),
             len(FIXTURES), facts['exit'], facts['sarif_results']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
