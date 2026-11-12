"""Invariant-table lock for Techniques 3 and 5: what shipped, what was refused, and why both.

    python benchmark/gates/cwe117_cwe208_invariant_table_probe.py

The mandate asked for a table of zero-risk CWE-117 log holes (`len`, `int`, `float`, `round`, `abs`,
`sum`, `time.time()`, `time.monotonic()`, `.shape`, `.ndim`, `.__name__`, `.__class__.__name__`) and
for CWE-208 sink pruning on literal operands, NLP delimiter literals and structural attribute pairs.
Both halves were measured before being written, through the emitter's own gate rather than through a
hand-rolled hole walk, and the results are in three groups.

Shipped -- `time.monotonic()` in `CWE117_STDLIB_SCALAR_METHODS`, and the clock arm made reachable
    CPython's clock getters return a builtin float or raise, so the printed text is digits, a sign and
    at most one dot regardless of what any name holds. `monotonic` joins `time` on that proof.
    Measuring it exposed the larger half of the slice: the arm's fail-close was written
    `"time" not in shadowed`, and `import time` is itself a binding, so the conjunct refused every
    module that legitimately uses the API and the `time.time()` seal had been unreachable code. The
    replacement is origin-aware instead of presence-based -- a receiver qualifies only when every site
    that binds its name is `import time`, so a `from tools import clock as time`, a reassignment, a
    parameter, a `del`, a `global`, an `import datetime as time` and a `time.monotonic(1)` each still
    refuse. Measured effect: 0 blessed keys move (119/119 and 425/425 with MISSING=0 and NEW=0) and 0
    arena rows move, because the arena -- transformers v4.38.0, 2,558 scanned files -- contains no
    `monotonic()` call at all. The entry is therefore coverage of a spelling the corpus has not used
    yet, plus the repair of an arm that could not fire; it is not the source of this round's
    FP number, and the scorecard says so. TIER 6b shows both halves carrying weight -- reinstate the
    old conjunct and the hole the arm alone seals comes back, blind the veto and six fail-closed
    fixtures go quiet at once.

Already shipped -- `round` and `.ndim`, the two table entries with nothing left to do
    `_c117_evaluate_log_holes_fact` (ast_scanner.py:6631) returns FACT_NUMERIC_SAFE for
    `int/float/len/round/ord/bool` behind the shadow test at ast_scanner.py:6731 and for any `.ndim`
    at ast_scanner.py:6748, and `_c117_message_is_numeric_composite` (ast_scanner.py:6899) adopts that
    verdict as a whole-message seal. TIER 4b asserts both halves of the finding on live fixtures: the
    hole is refused by `_numeric_safe_expr`, so the invariant table is not what seals it, and the
    message seals anyway. Adding `round` to `CWE117_BUILTIN_SEALED_NAMES` would extend a
    dispatch-returning builtin (`round(x)` is `x.__round__()`) into the conjunct that does *not*
    already carry it, for 0 measured rows, so it stays out.

A fail-open measured here and deliberately not touched
    ast_scanner.py:6736 also seals `time.time()` without asking what `time` is, so a module that
    rebinds the name to something returning `"a\\nb"` still loses the finding -- TIER 4b prints that
    row's state as a measurement, not a lock. Closing it is a tightening, which can only add rows, and
    rule 1's MISSING=0/NEW=0 locks make this slice the wrong vehicle. It is written down so the next
    one does not have to rediscover it.

Already shipped -- all three CWE-208 prunes
    `_compares_two_secrets` (ast_scanner.py:10117) refuses a comparison with ANY `ast.Constant`
    operand, which subsumes both "integer, float, boolean or empty literal" and every NLP delimiter
    literal, and `_c208_is_tensor_dimension_compare` (`_is_arena_dim`, ast_scanner.py:10013) already
    lists `shape`, `ndim`, `size`, `dim`, `dtype` and `len`/`numel`/`sum` call leaves. Measured on the
    blessed corpora: 42 comparisons carrying a credential name are refused by the Constant rule today.
    There is no new predicate to add, so this gate locks the ones that exist.

Refused, with the mechanism demonstrated by running it -- `abs`, `sum`, `.shape`, `__name__`,
`__class__.__name__`, and the standalone value-domain arm
    Each entry is a claim about a *return type* that the spelling of a leaf does not carry, and TIER 3
    proves the counterexample by executing it in this process: `sum` is `+` folded, so `__radd__`
    decides and returns `'a\\nb'`; `abs(x)` runs `x.__abs__()`; a `shape` property returns whatever
    its author wrote; and `SomeClass.__name__` is a writable attribute that accepts a newline -- the
    mandate's "identifiers cannot contain CRLF" holds for the name at definition time and not for the
    value of `type.__name__` at print time, which is why `int.__name__` refuses while a heap class
    accepts. Then the numbers: sealing `__name__` silences 2 of the 43 blessed Big-8 CWE-117 keys
    (`src/transformers/modeling_utils.py:1983` and `:2024`, both `f"{self.__class__.__name__} does not
    support setting its attention implementation dynamically..."`), and running
    `_c22_value_is_newline_free` without the two operator-presence facts it is gated behind silences 2
    more (`:832` and `:846`, both `dtype` fed from `config.dtype` and from checkpoint metadata) for
    exactly 1 arena row. AGENTS.md rule 1 makes a dropped blessed key a hard rollback, and rule 2
    asks for the (N - K) verified-safe remainder -- here N - K is empty at the same site, because the
    rows that make the axis tempting and the rows that make it fatal are the same statement: the two
    blessed keys are `self.__class__.__name__` inside a class whose name is never rebound, which is
    precisely the case an `__name__` seal would silence. No AST fact separates them from the 29 arena
    rows the same predicate would clear, so the only discriminator available is a path-and-line list,
    which rule 5 keeps out of the engine. So the refusal is on soundness, it is not a punt, and TIER 6
    installs each refused predicate to show the fixtures move.

Also refused -- widening the CWE-208 credential tuple from 6 words to the requested 14
    `sensitive_markers` (ast_scanner.py:22593) is the emitter's PRECONDITION, not its veto: a
    comparison with no credential name in it is never considered at all. Adding `key`, `password`,
    `pwd`, `auth`, `hash`, `digest`, `nonce`, `salt`, `mac` and `credential` therefore suppresses
    nothing and reports more. Measured over the two blessed corpora it produces 9 rows that pass every
    other conjunct and would arrive as NEW keys -- 8 on bare `key`, 1 on `digest` -- which breaks the
    119/119 and 425/425 locks from the other side.
"""
from __future__ import annotations

import ast
import collections
import contextlib
import io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys  # noqa: E402

LOCKED_CWE117 = {'parity': 6, 'big8': 43}
LOCKED_CWE208 = {'parity': 6, 'big8': 30}

TIME_HEAD = 'import time\n'
LOG_HEAD = 'import logging\nlogger = logging.getLogger(__name__)\n'
REQ_HEAD = 'from flask import request\n'

SHIPPED_STDLIB_METHODS = frozenset({'time', 'monotonic'})
SHIPPED_BUILTIN_NAMES = frozenset({'len', 'int', 'float', 'bool', 'ord'})
SHIPPED_SENSITIVE_MARKERS = ('token', 'secret', 'signature', 'hmac', 'api_key', 'auth_token')
REQUESTED_MARKERS = ('secret', 'key', 'token', 'password', 'pwd', 'auth', 'hash', 'digest',
                     'signature', 'nonce', 'salt', 'mac', 'credential', 'api_key')

def clock_case(holes, head=TIME_HEAD, sig='h()'):
    """A log message whose taint enters through a sealed builtin, plus the clock hole under test.

    The `len(rows)` field matters: CWE-117 needs a tainted value in the message, and a bare
    `time.monotonic()` hole carries none, so a fixture without this shape is silent whether or not
    the arm exists. With it, the row is silent exactly when the clock hole is provably numeric, which
    is the claim under test.
    """
    return (head + REQ_HEAD + LOG_HEAD + f'def {sig}:\n    rows = request.args.get("q")\n'
            '    logger.info(f"n={len(rows)} ' + holes + '")\n')


# (label, source, cwe) -- the claim is that the shipped arm fires and the row goes quiet.
SEALED_TARGETS = [
    ('time_time_hole', clock_case('t={time.time()}'), 'CWE-117'),
    ('time_monotonic_hole', clock_case('t={time.monotonic()}'), 'CWE-117'),
]

# The holes whose seal is the arm and nothing else. `time.time()` is excluded because
# ast_scanner.py:6736 seals it on the receiver's spelling alone -- the fail-open TIER 4b measures --
# so blinding the arm cannot bring that row back and asserting it would only re-lock the fail-open.
ARM_ONLY_SEALS = {'time_monotonic_hole'}

# Each entry is the same message with one reason for the arm to refuse.
LOUD_BUDGET = [
    ('time_rebound_by_from_import',
     clock_case('t={time.monotonic()}', head='from tools import clock as time\n')),
    ('time_reassigned_at_module_scope',
     clock_case('t={time.monotonic()}', head=TIME_HEAD + 'time = lambda: "x\\ny"\n')),
    ('time_rebound_by_parameter', clock_case('t={time.monotonic()}', sig='h(time)')),
    ('time_module_del_after_import',
     clock_case('t={time.monotonic()}', head='import time\ndel time\n')),
    ('time_declared_global_in_a_helper',
     clock_case('t={time.monotonic()}', head=TIME_HEAD + 'def g():\n    global time\n')),
    ('datetime_imported_under_the_name_time',
     clock_case('t={time.monotonic()}', head='import datetime as time\n')),
    ('clock_called_with_an_argument', clock_case('t={time.monotonic(1)}')),
    ('clock_on_a_different_module', clock_case('t={perf.monotonic()}', head='import perf\n')),
    ('clock_behind_an_aliased_import', clock_case('t={clock.monotonic()}',
                                                  head='import time as clock\n')),
    ('clock_hole_alongside_a_bare_taint', clock_case('t={time.monotonic()} u={rows}')),
]

# TIER 3: each refused table entry, executed. A counterexample that runs is worth more here than a
# paragraph arguing it, and every one of these values is what a log line would print.
def demonstrate_return_type_risk():
    """Return {label: (printed_text_carries_crlf, why)} for the refused spellings."""
    out = {}

    class Addable:
        """`sum` folds with `+`, so the accumulator's type is whatever the elements' reflect method
        hands back. That is the whole objection to sealing `sum` by its spelling."""

        def __radd__(self, other):
            return 'a\nb'

    out['sum_via_radd'] = ('\n' in str(sum([Addable(), Addable()], 0)),
                           '`sum` is `+` folded, so it returns what `__radd__` returns')
    try:
        sum(['a\n', 'b'])
        out['sum_of_strings_raises'] = (False, 'CPython summed strings without raising')
    except TypeError:
        out['sum_of_strings_raises'] = (True, 'the operand type decides, and here it decided to raise')
    out['sum_of_ints'] = ('\n' not in str(sum([2, 3])), 'the safe half of the same spelling')

    class Absorbs:
        def __abs__(self):
            return 'p\nq'

    class Rounds:
        def __round__(self, n=None):
            return 'r\ns'

    class Shaped:
        @property
        def shape(self):
            return 't\nu'

    out['abs_custom'] = ('\n' in str(abs(Absorbs())), '`abs(x)` is `x.__abs__()`')
    out['round_custom'] = ('\n' in str(round(Rounds())), '`round(x)` is `x.__round__()`')
    out['shape_property'] = ('\n' in str(Shaped().shape), 'a `shape` is whatever its author returns')

    class Model:
        pass

    Model.__name__ = 'attn\nimpl'
    out['class_name_rebound'] = ('\n' in f'{Model.__name__}',
                                 '`type.__name__` is writable on a heap type')
    instance = Model()
    out['class_dunder_chain'] = ('\n' in f'{instance.__class__.__name__}',
                                 'so `self.__class__.__name__` prints it too')
    try:
        int.__name__ = 'bad\nname'
        out['builtin_name_refused'] = (False, 'immutable types should refuse, and did not')
    except TypeError:
        out['builtin_name_refused'] = (True, 'immutable builtins refuse; heap types do not')
    return out


# (label, source, cwe) shapes whose holes are exactly the refused spellings, plus the blessed shapes.
#
# Every fixture is built by `refused_case`: the taint enters the message through `{len(rows)}`, which
# the shipped table already seals, and the hole under test is the last field. That construction is
# what makes the tier mean anything -- CWE-117 needs a tainted value in the message to emit a row at
# all, so a fixture whose only hole is `abs(rows)` is silent with or without the refusal and proves
# nothing. With the sealed companion, the row is reported exactly while the hole under test stays
# unsealed, which is the same condition TIER 6 mutates.
def refused_case(hole, head=REQ_HEAD):
    return (head + LOG_HEAD + 'def h(self):\n    rows = request.args.get("q")\n'
            '    logger.info(f"n={len(rows)} ' + hole + '")\n')


REFUSED_SHAPES = [
    ('abs_hole_stays_loud', refused_case('v={abs(rows)}'), 'CWE-117'),
    ('sum_hole_stays_loud', refused_case('v={sum(rows)}'), 'CWE-117'),
    ('shape_hole_stays_loud', refused_case('v={rows.shape}'), 'CWE-117'),
    ('class_name_hole_stays_loud', refused_case('m={self.__class__.__name__}'), 'CWE-117'),
    # src/transformers/modeling_utils.py:1983 and :2024, the two blessed keys a `__name__` seal
    # deletes. Reproduced under a vendor module name so no corpus-path shield can apply.
    ('blessed_class_name_message_loud', REQ_HEAD + LOG_HEAD + 'def h(self):\n'
     '    rows = request.args.get("q")\n    logger.warning(\n'
     '        f"n={len(rows)} {self.__class__.__name__} does not support setting its attention '
     'implementation dynamically, because it "\n'
     '        "does not follow the functional approach based on AttentionInterface "\n'
     '        "(see https://huggingface.co/docs/transformers/en/attention_interface)"\n'
     '    )\n', 'CWE-117'),
    # src/transformers/modeling_utils.py:832/:846, the two keys the standalone value-domain arm
    # deletes: `dtype` is fed from a config field and from checkpoint metadata.
    ('blessed_dtype_from_config_loud', REQ_HEAD + LOG_HEAD + 'def h(config):\n'
     '    rows = request.args.get("q")\n    dtype = config.dtype\n'
     '    logger.info(f"n={len(rows)} Will use dtype={dtype} as defined in model\'s config '
     'object")\n', 'CWE-117'),
    ('blessed_dtype_from_weights_loud', REQ_HEAD + LOG_HEAD + 'def h(state_dict):\n'
     '    rows = request.args.get("q")\n    dtype = get_state_dict_dtype(state_dict)\n'
     '    logger.info(f"n={len(rows)} will use dtype={dtype} as derived from model weights")\n',
     'CWE-117'),
]

# Two of the requested entries need no engine change because a shipped conjunct already seals them --
# and not through `_numeric_safe_expr`. `round` is in the LogHolesFact builtin list (ast_scanner.py:
# 6731, shadow-tested) and a bare `.ndim` is FACT_NUMERIC_SAFE at ast_scanner.py:6748 (name-matched,
# which is the pattern the contract forbids new code from adding). TIER 4b asserts both halves of
# that: the hole is refused by the table AND the message seals, so the seal demonstrably lives
# elsewhere.
ALREADY_SEALED_SHAPES = [
    ('round_hole_sealed_by_fact_engine', refused_case('v={round(rows)}')),
    ('ndim_hole_sealed_by_fact_engine', refused_case('v={rows.ndim}')),
]

CWE208_PRUNES = [
    ('int_literal_operand', 'def h(user_token, stored_token):\n    if user_token == 0:\n'
     '        return 1\n    return 0\n', 'silent'),
    ('empty_string_operand', 'def h(user_token, stored_token):\n    if user_token == "":\n'
     '        return 1\n    return 0\n', 'silent'),
    ('cls_delimiter_literal', 'def h(pieces, cls_token_id):\n    if pieces == "[CLS]":\n'
     '        return 1\n    return 0\n', 'silent'),
    ('pad_delimiter_membership', 'def h(sequence):\n    if "[PAD]" in sequence:\n'
     '        return 1\n    return 0\n', 'silent'),
    ('shape_pair_compare', 'def h(left, right):\n    if left.shape == right.shape:\n'
     '        return 1\n    return 0\n', 'silent'),
    ('ndim_pair_compare', 'def h(left, right):\n    if left.ndim == right.ndim:\n'
     '        return 1\n    return 0\n', 'silent'),
    ('two_secrets_loud', 'def h(api_token, signing_key):\n    if api_token == signing_key:\n'
     '        return 1\n    return 0\n', 'report'),
    ('digest_compare_loud', 'import hmac\n\n\ndef h(received_signature, stored_signature):\n'
     '    if hmac.compare_digest(received_signature, stored_signature):\n        return 1\n'
     '    return 0\n', 'silent'),
]

MARKER_WIDENING_FIXTURES = [
    ('hash_named_pair', 'def h(input_hash, stored_hash):\n    if input_hash == stored_hash:\n'
     '        return 1\n    return 0\n', 'key'),
    ('nonce_named_pair', 'def h(client_nonce, server_nonce):\n    if client_nonce == server_nonce:\n'
     '        return 1\n    return 0\n', 'nonce'),
    ('credential_named_pair', 'def h(entered_credential, stored_credential):\n'
     '    if entered_credential == stored_credential:\n        return 1\n    return 0\n',
     'credential'),
]


SEALED_BY_LABEL = {label: (source, cwe) for label, source, cwe in SEALED_TARGETS}
REFUSED_BY_LABEL = {label: (source, cwe) for label, source, cwe in REFUSED_SHAPES}


def scan(label, source, cwe):
    """One in-memory module through the real record path: tracker, edges, finding rows."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return [row for row in rows if row['cwe'] == cwe]


def check_table_identity():
    """TIER 1: the frozen tables are the shipped ones, by object identity, not by prose."""
    failures = []
    got_methods = ast_scanner.TaintTracker.CWE117_STDLIB_SCALAR_METHODS
    got_builtins = ast_scanner.TaintTracker.CWE117_BUILTIN_SEALED_NAMES
    print(f'  stdlib scalar methods = {sorted(got_methods)}')
    print(f'  sealed builtin names  = {sorted(got_builtins)}')
    if got_methods != SHIPPED_STDLIB_METHODS:
        failures.append(('CWE117_STDLIB_SCALAR_METHODS', sorted(SHIPPED_STDLIB_METHODS),
                         sorted(got_methods), 'the clock-getter table moved'))
    if got_builtins != SHIPPED_BUILTIN_NAMES:
        failures.append(('CWE117_BUILTIN_SEALED_NAMES', sorted(SHIPPED_BUILTIN_NAMES),
                         sorted(got_builtins),
                         'a builtin joined or left the CPython-forced-scalar table'))
    for entry in ('round', 'abs', 'sum', 'str'):
        if entry in got_methods or entry in got_builtins:
            failures.append((entry, 'absent from both tables', 'present',
                             'a dispatch-returning builtin was sealed'))
    with open(os.path.join(GATES_DIR, META['big8']['keys_file']), encoding='utf-8') as handle:
        keys_text = handle.read()
    split = collections.Counter(line.split("'")[3] for line in keys_text.splitlines()
                                if line.startswith('('))
    print(f"  big8 blessed CWE-117={split['CWE-117']} CWE-208={split['CWE-208']}")
    for name, expected in (('big8', LOCKED_CWE117['big8']), ('parity', LOCKED_CWE117['parity'])):
        rows = load_keys(os.path.join(GATES_DIR, META[name]['keys_file']), name)
        count = sum(1 for row in rows if row[2] == 'CWE-117')
        if count != expected:
            failures.append((name, 'CWE-117 keys', expected, count,
                             'the floor this table may never move changed'))
    return failures


def check_sealed_and_loud():
    """TIER 2: what the clock arm seals, and every shape that keeps the arm fail-closed."""
    failures = []
    for label, source, cwe in SEALED_TARGETS:
        got = 'silent' if not scan(label, source, cwe) else 'report'
        print(f'  ok   {label:26s} want=silent got={got}' if got == 'silent'
              else f'  FAIL {label:26s} want=silent got={got}')
        if got != 'silent':
            failures.append((label, 'silent', got, 'a sealed clock hole is still reported'))
    for label, source in LOUD_BUDGET:
        got = 'report' if scan(label, source, 'CWE-117') else 'silent'
        print(f'  ok   {label:26s} want=report got={got}' if got == 'report'
              else f'  FAIL {label:26s} want=report got={got}')
        if got != 'report':
            failures.append((label, 'report', got,
                             'the clock arm fired where the module binds `time` or passes arguments'))
    return failures


def check_demonstrations():
    """TIER 3: each refusal rests on a claim executed in this process, and every claim must hold.

    A flag that flips means CPython changed underneath the reasoning, which is the moment the
    refusal list has to be re-read -- not the moment this tier gets weakened.
    """
    failures = []
    for label, (holds, why) in sorted(demonstrate_return_type_risk().items()):
        print(f'  {"ok  " if holds else "FAIL"} {label:24s} claim_holds={holds}  ({why})')
        if not holds:
            failures.append((label, 'claim holds', 'claim broken',
                             'the evidence behind a refused table entry no longer runs - '
                             're-read the refusal before changing the engine'))
    return failures


def check_refused_shapes():
    """TIER 4: the refused table entries and the blessed keys they would delete, all still loud."""
    failures = []
    for label, source, cwe in REFUSED_SHAPES:
        got = 'report' if scan(label, source, cwe) else 'silent'
        print(f'  {"ok  " if got == "report" else "FAIL"} {label:32s} want=report got={got}')
        if got != 'report':
            failures.append((label, 'report', got,
                             'a refused predicate exists in the engine: this shape went quiet'))
    return failures


def _first_log_call(tree):
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and getattr(node.func, 'attr', '') in ('info', 'warning', 'error', 'debug',
                                                       'critical', 'exception', 'log')):
            return node
    return None


def check_already_sealed():
    """TIER 4b: `round` and `.ndim` seal today, and the seal is not the invariant table's doing."""
    failures = []
    for label, source in ALREADY_SEALED_SHAPES:
        reported = bool(scan(label, source, 'CWE-117'))
        tree = ast.parse(source)
        call = _first_log_call(tree)
        with contextlib.redirect_stderr(io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
            tracker.analyze()
        shadowed = tracker._shadowed_names_in_tree(tree)
        holes = [h.value if isinstance(h, ast.FormattedValue) else h
                 for h in tracker._cwe117_logged_values(call)]
        under_test = holes[-1]
        table_refuses = not tracker._numeric_safe_expr(under_test, shadowed)
        fact_seals = tracker._c117_message_is_numeric_composite(call, shadowed)
        ok = (not reported) and table_refuses and fact_seals
        print(f'  {"ok  " if ok else "FAIL"} {label:36s} reported={reported} '
              f'table_refuses_hole={table_refuses} fact_engine_seals_message={fact_seals}')
        if reported:
            failures.append((label, 'silent', 'reported',
                             'the shipped conjunct stopped sealing this shape'))
        if not table_refuses:
            failures.append((label, 'hole refused by CWE117_BUILTIN_SEALED_NAMES', 'sealed by table',
                             'the requested entry was added to the table; re-read the counterexample'))
        if not fact_seals:
            failures.append((label, 'LogHolesFact seals the message', 'does not seal',
                             'the reach of the requested entry is no longer already covered'))
    fail_open = refused_case('t={time.time()}', head=TIME_HEAD + 'time = lambda: "x\\ny"\n')
    print(f'  measurement (not a lock): a rebound `time` still loses the `time.time()` finding '
          f'here: reported={bool(scan("rebound_time_time", fail_open, "CWE-117"))}')
    return failures


def check_cwe208_prunes():
    """TIER 5: the three requested CWE-208 prunes are already shipped, and the guards still win."""
    failures = []
    for label, source, want in CWE208_PRUNES:
        got = 'silent' if not scan(label, source, 'CWE-208') else 'report'
        ok = got == want
        print(f'  {"ok  " if ok else "FAIL"} {label:26s} want={want:6s} got={got}')
        if not ok:
            failures.append((label, want, got,
                             'the constant-operand / tensor-dimension partition moved'))
    return failures


def check_marker_direction():
    """TIER 5b: the credential tuple is a precondition, so widening it adds findings.

    Asserted two ways per fixture: the shipped 6 words do not consider the comparison at all while
    the requested 14 do, and the same fixture is silent today through the real emitter, so the extra
    word could only arrive as a NEW key.
    """
    failures = []
    for label, source, word in MARKER_WIDENING_FIXTURES:
        today = scan(f'{label}_today', source, 'CWE-208')
        considered_now = any(any(m in n for m in SHIPPED_SENSITIVE_MARKERS)
                             for n in (word,))
        considered_widened = any(any(m in n for m in REQUESTED_MARKERS) for n in (word,))
        print(f'  {label:24s} word={word:10s} in_shipped_tuple={considered_now} '
              f'in_requested_tuple={considered_widened} reported_today={bool(today)}')
        if considered_now:
            failures.append((label, word, 'absent from the shipped tuple', 'present',
                             'fixture no longer isolates the widening'))
        if not considered_widened:
            failures.append((label, word, 'present in the requested tuple', 'absent',
                             'the requested 14-word list no longer contains this word'))
        if today:
            failures.append((label, 'silent', 'report',
                             'the row is already reported, so it proves nothing about widening'))
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        engine_text = handle.read()
    shipped_line = 'sensitive_markers = ("token", "secret", "signature", "hmac", "api_key", ' \
                   '"auth_token")'
    print(f'  emitter precondition tuple present verbatim: {shipped_line in engine_text}')
    if shipped_line not in engine_text:
        failures.append(('sensitive_markers', shipped_line, 'missing', 'source text changed'))
    return failures


def _patched_numeric_seal(extra):
    """Install `extra(expr)` as an additional CWE-117 hole exemption and hand back the restorer."""
    original = ast_scanner.TaintTracker._numeric_safe_expr

    def patched(self, expr, shadowed=None):
        if extra(expr):
            return True
        return original(self, expr, shadowed)

    ast_scanner.TaintTracker._numeric_safe_expr = patched

    def restore():
        ast_scanner.TaintTracker._numeric_safe_expr = original

    return restore


def check_mutations():
    """TIER 6: every refusal is load-bearing -- install it and watch the blessed rows go quiet."""
    failures = []
    probes = [('class name seal', lambda e: isinstance(e, ast.Attribute) and e.attr == '__name__',
               'class_name_hole_stays_loud'),
              ('class name seal', lambda e: isinstance(e, ast.Attribute) and e.attr == '__name__',
               'blessed_class_name_message_loud'),
              ('shape seal', lambda e: isinstance(e, ast.Attribute) and e.attr in ('shape', 'ndim'),
               'shape_hole_stays_loud'),
              ('arg-typed builtin seal',
               lambda e: isinstance(e, ast.Call) and getattr(e.func, 'id', '') in ('abs', 'sum'),
               'abs_hole_stays_loud'),
              ('arg-typed builtin seal',
               lambda e: isinstance(e, ast.Call) and getattr(e.func, 'id', '') in ('abs', 'sum'),
               'sum_hole_stays_loud')]
    for label, predicate, fixture in probes:
        source = REFUSED_BY_LABEL[fixture][0]
        before = bool(scan(f'{fixture}_pre', source, 'CWE-117'))
        restore = _patched_numeric_seal(predicate)
        try:
            after = bool(scan(f'{fixture}_post', source, 'CWE-117'))
        finally:
            restore()
        revived = bool(scan(f'{fixture}_restored', source, 'CWE-117'))
        print(f'  {label:24s} {fixture:32s} loud={before} under_mutation={after} '
              f'restored={revived}')
        if not before:
            failures.append((label, 'loud before mutation', 'silent',
                             'the fixture does not test the refusal'))
        if after:
            failures.append((label, 'silenced by the installed predicate', 'still loud',
                             'the mutation is inert, so the tier proves nothing'))
        if not revived:
            failures.append((label, 'loud again after restore', 'silent',
                             'restore failed - the mutation leaked into the next tier'))
    monotonic_source = SEALED_BY_LABEL['time_monotonic_hole'][0]
    methods = ast_scanner.TaintTracker.CWE117_STDLIB_SCALAR_METHODS
    ast_scanner.TaintTracker.CWE117_STDLIB_SCALAR_METHODS = frozenset({'time'})
    try:
        without_monotonic = bool(scan('monotonic_without_arm', monotonic_source, 'CWE-117'))
    finally:
        ast_scanner.TaintTracker.CWE117_STDLIB_SCALAR_METHODS = methods
    print(f'  monotonic removed      time_monotonic_hole reported again: {without_monotonic} '
          f'(table={sorted(ast_scanner.TaintTracker.CWE117_STDLIB_SCALAR_METHODS)})')
    if not without_monotonic:
        failures.append(('monotonic', 'silent with time.time() only', 'reported',
                         'the shipped entry is not what seals the hole'))
    failures += check_clock_mutations()
    return failures


def check_clock_mutations():
    """TIER 6b: the two conjuncts that make the clock arm live, each shown to move a row.

    M-a reinstates the arm as it shipped before this slice -- `time` must not appear in the module's
    shadow set -- which is a condition no importer can satisfy, so the hole the arm alone seals comes
    back. M-b removes the competing-binding veto from the origin proof, which silences the fail-closed
    budget: that is the false negative the veto exists to prevent.
    """
    failures = []
    original = ast_scanner.TaintTracker._clock_receiver_is_stdlib_time
    ast_scanner.TaintTracker._clock_receiver_is_stdlib_time = lambda self, receiver: False
    try:
        pre_fix = [(label, bool(scan(f'{label}_oldconj', source, 'CWE-117')))
                   for label, source, _ in SEALED_TARGETS]
    finally:
        ast_scanner.TaintTracker._clock_receiver_is_stdlib_time = original
    print('  old shadow-set conjunct reinstated (the arm is the only seal for the rows marked '
          'arm-only; `time.time()` is also sealed by the fact engine, measured in TIER 4b):')
    for label, reported in pre_fix:
        sole = label in ARM_ONLY_SEALS
        print(f'    {label:24s} arm_only={sole} reported={reported}')
        if sole and not reported:
            failures.append((label, 'loud under the pre-fix conjunct', 'silent',
                             'the origin proof is not what makes the arm fire'))
        if bool(scan(f'{label}_restored2', SEALED_BY_LABEL[label][0], 'CWE-117')):
            failures.append((label, 'silent again after restore', 'reported',
                             'restore failed - the mutation leaked'))

    veto_original = ast_scanner.TaintTracker._stdlib_time_module_names
    ast_scanner.TaintTracker._stdlib_time_module_names = lambda self, tree: frozenset({'time'})
    try:
        no_veto = [(label, bool(scan(f'{label}_noveto', source, 'CWE-117')))
                   for label, source in LOUD_BUDGET[:6]]
    finally:
        ast_scanner.TaintTracker._stdlib_time_module_names = veto_original
    print('  competing-binding veto removed (each row below is a false negative):')
    for label, reported in no_veto:
        print(f'    {label:38s} reported={reported}')
        if reported:
            failures.append((label, 'silenced once the veto is blind', 'still reported',
                             'the fixture does not exercise the veto, so the veto is unproven'))
    for label, source in LOUD_BUDGET[:3]:
        if not bool(scan(f'{label}_back', source, 'CWE-117')):
            failures.append((label, 'loud after restore', 'silent', 'restore leaked'))
    return failures


def main() -> int:
    print('TIER 1 - frozen tables and the blessed CWE-117 floor (asserted):')
    failures = check_table_identity()
    print('TIER 2 - the clock-getter arm: sealed holes and its fail-closed budget:')
    failures += check_sealed_and_loud()
    print('TIER 3 - the refused spellings, demonstrated carrying CRLF in this process:')
    failures += check_demonstrations()
    print('TIER 4 - refused table entries and the blessed keys behind them, all still loud:')
    failures += check_refused_shapes()
    print('TIER 4b - `round` and `.ndim` already seal, through the LogHolesFact engine:')
    failures += check_already_sealed()
    print('TIER 5 - CWE-208: the requested prunes are already shipped, guards still win:')
    failures += check_cwe208_prunes()
    print('TIER 5b - the credential tuple is a precondition, so widening adds findings:')
    failures += check_marker_direction()
    print('TIER 6 - falsification: install each refused predicate, watch rows move:')
    failures += check_mutations()
    print(f'\nfailures={len(failures)} sealed={len(SEALED_TARGETS)} '
          f'loud_budget={len(LOUD_BUDGET)} refused={len(REFUSED_SHAPES)} '
          f'already_sealed={len(ALREADY_SEALED_SHAPES)}')
    for item in failures[:14]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the invariant table no longer matches its evidence. Restore the '
              'finding or restore the table; re-blessing a baseline is not the fix.')
        return 1
    print('VERDICT: PASS - one sound table entry shipped and its dead fail-close repaired, four '
          'refused with the counterexample executed, two confirmed already sealed by the shipped '
          'fact engine, and the CWE-208 partition confirmed already-shipped.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
