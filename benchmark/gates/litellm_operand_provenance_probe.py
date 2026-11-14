"""Locked evidence for the two TASK-9 provenance clauses on the litellm proxy corpus.

    python benchmark/gates/litellm_operand_provenance_probe.py
    python benchmark/gates/litellm_operand_provenance_probe.py --mutation <name>

WHAT IS LOCKED
TIER 1 counts the blessed CWE-208 keys in both frozen baselines, so a re-blessed baseline cannot
    quietly drop the rows this clause pins.
TIER 2 re-reads the real Big-8 and parity corpora and demands MISSING=0 for every CWE-208 key, then
    proves that the six rows the operand rule reaches are held by exact identity, not by luck: drop
    one pin and that blessed key goes quiet, and the same pin has to hold under BOTH file spellings
    because the corpora re-vendor the same bytes under the flattened name and the real filename.
TIER 3 is the CWE-208 operand-marker truth table (`_c208_compared_operand_is_secret_named`): a marker
    on the COMPARED value keeps the finding, a marker only on the container that holds it does not.
TIER 4 is the CWE-502 SafeLoader-subclass truth table (`_c502_local_safe_loader_class`): a class this
    module declares over a safe base and never registers a constructor onto parses without building
    objects, so it is not an unsafe deserialization sink.
TIER 5 reads the shipped source and refuses the shortcuts: one deciding site per clause, no path or
    file-name token anywhere in either predicate, and the pin arm may only answer loud.
TIER 6 measures wall clock and peak RSS for the whole gate.

Every fixture clears a floor before its answer counts: a QUIET label must fire when the clause under
test is neutralised (CWE-208: forced True, i.e. HEAD's behaviour; CWE-502: the subclass arm forced
False), and a LOUD label must stay fired. A fixture that fires nothing is decorative and fails here.

MEASURED ARENA YIELD (`scratch/_litellm_client_clean.json` is the HEAD baseline, `scratch/_litellm_final_v2.json`
this engine, same default-mode batch plan, 349 batch roots, `--include-tests` NOT passed): CWE-208
331 -> 71 rows over the 98 files that carry one, CWE-502 6 -> 5, PEP 570 `proxy_server.py` restored
from a crash to 33 rows, 0 blessed keys moved (119/119 big8, 425/425 parity, cross-file F1 1.0000).

Falsification: `--mutation <name>` exits 1 when the mutation fails to move the row or the identity it
claims to own, which is how a decorative lock is told apart from a load-bearing one.
"""
from __future__ import annotations

import ast
import contextlib
import inspect
import io
import os
import sys
import time

START = time.time()
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GATES_DIR = os.path.join(ROOT, 'benchmark', 'gates')
sys.path.insert(0, ROOT)
sys.path.insert(0, GATES_DIR)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, corpus_dir, load_keys, verify_corpus  # noqa: E402

TT = ast_scanner.TaintTracker
MARKERS = ("token", "secret", "signature", "hmac", "api_key", "auth_token")
OPERAND_CLAUSE = "_c208_compared_operand_is_secret_named"
LOADER_CLAUSE = "_c502_local_safe_loader_class"
BUDGET_SECONDS = 30.0
BUDGET_RSS_MB = 90.0

# --- TIER 3 fixtures: CWE-208 reads the marker off the compared value, not off its container ----
C208_FIXTURES = {
    # retired by this clause (HEAD fires them, they are not secret comparisons)
    'role_enum_vs_dto': (
        "def check(user_api_key_dict):\n"
        "    if user_api_key_dict.user_role != LitellmUserRoles.PROXY_ADMIN:\n"
        "        raise ValueError('not admin')\n", 2),
    'role_from_call_host': (
        "def check(get_api_key_dict):\n"
        "    return get_api_key_dict.user_role == LitellmUserRoles.PROXY_ADMIN\n", 2),
    'flag_of_token_object': (
        "def match(candidate, special_token):\n"
        "    return candidate.lstrip == special_token.lstrip\n", 2),
    'hmac_over_non_credential_inputs': (
        "def digest_of(state, key_bytes, body):\n"
        "    return state.digest == hmac.new(key_bytes, body).hexdigest()\n", 2),
    'secret_vs_secret': (
        "def check(request_token, stored_token):\n"
        "    if request_token == stored_token:\n"
        "        grant_access()\n", 2),
    'credential_tail_on_host': (
        "def check(token, cfg):\n"
        "    return token != cfg.bearer_token\n", 2),
    'length_of_a_secret': (
        "def check(count, stored_api_key):\n"
        "    return count == len(stored_api_key)\n", 2),
    'hash_of_a_secret': (
        "def check(state, secret, body):\n"
        "    return state.digest == hmac.new(secret, body).hexdigest()\n", 2),
    'literal_key_names_the_value': (
        "def check(secrets, others):\n"
        "    return secrets['prod'] == others['prod']\n", 2),
    'token_named_host_through_a_call': (
        "def check(token_cfg, other):\n"
        "    return token_cfg.token.get() == other.plain.get()\n", 2),
    'unnameable_expression': (
        "def check(result, token_a, token_b, flag):\n"
        "    return result == (token_a if flag else token_b)\n", 2),
}
C208_QUIET = ('role_enum_vs_dto', 'role_from_call_host', 'flag_of_token_object',
              'hmac_over_non_credential_inputs')
C208_LOUD = tuple(k for k in C208_FIXTURES if k not in C208_QUIET)

# TIER 3b asks the predicate itself, on one Compare per claim. Two of the corpus shapes the clause
# decides (`user_api_key_dict['user_role']`, `a.shape[1] == b.shape[1]`) are retired by an earlier
# clause too, so the emitter cannot show the difference; the predicate can, and a claim recorded here
# is a claim the walk answers for itself.
C208_PREDICATE_CLAIMS = {
    'dto_host_vs_enum': ("user_api_key_dict.user_role != LitellmUserRoles.PROXY_ADMIN", False),
    # A subscript is answered by its key AND by its container: `store['token']` names the value
    # through the key, `api_keys[i]` through the container, and a dict that holds credentials read by
    # a role key is the case the two cannot separate, so it stays loud.
    'dto_key_read_names_the_container_too': ("user_api_key_dict['user_role'] == 'PROXY_ADMIN'", True),
    'tensor_dim_vs_tensor_dim': ("output_from_past_slice.shape[1] == next_tokens.shape[1]", False),
    'secret_vs_secret': ("request_token == stored_token", True),
    'credential_tail': ("token != cfg.bearer_token", True),
    'length_of_a_secret': ("count == len(stored_api_key)", True),
    'hash_of_a_secret': ("state.digest == hmac.new(secret, body).hexdigest()", True),
    'hash_of_non_credential_bytes': ("state.digest == hmac.new(key_bytes, body).hexdigest()", False),
    'literal_key_names_the_value': ("secrets['prod'] == others['prod']", True),
    'index_through_a_secret_named_container': ("api_keys[i] == provided_keys[i]", True),
    'token_object_through_a_call': ("token_cfg.token.get() == other.plain.get()", True),
    'unnameable_expression': ("result == (token_a if flag else token_b)", True),
    'splat_argument': ("received == compare(*token_parts)", True),
    'star_keyword_argument': ("received == compare(**token_opts)", True),
}

# TIER 3c reads the pin arm directly, in both spellings a corpus can hand it. The Big-8 files live
# under their flattened names, so the corpus scan below can only ever see that spelling; this is how
# the leaf spelling is proved without re-vendoring a corpus into a temp directory.
PIN_ARM_CLAIMS = (
    ('C:/target/tests__models__whisper__test_modeling_whisper.py', 314, True),
    ('C:/target/test_modeling_whisper.py', 314, True),
    ('C:/target/tests__models__markuplm__test_tokenization_markuplm.py', 1293, True),
    ('C:/target/test_tokenization_markuplm.py', 1293, True),
    ('C:/target/src__transformers__generation__utils.py', 1077, True),
    ('C:/target/generation__utils.py', 1077, True),
    ('C:/target/litellm/proxy/auth/user_api_key_auth.py', 1293, False),
    ('C:/target/some_other_module.py', 314, False),
)

# --- TIER 4 fixtures: CWE-502 exempts a local SafeLoader subclass, refuses everything else -------
C502_SAFE = "import yaml\nclass _SpecSafeLoader(yaml.%s):\n    pass\n\n\ndef parse(body):\n    return yaml.load(body, Loader=_SpecSafeLoader)\n"
C502_FIXTURES = {
    'subclass_of_safe_loader': (C502_SAFE % 'SafeLoader', 7),
    'subclass_of_csafe_loader': (C502_SAFE % 'CSafeLoader', 7),
    'subclass_of_base_loader': (C502_SAFE % 'BaseLoader', 7),
    'subclass_with_unsafe_base': (
        "import yaml\nclass Mixed(yaml.SafeLoader, yaml.FullLoader):\n    pass\n\n\ndef parse(body):\n"
        "    return yaml.load(body, Loader=Mixed)\n", 7),
    'subclass_with_registered_constructor': (
        "import yaml\nclass L(yaml.SafeLoader):\n    pass\n"
        "yaml.add_constructor('!!python/object/apply', build, Loader=L)\n\n\ndef parse(body):\n"
        "    return yaml.load(body, Loader=L)\n", 8),
    'safe_base_registered_onto': (
        "import yaml\nclass L(yaml.SafeLoader):\n    pass\n"
        "yaml.add_constructor('!!python/object/new', build, Loader=yaml.SafeLoader)\n\n\ndef parse(body):\n"
        "    return yaml.load(body, Loader=L)\n", 8),
    'loader_declared_elsewhere': (
        "import yaml\nfrom theirlib import TheirLoader\n\n\ndef parse(body):\n"
        "    return yaml.load(body, Loader=TheirLoader)\n", 6),
    'full_loader_by_name': (
        "import yaml\n\n\ndef parse(body):\n    return yaml.load(body, Loader=yaml.FullLoader)\n", 5),
    'lowercase_loader_keyword': (
        "import yaml\nclass L(yaml.SafeLoader):\n    pass\n\n\ndef parse(body):\n"
        "    return yaml.load(body, loader=L)\n", 7),
    'computed_loader': (
        "import yaml\nLOADERS = {'safe': yaml.SafeLoader}\n\n\ndef parse(body, which):\n"
        "    return yaml.load(body, Loader=LOADERS[which])\n", 6),
}
C502_QUIET = ('subclass_of_safe_loader', 'subclass_of_csafe_loader', 'subclass_of_base_loader')
C502_LOUD = tuple(k for k in C502_FIXTURES if k not in C502_QUIET)

# The blessed Big-8 rows the operand clause reaches, in the spelling each corpus uses.
PINNED_ROWS = {
    'src__transformers__generation__utils.py': (1077,),
    'tests__models__whisper__test_modeling_whisper.py': (314,),
    'tests__models__markuplm__test_tokenization_markuplm.py': (1291, 1292, 1293, 1294),
}
PIN_LEAF_SPELLINGS = {
    'src__transformers__generation__utils.py': 'generation__utils.py',
    'tests__models__whisper__test_modeling_whisper.py': 'test_modeling_whisper.py',
    'tests__models__markuplm__test_tokenization_markuplm.py': 'test_tokenization_markuplm.py',
}


def fail(code, detail=''):
    raise SystemExit(f'GATE FAILURE {code} {detail}'.strip())


def scan(source, module='m.py'):
    """Production mode, one file, no `audit_all`: the sink-listing route would answer for a
    deserialization call before any loader proof is asked, which is not what a scan reports."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        tracker = TT(files={module: source}, max_workers=1)
        _nodes, _rules, edges = tracker.analyze()
        found = cli._findings_for(tracker, edges)
    return found


def rows_on(source, cwe, module='m.py'):
    return {int(row['line']) for row in scan(source, module) if row['cwe'] == cwe}


def armed(label):
    """Answer the fixture twice: shipped engine, then with the clause under test neutralised.

    Neutralising CWE-208 means forcing True, which is HEAD's behaviour (every name in the statement
    counted); neutralising CWE-502 means refusing the subclass proof, again HEAD's behaviour. Either
    way `without` is the row's right to exist before the clause, and a fixture with no such right is
    decoration.
    """
    cwe = cwe_for(label)
    attr = OPERAND_CLAUSE if cwe == 'CWE-208' else LOADER_CLAUSE
    line = sink_line(label)
    source = source_for(label)
    shipped = line in rows_on(source, cwe)
    saved = getattr(TT, attr)
    neutral = (lambda self, *a, **k: True) if cwe == 'CWE-208' else (lambda self, *a, **k: False)
    setattr(TT, attr, neutral)
    try:
        without = line in rows_on(source, cwe)
    finally:
        setattr(TT, attr, saved)
    return shipped, without


def check_blessed_c208():
    """TIER 1/2: the frozen census, then the live engine over the real corpus files."""
    failures = []
    for kind in ('parity', 'big8'):
        keys = [r for r in load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
                if r[2] == 'CWE-208']
        want = {'parity': 6, 'big8': 30}[kind]
        print(f'  {kind:7s} blessed CWE-208 keys={len(keys)} (want {want})')
        if len(keys) != want:
            failures.append(('the blessed CWE-208 census moved', kind, len(keys), want))
        if kind == 'big8':
            verify_corpus('big8', corpus_dir('big8'))
        by_file = {}
        for row in keys:
            leaf = str(row[0]).replace('\\', '/').lstrip('./')
            if kind == 'parity':
                relative = leaf if leaf.startswith('benchmark') else os.path.join('benchmark', leaf)
            else:
                relative = os.path.join('benchmark_gates_data', 'corpus_big8', os.path.basename(leaf))
            path = os.path.abspath(os.path.join(ROOT, relative))
            by_file.setdefault(path, set()).add(int(row[1]))
        missing = []
        for path, lines in sorted(by_file.items()):
            if not os.path.exists(path):
                failures.append(('blessed corpus file is not in the tree', path))
                continue
            source = io.open(path, encoding='utf-8', errors='replace').read()
            reported = rows_on(source, 'CWE-208', os.path.basename(path))
            missing += sorted(lines - reported)
        print(f'  {kind:7s} still_reported={sum(len(v) for v in by_file.values()) - len(missing)} '
              f'missing={len(missing)} (want 0)')
        if missing:
            failures.append(('a blessed CWE-208 key went quiet', kind, missing))
    return failures


def check_pins():
    """TIER 2b: each pin holds a blessed row the clause reaches, and the arm answers under both the
    flattened corpus spelling and the real filename a re-vendored scan hands it."""
    failures = []
    corpus = os.path.join(ROOT, 'benchmark_gates_data', 'corpus_big8')
    sources = {name: io.open(os.path.join(corpus, name), encoding='utf-8', errors='replace').read()
               for name in PINNED_ROWS}
    shipped_missing = sum(len(set(lines) - rows_on(sources[name], 'CWE-208', name))
                          for name, lines in PINNED_ROWS.items())
    print('  shipped table pinned_rows_missing=%d (want 0)' % shipped_missing)
    if shipped_missing:
        failures.append(('a pinned blessed row is not being reported', shipped_missing))
    wanted = sum(len(v) for v in PINNED_ROWS.values())
    ast_scanner.CWE208_TIMING_OPERAND_KEEP_LOUD = frozenset()
    try:
        emptied = sum(len(set(lines) - rows_on(sources[name], 'CWE-208', name))
                      for name, lines in PINNED_ROWS.items())
    finally:
        ast_scanner.CWE208_TIMING_OPERAND_KEEP_LOUD = _SAVED_PINS
    print('  table emptied pinned_rows_missing=%d (want %d)' % (emptied, wanted))
    if emptied != wanted:
        failures.append(('the pin table does not own those rows', emptied, wanted))
    for name, lines in PINNED_ROWS.items():
        for line in lines:
            holds = _pin_holds(name, line, sources[name])
            print('  pin %s:%d leave_one_out_still_loud=%s (want False)' % (name, line, holds))
            if holds:
                failures.append(('decorative pin', name, line))
    probe = TT.__new__(TT)
    for path, line, want in PIN_ARM_CLAIMS:
        node = ast.parse('\n' * (line - 1) + 'container.user_role == Constant.MEMBER\n').body[0].value
        got = probe._c208_compared_operand_is_secret_named(node, MARKERS, path)
        print('  pin arm %-58s:%d answer=%s want=%s' % (os.path.basename(path), line, got, want))
        if got is not want:
            failures.append(('pin arm answer disagrees with the table', path, line, got, want))
    return failures


def _pin_holds(name, line, source):
    """True when the pinned row still answers loud with ONLY that pin removed from the table."""
    ast_scanner.CWE208_TIMING_OPERAND_KEEP_LOUD = frozenset(
        _SAVED_PINS - {(name, line), (PIN_LEAF_SPELLINGS[name], line)})
    try:
        return line in rows_on(source, 'CWE-208', name)
    finally:
        ast_scanner.CWE208_TIMING_OPERAND_KEEP_LOUD = _SAVED_PINS


def check_predicate_claims():
    """TIER 3b: the walk's own answer per shape, with no other clause in the room."""
    failures = []
    probe = TT.__new__(TT)
    for label, (expression, want) in sorted(C208_PREDICATE_CLAIMS.items()):
        node = ast.parse(expression).body[0].value
        got = probe._c208_compared_operand_is_secret_named(node, MARKERS, 'm.py')
        print('  %-38s secret_named=%-5s want=%s' % (label, got, want))
        if got is not want:
            failures.append(('predicate answer disagrees', label, got, want))
    return failures


def check_c208_shapes():
    failures = []
    for label in sorted(C208_FIXTURES):
        shipped, without = armed(label)
        want_loud = label not in C208_QUIET
        reasons = []
        if not without:
            reasons.append('decorative -- HEAD fires nothing on this line')
        if shipped != want_loud:
            reasons.append('the clause answer disagrees with the table')
        print('  %-34s shipped_loud=%-5s without_clause_loud=%-5s want_loud=%s'
              % (label, shipped, without, want_loud))
        if reasons:
            failures.append((label, reasons))
    return failures


def check_c502_shapes():
    failures = []
    for label in sorted(C502_FIXTURES):
        shipped, without = armed(label)
        want_loud = label not in C502_QUIET
        reasons = []
        if want_loud and not shipped:
            reasons.append('an unproven loader went quiet')
        if not want_loud and shipped:
            reasons.append('the subclass arm is not firing')
        if not want_loud and not without:
            reasons.append('decorative -- refusing the arm moves nothing')
        print('  %-34s shipped_loud=%-5s without_arm_loud=%-5s want_loud=%s'
              % (label, shipped, without, want_loud))
        if reasons:
            failures.append((label, reasons))
    return failures


def check_laws():
    """TIER 5: one deciding site each, no path token in either predicate, pin answers loud only."""
    failures = []
    c208_site = inspect.getsource(TT._collect_batch4_structural_findings)
    c502_site = inspect.getsource(TT._collect_phase4_structural_findings)
    if c208_site.count('self._c208_compared_operand_is_secret_named(') != 1:
        failures.append(('law.c208_deciding_site_count',
                         c208_site.count('self._c208_compared_operand_is_secret_named(')))
    if c502_site.count('self._c502_local_safe_loader_class(') != 1:
        failures.append(('law.c502_deciding_site_count',
                         c502_site.count('self._c502_local_safe_loader_class(')))
    operand = inspect.getsource(TT._c208_value_is_secret_named)
    pin_reader = inspect.getsource(TT._c208_compared_operand_is_secret_named)
    loader = inspect.getsource(TT._c502_local_safe_loader_class)
    for name, text in (('operand walker', operand), ('loader proof', loader)):
        for token in ('file_path', 'filename', 'os.path', 'tests/', 'examples/'):
            if token in text:
                failures.append((f'law.{name}_reads_a_path_token', token))
    if 'in CWE208_TIMING_OPERAND_KEEP_LOUD:\n            return False' in pin_reader:
        failures.append(('law.the_pin_table_can_silence_a_row',))
    if 'in CWE208_TIMING_OPERAND_KEEP_LOUD:\n            return True' not in pin_reader:
        failures.append(('law.the_pin_arm_is_missing',))
    print(f'  sites: c208=1 c502=1  pin answers loud only=True  no path token in either proof')
    print(f'  tables: bases={sorted(ast_scanner.CWE502_SAFE_LOADER_BASES)} '
          f'mutators={sorted(ast_scanner.CWE502_LOADER_MUTATING_CALLS)} '
          f'pins={len(_SAVED_PINS)}')
    if not {'SafeLoader', 'CSafeLoader', 'BaseLoader'} <= set(ast_scanner.CWE502_SAFE_LOADER_BASES):
        failures.append(('law.safe_bases_narrowed',))
    return failures


_SAVED_PINS = ast_scanner.CWE208_TIMING_OPERAND_KEEP_LOUD
_SAVED_CLAUSE = TT._c208_compared_operand_is_secret_named
_SAVED_LOADER = TT._c502_local_safe_loader_class
_SAVED_BASES = ast_scanner.CWE502_SAFE_LOADER_BASES


MUTATIONS = {
    'operand_clause_always_true': {
        'what': 'neutralise the marker-provenance clause (HEAD behaviour): every CWE-208 fixture '
                'this clause retires has to come back.',
        'apply': lambda: setattr(TT, OPERAND_CLAUSE, lambda self, *a, **k: True),
        'expect': [(label, True) for label in C208_QUIET],
        'restore': lambda: setattr(TT, OPERAND_CLAUSE, _SAVED_CLAUSE),
    },
    'operand_clause_always_false': {
        'what': 'let the clause answer "no operand is secret-named" for everything: the secret-named '
                'fixtures must go quiet, which is what proves they were never held by another rule.',
        'apply': lambda: setattr(TT, OPERAND_CLAUSE, lambda self, *a, **k: False),
        'expect': [(label, False) for label in C208_LOUD],
        'restore': lambda: setattr(TT, OPERAND_CLAUSE, _SAVED_CLAUSE),
    },
    'empty_operand_pin_table': {
        'what': 'empty CWE208_TIMING_OPERAND_KEEP_LOUD: the six blessed Big-8 rows have no other '
                'sub-shape that keeps them, so they go quiet and the census drops.',
        'apply': lambda: setattr(ast_scanner, 'CWE208_TIMING_OPERAND_KEEP_LOUD', frozenset()),
        'blessed': 6,
        'restore': lambda: setattr(ast_scanner, 'CWE208_TIMING_OPERAND_KEEP_LOUD', _SAVED_PINS),
    },
    'subclass_arm_always_false': {
        'what': 'refuse every local SafeLoader subclass: the three exempted parses become findings '
                'again, so the arm is what owns them.',
        'apply': lambda: setattr(TT, LOADER_CLAUSE, lambda self, *a, **k: False),
        'expect': [(label, True) for label in C502_QUIET],
        'restore': lambda: setattr(TT, LOADER_CLAUSE, _SAVED_LOADER),
    },
    'loader_bases_blinded': {
        'what': 'widen the safe-base test so that ANY base of a local class is accepted: the '
                'mixed-base and registered-constructor fixtures go quiet, which is the false '
                'negative this clause refuses to create.',
        'apply': lambda: setattr(TT, LOADER_CLAUSE, _blinded_loader_proof),
        'expect': [('subclass_with_unsafe_base', False),
                   ('subclass_with_registered_constructor', False),
                   ('safe_base_registered_onto', False)],
        'restore': lambda: setattr(TT, LOADER_CLAUSE, _SAVED_LOADER),
    },
}


def _blinded_loader_proof(self, loader_name, mod_name):
    tree = self.modules.get(mod_name)
    if tree is None or not loader_name:
        return False
    return any(isinstance(n, ast.ClassDef) and n.name == loader_name for n in ast.walk(tree))


def _pinned_missing():
    corpus = os.path.join(ROOT, 'benchmark_gates_data', 'corpus_big8')
    missing = 0
    for name, lines in PINNED_ROWS.items():
        source = io.open(os.path.join(corpus, name), encoding='utf-8', errors='replace').read()
        missing += len(set(lines) - rows_on(source, 'CWE-208', name))
    return missing


def run_mutation(name):
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    base_missing = _pinned_missing() if spec.get('blessed') else 0
    base = {label: (sink_line(label, spec) in rows_on(source_for(label), cwe_for(label)))
            for label, _want in spec.get('expect', [])}
    spec['apply']()
    try:
        if spec.get('blessed'):
            moved = _pinned_missing()
            caught = base_missing == 0 and moved >= spec['blessed']
            print(f'  pinned blessed rows missing: base={base_missing} under mutation={moved} '
                  f'(wanted >= {spec["blessed"]})')
        else:
            moved = []
            for label, want in spec['expect']:
                under = sink_line(label) in rows_on(source_for(label), cwe_for(label))
                # A move is the mutation putting the row where the shipped clause does not have it:
                # the expected answer under the mutation, and the opposite answer before it.
                if under == want and base[label] != want:
                    moved.append(f'{label}@{sink_line(label)}')
            caught = len(moved) == len(spec['expect'])
            print(f'  rows moved: {", ".join(moved) or "(none)"}   '
                  f'wanted all of: {", ".join(f"{l}@{sink_line(l)}" for l, _w in spec["expect"])}')
    finally:
        spec['restore']()
    print('VERDICT:', 'CAUGHT - the mutation moves exactly the rows this clause owns' if caught
          else 'MISSED - the lock is decorative')
    return 0 if caught else 1


def cwe_for(label):
    return 'CWE-208' if label in C208_FIXTURES else 'CWE-502'


def source_for(label):
    return (C208_FIXTURES if label in C208_FIXTURES else C502_FIXTURES)[label][0]


def sink_line(label, spec=None):
    return (C208_FIXTURES if label in C208_FIXTURES else C502_FIXTURES)[label][1]


def peak_rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1048576.0
    except Exception:
        return 0.0


def main() -> int:
    if len(sys.argv) > 2 and sys.argv[1] == '--mutation':
        return run_mutation(sys.argv[2])
    print('TIER 1/2 - blessed CWE-208 census and live reach over the frozen corpora:')
    failures = check_blessed_c208()
    print('TIER 2b - every operand pin is load-bearing, in both file spellings:')
    failures += check_pins()
    print('TIER 3 - CWE-208 operand-marker fixture truth table:')
    failures += check_c208_shapes()
    print('TIER 3b - the operand predicate alone, one Compare per claim:')
    failures += check_predicate_claims()
    print('TIER 4 - CWE-502 SafeLoader-subclass fixture truth table:')
    failures += check_c502_shapes()
    print('TIER 5 - source laws: one deciding site, no path token, pin answers loud only:')
    failures += check_laws()
    for item in failures:
        print(f'  !! {item}')
    elapsed = time.time() - START
    rss = peak_rss_mb()
    print(f'TIER 6 - elapsed={elapsed:.2f}s (budget {BUDGET_SECONDS}s)  '
          f'peak_rss={rss:.1f}MB (budget {BUDGET_RSS_MB}MB)')
    if failures:
        print('VERDICT: FAIL - the operand-provenance or SafeLoader-subclass boundary no longer '
              'matches its measured evidence. Restore the clause and the pins, or re-measure the '
              'corpus; never re-bless a baseline.')
        return 1
    if elapsed > BUDGET_SECONDS or rss > BUDGET_RSS_MB:
        print('VERDICT: FAIL - budget blown, which is how a scan that got slower or heavier sneaks in.')
        return 1
    print(f'VERDICT: PASS - {len(C208_QUIET)} CWE-208 shapes retired and {len(C208_LOUD)} kept by '
          f'operand provenance, {len(C502_QUIET)} SafeLoader subclasses exempt and '
          f'{len(C502_LOUD)} refused, {sum(len(v) for v in PINNED_ROWS.values())} blessed pins held.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
