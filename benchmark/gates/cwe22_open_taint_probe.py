"""Slice J truth table: when an `open()` in a library module owes a resolved untrusted origin.

Why this gate exists
--------------------
Two mechanisms reported `CWE-22: open` with no taint flow at all. Phase 11 adopts the registry `open`
sink and stamps a synthetic `UNTRUSTED_PATH_TRAVERSAL` -- and its only gate was `_is_safe_path`, so
"not provably safe" was being used as "untrusted". The funnel's `ProvenanceState.UNKNOWN` arm then
appended a 0.50 edge for whatever survived. At HEAD (the d0ef933 engine, snapshotted in
`scratch/_c22_open_head_ast_scanner.py`) the CWE-22 universe holds 359 rows carrying the registry
`open` message and 91 carrying the synthetic generic message, and not one of the 359 is there because
a source was proven -- they are there because nothing ruled the argument out. That is the fallback the
mandate named.

The rule therefore asks the same question the synthetic-source guard asks -- can this module be handed
a remote value? -- and where the answer is no, the `open()` must produce a *resolved* origin instead
of borrowing one. Measured, not claimed: the paired full-arena scan
(`scratch/_c22_pair_base_all.json` / `scratch/_c22_pair_live_all.json`, one arm per process, the
candidate arm loaded from `scratch/_c22_open_committed_ast_scanner.py` so nothing the other session
has in this worktree can help or hurt the number) moves **585 -> 481 CWE-22 lines and the whole arena
population 1559 -> 1455 findings: 104 tuples retired, 0 appeared, 0 message churn on surviving lines,
and every per-CWE delta except CWE-22 is zero.** The retired set is 102 `CWE-22: open` rows plus one
`os.open` and one `display.Image.open` -- both reached by the open-family leaf rule, both in modules
that declare no entrypoint -- and **zero** of the 91 generic synthetic rows, which belong to the
sibling gate and stay exactly where they were.
`scratch/_c22_open_retired_split.py` attributes the
retired sinks: 59 of them were carrying a synthetic `p5` `UNTRUSTED_PATH_TRAVERSAL` stamp and 33 were
carried by the UNKNOWN arm alone, and once the stamp is refused 46 resolve to an internal value while
46 come back UNKNOWN with nothing behind them.

What is left, attributed row by row
-----------------------------------
`scratch/_c22_open_survivor_split.py` asks the shipped predicates, while the engine decides, why each
of the 482 surviving CWE-22 lines in the CWE-22 universe is still loud: 225 are not the `open()`
fallback at all (91 generic synthetic rows, 25 `os.remove`, 17 `shutil.rmtree`, 14 `shutil.move`, 13
`save_json`, 8 `shutil.copy`, 4 `zipfile.ZipFile.extractall`, ...), 249 are `open()` in a module that
DOES declare an entrypoint or harness fact, 5 are held by the cut-short flavour and 3 by a proven
route. The single-digit floor the mandate named would have to reach into the first two of those
groups, and both are the mandate's own preservation arms: sink families other than `open()`, and
modules whose caller is right there in the file. What this rule could retire without violating either,
it retired -- 104 rows, 0 of them blessed.

Cost, measured against a control rather than against a hope
----------------------------------------------------------
`scratch/_c22_open_cost_probe.py` runs three arms in one process, alternating which goes first: HEAD,
this engine, and a control that loads THIS engine with the answer forced to False, which is HEAD's
behaviour with this slice's code in it. The control is what makes the number honest: it does strictly
less work than the shipped rule (it asks the 746 questions and prunes nothing, so it carries all 586
rows) and it measured *higher* than the candidate -- median 36.4s / 90.5 MB against the candidate's
35.6s / 90.0 MB and HEAD's 35.1s / 88.9 MB, with the same process reaching 128 MB on its third arm.
The gap attributable to this slice is therefore ~+0.5s (+1.4%) on the CWE-22 universe and ~1.01x on
the full arena (201.8s -> 203.6s), and `memo_builds=244` in both arms shows the assignment map is not
involved. Absolute RSS is not a usable ceiling on this box: HEAD itself measured 88.9 to 97.7 MB
across runs of the same engine.

One deciding site, and it can only subtract
------------------------------------------
`c22_open_owes_taint` is computed once per funnel record, strictly before any collector's synthetic
source can attach an edge -- the same placement discipline the CWE-78 execve guard uses, for the same
reason: a future emitter cannot register an `open()` finding that escapes the answer. The flag does
not resolve anything itself. It removes the right to short-circuit (both synthetic arms) and then
declines at the UNKNOWN arm, where it **only ever removes a sink**. A TAINTED answer, a STATIC answer
and any resolution that is cut short fall through to exactly the answer they already had, so no row
can appear and no message can change. TIER 5 pins that shape structurally: one assignment, two gated
short-circuits, a prune arm containing no `edges.append`.

What refuses the requirement -- and why each refusal is load-bearing
-------------------------------------------------------------------
Every refusal is in the keep-loud direction, and every one is falsified below by a mutation that
must move the rows it guards:

  * **not an open-family call** -- `os.remove(slot)` and `shutil.rmtree(slot)` in the same pure
    library module keep the answer they always had. The first revision of this rule reached them and
    retired deletes, which is not what the mandate asked for and not what a sink-family prune should
    do;
  * **an archive constructor or extraction** -- `tarfile.open` shares the `open` leaf with the
    builtin, and Zip-Slip is a finding about the archive, not about who chose the path. Pinned at the
    predicate for both the dotted and the `import tarfile as tf` spelling (a leaf-name test would
    miss the alias), because the exemption has **measured zero finding-level reach today**: no
    `tarfile.open` call exists in the arena, the Zip-Slip rows that do exist are carried by
    `extractall`, and `extractall` is refused by the open-family test above rather than by this
    table. A two-module name table that currently decides no finding is a liability only if nobody
    says so, so it is said here and falsified by `archive_table_emptied`;
  * **a module that declares an entrypoint or a test harness** -- 8 of the 16 Big-8 CWE-22 keys and
    1 of the 8 parity keys are harness `open()` rows, and the frozen baselines own them;
  * **the exact-identity pin** -- for the blessed row whose caller lives in another module, which no
    intra-file proof can ever see;
  * **three UNKNOWN flavours that are not "nothing reached here"** -- a walk cut short by the depth or
    cycle guard, a walk that landed on a directory enumeration, and a walk that landed on an
    untrusted-source spelling. The last of these was found by this gate, not by the arena:
    `open(os.environ["CFG"])` and `chosen = os.environ["CFG"]; open(chosen)` answer UNKNOWN because the
    resolver gives up on a subscript, so a rule that demanded the TAINTED label would have retired a
    real operator-controlled path. Condition (a) of the mandate is met on its face there.

Collateral: eight gates that pinned the blanket
---------------------------------------------
Because this rule answers before the synthetic arms, eight tracked gates lost carriers whose only
loudness basis was the fallback itself: `cwe22_entrypoint_injection_probe`'s two `SUPERSEDED_BY_OPEN_
TAINT` rows, `active_partition_probe`'s five resolver carriers, `cwe22_value_origin_probe`'s five
resolver/plain-local shapes, `cwe22_param_caller_probe`'s three self-field shapes,
`cwe22_vocab_serializer_probe`'s three serializer shapes, `mechanism_pitch_probe`'s `param_path_open`,
`cwe22_dirent_closure_probe`'s `glob_multi_component`, and `cwe117_cwe22_unknown_source_probe`'s
`parameter_derived_path_write`, which was locking the placeholder-edge contract on a module that
declares no entrypoint and so was loud only because of the blanket. No expectation was loosened: every
carrier module now declares an entrypoint fact, which is the thing those gates were already assuming
when they pinned the row, and the dirent seal's own abstention is respected by the enumeration
exemption rather than re-decided. `cwe22_dirent_closure_probe` also had a real bug fixed here -- its
`scan()` appended `.py` to a label that already ended in `.py`, so it was scanning `foo.py.py` and
reporting whatever fell out.

Usage
-----
    python benchmark/gates/cwe22_open_taint_probe.py
    python benchmark/gates/cwe22_open_taint_probe.py --mutate=<name>

Thirteen weakenings are pinned below. Per Harness Law 8 each must move the row its clause decides,
and the tripwire is line-scoped and message-scoped, because a fixture line can carry a CWE-22 row
that belongs to another emitter.
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
from gate_common import META, load_keys  # noqa: E402

GENERIC = ('CWE-22: Unvalidated user input or dynamic variable used in file path operation')
OPEN_MSG = 'CWE-22: open'
CWE22_LOCKED = {'parity': 8, 'big8': 16}
BASELINE_TOTALS = {'parity': 425, 'big8': 119}
EXPECTED_OPEN_PINS = [('modeling_utils.py', 336), ('modeling_utils.py', 3564),
                      ('src__transformers__trainer.py', 4301), ('trainer.py', 4301)]
# The blessed rows the leaf spellings exist for: `active_partition_probe` re-vendors every blessed
# line under `vendor/...`, where the corpus-name shield cannot help.
VENDORED_BLESSED = [('src__transformers__trainer.py', 'vendor/transformers/trainer.py', 4301),
                    ('src__transformers__modeling_utils.py',
                     'vendor/transformers/modeling_utils.py', 336)]

READ = '    with open({arg}) as handle:\n        return handle.read()\n'
WRITE = '    with open({arg}, "w") as handle:\n        handle.write(payload)\n'
PURE = 'src/library.py'


def module(*lines):
    return ''.join(line + '\n' for line in lines)


# A 56-deep aliasing chain, written so every name is assigned before it is read: the resolver walks
# it until the depth guard stops it, which is the only spelling that reaches `depth_guard` in a
# single function.
DEPTH_CHAIN = (module('def load(payload):',
                      *('    p%d = p%d' % (i, i + 1) for i in range(55, -1, -1)),
                      '    with open(p0, "w") as handle:', '        handle.write(payload)'))

# --------------------------------------------------------------------------- earned: loud at HEAD, quiet now
# Every one of these is `CWE-22: open` in `git show d0ef933:ast_scanner.py` (the snapshot this slice
# was measured against) and entirely absent now, with the sink owed a proof and nothing naming an
# origin. `scratch/_c22_open_taint_measure.py` produced the table.
EARNED_QUIET = {
    'write_mode_param': (2, module('def dump(slot, payload):', WRITE.format(arg='slot'))),
    'append_mode_param': (2, module('def dump(slot, payload):',
                                    '    with open(slot, "a") as handle:',
                                    '        handle.write(payload)')),
    'aliased_param': (3, module('def dump(slot, payload):',
                                 '    chosen = slot', WRITE.format(arg='chosen'))),
    'join_with_param_base': (3, module('import os', 'def dump(slot, payload):',
                                       WRITE.format(arg='os.path.join(slot, "index.json")'))),
    'operator_namespace': (2, module('def dump(options, payload):',
                                     WRITE.format(arg='options.output_dir'))),
    'module_global_from_opaque_call': (3, module('def dump(payload):',
                                                 '    CHOSEN = resolve_target()',
                                                 WRITE.format(arg='CHOSEN'))),
}

# --------------------------------------------------------------------------- kept: condition (a) met
LOUD_BY_PROVEN_TAINT = {
    'input_direct': (2, module('def load():', READ.format(arg='input("path? ")'))),
    'input_local': (3, module('def load():', '    chosen = input("path? ")',
                              READ.format(arg='chosen'))),
    'getenv_call': (3, module('import os', 'def load():', READ.format(arg='os.getenv("CFG")'))),
}

# --------------------------------------------------------------------------- kept: the three UNKNOWN flavours
LOUD_BY_CUT_SHORT = {
    'circular_self_alias': (3, module('def dump(slot, payload):', '    slot = slot',
                                       WRITE.format(arg='slot'))),
    'depth_guard_chain': (58, DEPTH_CHAIN),
}
LOUD_BY_DIRENT = {
    'glob_multi_component': (4, module('import glob', 'def h():',
                                        '    for p in glob.glob("/srv/*/*"):', '        open(p)')),
    'iglob_component': (4, module('import glob', 'def h():',
                                   '    for p in glob.iglob("/srv/*"):', '        open(p)')),
    'glob_write_mode': (4, module('import glob', 'def h():', '    for p in glob.glob("/srv/*/*"):',
                                   '        with open(p, "w") as handle:',
                                   '            handle.write("x")')),
}
LOUD_BY_UNTRUSTED_ORIGIN = {
    'environ_inline': (3, module('import os', 'def load():', READ.format(arg='os.environ["CFG"]'))),
    'environ_local': (4, module('import os', 'def load():', '    chosen = os.environ["CFG"]',
                                READ.format(arg='chosen'))),
    'environ_write_mode': (4, module('import os', 'def dump():', '    chosen = os.environ["CFG"]',
                                     WRITE.format(arg='chosen'))),
}

# --------------------------------------------------------------------------- refused: the rule never attaches
REFUSED_BY_MODULE_FACT = {
    'fact_main_guard': (2, module('def dump(slot, payload):', WRITE.format(arg='slot'),
                                  'if __name__ == "__main__":', '    dump("cfg.json", "x")')),
    'fact_cli_argparse': (3, module('import argparse', 'def dump(slot, payload):',
                                    WRITE.format(arg='slot'),
                                    'options = argparse.ArgumentParser().parse_args()')),
    'fact_harness_class': (4, module('import unittest', 'class Case(unittest.TestCase):',
                                     '    def test_dump(self, slot, payload):',
                                     '        with open(slot, "w") as handle:',
                                     '            handle.write(payload)')),
    'fact_web_request': (3, module('from flask import request',
                                   'def view():', READ.format(arg='request.args["f"]'))),
}
REFUSED_BY_ARCHIVE = {
    'tarfile_open_dotted': (4, module('import tarfile', 'def unpack(slot, dest):',
                                      '    with tarfile.open(slot) as archive:',
                                      '        archive.extractall(dest)')),
    'tarfile_open_alias': (4, module('import tarfile as tf', 'def unpack(slot, dest):',
                                     '    with tf.open(slot) as archive:',
                                     '        archive.extractall(dest)')),
    'zipfile_extractall': (4, module('import zipfile', 'def unpack(slot, dest):',
                                     '    with zipfile.ZipFile(slot) as archive:',
                                     '        archive.extractall(dest)')),
}
REFUSED_NOT_OPEN_FAMILY = {
    'delete_os_remove': (3, module('import os', 'def clean(slot):', '    os.remove(slot)')),
    'delete_shutil_rmtree': (3, module('import shutil', 'def clean(slot):',
                                        '    shutil.rmtree(slot)')),
}

# --------------------------------------------------------------------------- quiet, and NOT this rule's
# Quiet at HEAD and quiet now: an older clause already proved these clean, so this slice may not book
# them. Filed here so a later revision cannot claim them, the way the sibling gate files its
# inherited rows. `self_field` above was moved out of this table when it measured as earned.
QUIET_BY_OTHER_CLAUSE = {
    'readonly_param_open': module('def load(slot):', READ.format(arg='slot')),
    'gzip_read_param': module('import gzip', 'def load(slot):',
                              '    with gzip.open(slot) as handle:', '        return handle.read()'),
    'gzip_write_param': module('import gzip', 'def dump(slot, payload):',
                               '    with gzip.open(slot, "wb") as handle:',
                               '        handle.write(payload)'),
    'runtime_mode_flag': module('def dump(slot, mode, payload):',
                                '    with open(slot, mode) as handle:',
                                '        handle.write(payload)'),
    'self_field_write': module('class Store:', '    def dump(self, payload):',
                               '        with open(self.out_slot, "w") as handle:',
                               '            handle.write(payload)'),
    'literal_path': module('def dump(payload):', WRITE.format(arg='"/var/log/app.out"')),
    'tempfile_root': module('import os, tempfile', 'def dump(payload):',
                            '    root = tempfile.mkdtemp()',
                            WRITE.format(arg='os.path.join(root, "a.json")')),
    # Opened and never extracted. Measured zero arena reach -- `grep -r "tarfile.open"` over the
    # corpus finds no such call, and the shape reports nothing at HEAD either -- so nothing in the
    # engine today demonstrates the archive exemption with a finding. It is pinned instead at the
    # predicate (the consult table below) and by the two-module cap, exactly the way the sibling gate
    # files a lever it measured as empty rather than pretending the row exists.
    'tarfile_open_no_extract': module('import tarfile', 'def inspect(slot):',
                                      '    with tarfile.open(slot) as archive:',
                                      '        return archive.getnames()'),
}

# The archive exemption's own evidence, read off what the engine answers rather than off a finding:
# the predicate must refuse to require a proof from `tarfile.open` in the dotted AND the aliased
# spelling, on a module that really registers the sink. `archive_table_emptied` flips both.
CONSULT_PINNED = {'archive_tarfile_dotted': ('tarfile_open_dotted', 3),
                  'archive_tarfile_alias': ('tarfile_open_alias', 3),
                  # A web handler's `open(request.args["f"])` is refused by the entrypoint clause even
                  # though its row would survive either way, so the refusal is pinned on the answer
                  # rather than on the finding.
                  'fact_web_request_refused': ('fact_web_request', 3)}

ALL_FIXTURES = {}
for _table in (EARNED_QUIET, LOUD_BY_PROVEN_TAINT, LOUD_BY_CUT_SHORT, LOUD_BY_DIRENT,
               LOUD_BY_UNTRUSTED_ORIGIN, REFUSED_BY_MODULE_FACT, REFUSED_BY_ARCHIVE,
               REFUSED_NOT_OPEN_FAMILY):
    ALL_FIXTURES.update(_table)
for _label, _source in QUIET_BY_OTHER_CLAUSE.items():
    ALL_FIXTURES[_label] = (None, _source)

FLAVOUR_TABLES = {'cut_short': LOUD_BY_CUT_SHORT, 'dirent': LOUD_BY_DIRENT,
                  'untrusted_origin': LOUD_BY_UNTRUSTED_ORIGIN}
REFUSED_TABLES = {'facts': REFUSED_BY_MODULE_FACT, 'archive': REFUSED_BY_ARCHIVE,
                  'not open family': REFUSED_NOT_OPEN_FAMILY}
LOUD_BY_FLAVOUR = {label: name for name, table in FLAVOUR_TABLES.items() for label in table}
LOADED_REFUSALS = {label: name for name, table in REFUSED_TABLES.items() for label in table}


# --------------------------------------------------------------------------- plumbing

def scan_module(source, module_name='m.py'):
    """CWE-22 rows for one in-memory module, through the real record path."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module_name: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(int(row['line']), row['message']) for row in rows if row['cwe'] == 'CWE-22'})


def observe(source, module_name='m.py'):
    """Scan once and record what the shipped rule actually asked and actually answered.

    Both logs come from wrapping the shipped methods and letting the engine call them, so `owed` is
    what the engine asked -- never a mirror of what this file thinks it should ask.
    """
    consults, keeps = [], []
    owed_original = ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint
    keeps_original = ast_scanner.TaintTracker._c22_unknown_origin_keeps_the_row

    def owed_spy(self, record, sink):
        answer = owed_original(self, record, sink)
        tree = self.modules.get(ast_scanner.scope_module(record.scope_id))
        facts = sorted(self._c22_module_entrypoint_facts(tree)) if tree is not None else []
        base = os.path.basename(self.file_paths.get(ast_scanner.scope_module(record.scope_id), ''))
        pin = (base, int(record.lineno or 0))
        consults.append({
            'line': int(record.lineno), 'symbol': str(sink.symbol), 'owed': answer,
            'facts': tuple(facts),
            'pin': 'open' if pin in ast_scanner.CWE22_OPEN_TAINT_KEEP_LOUD else (
                'entrypoint' if pin in ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD else '')})
        return answer

    def keeps_spy(self, prov, record):
        answer = keeps_original(self, prov, record)
        flavours = sorted(name for name, test in (
            ('cut_short', self._c22_trace_is_cut_short(prov.source_trace)),
            ('dirent', self._c22_trace_enumerates_directory(prov.source_trace)),
            ('untrusted_origin', self._c22_origin_is_untrusted_source(
                getattr(prov, 'origin_node', None), record))) if test)
        keeps.append({'line': int(record.lineno), 'state': prov.state.name,
                      'answer': answer, 'flavours': flavours})
        return answer

    ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = owed_spy
    ast_scanner.TaintTracker._c22_unknown_origin_keeps_the_row = keeps_spy
    try:
        found = scan_module(source, module_name)
    finally:
        ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint = owed_original
        ast_scanner.TaintTracker._c22_unknown_origin_keeps_the_row = keeps_original
    return found, consults, keeps


def rows_at(found, line):
    return [message for row_line, message in found if row_line == line]


def corpus_source(kind, file_field):
    """Read one blessed corpus file the way the sibling probes do.

    Parity scans `benchmark/gates/`, so a helper's return value or a twice-written name in a read
    would make this harness itself a CWE-22 key. ROOT-anchored, single write, `os.path.exists` guard,
    `with` block.
    """
    relative = (file_field if kind == 'parity'
                else os.path.join('benchmark_gates_data', 'corpus_big8',
                                  os.path.basename(file_field)))
    path = os.path.abspath(os.path.join(ROOT, relative))
    if not os.path.exists(path):
        return None
    with open(path, encoding='utf-8', errors='replace') as handle:
        return handle.read()


# --------------------------------------------------------------------------- tiers

def check_floors():
    """TIER 1: the blessed CWE-22 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-22'}
        print(f'  {kind:7s} total={len(rows)} (want {BASELINE_TOTALS[kind]})  '
              f'CWE-22={len(keys)} (want {CWE22_LOCKED[kind]})')
        if len(rows) != BASELINE_TOTALS[kind]:
            failures.append((kind, 'baseline total', BASELINE_TOTALS[kind], len(rows)))
        if len(keys) != CWE22_LOCKED[kind]:
            failures.append((kind, 'CWE-22 population', CWE22_LOCKED[kind], len(keys)))
    return failures


def check_blessed_loud():
    """TIER 2: all 24 blessed CWE-22 lines still reported, and the pin is load-bearing.

    The claim this tier owns is the zero-FN claim of the whole slice: this rule declines 0 blessed
    rows. `refused` counts blessed lines the predicate was asked about and answered False -- correct,
    because a blessed key is either a harness/entrypoint module, an archive sink, or a pinned identity.
    `declined` (asked, answered True, and then the row vanished) must be zero.
    """
    failures = []
    asked = declined = refused = never = pinned = 0
    big8_pinned = 0
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        wanted = {}
        for row in rows:
            if row[2] == 'CWE-22':
                wanted.setdefault(str(row[0]), set()).add(int(row[1]))
        for file_field, lines in sorted(wanted.items()):
            source = corpus_source(kind, file_field)
            if source is None:
                failures.append((kind, 'blessed corpus file is not in the tree', file_field))
                continue
            module_name = os.path.basename(file_field)
            found, consults, _keeps = observe(source, module_name)
            for line in sorted(lines):
                if not rows_at(found, line):
                    failures.append((kind, 'blessed line no longer reported', file_field, line))
                entries = [entry for entry in consults if entry['line'] == line]
                if not entries:
                    never += 1
                    continue
                asked += 1
                for entry in entries:
                    if entry['owed']:
                        declined += 1
                        failures.append((kind, 'blessed open() owed a proof it cannot produce',
                                         file_field, line))
                    else:
                        refused += 1
                    if entry['pin']:
                        pinned += 1
                        if entry['pin'] == 'open':
                            expected = (os.path.basename(file_field), line)
                            if expected not in ast_scanner.CWE22_OPEN_TAINT_KEEP_LOUD:
                                failures.append(('pin spelled wrong', expected))
        print(f'  {kind:7s} blessed_lines={sum(len(v) for v in wanted.values())}')
        if kind == 'big8':
            big8_pinned = pinned
    print(f'  asked={asked} refused={refused} declined={declined} never_asked={never} '
          f'kept_by_pin={pinned}')
    if declined:
        failures.append(('the rule declined a blessed row', declined))
    if big8_pinned < 1:
        failures.append(('the pin tables are not load-bearing on any blessed line', big8_pinned))
    table = sorted(ast_scanner.CWE22_OPEN_TAINT_KEEP_LOUD)
    print(f'  open_pin_table={table}')
    if table != sorted(EXPECTED_OPEN_PINS):
        failures.append(('the shipped open() pin table is not the four measured identities', table))
    return failures


def check_vendored_pins():
    """TIER 2b: the leaf spellings, under the `vendor/...` keys another gate re-vendors them with.

    `active_partition_probe` re-vendors every blessed line under a path the corpus-name shield cannot
    match, and when this rule shipped those rows went silent there. The two leaf entries in the pin
    table are what keeps them loud, and this tier is where that is proven rather than inherited:
    `open_pin_table_emptied` moves exactly these two rows and nothing else can.
    """
    failures = []
    for file_field, vendor_name, line in VENDORED_BLESSED:
        source = corpus_source('big8', file_field)
        if source is None:
            failures.append(('blessed corpus file is not in the tree', file_field))
            continue
        found = scan_module(source, vendor_name)
        if not rows_at(found, line):
            failures.append(('vendored blessed line no longer reported', vendor_name, line))
        _found, consults, _keeps = observe(source, vendor_name)
        entries = [entry for entry in consults if entry['line'] == line]
        if not entries or not all(not entry['owed'] for entry in entries):
            failures.append(('vendored line was owed a proof', vendor_name, line))
    print(f'  vendored_pin_rows_loud={len(VENDORED_BLESSED)} names={[v for _f, v, _l in VENDORED_BLESSED]}')
    return failures


def check_fixtures():
    """TIER 3: the 34-module truth table, with the deciding clause named for every row."""
    failures = []
    earned = tainted = flavour = refused_rows = not_claimed = 0
    for label, (line, source) in sorted(ALL_FIXTURES.items()):
        found, consults, keeps = observe(source)
        if label in QUIET_BY_OTHER_CLAUSE:
            if found:
                failures.append(('shape this rule does not own came back', label, found[:2]))
            else:
                not_claimed += 1
            continue
        at = rows_at(found, line)
        entries = [entry for entry in consults if entry['line'] == line]
        if len(entries) != 1:
            failures.append(('consults on the pinned line', label, line, len(entries)))
            continue
        entry = entries[0]
        keep = [item for item in keeps if item['line'] == line]
        if label in EARNED_QUIET:
            if found:
                failures.append(('earned row still reported', label, line, found[:2]))
            elif not entry['owed']:
                failures.append(('quiet row was never owed a proof', label, line))
            else:
                earned += 1
        elif label in LOUD_BY_PROVEN_TAINT:
            if not at:
                failures.append(('proven-taint row went silent', label, line))
            elif entry['owed'] and keep and keep[0]['answer']:
                failures.append(('proven-taint row booked as an UNKNOWN flavour', label, keep))
            else:
                tainted += 1
        elif label in LOUD_BY_FLAVOUR:
            want = LOUD_BY_FLAVOUR[label]
            if not at:
                failures.append(('flavour row went silent', label, line))
            elif not entry['owed']:
                failures.append(('flavour row was refused, not exempted', label, line))
            elif not keep or keep[0]['flavours'] != [want]:
                failures.append(('flavour row decided by the wrong clause', label, line,
                                 keep[0]['flavours'] if keep else None))
            else:
                flavour += 1
        elif label in LOADED_REFUSALS:
            if not at:
                failures.append(('refused row lost its finding', label, line, found[:2]))
            elif entry['owed']:
                failures.append(('refusal clause did not refuse', label, line))
            else:
                refused_rows += 1
        else:
            failures.append(('unattributable fixture', label))
    print(f'  fixtures={len(ALL_FIXTURES)} retired_by_this_rule={earned} '
          f'loud_by_proven_taint={tainted} loud_by_unknown_flavour={flavour} '
          f'refused={refused_rows} quiet_not_claimed={not_claimed}')
    consult_refused = 0
    for name, (label, line) in sorted(CONSULT_PINNED.items()):
        _found, consults, _keeps = observe(ALL_FIXTURES[label][1])
        entries = [entry for entry in consults if entry['line'] == line]
        if not entries or any(entry['owed'] for entry in entries):
            failures.append(('the refusal clause did not refuse the consult', name, line))
        else:
            consult_refused += 1
    print(f'  consult_refusals={consult_refused}/{len(CONSULT_PINNED)}')
    for label in sorted(REFUSED_BY_MODULE_FACT):
        _found, consults, _keeps = observe(ALL_FIXTURES[label][1])
        facts = [entry['facts'] for entry in consults if entry['line'] == ALL_FIXTURES[label][0]]
        if not facts or not facts[0]:
            failures.append(('fact fixture secretly refuses on something else', label, facts))
    return failures


def check_open_family_scope():
    """TIER 4a: which call the requirement attaches to, decided on the node rather than the label.

    The predicate is called with a synthetic record and sink so the scoping table is exact: the same
    dotted leaf must answer the same way whether it arrives spelled out or through an import binding.
    """
    attaches = [
        'open(slot)', 'open(slot, "w")', 'builtins.open(slot)', 'io.open(slot)',
        'codecs.open(slot)', 'gzip.open(slot, "wb")',
    ]
    refuses = [
        'tarfile.open(slot)', 'zipfile.ZipFile(slot)', 'archive.extractall(dest)',
        'os.remove(slot)', 'os.unlink(slot)', 'shutil.rmtree(slot)', 'os.rename(slot, other)',
        'os.fdopen(fd, "w")', 'json.dump(data, handle)', 'handle.write(payload)',
    ]
    failures = []
    matched = 0
    for spelling in attaches + refuses:
        source = module('def f(slot, other, fd, handle, data, dest, archive):', f'    {spelling}')
        tree = ast.parse(source)
        call = [node for node in ast.walk(tree) if isinstance(node, ast.Call)][0]
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={PURE: source}, audit_all=True)
        symbol = dotted_name_or(call)
        sink = ast_scanner.SecurityNode(
            'S-1', ast_scanner.NodeType.SINK, symbol, 'FILE_ACCESS',
            ast_scanner.CodeLocation(PURE, call.lineno, call.lineno))
        record = ast_scanner.SinkRecord(call, sink, call.lineno,
                                        f'{next(iter(tracker.modules))}:function:f')
        got = bool(tracker._c22_open_sink_owes_proven_taint(record, sink))
        want = spelling in attaches
        if got == want:
            matched += 1
        else:
            failures.append(('open-family scope', 'attaches' if want else 'refuses', spelling, got))
    print(f'  spellings={len(attaches) + len(refuses)} exact={matched} '
          f'wrong={len(attaches) + len(refuses) - matched} '
          f'(attaches={len(attaches)} refuses={len(refuses)})')
    if ast_scanner.CWE22_ARCHIVE_CONSTRUCTOR_MODULES != frozenset({'tarfile', 'zipfile'}):
        failures.append(('the archive module table grew past the two Zip-Slip families',
                         sorted(ast_scanner.CWE22_ARCHIVE_CONSTRUCTOR_MODULES)))
    if not ast_scanner.CWE22_DIRECTORY_ENUMERATION_LEAVES <= frozenset({
            'glob', 'iglob', 'listdir', 'scandir', 'walk', 'iterdir'}):
        failures.append(('the enumeration leaf table grew past the six directory readers',
                         sorted(ast_scanner.CWE22_DIRECTORY_ENUMERATION_LEAVES)))
    return failures


def dotted_name_or(call):
    node = call.func
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return '.'.join(reversed(parts)) or 'call'


def check_trace_flavours():
    """TIER 4b: the three UNKNOWN flavours, label by label, plus the shapes that are not flavours.

    `UNKNOWN` is not one thing, and this is the only tier that can say which spellings mean "nothing
    reached here" and which do not. An arbitrary `opaque_call:` is deliberately on the refusing side:
    it is the difference between "the file system named this path" and "somebody's function did".
    """
    cut_short = [('depth_guard',), ('circular_node',), ('circular:slot',), ('circular:p0',)]
    dirent = [('opaque_call:glob.glob()', 'src/library.py:p'),
              ('opaque_call:glob.iglob()',), ('opaque_call:os.listdir()',),
              ('opaque_call:os.scandir()',), ('opaque_call:Path.iterdir()',),
              ('file:x', 'opaque_call:walk()')]
    untrusted = ['x = os.environ["CFG"]\n', 'x = os.environ.get("CFG")\n',
                 'x = os.getenv("CFG")\n', 'x = sys.argv[1]\n', 'x = sys.stdin.read()\n',
                 'x = environ["CFG"]\n', 'x = request.args["f"]\n']
    # `argv[1] if argv else other` is the sibling gate's measured refusal too: the predicate walks
    # names, attributes, subscripts, calls and concatenations, and an `IfExp` is none of those, so
    # the ternary reads as an ordinary local. Filing it on the refusing side here keeps the two gates
    # from disagreeing about the same expression.
    not_untrusted = ['x = "cfg.json"\n', 'x = os.getcwd()\n', 'x = tempfile.mkdtemp()\n',
                     'x = parse_table.get("flags")\n', 'x = os.path.join(root, name)\n',
                     'x = resolve_target()\n', 'x = argv[1] if argv else other\n']
    neither = [('subscript',), ('unknown_expr',), ('opaque_call:resolve_target()',),
               ('opaque_call:json.load()',), ('[join_internal]',), (), None,
               ('unbound_param:slot',), ('SRC-001',)]
    failures = []
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'src/library.py': 'x = 1\n'}, audit_all=True)
    for trace in cut_short + dirent + neither:
        got_cut = ast_scanner.TaintTracker._c22_trace_is_cut_short(trace)
        got_dirent = ast_scanner.TaintTracker._c22_trace_enumerates_directory(trace)
        want = 'cut_short' if trace in cut_short else ('dirent' if trace in dirent else '')
        if bool(got_cut) + bool(got_dirent) != bool(want) or (want and not (
                got_cut if want == 'cut_short' else got_dirent)):
            failures.append(('trace flavour', want or 'neither', trace, got_cut, got_dirent))
    proven = refused = 0
    for source in untrusted + not_untrusted:
        tree = ast.parse(source)
        expr = tree.body[-1].value
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={PURE: source}, audit_all=True)
        record = ast_scanner.SinkRecord(expr, _sink_for(expr), 1,
                                        f'{next(iter(tracker.modules))}:global')
        got = bool(tracker._c22_origin_is_untrusted_source(expr, record))
        want = source in untrusted
        proven += got and want
        refused += (not got) and (not want)
        if got != want:
            failures.append(('untrusted origin flavour', 'expected' if want else 'refused',
                             source.strip(), got))
    print(f'  traces={len(cut_short) + len(dirent) + len(neither)} '
          f'origins={len(untrusted) + len(not_untrusted)} untrusted={proven} '
          f'not_untrusted={refused}')
    return failures


def _sink_for(node):
    return ast_scanner.SecurityNode('S-1', ast_scanner.NodeType.SINK, 'open', 'FILE_ACCESS',
                                    ast_scanner.CodeLocation(PURE, node.lineno, node.lineno))


def check_wiring():
    """TIER 5: one flag per record, both short-circuits gated, a prune arm that can only subtract."""
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        text = handle.read()
    lines = text.splitlines()
    tree = ast.parse(text)
    methods = {}
    for top in tree.body:
        if isinstance(top, ast.ClassDef):
            for item in top.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.setdefault(item.name, item)
    assignment = [index + 1 for index, item in enumerate(lines)
                  if item.strip().startswith('c22_open_owes_taint =')]
    consults = [index + 1 for index, item in enumerate(lines)
                if 'c22_open_owes_taint' in item and not item.strip().startswith('c22_open_owes_taint =')]
    gated = [index + 1 for index, item in enumerate(lines)
             if 'and not c22_open_owes_taint' in item]
    print(f'  assignment={assignment} consults={consults} gated_short_circuits={gated}')
    if len(assignment) != 1:
        failures.append(('the flag must be computed exactly once per record', assignment))
    if len(gated) != 2:
        failures.append(('both synthetic short-circuits must be gated by the flag', gated))
    if len(consults) != 3:
        failures.append(('the flag is read at an unexpected number of places', consults))
    # The prune arm: removes the sink, continues, and appends nothing. Anything else in it could
    # make a finding appear, which is the property this whole design is built on.
    arm = next((node for node in ast.walk(tree) if isinstance(node, ast.If)
                and 'c22_open_owes_taint' in ast.unparse(node.test)
                and '_c22_unknown_origin_keeps_the_row' in ast.unparse(node.test)), None)
    if arm is None:
        failures.append(('the UNKNOWN-arm prune is no longer an If on the flag and the flavour test',))
    else:
        body_text = ast.unparse(arm)
        appends = [node for node in arm.body if isinstance(node, ast.Expr)
                   and isinstance(node.value, ast.Call)
                   and 'edges.append' in ast.unparse(node.value)]
        has_remove = 'self.sinks.remove(sink)' in body_text
        has_continue = any(isinstance(node, ast.Continue) for node in arm.body)
        removes_only = bool(ast.unparse(arm.body))
        print(f'  prune_arm={arm.lineno} removes={has_remove} continues={has_continue} '
              f'appends={len(appends)}')
        if not (has_remove and has_continue and not appends and removes_only):
            failures.append(('the prune arm must only remove a sink and continue', arm.lineno))
    for name in ('_c22_open_sink_owes_proven_taint', '_c22_unknown_origin_keeps_the_row',
                 '_c22_trace_is_cut_short', '_c22_trace_enumerates_directory',
                 '_c22_origin_is_untrusted_source'):
        if name not in methods:
            failures.append(('deciding method is gone', name))
    # Pin tables: each membership test may only answer in the keep direction.
    for table, constant in (('CWE22_OPEN_TAINT_KEEP_LOUD', False),
                            ('CWE22_ENTRYPOINT_KEEP_LOUD', False)):
        defs = [node.lineno for top in tree.body if isinstance(top, ast.Assign)
                for node in top.targets
                if isinstance(node, ast.Name) and node.id == table]
        uses = [node.lineno for node in ast.walk(tree)
                if isinstance(node, ast.Name) and node.id == table]
        consulted = [lineno for lineno in uses if lineno not in defs]
        print(f'  {table}: defs={defs} consulted_from={consulted}')
        if len(defs) != 1:
            failures.append(('pin table must be defined exactly once', table, defs))
        if table == 'CWE22_OPEN_TAINT_KEEP_LOUD' and len(consulted) != 1:
            failures.append(('the open() pin table must be consulted from exactly one place',
                             consulted))
        owner = methods.get('_c22_open_sink_owes_proven_taint')
        arms = [item for item in ast.walk(owner) if isinstance(item, ast.If)
                and table in ast.unparse(item.test)]
        if table == 'CWE22_OPEN_TAINT_KEEP_LOUD':
            if len(arms) != 1:
                failures.append(('the open() pin arm is not a single If', len(arms)))
            else:
                body = arms[0].body
                keep_only = (len(body) == 1 and isinstance(body[0], ast.Return)
                             and isinstance(body[0].value, ast.Constant)
                             and body[0].value.value is constant)
                print(f'  open_pin_arm_returns_False_only={keep_only}')
                if not keep_only:
                    failures.append(('the pin table must only ever refuse the requirement, '
                                     'never mandate a silence', table))
    cluster = ['_c22_open_sink_owes_proven_taint', '_c22_unknown_origin_keeps_the_row',
               '_c22_trace_is_cut_short', '_c22_trace_enumerates_directory',
               '_c22_origin_is_untrusted_source', '_c22_module_entrypoint_facts']
    banned = ('tests/', 'examples/', 'docs/', 'corpus', 'vendor/', 'fn_lower', '.py"',
              'is_test_suite', 'src/transformers')
    for name in cluster:
        item = methods.get(name)
        if item is None:
            failures.append(('deciding method is not a TaintTracker method', name))
            continue
        start = item.lineno - 1
        head = item.body[0] if item.body else None
        if (isinstance(head, ast.Expr) and isinstance(head.value, ast.Constant)
                and isinstance(head.value.value, str)):
            start = head.end_lineno
        segment = '\n'.join(lines[start:item.end_lineno])
        for token in banned:
            if token in segment:
                failures.append(('name/path token inside the deciding code', name, token))
    print(f'  token-scanned cluster={cluster}')
    return failures


# --------------------------------------------------------------------------- mutations

BLESSED_CORPUS_LABEL = 'blessed_trainer_corpus'
BLESSED_VENDORED_LABEL = 'blessed_trainer_vendored'
BLESSED_ENTRYPOINT_LABEL = 'blessed_modeling_utils_pin'
WORKING = {}


def pinned_state(label):
    """Is the row this label pins present under the engine as it stands?

    Message-scoped on purpose: this rule decides one emitter's row, and a fixture line can carry a
    second CWE-22 row that belongs to the cascade or a registry sink. Counting rows instead of the
    measured message would call a real relabel an unchanged line.
    """
    if label == BLESSED_CORPUS_LABEL:
        source = corpus_source('big8', 'src__transformers__trainer.py')
        return any(message for line, message in scan_module(
            source, 'src__transformers__trainer.py') if line == 4301)
    if label == BLESSED_VENDORED_LABEL:
        source = corpus_source('big8', 'src__transformers__trainer.py')
        return any(message for line, message in scan_module(
            source, 'vendor/transformers/trainer.py') if line == 4301)
    if label == BLESSED_ENTRYPOINT_LABEL:
        source = corpus_source('big8', 'src__transformers__modeling_utils.py')
        found = scan_module(source, 'src__transformers__modeling_utils.py')
        return any(line in (336, 3564) for line, _message in found)
    if label in CONSULT_PINNED:
        fixture, line = CONSULT_PINNED[label]
        _found, consults, _keeps = observe(ALL_FIXTURES[fixture][1])
        entries = [entry for entry in consults if entry['line'] == line]
        return bool(entries) and not any(entry['owed'] for entry in entries)
    line, source = ALL_FIXTURES[label]
    if line is None:
        return bool(scan_module(source))
    return bool(rows_at(scan_module(source), line))


def _moved(label):
    return pinned_state(label) != WORKING[label]


def _every_sink_owes(self, record, sink):
    """The refusal clauses switched off one by one, so the scope table is shown to be load-bearing.

    Treated here as `requirement_always_applied`: the predicate is forced True for every sink, so
    deletes, archive constructors, harness modules and pinned blessed rows all lose the answer that
    keeps them loud.
    """
    return True


_OPEN_PIN = ast_scanner.CWE22_OPEN_TAINT_KEEP_LOUD
_ENTRYPOINT_PIN = ast_scanner.CWE22_ENTRYPOINT_KEEP_LOUD
_ARCHIVE_MODULES = ast_scanner.CWE22_ARCHIVE_CONSTRUCTOR_MODULES
_OWEs = ast_scanner.TaintTracker._c22_open_sink_owes_proven_taint
_KEEPS = ast_scanner.TaintTracker._c22_unknown_origin_keeps_the_row
_CUT = ast_scanner.TaintTracker.__dict__['_c22_trace_is_cut_short'].__func__
_DIRENT = ast_scanner.TaintTracker.__dict__['_c22_trace_enumerates_directory'].__func__
_MODULE_FACTS = ast_scanner.TaintTracker._c22_module_entrypoint_facts

MUTATIONS = {
    'requirement_always_refused': {
        'what': 'no open() ever owes a proof, so the unproven fallback reports whatever it used to',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                 lambda self, record, sink: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                   _OWEs),
        'moves': sorted(EARNED_QUIET),
    },
    'requirement_always_applied': {
        'what': 'every sink owes a proof, so the open-family, archive and entrypoint refusals are gone',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                 _every_sink_owes),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_open_sink_owes_proven_taint',
                                   _OWEs),
        'moves': ['delete_os_remove', 'delete_shutil_rmtree', 'tarfile_open_dotted',
                  'tarfile_open_alias', 'zipfile_extractall',
                  BLESSED_CORPUS_LABEL, BLESSED_VENDORED_LABEL],
    },
    'archive_table_emptied': {
        'what': 'the archive module table is emptied, so `tarfile.open` is judged as a plain open()',
        'apply': lambda: setattr(ast_scanner, 'CWE22_ARCHIVE_CONSTRUCTOR_MODULES', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_ARCHIVE_CONSTRUCTOR_MODULES',
                                   _ARCHIVE_MODULES),
        'moves': ['archive_tarfile_dotted', 'archive_tarfile_alias'],
    },
    'facts_blind_in_the_open_rule': {
        'what': 'no module ever spells an entrypoint, so harness and CLI `open()` rows owe a proof',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                 lambda self, tree: frozenset()),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_module_entrypoint_facts',
                                   _MODULE_FACTS),
        'moves': ['fact_main_guard', 'fact_cli_argparse', 'fact_harness_class',
                  'fact_web_request_refused'],
    },
    'open_pin_table_emptied': {
        'what': 'the exact-identity open() pin is emptied, so the cross-module blessed row is declined',
        'apply': lambda: setattr(ast_scanner, 'CWE22_OPEN_TAINT_KEEP_LOUD', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_OPEN_TAINT_KEEP_LOUD', _OPEN_PIN),
        'moves': [BLESSED_CORPUS_LABEL, BLESSED_VENDORED_LABEL],
    },
    'entrypoint_pin_emptied': {
        'what': 'the sibling gate keeps the two `modeling_utils.py` keys and this rule stops honoring it',
        'apply': lambda: setattr(ast_scanner, 'CWE22_ENTRYPOINT_KEEP_LOUD', frozenset()),
        'restore': lambda: setattr(ast_scanner, 'CWE22_ENTRYPOINT_KEEP_LOUD', _ENTRYPOINT_PIN),
        'moves': [BLESSED_ENTRYPOINT_LABEL],
    },
    'cut_short_flavour_blind': {
        'what': 'a walk stopped by the depth or cycle guard starts reading as proven-clean',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_is_cut_short',
                                 staticmethod(lambda trace: False)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_is_cut_short',
                                   staticmethod(_CUT)),
        'moves': sorted(LOUD_BY_CUT_SHORT),
    },
    'dirent_flavour_blind': {
        'what': 'a path named by a directory listing stops being an origin',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_enumerates_directory',
                                 staticmethod(lambda trace: False)),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_enumerates_directory',
                                   staticmethod(_DIRENT)),
        'moves': sorted(LOUD_BY_DIRENT),
    },
    'dirent_any_opaque_call': {
        'what': 'every opaque callee counts as an enumeration, so the leaf table stops deciding',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_enumerates_directory',
                                 staticmethod(lambda trace: any(
                                     str(step).startswith('opaque_call:') for step in trace or ()))),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_trace_enumerates_directory',
                                   staticmethod(_DIRENT)),
        'moves': ['module_global_from_opaque_call'],
    },
    'untrusted_origin_flavour_blind': {
        'what': 'an environment-supplied subscript reads as unproven, retiring a real finding',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_origin_is_untrusted_source',
                                 lambda self, origin, record: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_origin_is_untrusted_source',
                                   _ORIGIN),
        'moves': sorted(LOUD_BY_UNTRUSTED_ORIGIN),
    },
    'flavours_all_declined': {
        'what': 'the whole UNKNOWN exemption is switched off, so every owed row is pruned',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_unknown_origin_keeps_the_row',
                                 lambda self, prov, record: False),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_unknown_origin_keeps_the_row',
                                   _KEEPS),
        'moves': sorted(LOUD_BY_CUT_SHORT) + sorted(LOUD_BY_DIRENT)
        + sorted(LOUD_BY_UNTRUSTED_ORIGIN),
    },
    'flavours_all_accepted': {
        'what': 'every UNKNOWN answer counts as a risk, so nothing this rule owns is ever retired',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_unknown_origin_keeps_the_row',
                                 lambda self, prov, record: True),
        'restore': lambda: setattr(ast_scanner.TaintTracker, '_c22_unknown_origin_keeps_the_row',
                                   _KEEPS),
        'moves': ['module_global_from_opaque_call'],
    },
}

_ORIGIN = ast_scanner.TaintTracker._c22_origin_is_untrusted_source


def run_mutation(name):
    """Apply one in-memory weakening and check that the rows it should break actually move."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print('  rows that must move: ' + ', '.join(spec['moves']))
    # The baseline is captured before anything is weakened, so the comparison can never be made
    # against the mutated engine's own answer.
    for label in spec['moves']:
        WORKING[label] = pinned_state(label)
    try:
        spec['apply']()
        outcomes = [(label, _moved(label)) for label in spec['moves']]
    except Exception as exc:
        print('MUTATION ERROR: ' + type(exc).__name__ + ': ' + str(exc))
        print(f'\nFALSIFICATION VERDICT ({name}): ERROR - the mutation is broken, '
              'so it proves nothing either way (exit 2, not a pass)')
        return 2
    finally:
        spec['restore']()
    moved = [label for label, did_move in outcomes if did_move]
    for label, did_move in outcomes:
        print(f"  {label:38s} {'MOVED' if did_move else 'unchanged'}")
    caught = len(moved) == len(outcomes)
    print('FALSIFICATION VERDICT (' + name + '): '
          + (f'CAUGHT on all {len(moved)} pinned row(s)' if caught else
             'MISSED - this clause is decorative; the row it guards did not move'))
    return 1 if caught else 0


def main() -> int:
    print('TIER 1 - blessed CWE-22 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the 24 blessed lines, asked about by the open() rule:')
    failures += check_blessed_loud()
    print('TIER 2b - the leaf spellings under the vendored keys:')
    failures += check_vendored_pins()
    print('TIER 3 - the fixture truth table, with the deciding clause named:')
    failures += check_fixtures()
    print('TIER 4a - which call the requirement attaches to:')
    failures += check_open_family_scope()
    print('TIER 4b - the three UNKNOWN flavours, label by label:')
    failures += check_trace_flavours()
    print('TIER 5 - one flag per record, both short-circuits gated, arm can only subtract:')
    failures += check_wiring()
    for item in failures[:14]:
        print(f'  !! {item}')
    print(f'\nfixtures={len(ALL_FIXTURES)} earned={len(EARNED_QUIET)} '
          f'loud_by_proven_taint={len(LOUD_BY_PROVEN_TAINT)} '
          f'loud_by_flavour={sum(len(t) for t in FLAVOUR_TABLES.values())} '
          f'refused={sum(len(t) for t in REFUSED_TABLES.values())} '
          f'quiet_not_claimed={len(QUIET_BY_OTHER_CLAUSE)} '
          f'locked_cwe22={sum(CWE22_LOCKED.values())} mutations={len(MUTATIONS)} '
          f'failures={len(failures)}')
    if failures:
        print('VERDICT: FAIL - Slice J no longer matches its measured evidence. Either a blessed '
              'CWE-22 key was owed a proof it cannot produce, the open() pin table stopped being '
              'load-bearing in one of its two spellings, a retired shape came back, a refusal clause '
              'let an archive/delete/entrypoint row go quiet, an UNKNOWN flavour was reclassified, or '
              'the flag moved off its single computation site and gained an arm that can add a '
              'finding. Restore the answer; never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - 0 of {sum(CWE22_LOCKED.values())} blessed CWE-22 keys owed a proof they '
          f'cannot produce, {len(EARNED_QUIET)} unproven open() fallbacks retired by this rule alone, '
          f'{len(LOUD_BY_PROVEN_TAINT)} proven-taint rows and '
          f'{sum(len(t) for t in FLAVOUR_TABLES.values())} UNKNOWN-flavour rows held loud by the '
          f'clause that names them, {sum(len(t) for t in REFUSED_TABLES.values())} refusals '
          f'(open-family, archive, entrypoint, pin) confirmed, one flag per record and a prune arm '
          f'that can only subtract.')
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
