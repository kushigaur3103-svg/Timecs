"""Gate #68 -- the three Ansible v2.16.5 root causes, each held by its own falsifier.

All thirteen rows were fetched verbatim from the Ansible tree at 971e4d7 and replayed here as local
fixtures. Every clause below answers on the scanned source's own AST or literal text: a resolved
canonical name, an element-name vocabulary, a regex capture-group opener, a substitution marker, or
the joined argument's own SQL text. No clause reads a filename, a repository name or a folder.

  P1  BUILTIN-FOLDED LOCAL ALIAS (CWE-611). `incidental.py:368` writes `parse = tuple` in one branch
      and `parse = int` in the other, then calls `parse(v)`. `parse` is a CWE-611 sink LEAF, and the
      alias resolved it to the bare canonical name `int`. `_xml_sink_recognised` read every dotless
      name as "unresolved, cannot disprove" and reported `CWE-611: int` on a type conversion. A bare
      builtin IS resolved: `_t25_builtin_alias_refused` answers on the fourteen builtin
      type/conversion names and nothing else, so an unknown bare alias still reports.
      LOUD CONTROLS: `parse = xml.etree.ElementTree.fromstring; parse(user_xml)` and
      `import xml.etree.ElementTree as int; int.fromstring(user_xml)` -- the parser identity outranks
      the spelling it was imported under, and neither canonical name is dotless.

  P2  NON-ELEMENT MARKUP (CWE-79). `_MARKUP_SHAPE_RE` accepted ANY `<word>`, so a regex capture
      group, a CLI help placeholder and an object repr all read as HTML. Three independent clauses:
        (a) `strip_regex_named_groups` drops `(?P<name>` / `(?<name>` openers. `replace.py:268,270,
            272,281` are `u'%s(?P<subsection>.*?)%s'` patterns; line 281 reports through the `pattern`
            name hop, so it retires with them.
        (b) `HTML_ELEMENT_NAMES` + `_markup_name_is_element` confirm the pre-filter's hits against the
            HTML/SVG/MathML vocabulary, case-insensitively, plus hyphenated WHATWG custom elements.
            `<namespace>.<collection>` (collection/__init__.py:797), `<Response %d, %r %r, ...>`
            (winrm.py:661) and `<virtual namespace from {src!s} ...>` (dataclasses.py:523) name no
            element. `s` and `mask` ARE elements and stay reported, exactly as
            SUBWORD_CONTROL_SYMBOL_LITERALS already reasons.
        (c) `_MARKUP_TEMPLATE_HOLE` is a SECOND sentinel, not accepted as a tag name. `markup_skeleton`
            still writes `_MARKUP_HOLE` where the AST puts a runtime value in the name slot, so
            `f"<{tag}>{content}</{tag}>"` stays loud (blessed: cwe_79_xss/test_v02_bad.py:2 and
            test_v03_bad.py:3). `fold_markup_holes` writes the template sentinel over a literal's
            `%s`/`{}` markers, so `"<%s> %s" % (host, msg)` (display.py:460) is the CLI placeholder it
            is. `<%s>` appears in NEITHER blessed corpus; `<{` appears only in those three f-strings.
      `raise SomeError(...)` needs no new clause: the shipped `in_raise and _tag_free_payload(arg)`
      guard already asks `text_has_markup_shape`, so (b) retires the exception row through the grammar.
      LOUD CONTROLS: all eight mandated shapes -- `<div>` f-string, `<script>` concatenation,
      `<p>%s</p>`, `<a href='%s'>`, `<img src=%s>`, `HttpResponse(f"<span>...")`,
      `mark_safe(f"<b>...")`, `Markup(f"<li>...")` -- plus the dynamic-tag f-string, a hyphenated
      custom element and an SVG fragment.

  P3  NON-SQL `.join` (CWE-89). `builder_attrs` carries `join` because a SQL query builder spells it
      too, and the collector exempted only a CONSTANT or `os.sep`/`os.linesep` receiver from the
      SQL-shape-or-DB-receiver requirement. `filter/core.py:441` writes `p['newline'].join([''] +
      [p['postfix'] for x in range(...)])`: an `ast.Subscript` receiver fell through the exemption,
      so a list concatenation with no SQL verb and no database anywhere near it reported
      `SQL_QUERY_EXECUTION` CRITICAL on BOTH the call line and the argument line (`_emit89` emits on
      each). `_t25_builder_needs_sql_proof` completes that exemption with the SUBSCRIPT spelling, so
      a separator fetched from a mapping demands SQL proof exactly like a literal one does. It is
      deliberately NOT a blanket rule on every `join`: `URL(base).join(route)` has a CALL receiver,
      is not a separator shape, and must keep the function-wide evidence sweep --
      `cwe89_path_interpolation_probe.py` seals four such routes LOUD (`plain_text_chunk`,
      `verb_in_function`, `db_word_in_function`, `giant_function_cap`), and a blanket rule silenced
      all four. `execute_attrs` is exact set membership, so `executable` can never match
      `execute` -- there is no substring test to fix.
      LOUD CONTROLS: `cursor.execute("SELECT ... %s" % uid)`, `cursor.execute(f"DELETE ...")`,
      `db.execute(" ".join(["SELECT * FROM t WHERE id =", uid]))` (the execute path, and the joined
      argument carries the verb), `User.objects.raw(f"SELECT ...")`, and a bare join whose argument
      DOES carry SQL text.

Honest limits, measured rather than assumed. TWELVE of the thirteen rows reproduced against a real
HEAD checkout (`git worktree --detach` at 5b2cb2f). ONE did not, and is booked as a CONTROL, not credit:
  * `process.py:44` (`raise ValueError('Failed to find required executable "%s" in paths: %s' %
    (arg, os.pathsep.join(paths)))`) is QUIET at HEAD and stays QUIET with the full HEAD grammar
    restored by the arms. `os.pathsep` is an `ast.Attribute` whose leaf is `pathsep`, not
    `sep`/`linesep`, so it took the exempt branch -- but `_is_string_construction` never accepted the
    tuple operand, so no row was produced. The clause still ships, because that same exemption is
    what `p['newline']` escaped through.
An earlier harness run booked `paramiko_ssh.py:534` as unreproducible. That was a FIXTURE bug, not an
engine fact: its `\n` sat inside a non-raw triple-quoted string, so it became a real newline inside a
single-quoted literal, the module never parsed, and zero rows read as a quiet verdict. Written with
chr(92) it reports DYNAMIC_HTML_CONSTRUCTION at HEAD and is BOOKED here. TIER 0 now parses every
fixture, so this class of false QUIET cannot recur.
`!doctype` is deliberately NOT added to the vocabulary: `_MARKUP_SHAPE_RE` requires an ASCII letter
or `/` immediately after `<`, so `<!doctype html>` never matched at HEAD and adding it would create
NEW rows, breaking the monotonic-FP law. A literal template whose whole tag name is a `{}` format
marker is refused along with `%s`; no blessed key uses either, and the AST f-string hole is kept.
A bare `" ".join([...])` whose argument is a LIST is quiet at HEAD too -- `_is_string_construction`
does not read a list literal -- so the SQL-text join control uses a `+` concatenation, which is the
shape that actually reaches the guard.

Measured BEFORE -> AFTER against the HEAD worktree, over the nine verbatim reproducer groups and their
nine tainted twins: 24 rows -> 0, 0 new, 18/18 fixtures silent. All fourteen loud controls keep their
exact line, CWE, message, severity and confidence.

TIER 0 parses every fixture. TIER 1 reads every case twice against one shared fixture: its shipped
verdict, and its verdict with the owning clause reverted. TIER 1b asserts the verbatim fixtures produce
ZERO rows of any CWE. TIER 2 calls the shipped predicates directly. TIER 3 reads the shipped source and
asks it to keep the shape each proof depends on. TIER 4 is the falsifiers: one weakening per clause, and
an exact set of rows and predicates must move.

Usage: python benchmark/gates/ansible_rootcause_fp_probe.py [--dump] [--mutate=<name>]
"""
from __future__ import annotations

import ast
import contextlib
import gc
import inspect
import io as _io
import os
import sys
import time

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
import rule_engine  # noqa: E402

T = ast_scanner.TaintTracker
OWNERS = {'T': T, 'ast_scanner': ast_scanner, 'rule_engine': rule_engine}

BUDGET_SECONDS = 240.0
BUDGET_MUTATION_SECONDS = 60.0
BUDGET_RSS_MB = 60.0


def module(*lines):
    return ''.join(line + '\n' for line in lines)


def at(source, needle, offset=0):
    """The line of a unique needle, so a fixture is read instead of hand-counted."""
    lines = [index for index, text in enumerate(source.splitlines(), 1) if needle in text]
    if len(lines) != 1:
        raise AssertionError(f'{needle!r} matched {len(lines)} lines, need exactly 1')
    return lines[0] + offset


def link(tree):
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    return tree


_CACHE = {}


def scan_rows(source, state='ship', name='m.py'):
    """(name, line, cwe) for one fixture file, every clause in its shipped position."""
    key = ('scan', state, source, name)
    if key in _CACHE:
        return _CACHE[key]
    with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
        tracker = T(files={name: source}, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = sorted({(name, int(row['line']), row['cwe'])
                       for row in cli._findings_for(tracker, edges)})
    _CACHE[key] = rows
    return rows


def loud(rows, name, cwe, line):
    return (name, line, cwe) in rows


CASES = []


def case(pocket, label, cwe, name, line, expect, arm, arm_expect, source, note=''):
    CASES.append({'pocket': pocket, 'label': label, 'source': source, 'cwe': cwe, 'name': name,
                  'line': line, 'expect': expect, 'arm': arm, 'arm_expect': arm_expect,
                  'note': note})


def rows_for(entry, state='ship'):
    return scan_rows(entry['source'], state, entry['name'])


# --------------------------------------------------------------------------- P1 fixtures
# Verbatim ansible/module_utils/common/text/converters.py -> incidental.py:368 shape.
BUG1_INCIDENTAL = module(
    'def load(coverage_points, is_arcs):',
    '    if is_arcs:',
    '        parse = tuple',
    '    else:',
    '        parse = int',
    '    return set(parse(v) for v in coverage_points)')
BUG1_TAINTED = module(
    'def load(request, is_arcs):',
    '    coverage_points = request.GET["c"]',
    '    if is_arcs:',
    '        parse = tuple',
    '    else:',
    '        parse = int',
    '    return set(parse(v) for v in coverage_points)')
BUG1_TUPLE = module(
    'def load(coverage_points):',
    '    parse = tuple',
    '    return set(parse(v) for v in coverage_points)')
BUG1_STR = module(
    'def load(request):',
    '    parse = str',
    '    return parse(request.GET["x"])')
L_PARSE_XML_ALIAS = module(
    'import xml.etree.ElementTree', '',
    'def go(request):',
    '    parse = xml.etree.ElementTree.fromstring',
    '    return parse(request.GET["x"])')
L_INT_MODULE_ALIAS = module(
    'import xml.etree.ElementTree as int', '',
    'def go(request):',
    '    return int.fromstring(request.GET["x"])')
L_ETREE_FROMSTRING = module(
    'import xml.etree.ElementTree as ET', '',
    'def go(request):',
    '    return ET.fromstring(request.GET["x"])')
BARE_INT_CALL = module(
    'def go(request):',
    '    return int(request.GET["x"])')
UNKNOWN_BARE_ALIAS = module(
    'def go(request):',
    '    parse = mystery_callable',
    '    return parse(request.GET["x"])')

case('P1', 'builtin_int_alias_retired', 'CWE-611', 'm.py',
     at(BUG1_INCIDENTAL, 'return set(parse(v)'), 'quiet', 'builtin_alias_off_arm', 'loud',
     BUG1_INCIDENTAL, 'incidental.py:368 verbatim')
case('P1', 'builtin_int_alias_tainted_retired', 'CWE-611', 'm.py',
     at(BUG1_TAINTED, 'return set(parse(v)'), 'quiet', 'builtin_alias_off_arm', 'loud',
     BUG1_TAINTED, 'same, operands from the request')
case('P1', 'builtin_tuple_alias_retired', 'CWE-611', 'm.py',
     at(BUG1_TUPLE, 'return set(parse(v)'), 'quiet', 'builtin_alias_off_arm', 'loud',
     BUG1_TUPLE, 'the other branch of the same if')
case('P1', 'builtin_str_alias_retired', 'CWE-611', 'm.py',
     at(BUG1_STR, 'return parse(request'), 'quiet', 'builtin_alias_off_arm', 'loud',
     BUG1_STR, 'every builtin conversion, not just int')
case('P1', 'xml_parser_alias_kept', 'CWE-611', 'm.py',
     at(L_PARSE_XML_ALIAS, 'return parse(request'), 'loud', 'builtin_alias_off_arm', 'loud',
     L_PARSE_XML_ALIAS, 'MANDATED loud control')
case('P1', 'xml_module_named_int_kept', 'CWE-611', 'm.py',
     at(L_INT_MODULE_ALIAS, 'return int.fromstring'), 'loud', 'builtin_alias_off_arm', 'loud',
     L_INT_MODULE_ALIAS, 'MANDATED loud control')
case('P1', 'etree_fromstring_kept', 'CWE-611', 'm.py',
     at(L_ETREE_FROMSTRING, 'return ET.fromstring'), 'loud', 'builtin_alias_off_arm', 'loud',
     L_ETREE_FROMSTRING, 'the plain aliased parser')
case('P1', 'bare_builtin_call_control', 'CWE-611', 'm.py',
     at(BARE_INT_CALL, 'return int(request'), 'quiet', 'builtin_alias_off_arm', 'quiet',
     BARE_INT_CALL, 'already quiet at HEAD: TASK 24 callee-leaf clause')
case('P1', 'unknown_bare_alias_kept', 'CWE-611', 'm.py',
     at(UNKNOWN_BARE_ALIAS, 'return parse(request'), 'loud', 'builtin_alias_off_arm', 'loud',
     UNKNOWN_BARE_ALIAS, 'the narrowing is builtin-only')

# --------------------------------------------------------------------------- P2 fixtures
# Verbatim ansible/modules/replace.py:268,270,272,281.
REPLACE_PATTERN = module(
    'def go(params):',
    "    pattern = u'%s(?P<subsection>.*?)%s' % (params['after'], params['before'])",
    "    pattern = u'%s(?P<subsection>.*)' % params['after']",
    "    pattern = u'(?P<subsection>.*)%s' % params['before']",
    '    res_args = {}',
    "    res_args['msg'] = 'Pattern for before/after params did not match the given file: %s' % pattern",
    '    return res_args')
REPLACE_TAINTED = module(
    'def go(request):',
    '    params = request.GET',
    "    pattern = u'%s(?P<subsection>.*?)%s' % (params['after'], params['before'])",
    "    pattern = u'%s(?P<subsection>.*)' % params['after']",
    "    pattern = u'(?P<subsection>.*)%s' % params['before']",
    '    res_args = {}',
    "    res_args['msg'] = 'Pattern for before/after params did not match the given file: %s' % pattern",
    '    return res_args')
# A capture label that IS an element name: only the regex clause can retire this one, so it is the
# independent falsifier for `strip_regex_named_groups`.
REGEX_ELEMENT_LABEL = module(
    'def go(params):',
    "    pattern = u'%s(?P<div>.*?)%s' % (params['after'], params['before'])",
    '    return pattern')
REGEX_SHORT_LABEL = module(
    'def go(params):',
    "    pattern = u'(?<span>.*)%s' % params['before']",
    '    return pattern')
# Verbatim ansible/plugins/connection/paramiko_ssh.py:534. The `\n` is written with chr(92) so the
# fixture source carries a two-character escape, not a real newline inside a single-quoted literal.
PARAMIKO_SSH = module(
    'def go(u, addr, port, msg):',
    "    msg = 'ssh %s@%s:%s : %s" + chr(92) + "nTo connect as a different user, use -u <username>.' "
    '% (u, addr, port, msg)',
    '    raise AnsibleConnectionFailure(msg)')
# Verbatim ansible/plugins/filter/core.py -> collection/__init__.py:797.
COLLECTION_ERROR = module(
    'def go(name):',
    '    raise AnsibleError("Invalid collection name \'%s\', name must be in the format '
    '<namespace>.<collection>." % name)')
COLLECTION_TAINTED = module(
    'def go(request):',
    '    name = request.GET["n"]',
    '    raise AnsibleError("Invalid collection name \'%s\', name must be in the format '
    '<namespace>.<collection>." % name)')
# Verbatim ansible/plugins/connection/winrm.py:661.
WINRM_DISPLAY = module(
    'def go(rc, stdout, stderr, h):',
    "    display.vvvvv('WINRM RESULT <Response %d, %r %r, code err out>' % (rc, stdout, stderr), host=h)")
WINRM_TAINTED = module(
    'def go(request):',
    '    rc, stdout, stderr, h = request.GET["r"], request.GET["o"], request.GET["e"], request.GET["h"]',
    "    display.vvvvv('WINRM RESULT <Response %d, %r %r, code err out>' % (rc, stdout, stderr), host=h)")
# Verbatim ansible/utils/display.py:460.
DISPLAY_PREFIX = module(
    'def go(self, host, msg, color, to_stderr):',
    '    self.display("<%s> %s" % (host, msg), color=color, stderr=to_stderr)')
DISPLAY_TAINTED = module(
    'def go(self, request, color, to_stderr):',
    '    host, msg = request.GET["h"], request.GET["m"]',
    '    self.display("<%s> %s" % (host, msg), color=color, stderr=to_stderr)')
# Verbatim ansible/module_utils/common/dataclasses.py:523 (a __repr__ body).
VIRTUAL_NAMESPACE = module(
    'def go(src, src_type):',
    "    return '<virtual namespace from {src!s} of type {src_type!s}>'.format(src=src, src_type=src_type)")
VIRTUAL_TAINTED = module(
    'def go(request):',
    '    src, src_type = request.GET["s"], request.GET["t"]',
    "    return '<virtual namespace from {src!s} of type {src_type!s}>'.format(src=src, src_type=src_type)")

for needle, label in (('(?P<subsection>.*?)', 'l268'),
                      ('%s(?P<subsection>.*)', 'l270'),
                      ('(?P<subsection>.*)%s', 'l272')):
    case('P2', f'regex_named_group_retired_{label}', 'CWE-79', 'm.py',
         at(REPLACE_PATTERN, needle), 'quiet', 'regex_and_vocab_off_arm', 'loud',
         REPLACE_PATTERN, f'replace.py:{label[1:]} verbatim')
case('P2', 'regex_msg_name_hop_retired_l281', 'CWE-79', 'm.py',
     at(REPLACE_PATTERN, "res_args['msg']"), 'quiet', 'regex_and_vocab_off_arm', 'loud',
     REPLACE_PATTERN, 'replace.py:281, reports through the pattern name')
case('P2', 'regex_named_group_tainted_retired', 'CWE-79', 'm.py',
     at(REPLACE_TAINTED, '(?P<subsection>.*?)'), 'quiet', 'regex_and_vocab_off_arm', 'loud',
     REPLACE_TAINTED, 'same, params from the request')
case('P2', 'regex_element_label_retired', 'CWE-79', 'm.py',
     at(REGEX_ELEMENT_LABEL, 'pattern = u'), 'quiet', 'regex_group_off_arm', 'loud',
     REGEX_ELEMENT_LABEL, 'independent falsifier: the label IS an element')
case('P2', 'regex_short_label_retired', 'CWE-79', 'm.py',
     at(REGEX_SHORT_LABEL, 'pattern = u'), 'quiet', 'regex_group_off_arm', 'loud',
     REGEX_SHORT_LABEL, 'the regex module spelling (?<name>')
case('P2', 'ssh_help_placeholder_retired', 'CWE-79', 'm.py',
     at(PARAMIKO_SSH, 'msg = '), 'quiet', 'markup_vocab_off_arm', 'loud',
     PARAMIKO_SSH, 'paramiko_ssh.py:534 verbatim')
case('P2', 'cli_placeholder_error_retired', 'CWE-79', 'm.py',
     at(COLLECTION_ERROR, 'raise AnsibleError'), 'quiet', 'markup_vocab_off_arm', 'loud',
     COLLECTION_ERROR, 'collection/__init__.py:797 verbatim')
case('P2', 'cli_placeholder_error_tainted_retired', 'CWE-79', 'm.py',
     at(COLLECTION_TAINTED, 'raise AnsibleError'), 'quiet', 'markup_vocab_off_arm', 'loud',
     COLLECTION_TAINTED, 'same, name from the request')
case('P2', 'debug_repr_placeholder_retired', 'CWE-79', 'm.py',
     at(WINRM_DISPLAY, 'display.vvvvv'), 'quiet', 'markup_vocab_off_arm', 'loud',
     WINRM_DISPLAY, 'winrm.py:661 verbatim')
case('P2', 'debug_repr_placeholder_tainted_retired', 'CWE-79', 'm.py',
     at(WINRM_TAINTED, 'display.vvvvv'), 'quiet', 'markup_vocab_off_arm', 'loud',
     WINRM_TAINTED, 'same, operands from the request')
case('P2', 'printf_hole_display_retired', 'CWE-79', 'm.py',
     at(DISPLAY_PREFIX, 'self.display'), 'quiet', 'template_hole_off_arm', 'loud',
     DISPLAY_PREFIX, 'display.py:460 verbatim')
case('P2', 'printf_hole_display_tainted_retired', 'CWE-79', 'm.py',
     at(DISPLAY_TAINTED, 'self.display'), 'quiet', 'template_hole_off_arm', 'loud',
     DISPLAY_TAINTED, 'same, operands from the request')
case('P2', 'format_repr_placeholder_retired', 'CWE-79', 'm.py',
     at(VIRTUAL_NAMESPACE, 'return '), 'quiet', 'markup_vocab_off_arm', 'loud',
     VIRTUAL_NAMESPACE, 'dataclasses.py:523 verbatim')
case('P2', 'format_repr_placeholder_tainted_retired', 'CWE-79', 'm.py',
     at(VIRTUAL_TAINTED, 'return '), 'quiet', 'markup_vocab_off_arm', 'loud',
     VIRTUAL_TAINTED, 'same, operands from the request')

# The eight mandated loud controls, verbatim from the task.
L_DIV_FSTRING = module('def go(request):', '    return HttpResponse(f"<div>{request.GET[\'x\']}</div>")')
L_SCRIPT_CONCAT = module('def go(request):', '    x = request.GET["x"]',
                         '    return "<script>" + x + "</script>"')
L_P_PERCENT = module('def go(request):', '    return "<p>%s</p>" % request.GET["u"]')
L_A_HREF = module('def go(request):', '    return "<a href=\'%s\'>click</a>" % request.GET["url"]')
L_IMG_SRC = module('def go(request):', '    return "<img src=%s>" % request.GET["x"]')
L_SPAN_RESPONSE = module('from django.http import HttpResponse', '', 'def go(request):',
                         '    return HttpResponse(f"<span>{request.GET[\'x\']}</span>")')
L_MARK_SAFE_B = module('from django.utils.safestring import mark_safe', '', 'def go(request):',
                       '    return mark_safe(f"<b>{request.GET[\'x\']}</b>")')
L_MARKUP_LI = module('from markupsafe import Markup', '', 'def go(request):',
                     '    return Markup(f"<li>{request.GET[\'x\']}</li>")')
L_DYNAMIC_TAG = module('def go(request):', '    tag = request.GET["t"]',
                       '    content = request.GET["c"]', '    return f"<{tag}>{content}</{tag}>"')
L_CUSTOM_ELEMENT = module('def go(request):', '    x = request.GET["x"]',
                          '    return f"<my-widget>{x}</my-widget>"')
L_SVG_FRAGMENT = module('def go(request):', '    d = request.GET["d"]',
                        '    return f"<svg><path d=\'{d}\'/></svg>"')
L_S_ELEMENT = module('def go(request):', '    return "<s>%s</s>" % request.GET["x"]')
L_MASK_ELEMENT = module('def go(request):', '    return f"<mask>{request.GET[\'x\']}</mask>"')
SUBWORD_W = module('def go(token):', '    return token + "</w>"')
ADDRESS_REPR = module('def go(name, local, domain):', '    return f\'"{name}" <{local}@{domain}>\'')

case('P2', 'div_fstring_kept', 'CWE-79', 'm.py', at(L_DIV_FSTRING, 'return HttpResponse'),
     'loud', 'markup_vocab_blind_arm', 'loud', L_DIV_FSTRING,
     'MANDATED loud control; the response collector is a second fence')
case('P2', 'script_concat_kept', 'CWE-79', 'm.py', at(L_SCRIPT_CONCAT, 'return "<script>"'),
     'loud', 'markup_vocab_blind_arm', 'quiet', L_SCRIPT_CONCAT, 'MANDATED loud control')
case('P2', 'p_percent_kept', 'CWE-79', 'm.py', at(L_P_PERCENT, 'return "<p>'),
     'loud', 'markup_vocab_blind_arm', 'quiet', L_P_PERCENT, 'MANDATED loud control')
case('P2', 'a_href_kept', 'CWE-79', 'm.py', at(L_A_HREF, 'return "<a href'),
     'loud', 'markup_vocab_blind_arm', 'quiet', L_A_HREF, 'MANDATED loud control')
case('P2', 'img_src_kept', 'CWE-79', 'm.py', at(L_IMG_SRC, 'return "<img'),
     'loud', 'markup_vocab_blind_arm', 'quiet', L_IMG_SRC, 'MANDATED loud control')
case('P2', 'span_response_kept', 'CWE-79', 'm.py', at(L_SPAN_RESPONSE, 'return HttpResponse'),
     'loud', 'markup_vocab_blind_arm', 'loud', L_SPAN_RESPONSE,
     'MANDATED loud control; the imported HttpResponse sink is a second fence')
case('P2', 'mark_safe_b_kept', 'CWE-79', 'm.py', at(L_MARK_SAFE_B, 'return mark_safe'),
     'loud', 'markup_vocab_blind_arm', 'loud', L_MARK_SAFE_B,
     'MANDATED loud control; the mark_safe bank rule is a second fence')
case('P2', 'markup_li_kept', 'CWE-79', 'm.py', at(L_MARKUP_LI, 'return Markup'),
     'loud', 'markup_vocab_blind_arm', 'loud', L_MARKUP_LI,
     'MANDATED loud control; the Markup bank rule is a second fence')
case('P2', 'dynamic_tag_fstring_kept', 'CWE-79', 'm.py', at(L_DYNAMIC_TAG, 'return f"<{tag}>'),
     'loud', 'markup_vocab_blind_arm', 'loud', L_DYNAMIC_TAG,
     'blessed cwe_79_xss/test_v02_bad.py:2 shape: the AST hole is a name')
case('P2', 'custom_element_kept', 'CWE-79', 'm.py', at(L_CUSTOM_ELEMENT, 'return f"<my-widget>'),
     'loud', 'markup_vocab_blind_arm', 'loud', L_CUSTOM_ELEMENT, 'WHATWG hyphenated custom element')
case('P2', 'svg_fragment_kept', 'CWE-79', 'm.py', at(L_SVG_FRAGMENT, 'return f"<svg>'),
     'loud', 'markup_vocab_blind_arm', 'quiet', L_SVG_FRAGMENT, 'SVG names are in the vocabulary')
case('P2', 's_element_kept', 'CWE-79', 'm.py', at(L_S_ELEMENT, 'return "<s>'),
     'loud', 'markup_vocab_blind_arm', 'quiet', L_S_ELEMENT,
     'strike-through is a real element, deliberately not muted')
case('P2', 'mask_element_kept', 'CWE-79', 'm.py', at(L_MASK_ELEMENT, 'return f"<mask>'),
     'loud', 'markup_vocab_blind_arm', 'quiet', L_MASK_ELEMENT, 'SVG clipping is a real element')
case('P2', 'subword_w_control', 'CWE-79', 'm.py', at(SUBWORD_W, 'return token'),
     'quiet', 'markup_vocab_off_arm', 'quiet', SUBWORD_W, 'tokenizer control symbol, quiet at HEAD')
case('P2', 'address_repr_control', 'CWE-79', 'm.py', at(ADDRESS_REPR, 'return f'),
     'quiet', 'markup_vocab_off_arm', 'quiet', ADDRESS_REPR, 'RFC 2822 address, quiet at HEAD')

# --------------------------------------------------------------------------- P3 fixtures
# Verbatim ansible/module_utils/common/process.py:44 -- QUIET at HEAD, a control not credit.
PROCESS_VALUEERROR = module(
    'def go(arg, paths):',
    '    raise ValueError(\'Failed to find required executable "%s" in paths: %s\' '
    '% (arg, os.pathsep.join(paths)))')
# Verbatim ansible/plugins/filter/core.py:441-442. `_emit89` reports the call line AND the argument
# line, which is why one statement produced two rows.
FILTER_NEWLINE_JOIN = module(
    'def go(p):',
    "    str_postfix = p['newline'].join(",
    "        [''] + [p['postfix'] for x in range(p['postfix_count'])])",
    '    return str_postfix')
FILTER_TAINTED = module(
    'def go(request):',
    '    p = request.GET',
    "    str_postfix = p['newline'].join(",
    "        [''] + [p['postfix'] for x in range(p['postfix_count'])])",
    '    return str_postfix')
SEP_JOIN_NO_SQL = module(
    'import os', '',
    'def go(request):',
    '    parts = request.GET["p"]',
    '    return os.linesep.join(["a"] + [parts])')
SUBSCRIPT_JOIN_NO_SQL = module(
    'def go(request, p):',
    '    parts = request.GET["x"]',
    '    return p["sep"].join(["a"] + [parts])')
L_CURSOR_PERCENT = module(
    'def go(request, cursor):', '    uid = request.GET["id"]',
    '    cursor.execute("SELECT * FROM users WHERE id = %s" % uid)')
L_CURSOR_FSTRING = module(
    'def go(request, cursor):', '    k = request.GET["k"]',
    '    cursor.execute(f"DELETE FROM t WHERE k={k}")')
L_DB_JOIN_SQL = module(
    'def go(request, db):', '    uid = request.GET["id"]',
    '    db.execute(" ".join(["SELECT * FROM t WHERE id =", uid]))')
L_ORM_RAW = module(
    'def go(request):', '    n = request.GET["n"]',
    '    return User.objects.raw(f"SELECT * FROM u WHERE name=\'{n}\'")')
L_JOIN_SQL_SHAPE = module(
    'def go(request):', '    uid = request.GET["id"]',
    '    return " ".join("SELECT * FROM t WHERE id =" + uid)')

case('P3', 'executable_valueerror_control', 'CWE-89', 'm.py',
     at(PROCESS_VALUEERROR, 'raise ValueError'), 'quiet', 'join_off_arm', 'quiet',
     PROCESS_VALUEERROR, 'process.py:44 NOT REPRODUCED at HEAD')
case('P3', 'newline_join_retired_call_line', 'CWE-89', 'm.py',
     at(FILTER_NEWLINE_JOIN, "str_postfix = p['newline'].join("), 'quiet', 'join_off_arm', 'loud',
     FILTER_NEWLINE_JOIN, 'filter/core.py:441 verbatim')
case('P3', 'newline_join_retired_arg_line', 'CWE-89', 'm.py',
     at(FILTER_NEWLINE_JOIN, "[''] + [p['postfix']"), 'quiet', 'join_off_arm', 'loud',
     FILTER_NEWLINE_JOIN, 'filter/core.py:442, the second _emit89 line')
case('P3', 'newline_join_tainted_retired', 'CWE-89', 'm.py',
     at(FILTER_TAINTED, "str_postfix = p['newline'].join("), 'quiet', 'join_off_arm', 'loud',
     FILTER_TAINTED, 'same, p from the request')
case('P3', 'subscript_join_retired', 'CWE-89', 'm.py',
     at(SUBSCRIPT_JOIN_NO_SQL, 'return p["sep"].join'), 'quiet', 'join_off_arm', 'loud',
     SUBSCRIPT_JOIN_NO_SQL, 'any subscript separator, not just newline')
case('P3', 'literal_separator_join_control', 'CWE-89', 'm.py',
     at(SEP_JOIN_NO_SQL, 'return os.linesep.join'), 'quiet', 'join_blind_arm', 'loud',
     SEP_JOIN_NO_SQL, 'HEAD already required proof here; the blind arm drops it')
case('P3', 'cursor_percent_kept', 'CWE-89', 'm.py', at(L_CURSOR_PERCENT, 'cursor.execute'),
     'loud', 'join_off_arm', 'loud', L_CURSOR_PERCENT, 'MANDATED loud control')
case('P3', 'cursor_fstring_kept', 'CWE-89', 'm.py', at(L_CURSOR_FSTRING, 'cursor.execute'),
     'loud', 'join_off_arm', 'loud', L_CURSOR_FSTRING, 'MANDATED loud control')
case('P3', 'db_join_sql_kept', 'CWE-89', 'm.py', at(L_DB_JOIN_SQL, 'db.execute'),
     'loud', 'join_off_arm', 'loud', L_DB_JOIN_SQL, 'MANDATED loud control: the execute path')
case('P3', 'orm_raw_kept', 'CWE-89', 'm.py', at(L_ORM_RAW, 'User.objects.raw'),
     'loud', 'join_off_arm', 'loud', L_ORM_RAW, 'MANDATED loud control')
case('P3', 'join_with_sql_text_kept', 'CWE-89', 'm.py', at(L_JOIN_SQL_SHAPE, 'return " ".join'),
     'loud', 'join_off_arm', 'loud', L_JOIN_SQL_SHAPE,
     'a join whose argument DOES carry SQL text, so the proof is satisfied')


# --------------------------------------------------------------------------- zero-row contract
# The task asks for ZERO rows on every verbatim reproducer, not just on the tracked line.
ZERO_ROW_FIXTURES = {
    'incidental.py:368': BUG1_INCIDENTAL,
    'incidental.py:368 tainted': BUG1_TAINTED,
    'replace.py:268,270,272,281': REPLACE_PATTERN,
    'replace.py tainted': REPLACE_TAINTED,
    'paramiko_ssh.py:534': PARAMIKO_SSH,
    'collection/__init__.py:797': COLLECTION_ERROR,
    'collection/__init__.py:797 tainted': COLLECTION_TAINTED,
    'winrm.py:661': WINRM_DISPLAY,
    'winrm.py:661 tainted': WINRM_TAINTED,
    'display.py:460': DISPLAY_PREFIX,
    'display.py:460 tainted': DISPLAY_TAINTED,
    'dataclasses.py:523': VIRTUAL_NAMESPACE,
    'dataclasses.py:523 tainted': VIRTUAL_TAINTED,
    'process.py:44': PROCESS_VALUEERROR,
    'filter/core.py:441,442': FILTER_NEWLINE_JOIN,
    'filter/core.py tainted': FILTER_TAINTED,
}


# --------------------------------------------------------------------------- clause registry
def _never(self, *args, **kwargs):
    return False


def _always_static(*args, **kwargs):
    return True


def _identity(text):
    return text


def _head_join_shape(self, attr, node):
    """HEAD's exact exemption: only a literal separator or os.sep/os.linesep had to show SQL."""
    if attr != 'join':
        return False
    recv = node.func.value
    return isinstance(recv, (ast.Constant, ast.Str)) or (
        isinstance(recv, ast.Attribute) and recv.attr in ('sep', 'linesep'))


ARMS = {
    'builtin_alias_off_arm': (('T', '_t25_builtin_alias_refused', _never),),
    'markup_vocab_off_arm': (('ast_scanner', '_markup_name_is_element', _always_static),),
    'markup_vocab_blind_arm': (('ast_scanner', 'HTML_ELEMENT_NAMES', frozenset()),),
    'regex_group_off_arm': (('ast_scanner', 'strip_regex_named_groups', _identity),),
    'regex_and_vocab_off_arm': (('ast_scanner', 'strip_regex_named_groups', _identity),
                                ('ast_scanner', '_markup_name_is_element', _always_static)),
    'template_hole_off_arm': (('ast_scanner', '_MARKUP_TEMPLATE_HOLE', ast_scanner._MARKUP_HOLE),),
    'join_off_arm': (('T', '_t25_builder_needs_sql_proof', _head_join_shape),),
    'join_blind_arm': (('T', '_t25_builder_needs_sql_proof', _never),),
}


def _apply(patches, function):
    saved = []
    try:
        for owner, attribute, replacement in patches:
            target = OWNERS[owner]
            if not hasattr(target, attribute):
                raise AssertionError(f'no such clause: {owner}.{attribute}')
            saved.append((target, attribute, getattr(target, attribute)))
            setattr(target, attribute, replacement)
        return function()
    finally:
        for target, attribute, value in reversed(saved):
            setattr(target, attribute, value)


def case_rows(entry, state='ship'):
    key = ('rows', state, id(entry))
    if key not in _CACHE:
        _CACHE[key] = _apply(() if state == 'ship' else ARMS[state],
                             lambda: rows_for(entry, state))
    return _CACHE[key]


def _release():
    """Drop every weakened-state memo and collect, so the arms do not stack up scanners."""
    for key in [k for k in _CACHE if k[1] != 'ship']:
        del _CACHE[key]
    gc.collect()


def check_retirements():
    """TIER 1 -- every pocket: the shipped verdict and the verdict with its own clause reverted."""
    failures = []
    for pocket in sorted({entry['pocket'] for entry in CASES}):
        print(f'\nTIER 1  {pocket}')
        for entry in [e for e in CASES if e['pocket'] == pocket]:
            shipped = case_rows(entry)
            reverted = case_rows(entry, entry['arm'])
            now = 'loud' if loud(shipped, entry['name'], entry['cwe'], entry['line']) else 'quiet'
            arm = 'loud' if loud(reverted, entry['name'], entry['cwe'], entry['line']) else 'quiet'
            booked = (entry['expect'], arm) == ('quiet', 'loud')
            closer = (entry['expect'], arm) == ('loud', 'quiet')
            control = entry['expect'] == 'loud' and arm == 'loud'
            receipt = ('BOOKED' if booked else ('FN-CLOSER' if closer
                                                else ('CONTROL' if control else 'not booked')))
            print(f'  {now:5s} arm={arm:5s} {receipt:11s} {entry["label"]:44s} {entry["note"][:44]}')
            if now != entry['expect']:
                failures.append(f'{pocket}/{entry["label"]}: shipped {now}, want {entry["expect"]}')
            if arm != entry['arm_expect']:
                failures.append(f'{pocket}/{entry["label"]}: arm-off {arm}, want {entry["arm_expect"]}')
    _release()
    return failures


def check_fixtures_parse():
    """TIER 0 -- every fixture is valid Python.

    A fixture that does not parse yields ZERO rows, which reads exactly like a successful retirement.
    That is how a `\\n` written inside a non-raw triple-quoted harness string once turned
    `paramiko_ssh.py:534` into a false QUIET: the escape became a real newline inside a single-quoted
    literal, the module never parsed, and the row was booked as unreproducible. No quiet verdict in
    this gate is trusted until its source parses.
    """
    print('\nTIER 0  every fixture parses')
    sources = {entry['source'] for entry in CASES} | set(ZERO_ROW_FIXTURES.values())
    failures = []
    for source in sorted(sources):
        try:
            ast.parse(source)
        except SyntaxError as error:
            failures.append(f'fixture does not parse: {error}: {source.splitlines()[:3]}')
    print(f'  {"OK  " if not failures else "FAIL"} {len(sources)} distinct fixture sources')
    return failures


def check_zero_rows():
    """TIER 1b -- the thirteen verbatim reproducers and their tainted twins produce NO row at all."""
    print('\nTIER 1b  zero-row contract on every verbatim reproducer')
    failures = []
    for label, source in ZERO_ROW_FIXTURES.items():
        rows = scan_rows(source)
        print(f'  {"OK  " if not rows else "FAIL"} {label:38s} rows={len(rows)}')
        if rows:
            failures.append(f'{label}: {len(rows)} rows, want 0 -> {rows}')
    return failures


# --------------------------------------------------------------------------- TIER 2 predicates
_TRACKER = None


def tracker():
    global _TRACKER
    if _TRACKER is None:
        with contextlib.redirect_stdout(_io.StringIO()), contextlib.redirect_stderr(_io.StringIO()):
            _TRACKER = T(files={'m.py': 'x = 1\n'}, max_workers=1)
    return _TRACKER


def _call_on(source, line, leaf=None):
    for node in ast.walk(link(ast.parse(source))):
        if isinstance(node, ast.Call) and node.lineno == line:
            callee = getattr(node.func, 'attr', None) or getattr(node.func, 'id', None)
            if leaf is None or callee == leaf:
                return node
    raise AssertionError(f'no call on line {line} of the fixture')


def _expr(source):
    return link(ast.parse(source, mode='eval').body)


PROBES = {}


def probe(name, description):
    def register(function):
        PROBES[name] = (description, function)
        return function
    return register


@probe('c611_builtin_alias_vocabulary', 'the fourteen builtins are refused bare, and nothing else is')
def _():
    names = {'int', 'str', 'float', 'bool', 'bytes', 'bytearray', 'list', 'dict', 'set', 'tuple',
             'len', 'repr', 'ord', 'chr'}
    if not names <= ast_scanner.CWE611_BUILTIN_CALLEE_EXCLUSIONS:
        return False
    refuse = tracker()._t25_builtin_alias_refused
    return (all(refuse(name) for name in names)
            and not any(refuse(name) for name in
                        ('parse', 'fromstring', 'mystery', 'xml.etree.ElementTree.fromstring',
                         'lxml.etree.fromstring', 'int.fromstring', '', None)))


@probe('c611_parser_identity_outranks_spelling', 'a dotted XML parser is recognised, a bare int is not')
def _():
    recognise = tracker()._xml_sink_recognised
    node = _call_on(L_PARSE_XML_ALIAS, at(L_PARSE_XML_ALIAS, 'return parse(request'), 'parse')
    aliased = _call_on(L_INT_MODULE_ALIAS, at(L_INT_MODULE_ALIAS, 'return int.fromstring'), 'fromstring')
    return (recognise('xml.etree.ElementTree.fromstring', node, '') is True
            and recognise('xml.etree.ElementTree.fromstring', aliased, '') is True
            and recognise('int', node, '') is False
            and recognise('tuple', node, '') is False
            and recognise('mystery_callable', node, '') is True)


@probe('c79_element_vocabulary', 'the mandated elements are in, the Ansible placeholders are out')
def _():
    required = {'html', 'head', 'body', 'div', 'span', 'p', 'a', 'script', 'style', 'img', 'iframe',
                'form', 'input', 'button', 'textarea', 'select', 'option', 'label', 'table', 'thead',
                'tbody', 'tr', 'td', 'th', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                'br', 'hr', 'pre', 'code', 'b', 'i', 'u', 'em', 'strong', 'small', 'sub', 'sup',
                'section', 'article', 'nav', 'header', 'footer', 'main', 'aside', 'svg', 'path',
                'math', 'meta', 'link', 'title', 'object', 'embed', 'video', 'audio', 'source',
                'canvas', 'template', 'slot', 'details', 'summary', 'dialog', 'blockquote', 'dl',
                'dt', 'dd', 'figure', 'figcaption', 'fieldset', 'legend', 'caption', 'col',
                'colgroup', 'font', 'center', 'marquee', 'base', 'area', 'map', 'track', 'wbr',
                'bdi', 'bdo', 'data', 'time', 'mark', 'del', 'ins', 's', 'abbr', 'cite', 'dfn',
                'kbd', 'q', 'samp', 'var', 'ruby', 'rt', 'rp', 'mask'}
    forbidden = {'subsection', 'username', 'namespace', 'collection', 'response', 'virtual',
                 'placeholder', 'tag', 'name', 'value'}
    return (required <= ast_scanner.HTML_ELEMENT_NAMES
            and not (forbidden & ast_scanner.HTML_ELEMENT_NAMES)
            and '!doctype' not in ast_scanner.HTML_ELEMENT_NAMES)


@probe('c79_name_confirmation', 'case-insensitive elements and hyphenated custom elements answer')
def _():
    name = ast_scanner._markup_name_is_element
    hole = ast_scanner._MARKUP_HOLE
    return (all(name(n) for n in ('div', 'DIV', 'Script', 'svg', 'path', 's', 'mask', 'h1',
                                  'my-widget', 'x-foo', hole))
            and not any(name(n) for n in ('subsection', 'username', 'namespace', 'collection',
                                          'Response', 'virtual', 'unknown')))


@probe('c79_regex_group_stripper', 'both capture-group spellings go, everything else stays')
def _():
    strip = ast_scanner.strip_regex_named_groups
    return (strip(u'%s(?P<subsection>.*?)%s') == '%s.*?)%s'
            and strip(u'(?<span>.*)%s') == '.*)%s'
            and strip('<div>%s</div>') == '<div>%s</div>'
            and strip('no groups here') == 'no groups here'
            and strip('') == '')


@probe('c79_template_hole_is_not_a_name', 'a literal placeholder is not markup, a written tag is')
def _():
    shape = ast_scanner.text_has_markup_shape
    hole = ast_scanner._MARKUP_HOLE
    template = ast_scanner._MARKUP_TEMPLATE_HOLE
    return (template != hole
            and ast_scanner.fold_markup_holes('<%s>') == '<' + template + '>'
            and shape('<%s> %s') is False
            and shape('<{}>') is False
            and shape('<b>%s</b>') is True
            and shape('<' + hole + '>') is True
            and shape('<div>') is True
            and shape('<subsection>') is False)


@probe('c79_ast_dynamic_tag_stays_markup', 'the f-string hole keeps the blessed BAD shape loud')
def _():
    skeleton = ast_scanner.markup_skeleton
    shape = ast_scanner.text_has_markup_shape
    bad = skeleton(_expr('f"<{tag}>{content}</{tag}>"'))
    address = skeleton(_expr('f\'"{name}" <{local}@{domain}>\''))
    return (shape(bad) is True and shape(address) is False
            and shape(skeleton(_expr('f"<div>{x}</div>"'))) is True)


@probe('c79_regex_rows_are_not_markup', 'the four verbatim replace.py templates spell no element')
def _():
    shape = ast_scanner.text_has_markup_shape
    return (shape(u'%s(?P<subsection>.*?)%s') is False
            and shape(u'%s(?P<subsection>.*)') is False
            and shape(u'(?P<subsection>.*)%s') is False
            and shape(u'%s(?P<div>.*?)%s') is False
            and shape('WINRM RESULT <Response %d, %r %r, code err out>') is False
            and shape("Invalid collection name '%s', name must be in the format "
                      '<namespace>.<collection>.') is False
            and shape('<virtual namespace from {src!s} of type {src_type!s}>') is False)


@probe('c89_join_needs_sql_proof', 'join always needs proof, the other builder leaves never do')
def _():
    needs = tracker()._t25_builder_needs_sql_proof
    node = _call_on(FILTER_NEWLINE_JOIN, at(FILTER_NEWLINE_JOIN, "str_postfix = p['newline'].join("),
                    'join')
    return (needs('join', node) is True
            and all(needs(attr, node) is False for attr in
                    ('distinct', 'having', 'group_by', 'order_by', 'filter', 'where')))


@probe('c89_call_receiver_join_keeps_the_sweep',
       'a CALL receiver is not a separator shape, so the four sealed routes keep their sweep')
def _():
    source = ('def run_lookup(parts, base):\n'
              '    text = "SELECT name FROM people WHERE id = "\n'
              '    return str(URL(base).join(f"guards/{parts}/validate")) + text\n')
    needs = tracker()._t25_builder_needs_sql_proof
    route = _call_on(source, at(source, 'return str(URL(base).join('), 'join')
    literal = _call_on(L_JOIN_SQL_SHAPE, at(L_JOIN_SQL_SHAPE, 'return " ".join('), 'join')
    return needs('join', route) is False and needs('join', literal) is True


@probe('c89_execute_is_exact_membership', 'the execute leaves are a set, so executable cannot match')
def _():
    source = inspect.getsource(T._collect_cwe89_driver_querybuilder_findings)
    return ('execute_attrs = {"execute", "executemany", "executescript"}' in source
            and 'if attr in execute_attrs or attr in driver_attrs:' in source
            and 'executable' not in source)


def probe_value(name, state='ship'):
    key = ('probe', state, name)
    if key not in _CACHE:
        try:
            _CACHE[key] = _apply(() if state == 'ship' else ARMS[state], PROBES[name][1])
        except Exception as error:
            _CACHE[key] = f'error: {type(error).__name__}: {error}'
    return _CACHE[key]


def check_predicates():
    print('\nTIER 2  predicate contracts, called directly')
    failures = []
    for name in sorted(PROBES):
        description, function = PROBES[name]
        try:
            ok = function() is True
        except Exception as error:
            ok = False
            description += f'  [{type(error).__name__}: {error}]'
        print(f'  {"OK  " if ok else "FAIL"} {name:48s} {description}')
        if not ok:
            failures.append(f'predicate {name}: {description}')
    return failures


# --------------------------------------------------------------------------- TIER 3 shipped shapes
_ALIAS = inspect.getsource(T._t25_builtin_alias_refused)
_XMLREC = inspect.getsource(T._xml_sink_recognised)
_SHAPE = inspect.getsource(ast_scanner.text_has_markup_shape)
_FOLD = inspect.getsource(ast_scanner.fold_markup_holes)
_STRIP = inspect.getsource(ast_scanner.strip_regex_named_groups)
_CONFIRM = inspect.getsource(ast_scanner._markup_shape_confirmed)
_NAME = inspect.getsource(ast_scanner._markup_name_is_element)
_JOIN = inspect.getsource(T._t25_builder_needs_sql_proof)
_QUERYBUILDER = inspect.getsource(T._collect_cwe89_driver_querybuilder_findings)
_XSS_RECOVERY = inspect.getsource(T._collect_cwe79_xss_recovery_findings)

LAWS = (
    ('P1 the dotless branch asks the builtin-alias predicate, not a blanket True',
     lambda: 'if "." not in canon_name:' in _XMLREC
             and 'return not self._t25_builtin_alias_refused(canon_name)' in _XMLREC),
    ('P1 the predicate is a dotless name in the builtin vocabulary and nothing wider',
     lambda: '"." not in canon_name' in _ALIAS
             and 'canon_name in CWE611_BUILTIN_CALLEE_EXCLUSIONS' in _ALIAS),
    ('P1 the parser-identity override still outranks the callee spelling',
     lambda: 'canon_name.startswith(XML_ENTITY_PARSER_ROOTS)' in _XMLREC
             and 'canon_name.rsplit(".", 1)[-1] in XML_ENTITY_PARSER_LEAVES' in _XMLREC),
    ('P2 the shape test strips regex named groups before testing',
     lambda: 'text = strip_regex_named_groups(text)' in _SHAPE
             and "if '(?P<' in text or '(?<' in text:" in _SHAPE),
    ('P2 the stripper only removes a capture-group opener',
     lambda: "_REGEX_NAMED_GROUP_RE.sub('', text)" in _STRIP
             and "if '(?P<' not in text and '(?<' not in text:" in _STRIP),
    ('P2 both the raw and the folded text must be confirmed against the vocabulary',
     lambda: 'if _markup_shape_confirmed(text):' in _SHAPE
             and '_markup_shape_confirmed(folded)' in _SHAPE),
    ('P2 the confirmation reads the element vocabulary and the custom-element hyphen',
     lambda: 'HTML_ELEMENT_NAMES' in _NAME and 'lowered = name.lower()' in _NAME
             and 'return "-" in lowered' in _NAME
             and '_MARKUP_TAG_NAME_RE.finditer(text)' in _CONFIRM),
    ('P2 the template marker folds to its own sentinel, not the AST hole',
     lambda: '_SUBSTITUTION_MARKER_RE.sub(_MARKUP_TEMPLATE_HOLE, text)' in _FOLD
             and ast_scanner._MARKUP_TEMPLATE_HOLE != ast_scanner._MARKUP_HOLE
             and ast_scanner._MARKUP_HOLE in ast_scanner._MARKUP_SHAPE_RE.pattern
             and ast_scanner._MARKUP_TEMPLATE_HOLE not in ast_scanner._MARKUP_SHAPE_RE.pattern),
    ('P2 the AST skeleton still writes the accepted hole for a runtime tag name',
     lambda: 'out.append(_MARKUP_HOLE)' in inspect.getsource(ast_scanner.markup_skeleton)),
    ('P2 the raise guard is unchanged and reads the same grammar',
     lambda: 'in_raise and _tag_free_payload(arg)' in _XSS_RECOVERY
             and 'return not text_has_markup_shape(markup_skeleton(expr))' in _XSS_RECOVERY),
    ('P3 every join asks the proof predicate, and the receiver spelling moved into it',
     lambda: 'require_shape_or_db=self._t25_builder_needs_sql_proof(attr, node)' in _QUERYBUILDER
             and 'require_shape = False' not in _QUERYBUILDER
             and 'recv.attr in ("sep", "linesep")' not in _QUERYBUILDER),
    ('P3 the predicate reads the join leaf and the separator shape only, never a filename',
     lambda: 'if attr != "join":' in _JOIN
             and 'isinstance(recv, (ast.Constant, ast.Str, ast.Subscript))' in _JOIN
             and 'recv.attr in ("sep", "linesep")' in _JOIN
             and 'file' not in _JOIN and 'path' not in _JOIN),
    ('no new clause reads a repository, a folder or a filename',
     lambda: all(word not in _ALIAS + _JOIN + _NAME + _CONFIRM + _STRIP + _FOLD
                 for word in ('ansible', 'tests/', 'examples/', 'docs/', 'file_paths',
                              'mod_name', 'os.path'))),
)


def check_laws():
    print('\nTIER 3  the shipped source keeps each shape')
    failures = []
    for label, law in LAWS:
        try:
            ok = bool(law())
        except Exception as error:
            ok = False
            label = f'{label}  [{type(error).__name__}: {error}]'
        print(f'  {"OK  " if ok else "FAIL"} {label}')
        if not ok:
            failures.append(label)
    return failures


# --------------------------------------------------------------------------- TIER 4 falsifiers
_P1_BOOKED = ['builtin_int_alias_retired', 'builtin_int_alias_tainted_retired',
              'builtin_tuple_alias_retired', 'builtin_str_alias_retired']
_P2_REGEX_BOOKED = ['regex_named_group_retired_l268', 'regex_named_group_retired_l270',
                    'regex_named_group_retired_l272', 'regex_msg_name_hop_retired_l281',
                    'regex_named_group_tainted_retired']
_P2_REGEX_ONLY = ['regex_element_label_retired', 'regex_short_label_retired']
_P2_VOCAB_BOOKED = ['ssh_help_placeholder_retired', 'cli_placeholder_error_retired',
                    'cli_placeholder_error_tainted_retired', 'debug_repr_placeholder_retired',
                    'debug_repr_placeholder_tainted_retired', 'format_repr_placeholder_retired',
                    'format_repr_placeholder_tainted_retired']
_P2_HOLE_BOOKED = ['printf_hole_display_retired', 'printf_hole_display_tainted_retired']
# The controls whose ONLY fence is the element vocabulary. `div_fstring_kept`, `span_response_kept`,
# `mark_safe_b_kept` and `markup_li_kept` are deliberately absent: their rows come from the response
# collector and the mark_safe/Markup bank rules, which do not consult this vocabulary, so emptying it
# leaves them loud. That is measured, not assumed, and it is why they are CONTROLs and not FN-closers.
_P2_ELEMENT_KEPT = ['script_concat_kept', 'p_percent_kept', 'a_href_kept', 'img_src_kept',
                    'svg_fragment_kept', 's_element_kept', 'mask_element_kept']
_P3_BOOKED = ['newline_join_retired_call_line', 'newline_join_retired_arg_line',
              'newline_join_tainted_retired', 'subscript_join_retired']

MUTATIONS = {
    'p1_builtin_alias_proof_removed': (
        'P1: a dotless canonical name is always recognised, which is HEAD -- the four alias rows report',
        'builtin_alias_off_arm', _P1_BOOKED,
        ['c611_builtin_alias_vocabulary', 'c611_parser_identity_outranks_spelling']),
    'p2_element_vocabulary_removed': (
        'P2: any <word> is an element, which is HEAD -- the seven CLI/repr placeholder rows report',
        'markup_vocab_off_arm', _P2_VOCAB_BOOKED,
        ['c79_name_confirmation', 'c79_regex_rows_are_not_markup',
         'c79_template_hole_is_not_a_name']),
    'p2_element_vocabulary_blinded': (
        'P2: no name is an element, so the seven controls held only by this vocabulary go quiet',
        'markup_vocab_blind_arm', _P2_ELEMENT_KEPT,
        ['c79_ast_dynamic_tag_stays_markup', 'c79_element_vocabulary', 'c79_name_confirmation',
         'c79_template_hole_is_not_a_name']),
    'p2_regex_group_stripper_removed': (
        'P2: capture-group openers stay in the text -- the two element-labelled groups report',
        'regex_group_off_arm', _P2_REGEX_ONLY,
        ['c79_regex_group_stripper', 'c79_regex_rows_are_not_markup']),
    'p2_regex_and_vocabulary_removed': (
        'P2: both grammar clauses off, which is HEAD -- all fourteen regex and placeholder rows report',
        'regex_and_vocab_off_arm', _P2_REGEX_BOOKED + _P2_REGEX_ONLY + _P2_VOCAB_BOOKED,
        ['c79_regex_group_stripper', 'c79_name_confirmation', 'c79_regex_rows_are_not_markup',
         'c79_template_hole_is_not_a_name']),
    'p2_template_hole_removed': (
        'P2: the printf marker folds to the accepted AST hole, which is HEAD -- the two display rows report',
        'template_hole_off_arm', _P2_HOLE_BOOKED, ['c79_template_hole_is_not_a_name']),
    'p3_join_proof_removed': (
        'P3: HEAD receiver exemption restored -- the four non-SQL join rows report',
        'join_off_arm', _P3_BOOKED, ['c89_join_needs_sql_proof']),
    'p3_join_proof_blinded': (
        'P3: no builder leaf ever needs proof, so even a literal separator join reports',
        'join_blind_arm', _P3_BOOKED + ['literal_separator_join_control'],
        ['c89_join_needs_sql_proof', 'c89_call_receiver_join_keeps_the_sweep']),
}


def run_mutation(name):
    """Weaken one clause and report every row and predicate that moved.

    The baseline is read BEFORE the weakening is installed; reading it afterwards compares the
    mutated gate with itself and reports every mutation as MISSED.
    """
    description, state, expected_rows, expected_probes = MUTATIONS[name]
    moved = [entry['label'] for entry in CASES
             if loud(case_rows(entry), entry['name'], entry['cwe'], entry['line'])
             != loud(case_rows(entry, state), entry['name'], entry['cwe'], entry['line'])]
    flipped = [key for key in sorted(PROBES)
               if (probe_value(key) is True) != (probe_value(key, state) is True)]
    _release()
    return description, moved, flipped, expected_rows, expected_probes


def check_mutations(only=None):
    print()
    print('TIER 4  falsifiers (one weakening per clause)')
    failures = []
    for name in sorted(MUTATIONS):
        if only and name != only:
            continue
        started = time.perf_counter()
        description, moved, flipped, expected_rows, expected_probes = run_mutation(name)
        elapsed = time.perf_counter() - started
        ok = (sorted(moved) == sorted(expected_rows)
              and sorted(flipped) == sorted(expected_probes))
        print(f'  {"CAUGHT" if ok else "MISSED"} {name:40s} rows={len(moved)} probes={flipped} '
              f'({elapsed:.2f}s rss={rss_mb():.0f}MB)')
        if not ok:
            failures.append(f'{name}: want rows {sorted(expected_rows)} probes '
                            f'{sorted(expected_probes)}, moved {sorted(moved)} '
                            f'flipped {sorted(flipped)}')
        if elapsed > BUDGET_MUTATION_SECONDS:
            failures.append(f'{name}: took {elapsed:.2f}s (budget {BUDGET_MUTATION_SECONDS}s)')
    return failures


def rss_mb():
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None
    if sys.platform != 'win32':
        return None

    class Counter(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD),
                    ('PeakWorkingSetSize', ctypes.c_size_t),
                    ('WorkingSetSize', ctypes.c_size_t),
                    ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                    ('PagefileUsage', ctypes.c_size_t),
                    ('PeakPagefileUsage', ctypes.c_size_t)]

    counter = Counter()
    counter.cb = ctypes.sizeof(counter)
    get_memory = ctypes.windll.psapi.GetProcessMemoryInfo
    get_memory.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counter), wintypes.DWORD]
    get_memory.restype = wintypes.BOOL
    if not get_memory(wintypes.HANDLE(-1), ctypes.byref(counter), counter.cb):
        return None
    return counter.PeakWorkingSetSize / 1048576.0


def dump():
    for entry in CASES:
        print(f'\n=== {entry["pocket"]} {entry["label"]} expect={entry["expect"]}')
        for row in case_rows(entry):
            print('   ', row)


def main():
    argv = sys.argv[1:]
    only = next((a.split('=', 1)[1] for a in argv if a.startswith('--mutate=')), None)
    if only and only not in MUTATIONS:
        print(f'unknown mutation {only}; known: {sorted(MUTATIONS)}')
        return 2
    started = time.perf_counter()
    failures = []
    if '--dump' in argv:
        dump()
        return 0
    if not only:
        failures += check_fixtures_parse()
        failures += check_retirements()
        failures += check_zero_rows()
        failures += check_predicates()
        failures += check_laws()
    failures += check_mutations(only)
    work = time.perf_counter() - started
    peak = rss_mb()
    total = len(CASES)
    booked = sum(1 for entry in CASES if entry['expect'] == 'quiet' and entry['arm_expect'] == 'loud')
    loud_cases = sum(1 for entry in CASES if entry['expect'] == 'loud')
    print(f'\ncases={total} clause_retirements={booked} expected_loud={loud_cases} '
          f'zero_row_fixtures={len(ZERO_ROW_FIXTURES)} '
          f'probes={len(PROBES)} mutations={len(MUTATIONS) if not only else 1} '
          f'work={work:.2f}s (budget {BUDGET_SECONDS}s) peak_rss='
          + ('n/a' if peak is None else f'{peak:.1f} MB')
          + f' (budget {BUDGET_RSS_MB:.0f} MB)')
    if work > BUDGET_SECONDS:
        failures.append(f'work {work:.2f}s over budget')
    if peak is not None and peak > BUDGET_RSS_MB:
        failures.append(f'peak RSS {peak:.1f} MB over budget')
    for failure in failures:
        print(f'  FAILURE {failure}')
    print('VERDICT: ' + ('PASS' if not failures else 'FAIL'))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())