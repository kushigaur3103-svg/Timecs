"""Gate #67 -- the three-arena structural FP families, each held by its own falsifier.

Every clause below answers on provenance the scanned source itself wrote: an import fold, a
constructor, a declared base class, an assignment binding, the argument's own literal text, or the
callee's own identity. No clause reads a repository name, and the only path shape any clause reads
is the migration-script filename grammar that TASK 22 already established.

  P1  CODE-EVAL RECEIVER PROVENANCE (CWE-95). `self.compiler.compile(expr)` is the Django ORM's SQL
      compiler, `x.eval(context)` is a template operator in `smartif.py`, and neither evaluates
      Python. The refusal only reaches an ATTRIBUTE callee whose leaf is `eval`/`compile`; a bare
      builtin `eval(x)` / `compile(x, "<s>", "exec")` is not an attribute at all and keeps its row.
      An attribute receiver is excused only when it names a real eval engine -- `builtins`, `pandas`
      / `pd`, `numexpr`, `asteval`, `simpleeval`, `PIL.ImageMath`, `torch` -- written or resolved,
      including a constructor receiver such as `asteval.Interpreter().eval`.

  P2  DOMAIN `choice` (CWE-338). `self.choice(obj)` inside `ModelChoiceIterator(BaseChoiceIterator)`
      yields form choices. A DECLARED base is the proof: a class over `random.Random` /
      `random.SystemRandom` really does draw and keeps its row, and a class with no base list is
      unknown, so it stays reported too. `random.choice`, `random.Random().choice` and a bound
      `rng.choice` are not `self`/`cls` receivers and are never touched by this clause.

  P3  `.raw` PROVENANCE (CWE-89). Odoo's `Escpos.raw(bytes)` drives a receipt printer. The refusal
      needs BOTH halves to fail: the receiver is not an ORM manager (`objects`, `manager`,
      `queryset`, ... written or resolved, or a `Manager`/`QuerySet`/`RawQuerySet` constructor) AND
      the first argument -- positional or `sql=`/`query=`/`raw_query=` -- carries no SQL keyword
      literal anywhere inside it. `User.objects.raw(query_var)` with no literal SQL stays loud on
      the manager alone, and `conn.raw(f"SELECT ... {uid}")` stays loud on the SQL alone.

  P4  BARE `extract` (CWE-22). Odoo's `template_inheritance.py` passes a view-inheritance closure
      named `extract` and calls it bare. Only a BARE name with no `zipfile.`/`tarfile.` import behind
      it is proven foreign: an attribute receiver keeps its finding, because Big-8 blesses
      `TokenizersExtractor.extract`, which is no archive handle. `ZipFile(...).extract`,
      `tar.extractall` and `ZipFile(...).extractall` are all attribute callees and stay loud.

  P5  RECORDSET `.read()` (CWE-400). `move_out.raw_material_production_id.read()`,
      `self.env[...].search(...).read()` and `.browse(...).read()` project database columns. The
      clause only reads a BARE `.read()` -- no positional argument, no keyword -- so `.read(fields)`
      is not this clause's business at all. A stream handle is never a recordset: any dotted segment
      naming a file/stream/socket (`fp`, `fh`, `files`, `stream`, `resp`, `socket`, `makefile`,
      `BytesIO`, ...) vetoes the refusal, and a relational `_id`/`_ids` tail is required. A bare name
      gets exactly one bounded hop through its own prior assignment, with a `seen` tuple so a
      self-referential binding cannot loop.

  P6  XXE SINK PRECISION (CWE-611). libxml2's HTMLParser reads no DTD and expands no external
      entity, so `lxml.html.fromstring` / `parse` / `document_fromstring` / `fragment_fromstring`
      are not XXE sinks -- refused on the canonical name AND on the resolved receiver, and refused
      again in the cluster-2 aliased emitter, which does not consult `_xml_sink_recognised` at all.
      Separately, a Python builtin type/conversion callee (`int`, `str`, `len`, `repr`, ...) can
      never be an XML parser. An alias that genuinely points AT a parser leaf keeps its finding:
      `import xml.etree.ElementTree as int` + `int.fromstring(x)` is still loud, because the parser
      identity outranks the spelling it was imported under.

  P7  NON-RENDER CWE-79 (DYNAMIC_HTML_ARGUMENT). Parsing markup INTO a tree is the opposite of
      rendering it out to a client. `lxml.etree.fromstring`, `lxml.html.fromstring`,
      `minidom.parseString` and `BeautifulSoup` / `bs4.BeautifulSoup` stop co-firing CWE-79 while
      their CWE-611/CWE-776 rows are untouched. Three separate vocabularies carry this: the parser
      LEAVES, the module RECEIVERS (`bs4` among them, because a bare module name does not start with
      `bs4.`), and the bare CONSTRUCTORS. `mark_safe`, `Markup` and `HttpResponse` are not parser
      leaves and keep every row.

  P8  `HttpResponseNotAllowed` (CWE-79). Django's signature is
      `(permitted_methods, content=b'', *args, **kwargs)`: the first positional argument is the verb
      list that becomes the `Allow` header, not a body. BOTH emitters are held -- the phase-11
      response collector, which is the one that actually produced the local row, and
      `rule_engine._http_response_dynamic_body`, the bank-rule shape predicate, which is a second
      fence: reverting it alone moves 0 local rows, so it is booked as a contract, not as credit.
      An explicit `content=` keyword IS the body and stays loud, as do `HttpResponse`,
      `HttpResponseBadRequest` and `HttpResponseForbidden`.

  P9  ODOO VERSIONED MIGRATION / UPGRADE SCRIPTS (CWE-89). TASK 22's `migrations/0001_*.py` grammar
      missed `migrations/<version>/(pre|post|end)-*.py` and `upgrades/<version>/(pre|post|end)-*.py`.
      The version segment and the `pre|post|end-` prefix are both required, so
      `migrations/9.0.1.2/helpers.py`, `upgrades/utils.py`, `models/account.py` and `report/sales.py`
      all keep reporting.

  P10 CWE-208 TYPE LABELS. `token.token_type == TokenType.VAR` branches on which grammar category
      the parser produced; the marker sits inside the word `token_type` but the value compared is an
      enum member. The refusal needs EVERY secret-named operand to be a label, it never overrules a
      pinned `CWE208_TIMING_OPERAND_KEEP_LOUD` operand, and `secret == request.GET["s"]`,
      `signature == ...`, `api_key == ...`, `secret_key == settings.SECRET_KEY` and
      `csrf_token == request.META["CSRF"]` all stay loud.

Measured on the local arena snapshots and the fixtures below, HEAD 971e4d7 -> candidate: 150 rows ->
92, 58 retired, 0 new, 0 relabelled. Django `smartif.py` 13 CWE-95 rows -> 0, `sql/compiler.py` 9
CWE-95 -> 0 (its 3 CWE-89 rows at 275/475/482 preserved), `forms/models.py:1457` CWE-338 -> 0,
`decorators/http.py:38,54` and `generic/base.py:146` CWE-79 -> 0 (the two CWE-601 rows at 265/269
preserved). Odoo `template_inheritance.py:39,199` CWE-22 -> 0, `escpos.py:238` CWE-89 -> 0 (CWE-328
at 437 and CWE-611/CWE-776 at 701 preserved), `_monkeypatches_lxml.py:28` CWE-611 -> 0.

Honest limits, measured rather than assumed: the task's line numbers are off by one in two places
(`forms/models.py` is 1457 not 1458, `generic/base.py` is 146 not 147). The full Odoo and Ansible
trees are not in this checkout, so the Ansible `CWE-611: int` row could not be reproduced in any
tested shape -- the builtin exclusion ships as a permanent invariant held by probes and laws, and
retires 0 local rows. `numexpr.evaluate`, `db.raw(sql=...)`, `self.env[...].read()` and
`.read(["name","id"])` are already quiet at HEAD, so they are controls here, not credit. Item 5
(same-line CWE-1336 + CWE-79 consolidation on `.render()`) is NOT TOUCHED: `parity_before.keys`
pins both rows separately at `cwe_1336_ssti/test_v04_bad.py:8` and `test_v05_bad.py:8`, so
consolidating them would make MISSING > 0 on a hard lock. Item 6b is UNKNOWN / NOT TOUCHED:
`(?P<name>...)` emits CWE-1333, not DYNAMIC_HTML_CONSTRUCTION, and `strategy.execute`,
`pipeline.execute`, `executor.submit` and `cursor.execute("COMMIT")` are all already quiet.

TIER 1 reads every case twice against one shared fixture: its shipped verdict, and its verdict with
the owning clause reverted. TIER 2 calls the shipped predicates directly. TIER 3 reads the shipped
source and asks it to keep the shape each proof depends on. TIER 4 is the falsifiers: one weakening
per clause, and an exact set of rows and predicates must move.

Usage: python benchmark/gates/arena3_structural_fp_probe.py [--dump] [--mutate=<name>]
"""
from __future__ import annotations

import ast
import contextlib
import gc
import inspect
import io as _io
import os
import re
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
EVAL_BUILTIN = module('def go(request):', '    return eval(request.GET["e"])')
COMPILE_BUILTIN = module('def go(request):', '    return compile(request.GET["c"], "<s>", "exec")')
BUILTINS_EVAL = module('import builtins', '', 'def go(request):',
                       '    return builtins.eval(request.GET["e"])')
PANDAS_EVAL = module('import pandas as pd', '', 'def go(request):',
                     '    return pd.eval(request.GET["e"])')
IMAGEMATH_EVAL = module('from PIL import ImageMath', '', 'def go(request):',
                        '    return ImageMath.eval(request.GET["e"])')
ASTEVAL_EVAL = module('import asteval', '', 'def go(request):',
                      '    return asteval.Interpreter().eval(request.GET["e"])')
COMPILER_COMPILE = module('class SQLCompiler:', '    def as_sql(self, request):',
                          '        return self.compiler.compile(request.GET["q"])')
SELF_COMPILE = module('class Compiler:', '    def run(self, request):',
                      '        return self.compile(request.GET["c"])')
TOKEN_EVAL = module('class IfParser:', '    def parse(self, request):',
                    '        return self.token.eval(request.GET["e"])')
X_EVAL = module('def go(x, request):', '    return x.eval(request.GET["e"])')

case('P1', 'orm_compiler_compile_retired', 'CWE-95', 'm.py',
     at(COMPILER_COMPILE, 'self.compiler.compile'), 'quiet', 'eval_off_arm', 'loud',
     COMPILER_COMPILE, 'the Django SQL compiler is not a Python eval engine')
case('P1', 'self_compile_retired', 'CWE-95', 'm.py', at(SELF_COMPILE, 'self.compile'),
     'quiet', 'eval_off_arm', 'loud', SELF_COMPILE, 'sql/compiler.py self.compile shape')
case('P1', 'template_token_eval_retired', 'CWE-95', 'm.py', at(TOKEN_EVAL, 'self.token.eval'),
     'quiet', 'eval_off_arm', 'loud', TOKEN_EVAL, 'smartif operator token, not code')
case('P1', 'operator_x_eval_retired', 'CWE-95', 'm.py', at(X_EVAL, 'x.eval'),
     'quiet', 'eval_off_arm', 'loud', X_EVAL, 'smartif.py x.eval(context)')
case('P1', 'bare_builtin_eval_kept', 'CWE-95', 'm.py', at(EVAL_BUILTIN, 'return eval('),
     'loud', 'eval_blind_arm', 'loud', EVAL_BUILTIN, 'a bare builtin is not an attribute callee')
case('P1', 'bare_builtin_compile_kept', 'CWE-95', 'm.py', at(COMPILE_BUILTIN, 'return compile('),
     'loud', 'eval_blind_arm', 'loud', COMPILE_BUILTIN, 'compile(x, "<s>", "exec") stays loud')
case('P1', 'builtins_eval_kept', 'CWE-95', 'm.py', at(BUILTINS_EVAL, 'builtins.eval'),
     'loud', 'eval_off_arm', 'loud', BUILTINS_EVAL, 'the mandated builtins.eval engine')
case('P1', 'pandas_eval_kept', 'CWE-95', 'm.py', at(PANDAS_EVAL, 'pd.eval'),
     'loud', 'eval_blind_arm', 'quiet', PANDAS_EVAL, 'the mandated pandas.eval engine')
case('P1', 'imagemath_eval_kept', 'CWE-95', 'm.py', at(IMAGEMATH_EVAL, 'ImageMath.eval'),
     'loud', 'eval_blind_arm', 'quiet', IMAGEMATH_EVAL, 'PIL.ImageMath.eval is a real eval engine')
case('P1', 'asteval_constructor_kept', 'CWE-95', 'm.py', at(ASTEVAL_EVAL, 'Interpreter().eval'),
     'loud', 'eval_off_arm', 'loud', ASTEVAL_EVAL, 'a constructor receiver from an eval engine')

# --------------------------------------------------------------------------- P2 fixtures
DOMAIN_CHOICE = module('class ModelChoiceIterator(BaseChoiceIterator):',
                       '    def __iter__(self, request):',
                       '        yield self.choice(request.GET["o"])')
DOMAIN_CHOICES = module('class ModelChoiceIterator(BaseChoiceIterator):',
                        '    def go(self, request):',
                        '        return self.choices(request.GET["o"])')
NO_BASE_CHOICE = module('class ModelChoiceField:', '    def clean(self, request):',
                        '        return self.choice(request.GET["v"])')
NO_BASE_CHOICES = module('class F:', '    def go(self, request):',
                         '        return self.choices(request.GET["x"])')
RANDOM_CHOICE = module('import random', '', 'def go(request):',
                       '    return random.choice(request.GET["t"])')
RANDOM_INSTANCE = module('import random', '', 'def go(request):',
                         '    return random.Random().choice(request.GET["t"])')
RANDOM_BOUND = module('import random', '', 'def go(request):', '    rng = random.Random()',
                      '    return rng.choice(request.GET["t"])')
PRNG_SUBCLASS = module('import random', '', 'class Tokens(random.Random):',
                       '    def pick(self, request):',
                       '        return self.choice(request.GET["t"])')
PRNG_SUBCLASS_DOTTED = module('import random', '', 'class Tokens(random.SystemRandom):',
                              '    def pick(self, request):',
                              '        return self.choice(request.GET["t"])')

case('P2', 'domain_choice_retired', 'CWE-338', 'm.py', at(DOMAIN_CHOICE, 'self.choice'),
     'quiet', 'choice_off_arm', 'loud', DOMAIN_CHOICE, 'forms/models.py:1457 declared base')
case('P2', 'domain_choices_retired', 'CWE-338', 'm.py', at(DOMAIN_CHOICES, 'self.choices'),
     'quiet', 'choice_off_arm', 'loud', DOMAIN_CHOICES, 'the plural domain leaf is the same shape')
case('P2', 'baseless_class_kept', 'CWE-338', 'm.py', at(NO_BASE_CHOICE, 'self.choice'),
     'loud', 'choice_off_arm', 'loud', NO_BASE_CHOICE, 'no base list is unknown, so it reports')
case('P2', 'baseless_choices_kept', 'CWE-338', 'm.py', at(NO_BASE_CHOICES, 'self.choices'),
     'loud', 'choice_off_arm', 'loud', NO_BASE_CHOICES, 'unknown provenance is never refused')
case('P2', 'random_choice_kept', 'CWE-338', 'm.py', at(RANDOM_CHOICE, 'random.choice'),
     'loud', 'choice_off_arm', 'loud', RANDOM_CHOICE, 'the mandated random.choice control')
case('P2', 'random_instance_kept', 'CWE-338', 'm.py', at(RANDOM_INSTANCE, 'random.Random().choice'),
     'loud', 'choice_off_arm', 'loud', RANDOM_INSTANCE, 'random.Random().choice(tokens)')
case('P2', 'bound_rng_kept', 'CWE-338', 'm.py', at(RANDOM_BOUND, 'rng.choice'),
     'loud', 'choice_off_arm', 'loud', RANDOM_BOUND, 'a bound instance is not a self receiver')
case('P2', 'prng_subclass_kept', 'CWE-338', 'm.py', at(PRNG_SUBCLASS, 'self.choice'),
     'loud', 'choice_blind_arm', 'quiet', PRNG_SUBCLASS, 'a class over random.Random really draws')
case('P2', 'systemrandom_subclass_kept', 'CWE-338', 'm.py', at(PRNG_SUBCLASS_DOTTED, 'self.choice'),
     'loud', 'choice_blind_arm', 'quiet', PRNG_SUBCLASS_DOTTED, 'the dotted PRNG base is read too')

# --------------------------------------------------------------------------- P3 fixtures
PRINTER_RAW = module('class Escpos:', '    def print_receipt(self, request):',
                     '        self.raw(request.GET["cmd"])')
ORM_RAW = module('def go(request):',
                 '    return User.objects.raw(f"SELECT * FROM u WHERE id={request.GET[\'id\']}")')
MANAGER_RAW = module('def go(request, manager):',
                     '    return manager.raw("SELECT * FROM t WHERE a = %s" % request.GET["a"])')
CONN_RAW_SQL = module('def go(request, conn):',
                      '    return conn.raw(f"SELECT * FROM t WHERE id={request.GET[\'id\']}")')
ORM_RAW_VAR = module('def go(request):', '    query = request.GET["q"]',
                     '    return User.objects.raw(query)')

case('P3', 'printer_raw_retired', 'CWE-89', 'm.py', at(PRINTER_RAW, 'self.raw'),
     'quiet', 'raw_off_arm', 'loud', PRINTER_RAW, 'escpos.py:238 drives a printer, not a database')
case('P3', 'orm_raw_interpolation_kept', 'CWE-89', 'm.py', at(ORM_RAW, 'User.objects.raw'),
     'loud', 'raw_off_arm', 'loud', ORM_RAW, 'the mandated f-string SQL injection')
case('P3', 'manager_raw_kept', 'CWE-89', 'm.py', at(MANAGER_RAW, 'manager.raw'),
     'loud', 'raw_off_arm', 'loud', MANAGER_RAW, 'a manager receiver is ORM provenance')
case('P3', 'non_orm_sql_raw_kept', 'CWE-89', 'm.py', at(CONN_RAW_SQL, 'conn.raw'),
     'loud', 'raw_sql_blind_arm', 'quiet', CONN_RAW_SQL, 'SQL literal alone proves the sink')
case('P3', 'orm_raw_without_literal_kept', 'CWE-89', 'm.py', at(ORM_RAW_VAR, 'User.objects.raw'),
     'loud', 'raw_orm_vocab_off_arm', 'quiet', ORM_RAW_VAR, 'the manager alone proves the sink')

# --------------------------------------------------------------------------- P4 fixtures
# The verbatim Odoo view-inheritance shape: `extract` is a local closure / passed-in callable, and
# the tainted spec child is handed to it bare. Trimmed to the region that carries the taint.
ODOO_EXTRACT = r'''
from lxml import etree
from lxml.builder import E
import copy
import itertools
import logging
import re

from odoo.tools.translate import _
from odoo.tools import SKIPPED_ELEMENT_TYPES, html_escape
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)
RSTRIP_REGEXP = re.compile(r'\n[ \t]*$')
def remove_element(node):
    """ Remove ``node`` but not its tail, from its XML tree. """
    add_text_before(node, node.tail)
    node.tail = None
    node.getparent().remove(node)


def locate_node(arch, spec):
    """ Locate a node in a source (parent) architecture.

    Given a complete source (parent) architecture (i.e. the field
    `arch` in a view), and a 'spec' node (a node in an inheriting
    view that specifies the location in the source view of what
    should be changed), return (if it exists) the node in the
    source view matching the specification.

    :param arch: a parent architecture to modify
    :param spec: a modifying node in an inheriting view
    :return: a node in the source matching the spec
    """
    if spec.tag == 'xpath':
        expr = spec.get('expr')
        try:
            xPath = etree.ETXPath(expr)
        except etree.XPathSyntaxError as e:
            raise ValidationError(_("Invalid Expression while parsing xpath %r", expr)) from e
        nodes = xPath(arch)
        return nodes[0] if nodes else None
    elif spec.tag == 'field':
        # Only compare the field name: a field can be only once in a given view
        # at a given level (and for multilevel expressions, we should use xpath
        # inheritance spec anyway).
        for node in arch.iter('field'):
            if node.get('name') == spec.get('name'):
                return node
        return None

    for node in arch.iter(spec.tag):
        if all(node.get(attr) == spec.get(attr) for attr in spec.attrib if attr != 'position'):
            return node
    return None


def apply_inheritance_specs(source, specs_tree, inherit_branding=False, pre_locate=lambda s: True):
    """ Apply an inheriting view (a descendant of the base view)

    Apply to a source architecture all the spec nodes (i.e. nodes
    describing where and what changes to apply to some parent
    architecture) given by an inheriting view.

    :param Element source: a parent architecture to modify
    :param Element specs_tree: a modifying architecture in an inheriting view
    :param bool inherit_branding:
    :param pre_locate: function that is executed before locating a node.
                        This function receives an arch as argument.
                        This is required by studio to properly handle group_ids.
    :return: a modified source where the specs are applied
    :rtype: Element
    """
    # Queue of specification nodes (i.e. nodes describing where and
    # changes to apply to some parent architecture).
    specs = specs_tree if isinstance(specs_tree, list) else [specs_tree]

    def extract(spec):
        """
        Utility function that locates a node given a specification, remove
        it from the source and returns it.
        """
        if len(spec):
            raise ValueError(
                _("Invalid specification for moved nodes: %r", etree.tostring(spec, encoding='unicode'))
            )
        pre_locate(spec)
        to_extract = locate_node(source, spec)
        if to_extract is not None:
            remove_element(to_extract)
            return to_extract
        else:
            raise ValueError(
                _("Element %r cannot be located in parent view", etree.tostring(spec, encoding='unicode'))
            )

    while len(specs):
        spec = specs.pop(0)
        if isinstance(spec, SKIPPED_ELEMENT_TYPES):
            continue
        if spec.tag == 'data':
            specs += [c for c in spec]
            continue
        pre_locate(spec)
        node = locate_node(source, spec)
        if node is not None:
            pos = spec.get('position', 'inside')
            if pos == 'replace':
                mode = spec.get('mode', 'outer')
                if mode == "outer":
                    for loc in spec.xpath(".//*[text()='$0']"):
                        loc.text = ''
                        copied_node = copy.deepcopy(node)
                        # TODO: Remove 'inherit_branding' logic if possible;
                        # currently needed to track node removal for branding
                        # distribution. Avoid marking root nodes to prevent
                        # sibling branding issues.
                        if inherit_branding:
                            copied_node.set('data-oe-no-branding', '1')
                        loc.append(copied_node)
                    if node.getparent() is None:
                        spec_content = None
                        comment = None
                        for content in spec:
                            if content.tag is not etree.Comment:
                                spec_content = content
                                break
                            else:
                                comment = content
                        source = copy.deepcopy(spec_content)
                        # only keep the t-name of a template root node
                        t_name = node.get('t-name')
                        if t_name:
                            source.set('t-name', t_name)
                        if comment is not None:
                            text = source.text
                            source.text = None
                            comment.tail = text
                            source.insert(0, comment)
                    else:
                        # TODO ideally the notion of 'inherit_branding' should
                        # not exist in this function. Given the current state of
                        # the code, it is however necessary to know where nodes
                        # were removed when distributing branding. As a stable
                        # fix, this solution was chosen: the location is marked
                        # with a "ProcessingInstruction" which will not impact
                        # the "Element" structure of the resulting tree.
                        # Exception: if we happen to replace a node that already
                        # has xpath branding (root level nodes), do not mark the
                        # location of the removal as it will mess up the branding
                        # of siblings elements coming from other views, after the
                        # branding is distributed (and those processing instructions
                        # removed).
                        if inherit_branding and not node.get('data-oe-xpath'):
                            node.addprevious(etree.ProcessingInstruction('apply-inheritance-specs-node-removal', node.tag))

                        for child in spec:
                            if child.get('position') == 'move':
                                child = extract(child)
                            node.addprevious(child)
                        node.getparent().remove(node)
                elif mode == "inner":
                    # Replace the entire content of an element
                    for child in node:
                        node.remove(child)
                    node.text = None

                    for child in spec:
                        node.append(copy.deepcopy(child))
                    node.text = spec.text'''
ZIP_EXTRACT = module('import zipfile', '', 'def go(request, dest):',
                     '    zipfile.ZipFile(request.GET["f"]).extract(request.GET["m"], dest)')
TAR_EXTRACTALL = module('import tarfile', '', 'def go(request, dest):',
                        '    tar = tarfile.open(request.GET["p"])', '    tar.extractall(dest)')
ZIP_EXTRACTALL = module('from zipfile import ZipFile', '', 'def go(request, dest):',
                        '    ZipFile(request.GET["f"]).extractall(dest)')

case('P4', 'odoo_bare_extract_retired', 'CWE-22', 'm.py', at(ODOO_EXTRACT, 'child = extract(child)'),
     'quiet', 'extract_off_arm', 'loud', ODOO_EXTRACT, 'template_inheritance.py:199 closure call')
case('P4', 'zipfile_extract_kept', 'CWE-22', 'm.py', at(ZIP_EXTRACT, '.extract('),
     'loud', 'extract_off_arm', 'loud', ZIP_EXTRACT, 'a real archive handle keeps its row')
case('P4', 'tar_extractall_kept', 'CWE-22', 'm.py', at(TAR_EXTRACTALL, 'tar.extractall'),
     'loud', 'extract_off_arm', 'loud', TAR_EXTRACTALL, 'tarfile.open bound to a var')
case('P4', 'zip_extractall_kept', 'CWE-22', 'm.py', at(ZIP_EXTRACTALL, '.extractall('),
     'loud', 'extract_off_arm', 'loud', ZIP_EXTRACTALL, 'the mandated ZipFile.extractall control')

# --------------------------------------------------------------------------- P5 fixtures
ODOO_ID_READ = module('def go(request):', '    move_out = request.GET["m"]',
                      '    return move_out.raw_material_production_id.read()')
ODOO_SEARCH_READ = module('def go(self, request):',
                          '    rec = self.env["res.partner"].search(request.GET["d"])',
                          '    return rec.read()')
ODOO_BROWSE_READ = module('def go(self, request):',
                          '    rec = self.env["res.partner"].browse(request.GET["i"])',
                          '    return rec.read()')
FILES_READ = module('def go(request):', '    return request.FILES["f"].read()')
STREAM_READ = module('def go(request):', '    return request.stream.read()')
IMAGE_STREAM_READ = module('def go(request):', '    return request.default_image_stream.read()')
BYTESIO_READ = module('import io', '', 'def go(request):',
                      '    return io.BytesIO(request.GET["b"]).read()')
TAINTED_RECV_READ = module('def go(request):', '    return request.GET["o"].read()')
FP_READ = module('def go(request, fp):', '    fp = request.GET["f"]', '    return fp.read()')
RESP_READ = module('def go(request):', '    resp = request.GET["r"]', '    return resp.read()')
MAKEFILE_READ = module('def go(request, sock):', '    sock = request.GET["s"]',
                       '    return sock.makefile().read()')
READ_FIELDS = module('def go(new_code):', '    return new_code.read(["name", "id"])')

case('P5', 'odoo_relational_id_read_retired', 'CWE-400', 'm.py', at(ODOO_ID_READ, '.read()'),
     'quiet', 'read_off_arm', 'loud', ODOO_ID_READ, 'a relational _id tail projects columns')
case('P5', 'odoo_search_read_retired', 'CWE-400', 'm.py', at(ODOO_SEARCH_READ, 'rec.read()'),
     'quiet', 'read_producers_off_arm', 'loud', ODOO_SEARCH_READ, 'search() produces a recordset')
case('P5', 'odoo_browse_read_retired', 'CWE-400', 'm.py', at(ODOO_BROWSE_READ, 'rec.read()'),
     'quiet', 'read_producers_off_arm', 'loud', ODOO_BROWSE_READ, 'browse() produces a recordset')
case('P5', 'uploaded_file_read_kept', 'CWE-400', 'm.py', at(FILES_READ, '.read()'),
     'loud', 'read_blind_arm', 'quiet', FILES_READ, 'request.FILES is an attacker-sized stream')
case('P5', 'request_stream_read_kept', 'CWE-400', 'm.py', at(STREAM_READ, '.read()'),
     'loud', 'read_blind_arm', 'quiet', STREAM_READ, 'the mandated request.stream control')
case('P5', 'image_stream_read_kept', 'CWE-400', 'm.py', at(IMAGE_STREAM_READ, '.read()'),
     'loud', 'read_blind_arm', 'quiet', IMAGE_STREAM_READ, 'default_image_stream is a stream')
case('P5', 'bytesio_read_kept', 'CWE-400', 'm.py', at(BYTESIO_READ, '.read()'),
     'loud', 'read_blind_arm', 'quiet', BYTESIO_READ, 'an in-memory stream is still a stream')
case('P5', 'file_handle_read_kept', 'CWE-400', 'm.py', at(FP_READ, 'fp.read()'),
     'loud', 'read_blind_arm', 'quiet', FP_READ, 'a bound file handle keeps its row')
case('P5', 'response_read_kept', 'CWE-400', 'm.py', at(RESP_READ, 'resp.read()'),
     'loud', 'read_blind_arm', 'quiet', RESP_READ, 'an HTTP response body is a stream')
case('P5', 'socket_makefile_read_kept', 'CWE-400', 'm.py', at(MAKEFILE_READ, '.read()'),
     'loud', 'read_blind_arm', 'quiet', MAKEFILE_READ, 'makefile() is not a recordset producer')
case('P5', 'tainted_receiver_read_kept', 'CWE-400', 'm.py', at(TAINTED_RECV_READ, '.read()'),
     'loud', 'read_off_arm', 'loud', TAINTED_RECV_READ, 'an unexplained receiver stays reported')
case('P5', 'read_with_fields_not_this_clause', 'CWE-400', 'm.py', at(READ_FIELDS, '.read('),
     'quiet', 'read_blind_arm', 'quiet', READ_FIELDS, 'already quiet at HEAD: an argumented read')

# --------------------------------------------------------------------------- P6 fixtures
LXML_HTML = module('from lxml import html', '', 'def go(request):',
                   '    return html.fromstring(request.GET["h"])')
LXML_HTML_PARSE = module('from lxml import html', '', 'def go(request):',
                         '    return html.parse(request.GET["f"])')
LXML_HTML_DOTTED = module('import lxml.html', '', 'def go(request):',
                          '    return lxml.html.fromstring(request.GET["x"])')
LXML_HTML_ALIAS = module('from lxml.html import fromstring as parse_html', '', 'def go(request):',
                         '    return parse_html(request.GET["x"])')
LXML_HTML_BUILTIN_ALIAS = module('from lxml.html import fromstring as int', '', 'def go(request):',
                                 '    return int(request.GET["x"])')
ETREE_FROMSTRING = module('from lxml import etree', '', 'def go(request):',
                          '    return etree.fromstring(request.GET["x"])')
ET_PARSE = module('import xml.etree.ElementTree as ET', '', 'def go(request):',
                  '    return ET.parse(request.GET["f"])')
OBJECTIFY = module('from lxml import objectify', '', 'def go(request):',
                   '    return objectify.fromstring(request.GET["x"])')
PULLDOM = module('from xml.dom import pulldom', '', 'def go(request):',
                 '    return pulldom.parse(request.GET["f"])')
MINIDOM = module('from xml.dom import minidom', '', 'def go(request):',
                 '    return minidom.parseString(request.GET["x"])')
FROMSTRING_IMPORT = module('from xml.etree.ElementTree import fromstring', '', 'def go(request):',
                           '    return fromstring(request.GET["x"])')
ETREE_ALIAS = module('from lxml.etree import fromstring as fx', '', 'def go(request):',
                     '    return fx(request.GET["x"])')
INT_MODULE_ALIAS = module('import xml.etree.ElementTree as int', '', 'def go(request):',
                          '    return int.fromstring(request.GET["x"])')
PLAIN_INT = module('from lxml import etree', '', 'def go(request):',
                   '    return int(request.GET["n"])')

case('P6', 'lxml_html_fromstring_retired', 'CWE-611', 'm.py', at(LXML_HTML, 'html.fromstring'),
     'quiet', 'xml_html_off_arm', 'loud', LXML_HTML, 'the HTMLParser reads no DTD')
case('P6', 'lxml_html_parse_retired', 'CWE-611', 'm.py', at(LXML_HTML_PARSE, 'html.parse'),
     'quiet', 'xml_html_off_arm', 'loud', LXML_HTML_PARSE, 'every lxml.html entry point')
case('P6', 'lxml_html_dotted_retired', 'CWE-611', 'm.py', at(LXML_HTML_DOTTED, 'lxml.html.fromstring'),
     'quiet', 'xml_html_off_arm', 'loud', LXML_HTML_DOTTED, 'the fully dotted spelling')
case('P6', 'lxml_html_alias_retired', 'CWE-611', 'm.py', at(LXML_HTML_ALIAS, 'parse_html('),
     'quiet', 'xml_html_off_arm', 'loud', LXML_HTML_ALIAS, 'an alias folds back to lxml.html')
case('P6', 'lxml_html_builtin_alias_retired', 'CWE-611', 'm.py',
     at(LXML_HTML_BUILTIN_ALIAS, 'return int('), 'quiet', 'xml_html_off_arm', 'loud',
     LXML_HTML_BUILTIN_ALIAS, 'a builtin spelling does not launder an HTML parser')
case('P6', 'lxml_etree_fromstring_kept', 'CWE-611', 'm.py', at(ETREE_FROMSTRING, 'etree.fromstring'),
     'loud', 'xml_html_off_arm', 'loud', ETREE_FROMSTRING, 'the mandated XXE control')
case('P6', 'elementtree_parse_kept', 'CWE-611', 'm.py', at(ET_PARSE, 'ET.parse'),
     'loud', 'xml_html_off_arm', 'loud', ET_PARSE, 'stdlib ElementTree still parses entities')
case('P6', 'objectify_fromstring_kept', 'CWE-611', 'm.py', at(OBJECTIFY, 'objectify.fromstring'),
     'loud', 'xml_html_off_arm', 'loud', OBJECTIFY, 'lxml.objectify is an entity parser')
case('P6', 'pulldom_parse_kept', 'CWE-611', 'm.py', at(PULLDOM, 'pulldom.parse'),
     'loud', 'xml_html_off_arm', 'loud', PULLDOM, 'the mandated pulldom control')
case('P6', 'minidom_parsestring_kept', 'CWE-611', 'm.py', at(MINIDOM, 'minidom.parseString'),
     'loud', 'xml_html_off_arm', 'loud', MINIDOM, 'the mandated minidom control')
case('P6', 'fromstring_import_kept', 'CWE-611', 'm.py', at(FROMSTRING_IMPORT, 'return fromstring('),
     'loud', 'xml_html_off_arm', 'loud', FROMSTRING_IMPORT, 'a bare imported parser leaf')
case('P6', 'etree_leaf_alias_kept', 'CWE-611', 'm.py', at(ETREE_ALIAS, 'fx('),
     'loud', 'xml_html_off_arm', 'loud', ETREE_ALIAS, 'an alias pointing AT a parser leaf')
case('P6', 'int_module_alias_kept', 'CWE-611', 'm.py', at(INT_MODULE_ALIAS, 'int.fromstring'),
     'loud', 'xml_builtin_off_arm', 'loud', INT_MODULE_ALIAS,
     'the builtin exclusion never blinds a real parser')
case('P6', 'plain_builtin_int_already_quiet', 'CWE-611', 'm.py', at(PLAIN_INT, 'return int('),
     'quiet', 'xml_builtin_off_arm', 'quiet', PLAIN_INT,
     'the Ansible int row is not reproducible here: 0 rows retired')

# --------------------------------------------------------------------------- P7 fixtures
HTML_PARSER_FSTRING = module('from lxml import html', '', 'def go(request):',
                             '    return html.fromstring(f"<div>{request.GET[\'x\']}</div>")')
ETREE_FSTRING = module('from lxml import etree', '', 'def go(request):',
                       '    return etree.fromstring(f"<a>{request.GET[\'x\']}</a>")')
BS4_FSTRING = module('from bs4 import BeautifulSoup', '', 'def go(request):',
                     '    return BeautifulSoup(f"<p>{request.GET[\'x\']}</p>", "html.parser")')
BS4_DOTTED = module('import bs4', '', 'def go(request):',
                    '    return bs4.BeautifulSoup(f"<p>{request.GET[\'x\']}</p>", "html.parser")')
MINIDOM_FSTRING = module('from xml.dom import minidom', '', 'def go(request):',
                         '    return minidom.parseString(f"<a>{request.GET[\'x\']}</a>")')
MARK_SAFE = module('from django.utils.safestring import mark_safe', '', 'def go(request):',
                   '    return mark_safe(f"<div>{request.GET[\'x\']}</div>")')
MARKUP = module('from markupsafe import Markup', '', 'def go(request):',
                '    return Markup(f"<p>{request.GET[\'x\']}</p>")')
RESPONSE_FSTRING = module('from django.http import HttpResponse', '', 'def go(request):',
                          '    return HttpResponse(f"<div>{request.GET[\'x\']}</div>")')

case('P7', 'html_parser_co_fire_retired', 'CWE-79', 'm.py', at(HTML_PARSER_FSTRING, 'html.fromstring'),
     'quiet', 'parser_off_arm', 'loud', HTML_PARSER_FSTRING, 'parsing into a tree renders nothing')
case('P7', 'etree_parser_co_fire_retired', 'CWE-79', 'm.py', at(ETREE_FSTRING, 'etree.fromstring'),
     'quiet', 'parser_off_arm', 'loud', ETREE_FSTRING, 'the XML parser keeps its CWE-611 row only')
case('P7', 'beautifulsoup_co_fire_retired', 'CWE-79', 'm.py', at(BS4_FSTRING, 'BeautifulSoup('),
     'quiet', 'parser_constructors_off_arm', 'loud', BS4_FSTRING, 'a DOM builder is not a response')
case('P7', 'minidom_co_fire_retired', 'CWE-79', 'm.py', at(MINIDOM_FSTRING, 'minidom.parseString'),
     'quiet', 'parser_off_arm', 'loud', MINIDOM_FSTRING, 'CWE-611 and CWE-776 are preserved')
case('P7', 'dotted_bs4_co_fire_retired', 'CWE-79', 'm.py', at(BS4_DOTTED, 'bs4.BeautifulSoup'),
     'quiet', 'parser_receivers_off_arm', 'loud', BS4_DOTTED,
     'the module receiver vocabulary is load-bearing')
case('P7', 'mark_safe_kept', 'CWE-79', 'm.py', at(MARK_SAFE, 'mark_safe('),
     'loud', 'parser_off_arm', 'loud', MARK_SAFE, 'the mandated mark_safe control')
case('P7', 'markup_kept', 'CWE-79', 'm.py', at(MARKUP, 'Markup('),
     'loud', 'parser_off_arm', 'loud', MARKUP, 'the mandated Markup control')
case('P7', 'response_fstring_kept', 'CWE-79', 'm.py', at(RESPONSE_FSTRING, 'HttpResponse('),
     'loud', 'parser_off_arm', 'loud', RESPONSE_FSTRING, 'a real rendered body is not a parser')
case('P7', 'etree_cwe611_survives_co_fire_retirement', 'CWE-611', 'm.py',
     at(ETREE_FSTRING, 'etree.fromstring'), 'loud', 'parser_off_arm', 'loud', ETREE_FSTRING,
     'the co-fire refusal never touches the XXE row')
case('P7', 'minidom_cwe776_survives', 'CWE-776', 'm.py', at(MINIDOM_FSTRING, 'minidom.parseString'),
     'loud', 'parser_off_arm', 'loud', MINIDOM_FSTRING, 'entity expansion is a separate question')

# --------------------------------------------------------------------------- P8 fixtures
NOT_ALLOWED = module('from django.http import HttpResponseNotAllowed', '', 'def go(request):',
                     '    return HttpResponseNotAllowed(request.GET["m"])')
NOT_ALLOWED_LITERAL = module('from django.http import HttpResponseNotAllowed', '', 'def go(request):',
                             '    return HttpResponseNotAllowed(["GET", "POST"])')
NOT_ALLOWED_CONTENT = module('from django.http import HttpResponseNotAllowed', '', 'def go(request):',
                             '    return HttpResponseNotAllowed(permitted_methods=["GET"],'
                             ' content=request.GET["x"])')
HTTP_RESPONSE = module('from django.http import HttpResponse', '', 'def go(request):',
                       '    return HttpResponse(request.GET["x"])')
BAD_REQUEST = module('from django.http import HttpResponseBadRequest', '', 'def go(request):',
                     '    return HttpResponseBadRequest(request.GET["x"])')
FORBIDDEN = module('from django.http import HttpResponseForbidden', '', 'def go(request):',
                   '    return HttpResponseForbidden(request.GET["x"])')

case('P8', 'not_allowed_header_row_retired', 'CWE-79', 'm.py', at(NOT_ALLOWED, 'HttpResponseNotAllowed('),
     'quiet', 'not_allowed_phase11_off_arm', 'loud', NOT_ALLOWED,
     'the response collector produced the arena row')
case('P8', 'not_allowed_content_kept', 'CWE-79', 'm.py', at(NOT_ALLOWED_CONTENT, 'content='),
     'loud', 'response_blind_arm', 'quiet', NOT_ALLOWED_CONTENT,
     'an explicit content keyword IS the body')
case('P8', 'http_response_kept', 'CWE-79', 'm.py', at(HTTP_RESPONSE, 'HttpResponse('),
     'loud', 'response_blind_arm', 'loud', HTTP_RESPONSE, 'the mandated HttpResponse control')
case('P8', 'bad_request_kept', 'CWE-79', 'm.py', at(BAD_REQUEST, 'HttpResponseBadRequest('),
     'loud', 'response_blind_arm', 'loud', BAD_REQUEST, 'the mandated BadRequest control')
case('P8', 'forbidden_kept', 'CWE-79', 'm.py', at(FORBIDDEN, 'HttpResponseForbidden('),
     'loud', 'response_blind_arm', 'loud', FORBIDDEN, 'the mandated Forbidden control')
case('P8', 'literal_verb_list_already_quiet', 'CWE-79', 'm.py',
     at(NOT_ALLOWED_LITERAL, 'HttpResponseNotAllowed('), 'quiet', 'not_allowed_bank_off_arm', 'quiet',
     NOT_ALLOWED_LITERAL, 'a compile-time verb list carries no taint')

# --------------------------------------------------------------------------- P9 fixtures
MIGRATION_BODY = module('def migrate(cr, version):',
                        '    cr.execute("UPDATE t SET a = %s" % version)')
ODOO_PRE = 'addons/purchase/migrations/9.0.1.2/pre-create-properties.py'
ODOO_POST = 'addons/l10n_es/upgrades/15.0.5.0/post-61-tag-split-2021.py'
ODOO_END = 'addons/x/migrations/17.0.1.0/end-cleanup.py'
ODOO_HELPER = 'addons/x/migrations/9.0.1.2/helpers.py'
ODOO_UPGRADE_UTIL = 'addons/x/upgrades/utils.py'
ODOO_MODEL = 'addons/x/models/account.py'
ODOO_REPORT = 'addons/x/report/sales.py'
DJANGO_MIGRATION = 'app/migrations/0001_initial.py'

case('P9', 'odoo_pre_migration_retired', 'CWE-89', ODOO_PRE, at(MIGRATION_BODY, 'cr.execute'),
     'quiet', 'migration_off_arm', 'loud', MIGRATION_BODY, 'the versioned pre- script grammar')
case('P9', 'odoo_post_upgrade_retired', 'CWE-89', ODOO_POST, at(MIGRATION_BODY, 'cr.execute'),
     'quiet', 'migration_off_arm', 'loud', MIGRATION_BODY, 'upgrades/<version>/post- is the same')
case('P9', 'odoo_end_migration_retired', 'CWE-89', ODOO_END, at(MIGRATION_BODY, 'cr.execute'),
     'quiet', 'migration_off_arm', 'loud', MIGRATION_BODY, 'the end- prefix is covered too')
case('P9', 'versioned_helper_kept', 'CWE-89', ODOO_HELPER, at(MIGRATION_BODY, 'cr.execute'),
     'loud', 'migration_blind_arm', 'quiet', MIGRATION_BODY,
     'a helper inside a version directory is not a migration script')
case('P9', 'upgrade_util_kept', 'CWE-89', ODOO_UPGRADE_UTIL, at(MIGRATION_BODY, 'cr.execute'),
     'loud', 'migration_blind_arm', 'quiet', MIGRATION_BODY, 'upgrades/utils.py stays loud')
case('P9', 'model_file_kept', 'CWE-89', ODOO_MODEL, at(MIGRATION_BODY, 'cr.execute'),
     'loud', 'migration_blind_arm', 'loud', MIGRATION_BODY, 'models/account.py is not a migration')
case('P9', 'report_file_kept', 'CWE-89', ODOO_REPORT, at(MIGRATION_BODY, 'cr.execute'),
     'loud', 'migration_blind_arm', 'loud', MIGRATION_BODY, 'report/sales.py is not a migration')
case('P9', 'django_numbered_migration_still_retired', 'CWE-89', DJANGO_MIGRATION,
     at(MIGRATION_BODY, 'cr.execute'), 'quiet', 'migration_off_arm', 'quiet', MIGRATION_BODY,
     'TASK 22 grammar is preserved, not replaced')

# --------------------------------------------------------------------------- P10 fixtures
TOKEN_TYPE_ATTR = module('def go(token):', '    return token.token_type == TokenType.VAR')
TOKEN_KIND_ATTR = module('def go(token):', '    return token.token_kind == TokenKind.NAME')
SECRET_CMP = module('def go(request, secret):', '    return secret == request.GET["s"]')
SIGNATURE_CMP = module('def go(request, signature):', '    return signature == request.GET["sig"]')
API_KEY_CMP = module('def go(request, api_key):', '    return api_key == request.GET["k"]')
SECRET_KEY_CMP = module('def go(secret_key):', '    return secret_key == settings.SECRET_KEY')
CSRF_CMP = module('def go(request, csrf_token):', '    return csrf_token == request.META["CSRF"]')
GENERIC_CMP = module('def go(request):', '    a = request.GET["a"]', '    b = request.GET["b"]',
                     '    return a == b')
TOKEN_TYPE_PLAIN = module('def go(token_type):', '    return token_type == "bearer"')

case('P10', 'token_type_label_retired', 'CWE-208', 'm.py', at(TOKEN_TYPE_ATTR, '=='),
     'quiet', 'type_label_off_arm', 'loud', TOKEN_TYPE_ATTR, 'an enum category is not secret material')
case('P10', 'token_kind_label_retired', 'CWE-208', 'm.py', at(TOKEN_KIND_ATTR, '=='),
     'quiet', 'type_suffix_off_arm', 'loud', TOKEN_KIND_ATTR, 'the _kind tail is the same proof')
case('P10', 'secret_compare_kept', 'CWE-208', 'm.py', at(SECRET_CMP, '=='),
     'loud', 'type_label_blind_arm', 'quiet', SECRET_CMP, 'the mandated secret timing control')
case('P10', 'signature_compare_kept', 'CWE-208', 'm.py', at(SIGNATURE_CMP, '=='),
     'loud', 'type_label_blind_arm', 'quiet', SIGNATURE_CMP, 'a signature is secret material')
case('P10', 'api_key_compare_kept', 'CWE-208', 'm.py', at(API_KEY_CMP, '=='),
     'loud', 'type_label_blind_arm', 'quiet', API_KEY_CMP, 'an api key is secret material')
case('P10', 'secret_key_compare_kept', 'CWE-208', 'm.py', at(SECRET_KEY_CMP, '=='),
     'loud', 'type_label_blind_arm', 'quiet', SECRET_KEY_CMP, 'settings.SECRET_KEY comparison')
case('P10', 'csrf_compare_kept', 'CWE-208', 'm.py', at(CSRF_CMP, '=='),
     'loud', 'type_label_blind_arm', 'quiet', CSRF_CMP, 'a CSRF token comparison')
case('P10', 'generic_compare_already_quiet', 'CWE-208', 'm.py', at(GENERIC_CMP, 'a == b'),
     'quiet', 'type_label_off_arm', 'quiet', GENERIC_CMP, 'the emitter already refuses a == b')
case('P10', 'plain_token_type_already_quiet', 'CWE-208', 'm.py', at(TOKEN_TYPE_PLAIN, '=='),
     'quiet', 'type_label_off_arm', 'quiet', TOKEN_TYPE_PLAIN, 'no secret-named operand at HEAD')


# --------------------------------------------------------------------------- clause registry
def _never(self, *args, **kwargs):
    return False


def _always(self, *args, **kwargs):
    return True


def _never_static(*args, **kwargs):
    return False


def _always_static(*args, **kwargs):
    return True


_SHIPPED_BANK_BODY = rule_engine._http_response_dynamic_body


def _head_bank_body(node, name, canon_name=None):
    """HEAD's shape: the FIRST positional argument is the body for every HttpResponse subclass."""
    if isinstance(node, ast.Call):
        short = (name or canon_name or '').rsplit('.', 1)[-1]
        if short == 'HttpResponseNotAllowed':
            body = node.args[0] if node.args else None
            return body is not None and not rule_engine._is_literal_text(body)
    return _SHIPPED_BANK_BODY(node, name, canon_name)


_NEVER_MATCHES = re.compile(r'(?!x)x')
BROAD_MIGRATION = re.compile(r'(?:^|/)(?:migrations|upgrades)/')

ARMS = {
    'eval_off_arm': (('T', '_t24_receiver_is_code_eval_engine', _always),),
    'eval_blind_arm': (('T', '_t24_receiver_is_code_eval_engine', _never),),
    'choice_off_arm': (('T', '_t24_self_choice_is_domain_method', _never),),
    'choice_blind_arm': (('T', '_t24_self_choice_is_domain_method', _always),),
    'raw_off_arm': (('T', '_t24_raw_receiver_is_orm_manager', _always),
                    ('T', '_t24_raw_argument_is_sql', _always)),
    'raw_sql_blind_arm': (('T', '_t24_raw_argument_is_sql', _never),),
    'raw_orm_vocab_off_arm': (('ast_scanner', 'CWE89_ORM_RAW_RECEIVER_SEGMENTS', frozenset()),),
    'extract_off_arm': (('ast_scanner', 'CWE22_ARCHIVE_LEAVES', frozenset()),),
    'extract_roots_blind_arm': (('ast_scanner', 'CWE22_ARCHIVE_IMPORT_ROOTS',
                                 ('zzz_no_such_module.',)),),
    'read_off_arm': (('T', '_t24_read_receiver_is_recordset', _never),),
    'read_blind_arm': (('T', '_t24_read_receiver_is_recordset', _always),),
    'read_producers_off_arm': (('ast_scanner', 'CWE400_ORM_RECORDSET_PRODUCERS', frozenset()),),
    'xml_html_off_arm': (('ast_scanner', 'XML_NON_ENTITY_PARSER_ROOTS', ()),),
    'xml_builtin_off_arm': (('ast_scanner', 'CWE611_BUILTIN_CALLEE_EXCLUSIONS', frozenset()),),
    'parser_off_arm': (('ast_scanner', 'CWE79_NON_RENDER_PARSER_LEAVES', frozenset()),),
    'parser_receivers_off_arm': (('ast_scanner', 'CWE79_NON_RENDER_PARSER_RECEIVERS', frozenset()),),
    'parser_constructors_off_arm': (('ast_scanner', 'CWE79_NON_RENDER_PARSER_CONSTRUCTORS',
                                     frozenset()),),
    'not_allowed_phase11_off_arm': (('T', '_cwe79_not_allowed_is_header_only', _never),),
    'not_allowed_bank_off_arm': (('rule_engine', '_http_response_dynamic_body', _head_bank_body),),
    'response_blind_arm': (('T', '_cwe79_not_allowed_is_header_only', _always),
                           ('rule_engine', '_http_response_dynamic_body', _never_static)),
    'migration_off_arm': (('T', 'ODOO_VERSIONED_MIGRATION_PATH_RE', _NEVER_MATCHES),),
    'migration_blind_arm': (('T', 'ODOO_VERSIONED_MIGRATION_PATH_RE', BROAD_MIGRATION),),
    'type_label_off_arm': (('T', '_c208_compare_is_type_label', _never),),
    'type_label_blind_arm': (('T', '_c208_compare_is_type_label', _always),),
    'type_suffix_off_arm': (('ast_scanner', 'CWE208_TYPE_LABEL_SUFFIXES', ()),),
    'dispatch_off_arm': (('T', '_t24_callee_provenance_refused', _never),),
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
    for pocket in sorted({entry['pocket'] for entry in CASES},
                         key=lambda text: int(text[1:])):
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
            print(f'  {now:5s} arm={arm:5s} {receipt:11s} {entry["label"]:44s} {entry["note"][:40]}')
            if now != entry['expect']:
                failures.append(f'{pocket}/{entry["label"]}: shipped {now}, want {entry["expect"]}')
            if arm != entry['arm_expect']:
                failures.append(f'{pocket}/{entry["label"]}: arm-off {arm}, want {entry["arm_expect"]}')
    _release()
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


def _receiver_on(source, line, leaf=None):
    return _call_on(source, line, leaf).func.value


def _compare_on(source, line):
    for node in ast.walk(link(ast.parse(source))):
        if isinstance(node, ast.Compare) and node.lineno == line:
            return node
    raise AssertionError(f'no compare on line {line}')


def _refused(cwe, source, line, leaf=None):
    return tracker()._t24_callee_provenance_refused(cwe, _call_on(source, line, leaf), '')


PROBES = {}


def probe(name, description):
    def register(function):
        PROBES[name] = (description, function)
        return function
    return register


@probe('c95_eval_vocabulary', 'the eval leaves and the mandated engine receivers')
def _():
    return (ast_scanner.CWE95_CODE_EVAL_LEAVES == frozenset({'eval', 'compile'})
            and {'builtins', 'pandas', 'pd', 'numexpr', 'asteval', 'simpleeval', 'ImageMath'}
            <= ast_scanner.CWE95_CODE_EVAL_RECEIVER_LEAVES
            and 'PIL.ImageMath.' in ast_scanner.CWE95_CODE_EVAL_RECEIVER_ROOTS)


@probe('c95_bare_builtin_is_not_an_attribute', 'a bare eval/compile is never refused')
def _():
    return (_refused('CWE-95', EVAL_BUILTIN, at(EVAL_BUILTIN, 'return eval('), 'eval') is False
            and _refused('CWE-95', COMPILE_BUILTIN, at(COMPILE_BUILTIN, 'return compile('),
                         'compile') is False)


@probe('c95_engine_receiver_accepted', 'engines answer True, domain receivers answer False')
def _():
    engine = tracker()._t24_receiver_is_code_eval_engine
    return (engine(_receiver_on(PANDAS_EVAL, at(PANDAS_EVAL, 'pd.eval'), 'eval'), '') is True
            and engine(_receiver_on(BUILTINS_EVAL, at(BUILTINS_EVAL, 'builtins.eval'), 'eval'), '')
            is True
            and engine(_receiver_on(IMAGEMATH_EVAL, at(IMAGEMATH_EVAL, 'ImageMath.eval'), 'eval'),
                       '') is True
            and engine(_receiver_on(ASTEVAL_EVAL, at(ASTEVAL_EVAL, 'Interpreter().eval'), 'eval'),
                       '') is True
            and engine(_receiver_on(COMPILER_COMPILE, at(COMPILER_COMPILE, 'self.compiler.compile'),
                                    'compile'), '') is False
            and engine(_receiver_on(X_EVAL, at(X_EVAL, 'x.eval'), 'eval'), '') is False)


@probe('c338_prng_base_vocabulary', 'the PRNG bases and the domain choice leaves')
def _():
    return (ast_scanner.CWE338_PRNG_BASE_LEAVES == frozenset({'Random', 'SystemRandom',
                                                              'WichmannHill'})
            and ast_scanner.CWE338_DOMAIN_CHOICE_LEAVES == frozenset({'choice', 'choices'}))


@probe('c338_declared_base_is_the_proof', 'a base list decides, and self/cls is required')
def _():
    domain = tracker()._t24_self_choice_is_domain_method
    return (domain(_receiver_on(DOMAIN_CHOICE, at(DOMAIN_CHOICE, 'self.choice'), 'choice'),
                   _call_on(DOMAIN_CHOICE, at(DOMAIN_CHOICE, 'self.choice'), 'choice')) is True
            and domain(_receiver_on(PRNG_SUBCLASS, at(PRNG_SUBCLASS, 'self.choice'), 'choice'),
                       _call_on(PRNG_SUBCLASS, at(PRNG_SUBCLASS, 'self.choice'), 'choice')) is False
            and domain(_receiver_on(NO_BASE_CHOICE, at(NO_BASE_CHOICE, 'self.choice'), 'choice'),
                       _call_on(NO_BASE_CHOICE, at(NO_BASE_CHOICE, 'self.choice'), 'choice'))
            is False
            and domain(_receiver_on(RANDOM_CHOICE, at(RANDOM_CHOICE, 'random.choice'), 'choice'),
                       _call_on(RANDOM_CHOICE, at(RANDOM_CHOICE, 'random.choice'), 'choice'))
            is False)


@probe('c89_orm_and_sql_vocabulary', 'the manager segments and the SQL keyword reader')
def _():
    return ({'objects', 'manager', 'queryset'} <= ast_scanner.CWE89_ORM_RAW_RECEIVER_SEGMENTS
            and bool(ast_scanner.CWE89_SQL_KEYWORD_RE.search('SELECT * FROM u'))
            and not ast_scanner.CWE89_SQL_KEYWORD_RE.search('printer reset bytes'))


@probe('c89_raw_refusal_needs_both_halves', 'ORM alone or SQL alone keeps the finding')
def _():
    return (_refused('CWE-89', PRINTER_RAW, at(PRINTER_RAW, 'self.raw'), 'raw') is True
            and _refused('CWE-89', ORM_RAW_VAR, at(ORM_RAW_VAR, 'User.objects.raw'), 'raw') is False
            and _refused('CWE-89', CONN_RAW_SQL, at(CONN_RAW_SQL, 'conn.raw'), 'raw') is False
            and _refused('CWE-89', MANAGER_RAW, at(MANAGER_RAW, 'manager.raw'), 'raw') is False)


@probe('c22_archive_vocabulary', 'the archive leaves and their import homes')
def _():
    return (ast_scanner.CWE22_ARCHIVE_LEAVES == frozenset({'extract', 'extractall'})
            and ast_scanner.CWE22_ARCHIVE_IMPORT_ROOTS == ('zipfile.', 'tarfile.'))


@probe('c22_attribute_receiver_is_never_refused', 'an archive handle keeps its finding')
def _():
    return (_refused('CWE-22', ZIP_EXTRACT, at(ZIP_EXTRACT, '.extract('), 'extract') is False
            and _refused('CWE-22', TAR_EXTRACTALL, at(TAR_EXTRACTALL, 'tar.extractall'),
                         'extractall') is False
            and _refused('CWE-22', ODOO_EXTRACT, at(ODOO_EXTRACT, 'child = extract(child)'),
                         'extract') is True)


@probe('c400_recordset_and_stream_vocabulary', 'the producers and the stream veto segments')
def _():
    return ({'search', 'browse', 'sudo', 'filtered'}
            <= ast_scanner.CWE400_ORM_RECORDSET_PRODUCERS
            and {'fp', 'fh', 'files', 'stream', 'resp', 'response', 'socket', 'conn', 'stdin',
                 'BytesIO', 'StringIO', 'makefile'}
            <= ast_scanner.CWE400_STREAM_RECEIVER_SEGMENTS)


@probe('c400_stream_receiver_is_never_a_recordset', 'streams veto, recordsets answer True')
def _():
    recordset = tracker()._t24_read_receiver_is_recordset
    return (recordset(_receiver_on(STREAM_READ, at(STREAM_READ, '.read()'), 'read'), '', 0) is False
            and recordset(_receiver_on(FILES_READ, at(FILES_READ, '.read()'), 'read'), '', 0)
            is False
            and recordset(_receiver_on(BYTESIO_READ, at(BYTESIO_READ, '.read()'), 'read'), '', 0)
            is False
            and recordset(_receiver_on(MAKEFILE_READ, at(MAKEFILE_READ, '.read()'), 'read'), '', 0)
            is False
            and recordset(_receiver_on(ODOO_ID_READ, at(ODOO_ID_READ, '.read()'), 'read'), '', 0)
            is True
            and recordset(_call_on(ODOO_SEARCH_READ, at(ODOO_SEARCH_READ, '.search('), 'search'),
                          '', 0) is True
            and recordset(_call_on(ODOO_BROWSE_READ, at(ODOO_BROWSE_READ, '.browse('), 'browse'),
                          '', 0) is True)


@probe('c400_argumented_read_is_not_this_clause', 'a read with arguments is left alone')
def _():
    return _refused('CWE-400', READ_FIELDS, at(READ_FIELDS, '.read('), 'read') is False


@probe('c611_builtin_exclusion', 'the fourteen builtins can never be an XML parser')
def _():
    recognised = tracker()._xml_sink_recognised
    call = _call_on(PLAIN_INT, at(PLAIN_INT, 'return int('), 'int')
    return (ast_scanner.CWE611_BUILTIN_CALLEE_EXCLUSIONS == frozenset({
                'int', 'str', 'float', 'bool', 'bytes', 'bytearray', 'list', 'dict', 'set',
                'tuple', 'len', 'repr', 'ord', 'chr'})
            and recognised('int', call, '') is False
            and recognised('lxml.etree.fromstring',
                           _call_on(ETREE_FROMSTRING, at(ETREE_FROMSTRING, 'etree.fromstring'),
                                    'fromstring'), '') is True)


@probe('c611_html_parser_refused', 'lxml.html is refused, lxml.etree is not')
def _():
    recognised = tracker()._xml_sink_recognised
    return (recognised('lxml.html.fromstring',
                       _call_on(LXML_HTML_DOTTED, at(LXML_HTML_DOTTED, 'lxml.html.fromstring'),
                                'fromstring'), '') is False
            and recognised('lxml.html.parse', None, '') is False
            and recognised('lxml.etree.parse', None, '') is True
            and recognised('xml.dom.minidom.parseString', None, '') is True)


@probe('c79_parser_vocabulary', 'the parser leaves, receivers and roots')
def _():
    return ({'fromstring', 'parse', 'parseString', 'XML', 'BeautifulSoup'}
            <= ast_scanner.CWE79_NON_RENDER_PARSER_LEAVES
            and {'etree', 'html', 'minidom', 'BeautifulSoup', 'bs4'}
            <= ast_scanner.CWE79_NON_RENDER_PARSER_RECEIVERS
            and ast_scanner.CWE79_NON_RENDER_PARSER_ROOTS == ('lxml.', 'xml.', 'defusedxml.',
                                                              'bs4.')
            and ast_scanner.CWE79_NON_RENDER_PARSER_CONSTRUCTORS == frozenset({'BeautifulSoup'}))


@probe('c79_not_allowed_header_only', 'the verb list is a header, content= is a body')
def _():
    header_only = tracker()._cwe79_not_allowed_is_header_only
    return (header_only(_call_on(NOT_ALLOWED, at(NOT_ALLOWED, 'HttpResponseNotAllowed(')),
                        {'HttpResponseNotAllowed', 'django.http.HttpResponseNotAllowed'}) is True
            and header_only(_call_on(NOT_ALLOWED_CONTENT, at(NOT_ALLOWED_CONTENT, 'content=')),
                            {'HttpResponseNotAllowed'}) is False
            and header_only(_call_on(HTTP_RESPONSE, at(HTTP_RESPONSE, 'HttpResponse(')),
                            {'HttpResponse'}) is False)


@probe('c79_bank_rule_reads_the_body_slot', 'the bank predicate never reads args[0] for NotAllowed')
def _():
    body = rule_engine._http_response_dynamic_body
    tainted = ast.parse('f(x)').body[0].value
    literal = ast.parse('"GET"').body[0].value
    methods = ast.parse('["GET"]').body[0].value
    return (body(_call_on(NOT_ALLOWED, at(NOT_ALLOWED, 'HttpResponseNotAllowed(')),
                 'HttpResponseNotAllowed', 'django.http.HttpResponseNotAllowed') is False
            and body(_call_on(NOT_ALLOWED_CONTENT, at(NOT_ALLOWED_CONTENT, 'content=')),
                     'HttpResponseNotAllowed', 'django.http.HttpResponseNotAllowed') is True
            and body(ast.Call(func=ast.Name(id='HttpResponseNotAllowed'),
                              args=[methods, tainted], keywords=[]),
                     'HttpResponseNotAllowed') is True
            and body(ast.Call(func=ast.Name(id='HttpResponseNotAllowed'),
                              args=[methods, literal], keywords=[]),
                     'HttpResponseNotAllowed') is False
            and body(_call_on(HTTP_RESPONSE, at(HTTP_RESPONSE, 'HttpResponse(')),
                     'HttpResponse', 'django.http.HttpResponse') is True)


@probe('c9_odoo_versioned_shape', 'the version segment and the pre|post|end prefix are required')
def _():
    pattern = T.ODOO_VERSIONED_MIGRATION_PATH_RE
    return (all(pattern.search(path) for path in (ODOO_PRE, ODOO_POST, ODOO_END))
            and not any(pattern.search(path) for path in (ODOO_HELPER, ODOO_UPGRADE_UTIL,
                                                          ODOO_MODEL, ODOO_REPORT))
            and bool(T.NUMBERED_MIGRATION_PATH_RE.search(DJANGO_MIGRATION))
            and not T.NUMBERED_MIGRATION_PATH_RE.search(ODOO_PRE))


@probe('c9_migration_predicate_reads_both_grammars', 'the shipped predicate consults both regexes')
def _():
    predicate = tracker()._file_is_numbered_django_migration
    return (predicate(ODOO_PRE) is True and predicate(ODOO_POST) is True
            and predicate(DJANGO_MIGRATION) is True and predicate(ODOO_HELPER) is False
            and predicate(ODOO_MODEL) is False and predicate('') is False)


@probe('c208_type_label_vocabulary', 'the label tails and the enum hosts')
def _():
    return (ast_scanner.CWE208_TYPE_LABEL_SUFFIXES == ('_type', '_kind', '_class')
            and {'TokenType', 'TokenTypes', 'NodeType', 'NodeTypes'}
            == ast_scanner.CWE208_TYPE_LABEL_HOSTS)


@probe('c208_secret_material_is_not_a_label', 'only a label operand is excused')
def _():
    label = tracker()._c208_compare_is_type_label
    return (label(_compare_on(TOKEN_TYPE_ATTR, at(TOKEN_TYPE_ATTR, '==')), 'm.py') is True
            and label(_compare_on(SECRET_CMP, at(SECRET_CMP, '==')), 'm.py') is False
            and label(_compare_on(SIGNATURE_CMP, at(SIGNATURE_CMP, '==')), 'm.py') is False
            and label(_compare_on(API_KEY_CMP, at(API_KEY_CMP, '==')), 'm.py') is False)


@probe('c208_pin_outranks_the_label', 'a blessed operand keeps the finding whatever its name')
def _():
    if not ast_scanner.CWE208_TIMING_OPERAND_KEEP_LOUD:
        return False
    basename, lineno = sorted(ast_scanner.CWE208_TIMING_OPERAND_KEEP_LOUD)[0]
    node = _compare_on(TOKEN_TYPE_ATTR, at(TOKEN_TYPE_ATTR, '=='))
    node.lineno = lineno
    label = tracker()._c208_compare_is_type_label
    return label(node, basename) is False and label(node, 'not_pinned.py') is True


@probe('dispatch_refuses_only_its_five_cwes', 'CWE-79/611/208 are never this dispatcher\'s business')
def _():
    node = _call_on(ETREE_FROMSTRING, at(ETREE_FROMSTRING, 'etree.fromstring'), 'fromstring')
    refused = tracker()._t24_callee_provenance_refused
    return (refused('CWE-79', node, '') is False and refused('CWE-611', node, '') is False
            and refused('CWE-208', node, '') is False and refused('', node, '') is False)


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
_DISPATCH = inspect.getsource(T._t24_callee_provenance_refused)
_EVAL = inspect.getsource(T._t24_receiver_is_code_eval_engine)
_RAW = inspect.getsource(T._t24_raw_receiver_is_orm_manager)
_SQL = inspect.getsource(T._t24_raw_argument_is_sql)
_CHOICE = inspect.getsource(T._t24_self_choice_is_domain_method)
_READ = inspect.getsource(T._t24_read_receiver_is_recordset)
_XMLREC = inspect.getsource(T._xml_sink_recognised)
_NOTALLOWED = inspect.getsource(T._cwe79_not_allowed_is_header_only)
_MIGRATION = inspect.getsource(T._file_is_numbered_django_migration)
_LABEL = inspect.getsource(T._c208_compare_is_type_label)
_SINKCALL = inspect.getsource(T.is_sink_call)
_GETSINK = inspect.getsource(T.get_or_create_sink)
_CLUSTER2 = inspect.getsource(T._collect_cluster2_structural_findings)
_XSS_RECOVERY = inspect.getsource(T._collect_cwe79_xss_recovery_findings)
_RESPONSE = inspect.getsource(T._collect_template_response_xss_findings)
_BATCH4 = inspect.getsource(T._collect_batch4_structural_findings)
_BANK = inspect.getsource(rule_engine._http_response_dynamic_body)

LAWS = (
    ('P1 the dispatcher only refuses an attribute eval/compile callee',
     lambda: 'if leaf not in CWE95_CODE_EVAL_LEAVES or not isinstance(func, ast.Attribute):'
             in _DISPATCH
             and 'return not self._t24_receiver_is_code_eval_engine(func.value, scope_id)'
             in _DISPATCH),
    ('P1 an engine is read from the written and the resolved path, plus a constructor',
     lambda: 'for path in (canon, written):' in _EVAL
             and 'if path.rsplit(".", 1)[-1] in CWE95_CODE_EVAL_RECEIVER_LEAVES:' in _EVAL
             and 'if path.startswith(CWE95_CODE_EVAL_RECEIVER_ROOTS):' in _EVAL
             and 'if isinstance(receiver, ast.Call):' in _EVAL),
    ('P2 a declared base list is the proof, and self/cls is required',
     lambda: 'not in {"self", "cls"}' in _CHOICE
             and 'if current is None or not current.bases:' in _CHOICE
             and 'if base_leaf in CWE338_PRNG_BASE_LEAVES or base_leaf.endswith("Random"):'
             in _CHOICE),
    ('P3 the raw refusal needs the manager AND the SQL argument to fail',
     lambda: 'if self._t24_raw_receiver_is_orm_manager(func.value, scope_id):' in _DISPATCH
             and 'return not self._t24_raw_argument_is_sql(node)' in _DISPATCH
             and 'any(seg in CWE89_ORM_RAW_RECEIVER_SEGMENTS for seg in path.split("."))' in _RAW
             and '{"Manager", "QuerySet", "RawQuerySet"}' in _RAW),
    ('P3 the SQL proof reads a literal anywhere inside the first argument',
     lambda: 'kw.arg in {"sql", "query", "raw_query"}' in _SQL
             and 'for child in ast.walk(arg):' in _SQL
             and 'if CWE89_SQL_KEYWORD_RE.search(text):' in _SQL),
    ('P4 an attribute extract keeps its finding, only a bare name is refused',
     lambda: 'if leaf not in CWE22_ARCHIVE_LEAVES or isinstance(func, ast.Attribute):' in _DISPATCH
             and 'return not (canon and canon.startswith(CWE22_ARCHIVE_IMPORT_ROOTS))' in _DISPATCH),
    ('P5 the read clause only reads a bare argumentless read',
     lambda: 'if leaf != "read" or node.args or node.keywords or not isinstance(func, ast.Attribute):'
             in _DISPATCH),
    ('P5 a stream segment vetoes the recordset reading, and an _id tail is required',
     lambda: 'if not segments or any(seg in CWE400_STREAM_RECEIVER_SEGMENTS for seg in segments):'
             in _READ
             and 'return len(segments) >= 2 and segments[-1].endswith(("_id", "_ids"))' in _READ
             and 'return ctor_leaf in CWE400_ORM_RECORDSET_PRODUCERS' in _READ),
    ('P5 the name hop is bounded by a seen tuple',
     lambda: 'receiver.id not in seen' in _READ and '(*seen, receiver.id)' in _READ),
    ('P6 the HTML parser is refused before the entity root is accepted',
     lambda: _XMLREC.find('if canon_name.startswith(XML_NON_ENTITY_PARSER_ROOTS):')
             < _XMLREC.find('if canon_name.startswith(XML_ENTITY_PARSER_ROOTS):')
             and 'receiver_canon = self.resolve_canonical_name(receiver, scope_id)' in _XMLREC),
    ('P6 a builtin callee is excluded unless it resolves onto a real parser leaf',
     lambda: 'if callee_leaf in CWE611_BUILTIN_CALLEE_EXCLUSIONS and not (' in _XMLREC
             and 'canon_name.startswith(XML_ENTITY_PARSER_ROOTS)' in _XMLREC
             and 'canon_name.rsplit(".", 1)[-1] in XML_ENTITY_PARSER_LEAVES' in _XMLREC),
    ('P6 the cluster-2 aliased emitter holds both refusals itself',
     lambda: 'and not form.startswith(XML_NON_ENTITY_PARSER_ROOTS)' in _CLUSTER2
             and 'in CWE611_BUILTIN_CALLEE_EXCLUSIONS' in _CLUSTER2),
    ('P7 the co-fire refusal reads a parser leaf, then a receiver, then a resolved root',
     lambda: 'if segment in CWE79_NON_RENDER_PARSER_LEAVES:' in _XSS_RECOVERY
             and 'if receiver.split(".")[-1] in CWE79_NON_RENDER_PARSER_RECEIVERS:' in _XSS_RECOVERY
             and 'if receiver_canon.startswith(CWE79_NON_RENDER_PARSER_ROOTS):' in _XSS_RECOVERY
             and 'return call_node.func.id in CWE79_NON_RENDER_PARSER_CONSTRUCTORS'
             in _XSS_RECOVERY),
    ('P8 the response collector asks the header-only predicate',
     lambda: 'elif self._cwe79_not_allowed_is_header_only(node, call_names):' in _RESPONSE
             and 'if not any(name.rsplit(".", 1)[-1] == "HttpResponseNotAllowed"' in _NOTALLOWED
             and 'kw.arg in {"content", "response", "body", "data"}' in _NOTALLOWED),
    ('P8 the bank rule reads the second positional slot, never the first',
     lambda: _BANK.find('if short == "HttpResponseNotAllowed":')
             < _BANK.find('body = node.args[1]')
             < _BANK.find('body = node.args[0]')
             and 'if body is None and len(node.args) > 1:' in _BANK),
    ('P9 the migration predicate keeps both grammars and normalises separators',
     lambda: 'NUMBERED_MIGRATION_PATH_RE.search(normalised)' in _MIGRATION
             and 'ODOO_VERSIONED_MIGRATION_PATH_RE.search(normalised)' in _MIGRATION
             and 'file_path.replace("\\\\", "/").lower()' in _MIGRATION
             and T.ODOO_VERSIONED_MIGRATION_PATH_RE.pattern
             == r'(?:^|/)(?:migrations|upgrades)/\d+(?:\.\d+)+/(?:pre|post|end)-[^/]+\.py$'),
    ('P10 the label refusal never overrules a pinned operand',
     lambda: 'in CWE208_TIMING_OPERAND_KEEP_LOUD' in _LABEL and 'if not named:' in _LABEL
             and 'return all(self._c208_operand_is_type_label(operand) for operand in named)'
             in _LABEL
             and 'and not self._c208_compare_is_type_label(node, file_path)):' in _BATCH4),
    ('the dispatcher is wired at BOTH sink choke points',
     lambda: 'if _t24_cwe and self._t24_callee_provenance_refused(_t24_cwe, node, scope_id):'
             in _SINKCALL
             and 'if self._t24_callee_provenance_refused(sink.metadata.get("cwe"), node, scope_id):'
             in _GETSINK),
    ('no provenance clause reads a path, a module name or a file table',
     lambda: not re.search(r'self\.(files|current_file|path)|mod_name|filename|basename',
                           _DISPATCH + _EVAL + _RAW + _SQL + _CHOICE + _READ + _XMLREC
                           + _NOTALLOWED)),
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
_P1_BOOKED = ['orm_compiler_compile_retired', 'self_compile_retired',
              'template_token_eval_retired', 'operator_x_eval_retired']
_P2_BOOKED = ['domain_choice_retired', 'domain_choices_retired']
_P3_BOOKED = ['printer_raw_retired']
_P4_BOOKED = ['odoo_bare_extract_retired']
_P5_BOOKED = ['odoo_relational_id_read_retired', 'odoo_search_read_retired',
              'odoo_browse_read_retired']
_P6_BOOKED = ['lxml_html_fromstring_retired', 'lxml_html_parse_retired',
              'lxml_html_dotted_retired', 'lxml_html_alias_retired',
              'lxml_html_builtin_alias_retired']
_P7_BOOKED = ['html_parser_co_fire_retired', 'etree_parser_co_fire_retired',
              'minidom_co_fire_retired', 'dotted_bs4_co_fire_retired']
_P10_BOOKED = ['token_type_label_retired', 'token_kind_label_retired']

MUTATIONS = {
    'p1_eval_engine_proof_removed': (
        'P1: every receiver counts as an eval engine, which is HEAD -- the four domain rows report',
        'eval_off_arm', _P1_BOOKED, ['c95_engine_receiver_accepted']),
    'p1_eval_engine_proof_blinded': (
        'P1: no receiver is an engine, so the pandas and ImageMath eval rows go quiet',
        'eval_blind_arm', ['pandas_eval_kept', 'imagemath_eval_kept'],
        ['c95_engine_receiver_accepted']),
    'p2_declared_base_proof_removed': (
        'P2: a base list proves nothing, which is HEAD -- the two domain choice rows report',
        'choice_off_arm', _P2_BOOKED, ['c338_declared_base_is_the_proof']),
    'p2_declared_base_proof_blinded': (
        'P2: every choice callee is a domain method, so the PRNG subclasses and random go quiet',
        'choice_blind_arm',
        ['prng_subclass_kept', 'systemrandom_subclass_kept', 'baseless_class_kept',
         'baseless_choices_kept', 'random_choice_kept', 'bound_rng_kept'],
        ['c338_declared_base_is_the_proof']),
    'p3_raw_provenance_removed': (
        'P3: neither the manager nor the SQL argument is read, which is HEAD -- the printer reports',
        'raw_off_arm', _P3_BOOKED, ['c89_raw_refusal_needs_both_halves']),
    'p3_sql_argument_blinded': (
        'P3: no argument is SQL, so a non-ORM connection raw query loses its row',
        'raw_sql_blind_arm', ['non_orm_sql_raw_kept'], ['c89_raw_refusal_needs_both_halves']),
    'p3_orm_vocabulary_emptied': (
        'P3: no segment names a manager, so objects.raw(query_var) is refused',
        'raw_orm_vocab_off_arm', ['orm_raw_without_literal_kept'],
        ['c89_orm_and_sql_vocabulary', 'c89_raw_refusal_needs_both_halves']),
    'p4_archive_leaf_vocabulary_emptied': (
        'P4: no leaf is an archive leaf, which is HEAD -- the Odoo closure call reports',
        'extract_off_arm', _P4_BOOKED, ['c22_archive_vocabulary',
                                       'c22_attribute_receiver_is_never_refused']),
    'p4_archive_import_homes_blinded': (
        'P4: no import home is an archive module, so the vocabulary contract breaks',
        'extract_roots_blind_arm', [], ['c22_archive_vocabulary']),
    'p5_recordset_proof_removed': (
        'P5: no receiver is a recordset, which is HEAD -- all three Odoo reads report',
        'read_off_arm', _P5_BOOKED,
        ['c400_stream_receiver_is_never_a_recordset']),
    'p5_recordset_proof_blinded': (
        'P5: every receiver is a recordset, so all eight stream reads go quiet',
        'read_blind_arm',
        ['uploaded_file_read_kept', 'request_stream_read_kept', 'image_stream_read_kept',
         'bytesio_read_kept', 'file_handle_read_kept', 'response_read_kept',
         'socket_makefile_read_kept', 'tainted_receiver_read_kept'],
        ['c400_stream_receiver_is_never_a_recordset']),
    'p5_recordset_producers_emptied': (
        'P5: no constructor produces a recordset, so the search/browse reads report',
        'read_producers_off_arm', ['odoo_search_read_retired', 'odoo_browse_read_retired'],
        ['c400_recordset_and_stream_vocabulary', 'c400_stream_receiver_is_never_a_recordset']),
    'p6_html_parser_refusal_removed': (
        'P6: lxml.html is an entity parser again, which is HEAD -- the five HTML rows report',
        'xml_html_off_arm', _P6_BOOKED, ['c611_html_parser_refused']),
    'p6_builtin_exclusion_removed': (
        'P6: a builtin may be an XML parser again; no local row moves, the contract does',
        'xml_builtin_off_arm', [], ['c611_builtin_exclusion']),
    'p7_parser_leaf_vocabulary_emptied': (
        'P7: no leaf is a parser, which is HEAD -- the four co-fire rows report',
        'parser_off_arm', _P7_BOOKED, ['c79_parser_vocabulary']),
    'p7_parser_receiver_vocabulary_emptied': (
        'P7: no receiver names a parser module, so the dotted bs4 co-fire reports',
        'parser_receivers_off_arm', ['dotted_bs4_co_fire_retired'], ['c79_parser_vocabulary']),
    'p7_parser_constructor_vocabulary_emptied': (
        'P7: no bare constructor builds a DOM, so the bare BeautifulSoup co-fire reports',
        'parser_constructors_off_arm', ['beautifulsoup_co_fire_retired'],
        ['c79_parser_vocabulary']),
    'p8_collector_refusal_removed': (
        'P8: the response collector stops reading the Allow header, so its row returns',
        'not_allowed_phase11_off_arm', ['not_allowed_header_row_retired'],
        ['c79_not_allowed_header_only']),
    'p8_bank_rule_refusal_removed': (
        'P8: the bank rule reads args[0] as the body again; 0 local rows move, the contract does',
        'not_allowed_bank_off_arm', [],
        ['c79_bank_rule_reads_the_body_slot']),
    'p8_response_body_blinded': (
        'P8: every response is header-only, so the explicit content= body goes quiet',
        'response_blind_arm', ['not_allowed_content_kept'],
        ['c79_not_allowed_header_only', 'c79_bank_rule_reads_the_body_slot']),
    'p9_odoo_versioned_grammar_removed': (
        'P9: the versioned grammar matches nothing, which is HEAD -- the three scripts report',
        'migration_off_arm',
        ['odoo_pre_migration_retired', 'odoo_post_upgrade_retired', 'odoo_end_migration_retired'],
        ['c9_odoo_versioned_shape', 'c9_migration_predicate_reads_both_grammars']),
    'p9_odoo_versioned_grammar_blinded': (
        'P9: any file under migrations/upgrades is a script, so the two helpers go quiet',
        'migration_blind_arm', ['versioned_helper_kept', 'upgrade_util_kept'],
        ['c9_odoo_versioned_shape', 'c9_migration_predicate_reads_both_grammars']),
    'p10_type_label_refusal_removed': (
        'P10: no operand is a label, which is HEAD -- the token_type comparison reports',
        'type_label_off_arm', _P10_BOOKED,
        ['c208_secret_material_is_not_a_label', 'c208_pin_outranks_the_label']),
    'p10_type_label_refusal_blinded': (
        'P10: every secret-named compare is a label, so all five secret timings go quiet',
        'type_label_blind_arm',
        ['secret_compare_kept', 'signature_compare_kept', 'api_key_compare_kept',
         'secret_key_compare_kept', 'csrf_compare_kept'],
        ['c208_secret_material_is_not_a_label', 'c208_pin_outranks_the_label']),
    'p10_label_tail_vocabulary_emptied': (
        'P10: no tail names a category, so both label comparisons report',
        'type_suffix_off_arm', _P10_BOOKED,
        ['c208_type_label_vocabulary', 'c208_secret_material_is_not_a_label',
         'c208_pin_outranks_the_label']),
    'dispatcher_unwired': (
        'the whole provenance dispatcher is blinded, so all eleven P1-P5 retirements return',
        'dispatch_off_arm',
        _P1_BOOKED + _P2_BOOKED + _P3_BOOKED + _P4_BOOKED + _P5_BOOKED,
        ['c89_raw_refusal_needs_both_halves',
         'c22_attribute_receiver_is_never_refused']),
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
        failures += check_retirements()
        failures += check_predicates()
        failures += check_laws()
    failures += check_mutations(only)
    work = time.perf_counter() - started
    peak = rss_mb()
    total = len(CASES)
    booked = sum(1 for entry in CASES if entry['expect'] == 'quiet' and entry['arm_expect'] == 'loud')
    loud_cases = sum(1 for entry in CASES if entry['expect'] == 'loud')
    print(f'\ncases={total} clause_retirements={booked} expected_loud={loud_cases} '
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