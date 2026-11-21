"""
TimeCodeSecurity - Phase 4: Function Summary Extractor
Extracts deterministic taint contracts (Param -> Return, Param -> Sink) per function.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from symbol_indexer import GlobalSymbolIndex, SymbolDefinition


KNOWN_SINKS = {
    # CWE-89: SQL Injection
    "execute": "CWE-89",
    "executemany": "CWE-89",
    "raw": "CWE-89",
    # CWE-78: Command Injection
    "system": "CWE-78",
    "popen": "CWE-78",
    "check_output": "CWE-78",
    "call": "CWE-78",
    "run": "CWE-78",
    # CWE-95 / 94: Code Exec
    "eval": "CWE-95",
    "exec": "CWE-94",
    # CWE-502: Deserialization
    "loads": "CWE-502",
    "load": "CWE-502",
    # CWE-22: Path Traversal
    "open": "CWE-22",
}

KNOWN_SANITIZERS = {
    "int", "float", "bool", "len", "escape", "quote", "sha256", "md5"
}

# `KNOWN_SINKS` keys on the leaf name of the callee, and four JSON parsers share that leaf with
# `pickle.loads`: json, orjson, ujson, simplejson. A JSON parser builds dicts, lists, strings and
# numbers -- it constructs no arbitrary class and executes nothing the payload chose -- so it carries
# no CWE-502 obligation. Zulip paid for the collision twice over: `zerver/lib/queue.py` and
# `zerver/lib/send_email.py` were reported as unsafe deserialization on `orjson.loads(...)`.
JSON_PARSER_MODULES = frozenset({"json", "orjson", "ujson", "simplejson"})
JSON_LEAF_SINKS = frozenset({"loads", "load"})

# A unit-test assertion compares two values; it is not a place where data is handed to something
# dangerous. Left unmarked, a helper shaped like `ZulipTestCaseMixin.assertEqual(self, first, second)`
# that touches `subprocess.check_output` internally lifts a CWE-78 contract onto `first`, and every
# test that passes data in becomes a cross-file finding.
TEST_ASSERTION_METHODS = frozenset({
    "assertEqual", "assertNotEqual", "assertIn", "assertNotIn", "assertIs", "assertIsNot",
    "assertTrue", "assertFalse", "assertRaises", "assertAlmostEqual", "assertGreater",
    "assertDictContainsSubset", "raises",
})


def _has_static_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True for a @staticmethod, whose first parameter is a real argument, not a receiver."""
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "staticmethod":
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr == "staticmethod":
            return True
    return False


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    """The literal string a key expression holds, or None when it is not one."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


@dataclass(slots=True)
class ParamSinkEdge:
    param_idx: int
    param_name: str
    sink_cwe: str
    sink_name: str
    lineno: int


@dataclass
class FunctionSummary:
    qualname: str
    file_path: str
    lineno: int
    params: list[str] = field(default_factory=list)
    tainted_returns: set[int] = field(default_factory=set)  # indices of params that reach 'return'
    param_sinks: list[ParamSinkEdge] = field(default_factory=list)  # params that hit an internal sink
    is_sanitizer: bool = False
    # True when the signature opens with self/cls, i.e. params excludes a bound receiver.
    # Callers that invoke the method unbound (Class.method(instance, ...)) must skip one
    # positional argument so parameter indices stay aligned with params.
    takes_receiver: bool = False


class FunctionSummarizer:
    """Pass 1.5: Computes taint contracts for all indexed functions."""

    def __init__(self, indexer: GlobalSymbolIndex):
        self.indexer = indexer
        self.summaries: dict[tuple[str, str], FunctionSummary] = {}  # (mod_name, func_name) -> Summary

    def build_all_summaries(self) -> dict[tuple[str, str], FunctionSummary]:
        for mod_name, mod_idx in self.indexer.modules.items():
            tree = self.indexer._ast_cache.get(mod_name)
            if not tree:
                continue
            self.summarize_module(mod_name, mod_idx.file_path, tree)

        return self.summaries

    def summarize_module(self, mod_name: str, file_path, tree: ast.AST) -> list[FunctionSummary]:
        """Summarise one module's top-level functions and methods; returns what it created.

        The streaming indexer calls this as each file is parsed, so the tree can be released
        immediately; `build_all_summaries` calls the same code over the cached trees, which
        keeps insertion order (and therefore every downstream iteration) identical.
        """
        path_str = str(file_path)
        created: list[FunctionSummary] = []
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                summary = self._summarize_function(stmt, mod_name, path_str)
                self.summaries[(mod_name, stmt.name)] = summary
                created.append(summary)
            elif isinstance(stmt, ast.ClassDef):
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qual = f"{stmt.name}.{item.name}"
                        summary = self._summarize_function(
                            item, mod_name, path_str,
                            qualname=qual, is_method=True,
                        )
                        self.summaries[(mod_name, qual)] = summary
                        created.append(summary)
        return created

    def _summarize_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        mod_name: str,
        file_path: str,
        qualname: Optional[str] = None,
        is_method: bool = False,
    ) -> FunctionSummary:
        name = qualname or node.name
        takes_receiver = bool(
            is_method
            and not _has_static_decorator(node)
            and node.args.args
            and node.args.args[0].arg in ("self", "cls")
        )
        params = [a.arg for a in (node.args.args[1:] if takes_receiver else node.args.args)]
        kw_containers, kw_slots = self._kwarg_slots(node, params)
        params = params + kw_slots
        param_to_idx = {p: i for i, p in enumerate(params)}

        summary = FunctionSummary(
            qualname=name,
            file_path=file_path,
            lineno=node.lineno,
            params=params,
            takes_receiver=takes_receiver,
        )

        # Sanitizer heuristic
        if any(san in name.lower() for san in KNOWN_SANITIZERS):
            summary.is_sanitizer = True

        # A test assertion compares two values, so it owns no sink obligation and returns no tainted
        # value. Declaring the contract empty -- rather than pruning its callers -- is what stops an
        # assertion helper from becoming a cross-file taint hop.
        if node.name in TEST_ASSERTION_METHODS:
            return summary

        # Intra-function variable flow tracking
        # Maps local_var -> set of param indices it was derived from
        alias_map: dict[str, set[int]] = {p: {i} for i, p in enumerate(params)}
        # Collecting the sanitized locals and the Return nodes inside the sweep below replaces
        # two extra full traversals of the same body. The walk order is identical to the
        # dedicated passes it replaces (same `for stmt in node.body` / `ast.walk(stmt)` nesting),
        # so the add/discard sequence for `sanitized` is unchanged and every Return is still
        # evaluated against the finished alias_map by the post-loop check.
        returns: list[ast.Return] = []
        sanitized: Set[str] = set()

        for stmt in node.body:
            for sub in ast.walk(stmt):
                # 1. Track assignments: local_var = param
                if isinstance(sub, ast.Assign):
                    callee = (
                        self._callee_name(sub.value.func)
                        if isinstance(sub.value, ast.Call)
                        else None
                    )
                    produced_by_sanitizer = callee in KNOWN_SANITIZERS
                    for target in sub.targets:
                        if isinstance(target, ast.Name):
                            if produced_by_sanitizer:
                                sanitized.add(target.id)
                            else:
                                sanitized.discard(target.id)

                    val_params = self._resolve_referenced_params(sub.value, alias_map, kw_containers)
                    if val_params:
                        for target in sub.targets:
                            if isinstance(target, ast.Name):
                                alias_map.setdefault(target.id, set()).update(val_params)

                # 2. Track Returns: return param / return expr(param)
                elif isinstance(sub, ast.Return) and sub.value is not None:
                    returns.append(sub)
                    ret_params = self._resolve_referenced_params(sub.value, alias_map, kw_containers)
                    summary.tainted_returns.update(ret_params)

                # 3. Track Sinks: sink_call(param)
                elif isinstance(sub, ast.Call):
                    call_name = ""
                    if isinstance(sub.func, ast.Name):
                        call_name = sub.func.id
                    elif isinstance(sub.func, ast.Attribute):
                        call_name = sub.func.attr

                    cwe = KNOWN_SINKS.get(call_name)
                    if cwe == "CWE-502" and call_name in JSON_LEAF_SINKS:
                        # Same leaf, different guarantee: a JSON parser builds values, not objects.
                        if self._parses_json_only(sub.func, mod_name):
                            continue
                    if cwe:
                        for position, arg in enumerate(sub.args):
                            # DB-API semantics: execute(operation, parameters) interpolates
                            # only the operation slot into the statement, so taint that reaches
                            # the parameters slot is bound by the driver and not injectable.
                            if cwe == "CWE-89" and position > 0:
                                continue
                            arg_params = self._resolve_referenced_params(arg, alias_map, kw_containers)
                            for p_idx in arg_params:
                                edge = ParamSinkEdge(
                                    param_idx=p_idx,
                                    param_name=params[p_idx],
                                    sink_cwe=cwe,
                                    sink_name=call_name,
                                    lineno=getattr(sub, "lineno", stmt.lineno),
                                )
                                summary.param_sinks.append(edge)

        # Body-level sanitizer evidence: the name heuristic above misses helpers such as
        # `format_command` that sanitize through a call rather than through their own name.
        if not summary.is_sanitizer and params and not summary.param_sinks:
            propagating = [
                ret.value
                for ret in returns
                if self._resolve_referenced_params(ret.value, alias_map, kw_containers)
            ]
            if propagating and all(
                self._is_sanitized_expr(expr, sanitized) for expr in propagating
            ):
                summary.is_sanitizer = True

        return summary

    def _parses_json_only(self, func: ast.AST, mod_name: str) -> bool:
        """True when this `loads`/`load` callee is a JSON parser, whichever name it was imported under.

        The leaf name cannot answer that on its own -- `pickle.loads` and `orjson.loads` are spelled
        identically from here -- so the receiver is resolved through the file's own import bindings,
        which covers `import orjson as oj`. Anything unresolvable stays a sink: the rule refuses only
        what it can name.
        """
        module_index = self.indexer.modules.get(mod_name)
        bindings = getattr(module_index, "imports", None)
        if not bindings:
            return False
        if isinstance(func, ast.Attribute):
            receiver = func.value
            local = receiver.id if isinstance(receiver, ast.Name) else ""
            binding = bindings.get(local)
            return binding is not None and binding.source_module in JSON_PARSER_MODULES
        if isinstance(func, ast.Name):
            binding = bindings.get(func.id)
            return (binding is not None
                    and binding.source_module in JSON_PARSER_MODULES
                    and binding.imported_name in JSON_LEAF_SINKS)
        return False

    @staticmethod
    def _callee_name(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _is_sanitized_expr(self, expr: ast.AST, sanitized_locals: Set[str]) -> bool:
        if isinstance(expr, ast.Call):
            return self._callee_name(expr.func) in KNOWN_SANITIZERS
        if isinstance(expr, ast.Name):
            return expr.id in sanitized_locals
        return False

    def _resolve_referenced_params(
        self,
        expr: ast.AST,
        alias_map: dict[str, set[int]],
        kw_containers: frozenset[str] = frozenset(),
    ) -> set[int]:
        referenced: set[int] = set()
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and node.id in alias_map:
                referenced.update(alias_map[node.id])
            elif kw_containers:
                slot = self._kwarg_slot(node, kw_containers)
                if slot is not None and f"{slot[0]}[{slot[1]}]" in alias_map:
                    referenced.update(alias_map[f"{slot[0]}[{slot[1]}]"])
        return referenced

    @staticmethod
    def _kwarg_slot(node: ast.AST, kw_containers: frozenset[str]) -> Optional[tuple[str, str]]:
        """(container, literal key) for `kwargs["k"]` / `kwargs.get("k")` reads."""
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id in kw_containers:
                key = _const_str(node.slice)
                return (node.value.id, key) if key is not None else None
            return None
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("get", "pop") and node.args
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in kw_containers):
            key = _const_str(node.args[0])
            return (node.func.value.id, key) if key is not None else None
        return None

    @staticmethod
    def _kwarg_slots(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        params: list[str],
    ) -> tuple[frozenset[str], list[str]]:
        """Per-key contract slots for a `**kwargs` parameter.

        Django signal receivers take their payload through `**kwargs`, so a receiver such as
        `def on_event(sender, **kwargs): os.system(kwargs["payload"])` has no positional
        parameter to bind the emission keyword onto. Only the literal keys the body actually
        reads become slots, which keeps each payload key tracked on its own instead of tainting
        the whole mapping.
        """
        if node.args.kwarg is None:
            return frozenset(), []
        container = node.args.kwarg.arg
        if container in params:
            return frozenset(), []
        slots: list[str] = []
        seen = {container}
        for sub in ast.walk(node):
            slot = FunctionSummarizer._kwarg_slot(sub, frozenset({container}))
            if slot is None:
                continue
            virtual = f"{slot[0]}[{slot[1]}]"
            if virtual not in seen:
                seen.add(virtual)
                slots.append(virtual)
        return frozenset({container}), slots


if __name__ == "__main__":
    import time

    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Building Symbol Index for: {target_dir}")
    indexer = GlobalSymbolIndex(target_dir).build()

    print("[*] Extracting Function Taint Contracts...")
    t0 = time.perf_counter()
    summarizer = FunctionSummarizer(indexer)
    contracts = summarizer.build_all_summaries()
    elapsed = (time.perf_counter() - t0) * 1000

    total_funcs = len(contracts)
    funcs_with_sinks = sum(1 for c in contracts.values() if c.param_sinks)
    funcs_with_returns = sum(1 for c in contracts.values() if c.tainted_returns)

    print("\n--- FUNCTION TAINT CONTRACTS SUMMARY ---")
    print(f"Total Functions Summarized:     {total_funcs}")
    print(f"Functions Propagating to Return: {funcs_with_returns}")
    print(f"Functions Leading to Sinks:     {funcs_with_sinks}")
    print(f"Contract Analysis Time:         {elapsed:.2f} ms")

    # Sample dangerous sink contracts
    if funcs_with_sinks > 0:
        print("\n[+] Top Identified Sink Contracts:")
        count = 0
        for (m, f), c in contracts.items():
            for s in c.param_sinks:
                print(f"  • {m}.{f}(param '{s.param_name}') -> {s.sink_name} [{s.sink_cwe}] at line {s.lineno}")
                count += 1
                if count >= 5:
                    break
            if count >= 5:
                break