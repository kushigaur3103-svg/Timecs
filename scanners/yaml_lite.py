"""A streaming YAML subset reader for security auditing -- stdlib only, no PyYAML.

The container and IaC rules need three things from a YAML document: the key path a value sits at,
the line it sits on, and its literal text. They do not need anchors, tags, merge keys, flow
collections beyond the empty ``{}``/``[]``, or multi-document streams. This reader implements
exactly that subset and refuses to guess at the rest: a construct it cannot represent becomes a
scalar holding the raw text, so a rule reading it sees an unresolvable value and stays quiet
rather than inventing a structure.

Keys are kept as the literal source spelling. PyYAML resolves a bare ``on:`` to the boolean
``True`` (YAML 1.1), which silently loses every GitHub Actions trigger block; here ``on`` stays
``on`` because the auditor asks about the document, not about a YAML 1.1 type system.

Memory is one line list plus one node per entry -- no whole-file regex sweep, no dependency.
"""

from __future__ import annotations

from typing import Any, Iterator, List, Optional, Tuple

__all__ = ["Scalar", "Mapping", "Sequence", "parse", "get", "walk", "scalar_text"]


class Scalar:
    __slots__ = ("lineno", "text", "end_lineno")

    def __init__(self, lineno: int, text: str, end_lineno: Optional[int] = None) -> None:
        self.lineno = lineno
        self.text = text
        self.end_lineno = lineno if end_lineno is None else end_lineno


class Mapping:
    __slots__ = ("lineno", "items")

    def __init__(self, lineno: int) -> None:
        self.lineno = lineno
        self.items: List[Tuple[str, int, Any]] = []


class Sequence:
    __slots__ = ("lineno", "items")

    def __init__(self, lineno: int) -> None:
        self.lineno = lineno
        self.items: List[Tuple[int, Any]] = []


_BLOCK_SCALARS = frozenset({"|", "|-", "|+", ">", ">-", ">+"})


def _strip_comment(text: str) -> str:
    """Drop a trailing ``#`` comment that is outside quotes."""
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index].rstrip()
    return text.rstrip()


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _lines(source: str) -> List[Tuple[int, int, str, str]]:
    """[(lineno, indent, content, raw)] for every non-blank, non-comment line."""
    out: List[Tuple[int, int, str, str]] = []
    for lineno, raw in enumerate(source.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in ("---", "..."):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        out.append((lineno, indent, _strip_comment(stripped), raw))
    return out


class _Reader:
    def __init__(self, source: str) -> None:
        self.raw = source.splitlines()
        self.lines = _lines(source)
        self.index = 0

    def peek(self) -> Optional[Tuple[int, int, str, str]]:
        return self.lines[self.index] if self.index < len(self.lines) else None

    def block_scalar(self, header_indent: int, style: str) -> Scalar:
        """Consume the indented body of a ``|``/``>`` scalar, keeping its own line numbers."""
        start = self.index
        body: List[str] = []
        body_indent: Optional[int] = None
        last_lineno = self.lines[start][0] if start < len(self.lines) else 1
        while self.index < len(self.lines):
            lineno, indent, _content, raw = self.lines[self.index]
            if indent <= header_indent:
                break
            if body_indent is None:
                body_indent = indent
            body.append(raw[body_indent:] if len(raw) >= body_indent else raw.strip())
            last_lineno = lineno
            self.index += 1
        if not body:
            return Scalar(last_lineno, "")
        text = "\n".join(body) if style.startswith("|") else " ".join(part.strip() for part in body)
        if style.endswith("-"):
            text = text.rstrip("\n")
        return Scalar(self.lines[start][0], text, last_lineno)

    def parse_block(self, indent: int) -> Any:
        entry = self.peek()
        if entry is None or entry[1] < indent:
            return Scalar(entry[0] if entry else 1, "")
        if entry[2].startswith("- ") or entry[2] == "-":
            return self.parse_sequence(entry[1])
        return self.parse_mapping(entry[1])

    def parse_sequence(self, indent: int) -> Sequence:
        node = Sequence(self.peek()[0])
        while True:
            entry = self.peek()
            if entry is None or entry[1] != indent or not (entry[2].startswith("- ") or entry[2] == "-"):
                break
            lineno, _indent, content, _raw = entry
            self.index += 1
            remainder = content[1:].strip()
            if not remainder:
                child = self.parse_block(indent + 1)
                node.items.append((lineno, child))
                continue
            item_indent = indent + (len(content) - len(content[1:].lstrip()))
            if ":" in remainder and not remainder.startswith(("'", '"')):
                key, _, value = remainder.partition(":")
                mapping = Mapping(lineno)
                self.fill_entry(mapping, key.strip(), value.strip(), lineno, item_indent)
                while True:
                    nxt = self.peek()
                    if nxt is None or nxt[1] != item_indent or nxt[2].startswith("- "):
                        break
                    self.index += 1
                    k, _, v = nxt[2].partition(":")
                    self.fill_entry(mapping, k.strip(), v.strip(), nxt[0], item_indent)
                node.items.append((lineno, mapping))
            else:
                node.items.append((lineno, Scalar(lineno, _unquote(remainder))))
        return node

    def fill_entry(self, mapping: Mapping, key: str, value: str, lineno: int, indent: int) -> None:
        key = _unquote(key)
        if value in _BLOCK_SCALARS:
            mapping.items.append((key, lineno, self.block_scalar(indent, value)))
            return
        if value:
            mapping.items.append((key, lineno, Scalar(lineno, _unquote(value))))
            return
        nxt = self.peek()
        if nxt is not None and nxt[1] > indent:
            mapping.items.append((key, lineno, self.parse_block(nxt[1])))
        elif nxt is not None and nxt[1] == indent and (nxt[2].startswith("- ") or nxt[2] == "-"):
            mapping.items.append((key, lineno, self.parse_sequence(indent)))
        else:
            mapping.items.append((key, lineno, Scalar(lineno, "")))

    def parse_mapping(self, indent: int) -> Mapping:
        node = Mapping(self.peek()[0])
        while True:
            entry = self.peek()
            if entry is None or entry[1] != indent or entry[2].startswith("- "):
                break
            if ":" not in entry[2]:
                break
            self.index += 1
            key, _, value = entry[2].partition(":")
            self.fill_entry(node, key.strip(), value.strip(), entry[0], indent)
        return node


def parse(source: str) -> Any:
    """Parse the first document of ``source`` into Mapping/Sequence/Scalar nodes."""
    reader = _Reader(source)
    if not reader.lines:
        return Scalar(1, "")
    return reader.parse_block(reader.lines[0][1])


def get(node: Any, key: str) -> Optional[Any]:
    """The value node under ``key`` in a mapping, or None. Last write wins, as YAML does."""
    if not isinstance(node, Mapping):
        return None
    found = None
    for name, _lineno, value in node.items:
        if name == key:
            found = value
    return found


def scalar_text(node: Any) -> str:
    return node.text if isinstance(node, Scalar) else ""


def walk(node: Any, path: Tuple[str, ...] = ()) -> Iterator[Tuple[Tuple[str, ...], int, Any]]:
    """Yield ``(key_path, lineno, node)`` once per node, depth first, in source order."""
    yield path, getattr(node, "lineno", 1), node
    if isinstance(node, Mapping):
        for key, _lineno, value in node.items:
            yield from walk(value, path + (key,))
    elif isinstance(node, Sequence):
        for _lineno, value in node.items:
            yield from walk(value, path + ("[]",))