"""A small YAML subset parser.

It covers what policy files need: nested mappings, block sequences, flow
sequences and mappings, quoted and plain scalars, comments, and literal or
folded block scalars. It does not support anchors, aliases, tags, or
multi document streams, and it raises YamlError when it meets one of those.

JSON is valid YAML for the shapes we care about, so a document that starts
with "{" is handed to json.loads first.
"""

from __future__ import annotations

import json
import re


class YamlError(ValueError):
    """Raised when a document is outside the supported YAML subset."""

    def __init__(self, message: str, line: int | None = None) -> None:
        self.line = line
        if line is not None:
            message = "line %d: %s" % (line, message)
        super().__init__(message)


_TRUE = frozenset({"true", "yes", "on"})
_FALSE = frozenset({"false", "no", "off"})
_NULL = frozenset({"null", "~", "none"})

_INT_RE = re.compile(r"[-+]?\d+")
_FLOAT_RE = re.compile(r"[-+]?(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?|[-+]?\d+[eE][-+]?\d+")


class _Line:
    __slots__ = ("indent", "text", "number")

    def __init__(self, indent: int, text: str, number: int) -> None:
        self.indent = indent
        self.text = text
        self.number = number

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "_Line(%d, %r, %d)" % (self.indent, self.text, self.number)


def _strip_comment(text: str) -> str:
    out: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is not None:
            out.append(ch)
            if quote == "'" and ch == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                quote = None
            elif quote == '"' and ch == "\\":
                if i + 1 < len(text):
                    out.append(text[i + 1])
                    i += 2
                    continue
            elif quote == '"' and ch == '"':
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            break
        out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _split_key(text: str) -> tuple[str | None, str | None]:
    quote: str | None = None
    for i, ch in enumerate(text):
        if quote is not None:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            continue
        if ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].strip(), text[i + 1:].strip()
    return None, None


def _split_flow(text: str, line: int) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    i = 0
    while i < len(text):
        ch = text[i]
        if quote == '"':
            buf.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quote = None
            i += 1
            continue
        if quote == "'":
            buf.append(ch)
            if ch == "'" and i + 1 < len(text) and text[i + 1] == "'":
                buf.append("'")
                i += 2
                continue
            if ch == "'":
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
            if depth < 0:
                raise YamlError("unbalanced brackets in flow collection", line)
        if ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if quote is not None:
        raise YamlError("unterminated string in flow collection", line)
    if depth != 0:
        raise YamlError("unbalanced brackets in flow collection", line)
    tail = "".join(buf).strip()
    if tail or parts:
        parts.append(tail)
    return parts


def parse_scalar(text: str, line: int):
    t = text.strip()
    if not t:
        return None
    if t[0] == '"':
        if len(t) < 2 or not t.endswith('"'):
            raise YamlError("unterminated double quoted string", line)
        try:
            return json.loads(t)
        except json.JSONDecodeError as exc:
            raise YamlError("invalid double quoted string: %s" % exc.msg, line) from None
    if t[0] == "'":
        if len(t) < 2 or not t.endswith("'"):
            raise YamlError("unterminated single quoted string", line)
        return t[1:-1].replace("''", "'")
    if t[0] == "[":
        if not t.endswith("]"):
            raise YamlError("unterminated flow sequence", line)
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(part, line) for part in _split_flow(inner, line)]
    if t[0] == "{":
        if not t.endswith("}"):
            raise YamlError("unterminated flow mapping", line)
        inner = t[1:-1].strip()
        result: dict = {}
        if not inner:
            return result
        for part in _split_flow(inner, line):
            key, rest = _split_key(part)
            if key is None:
                raise YamlError("expected 'key: value' in flow mapping, got %r" % part, line)
            result[str(parse_scalar(key, line))] = parse_scalar(rest, line)
        return result
    low = t.lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    if low in _NULL:
        return None
    if _INT_RE.fullmatch(t):
        return int(t)
    if _FLOAT_RE.fullmatch(t):
        return float(t)
    return t


def _tokenize(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        raw = raw.rstrip()
        if not raw.strip():
            continue
        leading = raw[: len(raw) - len(raw.lstrip(" \t"))]
        if "\t" in leading:
            raise YamlError("tabs are not allowed for indentation", number)
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append(_Line(indent, stripped[indent:], number))
    return lines


def _parse_block_scalar(lines: list[_Line], index: int, parent_indent: int, style: str, number: int):
    block: list[str] = []
    block_indent: int | None = None
    while index < len(lines) and lines[index].indent > parent_indent:
        if block_indent is None:
            block_indent = lines[index].indent
        block.append(" " * max(0, lines[index].indent - block_indent) + lines[index].text)
        index += 1
    if style.startswith(">"):
        return " ".join(part.strip() for part in block).strip(), index
    return "\n".join(block).strip("\n"), index


def _parse_mapping(lines: list[_Line], index: int, indent: int):
    result: dict = {}
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise YamlError("unexpected indentation", line.number)
        if line.text == "-" or line.text.startswith("- "):
            break
        key, rest = _split_key(line.text)
        if key is None:
            raise YamlError("expected 'key: value', got %r" % line.text, line.number)
        if key == "":
            raise YamlError("empty mapping key", line.number)
        if rest == "":
            index += 1
            if index < len(lines) and lines[index].indent > indent:
                value, index = _parse_block(lines, index, lines[index].indent)
            else:
                value = None
        elif rest in ("|", ">", "|-", ">-", "|+", ">+"):
            value, index = _parse_block_scalar(lines, index + 1, indent, rest, line.number)
        else:
            value = parse_scalar(rest, line.number)
            index += 1
        if key in result:
            raise YamlError("duplicate key %r" % key, line.number)
        result[key] = value
    return result, index


def _parse_sequence(lines: list[_Line], index: int, indent: int):
    items: list = []
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise YamlError("unexpected indentation in sequence", line.number)
        if not (line.text == "-" or line.text.startswith("- ")):
            break
        rest = line.text[1:].strip()
        if rest == "":
            index += 1
            if index < len(lines) and lines[index].indent > indent:
                value, index = _parse_block(lines, index, lines[index].indent)
            else:
                value = None
        else:
            key, _ = _split_key(rest)
            if key is not None:
                line.text = rest
                line.indent = indent + 2
                value, index = _parse_mapping(lines, index, indent + 2)
            else:
                value = parse_scalar(rest, line.number)
                index += 1
        items.append(value)
    return items, index


def _parse_block(lines: list[_Line], index: int, indent: int):
    line = lines[index]
    if line.text == "-" or line.text.startswith("- "):
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def loads(text: str):
    """Parse a YAML document into Python objects."""
    if not isinstance(text, str):
        raise TypeError("loads() expects a string")
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    lines = _tokenize(text)
    if not lines:
        return None
    first = lines[0]
    if not (first.text == "-" or first.text.startswith("- ")):
        if _split_key(first.text)[0] is None:
            if len(lines) > 1:
                raise YamlError("unexpected content after a scalar", lines[1].number)
            return parse_scalar(first.text, first.number)
    value, index = _parse_block(lines, 0, first.indent)
    if index != len(lines):
        raise YamlError("unexpected content", lines[index].number)
    return value


def load_file(path) -> object:
    from pathlib import Path

    return loads(Path(path).read_text(encoding="utf-8"))
