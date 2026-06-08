"""Small Kibana Query Language (KQL/kuery) evaluator.

Grammar supported in v0.1:
- field equality: ``field: value``
- wildcards in value: ``field: "power*"`` matches anything starting with ``power``
- quoted strings: ``field: "value with spaces"``
- boolean composition: ``and``, ``or``, ``not``, parens
- dotted field paths resolve into nested dicts (e.g., ``process.name``)

NOT supported in v0.1 (rule routes to ``unsupported``):
- field-less keyword search (e.g., bare ``"powershell.exe"``)
- range queries (``field > 5``, ``field <= "x"``)
- exists queries (``field: *``)
- nested KQL (``field:{ inner: value }``)

Public entry points:
- ``parse_kql(query) -> KqlNode`` — raises KqlUnsupported on out-of-subset features
- ``evaluate(node, event) -> bool``
"""

from __future__ import annotations

import re
from typing import Any


class KqlNode:
    pass


class KqlAnd(KqlNode):
    def __init__(self, left: KqlNode, right: KqlNode) -> None:
        self.left, self.right = left, right


class KqlOr(KqlNode):
    def __init__(self, left: KqlNode, right: KqlNode) -> None:
        self.left, self.right = left, right


class KqlNot(KqlNode):
    def __init__(self, inner: KqlNode) -> None:
        self.inner = inner


class KqlField(KqlNode):
    def __init__(self, field: str, value: str) -> None:
        self.field = field
        self.value = value


class KqlUnsupported(Exception):
    """Raised when the query uses a feature not in v0.1 KQL subset."""


_TOKEN_RE = re.compile(
    r'\(|\)|\{|\}|"[^"]*"|\band\b|\bor\b|\bnot\b|:|[^\s\(\):\{\}]+',
    re.IGNORECASE,
)


def _tokenize(query: str) -> list[str]:
    return _TOKEN_RE.findall(query)


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self) -> str:
        if self.pos >= len(self.tokens):
            raise KqlUnsupported("Unexpected end of query")
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def parse_or(self) -> KqlNode:
        node = self.parse_and()
        while (p := self._peek()) is not None and p.lower() == "or":
            self._consume()
            right = self.parse_and()
            node = KqlOr(node, right)
        return node

    def parse_and(self) -> KqlNode:
        node = self.parse_not()
        while (p := self._peek()) is not None and p.lower() == "and":
            self._consume()
            right = self.parse_not()
            node = KqlAnd(node, right)
        return node

    def parse_not(self) -> KqlNode:
        if (p := self._peek()) is not None and p.lower() == "not":
            self._consume()
            return KqlNot(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> KqlNode:
        t = self._consume()
        if t == "(":
            node = self.parse_or()
            close = self._consume()
            if close != ")":
                raise KqlUnsupported(f"Expected ')' got {close!r}")
            return node
        # Expect either a field:value or a field-less keyword.
        if self._peek() == ":":
            self._consume()  # consume ':'
            value_tok = self._consume()
            # Nested object query — out of v0.1 subset.
            if value_tok == "{":
                raise KqlUnsupported(
                    f"Nested KQL (field:{{...}}) not supported: {t}"
                )
            value = value_tok.strip('"')
            # Bare wildcard = KQL "exists" query — out of v0.1 subset.
            if value == "*":
                raise KqlUnsupported(
                    f"Exists query (field: *) not supported: {t}"
                )
            return KqlField(field=t, value=value)
        # Field-less keyword — not supported in v0.1.
        raise KqlUnsupported(f"Field-less keyword search not supported: {t}")


def parse_kql(query: str) -> KqlNode:
    """Parse a KQL query string into an AST node.

    Raises KqlUnsupported on out-of-subset features.
    """
    tokens = _tokenize(query)
    if not tokens:
        raise KqlUnsupported("Empty query")
    parser = _Parser(tokens)
    return parser.parse_or()


def _get_field(event: dict[str, Any], dotted: str) -> Any:
    cur: Any = event
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _value_matches(actual: Any, pattern: str) -> bool:
    if actual is None:
        return False
    if isinstance(actual, list):
        # ECS list-valued fields: KQL matches if ANY element matches the pattern.
        return any(_value_matches(item, pattern) for item in actual)
    s = str(actual)
    if "*" in pattern:
        regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        return re.match(regex, s) is not None
    return s == pattern


def evaluate(node: KqlNode, event: dict[str, Any]) -> bool:
    """Evaluate a parsed KQL AST node against a single event dict."""
    if isinstance(node, KqlField):
        actual = _get_field(event, node.field)
        return _value_matches(actual, node.value)
    if isinstance(node, KqlAnd):
        return evaluate(node.left, event) and evaluate(node.right, event)
    if isinstance(node, KqlOr):
        return evaluate(node.left, event) or evaluate(node.right, event)
    if isinstance(node, KqlNot):
        return not evaluate(node.inner, event)
    return False
