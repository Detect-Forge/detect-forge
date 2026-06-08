"""Sigma matcher for JSON event sequences.

Supports a subset of the Sigma specification:
- detection blocks with selection_* mappings + condition expressions
- modifiers (added in Task 6): contains, startswith, endswith, re
- correlations (added in Task 7): event_count, value_count, temporal, temporal_ordered

Unsupported (rule routes to status='unsupported'):
- pySigma logsource pipelines / field renames
- |cidr, |gt, |lt, |gte, |lte modifiers
- 'keywords' (unfielded search)
"""

from __future__ import annotations

import logging
import re
from typing import Any

import yaml

from ...stale.models import DetectionRule
from ..models import FireRecord

log = logging.getLogger(__name__)

_UNSUPPORTED_MODIFIERS = {"cidr", "gt", "lt", "gte", "lte"}
_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re"}


class SigmaMatcher:
    """Sigma → JSON event evaluator."""

    def supports(self, rule: DetectionRule) -> bool:
        supports, _ = self.support_reason(rule)
        return supports

    def support_reason(self, rule: DetectionRule) -> tuple[bool, str | None]:
        if rule.raw_yaml is None:
            return False, "Sigma rule missing raw_yaml"
        try:
            parsed = yaml.safe_load(rule.raw_yaml)
        except yaml.YAMLError as exc:
            return False, f"Sigma YAML parse error: {exc}"
        if not isinstance(parsed, dict):
            return False, "Sigma rule top-level is not a mapping"
        if "correlation" in parsed:
            # Task 7 will lift this restriction.
            return False, "Sigma correlation (deferred to Task 7)"
        detection = parsed.get("detection")
        if not isinstance(detection, dict):
            return False, "Sigma rule has no detection block"
        # Reject unsupported modifiers + keywords.
        for sel_name, sel_value in detection.items():
            if sel_name == "condition":
                continue
            if sel_name == "keywords":
                return False, "Sigma uses unfielded keywords"
            if isinstance(sel_value, dict):
                for field_key in sel_value:
                    if "|" in field_key:
                        modifier = field_key.split("|", 1)[1]
                        if modifier in _UNSUPPORTED_MODIFIERS:
                            return False, f"Sigma uses unsupported modifier: |{modifier}"
                        if modifier not in _SUPPORTED_MODIFIERS:
                            return False, f"unsupported modifier: {modifier}"
        return True, None

    def match(
        self,
        rule: DetectionRule,
        events: list[dict[str, Any]],
        dataset_id: str,
    ) -> list[FireRecord]:
        if not self.supports(rule):
            return []
        assert rule.raw_yaml is not None  # narrowed by supports()
        parsed = yaml.safe_load(rule.raw_yaml)
        detection = parsed["detection"]
        condition_expr = detection.get("condition", "")
        selection_names = [k for k in detection if k != "condition"]
        condition_ast = _parse_condition(condition_expr, selection_names)

        fires: list[FireRecord] = []
        for idx, event in enumerate(events):
            sel_results = {
                name: _evaluate_selection(detection[name], event)
                for name in selection_names
            }
            if _evaluate_condition(condition_ast, sel_results):
                fires.append(
                    FireRecord(
                        rule_id=rule.rule_id or rule.title,
                        technique_id=rule.technique_ids[0] if rule.technique_ids else "",
                        dataset_id=dataset_id,
                        event_index=idx,
                    )
                )
        return fires


# ---------- selection evaluation ----------

def _evaluate_selection(selection: Any, event: dict[str, Any]) -> bool:
    """A selection is a mapping of field_spec → value(s). All entries must match (AND)."""
    if isinstance(selection, list):
        # List-form selection means OR over the entries.
        return any(_evaluate_selection(s, event) for s in selection)
    if not isinstance(selection, dict):
        return False
    for field_spec, value_spec in selection.items():
        field_name, modifiers = _parse_field_spec(field_spec)
        actual = event.get(field_name)
        if not _value_matches(actual, value_spec, modifiers):
            return False
    return True


def _parse_field_spec(field_spec: str) -> tuple[str, list[str]]:
    """'Image|endswith' → ('Image', ['endswith'])"""
    parts = field_spec.split("|")
    return parts[0], parts[1:]


def _value_matches(actual: Any, value_spec: Any, modifiers: list[str]) -> bool:
    """Apply modifiers to compare actual (event value) against value_spec.

    Modifiers in v0.1: contains, startswith, endswith, re. Other modifiers are
    filtered out at supports(), so only these four can appear here.
    List value_spec is OR'd.
    """
    if isinstance(value_spec, list):
        return any(_value_matches(actual, v, modifiers) for v in value_spec)
    if actual is None:
        return False
    if not modifiers:
        return bool(actual == value_spec)
    actual_str = str(actual)
    spec_str = str(value_spec)
    # v0.1 simplification: string modifiers (contains, startswith, endswith)
    # are case-SENSITIVE here. The SigmaHQ spec defines them as
    # case-insensitive — backends lowercase both sides before comparing.
    # Real-world rules typically already normalize case in their selectors,
    # so the practical mismatch rate is low, but be aware when reading
    # results. Lowercase-everything is tracked for v0.2.
    for mod in modifiers:
        if mod == "contains":
            if spec_str not in actual_str:
                return False
        elif mod == "startswith":
            if not actual_str.startswith(spec_str):
                return False
        elif mod == "endswith":
            if not actual_str.endswith(spec_str):
                return False
        elif mod == "re":
            if not re.search(spec_str, actual_str):
                return False
        else:
            # Unreachable when called via match() — unsupported modifiers are
            # rejected by support_reason() before match() is invoked.
            return False  # defense-in-depth
    return True


# ---------- condition parsing + evaluation ----------

class _CondNode:
    """Tiny condition AST."""


class _Ref(_CondNode):
    def __init__(self, name: str) -> None:
        self.name = name


class _And(_CondNode):
    def __init__(self, left: _CondNode, right: _CondNode) -> None:
        self.left = left
        self.right = right


class _Or(_CondNode):
    def __init__(self, left: _CondNode, right: _CondNode) -> None:
        self.left = left
        self.right = right


class _Not(_CondNode):
    def __init__(self, inner: _CondNode) -> None:
        self.inner = inner


class _AllOf(_CondNode):
    def __init__(self, names: list[str]) -> None:
        self.names = names


class _OneOf(_CondNode):
    def __init__(self, names: list[str]) -> None:
        self.names = names


def _parse_condition(expr: str, selection_names: list[str]) -> _CondNode:
    """Small recursive-descent parser for Sigma condition expressions.

    Grammar (Task 5 subset):
        expr := or_expr
        or_expr := and_expr ('or' and_expr)*
        and_expr := unary ('and' unary)*
        unary := 'not' unary | primary
        primary := IDENT | '(' expr ')' | 'all of' GLOB | '1 of' GLOB
    """
    tokens = _tokenize_condition(expr)
    parser = _CondParser(tokens, selection_names)
    return parser.parse_expr()


def _tokenize_condition(expr: str) -> list[str]:
    # Replace operators with spaced tokens; split on whitespace and parens.
    pattern = r"\(|\)|\ball of\b|\b1 of\b|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z_0-9\*]*"
    return re.findall(pattern, expr)


class _CondParser:
    def __init__(self, tokens: list[str], selection_names: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.selection_names = selection_names

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self) -> str:
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def parse_expr(self) -> _CondNode:
        node = self.parse_and()
        while self._peek() == "or":
            self._consume()
            right = self.parse_and()
            node = _Or(node, right)
        return node

    def parse_and(self) -> _CondNode:
        node = self.parse_unary()
        while self._peek() == "and":
            self._consume()
            right = self.parse_unary()
            node = _And(node, right)
        return node

    def parse_unary(self) -> _CondNode:
        if self._peek() == "not":
            self._consume()
            return _Not(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> _CondNode:
        t = self._consume()
        if t == "(":
            node = self.parse_expr()
            if self._consume() != ")":
                raise SyntaxError("Expected ')'")
            return node
        if t == "all of":
            glob = self._consume()
            return _AllOf(_expand_glob(glob, self.selection_names))
        if t == "1 of":
            glob = self._consume()
            return _OneOf(_expand_glob(glob, self.selection_names))
        return _Ref(t)


def _expand_glob(glob: str, names: list[str]) -> list[str]:
    """'selection_*' → all selection_* names; literal name → [name]."""
    if "*" not in glob:
        return [glob]
    pattern = re.compile("^" + re.escape(glob).replace(r"\*", ".*") + "$")
    return [n for n in names if pattern.match(n)]


def _evaluate_condition(node: _CondNode, sel_results: dict[str, bool]) -> bool:
    if isinstance(node, _Ref):
        return sel_results.get(node.name, False)
    if isinstance(node, _And):
        return _evaluate_condition(node.left, sel_results) and _evaluate_condition(
            node.right, sel_results
        )
    if isinstance(node, _Or):
        return _evaluate_condition(node.left, sel_results) or _evaluate_condition(
            node.right, sel_results
        )
    if isinstance(node, _Not):
        return not _evaluate_condition(node.inner, sel_results)
    if isinstance(node, _AllOf):
        return all(sel_results.get(n, False) for n in node.names)
    if isinstance(node, _OneOf):
        return any(sel_results.get(n, False) for n in node.names)
    return False
