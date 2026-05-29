"""Matcher protocol and format-detection helper.

Each matcher is stateless: given a parsed rule and a JSON event list, return
the rule's fire records for that event sequence. Per-rule capability is
expressed via ``supports()``; rules the matcher can't evaluate route through
the ``unsupported`` status path with a reason string.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol

from ...stale.models import DetectionRule
from ..models import FireRecord


class Matcher(Protocol):
    """Stateless matcher protocol."""

    def supports(self, rule: DetectionRule) -> bool:
        """Can this matcher evaluate this rule? False → status='unsupported'."""
        ...

    def support_reason(self, rule: DetectionRule) -> tuple[bool, str | None]:
        """Returns (supports, reason). Reason populated when supports=False
        (e.g., 'Sigma correlation', 'ES|QL', 'uses |cidr modifier')."""
        ...

    def match(
        self,
        rule: DetectionRule,
        events: list[dict[str, Any]],
        dataset_id: str,
    ) -> list[FireRecord]:
        """Return fire records for this rule against this dataset's events.

        Caller truncates per-pair to 20.
        """
        ...


def select_matcher(
    rule: DetectionRule,
) -> tuple[Matcher | None, Literal["sigma", "elastic"]]:
    """Pick a matcher based on the rule's source-file suffix.

    Returns (None, 'sigma') for unknown formats; the orchestrator surfaces
    those as ``unsupported``.

    Note: actual matcher instances are wired up by the orchestrator (Task 10)
    which imports SigmaMatcher and ElasticMatcher. This helper only routes
    by format.
    """
    suffix = rule.source_file.suffix.lower()
    if suffix == ".toml":
        return None, "elastic"  # ElasticMatcher injected by orchestrator
    if suffix in (".yml", ".yaml"):
        return None, "sigma"
    return None, "sigma"
