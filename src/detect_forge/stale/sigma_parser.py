from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from pathlib import Path

import yaml
from pydantic import ValidationError

from ._dates import _parse_rule_date
from .models import DetectionRule

log = logging.getLogger(__name__)

# Matches technique IDs: "attack." + "t" + 4 digits, optionally followed by ".<3 digits>".
_TECHNIQUE_PATTERN = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def _extract_technique_ids(tags: Sequence[object]) -> list[str]:
    """Return normalised ATT&CK technique IDs from a Sigma tags list.

    Skips tactics, groups, software refs, non-ATT&CK namespaces, and any
    non-string values (YAML can yield ints or bools for malformed tags).
    The output is uppercase dot-notation (e.g. "T1059.001") preserving
    source order.
    """
    ids: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        m = _TECHNIQUE_PATTERN.match(tag.strip())
        if m:
            ids.append(m.group(1).upper())
    return ids


def parse_rule_file(path: Path) -> DetectionRule | None:
    """Parse a single Sigma YAML rule file.

    Returns None if the file can't be read, isn't valid YAML, isn't a YAML dict,
    or fails DetectionRule validation.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        log.warning("Failed to read %s: %s", path, exc)
        return None

    if not isinstance(raw, dict):
        log.debug("Skipping non-dict YAML in %s", path)
        return None

    tags: list[str] = raw.get("tags") or []
    technique_ids = _extract_technique_ids(tags)

    try:
        return DetectionRule(
            rule_id=raw.get("id"),
            title=raw.get("title", path.stem),
            description=raw.get("description"),
            status=raw.get("status"),
            rule_date=_parse_rule_date(raw.get("date")),
            modified_date=_parse_rule_date(raw.get("modified")),
            technique_ids=technique_ids,
            source_file=path.resolve(),
            raw_tags=tags,
        )
    except ValidationError as exc:
        log.warning("Validation error parsing %s: %s", path, exc)
        return None
