from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from datetime import date, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

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


def _parse_sigma_date(value: object) -> date | None:
    """Parse Sigma date fields.

    Accepts:
    - ``None`` → ``None``
    - a ``datetime.datetime`` (PyYAML auto-parses ISO timestamps) → its ``.date()``
    - a ``datetime.date`` (PyYAML auto-parses ISO dates) → returned as-is
    - a string in ``YYYY/MM/DD`` or ``YYYY-MM-DD`` form → parsed via ``date.fromisoformat``

    Returns ``None`` for anything unparseable (logged at DEBUG).
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        # datetime is a subclass of date — this branch must run FIRST.
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip().replace("/", "-")
    try:
        return date.fromisoformat(text)
    except ValueError:
        log.debug("Unparseable date value: %r", value)
        return None


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
            status=raw.get("status"),
            rule_date=_parse_sigma_date(raw.get("date")),
            modified_date=_parse_sigma_date(raw.get("modified")),
            technique_ids=technique_ids,
            source_file=path.resolve(),
            raw_tags=tags,
        )
    except ValidationError as exc:
        log.warning("Validation error parsing %s: %s", path, exc)
        return None


# TODO(detect-forge): the bundled rules in data/rules/ are *.toml, but this
# default glob only matches *.yml — so `detect-forge stale data/rules` finds
# nothing out of the box. Either rename the fixtures, broaden the default
# glob, or auto-detect the rule format. See conversation 2026-05-11.
def parse_rule_dir(
    rule_dir: Path,
    glob: str = "**/*.yml",
) -> list[DetectionRule]:
    """Recursively find and parse Sigma rule YAML files in ``rule_dir``.

    Files that fail parsing (bad YAML, non-dict content, validation errors)
    are silently skipped with a warning log. Returns an empty list if no
    valid rules are found.

    The default glob only matches ``.yml``; repos that use ``.yaml`` must pass
    ``glob="**/*.yaml"`` explicitly.
    """
    rules: list[DetectionRule] = []
    found = list(rule_dir.glob(glob))
    log.info("Found %d YAML files in %s", len(found), rule_dir)

    for path in found:
        rule = parse_rule_file(path)
        if rule is not None:
            rules.append(rule)

    log.info("Successfully parsed %d / %d rules", len(rules), len(found))
    return rules
