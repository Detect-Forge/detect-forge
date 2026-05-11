from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from . import elastic_parser, sigma_parser
from .models import DetectionRule

log = logging.getLogger(__name__)


_EXT_DISPATCH: dict[str, Callable[[Path], DetectionRule | None]] = {
    ".yml": sigma_parser.parse_rule_file,
    ".yaml": sigma_parser.parse_rule_file,
    ".toml": elastic_parser.parse_rule_file,
}


def parse_rule_file(path: Path) -> DetectionRule | None:
    """Parse a single detection rule file by dispatching on its extension.

    Returns None for unknown extensions. For known extensions, the per-format
    parser is responsible for returning None on unreadable files, malformed
    content, or validation errors (and logging the cause).
    """
    parser = _EXT_DISPATCH.get(path.suffix.lower())
    if parser is None:
        return None
    return parser(path)


def parse_rule_dir(rule_dir: Path) -> list[DetectionRule]:
    """Recursively walk ``rule_dir`` and parse every file with a known extension.

    Files with unknown extensions are skipped silently. Files that fail
    parsing are logged at WARNING by the per-format parser and skipped.
    Returns an empty list if no parseable files are found.

    Note: the legacy ``glob=`` parameter was removed; dispatch is now driven
    by the registered extensions in ``_EXT_DISPATCH``.
    """
    rules: list[DetectionRule] = []
    candidates = [
        p
        for p in rule_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in _EXT_DISPATCH
    ]
    log.info("Found %d candidate rule files under %s", len(candidates), rule_dir)

    for path in candidates:
        rule = parse_rule_file(path)
        if rule is not None:
            rules.append(rule)

    log.info("Successfully parsed %d / %d rules", len(rules), len(candidates))
    return rules
