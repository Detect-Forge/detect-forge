"""Canonical ATT&CK enterprise tactic shortname → (TA-ID, display name) mapping.

Source: MITRE ATT&CK Enterprise matrix. Stable across ATT&CK versions — last refreshed
2026-05-29 against ATT&CK v15.

The shortname is what each ``AttackTechnique.tactic_ids`` actually contains (parsed
from STIX ``kill_chain_phases.phase_name``). The TA-ID and display name are used for
reports and the Navigator layer.
"""

from __future__ import annotations

# Ordered by ATT&CK Navigator matrix display order (left to right).
TACTIC_DISPLAY_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)

_TACTIC_LOOKUP: dict[str, tuple[str, str]] = {
    "reconnaissance":        ("TA0043", "Reconnaissance"),
    "resource-development":  ("TA0042", "Resource Development"),
    "initial-access":        ("TA0001", "Initial Access"),
    "execution":             ("TA0002", "Execution"),
    "persistence":           ("TA0003", "Persistence"),
    "privilege-escalation":  ("TA0004", "Privilege Escalation"),
    "defense-evasion":       ("TA0005", "Defense Evasion"),
    "credential-access":     ("TA0006", "Credential Access"),
    "discovery":             ("TA0007", "Discovery"),
    "lateral-movement":      ("TA0008", "Lateral Movement"),
    "collection":            ("TA0009", "Collection"),
    "command-and-control":   ("TA0011", "Command and Control"),
    "exfiltration":          ("TA0010", "Exfiltration"),
    "impact":                ("TA0040", "Impact"),
}


def lookup_tactic(shortname: str) -> tuple[str, str]:
    """Return ``(TA-ID, display_name)`` for an ATT&CK tactic shortname.

    Unknown shortnames return ``(shortname, shortname.title().replace("-", " "))`` so
    the report stays informative if MITRE adds a new tactic before we refresh.
    """
    if shortname in _TACTIC_LOOKUP:
        return _TACTIC_LOOKUP[shortname]
    return (shortname, shortname.replace("-", " ").title())
