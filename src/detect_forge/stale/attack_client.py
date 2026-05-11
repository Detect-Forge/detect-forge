from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests
from mitreattack.stix20 import MitreAttackData

from ..cache import (
    DEFAULT_TTL_HOURS,
    cache_path,
    is_cache_valid,
    write_cache,
)
from .models import AttackIndex, AttackTechnique

log = logging.getLogger(__name__)

STIX_URLS = {
    "enterprise-attack": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "ics-attack": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    "mobile-attack": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
}


def _extract_technique_id(stix_obj: Any) -> str | None:
    """Pull the ATT&CK technique ID (e.g. T1059.001) from STIX external_references."""
    for ref in getattr(stix_obj, "external_references", []):
        if ref.get("source_name") == "mitre-attack":
            external_id = (ref.get("external_id") or "").upper()
            return external_id or None
    return None


def _parse_technique(stix_obj: Any) -> AttackTechnique | None:
    """Convert a raw STIX attack-pattern object into an AttackTechnique.

    Returns None if the object lacks a mitre-attack external reference.
    """
    technique_id = _extract_technique_id(stix_obj)
    if not technique_id:
        log.debug("Skipping STIX object with no ATT&CK external_id: %s", stix_obj.id)
        return None

    modified: datetime = stix_obj.modified
    if modified.tzinfo is None:
        modified = modified.replace(tzinfo=UTC)

    tactic_ids = [
        phase.phase_name
        for phase in getattr(stix_obj, "kill_chain_phases", [])
        if getattr(phase, "kill_chain_name", None) == "mitre-attack"
    ]

    return AttackTechnique(
        technique_id=technique_id,
        name=stix_obj.name,
        modified=modified,
        is_subtechnique=getattr(stix_obj, "x_mitre_is_subtechnique", False),
        deprecated=getattr(stix_obj, "x_mitre_deprecated", False),
        revoked=getattr(stix_obj, "revoked", False),
        tactic_ids=tactic_ids,
        stix_id=stix_obj.id,
    )


def build_index(
    domain: str = "enterprise-attack",
    cache_dir: Path | None = None,
    ttl_hours: int = DEFAULT_TTL_HOURS,
    stix_path: Path | None = None,
) -> AttackIndex:
    """Fetch the ATT&CK STIX bundle and return a fully-parsed AttackIndex.

    Network behavior:
    - If `stix_path` is provided, load directly from that file (used by tests).
    - Else, use the on-disk cache if it's fresher than `ttl_hours`.
    - Else, fetch from the MITRE CTI GitHub URL, write the cache, and load from it.
    """
    fetched_at = datetime.now(UTC)

    if stix_path is not None:
        log.debug("Loading ATT&CK from local file: %s", stix_path)
        attack_data = MitreAttackData(str(stix_path))
    else:
        path = cache_path(domain, cache_dir)
        if is_cache_valid(path, ttl_hours):
            log.debug("Using cached ATT&CK bundle: %s", path)
        else:
            url = STIX_URLS.get(domain)
            if not url:
                raise ValueError(
                    f"Unknown ATT&CK domain: {domain!r}. Valid: {list(STIX_URLS)}"
                )
            log.info("Fetching ATT&CK bundle from %s", url)
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            raw = response.json()
            if raw.get("type") != "bundle":
                raise ValueError(
                    f"URL did not return a STIX bundle (type={raw.get('type')!r}): {url}"
                )
            write_cache(path, raw)
            log.debug("Cached ATT&CK bundle to %s", path)
        attack_data = MitreAttackData(str(path))

    techniques: dict[str, AttackTechnique] = {}
    stix_techniques = attack_data.get_techniques(remove_revoked_deprecated=False)

    for stix_obj in stix_techniques:
        parsed = _parse_technique(stix_obj)
        if parsed is None:
            continue
        if parsed.technique_id in techniques:
            log.warning(
                "Duplicate technique_id %s — keeping first occurrence",
                parsed.technique_id,
            )
            continue
        techniques[parsed.technique_id] = parsed

    log.info("Loaded %d ATT&CK techniques (%s)", len(techniques), domain)

    return AttackIndex(
        techniques=techniques,
        fetched_at=fetched_at,
        source_domain=domain,
    )
