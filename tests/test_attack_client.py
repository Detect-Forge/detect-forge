from __future__ import annotations

from pathlib import Path

import pytest

from detect_forge.stale.attack_client import build_index
from detect_forge.stale.models import AttackIndex


@pytest.fixture
def stix_fixture() -> Path:
    return Path(__file__).parent / "fixtures" / "enterprise-attack-mini.json"


def test_build_index_from_fixture(stix_fixture: Path) -> None:
    idx = build_index(stix_path=stix_fixture)
    assert isinstance(idx, AttackIndex)
    assert "T1059" in idx.techniques
    assert "T1059.001" in idx.techniques
    assert idx.source_domain == "enterprise-attack"
    assert idx.fetched_at.tzinfo is not None


def test_technique_modified_is_utc_aware(stix_fixture: Path) -> None:
    idx = build_index(stix_path=stix_fixture)
    tech = idx.techniques["T1059.001"]
    assert tech.modified.tzinfo is not None


def test_technique_id_is_uppercase(stix_fixture: Path) -> None:
    idx = build_index(stix_path=stix_fixture)
    for tid in idx.techniques:
        assert tid == tid.upper()


def test_subtechnique_flag(stix_fixture: Path) -> None:
    idx = build_index(stix_path=stix_fixture)
    assert idx.techniques["T1059.001"].is_subtechnique is True
    assert idx.techniques["T1059"].is_subtechnique is False


def test_deprecated_technique_is_included(stix_fixture: Path) -> None:
    idx = build_index(stix_path=stix_fixture)
    deprecated = [t for t in idx.techniques.values() if t.deprecated]
    assert len(deprecated) >= 1
    assert any(t.technique_id == "T1040" for t in deprecated)


def test_no_attack_id_object_is_skipped(stix_fixture: Path) -> None:
    idx = build_index(stix_path=stix_fixture)
    # Fixture has 5 attack-patterns; 1 has no mitre-attack external ref.
    # Remaining 4: T1059, T1059.001, T1040, T1999.
    assert len(idx.techniques) == 4
    assert "T1059" in idx.techniques
    assert "T1059.001" in idx.techniques
    assert "T1040" in idx.techniques
    assert "T1999" in idx.techniques


def test_cache_is_written_on_miss(
    tmp_path: Path, stix_fixture: Path, requests_mock
) -> None:
    from detect_forge.stale.attack_client import STIX_URLS

    url = STIX_URLS["enterprise-attack"]
    raw_bundle = stix_fixture.read_text(encoding="utf-8")
    requests_mock.get(url, text=raw_bundle)

    cache_dir = tmp_path / "cache"
    idx = build_index(cache_dir=cache_dir, ttl_hours=24)

    assert (cache_dir / "enterprise-attack.json").exists()
    assert "T1059" in idx.techniques
    assert requests_mock.call_count == 1


def test_cache_is_used_on_hit(
    tmp_path: Path, stix_fixture: Path, mocker
) -> None:
    import shutil

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    shutil.copy(stix_fixture, cache_dir / "enterprise-attack.json")

    get_spy = mocker.patch("detect_forge.stale.attack_client.requests.get")

    idx = build_index(cache_dir=cache_dir, ttl_hours=999)

    get_spy.assert_not_called()
    assert "T1059" in idx.techniques


def test_revoked_technique_flag_is_parsed(stix_fixture: Path) -> None:
    """The T1999 fixture has `revoked: true`; parsed AttackTechnique.revoked
    must reflect that. Separate from the `deprecated` flag (which T1040 sets)."""
    idx = build_index(stix_path=stix_fixture)

    assert idx.techniques["T1999"].revoked is True
    # Sanity-check that a normal technique is NOT revoked.
    assert idx.techniques["T1059"].revoked is False
    # Deprecated ≠ revoked — T1040 is deprecated but not revoked in the fixture.
    assert idx.techniques["T1040"].deprecated is True
    assert idx.techniques["T1040"].revoked is False


def test_technique_description_extracted_from_stix(stix_fixture: Path) -> None:
    idx = build_index(stix_path=stix_fixture)
    t1059 = idx.techniques["T1059"]
    assert t1059.description is not None
    assert "command and scripting" in t1059.description.lower()


def test_parse_technique_handles_missing_description() -> None:
    """Defensive: when the STIX object lacks a description attribute, _parse_technique
    must produce a DetectionTechnique with description=None — not raise AttributeError.

    Guards against accidentally changing `getattr(stix_obj, "description", None)`
    to `stix_obj.description` in attack_client._parse_technique.
    """
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from detect_forge.stale.attack_client import _parse_technique

    # SimpleNamespace gives us an object whose attribute access mirrors a real
    # stix2 AttackPattern, but we deliberately omit `description`.
    stix_like = SimpleNamespace(
        id="attack-pattern--00000000-0000-0000-0000-000000000001",
        name="Synthetic Technique Without Description",
        modified=datetime(2025, 1, 1, tzinfo=UTC),
        external_references=[
            {"source_name": "mitre-attack", "external_id": "T9999"},
        ],
        kill_chain_phases=[],
        # Intentionally no `description` attribute.
    )
    parsed = _parse_technique(stix_like)
    assert parsed is not None
    assert parsed.technique_id == "T9999"
    assert parsed.description is None


def test_parse_technique_populates_parent_id_for_subtechnique() -> None:
    """A sub-technique's parent_id is derived from its technique_id."""
    from types import SimpleNamespace

    from detect_forge.stale.attack_client import _parse_technique

    stix = SimpleNamespace(
        id="attack-pattern--abc",
        name="PowerShell",
        description="...",
        modified=__import__("datetime").datetime.now(__import__("datetime").UTC),
        x_mitre_is_subtechnique=True,
        x_mitre_deprecated=False,
        revoked=False,
        external_references=[
            {"source_name": "mitre-attack", "external_id": "T1059.001"}
        ],
        kill_chain_phases=[],
    )
    t = _parse_technique(stix)
    assert t is not None
    assert t.parent_id == "T1059"


def test_parse_technique_parent_id_none_for_parent_technique() -> None:
    """A parent technique has parent_id=None."""
    from types import SimpleNamespace

    from detect_forge.stale.attack_client import _parse_technique

    stix = SimpleNamespace(
        id="attack-pattern--abc",
        name="Command and Scripting Interpreter",
        description="...",
        modified=__import__("datetime").datetime.now(__import__("datetime").UTC),
        x_mitre_is_subtechnique=False,
        x_mitre_deprecated=False,
        revoked=False,
        external_references=[
            {"source_name": "mitre-attack", "external_id": "T1059"}
        ],
        kill_chain_phases=[],
    )
    t = _parse_technique(stix)
    assert t is not None
    assert t.parent_id is None
