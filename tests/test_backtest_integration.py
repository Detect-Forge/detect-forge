"""End-to-end integration test for the backtest pipeline.

Exercises the full scan_backtest() → reporter chain against a fixture rule
corpus + mocked Mordor corpus. Catches wiring breaks across modules that
unit tests miss (model field renames, matcher protocol drift, reporter
template variable mismatches).

Mock boundaries (everything below scan_backtest() runs for real):
- build_index → fake AttackIndex with 3 techniques in scope
- resolve_priority_techniques → {"T1078"} (priority list)
- MordorCorpus → mock whose datasets_for(tid) returns synthetic events
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

from pytest_mock import MockerFixture

# NOTE on backslashes in _FIRES_YAML / _PRIORITY_SILENT_YAML:
# The YAML single-quoted string '\\powershell.exe' (one backslash in the
# Python source literal, written as a single backslash in the YAML text,
# decoded by PyYAML as one backslash) must equal the trailing slice of the
# event's "Image" value "C:\\Windows\\System32\\powershell.exe" (one
# backslash per separator in the actual Python string). Using two backslashes
# in the Python source produces '\\\\powershell.exe' after yaml.safe_load
# (two backslashes) which does NOT match the single-backslash event path.
_FIRES_YAML = """\
title: Fires
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
"""

_SILENT_YAML = """\
title: Silent on All
detection:
    selection:
        CommandLine: 'this string never appears'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
"""

_ELASTIC_TOML = """\
[rule]
name = "Elastic Fires"
type = "eql"
language = "eql"
query = '''
process where process.name == "lsass.exe"
'''
[[rule.threat]]
framework = "MITRE ATT&CK"
[rule.threat.tactic]
id = "TA0006"
name = "Credential Access"
reference = "https://attack.mitre.org/tactics/TA0006/"
[[rule.threat.technique]]
id = "T1003.001"
name = "LSASS Memory"
reference = "https://attack.mitre.org/techniques/T1003/001/"
"""

_PRIORITY_SILENT_YAML = """\
title: Priority Silent
detection:
    selection:
        Image|endswith: '\\never_present.exe'
    condition: selection
tags:
    - attack.initial_access
    - attack.t1078
"""


def _make_index() -> object:
    """Build an AttackIndex with the 3 techniques our fixtures tag."""
    from detect_forge.stale.models import AttackIndex, AttackTechnique

    now = datetime.now(UTC)
    techs = {
        "T1059.001": AttackTechnique(
            technique_id="T1059.001",
            name="PowerShell",
            modified=now,
            is_subtechnique=True,
            deprecated=False,
            revoked=False,
            tactic_ids=["execution"],
            stix_id="attack-pattern--T1059.001",
        ),
        "T1003.001": AttackTechnique(
            technique_id="T1003.001",
            name="LSASS Memory",
            modified=now,
            is_subtechnique=True,
            deprecated=False,
            revoked=False,
            tactic_ids=["credential-access"],
            stix_id="attack-pattern--T1003.001",
        ),
        "T1078": AttackTechnique(
            technique_id="T1078",
            name="Valid Accounts",
            modified=now,
            is_subtechnique=False,
            deprecated=False,
            revoked=False,
            tactic_ids=["initial-access"],
            stix_id="attack-pattern--T1078",
        ),
    }
    return AttackIndex(techniques=techs, fetched_at=now)


def _mock_corpus_factory() -> MagicMock:
    """Build a MagicMock MordorCorpus whose datasets_for(tid) returns
    synthetic events that the fixture fires rules will match."""
    from detect_forge.backtest.corpus import MordorDataset

    def datasets_for(tid: str) -> list[MordorDataset]:
        if tid == "T1059.001":
            return [
                MordorDataset(
                    dataset_id="ds_powershell",
                    technique_id=tid,
                    platform="windows",
                    events=[
                        {"Image": "C:\\Windows\\System32\\powershell.exe"},
                    ],
                ),
            ]
        if tid == "T1003.001":
            return [
                MordorDataset(
                    dataset_id="ds_lsass",
                    technique_id=tid,
                    platform="windows",
                    events=[
                        {
                            "event": {"category": ["process"]},
                            "process": {"name": "lsass.exe"},
                        },
                    ],
                ),
            ]
        if tid == "T1078":
            return [
                MordorDataset(
                    dataset_id="ds_t1078",
                    technique_id=tid,
                    platform="windows",
                    events=[
                        {"Image": "C:\\Windows\\System32\\benign.exe"},
                    ],
                ),
            ]
        return []

    corpus = MagicMock()
    corpus.datasets_for.side_effect = datasets_for
    corpus.datasets_consulted.return_value = 3
    corpus.source_label.return_value = "synthetic"
    return corpus


def test_scan_backtest_end_to_end_full_pipeline(
    tmp_path: Path, mocker: MockerFixture,
) -> None:
    """Exercise scan_backtest() → BacktestReport → all 4 reporter formats."""
    # ---- Fixture rule corpus ----
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    (rule_dir / "fires.yml").write_text(_FIRES_YAML, encoding="utf-8")
    (rule_dir / "silent.yml").write_text(_SILENT_YAML, encoding="utf-8")
    (rule_dir / "elastic.toml").write_text(_ELASTIC_TOML, encoding="utf-8")
    (rule_dir / "priority_silent.yml").write_text(
        _PRIORITY_SILENT_YAML, encoding="utf-8",
    )

    # ---- Mock the 3 boundaries below scan_backtest() ----
    mocker.patch(
        "detect_forge.backtest.build_index", return_value=_make_index(),
    )
    mocker.patch(
        "detect_forge.backtest.resolve_priority_techniques",
        return_value={"T1078"},
    )
    mock_corpus = _mock_corpus_factory()
    mocker.patch("detect_forge.backtest.MordorCorpus", return_value=mock_corpus)

    # ---- Call the real scan_backtest() ----
    from detect_forge.backtest import scan_backtest
    report = scan_backtest(rule_dir)

    # ---- Summary assertions (gate-input shape) ----
    s = report.summary
    assert s.rules_parsed == 4
    assert s.rules_fires == 2, (
        f"Expected 2 fires rules, got {s.rules_fires} "
        f"(statuses: {[r.status for r in report.rule_results]})"
    )
    assert s.rules_silent_on_all == 2
    assert s.priority_total == 1
    assert s.priority_silent == 1   # T1078 silent + priority
    assert s.techniques_verified == 2  # T1059.001 + T1003.001
    assert s.techniques_silent == 1    # T1078

    # ---- Per-rule assertions ----
    rule_statuses = {r.source_file.name: r.status for r in report.rule_results}
    assert rule_statuses == {
        "fires.yml": "fires",
        "silent.yml": "silent_on_all",
        "elastic.toml": "fires",
        "priority_silent.yml": "silent_on_all",
    }

    # ---- Per-technique rollup assertions ----
    rollups = {t.technique_id: t for t in report.technique_rollups}
    assert rollups["T1059.001"].status == "verified"
    assert rollups["T1003.001"].status == "verified"
    assert rollups["T1078"].status == "silent"
    assert rollups["T1078"].is_priority is True

    # ---- Reporter render assertions (all 4 formats) ----
    from detect_forge.backtest.reporter import render

    terminal_out = render(report, output_format="terminal")
    assert "Adversarial Backtest" in terminal_out
    assert "Silent on all" in terminal_out

    json_out = render(report, output_format="json")
    parsed = json.loads(json_out)
    assert parsed["summary"]["rules_fires"] == 2

    html_out = render(report, output_format="html")
    assert "<!DOCTYPE html>" in html_out
    assert "T1078" in html_out

    navigator_out = render(report, output_format="navigator")
    nav = json.loads(navigator_out)
    assert nav["domain"] == "enterprise-attack"
    by_tid = {t["techniqueID"]: t for t in nav["techniques"]}
    # T1078 is priority + silent → deep red per spec §8 mapping
    assert by_tid["T1078"]["color"] == "#d32f2f"
