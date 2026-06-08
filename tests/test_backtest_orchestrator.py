from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock


def _now() -> datetime:
    return datetime.now(UTC)


def _make_index(*technique_specs):  # type: ignore[no-untyped-def]
    from detect_forge.stale.models import AttackIndex, AttackTechnique
    techs = {}
    for spec in technique_specs:
        tid, name, deprecated, revoked = spec
        techs[tid] = AttackTechnique(
            technique_id=tid,
            name=name,
            modified=_now(),
            is_subtechnique=False,
            deprecated=deprecated,
            revoked=revoked,
            tactic_ids=["execution"],
            stix_id=f"attack-pattern--{tid}",
        )
    return AttackIndex(techniques=techs, fetched_at=_now())


def _make_sigma_rule(tids: list[str], yaml_text: str, source: str = "/r.yml"):  # type: ignore[no-untyped-def]
    from detect_forge.stale.models import DetectionRule
    return DetectionRule(
        title="Test", technique_ids=tids, source_file=Path(source),
        raw_tags=[], raw_yaml=yaml_text,
    )


def _mock_corpus(datasets_by_tid: dict[str, list]) -> MagicMock:
    from detect_forge.backtest.corpus import MordorDataset
    corpus = MagicMock()
    def _datasets_for(tid: str):
        return [
            MordorDataset(
                dataset_id=ds["id"],
                technique_id=tid,
                platform="windows",
                events=ds["events"],
            )
            for ds in datasets_by_tid.get(tid, [])
        ]
    corpus.datasets_for.side_effect = _datasets_for
    corpus.datasets_consulted.return_value = sum(
        len(v) for v in datasets_by_tid.values()
    )
    corpus.source_label.return_value = "fetched"
    return corpus


_BASIC_YAML = """
title: Notepad
detection:
    selection:
        Image: 'notepad.exe'
    condition: selection
"""


def test_run_backtest_empty_corpus_marks_rules_untested() -> None:
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", False, False))
    rule = _make_sigma_rule(["T1059"], _BASIC_YAML)
    corpus = _mock_corpus({})
    report = run_backtest([rule], idx, corpus, priority_ids=set())
    assert report.summary.rules_parsed == 1
    assert report.summary.rules_untested == 1
    assert report.rule_results[0].status == "untested"


def test_run_backtest_verified_when_rule_fires() -> None:
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", False, False))
    rule = _make_sigma_rule(["T1059"], _BASIC_YAML)
    corpus = _mock_corpus({
        "T1059": [{"id": "ds1", "events": [{"Image": "notepad.exe"}]}],
    })
    report = run_backtest([rule], idx, corpus, priority_ids=set())
    assert report.summary.rules_fires == 1
    assert report.rule_results[0].status == "fires"
    assert report.technique_rollups[0].status == "verified"


def test_run_backtest_silent_on_all_when_rule_never_fires() -> None:
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", False, False))
    rule = _make_sigma_rule(["T1059"], _BASIC_YAML)
    corpus = _mock_corpus({
        "T1059": [{"id": "ds1", "events": [{"Image": "powershell.exe"}]}],
    })
    report = run_backtest([rule], idx, corpus, priority_ids=set())
    assert report.summary.rules_silent_on_all == 1
    assert report.rule_results[0].status == "silent_on_all"


def test_run_backtest_partial_status() -> None:
    """Rule tagged for 2 techniques: fires on one, silent on the other."""
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(
        ("T1059", "A", False, False),
        ("T1078", "B", False, False),
    )
    rule = _make_sigma_rule(["T1059", "T1078"], _BASIC_YAML)
    corpus = _mock_corpus({
        "T1059": [{"id": "ds1", "events": [{"Image": "notepad.exe"}]}],
        "T1078": [{"id": "ds2", "events": [{"Image": "calc.exe"}]}],
    })
    report = run_backtest([rule], idx, corpus, priority_ids=set())
    assert report.rule_results[0].status == "partial"


def test_run_backtest_skips_rules_with_no_technique_tags() -> None:
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", False, False))
    rule = _make_sigma_rule([], _BASIC_YAML)
    corpus = _mock_corpus({})
    report = run_backtest([rule], idx, corpus, priority_ids=set())
    assert report.summary.rules_parsed == 1
    assert all(r.status == "untested" for r in report.rule_results)


def test_run_backtest_routes_deprecated_to_skip() -> None:
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", True, False))  # deprecated
    rule = _make_sigma_rule(["T1059"], _BASIC_YAML)
    corpus = _mock_corpus({})
    report = run_backtest([rule], idx, corpus, priority_ids=set())
    assert report.rule_results[0].status == "untested"


def test_run_backtest_unsupported_rule_uses_status() -> None:
    """Sigma rule with |cidr modifier → unsupported with reason."""
    from detect_forge.backtest.orchestrator import run_backtest

    yaml_text = """
title: cidr
detection:
    selection:
        sourceIp|cidr: '10.0.0.0/8'
    condition: selection
"""
    idx = _make_index(("T1059", "Cmd", False, False))
    rule = _make_sigma_rule(["T1059"], yaml_text)
    corpus = _mock_corpus({"T1059": [{"id": "ds1", "events": []}]})
    report = run_backtest([rule], idx, corpus, priority_ids=set())
    assert report.summary.rules_unsupported == 1
    assert report.rule_results[0].status == "unsupported"
    assert "cidr" in (report.rule_results[0].unsupported_reason or "").lower()


def test_run_backtest_priority_silent_counts() -> None:
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", False, False))
    rule = _make_sigma_rule(["T1059"], _BASIC_YAML)
    corpus = _mock_corpus({
        "T1059": [{"id": "ds1", "events": [{"Image": "powershell.exe"}]}],
    })
    report = run_backtest(
        [rule], idx, corpus, priority_ids={"T1059"},
    )
    assert report.summary.priority_total == 1
    assert report.summary.priority_silent == 1


def test_run_backtest_priority_untested_counts() -> None:
    """Priority technique with no dataset is 'untested', not 'silent'."""
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", False, False))
    rule = _make_sigma_rule(["T1059"], _BASIC_YAML)
    corpus = _mock_corpus({})  # no datasets
    report = run_backtest([rule], idx, corpus, priority_ids={"T1059"})
    assert report.summary.priority_untested == 1
    assert report.summary.priority_silent == 0


def test_run_backtest_multiple_rules_one_fires_technique_verified() -> None:
    """If any rule fires on a technique's dataset, the technique rollup is verified."""
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", False, False))
    silent = _make_sigma_rule(["T1059"], _BASIC_YAML, "/silent.yml")
    fires_yaml = """
title: Fires
detection:
    selection:
        Image: 'powershell.exe'
    condition: selection
"""
    fires_rule = _make_sigma_rule(["T1059"], fires_yaml, "/fires.yml")
    corpus = _mock_corpus({
        "T1059": [{"id": "ds1", "events": [{"Image": "powershell.exe"}]}],
    })
    report = run_backtest([silent, fires_rule], idx, corpus, priority_ids=set())
    tr = next(t for t in report.technique_rollups if t.technique_id == "T1059")
    assert tr.status == "verified"
    assert tr.rules_tagged == 2
    assert tr.rules_fired == 1


def test_run_backtest_matcher_exception_logged_not_raised() -> None:
    """A matcher exception on one event doesn't crash the scan."""
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", False, False))
    # Malformed YAML — supports() returns False → unsupported.
    bad_rule = _make_sigma_rule(["T1059"], "not valid yaml: : : :")
    corpus = _mock_corpus({
        "T1059": [{"id": "ds1", "events": [{"Image": "x"}]}],
    })
    report = run_backtest([bad_rule], idx, corpus, priority_ids=set())
    assert report.rule_results[0].status == "unsupported"


def test_run_backtest_sort_order_silent_first() -> None:
    from detect_forge.backtest.orchestrator import run_backtest

    idx = _make_index(("T1059", "Cmd", False, False))
    silent_rule = _make_sigma_rule(["T1059"], _BASIC_YAML, "/silent.yml")
    fires_yaml = """
title: Fires
detection:
    selection:
        Image: 'powershell.exe'
    condition: selection
"""
    fires_rule = _make_sigma_rule(["T1059"], fires_yaml, "/fires.yml")
    corpus = _mock_corpus({
        "T1059": [{"id": "ds1", "events": [{"Image": "powershell.exe"}]}],
    })
    report = run_backtest([fires_rule, silent_rule], idx, corpus, priority_ids=set())
    statuses = [r.status for r in report.rule_results]
    assert statuses.index("silent_on_all") < statuses.index("fires")
