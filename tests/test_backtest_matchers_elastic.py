from __future__ import annotations

from pathlib import Path

from detect_forge.stale.models import DetectionRule


def _eql_rule(query: str, source: str = "/r.toml") -> DetectionRule:
    """Build a DetectionRule with EQL query stashed in raw_toml."""
    toml = f"""
[rule]
name = "Test Rule"
type = "eql"
language = "eql"
query = '''
{query}
'''
"""
    return DetectionRule(
        title="Test Rule",
        technique_ids=["T1059"],
        source_file=Path(source),
        raw_tags=[],
        raw_toml=toml,
    )


def test_elastic_supports_eql_rule() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("process where process.name == \"powershell.exe\"")
    m = ElasticMatcher()
    assert m.supports(rule) is True


def test_elastic_eql_simple_process_match() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("process where process.name == \"powershell.exe\"")
    events = [
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}},
        {"event": {"category": "process"}, "process": {"name": "notepad.exe"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0}


def test_elastic_eql_sequence_pattern() -> None:
    """A two-step sequence: process spawn followed by network connection from same parent."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule(
        'sequence by process.entity_id\n'
        '  [process where event.action == "start"]\n'
        '  [network where event.action == "connection"]'
    )
    events = [
        {"event": {"category": "process", "action": "start"}, "process": {"entity_id": "p1", "name": "x"}},  # noqa: E501
        {"event": {"category": "network", "action": "connection"}, "process": {"entity_id": "p1"}},
        {"event": {"category": "process", "action": "start"}, "process": {"entity_id": "p2"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    # The sequence "[process start] [network connection]" closes on event
    # index 1 (the network connection from process p1). Event 2 is a
    # second process start that doesn't pair with a network event.
    assert [f.event_index for f in fires] == [1]


def test_elastic_kql_rule_falls_through_to_kql_evaluator() -> None:
    """KQL rules support but route to the KQL evaluator (Task 9).
    In this Task 8 commit, KQL → unsupported with reason."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    toml = """
[rule]
name = "KQL test"
type = "query"
language = "kuery"
query = 'process.name : "powershell.exe"'
"""
    rule = DetectionRule(
        title="KQL test",
        technique_ids=["T1059"],
        source_file=Path("/r.toml"),
        raw_tags=[],
        raw_toml=toml,
    )
    m = ElasticMatcher()
    supports, reason = m.support_reason(rule)
    # Task 8: KQL not yet implemented → unsupported. Task 9 lifts this.
    assert supports is False
    assert "kql" in (reason or "").lower() or "kuery" in (reason or "").lower()


def test_elastic_esql_rule_unsupported() -> None:
    """ESQL rules report as unsupported with a clear reason."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    toml = """
[rule]
name = "ESQL test"
type = "esql"
language = "esql"
query = 'FROM logs | WHERE process.name == "powershell.exe"'
"""
    rule = DetectionRule(
        title="ESQL test",
        technique_ids=["T1059"],
        source_file=Path("/r.toml"),
        raw_tags=[],
        raw_toml=toml,
    )
    m = ElasticMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "esql" in (reason or "").lower() or "es|ql" in (reason or "").lower()


def test_elastic_invalid_eql_unsupported_with_reason() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("THIS IS NOT VALID EQL")
    m = ElasticMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "parse" in (reason or "").lower() or "syntax" in (reason or "").lower()


def test_elastic_eql_handles_ecs_list_category() -> None:
    """ECS v8 represents event.category as a list — must be unwrapped."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("process where process.name == \"powershell.exe\"")
    events = [
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
        {"event": {"category": ["network"]}, "process": {"name": "powershell.exe"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    # Only event 0 matches: process category + powershell.exe.
    assert [f.event_index for f in fires] == [0]


def test_elastic_eql_events_without_category_dont_fire_typed_queries() -> None:
    """Events missing event.category fall through to 'generic' and don't
    satisfy category-filtered EQL queries (documented v0.1 limitation)."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("process where process.name == \"powershell.exe\"")
    events = [
        # Has process.name but no event.category — type defaults to 'generic'.
        {"process": {"name": "powershell.exe"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    assert fires == []
