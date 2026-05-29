from __future__ import annotations

from pathlib import Path

from detect_forge.stale.models import DetectionRule


def _rule_from_yaml(yaml_text: str, source: str = "/r.yml") -> DetectionRule:
    """Build a DetectionRule with raw YAML stashed for the matcher to re-read."""
    return DetectionRule(
        title="Test Rule",
        technique_ids=["T1059"],
        source_file=Path(source),
        raw_tags=[],
        raw_yaml=yaml_text,
    )


def test_sigma_supports_basic_detection_block() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: PS Encoded
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    m = SigmaMatcher()
    assert m.supports(rule) is True


def test_sigma_matches_simple_equality() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: Notepad
detection:
    selection:
        Image: 'notepad.exe'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "notepad.exe"},
        {"Image": "calc.exe"},
        {"Image": "notepad.exe", "CommandLine": "x"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 2}


def test_sigma_matches_list_value_as_OR() -> None:
    """A list value in a selection means any-of."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: PS or CMD
detection:
    selection:
        Image:
            - 'powershell.exe'
            - 'cmd.exe'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [{"Image": "powershell.exe"}, {"Image": "notepad.exe"}, {"Image": "cmd.exe"}]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 2}


def test_sigma_condition_all_of_selection_globs() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: both
detection:
    selection_a:
        Image: 'powershell.exe'
    selection_b:
        CommandLine: '-EncodedCommand'
    condition: all of selection_*
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "powershell.exe", "CommandLine": "-EncodedCommand AABB"},
        {"Image": "powershell.exe", "CommandLine": "other"},
        {"Image": "notepad.exe", "CommandLine": "-EncodedCommand"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0}


def test_sigma_condition_one_of_selection_globs() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: either
detection:
    selection_a:
        Image: 'powershell.exe'
    selection_b:
        CommandLine: 'whoami'
    condition: 1 of selection_*
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "powershell.exe"},
        {"Image": "cmd.exe", "CommandLine": "whoami"},
        {"Image": "notepad.exe"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 1}


def test_sigma_condition_and_or_not_parens() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: complex
detection:
    selection_a:
        Image: 'powershell.exe'
    selection_b:
        CommandLine: 'whoami'
    selection_c:
        Image: 'notepad.exe'
    condition: (selection_a and selection_b) or (selection_c and not selection_b)
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "powershell.exe", "CommandLine": "whoami"},
        {"Image": "notepad.exe"},
        {"Image": "notepad.exe", "CommandLine": "whoami"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 1}


def test_sigma_unsupported_fallback_for_correlations_at_this_task() -> None:
    """Correlations are added in Task 7; in Task 5 they're unsupported."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: corr
correlation:
    type: event_count
    rules:
        - some_rule
    timespan: 5m
    condition:
        gt: 5
detection:
    selection: {}
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    m = SigmaMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "correlation" in (reason or "").lower()
