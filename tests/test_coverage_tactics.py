from __future__ import annotations


def test_tactic_lookup_returns_ta_id_and_name_for_known_shortname() -> None:
    from detect_forge.coverage._tactics import lookup_tactic

    ta_id, name = lookup_tactic("execution")
    assert ta_id == "TA0002"
    assert name == "Execution"


def test_tactic_lookup_handles_multi_word_shortname() -> None:
    from detect_forge.coverage._tactics import lookup_tactic

    ta_id, name = lookup_tactic("command-and-control")
    assert ta_id == "TA0011"
    assert name == "Command and Control"


def test_tactic_lookup_returns_passthrough_for_unknown_shortname() -> None:
    """Unknown shortnames pass through as (shortname, shortname-titled) — defensive."""
    from detect_forge.coverage._tactics import lookup_tactic

    ta_id, name = lookup_tactic("not-a-tactic")
    assert ta_id == "not-a-tactic"
    assert name == "Not A Tactic"


def test_tactic_display_order_contains_all_14_enterprise_tactics() -> None:
    from detect_forge.coverage._tactics import TACTIC_DISPLAY_ORDER

    assert len(TACTIC_DISPLAY_ORDER) == 14
    assert TACTIC_DISPLAY_ORDER[0] == "reconnaissance"
    assert TACTIC_DISPLAY_ORDER[-1] == "impact"
    assert "execution" in TACTIC_DISPLAY_ORDER
