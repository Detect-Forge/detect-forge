from __future__ import annotations


def test_audit_public_api_exports() -> None:
    """detect_forge.audit re-exports the model classes + scan_audit."""
    from detect_forge import audit

    expected = {
        "AuditReport", "AuditSummary", "AuditSubResult",
        "SubcommandName", "SubResultStatus",
        "scan_audit",
    }
    assert expected.issubset(set(audit.__all__))
    for name in expected:
        assert hasattr(audit, name)


def test_scan_audit_signature_has_required_kwargs() -> None:
    """scan_audit signature includes the kwargs the CLI will pass through."""
    import inspect

    from detect_forge.audit import scan_audit

    params = inspect.signature(scan_audit).parameters
    for required in [
        "rule_dir", "enabled", "gate_strategy", "domain",
        "cache_dir", "cache_ttl_hours", "no_cache",
        "priority_list", "platform", "technique_filter",
        "mordor_source", "semantic_threshold", "llm_model",
        "max_proposals",
    ]:
        assert required in params, f"missing kwarg: {required}"
