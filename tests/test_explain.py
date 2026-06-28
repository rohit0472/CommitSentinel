import json
from types import SimpleNamespace

import pytest

from commitsentinel.ai.explain import ExplainError, explain_findings
from commitsentinel.models.finding import Finding, Severity


def _finding(title: str = "test finding", **overrides) -> Finding:
    defaults = dict(
        source="secrets",
        scan_type="secret_scan",
        severity=Severity.HIGH,
        category="credential_exposure",
        title=title,
        description="desc",
        recommendation="rotate it",
        asset="a.py",
        rule="TEST_RULE",
        line=1,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _fake_client(response_text: str):
    """Stand-in for anthropic.Anthropic — only needs .messages.create()."""

    def create(**kwargs):
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=response_text)])

    return SimpleNamespace(messages=SimpleNamespace(create=create))


def test_attaches_explanation_to_matching_finding_by_index():
    findings = [_finding("AWS key"), _finding("Conflict marker")]
    response_text = json.dumps(
        [
            {"index": 0, "explanation": "This AWS key grants full account access."},
            {"index": 1, "explanation": "An unresolved conflict will break the build."},
        ]
    )

    explain_findings(findings, client=_fake_client(response_text))

    assert findings[0].metadata["ai_explanation"] == "This AWS key grants full account access."
    assert findings[1].metadata["ai_explanation"] == "An unresolved conflict will break the build."


def test_empty_findings_list_is_a_noop():
    # No client, no API key — should not raise, since there's nothing to explain.
    explain_findings([])


def test_missing_api_key_raises_explain_error(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ExplainError, match="ANTHROPIC_API_KEY"):
        explain_findings([_finding()])


def test_malformed_json_response_raises_explain_error():
    with pytest.raises(ExplainError, match="unparseable"):
        explain_findings([_finding()], client=_fake_client("not valid json"))


def test_out_of_range_index_is_ignored_not_crashed():
    findings = [_finding()]
    response_text = json.dumps([{"index": 99, "explanation": "ignored"}])

    explain_findings(findings, client=_fake_client(response_text))

    assert "ai_explanation" not in findings[0].metadata


def test_client_request_failure_raises_explain_error():
    def _raise(**kwargs):
        raise RuntimeError("network down")

    broken_client = SimpleNamespace(messages=SimpleNamespace(create=_raise))
    with pytest.raises(ExplainError, match="request failed"):
        explain_findings([_finding()], client=broken_client)


def test_prompt_never_includes_finding_metadata():
    """The redacted secret preview lives in finding.metadata — it must
    never be sent to the model, even by accident."""
    finding = _finding(metadata={"preview": "AKIA****REAL****1234"})
    captured = {}

    def create(**kwargs):
        captured["sent"] = kwargs["messages"][0]["content"]
        return SimpleNamespace(content=[SimpleNamespace(type="text", text="[]")])

    client = SimpleNamespace(messages=SimpleNamespace(create=create))
    explain_findings([finding], client=client)

    assert "AKIA" not in captured["sent"]
    assert "preview" not in captured["sent"]
