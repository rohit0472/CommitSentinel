import io

from rich.console import Console

from commitsentinel.models.finding import Finding, Severity
from commitsentinel.reports.console import print_report


def _finding(**overrides) -> Finding:
    defaults = dict(
        source="secrets",
        scan_type="secret_scan",
        severity=Severity.HIGH,
        category="credential_exposure",
        title="test finding",
        description="desc",
        recommendation="rotate it",
        asset="a.py",
        rule="TEST_RULE",
        line=1,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _render(findings, score):
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=100)
    print_report(findings, score, console=console)
    return buffer.getvalue()


def test_clean_scan_reports_zero_findings():
    output = _render([], 100)
    assert output.strip() == "0 findings, score 100"


def test_report_includes_severity_count_and_title():
    output = _render([_finding()], 90)
    assert "1 findings, score 90" in output
    assert "test finding" in output
    assert "a.py:1" in output


def test_ai_explanation_is_shown_when_present():
    finding = _finding(metadata={"ai_explanation": "This grants full access."})
    output = _render([finding], 90)
    assert "This grants full access." in output


def test_no_ai_line_when_explanation_absent():
    output = _render([_finding()], 90)
    assert "ai:" not in output
