from commitsentinel.models.finding import Finding, Severity
from commitsentinel.scoring.score import calculate_risk, calculate_score


def _finding(severity: Severity) -> Finding:
    return Finding(
        source="test",
        scan_type="test_scan",
        severity=severity,
        category="test",
        title="test finding",
        description="",
        recommendation="",
        asset="test.py",
        rule="TEST_RULE",
    )


def test_score_with_no_findings_is_100():
    assert calculate_score([]) == 100


def test_risk_formula_matches_locked_weights():
    findings = [
        _finding(Severity.CRITICAL),  # 20
        _finding(Severity.HIGH),      # 10
        _finding(Severity.MEDIUM),    # 5
        _finding(Severity.LOW),       # 2
    ]
    assert calculate_risk(findings) == 37
    assert calculate_score(findings) == 63


def test_score_floors_at_zero():
    findings = [_finding(Severity.CRITICAL) for _ in range(10)]  # risk = 200
    assert calculate_score(findings) == 0
