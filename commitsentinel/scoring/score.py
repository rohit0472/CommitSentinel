"""Risk score calculation — section 6 of the build plan.

    risk = (critical_count * 20) + (high_count * 10)
         + (medium_count * 5)  + (low_count * 2)

    security_score = max(0, 100 - risk)

"""

from __future__ import annotations

from commitsentinel.models.finding import Finding, Severity

_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
}


def calculate_risk(findings: list[Finding]) -> int:
    return sum(_WEIGHTS[finding.severity] for finding in findings)


def calculate_score(findings: list[Finding]) -> int:
    return max(0, 100 - calculate_risk(findings))
