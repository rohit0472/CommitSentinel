
from __future__ import annotations

from rich.console import Console

from commitsentinel.models.finding import Finding, Severity

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold dark_orange",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
}


def print_report(findings: list[Finding], score: int, console: Console | None = None) -> None:
    console = console or Console()

    if not findings:
        console.print(f"0 findings, score {score}")
        return

    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1

    console.print(f"{len(findings)} findings, score {score}\n")
    for sev in _SEVERITY_ORDER:
        if counts[sev]:
            console.print(f"  [{_SEVERITY_STYLE[sev]}]{sev.value.upper():<8}[/] {counts[sev]}")
    console.print()

    for finding in findings:
        location = f"{finding.asset}:{finding.line}" if finding.line is not None else finding.asset
        style = _SEVERITY_STYLE[finding.severity]
        console.print(f"[{style}][{finding.severity.value.upper()}][/] {finding.title} ({location})")
        explanation = finding.metadata.get("ai_explanation")
        if explanation:
            console.print(f"    [dim]ai:[/] {explanation}")
        if finding.recommendation:
            console.print(f"    [dim]->[/] {finding.recommendation}")
