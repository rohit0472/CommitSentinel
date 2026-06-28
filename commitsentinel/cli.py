"""typer entrypoint. Wires scanners together — this file owns the loop,
nothing else does.

    findings = []
    for scanner in scanners:
        findings.extend(scanner.scan(repo_path))

Registering a new scanner is exactly one line in SCANNERS below.
Nothing else in the codebase changes.
"""

from __future__ import annotations

from pathlib import Path

import typer

from commitsentinel.ai.explain import ExplainError, explain_findings
from commitsentinel.reports.console import print_report
from commitsentinel.scanners.base import Scanner
from commitsentinel.scanners.conflict_markers import ConflictMarkerScanner
from commitsentinel.scanners.secrets import SecretScanner
from commitsentinel.scanners.sensitive_files import SensitiveFileScanner
from commitsentinel.scoring.score import calculate_score

app = typer.Typer(
    help="CommitSentinel — scan a repo for secrets, conflict markers, and sensitive files."
)


@app.callback()
def main() -> None:
    """CommitSentinel CLI. Run `commitsentinel scan <path>` to scan a repo."""
    # Empty on purpose: this callback exists only so Typer keeps `scan`
    # as an explicit subcommand instead of collapsing to the single
    # registered command (its default behavior with only one command).
    # Once Phase 2/3 add more commands, this still won't change.

# Each scanner is its own module under scanners/ and knows nothing about
# the others. Adding a new one later is exactly one line here.
SCANNERS: list[Scanner] = [
    SecretScanner(),
    ConflictMarkerScanner(),
    SensitiveFileScanner(),
]


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Path to the repo to scan."),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Add an AI-generated explanation to each finding (requires ANTHROPIC_API_KEY).",
    ),
) -> None:
    """Scan a repository and print a console report."""
    repo_path = path.resolve()
    if not repo_path.exists():
        typer.secho(f"Path not found: {repo_path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    findings = []
    for scanner in SCANNERS:
        findings.extend(scanner.scan(repo_path))

    if explain and findings:
        # Runs once, after every scanner has already finished — never
        # inside a scanner. A failure here (no key, no package, network
        # issue) is a warning, not a reason to throw away the scan
        # results that just took real time to produce.
        try:
            explain_findings(findings)
        except ExplainError as exc:
            typer.secho(f"Warning: {exc}", fg=typer.colors.YELLOW, err=True)

    score = calculate_score(findings)
    print_report(findings, score)


if __name__ == "__main__":
    app()
