"""Merge-conflict-marker scanner — flags unresolved `<<<<<<<` / `=======` /
`>>>>>>>` markers left in committed code. See section 4.2 of the build plan.

A bare `=======` is only flagged when it falls between an unmatched
`<<<<<<<` and the next `>>>>>>>` in the same file — that's what stops a
Markdown Setext heading underline (`Title\\n=======`) from being mistaken
for a conflict marker.
"""

from __future__ import annotations

from pathlib import Path

from commitsentinel.models.finding import Finding, Severity
from commitsentinel.scanners._shared import iter_files, read_text_lines, relative_asset
from commitsentinel.scanners.base import Scanner

_START = "<<<<<<<"
_MID = "======="
_END = ">>>>>>>"


class ConflictMarkerScanner(Scanner):
    name = "conflict_markers"

    def scan(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        for path in iter_files(repo_path):
            lines = read_text_lines(path)
            if lines is None:
                continue

            asset = relative_asset(path, repo_path)
            in_conflict = False

            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()

                if stripped.startswith(_START):
                    in_conflict = True
                    findings.append(self._finding(asset, lineno, _START))
                elif stripped.startswith(_END):
                    in_conflict = False
                    findings.append(self._finding(asset, lineno, _END))
                elif in_conflict and stripped == _MID:
                    findings.append(self._finding(asset, lineno, _MID))

        return findings

    @staticmethod
    def _finding(asset: str, lineno: int, marker: str) -> Finding:
        return Finding(
            source="conflict_markers",
            scan_type="conflict_marker_scan",
            severity=Severity.HIGH,
            category="unresolved_merge_conflict",
            title="Unresolved merge conflict marker",
            description=f"Found a `{marker}` conflict marker on line {lineno}.",
            recommendation="Resolve the merge conflict and remove the marker before committing.",
            asset=asset,
            rule="MERGE_CONFLICT_MARKER",
            line=lineno,
            confidence=0.95,
        )
