"""Secret scanner — regex rules for known credential formats, plus
Shannon-entropy detection for high-entropy strings that don't match a
known format. See section 4.1 of the build plan.
"""

from __future__ import annotations

from pathlib import Path

from commitsentinel.models.finding import Finding, Severity
from commitsentinel.scanners._shared import iter_files, read_text_lines, relative_asset
from commitsentinel.scanners.base import Scanner
from commitsentinel.scanners.rules import (
    ENTROPY_THRESHOLD,
    ENTROPY_TOKEN_RE,
    PLACEHOLDER_VALUES,
    SECRET_RULES,
    looks_like_secret_candidate,
    shannon_entropy,
)

# Files where high-entropy strings are expected and not worth flagging —
# lockfiles and minified bundles are full of them by design.
_SKIP_ENTROPY_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "composer.lock",
}
_SKIP_ENTROPY_SUFFIXES = (".min.js", ".min.css", ".map")


def _redact(value: str) -> str:
    """Mask a matched secret so the report itself doesn't leak it."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


class SecretScanner(Scanner):
    name = "secrets"

    def scan(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        for path in iter_files(repo_path):
            lines = read_text_lines(path)
            if lines is None:
                continue

            asset = relative_asset(path, repo_path)
            skip_entropy = path.name in _SKIP_ENTROPY_NAMES or path.name.endswith(
                _SKIP_ENTROPY_SUFFIXES
            )

            for lineno, line in enumerate(lines, start=1):
                matched_chars: set[int] = set()

                for rule in SECRET_RULES:
                    for match in rule.pattern.finditer(line):
                        if rule.rule == "GENERIC_SECRET_ASSIGNMENT":
                            value = match.group(2)
                            if self._is_placeholder(value):
                                continue
                            matched_text = value
                        else:
                            matched_text = match.group(0)

                        findings.append(
                            Finding(
                                source=self.name,
                                scan_type="secret_scan",
                                severity=rule.severity,
                                category="credential_exposure",
                                title=rule.title,
                                description=f"Matched pattern for {rule.rule} on line {lineno}.",
                                recommendation=rule.recommendation,
                                asset=asset,
                                rule=rule.rule,
                                line=lineno,
                                confidence=rule.confidence,
                                metadata={"preview": _redact(matched_text)},
                            )
                        )
                        matched_chars.update(range(match.start(), match.end()))

                if skip_entropy or "://" in line:
                    continue

                for token_match in ENTROPY_TOKEN_RE.finditer(line):
                    token = token_match.group(0)
                    span = range(token_match.start(), token_match.end())
                    if matched_chars.intersection(span):
                        continue  # already caught by a known-format rule above
                    if not looks_like_secret_candidate(token):
                        continue
                    entropy = shannon_entropy(token)
                    if entropy < ENTROPY_THRESHOLD:
                        continue

                    findings.append(
                        Finding(
                            source=self.name,
                            scan_type="secret_scan",
                            severity=Severity.MEDIUM,
                            category="credential_exposure",
                            title="High-entropy string detected",
                            description=(
                                f"Found a {len(token)}-character string with entropy "
                                f"{entropy:.2f} bits/char on line {lineno} — could be an "
                                f"unrecognized API key or token."
                            ),
                            recommendation="Confirm whether this is a real credential; if so, rotate it and move it out of source control.",
                            asset=asset,
                            rule="HIGH_ENTROPY",
                            line=lineno,
                            confidence=min(0.9, entropy / 6.0),
                            metadata={"preview": _redact(token), "entropy": round(entropy, 2)},
                        )
                    )

        return findings

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        normalized = value.strip().lower()
        if normalized in PLACEHOLDER_VALUES:
            return True
        if len(set(normalized)) <= 2:
            return True
        if normalized.startswith("${") or normalized.startswith("{{"):
            return True
        return False
