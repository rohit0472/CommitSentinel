from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

from commitsentinel.models.finding import Finding, Severity
from commitsentinel.scanners._shared import iter_files, relative_asset
from commitsentinel.scanners.base import Scanner

SENSITIVE_FILE_PATTERNS = [
    ".env", ".env.*",
    "*.pem", "*.p12", "*.pfx", "*.keystore", "*.jks",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials.json", "firebase-adminsdk*.json",
    ".npmrc", ".netrc", ".pgpass",
]

# Templates and public keys that look sensitive by name but aren't.
_SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist")
_PUBLIC_KEY_SUFFIX = ".pub"


def _is_sensitive(name: str) -> bool:
    if name.endswith(_PUBLIC_KEY_SUFFIX):
        return False
    if name.startswith(".env") and name.endswith(_SAFE_ENV_SUFFIXES):
        return False
    return any(fnmatch.fnmatch(name, pattern) for pattern in SENSITIVE_FILE_PATTERNS)


class SensitiveFileScanner(Scanner):
    name = "sensitive_files"

    def scan(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        candidates = [path for path in iter_files(repo_path) if _is_sensitive(path.name)]
        if not candidates:
            return findings

        is_git_repo = self._git(["rev-parse", "--is-inside-work-tree"], repo_path)[0] == 0
        staged: set[str] = set()
        if is_git_repo:
            staged = set(self._git(["diff", "--cached", "--name-only"], repo_path)[1].splitlines())

        for path in candidates:
            asset = relative_asset(path, repo_path)

            if not is_git_repo:
                findings.append(
                    self._finding(
                        asset,
                        Severity.MEDIUM,
                        "Sensitive file present",
                        "This file matches a known sensitive-file pattern. Couldn't check "
                        "git status (not a git repository) — verify it isn't meant to stay "
                        "out of version control.",
                        "REVIEW_AND_GITIGNORE",
                    )
                )
                continue

            # `git ls-files` would also catch newly-staged files, which is not what
            # we want here — check HEAD specifically so "already committed" only
            # fires for files that genuinely exist in history.
            tracked_at_head = self._git(["cat-file", "-e", f"HEAD:{asset}"], repo_path)[0] == 0

            if tracked_at_head:
                findings.append(
                    self._finding(
                        asset,
                        Severity.CRITICAL,
                        "Sensitive file is tracked in git",
                        "This file is already committed to git history. Removing it now "
                        "won't remove it from past commits.",
                        "ROTATE_AND_PURGE_HISTORY",
                    )
                )
            elif asset in staged:
                findings.append(
                    self._finding(
                        asset,
                        Severity.HIGH,
                        "Sensitive file staged for commit",
                        "This file is staged and about to be committed. Unstage it and add "
                        "it to .gitignore before committing.",
                        "UNSTAGE_AND_GITIGNORE",
                    )
                )
            else:
                returncode, _ = self._git(["check-ignore", "-q", asset], repo_path)
                if returncode != 0:
                    findings.append(
                        self._finding(
                            asset,
                            Severity.MEDIUM,
                            "Sensitive file not covered by .gitignore",
                            "This file exists in the working tree, isn't tracked or staged "
                            "yet, but also isn't gitignored — one `git add .` away from "
                            "being committed.",
                            "ADD_TO_GITIGNORE",
                        )
                    )
                # else: untracked, unstaged, and gitignored — working as intended.

        return findings

    @staticmethod
    def _git(args: list[str], repo_path: Path) -> tuple[int, str]:
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10,
                stdin=subprocess.DEVNULL,
            )
            return result.returncode, result.stdout
        except (OSError, subprocess.TimeoutExpired):
            return 1, ""

    @staticmethod
    def _finding(
        asset: str, severity: Severity, title: str, description: str, rule: str
    ) -> Finding:
        recommendations = {
            "REVIEW_AND_GITIGNORE": "Confirm this file shouldn't be committed, and add it to .gitignore if not.",
            "ROTATE_AND_PURGE_HISTORY": "Rotate any credentials inside this file, remove it, and scrub it from git history (e.g. git filter-repo).",
            "UNSTAGE_AND_GITIGNORE": "Run `git restore --staged <file>` and add it to .gitignore.",
            "ADD_TO_GITIGNORE": "Add this file (or its pattern) to .gitignore before it gets staged by accident.",
        }
        return Finding(
            source="sensitive_files",
            scan_type="sensitive_file_scan",
            severity=severity,
            category="sensitive_file_exposure",
            title=title,
            description=description,
            recommendation=recommendations[rule],
            asset=asset,
            rule=rule,
            confidence=0.95,
        )
