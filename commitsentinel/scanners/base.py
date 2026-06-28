from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from commitsentinel.models.finding import Finding


class Scanner(ABC):
    #: short, stable identifier used as Finding.source (e.g. "secrets")
    name: str = "base"

    @abstractmethod
    def scan(self, repo_path: Path) -> list[Finding]:
        """Scan `repo_path` and return any findings.

        Must not raise on a clean repo or on a repo with nothing to
        find for this scanner — return an empty list instead.
        """
        raise NotImplementedError
