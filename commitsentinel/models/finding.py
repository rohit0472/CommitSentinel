"""The Finding model. This is the contract every scanner returns —
no exceptions. See section 3 of the build plan.

`metadata` is the escape hatch: future scanners (Phase 2/3) attach
extra data there without changing this schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    source: str                # which scanner produced this, e.g. "secrets"
    scan_type: str              # e.g. "secret_scan"
    severity: Severity
    category: str               # e.g. "credential_exposure"
    title: str
    description: str
    recommendation: str
    asset: str                  # file path (or other identifier) affected
    rule: str                   # which rule/pattern matched
    line: Optional[int] = None
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
