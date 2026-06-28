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
    source: str               
    scan_type: str            
    severity: Severity
    category: str             
    title: str
    description: str
    recommendation: str
    asset: str                
    rule: str                  
    line: Optional[int] = None
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
