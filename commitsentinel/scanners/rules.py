from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from commitsentinel.models.finding import Severity


@dataclass(frozen=True)
class SecretRule:
    rule: str
    pattern: re.Pattern
    severity: Severity
    title: str
    recommendation: str
    confidence: float = 0.95


SECRET_RULES: list[SecretRule] = [
    SecretRule(
        rule="AWS_ACCESS_KEY_ID",
        pattern=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        severity=Severity.CRITICAL,
        title="AWS access key ID detected",
        recommendation="Rotate this AWS key immediately and load it from environment variables or a secrets manager instead.",
    ),
    SecretRule(
        rule="GITHUB_TOKEN",
        pattern=re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        severity=Severity.CRITICAL,
        title="GitHub personal access token detected",
        recommendation="Revoke this token in GitHub settings and use a fine-grained token loaded from a secret store.",
    ),
    SecretRule(
        rule="OPENAI_API_KEY",
        pattern=re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b"),
        severity=Severity.HIGH,
        title="OpenAI API key detected",
        recommendation="Revoke this key in the OpenAI dashboard and load it from an environment variable instead.",
    ),
    SecretRule(
        rule="GOOGLE_API_KEY",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        severity=Severity.HIGH,
        title="Google API key detected",
        recommendation="Restrict or rotate this key in Google Cloud Console and load it from an environment variable instead.",
    ),
    SecretRule(
        rule="SLACK_TOKEN",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"),
        severity=Severity.HIGH,
        title="Slack token detected",
        recommendation="Revoke this token in Slack app settings and load it from a secret store instead.",
    ),
    SecretRule(
        rule="JWT",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity=Severity.MEDIUM,
        title="JWT detected",
        recommendation="Confirm this isn't a live token committed by mistake; rotate it if it grants real access.",
        confidence=0.85,
    ),
    SecretRule(
        rule="PRIVATE_KEY_BLOCK",
        pattern=re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        title="Private key detected",
        recommendation="Remove this key from version control, rotate it, and store it outside the repo (e.g. a secrets manager, or a local-only file covered by .gitignore).",
    ),
    SecretRule(
        rule="GENERIC_SECRET_ASSIGNMENT",
        pattern=re.compile(
            r"""(?i)\b(api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]"""
        ),
        severity=Severity.MEDIUM,
        title="Hardcoded credential-like value detected",
        recommendation="Move this value to an environment variable or secret store; don't commit literal credentials.",
        confidence=0.6,
    ),
]


PLACEHOLDER_VALUES = {
    "changeme", "change_me", "your_api_key", "your-api-key", "xxxxxxxx",
    "placeholder", "example", "dummy", "test", "fake", "redacted",
    "insert_key_here", "<password>", "<api_key>", "<secret>", "todo",
    "password", "secret", "string", "none", "null", "undefined",
}



ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=-]{20,100}")
ENTROPY_THRESHOLD = 4.3
_HEX_HASH_LENGTHS = {32, 40, 64}  
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_like_secret_candidate(token: str) -> bool:
    """Filter out common high-entropy-but-harmless tokens before scoring
    (UUIDs, hex hashes, and degenerate repeated-character strings)."""
    if _UUID_RE.match(token):
        return False
    if len(token) in _HEX_HASH_LENGTHS and all(c in "0123456789abcdef" for c in token.lower()):
        return False
    if len(set(token)) <= 3:
        return False
    return True
