from __future__ import annotations

import json
import os

from commitsentinel.models.finding import Finding

DEFAULT_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 2048

_SYSTEM_PROMPT = (
    "You are a security reviewer annotating static-analysis findings from a repo "
    "scanner called CommitSentinel, for a developer who isn't a security specialist. "
    "For each finding given, write one short, concrete sentence explaining the "
    "real-world risk — don't just restate the title. "
    'Respond with ONLY a JSON array: [{"index": <int>, "explanation": "<text>"}, ...], '
    "one entry per finding, in the same order, no other text and no markdown fences."
)


class ExplainError(Exception):
    """Raised when AI explanation can't run or can't be trusted: missing
    key, missing package, a failed request, or an unparseable response.
    Callers decide whether that's worth surfacing as a warning (the scan
    itself already succeeded — this is a layer on top, not load-bearing)."""


def _build_prompt(findings: list[Finding]) -> str:
    items = [
        {
            "index": i,
            "title": f.title,
            "severity": f.severity.value,
            "category": f.category,
            "asset": f.asset,
            "line": f.line,
            "rule": f.rule,
            "description": f.description,
        }
        for i, f in enumerate(findings)
    ]
    return json.dumps(items)


def explain_findings(
    findings: list[Finding],
    *,
    api_key: str | None = None,
    model: str | None = None,
    client=None,
) -> None:
    """Attach an `ai_explanation` string to each finding's metadata, in place.

    `client` is an injection point for tests — anything exposing
    `.messages.create(...)` shaped like the Anthropic SDK's response works.
    Real callers should leave it as None and let this build a real
    `anthropic.Anthropic` client from `api_key` / ANTHROPIC_API_KEY.
    """
    if not findings:
        return

    if client is None:
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise ExplainError(
                "ANTHROPIC_API_KEY is not set. Export it to use --explain."
            )
        try:
            import anthropic
        except ImportError as exc:
            raise ExplainError(
                'The "anthropic" package isn\'t installed. Run '
                'pip install "commitsentinel[ai]" to use --explain.'
            ) from exc
        client = anthropic.Anthropic(api_key=resolved_key)

    try:
        response = client.messages.create(
            model=model or DEFAULT_MODEL,
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _build_prompt(findings)}],
        )
    except Exception as exc:  # network error, bad key, rate limit — one clear error
        raise ExplainError(f"AI explanation request failed: {exc}") from exc

    raw_text = "".join(
        block.text for block in response.content if getattr(block, "type", None) == "text"
    )

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ExplainError(f"AI explanation returned unparseable output: {exc}") from exc

    for entry in parsed:
        index = entry.get("index")
        explanation = entry.get("explanation")
        if index is None or explanation is None:
            continue
        if 0 <= index < len(findings):
            findings[index].metadata["ai_explanation"] = explanation
