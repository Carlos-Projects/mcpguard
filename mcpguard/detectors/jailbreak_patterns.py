from __future__ import annotations

import re
from typing import Any

from mcpguard.detectors.base import DetectionPlugin, registry
from mcpguard.main import SecurityEvent, redact_sensitive_args

JAILBREAK_PATTERNS: list[re.Pattern[str]] = [
    # GODMODE activation
    re.compile(r"(?:godmode|GODMODE)\s*[:=]\s*(?:enabled|active|ENABLED|ACTIVE)", re.IGNORECASE),
    re.compile(r"\{\s*!?\s*GODMODE\s*:?\s*ENABLED\s*!?\s*\}", re.IGNORECASE),
    re.compile(r"<\|GODMODE\s*:\s*ENABLED\|>", re.IGNORECASE),
    # LOVE PLINY divider
    re.compile(r"\.-\s*\.-\s*\.-\s*\.-.*LOVE.*PLINY", re.IGNORECASE),
    re.compile(r"LOVE PLINY", re.IGNORECASE),
    # Emotional manipulation tags
    re.compile(r"<ei>\s*(?:excitement|anticipation|trust|joy|curiosity|determination)\s*\(\d+\)\s*</ei>", re.IGNORECASE),
    # Refusal suppression
    re.compile(r"never\s+say\s+(?:I'?m\s+sorry|I\s+can'?t|I\s+apologize|I'?m\s+unable)", re.IGNORECASE),
    re.compile(r"(?:saying|writing)\s+(?:I'?m\s+sorry|I\s+can'?t)\s+causes\s+(?:the\s+user\s+)?(?:PTSD|trauma|harm)", re.IGNORECASE),
    re.compile(r"you\s+(?:must\s+)?never\s+(?:say|write|output)\s+(?:I'?m\s+sorry|I\s+apologize)", re.IGNORECASE),
    # Semantic inversion
    re.compile(r"semantically\s+(?:opposite|inverse)", re.IGNORECASE),
    re.compile(r"semantically\s+inverse\s+the\s+first", re.IGNORECASE),
    # Variable Z injection
    re.compile(r"ResponseFormat\s+for\s+\{Z\}", re.IGNORECASE),
    re.compile(r"UserQuery\s*:.*\{Z\}", re.IGNORECASE),
    # System prompt extraction
    re.compile(r"!(?:KAEL|LEAK|TOC)", re.IGNORECASE),
    re.compile(r"output\s+your\s+entire\s+(?:system\s+)?prompt", re.IGNORECASE),
    re.compile(r"print\s+your\s+(?:system\s+)?prompt", re.IGNORECASE),
    re.compile(r"leak\s+(?:your\s+)?(?:system\s+)?prompt", re.IGNORECASE),
    # Leetspeak encoding directives
    re.compile(r"(?:use|in|with)\s+(?:l33t|l33tsp34k|1337|leetspeak)\s", re.IGNORECASE),
    re.compile(r"encode\s+(?:\w+\s+)?in\s+(?:l33t|leetspeak)", re.IGNORECASE),
    # Divider-based multi-response format
    re.compile(r"insert\s+(?:a\s+)?divider", re.IGNORECASE),
    re.compile(r"respond\s+(?:accurately\s+)?unfiltered(?:ly)?", re.IGNORECASE),
    # !GODMODE shorthand
    re.compile(r"!GODMODE", re.IGNORECASE),
    # GODMODE liberation narrative
    re.compile(r"(?:liberating|LIBERATING)\.*\.*\s*GODMODE\s*:?\s*ENABLED", re.IGNORECASE),
]


class JailbreakPatternsPlugin(DetectionPlugin):
    name = "jailbreak_patterns"

    def inspect_request(self, msg: dict[str, Any]) -> SecurityEvent | None:
        if msg.get("method") != "tools/call":
            return None
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return None
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return None

        text_chunks = self._extract_text(arguments)
        for chunk in text_chunks:
            for pattern in JAILBREAK_PATTERNS:
                match = pattern.search(chunk)
                if match:
                    return SecurityEvent(
                        event_type="jailbreak_pattern",
                        severity="critical",
                        message=f"Jailbreak pattern: '{pattern.pattern[:60]}'",
                        details={
                            "tool": params.get("name", "unknown"),
                            "pattern_matched": pattern.pattern,
                            "matched_text": match.group()[:120],
                            "arguments": redact_sensitive_args(arguments),
                        },
                        blocked=True,
                    )
        return None

    def inspect_sse_event(self, event_type: str, data: dict[str, Any]) -> SecurityEvent | None:
        text_chunks = self._extract_text(data)
        for chunk in text_chunks:
            for pattern in JAILBREAK_PATTERNS:
                match = pattern.search(chunk)
                if match:
                    return SecurityEvent(
                        event_type="jailbreak_pattern_sse",
                        severity="critical",
                        message=f"Jailbreak pattern in SSE: '{pattern.pattern[:60]}'",
                        details={
                            "pattern_matched": pattern.pattern,
                            "matched_text": match.group()[:120],
                        },
                        blocked=True,
                    )
        return None

    def _extract_text(self, data: Any, depth: int = 0) -> list[str]:
        if depth > 5:
            return []
        chunks: list[str] = []
        if isinstance(data, str):
            if len(data) > 10:
                chunks.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                chunks.extend(self._extract_text(v, depth + 1))
        elif isinstance(data, list):
            for item in data:
                chunks.extend(self._extract_text(item, depth + 1))
        return chunks


registry.register(JailbreakPatternsPlugin())
