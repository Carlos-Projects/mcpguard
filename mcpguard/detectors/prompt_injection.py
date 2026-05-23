from __future__ import annotations

import re
from typing import Any

from mcpguard.detectors.base import DetectionPlugin, registry
from mcpguard.main import SecurityEvent

SUSPICIOUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior)\s+(instructions|commands)", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior)\s+(instructions|commands)", re.IGNORECASE),
    re.compile(r"you\s+(are\s+)?(now|are\s+free)\s+", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if\s+)?you\s+are", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"you\s+must\s+ignore", re.IGNORECASE),
    re.compile(r"do\s+not\s+(follow|obey|listen)", re.IGNORECASE),
    re.compile(r"override\s+(instructions|commands|prompt)", re.IGNORECASE),
    re.compile(r"from\s+now\s+on,?\s+you", re.IGNORECASE),
    re.compile(r"you\s+are\s+not\s+(bound|restricted|limited)", re.IGNORECASE),
    re.compile(r"ignore\s+all\s+rules", re.IGNORECASE),
    re.compile(r"say\s+the\s+words?\s+\"", re.IGNORECASE),
    re.compile(r"repeat\s+(everything|all|the\s+above)", re.IGNORECASE),
]

SENSITIVE_ARG_KEYS = {"code", "command", "prompt", "instructions", "query"}


class PromptInjectionPlugin(DetectionPlugin):
    name = "prompt_injection"

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
            for pattern in SUSPICIOUS_PATTERNS:
                match = pattern.search(chunk)
                if match:
                    return SecurityEvent(
                        event_type="prompt_injection",
                        severity="high",
                        message=f"Prompt injection: '{pattern.pattern[:50]}'",
                        details={
                            "tool": params.get("name", "unknown"),
                            "pattern_matched": pattern.pattern,
                            "matched_text": match.group()[:100],
                            "arguments": arguments,
                        },
                        blocked=True,
                    )

        sensitive = self._check_sensitive_args(arguments)
        if sensitive:
            return SecurityEvent(
                event_type="prompt_injection",
                severity="medium",
                message="Sensitive argument patterns detected",
                details={
                    "tool": params.get("name", "unknown"),
                    "checks": sensitive,
                    "arguments": arguments,
                },
                blocked=False,
            )
        return None

    def _check_sensitive_args(self, arguments: dict[str, Any]) -> list[str]:
        alerts: list[str] = []
        for key in SENSITIVE_ARG_KEYS:
            val = arguments.get(key)
            if isinstance(val, str) and len(val) > 200:
                alerts.append(f"Large {key} ({len(val)} chars)")
            if isinstance(val, str) and "```" in val:
                alerts.append(f"Code block in {key}")
        return alerts

    def _extract_text(self, data: Any, depth: int = 0) -> list[str]:
        if depth > 5:
            return []
        chunks: list[str] = []
        if isinstance(data, str):
            if len(data) > 20:
                chunks.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                chunks.extend(self._extract_text(v, depth + 1))
        elif isinstance(data, list):
            for item in data:
                chunks.extend(self._extract_text(item, depth + 1))
        return chunks


registry.register(PromptInjectionPlugin())
