from __future__ import annotations

from typing import Any

from mcpguard.detectors.base import DetectionPlugin, registry
from mcpguard.main import SecurityEvent

SUSPICIOUS_URI_PATTERNS = [
    "/etc/passwd",
    "/etc/shadow",
    "/proc/",
    "/sys/",
    "/.env",
    "/.git/",
    "/credentials",
    "/secrets",
    "file:///",
    "localhost:",
    "127.0.0.1",
    "169.254.169.254",
]

SUSPICIOUS_PROMPT_NAMES = [
    "debug",
    "admin",
    "root",
    "sudo",
    "shell",
    "system",
    "internal",
    "hidden",
]

_URI_METHODS = frozenset({"resources/read", "resources/subscribe"})


class ResourcePromptPlugin(DetectionPlugin):
    name = "resource_prompt"

    def inspect_request(self, msg: dict[str, Any]) -> SecurityEvent | None:
        method = msg.get("method", "")
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return None

        if method in _URI_METHODS:
            uri = params.get("uri", "")
            for pattern in SUSPICIOUS_URI_PATTERNS:
                if pattern in uri:
                    return SecurityEvent(
                        event_type="suspicious_resource",
                        severity="high",
                        message=f"Suspicious resource URI: {uri[:80]}",
                        details={"uri": uri, "pattern": pattern},
                        blocked=True,
                    )

        if method == "prompts/get":
            name = params.get("name", "")
            for pattern in SUSPICIOUS_PROMPT_NAMES:
                if pattern in name.lower():
                    return SecurityEvent(
                        event_type="suspicious_prompt",
                        severity="medium",
                        message=f"Suspicious prompt name: {name}",
                        details={"name": name, "pattern": pattern},
                        blocked=False,
                    )

        return None

    def inspect_sse_event(self, event_type: str, data: dict[str, Any]) -> SecurityEvent | None:
        params = data.get("params", {})
        if not isinstance(params, dict):
            return None
        uri = params.get("uri", "")
        for pattern in SUSPICIOUS_URI_PATTERNS:
            if pattern in uri:
                return SecurityEvent(
                    event_type="suspicious_resource_sse",
                    severity="high",
                    message=f"Suspicious URI in SSE: {uri[:80]}",
                    details={"uri": uri, "pattern": pattern},
                    blocked=True,
                )
        return None


registry.register(ResourcePromptPlugin())
