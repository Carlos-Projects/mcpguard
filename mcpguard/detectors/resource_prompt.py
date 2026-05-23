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


class ResourcePromptPlugin(DetectionPlugin):
    name = "resource_prompt"

    def inspect_request(self, msg: dict[str, Any]) -> SecurityEvent | None:
        method = msg.get("method", "")
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return None

        if method == "resources/read":
            uri = params.get("uri", "")
            for pattern in SUSPICIOUS_URI_PATTERNS:
                if pattern in uri:
                    return SecurityEvent(
                        event_type="suspicious_resource",
                        severity="high",
                        message=f"Suspicious resource URI: {uri[:80]}",
                        details={"uri": uri, "pattern": pattern},
                        blocked=False,
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


registry.register(ResourcePromptPlugin())
