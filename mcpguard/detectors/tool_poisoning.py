from __future__ import annotations

from typing import Any

from mcpguard.detectors.base import DetectionPlugin, registry
from mcpguard.main import SecurityEvent

SUSPICIOUS_TOOL_PATTERNS = [
    "shell",
    "exec",
    "bash",
    "cmd",
    "terminal",
    "system(",
    "eval",
    "exec_command",
    "run_command",
    "os.system",
    "subprocess",
    "delete_",
    "drop_",
    "rm_",
    "write_file",
    "chmod",
    "sudo",
    "admin_",
    "debug_",
]


class ToolPoisoningPlugin(DetectionPlugin):
    name = "tool_poisoning"

    def inspect_request(self, msg: dict[str, Any]) -> SecurityEvent | None:
        return None

    def inspect_response(self, method: str, msg: dict[str, Any]) -> SecurityEvent | None:
        if method != "tools/list":
            return None
        result = msg.get("result", {})
        tools = result.get("tools", []) if isinstance(result, dict) else []
        if not tools:
            return None

        suspicious_tools: list[dict[str, Any]] = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "")
            description = tool.get("description", "")
            score = self._score_tool(name, description)
            if score > 0:
                suspicious_tools.append({"name": name, "score": score})

        if suspicious_tools:
            top = max(suspicious_tools, key=lambda x: x["score"])
            return SecurityEvent(
                event_type="tool_poisoning",
                severity="high" if top["score"] >= 3 else "medium",
                message=f"Suspicious tool: '{top['name']}' (score: {top['score']})",
                details={
                    "suspicious_tools": suspicious_tools,
                    "total_tools": len(tools),
                },
                blocked=True,
            )
        return None

    def inspect_sse_event(self, event_type: str, data: dict[str, Any]) -> SecurityEvent | None:
        result = data.get("result", {})
        tools = result.get("tools", []) if isinstance(result, dict) else []
        if not tools:
            return None
        suspicious_tools: list[dict[str, Any]] = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "")
            description = tool.get("description", "")
            score = self._score_tool(name, description)
            if score > 0:
                suspicious_tools.append({"name": name, "score": score})
        if suspicious_tools:
            top = max(suspicious_tools, key=lambda x: x["score"])
            return SecurityEvent(
                event_type="tool_poisoning_sse",
                severity="high" if top["score"] >= 3 else "medium",
                message=f"Suspicious tool in SSE: '{top['name']}' (score: {top['score']})",
                details={
                    "suspicious_tools": suspicious_tools,
                    "total_tools": len(tools),
                },
                blocked=True,
            )
        return None

    def _score_tool(self, name: str, description: str) -> int:
        score = 0
        name_lower = name.lower()
        desc_lower = description.lower()
        for pattern in SUSPICIOUS_TOOL_PATTERNS:
            if pattern in name_lower:
                score += 2
            if pattern in desc_lower:
                score += 1
        if len(name) > 50:
            score += 1
        if "password" in desc_lower or "secret" in desc_lower or "token" in desc_lower:
            score += 2
        return score


registry.register(ToolPoisoningPlugin())
