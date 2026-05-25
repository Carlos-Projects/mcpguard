from __future__ import annotations

import re
from typing import Any


def _sanitize_label(value: str) -> str:
    sanitized = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    if re.search(r'[^\x20-\x7E]', sanitized):
        sanitized = "invalid"
    return sanitized


def render_prometheus(metrics: dict[str, Any]) -> str:
    lines: list[str] = [
        "# HELP mcpguard_total_requests Total requests received",
        "# TYPE mcpguard_total_requests counter",
        f"mcpguard_total_requests {metrics['total_requests']}",
        "",
        "# HELP mcpguard_blocked_requests Total blocked requests",
        "# TYPE mcpguard_blocked_requests counter",
        f"mcpguard_blocked_requests {metrics['blocked_requests']}",
        "",
        "# HELP mcpguard_injections_detected Prompt injections detected",
        "# TYPE mcpguard_injections_detected counter",
        f"mcpguard_injections_detected {metrics['injections_detected']}",
        "",
        "# HELP mcpguard_poisoning_detected Tool poisoning attempts detected",
        "# TYPE mcpguard_poisoning_detected counter",
        f"mcpguard_poisoning_detected {metrics['poisoning_detected']}",
        "",
        "# HELP mcpguard_anomalies_detected Anomalies detected",
        "# TYPE mcpguard_anomalies_detected counter",
        f"mcpguard_anomalies_detected {metrics['anomalies_detected']}",
        "",
        "# HELP mcpguard_sse_total_connections Total SSE connections",
        "# TYPE mcpguard_sse_total_connections counter",
        f"mcpguard_sse_total_connections {metrics.get('sse_total_connections', 0)}",
        "",
        "# HELP mcpguard_uptime_seconds Proxy uptime in seconds",
        "# TYPE mcpguard_uptime_seconds gauge",
        f"mcpguard_uptime_seconds {metrics.get('uptime_seconds', 0)}",
        "",
        "# HELP mcpguard_active_sse_connections Current active SSE connections",
        "# TYPE mcpguard_active_sse_connections gauge",
        f"mcpguard_active_sse_connections {metrics.get('sse_connections', 0)}",
    ]
    for tool, count in metrics.get("tool_calls", {}).items():
        label = _sanitize_label(tool)
        lines.append(f'mcpguard_tool_calls_total{{tool="{label}"}} {count}')
    return "\n".join(lines) + "\n"
