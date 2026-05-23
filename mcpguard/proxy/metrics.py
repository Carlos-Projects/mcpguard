from __future__ import annotations

from typing import Any


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
        "# HELP mcpguard_sse_connections Total SSE connections",
        "# TYPE mcpguard_sse_connections counter",
        f"mcpguard_sse_connections {metrics['sse_connections']}",
        "",
    ]
    for tool, count in metrics.get("tool_calls", {}).items():
        sanitized = tool.replace('"', '\\"').replace("\n", "")
        lines.append(f"mcpguard_tool_calls_total{{tool=\"{sanitized}\"}} {count}")
    return "\n".join(lines) + "\n"
