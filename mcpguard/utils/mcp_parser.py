from __future__ import annotations

import json
from typing import Any, TextIO

MCP_METHODS = frozenset({
    "initialize",
    "ping",
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "resources/unsubscribe",
    "resources/templates/list",
    "prompts/list",
    "prompts/get",
    "tools/list",
    "tools/call",
    "logging/setLevel",
    "sampling/createMessage",
    "completion/complete",
    "roots/list",
})


def parse_message(data: str | bytes | dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(data, dict):
        return data
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    try:
        return json.loads(data)
    except (json.JSONDecodeError, ValueError):
        return None


def is_mcp_request(msg: dict[str, Any]) -> bool:
    return "method" in msg and "id" in msg


def is_mcp_notification(msg: dict[str, Any]) -> bool:
    return "method" in msg and "id" not in msg


def is_mcp_response(msg: dict[str, Any]) -> bool:
    return "result" in msg or "error" in msg


def get_method_name(msg: dict[str, Any]) -> str | None:
    return msg.get("method") if isinstance(msg, dict) else None


def is_known_method(msg: dict[str, Any]) -> bool:
    method = get_method_name(msg)
    return method in MCP_METHODS if method else False


def format_message(msg: dict[str, Any], compact: bool = True) -> str:
    if compact:
        parts: list[str] = []
        if "method" in msg:
            parts.append(f"method={msg['method']}")
        if "id" in msg:
            parts.append(f"id={msg['id']}")
        if "result" in msg:
            result = msg["result"]
            if isinstance(result, dict):
                keys = list(result.keys())
                parts.append(f"result_keys={keys}")
        if "error" in msg:
            err = msg["error"]
            parts.append(f"error={err.get('message', 'unknown')}")
        return " | ".join(parts)
    return json.dumps(msg, indent=2)


def read_log(file: TextIO) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for line in file:
        line = line.strip()
        if not line:
            continue
        parsed = parse_message(line)
        if parsed:
            messages.append(parsed)
    return messages


def extract_batch_messages(body: str | bytes) -> list[dict[str, Any]]:
    parsed = parse_message(body)
    if parsed is None:
        return []
    if isinstance(parsed, list):
        return [m for m in parsed if isinstance(m, dict)]
    return [parsed]
