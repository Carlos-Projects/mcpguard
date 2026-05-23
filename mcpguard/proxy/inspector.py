from __future__ import annotations

from typing import Any


class MessageInspector:
    def inspect(self, msg: dict[str, Any]) -> dict[str, Any]:
        method = ""
        params: Any = None
        msg_id: Any = None
        msg_type = "unknown"

        if "method" in msg:
            if "id" in msg:
                msg_type = "request"
            else:
                msg_type = "notification"
            method = msg["method"]
            params = msg.get("params")
            msg_id = msg.get("id")
        elif "result" in msg:
            msg_type = "response"
            msg_id = msg.get("id")
        elif "error" in msg:
            msg_type = "error"
            msg_id = msg.get("id")

        return {
            "type": msg_type,
            "method": method,
            "params": params,
            "id": msg_id,
            "raw": msg,
        }

    def get_tool_name(self, msg: dict[str, Any]) -> str | None:
        if msg.get("method") == "tools/call":
            params = msg.get("params", {})
            if isinstance(params, dict):
                return params.get("name")
        return None

    def get_tool_arguments(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        if msg.get("method") == "tools/call":
            params = msg.get("params", {})
            if isinstance(params, dict):
                return params.get("arguments", {})
        return None
