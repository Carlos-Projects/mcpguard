from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from mcpguard.main import SecurityEvent


class DetectionPlugin(ABC):
    name: str = "base"

    @abstractmethod
    def inspect_request(self, msg: dict[str, Any]) -> SecurityEvent | None:
        ...

    def inspect_response(self, method: str, msg: dict[str, Any]) -> SecurityEvent | None:
        return None

    def inspect_sse_event(self, event_type: str, data: dict[str, Any]) -> SecurityEvent | None:
        return None


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: list[DetectionPlugin] = []

    def register(self, plugin: DetectionPlugin) -> None:
        self._plugins.append(plugin)

    def inspect_request(self, msg: dict[str, Any]) -> SecurityEvent | None:
        for plugin in self._plugins:
            result = plugin.inspect_request(msg)
            if result is not None:
                return result
        return None

    def inspect_response(self, method: str, msg: dict[str, Any]) -> SecurityEvent | None:
        for plugin in self._plugins:
            result = plugin.inspect_response(method, msg)
            if result is not None:
                return result
        return None

    def inspect_sse_event(self, event_type: str, data: dict[str, Any]) -> SecurityEvent | None:
        for plugin in self._plugins:
            result = plugin.inspect_sse_event(event_type, data)
            if result is not None:
                return result
        return None

    @property
    def plugins(self) -> list[DetectionPlugin]:
        return list(self._plugins)


registry = PluginRegistry()
