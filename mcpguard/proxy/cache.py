from __future__ import annotations

import time
from typing import Any


class ToolCache:
    def __init__(self, ttl: int = 60) -> None:
        self._data: list[dict[str, Any]] | None = None
        self._ts: float = 0
        self._ttl = ttl

    def get(self) -> list[dict[str, Any]] | None:
        if self._data is not None and time.time() - self._ts < self._ttl:
            return self._data
        return None

    def set(self, tools: list[dict[str, Any]]) -> None:
        self._data = tools
        self._ts = time.time()

    def invalidate(self) -> None:
        self._data = None
        self._ts = 0
