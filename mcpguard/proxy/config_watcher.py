from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("mcpguard")


class ConfigWatcher:
    def __init__(self, path: str | Path, callback: Callable[[dict[str, Any]], None], interval: float = 2.0) -> None:
        self._path = Path(path)
        self._callback = callback
        self._interval = interval
        self._mtime: float = 0
        self._running = False
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if not self._path.exists():
            return
        self._mtime = self._path.stat().st_mtime
        self._running = True
        self._task = asyncio.create_task(self._watch())

    async def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _watch(self) -> None:
        while self._running:
            await asyncio.sleep(self._interval)
            if not self._path.exists():
                continue
            try:
                mtime = self._path.stat().st_mtime
                if mtime > self._mtime:
                    self._mtime = mtime
                    import yaml
                    raw = self._path.read_text()
                    if self._path.suffix in (".yaml", ".yml"):
                        data = yaml.safe_load(raw)
                    elif self._path.suffix == ".json":
                        import json
                        data = json.loads(raw)
                    else:
                        continue
                    self._callback(data)
                    logger.info("Config reloaded from %s", self._path)
            except Exception as e:
                logger.warning("Config watch error: %s", e, exc_info=True)
