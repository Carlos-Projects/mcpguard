from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


class ConfigWatcher:
    def __init__(self, path: str | Path, callback: Callable[[dict[str, Any]], None], interval: float = 2.0) -> None:
        self._path = Path(path)
        self._callback = callback
        self._interval = interval
        self._mtime: float = 0
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self._path.exists():
            return
        self._mtime = self._path.stat().st_mtime
        self._running = True
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _watch(self) -> None:
        while self._running:
            time.sleep(self._interval)
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
            except Exception:
                pass
