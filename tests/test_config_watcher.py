from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest
import yaml

from mcpguard.proxy.config_watcher import ConfigWatcher


class TestConfigWatcher:
    @pytest.mark.asyncio
    async def test_detects_yaml_change(self):
        callback_data = []

        def cb(data):
            callback_data.append(data)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"mode": "http"}, f)
            f.flush()
            path = Path(f.name)

        try:
            watcher = ConfigWatcher(path, cb, interval=0.2)
            watcher.start()
            await asyncio.sleep(0.3)

            yaml.dump({"mode": "stdio", "command": ["echo", "hi"]}, open(path, "w"))
            await asyncio.sleep(0.5)

            await watcher.stop()
            assert len(callback_data) >= 1
            assert callback_data[-1]["mode"] == "stdio"
        finally:
            path.unlink()

    @pytest.mark.asyncio
    async def test_detects_json_change(self):
        callback_data = []

        def cb(data):
            callback_data.append(data)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"mode": "http"}, f)
            f.flush()
            path = Path(f.name)

        try:
            watcher = ConfigWatcher(path, cb, interval=0.2)
            watcher.start()
            await asyncio.sleep(0.3)

            json.dump({"mode": "stdio"}, open(path, "w"))
            await asyncio.sleep(0.5)

            await watcher.stop()
            assert len(callback_data) >= 1
        finally:
            path.unlink()

    @pytest.mark.asyncio
    async def test_no_change_no_callback(self):
        callback_data = []

        def cb(data):
            callback_data.append(data)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"mode": "http"}, f)
            f.flush()
            path = Path(f.name)

        try:
            watcher = ConfigWatcher(path, cb, interval=0.2)
            watcher.start()
            await asyncio.sleep(0.6)
            await watcher.stop()
            assert len(callback_data) == 0
        finally:
            path.unlink()

    @pytest.mark.asyncio
    async def test_nonexistent_path(self):
        watcher = ConfigWatcher("/nonexistent/path.yaml", lambda d: None)
        watcher.start()
        assert watcher._task is None
