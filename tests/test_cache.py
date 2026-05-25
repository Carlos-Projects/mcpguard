from __future__ import annotations

import time

from mcpguard.proxy.cache import ToolCache


class TestToolCache:
    def test_get_empty(self):
        c = ToolCache()
        assert c.get() is None

    def test_set_and_get(self):
        c = ToolCache()
        tools = [{"name": "test"}]
        c.set(tools)
        assert c.get() == tools

    def test_ttl_expiry(self):
        c = ToolCache(ttl=1)
        c.set([{"name": "test"}])
        time.sleep(1.1)
        assert c.get() is None

    def test_invalidate(self):
        c = ToolCache()
        c.set([{"name": "test"}])
        c.invalidate()
        assert c.get() is None

    def test_ttl_not_expired(self):
        c = ToolCache(ttl=60)
        c.set([{"name": "test"}])
        assert c.get() == [{"name": "test"}]
