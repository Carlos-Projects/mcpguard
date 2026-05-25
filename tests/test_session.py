from __future__ import annotations

import asyncio
import time

import pytest

from mcpguard.proxy.session import Session, SessionManager
from mcpguard.transport.base import MCPTransport


class MockTransport(MCPTransport):
    async def connect(self) -> None:
        pass

    async def send_message(self, body: bytes) -> bytes:
        return b'{"result": "ok"}'

    async def event_stream(self):
        yield b'{"event": "test"}'
        await asyncio.sleep(0.1)

    async def close(self) -> None:
        pass


class TestSession:
    @pytest.mark.asyncio
    async def test_session_id_is_hex(self):
        t = MockTransport()
        s = Session(t)
        assert len(s.id) == 32
        int(s.id, 16)  # should not raise

    @pytest.mark.asyncio
    async def test_session_touch_updates_last_seen(self):
        t = MockTransport()
        s = Session(t)
        old = s.last_seen
        await asyncio.sleep(0.01)
        s.touch()
        assert s.last_seen > old

    @pytest.mark.asyncio
    async def test_session_age(self):
        t = MockTransport()
        s = Session(t)
        await asyncio.sleep(0.05)
        assert s.age > 0.04

    @pytest.mark.asyncio
    async def test_session_idle(self):
        t = MockTransport()
        s = Session(t)
        await asyncio.sleep(0.05)
        s.touch()
        assert s.idle < 0.01


class TestSessionManager:
    @pytest.mark.asyncio
    async def test_create_and_get(self):
        mgr = SessionManager()
        t = MockTransport()
        s = mgr.create(t)
        got = mgr.get(s.id)
        assert got is s

    @pytest.mark.asyncio
    async def test_get_nonexistent(self):
        mgr = SessionManager()
        assert mgr.get("nonexistent") is None

    @pytest.mark.asyncio
    async def test_remove(self):
        mgr = SessionManager()
        t = MockTransport()
        s = mgr.create(t)
        await mgr.remove(s.id)
        assert mgr.get(s.id) is None

    @pytest.mark.asyncio
    async def test_active_count(self):
        mgr = SessionManager()
        t1 = MockTransport()
        t2 = MockTransport()
        mgr.create(t1)
        mgr.create(t2)
        assert mgr.active_count == 2

    @pytest.mark.asyncio
    async def test_stats(self):
        mgr = SessionManager()
        t = MockTransport()
        mgr.create(t)
        stats = mgr.stats()
        assert stats["active_sessions"] == 1
        assert len(stats["sessions"]) == 1

    @pytest.mark.asyncio
    async def test_cleanup_removes_idle(self):
        mgr = SessionManager(cleanup_interval=1, max_idle=1)
        t = MockTransport()
        s = mgr.create(t)
        s.last_seen = time.time() - 10
        await mgr.start_cleanup()
        await asyncio.sleep(1.5)
        await mgr.stop_cleanup()
        assert mgr.get(s.id) is None

    @pytest.mark.asyncio
    async def test_close_all(self):
        mgr = SessionManager()
        mgr.create(MockTransport())
        mgr.create(MockTransport())
        await mgr.close_all()
        assert mgr.active_count == 0
