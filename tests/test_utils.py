from __future__ import annotations

import asyncio

import pytest

from mcpguard.utils import push_event


class TestPushEvent:
    @pytest.mark.asyncio
    async def test_push_success(self):
        q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=10)
        result = await push_event(q, b"test")
        assert result is True
        assert q.qsize() == 1

    @pytest.mark.asyncio
    async def test_push_timeout(self):
        q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1)
        await q.put(b"existing")
        result = await push_event(q, b"new", timeout=0.01)
        assert result is False

    @pytest.mark.asyncio
    async def test_push_full_queue(self):
        q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1)
        await q.put(b"existing")
        result = await push_event(q, b"new", timeout=0.01)
        assert result is False
