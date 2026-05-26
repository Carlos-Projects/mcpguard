from __future__ import annotations

import pytest

from mcpguard.transport.websocket import WebSocketTransport


class TestWebSocketTransport:
    def test_url_normalization(self):
        t = WebSocketTransport("ws://localhost:8000/ws")
        assert t._target_url == "http://localhost:8000/ws"

    def test_wss_url_normalization(self):
        t = WebSocketTransport("wss://example.com/api")
        assert t._target_url == "https://example.com/api"

    def test_trailing_slash_removed(self):
        t = WebSocketTransport("ws://localhost:8000/api/")
        assert t._target_url == "http://localhost:8000/api"

    @pytest.mark.asyncio
    async def test_send_message_not_connected(self):
        t = WebSocketTransport("ws://localhost:8000")
        with pytest.raises(RuntimeError, match="not connected"):
            await t.send_message(b'{"id": 1}')

    @pytest.mark.asyncio
    async def test_close_without_connect(self):
        t = WebSocketTransport("ws://localhost:8000")
        await t.close()

    @pytest.mark.asyncio
    async def test_event_stream_empty(self):
        t = WebSocketTransport("ws://localhost:8000")
        t._connected = True
        t._event_queue.put_nowait(b'{"test": true}')
        async for event in t.event_stream():
            assert event == b'{"test": true}\n'
            break
        t._connected = False
        await t.close()
