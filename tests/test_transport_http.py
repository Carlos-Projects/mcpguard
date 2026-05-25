from __future__ import annotations

import pytest

from mcpguard.transport.http import HTTPTransport


class TestHTTPTransport:
    def test_valid_url(self):
        t = HTTPTransport("http://localhost:8000")
        assert t._target_url == "http://localhost:8000"

    def test_https_url(self):
        t = HTTPTransport("https://example.com/api")
        assert t._target_url == "https://example.com/api"

    def test_invalid_url_scheme(self):
        with pytest.raises(ValueError, match="must start with http://"):
            HTTPTransport("ws://localhost:8000")

    def test_custom_paths(self):
        t = HTTPTransport("http://localhost:8000", sse_path="/events", messages_path="/msg/")
        assert t._sse_url == "http://localhost:8000/events"
        assert t._messages_url == "http://localhost:8000/msg/"

    def test_custom_timeout(self):
        t = HTTPTransport("http://localhost:8000", timeout=60.0)
        assert t._timeout == 60.0

    @pytest.mark.asyncio
    async def test_connect_and_close(self):
        t = HTTPTransport("http://localhost:8000")
        await t.connect()
        assert t._client is not None
        await t.close()
        assert t._client is not None  # client object exists but is closed

    @pytest.mark.asyncio
    async def test_send_message_not_connected(self):
        t = HTTPTransport("http://localhost:8000")
        with pytest.raises(RuntimeError, match="not connected"):
            await t.send_message(b'{"id": 1}')

    @pytest.mark.asyncio
    async def test_event_stream_not_connected(self):
        t = HTTPTransport("http://localhost:8000")
        with pytest.raises(RuntimeError, match="not connected"):
            async for _ in t.event_stream():
                pass
