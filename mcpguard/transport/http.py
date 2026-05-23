from __future__ import annotations

from collections.abc import AsyncGenerator

import httpx

from mcpguard.transport.base import MCPTransport


class HTTPTransport(MCPTransport):
    def __init__(
        self,
        target_url: str,
        sse_path: str = "/sse",
        messages_path: str = "/messages/",
    ) -> None:
        self._target_url = target_url.rstrip("/")
        self._sse_path = sse_path
        self._messages_path = messages_path
        self._client: httpx.AsyncClient | None = None
        self._sse_url = f"{self._target_url}{self._sse_path}"
        self._messages_url = f"{self._target_url}{self._messages_path}"

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)

    async def send_message(self, body: bytes) -> bytes:
        if self._client is None:
            raise RuntimeError("Transport not connected")
        resp = await self._client.post(
            self._messages_url,
            content=body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.content

    async def event_stream(self) -> AsyncGenerator[bytes, None]:
        if self._client is None:
            raise RuntimeError("Transport not connected")
        async with self._client.stream("GET", self._sse_url) as resp:
            async for line in resp.aiter_lines():
                yield (line + "\n").encode()

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
