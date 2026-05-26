from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from typing import Any

from mcpguard.transport.base import MCPTransport
from mcpguard.utils import push_event

logger = logging.getLogger("mcpguard")


class WebSocketTransport(MCPTransport):
    def __init__(self, target_url: str) -> None:
        parsed_target = target_url.replace("ws://", "http://").replace("wss://", "https://")
        self._target_url = parsed_target.rstrip("/")
        self._ws_url = target_url
        self._ws: Any = None
        self._event_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)
        self._pending: dict[Any, asyncio.Future[bytes]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._connected = False

    async def connect(self) -> None:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get(self._target_url, follow_redirects=False, timeout=5.0)
            if resp.status_code >= 400:
                raise ConnectionError(f"WebSocket target returned {resp.status_code}")
        self._connected = True

    async def accept_ws(self, ws: Any) -> None:
        await ws.accept()
        self._ws = ws
        self._reader_task = asyncio.create_task(self._read_ws())

    async def _read_ws(self) -> None:
        if self._ws is None:
            return
        try:
            while True:
                data = await self._ws.receive_text()
                raw = data.encode("utf-8")
                try:
                    msg = json.loads(data)
                except json.JSONDecodeError:
                    await push_event(self._event_queue, raw)
                    continue
                msg_id = msg.get("id")
                if msg_id is not None and msg_id in self._pending:
                    future = self._pending.pop(msg_id)
                    if not future.done():
                        future.set_result(raw)
                else:
                    await push_event(self._event_queue, raw)
        except Exception as e:
            logger.warning("WebSocket reader error: %s", e, exc_info=True)

    async def send_message(self, body: bytes) -> bytes:
        if self._ws is None:
            raise RuntimeError("WebSocket not connected")
        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            return await self._send_raw(body)
        msg_id = msg.get("id")
        if msg_id is None:
            return await self._send_raw(body)

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._pending[msg_id] = future

        await self._ws.send_text(body.decode("utf-8"))

        try:
            result = await asyncio.wait_for(future, timeout=30.0)
            return result
        except asyncio.TimeoutError:
            self._pending.pop(msg_id, None)
            raise TimeoutError(f"Timeout waiting for response to id={msg_id}")

    async def _send_raw(self, body: bytes) -> bytes:
        if self._ws is None:
            raise RuntimeError("WebSocket not connected")
        await self._ws.send_text(body.decode("utf-8"))
        data = await asyncio.wait_for(self._ws.receive_text(), timeout=30.0)
        return data.encode("utf-8")

    async def event_stream(self) -> AsyncGenerator[bytes, None]:
        while True:
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                yield event + b"\n"
            except asyncio.TimeoutError:
                if not self._connected:
                    break
                continue

    async def close(self) -> None:
        self._connected = False
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception) as e:
                logger.debug("WebSocket reader cancelled: %s", e)
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()
