from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger("mcpguard.mcpscop")


class MCPscopForwarder:
    def __init__(self, target_url: str = "", api_key: str = "") -> None:
        self.target_url = target_url.rstrip("/")
        self.api_key = api_key
        self._client: httpx.AsyncClient | None = None
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        self._worker_task: asyncio.Task | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.target_url)

    async def start(self) -> None:
        if not self.enabled:
            return
        self._client = httpx.AsyncClient(timeout=5.0)
        self._worker_task = asyncio.create_task(self._worker())
        logger.info("MCPscop forwarder started → %s", self.target_url)

    async def stop(self) -> None:
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.aclose()

    async def forward(self, event: dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("MCPscop queue full, dropping event")

    async def _worker(self) -> None:
        if not self._client:
            return
        while True:
            try:
                event = await self._queue.get()
                await self._send(event)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("MCPscop send error: %s", e)

    async def _send(self, event: dict[str, Any]) -> None:
        if not self._client:
            return
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        try:
            resp = await self._client.post(
                f"{self.target_url}/api/events",
                json=event,
                headers=headers,
            )
            if resp.status_code not in (200, 201):
                logger.debug("MCPscop responded %d: %s", resp.status_code, resp.text[:100])
        except httpx.RequestError as e:
            logger.debug("MCPscop unreachable: %s", e)


_forwarder: MCPscopForwarder | None = None
_lock = asyncio.Lock()


async def get_forwarder(
    target_url: str = "",
    api_key: str = "",
) -> MCPscopForwarder:
    global _forwarder
    if _forwarder is None:
        async with _lock:
            if _forwarder is None:
                fwd = MCPscopForwarder(target_url=target_url, api_key=api_key)
                await fwd.start()
                _forwarder = fwd
    return _forwarder


async def forward_event(event: dict[str, Any]) -> None:
    global _forwarder
    if _forwarder and _forwarder.enabled:
        await _forwarder.forward(event)


async def shutdown_forwarder() -> None:
    global _forwarder
    if _forwarder:
        await _forwarder.stop()
        _forwarder = None
