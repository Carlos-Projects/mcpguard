from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

from mcpguard.transport.base import MCPTransport


class Session:
    def __init__(self, transport: MCPTransport) -> None:
        self.id: str = uuid.uuid4().hex[:12]
        self.transport = transport
        self.created_at: float = time.time()
        self.last_seen: float = time.time()
        self._event_task: asyncio.Task[None] | None = None
        self._event_queue: asyncio.Queue[bytes] = asyncio.Queue()

    async def push_event(self, data: bytes) -> None:
        await self._event_queue.put(data)

    async def get_event(self) -> bytes:
        return await self._event_queue.get()

    def touch(self) -> None:
        self.last_seen = time.time()

    @property
    def age(self) -> float:
        return time.time() - self.created_at

    @property
    def idle(self) -> float:
        return time.time() - self.last_seen

    async def start_event_loop(self) -> None:
        async def _run() -> None:
            try:
                async for event in self.transport.event_stream():
                    await self._event_queue.put(event)
            except Exception:
                pass

        self._event_task = asyncio.create_task(_run())

    async def close(self) -> None:
        if self._event_task and not self._event_task.done():
            self._event_task.cancel()
            try:
                await self._event_task
            except (asyncio.CancelledError, Exception):
                pass
        await self.transport.close()


class SessionManager:
    def __init__(self, cleanup_interval: int = 60, max_idle: int = 300) -> None:
        self._sessions: dict[str, Session] = {}
        self._cleanup_interval = cleanup_interval
        self._max_idle = max_idle
        self._cleanup_task: asyncio.Task[None] | None = None

    def create(self, transport: MCPTransport) -> Session:
        session = Session(transport)
        self._sessions[session.id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        session = self._sessions.get(session_id)
        if session:
            session.touch()
        return session

    async def remove(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session:
            await session.close()

    async def start_cleanup(self) -> None:
        async def _cleanup_loop() -> None:
            while True:
                await asyncio.sleep(self._cleanup_interval)
                now = time.time()
                stale = [
                    sid
                    for sid, s in self._sessions.items()
                    if now - s.last_seen > self._max_idle
                ]
                for sid in stale:
                    await self.remove(sid)

        self._cleanup_task = asyncio.create_task(_cleanup_loop())

    async def stop_cleanup(self) -> None:
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except (asyncio.CancelledError, Exception):
                pass

    async def close_all(self) -> None:
        for sid in list(self._sessions):
            await self.remove(sid)

    @property
    def active_count(self) -> int:
        return len(self._sessions)

    def stats(self) -> dict[str, Any]:
        return {
            "active_sessions": self.active_count,
            "sessions": [
                {
                    "id": s.id,
                    "age_seconds": int(s.age),
                    "idle_seconds": int(s.idle),
                }
                for s in self._sessions.values()
            ],
        }
