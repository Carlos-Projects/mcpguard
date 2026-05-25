from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from typing import Any

from mcpguard.transport.base import MCPTransport


class StdioTransport(MCPTransport):
    def __init__(self, command: list[str], env: dict[str, str] | None = None) -> None:
        self._command = command
        self._env = env
        self._process: asyncio.subprocess.Process | None = None
        self._pending: dict[Any, asyncio.Future[bytes]] = {}
        self._event_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None

    async def connect(self) -> None:
        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._env,
        )
        self._reader_task = asyncio.create_task(self._read_stdout())
        self._stderr_task = asyncio.create_task(self._read_stderr())

    async def _read_stderr(self) -> None:
        if self._process is None or self._process.stderr is None:
            return
        try:
            while True:
                line = await self._process.stderr.readline()
                if not line:
                    break
        except Exception:
            pass

    async def _read_stdout(self) -> None:
        while self._process and self._process.stdout and not self._process.stdout.at_eof():
            line = await self._process.stdout.readline()
            if not line:
                break
            line = line.rstrip(b"\n\r")
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                await self._push_event(line)
                continue
            msg_id = msg.get("id")
            if msg_id is not None and msg_id in self._pending:
                future = self._pending.pop(msg_id)
                if not future.done():
                    future.set_result(line)
            else:
                await self._push_event(line)

    async def _push_event(self, data: bytes) -> None:
        try:
            await asyncio.wait_for(self._event_queue.put(data), timeout=1.0)
        except (asyncio.TimeoutError, asyncio.QueueFull):
            pass

    async def send_message(self, body: bytes) -> bytes:
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("Transport not connected")
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

        self._process.stdin.write(body + b"\n")
        await self._process.stdin.drain()

        try:
            result = await asyncio.wait_for(future, timeout=30.0)
            return result
        except asyncio.TimeoutError:
            self._pending.pop(msg_id, None)
            raise TimeoutError(f"Timeout waiting for response to id={msg_id}")

    async def _send_raw(self, body: bytes) -> bytes:
        if self._process is None or self._process.stdin is None or self._process.stdout is None:
            raise RuntimeError("Transport not connected")
        self._process.stdin.write(body + b"\n")
        await self._process.stdin.drain()
        line = await asyncio.wait_for(self._process.stdout.readline(), timeout=30.0)
        return line.rstrip(b"\n\r")

    async def event_stream(self) -> AsyncGenerator[bytes, None]:
        while True:
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                yield event + b"\n"
            except asyncio.TimeoutError:
                if self._process and self._process.returncode is not None:
                    break
                continue

    async def close(self) -> None:
        for task in (self._reader_task, self._stderr_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        if self._process:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()
