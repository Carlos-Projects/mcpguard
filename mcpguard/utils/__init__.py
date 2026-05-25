from __future__ import annotations

import asyncio


async def push_event(queue: asyncio.Queue[bytes], data: bytes, timeout: float = 1.0) -> bool:
    try:
        await asyncio.wait_for(queue.put(data), timeout=timeout)
        return True
    except (asyncio.TimeoutError, asyncio.QueueFull):
        return False
