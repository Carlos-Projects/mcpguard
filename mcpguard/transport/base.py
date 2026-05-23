from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator


class MCPTransport(ABC):
    @abstractmethod
    async def connect(self) -> None:
        ...

    @abstractmethod
    async def send_message(self, body: bytes) -> bytes:
        ...

    @abstractmethod
    async def event_stream(self) -> AsyncIterator[bytes]:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...
