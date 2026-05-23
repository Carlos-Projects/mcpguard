from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator


class MCPTransport(ABC):
    @abstractmethod
    async def connect(self) -> None:
        ...

    @abstractmethod
    async def send_message(self, body: bytes) -> bytes:
        ...

    @abstractmethod
    def event_stream(self) -> AsyncGenerator[bytes, None]:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...
