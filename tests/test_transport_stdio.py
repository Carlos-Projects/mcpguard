from __future__ import annotations

import pytest

from mcpguard.transport.stdio import StdioTransport


class TestStdioTransport:
    def test_empty_command_validation(self):
        import asyncio

        t = StdioTransport(command=[])
        with pytest.raises(ValueError, match="No command configured"):
            asyncio.run(t.connect())

    def test_nonexistent_command(self):
        import asyncio

        t = StdioTransport(command=["nonexistent_command_xyz"])
        with pytest.raises(FileNotFoundError, match="Command not found"):
            asyncio.run(t.connect())

    @pytest.mark.asyncio
    async def test_valid_command_connects(self):
        t = StdioTransport(command=["echo", "hello"])
        await t.connect()
        assert t._process is not None
        await t.close()

    @pytest.mark.asyncio
    async def test_send_message_not_connected(self):
        t = StdioTransport(command=["echo", "hello"])
        with pytest.raises(RuntimeError, match="not connected"):
            await t.send_message(b'{"id": 1}')

    @pytest.mark.asyncio
    async def test_get_stderr_empty(self):
        t = StdioTransport(command=["echo", "hello"])
        assert t.get_stderr() == []
