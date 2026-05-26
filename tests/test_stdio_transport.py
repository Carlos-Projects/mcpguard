from __future__ import annotations

import asyncio
import json
import sys

import pytest

from mcpguard.transport.stdio import StdioTransport


class TestStdioTransportValidation:
    @pytest.mark.asyncio
    async def test_empty_command_raises(self):
        t = StdioTransport(command=[])
        with pytest.raises(ValueError, match="No command configured"):
            await t.connect()

    @pytest.mark.asyncio
    async def test_nonexistent_command_raises(self):
        t = StdioTransport(command=["nonexistent_cmd_xyz_123"])
        with pytest.raises(FileNotFoundError, match="Command not found"):
            await t.connect()

    @pytest.mark.asyncio
    async def test_valid_command_connects(self):
        t = StdioTransport(command=["echo", "hello"])
        await t.connect()
        assert t._process is not None
        assert t._process.returncode is None
        await t.close()


class TestStdioTransportSend:
    @pytest.mark.asyncio
    async def test_send_message_not_connected(self):
        t = StdioTransport(command=["echo", "hello"])
        with pytest.raises(RuntimeError, match="not connected"):
            await t.send_message(b'{"id": 1}')

    @pytest.mark.asyncio
    async def test_send_raw_message(self):
        t = StdioTransport(command=["cat"])
        await t.connect()
        try:
            resp = await t.send_message(b"hello world")
            assert b"hello world" in resp
        finally:
            await t.close()

    @pytest.mark.asyncio
    async def test_send_json_message(self):
        t = StdioTransport(command=["cat"])
        await t.connect()
        try:
            msg = json.dumps({"id": 1, "method": "test"}).encode()
            resp = await asyncio.wait_for(t.send_message(msg), timeout=5.0)
            assert b'"id"' in resp
        finally:
            await t.close()

    @pytest.mark.asyncio
    async def test_send_message_without_id(self):
        t = StdioTransport(command=["cat"])
        await t.connect()
        try:
            msg = json.dumps({"method": "test"}).encode()
            resp = await asyncio.wait_for(t.send_message(msg), timeout=5.0)
            assert resp is not None
        finally:
            await t.close()


class TestStdioTransportStderr:
    @pytest.mark.asyncio
    async def test_stderr_captured(self):
        t = StdioTransport(
            command=[sys.executable, "-c", "import sys; sys.stderr.write('err\\n'); sys.stdout.write('{\"id\":1}\\n')"]
        )
        await t.connect()
        await asyncio.sleep(0.2)
        stderr = t.get_stderr()
        assert len(stderr) > 0
        assert "err" in stderr[0]
        await t.close()

    @pytest.mark.asyncio
    async def test_stderr_empty_initially(self):
        t = StdioTransport(command=["echo", "hello"])
        assert t.get_stderr() == []


class TestStdioTransportEventStream:
    @pytest.mark.asyncio
    async def test_event_stream_receives(self):
        t = StdioTransport(
            command=[
                sys.executable,
                "-c",
                'import time; print(\'{"jsonrpc":"2.0","method":"test"}\'); time.sleep(0.1); print(\'{"jsonrpc":"2.0","method":"test2"}\')',
            ]
        )
        await t.connect()
        events = []
        async for event in t.event_stream():
            events.append(event)
            if len(events) >= 2:
                break
        await t.close()
        assert len(events) == 2
        assert b'"method":"test"' in events[0] or b'"method":"test2"' in events[0]


class TestStdioTransportClose:
    @pytest.mark.asyncio
    async def test_close_terminates_process(self):
        t = StdioTransport(command=["sleep", "60"])
        await t.connect()
        await t.close()
        assert t._process.returncode is not None

    @pytest.mark.asyncio
    async def test_close_cleans_pending(self):
        t = StdioTransport(command=["echo", "hello"])
        await t.connect()
        loop = asyncio.get_running_loop()
        t._pending["test"] = loop.create_future()
        await t.close()
        assert t._pending == {}

    @pytest.mark.asyncio
    async def test_double_close_safe(self):
        t = StdioTransport(command=["echo", "hello"])
        await t.connect()
        await t.close()
        await t.close()
