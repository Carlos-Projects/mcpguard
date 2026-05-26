from __future__ import annotations

import pytest

from mcpguard.main import AppState, ProxyConfig, SecurityEvent
from mcpguard.proxy.mcpscop import MCPscopForwarder


@pytest.mark.asyncio
async def test_forwarder_enabled():
    fwd = MCPscopForwarder(target_url="http://localhost:9999")
    assert fwd.enabled is True
    await fwd.stop()


@pytest.mark.asyncio
async def test_forwarder_disabled():
    fwd = MCPscopForwarder()
    assert fwd.enabled is False
    await fwd.stop()


@pytest.mark.asyncio
async def test_forwarder_queue_and_drain():
    fwd = MCPscopForwarder(target_url="http://localhost:9999")
    await fwd.start()
    await fwd.forward({"event_type": "test", "severity": "high", "message": "test"})
    assert fwd._queue.qsize() == 1
    await fwd.stop()
    assert fwd._worker_task is None or fwd._worker_task.done()


def test_log_event_calls_forwarder():
    config = ProxyConfig(mcpscop_url="http://localhost:9999")
    state = AppState(config=config)
    event = SecurityEvent(
        event_type="prompt_injection",
        severity="high",
        message="Test",
        details={"tool": "test_tool"},
    )
    state.log_event(event)
    assert len(state.events) == 1
    assert state.events[0].event_type == "prompt_injection"


def test_log_event_no_mcpscop():
    config = ProxyConfig()
    state = AppState(config=config)
    event = SecurityEvent(
        event_type="prompt_injection",
        severity="high",
        message="Test",
        details={},
    )
    state.log_event(event)
    assert len(state.events) == 1
