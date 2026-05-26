from __future__ import annotations

import pytest

from mcpguard.proxy.circuit_breaker import CircuitBreaker


class TestCircuitBreaker:
    def test_initial_state_closed(self):
        cb = CircuitBreaker()
        assert cb.state == "closed"

    @pytest.mark.asyncio
    async def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)

        async def failing():
            raise ConnectionError("fail")

        for _ in range(3):
            with pytest.raises(ConnectionError):
                await cb.call(failing)

        assert cb.state == "open"

    @pytest.mark.asyncio
    async def test_raises_when_open(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=10.0)

        async def failing():
            raise ConnectionError("fail")

        with pytest.raises(ConnectionError):
            await cb.call(failing)

        assert cb.state == "open"

        with pytest.raises(RuntimeError, match="Circuit breaker is open"):
            await cb.call(failing)

    @pytest.mark.asyncio
    async def test_half_open_after_recovery(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)

        async def failing():
            raise ConnectionError("fail")

        with pytest.raises(ConnectionError):
            await cb.call(failing)

        assert cb.state == "open"

        import time
        time.sleep(0.15)

        assert cb.state == "half-open"

    @pytest.mark.asyncio
    async def test_closes_on_success_in_half_open(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)

        async def failing():
            raise ConnectionError("fail")

        async def success():
            return "ok"

        with pytest.raises(ConnectionError):
            await cb.call(failing)

        import time
        time.sleep(0.15)

        assert cb.state == "half-open"

        result = await cb.call(success)
        assert result == "ok"
        assert cb.state == "closed"

    @pytest.mark.asyncio
    async def test_success_resets_failures(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)

        async def failing():
            raise ConnectionError("fail")

        async def success():
            return "ok"

        with pytest.raises(ConnectionError):
            await cb.call(failing)
        with pytest.raises(ConnectionError):
            await cb.call(failing)
        assert cb._failures == 2

        result = await cb.call(success)
        assert result == "ok"
        assert cb._failures == 2

    @pytest.mark.asyncio
    async def test_success_resets_failures_in_half_open(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)

        async def failing():
            raise ConnectionError("fail")

        async def success():
            return "ok"

        with pytest.raises(ConnectionError):
            await cb.call(failing)
        assert cb.state == "open"

        import time
        time.sleep(0.15)
        assert cb.state == "half-open"

        result = await cb.call(success)
        assert result == "ok"
        assert cb._failures == 0
        assert cb.state == "closed"
