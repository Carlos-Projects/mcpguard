from __future__ import annotations

import time


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0) -> None:
        self._failures = 0
        self._threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._last_failure: float = 0
        self._state: str = "closed"

    @property
    def state(self) -> str:
        if self._state == "open" and time.time() - self._last_failure > self._recovery_timeout:
            self._state = "half-open"
        return self._state

    async def call(self, func, *args, **kwargs):
        if self.state == "open":
            raise RuntimeError("Circuit breaker is open")
        try:
            result = await func(*args, **kwargs)
            if self._state == "half-open":
                self._state = "closed"
                self._failures = 0
            return result
        except Exception:
            self._failures += 1
            self._last_failure = time.time()
            if self._failures >= self._threshold:
                self._state = "open"
            raise
