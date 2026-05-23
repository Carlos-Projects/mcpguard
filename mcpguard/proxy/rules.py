from __future__ import annotations

import time
from collections import defaultdict

from mcpguard.main import ProxyConfig, SecurityEvent


class RuleEngine:
    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self._rate_counts: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, method: str) -> bool:
        if not method:
            return True
        if self.config.denylisted_tools:
            for pattern in self.config.denylisted_tools:
                if pattern in method:
                    return False
        if self.config.allowlisted_tools:
            for pattern in self.config.allowlisted_tools:
                if pattern in method:
                    return True
            return False
        return True

    def check_rate(self, method: str) -> SecurityEvent | None:
        now = time.time()
        window_start = now - self.config.rate_window
        self._rate_counts[method] = [
            t for t in self._rate_counts[method] if t > window_start
        ]

        if len(self._rate_counts[method]) >= self.config.rate_limit:
            return SecurityEvent(
                event_type="rate_limit",
                severity="medium",
                message=f"Rate limit exceeded for {method}",
                details={
                    "method": method,
                    "count": len(self._rate_counts[method]),
                    "limit": self.config.rate_limit,
                    "window": self.config.rate_window,
                },
                blocked=True,
            )

        self._rate_counts[method].append(now)
        return None

    def get_rate_counts(self) -> dict[str, int]:
        now = time.time()
        window_start = now - self.config.rate_window
        return {
            method: len([t for t in ts if t > window_start])
            for method, ts in self._rate_counts.items()
        }
