from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from mcpguard.main import SecurityEvent


class AnomalyDetector:
    def __init__(self) -> None:
        self._timeline: dict[str, list[float]] = defaultdict(list)
        self._total: int = 0
        self._start: float = time.time()

    def record(self, method: str) -> None:
        self._timeline[method].append(time.time())
        self._total += 1

    def check(self, method: str) -> SecurityEvent | None:
        now = time.time()
        uptime = now - self._start
        if uptime < 60:
            return None

        alerts: list[str] = []

        recent_total = sum(
            1 for ts_list in self._timeline.values() for ts in ts_list if ts > now - 60
        )
        if recent_total > 500:
            alerts.append(f"High volume: {recent_total} req/min")

        method_recent = [ts for ts in self._timeline.get(method, []) if ts > now - 60]
        if len(method_recent) > 50:
            alerts.append(f"Burst '{method}': {len(method_recent)} in 60s")

        all_recent = {
            m: sum(1 for ts in ts_list if ts > now - 60)
            for m, ts_list in self._timeline.items()
        }
        if all_recent:
            top_m = max(all_recent, key=all_recent.get)
            top_c = all_recent[top_m]
            total_recent = sum(all_recent.values())
            if total_recent > 10 and top_c / total_recent > 0.9:
                alerts.append(f"Dominant '{top_m}': {top_c}/{total_recent}")

        if alerts:
            return SecurityEvent(
                event_type="anomaly",
                severity="medium",
                message="; ".join(alerts),
                details={
                    "total": self._total,
                    "recent": recent_total,
                    "uptime": int(uptime),
                    "alerts": alerts,
                },
                blocked=False,
            )
        return None

    def stats(self) -> dict[str, Any]:
        now = time.time()
        recent = sum(
            1 for ts_list in self._timeline.values() for ts in ts_list if ts > now - 60
        )
        return {
            "total": self._total,
            "rpm": recent,
            "uptime": int(now - self._start),
            "methods": {m: len(ts) for m, ts in self._timeline.items()},
        }
