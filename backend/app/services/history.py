"""In-memory rolling history.

Bounded ring buffers, no database. Retention is capped by
`settings.history_max_points` so memory can never grow without limit on a host
that only has ~1.8 GiB available.

At the default 10 s sample interval, 43200 points = 120 hours (5 days) of
retention for the 7 d selector's benefit while staying a few MiB of RAM.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from app.config import settings

# Fields tracked over time, per the spec.
TRACKED = (
    "cpu_percent",
    "gpu_percent",
    "cpu_temp",
    "gpu_temp",
    "ram_percent",
    "vram_percent",
    "net_rx",
    "net_tx",
)

# Range selector -> seconds covered.
RANGES: dict[str, int] = {
    "15m": 15 * 60,
    "1h": 60 * 60,
    "6h": 6 * 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
}


def _plain(metric: Any) -> float | None:
    if isinstance(metric, dict):
        return metric.get("value") if metric.get("supported") else None
    if isinstance(metric, (int, float)):
        return float(metric)
    return None


class HistoryBuffer:
    def __init__(self, max_points: int | None = None) -> None:
        cap = max_points or settings.history_max_points
        self._timestamps: deque[int] = deque(maxlen=cap)
        self._series: dict[str, deque] = {field: deque(maxlen=cap) for field in TRACKED}
        self._last_sample = 0.0
        self._boot = time.time()

    def maybe_sample(self, snapshot: dict) -> None:
        """Append a sample if the sample interval has elapsed."""
        now = time.monotonic()
        if now - self._last_sample < settings.history_sample_interval_s:
            return
        self._last_sample = now
        self.add(snapshot)

    def add(self, snapshot: dict) -> None:
        ts = int(time.time())
        values = {
            "cpu_percent": _plain((snapshot.get("cpu") or {}).get("percent")),
            "gpu_percent": _plain((snapshot.get("gpu") or {}).get("utilization")),
            "cpu_temp": (snapshot.get("temperature") or {}).get("cpu", {}).get("package_c"),
            "gpu_temp": _plain((snapshot.get("gpu") or {}).get("temperature")),
            "ram_percent": _plain(((snapshot.get("memory") or {}).get("ram") or {}).get("percent")),
            "vram_percent": _plain(((snapshot.get("gpu") or {}).get("memory") or {}).get("percent")),
            "net_rx": ((snapshot.get("network") or {}).get("totals") or {}).get("rx_bytes_per_sec"),
            "net_tx": ((snapshot.get("network") or {}).get("totals") or {}).get("tx_bytes_per_sec"),
        }

        self._timestamps.append(ts)
        for field in TRACKED:
            value = values.get(field)
            self._series[field].append(float(value) if value is not None else None)

    def query(self, range_key: str = "15m", max_points: int = 720) -> dict[str, Any]:
        """Return downsampled series for a range selector.

        Always returns the timestamp axis plus each tracked field, so a gap in
        an unsupported metric stays a null rather than being interpolated.
        """
        seconds = RANGES.get(range_key, RANGES["15m"])
        cutoff = int(time.time()) - seconds

        idx = [i for i, ts in enumerate(self._timestamps) if ts >= cutoff]
        if not idx:
            return {
                "range": range_key,
                "seconds": seconds,
                "available": False,
                "reason": "no samples in this range yet",
                "timestamps": [],
                "series": {field: [] for field in TRACKED},
                "sample_interval_s": settings.history_sample_interval_s,
            }

        stride = max(1, len(idx) // max_points)

        timestamps: list[int] = []
        series: dict[str, list] = {field: [] for field in TRACKED}

        for i in idx:
            timestamps.append(self._timestamps[i])
            for field in TRACKED:
                series[field].append(self._series[field][i])

        if stride > 1:
            timestamps = timestamps[::stride] + [timestamps[-1]]
            for field in TRACKED:
                sampled = series[field][::stride]
                if not sampled or sampled[-1] != series[field][-1]:
                    sampled.append(series[field][-1])
                series[field] = sampled

        return {
            "range": range_key,
            "seconds": seconds,
            "available": True,
            "count": len(timestamps),
            "timestamps": timestamps,
            "series": series,
            "sample_interval_s": settings.history_sample_interval_s,
            "retention_points": self._timestamps.maxlen,
        }

    def stats(self) -> dict[str, Any]:
        return {
            "points": len(self._timestamps),
            "max_points": self._timestamps.maxlen,
            "sample_interval_s": settings.history_sample_interval_s,
            "oldest": self._timestamps[0] if self._timestamps else None,
            "newest": self._timestamps[-1] if self._timestamps else None,
            "ranges": list(RANGES),
        }