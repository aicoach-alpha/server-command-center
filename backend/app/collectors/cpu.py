"""CPU collector.

CPU% is obtained from `psutil.cpu_percent(interval=None)`, which compares two
reads of /proc/stat. It never blocks: the previous counter snapshot is kept
inside the collector and the returned value is the delta since the previous
call. The first call after process start returns 0.0 by definition, so the
collector primes itself at construction time when `cpu_prime` is set.
"""

from __future__ import annotations

import os
import time

import psutil

from app.utils.common import metric


class CpuCollector:
    def __init__(self, prime: bool = True) -> None:
        self._last_call = time.monotonic()
        # Prime so the very first real sample is meaningful.
        psutil.cpu_percent(interval=None, percpu=True)
        if prime:
            # Take one more read after a short pause so a non-zero value is
            # available immediately rather than on the second tick.
            time.sleep(0.12)
            psutil.cpu_percent(interval=None)
            self._last_call = time.monotonic()

    def collect(self) -> dict:
        total_pct = psutil.cpu_percent(interval=None)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        load1, load5, load15 = os.getloadavg()
        now = time.monotonic()
        elapsed = max(1e-6, now - self._last_call)
        self._last_call = now

        freq = self._collect_frequency()
        boot_time = psutil.boot_time()

        return {
            "percent": metric(total_pct, unit="%"),
            "per_core": [
                metric(p, unit="%") for p in per_core
            ],
            "cores_logical": psutil.cpu_count(logical=True) or 0,
            "cores_physical": psutil.cpu_count(logical=False) or 0,
            "load_average": {
                "1m": round(load1, 2),
                "5m": round(load5, 2),
                "15m": round(load15, 2),
                # Normalised load: how saturated the machine actually is.
                "1m_per_core": round(load1 / (psutil.cpu_count(logical=True) or 1), 2),
            },
            "frequency_mhz": freq,
            "sample_interval_s": round(elapsed, 3),
            "uptime_seconds": round(time.time() - boot_time, 0),
            "boot_time": boot_time,
        }

    @staticmethod
    def _collect_frequency() -> dict:
        """Current/average/min/max CPU frequency in MHz."""
        out: dict = {"current": metric(None, supported=False, unit="MHz")}
        try:
            f = psutil.cpu_freq(percpu=False)
        except (OSError, RuntimeError, NotImplementedError):
            return out
        if not f:
            return out

        out["current"] = metric(f.current, unit="MHz")
        if f.min is not None:
            out["min"] = metric(f.min, unit="MHz")
        if f.max is not None:
            out["max"] = metric(f.max, unit="MHz")
        return out