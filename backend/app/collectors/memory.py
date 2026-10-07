"""Memory (RAM + swap) collector."""

from __future__ import annotations

import psutil

from app.utils.common import human_bytes, metric


def _pct(used: int, total: int) -> float:
    if not total:
        return 0.0
    return round((used / total) * 100.0, 1)


class MemoryCollector:
    def collect(self) -> dict:
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()

        # "Used" as Linux `free -h` reports it excludes buff/cache. psutil's
        # vm.used also excludes cache, so this matches `free -h` exactly and is
        # the number an operator will compare against.
        return {
            "available": True,
            "ram": {
                "total_bytes": vm.total,
                "used_bytes": vm.used,
                "available_bytes": vm.available,
                "free_bytes": vm.free,
                "buff_cache_bytes": getattr(vm, "buffers", 0) + psutil.virtual_memory().cached,
                "percent": metric(vm.percent, unit="%"),
                "human": {
                    "total": human_bytes(vm.total),
                    "used": human_bytes(vm.used),
                    "available": human_bytes(vm.available),
                    "free": human_bytes(vm.free),
                },
            },
            "swap": {
                "total_bytes": sm.total,
                "used_bytes": sm.used,
                "free_bytes": sm.free,
                "percent": metric(_pct(sm.used, sm.total), unit="%"),
                "human": {
                    "total": human_bytes(sm.total),
                    "used": human_bytes(sm.used),
                    "free": human_bytes(sm.free),
                },
            },
        }