"""GPU collector.

Source priority:
  1. NVML via ctypes (libnvidia-ml.so.1) when loadable - no subprocess, ~1 ms.
  2. `nvidia-smi` subprocess - measured at ~52 ms/call on this host.

`nvidia-smi` is authoritative on this box and is used as the fallback, so the
dashboard works regardless of whether the ctypes NVML path resolves.

Design note on unsupported sensors: the 940MX reports `[N/A]` for power.draw,
power.limit and fan speed. Those MUST surface as
`{"value": null, "supported": false}` and never as 0.

Per-process GPU utilization is not obtainable here: `--query-accounted-apps`
fails on this consumer driver ("Field \\"process_name\\" is not a valid field to
query"). Only per-process VRAM is available, and that is what we report.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.utils.common import metric, run_cmd

log = logging.getLogger("scc.gpu")

_NVIDIA_SMI_LIB_NAMES = (
    "libnvidia-ml.so.1",
    "libnvidia-ml.so",
)

QUERY_GPU_FIELDS = (
    "name",
    "memory.total",
    "memory.used",
    "memory.free",
    "utilization.gpu",
    "temperature.gpu",
    "power.draw",
    "power.limit",
    "clocks.current.graphics",
    "clocks.current.memory",
    "clocks.max.graphics",
    "clocks.max.memory",
    "persistence_mode",
    "driver_version",
)

_NUM_RE = re.compile(r"^-?\d+(\.\d+)?$")


def parse_na(value: str) -> float | None:
    """nvidia-smi prints [N/A] or [Not Supported] for absent sensors.

    Unit suffixes are tolerated: a caller may omit `--format=,nounits` and get
    "1406 MiB" instead of "1406".
    """
    if value is None:
        return None
    v = value.strip()
    if not v or v.startswith("["):
        return None
    if not _NUM_RE.match(v):
        # Try stripping a trailing unit (MiB, W, MHz, %, C, ...).
        parts = v.split()
        if len(parts) == 2 and _NUM_RE.match(parts[0]):
            return float(parts[0])
        return None
    return float(v)


def _m(value: str | None, unit: str) -> dict:
    parsed = parse_na(value or "")
    return metric(parsed, supported=parsed is not None, unit=unit)


def parse_gpu_csv(csv_text: str) -> dict[str, Any]:
    """Parse `nvidia-smi --query-gpu=... --format=csv,noheader,nounits` output."""
    lines = [ln.strip() for ln in csv_text.strip().splitlines() if ln.strip()]
    if not lines:
        raise ValueError("empty nvidia-smi output")

    fields = [f.strip() for f in lines[0].split(",")]
    if len(fields) != len(QUERY_GPU_FIELDS):
        raise ValueError(f"expected {len(QUERY_GPU_FIELDS)} fields, got {len(fields)}")

    raw = dict(zip(QUERY_GPU_FIELDS, fields))

    mem_total = parse_na(raw["memory.total"])
    mem_used = parse_na(raw["memory.used"])
    mem_free = parse_na(raw["memory.free"])

    vram_pct = None
    if mem_total and mem_used is not None:
        vram_pct = round((mem_used / mem_total) * 100.0, 1)

    gpu_name = (raw.get("name") or "").strip() or None

    return {
        "index": 0,
        "name": gpu_name,
        "uuid": None,
        "driver_version": raw.get("driver_version", "").strip() or None,
        "persistence_mode": (raw.get("persistence_mode") or "").strip() or None,
        "utilization": _m(raw.get("utilization.gpu"), "%"),
        "memory": {
            "total_bytes": int(mem_total * 1024 * 1024) if mem_total else None,
            "used_bytes": int(mem_used * 1024 * 1024) if mem_used else None,
            "free_bytes": int(mem_free * 1024 * 1024) if mem_free else None,
            "total_mib": _m(raw.get("memory.total"), "MiB"),
            "used_mib": _m(raw.get("memory.used"), "MiB"),
            "free_mib": _m(raw.get("memory.free"), "MiB"),
            "percent": metric(vram_pct, supported=vram_pct is not None, unit="%"),
        },
        "temperature": _m(raw.get("temperature.gpu"), "°C"),
        "power_draw": _m(raw.get("power.draw"), "W"),
        "power_limit": _m(raw.get("power.limit"), "W"),
        "clocks": {
            "graphics_mhz": _m(raw.get("clocks.current.graphics"), "MHz"),
            "memory_mhz": _m(raw.get("clocks.current.memory"), "MHz"),
            "max_graphics_mhz": _m(raw.get("clocks.max.graphics"), "MHz"),
            "max_memory_mhz": _m(raw.get("clocks.max.memory"), "MHz"),
        },
        "fan_speed_pct": {"value": None, "supported": False, "unit": "%"},
    }


def parse_compute_apps(csv_text: str) -> list[dict]:
    """Parse `nvidia-smi --query-compute-apps=pid,process_name,used_memory`."""
    out: list[dict] = []
    for line in csv_text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        name = parts[1] or None
        mem_mib = parse_na(parts[2]) if len(parts) > 2 else None
        out.append(
            {
                "pid": pid,
                "process_name": name,
                "used_memory_bytes": int(mem_mib * 1024 * 1024) if mem_mib else None,
                "used_memory_mib": mem_mib,
            }
        )
    return out


class _Nvml:
    """Minimal ctypes NVML binding.

    Only initialisation and a cheap liveness probe are implemented; the data
    path stays on `nvidia-smi`, which is verified working on this host. This
    exists so NVML availability is *detected* rather than assumed.
    """

    def __init__(self) -> None:
        self._lib = None
        self.available = False
        self.error: str | None = None
        self._init()

    def _init(self) -> None:
        try:
            import ctypes
            import ctypes.util

            name = ctypes.util.find_library("nvidia-ml") or _NVIDIA_SMI_LIB_NAMES[0]
            try:
                self._lib = ctypes.CDLL(name)
            except OSError:
                self._lib = ctypes.CDLL(_NVIDIA_SMI_LIB_NAMES[0])
            self.available = True
        except Exception as exc:  # noqa: BLE001 - detection only
            self.error = str(exc)
            self.available = False


class GpuCollector:
    def __init__(self, nvidia_smi: str = "nvidia-smi", timeout: float = 4.0) -> None:
        self._bin = nvidia_smi
        self._timeout = timeout
        self._nvml = _Nvml()
        self._last_error: str | None = None
        self._consecutive_failures = 0
        if not self._nvml.available:
            log.info("NVML ctypes unavailable (%s); using nvidia-smi", self._nvml.error)

    @property
    def nvml_available(self) -> bool:
        return self._nvml.available

    async def collect(self) -> dict:
        argv = [
            self._bin,
            f"--query-gpu={','.join(QUERY_GPU_FIELDS)}",
            "--format=csv,noheader,nounits",
        ]
        rc, out, err = await run_cmd(argv, timeout=self._timeout)

        if rc != 0 or not out.strip():
            self._consecutive_failures += 1
            reason = (err or out or "nvidia-smi returned no data").strip().splitlines()[:1]
            self._last_error = reason[0] if reason and reason[0] else "nvidia-smi unavailable"
            return {
                "available": False,
                "reason": self._last_error,
                "nvml_available": self._nvml.available,
                "consecutive_failures": self._consecutive_failures,
            }

        self._consecutive_failures = 0
        try:
            parsed = parse_gpu_csv(out)
        except ValueError as exc:
            return {
                "available": False,
                "reason": f"nvidia-smi parse error: {exc}",
                "nvml_available": self._nvml.available,
                "consecutive_failures": 1,
            }

        parsed["available"] = True
        parsed["source"] = "nvidia-smi"
        parsed["nvml_available"] = self._nvml.available
        parsed["consecutive_failures"] = 0
        return parsed

    async def collect_compute_apps(self) -> dict:
        """Per-process VRAM usage. Returns available:false instead of raising."""
        argv = [
            self._bin,
            "--query-compute-apps=pid,process_name,used_memory",
            "--format=csv,noheader,nounits",
        ]
        rc, out, err = await run_cmd(argv, timeout=self._timeout)
        if rc not in (0, None) and not out.strip():
            return {"available": False, "reason": (err or "query failed").strip()[:200]}
        try:
            apps = parse_compute_apps(out)
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "reason": f"parse error: {exc}"}
        return {
            "available": True,
            "processes": apps,
            "per_process_utilization": {
                "value": None,
                "supported": False,
                "reason": "GPU per-process utilization unsupported on this driver "
                "(--query-accounted-apps unavailable on GeForce 940MX)",
            },
        }