"""Transparent health engine.

Every rule is explicit and returns a human-readable reason string, so the UI
can always answer "why is it warning?". No rule fires on a metric whose value is
None - an unsupported sensor can never trigger a health alarm.
"""

from __future__ import annotations

from typing import Any

from app.config import Thresholds


def _status_rank(status: str) -> int:
    return {"healthy": 0, "warning": 1, "critical": 2}.get(status, 0)


def _worst(a: str, b: str) -> str:
    return a if _status_rank(a) >= _status_rank(b) else b


def _value(metric: Any) -> float | None:
    """Extract a numeric value from a {value, supported} envelope."""
    if metric is None:
        return None
    if isinstance(metric, dict):
        if not metric.get("supported"):
            return None
        return metric.get("value")
    return float(metric)


class HealthEngine:
    def __init__(self, thresholds: Thresholds) -> None:
        self.t = thresholds

    def evaluate(self, snapshot: dict) -> dict[str, Any]:
        warnings: list[str] = []
        criticals: list[str] = []

        self._cpu(snapshot, warnings, criticals)
        self._gpu(snapshot, warnings, criticals)
        self._memory(snapshot, warnings, criticals)
        self._storage(snapshot, warnings, criticals)
        self._fan(snapshot, warnings, criticals)
        self._services(snapshot, warnings, criticals)

        if criticals:
            status = "critical"
        elif warnings:
            status = "warning"
        else:
            status = "healthy"

        reasons = criticals + warnings
        return {
            "status": status,
            "reasons": reasons,
            "warning_count": len(warnings),
            "critical_count": len(criticals),
            "thresholds": {
                "cpu_temp_warn_c": self.t.cpu_temp_warn_c,
                "cpu_temp_crit_c": self.t.cpu_temp_crit_c,
                "gpu_temp_warn_c": self.t.gpu_temp_warn_c,
                "gpu_temp_crit_c": self.t.gpu_temp_crit_c,
                "ram_warn_pct": self.t.ram_warn_pct,
                "vram_warn_pct": self.t.vram_warn_pct,
                "disk_warn_pct": self.t.disk_warn_pct,
                "disk_crit_pct": self.t.disk_crit_pct,
            },
        }

    # -- individual rule groups -------------------------------------------
    def _cpu(self, snap: dict, warnings: list, criticals: list) -> None:
        temp = (snap.get("temperature") or {}).get("cpu", {}).get("package_c")
        if temp is not None:
            if temp >= self.t.cpu_temp_crit_c:
                criticals.append(f"CPU temperature critical: {temp}°C (>= {self.t.cpu_temp_crit_c}°C)")
            elif temp >= self.t.cpu_temp_warn_c:
                warnings.append(
                    f"CPU temperature elevated: {temp}°C (>= {self.t.cpu_temp_warn_c}°C)"
                )

        cpu = snap.get("cpu") or {}
        load_per_core = ((cpu.get("load_average") or {}).get("1m_per_core"))
        if load_per_core is not None and load_per_core >= self.t.cpu_load_warn_per_core:
            warnings.append(
                f"Load average high: {load_per_core} per-core (>= {self.t.cpu_load_warn_per_core})"
            )

    def _gpu(self, snap: dict, warnings: list, criticals: list) -> None:
        gpu = snap.get("gpu") or {}
        if not gpu.get("available", False):
            # A missing GPU is reported as degraded but not critical: the card
            # may legitimately be absent or the driver unloaded.
            warnings.append(f"GPU telemetry unavailable: {gpu.get('reason', 'unknown reason')}")
            return

        temp = _value(gpu.get("temperature"))
        if temp is not None:
            if temp >= self.t.gpu_temp_crit_c:
                criticals.append(f"GPU temperature critical: {temp}°C (>= {self.t.gpu_temp_crit_c}°C)")
            elif temp >= self.t.gpu_temp_warn_c:
                warnings.append(f"GPU temperature elevated: {temp}°C (>= {self.t.gpu_temp_warn_c}°C)")

        vram = _value((gpu.get("memory") or {}).get("percent"))
        if vram is not None:
            if vram >= self.t.vram_crit_pct:
                criticals.append(f"VRAM usage critical: {vram}% (>= {self.t.vram_crit_pct}%)")
            elif vram >= self.t.vram_warn_pct:
                warnings.append(f"VRAM usage above {self.t.vram_warn_pct}%: {vram}%")

    def _memory(self, snap: dict, warnings: list, criticals: list) -> None:
        mem = snap.get("memory") or {}
        ram = _value((mem.get("ram") or {}).get("percent"))
        if ram is not None:
            if ram >= self.t.ram_crit_pct:
                criticals.append(f"RAM usage critical: {ram}% (>= {self.t.ram_crit_pct}%)")
            elif ram >= self.t.ram_warn_pct:
                warnings.append(f"RAM usage above {self.t.ram_warn_pct}%: {ram}%")

        swap = _value((mem.get("swap") or {}).get("percent"))
        if swap is not None:
            if swap >= self.t.swap_crit_pct:
                criticals.append(f"Swap usage critical: {swap}% (>= {self.t.swap_crit_pct}%)")
            elif swap >= self.t.swap_warn_pct:
                warnings.append(f"Swap usage above {self.t.swap_warn_pct}%: {swap}%")

    def _storage(self, snap: dict, warnings: list, criticals: list) -> None:
        storage = snap.get("storage") or {}
        if not storage.get("available", False):
            return
        for disk in storage.get("disks", []):
            pct = disk.get("percent")
            if pct is None:
                continue
            mount = disk.get("mount", "?")
            if pct >= self.t.disk_crit_pct:
                criticals.append(f"Disk {mount} critically full: {pct}% (>= {self.t.disk_crit_pct}%)")
            elif pct >= self.t.disk_warn_pct:
                warnings.append(f"Disk {mount} above {self.t.disk_warn_pct}%: {pct}%")

        # Optional UUID-tracked external storage
        ext = snap.get("storage_external") or {}
        if not ext.get("available", False):
            return
        name = ext.get("name") or "External storage"
        mountpoint = ext.get("expected_mountpoint") or ext.get("mountpoint") or "/mnt/data"
        health = ext.get("health", "")
        if health == "DISCONNECTED":
            criticals.append(f"{name} disconnected")
        elif health == "WRONG_DEVICE":
            criticals.append(f"Unexpected filesystem mounted at {mountpoint}")
        elif health == "READ_ONLY":
            warnings.append(f"{name} filesystem is read-only")
        elif health == "IO_ERROR":
            criticals.append(f"{name} I/O error detected")
        elif health == "FILESYSTEM_ERROR":
            criticals.append(f"{name} filesystem error detected")
        elif health == "CONNECTED_UNMOUNTED":
            warnings.append(f"{name} present but {mountpoint} not mounted")

        pct = ext.get("percent_used")
        if pct is not None:
            if pct >= self.t.disk_crit_pct:
                criticals.append(f"{name} critically full: {pct}%")
            elif pct >= self.t.disk_warn_pct:
                warnings.append(f"{name} above {self.t.disk_warn_pct}%: {pct}%")

        recent_errors = ext.get("recent_errors", [])
        if isinstance(recent_errors, list) and recent_errors:
            for err in recent_errors:
                warnings.append(f"{name} recent error: {err}")

    def _fan(self, snap: dict, warnings: list, criticals: list) -> None:
        fan = snap.get("fan") or {}
        controller = fan.get("controller") or {}
        unit = controller.get("unit", "cpu-fan-controller.service")
        controller_active = bool(controller.get("active"))
        cpu_temp = (snap.get("temperature") or {}).get("cpu", {}).get("package_c")
        cpu_is_hot = cpu_temp is not None and cpu_temp >= self.t.cpu_temp_warn_c

        if not controller_active:
            # Cooling being down matters far more when the CPU is actually hot.
            # A dead controller on a cool machine is a warning; on a hot machine
            # it is critical.
            if cpu_is_hot:
                criticals.append(
                    f"Fan controller {unit} is not running while CPU is at {cpu_temp}°C"
                )
            elif controller.get("available") is False:
                criticals.append(f"Fan controller {unit} not observable")
            else:
                warnings.append(
                    f"Fan controller {unit} is {controller.get('status', 'not running')}"
                )
            return

        # Controller alive but reporting stale data == comms problem.
        fan_state = fan.get("fan") or {}
        if fan_state.get("data_stale") and fan_state.get("poll_age_seconds") is not None:
            warnings.append(
                f"Fan controller data stale: last poll {fan_state['poll_age_seconds']}s ago"
            )

        if cpu_temp is not None and cpu_temp >= self.t.cpu_temp_crit_c and fan_state.get("on") is False:
            criticals.append(
                f"CPU at {cpu_temp}°C but fan reports OFF - cooling may have failed"
            )

    def _services(self, snap: dict, warnings: list, criticals: list) -> None:
        services = snap.get("services") or {}
        if not services.get("available", False):
            warnings.append("Service telemetry unavailable")
            return

        for svc in services.get("services", []):
            if not svc.get("important") or svc.get("optional"):
                continue
            state = svc.get("active_state")
            if state == "active":
                continue
            if state == "failed":
                criticals.append(f"Critical service failed: {svc['display_name']} ({svc['unit']})")
            else:
                warnings.append(
                    f"Important service not running: {svc['display_name']} ({state})"
                )