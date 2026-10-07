"""Temperature collector.

Reads `/sys/class/hwmon` directly - no subprocess, no dependency on `lm-sensors`,
readable as an unprivileged user on this host.

The CPU package sensor selection deliberately mirrors the running
cpu-fan-controller: coretemp "Package id 0". Using the same node guarantees the
dashboard shows exactly the temperature the fan automation is acting on.
"""

from __future__ import annotations

import glob
import logging
import os

log = logging.getLogger("scc.temperature")

SYS_HWMON = "/sys/class/hwmon"
SYS_THERMAL = "/sys/class/thermal"


def _read_int(path: str) -> int | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _find_coretemp_package() -> str | None:
    """Locate coretemp 'Package id 0' input, same as cpu-fan-controller.py."""
    for hwmon in sorted(glob.glob(os.path.join(SYS_HWMON, "hwmon*"))):
        try:
            with open(os.path.join(hwmon, "name"), "r", encoding="utf-8") as fh:
                if fh.read().strip() != "coretemp":
                    continue
        except OSError:
            continue

        for label_file in sorted(glob.glob(os.path.join(hwmon, "temp*_label"))):
            try:
                with open(label_file, "r", encoding="utf-8") as fh:
                    label = fh.read().strip()
            except OSError:
                continue
            if label == "Package id 0":
                return label_file.replace("_label", "_input")

    # Fall back to the plain first temp input of any coretemp node.
    for hwmon in sorted(glob.glob(os.path.join(SYS_HWMON, "hwmon*"))):
        try:
            with open(os.path.join(hwmon, "name"), "r", encoding="utf-8") as fh:
                if fh.read().strip() == "coretemp":
                    candidate = os.path.join(hwmon, "temp1_input")
                    if os.path.exists(candidate):
                        return candidate
        except OSError:
            continue
    return None


class TemperatureCollector:
    def __init__(self) -> None:
        self._coretemp = _find_coretemp_package()
        if self._coretemp is None:
            log.warning("coretemp Package id 0 sensor not found; CPU temp unavailable")

    @property
    def sensor_path(self) -> str | None:
        return self._coretemp

    def collect(self) -> dict:
        cpu_temp = None
        if self._coretemp:
            raw = _read_int(self._coretemp)
            if raw is not None:
                cpu_temp = round(raw / 1000.0, 1)

        crit = None
        if self._coretemp:
            crit_raw = _read_int(self._coretemp.replace("_input", "_crit"))
            if crit_raw is not None:
                crit = round(crit_raw / 1000.0, 1)

        cores = self._collect_cores()
        zones = self._collect_thermal_zones()

        return {
            "available": cpu_temp is not None,
            "cpu": {
                "package_c": cpu_temp,
                "supported": cpu_temp is not None,
                "source": self._coretemp,
                "critical_c": crit,
                "cores": cores,
            },
            "other": zones,
        }

    @staticmethod
    def _collect_cores() -> list[dict]:
        out: list[dict] = []
        for label_file in sorted(glob.glob(os.path.join(SYS_HWMON, "hwmon*", "temp*_label"))):
            input_file = label_file.replace("_label", "_input")
            raw = _read_int(input_file)
            if raw is None:
                continue
            try:
                with open(label_file, "r", encoding="utf-8") as fh:
                    label = fh.read().strip()
            except OSError:
                label = os.path.basename(label_file)
            if label == "Package id 0":
                continue  # already reported as the CPU package value
            out.append({"label": label, "celsius": round(raw / 1000.0, 1), "source": input_file})
        return out

    @staticmethod
    def _collect_thermal_zones() -> list[dict]:
        out: list[dict] = []
        for zone in sorted(glob.glob(os.path.join(SYS_THERMAL, "thermal_zone*"))):
            ztype_path = os.path.join(zone, "type")
            temp_path = os.path.join(zone, "temp")
            raw = _read_int(temp_path)
            if raw is None:
                continue
            try:
                with open(ztype_path, "r", encoding="utf-8") as fh:
                    ztype = fh.read().strip()
            except OSError:
                ztype = os.path.basename(zone)
            # Kernel zones report millidegrees on x86.
            celsius = round(raw / 1000.0, 1) if abs(raw) > 1000 else round(raw / 100.0, 1)
            out.append({"type": ztype, "celsius": celsius, "source": temp_path})
        return out