"""Tests for the health engine.

Two invariants matter most:
  1. An UNSUPPORTED metric (value None / supported False) must never raise a
     health alarm. The 940MX has no power sensor; its absence is not a problem.
  2. Every non-healthy status must carry an explicit human-readable reason.
"""

from __future__ import annotations

from app.config import Thresholds
from app.services.health import HealthEngine


def env(value, supported=True, unit="%"):
    return {"value": value, "supported": supported, "unit": unit}


def base_snapshot(**overrides):
    snap = {
        "cpu": {"percent": env(5.0), "load_average": {"1m_per_core": 0.1}},
        "memory": {"ram": {"percent": env(40.0)}, "swap": {"percent": env(10.0)}},
        "temperature": {"cpu": {"package_c": 45.0}},
        "gpu": {
            "available": True,
            "utilization": env(10.0),
            "temperature": env(50.0, unit="°C"),
            "memory": {"percent": env(30.0)},
        },
        "storage": {
            "available": True,
            "disks": [{"mount": "/", "percent": 50.0}, {"mount": "/mnt/data", "percent": 55.0}],
        },
        "fan": {
            "controller": {"available": True, "active": True, "unit": "cpu-fan-controller.service"},
            "fan": {"on": False, "data_stale": False, "poll_age_seconds": 2.0},
        },
        "services": {
            "available": True,
            "services": [
                {
                    "unit": "example-api.service",
                    "display_name": "Example PROD API",
                    "active_state": "active",
                    "important": True,
                    "optional": False,
                }
            ],
        },
    }
    snap.update(overrides)
    return snap


class TestHealthyPath:
    def test_all_normal_is_healthy(self):
        result = HealthEngine(Thresholds()).evaluate(base_snapshot())
        assert result["status"] == "healthy"
        assert result["reasons"] == []
        assert result["critical_count"] == 0
        assert result["warning_count"] == 0

    def test_thresholds_are_reported_for_transparency(self):
        result = HealthEngine(Thresholds()).evaluate(base_snapshot())
        assert "cpu_temp_warn_c" in result["thresholds"]
        assert "disk_warn_pct" in result["thresholds"]


class TestUnsupportedMetricsNeverAlarm:
    def test_unsupported_gpu_sensors_do_not_warn(self):
        snap = base_snapshot()
        snap["gpu"]["power_draw"] = env(None, supported=False, unit="W")
        snap["gpu"]["fan_speed_pct"] = env(None, supported=False, unit="%")
        snap["gpu"]["temperature"] = env(None, supported=False, unit="°C")

        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "healthy", result["reasons"]

    def test_none_values_do_not_warn(self):
        snap = base_snapshot()
        snap["cpu"]["percent"] = env(None, supported=False)
        snap["memory"]["ram"]["percent"] = env(None, supported=False)
        snap["gpu"]["memory"]["percent"] = env(None, supported=False)

        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "healthy", result["reasons"]

    def test_gpu_unavailable_is_a_warning_with_reason(self):
        snap = base_snapshot()
        snap["gpu"] = {"available": False, "reason": "nvidia-smi unavailable"}

        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "warning"
        assert any("GPU telemetry unavailable" in r for r in result["reasons"])


class TestWarnings:
    def test_cpu_temp_elevated(self):
        snap = base_snapshot()
        snap["temperature"]["cpu"]["package_c"] = 75.0
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "warning"
        assert any("CPU temperature elevated" in r for r in result["reasons"])

    def test_ram_above_85(self):
        snap = base_snapshot()
        snap["memory"]["ram"]["percent"] = env(91.0)
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert any("RAM usage above" in r for r in result["reasons"])

    def test_vram_above_90(self):
        snap = base_snapshot()
        snap["gpu"]["memory"]["percent"] = env(93.0)
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert any("VRAM usage above" in r for r in result["reasons"])

    def test_disk_above_85_names_the_mount(self):
        snap = base_snapshot()
        snap["storage"]["disks"] = [{"mount": "/", "percent": 91.0}]
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert any("Disk /" in r for r in result["reasons"])

    def test_important_service_down(self):
        snap = base_snapshot()
        snap["services"]["services"][0]["active_state"] = "inactive"
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "warning"
        assert any("Example PROD API" in r for r in result["reasons"])

    def test_optional_service_down_is_not_a_warning(self):
        """An optional development service may be inactive by design."""
        snap = base_snapshot()
        snap["services"]["services"] = [
            {
                "unit": "example-next-dev.service",
                "display_name": "Example DEV Web",
                "active_state": "inactive",
                "important": False,
                "optional": True,
            }
        ]
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "healthy", result["reasons"]


class TestCritical:
    def test_cpu_thermal_danger(self):
        snap = base_snapshot()
        snap["temperature"]["cpu"]["package_c"] = 95.0
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "critical"
        assert result["critical_count"] >= 1

    def test_gpu_thermal_danger(self):
        snap = base_snapshot()
        snap["gpu"]["temperature"] = env(85.0, unit="°C")
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "critical"

    def test_disk_critically_full(self):
        snap = base_snapshot()
        snap["storage"]["disks"] = [{"mount": "/", "percent": 97.0}]
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "critical"

    def test_fan_down_while_cpu_hot_is_critical(self):
        snap = base_snapshot()
        snap["temperature"]["cpu"]["package_c"] = 85.0
        snap["fan"]["controller"]["active"] = False
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "critical"
        assert any("Fan controller" in r for r in result["reasons"])

    def test_fan_down_while_cpu_cool_is_only_warning(self):
        snap = base_snapshot()
        snap["temperature"]["cpu"]["package_c"] = 45.0
        snap["fan"]["controller"]["active"] = False
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "warning"
        assert result["critical_count"] == 0

    def test_critical_service_failed(self):
        snap = base_snapshot()
        snap["services"]["services"][0]["active_state"] = "failed"
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "critical"

    def test_hot_cpu_with_fan_off_is_critical(self):
        snap = base_snapshot()
        snap["temperature"]["cpu"]["package_c"] = 92.0
        snap["fan"]["fan"]["on"] = False
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert result["status"] == "critical"
        assert any("cooling may have failed" in r for r in result["reasons"])


class TestResilience:
    def test_missing_sections_do_not_crash(self):
        result = HealthEngine(Thresholds()).evaluate({})
        assert result["status"] in {"healthy", "warning", "critical"}

    def test_every_reason_is_a_string(self):
        snap = base_snapshot()
        snap["temperature"]["cpu"]["package_c"] = 95.0
        snap["memory"]["ram"]["percent"] = env(99.0)
        result = HealthEngine(Thresholds()).evaluate(snap)
        assert all(isinstance(r, str) and r for r in result["reasons"])