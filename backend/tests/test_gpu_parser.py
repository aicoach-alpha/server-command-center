"""Tests for the nvidia-smi output parsers.

Fixtures represent output from a GeForce 940MX on homelab-server, including
the `[N/A]` sentinels the driver emits for sensors this card does not have.
"""

from __future__ import annotations

import pytest

from app.collectors.gpu import parse_compute_apps, parse_gpu_csv, parse_na


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("47", 47.0),
        (" 47 ", 47.0),
        ("135", 135.0),
        ("0.5", 0.5),
        ("-3", -3.0),
        ("[N/A]", None),
        ("[Not Supported]", None),
        ("", None),
        (None, None),
        ("n/a", None),
    ],
)
def test_parse_na(raw, expected):
    assert parse_na(raw) == expected


def test_parse_gpu_csv_real_940mx_output():
    """Representative `nvidia-smi --query-gpu` output."""
    raw = (
        "NVIDIA GeForce 940MX, 2048, 1409, 587, 0, 47, [N/A], [N/A], "
        "135, 405, 862, 2505, Disabled, 580.178.04"
    )
    gpu = parse_gpu_csv(raw)

    assert gpu["name"] == "NVIDIA GeForce 940MX"
    assert gpu["driver_version"] == "580.178.04"
    assert gpu["memory"]["total_bytes"] == 2048 * 1024 * 1024
    assert gpu["memory"]["used_bytes"] == 1409 * 1024 * 1024
    assert gpu["memory"]["free_bytes"] == 587 * 1024 * 1024

    # 1409/2048 = 68.8%
    assert gpu["memory"]["percent"]["value"] == pytest.approx(68.8, abs=0.1)
    assert gpu["memory"]["percent"]["supported"] is True

    assert gpu["utilization"] == {"value": 0.0, "supported": True, "unit": "%"}
    assert gpu["temperature"] == {"value": 47.0, "supported": True, "unit": "°C"}
    assert gpu["clocks"]["graphics_mhz"]["value"] == 135.0
    assert gpu["clocks"]["memory_mhz"]["value"] == 405.0


def test_unsupported_sensors_are_null_not_zero():
    """The 940MX has no power telemetry. It must NOT report 0 W."""
    raw = (
        "NVIDIA GeForce 940MX, 2048, 1409, 587, 0, 47, [N/A], [N/A], "
        "135, 405, 862, 2505, Disabled, 580.178.04"
    )
    gpu = parse_gpu_csv(raw)

    assert gpu["power_draw"] == {"value": None, "supported": False, "unit": "W"}
    assert gpu["power_limit"] == {"value": None, "supported": False, "unit": "W"}
    assert gpu["fan_speed_pct"] == {"value": None, "supported": False, "unit": "%"}

    # A supported-but-idle sensor is 0, which is different from unsupported.
    assert gpu["utilization"]["value"] == 0.0
    assert gpu["utilization"]["supported"] is True


def test_parse_gpu_csv_rejects_wrong_field_count():
    with pytest.raises(ValueError):
        parse_gpu_csv("NVIDIA GeForce 940MX, 2048, 1409")


def test_parse_gpu_csv_rejects_empty():
    with pytest.raises(ValueError):
        parse_gpu_csv("")


def test_parse_compute_apps_real_output():
    raw = (
        "584603, /home/user/example_ops/deployments/local-ai-router/bin/llama-server, 1406 MiB"
    )
    apps = parse_compute_apps(raw)

    assert len(apps) == 1
    assert apps[0]["pid"] == 584603
    assert apps[0]["process_name"].endswith("llama-server")
    assert apps[0]["used_memory_mib"] == 1406.0
    assert apps[0]["used_memory_bytes"] == 1406 * 1024 * 1024


def test_parse_compute_apps_multiple():
    raw = "123, /usr/bin/one, 100 MiB\n456, /usr/bin/two, 250 MiB"
    apps = parse_compute_apps(raw)
    assert [a["pid"] for a in apps] == [123, 456]
    assert apps[1]["used_memory_mib"] == 250.0


def test_parse_compute_apps_empty_when_no_gpu_workload():
    assert parse_compute_apps("") == []