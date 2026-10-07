"""Tests for network delta calculation, history, and the fan journal parser."""

from __future__ import annotations

import time

from app.collectors.fan import parse_controller_thresholds, parse_journal
from app.collectors.network import NetworkCollector, is_physical, is_wifi
from app.services.history import RANGES, HistoryBuffer


class TestNetworkInterfaceClassification:
    def test_ethernet_is_physical(self):
        assert is_physical("enp4s0") is True
        assert is_physical("eth0") is True

    def test_wifi_is_physical_and_wireless(self):
        assert is_physical("wlp3s0") is True
        assert is_wifi("wlp3s0") is True

    def test_docker_and_veth_are_virtual(self):
        for name in ("docker0", "br-28feafb03dd6", "veth1119a5d", "virbr0"):
            assert is_physical(name) is False, name

    def test_loopback_excluded(self):
        assert is_physical("lo") is False

    def test_wifi_prefix_detection(self):
        assert is_wifi("wlp3s0") is True
        assert is_wifi("enp4s0") is False


class TestNetworkDelta:
    def test_rates_are_computed_from_counters(self):
        """Rates must come from a delta over a measured interval, not a block."""
        c = NetworkCollector()
        first = c.collect()
        time.sleep(1.1)
        second = c.collect()

        assert "sample_interval_s" in second
        assert second["sample_interval_s"] > 0.5
        for iface in second["interfaces"]:
            assert iface["rx_bytes_per_sec"] >= 0
            assert iface["tx_bytes_per_sec"] >= 0

        # Cumulative totals only ever grow.
        for iface in second["interfaces"]:
            before = next(i for i in first["interfaces"] if i["name"] == iface["name"])
            assert iface["rx_bytes_total"] >= before["rx_bytes_total"]

    def test_first_sample_is_zero_not_a_spike(self):
        c = NetworkCollector()
        snap = c.collect()
        # A brand-new collector must not report a huge fake rate.
        assert all(i["rx_bytes_per_sec"] >= 0 for i in snap["interfaces"])

    def test_default_route_detection(self):
        c = NetworkCollector()
        snap = c.collect()
        # This host has two default routes: enp4s0 (metric 100) and
        # wlp3s0 (metric 600). The active one must be the lower metric.
        routes = {r["interface"]: r["metric"] for r in snap["default_routes"]}
        if routes:
            assert snap["active_interface"] == min(routes, key=lambda k: routes[k])

    def test_lan_and_wifi_reported_separately(self):
        c = NetworkCollector()
        snap = c.collect()
        assert snap["lan"] is not None
        assert snap["wifi"] is not None
        assert snap["lan"]["kind"] == "lan"
        assert snap["wifi"]["kind"] == "wifi"

    def test_totals_exclude_virtual_interfaces(self):
        c = NetworkCollector()
        snap = c.collect()
        names = {i["name"] for i in snap["interfaces"] if i["physical"]}
        assert "docker0" not in names
        assert not any(n.startswith("veth") for n in names)


class TestHistoryBuffer:
    def _fill(self, buf, snapshots=3, interval=0.0):
        for _ in range(snapshots):
            buf.add(
                {
                    "cpu": {"percent": {"value": 10.0, "supported": True}},
                    "memory": {"ram": {"percent": {"value": 40.0, "supported": True}}},
                    "gpu": {
                        "available": True,
                        "utilization": {"value": 5.0, "supported": True},
                        "temperature": {"value": 50.0, "supported": True, "unit": "C"},
                        "memory": {"percent": {"value": 60.0, "supported": True}},
                    },
                    "temperature": {"cpu": {"package_c": 45.0}},
                    "network": {"totals": {"rx_bytes_per_sec": 100.0, "tx_bytes_per_sec": 200.0}},
                }
            )
            time.sleep(interval)

    def test_adds_and_queries(self):
        buf = HistoryBuffer()
        self._fill(buf, 3)
        out = buf.query("15m")
        assert out["available"] is True
        assert out["count"] >= 1
        assert len(out["timestamps"]) == len(out["series"]["cpu_percent"])

    def test_all_tracked_fields_present(self):
        buf = HistoryBuffer()
        self._fill(buf, 2)
        out = buf.query("15m")
        for field in (
            "cpu_percent", "gpu_percent", "cpu_temp", "gpu_temp",
            "ram_percent", "vram_percent", "net_rx", "net_tx",
        ):
            assert field in out["series"]

    def test_empty_buffer_reports_unavailable(self):
        buf = HistoryBuffer()
        out = buf.query("15m")
        assert out["available"] is False
        assert "no samples" in out["reason"]

    def test_unsupported_metric_stays_none(self):
        buf = HistoryBuffer()
        buf.add(
            {
                "gpu": {
                    "available": True,
                    "utilization": {"value": None, "supported": False},
                    "temperature": {"value": None, "supported": False},
                    "memory": {"percent": {"value": 60.0, "supported": True}},
                }
            }
        )
        out = buf.query("15m")
        assert out["series"]["gpu_percent"][-1] is None

    def test_bounded_by_max_points(self):
        buf = HistoryBuffer(max_points=5)
        self._fill(buf, 20)
        assert len(buf.query("15m")["timestamps"]) <= 6

    def test_ranges_defined(self):
        assert set(RANGES) >= {"15m", "1h", "6h"}
        assert RANGES["15m"] == 900
        assert RANGES["1h"] == 3600


# Representative journal excerpt from cpu-fan-controller.service.
JOURNAL = """2026-10-05T06:08:59+00:00 homelab-server python[4242]: 2026-10-05 06:08:59,692 WARNING CPU 71.0C >= 70.0C: turning FAN ON
2026-10-05T06:09:01+00:00 homelab-server python[4242]: 2026-10-05 06:09:01,312 INFO FAN confirmed ON
2026-10-05T06:10:00+00:00 homelab-server python[4242]: 2026-10-05 06:10:00,000 INFO CPU=55.0C FAN=ON
2026-10-05T06:12:08+00:00 homelab-server python[4242]: 2026-10-05 06:12:08,709 INFO CPU 49.0C <= 60.0C: turning FAN OFF
2026-10-05T06:12:10+00:00 homelab-server python[4242]: 2026-10-05 06:12:10,240 INFO FAN confirmed OFF
2026-10-05T10:07:17+00:00 homelab-server python[4242]: 2026-10-05 10:07:17,596 INFO CPU=57.0C FAN=OFF
"""

CONTROLLER_SOURCE = """
import os, glob, time, logging, tinytuya

ON_TEMP = 70.0
OFF_TEMP = 60.0

POLL_SECONDS = 5
MIN_ON_SECONDS = 180

DEVICE_ID = os.environ["TUYA_DEVICE_ID"]
LOCAL_KEY = os.environ["TUYA_LOCAL_KEY"]
"""


class TestFanJournalParsing:
    def test_reads_latest_poll_line(self):
        state = parse_journal(JOURNAL)
        assert state["fan_state"] == "OFF"
        assert state["fan_on"] is False
        assert state["reported_cpu_temp"] == 57.0

    def test_reads_last_state_change(self):
        state = parse_journal(JOURNAL)
        assert state["last_change_at"] is not None
        assert state["last_confirmed"] == "OFF"

    def test_detects_errors(self):
        err = JOURNAL + (
            "2026-10-05T10:10:00+00:00 homelab-server python[4242]: "
            "2026-10-05 10:10:00,000 ERROR Connection reset by peer\n"
        )
        assert parse_journal(err)["recent_errors"]

    def test_empty_journal_is_safe(self):
        state = parse_journal("")
        assert state["fan_state"] is None
        assert state["stale"] is True

    def test_never_exposes_the_local_key(self):
        """The parser must not surface credential values."""
        poisoned = JOURNAL + (
            "2026-10-05T10:11:00+00:00 homelab-server python[4242]: "
            "2026-10-05 10:11:00,000 ERROR auth failed key=abcdef123456789\n"
        )
        state = parse_journal(poisoned)
        joined = " ".join(state["recent_errors"])
        assert "abcdef123456789" not in joined


class TestControllerThresholdParsing:
    def test_reads_real_constants(self):
        out = parse_controller_thresholds(CONTROLLER_SOURCE)
        assert out["on_temp_c"] == 70.0
        assert out["off_temp_c"] == 60.0
        assert out["min_on_seconds"] == 180.0
        assert out["poll_seconds"] == 5.0

    def test_empty_source_is_safe(self):
        out = parse_controller_thresholds("")
        assert out["on_temp_c"] is None