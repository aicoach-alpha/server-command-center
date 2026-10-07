"""Tests for the systemctl output parser.

Regression guard: `systemctl show <multi-units>` does NOT guarantee property
order. In this fixture `Id=` appears near the END of each block, after
MainPID/NRestarts. An earlier implementation split on `Id=` and therefore
attributed unit N+1's leading properties to unit N, producing cross-assigned
PIDs (docker.service showing dockerd's pid under NetworkManager, etc).
"""

from __future__ import annotations

from app.collectors.services import (
    parse_show_blocks,
    parse_show_properties,
    parse_timestamp,
    status_color,
)

# Representative two-unit output from homelab-server.
MULTI = """MainPID=4242
NRestarts=0
ExecMainStartTimestamp=Fri 2026-10-02 10:49:54 UTC
MemoryCurrent=5005312
CPUUsageNSec=126557692000
Id=cpu-fan-controller.service
Description=CPU Temperature Tuya Fan Controller
LoadState=loaded
ActiveState=active
SubState=running
ActiveEnterTimestamp=Fri 2026-10-02 10:49:54 UTC

MainPID=622626
NRestarts=0
ExecMainStartTimestamp=2026-10-02 03:30:06 UTC
MemoryCurrent=83439616
CPUUsageNSec=8478736853000
Id=docker.service
Description=Docker Application Container Engine
LoadState=loaded
ActiveState=active
SubState=running
ActiveEnterTimestamp=2026-10-02 03:30:11 UTC
"""

SINGLE = """MainPID=4242
NRestarts=0
Id=cpu-fan-controller.service
LoadState=loaded
ActiveState=active
SubState=running
"""


class TestParseShowProperties:
    def test_single_unit(self):
        props = parse_show_properties(SINGLE)
        assert props["MainPID"] == "4242"
        assert props["Id"] == "cpu-fan-controller.service"
        assert props["ActiveState"] == "active"

    def test_empty(self):
        assert parse_show_properties("") == {}


class TestParseShowBlocks:
    def test_two_units_parsed_separately(self):
        blocks = parse_show_blocks(MULTI)
        assert len(blocks) == 2

        fan = blocks["cpu-fan-controller.service"]
        docker = blocks["docker.service"]

        # The critical assertion: PIDs must NOT be swapped between units.
        assert fan["MainPID"] == "4242"
        assert docker["MainPID"] == "622626"

        assert fan["Description"] == "CPU Temperature Tuya Fan Controller"
        assert docker["Description"] == "Docker Application Container Engine"

    def test_trailing_block_without_blank_line(self):
        blocks = parse_show_blocks(SINGLE)
        assert list(blocks) == ["cpu-fan-controller.service"]

    def test_single_block_no_trailing_newline(self):
        blocks = parse_show_blocks("Id=a.service\nActiveState=active")
        assert blocks["a.service"]["ActiveState"] == "active"

    def test_empty_output(self):
        assert parse_show_blocks("") == {}

    def test_block_without_id_is_skipped(self):
        assert parse_show_blocks("ActiveState=active\n") == {}


class TestParseTimestamp:
    def test_systemd_utc_format(self):
        ts = parse_timestamp("Fri 2026-10-02 10:49:54 UTC")
        assert ts is not None
        assert ts > 1_700_000_000

    def test_na_values(self):
        assert parse_timestamp(None) is None
        assert parse_timestamp("n/a") is None
        assert parse_timestamp("") is None

    def test_iso_format(self):
        assert parse_timestamp("2026-10-02 03:30:06") is not None


class TestStatusColor:
    def test_healthy_is_green(self):
        assert status_color("active", "running", "loaded") == "green"

    def test_active_but_degraded_is_amber(self):
        assert status_color("active", "degraded", "loaded") == "amber"

    def test_failed_is_red(self):
        assert status_color("failed", "failed", "loaded") == "red"

    def test_inactive_is_gray(self):
        assert status_color("inactive", "dead", "loaded") == "gray"

    def test_not_found_is_gray(self):
        assert status_color("inactive", "dead", "not-found") == "gray"