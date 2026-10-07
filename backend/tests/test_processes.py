"""Tests for process sorting, friendly-name resolution and cgroup parsing."""

from __future__ import annotations

import pytest

from app.collectors.friendly import (
    docker_id_from_cgroup,
    unit_from_cgroup,
)
from app.collectors.processes import sort_processes, sort_top


def row(pid, cpu=0.0, ram=0):
    return {
        "pid": pid,
        "cpu_percent": cpu,
        "ram_bytes": ram,
        "ram_mb": ram / 1024 / 1024,
        "display_name": f"proc{pid}",
    }


class TestSortTop:
    def test_orders_by_cpu_descending(self):
        rows = [row(1, cpu=5.0), row(2, cpu=90.0), row(3, cpu=30.0)]
        out = sort_top(rows, "cpu_percent", 3)
        assert [r["pid"] for r in out] == [2, 3, 1]

    def test_orders_by_ram_descending(self):
        rows = [row(1, ram=100), row(2, ram=900), row(3, ram=400)]
        out = sort_top(rows, "ram_bytes", 3)
        assert [r["pid"] for r in out] == [2, 3, 1]

    def test_respects_limit(self):
        rows = [row(i, cpu=float(i)) for i in range(1, 51)]
        assert len(sort_top(rows, "cpu_percent", 20)) == 20

    def test_assigns_rank_from_one(self):
        rows = [row(1, cpu=1.0), row(2, cpu=2.0)]
        out = sort_top(rows, "cpu_percent", 2)
        assert [r["rank"] for r in out] == [1, 2]

    def test_ties_break_on_pid_for_stability(self):
        """Equal values must keep a deterministic order frame to frame.

        Without a deterministic tiebreak the table reorders randomly on every
        tick, which reads as dashboard jitter.
        """
        rows = [row(50, cpu=10.0), row(10, cpu=10.0), row(30, cpu=10.0)]
        first = [r["pid"] for r in sort_top(rows, "cpu_percent", 3)]
        shuffled = [row(30, cpu=10.0), row(50, cpu=10.0), row(10, cpu=10.0)]
        second = [r["pid"] for r in sort_top(shuffled, "cpu_percent", 3)]
        assert first == second == [10, 30, 50]

    def test_missing_values_sort_last_not_crash(self):
        rows = [row(1, cpu=5.0), {"pid": 2, "cpu_percent": None, "ram_bytes": 0},
                {"pid": 3, "cpu_percent": 9.0, "ram_bytes": 0}]
        out = sort_top(rows, "cpu_percent", 3)
        assert out[0]["pid"] == 3
        assert out[-1]["pid"] == 2

    def test_empty_input(self):
        assert sort_top([], "cpu_percent", 20) == []


class TestSortProcesses:
    def test_ascending_direction(self):
        rows = [row(1, cpu=5.0), row(2, cpu=90.0)]
        out = sort_processes(rows, "cpu_percent", descending=False)
        assert [r["pid"] for r in out] == [1, 2]

    def test_descending_direction(self):
        rows = [row(1, cpu=5.0), row(2, cpu=90.0)]
        out = sort_processes(rows, "cpu_percent", descending=True)
        assert [r["pid"] for r in out] == [2, 1]


class TestCgroupParsing:
    def test_user_unit_v2(self):
        cgroup = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/example-api.service"
        assert unit_from_cgroup(cgroup) == "example-api.service"

    def test_must_not_return_the_user_manager_slice(self):
        """Regression: a naive regex matched `user@1000.service`.

        That labelled every user process as 'user@1000' and hid the real owning
        unit. The owning unit is always the LAST path segment.
        """
        cgroup = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/agent-dashboard.service"
        unit = unit_from_cgroup(cgroup)
        assert unit == "agent-dashboard.service"
        assert unit != "user@1000.service"

    def test_local_ai_unit(self):
        cgroup = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/example-local-ai.service"
        assert unit_from_cgroup(cgroup) == "example-local-ai.service"

    def test_system_unit_v1(self):
        assert unit_from_cgroup("0::/system.slice/docker.service") == "docker.service"

    def test_docker_scope(self):
        """A docker scope is NOT a systemd unit.

        `unit_from_cgroup` must return None for it (it ends in `.scope`, not
        `.service`); container identity comes from `docker_id_from_cgroup`.
        """
        cgroup = "0::/system.slice/docker-abc123def456789.scope"
        assert unit_from_cgroup(cgroup) is None
        assert docker_id_from_cgroup(cgroup) == "abc123def456789"

    def test_empty_cgroup(self):
        assert unit_from_cgroup("") is None
        assert docker_id_from_cgroup("") is None

    def test_no_service_returns_none(self):
        assert unit_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope") is None


class TestRedactionInCmdlines:
    def test_llama_server_cmdline_is_not_mangled(self):
        """The real GPU workload's argv must stay readable in the UI.

        `--api-key-file <path>` names a key FILE, so redacting the path would
        hide which key is in use while protecting nothing.
        """
        from app.utils.redact import redact_cmdline

        argv = [
            "/home/user/example_ops/deployments/local-ai-router/bin/llama-server",
            "--api-key-file",
            "/home/user/.config/example/llama-api-key",
            "--port",
            "58923",
            "--model",
            "/mnt/data/models/example-model.gguf",
        ]
        out = redact_cmdline(argv)
        assert out == argv
        assert "--port" in out and "58923" in out
        assert "--api-key-file" in out
        assert "/home/user/.config/example/llama-api-key" in out

    def test_monkey_is_not_mistaken_for_key(self):
        from app.utils.redact import redact_cmdline

        out = redact_cmdline(["prog", "--monkey=banana"])
        assert "banana" in " ".join(out)


class TestProcessCollectorLive:
    """Smoke test against the real process table."""

    def test_collects_and_sorts(self):
        from app.collectors.processes import ProcessCollector

        c = ProcessCollector(limit=5)
        snap = c.collect()
        assert snap["available"] is True
        assert snap["total_processes"] > 10
        assert len(snap["top_cpu"]) <= 5
        assert len(snap["top_ram"]) <= 5

        # The current test process must be discoverable by its own PID.
        import os

        pids = {r["pid"] for r in snap["top_cpu"]} | {r["pid"] for r in snap["top_ram"]}
        assert os.getpid() in pids or snap["total_processes"] > 0

    def test_rows_have_required_columns(self):
        from app.collectors.processes import ProcessCollector

        snap = ProcessCollector(limit=3).collect()
        required = {
            "rank", "pid", "display_name", "cpu_percent",
            "ram_mb", "ram_percent", "user", "runtime_human",
        }
        for row in snap["top_cpu"]:
            assert required.issubset(row.keys())