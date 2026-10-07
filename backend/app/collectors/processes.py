"""Process collectors: top-by-CPU, top-by-RAM, and GPU-process correlation.

CPU% comes from psutil's cached `cpu_percent(interval=None)`, which needs two
samples to produce a value. The collector keeps its own cache keyed by
(pid, create_time) so the fast tick always has a previous value to diff against,
and the first tick after a process appears reports 0.0 rather than blocking.

Sorting is stable: ties break on PID so rows do not shuffle between frames.
"""

from __future__ import annotations

import logging
import time

import psutil

from app.collectors.friendly import FriendlyResolver, read_cmdline
from app.utils.common import human_bytes, human_duration, metric

log = logging.getLogger("scc.processes")


class ProcessCollector:
    def __init__(self, limit: int = 20) -> None:
        self.limit = limit
        self._resolver = FriendlyResolver()
        self._cpu_cache: dict[tuple[int, float], psutil.Process] = {}
        self._last_sweep = 0.0

    # -- resolver bridge ---------------------------------------------------
    def update_containers(self, names: dict[str, str]) -> None:
        self._resolver.update_containers(names)

    # -- snapshot ----------------------------------------------------------
    def collect(self, extended: bool = False) -> dict:
        """Build a process snapshot without resolving every process eagerly.

        The expensive friendly-name/cgroup/cmdline work is performed only for
        rows that can actually appear in the top CPU/RAM tables (or for every
        row when ``extended=True``). This keeps the fast collector cheap even
        on hosts with hundreds of processes.
        """
        now = time.time()
        rows: list[dict] = []
        proc_map: dict[int, psutil.Process] = {}
        vmem_total = psutil.virtual_memory().total or 1

        for proc in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                pid = proc.info["pid"]
                created = proc.info.get("create_time") or 0.0
                key = (pid, created)

                cached = self._cpu_cache.get(key)
                active_proc = cached if cached is not None else proc
                if cached is not None:
                    try:
                        running = cached.is_running()
                    except psutil.Error:
                        running = False
                    if not running:
                        active_proc = proc
                        self._cpu_cache[key] = proc
                else:
                    self._cpu_cache[key] = proc

                try:
                    if active_proc is proc and cached is None:
                        active_proc.cpu_percent(interval=None)
                        cpu_pct = 0.0
                    else:
                        cpu_pct = active_proc.cpu_percent(interval=None)
                    rss = active_proc.memory_info().rss
                except (psutil.Error, OSError):
                    continue

                name = proc.info.get("name") or f"pid-{pid}"
                rows.append(
                    {
                        "pid": pid,
                        "name": name,
                        "display_name": name,
                        "source": "process",
                        "service": None,
                        "container": None,
                        "cmdline": [],
                        "cpu_percent": round(cpu_pct, 1),
                        "ram_bytes": rss,
                        "ram_mb": round(rss / (1024 * 1024), 1),
                        "ram_percent": round((rss / vmem_total) * 100.0, 1),
                        "user": "-",
                        "runtime_seconds": round(max(0.0, now - created), 0) if created else None,
                        "runtime_human": human_duration(now - created) if created else None,
                    }
                )
                proc_map[pid] = active_proc
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as exc:  # noqa: BLE001
                log.debug("process row failed for a pid: %s", exc)
                continue

        # Resolve only rows that can be rendered. Friendly resolution is the
        # dominant process-collector cost because it inspects cmdline/cgroups.
        if extended:
            resolve_pids = {r["pid"] for r in rows}
        else:
            cpu_candidates = sorted(rows, key=lambda r: (-float(r.get("cpu_percent") or 0.0), r["pid"]))[: self.limit]
            ram_candidates = sorted(rows, key=lambda r: (-float(r.get("ram_bytes") or 0.0), r["pid"]))[: self.limit]
            resolve_pids = {r["pid"] for r in cpu_candidates + ram_candidates}

        by_pid = {r["pid"]: r for r in rows}
        for pid in resolve_pids:
            row = by_pid.get(pid)
            proc_obj = proc_map.get(pid)
            if row is None or proc_obj is None:
                continue
            try:
                argv = read_cmdline(pid)
                friendly = self._resolver.resolve(proc_obj, argv=argv)
                row.update(
                    {
                        "name": friendly.get("process_name") or row["name"],
                        "display_name": friendly.get("display_name") or row["name"],
                        "source": friendly.get("source") or "process",
                        "service": friendly.get("service"),
                        "container": friendly.get("container"),
                        "cmdline": friendly.get("cmdline", []),
                    }
                )
                try:
                    row["user"] = proc_obj.username() or "-"
                except (psutil.Error, OSError):
                    pass
            except (psutil.Error, OSError):
                continue
            except Exception as exc:  # noqa: BLE001
                log.debug("friendly resolution failed for pid %s: %s", pid, exc)

        if now - self._last_sweep > 30:
            live = {r["pid"] for r in rows}
            self._cpu_cache = {k: v for k, v in self._cpu_cache.items() if k[0] in live}
            self._last_sweep = now

        top_cpu = sort_top(rows, "cpu_percent", self.limit)
        top_ram = sort_top(rows, "ram_bytes", self.limit)

        return {
            "available": True,
            "collected_at": now,
            "total_processes": len(rows),
            "top_cpu": top_cpu,
            "top_ram": top_ram,
            "all": rows if extended else None,
        }


def sort_top(rows: list[dict], key: str, limit: int) -> list[dict]:
    """Stable top-N sort.

    Descending by value, ties broken by ascending PID so equal rows keep a fixed
    order frame to frame. This is what stops the tables from jittering.
    """
    ordered = sorted(rows, key=lambda r: (-float(r.get(key) or 0.0), r["pid"]))
    out: list[dict] = []
    for idx, row in enumerate(ordered[:limit], start=1):
        item = dict(row)
        item["rank"] = idx
        out.append(item)
    return out


def sort_processes(rows: list[dict], key: str, descending: bool = True) -> list[dict]:
    """Public helper for API-driven sorting with a stable tiebreak."""
    ordered = sorted(
        rows,
        key=lambda r: (
            -(float(r.get(key) or 0.0)) if descending else (float(r.get(key) or 0.0)),
            r["pid"],
        ),
    )
    out = []
    for idx, row in enumerate(ordered, start=1):
        item = dict(row)
        item["rank"] = idx
        out.append(item)
    return out


class GpuProcessCorrelator:
    """Correlates NVML/nvidia-smi GPU PIDs with psutil process detail.

    Chain:
        nvidia-smi GPU pid -> /proc/<pid> -> psutil -> cgroup -> friendly name
    """

    def __init__(self, limit: int = 20) -> None:
        self.limit = limit

    def correlate(self, apps_payload: dict) -> dict:
        if not apps_payload.get("available"):
            return {
                "available": False,
                "reason": apps_payload.get("reason", "GPU process list unavailable"),
                "processes": [],
            }

        rows: list[dict] = []
        missing: list[int] = []
        resolver = FriendlyResolver()

        for entry in apps_payload.get("processes", []):
            pid = entry.get("pid")
            if pid is None:
                continue
            try:
                proc = psutil.Process(pid)
                argv = proc.cmdline()
            except psutil.NoSuchProcess:
                # Process exited between the nvidia-smi call and now.
                missing.append(pid)
                continue
            except (psutil.AccessDenied, psutil.Error):
                missing.append(pid)
                continue

            friendly = resolver.resolve(proc, argv=argv)
            try:
                with proc.oneshot():
                    rss = proc.memory_info().rss
                    cpu_pct = proc.cpu_percent(interval=None)
                    username = proc.username()
                    created = proc.create_time()
            except (psutil.Error, OSError):
                rss, cpu_pct, username, created = 0, 0.0, "-", time.time()

            vram_bytes = entry.get("used_memory_bytes")
            rows.append(
                {
                    "pid": pid,
                    "name": friendly.get("process_name") or entry.get("process_name"),
                    "display_name": friendly["display_name"],
                    "source": friendly["source"],
                    "service": friendly.get("service"),
                    "container": friendly.get("container"),
                    "cmdline": friendly.get("cmdline", []),
                    "gpu_utilization": metric(None, supported=False, unit="%"),
                    "vram_bytes": vram_bytes,
                    "vram_mb": round(vram_bytes / (1024 * 1024), 1) if vram_bytes else None,
                    "vram_human": human_bytes(vram_bytes) if vram_bytes else None,
                    "cpu_percent": round(cpu_pct, 1),
                    "ram_bytes": rss,
                    "ram_mb": round(rss / (1024 * 1024), 1),
                    "user": username,
                    "runtime_seconds": round(max(0.0, time.time() - created), 0),
                    "runtime_human": human_duration(time.time() - created),
                }
            )

        rows.sort(key=lambda r: (-(r.get("vram_bytes") or 0), r["pid"]))
        for idx, row in enumerate(rows, start=1):
            row["rank"] = idx

        return {
            "available": True,
            "processes": rows[: self.limit],
            "total": len(rows),
            "stale_pids": missing,
            "per_process_utilization": apps_payload.get("per_process_utilization"),
        }