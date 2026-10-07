"""Central sampling hub.

ONE collector loop samples the whole machine, regardless of how many browsers
are watching. WebSocket clients receive the already-computed snapshot; they
never trigger their own system sampling. This is the architecture the spec
requires and it is what keeps the dashboard cheap on a 2-core box.

Two cadences:
  fast (2 s)  : cpu, memory, network, temperature, gpu, processes, gpu processes
  slow (10 s) : services, storage, containers, fan

Slow sections persist between ticks, so the emitted payload always contains a
complete snapshot even though only part of it was just re-measured.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from app.collectors.containers import ContainerCollector
from app.collectors.cpu import CpuCollector
from app.collectors.fan import FanCollector
from app.collectors.gpu import GpuCollector
from app.collectors.memory import MemoryCollector
from app.collectors.network import NetworkCollector
from app.collectors.processes import GpuProcessCorrelator, ProcessCollector
from app.collectors.services import ServiceCollector
from app.collectors.storage import StorageCollector
from app.collectors.storage_external import StorageExternalCollector
from app.collectors.temperature import TemperatureCollector
from app.config import settings
from app.services.health import HealthEngine
from app.services.history import HistoryBuffer

log = logging.getLogger("scc.hub")


class CollectorHub:
    def __init__(self) -> None:
        self.cpu = CpuCollector(prime=settings.cpu_prime)
        self.memory = MemoryCollector()
        self.temperature = TemperatureCollector()
        self.network = NetworkCollector()
        self.gpu = GpuCollector(settings.nvidia_smi_bin, settings.nvidia_smi_timeout_s)
        self.processes = ProcessCollector(settings.process_limit)
        self.gpu_processes = GpuProcessCorrelator(settings.process_limit)
        self.storage = StorageCollector()
        self.storage_external = StorageExternalCollector()
        self.services = ServiceCollector()
        self.containers = ContainerCollector(settings.docker_bin)
        self.fan = FanCollector()
        self.health = HealthEngine(settings.thresholds)
        self.history = HistoryBuffer()

        self._snapshot: dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._subscribers: set[asyncio.Queue] = set()
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._last_slow = 0.0
        self._last_slow_ms: float | None = None
        self._last_process_collect = 0.0
        self._last_gpu_process_collect = 0.0
        self._boot_at = time.time()
        self._collect_errors: dict[str, str] = {}
        self._cycle_count = 0
        self._last_collect_ms: float | None = None

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        log.info(
            "collector hub starting: fast=%.1fs process=%.1fs gpu_process=%.1fs slow=%.1fs",
            settings.fast_interval_s,
            settings.process_interval_s,
            settings.gpu_process_interval_s,
            settings.slow_interval_s,
        )
        # Prime BOTH cadences before serving. Without the slow tick the first
        # snapshots would carry empty services/storage/containers sections,
        # which the health engine would misreport as a real outage.
        await self.collect_now()
        await self.collect_slow()
        self._tasks.append(asyncio.create_task(self._fast_loop(), name="scc-fast"))
        self._tasks.append(asyncio.create_task(self._slow_loop(), name="scc-slow"))

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: B014
                pass
        self._tasks.clear()

    async def _fast_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(settings.fast_interval_s)
                await self.collect_now()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - loop must never die
                log.error("fast collector loop error: %s", exc)

    async def _slow_loop(self) -> None:
        while self._running:
            try:
                # Stagger so the two loops never contend.
                await asyncio.sleep(settings.slow_interval_s)
                await self.collect_slow()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.error("slow collector loop error: %s", exc)

    # -- collection --------------------------------------------------------
    async def collect_now(self) -> dict[str, Any]:
        """Fast scalar tick with process-heavy work on independent cadences."""
        started = time.perf_counter()
        now_mono = time.monotonic()

        async def section(name: str, coro):
            try:
                return await coro
            except Exception as exc:  # noqa: BLE001
                log.warning("collector section %s failed: %s", name, exc)
                self._collect_errors[name] = str(exc)
                return None

        do_processes = (
            self._last_process_collect == 0.0
            or now_mono - self._last_process_collect >= settings.process_interval_s
        )
        do_gpu_processes = (
            self._last_gpu_process_collect == 0.0
            or now_mono - self._last_gpu_process_collect >= settings.gpu_process_interval_s
        )

        cpu_task = section("cpu", asyncio.to_thread(self.cpu.collect))
        mem_task = section("memory", asyncio.to_thread(self.memory.collect))
        temp_task = section("temperature", asyncio.to_thread(self.temperature.collect))
        net_task = section("network", asyncio.to_thread(self.network.collect))
        proc_task = (
            section("processes", asyncio.to_thread(self.processes.collect, False))
            if do_processes
            else asyncio.sleep(0, result=None)
        )
        gpu_task = section("gpu", self.gpu.collect())

        cpu, memory, temperature, network, processes, gpu = await asyncio.gather(
            cpu_task, mem_task, temp_task, net_task, proc_task, gpu_task
        )
        if do_processes:
            self._last_process_collect = now_mono

        gpu_apps = None
        if gpu and gpu.get("available") and do_gpu_processes:
            compute_apps = await self.gpu.collect_compute_apps()
            gpu_apps = await section(
                "gpu_processes",
                asyncio.to_thread(self.gpu_processes.correlate, compute_apps),
            )
            self._last_gpu_process_collect = now_mono

        async with self._lock:
            snap = self._snapshot
            if cpu:
                snap["cpu"] = cpu
            if memory:
                snap["memory"] = memory
            if temperature:
                snap["temperature"] = temperature
            if network:
                snap["network"] = network
            if processes:
                snap["processes"] = processes
            if gpu:
                snap["gpu"] = gpu
            if gpu_apps:
                snap["gpu_processes"] = gpu_apps

            snap.setdefault("services", {"available": False, "services": [], "counts": {}})
            snap.setdefault("storage", {"available": False, "disks": []})
            snap.setdefault("storage_external", {"available": False, "connected": False, "health": "DISCONNECTED"})
            snap.setdefault("containers", {"available": False, "containers": [], "count": 0})
            snap.setdefault("fan", {"available": False})
            snap.setdefault("processes", {"available": False, "top_cpu": [], "top_ram": [], "total_processes": 0})
            snap.setdefault("gpu_processes", {"available": False, "processes": [], "total": 0})

            self._evaluate(snap)
            self.history.maybe_sample(snap)
            self._stamp(snap)

            self._cycle_count += 1
            self._last_collect_ms = round((time.perf_counter() - started) * 1000, 1)

        return self._snapshot

    async def collect_slow(self) -> dict[str, Any]:
        """Slow tick: services, storage, containers."""
        started = time.perf_counter()

        async def section(name: str, coro):
            try:
                return await coro
            except Exception as exc:  # noqa: BLE001
                log.warning("collector section %s failed: %s", name, exc)
                self._collect_errors[name] = str(exc)
                return None

        async with self._lock:
            cpu_temp = ((self._snapshot.get("temperature") or {}).get("cpu") or {}).get("package_c")

        services, storage, storage_external, containers, fan = await asyncio.gather(
            section("services", self.services.collect()),
            section("storage", asyncio.to_thread(self.storage.collect)),
            section("storage_external", asyncio.to_thread(self.storage_external.collect)),
            section("containers", self.containers.collect()),
            section("fan", self._collect_fan(cpu_temp)),
        )

        async with self._lock:
            snap = self._snapshot
            if services is not None:
                snap["services"] = services
            if storage is not None:
                snap["storage"] = storage
            if storage_external is not None:
                snap["storage_external"] = storage_external
            if fan is not None:
                snap["fan"] = fan
            if containers is not None:
                snap["containers"] = containers
                names = {
                    cid[:12]: c["name"]
                    for c in containers.get("containers", [])
                    for cid in [c.get("id") or ""]
                    if cid
                }
                if names:
                    self.processes.update_containers(names)
            # Slow sections can materially change overall health (service down,
            # storage missing, fan controller unavailable), so refresh health
            # immediately instead of waiting for the next fast tick.
            self._evaluate(snap)
            self._stamp(snap)
            self._last_slow = time.time()
            self._last_slow_ms = round((time.perf_counter() - started) * 1000, 1)

        return self._snapshot

    async def _collect_fan(self, cpu_temp: float | None) -> dict:
        try:
            return await self.fan.collect(cpu_temp)
        except Exception as exc:  # noqa: BLE001 - Tuya/fan must never break the dashboard
            log.warning("fan collector failed: %s", exc)
            return {"available": False, "reason": str(exc)}

    def _evaluate(self, snap: dict) -> None:
        try:
            snap["health"] = self.health.evaluate(snap)
        except Exception as exc:  # noqa: BLE001
            log.warning("health evaluation failed: %s", exc)
            snap["health"] = {
                "status": "warning",
                "reasons": [f"health engine error: {exc}"],
                "warning_count": 1,
                "critical_count": 0,
            }

    def _stamp(self, snap: dict) -> None:
        health = snap.get("health") or {}
        snap["meta"] = {
            "host": _hostname(),
            "generated_at": time.time(),
            "generated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "uptime_seconds": round(time.time() - self._boot_at, 1),
            "health_status": health.get("status", "unknown"),
            "fast_interval_s": settings.fast_interval_s,
            "slow_interval_s": settings.slow_interval_s,
            "cycle": self._cycle_count,
            "collect_ms": self._last_collect_ms,
            "errors": dict(self._collect_errors),
            "gpu_source": (snap.get("gpu") or {}).get("source"),
            "nvml_available": (snap.get("gpu") or {}).get("nvml_available"),
        }

    # -- snapshot access ---------------------------------------------------
    def current(self) -> dict[str, Any]:
        return self._snapshot

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return self._snapshot

    def stats(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "cycles": self._cycle_count,
            "fast_interval_s": settings.fast_interval_s,
            "slow_interval_s": settings.slow_interval_s,
            "process_interval_s": settings.process_interval_s,
            "gpu_process_interval_s": settings.gpu_process_interval_s,
            "last_fast_collect_ms": self._last_collect_ms,
            "last_slow_collect_ms": getattr(self, "_last_slow_ms", None),
            "subscribers": len(self._subscribers),
            "history": self.history.stats(),
            "errors": dict(self._collect_errors),
        }

    # -- pub/sub -----------------------------------------------------------
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        self._subscribers.add(q)
        return q

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def broadcast(self) -> None:
        """Push the latest snapshot to every subscriber. Drops slow clients.

        Each client queue has maxsize=2 and we discard the oldest item when
        full, so a browser on a slow link can never back-pressure the collector.
        """
        if not self._subscribers:
            return
        async with self._lock:
            payload = self.slim_for_ws(self._snapshot)

        dead: list[asyncio.Queue] = []
        for q in list(self._subscribers):
            try:
                if q.full():
                    q.get_nowait()  # drop oldest
                q.put_nowait(payload)
            except (asyncio.QueueFull, asyncio.QueueEmpty):
                dead.append(q)
        for q in dead:
            self._subscribers.discard(q)

    # -- payload slimming ---------------------------------------------------
    @staticmethod
    def slim_for_ws(snap: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of the snapshot with unrendered fields stripped.

        The WebSocket payload is the hottest path (every 2s to every client),
        so we strip fields the frontend never renders. The REST API endpoints
        return the full snapshot for programmatic consumers.
        """
        slim = dict(snap)

        # Processes: keep only rendered fields
        processes = slim.get("processes")
        if processes and isinstance(processes, dict):
            slim["processes"] = {
                "available": processes.get("available", True),
                "collected_at": processes.get("collected_at"),
                "total_processes": processes.get("total_processes", 0),
                "top_cpu": [_slim_process_row(r) for r in (processes.get("top_cpu") or [])],
                "top_ram": [_slim_process_row(r) for r in (processes.get("top_ram") or [])],
                "all": None,
            }

        # GPU processes: keep only rendered fields
        gpu_procs = slim.get("gpu_processes")
        if gpu_procs and isinstance(gpu_procs, dict):
            slim["gpu_processes"] = {
                "available": gpu_procs.get("available", True),
                "processes": [_slim_gpu_process_row(r) for r in (gpu_procs.get("processes") or [])],
                "total": gpu_procs.get("total", 0),
                "stale_pids": gpu_procs.get("stale_pids", []),
                "per_process_utilization": gpu_procs.get("per_process_utilization"),
            }

        # Network: drop interfaces array and default_routes (not rendered)
        network = slim.get("network")
        if network and isinstance(network, dict):
            slim["network"] = {
                "active_interface": network.get("active_interface"),
                "active_link": network.get("active_link"),
                "lan": network.get("lan"),
                "wifi": network.get("wifi"),
                "totals": {
                    "rx_bytes_per_sec": (network.get("totals") or {}).get("rx_bytes_per_sec", 0),
                    "tx_bytes_per_sec": (network.get("totals") or {}).get("tx_bytes_per_sec", 0),
                },
            }

        # Services: keep only rendered fields
        services = slim.get("services")
        if services and isinstance(services, dict):
            slim["services"] = {
                "available": services.get("available", True),
                "services": [_slim_service_row(s) for s in (services.get("services") or [])],
                "counts": services.get("counts", {}),
            }

        # Containers: keep only rendered fields
        containers = slim.get("containers")
        if containers and isinstance(containers, dict):
            slim["containers"] = {
                "available": containers.get("available", True),
                "containers": [_slim_container_row(c) for c in (containers.get("containers") or [])],
                "count": containers.get("count", 0),
            }

        return slim


def _hostname() -> str:
    import socket

    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _slim_process_row(row: dict[str, Any]) -> dict[str, Any]:
    """Keep only fields rendered in the process table."""
    return {
        "pid": row.get("pid"),
        "name": row.get("name"),
        "display_name": row.get("display_name"),
        "cpu_percent": row.get("cpu_percent"),
        "ram_bytes": row.get("ram_bytes"),
        "ram_percent": row.get("ram_percent"),
        "runtime_human": row.get("runtime_human"),
        "rank": row.get("rank"),
    }


def _slim_gpu_process_row(row: dict[str, Any]) -> dict[str, Any]:
    """Keep only fields rendered in the GPU process table."""
    return {
        "pid": row.get("pid"),
        "name": row.get("name"),
        "display_name": row.get("display_name"),
        "vram_bytes": row.get("vram_bytes"),
        "cpu_percent": row.get("cpu_percent"),
        "ram_bytes": row.get("ram_bytes"),
        "rank": row.get("rank"),
    }


def _slim_service_row(svc: dict[str, Any]) -> dict[str, Any]:
    """Keep only fields rendered in the services panel."""
    return {
        "unit": svc.get("unit"),
        "display_name": svc.get("display_name"),
        "active_state": svc.get("active_state"),
        "sub_state": svc.get("sub_state"),
        "status": svc.get("status"),
        "important": svc.get("important"),
        "optional": svc.get("optional"),
    }


def _slim_container_row(c: dict[str, Any]) -> dict[str, Any]:
    """Keep only fields rendered in the containers panel."""
    return {
        "name": c.get("name"),
        "state": c.get("state"),
    }