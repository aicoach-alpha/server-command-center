"""Service + container collectors.

Services are read via `systemctl show` for both scopes:
  - system scope: configured system units (Docker and NetworkManager by default)
  - user scope (--user): configured per-user application units

Units installed in `~/.config/systemd/user/` belong to the user scope, not
the system scope. Querying only system units would miss these applications.

READ-ONLY: only `show`/`list-units` are used. No start/stop/restart is ever
invoked from this application.
"""

from __future__ import annotations

import logging
from typing import Any

from app.config import (
    IMPORTANT_SYSTEM_UNITS,
    IMPORTANT_USER_UNITS,
    OPTIONAL_USER_UNITS,
    SERVICE_LABELS,
    SERVICE_PORTS,
    SYSTEM_SERVICE_UNITS,
    USER_SERVICE_UNITS,
    settings,
)
from app.utils.common import human_duration, run_cmd

log = logging.getLogger("scc.services")

SHOW_PROPS = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "NRestarts",
    "ActiveEnterTimestamp",
    "ExecMainStartTimestamp",
    "MemoryCurrent",
    "CPUUsageNSec",
    "Description",
)

# Units we always want in the panel, whether or not they currently exist.
# Scope comes straight from config, which is the authoritative Phase A map.
DISCOVER_SYSTEM_UNITS = SYSTEM_SERVICE_UNITS
DISCOVER_USER_UNITS = USER_SERVICE_UNITS


def parse_show_properties(text: str) -> dict[str, str]:
    """Parse a SINGLE unit's `systemctl show -p ...` KEY=VALUE output."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def parse_show_blocks(text: str) -> dict[str, dict[str, str]]:
    """Parse MULTI-unit `systemctl show` output.

    systemd separates per-unit blocks with a blank line, and the property order
    inside a block is NOT guaranteed (on this host `Id` appears near the end,
    after MainPID/NRestarts). Splitting on `Id=` would therefore attribute the
    leading properties of unit N+1 to unit N. Blank-line splitting is the only
    reliable delimiter.
    """
    results: dict[str, dict[str, str]] = {}
    block: list[str] = []

    def flush(buf: list[str]) -> None:
        props: dict[str, str] = {}
        for line in buf:
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            props[key.strip()] = value.strip()
        unit = props.get("Id")
        if unit:
            results[unit] = props

    for line in text.splitlines():
        if not line.strip():
            flush(block)
            block = []
        else:
            block.append(line)
    flush(block)
    return results


def parse_timestamp(value: str | None) -> float | None:
    """systemd timestamps -> epoch seconds.

    systemd emits `Fri 2026-10-02 10:49:54 UTC`, but `ExecMainStartTimestamp`
    can also come back as a bare `2026-10-02 03:30:06 UTC`. Both are handled.
    """
    if not value or value in {"n/a", "", "0"}:
        return None
    try:
        from datetime import datetime, timezone

        cleaned = value.replace(" UTC", "").strip()
        for fmt in ("%a %Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue
        return None
    except (ValueError, TypeError):
        return None


def status_color(active_state: str, sub_state: str, load_state: str) -> str:
    """green / amber / red / gray, per the spec's colour contract."""
    if load_state == "not-found" or not load_state:
        return "gray"
    if active_state == "active":
        return "green" if sub_state in {"running", "exited", "reloading"} else "amber"
    if active_state in {"failed", "deactivating", "activating"}:
        return "red"
    if active_state == "inactive":
        return "gray"
    return "gray"


class ServiceCollector:
    def __init__(self) -> None:
        self._last_state: dict[str, str] = {}

    @staticmethod
    async def _detect_process_service() -> dict[str, Any] | None:
        """Some important services are bare processes, not systemd units.

        A directly started tunnel may have no unit file. Detect it from the
        process table instead of displaying a phantom "down" row.
        """
        try:
            import psutil
        except ImportError:  # pragma: no cover
            return None

        for proc in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                if (proc.info.get("name") or "") != "cloudflared":
                    continue
                created = proc.info.get("create_time") or 0
                import time as _time

                return {
                    "unit": "cloudflared.service",
                    "scope": "process",
                    "display_name": SERVICE_LABELS.get("cloudflared.service", "Cloudflare Tunnel"),
                    "description": "Cloudflare Tunnel (direct process, no unit file)",
                    "status": "active/running",
                    "color": "green",
                    "active_state": "active",
                    "sub_state": "running",
                    "pid": proc.info["pid"],
                    "restarts": None,
                    "uptime_seconds": round(_time.time() - created, 0) if created else None,
                    "uptime_human": human_duration(_time.time() - created) if created else None,
                    "important": False,
                    "optional": False,
                    "exists": True,
                    "expected_port": None,
                    "detected_via": "process-table",
                }
            except (psutil.Error, OSError):
                continue
        return None

    async def _show_one(self, unit: str, user_scope: bool) -> dict[str, Any] | None:
        argv = [settings.systemctl_bin]
        if user_scope:
            argv.append("--user")
        argv += ["show", unit, "-p", ",".join(SHOW_PROPS), "--no-pager"]
        rc, out, _ = await run_cmd(argv, timeout=4.0)
        if rc != 0 or not out.strip():
            return None
        return parse_show_properties(out)

    async def _show_many(self, units: list[str], user_scope: bool) -> dict[str, dict]:
        """One systemctl call for all units: cheaper than N calls."""
        if not units:
            return {}
        argv = [settings.systemctl_bin]
        if user_scope:
            argv.append("--user")
        argv += ["show"] + units + ["-p", ",".join(SHOW_PROPS), "--no-pager"]
        rc, out, _ = await run_cmd(argv, timeout=6.0)
        if rc != 0 or not out.strip():
            # Fall back to per-unit calls so one bad unit cannot blind the panel.
            results: dict[str, dict] = {}
            for unit in units:
                one = await self._show_one(unit, user_scope)
                if one:
                    results[unit] = one
            return results

        results = parse_show_blocks(out)
        # Guard against a partial parse: every requested unit must be present.
        missing = [u for u in units if u not in results]
        if missing:
            log.debug("multi-unit show missing %s; fetching individually", missing)
            for unit in missing:
                one = await self._show_one(unit, user_scope)
                if one:
                    results[unit] = one
        return results

    async def collect(self) -> dict:
        import time

        sys_units = await self._show_many(list(DISCOVER_SYSTEM_UNITS), user_scope=False)
        user_units = await self._show_many(list(DISCOVER_USER_UNITS), user_scope=True)

        important = set(IMPORTANT_SYSTEM_UNITS) | set(IMPORTANT_USER_UNITS)
        optional = set(OPTIONAL_USER_UNITS)

        services: list[dict] = []
        for unit, scope, table in (
            [(u, "system", sys_units) for u in DISCOVER_SYSTEM_UNITS]
            + [(u, "user", user_units) for u in DISCOVER_USER_UNITS]
        ):
            entry = table.get(unit)
            if entry is None:
                # A unit with no unit file may still be running as a bare
                # process (cloudflared). Detect that instead of showing "down".
                load_state = "not-found"
                if scope == "system":
                    detected = await self._detect_process_service()
                    if detected and detected["unit"] == unit:
                        services.append(detected)
                        continue

                services.append(
                    {
                        "unit": unit,
                        "scope": scope,
                        "display_name": SERVICE_LABELS.get(unit, unit),
                        "status": "not-found",
                        "color": "gray",
                        "active_state": None,
                        "sub_state": None,
                        "pid": None,
                        "restarts": None,
                        "uptime_seconds": None,
                        "uptime_human": None,
                        "important": unit in important,
                        "optional": unit in optional,
                        "exists": load_state != "not-found",
                        "expected_port": SERVICE_PORTS.get(unit),
                    }
                )
                continue

            active_state = entry.get("ActiveState", "unknown")
            sub_state = entry.get("SubState", "unknown")
            load_state = entry.get("LoadState", "unknown")

            # A unit with no unit file can still be running as a bare process
            # (cloudflared). `systemctl show` returns a not-found placeholder
            # for those, so the placeholder must be replaced, not rendered.
            if load_state == "not-found" and scope == "system":
                detected = await self._detect_process_service()
                if detected and detected["unit"] == unit:
                    services.append(detected)
                    continue
            pid_raw = entry.get("MainPID", "0")
            try:
                pid = int(pid_raw)
            except (TypeError, ValueError):
                pid = 0
            try:
                restarts = int(entry.get("NRestarts", "0"))
            except (TypeError, ValueError):
                restarts = None

            started = parse_timestamp(entry.get("ActiveEnterTimestamp")) or parse_timestamp(
                entry.get("ExecMainStartTimestamp")
            )
            uptime = round(time.time() - started, 0) if started and active_state == "active" else None

            svc = {
                "unit": unit,
                "scope": scope,
                "display_name": SERVICE_LABELS.get(unit, unit.replace(".service", "")),
                "description": entry.get("Description") or None,
                "status": f"{active_state}/{sub_state}",
                "color": status_color(active_state, sub_state, load_state),
                "active_state": active_state,
                "sub_state": sub_state,
                "pid": pid or None,
                "restarts": restarts,
                "uptime_seconds": uptime,
                "uptime_human": human_duration(uptime) if uptime else None,
                "important": unit in important,
                "optional": unit in optional,
                "exists": load_state != "not-found",
                "expected_port": SERVICE_PORTS.get(unit),
            }
            services.append(svc)
            self._note_transition(unit, active_state)

        services.sort(key=lambda s: (not s["important"], s["scope"], s["unit"]))

        return {
            "available": True,
            "services": services,
            "counts": {
                "total": len(services),
                "running": sum(1 for s in services if s["active_state"] == "active"),
                "failed": sum(1 for s in services if s["active_state"] == "failed"),
                "important_down": sum(
                    1
                    for s in services
                    if s["important"] and not s["optional"] and s["active_state"] != "active"
                ),
            },
        }

    def _note_transition(self, unit: str, active_state: str) -> None:
        """Log state transitions only - never log every sample."""
        previous = self._last_state.get(unit)
        if previous != active_state:
            if previous is not None:
                log.info("service state change: %s %s -> %s", unit, previous, active_state)
            self._last_state[unit] = active_state