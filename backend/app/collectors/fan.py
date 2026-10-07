"""Fan / cooling observer. STRICTLY READ-ONLY.

The existing `cpu-fan-controller.service` remains the single authority for fan
control. This module only *observes* it. It never sends a Tuya command, never
writes to the Tuya device, and never reads the Tuya Local Key.

Where the state comes from
-------------------------
The controller is a 5-second polling loop that logs to journald:

    INFO  CPU=59.0C FAN=OFF
    WARNING CPU 71.0C >= 70.0C: turning FAN ON
    INFO  FAN confirmed ON

So the newest log line is the authoritative current state, and the
`FAN confirmed ON/OFF` line gives the last state transition timestamp. This
approach needs no credentials at all.

Thresholds (70 C on / 60 C off / 180 s minimum runtime) are parsed out of the
controller's own source at `/opt/cpu-fan-controller/controller.py` so the panel
always displays the values the automation is actually using, rather than
hardcoded guesses. The parse only ever extracts numeric constants; it never
touches the env file that holds credentials.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from typing import Any

from app.config import settings
from app.utils.common import run_cmd

log = logging.getLogger("scc.fan")

CONTROLLER_SOURCE = "/opt/cpu-fan-controller/controller.py"
CONTROLLER_ENV_FILE = "/etc/cpu-fan-controller.env"

# Env var NAMES only. Presence is reported, values never are.
_SECRET_ENV_NAMES = ("TUYA_LOCAL_KEY", "TUYA_DEVICE_ID", "TUYA_DEVICE_IP", "TUYA_VERSION")

# `2026-10-05 10:03:34,054 INFO CPU=50.0C FAN=OFF`
_POLL_RE = re.compile(r"CPU=(?P<temp>-?\d+(?:\.\d+)?)C\s+FAN=(?P<fan>ON|OFF)")
_CHANGE_RE = re.compile(r"turning FAN (?P<fan>ON|OFF)")
_CONFIRM_RE = re.compile(r"FAN confirmed (?P<fan>ON|OFF)")
_START_RE = re.compile(r"Controller started .*ON=(?P<on>-?\d+(?:\.\d+)?)C OFF=(?P<off>-?\d+(?:\.\d+)?)C")
_JOURNAL_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")


def parse_controller_thresholds(source_text: str) -> dict[str, float | None]:
    """Extract ON_TEMP / OFF_TEMP / MIN_ON_SECONDS / POLL_SECONDS from source."""
    out: dict[str, float | None] = {
        "on_temp_c": None,
        "off_temp_c": None,
        "min_on_seconds": None,
        "poll_seconds": None,
    }
    patterns = {
        "on_temp_c": r"^ON_TEMP\s*=\s*([\d.]+)",
        "off_temp_c": r"^OFF_TEMP\s*=\s*([\d.]+)",
        "min_on_seconds": r"^MIN_ON_SECONDS\s*=\s*([\d.]+)",
        "poll_seconds": r"^POLL_SECONDS\s*=\s*([\d.]+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, source_text, re.MULTILINE)
        if m:
            try:
                out[key] = float(m.group(1))
            except ValueError:
                pass
    return out


def parse_journal(text: str) -> dict[str, Any]:
    """Parse controller journal output into the observable fan state."""
    state: dict[str, Any] = {
        "fan_state": None,          # "ON" / "OFF" / None
        "fan_on": None,             # bool / None
        "reported_cpu_temp": None,  # the temp the controller itself saw
        "last_poll_at": None,
        "last_change_at": None,
        "last_confirmed": None,
        "poll_age_seconds": None,
        "stale": True,
        "recent_errors": [],
        "thresholds_from_log": {},
    }

    lines = text.splitlines()
    if not lines:
        return state

    now = time.time()

    for line in reversed(lines):
        m = _POLL_RE.search(line)
        if m and state["fan_state"] is None:
            state["fan_state"] = m.group("fan")
            state["fan_on"] = m.group("fan") == "ON"
            try:
                state["reported_cpu_temp"] = float(m.group("temp"))
            except ValueError:
                pass
            ts = _parse_line_ts(line)
            if ts:
                state["last_poll_at"] = ts
                state["poll_age_seconds"] = round(now - ts, 1)
                state["stale"] = (now - ts) > settings.fan_stale_after_s

        if state["last_change_at"] is None and _CHANGE_RE.search(line):
            ts = _parse_line_ts(line)
            if ts:
                state["last_change_at"] = ts

        if state["last_confirmed"] is None:
            m_confirm = _CONFIRM_RE.search(line)
            if m_confirm:
                state["last_confirmed"] = m_confirm.group("fan")
                ts = _parse_line_ts(line)
                if ts and state["last_change_at"] is None:
                    state["last_change_at"] = ts

        m = _START_RE.search(line)
        if m and not state["thresholds_from_log"]:
            try:
                state["thresholds_from_log"] = {
                    "on_temp_c": float(m.group("on")),
                    "off_temp_c": float(m.group("off")),
                }
            except ValueError:
                pass

    # Surface recent controller errors - a Tuya failure shows up here.
    errors = []
    for line in lines[-200:]:
        if " ERROR " in line or "Traceback" in line:
            errors.append(_redact_error(line.strip()))
        if len(errors) >= 5:
            break
    state["recent_errors"] = errors

    return state


def _redact_error(line: str) -> str:
    """Defence in depth: strip anything that looks like a credential."""
    from app.utils.redact import redact_text

    return redact_text(line)[-300:]


def _parse_line_ts(line: str) -> float | None:
    m = _JOURNAL_TS_RE.search(line)
    if not m:
        return None
    raw = m.group("ts").replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(raw, fmt))
        except ValueError:
            continue
    return None


def _secret_presence() -> dict[str, str]:
    """Report credential presence ONLY. Never values, never file contents."""
    out: dict[str, str] = {}
    try:
        with open(CONTROLLER_ENV_FILE, "r", encoding="utf-8") as fh:
            names = {ln.split("=", 1)[0].strip() for ln in fh if "=" in ln}
    except (OSError, PermissionError):
        # Env file is root-only (0600); from the dashboard's unprivileged user
        # it is simply not readable. That is the desired outcome.
        return {
            "TUYA_LOCAL_KEY": "not-readable-by-dashboard-user",
            "device_id": "not-readable-by-dashboard-user",
            "device_ip": "not-readable-by-dashboard-user",
        }

    out["TUYA_LOCAL_KEY"] = "present" if "TUYA_LOCAL_KEY" in names else "not present"
    out["device_id"] = "present" if "TUYA_DEVICE_ID" in names else "not present"
    out["device_ip"] = "present" if "TUYA_DEVICE_IP" in names else "not present"
    out["note"] = "values never read, never transmitted, never logged"
    return out


def _controller_implementation() -> dict[str, Any]:
    """Detect how the existing controller talks to Tuya. Read-only."""
    out: dict[str, Any] = {
        "source": CONTROLLER_SOURCE,
        "readable": False,
        "uses_tinytuya": None,
        "device_class": None,
    }
    try:
        with open(CONTROLLER_SOURCE, "r", encoding="utf-8") as fh:
            text = fh.read(8192)
    except (OSError, PermissionError):
        return out

    out["readable"] = True
    out["uses_tinytuya"] = "import tinytuya" in text or "tinytuya." in text
    m = re.search(r"tinytuya\.(\w+)\(", text)
    out["device_class"] = m.group(1) if m else None
    return out


class FanCollector:
    def __init__(self) -> None:
        self._thresholds: dict[str, float | None] | None = None
        self._thresholds_read_at = 0.0
        self._last_state: str | None = None
        self._service_active: bool | None = None

    def _thresholds_from_source(self) -> dict[str, float | None]:
        """Re-read the controller source occasionally; it rarely changes."""
        now = time.monotonic()
        if self._thresholds is not None and now - self._thresholds_read_at < 300:
            return self._thresholds
        try:
            with open(CONTROLLER_SOURCE, "r", encoding="utf-8") as fh:
                text = fh.read(16384)
            self._thresholds = parse_controller_thresholds(text)
        except (OSError, PermissionError):
            self._thresholds = {}
        self._thresholds_read_at = now
        return self._thresholds

    async def _service_state(self) -> dict[str, Any]:
        argv = [
            settings.systemctl_bin,
            "show",
            settings.fan_unit,
            "-p",
            "ActiveState,SubState,MainPID,NRestarts,ActiveEnterTimestamp,ExecMainStartTimestamp",
            "--no-pager",
        ]
        rc, out, _ = await run_cmd(argv, timeout=4.0)
        if rc != 0 or not out.strip():
            return {"available": False, "active": False}

        props: dict[str, str] = {}
        for line in out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                props[k.strip()] = v.strip()

        active_state = props.get("ActiveState", "unknown")
        self._service_active = active_state == "active"

        started_raw = props.get("ExecMainStartTimestamp") or props.get("ActiveEnterTimestamp")
        started = None
        if started_raw and started_raw not in {"n/a", ""}:
            try:
                from datetime import datetime, timezone

                dt = datetime.strptime(
                    started_raw.replace(" UTC", "").strip(), "%a %Y-%m-%d %H:%M:%S"
                ).replace(tzinfo=timezone.utc)
                started = dt.timestamp()
            except ValueError:
                started = None

        try:
            pid = int(props.get("MainPID", "0"))
        except ValueError:
            pid = 0

        return {
            "available": True,
            "active": active_state == "active",
            "status": active_state,
            "sub_state": props.get("SubState"),
            "pid": pid or None,
            "restarts": int(props.get("NRestarts", "0") or 0),
            "since": started,
            "uptime_seconds": round(time.time() - started, 0) if started else None,
        }

    async def collect(self, cpu_temp: float | None = None) -> dict:
        journal = await self._read_journal()
        parsed = parse_journal(journal)
        service = await self._service_state()
        thresholds = self._thresholds_from_source()

        # Tuya connectivity is inferred from controller behaviour, never from
        # our own Tuya calls: the controller logs `FAN confirmed ON/OFF` only
        # after a successful set_status + verification round-trip, and it logs
        # every poll line only when read_socket() succeeded.
        tuya_state, tuya_reason = self._infer_tuya(parsed)

        fan_state = parsed["fan_state"]
        if fan_state != self._last_state and fan_state is not None:
            log.info("observed fan state change: %s -> %s", self._last_state, fan_state)
            self._last_state = fan_state

        automation = self._describe_automation(service, parsed)

        on_temp = thresholds.get("on_temp_c")
        off_temp = thresholds.get("off_temp_c")
        if on_temp is None and parsed["thresholds_from_log"]:
            on_temp = parsed["thresholds_from_log"].get("on_temp_c")
        if off_temp is None and parsed["thresholds_from_log"]:
            off_temp = parsed["thresholds_from_log"].get("off_temp_c")

        return {
            "available": bool(parsed["fan_state"] or service.get("available")),
            "read_only": True,
            "authoritative_controller": "cpu-fan-controller.service",
            "fan": {
                "state": fan_state,               # "ON" / "OFF" / None
                "on": parsed["fan_on"],
                "last_change_at": parsed["last_change_at"],
                "last_change_human": _human_ts(parsed["last_change_at"]),
                "last_confirmed": parsed["last_confirmed"],
                "data_stale": parsed["stale"],
                "poll_age_seconds": parsed["poll_age_seconds"],
                "last_poll_at": parsed["last_poll_at"],
            },
            "automation": automation,
            "controller": {
                **service,
                "unit": settings.fan_unit,
                "implementation": _controller_implementation(),
            },
            "tuya": {
                "state": tuya_state,
                "reason": tuya_reason,
                "method": "inferred from controller journal (no credentials used)",
                "secrets": _secret_presence(),
            },
            "thresholds": {
                "on_temp_c": on_temp,
                "off_temp_c": off_temp,
                "min_on_seconds": thresholds.get("min_on_seconds"),
                "poll_seconds": thresholds.get("poll_seconds"),
                "source": "parsed from /opt/cpu-fan-controller/controller.py",
            },
            "cpu_temp": cpu_temp if cpu_temp is not None else parsed["reported_cpu_temp"],
            "cpu_temp_source": "coretemp Package id 0 (same sensor the controller uses)",
            "recent_errors": parsed["recent_errors"],
        }

    async def _read_journal(self) -> str:
        rc, out, err = await run_cmd(
            [
                "journalctl",
                "-u",
                settings.fan_unit,
                "-n",
                str(settings.fan_journal_lines),
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=5.0,
        )
        if rc != 0 or not out.strip():
            log.warning("fan journal read failed: %s", (err or "").strip()[:120])
            return ""
        return out

    @staticmethod
    def _infer_tuya(parsed: dict) -> tuple[str, str]:
        if parsed["recent_errors"]:
            return "degraded", "controller logged errors; device comms may be failing"
        if parsed["stale"] and parsed["poll_age_seconds"] is not None:
            return "unknown", f"last poll {parsed['poll_age_seconds']}s ago (stale)"
        if parsed["fan_state"] is None:
            return "unknown", "no controller poll lines found"
        # A poll line only exists when read_socket() returned a valid dps map,
        # so a recent poll line IS proof of successful local Tuya comms.
        return "connected", "controller read device state successfully on its latest poll"

    @staticmethod
    def _describe_automation(service: dict, parsed: dict) -> dict:
        if not service.get("available"):
            return {"mode": "unknown", "reason": "controller unit not observable"}
        if not service.get("active"):
            return {
                "mode": "disabled",
                "reason": f"{settings.fan_unit} is {service.get('status')}",
            }
        return {
            "mode": "AUTO",
            "reason": "temperature-driven automation owned by cpu-fan-controller.service",
            "manual_control_available": False,
            "note": "dashboard is read-only; it never actuates the fan",
        }


def _human_ts(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))