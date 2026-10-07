"""Small shared primitives used across collectors."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from typing import Any

log = logging.getLogger("scc.utils")


def metric(value: float | int | None, supported: bool = True, unit: str | None = None) -> dict[str, Any]:
    """Build the canonical metric envelope.

    An unsupported sensor must never be reported as 0. Callers pass
    `supported=False` and get `{"value": null, "supported": false}` so the
    frontend can render "n/a" instead of a misleading zero.
    """
    if not supported or value is None:
        return {"value": None, "supported": False, "unit": unit}
    return {"value": round(float(value), 2), "supported": True, "unit": unit}


async def run_cmd(
    argv: list[str],
    timeout: float = 5.0,
    check: bool = False,
) -> tuple[int | None, str, str]:
    """Run a command without blocking the event loop.

    Returns (returncode, stdout, stderr). returncode is None on timeout or when
    the binary does not exist.
    """
    if shutil.which(argv[0]) is None and not os.path.exists(argv[0]):
        return None, "", "not-found"

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (OSError, ValueError) as exc:
        return None, "", str(exc)

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return None, "", "timeout"

    rc = proc.returncode
    if check and rc not in (0, None):
        return rc, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    return rc, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def safe(fn, default: Any = None):
    """Run a collector function, swallowing and logging any failure.

    Resilience requirement: one broken collector must never take down the whole
    dashboard. Every collector body is wrapped in this.
    """

    def _wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - deliberate boundary
            log.warning("collector %s failed: %s", getattr(fn, "__name__", fn), exc)
            return default

    _wrapped.__name__ = getattr(fn, "__name__", "collector")
    return _wrapped


def human_bytes(num: float | None) -> str | None:
    if num is None:
        return None
    step = 1024.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < step:
            return f"{num:.1f} {unit}"
        num /= step
    return f"{num:.1f} PiB"


def human_duration(seconds: float | None) -> str | None:
    if seconds is None:
        return None
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"