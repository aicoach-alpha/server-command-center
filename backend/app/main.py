"""Server Command Center API.

Design constraints honoured here:
  * binds 127.0.0.1 by default - no public exposure
  * one shared sampling loop; clients only receive data
  * every collector failure is isolated to its own section
  * no secret ever crosses this boundary
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles

from app.auth import LoginGuard, create_session, token_fingerprint, verify_password, verify_session
from app.config import settings
from app.services.history import RANGES
from app.services.hub import CollectorHub

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("scc.api")

hub = CollectorHub()
login_guard = LoginGuard()

# Server-side session revocation. Sessions are stateless HMAC tokens, so logout
# records the token fingerprint here until its natural expiry: a replayed token
# is then rejected by every REST call and by the WebSocket. Only non-reversible
# fingerprints are kept, never the token itself.
_revoked_sessions: dict[str, float] = {}


def _revoke_token(token: str | None) -> None:
    fp = token_fingerprint(token)
    if fp:
        _revoked_sessions[fp] = time.time() + settings.auth_session_ttl_s


def _is_revoked(token: str | None) -> bool:
    if not _revoked_sessions:
        return False
    now = time.time()
    for fp, expiry in list(_revoked_sessions.items()):
        if expiry <= now:
            del _revoked_sessions[fp]
    fp = token_fingerprint(token)
    return bool(fp) and fp in _revoked_sessions


def _auth_configured() -> bool:
    return bool(settings.auth_username and settings.auth_password_hash and settings.session_secret)


def _request_is_https(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    return forwarded == "https" or request.url.scheme == "https"


def _client_key(request: Request) -> str:
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _request_authenticated(request: Request) -> bool:
    if not settings.auth_enabled:
        return True
    if not _auth_configured():
        return False
    token = request.cookies.get(settings.auth_cookie_name)
    if _is_revoked(token):
        return False
    return verify_session(token, settings.session_secret, settings.auth_username)



@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("starting %s", app.title)
    await hub.start()

    # Broadcast pump: pushes the shared snapshot to subscribers on the fast tick.
    async def pump() -> None:
        while True:
            try:
                await asyncio.sleep(settings.fast_interval_s)
                await hub.broadcast()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.error("broadcast pump error: %s", exc)

    pump_task = asyncio.create_task(pump(), name="scc-broadcast")
    log.info("listening interface ready")
    try:
        yield
    finally:
        pump_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await pump_task
        await hub.stop()
        log.info("collector hub stopped")


app = FastAPI(
    title="Server Command Center API",
    description="Real-time, read-only server telemetry. Never exposes secrets.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# The frontend is served as static files from the same FastAPI process (no
# separate Node.js server). dist/ lives at the project root, two levels up
# from this module. Mounted at the END of the file so all API routes and the
# WebSocket route take priority; unmatched paths fall through to StaticFiles.
_DIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dist")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
)


_PUBLIC_API_PATHS = {"/api/auth/login", "/api/auth/me", "/api/health/live", "/api/demo"}


@app.middleware("http")
async def require_auth_for_api(request: Request, call_next):
    path = request.url.path
    if (
        settings.auth_enabled
        and path.startswith("/api/")
        and path not in _PUBLIC_API_PATHS
        and not _request_authenticated(request)
    ):
        status_code = 503 if not _auth_configured() else 401
        detail = "Authentication is not configured" if status_code == 503 else "Authentication required"
        return JSONResponse({"detail": detail}, status_code=status_code)
    return await call_next(request)


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/api/auth/me")
async def auth_me(request: Request) -> dict:
    authenticated = _request_authenticated(request)
    return {
        "enabled": settings.auth_enabled,
        "configured": _auth_configured(),
        "authenticated": authenticated,
        "username": settings.auth_username if authenticated else None,
    }


@app.post("/api/auth/login")
async def auth_login(payload: LoginRequest, request: Request) -> Response:
    if not settings.auth_enabled:
        return JSONResponse({"authenticated": True, "username": payload.username})
    if not _auth_configured():
        raise HTTPException(status_code=503, detail="Authentication is not configured")

    key = _client_key(request)
    allowed, retry_after = login_guard.allowed(key)
    if not allowed:
        return JSONResponse(
            {"detail": "Too many login attempts. Try again later."},
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    valid_user = secrets_compare(payload.username, settings.auth_username)
    valid_password = verify_password(payload.password, settings.auth_password_hash)
    if not (valid_user and valid_password):
        login_guard.failure(key)
        return JSONResponse({"detail": "Invalid username or password"}, status_code=401)

    login_guard.success(key)
    token = create_session(settings.auth_username, settings.session_secret, settings.auth_session_ttl_s)
    response = JSONResponse({"authenticated": True, "username": settings.auth_username})
    response.set_cookie(
        settings.auth_cookie_name,
        token,
        max_age=settings.auth_session_ttl_s,
        httponly=True,
        secure=_request_is_https(request),
        samesite="lax",
        path="/",
    )
    return response


@app.post("/api/auth/logout")
async def auth_logout(request: Request) -> Response:
    _revoke_token(request.cookies.get(settings.auth_cookie_name))
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(
        settings.auth_cookie_name,
        path="/",
        secure=_request_is_https(request),
        httponly=True,
        samesite="lax",
    )
    return response


def secrets_compare(left: str, right: str) -> bool:
    import secrets
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
@app.websocket("/ws/metrics")
async def ws_metrics(websocket: WebSocket) -> None:
    """Push the shared snapshot. Does NOT sample the system per client."""
    if settings.auth_enabled:
        if not _auth_configured():
            await websocket.close(code=1013, reason="Authentication is not configured")
            return
        token = websocket.cookies.get(settings.auth_cookie_name)
        if _is_revoked(token) or not verify_session(token, settings.session_secret, settings.auth_username):
            await websocket.close(code=4401, reason="Authentication required")
            return
    await websocket.accept()
    queue = hub.subscribe()
    log.info("websocket client connected (%d total)", hub.subscriber_count)

    try:
        # Send an immediate snapshot so the UI paints without waiting a tick.
        # Slim it exactly like the broadcast path so the initial frame is never
        # larger than subsequent frames.
        snapshot = hub.slim_for_ws(await hub.snapshot())
        await websocket.send_text(json.dumps(snapshot, default=_json_default))

        while True:
            payload = await queue.get()
            await websocket.send_text(json.dumps(payload, default=_json_default))
    except WebSocketDisconnect:
        log.info("websocket client disconnected")
    except (asyncio.CancelledError, RuntimeError):
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning("websocket error: %s", exc)
    finally:
        hub.unsubscribe(queue)


# ---------------------------------------------------------------------------
# REST
# ---------------------------------------------------------------------------
@app.get("/api/health/live")
async def health_live() -> dict:
    """Liveness probe: does the collector loop still run?"""
    return {"status": "ok", "cycles": hub._cycle_count, "running": hub._running}


@app.get("/api/snapshot")
async def snapshot() -> dict:
    """Full current snapshot."""
    return await hub.snapshot()


@app.get("/api/system")
async def system() -> dict:
    snap = await hub.snapshot()
    return {
        "meta": snap.get("meta"),
        "health": snap.get("health"),
        "cpu": snap.get("cpu"),
        "memory": snap.get("memory"),
        "temperature": snap.get("temperature"),
        "gpu": snap.get("gpu"),
    }


@app.get("/api/cpu")
async def cpu() -> dict:
    snap = await hub.snapshot()
    return {"cpu": snap.get("cpu"), "temperature": snap.get("temperature")}


@app.get("/api/memory")
async def memory() -> dict:
    return {"memory": (await hub.snapshot()).get("memory")}


@app.get("/api/gpu")
async def gpu() -> dict:
    snap = await hub.snapshot()
    return {"gpu": snap.get("gpu"), "gpu_processes": snap.get("gpu_processes")}


@app.get("/api/network")
async def network() -> dict:
    return {"network": (await hub.snapshot()).get("network")}


@app.get("/api/storage")
async def storage() -> dict:
    return {"storage": (await hub.snapshot()).get("storage")}


@app.get("/api/storage/external")
async def storage_external() -> dict:
    return {"storage_external": (await hub.snapshot()).get("storage_external")}


@app.get("/api/storage/events")
async def storage_events(
    limit: int = Query(default=100, ge=1, le=1000),
    severity: str | None = Query(default=None),
) -> dict:
    from app.services.storage_events import get_store
    store = get_store()
    events = store.get_events(limit=limit, severity=severity) if severity else store.get_events(limit=limit)
    return {"events": events, "count": len(events)}


@app.get("/api/fan")
async def fan() -> dict:
    return {"fan": (await hub.snapshot()).get("fan")}


@app.get("/api/services")
async def services() -> dict:
    return {"services": (await hub.snapshot()).get("services")}


@app.get("/api/containers")
async def containers() -> dict:
    return {"containers": (await hub.snapshot()).get("containers")}


@app.get("/api/processes")
async def processes(
    limit: int = Query(default=settings.process_limit, ge=1, le=200),
) -> dict:
    snap = await hub.snapshot()
    proc = snap.get("processes") or {}
    return {
        "total": proc.get("total_processes"),
        "top_cpu": (proc.get("top_cpu") or [])[:limit],
        "top_ram": (proc.get("top_ram") or [])[:limit],
    }


@app.get("/api/gpu/processes")
async def gpu_processes() -> dict:
    return {"gpu_processes": (await hub.snapshot()).get("gpu_processes")}


@app.get("/api/health")
async def health() -> dict:
    return {"health": (await hub.snapshot()).get("health")}


@app.get("/api/history")
async def history(
    range: str = Query(default="15m", pattern="^(15m|1h|6h|24h|7d)$"),
    max_points: int = Query(default=720, ge=10, le=5000),
) -> dict:
    return hub.history.query(range, max_points=max_points)


@app.get("/api/stats")
async def stats() -> dict:
    return hub.stats()


@app.get("/api/info")
async def root() -> Response:
    """API metadata endpoint. Frontend is served at / via StaticFiles."""
    return JSONResponse(
        {
            "name": "Server Command Center API",
            "version": "1.0.0",
            "mode": "read-only",
            "docs": "/api/docs",
            "websocket": "/ws/metrics",
            "ranges": list(RANGES),
        }
    )


@app.get("/api/demo")
async def demo_snapshot() -> dict:
    """Return a synthetic, sanitized snapshot for screenshots and documentation.

    This endpoint is ALWAYS available (even when auth is enabled) and returns
    deterministic demo data. It never exposes real host telemetry.
    """
    import time as _time

    now = _time.time()
    snap = {
        "cpu": {
            "percent": {"value": 34.8, "supported": True, "unit": "%"},
            "per_core": [
                {"value": 32.1, "supported": True, "unit": "%"},
                {"value": 36.5, "supported": True, "unit": "%"},
                {"value": 31.2, "supported": True, "unit": "%"},
                {"value": 39.4, "supported": True, "unit": "%"},
            ],
            "cores_logical": 4,
            "cores_physical": 2,
            "load_average": {"1m": 1.24, "5m": 0.98, "15m": 0.76, "1m_per_core": 0.31},
            "frequency_mhz": {
                "current": {"value": 2400.0, "supported": True, "unit": "MHz"},
                "min": {"value": 400.0, "supported": True, "unit": "MHz"},
                "max": {"value": 2800.0, "supported": True, "unit": "MHz"},
            },
            "sample_interval_s": 2.0,
            "uptime_seconds": 86400.0,
            "boot_time": now - 86400.0,
        },
        "memory": {
            "available": True,
            "ram": {
                "total_bytes": 17179869184,
                "used_bytes": 11811160064,
                "available_bytes": 4831838208,
                "free_bytes": 536870912,
                "buff_cache_bytes": 2684354560,
                "percent": {"value": 45.6, "supported": True, "unit": "%"},
                "human": {"total": "16.0 GiB", "used": "11.0 GiB", "available": "4.5 GiB", "free": "512.0 MiB"},
            },
            "swap": {
                "total_bytes": 8589934592,
                "used_bytes": 1288490188,
                "free_bytes": 7301444403,
                "percent": {"value": 15.0, "supported": True, "unit": "%"},
                "human": {"total": "8.0 GiB", "used": "1.2 GiB", "free": "6.8 GiB"},
            },
        },
        "temperature": {
            "available": True,
            "cpu": {
                "package_c": 52.0,
                "supported": True,
                "source": "/sys/class/hwmon/hwmon0/temp1_input",
                "critical_c": 100.0,
                "cores": [
                    {"label": "Core 0", "celsius": 50.0, "source": "/sys/class/hwmon/hwmon0/temp2_input"},
                    {"label": "Core 1", "celsius": 54.0, "source": "/sys/class/hwmon/hwmon0/temp3_input"},
                ],
            },
            "other": [
                {"type": "acpitz", "celsius": 48.0, "source": "/sys/class/thermal/thermal_zone0/temp"},
            ],
        },
        "gpu": {
            "index": 0,
            "name": "NVIDIA GeForce RTX 3060",
            "uuid": None,
            "driver_version": "535.104.05",
            "persistence_mode": "Enabled",
            "utilization": {"value": 21.0, "supported": True, "unit": "%"},
            "memory": {
                "total_bytes": 12884901888,
                "used_bytes": 3374730444,
                "free_bytes": 9510171444,
                "total_mib": {"value": 12288.0, "supported": True, "unit": "MiB"},
                "used_mib": {"value": 3218.0, "supported": True, "unit": "MiB"},
                "free_mib": {"value": 9070.0, "supported": True, "unit": "MiB"},
                "percent": {"value": 26.2, "supported": True, "unit": "%"},
            },
            "temperature": {"value": 49.0, "supported": True, "unit": "°C"},
            "power_draw": {"value": 85.0, "supported": True, "unit": "W"},
            "power_limit": {"value": 170.0, "supported": True, "unit": "W"},
            "clocks": {
                "graphics_mhz": {"value": 1500.0, "supported": True, "unit": "MHz"},
                "memory_mhz": {"value": 7500.0, "supported": True, "unit": "MHz"},
                "max_graphics_mhz": {"value": 1800.0, "supported": True, "unit": "MHz"},
                "max_memory_mhz": {"value": 9000.0, "supported": True, "unit": "MHz"},
            },
            "fan_speed_pct": {"value": 35.0, "supported": True, "unit": "%"},
            "available": True,
            "source": "nvidia-smi",
            "nvml_available": True,
            "consecutive_failures": 0,
        },
        "gpu_processes": {
            "available": True,
            "processes": [
                {
                    "pid": 1234,
                    "name": "video-editor",
                    "display_name": "Video Editor",
                    "source": "argv",
                    "service": None,
                    "container": None,
                    "cmdline": [],
                    "gpu_utilization": {"value": 15.0, "supported": True, "unit": "%"},
                    "vram_bytes": 2147483648,
                    "vram_mb": 2048.0,
                    "vram_human": "2.0 GiB",
                    "cpu_percent": 12.5,
                    "ram_bytes": 1073741824,
                    "ram_mb": 1024.0,
                    "user": "demo",
                    "runtime_seconds": 3600.0,
                    "runtime_human": "1h 0m",
                    "rank": 1,
                },
            ],
            "total": 1,
            "stale_pids": [],
            "per_process_utilization": {"value": 15.0, "supported": True, "unit": "%"},
        },
        "network": {
            "active_interface": "eth0",
            "active_link": {
                "interface": "eth0",
                "kind": "lan",
                "address": "192.0.2.10",
                "state": "up",
            },
            "default_routes": [{"interface": "eth0", "metric": 100}],
            "lan": {
                "interface": "eth0",
                "kind": "lan",
                "state": "up",
                "address": "192.0.2.10",
                "rx_bytes_per_sec": 8600000.0,
                "tx_bytes_per_sec": 1200000.0,
            },
            "wifi": {
                "interface": "wlan0",
                "kind": "wifi",
                "state": "standby",
                "address": "192.0.2.11",
                "rx_bytes_per_sec": 100.0,
                "tx_bytes_per_sec": 0.0,
            },
            "totals": {
                "rx_bytes_per_sec": 8600000.0,
                "tx_bytes_per_sec": 1200000.0,
                "rx_bytes_total": 1099511627776,
                "tx_bytes_total": 549755813888,
            },
            "interfaces": [
                {
                    "name": "eth0",
                    "physical": True,
                    "wireless": False,
                    "is_default_route": True,
                    "rx_bytes_total": 1099511627776,
                    "tx_bytes_total": 549755813888,
                    "rx_packets_total": 1000000,
                    "tx_packets_total": 500000,
                    "rx_errors_total": 0,
                    "tx_errors_total": 0,
                    "rx_dropped_total": 0,
                    "tx_dropped_total": 0,
                    "address": {"ipv4": "192.0.2.10", "mac": "aa:bb:cc:dd:ee:ff", "all_ipv4": ["192.0.2.10"]},
                    "state": "up",
                    "rx_bytes_per_sec": 8600000.0,
                    "tx_bytes_per_sec": 1200000.0,
                    "rx_packets_per_sec": 1000.0,
                    "tx_packets_per_sec": 500.0,
                },
            ],
            "sample_interval_s": 2.0,
        },
        "processes": {
            "available": True,
            "collected_at": now,
            "total_processes": 156,
            "top_cpu": [
                {"pid": 1001, "name": "web-server", "display_name": "Web Application", "source": "systemd", "service": "webapp.service", "container": None, "cmdline": [], "cpu_percent": 18.5, "ram_bytes": 536870912, "ram_mb": 512.0, "ram_percent": 3.1, "user": "www-data", "runtime_seconds": 86400.0, "runtime_human": "1d 0h", "rank": 1},
                {"pid": 1002, "name": "database", "display_name": "Database Server", "source": "systemd", "service": "database.service", "container": None, "cmdline": [], "cpu_percent": 12.3, "ram_bytes": 1073741824, "ram_mb": 1024.0, "ram_percent": 6.3, "user": "postgres", "runtime_seconds": 43200.0, "runtime_human": "12h 0m", "rank": 2},
                {"pid": 1003, "name": "media-server", "display_name": "Media Server", "source": "systemd", "service": "media.service", "container": None, "cmdline": [], "cpu_percent": 8.7, "ram_bytes": 268435456, "ram_mb": 256.0, "ram_percent": 1.6, "user": "media", "runtime_seconds": 21600.0, "runtime_human": "6h 0m", "rank": 3},
                {"pid": 1004, "name": "backup-agent", "display_name": "Backup Service", "source": "systemd", "service": "backup.service", "container": None, "cmdline": [], "cpu_percent": 5.2, "ram_bytes": 134217728, "ram_mb": 128.0, "ram_percent": 0.8, "user": "backup", "runtime_seconds": 7200.0, "runtime_human": "2h 0m", "rank": 4},
                {"pid": 1005, "name": "ai-worker", "display_name": "AI Worker", "source": "systemd", "service": "ai-worker.service", "container": None, "cmdline": [], "cpu_percent": 3.8, "ram_bytes": 2147483648, "ram_mb": 2048.0, "ram_percent": 12.5, "user": "ai", "runtime_seconds": 3600.0, "runtime_human": "1h 0m", "rank": 5},
            ],
            "top_ram": [
                {"pid": 1002, "name": "database", "display_name": "Database Server", "source": "systemd", "service": "database.service", "container": None, "cmdline": [], "cpu_percent": 12.3, "ram_bytes": 1073741824, "ram_mb": 1024.0, "ram_percent": 6.3, "user": "postgres", "runtime_seconds": 43200.0, "runtime_human": "12h 0m", "rank": 1},
                {"pid": 1005, "name": "ai-worker", "display_name": "AI Worker", "source": "systemd", "service": "ai-worker.service", "container": None, "cmdline": [], "cpu_percent": 3.8, "ram_bytes": 2147483648, "ram_mb": 2048.0, "ram_percent": 12.5, "user": "ai", "runtime_seconds": 3600.0, "runtime_human": "1h 0m", "rank": 2},
                {"pid": 1001, "name": "web-server", "display_name": "Web Application", "source": "systemd", "service": "webapp.service", "container": None, "cmdline": [], "cpu_percent": 18.5, "ram_bytes": 536870912, "ram_mb": 512.0, "ram_percent": 3.1, "user": "www-data", "runtime_seconds": 86400.0, "runtime_human": "1d 0h", "rank": 3},
                {"pid": 1003, "name": "media-server", "display_name": "Media Server", "source": "systemd", "service": "media.service", "container": None, "cmdline": [], "cpu_percent": 8.7, "ram_bytes": 268435456, "ram_mb": 256.0, "ram_percent": 1.6, "user": "media", "runtime_seconds": 21600.0, "runtime_human": "6h 0m", "rank": 4},
                {"pid": 1004, "name": "backup-agent", "display_name": "Backup Service", "source": "systemd", "service": "backup.service", "container": None, "cmdline": [], "cpu_percent": 5.2, "ram_bytes": 134217728, "ram_mb": 128.0, "ram_percent": 0.8, "user": "backup", "runtime_seconds": 7200.0, "runtime_human": "2h 0m", "rank": 5},
            ],
            "all": None,
        },
        "services": {
            "available": True,
            "services": [
                {"unit": "docker.service", "scope": "system", "display_name": "Docker Engine", "description": "Docker Application Container Engine", "status": "active/running", "color": "green", "active_state": "active", "sub_state": "running", "pid": 100, "restarts": 0, "uptime_seconds": 86400.0, "uptime_human": "1d 0h", "important": True, "optional": False, "exists": True, "expected_port": None},
                {"unit": "NetworkManager.service", "scope": "system", "display_name": "Network Manager", "description": "Network Manager", "status": "active/running", "color": "green", "active_state": "active", "sub_state": "running", "pid": 200, "restarts": 0, "uptime_seconds": 86400.0, "uptime_human": "1d 0h", "important": True, "optional": False, "exists": True, "expected_port": None},
                {"unit": "webapp.service", "scope": "user", "display_name": "Web Application", "description": "Main web application", "status": "active/running", "color": "green", "active_state": "active", "sub_state": "running", "pid": 1001, "restarts": 0, "uptime_seconds": 86400.0, "uptime_human": "1d 0h", "important": True, "optional": False, "exists": True, "expected_port": 8080},
                {"unit": "database.service", "scope": "user", "display_name": "Database Server", "description": "PostgreSQL database", "status": "active/running", "color": "green", "active_state": "active", "sub_state": "running", "pid": 1002, "restarts": 0, "uptime_seconds": 43200.0, "uptime_human": "12h 0h", "important": True, "optional": False, "exists": True, "expected_port": 5432},
                {"unit": "media.service", "scope": "user", "display_name": "Media Server", "description": "Media streaming server", "status": "active/running", "color": "green", "active_state": "active", "sub_state": "running", "pid": 1003, "restarts": 0, "uptime_seconds": 21600.0, "uptime_human": "6h 0h", "important": False, "optional": True, "exists": True, "expected_port": None},
                {"unit": "backup.service", "scope": "user", "display_name": "Backup Service", "description": "Automated backup service", "status": "active/running", "color": "green", "active_state": "active", "sub_state": "running", "pid": 1004, "restarts": 0, "uptime_seconds": 7200.0, "uptime_human": "2h 0h", "important": False, "optional": True, "exists": True, "expected_port": None},
                {"unit": "ai-worker.service", "scope": "user", "display_name": "AI Worker", "description": "AI processing worker", "status": "active/running", "color": "green", "active_state": "active", "sub_state": "running", "pid": 1005, "restarts": 0, "uptime_seconds": 3600.0, "uptime_human": "1h 0h", "important": False, "optional": True, "exists": True, "expected_port": None},
            ],
            "counts": {"total": 7, "running": 7, "failed": 0, "important_down": 0},
        },
        "storage": {
            "available": True,
            "disks": [
                {
                    "display_name": "System Disk",
                    "mount": "/",
                    "device": "/dev/sda1",
                    "parent_device": "/dev/sda",
                    "fstype": "ext4",
                    "options": "rw,relatime",
                    "read_only": False,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "label": None,
                    "model": "Internal SSD",
                    "transport": "sata",
                    "rotational": False,
                    "kind": "internal",
                    "health": "healthy",
                    "total_bytes": 250901458944,
                    "used_bytes": 153060876288,
                    "free_bytes": 97840582656,
                    "percent": 61.0,
                    "human": {"total": "233.7 GiB", "used": "142.3 GiB", "free": "91.4 GiB"},
                },
                {
                    "display_name": "Internal SSD",
                    "mount": "/mnt/ssd-cache",
                    "device": "/dev/sda2",
                    "parent_device": "/dev/sda",
                    "fstype": "ext4",
                    "options": "rw,relatime",
                    "read_only": False,
                    "uuid": "22222222-3333-4444-5555-666666666666",
                    "label": None,
                    "model": "Internal SSD",
                    "transport": "sata",
                    "rotational": False,
                    "kind": "internal",
                    "health": "healthy",
                    "total_bytes": 125425008640,
                    "used_bytes": 35126001664,
                    "free_bytes": 90299006976,
                    "percent": 28.0,
                    "human": {"total": "116.8 GiB", "used": "32.7 GiB", "free": "84.1 GiB"},
                },
                {
                    "display_name": "External Storage",
                    "mount": "/mnt/data",
                    "device": "/dev/sdb1",
                    "parent_device": "/dev/sdb",
                    "fstype": "ext4",
                    "options": "rw,relatime",
                    "read_only": False,
                    "uuid": "33333333-4444-5555-6666-777777777777",
                    "label": None,
                    "model": "External HDD",
                    "transport": "usb",
                    "rotational": True,
                    "kind": "external",
                    "health": "healthy",
                    "total_bytes": 1967762120704,
                    "used_bytes": 1061933198336,
                    "free_bytes": 905828922368,
                    "percent": 54.0,
                    "human": {"total": "1.8 TiB", "used": "990.0 GiB", "free": "844.0 GiB"},
                },
            ],
            "count": 3,
            "internal_count": 2,
            "external_count": 1,
            "pinned": ["/", "/mnt/ssd-cache", "/mnt/data"],
        },
        "storage_external": {
            "health": "HEALTHY",
            "connected": True,
            "mounted": True,
            "correct_uuid_mounted": True,
            "current_device": "/dev/sdb1",
            "mountpoint": "/mnt/data",
            "filesystem": "ext4",
            "mount_mode": "rw,relatime",
            "capacity_bytes": 1967762120704,
            "used_bytes": 1061933198336,
            "free_bytes": 905828922368,
            "percent_used": 54.0,
            "serial_number": "TESTSERIAL123",
            "transport": "usb",
            "model": "External HDD",
            "last_seen_at": now,
            "connected_since": now - 86400.0,
            "last_state_change_at": now - 86400.0,
            "last_mount_at": None,
            "last_disconnect_at": None,
            "last_event": None,
            "name": "External Storage",
            "filesystem_uuid": "33333333-4444-5555-6666-777777777777",
            "by_uuid_path": "/dev/disk/by-uuid/33333333-4444-5555-6666-777777777777",
            "abbreviated_uuid": "3333…7777",
            "expected_mountpoint": "/mnt/data",
            "available": True,
        },
        "containers": {
            "available": True,
            "containers": [
                {"id": "a1b2c3d4e5f6", "name": "webapp", "image": "nginx:latest", "state": "running", "running": True, "health": "healthy", "health_supported": True, "started_at": "2026-10-01T00:00:00Z", "uptime_seconds": 86400.0, "uptime_human": "1d 0h", "restarts": 0, "restart_policy": "unless-stopped", "cpu_percent": 2.5, "ram_bytes": 134217728, "ram_mb": 128.0, "ports": ["80->80/tcp", "443->443/tcp"]},
                {"id": "b2c3d4e5f6a7", "name": "database", "image": "postgres:16", "state": "running", "running": True, "health": None, "health_supported": False, "started_at": "2026-10-01T00:00:00Z", "uptime_seconds": 86400.0, "uptime_human": "1d 0h", "restarts": 0, "restart_policy": "unless-stopped", "cpu_percent": 5.1, "ram_bytes": 536870912, "ram_mb": 512.0, "ports": ["5432->5432/tcp"]},
            ],
            "count": 2,
        },
        "fan": {
            "available": True,
            "read_only": True,
            "authoritative_controller": "fan-controller.service",
            "fan": {
                "state": "ON",
                "on": True,
                "last_change_at": now - 300.0,
                "last_change_human": "2026-10-07 04:55:00",
                "last_confirmed": "ON",
                "data_stale": False,
                "poll_age_seconds": 2.0,
                "last_poll_at": now - 2.0,
            },
            "automation": {
                "mode": "AUTO",
                "reason": "temperature-driven automation",
                "manual_control_available": False,
                "note": "dashboard is read-only; it never actuates the fan",
            },
            "controller": {
                "available": True,
                "active": True,
                "status": "active",
                "sub_state": "running",
                "pid": 500,
                "restarts": 0,
                "since": now - 86400.0,
                "uptime_seconds": 86400.0,
                "unit": "fan-controller.service",
                "implementation": {"source": "/opt/fan-controller/controller.py", "readable": True, "uses_tinytuya": True, "device_class": "OutletDevice"},
            },
            "tuya": {
                "state": "connected",
                "reason": "controller read device state successfully",
                "method": "inferred from controller journal (no credentials used)",
                "secrets": {"TUYA_LOCAL_KEY": "not-readable-by-dashboard-user", "device_id": "not-readable-by-dashboard-user", "device_ip": "not-readable-by-dashboard-user"},
            },
            "thresholds": {
                "on_temp_c": 70.0,
                "off_temp_c": 60.0,
                "min_on_seconds": 180.0,
                "poll_seconds": 5.0,
                "source": "parsed from controller configuration",
            },
            "cpu_temp": 52.0,
            "cpu_temp_source": "coretemp Package id 0",
            "recent_errors": [],
        },
        "health": {
            "status": "healthy",
            "reasons": [],
            "warning_count": 0,
            "critical_count": 0,
            "thresholds": {
                "cpu_temp_warn_c": 70.0,
                "cpu_temp_crit_c": 90.0,
                "gpu_temp_warn_c": 75.0,
                "gpu_temp_crit_c": 82.0,
                "ram_warn_pct": 85.0,
                "vram_warn_pct": 90.0,
                "disk_warn_pct": 85.0,
                "disk_crit_pct": 95.0,
            },
        },
        "meta": {
            "host": "homelab-server",
            "generated_at": now,
            "generated_at_iso": "2026-10-07T05:00:00+0000",
            "uptime_seconds": 86400.0,
            "health_status": "healthy",
            "fast_interval_s": 2.0,
            "slow_interval_s": 10.0,
            "cycle": 1,
            "collect_ms": 150.0,
            "errors": {},
            "gpu_source": "nvidia-smi",
            "nvml_available": True,
        },
    }

    # Deterministic time-varying telemetry: the frontend polls /api/demo a few
    # times to populate its rolling charts, so the scalar metrics follow a smooth
    # sinusoid (period ~24 s). Values stay reproducible for any wall-clock time
    # and remain clearly synthetic; nothing here reflects the real host.
    import math as _math

    def _wave(base: float, amp: float, phase: float, period: float = 24.0) -> float:
        return round(base + amp * _math.sin(2 * _math.pi * (now / period) + phase), 1)

    def _gib(n: float) -> str:
        return f"{n / 1073741824.0:.1f} GiB"

    _cpu = snap["cpu"]
    _cpu["percent"]["value"] = _wave(34.8, 12.0, 0.0)
    for _i, _core in enumerate(_cpu.get("per_core", [])):
        _core["value"] = _wave(34.0, 10.0, _i * 0.7)
    _la = _cpu.get("load_average")
    if _la:
        _la["1m"] = round(_wave(1.24, 0.6, 0.0), 2)
        _la["5m"] = round(_wave(0.98, 0.35, 0.5), 2)
        _la["15m"] = round(_wave(0.76, 0.2, 1.0), 2)

    _ram = snap["memory"]["ram"]
    _ram_pct = _wave(45.6, 8.0, 1.2)
    _ram["percent"]["value"] = _ram_pct
    _ram["used_bytes"] = int(_ram["total_bytes"] * _ram_pct / 100.0)
    _ram["free_bytes"] = _ram["total_bytes"] - _ram["used_bytes"]
    _ram["human"]["used"] = _gib(_ram["used_bytes"])
    _ram["human"]["free"] = _gib(_ram["free_bytes"])

    _swap = snap["memory"]["swap"]
    _swap_pct = _wave(15.0, 5.0, 2.0)
    _swap["percent"]["value"] = _swap_pct
    _swap["used_bytes"] = int(_swap["total_bytes"] * _swap_pct / 100.0)
    _swap["free_bytes"] = _swap["total_bytes"] - _swap["used_bytes"]
    _swap["human"]["used"] = _gib(_swap["used_bytes"])
    _swap["human"]["free"] = _gib(_swap["free_bytes"])

    _gpu = snap["gpu"]
    _gpu["utilization"]["value"] = _wave(21.0, 14.0, 0.8)
    _vram_pct = _wave(26.2, 6.0, 1.6)
    _gpu["memory"]["percent"]["value"] = _vram_pct
    _gpu["memory"]["used_bytes"] = int(_gpu["memory"]["total_bytes"] * _vram_pct / 100.0)
    _gpu["temperature"]["value"] = _wave(49.0, 4.0, 0.4)

    _temp = snap["temperature"]
    _temp["cpu"]["package_c"] = _wave(52.0, 5.0, 0.2)
    for _i, _core in enumerate(_temp["cpu"].get("cores", [])):
        _core["celsius"] = _wave(52.0, 5.0, 0.2 + _i * 0.3)

    _net = snap["network"]
    _rx = _wave(8600000.0, 5200000.0, 0.0)
    _tx = _wave(1200000.0, 800000.0, 1.1)
    _net["lan"]["rx_bytes_per_sec"] = _rx
    _net["lan"]["tx_bytes_per_sec"] = _tx
    if _net.get("wifi"):
        _net["wifi"]["rx_bytes_per_sec"] = 0.0
        _net["wifi"]["tx_bytes_per_sec"] = 0.0
    _net["totals"]["rx_bytes_per_sec"] = _rx
    _net["totals"]["tx_bytes_per_sec"] = _tx

    snap["fan"]["cpu_temp"] = _temp["cpu"]["package_c"]

    return snap


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (set, tuple)):
        return list(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return str(obj)


if os.path.isdir(_DIST_DIR):
    app.mount("/", StaticFiles(directory=_DIST_DIR, html=True), name="frontend")
else:
    @app.get("/")
    async def frontend_not_built() -> Response:
        return JSONResponse(
            {"detail": "Frontend is not built. Run `npm run build` in frontend/."},
            status_code=503,
        )