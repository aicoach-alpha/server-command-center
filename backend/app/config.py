"""Runtime configuration for the Server Command Center.

Every value can be overridden by environment variable. Thresholds are documented
explicitly here rather than invented at call sites so the health engine stays
transparent and auditable.

SECURITY: this module never reads Tuya credentials and never returns them.
The dashboard only ever *observes* the existing fan controller.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_csv(name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _env_json_dict(name: str, default: dict | None = None) -> dict:
    raw = os.environ.get(name)
    if not raw:
        return dict(default or {})
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else dict(default or {})
    except (json.JSONDecodeError, TypeError):
        return dict(default or {})


def _env_process_labels() -> tuple[tuple[re.Pattern[str], str], ...]:
    """Compile ordered deployment rules; ignore malformed entries safely."""
    rules = []
    for pattern, label in _env_json_dict("SCC_PROCESS_LABELS_JSON").items():
        if not isinstance(label, str) or not label.strip() or not pattern:
            continue
        try:
            rules.append((re.compile(pattern), label))
        except re.error:
            logging.getLogger("scc.config").warning("Ignoring invalid process-label regex")
    return tuple(rules)


@dataclass(frozen=True)
class Thresholds:
    """Documented, configurable health thresholds.

    CPU thermal values are anchored on the value the hardware itself reports:
    `/sys/class/hwmon/hwmon3/temp1_crit` = 100 C (coretemp "Package id 0"
    critical). The warning level sits well below that and matches the existing
    cpu-fan-controller's own turn-on point (70 C) so the dashboard never
    contradicts the running automation.
    """

    cpu_temp_warn_c: float = field(default_factory=lambda: _env_float("SCC_CPU_TEMP_WARN_C", 70.0))
    cpu_temp_crit_c: float = field(default_factory=lambda: _env_float("SCC_CPU_TEMP_CRIT_C", 90.0))

    # 940MX is a passively/partially cooled laptop part; 80 C sustained is
    # already hot for it. TDX limit on modern GeForce is ~83-86 C.
    gpu_temp_warn_c: float = field(default_factory=lambda: _env_float("SCC_GPU_TEMP_WARN_C", 75.0))
    gpu_temp_crit_c: float = field(default_factory=lambda: _env_float("SCC_GPU_TEMP_CRIT_C", 82.0))

    ram_warn_pct: float = field(default_factory=lambda: _env_float("SCC_RAM_WARN_PCT", 85.0))
    ram_crit_pct: float = field(default_factory=lambda: _env_float("SCC_RAM_CRIT_PCT", 95.0))

    vram_warn_pct: float = field(default_factory=lambda: _env_float("SCC_VRAM_WARN_PCT", 90.0))
    vram_crit_pct: float = field(default_factory=lambda: _env_float("SCC_VRAM_CRIT_PCT", 97.0))

    disk_warn_pct: float = field(default_factory=lambda: _env_float("SCC_DISK_WARN_PCT", 85.0))
    disk_crit_pct: float = field(default_factory=lambda: _env_float("SCC_DISK_CRIT_PCT", 95.0))

    swap_warn_pct: float = field(default_factory=lambda: _env_float("SCC_SWAP_WARN_PCT", 50.0))
    swap_crit_pct: float = field(default_factory=lambda: _env_float("SCC_SWAP_CRIT_PCT", 80.0))

    cpu_load_warn_per_core: float = field(
        default_factory=lambda: _env_float("SCC_CPU_LOAD_WARN_PER_CORE", 1.5)
    )


@dataclass(frozen=True)
class Settings:
    host: str = field(default_factory=lambda: os.environ.get("SCC_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("SCC_PORT", 18680))

    # Authentication. Enabled by default; if credentials are not configured,
    # protected API/WS routes fail closed while the static login shell remains reachable.
    auth_enabled: bool = field(default_factory=lambda: _env_bool("SCC_AUTH_ENABLED", True))
    auth_username: str = field(default_factory=lambda: os.environ.get("SCC_AUTH_USERNAME", "admin"))
    auth_password_hash: str = field(default_factory=lambda: os.environ.get("SCC_AUTH_PASSWORD_HASH", ""))
    session_secret: str = field(default_factory=lambda: os.environ.get("SCC_SESSION_SECRET", ""))
    auth_cookie_name: str = field(default_factory=lambda: os.environ.get("SCC_AUTH_COOKIE_NAME", "scc_session"))
    auth_session_ttl_s: int = field(default_factory=lambda: _env_int("SCC_AUTH_SESSION_TTL_S", 43200))

    # Optional UUID-tracked external storage. Leave UUID empty to disable
    # external-storage incident tracking on generic installations.
    external_storage_uuid: str = field(default_factory=lambda: os.environ.get("SCC_EXTERNAL_STORAGE_UUID", ""))
    external_storage_mountpoint: str = field(default_factory=lambda: os.environ.get("SCC_EXTERNAL_STORAGE_MOUNTPOINT", "/mnt/data"))
    external_storage_name: str = field(default_factory=lambda: os.environ.get("SCC_EXTERNAL_STORAGE_NAME", "External Storage"))

    # Realtime cadence. Two tiers so expensive probes never run on the fast tick.
    fast_interval_s: float = field(default_factory=lambda: _env_float("SCC_FAST_INTERVAL_S", 2.0))
    slow_interval_s: float = field(default_factory=lambda: _env_float("SCC_SLOW_INTERVAL_S", 10.0))
    process_interval_s: float = field(default_factory=lambda: _env_float("SCC_PROCESS_INTERVAL_S", 4.0))
    gpu_process_interval_s: float = field(default_factory=lambda: _env_float("SCC_GPU_PROCESS_INTERVAL_S", 6.0))

    # psutil.cpu_percent() needs a prior call to prime the delta; do it at boot.
    cpu_prime: bool = field(default_factory=lambda: _env_bool("SCC_CPU_PRIME", True))

    process_limit: int = field(default_factory=lambda: _env_int("SCC_PROCESS_LIMIT", 20))

    history_max_points: int = field(default_factory=lambda: _env_int("SCC_HISTORY_MAX_POINTS", 43200))
    history_sample_interval_s: float = field(
        default_factory=lambda: _env_float("SCC_HISTORY_SAMPLE_INTERVAL_S", 10.0)
    )

    # Read-only observation of the EXISTING controller. We never write to it.
    fan_unit: str = field(default_factory=lambda: os.environ.get("SCC_FAN_UNIT", "cpu-fan-controller.service"))
    fan_journal_lines: int = field(default_factory=lambda: _env_int("SCC_FAN_JOURNAL_LINES", 400))
    fan_stale_after_s: float = field(default_factory=lambda: _env_float("SCC_FAN_STALE_AFTER_S", 30.0))

    nvidia_smi_bin: str = field(default_factory=lambda: os.environ.get("SCC_NVIDIA_SMI", "nvidia-smi"))
    nvidia_smi_timeout_s: float = field(
        default_factory=lambda: _env_float("SCC_NVIDIA_SMI_TIMEOUT_S", 4.0)
    )

    docker_bin: str = field(default_factory=lambda: os.environ.get("SCC_DOCKER_BIN", "docker"))
    systemctl_bin: str = field(default_factory=lambda: os.environ.get("SCC_SYSTEMCTL_BIN", "systemctl"))

    thresholds: Thresholds = field(default_factory=Thresholds)

    log_level: str = field(default_factory=lambda: os.environ.get("SCC_LOG_LEVEL", "INFO"))

    # Demo mode: return synthetic telemetry for screenshots/docs. NEVER enable
    # on a production deployment.
    demo_mode: bool = field(default_factory=lambda: _env_bool("SCC_DEMO_MODE", False))


settings = Settings()

# ---------------------------------------------------------------------------
# Service inventory. Generic defaults are intentionally small; deployments can
# supply comma-separated unit lists and JSON label/port maps via environment.
# ---------------------------------------------------------------------------

SYSTEM_SERVICE_UNITS: tuple[str, ...] = _env_csv(
    "SCC_SYSTEM_SERVICE_UNITS",
    ("docker.service", "NetworkManager.service"),
)
USER_SERVICE_UNITS: tuple[str, ...] = _env_csv("SCC_USER_SERVICE_UNITS", ())

IMPORTANT_SYSTEM_UNITS: tuple[str, ...] = _env_csv(
    "SCC_IMPORTANT_SYSTEM_UNITS",
    ("docker.service", "NetworkManager.service"),
)
IMPORTANT_USER_UNITS: tuple[str, ...] = _env_csv("SCC_IMPORTANT_USER_UNITS", ())
OPTIONAL_USER_UNITS: tuple[str, ...] = _env_csv("SCC_OPTIONAL_USER_UNITS", ())

_DEFAULT_SERVICE_LABELS: dict[str, str] = {
    "docker.service": "Docker Engine",
    "NetworkManager.service": "Network Manager",
    "cloudflared.service": "Cloudflare Tunnel",
}
SERVICE_LABELS: dict[str, str] = {
    **_DEFAULT_SERVICE_LABELS,
    **{str(k): str(v) for k, v in _env_json_dict("SCC_SERVICE_LABELS_JSON").items()},
}

SERVICE_PORTS: dict[str, int | None] = {}
for _unit, _port in _env_json_dict("SCC_SERVICE_PORTS_JSON").items():
    try:
        SERVICE_PORTS[str(_unit)] = None if _port is None else int(_port)
    except (TypeError, ValueError):
        continue

EXTRA_PROCESS_TARGETS: tuple[tuple[str, str], ...] = (
    ("cloudflared", "Cloudflare Tunnel"),
    ("llama-server", "Local AI / llama.cpp"),
)

# JSON object insertion order controls first-match precedence. Configuration is
# loaded at startup; deployment rules precede the generic argv rules.
PROCESS_LABELS: tuple[tuple[re.Pattern[str], str], ...] = _env_process_labels()
