"""Friendly application-name resolution.

A raw `ps aux` on this host shows a wall of `python`, `python`, `node`, `node`.
This module turns a PID into something an operator recognises, using only
read-only sources:

    /proc/<pid>/cmdline   -> what it is running
    /proc/<pid>/cgroup    -> systemd unit (both v1 and v2 layouts) or container id
    /proc/<pid>/exe       -> real binary behind an interpreter
    psutil                -> cwd, username, create_time

Priority: known container identity, configured argv labels, generic argv rules,
systemd ownership, then process-name and interpreter fallbacks.

No PID is ever hardcoded. Resolution is derived per sample.
"""

from __future__ import annotations

import logging
import os
import re

import psutil

from app.config import PROCESS_LABELS, SERVICE_LABELS
from app.utils.redact import redact_cmdline

log = logging.getLogger("scc.friendly")

# cgroup v2 on Ubuntu:
#   /user.slice/user-1000.slice/user@1000.service/app.slice/example-api.service
# The owning unit is ALWAYS the LAST path segment. Matching on a generic
# `.service` pattern is wrong: intermediate segments such as `user@1000.service`
# also end in `.service` and would win, labelling every user process as
# "user@1000". Anchoring to the final segment is what makes this correct.
_CGROUP_V2_UNIT = re.compile(r"(?:^|/)(?P<unit>[^/]+\.service)$")
# cgroup v1: /system.slice/foo.service  or  /system.slice/docker-<id>.scope
_CGROUP_V1_UNIT = re.compile(r"(?:^|/)(?P<unit>[^/]+\.service)$")
_DOCKER_CGROUP = re.compile(r"docker[-/](?P<id>[0-9a-f]{12,64})(?:\.scope)?$")

# Ordered (pattern, friendly name). First match wins.
ARGV_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"llama-server"), "Local AI / llama.cpp"),

    (re.compile(r"\bnext-server\b|\bnext start\b|next/dist/bin/next"), "Next.js Server"),
    (re.compile(r"\bcloudflared\b.*tunnel\b"), "Cloudflare Tunnel"),
    (re.compile(r"\bglances\b.*-w\b"), "Glances Web"),
    (re.compile(r"opencode\s+serve"), "OpenCode Server"),

    (re.compile(r"redis-server"), "Redis"),
    (re.compile(r"\bapache2\b|\bhttpd\b"), "Apache HTTPD"),
    (re.compile(r"\bmariadbd?\b|\bmysqld\b"), "MariaDB"),
    (re.compile(r"\bclamd\b"), "ClamAV Daemon"),
    (re.compile(r"\bdockerd\b"), "Docker Engine"),
    (re.compile(r"\bcontainerd\b"), "containerd"),
    (re.compile(r"\btailscaled\b"), "Tailscale"),
    (re.compile(r"\bpihole-FTL\b"), "Pi-hole FTL"),
    (re.compile(r"casaos"), "CasaOS"),
    (re.compile(r"\bsamba|\bsmbd\b|\bnmbd\b"), "Samba"),
)

# Known process names that are self-explanatory.
NAME_MAP: dict[str, str] = {
    "llama-server": "Local AI / llama.cpp",
    "cloudflared": "Cloudflare Tunnel",
    "dockerd": "Docker Engine",
    "containerd": "containerd",
    "redis-server": "Redis",
    "glances": "Glances Web",
    "next-server": "Next.js Server",
    "pihole-FTL": "Pi-hole FTL",
    "mariadbd": "MariaDB",
    "clamd": "ClamAV Daemon",
    "apache2": "Apache HTTPD",
    "tailscaled": "Tailscale",
    "sshd": "OpenSSH Server",
    "systemd": "systemd",
    "kthreadd": "Linux Kernel Thread",
}

# Interpreter processes get a better name when we can see what they run.
INTERPRETERS = {"python", "python3", "python3.14", "python3.13", "node", "bash", "sh", "ruby", "deno"}


def read_cgroup(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cgroup", "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def unit_from_cgroup(cgroup_text: str) -> str | None:
    """Extract the systemd unit name from cgroup content (v1 or v2)."""
    if not cgroup_text:
        return None
    m = _CGROUP_V2_UNIT.search(cgroup_text) or _CGROUP_V1_UNIT.search(cgroup_text)
    return m.group("unit") if m else None


def docker_id_from_cgroup(cgroup_text: str) -> str | None:
    if not cgroup_text:
        return None
    m = _DOCKER_CGROUP.search(cgroup_text)
    return m.group("id") if m else None


def read_cmdline(pid: int) -> list[str]:
    try:
        raw = open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        return []
    parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\0") if p]
    return parts


def _argv_joined(argv: list[str]) -> str:
    return " ".join(argv)


class FriendlyResolver:
    """Resolves PID -> friendly display name with a per-(pid, mtime) cache.

    Resolution hits /proc, so it is cached: a process's cmdline and cgroup do
    not change for the lifetime of the process. The cache is keyed by
    (pid, process create_time) so PID reuse cannot produce a stale name.
    """

    def __init__(self, container_names: dict[str, str] | None = None) -> None:
        self._cache: dict[tuple[int, float], dict] = {}
        self._container_names = container_names or {}

    def update_containers(self, names: dict[str, str]) -> None:
        """Container id prefix -> name, refreshed on the slow tick."""
        self._container_names = names
        # Container identity can change for a live PID; drop the cache.
        self._cache.clear()

    def resolve(self, proc: psutil.Process, argv: list[str] | None = None) -> dict:
        try:
            created = proc.create_time()
        except (psutil.Error, OSError):
            created = 0.0

        key = (proc.pid, created)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        if argv is None:
            try:
                argv = proc.cmdline()
            except (psutil.Error, OSError):
                argv = []

        name = proc.name() if _safe_name(proc) else None
        cgroup = read_cgroup(proc.pid)
        unit = unit_from_cgroup(cgroup)
        container_id = docker_id_from_cgroup(cgroup)
        joined = _argv_joined(argv)

        display_name, source, service = self._decide(name, joined, unit, container_id, cgroup)

        result = {
            "pid": proc.pid,
            "process_name": name or (argv[0] if argv else None),
            "display_name": display_name,
            "source": source,
            "service": service,
            "container": self._container_names.get(container_id[:12]) if container_id else None,
            "container_id": container_id[:12] if container_id else None,
            "cmdline": redact_cmdline(argv),
        }
        self._cache[key] = result
        return result

    def _decide(
        self,
        name: str | None,
        joined: str,
        unit: str | None,
        container_id: str | None,
        cgroup: str,
    ) -> tuple[str, str, str | None]:
        # 1. Container identity wins outright. A containerised process belongs
        #    to its container, not to whatever binary happens to run inside it
        #    (e.g. clamd inside the `poste` container must read as the container).
        if container_id:
            container = self._container_names.get(container_id[:12])
            if container:
                return f"Docker: {container}", "docker", unit

        # 2. Deployment-specific labels precede generic rules. An argv rule
        #    can distinguish children that inherit the same coarse unit label.
        for pattern, label in (*PROCESS_LABELS, *ARGV_RULES):
            if pattern.search(joined):
                return label, "argv", unit

        # 3. systemd ownership is the authoritative fallback.
        if unit:
            label = SERVICE_LABELS.get(unit)
            if label:
                return label, "systemd", unit
            if unit.startswith("docker-"):
                container = self._container_names.get(unit[:19]) or self._container_names.get(
                    (container_id or "")[:12]
                )
                if container:
                    return f"Docker: {container}", "docker", None
            # A unit we have no label for is still better than a bare binary
            # name, but never surface the generic slice wrappers.
            if not unit.startswith(("user@", "user-", "system-", "init.scope")):
                return unit.replace(".service", ""), "systemd", unit

        # 4. Known process names.
        if name and name in NAME_MAP:
            return NAME_MAP[name], "name", None

        # 5. A bare interpreter is useless; try harder before giving up.
        if name and name in INTERPRETERS:
            hint = _interpreter_hint(joined)
            if hint:
                return hint, "argv", unit

        # 6. Docker cgroup we could not name.
        if "docker" in cgroup:
            return "Docker container", "docker", None

        return name or "unknown", "process", unit


def _safe_name(proc: psutil.Process) -> bool:
    try:
        proc.name()
        return True
    except (psutil.Error, OSError):
        return False


def _interpreter_hint(joined: str) -> str | None:
    """Derive something better than `python` from an interpreter's argv."""
    if re.search(r"\bnext-server\b", joined):
        return "Next.js Server"

    # A script/module name is still more useful than the interpreter.
    m = re.search(r"(?:-m\s+([\w.]+)|([/\w.-]+\.py))", joined)
    if m:
        candidate = m.group(1) or m.group(2)
        return os.path.basename(candidate)
    return None