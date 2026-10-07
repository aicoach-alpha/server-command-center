"""Optional UUID-tracked external storage collector.

UUID-based identity is authoritative. `/dev/sdX` is transient and used only
as telemetry. The collector resolves the current block device from
`/dev/disk/by-uuid/<UUID>` every cycle, so a path change from
`/dev/sdc1` → `/dev/sdd1` is reported as `DEVICE_PATH_CHANGED`,
NOT `DISCONNECTED`, unless the UUID itself disappears.

States:
    NOT_CONFIGURED      – no UUID configured; monitoring disabled, no alarm
    HEALTHY             – UUID present, /mnt/data mounted, source UUID matches, rw
    CONNECTED_UNMOUNTED – UUID present but /mnt/data not mounted
    DISCONNECTED        – UUID absent
    WRONG_DEVICE        – /mnt/data mounted but source UUID != expected
    READ_ONLY           – mounted rw=false
    IO_ERROR            – I/O errors detected in kernel log
    FILESYSTEM_ERROR    – EXT4 errors detected in kernel log
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from app.config import settings

log = logging.getLogger("scc.storage_external")

EXPECTED_UUID = settings.external_storage_uuid
EXPECTED_MOUNTPOINT = settings.external_storage_mountpoint
DEVICE_NAME = settings.external_storage_name
BY_UUID_PATH = f"/dev/disk/by-uuid/{EXPECTED_UUID}" if EXPECTED_UUID else ""


@dataclass
class StorageState:
    """Normalized state returned by every collection cycle."""

    health: str = "DISCONNECTED"
    connected: bool = False
    mounted: bool = False
    correct_uuid_mounted: bool = False
    current_device: str | None = None
    mountpoint: str | None = None
    filesystem: str | None = None
    mount_mode: str | None = None
    capacity_bytes: int = 0
    used_bytes: int = 0
    free_bytes: int = 0
    percent_used: float = 0.0
    serial_number: str | None = None
    transport: str | None = None
    model: str | None = None
    last_seen_at: float | None = None
    connected_since: float | None = None
    last_state_change_at: float | None = None
    last_mount_at: float | None = None
    last_disconnect_at: float | None = None
    last_event: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)


def _abbreviate_uuid(uuid: str | None) -> str:
    if not uuid or len(uuid) < 8:
        return uuid or ""
    return f"{uuid[:4]}…{uuid[-4:]}"


def _severity_for_state(state: str) -> str:
    mapping = {
        "HEALTHY": "info",
        "CONNECTED_UNMOUNTED": "warning",
        "DISCONNECTED": "critical",
        "WRONG_DEVICE": "critical",
        "READ_ONLY": "warning",
        "IO_ERROR": "critical",
        "FILESYSTEM_ERROR": "critical",
    }
    return mapping.get(state, "info")


def _run_cmd(argv: list[str], timeout: float = 3.0) -> tuple[int | None, str, str]:
    """Synchronous subprocess runner — safe to call from asyncio.to_thread."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None, "", "not-found"


def resolve_device_from_uuid() -> str | None:
    """Resolve the current /dev/sdX device from the persistent UUID path."""
    try:
        resolved = os.path.realpath(BY_UUID_PATH)
        if resolved and resolved != BY_UUID_PATH:
            return resolved
    except (OSError, ValueError):
        pass
    return None


def _find_parent_device(device: str) -> str | None:
    """Find the parent device of a partition.

    sdc1 -> sdc, sdd2 -> sdd, nvme0n1p1 -> nvme0n1, mmcblk0p1 -> mmcblk0
    """
    base = os.path.basename(device)
    # nvme0n1p1 -> nvme0n1, nvme0n1p2 -> nvme0n1
    if base.startswith("nvme"):
        idx = base.rfind("p")
        if idx > 0:
            return f"/dev/{base[:idx]}"
        return None
    # mmcblk0p1 -> mmcblk0, mmcblk0p2 -> mmcblk0
    if base.startswith("mmcblk"):
        idx = base.rfind("p")
        if idx > 0:
            return f"/dev/{base[:idx]}"
        return None
    # sdc1 -> sdc, sdc2 -> sdc, sdd1 -> sdd
    # For sdX[N], strip trailing digits
    m = re.match(r"^(sd[a-z]+)(\d+)$", base)
    if m:
        return f"/dev/{m.group(1)}"
    return None


def get_device_info(device: str | None) -> dict[str, Any]:
    """Get device info: filesystem type, serial, transport, model."""
    info: dict[str, Any] = {}
    if not device:
        return info

    # blkid for filesystem type and UUID verification
    rc, out, _ = _run_cmd(["blkid", device], timeout=2.0)
    if rc == 0 and out.strip():
        for token in out.split():
            if token.startswith("TYPE="):
                info["filesystem"] = token.split("=", 1)[1].strip('"')
            elif token.startswith("UUID="):
                info["uuid"] = token.split("=", 1)[1].strip('"')

    # lsblk for serial, transport, model on parent device
    parent = _find_parent_device(device)
    if parent:
        rc, out, _ = _run_cmd(
            ["lsblk", "-n", "-o", "NAME,SERIAL,TRAN,MODEL", parent],
            timeout=3.0,
        )
        if rc == 0 and out.strip():
            for line in out.strip().splitlines():
                cols = line.split()
                if cols and cols[0] == os.path.basename(parent):
                    if len(cols) >= 4:
                        serial = cols[1]
                        info["serial_number"] = serial if serial else None
                        transport = cols[2]
                        info["transport"] = transport if transport else None
                        model = " ".join(cols[3:])
                        info["model"] = model if model else None

    # Also check lsblk for the partition itself
    rc, out, _ = _run_cmd(
        ["lsblk", "-n", "-o", "NAME,FSTYPE,MOUNTPOINTS", device],
        timeout=3.0,
    )
    if rc == 0 and out.strip():
        cols = out.strip().split()
        if len(cols) >= 2 and cols[0] == os.path.basename(device):
            if not info.get("filesystem") and cols[1] and cols[1] != "0":
                info["filesystem"] = cols[1]

    return info


def get_mount_info(mountpoint: str) -> dict[str, Any] | None:
    """Get mount info using findmnt."""
    rc, out, _ = _run_cmd(
        ["findmnt", "-n", "-o", "SOURCE,TARGET,FSTYPE,OPTIONS", mountpoint],
        timeout=2.0,
    )
    if rc != 0 or not out.strip():
        return None

    parts = out.strip().split()
    if len(parts) < 4:
        return None

    return {
        "source": parts[0],
        "target": parts[1],
        "fstype": parts[2],
        "options": parts[3],
    }


def get_uuid_from_device(device: str | None) -> str | None:
    """Get the filesystem UUID of a device via blkid or lsblk."""
    if not device:
        return None

    # Try blkid first
    rc, out, _ = _run_cmd(["blkid", "-s", "UUID", "-o", "value", device], timeout=2.0)
    if rc == 0 and out.strip():
        return out.strip()

    # Fallback: use lsblk to get UUID
    rc, out, _ = _run_cmd(
        ["lsblk", "-n", "-o", "UUID", os.path.basename(device)],
        timeout=2.0,
    )
    if rc == 0 and out.strip():
        # Take the first non-empty line
        for line in out.strip().splitlines():
            uuid = line.strip()
            if uuid:
                return uuid
    return None


def get_filesystem_stats(path: str) -> dict[str, int]:
    """Get filesystem stats using os.statvfs for exact byte values."""
    try:
        stat = os.statvfs(path)
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        used = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
        return {"total": total, "used": used, "free": free}
    except (OSError, PermissionError):
        return {"total": 0, "used": 0, "free": 0}


def scan_kernel_errors(since_epoch: float) -> list[str]:
    """Scan kernel log for recent I/O and filesystem errors."""
    errors: list[str] = []
    since_ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since_epoch))
    rc, out, _ = _run_cmd(
        ["journalctl", "-k", "--since", since_ts, "--no-pager"],
        timeout=3.0,
    )
    if rc == 0 and out:
        for line in out.splitlines():
            line_lower = line.lower()
            if "i/o error" in line_lower or "buffer i/o error" in line_lower:
                if "IO_ERROR" not in errors:
                    errors.append("IO_ERROR")
            elif "ext4-fs error" in line_lower or "ext4-fs warning" in line_lower:
                if "FILESYSTEM_ERROR" not in errors:
                    errors.append("FILESYSTEM_ERROR")
            elif "usb disconnect" in line_lower:
                if "USB_DISCONNECT" not in errors:
                    errors.append("USB_DISCONNECT")
            elif "reset super" in line_lower or "reset high-speed" in line_lower:
                if "USB_RESET" not in errors:
                    errors.append("USB_RESET")
    return errors


class StorageExternalCollector:
    """Collects configured external storage state.

    Uses UUID as primary identity. `/dev/sdX` is resolved dynamically.
    Designed to run under asyncio.to_thread() like the existing StorageCollector.
    """

    def __init__(self) -> None:
        from app.services.storage_events import get_store
        self._event_store = get_store()
        self._last_device_path: str | None = None
        self._last_state: str | None = None
        self._last_seen_at: float | None = None
        self._connected_since: float | None = None
        self._last_state_change_at: float | None = None
        self._last_mount_at: float | None = None
        self._last_disconnect_at: float | None = None

    def collect(self) -> dict[str, Any]:
        """Collect current storage state synchronously (run via to_thread)."""
        if not EXPECTED_UUID:
            return {
                "available": False,
                "configured": False,
                "name": DEVICE_NAME,
                "health": "NOT_CONFIGURED",
                "connected": False,
                "mounted": False,
                "expected_mountpoint": EXPECTED_MOUNTPOINT,
                "reason": "Set SCC_EXTERNAL_STORAGE_UUID to enable UUID-tracked external storage.",
            }
        state = self._sample()
        self._transition(state)
        result = state.__dict__
        result.update({
            "name": DEVICE_NAME,
            "filesystem_uuid": EXPECTED_UUID,
            "by_uuid_path": BY_UUID_PATH,
            "abbreviated_uuid": _abbreviate_uuid(EXPECTED_UUID),
            "expected_mountpoint": EXPECTED_MOUNTPOINT,
            "available": True,
        })
        result.pop("errors", None)
        return result

    def _sample(self) -> StorageState:
        state = StorageState()
        now = time.time()

        # 1. Check UUID presence via /dev/disk/by-uuid/<UUID>
        uuid_present = os.path.exists(BY_UUID_PATH)

        if not uuid_present:
            state.health = "DISCONNECTED"
            state.connected = False
            state.last_seen_at = self._last_seen_at
            state.connected_since = self._connected_since
            state.last_state_change_at = self._last_state_change_at
            state.last_mount_at = self._last_mount_at
            state.last_disconnect_at = self._last_disconnect_at
            if self._last_state != "DISCONNECTED":
                state.last_disconnect_at = now
                self._last_disconnect_at = now
            return state

        # UUID exists; update timestamps
        state.last_seen_at = now
        if self._connected_since is None:
            state.connected_since = now
            self._connected_since = now
            state.last_state_change_at = now
            self._last_state_change_at = now
        else:
            state.connected_since = self._connected_since
            state.last_state_change_at = self._last_state_change_at

        self._last_seen_at = now
        state.connected = True

        # 2. Resolve current device path from UUID
        current_device = resolve_device_from_uuid()
        state.current_device = current_device

        # 3. Get device info
        dev_info = get_device_info(current_device)
        state.filesystem = dev_info.get("filesystem") or "ext4"
        state.serial_number = dev_info.get("serial_number")
        state.transport = dev_info.get("transport") or "usb"
        state.model = dev_info.get("model")

        # 4. Check mount status
        mount_info = get_mount_info(EXPECTED_MOUNTPOINT)

        if mount_info is None:
            state.health = "CONNECTED_UNMOUNTED"
            state.mounted = False
            state.errors = scan_kernel_errors(now - 300)
            return state

        # 5. Validate mount source UUID
        source_device = mount_info.get("source")
        mounted_uuid = get_uuid_from_device(source_device)

        state.mounted = True
        state.mountpoint = mount_info.get("target")
        state.filesystem = mount_info.get("fstype") or dev_info.get("filesystem") or "ext4"
        state.mount_mode = mount_info.get("options", "")

        # Check if the mounted source UUID matches expected
        correct_uuid = False
        if mounted_uuid:
            correct_uuid = mounted_uuid == EXPECTED_UUID
        elif source_device:
            # Fallback: check if source resolves to the by-uuid path
            try:
                resolved = os.path.realpath(source_device)
                if resolved == BY_UUID_PATH:
                    correct_uuid = True
            except OSError:
                pass

        state.correct_uuid_mounted = correct_uuid

        if not correct_uuid:
            state.health = "WRONG_DEVICE"
            state.errors = scan_kernel_errors(now - 300)
            return state

        if "ro" in (state.mount_mode or ""):
            state.health = "READ_ONLY"
            state.last_mount_at = self._last_mount_at or now
            self._last_mount_at = now
            state.errors = scan_kernel_errors(now - 300)
            return state

        # Check for I/O or filesystem errors
        errors = scan_kernel_errors(now - 300)
        state.errors = errors
        if "IO_ERROR" in errors:
            state.health = "IO_ERROR"
        elif "FILESYSTEM_ERROR" in errors:
            state.health = "FILESYSTEM_ERROR"
        else:
            state.health = "HEALTHY"
            if not self._last_mount_at or self._last_state != "HEALTHY":
                state.last_mount_at = now
                self._last_mount_at = now
                if self._last_state != "HEALTHY" and self._last_state:
                    state.last_state_change_at = now
                    self._last_state_change_at = now

        # 6. Get capacity from statvfs
        cap = get_filesystem_stats(EXPECTED_MOUNTPOINT)
        state.capacity_bytes = cap["total"]
        state.used_bytes = cap["used"]
        state.free_bytes = cap["free"]
        state.percent_used = round((cap["used"] / cap["total"]) * 100, 1) if cap["total"] else 0.0

        return state

    def _transition(self, state: StorageState) -> None:
        """Emit events on state transitions only."""
        new_state = state.health
        old_state = self._last_state

        if old_state is None:
            self._event_store.log_event(
                event_type="CONNECTED" if state.connected else "DISCONNECTED",
                severity="info" if state.connected else "critical",
                filesystem_uuid=EXPECTED_UUID,
                device_path=state.current_device,
                mountpoint=state.mountpoint,
                reason=f"Initial observation: {new_state}",
                details={"state": new_state, "name": DEVICE_NAME},
            )
            if state.mounted:
                self._event_store.log_event(
                    event_type="MOUNTED",
                    severity="info",
                    filesystem_uuid=EXPECTED_UUID,
                    device_path=state.current_device,
                    mountpoint=state.mountpoint,
                    reason=f"Mounted at {state.mountpoint}",
                    details={"mount_mode": state.mount_mode, "filesystem": state.filesystem},
                )
            self._last_state = new_state
            self._last_device_path = state.current_device
            return

        if new_state != old_state:
            self._last_state_change_at = time.time()
            self._event_store.log_event(
                event_type=new_state,
                severity=_severity_for_state(new_state),
                filesystem_uuid=EXPECTED_UUID,
                device_path=state.current_device,
                previous_device_path=self._last_device_path,
                mountpoint=state.mountpoint,
                reason=f"State changed: {old_state} -> {new_state}",
                details={
                    "old_state": old_state,
                    "new_state": new_state,
                    "last_seen_at": state.last_seen_at,
                },
            )

        # Check for device path change (same UUID, different /dev/sdX)
        if (
            state.connected
            and self._last_device_path
            and state.current_device
            and self._last_device_path != state.current_device
        ):
            self._event_store.log_event(
                event_type="DEVICE_PATH_CHANGED",
                severity="info",
                filesystem_uuid=EXPECTED_UUID,
                device_path=state.current_device,
                previous_device_path=self._last_device_path,
                reason=f"Device path changed: {self._last_device_path} -> {state.current_device}",
                details={
                    "old_path": self._last_device_path,
                    "new_path": state.current_device,
                    "filesystem_uuid": EXPECTED_UUID,
                },
            )

        # Special transition events
        if new_state == "HEALTHY" and old_state in ("IO_ERROR", "FILESYSTEM_ERROR"):
            self._event_store.log_event(
                event_type="RECOVERED",
                severity="info",
                filesystem_uuid=EXPECTED_UUID,
                device_path=state.current_device,
                reason=f"Recovered from {old_state}",
                details={"from": old_state, "to": new_state},
            )

        self._last_device_path = state.current_device
        self._last_state = new_state
