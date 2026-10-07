"""Mounted storage collector.

Discovers real mounted filesystems and enriches them with stable, low-cost block
metadata so the UI can distinguish internal disks from USB/external storage.
No benchmark, mount, unmount, or write operation is ever performed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import psutil

SKIP_FSTYPES = {
    "squashfs", "tmpfs", "devtmpfs", "overlay", "autofs", "proc", "sysfs",
    "cgroup2", "nsfs", "fuse.portal",
}

# Mounts that sort first in the overview. The root filesystem is always pinned;
# deployments can add extra important mounts via SCC_PINNED_MOUNTS (comma-separated).
# Additional real mounts are still shown, after the pinned ones.
PINNED: tuple[str, ...] = ("/",) + tuple(
    m.strip() for m in os.environ.get("SCC_PINNED_MOUNTS", "").split(",") if m.strip()
)


class StorageCollector:
    def __init__(self) -> None:
        self._block_cache: dict[str, dict] = {}

    def collect(self) -> dict:
        parts = self._partitions()
        disks = [d for d in (self._usage(mount, meta) for mount, meta in parts) if d]
        ordered = self._order(disks)
        return {
            "available": True,
            "disks": ordered,
            "count": len(ordered),
            "internal_count": sum(1 for d in ordered if d.get("kind") == "internal"),
            "external_count": sum(1 for d in ordered if d.get("kind") == "external"),
            "pinned": [d["mount"] for d in ordered if d["mount"] in PINNED],
        }

    @staticmethod
    def _partitions() -> list[tuple[str, dict]]:
        found: list[tuple[str, dict]] = []
        seen: set[str] = set()
        try:
            parts = psutil.disk_partitions(all=False)
        except (OSError, RuntimeError):
            parts = []

        for p in parts:
            if p.fstype in SKIP_FSTYPES:
                continue
            if not p.mountpoint.startswith("/"):
                continue
            if "/snap/" in p.mountpoint or p.mountpoint.count("/") > 3:
                continue
            if p.mountpoint in seen:
                continue
            seen.add(p.mountpoint)
            found.append(
                (
                    p.mountpoint,
                    {"device": p.device, "fstype": p.fstype, "options": p.opts},
                )
            )

        for pinned in PINNED:
            if pinned in seen or not os.path.isdir(pinned):
                continue
            seen.add(pinned)
            found.append((pinned, _mounts_entry(pinned)))
        return found

    def _usage(self, mount: str, meta: dict) -> dict | None:
        try:
            usage = psutil.disk_usage(mount)
        except (OSError, PermissionError):
            return None

        percent = round((usage.used / usage.total) * 100.0, 1) if usage.total else 0.0
        device = meta.get("device")
        block = self._block_metadata(device)
        options = meta.get("options") or ""
        read_only = "ro" in {part.strip() for part in options.split(",") if part.strip()}

        if percent >= 95:
            health = "critical"
        elif percent >= 85:
            health = "warning"
        elif read_only:
            health = "warning"
        else:
            health = "healthy"

        label = block.get("label")
        model = block.get("model")
        display_name = (
            "System Disk"
            if mount == "/"
            else label
            or model
            or (Path(mount).name if mount != "/" else "Storage")
        )

        return {
            "display_name": display_name,
            "mount": mount,
            "device": device,
            "parent_device": block.get("parent_device"),
            "fstype": meta.get("fstype"),
            "options": options,
            "read_only": read_only,
            "uuid": block.get("uuid"),
            "label": label,
            "model": model,
            "transport": block.get("transport"),
            "rotational": block.get("rotational"),
            "kind": block.get("kind"),
            "health": health,
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "percent": percent,
            "human": {
                "total": human(usage.total),
                "used": human(usage.used),
                "free": human(usage.free),
            },
        }

    def _block_metadata(self, device: str | None) -> dict:
        if not device or not device.startswith("/dev/"):
            return {"kind": "virtual"}
        resolved = os.path.realpath(device)
        base = os.path.basename(resolved)
        if base in self._block_cache:
            return self._block_cache[base]

        parent = _parent_block(base)
        model = _read_text(f"/sys/class/block/{parent}/device/model")
        rotational_raw = _read_text(f"/sys/class/block/{parent}/queue/rotational")
        rotational = None if rotational_raw is None else rotational_raw == "1"
        transport = _transport(parent)
        kind = "external" if transport == "usb" else "internal"

        result = {
            "parent_device": f"/dev/{parent}",
            "model": model.strip() if model else None,
            "transport": transport,
            "rotational": rotational,
            "kind": kind,
            "uuid": _name_for_target("/dev/disk/by-uuid", resolved),
            "label": _name_for_target("/dev/disk/by-label", resolved),
        }
        self._block_cache[base] = result
        return result

    @staticmethod
    def _order(disks: list[dict]) -> list[dict]:
        def key(d: dict) -> tuple[int, str]:
            mount = d["mount"]
            if mount in PINNED:
                return (PINNED.index(mount), "")
            return (len(PINNED), mount)

        return sorted(disks, key=key)


def _parent_block(base: str) -> str:
    sys_path = f"/sys/class/block/{base}"
    try:
        if os.path.exists(f"{sys_path}/partition"):
            return os.path.basename(os.path.dirname(os.path.realpath(sys_path)))
    except OSError:
        pass
    return base


def _transport(parent: str) -> str | None:
    if parent.startswith("nvme"):
        return "nvme"
    if parent.startswith("mmcblk"):
        return "mmc"
    device_path = os.path.realpath(f"/sys/class/block/{parent}/device")
    if "/usb" in device_path.lower():
        return "usb"
    try:
        result = subprocess.run(
            ["lsblk", "-dn", "-o", "TRAN", f"/dev/{parent}"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
        value = result.stdout.strip().splitlines()[0].strip() if result.stdout.strip() else ""
        return value or None
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def _read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None


def _name_for_target(directory: str, target: str) -> str | None:
    try:
        for item in Path(directory).iterdir():
            try:
                if os.path.realpath(item) == target:
                    return item.name
            except OSError:
                continue
    except OSError:
        pass
    return None


def _mounts_entry(mount: str) -> dict:
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[1] == mount:
                    return {
                        "device": parts[0],
                        "fstype": parts[2],
                        "options": parts[3],
                    }
    except OSError:
        pass
    return {"device": None, "fstype": None, "options": ""}


def human(num: float) -> str:
    step = 1024.0
    val = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(val) < step:
            return f"{val:.1f} {unit}"
        val /= step
    return f"{val:.1f} EiB"
