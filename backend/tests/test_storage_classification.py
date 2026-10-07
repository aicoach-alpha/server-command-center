"""Storage classification + external-monitor tests."""
from __future__ import annotations

from app.collectors.storage import StorageCollector, SKIP_FSTYPES
from app.collectors.storage_external import StorageExternalCollector


def test_skip_filesystems_filter_virtual() -> None:
    """Virtual filesystems must be excluded from the storage overview."""
    expected_virtual = {
        "squashfs", "tmpfs", "devtmpfs", "overlay", "autofs",
        "proc", "sysfs", "cgroup2", "nsfs", "fuse.portal",
    }
    assert expected_virtual.issubset(SKIP_FSTYPES)


def test_storage_collector_classifies_internal_and_external() -> None:
    """Live collector must report integer internal/external counts."""
    c = StorageCollector()
    snap = c.collect()
    assert snap["available"] is True
    assert isinstance(snap["internal_count"], int)
    assert isinstance(snap["external_count"], int)
    # On this host we expect at least 1 internal and 1 external.
    assert snap["internal_count"] >= 1
    assert snap["external_count"] >= 1


def test_storage_collector_filters_virtual_filesystems() -> None:
    """No virtual filesystem should appear in the disks list."""
    c = StorageCollector()
    snap = c.collect()
    for disk in snap["disks"]:
        assert disk["fstype"] not in SKIP_FSTYPES


def test_storage_collector_health_thresholds() -> None:
    """Health must follow: <85% healthy, 85-94.9% warning, >=95% critical."""
    c = StorageCollector()
    snap = c.collect()
    for disk in snap["disks"]:
        pct = disk["percent"]
        if pct >= 95:
            assert disk["health"] == "critical"
        elif pct >= 85:
            assert disk["health"] == "warning"
        elif disk["read_only"]:
            assert disk["health"] == "warning"
        else:
            assert disk["health"] == "healthy"


def test_storage_collector_read_only_is_warning() -> None:
    """A read-only filesystem must report warning health."""
    c = StorageCollector()
    snap = c.collect()
    for disk in snap["disks"]:
        if disk["read_only"]:
            assert disk["health"] == "warning"


def test_storage_collector_pinned_mounts_first() -> None:
    """Every configured pinned mount that is present must be reported as pinned."""
    from app.collectors.storage import PINNED

    c = StorageCollector()
    snap = c.collect()
    pinned = snap.get("pinned", [])
    for mount in PINNED:
        if any(d["mount"] == mount for d in snap["disks"]):
            assert mount in pinned


def test_storage_collector_root_is_always_pinned() -> None:
    """The root filesystem is a generic default and must always be pinned first."""
    from app.collectors.storage import PINNED

    assert "/" in PINNED
    c = StorageCollector()
    snap = c.collect()
    if any(d["mount"] == "/" for d in snap["disks"]):
        assert snap["disks"][0]["mount"] == "/"


def test_external_not_configured_is_noncritical(monkeypatch) -> None:
    """When SCC_EXTERNAL_STORAGE_UUID is blank, health must be NOT_CONFIGURED."""
    import app.collectors.storage_external as se

    # Patch the module-level constant that the collector reads.
    monkeypatch.setattr(se, "EXPECTED_UUID", "")
    collector = se.StorageExternalCollector()
    snap = collector.collect()
    assert snap["health"] == "NOT_CONFIGURED"
    assert snap["configured"] is False
    assert snap["connected"] is False
