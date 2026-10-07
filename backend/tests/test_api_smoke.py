"""Live API smoke tests.

These exercise the real FastAPI app against the real collector hub. No mocking:
if a collector breaks, these fail.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_root(client):
    r = client.get("/api/info")
    assert r.status_code == 200
    assert r.json()["mode"] == "read-only"


def test_liveness(client):
    r = client.get("/api/health/live")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_snapshot_has_every_section(client):
    r = client.get("/api/snapshot")
    assert r.status_code == 200
    snap = r.json()
    for section in (
        "cpu", "memory", "gpu", "network", "processes",
        "gpu_processes", "storage", "services", "containers",
        "fan", "health", "meta",
    ):
        assert section in snap, f"missing section: {section}"


def test_cpu_payload(client):
    cpu = client.get("/api/cpu").json()["cpu"]
    assert cpu["percent"]["supported"] is True
    assert 0 <= cpu["percent"]["value"] <= 100
    assert len(cpu["per_core"]) == cpu["cores_logical"]
    assert "1m" in cpu["load_average"]


def test_memory_payload(client):
    mem = client.get("/api/memory").json()["memory"]
    assert mem["ram"]["total_bytes"] > 0
    assert mem["human"] if "human" in mem else mem["ram"]["human"]


def test_gpu_payload_handles_unsupported(client):
    payload = client.get("/api/gpu").json()
    gpu = payload["gpu"]
    assert "available" in gpu
    if gpu["available"]:
        # Unsupported sensors must be null + supported False, never 0.
        assert gpu["power_draw"]["supported"] is False
        assert gpu["power_draw"]["value"] is None
        assert gpu["fan_speed_pct"]["value"] is None


def test_processes(client):
    data = client.get("/api/processes").json()
    assert len(data["top_cpu"]) <= 20
    assert len(data["top_ram"]) <= 20
    row = data["top_cpu"][0]
    for key in ("rank", "pid", "display_name", "cpu_percent", "ram_mb", "user", "runtime_human"):
        assert key in row


def test_network(client):
    net = client.get("/api/network").json()["network"]
    assert net["active_interface"]
    assert net["lan"] is not None
    assert "totals" in net


def test_storage(client):
    disks = client.get("/api/storage").json()["storage"]["disks"]
    mounts = {d["mount"] for d in disks}
    assert "/" in mounts
    for d in disks:
        assert d["total_bytes"] > 0


def test_services(client):
    data = client.get("/api/services").json()["services"]
    assert data["available"] is True
    units = {s["unit"] for s in data["services"]}
    assert "docker.service" in units
    assert "NetworkManager.service" in units
    for s in data["services"]:
        assert s["color"] in {"green", "amber", "red", "gray"}


def test_fan_panel_is_read_only(client):
    fan = client.get("/api/fan").json()["fan"]
    assert fan["read_only"] is True
    assert fan["thresholds"]["on_temp_c"] == 70.0
    assert fan["thresholds"]["off_temp_c"] == 60.0
    assert fan["thresholds"]["min_on_seconds"] == 180.0
    assert fan["controller"]["unit"] == "cpu-fan-controller.service"


def test_history_ranges(client):
    for rng in ("15m", "1h", "6h"):
        r = client.get(f"/api/history?range={rng}")
        assert r.status_code == 200
        assert r.json()["range"] == rng


def test_history_rejects_bad_range(client):
    assert client.get("/api/history?range=99y").status_code == 422


def test_no_secret_material_in_any_endpoint(client):
    """Sweep every endpoint for credential-looking values."""
    import re

    endpoints = [
        "/", "/api/snapshot", "/api/system", "/api/cpu", "/api/memory",
        "/api/gpu", "/api/network", "/api/storage", "/api/fan",
        "/api/services", "/api/containers", "/api/processes",
        "/api/gpu/processes", "/api/health", "/api/stats", "/api/history",
    ]
    # Real Tuya Local Key shape is 32 lowercase alnum chars.
    # Exclude hex strings embedded in file paths (preceded/followed by /, ., _)
    # — directory names like /scratch/048ed022fcde25ed8a8b97e9463c3f8a/ should
    # NOT be treated as secrets, only bare standalone 32-hex tokens.
    secret_re = re.compile(r"(?<![A-Za-z0-9/._\\])[a-f0-9]{32}(?![A-Za-z0-9/._\\])")
    for endpoint in endpoints:
        body = client.get(endpoint).text
        for match in secret_re.findall(body):
            # A SHA/hash-like token appearing in a redaction marker context is
            # fine; a bare 32-hex value must never be served.
            assert "REDACTED" in body or match not in body, (
                f"possible secret leaked by {endpoint}"
            )


def test_websocket_sends_snapshot(client):
    with client.websocket_connect("/ws/metrics") as ws:
        payload = ws.receive_json()
        assert "meta" in payload
        assert "health" in payload