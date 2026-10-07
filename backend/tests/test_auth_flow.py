"""End-to-end authentication flow tests.

Exercises the real FastAPI app (middleware, login, logout revocation and the
WebSocket gate) with authentication enabled, so the deployment's security
behaviour is covered rather than just the crypto primitives.
"""

from __future__ import annotations

import dataclasses

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import app.main as main_module
from app.auth import hash_password
from app.config import settings as base_settings

PASSWORD = "s3cret-pw"
COOKIE = "scc_session"


@pytest.fixture()
def cfg(monkeypatch):
    """A configured, auth-enabled Settings object patched into app.main."""
    configured = dataclasses.replace(
        base_settings,
        auth_enabled=True,
        auth_username="tester",
        auth_password_hash=hash_password(PASSWORD, iterations=10_000),
        session_secret="unit-test-session-secret",
        auth_session_ttl_s=60,
        auth_cookie_name=COOKIE,
    )
    monkeypatch.setattr(main_module, "settings", configured)
    main_module._revoked_sessions.clear()
    main_module.login_guard._failures.clear()
    main_module.login_guard._locked_until.clear()
    return configured


@pytest.fixture()
def client(cfg):
    with TestClient(main_module.app) as c:
        yield c


def login(client: TestClient, password: str = PASSWORD) -> str:
    r = client.post("/api/auth/login", json={"username": "tester", "password": password})
    assert r.status_code == 200, r.text
    token = client.cookies.get(COOKIE) or r.cookies.get(COOKIE)
    assert token
    return token


# ---------------------------------------------------------------------------
# REST gate
# ---------------------------------------------------------------------------
def test_unauthenticated_rest_rejected(client):
    assert client.get("/api/storage").status_code == 401
    assert client.get("/api/snapshot").status_code == 401


def test_me_reports_unauthenticated_without_cookie(client):
    body = client.get("/api/auth/me").json()
    assert body["authenticated"] is False
    assert body["username"] is None


def test_wrong_password_rejected(client):
    r = client.post("/api/auth/login", json={"username": "tester", "password": "nope"})
    assert r.status_code == 401
    assert "scc_session" not in r.cookies


def test_correct_login_accepted_and_rest_allowed(client):
    login(client)
    assert client.get("/api/auth/me").json()["authenticated"] is True
    assert client.get("/api/storage").status_code == 200
    assert client.get("/api/snapshot").status_code == 200


def test_tampered_session_rejected(client):
    token = login(client)
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    assert client.get("/api/storage", cookies={COOKIE: tampered}).status_code == 401


# ---------------------------------------------------------------------------
# Logout revocation
# ---------------------------------------------------------------------------
def test_logout_invalidates_the_session(client):
    token = login(client)
    assert client.get("/api/storage", cookies={COOKIE: token}).status_code == 200

    assert client.post("/api/auth/logout", cookies={COOKIE: token}).status_code == 200

    # The very same token must now be refused, even if a client replays it.
    assert client.get("/api/storage", cookies={COOKIE: token}).status_code == 401
    me = client.get("/api/auth/me", cookies={COOKIE: token}).json()
    assert me["authenticated"] is False


# ---------------------------------------------------------------------------
# WebSocket gate
# ---------------------------------------------------------------------------
def test_websocket_rejected_without_session(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/metrics"):
            pass


def test_websocket_accepted_with_valid_session(client):
    token = login(client)
    with client.websocket_connect("/ws/metrics", cookies={COOKIE: token}) as ws:
        frame = ws.receive_json()
        assert "cpu" in frame and "meta" in frame


def test_websocket_rejected_after_logout(client):
    token = login(client)
    client.post("/api/auth/logout", cookies={COOKIE: token})
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/metrics", cookies={COOKIE: token}):
            pass


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
def test_rate_limiter_locks_out_after_repeated_failures(client):
    for _ in range(main_module.login_guard.max_attempts):
        assert client.post(
            "/api/auth/login", json={"username": "tester", "password": "wrong"}
        ).status_code == 401

    r = client.post("/api/auth/login", json={"username": "tester", "password": PASSWORD})
    assert r.status_code == 429
    assert "Retry-After" in r.headers
