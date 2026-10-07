"""Minimal authentication helpers for Server Command Center.

Uses PBKDF2-SHA256 for password verification and an HMAC-signed, expiring
session cookie. No third-party auth dependency is required.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


PBKDF2_ITERATIONS = 600_000


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_s, salt_s, digest_s = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = _b64d(salt_s)
        expected = _b64d(digest_s)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_session(username: str, secret: str, ttl_s: int) -> str:
    payload = {
        "u": username,
        "exp": int(time.time()) + int(ttl_s),
        "n": secrets.token_hex(8),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    body = _b64e(raw)
    sig = _b64e(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_session(token: str | None, secret: str, expected_username: str) -> bool:
    if not token or not secret or "." not in token:
        return False
    try:
        body, sig = token.rsplit(".", 1)
        expected_sig = _b64e(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected_sig):
            return False
        payload = json.loads(_b64d(body))
        if payload.get("u") != expected_username:
            return False
        return int(payload.get("exp", 0)) > int(time.time())
    except (ValueError, TypeError, json.JSONDecodeError):
        return False


def token_fingerprint(token: str | None) -> str:
    """Stable, non-reversible fingerprint of a session token.

    Used as the key for server-side revocation so a replayed token can be
    rejected after logout without ever storing the token itself.
    """
    if not token:
        return ""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class LoginGuard:
    max_attempts: int = 5
    window_s: int = 300
    lockout_s: int = 900

    def __post_init__(self) -> None:
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def allowed(self, key: str) -> tuple[bool, int]:
        now = time.time()
        locked_until = self._locked_until.get(key, 0)
        if locked_until > now:
            return False, max(1, int(locked_until - now))
        recent = [t for t in self._failures.get(key, []) if now - t <= self.window_s]
        self._failures[key] = recent
        return True, 0

    def failure(self, key: str) -> None:
        now = time.time()
        failures = [t for t in self._failures.get(key, []) if now - t <= self.window_s]
        failures.append(now)
        self._failures[key] = failures
        if len(failures) >= self.max_attempts:
            self._locked_until[key] = now + self.lockout_s
            self._failures[key] = []

    def success(self, key: str) -> None:
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)
