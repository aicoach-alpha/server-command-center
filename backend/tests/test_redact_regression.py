"""Regression tests for secret redaction and the secret detector in test_api_smoke.

Covers:
  * Bare 32-hex tokens → flagged as secret-looking
  * Hex strings embedded in file paths → NOT flagged (false-positive guard)
  * Real credential formats → redacted by redact_text/redact_cmdline
"""

from __future__ import annotations

import re

import pytest

from app.utils.redact import redact_cmdline, redact_text


# Mirrors the regex in test_api_smoke.test_no_secret_material_in_any_endpoint.
SECRET_RE = re.compile(r"(?<![A-Za-z0-9/._\\])[a-f0-9]{32}(?![A-Za-z0-9/._\\])")


# ---------------------------------------------------------------------------
# Secret detector regex regression tests
# ---------------------------------------------------------------------------
class TestSecretDetectorRegex:
    def test_bare_32_hex_is_secret(self):
        body = '{"key": "048ed022fcde25ed8a8b97e9463c3f8a"}'
        matches = SECRET_RE.findall(body)
        assert "048ed022fcde25ed8a8b97e9463c3f8a" in matches

    def test_hex_in_path_is_not_secret(self):
        body = '{"cmdline": ["/home/user/.agent/cache/scratch/048ed022fcde25ed8a8b97e9463c3f8a/entrypoint"]}'
        assert SECRET_RE.findall(body) == []

    def test_hex_in_path_with_dot_is_not_secret(self):
        body = '{"cmdline": ["/var/lib/app/.cache/abcdef0123456789abcdef0123456789/config.json"]}'
        assert SECRET_RE.findall(body) == []

    def test_hex_in_env_var_is_flagged(self):
        # Standalone hex value (not embedded in path) — flagged as suspicious.
        body = 'export CACHE_HASH=abcdef0123456789abcdef0123456789'
        matches = SECRET_RE.findall(body)
        assert "abcdef0123456789abcdef0123456789" in matches

    def test_real_bearer_token_is_redacted(self):
        body = redact_text("Authorization: Bearer sk-1234567890abcdef1234567890abcdef")
        # The secret detector might still match a bare hex in output,
        # but redact_text should have replaced the token.
        assert "sk-1234567890abcdef1234567890abcdef" not in body

    def test_tuya_key_shape_would_be_caught(self):
        # A bare 32-char lowercase alnum key (Tuya shape) not embedded in a path.
        body = '{"tuya_key": "0123456789abcdef0123456789abcdef"}'
        matches = SECRET_RE.findall(body)
        assert "0123456789abcdef0123456789abcdef" in matches


# ---------------------------------------------------------------------------
# redact_text regression tests
# ---------------------------------------------------------------------------
class TestRedactText:
    def test_password_assignment(self):
        out = redact_text("PASSWORD=abcdef0123456789abcdef0123456789")
        assert "***REDACTED***" in out
        assert "abcdef0123456789abcdef0123456789" not in out

    def test_bearer_token(self):
        out = redact_text("Authorization: Bearer eyJhbGci.eyJzdWI.AbcDEFghiJK")
        assert "***REDACTED***" in out

    def test_api_key_prefix(self):
        out = redact_text("API_KEY=sk-1234567890abcdef1234567890abcdef")
        assert "***REDACTED***" in out
        assert "sk-1234567890abcdef1234567890abcdef" not in out

    def test_bearer_assignment(self):
        out = redact_text("TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzAB")
        assert "***REDACTED***" in out

    def test_path_with_hex_not_redacted(self):
        path = "/home/user/.agent/cache/scratch/048ed022fcde25ed8a8b97e9463c3f8a/entrypoint"
        out = redact_text(path)
        assert "048ed022fcde25ed8a8b97e9463c3f8a" in out  # path preserved
        assert "***REDACTED***" not in out

    def test_aws_key_pattern(self):
        out = redact_text("AKIAIOSFODNN7EXAMPLE")
        assert "***REDACTED***" in out


# ---------------------------------------------------------------------------
# redact_cmdline regression tests
# ---------------------------------------------------------------------------
class TestRedactCmdline:
    def test_scratch_dir_path_preserved(self):
        argv = ["/usr/bin/opencode", "serve", "--workspace", "/home/user/.agent/cache/scratch/048ed022fcde25ed8a8b97e9463c3f8a/x"]
        out = redact_cmdline(argv)
        assert out[0] == "/usr/bin/opencode"
        assert "048ed022fcde25ed8a8b97e9463c3f8a" in out[3]
        assert "***REDACTED***" not in out[3]

    def test_password_flag_redacted(self):
        argv = ["--password", "hunter2"]
        out = redact_cmdline(argv)
        assert out == ["--password", "***REDACTED***"]

    def test_password_equals_redacted(self):
        argv = ["--password=hunter2"]
        out = redact_cmdline(argv)
        assert out == ["--password=***REDACTED***"]

    def test_non_secret_flag_value_preserved(self):
        argv = ["--port", "18080", "--working-dir", "/tmp/foo"]
        out = redact_cmdline(argv)
        assert out == ["--port", "18080", "--working-dir", "/tmp/foo"]
