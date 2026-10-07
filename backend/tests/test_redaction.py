"""Tests for secret redaction.

The critical property: a credential must never survive redaction, while
non-secret context (like a key FILE PATH) must survive so the dashboard stays
diagnosable.
"""

from __future__ import annotations

from app.utils.redact import REDACTED, redact_cmdline, redact_text


class TestRedactText:
    def test_inline_assignment(self):
        assert redact_text("--api-key=sk-abc123") == f"--api-key={REDACTED}"

    def test_space_separated_in_text(self):
        out = redact_text("run with --password hunter2 now")
        assert "hunter2" not in out
        assert REDACTED in out

    def test_env_style(self):
        out = redact_text("TUYA_LOCAL_KEY=abcdef123456")
        assert "abcdef123456" not in out
        assert "TUYA_LOCAL_KEY" in out

    def test_bearer_header(self):
        out = redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
        assert "eyJhbGciOiJIUzI1NiJ9" not in out
        assert "Authorization" in out

    def test_openai_style_key(self):
        out = redact_text("key is sk-abcdefghijklmnopqrstuvwxyz")
        assert "sk-abcdefghijklmnopqrstuvwxyz" not in out

    def test_github_pat(self):
        out = redact_text("ghp_abcdefghijklmnopqrstuvwxyz012345")
        assert "ghp_abcdefghijklmnopqrstuvwxyz012345" not in out

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
        out = redact_text(f"token {jwt}")
        assert jwt not in out

    def test_harmless_text_untouched(self):
        text = "/home/user/example_prod/current/venv/bin/python -m uvicorn api.app:create_app"
        assert redact_text(text) == text

    def test_empty_and_none(self):
        assert redact_text("") == ""
        assert redact_text(None) == ""


class TestRedactCmdline:
    def test_real_llama_server_cmdline_keeps_key_file_path(self):
        """A representative argv uses a key-file path, not a secret value.

        `--api-key-file /home/user/.config/example/llama-api-key` carries no
        secret material - it is a path. It MUST survive so operators can see
        which key file is in use.
        """
        argv = [
            "/home/user/example_ops/deployments/local-ai-router/bin/llama-server",
            "--api-key-file",
            "/home/user/.config/example/llama-api-key",
            "--host",
            "127.0.0.1",
            "--port",
            "58923",
            "--model",
            "/mnt/data/models/example-model.gguf",
        ]
        out = redact_cmdline(argv)

        assert out == argv
        assert "/home/user/.config/example/llama-api-key" in out
        assert "--port" in out and "58923" in out

    def test_inline_secret_argv(self):
        out = redact_cmdline(["prog", "--api-key=supersecretvalue", "--port", "8080"])
        assert "supersecretvalue" not in out
        assert out[0] == "prog"
        assert out[1] == f"--api-key={REDACTED}"
        # Boundaries preserved.
        assert len(out) == 4
        assert out[2] == "--port"
        assert out[3] == "8080"

    def test_space_separated_secret_argv(self):
        out = redact_cmdline(["prog", "--password", "hunter2", "--verbose"])
        assert out == ["prog", "--password", REDACTED, "--verbose"]

    def test_space_separated_secret_followed_by_flag(self):
        """A missing value must not cause the next flag to be eaten."""
        out = redact_cmdline(["prog", "--token", "--other", "value"])
        assert out == ["prog", "--token", "--other", "value"]

    def test_env_argv(self):
        out = redact_cmdline(["prog", "SECRET_TOKEN=abcdefghijklm"])
        assert "abcdefghijklm" not in out

    def test_empty_and_none(self):
        assert redact_cmdline([]) == []
        assert redact_cmdline(None) == []


class TestNoSecretSurfaces:
    def test_local_key_never_returned(self):
        """A realistic worst case: a Tuya-style invocation in argv."""
        argv = [
            "python",
            "controller.py",
            "--local-key",
            "abcdefghijklmnopqrstuvwx",
        ]
        joined = " ".join(redact_cmdline(argv))
        assert "abcdefghijklmnopqrstuvwx" not in joined

    def test_namespaced_env_vars_are_redacted(self):
        """`TUYA_LOCAL_KEY=` must be caught despite the `_` before LOCAL."""
        for name in ("TUYA_LOCAL_KEY", "OPENAI_API_KEY", "EXAMPLE_BETA_SECRET"):
            out = redact_text(f"{name}=supersecretvalue123")
            assert "supersecretvalue123" not in out, name
            assert name in out, name

    def test_namespaced_env_vars_in_argv(self):
        for name in ("TUYA_LOCAL_KEY", "GITHUB_TOKEN", "DB_PASSWORD"):
            out = redact_cmdline(["prog", f"{name}=supersecretvalue123"])
            assert "supersecretvalue123" not in out, name

    def test_device_id_is_not_treated_as_a_secret(self):
        """A device ID is an identifier, not a credential.

        The panel legitimately shows device IDs; redacting them would make the
        Tuya section undiagnosable while protecting nothing.
        """
        out = redact_cmdline(["prog", "--device-id", "12345678901234567890abcdef"])
        assert "12345678901234567890abcdef" in out
