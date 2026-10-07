#!/usr/bin/env python3
"""Create/update a private SCC authentication environment file."""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.auth import hash_password  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="~/.config/server-command-center/auth.env")
    parser.add_argument("--username", default="admin")
    args = parser.parse_args()

    first = getpass.getpass("New dashboard password: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    if len(first) < 12:
        print("Use at least 12 characters.", file=sys.stderr)
        return 2

    path = Path(args.output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    existing: list[str] = []
    if path.exists():
        existing = [
            line for line in path.read_text().splitlines()
            if not line.startswith(("SCC_AUTH_", "SCC_SESSION_SECRET="))
        ]

    lines = [
        "SCC_AUTH_ENABLED=true",
        f"SCC_AUTH_USERNAME={args.username}",
        f'SCC_AUTH_PASSWORD_HASH="{hash_password(first)}"',
        f'SCC_SESSION_SECRET="{secrets.token_urlsafe(48)}"',
        "SCC_AUTH_SESSION_TTL_S=43200",
        *existing,
        "",
    ]
    path.write_text("\n".join(lines))
    os.chmod(path, 0o600)
    print(f"Wrote {path} with mode 0600")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
