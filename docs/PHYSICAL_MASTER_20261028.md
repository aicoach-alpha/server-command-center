# Physical master deployment — 2026-10-28

The Server Command Center live deployment uses a physical repository at
`/home/andre/projects/infrastructure/server-command-center`, not a symlink to
the old home directory. Its user systemd drop-in is
`~/.config/systemd/user/scc-server-command-center.service.d/99-projects-master.conf`.
The existing auth environment file remains separate under
`~/.config/server-command-center/auth.env`.

The Python venv entrypoints were rewritten for the physical path, the user
systemd service restarted twice, and HTTP `/` returned 200 with the original
`/home/andre/server-command-center` alias removed. Pre-existing uncommitted
changes in `scripts/setup-auth.py` were preserved. Migration receipts are
stored outside this Git repo at
`/home/andre/projects/infrastructure/audits/scc-physical-master-20261028.json`.

## Regression gates

Run from this repository root:

```bash
backend/.venv/bin/python -m pytest -q backend/tests
```

Historical 2026-10-05 kernel journal assertions require archived evidence.
If `journalctl -k` has rotated away those records or the caller has no
access, the two archive-specific tests are explicitly **skipped**, not falsely
claimed as passing observations. All remaining tests continue to run.

## Rollback

Inspect the receipt before operating. The systemd drop-in may be removed
and the service reloaded/restarted with a separately restored source tree
only after validating the old source exists; do not point the unit to an
absent path or alter the current auth environment.
