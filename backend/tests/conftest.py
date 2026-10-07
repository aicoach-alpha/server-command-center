import os

# Test suite exercises collectors/API independently of deployment authentication.
# Production enables auth explicitly via its systemd EnvironmentFile.
os.environ.setdefault("SCC_AUTH_ENABLED", "false")
os.environ.setdefault("SCC_EXTERNAL_STORAGE_UUID", "11111111-2222-3333-4444-555555555555")
os.environ.setdefault("SCC_EXTERNAL_STORAGE_MOUNTPOINT", "/mnt/data")
os.environ.setdefault("SCC_EXTERNAL_STORAGE_NAME", "Test External Storage")
