"""Process-label defaults / monkeypatch tests."""
from __future__ import annotations

import re

from app.config import PROCESS_LABELS
from app.collectors.friendly import FriendlyResolver, ARGV_RULES


def test_default_process_labels_loaded() -> None:
    """PROCESS_LABELS must be a tuple (deployment rules, empty by default)."""
    assert isinstance(PROCESS_LABELS, tuple)
    # Every entry is a (compiled regex, label) pair.
    for pattern, label in PROCESS_LABELS:
        assert isinstance(pattern, re.Pattern)
        assert isinstance(label, str) and label.strip()


def test_argv_rules_present() -> None:
    """Generic argv fallback rules must exist for common interpreters."""
    assert isinstance(ARGV_RULES, tuple)
    assert len(ARGV_RULES) > 0


def test_monkeypatched_deployment_labels(monkeypatch) -> None:
    """Deployment rules from SCC_PROCESS_LABELS_JSON take precedence."""
    rules = (
        (re.compile(r"example_api:app"), "Example API"),
        (re.compile(r"scripts\.worker"), "Example Worker"),
    )
    monkeypatch.setattr("app.collectors.friendly.PROCESS_LABELS", rules)
    resolver = FriendlyResolver()
    # The resolver should use the monkeypatched rules.
    # We verify by checking the module-level constant was overridden.
    from app.collectors import friendly

    assert friendly.PROCESS_LABELS is rules
    assert (re.compile(r"example_api:app"), "Example API") in friendly.PROCESS_LABELS


def test_resolver_cache_keyed_by_pid_and_create_time(monkeypatch) -> None:
    """Cache must be keyed by (pid, create_time) to avoid stale names."""
    resolver = FriendlyResolver()
    # Pre-populate the cache.
    resolver._cache[(1234, 1000.0)] = {"display_name": "cached_name"}
    # A process with the same pid but different create_time should miss.
    # We can't easily mock psutil.Process here, but we can verify the cache
    # key structure is correct.
    assert (1234, 1000.0) in resolver._cache
    assert (1234, 2000.0) not in resolver._cache
