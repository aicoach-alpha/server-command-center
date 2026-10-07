from app.auth import LoginGuard, create_session, hash_password, verify_password, verify_session


def test_password_hash_round_trip():
    encoded = hash_password("correct horse battery staple", iterations=10_000)
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)
    assert "correct horse" not in encoded


def test_session_round_trip_and_tamper_rejected():
    token = create_session("admin", "test-secret-value", 60)
    assert verify_session(token, "test-secret-value", "admin")
    assert not verify_session(token + "x", "test-secret-value", "admin")
    assert not verify_session(token, "test-secret-value", "other")


def test_login_guard_locks_after_failures():
    guard = LoginGuard(max_attempts=2, window_s=60, lockout_s=60)
    assert guard.allowed("client")[0]
    guard.failure("client")
    assert guard.allowed("client")[0]
    guard.failure("client")
    allowed, retry = guard.allowed("client")
    assert not allowed
    assert retry > 0
    guard.success("client")
    assert guard.allowed("client")[0]
