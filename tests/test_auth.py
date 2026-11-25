"""
tests/test_auth.py
Stage 1: password hashing tests. Later stages add auth service tests.
Run:  pytest tests/test_auth.py -v
"""
from utils import passwords


def test_hash_is_argon2id_and_not_plaintext():
    h = passwords.hash_password("CorrectHorse9!")
    assert h.startswith("$argon2id$")
    assert "CorrectHorse9!" not in h


def test_verify_correct_and_wrong_password():
    h = passwords.hash_password("CorrectHorse9!")
    assert passwords.verify_password(h, "CorrectHorse9!") is True
    assert passwords.verify_password(h, "wrong-password") is False


def test_same_password_gives_different_hashes_salted():
    assert passwords.hash_password("samepass1") != passwords.hash_password("samepass1")


def test_verify_garbage_hash_returns_false_not_exception():
    assert passwords.verify_password("not-a-hash", "x") is False
    assert passwords.verify_password("", "x") is False


def test_unicode_password():
    h = passwords.hash_password("pässwörd-密码-9")
    assert passwords.verify_password(h, "pässwörd-密码-9")


def test_burn_time_runs():
    passwords.burn_time("anything")  # must not raise
