"""
tests/test_files.py
Stage 1: hashing + path-safety tests. Later stages add upload/download tests.
Run:  pytest tests/test_files.py -v
"""
import hashlib
import os

import pytest

import config
from mocks import mock_controllers
from middleware import validators
from services.errors import AppError
from utils import hashing, paths


# ---------- upload size validation ----------
def test_validate_size_accepts_configured_limit(monkeypatch):
    monkeypatch.setattr(config, "MAX_FILE_SIZE", 100)
    validators.validate_size(100)


def test_validate_size_rejects_over_limit_with_413(monkeypatch):
    monkeypatch.setattr(config, "MAX_FILE_SIZE", 100)
    with pytest.raises(AppError) as exc_info:
        validators.validate_size(101)
    assert exc_info.value.status == 413
    assert exc_info.value.code == "TOO_LARGE"


@pytest.mark.parametrize("size", [0, -1, True, "1", None])
def test_validate_size_rejects_invalid_values(size):
    with pytest.raises(AppError) as exc_info:
        validators.validate_size(size)
    assert exc_info.value.status == 400


def test_validate_filename_uses_shared_path_rules():
    validators.validate_filename("report.pdf")
    with pytest.raises(AppError):
        validators.validate_filename("CON.txt")


def test_mock_controller_rejects_upload_over_configured_limit(monkeypatch):
    monkeypatch.setattr(config, "MAX_FILE_SIZE", 100)
    controllers = mock_controllers.build()
    controllers.register("testuser", "password123", "127.0.0.1")
    login = controllers.login("testuser", "password123", "127.0.0.1")

    result, handle = controllers.begin_upload(
        login["data"]["token"], "127.0.0.1", "file.txt", 101, "a" * 64
    )

    assert result["status"] == 413
    assert result["code"] == "TOO_LARGE"
    assert handle is None


# ---------- hashing ----------
def test_sha256_file_matches_hashlib(tmp_path):
    data = os.urandom(300_000)
    f = tmp_path / "x.bin"
    f.write_bytes(data)
    assert hashing.sha256_file(str(f), chunk_size=1000) == hashlib.sha256(data).hexdigest()


def test_sha256_empty_file(tmp_path):
    f = tmp_path / "empty"
    f.write_bytes(b"")
    assert hashing.sha256_file(str(f)) == hashlib.sha256(b"").hexdigest()


def test_is_valid_sha256_hex():
    good = "a" * 64
    assert hashing.is_valid_sha256_hex(good)
    assert not hashing.is_valid_sha256_hex("A" * 64)      # uppercase not allowed
    assert not hashing.is_valid_sha256_hex("a" * 63)
    assert not hashing.is_valid_sha256_hex("g" * 64)
    assert not hashing.is_valid_sha256_hex(None)


# ---------- filenames ----------
@pytest.mark.parametrize("name", ["report.pdf", "a", "notes-2026_v1.txt", "A.b.c", "x" * 128])
def test_good_filenames(name):
    assert paths.is_safe_filename(name)


@pytest.mark.parametrize("name", [
    "", ".hidden", "-rf", "../etc/passwd", "..", "a/b", "a\\b", "/abs", "C:\\x",
    "has space.txt", "a..b", "trailing.", "x" * 129, "nul", "CON.txt", "com1",
    "bad\x00name", "tab\tname", "uni✓.txt", None, 123, b"bytes",
])
def test_bad_filenames(name):
    assert not paths.is_safe_filename(name)


# ---------- safe_user_path ----------
def test_safe_path_inside_user_folder(tmp_path):
    p = paths.safe_user_path(str(tmp_path), 7, "report.pdf")
    assert p == os.path.join(os.path.realpath(str(tmp_path)), "7", "report.pdf")


@pytest.mark.parametrize("name", ["../8/secret.txt", "..%2f..%2fx", "/etc/passwd", "a/../../b"])
def test_traversal_attempts_rejected(tmp_path, name):
    with pytest.raises(ValueError):
        paths.safe_user_path(str(tmp_path), 7, name)


@pytest.mark.parametrize("uid", [0, -1, "7", None, 1.5, True])
def test_bad_user_ids_rejected(tmp_path, uid):
    with pytest.raises(ValueError):
        paths.safe_user_path(str(tmp_path), uid, "ok.txt")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks")
def test_symlink_escape_rejected(tmp_path):
    base = tmp_path / "storage"
    (base / "7").mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    try:
        os.symlink(str(outside), str(base / "7" / "link.txt"))
    except OSError:
        pytest.skip("cannot create symlink here")
    with pytest.raises(ValueError):
        paths.safe_user_path(str(base), 7, "link.txt")


def test_temp_dir(tmp_path):
    assert paths.temp_dir(str(tmp_path)).endswith(".tmp")
