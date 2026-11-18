"""
mocks/mock_controllers.py  [PERSON A]

In-memory fake of Person B's controllers so Person A can build and test the
network side without MySQL. It follows INTERFACE_CONTRACT.md section 6 exactly.

WARNING: passwords are stored in plain text here. This is a TEST DOUBLE only;
the real system uses Argon2id (Person B). Never use this for real data.
"""
import hashlib
import secrets
import threading
from types import SimpleNamespace

MOCK_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB is plenty for tests


def _resp(status, code, message, data=None):
    return {"status": status, "code": code, "message": message, "data": data or {}}


class _MockUploadHandle:
    def __init__(self, state, user, filename, size, sha256):
        self._state, self._user = state, user
        self._filename, self._size, self._sha256 = filename, size, sha256
        self._buf = bytearray()
        self.finished = False
        self.aborted = False

    def write(self, chunk):
        self._buf.extend(chunk)

    def commit(self):
        self.finished = True
        data = bytes(self._buf)
        if len(data) != self._size or hashlib.sha256(data).hexdigest() != self._sha256:
            return _resp(422, "CHECKSUM_MISMATCH", "File integrity check failed")
        with self._state["lock"]:
            self._state["files"].setdefault(self._user, {})[self._filename] = data
        return _resp(200, "OK", "Uploaded and verified",
                     {"filename": self._filename, "size": self._size, "sha256": self._sha256})

    def abort(self, reason=""):
        self.aborted = True
        self._buf = bytearray()


class _MockDownloadHandle:
    def __init__(self, data):
        self._data = data
        self.size = len(data)
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.closed = False

    def read_chunks(self, chunk_size=65536):
        for i in range(0, len(self._data), chunk_size):
            yield self._data[i:i + chunk_size]

    def close(self):
        self.closed = True


def build():
    """Return a controllers object with the six contract functions."""
    state = {"lock": threading.Lock(), "users": {}, "tokens": {}, "files": {}}

    def _user_for(token):
        with state["lock"]:
            return state["tokens"].get(token)

    def register(username, password, ip):
        with state["lock"]:
            if username in state["users"]:
                return _resp(409, "CONFLICT", "Username already exists")
            state["users"][username] = password
        return _resp(200, "OK", "Registered")

    def login(username, password, ip):
        with state["lock"]:
            if state["users"].get(username) != password:
                return _resp(401, "UNAUTHENTICATED", "Invalid username or password")
            token = secrets.token_urlsafe(32)
            state["tokens"][token] = username
        return _resp(200, "OK", "Logged in",
                     {"token": token, "expires_in": 1800, "username": username, "role": "user"})

    def logout(token, ip):
        with state["lock"]:
            if state["tokens"].pop(token, None) is None:
                return _resp(401, "UNAUTHENTICATED", "Invalid or expired session")
        return _resp(200, "OK", "Logged out")

    def list_files(token, ip):
        user = _user_for(token)
        if user is None:
            return _resp(401, "UNAUTHENTICATED", "Invalid or expired session")
        with state["lock"]:
            files = [
                {"filename": n, "size": len(d), "sha256": hashlib.sha256(d).hexdigest(),
                 "modified": "2026-01-01T00:00:00Z"}
                for n, d in sorted(state["files"].get(user, {}).items())
            ]
        return _resp(200, "OK", "%d file(s)" % len(files), {"files": files})

    def begin_upload(token, ip, filename, size, sha256, overwrite=False):
        user = _user_for(token)
        if user is None:
            return _resp(401, "UNAUTHENTICATED", "Invalid or expired session"), None
        if size <= 0 or not filename:
            return _resp(400, "BAD_REQUEST", "Invalid size or filename"), None
        if size > MOCK_MAX_FILE_SIZE:
            return _resp(413, "TOO_LARGE", "File too large"), None
        with state["lock"]:
            exists = filename in state["files"].get(user, {})
        if exists and not overwrite:
            return _resp(409, "CONFLICT", "File already exists"), None
        return _resp(200, "OK", "Ready"), _MockUploadHandle(state, user, filename, size, sha256)

    def open_download(token, ip, filename):
        user = _user_for(token)
        if user is None:
            return _resp(401, "UNAUTHENTICATED", "Invalid or expired session"), None
        with state["lock"]:
            data = state["files"].get(user, {}).get(filename)
        if data is None:
            return _resp(404, "NOT_FOUND", "File not found"), None
        handle = _MockDownloadHandle(data)
        return _resp(200, "OK", "Sending",
                     {"filename": filename, "size": handle.size, "sha256": handle.sha256}), handle

    return SimpleNamespace(
        register=register, login=login, logout=logout, list_files=list_files,
        begin_upload=begin_upload, open_download=open_download,
    )
