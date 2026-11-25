"""
services/file_service.py

File listing, upload and download.

UPLOAD  (UploadHandle)
  1. begin_upload() validates everything and opens a temp file in storage/.tmp/
  2. The route calls handle.write(chunk) for every chunk; we hash while writing
  3. handle.commit(): flush + fsync, compare the SHA-256 with the one the client
     declared, then os.replace() the temp file onto storage/<user_id>/<name>.
     os.replace is atomic: readers see the old file or the new file, never half.
  4. handle.abort() deletes the temp file (client vanished, disk error...).

DOWNLOAD  (DownloadHandle)
  open_download() finds the file for THIS user only, and the handle streams it
  in chunks. We re-hash while streaming and record in the audit log if the file
  on disk no longer matches the stored hash.

The user's identity always comes from the session (`info`), never from the
request, so a user cannot name someone else's files.
"""
import logging
import os
import secrets
import threading
import time

import config
from middleware import validators
from models import file_record
from services import audit_service
from services.errors import AppError, bad_request, ok, response
from utils import hashing, paths

log = logging.getLogger("sft.files")

# Held only for the short "check name, rename, write DB row" step, so two
# uploads of the same filename cannot both succeed when overwrite is false.
_finalize_lock = threading.Lock()


# ------------------------------------------------------------ housekeeping
def ensure_storage_dirs():
    os.makedirs(paths.temp_dir(config.STORAGE_DIR), exist_ok=True)


def cleanup_stale_temp(max_age_seconds=3600):
    """Delete leftover .part files (e.g. after a crash). Returns how many were removed."""
    folder = paths.temp_dir(config.STORAGE_DIR)
    removed = 0
    if not os.path.isdir(folder):
        return 0
    cutoff = time.time() - max_age_seconds
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        try:
            if name.endswith(".part") and os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
        except OSError:
            log.exception("could not remove stale temp file %s", name)
    return removed


def _iso_utc(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _check_filename(info, ip, filename, event):
    """Validate the filename; record traversal-looking attempts in the audit log."""
    try:
        validators.validate_filename(filename)
    except AppError:
        if isinstance(filename, str) and (".." in filename or "/" in filename or "\\" in filename):
            audit_service.log_event("ACCESS_DENIED", False, user_id=info["user_id"],
                                    username=info["username"], ip=ip,
                                    detail="unsafe filename in %s: %r" % (event, filename[:60]))
        raise


# -------------------------------------------------------------------- LIST
def list_files(info, ip):
    rows = file_record.list_for_user(info["user_id"])
    audit_service.log_event("LIST", True, user_id=info["user_id"], username=info["username"], ip=ip,
                            detail="%d file(s)" % len(rows))
    return [
        {"filename": r["filename"], "size": int(r["size_bytes"]), "sha256": r["sha256"],
         "modified": _iso_utc(r["updated_at"])}
        for r in rows
    ]


# ------------------------------------------------------------------ UPLOAD
class UploadHandle:
    def __init__(self, info, ip, filename, size, sha256, overwrite):
        self._info, self._ip = info, ip
        self.filename, self.size, self.sha256, self.overwrite = filename, size, sha256, overwrite
        self._hash = hashing.new_sha256()
        self._written = 0
        self._state = "open"  # open -> committed | aborted | failed
        self.temp_path = os.path.join(
            paths.temp_dir(config.STORAGE_DIR),
            "%d_%s.part" % (info["user_id"], secrets.token_hex(16)),
        )
        # O_EXCL: never reuse an existing file. 0o600: owner-only permissions.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        self._file = os.fdopen(os.open(self.temp_path, flags, 0o600), "wb")

    def write(self, chunk):
        if self._state != "open":
            raise ValueError("upload is not open")
        if self._written + len(chunk) > self.size:
            raise ValueError("received more data than declared")
        self._file.write(chunk)
        self._hash.update(chunk)
        self._written += len(chunk)

    def commit(self):
        if self._state != "open":
            raise ValueError("upload is not open")
        try:
            self._file.flush()
            os.fsync(self._file.fileno())
            self._file.close()
        except Exception:
            self._state = "failed"
            self._remove_temp()
            raise

        if self._written != self.size or self._hash.hexdigest() != self.sha256:
            self._state = "failed"
            self._remove_temp()
            self._audit("UPLOAD", False, "integrity check failed for %s" % self.filename)
            return response(422, "CHECKSUM_MISMATCH", "File integrity check failed")

        user_id = self._info["user_id"]
        try:
            with _finalize_lock:
                existed = file_record.get(user_id, self.filename) is not None
                if existed and not self.overwrite:
                    self._state = "failed"
                    self._remove_temp()
                    self._audit("UPLOAD", False, "%s already exists" % self.filename)
                    return response(409, "CONFLICT", "File already exists")
                final_path = paths.safe_user_path(config.STORAGE_DIR, user_id, self.filename)
                os.makedirs(os.path.dirname(final_path), exist_ok=True)
                os.replace(self.temp_path, final_path)  # atomic
                try:
                    file_record.upsert(user_id, self.filename, self.size, self.sha256)
                except Exception:
                    if not existed:  # do not leave an untracked file behind
                        self._silent_remove(final_path)
                    raise
        except Exception:
            self._state = "failed"
            self._remove_temp()
            raise

        self._state = "committed"
        self._audit("UPLOAD", True, "%s (%d bytes)" % (self.filename, self.size))
        return ok("Uploaded and verified",
                  {"filename": self.filename, "size": self.size, "sha256": self.sha256})

    def abort(self, reason=""):
        """Throw the upload away. Safe to call more than once or after commit."""
        if self._state != "open":
            return
        self._state = "aborted"
        try:
            self._file.close()
        except Exception:
            pass
        self._remove_temp()
        self._audit("UPLOAD_ABORT", False, "%s: %s" % (self.filename, reason or "aborted"))

    # -- helpers
    def _audit(self, event, success, detail):
        audit_service.log_event(event, success, user_id=self._info["user_id"],
                                username=self._info["username"], ip=self._ip, detail=detail)

    def _remove_temp(self):
        self._silent_remove(self.temp_path)

    @staticmethod
    def _silent_remove(path):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            log.exception("could not remove %s", path)


def begin_upload(info, ip, filename, size, sha256, overwrite=False):
    _check_filename(info, ip, filename, "upload")
    validators.validate_size(size)
    validators.validate_sha256(sha256)
    if not isinstance(overwrite, bool):
        raise bad_request("'overwrite' must be true or false")
    if not overwrite and file_record.get(info["user_id"], filename) is not None:
        audit_service.log_event("UPLOAD", False, user_id=info["user_id"], username=info["username"],
                                ip=ip, detail="%s already exists" % filename)
        raise AppError(409, "CONFLICT", "File already exists")
    ensure_storage_dirs()
    return UploadHandle(info, ip, filename, size, sha256, overwrite)


# ---------------------------------------------------------------- DOWNLOAD
class DownloadHandle:
    def __init__(self, info, ip, filename, file_obj, size, sha256):
        self._info, self._ip, self.filename = info, ip, filename
        self._file = file_obj
        self.size, self.sha256 = size, sha256
        self._sent = 0
        self._finished = False
        self._intact = False
        self._closed = False

    def read_chunks(self, chunk_size=65536):
        hasher = hashing.new_sha256()
        while self._sent < self.size:
            chunk = self._file.read(min(chunk_size, self.size - self._sent))
            if not chunk:
                break  # file got shorter than recorded
            hasher.update(chunk)
            self._sent += len(chunk)
            yield chunk
        self._finished = self._sent == self.size
        self._intact = self._finished and hasher.hexdigest() == self.sha256

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._file.close()
        except Exception:
            pass
        if self._intact:
            detail, success = "%s (%d bytes)" % (self.filename, self.size), True
        elif self._finished:
            detail, success = "STORED FILE CHANGED ON DISK: %s" % self.filename, False
            log.error("stored file %s of user %s no longer matches its hash",
                      self.filename, self._info["user_id"])
        else:
            detail, success = "incomplete transfer of %s" % self.filename, False
        audit_service.log_event("DOWNLOAD", success, user_id=self._info["user_id"],
                                username=self._info["username"], ip=self._ip, detail=detail)


def open_download(info, ip, filename):
    _check_filename(info, ip, filename, "download")
    user_id = info["user_id"]
    record = file_record.get(user_id, filename)
    if record is None:
        audit_service.log_event("DOWNLOAD", False, user_id=user_id, username=info["username"],
                                ip=ip, detail="%s not found" % filename)
        raise AppError(404, "NOT_FOUND", "File not found")
    try:
        path = paths.safe_user_path(config.STORAGE_DIR, user_id, filename)
    except ValueError:
        audit_service.log_event("ACCESS_DENIED", False, user_id=user_id, username=info["username"],
                                ip=ip, detail="path escape for %s" % filename)
        raise AppError(403, "FORBIDDEN", "Access denied")
    try:
        file_obj = open(path, "rb")
    except FileNotFoundError:
        log.error("file %s of user %s is in the database but missing on disk", filename, user_id)
        audit_service.log_event("DOWNLOAD", False, user_id=user_id, username=info["username"],
                                ip=ip, detail="%s missing on disk" % filename)
        raise AppError(404, "NOT_FOUND", "File not found")
    size = os.fstat(file_obj.fileno()).st_size
    if size != int(record["size_bytes"]):
        file_obj.close()
        log.error("size of %s (user %s) differs from the database record", filename, user_id)
        audit_service.log_event("DOWNLOAD", False, user_id=user_id, username=info["username"],
                                ip=ip, detail="%s size differs from record" % filename)
        raise AppError(500, "SERVER_ERROR", "File is currently unavailable")
    return DownloadHandle(info, ip, filename, file_obj, size, record["sha256"])
