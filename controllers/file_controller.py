"""
controllers/file_controller.py  [PERSON B]

The three functions Person A's routes call (INTERFACE_CONTRACT.md 6.3).
Each one: check the session, call the service, build the response dict.
They never raise; unexpected errors become a generic 500 (details only in logs).
"""
import logging

from middleware import auth_middleware
from services import file_service
from services.errors import AppError, from_error, ok, response

log = logging.getLogger("sft.files")


def _server_error():
    return response(500, "SERVER_ERROR", "Internal server error")


def list_files(token, ip):
    try:
        info = auth_middleware.require_session(token, ip)
        files = file_service.list_files(info, ip)
        return ok("%d file(s)" % len(files), {"files": files})
    except AppError as err:
        return from_error(err)
    except Exception:
        log.exception("unexpected error in list_files")
        return _server_error()


def begin_upload(token, ip, filename, size, sha256, overwrite=False):
    """Returns (response_dict, UploadHandle or None)."""
    try:
        info = auth_middleware.require_session(token, ip)
        handle = file_service.begin_upload(info, ip, filename, size, sha256, overwrite)
        return ok("Ready"), handle
    except AppError as err:
        return from_error(err), None
    except Exception:
        log.exception("unexpected error in begin_upload")
        return _server_error(), None


def open_download(token, ip, filename):
    """Returns (response_dict, DownloadHandle or None)."""
    try:
        info = auth_middleware.require_session(token, ip)
        handle = file_service.open_download(info, ip, filename)
        return ok("Sending", {"filename": handle.filename, "size": handle.size,
                              "sha256": handle.sha256}), handle
    except AppError as err:
        return from_error(err), None
    except Exception:
        log.exception("unexpected error in open_download")
        return _server_error(), None
