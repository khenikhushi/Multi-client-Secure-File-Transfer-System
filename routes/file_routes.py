"""
routes/file_routes.py

Maps each protocol command to its controller function and runs the network
conversation (control messages + raw file bytes).

This file is the ONLY place where the network side meets the application side.
It calls exactly the six functions listed in INTERFACE_CONTRACT.md section 6.
"""
import logging

from config import CHUNK_SIZE, TRANSFER_TIMEOUT
from protocol import error_response, response_from_result
from utils.framing import ConnectionClosed, FramingError, recv_file_bytes, send_file_bytes, send_message

log = logging.getLogger("sft.routes")


class _StorageFailure(Exception):
    """Marks a failure from the upload storage handle."""


class DesyncError(Exception):
    """
    The conversation is in an unknown state (e.g. a failure in the middle of a
    file transfer). The server must close this connection.
    """


# ---------------------------------------------------------------- helpers
def _send_result(sock, req_id, result):
    send_message(sock, response_from_result(req_id, result))


def _best_effort_send(sock, message):
    try:
        send_message(sock, message)
    except Exception:
        pass


def _safe_abort(handle, reason):
    try:
        handle.abort(reason)
    except Exception:
        log.exception("handle.abort() failed")


def _safe_close(handle):
    try:
        handle.close()
    except Exception:
        log.exception("handle.close() failed")


# --------------------------------------------------------------- handlers
def _handle_register(req, ip, sock, controllers):
    _send_result(sock, req["id"], controllers.register(req["username"], req["password"], ip))


def _handle_login(req, ip, sock, controllers):
    _send_result(sock, req["id"], controllers.login(req["username"], req["password"], ip))


def _handle_logout(req, ip, sock, controllers):
    _send_result(sock, req["id"], controllers.logout(req["token"], ip))


def _handle_list(req, ip, sock, controllers):
    _send_result(sock, req["id"], controllers.list_files(req["token"], ip))


def _handle_put(req, ip, sock, controllers):
    req_id = req["id"]
    result, handle = controllers.begin_upload(
        req["token"], ip, req["filename"], req["size"], req["sha256"], req.get("overwrite", False)
    )
    if handle is None or result.get("status") != 200:
        # Refused. The client waits for this answer before sending any bytes,
        # so the stream is still clean and the connection can continue.
        if handle is not None:
            _safe_abort(handle, "refused")
        _send_result(sock, req_id, result)
        return

    # Accepted: tell the client to start sending raw bytes.
    # Two kinds of failure are handled differently:
    #   * network problems (peer gone, timeout)  -> come out of recv_file_bytes
    #   * storage problems (disk full, bug)      -> come out of handle.write/commit
    previous_timeout = sock.gettimeout()
    try:
        _send_result(sock, req_id, result)
        sock.settimeout(TRANSFER_TIMEOUT)
        for chunk in recv_file_bytes(sock, req["size"], CHUNK_SIZE):
            try:
                handle.write(chunk)
            except Exception as exc:
                raise _StorageFailure() from exc
        try:
            final = handle.commit()
        except Exception as exc:
            raise _StorageFailure() from exc
    except _StorageFailure as exc:
        _safe_abort(handle, "storage failure")
        log.error("upload failed on the server side", exc_info=exc.__cause__)
        _best_effort_send(sock, error_response(req_id, 500, "Internal server error"))
        raise DesyncError("upload failed mid-transfer") from exc.__cause__
    except Exception as exc:
        _safe_abort(handle, "network failure: %s" % type(exc).__name__)
        raise  # ConnectionClosed / timeout / OSError: the server closes the connection
    finally:
        _restore_timeout(sock, previous_timeout)
    _send_result(sock, req_id, final)


def _handle_get(req, ip, sock, controllers):
    req_id = req["id"]
    result, handle = controllers.open_download(req["token"], ip, req["filename"])
    if handle is None or result.get("status") != 200:
        if handle is not None:
            _safe_close(handle)
        _send_result(sock, req_id, result)
        return

    previous_timeout = sock.gettimeout()
    try:
        # The header must carry the size we will really send.
        data = dict(result.get("data", {}))
        data["size"], data["sha256"] = handle.size, handle.sha256
        send_message(sock, response_from_result(req_id, dict(result, data=data)))
        sock.settimeout(TRANSFER_TIMEOUT)
        sent = send_file_bytes(sock, _guarded_chunks(handle))
        if sent != handle.size:
            raise DesyncError("file size changed during download")
    except (ConnectionClosed, OSError, DesyncError):
        raise
    except Exception as exc:
        log.exception("download failed on the server side")
        raise DesyncError("download failed mid-transfer") from exc
    finally:
        _safe_close(handle)
        _restore_timeout(sock, previous_timeout)


def _guarded_chunks(handle):
    """Yield file chunks; turn storage errors into DesyncError (with a log entry)."""
    try:
        for chunk in handle.read_chunks(CHUNK_SIZE):
            yield chunk
    except Exception as exc:
        log.exception("reading the file for download failed")
        raise DesyncError("download failed mid-transfer") from exc


def _restore_timeout(sock, timeout):
    """Put back the timeout the server had set before the transfer started."""
    try:
        sock.settimeout(timeout)
    except OSError:
        pass


_HANDLERS = {
    "REGISTER": _handle_register,
    "LOGIN": _handle_login,
    "LOGOUT": _handle_logout,
    "LIST": _handle_list,
    "GET": _handle_get,
    "PUT": _handle_put,
}


# --------------------------------------------------------------- dispatch
def dispatch(request, ip, sock, controllers):
    """
    Run one already-validated request and send every reply (and file bytes).

    Returns normally if the connection is still in a clean state.
    Raises ConnectionClosed / OSError / DesyncError if the server must close it.
    A controller that crashes only causes a 500 for that one request.
    """
    handler = _HANDLERS[request["cmd"]]
    try:
        handler(request, ip, sock, controllers)
    except (ConnectionClosed, FramingError, DesyncError, OSError):
        raise
    except Exception:
        log.exception("controller crashed while handling %s", request["cmd"])
        send_message(sock, error_response(request["id"], 500, "Internal server error"))
