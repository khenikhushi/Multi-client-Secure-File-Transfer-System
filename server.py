import logging
import logging.handlers
import os
import socket
import ssl
import threading

import config
from protocol import error_response, validate_request
from routes.file_routes import dispatch
from utils.framing import (
    ConnectionClosed,
    FramingError,
    recv_message,
    send_message,
)


def setup_logging(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not root.handlers:
        handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, "server.log"),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        ))
        root.addHandler(handler)
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        root.addHandler(console)


def _make_tls_context(cfg):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cfg.TLS_CERT, cfg.TLS_KEY)
    return context


def _handle_client(sock, address, controllers):
    ip = address[0] if address else ""
    sock.settimeout(config.IDLE_TIMEOUT)
    try:
        while True:
            request = None
            try:
                request = recv_message(sock, max_size=config.MAX_CONTROL_MSG)
                validate_request(request)
                dispatch(request, ip, sock, controllers)
            except (ConnectionClosed, OSError):
                break
            except FramingError as exc:
                req_id = request.get("id") if isinstance(request, dict) else None
                try:
                    send_message(sock, error_response(req_id, 400, str(exc), "BAD_REQUEST"))
                except (FramingError, OSError):
                    pass
                break
    finally:
        try:
            sock.close()
        except OSError:
            pass


def run_server(controllers, cfg):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((cfg.SERVER_HOST, cfg.SERVER_PORT))
    listener.listen(cfg.MAX_CLIENTS)
    listener.settimeout(1)

    tls_context = _make_tls_context(cfg) if cfg.USE_TLS else None
    semaphore = threading.BoundedSemaphore(cfg.MAX_CLIENTS)

    try:
        while True:
            try:
                raw, address = listener.accept()
            except socket.timeout:
                continue

            if not semaphore.acquire(blocking=False):
                raw.close()
                continue

            sock = raw
            if tls_context is not None:
                try:
                    sock = tls_context.wrap_socket(raw, server_side=True)
                except ssl.SSLError:
                    raw.close()
                    semaphore.release()
                    continue

            def worker(client_sock=sock, client_address=address):
                try:
                    _handle_client(client_sock, client_address, controllers)
                finally:
                    semaphore.release()

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()