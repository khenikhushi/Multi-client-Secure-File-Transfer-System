"""
services/audit_service.py  [PERSON B]

One function, log_event(), records who did what. Each event goes to:
  1. the audit_logs table (queryable), and
  2. logs/audit.log (plain text, rotated).

Rules:
  * Never pass passwords or tokens in here.
  * It must NEVER raise: a failing audit write must not break a user request.
  * Control characters are stripped so users cannot forge log lines.

Event types: REGISTER, LOGIN, LOGIN_FAIL, ACCOUNT_LOCKED, LOGOUT,
             LIST, UPLOAD, UPLOAD_ABORT, DOWNLOAD, ACCESS_DENIED
"""
import logging
import logging.handlers
import os
import threading
import time

import config
from models import audit_log

_app_log = logging.getLogger("sft.app")
_file_logger = None
_lock = threading.Lock()


def _get_file_logger():
    global _file_logger
    with _lock:
        if _file_logger is None:
            os.makedirs(config.LOG_DIR, exist_ok=True)
            logger = logging.getLogger("sft.audit")
            logger.setLevel(logging.INFO)
            logger.propagate = False
            if not logger.handlers:
                handler = logging.handlers.RotatingFileHandler(
                    os.path.join(config.LOG_DIR, "audit.log"),
                    maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8",
                )
                formatter = logging.Formatter("%(asctime)sZ %(message)s")
                formatter.converter = time.gmtime  # timestamps in UTC
                handler.setFormatter(formatter)
                logger.addHandler(handler)
            _file_logger = logger
    return _file_logger


def _clean(value, max_len):
    """Single-line, printable, length-limited text (prevents log injection)."""
    if value is None:
        return None
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return text[:max_len]


def log_event(event_type, success=True, user_id=None, username=None, detail="", ip=None):
    username = _clean(username, 32)
    detail = _clean(detail, 255)
    ip = _clean(ip, 45)
    try:
        _get_file_logger().info(
            "event=%s success=%s user_id=%s username=%s ip=%s detail=%s",
            event_type, "yes" if success else "no", user_id, username, ip, detail,
        )
    except Exception:
        _app_log.exception("could not write audit.log")
    try:
        audit_log.add(event_type, success, user_id, username, detail, ip)
    except Exception:
        _app_log.exception("could not write audit event to the database")
