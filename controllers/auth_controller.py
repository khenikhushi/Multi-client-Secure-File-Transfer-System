import logging

from services import auth_service
from services.errors import AppError, from_error, ok, response

log = logging.getLogger("sft.auth")


def _run(action, message, *args, include_result=False):
    try:
        result = action(*args)
    except AppError as err:
        return from_error(err)
    except Exception:
        log.exception("unexpected error in %s", action.__name__)
        return response(500, "SERVER_ERROR", "Internal server error")
    return ok(message, result if include_result else None)


def register(username, password, ip):
    return _run(auth_service.register, "Registered", username, password, ip)


def login(username, password, ip):
    return _run(auth_service.login, "Logged in", username, password, ip, include_result=True)


def logout(token, ip):
    return _run(auth_service.logout, "Logged out", token, ip)