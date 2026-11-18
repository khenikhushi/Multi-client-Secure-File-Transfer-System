import logging

from services import auth_service
from services.errors import AppError, from_error, ok, response

log = logging.getLogger("sft.auth")


def register(username, password, ip):
    try:
        auth_service.register(username, password, ip)
        return ok("Registered")
    except AppError as err:
        return from_error(err)
    except Exception:
        log.exception("unexpected error in register")
        return response(500, "SERVER_ERROR", "Internal server error")


def login(username, password, ip):
    try:
        data = auth_service.login(username, password, ip)
        return ok("Logged in", data)
    except AppError as err:
        return from_error(err)
    except Exception:
        log.exception("unexpected error in login")
        return response(500, "SERVER_ERROR", "Internal server error")


def logout(token, ip):
    try:
        auth_service.logout(token, ip)
        return ok("Logged out")
    except AppError as err:
        return from_error(err)
    except Exception:
        log.exception("unexpected error in logout")
        return response(500, "SERVER_ERROR", "Internal server error")