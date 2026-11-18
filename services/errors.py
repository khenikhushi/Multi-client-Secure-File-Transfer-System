"""
Shared application error and response helpers.
"""


class AppError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def bad_request(message):
    return AppError(400, "BAD_REQUEST", message)


def unauthorized(message="Invalid or expired session"):
    return AppError(401, "UNAUTHENTICATED", message)


def unauthenticated(message="Invalid or expired session"):
    return unauthorized(message)


def forbidden(message="Access denied"):
    return AppError(403, "FORBIDDEN", message)


def response(status, code, message, data=None):
    return {"status": status, "code": code, "message": message,
            "data": data if data is not None else {}}


def ok(message, data=None):
    return response(200, "OK", message, data)


def from_error(err):
    return response(err.status, err.code, err.message)
