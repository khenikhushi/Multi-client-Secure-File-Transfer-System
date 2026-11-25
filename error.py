"""
Shared application error and response helpers.

AppError is how services/middleware say "this request failed, here is why".
Controllers catch it and turn it into the response dict from
interface_contract.md section 6.1. AppError is internal to the application.
"""


class AppError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def bad_request(message):
    return AppError(400, "BAD_REQUEST", message)


def unauthenticated(message="Invalid or expired session"):
    return AppError(401, "UNAUTHENTICATED", message)


def response(status, code, message, data=None):
    """Build the response dictionary returned by a controller."""
    return {"status": status, "code": code, "message": message, "data": data if data is not None else {}}


def ok(message, data=None):
    return response(200, "OK", message, data)


def from_error(err):
    return response(err.status, err.code, err.message)
