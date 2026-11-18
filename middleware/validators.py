import re

from services.errors import AppError

USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,31}$")
PASSWORD_MIN = 8
PASSWORD_MAX = 1024
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def bad(message):
    raise AppError(400, "BAD_REQUEST", message)


def is_valid_username(username):
    return isinstance(username, str) and USERNAME_RE.fullmatch(username) is not None


def validate_username(username):
    if not is_valid_username(username):
        bad("Invalid username")


def is_valid_password(password):
    return isinstance(password, str) and PASSWORD_MIN <= len(password) <= PASSWORD_MAX


def validate_password(password):
    if not is_valid_password(password):
        bad("Password must be 8 to 1024 characters")


def is_safe_filename(filename):
    return (isinstance(filename, str) and FILENAME_RE.fullmatch(filename) is not None
            and filename not in {".", ".."}
            and ".." not in filename
            and filename.lower() not in {"nul", "con", "prn", "aux"}
            and not filename.lower().startswith(("com", "lpt")))


def validate_filename(filename):
    if not is_safe_filename(filename):
        bad("Invalid filename")


def validate_size(size):
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        bad("Invalid size")


def validate_sha256(sha256):
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        bad("Invalid SHA-256")