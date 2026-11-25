"""
utils/paths.py

Safe path handling to prevent directory traversal.

Two layers of defence:
  1. Whitelist the filename (letters, digits, '.', '_', '-' only; no slashes).
  2. Resolve the final path and confirm it is still inside the user's folder
     (this also catches symlink tricks).
"""
import os
import re

# Contract rule: first char alphanumeric, then up to 127 of [A-Za-z0-9._-]
_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# Names Windows treats as devices (CON.txt etc.). Rejected so storage is portable.
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *("COM%d" % i for i in range(1, 10)),
    *("LPT%d" % i for i in range(1, 10)),
}


def is_safe_filename(name) -> bool:
    """True if name is an acceptable plain filename."""
    if not isinstance(name, str) or not _FILENAME_RE.match(name):
        return False
    if ".." in name or name.endswith("."):
        return False
    if name.split(".")[0].upper() in _WINDOWS_RESERVED:
        return False
    return True


def user_dir(base_dir: str, user_id: int) -> str:
    """Return storage/<user_id> (not created here). Raises ValueError on bad id."""
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("invalid user id")
    return os.path.join(os.path.realpath(base_dir), str(user_id))


def safe_user_path(base_dir: str, user_id: int, filename: str) -> str:
    """
    Return the absolute path for a user's file, guaranteed to be inside
    storage/<user_id>/. Raises ValueError if anything looks unsafe.
    """
    if not is_safe_filename(filename):
        raise ValueError("unsafe filename")
    folder = os.path.realpath(user_dir(base_dir, user_id))
    full = os.path.realpath(os.path.join(folder, filename))
    if os.path.commonpath([folder, full]) != folder or full == folder:
        raise ValueError("path escapes user directory")
    return full


def temp_dir(base_dir: str) -> str:
    """Folder for in-progress uploads: storage/.tmp (not created here)."""
    return os.path.join(os.path.realpath(base_dir), ".tmp")
