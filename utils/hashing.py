"""
utils/hashing.py  [PERSON B]

Streaming SHA-256 so large files never have to fit in memory.
"""
import hashlib
import re

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def new_sha256():
    """Return a fresh hash object; call .update(chunk) then .hexdigest()."""
    return hashlib.sha256()


def sha256_file(path: str, chunk_size: int = 65536) -> str:
    """Return the lowercase hex SHA-256 of a file, read in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def is_valid_sha256_hex(value) -> bool:
    """True if value is a 64-character lowercase hex string."""
    return isinstance(value, str) and _HEX64.match(value) is not None
