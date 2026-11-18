"""
utils/passwords.py  [PERSON B]

Password hashing with Argon2id (argon2-cffi). We never store or log
plaintext passwords; only the encoded hash string goes into the database.
The encoded hash already contains the random salt and parameters.
"""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError

# argon2-cffi's PasswordHasher uses Argon2id by default.
_hasher = PasswordHasher()

# A real hash of a throw-away value. Used so that a login for a username that
# does not exist takes about as long as one that does (hides which users exist).
_DUMMY_HASH = _hasher.hash("not-a-real-password")


def hash_password(password: str) -> str:
    """Return an Argon2id encoded hash string for the password."""
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """True only if the password matches the stored hash. Never raises."""
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHash):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if the hash uses outdated parameters (optional upgrade on login)."""
    return _hasher.check_needs_rehash(stored_hash)


def burn_time(password: str) -> None:
    """Spend the same time as a real verification (use for unknown usernames)."""
    verify_password(_DUMMY_HASH, password)
