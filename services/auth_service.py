"""
services/auth_service.py  [PERSON B]

Registration, login, logout. Raises AppError for expected failures.

Security behaviour:
  * Argon2id password hashes (utils/passwords.py)
  * identical 401 message for unknown user / wrong password, and a dummy
    hash check for unknown users so timing does not reveal who exists
  * lockout: MAX_FAILED_ATTEMPTS wrong passwords -> locked for LOCK_SECONDS
  * every outcome is written to the audit log
"""
import logging

from mysql.connector import errors as mysql_errors

from middleware import validators
from models import role as role_model
from models import user as user_model
from services import audit_service, session_service
from services.errors import AppError, unauthenticated
from utils import passwords

log = logging.getLogger("sft.auth")

MAX_FAILED_ATTEMPTS = 5
LOCK_SECONDS = 300
INVALID_LOGIN = "Invalid username or password"


def register(username, password, ip):
    validators.validate_username(username)
    validators.validate_password(password)
    password_hash = passwords.hash_password(password)
    try:
        user_id = user_model.create_user(username, password_hash, role_model.get_id("user") or 1)
    except mysql_errors.IntegrityError:
        audit_service.log_event("REGISTER", False, username=username, ip=ip, detail="username taken")
        raise AppError(409, "CONFLICT", "Username already exists")
    audit_service.log_event("REGISTER", True, user_id=user_id, username=username, ip=ip)


def login(username, password, ip):
    """Return {"token","expires_in","username","role"} or raise AppError."""
    # Junk input: same answer as a wrong password, without touching the database.
    if not validators.is_valid_username(username) or not validators.is_valid_password(password):
        if isinstance(password, str):
            passwords.burn_time(password[:validators.PASSWORD_MAX])
        audit_service.log_event("LOGIN_FAIL", False, username=username, ip=ip, detail="malformed credentials")
        raise unauthenticated(INVALID_LOGIN)

    user = user_model.get_for_login(username)

    if user is None:
        passwords.burn_time(password)
        audit_service.log_event("LOGIN_FAIL", False, username=username, ip=ip, detail="unknown user")
        raise unauthenticated(INVALID_LOGIN)

    if user["is_locked"]:
        audit_service.log_event("LOGIN_FAIL", False, user_id=user["id"], username=username, ip=ip,
                                detail="account locked")
        raise AppError(429, "TOO_MANY_ATTEMPTS", "Too many failed attempts. Try again later.")

    if not user["is_active"] or not passwords.verify_password(user["password_hash"], password):
        failures = user_model.record_failed_login(user["id"])
        audit_service.log_event("LOGIN_FAIL", False, user_id=user["id"], username=username, ip=ip,
                                detail="bad password" if user["is_active"] else "inactive account")
        if failures >= MAX_FAILED_ATTEMPTS:
            user_model.lock_account(user["id"], LOCK_SECONDS)
            audit_service.log_event("ACCOUNT_LOCKED", False, user_id=user["id"], username=username, ip=ip,
                                    detail="locked for %d seconds" % LOCK_SECONDS)
        raise unauthenticated(INVALID_LOGIN)

    # Success
    user_model.reset_failed_logins(user["id"])
    if passwords.needs_rehash(user["password_hash"]):
        try:
            user_model.update_password_hash(user["id"], passwords.hash_password(password))
        except Exception:
            log.exception("password rehash failed (login still succeeds)")
    token, ttl = session_service.create_session(user["id"], ip)
    audit_service.log_event("LOGIN", True, user_id=user["id"], username=username, ip=ip)
    return {"token": token, "expires_in": ttl, "username": user["username"], "role": user["role"]}


def logout(token, ip):
    info = session_service.validate_token(token)
    if info is None:
        raise unauthenticated()
    session_service.revoke_token(token)
    audit_service.log_event("LOGOUT", True, user_id=info["user_id"], username=info["username"], ip=ip)
