import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import config
from models import session as session_model


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id, ip):
    token = secrets.token_urlsafe(32)
    expires = _utc_now() + timedelta(seconds=config.SESSION_TTL_SECONDS)
    session_model.create(user_id, _token_hash(token), ip, expires)
    return token, config.SESSION_TTL_SECONDS


def validate_token(token):
    if not isinstance(token, str) or not token:
        return None
    row = session_model.get_active(_token_hash(token), _utc_now())
    if row is None:
        return None
    return {
        "session_id": row["id"],
        "user_id": row["user_id"],
        "username": row["username"],
        "role": row["role"],
    }


def revoke_token(token):
    if not isinstance(token, str) or not token:
        return False
    return session_model.revoke(_token_hash(token))


def cleanup_expired():
    return session_model.delete_expired(_utc_now())