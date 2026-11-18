"""models/audit_log.py  [PERSON B]  Audit table access."""
from database.connection import execute, query_all


def add(event_type, success, user_id=None, username=None, detail=None, ip=None):
    execute(
        "INSERT INTO audit_logs (user_id, username, event_type, success, detail, ip, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, UTC_TIMESTAMP())",
        (user_id, username, event_type, 1 if success else 0, detail, ip),
    )


def recent_for_username(username, limit=50):
    return query_all(
        "SELECT * FROM audit_logs WHERE username = %s ORDER BY id DESC LIMIT %s",
        (username, int(limit)),
    )
