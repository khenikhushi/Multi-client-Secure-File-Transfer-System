from database.connection import execute


def add(event_type, success, user_id=None, username=None, detail=None, ip=None):
    execute(
        "INSERT INTO audit_logs "
        "(user_id, username, event_type, success, detail, ip) "
        "VALUES (%s,%s,%s,%s,%s,%s)",
        (user_id, username, event_type, 1 if success else 0, detail, ip),
    )