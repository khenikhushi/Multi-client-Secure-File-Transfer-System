from database.connection import execute, query_one


def create(user_id, token_hash, ip, expires_at):
    _, session_id = execute(
        "INSERT INTO sessions (user_id, token_hash, ip, expires_at) "
        "VALUES (%s,%s,%s,%s)",
        (user_id, token_hash, ip, expires_at),
    )
    return session_id


def get_active(token_hash, now):
    return query_one(
        "SELECT s.id, s.user_id, u.username, r.name AS role "
        "FROM sessions s "
        "JOIN users u ON u.id=s.user_id "
        "JOIN roles r ON r.id=u.role_id "
        "WHERE s.token_hash=%s AND s.revoked=0 "
        "AND s.expires_at>%s AND u.is_active=1",
        (token_hash, now),
    )


def revoke(token_hash):
    rows, _ = execute("UPDATE sessions SET revoked=1 WHERE token_hash=%s", (token_hash,))
    return rows > 0


def delete_expired(now):
    rows, _ = execute("DELETE FROM sessions WHERE expires_at <= %s", (now,))
    return rows