from database.connection import execute, query_one


def create_user(username, password_hash, role_id=1):
    _, user_id = execute(
        "INSERT INTO users (username, password_hash, role_id) VALUES (%s,%s,%s)",
        (username, password_hash, role_id),
    )
    return user_id


def get_for_login(username):
    return query_one(
        "SELECT u.id, u.username, u.password_hash, u.is_active, "
        "u.failed_attempts, u.locked_until, "
        "(u.locked_until IS NOT NULL AND u.locked_until > UTC_TIMESTAMP()) AS is_locked, "
        "r.name AS role "
        "FROM users u JOIN roles r ON r.id=u.role_id "
        "WHERE u.username=%s",
        (username,),
    )


def record_failed_login(user_id):
    execute("UPDATE users SET failed_attempts=failed_attempts+1 WHERE id=%s", (user_id,))
    row = query_one("SELECT failed_attempts FROM users WHERE id=%s", (user_id,))
    return int(row["failed_attempts"]) if row else 0


def reset_failed_logins(user_id):
    execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=%s", (user_id,))


def lock_account(user_id, seconds):
    execute(
        "UPDATE users SET locked_until=UTC_TIMESTAMP() + INTERVAL %s SECOND WHERE id=%s",
        (seconds, user_id),
    )


def update_password_hash(user_id, password_hash):
    execute("UPDATE users SET password_hash=%s WHERE id=%s", (password_hash, user_id))