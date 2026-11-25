"""
models/file_record.py

Metadata of stored files (the bytes live on disk under storage/<user_id>/).
Every query is scoped by user_id, so one user can never reach another's rows.
"""
from database.connection import execute, query_all, query_one


def get(user_id, filename):
    return query_one(
        "SELECT id, filename, size_bytes, sha256, updated_at FROM files "
        "WHERE user_id = %s AND filename = %s",
        (user_id, filename),
    )


def list_for_user(user_id):
    return query_all(
        "SELECT filename, size_bytes, sha256, updated_at FROM files "
        "WHERE user_id = %s ORDER BY filename",
        (user_id,),
    )


def upsert(user_id, filename, size_bytes, sha256):
    """Insert a new file row, or update size/hash/time if it already exists."""
    execute(
        "INSERT INTO files (user_id, filename, size_bytes, sha256, created_at, updated_at) "
        "VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP()) "
        "ON DUPLICATE KEY UPDATE size_bytes = VALUES(size_bytes), "
        "sha256 = VALUES(sha256), updated_at = UTC_TIMESTAMP()",
        (user_id, filename, size_bytes, sha256),
    )


def delete(user_id, filename):
    rows, _ = execute("DELETE FROM files WHERE user_id = %s AND filename = %s", (user_id, filename))
    return rows > 0
