"""
database/connection.py

A small MySQL connection pool plus three helper functions so the rest of
the code never builds SQL strings by hand. ALWAYS pass values through
`params` (parameterized queries) to prevent SQL injection:

    query_one("SELECT * FROM users WHERE username = %s", (name,))   # GOOD
    query_one("SELECT * FROM users WHERE username = '" + name + "'")  # NEVER
"""
import threading
from contextlib import contextmanager

from mysql.connector import pooling

import config

_pool = None
_pool_lock = threading.Lock()
_slots = None  # limits how many threads hold a connection at once
POOL_WAIT_SECONDS = 30  # how long a thread waits for a free connection


def _get_pool():
    """Create the pool on first use (thread-safe)."""
    global _pool, _slots
    with _pool_lock:
        if _pool is None:
            size = min(config.DB_POOL_SIZE, 32)
            _slots = threading.BoundedSemaphore(size)
            _pool = pooling.MySQLConnectionPool(
                pool_name="secure_ft_pool",
                pool_size=size,
                host=config.DB_HOST,
                port=config.DB_PORT,
                user=config.DB_USER,
                password=config.DB_PASSWORD,
                database=config.DB_NAME,
                charset="utf8mb4",
                autocommit=False,
            )
        return _pool


def reset_pool():
    """Forget the pool (used by tests that change settings)."""
    global _pool, _slots
    with _pool_lock:
        _pool = None
        _slots = None


@contextmanager
def get_connection():
    """
    Borrow a connection; it goes back to the pool when the block ends.

    mysql-connector raises an error immediately when every pooled connection
    is busy. With many client threads we want them to WAIT their turn instead,
    so a semaphore with the same size as the pool makes extra threads queue up.
    """
    pool = _get_pool()
    slots = _slots
    if not slots.acquire(timeout=POOL_WAIT_SECONDS):
        raise RuntimeError("timed out waiting for a database connection")
    try:
        conn = pool.get_connection()
        try:
            yield conn
        finally:
            conn.close()  # for pooled connections, close() returns it to the pool
    finally:
        slots.release()


def query_one(sql, params=()):
    """Run a SELECT and return the first row as a dict (or None)."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(sql, params)
            return cur.fetchone()
        finally:
            cur.close()


def query_all(sql, params=()):
    """Run a SELECT and return all rows as a list of dicts."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(sql, params)
            return cur.fetchall()
        finally:
            cur.close()


def execute(sql, params=()):
    """
    Run INSERT/UPDATE/DELETE and commit.
    Returns (rows_affected, last_insert_id). Rolls back on error and re-raises.
    """
    with get_connection() as conn:
        cur = conn.cursor()
        try:
            cur.execute(sql, params)
            conn.commit()
            return cur.rowcount, cur.lastrowid
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
