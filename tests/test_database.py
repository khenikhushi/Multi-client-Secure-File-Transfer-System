"""
tests/test_database.py  [PERSON B]
Needs a running MySQL/MariaDB configured in .env (run `python -m database.init_db` first).
Skipped automatically if the database is not reachable.
Run:  pytest tests/test_database.py -v
"""
import threading

import pytest

from database import connection

try:
    connection.query_one("SELECT 1 AS ok")
    DB_UP = True
except Exception:
    DB_UP = False

pytestmark = pytest.mark.skipif(not DB_UP, reason="database not reachable")


@pytest.fixture(autouse=True)
def clean_test_users():
    connection.execute("DELETE FROM users WHERE username LIKE 'tst\\_%'")
    yield
    connection.execute("DELETE FROM users WHERE username LIKE 'tst\\_%'")


def test_roles_seeded():
    names = {r["name"] for r in connection.query_all("SELECT name FROM roles")}
    assert {"user", "admin"} <= names


def test_insert_and_select_roundtrip():
    _, new_id = connection.execute(
        "INSERT INTO users (username, password_hash) VALUES (%s, %s)", ("tst_a", "hash")
    )
    row = connection.query_one("SELECT * FROM users WHERE id = %s", (new_id,))
    assert row["username"] == "tst_a" and row["role_id"] == 1 and row["is_active"] == 1


def test_sql_injection_string_is_just_data():
    evil = "x'; DROP TABLE users; --"
    connection.execute("INSERT INTO audit_logs (username, event_type, success) VALUES (%s,'TEST',0)", (evil,))
    row = connection.query_one("SELECT username FROM audit_logs WHERE username = %s", (evil,))
    assert row["username"] == evil
    assert connection.query_one("SELECT COUNT(*) AS n FROM users") is not None  # table still exists
    connection.execute("DELETE FROM audit_logs WHERE event_type = 'TEST'")


def test_duplicate_username_raises():
    connection.execute("INSERT INTO users (username, password_hash) VALUES ('tst_dup','h')")
    with pytest.raises(Exception):
        connection.execute("INSERT INTO users (username, password_hash) VALUES ('tst_dup','h')")


def test_pool_handles_many_threads():
    errors = []

    def work():
        try:
            for _ in range(20):
                assert connection.query_one("SELECT 1 AS ok")["ok"] == 1
        except Exception as e:  # collect, assert in main thread
            errors.append(e)

    threads = [threading.Thread(target=work) for _ in range(40)]  # more threads than pool size
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
