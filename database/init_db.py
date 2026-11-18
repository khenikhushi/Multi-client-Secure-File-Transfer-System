"""
database/init_db.py  [PERSON B]

Creates the database, tables and seed rows. Safe to run more than once.

    python -m database.init_db

Uses the DB_* values from .env. The MySQL user needs CREATE privilege
(or create the empty database yourself first).
"""
import os

import mysql.connector

import config

HERE = os.path.dirname(os.path.abspath(__file__))


def _read_statements(filename):
    """Read a .sql file and split it into individual statements."""
    with open(os.path.join(HERE, filename), "r", encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if not ln.strip().startswith("--")]
    return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]


def init_database():
    if not config.DB_PASSWORD:
        raise SystemExit("DB_PASSWORD is empty. Set it in your .env file first.")

    conn = mysql.connector.connect(
        host=config.DB_HOST, port=config.DB_PORT,
        user=config.DB_USER, password=config.DB_PASSWORD,
    )
    try:
        cur = conn.cursor()
        # DB_NAME comes from our own config; backticks guard the identifier.
        cur.execute(
            "CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4"
            % config.DB_NAME.replace("`", "")
        )
        cur.execute("USE `%s`" % config.DB_NAME.replace("`", ""))
        for filename in ("schema.sql", "seed.sql"):
            for statement in _read_statements(filename):
                cur.execute(statement)
        conn.commit()
        cur.close()
    finally:
        conn.close()
    print("Database '%s' is ready." % config.DB_NAME)


if __name__ == "__main__":
    init_database()
