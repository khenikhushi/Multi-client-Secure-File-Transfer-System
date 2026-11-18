from database.connection import query_one


def get_id(name):
    row = query_one("SELECT id FROM roles WHERE name = %s", (name,))
    return row["id"] if row else None