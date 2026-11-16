import os
import sqlite3

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    schema = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    conn = get_db()
    with open(schema, encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
