import os

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ["DATABASE_URL"]


def _connect():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def fetch_all(query: str, params: tuple = ()) -> list[dict]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchall()


def fetch_one(query: str, params: tuple = ()) -> dict | None:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchone()


def execute(query: str, params: tuple = ()) -> None:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(query, params)
        conn.commit()
