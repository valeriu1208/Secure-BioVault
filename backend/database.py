from typing import Any, Iterator

from fastapi import Request
from psycopg import Connection
from psycopg_pool import ConnectionPool


def get_db_connection(request: Request) -> Iterator[Connection[Any]]:
    pool: ConnectionPool = request.app.state.db_pool
    with pool.connection() as connection:
        yield connection