import sqlite3

import pytest

from eth_enr.sqlite3_db import create_tables


@pytest.fixture
def base_conn():
    return sqlite3.connect(":memory:")


@pytest.fixture
def conn(base_conn):
    create_tables(base_conn)
    return base_conn


@pytest.fixture
def cursor(conn):
    return conn.cursor()
