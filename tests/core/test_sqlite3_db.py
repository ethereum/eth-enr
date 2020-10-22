import datetime
import sqlite3

import pytest

from eth_enr.enr import ENR
from eth_enr.sqlite3_db import (
    Record,
    RecordNotFound,
    create_tables,
    delete_record,
    get_record,
    insert_record,
    query_records,
)
from eth_enr.tools.factories import ENRFactory


def test_database_initialization():
    conn = sqlite3.connect(":memory:")

    assert (
        conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", ("record",)
        ).fetchone()
        is None
    )
    assert (
        conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", ("field",)
        ).fetchone()
        is None
    )

    create_tables(conn)

    assert conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", ("record",)
    ).fetchone() == ("record",)
    assert conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", ("field",)
    ).fetchone() == ("field",)


def test_record_insert_and_retrieval(conn):
    enr = ENRFactory()
    record = Record.from_enr(enr)
    insert_record(conn, record)
    result = get_record(conn, enr.node_id)
    assert result == record


def test_record_get_with_unknown_node_id(conn):
    enr = ENRFactory()
    with pytest.raises(RecordNotFound):
        get_record(conn, enr.node_id)


def test_record_duplicate_insert(conn):
    enr = ENRFactory()
    record = Record.from_enr(enr)
    insert_record(conn, record)

    with pytest.raises(sqlite3.IntegrityError):
        insert_record(conn, record)

    dup_record = Record(
        node_id=record.node_id,
        sequence_number=record.sequence_number,
        signature=record.signature,
        created_at=datetime.datetime.utcnow(),
        fields=record.fields,
    )
    assert dup_record != record

    with pytest.raises(sqlite3.IntegrityError):
        insert_record(conn, dup_record)


def test_record_deletion(conn):
    record = Record.from_enr(ENRFactory())
    insert_record(conn, record)
    assert get_record(conn, record.node_id) == record

    row_count = delete_record(conn, record.node_id)
    assert row_count == 1

    with pytest.raises(RecordNotFound):
        get_record(conn, record.node_id)


def test_record_query_with_no_constraints(conn):
    record_a = Record.from_enr(ENRFactory())
    record_b = Record.from_enr(ENRFactory())

    insert_record(conn, record_a)
    insert_record(conn, record_b)

    all_records = tuple(query_records(conn))
    assert set(all_records) == {record_a, record_b}


def test_record_query_with_enr_sequence_zero(conn):
    # This is more of a regression test.  Previously the SQL query used a
    # HAVING clause which didn't work correctly when the only record had a
    # sequence number of 0.
    enr = ENR.from_repr(
        "enr:-Ji4QEdP7fMAICGFlUAxY2cbTYXbPImZzMoKHFyssXNz7zWRNkFZ7Q4EJo3rZsDUVbyo5e_d-zBIDCUHgq72oEIokSaAgmlkgnY0gmlwhMCzfZuJc2VjcDI1NmsxoQNCiVGdz4CJY3sD7bHTrhPcgOu18gfMuyc6kgicqYR_0YN0Y3CC192EdGVzdId2YWx1ZS1Bg3VkcIK0fw"  # noqa: E501
    )
    record = Record.from_enr(enr)
    insert_record(conn, record)
    assert get_record(conn, record.node_id) == record

    assert b"test" in enr

    results = tuple(query_records(conn, required_keys=(b"test",)))

    assert len(results) == 1
    assert results[0] == record


def test_record_query_with_key_present_in_earlier_record(conn):
    # Demonstrate that when we have an *outdated* record with the given key
    # that it doesn't get returned in the query
    enr_0 = ENR.from_repr(
        "enr:-Ji4QP4nHj12UZ8um1c9pplfNYzD7tmDKm5zjWXAQbtvaHQGHYfgHPBNMqPrKjkw1vPnzhxTxYvKxQaYsTsr8tXuG-aAgmlkgnY0gmlwhFIKDgiJc2VjcDI1NmsxoQLBnsAJ3ol6-WoC_oldxmv85K9CVaIxFD1U1qY5ik9-7YN0Y3CCme-EdGVzdId2YWx1ZS1Bg3VkcILjVw"  # noqa: E501
    )
    enr_7 = ENR.from_repr(
        "enr:-Iu4QAEoWs6MtSYdWONcnR7ekG2lunNxxVlg_xgTKzAUTJDLeqQo06oKbnesHUBl77IFzlnj_GcoYNVnM13ap0i3GAYHgmlkgnY0gmlwhDN7BECJc2VjcDI1NmsxoQLBnsAJ3ol6-WoC_oldxmv85K9CVaIxFD1U1qY5ik9-7YN0Y3CCxMGDdWRwguHh"  # noqa: E501
    )

    assert enr_0.node_id == enr_7.node_id
    assert enr_0.sequence_number == 0
    assert enr_7.sequence_number == 7

    assert b"test" in enr_0
    assert b"test" not in enr_7

    insert_record(conn, Record.from_enr(enr_0))
    insert_record(conn, Record.from_enr(enr_7))

    results = tuple(query_records(conn, required_keys=(b"test",)))

    assert len(results) == 0


def test_record_query_with_single_key_constraint(conn):
    record_a = Record.from_enr(ENRFactory())
    record_b = Record.from_enr(
        ENRFactory(
            custom_kv_pairs={b"test": b"value-A"},
        )
    )
    record_c = Record.from_enr(ENRFactory())
    record_d = Record.from_enr(
        ENRFactory(
            custom_kv_pairs={b"test": b"value-A"},
        )
    )

    insert_record(conn, record_a)
    insert_record(conn, record_b)
    insert_record(conn, record_c)
    insert_record(conn, record_d)

    matched_records = tuple(query_records(conn, required_keys=(b"test",)))
    assert len(matched_records) == 2
    assert set(matched_records) == {record_b, record_d}


def test_record_query_with_multi_key_constraint(conn):
    record_a = Record.from_enr(
        ENRFactory(
            custom_kv_pairs={b"test-a": b"value-A"},
        )
    )
    record_b = Record.from_enr(
        ENRFactory(
            custom_kv_pairs={b"test-a": b"value-A", b"test-b": b"value-B"},
        )
    )
    record_c = Record.from_enr(
        ENRFactory(
            custom_kv_pairs={b"test-b": b"value-B"},
        )
    )
    record_d = Record.from_enr(ENRFactory())
    record_e = Record.from_enr(
        ENRFactory(
            custom_kv_pairs={b"test-a": b"value-A", b"test-b": b"value-B"},
        )
    )

    insert_record(conn, record_a)
    insert_record(conn, record_b)
    insert_record(conn, record_c)
    insert_record(conn, record_d)
    insert_record(conn, record_e)

    matched_records = tuple(query_records(conn, required_keys=(b"test-a", b"test-b")))
    assert len(matched_records) == 2
    assert set(matched_records) == {record_b, record_e}
