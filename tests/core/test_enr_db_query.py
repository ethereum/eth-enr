import pytest

from eth_enr.constraints import (
    KeyExists,
    has_tcp_ipv4_endpoint,
    has_tcp_ipv6_endpoint,
    has_udp_ipv4_endpoint,
    has_udp_ipv6_endpoint,
)
from eth_enr.query_db import QueryableENRDB
from eth_enr.tools.factories import ENRFactory, IPv6Factory, PrivateKeyFactory


@pytest.fixture
def enr_db(session):
    return QueryableENRDB(session)


def test_query_with_empty_database(enr_db):
    assert not tuple(enr_db.query(KeyExists(b"nope")))
    assert not tuple(enr_db.query())


def test_query_by_key_existence(enr_db):
    enr_a = ENRFactory(custom_kv_pairs={b"test": b"value-A"})
    enr_b = ENRFactory(custom_kv_pairs={b"test": b"value-B"})
    enr_c = ENRFactory()

    enr_db.set_enr(enr_a)
    enr_db.set_enr(enr_b)
    enr_db.set_enr(enr_c)

    enr_results = set(enr_db.query(KeyExists(b"test")))
    assert len(enr_results) == 2

    assert enr_a in enr_results
    assert enr_b in enr_results
    assert enr_c not in enr_results


def test_query_only_returns_latest_record(enr_db):
    private_key_a = PrivateKeyFactory().to_bytes()

    enr_a_0 = ENRFactory(sequence_number=0, private_key=private_key_a)
    enr_a_7 = ENRFactory(sequence_number=7, private_key=private_key_a)

    private_key_b = PrivateKeyFactory().to_bytes()

    enr_b_1 = ENRFactory(sequence_number=1, private_key=private_key_b)
    enr_b_9 = ENRFactory(sequence_number=9, private_key=private_key_b)

    enr_db.set_enr(enr_a_0)
    enr_db.set_enr(enr_a_7)

    enr_db.set_enr(enr_b_1)
    enr_db.set_enr(enr_b_9)

    enr_results = set(enr_db.query())
    assert len(enr_results) == 2

    assert enr_a_7 in enr_results
    assert enr_b_9 in enr_results


def test_query_excludes_outdated_matching_records(enr_db):
    private_key_a = PrivateKeyFactory().to_bytes()

    enr_a_0 = ENRFactory(
        sequence_number=0,
        private_key=private_key_a,
        custom_kv_pairs={b"test": b"value-A"},
    )
    enr_a_7 = ENRFactory(sequence_number=7, private_key=private_key_a)

    private_key_b = PrivateKeyFactory().to_bytes()

    enr_b_1 = ENRFactory(
        sequence_number=1,
        private_key=private_key_b,
        custom_kv_pairs={b"test": b"value-A"},
    )

    enr_db.set_enr(enr_a_0)
    enr_db.set_enr(enr_a_7)

    enr_db.set_enr(enr_b_1)

    enr_results = tuple(enr_db.query(KeyExists(b"test")))
    assert len(enr_results) == 1

    enr = enr_results[0]
    assert enr == enr_b_1


@pytest.mark.parametrize("constraint", (has_tcp_ipv4_endpoint, has_udp_ipv4_endpoint))
def test_query_for_ipv4_endpoint(enr_db, constraint):
    enr_a = ENRFactory.minimal()
    enr_b = ENRFactory()
    enr_c = ENRFactory.minimal()

    enr_db.set_enr(enr_a)
    enr_db.set_enr(enr_b)
    enr_db.set_enr(enr_c)

    enr_results = tuple(enr_db.query(constraint))
    assert len(enr_results) == 1

    enr = enr_results[0]

    assert enr == enr_b


@pytest.mark.parametrize("constraint", (has_tcp_ipv6_endpoint, has_udp_ipv6_endpoint))
def test_query_for_ipv6_endpoint(enr_db, constraint):
    ip6 = IPv6Factory()
    stub = ENRFactory()

    enr_a = ENRFactory.minimal()
    enr_b = ENRFactory(
        custom_kv_pairs={
            b"ip6": ip6.packed,
            b"tcp6": stub[b"tcp"],
            b"udp6": stub[b"udp"],
        }
    )
    enr_c = ENRFactory.minimal()

    enr_db.set_enr(enr_a)
    enr_db.set_enr(enr_b)
    enr_db.set_enr(enr_c)

    enr_results = tuple(enr_db.query(constraint))
    assert len(enr_results) == 1

    enr = enr_results[0]

    assert enr == enr_b
