import pytest

from eth_enr.constants import (
    IP_V4_ADDRESS_ENR_KEY,
    IP_V6_ADDRESS_ENR_KEY,
    TCP6_PORT_ENR_KEY,
    TCP_PORT_ENR_KEY,
    UDP6_PORT_ENR_KEY,
    UDP_PORT_ENR_KEY,
)
from eth_enr.constraints import (
    KeyExists,
    has_tcp_ipv4_endpoint,
    has_tcp_ipv6_endpoint,
    has_udp_ipv4_endpoint,
    has_udp_ipv6_endpoint,
)
from eth_enr.enr import ENR
from eth_enr.query_db import QueryableENRDB
from eth_enr.tools.factories import (
    ENRFactory,
    ENRManagerFactory,
    IPv4Factory,
    IPv6Factory,
    PrivateKeyFactory,
)


@pytest.fixture
def enr_db(conn):
    return QueryableENRDB(conn)


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


def test_query_with_enr_sequence_number_zero(enr_db):
    enr = ENR.from_repr(
        "enr:-Ji4QEdP7fMAICGFlUAxY2cbTYXbPImZzMoKHFyssXNz7zWRNkFZ7Q4EJo3rZsDUVbyo5e_d-zBIDCUHgq72oEIokSaAgmlkgnY0gmlwhMCzfZuJc2VjcDI1NmsxoQNCiVGdz4CJY3sD7bHTrhPcgOu18gfMuyc6kgicqYR_0YN0Y3CC192EdGVzdId2YWx1ZS1Bg3VkcIK0fw"  # noqa: E501
    )

    assert b"test" in enr
    assert enr.sequence_number == 0

    enr_db.set_enr(enr)

    enr_results = set(enr_db.query(KeyExists(b"test")))
    assert len(enr_results) == 1

    assert enr in enr_results


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
    # doesn't have either key
    enr_a = ENRFactory.minimal()
    # two have the correct keys
    enr_b = ENRFactory()
    enr_c = ENRFactory()

    # missing port
    enr_d_manager = ENRManagerFactory()
    enr_d_manager.update((IP_V4_ADDRESS_ENR_KEY, IPv4Factory().packed))

    enr_d = enr_d_manager.enr

    # missing ip address
    enr_e_manager = ENRManagerFactory()
    enr_e_manager.update((UDP_PORT_ENR_KEY, 30303))
    enr_e_manager.update((TCP_PORT_ENR_KEY, 30303))

    enr_e = enr_e_manager.enr

    enr_db.set_enr(enr_a)
    enr_db.set_enr(enr_b)
    enr_db.set_enr(enr_c)
    enr_db.set_enr(enr_d)
    enr_db.set_enr(enr_e)

    enr_results = tuple(enr_db.query(constraint))
    assert len(enr_results) == 2

    assert set(enr_results) == {enr_b, enr_c}


@pytest.mark.parametrize("constraint", (has_tcp_ipv6_endpoint, has_udp_ipv6_endpoint))
def test_query_for_ipv6_endpoint(enr_db, constraint):
    ip6 = IPv6Factory()

    # missing both keys
    enr_a = ENRFactory.minimal()

    # has both
    enr_b = ENRFactory(
        custom_kv_pairs={
            b"ip6": ip6.packed,
            b"tcp6": 30303,
            b"udp6": 30303,
        }
    )

    # missing port
    enr_c_manager = ENRManagerFactory()
    enr_c_manager.update((IP_V6_ADDRESS_ENR_KEY, ip6.packed))

    enr_c = enr_c_manager.enr

    # missing ip address
    enr_d_manager = ENRManagerFactory()
    enr_d_manager.update((UDP6_PORT_ENR_KEY, 30303))
    enr_d_manager.update((TCP6_PORT_ENR_KEY, 30303))

    enr_d = enr_d_manager.enr

    enr_db.set_enr(enr_a)
    enr_db.set_enr(enr_b)
    enr_db.set_enr(enr_c)
    enr_db.set_enr(enr_d)

    enr_results = tuple(enr_db.query(constraint))
    assert len(enr_results) == 1

    enr = enr_results[0]

    assert enr == enr_b
