import pytest

from eth_enr.enr_db import ENRDB
from eth_enr.exceptions import DuplicateRecord, OldSequenceNumber, UnknownIdentityScheme
from eth_enr.identity_schemes import IdentitySchemeRegistry
from eth_enr.query_db import QueryableENRDB
from eth_enr.tools.factories import ENRFactory, ENRManagerFactory, PrivateKeyFactory


@pytest.fixture(params=("mapping", "orm"))
def enr_db(request):
    if request.param == "mapping":
        return ENRDB({})
    elif request.param == "orm":
        conn = request.getfixturevalue("conn")
        return QueryableENRDB(conn)
    else:
        raise Exception(f"Unsupported param: {request.param}")


def test_checks_identity_scheme():
    db = ENRDB(IdentitySchemeRegistry(), {})
    enr = ENRFactory()

    with pytest.raises(UnknownIdentityScheme):
        db.set_enr(enr)


def test_get_and_set_enr(enr_db):
    private_key = PrivateKeyFactory().to_bytes()
    db = enr_db
    enr = ENRFactory(private_key=private_key)

    with pytest.raises(KeyError):
        db.get_enr(enr.node_id)

    db.set_enr(enr)
    assert db.get_enr(enr.node_id) == enr


def test_get_and_set_enr_with_non_standard_values(enr_db):
    custom_kv_pairs = {
        b"ip": b"too-long-for-ipv4",
        b"ip6": b"too-short",
        b"udp": b"\x00\x01\x00",  # invalid encoding for an integer
        b"tcp": b"\x00\x01\x00",  # invalid encoding for an integer
        b"udp6": b"\x00\x01\x00",  # invalid encoding for an integer
        b"tcp6": b"\x00\x01\x00",  # invalid encoding for an integer
    }
    enr = ENRFactory(
        custom_kv_pairs=custom_kv_pairs,
    )

    for key, value in custom_kv_pairs.items():
        assert enr[key] == value

    enr_db.set_enr(enr)

    result = enr_db.get_enr(enr.node_id)
    assert result == enr

    # should be able to idempotently set the same record multiple times.
    enr_db.set_enr(enr)


def test_delete_enr(enr_db):
    db = enr_db
    enr = ENRFactory()

    with pytest.raises(KeyError):
        db.delete_enr(enr.node_id)

    db.set_enr(enr)
    db.delete_enr(enr.node_id)

    with pytest.raises(KeyError):
        db.get_enr(enr.node_id)


def test_enr_db_raises_DuplicateRecord(enr_db):
    private_key = PrivateKeyFactory().to_bytes()

    enr_a = ENRFactory(
        private_key=private_key,
        sequence_number=1,
        custom_kv_pairs={b"custom": b"enr-a"},
    )
    enr_b = ENRFactory(
        private_key=private_key,
        sequence_number=1,
        custom_kv_pairs={b"custom": b"enr-b"},
    )

    assert enr_a.node_id == enr_b.node_id
    assert enr_a.sequence_number == enr_b.sequence_number

    assert enr_a != enr_b

    # set it the first time.
    enr_db.set_enr(enr_a)

    with pytest.raises(DuplicateRecord):
        enr_db.set_enr(enr_b, raise_on_error=True)

    # without the flag it should silently ignore the error
    enr_db.set_enr(enr_b)


def test_enr_db_raises_OldSequenceNumber():
    enr_db = ENRDB({})
    enr_manager = ENRManagerFactory()

    base_enr = enr_manager.enr

    enr_manager.update((b"custom", b"test"))

    assert enr_manager.enr.sequence_number == base_enr.sequence_number + 1

    enr_db.set_enr(enr_manager.enr)

    with pytest.raises(OldSequenceNumber):
        enr_db.set_enr(base_enr, raise_on_error=True)

    # without the flag it should silently ignore the error
    enr_db.set_enr(base_enr)
