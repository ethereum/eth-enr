import pytest

from eth_enr.enr_db import ENRDB
from eth_enr.exceptions import OldSequenceNumber, UnknownIdentityScheme
from eth_enr.identity_schemes import IdentitySchemeRegistry
from eth_enr.query_db import QueryableENRDB
from eth_enr.tools.factories import ENRFactory, PrivateKeyFactory


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

    updated_enr = ENRFactory(
        private_key=private_key, sequence_number=enr.sequence_number + 1
    )
    db.set_enr(updated_enr)
    assert db.get_enr(enr.node_id) == updated_enr

    with pytest.raises(OldSequenceNumber):
        db.set_enr(enr)


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


def test_delete_enr(enr_db):
    db = enr_db
    enr = ENRFactory()

    with pytest.raises(KeyError):
        db.delete_enr(enr.node_id)

    db.set_enr(enr)
    db.delete_enr(enr.node_id)

    with pytest.raises(KeyError):
        db.get_enr(enr.node_id)
