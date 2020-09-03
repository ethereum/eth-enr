import pytest

from eth_enr.enr_db import ENRDB
from eth_enr.exceptions import OldSequenceNumber, UnknownIdentityScheme
from eth_enr.identity_schemes import IdentitySchemeRegistry
from eth_enr.tools.factories import ENRFactory, PrivateKeyFactory


@pytest.fixture
def enr_db():
    return ENRDB({})


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


def test_delete_enr(enr_db):
    db = enr_db
    enr = ENRFactory()

    with pytest.raises(KeyError):
        db.delete_enr(enr.node_id)

    db.set_enr(enr)
    db.delete_enr(enr.node_id)

    with pytest.raises(KeyError):
        db.get_enr(enr.node_id)
