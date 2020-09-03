from eth_utils import ValidationError
import pytest

from eth_enr.enr_db import ENRDB
from eth_enr.enr_manager import ENRManager
from eth_enr.tools.factories import ENRFactory, PrivateKeyFactory


@pytest.fixture
def enr_db():
    return ENRDB({})


def test_enr_manager_creates_enr_if_not_present(enr_db):
    enr_manager = ENRManager(PrivateKeyFactory(), enr_db)
    assert enr_manager.enr
    assert enr_db.get_enr(enr_manager.enr.node_id) == enr_manager.enr


def test_enr_manager_handles_existing_enr_in_database(enr_db):
    private_key = PrivateKeyFactory()
    enr = ENRFactory(private_key=private_key.to_bytes(), sequence_number=10)
    enr_db.set_enr(enr)

    enr_manager = ENRManager(private_key, enr_db)
    assert enr_manager.enr == enr


def test_enr_manager_updates_existing_enr(enr_db):
    private_key = PrivateKeyFactory()
    base_enr = ENRFactory(
        private_key=private_key.to_bytes(),
        sequence_number=0,
        custom_kv_pairs={b"unicorns": b"rainbows"},
    )
    assert base_enr[b"unicorns"] == b"rainbows"
    enr_db.set_enr(base_enr)

    enr_manager = ENRManager(
        private_key,
        enr_db,
        kv_pairs={b"unicorns": b"cupcakes"},
    )
    assert enr_manager.enr != base_enr
    assert enr_manager.enr.sequence_number == base_enr.sequence_number + 1
    assert enr_manager.enr[b"unicorns"] == b"cupcakes"
    assert enr_manager.enr == enr_db.get_enr(enr_manager.enr.node_id)


def test_enr_manager_update_api(enr_db):
    enr_manager = ENRManager(PrivateKeyFactory(), enr_db)
    assert b"unicorns" not in enr_manager.enr
    base_enr = enr_manager.enr

    enr_manager.update((b"unicorns", b"rainbows"))
    enr_a = enr_manager.enr
    assert enr_a.sequence_number == base_enr.sequence_number + 1
    assert enr_manager.enr == enr_db.get_enr(enr_manager.enr.node_id)

    assert enr_manager.enr[b"unicorns"] == b"rainbows"

    enr_manager.update((b"unicorns", b"cupcakes"))
    enr_b = enr_manager.enr
    assert enr_b.sequence_number == enr_a.sequence_number + 1
    assert enr_manager.enr == enr_db.get_enr(enr_manager.enr.node_id)

    assert enr_manager.enr[b"unicorns"] == b"cupcakes"

    with pytest.raises(ValidationError):
        enr_manager.update((b"dup", b"a"), (b"dup", b"b"))

    enr_manager.update((b"unicorns", None))
    enr_c = enr_manager.enr
    assert enr_manager.enr == enr_db.get_enr(enr_manager.enr.node_id)

    with pytest.raises(KeyError):
        enr_c[b"unicorns"]
