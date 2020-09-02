from eth_enr.enr_manager import ENRManager
from eth_enr.tools.factories import ENRFactory, PrivateKeyFactory


def test_enr_manager_creates_enr_if_not_present():
    enr_manager = ENRManager(PrivateKeyFactory())
    assert enr_manager.enr


def test_enr_manager_handles_existing_enr():
    private_key = PrivateKeyFactory()
    base_enr = ENRFactory(private_key=private_key.to_bytes(), sequence_number=0)

    enr_manager = ENRManager(private_key, base_enr=base_enr)
    assert enr_manager.enr == base_enr


def test_enr_manager_updates_existing_enr():
    private_key = PrivateKeyFactory()
    base_enr = ENRFactory(
        private_key=private_key.to_bytes(),
        sequence_number=0,
        custom_kv_pairs={b"unicorns": b"rainbows"},
    )
    assert base_enr[b"unicorns"] == b"rainbows"

    enr_manager = ENRManager(
        private_key,
        kv_pairs={b"unicorns": b"cupcakes"},
        base_enr=base_enr,
    )
    assert enr_manager.enr != base_enr
    assert enr_manager.enr.sequence_number == base_enr.sequence_number + 1
    assert enr_manager.enr[b"unicorns"] == b"cupcakes"


def test_enr_manager_update_api():
    enr_manager = ENRManager(PrivateKeyFactory())
    assert b"unicorns" not in enr_manager.enr
    base_enr = enr_manager.enr

    enr_a = enr_manager.update((b"unicorns", b"rainbows"))
    assert enr_a.sequence_number == base_enr.sequence_number + 1

    assert enr_manager.enr[b"unicorns"] == b"rainbows"

    enr_b = enr_manager.update((b"unicorns", b"cupcakes"))
    assert enr_b.sequence_number == enr_a.sequence_number + 1

    assert enr_manager.enr[b"unicorns"] == b"cupcakes"
