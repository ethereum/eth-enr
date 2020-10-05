from eth_enr.db_models import Record
from eth_enr.tools.factories import ENRFactory


def test_orm_enr_saving_and_loading(session):
    enr = ENRFactory()
    record, fields = Record.from_enr(enr)

    with session.begin_nested():
        session.add(record)
        session.add_all(fields)

    record_from_db = (
        Record.query.filter(
            Record.node_id == enr.node_id,
        )
        .filter(Record.sequence_number == enr.sequence_number)
        .one()
    )
    enr_from_db = record_from_db.to_enr()

    assert enr_from_db == enr
