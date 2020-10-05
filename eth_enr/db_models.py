import datetime
from typing import Tuple, Union

import rlp
from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, scoped_session, sessionmaker

from eth_enr.abc import ENRAPI
from eth_enr.enr import ENR
from eth_enr.sedes import ENR_KEY_SEDES_MAPPING

Base = declarative_base()

Session = scoped_session(sessionmaker())


def _encode_enr_value(key: bytes, value: Union[int, bytes]) -> bytes:
    try:
        sedes = ENR_KEY_SEDES_MAPPING[key]
    except KeyError:
        if isinstance(value, bytes):
            return value
        else:
            raise TypeError("Cannot store non-bytes value: {type(value)}")
    else:
        return rlp.encode(value, sedes=sedes)  # type: ignore


def _decode_enr_value(key: bytes, raw: bytes) -> Union[int, bytes]:
    try:
        sedes = ENR_KEY_SEDES_MAPPING[key]
    except KeyError:
        return raw
    else:
        return rlp.decode(raw, sedes=sedes)  # type: ignore


class Record(Base):
    query = Session.query_property()

    __tablename__ = "record"
    __table_args__ = (
        Index(
            "ix_node_id_sequence_number",
            "node_id",
            "sequence_number",
            unique=True,
        ),
        CheckConstraint("sequence_number >= 0", name="_sequence_number_positive"),
    )

    node_id = Column(LargeBinary(32), primary_key=True)
    sequence_number = Column(Integer, primary_key=True)

    signature = Column(LargeBinary(), nullable=False)

    created_at = Column(DateTime(), nullable=False)

    fields = relationship(
        "Field",
        back_populates="record",
        foreign_keys="(Field.node_id, Field.sequence_number)",
        primaryjoin=(
            "and_("
            "Record.node_id == Field.node_id, "
            "Record.sequence_number == Field.sequence_number"
            ")"
        ),
    )

    @classmethod
    def from_enr(cls, enr: ENRAPI) -> Tuple["Record", Tuple["Field", ...]]:
        record = cls(
            node_id=enr.node_id,
            sequence_number=enr.sequence_number,
            signature=enr.signature,
            created_at=datetime.datetime.utcnow(),
        )
        fields = tuple(
            Field(  # type: ignore
                node_id=enr.node_id,
                sequence_number=enr.sequence_number,
                key=key,
                value=_encode_enr_value(key, value),
            )
            for key, value in enr.items()
        )
        return record, fields

    def to_enr(self) -> ENRAPI:
        kv_pairs = {
            field.key: _decode_enr_value(field.key, field.value)
            for field in self.fields  # type: ignore
        }
        return ENR(
            sequence_number=self.sequence_number,
            kv_pairs=kv_pairs,
            signature=self.signature,
        )


class Field(Base):
    query = Session.query_property()

    __tablename__ = "field"
    __table_args__ = (
        Index(
            "ix_node_id_sequence_number_key",
            "node_id",
            "sequence_number",
            "key",
            unique=True,
        ),
        UniqueConstraint(
            "node_id",
            "sequence_number",
            "key",
            name="uix_node_id_key",
        ),
    )

    node_id = Column(LargeBinary(32), ForeignKey("record.node_id"), primary_key=True)
    sequence_number = Column(
        Integer, ForeignKey("record.sequence_number"), primary_key=True
    )
    key = Column(LargeBinary(), primary_key=True)
    value = Column(LargeBinary(), nullable=False)

    record = relationship(
        "Record",
        back_populates="fields",
        foreign_keys=(node_id, sequence_number),
        primaryjoin=(
            "and_("
            "Record.node_id == Field.node_id, "
            "Record.sequence_number == Field.sequence_number"
            ")"
        ),
    )
