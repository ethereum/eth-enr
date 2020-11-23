import datetime
import logging
import operator
import sqlite3
from typing import Collection, Iterable, NamedTuple, Optional, Sequence, Tuple, Union

from eth_typing import NodeID
import rlp
from rlp.exceptions import DecodingError, DeserializationError, SerializationError

from eth_enr.abc import ENRAPI
from eth_enr.enr import ENR
from eth_enr.sedes import ENR_KEY_SEDES_MAPPING

logger = logging.getLogger("eth_enr.sqlite3")

RECORD_CREATE_STATEMENT = """CREATE TABLE record (
    node_id BLOB NOT NULL,
    short_node_id INTEGER NOT NULL,
    sequence_number INTEGER NOT NULL,
    signature BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (node_id, sequence_number),
    CONSTRAINT _sequence_number_positive CHECK (sequence_number >= 0)
)
"""

RECORD_INDEXES_AND_CONSTRAINTS = (
    "CREATE UNIQUE INDEX ix_node_id_sequence_number ON record (node_id, sequence_number)",
)

FIELD_CREATE_STATEMENT = """CREATE TABLE field (
    node_id BLOB NOT NULL,
    sequence_number INTEGER NOT NULL,
    "key" BLOB NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (node_id, sequence_number, "key"),
    CONSTRAINT uix_node_id_key UNIQUE (node_id, sequence_number, "key"),
    FOREIGN KEY(node_id) REFERENCES record (node_id),
    FOREIGN KEY(sequence_number) REFERENCES record (sequence_number)
)
"""

FIELD_INDEXES_AND_CONSTRAINTS = (
    'CREATE UNIQUE INDEX ix_node_id_sequence_number_key ON field (node_id, sequence_number, "key")',  # noqa: E501
)


def create_tables(conn: sqlite3.Connection) -> None:
    record_table_exists = (
        conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", ("record",)
        ).fetchone()
        is not None
    )
    field_table_exists = (
        conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", ("field",)
        ).fetchone()
        is not None
    )

    if record_table_exists and field_table_exists:
        return

    with conn:
        conn.execute(RECORD_CREATE_STATEMENT)
        conn.commit()
        for statement in RECORD_INDEXES_AND_CONSTRAINTS:
            conn.execute(statement)
            conn.commit()

        conn.execute(FIELD_CREATE_STATEMENT)
        conn.commit()
        for statement in FIELD_INDEXES_AND_CONSTRAINTS:
            conn.execute(statement)
            conn.commit()


def _encode_enr_value(key: bytes, value: Union[int, bytes]) -> bytes:
    try:
        sedes = ENR_KEY_SEDES_MAPPING[key]
    except KeyError:
        if isinstance(value, bytes):
            return value
        else:
            raise TypeError(f"Cannot store non-bytes value: {type(value)}")
    else:
        try:
            return rlp.encode(value, sedes=sedes)  # type: ignore
        except SerializationError:
            if isinstance(value, bytes):
                return value
            else:
                raise


def _decode_enr_value(key: bytes, raw: bytes) -> Union[int, bytes]:
    try:
        sedes = ENR_KEY_SEDES_MAPPING[key]
    except KeyError:
        return raw
    else:
        try:
            return rlp.decode(raw, sedes=sedes)  # type: ignore
        except (DeserializationError, DecodingError):
            return raw


class Field(NamedTuple):
    node_id: NodeID
    sequence_number: int
    key: bytes
    value: bytes

    @classmethod
    def from_row(cls, row: Tuple[bytes, int, bytes, bytes]) -> "Field":
        (
            raw_node_id,
            sequence_number,
            key,
            value,
        ) = row
        return cls(
            node_id=NodeID(raw_node_id),
            sequence_number=sequence_number,
            key=key,
            value=value,
        )

    def to_database_params(self) -> Tuple[NodeID, int, bytes, bytes]:
        return (
            self.node_id,
            self.sequence_number,
            self.key,
            self.value,
        )


DB_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


class Record(NamedTuple):
    node_id: NodeID
    sequence_number: int
    signature: bytes

    created_at: datetime.datetime

    fields: Tuple[Field, ...]

    @classmethod
    def from_enr(cls, enr: ENRAPI) -> "Record":
        fields = tuple(
            sorted(
                (
                    Field(
                        node_id=enr.node_id,
                        sequence_number=enr.sequence_number,
                        key=key,
                        value=_encode_enr_value(key, value),
                    )
                    for key, value in enr.items()
                ),
                key=operator.attrgetter("key"),
            )
        )
        return cls(
            node_id=enr.node_id,
            sequence_number=enr.sequence_number,
            signature=enr.signature,
            created_at=datetime.datetime.utcnow(),
            fields=fields,
        )

    def to_enr(self) -> ENRAPI:
        kv_pairs = {
            field.key: _decode_enr_value(field.key, field.value)
            for field in self.fields
        }
        return ENR(
            sequence_number=self.sequence_number,
            kv_pairs=kv_pairs,
            signature=self.signature,
        )

    @classmethod
    def from_row(
        cls, row: Tuple[bytes, int, bytes, str], fields: Collection[Field]
    ) -> "Record":
        (
            raw_node_id,
            sequence_number,
            signature,
            raw_created_at,
        ) = row
        return cls(
            node_id=NodeID(raw_node_id),
            sequence_number=sequence_number,
            signature=signature,
            created_at=datetime.datetime.strptime(raw_created_at, DB_DATETIME_FORMAT),
            fields=tuple(sorted(fields, key=operator.attrgetter("key"))),
        )

    def to_database_params(self) -> Tuple[NodeID, int, int, bytes, str]:
        return (
            self.node_id,
            # The high 64 bits of the node_id for doing proximate queries
            int.from_bytes(self.node_id, "big") >> 193,
            self.sequence_number,
            self.signature,
            self.created_at.isoformat(sep=" "),
        )


RECORD_INSERT_QUERY = "INSERT INTO record (node_id, short_node_id, sequence_number, signature, created_at) VALUES (?, ?, ?, ?, ?)"  # noqa: E501

FIELD_INSERT_QUERY = (
    'INSERT INTO field (node_id, sequence_number, "key", value) VALUES (?, ?, ?, ?)'
)


def insert_record(conn: sqlite3.Connection, record: Record) -> None:
    with conn:
        conn.execute(RECORD_INSERT_QUERY, record.to_database_params())
        field_params = tuple(field.to_database_params() for field in record.fields)
        conn.executemany(FIELD_INSERT_QUERY, field_params)


RECORD_GET_QUERY = """SELECT
    record.node_id AS record_node_id,
    record.sequence_number AS record_sequence_number,
    record.signature AS record_signature,
    record.created_at AS record_created_at

    FROM record
    WHERE record.node_id = ?
    ORDER BY record.sequence_number DESC
    LIMIT 1
"""


FIELD_GET_QUERY = """SELECT
    field.node_id AS field_node_id,
    field.sequence_number AS field_sequence_number,
    field."key" AS field_key,
    field.value AS field_value

    FROM field
    WHERE ? = field.node_id AND ? = field.sequence_number
"""


class RecordNotFound(Exception):
    pass


def get_record(conn: sqlite3.Connection, node_id: NodeID) -> Record:
    record_row = conn.execute(RECORD_GET_QUERY, (node_id,)).fetchone()
    if record_row is None:
        raise RecordNotFound(f"No record found: node_id={node_id.hex()}")
    field_rows = conn.execute(FIELD_GET_QUERY, (node_id, record_row[1])).fetchall()

    fields = tuple(Field.from_row(row) for row in field_rows)
    record = Record.from_row(row=record_row, fields=fields)
    return record


DELETE_RECORD_QUERY = """DELETE FROM record WHERE record.node_id = ?"""
DELETE_FIELD_QUERY = """DELETE FROM field WHERE field.node_id = ?"""


def delete_record(conn: sqlite3.Connection, node_id: NodeID) -> int:
    with conn:
        cursor = conn.execute(DELETE_RECORD_QUERY, (node_id,))
        conn.execute(DELETE_FIELD_QUERY, (node_id,))
    return cursor.rowcount  # type: ignore


BASE_QUERY = """SELECT
    record.node_id AS record_node_id,
    record.sequence_number AS record_sequence_number,
    record.signature AS record_signature,
    record.created_at AS record_created_at
    FROM record
    INNER JOIN (
        SELECT
            record.node_id,
            record.sequence_number,
            MAX(record.sequence_number)
        FROM record
        GROUP BY record.node_id
    ) latest_record
        ON
            record.node_id == latest_record.node_id AND
            record.sequence_number == latest_record.sequence_number
    JOIN field
        ON
            record.node_id = field.node_id AND
            record.sequence_number = field.sequence_number
    {where_statements}
    GROUP BY record.node_id
    {order_by_statement}
"""


PROXIMATE_ORDER_BY_CLAUSE = """
    ORDER BY ((?{PARAM_IDX} | record.short_node_id) - (?{PARAM_IDX} & record.short_node_id))
"""


EXISTS_CLAUSE = """EXISTS (
    SELECT 1
    FROM field
    WHERE
        record.node_id = field.node_id
        AND record.sequence_number = field.sequence_number AND field."key" = ?
)
"""


def query_records(
    conn: sqlite3.Connection,
    required_keys: Sequence[bytes] = (),
    order_closest_to: Optional[NodeID] = None,
) -> Iterable[Record]:
    num_required_keys = len(required_keys)

    if num_required_keys == 0:
        where_clause = ""
    elif num_required_keys == 1:
        where_clause = f"WHERE {EXISTS_CLAUSE}"
    else:
        query_components = tuple([f"({EXISTS_CLAUSE})"] * num_required_keys)
        combined_query_components = " AND ".join(query_components)
        where_clause = f"WHERE {combined_query_components}"

    if order_closest_to is None:
        order_by_clause = ""
        params = tuple(required_keys)
    else:
        order_by_clause = PROXIMATE_ORDER_BY_CLAUSE.format(
            PARAM_IDX=num_required_keys + 1
        )
        short_node_id = int.from_bytes(order_closest_to, "big") >> 193
        params = tuple(required_keys) + (short_node_id,)

    query = BASE_QUERY.format(
        where_statements=where_clause, order_by_statement=order_by_clause
    )

    logger.debug("query_records: query=%s  params=%r", query, params)

    for record_row in conn.execute(query, params):
        node_id, sequence_number, *_ = record_row
        field_rows = conn.execute(FIELD_GET_QUERY, (node_id, sequence_number))

        fields = tuple(Field.from_row(row) for row in field_rows.fetchall())
        record = Record.from_row(record_row, fields=fields)
        yield record
