import logging
from typing import Iterable

from eth_typing import NodeID
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import ClauseElement, desc

from eth_enr.abc import ENRAPI, ConstraintAPI, ENRDatabaseAPI, IdentitySchemeRegistryAPI
from eth_enr.constraints import (
    HasTCPIPv4Endpoint,
    HasTCPIPv6Endpoint,
    HasUDPIPv4Endpoint,
    HasUDPIPv6Endpoint,
    KeyExists,
)
from eth_enr.db_models import Field, Record, Session
from eth_enr.exceptions import OldSequenceNumber, UnknownIdentityScheme
from eth_enr.identity_schemes import default_identity_scheme_registry


def _get_filters(*constraints: ConstraintAPI) -> Iterable[ClauseElement]:
    for constraint in constraints:
        if isinstance(constraint, KeyExists):
            yield Record.fields.any(Field.key == constraint.key)
        elif isinstance(constraint, HasTCPIPv4Endpoint):
            yield Record.fields.any(Field.key == b"ip")
            yield Record.fields.any(Field.key == b"tcp")
        elif isinstance(constraint, HasTCPIPv6Endpoint):
            yield Record.fields.any(Field.key == b"ip6")
            yield Record.fields.any(Field.key == b"tcp6")
        elif isinstance(constraint, HasUDPIPv4Endpoint):
            yield Record.fields.any(Field.key == b"ip")
            yield Record.fields.any(Field.key == b"udp")
        elif isinstance(constraint, HasUDPIPv6Endpoint):
            yield Record.fields.any(Field.key == b"ip6")
            yield Record.fields.any(Field.key == b"udp6")
        else:
            raise TypeError(f"Unsupported constraint type: {type(constraint)}")


class QueryableENRDB(ENRDatabaseAPI):
    logger = logging.getLogger("eth_enr.ENRDB")

    def __init__(
        self,
        session: Session,  # type: ignore
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_identity_scheme_registry,
    ) -> None:
        self.session = session
        self._identity_scheme_registry = identity_scheme_registry

    @property
    def identity_scheme_registry(self) -> IdentitySchemeRegistryAPI:
        return self._identity_scheme_registry

    def _validate_identity_scheme(self, enr: ENRAPI) -> None:
        """
        Check that we know the identity scheme of the ENR.

        This check should be performed whenever an ENR is inserted or updated in serialized form to
        make sure retrieving it at a later time will succeed (deserializing the ENR would fail if
        we don't know the identity scheme).
        """
        if enr.identity_scheme.id not in self.identity_scheme_registry:
            raise UnknownIdentityScheme(
                f"ENRs identity scheme with id {enr.identity_scheme.id!r} unknown to ENR DBs "
                f"identity scheme registry"
            )

    def set_enr(self, enr: ENRAPI) -> None:
        record, fields = Record.from_enr(enr)

        try:
            with self.session.begin_nested():  # type: ignore
                self.session.add(record)  # type: ignore
                self.session.add_all(fields)  # type: ignore
        except IntegrityError:
            raise OldSequenceNumber

    def get_enr(self, node_id: NodeID) -> ENRAPI:
        record: Record = (
            self.session.query(Record)  # type: ignore
            .filter(
                Record.node_id == node_id,
            )
            .order_by(desc("sequence_number"))
            .first()
        )
        if record is None:
            raise KeyError(node_id)

        return record.to_enr()

    def delete_enr(self, node_id: NodeID) -> None:
        with self.session.begin_nested():  # type: ignore
            deleted_rows = sum(
                (
                    self.session.query(Field).filter(Field.node_id == node_id).delete(),  # type: ignore  # noqa: E501
                    self.session.query(Record)  # type: ignore
                    .filter(Record.node_id == node_id)
                    .delete(),
                )
            )
        if not deleted_rows:
            raise KeyError(node_id)

    def query(self, *constraints: ConstraintAPI) -> Iterable[ENRAPI]:
        filters = _get_filters(*constraints)
        records: Iterable[Record] = (
            self.session.query(Record)  # type: ignore
            .join(Record.fields)
            .group_by(
                Record.node_id,
            )
            .having(
                func.max(Record.sequence_number),
            )
            .filter(*filters)
            .all()
        )
        return (record.to_enr() for record in records)
