import logging
import sqlite3
from typing import Iterable, Optional

from eth_typing import NodeID
from eth_utils import to_tuple

from eth_enr.abc import (
    ENRAPI,
    ConstraintAPI,
    IdentitySchemeRegistryAPI,
    QueryableENRDatabaseAPI,
)
from eth_enr.constants import (
    IP_V4_ADDRESS_ENR_KEY,
    IP_V6_ADDRESS_ENR_KEY,
    TCP6_PORT_ENR_KEY,
    TCP_PORT_ENR_KEY,
    UDP6_PORT_ENR_KEY,
    UDP_PORT_ENR_KEY,
)
from eth_enr.constraints import (
    ClosestTo,
    HasTCPIPv4Endpoint,
    HasTCPIPv6Endpoint,
    HasUDPIPv4Endpoint,
    HasUDPIPv6Endpoint,
    KeyExists,
)
from eth_enr.exceptions import OldSequenceNumber, UnknownIdentityScheme
from eth_enr.identity_schemes import default_identity_scheme_registry
from eth_enr.sqlite3_db import (
    Record,
    RecordNotFound,
    create_tables,
    delete_record,
    get_record,
    insert_record,
    query_records,
)


@to_tuple
def _get_required_keys(*constraints: ConstraintAPI) -> Iterable[bytes]:
    for constraint in constraints:
        if isinstance(constraint, KeyExists):
            yield constraint.key
        elif isinstance(constraint, HasTCPIPv4Endpoint):
            yield IP_V4_ADDRESS_ENR_KEY
            yield TCP_PORT_ENR_KEY
        elif isinstance(constraint, HasTCPIPv6Endpoint):
            yield IP_V6_ADDRESS_ENR_KEY
            yield TCP6_PORT_ENR_KEY
        elif isinstance(constraint, HasUDPIPv4Endpoint):
            yield IP_V4_ADDRESS_ENR_KEY
            yield UDP_PORT_ENR_KEY
        elif isinstance(constraint, HasUDPIPv6Endpoint):
            yield IP_V6_ADDRESS_ENR_KEY
            yield UDP6_PORT_ENR_KEY
        elif isinstance(constraint, ClosestTo):
            continue
        else:
            raise TypeError(f"Unsupported constraint type: {type(constraint)}")


def _get_order_closest_to(*constraints: ConstraintAPI) -> Optional[NodeID]:
    closest_to_constraints = tuple(
        constraint for constraint in constraints if isinstance(constraint, ClosestTo)
    )
    if len(closest_to_constraints) == 0:
        return None
    elif len(closest_to_constraints) == 1:
        return closest_to_constraints[0].node_id
    else:
        raise ValueError(
            f"Got multiple ClosestTo constraints: {closest_to_constraints}"
        )


class QueryableENRDB(QueryableENRDatabaseAPI):
    """
    An implementation of :class:`eth_enr.abc.QueryableENRDatabaseAPI` on top of
    the ``sqlite3`` module from the standard library.

    For use with an in-memory database:

    .. code-block:: python

        >>> connection = sqlite3.connect(":memory:")
        >>> enr_db = QueryableENRDB(connection)
        ...

    Or use with an on-disk database:

    .. code-block:: python

        >>> connection = sqlite3.connect("/path/to/db.sqlite3")
        >>> enr_db = QueryableENRDB(connection)
        ...

    The database tables will lazily be created upon class instantiation if they
    are missing.
    """

    logger = logging.getLogger("eth_enr.ENRDB")

    def __init__(
        self,
        connection: sqlite3.Connection,
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_identity_scheme_registry,
    ) -> None:
        self.connection = connection
        self._identity_scheme_registry = identity_scheme_registry

        create_tables(self.connection)

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
        """
        Write a record to the database.

        Raises :class:`eth_enr.exceptions.OldSequenceNumber` if there is
        already a record in the database with the same sequence number as the
        provided ENR record.
        """
        record = Record.from_enr(enr)

        try:
            insert_record(self.connection, record)
        except sqlite3.IntegrityError:
            raise OldSequenceNumber(enr.sequence_number)

    def get_enr(self, node_id: NodeID) -> ENRAPI:
        """
        Retrieve the ENR record with the highest sequence number for the given
        ``node_id``

        Raises ``KeyError`` if there are no records with the geven ``node_id``
        """
        try:
            record = get_record(self.connection, node_id)
        except RecordNotFound:
            raise KeyError(node_id)

        return record.to_enr()

    def delete_enr(self, node_id: NodeID) -> None:
        """
        Delete ENR records with the given ``node_id``

        Raisees ``KeyError`` if there are no records with the given ``node_id``
        """
        deleted_rows = delete_record(self.connection, node_id)

        if not deleted_rows:
            raise KeyError(node_id)

    def query(self, *constraints: ConstraintAPI) -> Iterable[ENRAPI]:
        """
        Query the database for records that match the given constraints.

        Support constraints:

        - :class:`~eth_enr.constraints.KeyExists`
        - :class:`~eth_enr.constraints.HasTCPIPv4Endpoint`
        - :class:`~eth_enr.constraints.HasUDPIPv4Endpoint`
        - :class:`~eth_enr.constraints.HasTCPIPv6Endpoint`
        - :class:`~eth_enr.constraints.HasUDPIPv6Endpoint`

        Return an iterator of matching ENR records.  Only returns the record
        with the highest sequence number for each node_id.
        """
        required_keys = _get_required_keys(*constraints)
        order_closest_to = _get_order_closest_to(*constraints)

        records_iter = query_records(
            self.connection,
            required_keys=required_keys,
            order_closest_to=order_closest_to,
        )
        for record in records_iter:
            yield record.to_enr()
