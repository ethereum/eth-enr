import logging
from typing import MutableMapping, Optional

from eth_typing import NodeID
import rlp

from eth_enr import ENR
from eth_enr.abc import ENRAPI, ENRDatabaseAPI, IdentitySchemeRegistryAPI
from eth_enr.exceptions import OldSequenceNumber, UnknownIdentityScheme
from eth_enr.identity_schemes import default_identity_scheme_registry


class ENRDB(ENRDatabaseAPI):
    logger = logging.getLogger("eth_enr.ENRDB")

    def __init__(
        self,
        db: MutableMapping[bytes, bytes],
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_identity_scheme_registry,
    ) -> None:
        self.db = db
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
        existing_enr: Optional[ENRAPI]
        self._validate_identity_scheme(enr)
        try:
            existing_enr = self.get_enr(enr.node_id)
        except KeyError:
            existing_enr = None
        if existing_enr and existing_enr.sequence_number > enr.sequence_number:
            raise OldSequenceNumber(
                f"Cannot overwrite existing ENR ({existing_enr.sequence_number}) with old one "
                f"({enr.sequence_number})"
            )
        self.db[self._get_enr_key(enr.node_id)] = rlp.encode(enr)

    def get_enr(self, node_id: NodeID) -> ENRAPI:
        return rlp.decode(self.db[self._get_enr_key(node_id)], sedes=ENR)  # type: ignore

    def delete_enr(self, node_id: NodeID) -> None:
        del self.db[self._get_enr_key(node_id)]

    def _get_enr_key(self, node_id: NodeID) -> bytes:
        return bytes(node_id) + b":enr"
