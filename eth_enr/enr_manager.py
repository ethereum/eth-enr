import logging
from typing import Mapping, Optional

from eth_keys import keys
from eth_typing import NodeID
from eth_utils import ValidationError
from eth_utils.toolz import merge

from eth_enr.abc import ENRAPI, ENRDatabaseAPI, ENRManagerAPI, IdentitySchemeRegistryAPI
from eth_enr.enr import UnsignedENR
from eth_enr.identity_schemes import default_identity_scheme_registry
from eth_enr.typing import ENR_KV


class ENRManager(ENRManagerAPI):
    _enr_db: ENRDatabaseAPI
    _enr: ENRAPI
    _node_id: NodeID
    _identity_scheme_registry: IdentitySchemeRegistryAPI

    logger = logging.getLogger("eth_enr.ENRManager")

    def __init__(
        self,
        private_key: keys.PrivateKey,
        enr_db: ENRDatabaseAPI,
        kv_pairs: Optional[Mapping[bytes, bytes]] = None,
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_identity_scheme_registry,  # noqa: E501
    ) -> None:
        self._identity_scheme_registry = identity_scheme_registry
        self._private_key = private_key
        self._enr_db = enr_db

        if kv_pairs is None:
            kv_pairs = {}

        if b"id" in kv_pairs:
            identity_kv_pairs = {}
        else:
            identity_kv_pairs = {
                b"id": b"v4",
                b"secp256k1": self._private_key.public_key.to_compressed_bytes(),
            }

        minimal_enr = UnsignedENR(
            sequence_number=1,
            kv_pairs=merge(identity_kv_pairs, kv_pairs),
            identity_scheme_registry=self._identity_scheme_registry,
        ).to_signed_enr(self._private_key.to_bytes())
        self._node_id = minimal_enr.node_id

        try:
            base_enr = self._enr_db.get_enr(minimal_enr.node_id)
        except KeyError:
            self.logger.info(
                "ENR created: seq=%d  enr=%r",
                minimal_enr.sequence_number,
                minimal_enr,
            )
            self._enr = minimal_enr
            self._enr_db.set_enr(self._enr)
        else:
            self._enr = base_enr
            self.update(*tuple(kv_pairs.items()))

    @property
    def enr(self) -> ENRAPI:
        return self._enr

    def update(self, *kv_pairs: ENR_KV) -> None:
        if not kv_pairs:
            return
        keys, values = tuple(zip(*kv_pairs))
        if len(keys) != len(set(keys)):
            raise ValidationError("Duplicate keys found in: %s", keys)

        needs_update = any(
            (
                # key needs to be deleted
                (value is None and key in self._enr)
                # key is not present or does not match the provided value
                or (
                    value is not None
                    and (key not in self._enr or self._enr[key] != value)
                )
            )
            for key, value in kv_pairs
        )
        if needs_update:
            merged_kv_pairs = {
                key: value
                for key, value in merge(dict(self._enr), dict(kv_pairs)).items()
                if value is not None
            }
            self._enr = UnsignedENR(
                sequence_number=self._enr.sequence_number + 1,
                kv_pairs=merged_kv_pairs,
                identity_scheme_registry=self._identity_scheme_registry,
            ).to_signed_enr(self._private_key.to_bytes())
            self._enr_db.set_enr(self._enr)
            self.logger.info(
                "ENR Updated: seq=%d  enr=%r", self.enr.sequence_number, self.enr
            )
