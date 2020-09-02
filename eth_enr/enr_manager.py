import logging
from typing import Mapping, Optional

from eth_keys import keys
from eth_utils.toolz import merge

from eth_enr.abc import ENRAPI, ENRManagerAPI, IdentitySchemeRegistryAPI
from eth_enr.enr import UnsignedENR
from eth_enr.identity_schemes import default_identity_scheme_registry
from eth_enr.typing import ENR_KV


class ENRManager(ENRManagerAPI):
    _enr: ENRAPI
    _identity_scheme_registry: IdentitySchemeRegistryAPI

    logger = logging.getLogger("eth_enr.ENRManager")

    def __init__(
        self,
        private_key: keys.PrivateKey,
        base_enr: Optional[ENRAPI] = None,
        kv_pairs: Optional[Mapping[bytes, bytes]] = None,
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_identity_scheme_registry,  # noqa: E501
    ) -> None:
        self._identity_scheme_registry = identity_scheme_registry
        self._private_key = private_key

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

        if base_enr is None:
            self.logger.info(
                "Local ENR created: seq=%d  enr=%r",
                minimal_enr.sequence_number,
                minimal_enr,
            )
            self._enr = minimal_enr
        else:
            self._enr = base_enr
            self.update(*tuple(dict(minimal_enr).items()))

    @property
    def enr(self) -> ENRAPI:
        return self._enr

    def update(self, *kv_pairs: ENR_KV) -> ENRAPI:
        if any(
            key not in self._enr or self._enr[key] != value for key, value in kv_pairs
        ):
            self._enr = UnsignedENR(
                sequence_number=self._enr.sequence_number + 1,
                kv_pairs=merge(dict(self._enr), dict(kv_pairs)),
                identity_scheme_registry=self._identity_scheme_registry,
            ).to_signed_enr(self._private_key.to_bytes())
            self.logger.info(
                "Local ENR Updated: seq=%d  enr=%r", self.enr.sequence_number, self.enr
            )
        return self._enr
