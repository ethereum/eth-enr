import base64
import operator
from typing import AbstractSet, Any, Iterator, Mapping, Tuple, Type, ValuesView

from eth_typing import NodeID
from eth_utils import ValidationError
import rlp

from eth_enr.abc import (
    ENRAPI,
    CommonENRAPI,
    IdentitySchemeAPI,
    IdentitySchemeRegistryAPI,
    UnsignedENRAPI,
)
from eth_enr.constants import ENR_REPR_PREFIX, IDENTITY_SCHEME_ENR_KEY
from eth_enr.identity_schemes import (
    default_identity_scheme_registry as default_id_scheme_registry,
)
from eth_enr.identity_schemes import IdentitySchemeRegistry
from eth_enr.sedes import ENRContentSedes, ENRSedes


class ENRCommon(CommonENRAPI):
    def __init__(
        self,
        sequence_number: int,
        kv_pairs: Mapping[bytes, Any],
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_id_scheme_registry,
    ) -> None:
        self._sequence_number = sequence_number
        self._kv_pairs = dict(kv_pairs)
        self._identity_scheme = self._pick_identity_scheme(identity_scheme_registry)

        self._validate_sequence_number()
        self.identity_scheme.validate_enr_structure(self)

    def _validate_sequence_number(self) -> None:
        if self.sequence_number < 0:
            raise ValidationError("Sequence number is negative")

    def _pick_identity_scheme(
        self, identity_scheme_registry: IdentitySchemeRegistryAPI
    ) -> Type[IdentitySchemeAPI]:
        try:
            identity_scheme_id = self[IDENTITY_SCHEME_ENR_KEY]
        except KeyError:
            raise ValidationError("ENR does not specify identity scheme")

        try:
            return identity_scheme_registry[identity_scheme_id]
        except KeyError:
            raise ValidationError(
                f"ENR uses unsupported identity scheme {identity_scheme_id}"
            )

    @property
    def identity_scheme(self) -> Type[IdentitySchemeAPI]:
        return self._identity_scheme

    @property
    def sequence_number(self) -> int:
        return self._sequence_number

    @property
    def public_key(self) -> bytes:
        try:
            return self.identity_scheme.extract_public_key(self)
        except KeyError:
            raise Exception(
                "Invariant: presence of public key in ENR has been checked in identity scheme "
                "structure check during initialization"
            )

    @property
    def node_id(self) -> NodeID:
        try:
            return self.identity_scheme.extract_node_id(self)
        except KeyError:
            raise Exception(
                "Invariant: presence of public key in ENR has been checked in identity scheme "
                "structure check during initialization"
            )

    def get_signing_message(self) -> bytes:
        return rlp.encode(self, ENRContentSedes)  # type: ignore

    #
    # Mapping interface
    #
    def __getitem__(self, key: bytes) -> Any:
        return self._kv_pairs[key]

    def __iter__(self) -> Iterator[bytes]:
        return iter(self._kv_pairs)

    def __len__(self) -> int:
        return len(self._kv_pairs)

    def __contains__(self, key: Any) -> bool:
        return key in self._kv_pairs

    def keys(self) -> AbstractSet[bytes]:
        return self._kv_pairs.keys()

    def values(self) -> ValuesView[Any]:
        return self._kv_pairs.values()

    def items(self) -> AbstractSet[Tuple[bytes, Any]]:
        return self._kv_pairs.items()

    def get(self, key: bytes, default: Any = None) -> Any:
        return self._kv_pairs.get(key, default)


class UnsignedENR(ENRCommon, UnsignedENRAPI):
    def to_signed_enr(self, private_key: bytes) -> "ENR":
        signature = self.identity_scheme.create_enr_signature(self, private_key)

        transient_identity_scheme_registry = IdentitySchemeRegistry()
        transient_identity_scheme_registry.register(self.identity_scheme)

        return ENR(
            self.sequence_number,
            dict(self),
            signature,
            identity_scheme_registry=transient_identity_scheme_registry,
        )

    def __eq__(self, other: Any) -> bool:
        return other.__class__ is self.__class__ and dict(other) == dict(self)

    def __hash__(self) -> int:
        sorted_key_value_pairs = tuple(sorted(self.items(), key=operator.itemgetter(0)))
        return hash((self.sequence_number, sorted_key_value_pairs))


class ENR(ENRCommon, ENRSedes, ENRAPI):
    def __init__(
        self,
        sequence_number: int,
        kv_pairs: Mapping[bytes, Any],
        signature: bytes,
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_id_scheme_registry,
    ) -> None:
        self._signature = signature
        super().__init__(sequence_number, kv_pairs, identity_scheme_registry)

    @classmethod
    def from_repr(
        cls,
        representation: str,
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_id_scheme_registry,
    ) -> "ENR":
        if not representation.startswith("enr:"):
            raise ValidationError(f"Invalid ENR representation: {representation}")

        unpadded_b64 = representation[4:]
        padded_b64 = unpadded_b64 + "=" * (4 - len(unpadded_b64) % 4)
        rlp_encoded = base64.urlsafe_b64decode(padded_b64)
        return rlp.decode(  # type: ignore
            rlp_encoded, cls, identity_scheme_registry=identity_scheme_registry
        )

    @property
    def signature(self) -> bytes:
        return self._signature

    def validate_signature(self) -> None:
        self.identity_scheme.validate_enr_signature(self)

    def __eq__(self, other: Any) -> bool:
        return (
            other.__class__ is self.__class__
            and other.sequence_number == self.sequence_number
            and dict(other) == dict(self)
            and other.signature == self.signature
        )

    def __hash__(self) -> int:
        sorted_key_value_pairs = tuple(sorted(self.items(), key=operator.itemgetter(0)))
        return hash((self.signature, self.sequence_number, sorted_key_value_pairs))

    def __repr__(self) -> str:
        base64_rlp = base64.urlsafe_b64encode(rlp.encode(self))
        unpadded_base64_rlp = base64_rlp.rstrip(b"=")
        return "".join((ENR_REPR_PREFIX, unpadded_base64_rlp.decode("ASCII")))
