from abc import ABC, abstractmethod
from collections import UserDict
from typing import TYPE_CHECKING, Any, Mapping, Tuple, Type

from eth_enr.typing import ENR_KV, IDNonce, NodeID

# https://github.com/python/mypy/issues/5264#issuecomment-399407428
if TYPE_CHECKING:
    IdentitySchemeRegistryAPI = UserDict[bytes, Type["IdentitySchemeAPI"]]
else:
    IdentitySchemeRegistryAPI = UserDict


class CommonENRAPI(Mapping[bytes, Any], ABC):
    @property
    @abstractmethod
    def identity_scheme(self) -> Type["IdentitySchemeAPI"]:
        ...

    @property
    @abstractmethod
    def sequence_number(self) -> int:
        ...

    @property
    @abstractmethod
    def public_key(self) -> bytes:
        ...

    @property
    @abstractmethod
    def node_id(self) -> NodeID:
        ...

    @abstractmethod
    def get_signing_message(self) -> bytes:
        ...

    @abstractmethod
    def __eq__(self, other: Any) -> bool:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...


class UnsignedENRAPI(CommonENRAPI):
    @abstractmethod
    def to_signed_enr(self, private_key: bytes) -> "ENRAPI":
        ...


class ENRAPI(CommonENRAPI):
    @classmethod
    @abstractmethod
    def from_repr(
        cls,
        representation: str,
        identity_scheme_registry: IdentitySchemeRegistryAPI,
    ) -> "ENRAPI":
        ...

    @property
    @abstractmethod
    def signature(self) -> bytes:
        ...

    @abstractmethod
    def validate_signature(self) -> None:
        ...


class ENRManagerAPI(ABC):
    @property
    @abstractmethod
    def enr(self) -> ENRAPI:
        ...

    @abstractmethod
    def update(self, *kv_pairs: ENR_KV) -> ENRAPI:
        ...


class IdentitySchemeAPI(ABC):

    id: bytes

    #
    # ENR
    #
    @classmethod
    @abstractmethod
    def create_enr_signature(cls, enr: CommonENRAPI, private_key: bytes) -> bytes:
        """Create and return the signature for an ENR."""
        ...

    @classmethod
    @abstractmethod
    def validate_enr_structure(cls, enr: CommonENRAPI) -> None:
        """Validate that the data required by the identity scheme is present and valid in an ENR."""
        ...

    @classmethod
    @abstractmethod
    def validate_enr_signature(cls, enr: ENRAPI) -> None:
        """Validate the signature of an ENR."""
        ...

    @classmethod
    @abstractmethod
    def extract_public_key(cls, enr: CommonENRAPI) -> bytes:
        """Retrieve the public key from an ENR."""
        ...

    @classmethod
    @abstractmethod
    def extract_node_id(cls, enr: CommonENRAPI) -> NodeID:
        """Retrieve the node id from an ENR."""
        ...

    #
    # Handshake
    #
    @classmethod
    @abstractmethod
    def create_handshake_key_pair(cls) -> Tuple[bytes, bytes]:
        """Create a random private/public key pair used for performing a handshake."""
        ...

    @classmethod
    @abstractmethod
    def validate_handshake_public_key(cls, public_key: bytes) -> None:
        """Validate that a public key received during handshake is valid."""
        ...

    @classmethod
    @abstractmethod
    def create_id_nonce_signature(
        cls, *, id_nonce: IDNonce, ephemeral_public_key: bytes, private_key: bytes
    ) -> bytes:
        """Sign an id nonce received during handshake."""
        ...

    @classmethod
    @abstractmethod
    def validate_id_nonce_signature(
        cls,
        *,
        id_nonce: IDNonce,
        ephemeral_public_key: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> None:
        """Validate the id nonce signature received from a peer."""
        ...
