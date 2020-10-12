from abc import ABC, abstractmethod
from collections import UserDict
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Type

from eth_typing import NodeID

from eth_enr.typing import ENR_KV

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
    def update(self, *kv_pairs: ENR_KV) -> None:
        """
        Update the ENR record with the provided key/value pairs.  Providing
        `None` for a value will result in the associated key being removed from
        the ENR.
        """
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


class ENRDatabaseAPI(ABC):
    @abstractmethod
    def set_enr(self, enr: ENRAPI) -> None:
        ...

    @abstractmethod
    def get_enr(self, node_id: NodeID) -> ENRAPI:
        ...

    @abstractmethod
    def delete_enr(self, node_id: NodeID) -> None:
        ...


class ConstraintAPI(ABC):
    ...


class QueryableENRDatabaseAPI(ENRDatabaseAPI):
    @abstractmethod
    def query(self, *constraints: ConstraintAPI) -> Iterable[ENRAPI]:
        ...
