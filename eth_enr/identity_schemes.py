from typing import Type

from eth_keys.datatypes import NonRecoverableSignature, PrivateKey, PublicKey
from eth_keys.exceptions import BadSignature
from eth_keys.exceptions import ValidationError as EthKeysValidationError
from eth_typing import NodeID
from eth_utils import ValidationError, encode_hex, keccak

from eth_enr.abc import (
    ENRAPI,
    CommonENRAPI,
    IdentitySchemeAPI,
    IdentitySchemeRegistryAPI,
)


class IdentitySchemeRegistry(IdentitySchemeRegistryAPI):
    def register(
        self, identity_scheme_class: Type["IdentitySchemeAPI"]
    ) -> Type["IdentitySchemeAPI"]:
        """Class decorator to register identity schemes."""
        if identity_scheme_class.id is None:
            raise ValueError("Identity schemes must define ID")

        if identity_scheme_class.id in self:
            raise ValueError(
                f"Identity scheme with id {identity_scheme_class.id!r} is already registered"
            )

        self[identity_scheme_class.id] = identity_scheme_class

        return identity_scheme_class


default_identity_scheme_registry = IdentitySchemeRegistry()
discv4_identity_scheme_registry = IdentitySchemeRegistry()


@default_identity_scheme_registry.register
@discv4_identity_scheme_registry.register
class V4IdentityScheme(IdentitySchemeAPI):

    id = b"v4"
    public_key_enr_key = b"secp256k1"

    private_key_size = 32

    #
    # ENR
    #
    @classmethod
    def create_enr_signature(cls, enr: CommonENRAPI, private_key: bytes) -> bytes:
        message = enr.get_signing_message()
        private_key_object = PrivateKey(private_key)
        signature = private_key_object.sign_msg_non_recoverable(message)
        return bytes(signature)

    @classmethod
    def validate_enr_structure(cls, enr: CommonENRAPI) -> None:
        if cls.public_key_enr_key not in enr:
            raise ValidationError(
                f"ENR is missing required key {cls.public_key_enr_key!r}"
            )

        public_key = cls.extract_public_key(enr)
        cls.validate_compressed_public_key(public_key)

    @classmethod
    def validate_enr_signature(cls, enr: ENRAPI) -> None:
        message_hash = keccak(enr.get_signing_message())
        cls.validate_signature(
            message_hash=message_hash,
            signature=enr.signature,
            public_key=enr.public_key,
        )

    @classmethod
    def extract_public_key(cls, enr: CommonENRAPI) -> bytes:
        try:
            return enr[cls.public_key_enr_key]  # type: ignore
        except KeyError as error:
            raise KeyError("ENR does not contain public key") from error

    @classmethod
    def extract_node_id(cls, enr: CommonENRAPI) -> NodeID:
        public_key_object = PublicKey.from_compressed_bytes(enr.public_key)
        uncompressed_bytes = public_key_object.to_bytes()
        return NodeID(keccak(uncompressed_bytes))

    #
    # Helpers
    #
    @classmethod
    def validate_compressed_public_key(cls, public_key: bytes) -> None:
        try:
            PublicKey.from_compressed_bytes(public_key)
        except (EthKeysValidationError, ValueError) as error:
            raise ValidationError(
                f"Public key {encode_hex(public_key)} is invalid compressed public key: {error}"
            ) from error

    @classmethod
    def validate_uncompressed_public_key(cls, public_key: bytes) -> None:
        try:
            PublicKey(public_key)
        except EthKeysValidationError as error:
            raise ValidationError(
                f"Public key {encode_hex(public_key)} is invalid uncompressed public key: {error}"
            ) from error

    @classmethod
    def validate_signature(
        cls, *, message_hash: bytes, signature: bytes, public_key: bytes
    ) -> None:
        public_key_object = PublicKey.from_compressed_bytes(public_key)

        try:
            signature_object = NonRecoverableSignature(signature)
        except BadSignature:
            is_valid = False
        else:
            is_valid = signature_object.verify_msg_hash(message_hash, public_key_object)

        if not is_valid:
            raise ValidationError(
                f"Signature {encode_hex(signature)} is not valid for message hash "
                f"{encode_hex(message_hash)} and public key {encode_hex(public_key)}"
            )


@default_identity_scheme_registry.register
@discv4_identity_scheme_registry.register
class V4CompatIdentityScheme(V4IdentityScheme):
    """
    An identity scheme to be used for locally crafted ENRs representing remote nodes that don't
    support the ENR extension.

    ENRs using this identity scheme have a zero-length signature.
    """

    # The spec says all nodes should use the v4 id scheme, but the ENRs using this are forged
    # and meant to be used only internally, so we use a different ID to be able to easily
    # distinguish them.
    id = b"v4-compat"

    @classmethod
    def validate_enr_signature(cls, enr: ENRAPI) -> None:
        pass

    @classmethod
    def create_enr_signature(cls, enr: CommonENRAPI, private_key: bytes) -> bytes:
        raise NotImplementedError()
