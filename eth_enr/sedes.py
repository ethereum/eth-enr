import collections
import operator
from typing import TYPE_CHECKING, Any, Iterable, Sequence, Tuple

from eth_utils import to_dict
from eth_utils.toolz import cons, interleave
from rlp.exceptions import DeserializationError
from rlp.sedes import Binary, big_endian_int, binary, raw

from eth_enr.abc import ENRAPI, IdentitySchemeRegistryAPI, UnsignedENRAPI
from eth_enr.constants import IP_V4_SIZE, IP_V6_SIZE, MAX_ENR_SIZE
from eth_enr.identity_schemes import (
    default_identity_scheme_registry as default_id_scheme_registry,
)

if TYPE_CHECKING:
    from eth_enr.enr import ENR, UnsignedENR  # noqa: F401


ENR_KEY_SEDES_MAPPING = {
    b"id": binary,
    b"secp256k1": Binary.fixed_length(33),
    b"ip": Binary.fixed_length(IP_V4_SIZE),
    b"tcp": big_endian_int,
    b"udp": big_endian_int,
    b"ip6": Binary.fixed_length(IP_V6_SIZE),
    b"tcp6": big_endian_int,
    b"udp6": big_endian_int,
}


# Must use raw for values with an unknown key as they may be lists or individual values.
FALLBACK_ENR_VALUE_SEDES = raw


class ENRContentSedes:
    @classmethod
    def serialize(cls, enr: ENRAPI) -> Tuple[bytes, ...]:
        serialized_sequence_number = big_endian_int.serialize(enr.sequence_number)

        sorted_key_value_pairs = sorted(enr.items(), key=operator.itemgetter(0))

        serialized_keys = tuple(
            binary.serialize(key) for key, _ in sorted_key_value_pairs
        )
        values_and_serializers = tuple(
            (value, ENR_KEY_SEDES_MAPPING.get(key, FALLBACK_ENR_VALUE_SEDES))
            for key, value in sorted_key_value_pairs
        )
        serialized_values = tuple(
            value_serializer.serialize(value)
            for value, value_serializer in values_and_serializers
        )
        return tuple(
            cons(
                serialized_sequence_number,
                interleave((serialized_keys, serialized_values)),
            )
        )

    @classmethod
    def deserialize(
        cls,
        serialized_enr: Sequence[bytes],
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_id_scheme_registry,
    ) -> UnsignedENRAPI:
        from eth_enr.enr import UnsignedENR  # noqa: F811

        cls._validate_serialized_length(serialized_enr)
        sequence_number = big_endian_int.deserialize(serialized_enr[0])
        kv_pairs = cls._deserialize_kv_pairs(serialized_enr)
        return UnsignedENR(sequence_number, kv_pairs, identity_scheme_registry)

    @classmethod
    @to_dict
    def _deserialize_kv_pairs(
        cls, serialized_enr: Sequence[bytes]
    ) -> Iterable[Tuple[bytes, Any]]:
        serialized_keys = serialized_enr[1::2]
        serialized_values = serialized_enr[2::2]

        keys = tuple(
            binary.deserialize(serialized_key) for serialized_key in serialized_keys
        )
        cls._validate_key_uniqueness(keys, serialized_enr)
        cls._validate_key_order(keys, serialized_enr)

        value_deserializers = tuple(
            ENR_KEY_SEDES_MAPPING.get(key, FALLBACK_ENR_VALUE_SEDES) for key in keys
        )
        values = tuple(
            value_deserializer.deserialize(serialized_value)
            for value_deserializer, serialized_value in zip(
                value_deserializers, serialized_values
            )
        )

        return dict(zip(keys, values))

    @classmethod
    def _validate_serialized_length(cls, serialized_enr: Sequence[bytes]) -> None:
        if len(serialized_enr) < 1:
            raise DeserializationError(
                "ENR content must consist of at least a sequence number", serialized_enr
            )
        num_keys_and_values = len(serialized_enr) - 1
        if num_keys_and_values % 2 != 0:
            raise DeserializationError(
                "ENR must have exactly one value for each key", serialized_enr
            )

    @classmethod
    def _validate_key_uniqueness(
        cls, keys: Sequence[bytes], serialized_enr: Sequence[bytes]
    ) -> None:
        duplicates = {key for key, num in collections.Counter(keys).items() if num > 1}
        if duplicates:
            raise DeserializationError(
                f"ENR contains the following duplicate keys: {b', '.join(duplicates).decode()}",
                serialized_enr,
            )

    @classmethod
    def _validate_key_order(
        cls, keys: Sequence[bytes], serialized_enr: Sequence[bytes]
    ) -> None:
        if keys != tuple(sorted(keys)):
            raise DeserializationError(
                f"ENR keys are not sorted: {b', '.join(keys).decode()}", serialized_enr
            )


class ENRSedes:
    @classmethod
    def serialize(cls, enr: ENRAPI) -> Tuple[bytes, ...]:
        serialized_signature = binary.serialize(enr.signature)
        serialized_content = ENRContentSedes.serialize(enr)
        return (serialized_signature,) + serialized_content

    @classmethod
    def deserialize(
        cls,
        serialized_enr: Sequence[bytes],
        identity_scheme_registry: IdentitySchemeRegistryAPI = default_id_scheme_registry,
    ) -> ENRAPI:
        from eth_enr.enr import ENR  # noqa: F811

        cls._validate_serialized_length(serialized_enr)
        signature = binary.deserialize(serialized_enr[0])
        unsigned_enr = ENRContentSedes.deserialize(
            serialized_enr[1:], identity_scheme_registry=identity_scheme_registry
        )
        return ENR(
            unsigned_enr.sequence_number,
            dict(unsigned_enr),
            signature,
            identity_scheme_registry,
        )

    @classmethod
    def _validate_serialized_length(cls, serialized_enr: Sequence[bytes]) -> None:
        if len(serialized_enr) < 2:
            raise DeserializationError(
                "ENR must contain at least a signature and a sequence number",
                serialized_enr,
            )

        num_keys_and_values = len(serialized_enr) - 2
        if num_keys_and_values % 2 != 0:
            raise DeserializationError(
                "ENR must have exactly one value for each key", serialized_enr
            )

        byte_size = sum(len(element) for element in serialized_enr)
        if byte_size > MAX_ENR_SIZE:
            raise DeserializationError(
                f"ENRs must not be larger than {MAX_ENR_SIZE} bytes", serialized_enr
            )
