import collections
import ipaddress
import secrets
import socket
from typing import Any, Deque, Dict, cast

from eth_keys import keys
from eth_utils import int_to_big_endian
from eth_utils.toolz import merge
import factory

from eth_enr.enr import ENR, UnsignedENR
from eth_enr.identity_schemes import V4IdentityScheme


def _mk_private_key_bytes() -> bytes:
    return int_to_big_endian(secrets.randbits(256)).rjust(32, b"\x00")


class PrivateKeyFactory(factory.Factory):  # type: ignore
    class Meta:
        model = keys.PrivateKey

    private_key_bytes = factory.LazyFunction(_mk_private_key_bytes)


RECENT_PORTS: Deque[int] = collections.deque(maxlen=256)


def _get_open_port() -> int:
    port: int = 0
    while port < 1024:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]
        s.close()
    return port


def get_open_port() -> int:
    while True:
        port = _get_open_port()
        if port not in RECENT_PORTS:
            break
    RECENT_PORTS.appendleft(port)
    return port


IPAddressFactory = factory.Faker("ipv4")


class Address:
    def __init__(self, ip: str, udp_port: int, tcp_port: int) -> None:
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self._ip = cast(ipaddress.IPv4Address, ipaddress.ip_address(ip))

    @property
    def ip(self) -> str:
        return str(self._ip)

    @property
    def ip_packed(self) -> bytes:
        """The binary representation of this IP address."""
        return self._ip.packed


class AddressFactory(factory.Factory):  # type: ignore
    class Meta:
        model = Address

    ip = IPAddressFactory
    udp_port = tcp_port = factory.LazyFunction(get_open_port)

    @classmethod
    def localhost(cls, *args: Any, **kwargs: Any) -> Address:
        return cls(*args, ip="127.0.0.1", **kwargs)


class ENRFactory(factory.Factory):  # type: ignore
    class Meta:
        model = ENR

    sequence_number = factory.Faker("pyint", min_value=0, max_value=100)
    kv_pairs = factory.LazyAttribute(
        lambda o: merge(
            {
                b"id": b"v4",
                b"secp256k1": keys.PrivateKey(
                    o.private_key
                ).public_key.to_compressed_bytes(),
                b"ip": o.address.ip_packed,
                b"udp": o.address.udp_port,
                b"tcp": o.address.tcp_port,
            },
            o.custom_kv_pairs,
        )
    )
    signature = factory.LazyAttribute(
        lambda o: UnsignedENR(o.sequence_number, o.kv_pairs)
        .to_signed_enr(o.private_key)
        .signature
    )

    class Params:
        private_key = factory.Faker("binary", length=V4IdentityScheme.private_key_size)
        address = factory.SubFactory(AddressFactory)
        custom_kv_pairs: Dict[bytes, Any] = {}
