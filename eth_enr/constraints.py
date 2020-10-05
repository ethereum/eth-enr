from eth_enr.abc import ConstraintAPI


class KeyExists(ConstraintAPI):
    key: bytes

    def __init__(self, key: bytes) -> None:
        self.key = key


class HasUDPIPv4Endpoint(ConstraintAPI):
    pass


class HasTCPIPv4Endpoint(ConstraintAPI):
    pass


class HasUDPIPv6Endpoint(ConstraintAPI):
    pass


class HasTCPIPv6Endpoint(ConstraintAPI):
    pass


has_tcp_ipv4_endpoint = HasTCPIPv4Endpoint()
has_tcp_ipv6_endpoint = HasTCPIPv6Endpoint()
has_udp_ipv4_endpoint = HasUDPIPv4Endpoint()
has_udp_ipv6_endpoint = HasUDPIPv6Endpoint()
