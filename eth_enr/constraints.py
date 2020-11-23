from eth_typing import NodeID

from eth_enr.abc import ConstraintAPI


class KeyExists(ConstraintAPI):
    """
    Constrains ENR database queries to records which have a specified key.

    .. code-block:: python

        >>> enr_db = ...
        >>> from eth_enr.constraints import KeyExists
        >>> for enr in enr_db.query(KeyExists(b"some-key")):
        ...     print("ENR: ", enr)
    """

    key: bytes

    def __init__(self, key: bytes) -> None:
        self.key = key


class HasUDPIPv4Endpoint(ConstraintAPI):
    """
    Constrains ENR database queries to records which have both the ``"ip"`` and
    ``"udp"`` keys.

    .. code-block:: python

        >>> enr_db = ...
        >>> from eth_enr.constraints import has_udp_ipv4_endpoint
        >>> for enr in enr_db.query(has_udp_ipv4_endpoint):
        ...     print("ENR: ", enr)
    """

    pass


class HasTCPIPv4Endpoint(ConstraintAPI):
    """
    Constrains ENR database queries to records which have both the ``"ip"`` and
    ``"tcp"`` keys.

    .. code-block:: python

        >>> enr_db = ...
        >>> from eth_enr.constraints import has_tcp_ipv4_endpoint
        >>> for enr in enr_db.query(has_tcp_ipv4_endpoint):
        ...     print("ENR: ", enr)
    """

    pass


class HasUDPIPv6Endpoint(ConstraintAPI):
    """
    Constrains ENR database queries to records which have both the ``"ip6"`` and
    ``"udp6"`` keys.

    .. code-block:: python

        >>> enr_db = ...
        >>> from eth_enr.constraints import has_udp_ipv6_endpoint
        >>> for enr in enr_db.query(has_udp_ipv6_endpoint):
        ...     print("ENR: ", enr)
    """

    pass


class HasTCPIPv6Endpoint(ConstraintAPI):
    """
    Constrains ENR database queries to records which have both the ``"ip6"`` and
    ``"tcp6"`` keys.

    .. code-block:: python

        >>> enr_db = ...
        >>> from eth_enr.constraints import has_tcp_ipv6_endpoint
        >>> for enr in enr_db.query(has_tcp_ipv6_endpoint):
        ...     print("ENR: ", enr)
    """

    pass


class ClosestTo(ConstraintAPI):
    """
    Constrains ENR database queries to return records proximate to a specific `node_id`

    .. code-block:: python

        >>> enr_db = ...
        >>> node_id = ...
        >>> from eth_enr.constraints import ClosestTo
        >>> for enr in enr_db.query(ClosestTo(node_id)):
        ...     print("ENR: ", enr)
    """

    node_id: NodeID

    def __init__(self, node_id: NodeID) -> None:
        self.node_id = node_id


has_tcp_ipv4_endpoint = HasTCPIPv4Endpoint()
has_tcp_ipv6_endpoint = HasTCPIPv6Endpoint()
has_udp_ipv4_endpoint = HasUDPIPv4Endpoint()
has_udp_ipv6_endpoint = HasUDPIPv6Endpoint()
