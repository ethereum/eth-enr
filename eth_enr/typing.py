from typing import NewType, Tuple, Union

IDNonce = NewType("IDNonce", bytes)
NodeID = NewType("NodeID", bytes)

ENR_KV = Tuple[bytes, Union[int, bytes]]
