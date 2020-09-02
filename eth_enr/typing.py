from typing import NewType, Tuple, Union

NodeID = NewType("NodeID", bytes)

ENR_KV = Tuple[bytes, Union[int, bytes]]
