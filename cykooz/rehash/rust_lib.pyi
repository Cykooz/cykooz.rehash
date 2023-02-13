""" This module is a python module implemented in Rust. """
from typing import Optional


class Sha1:

    def __init__(self, data: Optional[bytes] = None):
        ...
    @property
    def digest_size(self) -> int:
        ...

    @property
    def block_size(self) -> int:
        ...

    def reset(self):
        """Resets the hash object to it's initial state."""
        ...

    def update(self, data: bytes):
        """Update hash with input data."""
        ...

    def digest(self) -> bytes:
        """Retrieve digest result."""
        ...

    def hexdigest(self) -> str:
        """Retrieve digest result as string in hex-format."""
        ...

    def serialize(self) -> bytes:
        """Serialize of hasher state."""
        ...

    @staticmethod
    def deserialize(buffer: bytes) -> Optional['Sha1']:
        """Deserialize of hasher from state."""
        ...


__all__ = [
    'Sha1',
]
