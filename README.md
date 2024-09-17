# cykooz.rehash

`cykooz.rehash` is a resumable implementation of SHA1 hasher.

Usage example:

```python
from cykooz.rehash import Sha1


hasher = Sha1()
hasher.update(b'x' * 78)
hasher_state = hasher.serialize()
assert len(hasher_state) == 94
hasher.update(b'x' * 41)
assert hasher.hexdigest() == '4300320394f7ee239bcdce7d3b8bcee173a0cd5c'

new_hasher = Sha1.deserialize(hasher_state)
new_hasher.update(b'x' * 41)
assert new_hasher.hexdigest() == '4300320394f7ee239bcdce7d3b8bcee173a0cd5c'
```
