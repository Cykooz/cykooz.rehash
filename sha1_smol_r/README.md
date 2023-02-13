# sha1-smol-r

It is a fork of minimal and dependency free implementation of SHA1 
for Rust - [sha1-smol](https://github.com/mitsuhiko/sha1-smol)

- Refactored code layout.
- Removed support of `no_std` and `serde`.
- Added methods `Sha1::serialize`, `Sha1::deserialize` and `Sha1::state_size`.
