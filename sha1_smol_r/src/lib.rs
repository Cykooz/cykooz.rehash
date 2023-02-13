//! A minimal implementation of SHA1 for rust.
//!
//! ## Example
//!
//! ```rust
//! let mut m = sha1_smol_r::Sha1::new();
//! m.update(b"Hello World!");
//! assert_eq!(m.digest().to_string(),
//!            "2ef7bde608ce5404e97d5f042f95f89f1c232871");
//! ```
//!
//! The sha1 object can be updated multiple times.  If you only need to use
//! it once you can also use shortcuts (requires std):
//!
//! ```
//! # trait X { fn hexdigest(&self) -> &'static str { "2ef7bde608ce5404e97d5f042f95f89f1c232871" }}
//! # impl X for sha1_smol_r::Sha1 {}
//! # fn main() {
//! assert_eq!(sha1_smol_r::Sha1::from("Hello World!").hexdigest(),
//!            "2ef7bde608ce5404e97d5f042f95f89f1c232871");
//! # }
//! ```
use crate::blocks::Blocks;
pub use crate::digest::*;
use crate::state::Sha1State;

mod blocks;
mod digest;
mod simd;
mod state;

/// Represents a Sha1 hash object in memory.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Sha1 {
    state: Sha1State,
    blocks: Blocks,
    len: u64,
}

const DEFAULT_STATE: Sha1State = Sha1State {
    state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
};

impl Default for Sha1 {
    fn default() -> Sha1 {
        Sha1::new()
    }
}

const SERIALIZED_STATE_SIZE: usize = 94;

impl Sha1 {
    /// Creates an fresh sha1 hash object.
    ///
    /// This is equivalent to creating a hash with `Default::default`.
    pub fn new() -> Sha1 {
        Sha1 {
            state: DEFAULT_STATE,
            len: 0,
            blocks: Blocks {
                len: 0,
                block: [0; 64],
            },
        }
    }

    /// Shortcut to create a sha1 from some bytes.
    ///
    /// This also lets you create a hash from a utf-8 string.  This is equivalent
    /// to making a new Sha1 object and calling `update` on it once.
    pub fn from<D: AsRef<[u8]>>(data: D) -> Sha1 {
        let mut rv = Sha1::new();
        rv.update(data.as_ref());
        rv
    }

    /// Resets the hash object to it's initial state.
    pub fn reset(&mut self) {
        self.state = DEFAULT_STATE;
        self.len = 0;
        self.blocks.len = 0;
    }

    /// Update hash with input data.
    pub fn update(&mut self, data: &[u8]) {
        let len = &mut self.len;
        let state = &mut self.state;
        self.blocks.input(data, |block| {
            *len += block.len() as u64;
            state.process(block);
        })
    }

    /// Retrieve digest result.
    pub fn digest(&self) -> Digest {
        let mut state = self.state;
        let bits = (self.len + (self.blocks.len as u64)) * 8;
        let extra = bits.to_be_bytes();
        let mut last = [0; 128];
        let blocklen = self.blocks.len as usize;
        last[..blocklen].clone_from_slice(&self.blocks.block[..blocklen]);
        last[blocklen] = 0x80;

        if blocklen < 56 {
            last[56..64].clone_from_slice(&extra);
            state.process(as_block(&last[0..64]));
        } else {
            last[120..128].clone_from_slice(&extra);
            state.process(as_block(&last[0..64]));
            state.process(as_block(&last[64..128]));
        }

        Digest { data: state }
    }

    /// Retrieve the digest result as hex string directly.
    pub fn hexdigest(&self) -> String {
        self.digest().to_string()
    }

    pub fn state_size(&self) -> usize {
        SERIALIZED_STATE_SIZE
    }

    // Offset|Description
    // 00 - version (u8)
    // 01 - state (5 * u32_le)
    // 21 - len (u64_le)
    // 29 - blocks size (u8)
    // 30 - blocks data (64 * u8)
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let result_size = self.state_size();
        if buf.len() < result_size {
            return 0;
        }
        // version
        buf[0] = 1;
        // state
        for (dst_chunk, state) in buf[1..21].chunks_exact_mut(4).zip(self.state.state) {
            dst_chunk.copy_from_slice(&state.to_le_bytes());
        }
        // len
        buf[21..29].copy_from_slice(&self.len.to_le_bytes());
        // blocks size
        let blocks_size = self.blocks.len as usize;
        buf[29] = blocks_size as u8;
        buf[30..30 + 64].copy_from_slice(&self.blocks.block);
        result_size
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }
        let version = buf[0];
        if version != 1 {
            return None;
        }
        if buf.len() < SERIALIZED_STATE_SIZE {
            return None;
        }

        let mut state = [0u32; 5];
        for (src, state_item) in buf[1..21].chunks_exact(4).zip(state.iter_mut()) {
            *state_item = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
        }

        let len = u64::from_le_bytes([
            buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27], buf[28],
        ]);

        let blocks_size = buf[29] as usize;
        if blocks_size > 64 {
            return None;
        }
        let mut block = [0u8; 64];
        block.copy_from_slice(&buf[30..30 + 64]);

        Some(Self {
            state: Sha1State { state },
            blocks: Blocks {
                len: blocks_size as u32,
                block,
            },
            len,
        })
    }
}

#[inline(always)]
fn as_block(input: &[u8]) -> &[u8; 64] {
    unsafe {
        assert_eq!(input.len(), 64);
        let arr: &[u8; 64] = &*(input.as_ptr() as *const [u8; 64]);
        arr
    }
}

#[cfg(test)]
mod tests {
    use super::Sha1;
    use crate::SERIALIZED_STATE_SIZE;

    #[test]
    fn test_simple() {
        let mut m = Sha1::new();

        let tests = [
            ("The quick brown fox jumps over the lazy dog",
             "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
            ("The quick brown fox jumps over the lazy cog",
             "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
            ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            ("testing\n", "9801739daae44ec5293d4e1f53d3f4d2d426d91c"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "025ecbd5d70f8fb3c5457cd96bab13fda305dc59"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "4300320394f7ee239bcdce7d3b8bcee173a0cd5c"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "cef734ba81a024479e09eb5a75b6ddae62e6abf1"),
        ];

        for &(s, h) in tests.iter() {
            let data = s.as_bytes();

            m.reset();
            m.update(data);
            let hh = m.digest().to_string();

            assert_eq!(hh.len(), h.len());
            assert_eq!(hh, *h);
        }
    }

    #[test]
    fn test_shortcuts() {
        let s = Sha1::from("The quick brown fox jumps over the lazy dog");
        assert_eq!(
            s.digest().to_string(),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );

        let s = Sha1::from(&b"The quick brown fox jumps over the lazy dog"[..]);
        assert_eq!(
            s.digest().to_string(),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );

        let s = Sha1::from("The quick brown fox jumps over the lazy dog");
        assert_eq!(s.hexdigest(), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    }

    #[test]
    fn test_multiple_updates() {
        let mut m = Sha1::new();

        m.reset();
        m.update("The quick brown ".as_bytes());
        m.update("fox jumps over ".as_bytes());
        m.update("the lazy dog".as_bytes());
        let hh = m.digest().to_string();

        let h = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";
        assert_eq!(hh.len(), h.len());
        assert_eq!(hh, h);
    }

    #[test]
    fn test_sha1_loop() {
        let mut m = Sha1::new();
        let s = "The quick brown fox jumps over the lazy dog.";
        let n = 1000u64;

        for _ in 0..3 {
            m.reset();
            for _ in 0..n {
                m.update(s.as_bytes());
            }
            assert_eq!(
                m.digest().to_string(),
                "7ca27655f67fceaa78ed2e645a81c7f1d6e249d2"
            );
        }
    }

    #[test]
    fn spray_and_pray() {
        use rand::{Rng, RngCore};

        let mut rng = rand::thread_rng();
        let mut m = Sha1::new();
        let mut bytes = [0; 512];

        for _ in 0..20 {
            let ty = openssl::hash::MessageDigest::sha1();
            let mut r = openssl::hash::Hasher::new(ty).unwrap();
            m.reset();
            for _ in 0..50 {
                let len = rng.gen::<usize>() % bytes.len();
                rng.fill_bytes(&mut bytes[..len]);
                m.update(&bytes[..len]);
                r.update(&bytes[..len]).unwrap();
            }
            assert_eq!(r.finish().unwrap().as_ref(), &m.digest().bytes());
        }
    }

    #[test]
    fn test_parse() {
        use crate::digest::Digest;
        let y: Digest = "2ef7bde608ce5404e97d5f042f95f89f1c232871".parse().unwrap();
        assert_eq!(y.to_string(), "2ef7bde608ce5404e97d5f042f95f89f1c232871");
        assert!("asdfasdf".parse::<Digest>().is_err());
        assert_eq!(
            "asdfasdf"
                .parse::<Digest>()
                .map_err(|x| x.to_string())
                .unwrap_err(),
            "not a valid sha1 hash"
        );
    }

    #[test]
    fn test_resumable_hash() {
        let mut s = Sha1::new();
        s.update(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_eq!(s.state_size(), SERIALIZED_STATE_SIZE);

        let mut small_buf = vec![0u8; 40];
        let state_size = s.serialize(&mut small_buf);
        assert_eq!(state_size, 0);

        let mut state = vec![0u8; 200];
        let state_size = s.serialize(&mut state);
        assert_eq!(state_size, SERIALIZED_STATE_SIZE);

        let mut s = Sha1::deserialize(&state).unwrap();
        s.update(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        let digest = s.digest().to_string();
        assert_eq!(&digest, "4300320394f7ee239bcdce7d3b8bcee173a0cd5c");
    }
}
