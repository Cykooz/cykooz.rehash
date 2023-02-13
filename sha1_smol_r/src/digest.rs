use crate::state::Sha1State;
use core::fmt;
use core::str;

/// The length of a SHA1 digest in bytes
pub const DIGEST_LENGTH: usize = 20;

/// Digest generated from a `Sha1` instance.
///
/// A digest can be formatted to view the digest as a hex string, or the bytes
/// can be extracted for later processing.
///
/// To retrieve a hex string result call `to_string` on it (requires that std
/// is available).
#[derive(PartialOrd, Ord, PartialEq, Eq, Hash, Clone, Copy, Default)]
pub struct Digest {
    pub(crate) data: Sha1State,
}

impl Digest {
    /// Returns the 160 bit (20 byte) digest as a byte array.
    pub fn bytes(&self) -> [u8; DIGEST_LENGTH] {
        [
            (self.data.state[0] >> 24) as u8,
            (self.data.state[0] >> 16) as u8,
            (self.data.state[0] >> 8) as u8,
            self.data.state[0] as u8,
            (self.data.state[1] >> 24) as u8,
            (self.data.state[1] >> 16) as u8,
            (self.data.state[1] >> 8) as u8,
            self.data.state[1] as u8,
            (self.data.state[2] >> 24) as u8,
            (self.data.state[2] >> 16) as u8,
            (self.data.state[2] >> 8) as u8,
            self.data.state[2] as u8,
            (self.data.state[3] >> 24) as u8,
            (self.data.state[3] >> 16) as u8,
            (self.data.state[3] >> 8) as u8,
            self.data.state[3] as u8,
            (self.data.state[4] >> 24) as u8,
            (self.data.state[4] >> 16) as u8,
            (self.data.state[4] >> 8) as u8,
            self.data.state[4] as u8,
        ]
    }
}

impl str::FromStr for Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Digest, DigestParseError> {
        if s.len() != 40 {
            return Err(DigestParseError);
        }
        let mut rv: Digest = Default::default();
        for idx in 0..5 {
            rv.data.state[idx] =
                u32::from_str_radix(&s[idx * 8..idx * 8 + 8], 16).map_err(|_| DigestParseError)?;
        }
        Ok(rv)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in self.data.state.iter() {
            write!(f, "{i:08x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Digest {{ \"{self}\" }}")
    }
}

/// Indicates that a digest couldn't be parsed.
#[derive(Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct DigestParseError;

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "not a valid sha1 hash")
    }
}

impl std::error::Error for DigestParseError {
    fn description(&self) -> &str {
        "not a valid sha1 hash"
    }
}
