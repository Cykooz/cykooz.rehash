use std::{cmp, hash};

pub(crate) struct Blocks {
    pub(crate) len: u32,
    pub(crate) block: [u8; 64],
}

impl Blocks {
    pub(crate) fn input<F>(&mut self, mut input: &[u8], mut f: F)
    where
        F: FnMut(&[u8; 64]),
    {
        if self.len > 0 {
            let len = self.len as usize;
            let amt = cmp::min(input.len(), self.block.len() - len);
            self.block[len..len + amt].clone_from_slice(&input[..amt]);
            if len + amt == self.block.len() {
                f(&self.block);
                self.len = 0;
                input = &input[amt..];
            } else {
                self.len += amt as u32;
                return;
            }
        }
        assert_eq!(self.len, 0);
        for chunk in input.chunks(64) {
            if chunk.len() == 64 {
                f(crate::as_block(chunk))
            } else {
                self.block[..chunk.len()].clone_from_slice(chunk);
                self.len = chunk.len() as u32;
            }
        }
    }
}

impl PartialEq for Blocks {
    fn eq(&self, other: &Blocks) -> bool {
        (self.len, &self.block[..]).eq(&(other.len, &other.block[..]))
    }
}

impl Ord for Blocks {
    fn cmp(&self, other: &Blocks) -> cmp::Ordering {
        (self.len, &self.block[..]).cmp(&(other.len, &other.block[..]))
    }
}

impl PartialOrd for Blocks {
    fn partial_cmp(&self, other: &Blocks) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for Blocks {}

impl hash::Hash for Blocks {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.block.hash(state);
    }
}

impl Clone for Blocks {
    fn clone(&self) -> Blocks {
        Blocks { ..*self }
    }
}
