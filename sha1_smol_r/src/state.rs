use crate::simd::*;

#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Default)]
pub(crate) struct Sha1State {
    pub(crate) state: [u32; 5],
}

impl Sha1State {
    pub(crate) fn process(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 16];
        for (word, b) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }
        let mut w0 = u32x4(words[0], words[1], words[2], words[3]).swap_bytes_order();
        let mut w1 = u32x4(words[4], words[5], words[6], words[7]).swap_bytes_order();
        let mut w2 = u32x4(words[8], words[9], words[10], words[11]).swap_bytes_order();
        let mut w3 = u32x4(words[12], words[13], words[14], words[15]).swap_bytes_order();

        // Rounds 0..20
        let state4 = u32x4(self.state[0], self.state[1], self.state[2], self.state[3]);
        let mut h0 = state4;
        let mut h1 = sha1_digest_round_x4(h0, sha1_first_add(self.state[4], w0), 0);
        h0 = rounds4(h1, h0, w1, 0);
        h1 = rounds4(h0, h1, w2, 0);
        h0 = rounds4(h1, h0, w3, 0);
        let mut w4 = schedule(w0, w1, w2, w3);
        h1 = rounds4(h0, h1, w4, 0);

        // Rounds 20..40
        w0 = schedule(w1, w2, w3, w4);
        h0 = rounds4(h1, h0, w0, 1);
        w1 = schedule(w2, w3, w4, w0);
        h1 = rounds4(h0, h1, w1, 1);
        w2 = schedule(w3, w4, w0, w1);
        h0 = rounds4(h1, h0, w2, 1);
        w3 = schedule(w4, w0, w1, w2);
        h1 = rounds4(h0, h1, w3, 1);
        w4 = schedule(w0, w1, w2, w3);
        h0 = rounds4(h1, h0, w4, 1);

        // Rounds 40..60
        w0 = schedule(w1, w2, w3, w4);
        h1 = rounds4(h0, h1, w0, 2);
        w1 = schedule(w2, w3, w4, w0);
        h0 = rounds4(h1, h0, w1, 2);
        w2 = schedule(w3, w4, w0, w1);
        h1 = rounds4(h0, h1, w2, 2);
        w3 = schedule(w4, w0, w1, w2);
        h0 = rounds4(h1, h0, w3, 2);
        w4 = schedule(w0, w1, w2, w3);
        h1 = rounds4(h0, h1, w4, 2);

        // Rounds 60..80
        w0 = schedule(w1, w2, w3, w4);
        h0 = rounds4(h1, h0, w0, 3);
        w1 = schedule(w2, w3, w4, w0);
        h1 = rounds4(h0, h1, w1, 3);
        w2 = schedule(w3, w4, w0, w1);
        h0 = rounds4(h1, h0, w2, 3);
        w3 = schedule(w4, w0, w1, w2);
        h1 = rounds4(h0, h1, w3, 3);
        w4 = schedule(w0, w1, w2, w3);
        h0 = rounds4(h1, h0, w4, 3);

        let e = sha1_first(h1).rotate_left(30);

        h0 = state4 + h0;
        self.state[0] = h0.0;
        self.state[1] = h0.1;
        self.state[2] = h0.2;
        self.state[3] = h0.3;
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[inline(always)]
fn schedule(v0: u32x4, v1: u32x4, v2: u32x4, v3: u32x4) -> u32x4 {
    sha1msg2(sha1msg1(v0, v1) ^ v2, v3)
}

#[inline(always)]
fn rounds4(h0: u32x4, h1: u32x4, wk: u32x4, i: i8) -> u32x4 {
    sha1_digest_round_x4(h0, sha1_first_half(h1, wk), i)
}

/// Not an intrinsic, but adds a word to the first element of a vector.
#[inline(always)]
fn sha1_first_add(e: u32, w0: u32x4) -> u32x4 {
    let u32x4(a, b, c, d) = w0;
    u32x4(e.wrapping_add(a), b, c, d)
}

/// Emulates `llvm.x86.sha1nexte` intrinsic.
#[inline(always)]
fn sha1_first_half(abcd: u32x4, msg: u32x4) -> u32x4 {
    sha1_first_add(sha1_first(abcd).rotate_left(30), msg)
}

/// Not an intrinsic, but gets the first element of a vector.
#[inline(always)]
fn sha1_first(w0: u32x4) -> u32 {
    w0.0
}

/// Emulates `llvm.x86.sha1msg1` intrinsic.
fn sha1msg1(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(_, _, w2, w3) = a;
    let u32x4(w4, w5, _, _) = b;
    a ^ u32x4(w2, w3, w4, w5)
}

/// Emulates `llvm.x86.sha1msg2` intrinsic.
fn sha1msg2(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(x0, x1, x2, x3) = a;
    let u32x4(_, w13, w14, w15) = b;

    let w16 = (x0 ^ w13).rotate_left(1);
    let w17 = (x1 ^ w14).rotate_left(1);
    let w18 = (x2 ^ w15).rotate_left(1);
    let w19 = (x3 ^ w16).rotate_left(1);

    u32x4(w16, w17, w18, w19)
}

// Round key constants
const K0: u32 = 0x5A827999u32;
const K1: u32 = 0x6ED9EBA1u32;
const K2: u32 = 0x8F1BBCDCu32;
const K3: u32 = 0xCA62C1D6u32;

/// Emulates `llvm.x86.sha1rnds4` intrinsic.
/// Performs 4 rounds of the message block digest.
#[inline(always)]
fn sha1_digest_round_x4(abcd: u32x4, work: u32x4, i: i8) -> u32x4 {
    const K0V: u32x4 = u32x4(K0, K0, K0, K0);
    const K1V: u32x4 = u32x4(K1, K1, K1, K1);
    const K2V: u32x4 = u32x4(K2, K2, K2, K2);
    const K3V: u32x4 = u32x4(K3, K3, K3, K3);

    match i {
        0 => sha1rnds4c(abcd, work + K0V),
        1 => sha1rnds4p(abcd, work + K1V),
        2 => sha1rnds4m(abcd, work + K2V),
        3 => sha1rnds4p(abcd, work + K3V),
        _ => panic!("unknown icosaround index"),
    }
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4c(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    // Choose, MD5F, SHA1C
    #[inline(always)]
    fn bool3ary_202(a: u32, b: u32, c: u32) -> u32 {
        c ^ (a & (b ^ c))
    }

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_202(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_202(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_202(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_202(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4p(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    // Parity, XOR, MD5H, SHA1P
    #[inline(always)]
    fn bool3ary_150(a: u32, b: u32, c: u32) -> u32 {
        a ^ b ^ c
    }

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_150(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_150(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_150(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_150(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4m(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    // Majority, SHA1M
    #[inline(always)]
    fn bool3ary_232(a: u32, b: u32, c: u32) -> u32 {
        (a & b) ^ (a & c) ^ (b & c)
    }

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_232(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_232(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_232(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_232(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}
