// Copyright 2016 Peter Reid. See the COPYRIGHT file at the top-level
// directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ChaCha is a family of 256-bit stream ciphers. This crate includes five
//! members of the family:
//!
//!
//! |              | nonce length | stream length  | key length | rounds
//! |--------------|--------------|----------------|------------|----------
//! | ChaCha20     | 8            | 2<sup>70</sup> | 32         | 20
//! | IETF         | 16           | 2<sup>38</sup> | 32         | 20
//! | XChaCha20    | 24           | 2<sup>70</sup> | 32         | 20
//! | ChaCha12     | 8            | 2<sup>70</sup> | 32         | 12
//! | ChaCha8      | 8            | 2<sup>70</sup> | 32         | 8
//! _(Lengths are given in bytes.)_
//!
//! ChaCha12 and ChaCha8 trade off the security margin in favor of performance.
//! The IETF implementation increases the nonce length, making randomly generating
//! the same nonce twice less likely, at the cost of making the stream shorter.
//! XChaCha20 increases the nonce length even further while maintaining the stream
//! length at the cost of a slightly more expensive initialization step.
//!
//! ChaCha benefits greatly from SIMD instructions, which currently requires Rust's
//! nightly build. Compile with the feature `nightly` enabled for maximum performance.
//!
//! ChaCha was designed by Daniel J. Bernstein in 2008 as a slightly modified version
//! of his Salsa family of ciphers. Salsa20 has been
//! [analyzed](http://www.ecrypt.eu.org/stream/salsa20pf.html) as part of
//! the [eSTREAM project](https://en.wikipedia.org/wiki/ESTREAM) and has not had
//! any practical attack found. That cryptanalysis would generally apply to ChaCha20 as well.
//! The ChaCha round function is used in the BLAKE hash function, which was
//! analyzed as part of the
//! [SHA-3 competition](https://en.wikipedia.org/wiki/NIST_hash_function_competition),
//! again without finding a practical attack. The IETF's
//! [RFC 7539](https://tools.ietf.org/html/rfc7539) standardizes a member
//! of the ChaCha family.

#![no_std]
#![cfg_attr(feature="nightly", feature(repr_simd))]
#![cfg_attr(feature="nightly", feature(test))]

extern crate keystream;

#[cfg(all(test, feature="bench"))]
extern crate test;

pub use keystream::{KeyStream, SeekableKeyStream};
pub use keystream::Error;
use core::cmp::min;
use core::convert::TryInto;

/// A ChaCha keystream.
///
/// After being initialized with a `key` and `nonce`, a `ChaCha` instance
/// will generate a long stream of bytes that is indistinguishable from
/// random for anyone not knowing the key and nonce.
///
/// # Examples
///
/// ```
/// use chacha::{ChaCha, KeyStream};
///
/// let secret_key = [
///     0x29, 0xfa, 0x35, 0x60, 0x88, 0x45, 0xc6, 0xf9, 
///     0xd8, 0xfe, 0x65, 0xe3, 0x22, 0x0e, 0x5b, 0x05, 
///     0x03, 0x4a, 0xa0, 0x9f, 0x9e, 0x27, 0xad, 0x0f, 
///     0x6c, 0x90, 0xa5, 0x73, 0xa8, 0x10, 0xe4, 0x94, 
/// ];
/// let nonce = [0u8; 8];
/// let mut stream = ChaCha::new_chacha20(&secret_key, &nonce);
///
/// let mut buffer = *b"abcdef";
/// stream.xor_read(&mut buffer[..]).expect("hit end of stream far too soon");
/// let expected_ciphertext = [0xde, 0x87, 0xa5, 0xbe, 0x1d, 0x77];
/// assert_eq!(buffer, expected_ciphertext);
/// ```
///
#[derive(Clone)]
pub struct ChaCha {
    input: [u32; 16],
    output: [u8; 64],
    offset: u8,
    rounds: u8,
    large_block_counter: bool,
}

impl ChaCha {
    /// Create a ChaCha stream conforming to the IETF's
    /// [RFC 7539](https://tools.ietf.org/html/rfc7539).
    /// The stream takes a 12-byte nonce and has a length of
    /// 2<sup>38</sup> bytes, or 256 GiB.
    pub fn new_ietf(key: &[u8; 32], nonce: &[u8; 12]) -> ChaCha {
        ChaCha {
            input: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                u32::from_le_bytes(key[ 0.. 4].try_into().unwrap()),
                u32::from_le_bytes(key[ 4.. 8].try_into().unwrap()),
                u32::from_le_bytes(key[ 8..12].try_into().unwrap()),
                u32::from_le_bytes(key[12..16].try_into().unwrap()),
                u32::from_le_bytes(key[16..20].try_into().unwrap()),
                u32::from_le_bytes(key[20..24].try_into().unwrap()),
                u32::from_le_bytes(key[24..28].try_into().unwrap()),
                u32::from_le_bytes(key[28..32].try_into().unwrap()),
                0, // block counter
                u32::from_le_bytes(nonce[ 0.. 4].try_into().unwrap()),
                u32::from_le_bytes(nonce[ 4.. 8].try_into().unwrap()),
                u32::from_le_bytes(nonce[ 8..12].try_into().unwrap()),
            ],
            output: [0; 64],
            offset: 255,
            large_block_counter: false,
            rounds: 20,
        }
    }

    /// Create a ChaCha stream with an 8-byte nonce and has a length of
    /// 2<sup>70</sup> bytes. This is compatible with libsodium's ChaCha20
    /// implementation and Daniel Bernstein's original
    /// [specification](https://cr.yp.to/chacha/chacha-20080128.pdf).
    pub fn new_chacha20(key: &[u8; 32], nonce: &[u8; 8]) -> ChaCha {
        ChaCha {
            input: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                u32::from_le_bytes(key[ 0.. 4].try_into().unwrap()),
                u32::from_le_bytes(key[ 4.. 8].try_into().unwrap()),
                u32::from_le_bytes(key[ 8..12].try_into().unwrap()),
                u32::from_le_bytes(key[12..16].try_into().unwrap()),
                u32::from_le_bytes(key[16..20].try_into().unwrap()),
                u32::from_le_bytes(key[20..24].try_into().unwrap()),
                u32::from_le_bytes(key[24..28].try_into().unwrap()),
                u32::from_le_bytes(key[28..32].try_into().unwrap()),
                0, // block counter
                0,
                u32::from_le_bytes(nonce[ 0.. 4].try_into().unwrap()),
                u32::from_le_bytes(nonce[ 4.. 8].try_into().unwrap()),
            ],
            output: [0; 64],
            offset: 255,
            large_block_counter: true,
            rounds: 20,
        }
    }

    /// Create a ChaCha stream with an 8-byte nonce and has a length of
    /// 2<sup>70</sup> bytes. This is compatible with libsodium's ChaCha12
    /// implementation. ChaCha12 decreases security margin relative to
    /// ChaCha20 in favor of speed.
    pub fn new_chacha12(key: &[u8; 32], nonce: &[u8; 8]) -> ChaCha {
        let mut st = ChaCha::new_chacha20(key, nonce);
        st.rounds = 12;
        st
    }

    /// Create a ChaCha stream with an 8-byte nonce and has a length of
    /// 2<sup>70</sup> bytes. This is compatible with libsodium's ChaCha12
    /// implementation. ChaCha8 decreases security margin relative to
    /// ChaCha20 in favor of speed.
    pub fn new_chacha8(key: &[u8; 32], nonce: &[u8; 8]) -> ChaCha {
        let mut st = ChaCha::new_chacha20(key, nonce);
        st.rounds = 8;
        st
    }

    /// Create a ChaCha stream with a 24-byte nonce and a length of
    /// 2<sup>70</sup> bytes. This stream's initialization relates
    /// to ChaCha20 in the same way that that
    /// [XSalsa20](https://cr.yp.to/snuffle/xsalsa-20110204.pdf)
    /// relates to Salsa20.
    pub fn new_xchacha20(key: &[u8; 32], nonce: &[u8; 24]) -> ChaCha {
        let mut st = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            u32::from_le_bytes(key[ 0.. 4].try_into().unwrap()),
            u32::from_le_bytes(key[ 4.. 8].try_into().unwrap()),
            u32::from_le_bytes(key[ 8..12].try_into().unwrap()),
            u32::from_le_bytes(key[12..16].try_into().unwrap()),
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
            u32::from_le_bytes(nonce[ 0.. 4].try_into().unwrap()),
            u32::from_le_bytes(nonce[ 4.. 8].try_into().unwrap()),
            u32::from_le_bytes(nonce[ 8..12].try_into().unwrap()),
            u32::from_le_bytes(nonce[12..16].try_into().unwrap()),
        ];
        permute_general(20, &mut st, false, None);

        ChaCha {
            input: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                st[ 0], st[ 1], st[ 2], st[ 3],
                st[12], st[13], st[14], st[15],
                0, 0,
                u32::from_le_bytes(nonce[16..20].try_into().unwrap()),
                u32::from_le_bytes(nonce[20..24].try_into().unwrap()),
            ],
            output: [0; 64],
            offset: 255,
            large_block_counter: true,
            rounds: 20,
        }
    }
}

#[cfg_attr(feature="nightly", repr(simd))]
#[derive(Copy, Clone)]
struct Row(u32, u32, u32, u32);

impl Row {
    fn add(self, x: Row) -> Row {
        Row(
            self.0.wrapping_add(x.0),
            self.1.wrapping_add(x.1),
            self.2.wrapping_add(x.2),
            self.3.wrapping_add(x.3)
        )
    }

    fn xor(self, x: Row) -> Row {
        Row(self.0^x.0, self.1^x.1, self.2^x.2, self.3^x.3)
    }

    fn or(self, x: Row) -> Row {
        Row(self.0|x.0, self.1|x.1, self.2|x.2, self.3|x.3)
    }

    fn shift_left(self, bit_distance: usize) -> Row {
        Row(self.0<<bit_distance, self.1<<bit_distance, self.2<<bit_distance, self.3<<bit_distance)
    }

    fn shift_right(self, bit_distance: usize) -> Row {
        Row(self.0>>bit_distance, self.1>>bit_distance, self.2>>bit_distance, self.3>>bit_distance)
    }

    fn roll_left(self, bit_distance: usize) -> Row {
        let lefted = self.shift_left(bit_distance);
        let righted = self.shift_right(32 - bit_distance);
        lefted.or(righted)
    }
    
    fn shuffle_left_1(self) -> Row {
        Row(self.1, self.2, self.3, self.0)
    }
    
    fn shuffle_left_2(self) -> Row {
        Row(self.2, self.3, self.0, self.1)
    }
    
    fn shuffle_left_3(self) -> Row {
        Row(self.3, self.0, self.1, self.2)
    }
    
}

// Inlining this causes the loop to unroll, which makes the disassembly hard
// to read.
#[inline(always)]
fn permute_general(mut rounds: u8, xs: &mut [u32; 16], do_add: bool, bs: Option<&mut [u8; 64]>) {
    let mut a = Row(xs[ 0], xs[ 1], xs[ 2], xs[ 3]);
    let mut b = Row(xs[ 4], xs[ 5], xs[ 6], xs[ 7]);
    let mut c = Row(xs[ 8], xs[ 9], xs[10], xs[11]);
    let mut d = Row(xs[12], xs[13], xs[14], xs[15]);

    loop {
        rounds = rounds.wrapping_sub(1);

        a = a.add(b); d = a.xor(d); d = d.roll_left(16);
        c = c.add(d); b = b.xor(c); b = b.roll_left(12);
        a = a.add(b); d = a.xor(d); d = d.roll_left( 8);
        c = c.add(d); b = b.xor(c); b = b.roll_left( 7);

        // Without this branch, making each iterate a double-round,
        // the compiler gets confused and does not use SSE instructions.
        if rounds%2==1 {
            // We are coming up on an odd round.
            // We will want to act on diagonals instead of columns, so
            // rearrange our rows accordingly.
            b = b.shuffle_left_1();
            c = c.shuffle_left_2();
            d = d.shuffle_left_3();
        } else {
            // We are coming up on an even round.
            // Undo our rearrangement into diagonals so we can act on
            // columns again.
            b = b.shuffle_left_3();
            c = c.shuffle_left_2();
            d = d.shuffle_left_1();
            if rounds==0 {
                break;
            }
        }
    }
    if do_add {
        a = a.add(Row(xs[ 0], xs[ 1], xs[ 2], xs[ 3]));
        b = b.add(Row(xs[ 4], xs[ 5], xs[ 6], xs[ 7]));
        c = c.add(Row(xs[ 8], xs[ 9], xs[10], xs[11]));
        d = d.add(Row(xs[12], xs[13], xs[14], xs[15]));
    }

    if let Some(bs) = bs {
        bs[ 0.. 4].copy_from_slice(&a.0.to_le_bytes());
        bs[ 4.. 8].copy_from_slice(&a.1.to_le_bytes());
        bs[ 8..12].copy_from_slice(&a.2.to_le_bytes());
        bs[12..16].copy_from_slice(&a.3.to_le_bytes());
        bs[16..20].copy_from_slice(&b.0.to_le_bytes());
        bs[20..24].copy_from_slice(&b.1.to_le_bytes());
        bs[24..28].copy_from_slice(&b.2.to_le_bytes());
        bs[28..32].copy_from_slice(&b.3.to_le_bytes());
        bs[32..36].copy_from_slice(&c.0.to_le_bytes());
        bs[36..40].copy_from_slice(&c.1.to_le_bytes());
        bs[40..44].copy_from_slice(&c.2.to_le_bytes());
        bs[44..48].copy_from_slice(&c.3.to_le_bytes());
        bs[48..52].copy_from_slice(&d.0.to_le_bytes());
        bs[52..56].copy_from_slice(&d.1.to_le_bytes());
        bs[56..60].copy_from_slice(&d.2.to_le_bytes());
        bs[60..64].copy_from_slice(&d.3.to_le_bytes());
    } else {
        xs[ 0] = a.0; xs[ 1] = a.1; xs[ 2] = a.2; xs[ 3] = a.3;
        xs[ 4] = b.0; xs[ 5] = b.1; xs[ 6] = b.2; xs[ 7] = b.3;
        xs[ 8] = c.0; xs[ 9] = c.1; xs[10] = c.2; xs[11] = c.3;
        xs[12] = d.0; xs[13] = d.1; xs[14] = d.2; xs[15] = d.3;
    }
}

/// Apply the ChaCha core function. Note that this is reversible.
pub fn permute(rounds: u8, xs: &mut [u32; 16]) {
    permute_general(rounds, xs, false, None)
}

/// Apply the ChaCha core function and add the result to the input.
/// This is what maps ChaCha streams' input blocks to output blocks.
pub fn permute_and_add(rounds: u8, xs: &mut [u32; 16]) {
    permute_general(rounds, xs, true, None)
}


impl ChaCha {
    fn increment_counter(&mut self) -> Result<(), Error> {
        if self.input[12] != 0 {
            // This is the common case, where we just increment the counter.

            let (incremented_low, overflow) = self.input[12].overflowing_add(1);

            self.input[12] = incremented_low;
            self.input[13] = self.input[13].wrapping_add((overflow & self.large_block_counter) as u32);
        } else {
            // The low block counter overflowed OR we are just starting.
            // We detect the "just starting" case by setting `offset` to 255.
            // (During other parts of operation, `offset` does not exceed 64.
            if self.offset == 255 {
                self.input[12] = 1;
                self.offset = 64;
            } else if self.input[13]==0 || !self.large_block_counter {
                // Our counter wrapped around!
                return Err(Error::EndReached);
            } else {
                self.input[12] = 1;
            }
        }

        Ok( () )
    }
}

impl KeyStream for ChaCha {
    fn xor_read(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        let dest = if self.offset < 64 {
            let from_existing = min(dest.len(), 64 - self.offset as usize);
            for (dest_byte, output_byte) in dest.iter_mut().zip(self.output[self.offset as usize..].iter()) {
                *dest_byte = *dest_byte ^ *output_byte;
            }
            self.offset += from_existing as u8;
            &mut dest[from_existing..]
        } else {
            dest
        };

        for dest_chunk in dest.chunks_mut(64) {
            let mut output_buf = self.input;
            permute_general(self.rounds, &mut output_buf, true, None);
            self.increment_counter()?;
            if dest_chunk.len() == 64 {
                for idx in 0..16 {
                    let word = u32::from_le_bytes(dest_chunk[idx*4..idx*4+4].try_into().unwrap()) ^ output_buf[idx];
                    dest_chunk[idx*4..idx*4+4].copy_from_slice(&word.to_le_bytes());
                }
            } else {
                for idx in 0..16 {
                    self.output[idx*4..idx*4+4].copy_from_slice(&output_buf[idx].to_le_bytes());
                }
                for (dest_byte, output_byte) in dest_chunk.iter_mut().zip(self.output.iter()) {
                    *dest_byte = *dest_byte ^ output_byte;
                }
                self.offset = dest_chunk.len() as u8;
            }
        }

        Ok( () )
    }
}

impl SeekableKeyStream for ChaCha {
    fn seek_to(&mut self, byte_offset: u64) -> Result<(), Error> {
        // With one block counter word, we can go past the end of the stream with a u64.
        if self.large_block_counter {
            self.input[12] = (byte_offset >> 6) as u32;
            self.input[13] = (byte_offset >> 38) as u32;
        } else {
            if byte_offset>=64*0x1_0000_0000 {
                // Set an overflow state.
                self.input[12] = 0;
                self.offset = 64;
                return Err(Error::EndReached);
            } else {
                self.input[12] = (byte_offset >> 6) as u32;
            }
        }

        self.offset = (byte_offset & 0x3f) as u8;
        permute_general(self.rounds, &mut self.input, true, Some(&mut self.output));

        let (incremented_low, overflow) = self.input[12].overflowing_add(1);
        self.input[12] = incremented_low;
        self.input[13] = self.input[13].wrapping_add(if overflow {
            if self.large_block_counter { 1 } else { 0 }
        } else { 0 });

        Ok( () )
    }
}


/// Runs the self-test for the chacha20 block function.
#[cold]
pub fn selftest() {
    let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
               0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
    let nonce = [0x00, 0x00, 0x00, 0x09,
                 0x00, 0x00, 0x00, 0x4a,
                 0x00, 0x00, 0x00, 0x00];
    let expected = [0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
                    0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
                    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
                    0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
                    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
                    0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
                    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
                    0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e];

    let mut result = [0u8; 64];
    let mut state = ChaCha::new_ietf(&key, &nonce);
    state.seek_to(64).unwrap();
    state.xor_read(&mut result).unwrap();
    assert_eq!(result, expected);
}


#[cfg(test)]
mod tests {
use super::*;

#[test]
fn do_selftest() {
    selftest();
}

#[test]
fn rfc_7539_permute_20() {
    let mut xs = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    ];

    permute(20, &mut xs);

    assert_eq!(xs, [
        0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
        0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
        0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
        0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2,
    ]);
}

#[test]
fn rfc_7539_permute_and_add_20() {
    let mut xs = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    ];

    permute_and_add(20, &mut xs);

    assert_eq!(xs, [
       0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
       0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
       0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
       0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
    ]);
}

#[test]
fn rfc_7539_case_1() {
    let mut st = ChaCha::new_ietf(
        &[
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        ], &[
            0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,
            0x00,0x00,0x00,0x00
        ]
    );

    let mut buf = [0u8; 128];
    st.xor_read(&mut buf).unwrap();
    assert_eq!(buf[64..].to_vec(), [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    ].to_vec());
}

#[test]
fn rfc_7539_case_2() {
    let mut st = ChaCha::new_ietf(
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ], &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        ]
    );

    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let mut buf = [0u8; 178];
    for (dest, src) in buf[64..].iter_mut().zip(plaintext.iter()) {
        *dest = *src;
    }
    st.xor_read(&mut buf[..]).unwrap();

    assert_eq!(buf[64..].to_vec(), [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    ].to_vec());
}

#[test]
fn rfc_7539_case_2_chunked() {
    let mut st = ChaCha::new_ietf(
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ], &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        ]
    );

    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let mut buf = [0u8; 178];
    for (dest, src) in buf[64..].iter_mut().zip(plaintext.iter()) {
        *dest = *src;
    }
    st.xor_read(&mut buf[..40]).unwrap();
    st.xor_read(&mut buf[40..78]).unwrap();
    st.xor_read(&mut buf[78..79]).unwrap();
    st.xor_read(&mut buf[79..128]).unwrap();
    st.xor_read(&mut buf[128..]).unwrap();

    assert_eq!(buf[64..].to_vec(), [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    ].to_vec());
}

#[test]
fn xchacha20_case_1() {
    let mut stream = ChaCha::new_xchacha20(
        &[
            0x82, 0xf4, 0x11, 0xa0, 0x74, 0xf6, 0x56, 0xc6,
            0x6e, 0x7d, 0xbd, 0xdb, 0x0a, 0x2c, 0x1b, 0x22,
            0x76, 0x0b, 0x9b, 0x21, 0x05, 0xf4, 0xff, 0xdb,
            0xb1, 0xd4, 0xb1, 0xe8, 0x24, 0xe2, 0x1d, 0xef,
        ],
        &[
            0x3b, 0x07, 0xca, 0x6e, 0x72, 0x9e, 0xb4, 0x4a,
            0x51, 0x0b, 0x7a, 0x1b, 0xe5, 0x18, 0x47, 0x83,
            0x8a, 0x80, 0x4f, 0x8b, 0x10, 0x6b, 0x38, 0xbd,
        ]
    );

    let mut xs = [0u8; 100];
    stream.xor_read(&mut xs).unwrap();

    assert_eq!(xs.to_vec(), [
        0x20, 0x18, 0x63, 0x97, 0x0b, 0x8e, 0x08, 0x1f, 0x41, 0x22,
        0xad, 0xdf, 0xdf, 0x32, 0xf6, 0xc0, 0x3e, 0x48, 0xd9, 0xbc,
        0x4e, 0x34, 0xa5, 0x96, 0x54, 0xf4, 0x92, 0x48, 0xb9, 0xbe,
        0x59, 0xd3, 0xea, 0xa1, 0x06, 0xac, 0x33, 0x76, 0xe7, 0xe7,
        0xd9, 0xd1, 0x25, 0x1f, 0x2c, 0xbf, 0x61, 0xef, 0x27, 0x00,
        0x0f, 0x3d, 0x19, 0xaf, 0xb7, 0x6b, 0x9c, 0x24, 0x71, 0x51,
        0xe7, 0xbc, 0x26, 0x46, 0x75, 0x83, 0xf5, 0x20, 0x51, 0x8e,
        0xcc, 0xd2, 0x05, 0x5c, 0xcd, 0x6c, 0xc8, 0xa1, 0x95, 0x95,
        0x3d, 0x82, 0xa1, 0x0c, 0x20, 0x65, 0x91, 0x67, 0x78, 0xdb,
        0x35, 0xda, 0x2b, 0xe4, 0x44, 0x15, 0xd2, 0xf5, 0xef, 0xb0,
    ].to_vec());
}

#[test]
fn chacha12_case_1() {
    let mut stream = ChaCha::new_chacha12(
        &[
            0x27, 0xfc, 0x12, 0x0b, 0x01, 0x3b, 0x82, 0x9f,
            0x1f, 0xae, 0xef, 0xd1, 0xab, 0x41, 0x7e, 0x86,
            0x62, 0xf4, 0x3e, 0x0d, 0x73, 0xf9, 0x8d, 0xe8,
            0x66, 0xe3, 0x46, 0x35, 0x31, 0x80, 0xfd, 0xb7,
        ],
        &[
            0xdb, 0x4b, 0x4a, 0x41, 0xd8, 0xdf, 0x18, 0xaa
        ]
    );

    let mut xs = [0u8; 100];
    stream.xor_read(&mut xs).unwrap();

    assert_eq!(xs.to_vec(), [
        0x5f, 0x3c, 0x8c, 0x19, 0x0a, 0x78, 0xab, 0x7f,
        0xe8, 0x08, 0xca, 0xe9, 0xcb, 0xcb, 0x0a, 0x98,
        0x37, 0xc8, 0x93, 0x49, 0x2d, 0x96, 0x3a, 0x1c,
        0x2e, 0xda, 0x6c, 0x15, 0x58, 0xb0, 0x2c, 0x83,
        0xfc, 0x02, 0xa4, 0x4c, 0xbb, 0xb7, 0xe6, 0x20,
        0x4d, 0x51, 0xd1, 0xc2, 0x43, 0x0e, 0x9c, 0x0b,
        0x58, 0xf2, 0x93, 0x7b, 0xf5, 0x93, 0x84, 0x0c,
        0x85, 0x0b, 0xda, 0x90, 0x51, 0xa1, 0xf0, 0x51,
        0xdd, 0xf0, 0x9d, 0x2a, 0x03, 0xeb, 0xf0, 0x9f,
        0x01, 0xbd, 0xba, 0x9d, 0xa0, 0xb6, 0xda, 0x79,
        0x1b, 0x2e, 0x64, 0x56, 0x41, 0x04, 0x7d, 0x11,
        0xeb, 0xf8, 0x50, 0x87, 0xd4, 0xde, 0x5c, 0x01,
        0x5f, 0xdd, 0xd0, 0x44,
    ].to_vec());
}


#[test]
fn chacha8_case_1() {
    let mut stream = ChaCha::new_chacha8(
        &[
            0x64, 0x1a, 0xea, 0xeb, 0x08, 0x03, 0x6b, 0x61,
            0x7a, 0x42, 0xcf, 0x14, 0xe8, 0xc5, 0xd2, 0xd1,
            0x15, 0xf8, 0xd7, 0xcb, 0x6e, 0xa5, 0xe2, 0x8b,
            0x9b, 0xfa, 0xf8, 0x3e, 0x03, 0x84, 0x26, 0xa7,
        ],
        &[
            0xa1, 0x4a, 0x11, 0x68, 0x27, 0x1d, 0x45, 0x9b,
        ]
    );

    let mut xs = [0u8; 100];
    stream.xor_read(&mut xs).unwrap();

    assert_eq!(xs.to_vec(), [
        0x17, 0x21, 0xc0, 0x44, 0xa8, 0xa6, 0x45, 0x35,
        0x22, 0xdd, 0xdb, 0x31, 0x43, 0xd0, 0xbe, 0x35,
        0x12, 0x63, 0x3c, 0xa3, 0xc7, 0x9b, 0xf8, 0xcc,
        0xc3, 0x59, 0x4c, 0xb2, 0xc2, 0xf3, 0x10, 0xf7,
        0xbd, 0x54, 0x4f, 0x55, 0xce, 0x0d, 0xb3, 0x81,
        0x23, 0x41, 0x2d, 0x6c, 0x45, 0x20, 0x7d, 0x5c,
        0xf9, 0xaf, 0x0c, 0x6c, 0x68, 0x0c, 0xce, 0x1f,
        0x7e, 0x43, 0x38, 0x8d, 0x1b, 0x03, 0x46, 0xb7,
        0x13, 0x3c, 0x59, 0xfd, 0x6a, 0xf4, 0xa5, 0xa5,
        0x68, 0xaa, 0x33, 0x4c, 0xcd, 0xc3, 0x8a, 0xf5,
        0xac, 0xe2, 0x01, 0xdf, 0x84, 0xd0, 0xa3, 0xca,
        0x22, 0x54, 0x94, 0xca, 0x62, 0x09, 0x34, 0x5f,
        0xcf, 0x30, 0x13, 0x2e,
    ].to_vec());
}

#[test]
fn chacha20_case_1() {
    let mut stream = ChaCha::new_chacha20(
        &[
            0xfa, 0x44, 0x47, 0x8c, 0x59, 0xca, 0x70, 0x53,
            0x8e, 0x35, 0x49, 0x09, 0x6c, 0xe8, 0xb5, 0x23,
            0x23, 0x2c, 0x50, 0xd9, 0xe8, 0xe8, 0xd1, 0x0c,
            0x20, 0x3e, 0xf6, 0xc8, 0xd0, 0x70, 0x98, 0xa5
        ],
        &[
            0x8d, 0x3a, 0x0d, 0x6d, 0x78, 0x27, 0xc0, 0x07
        ]
    );

    let offset = 274877906800u64;
    assert!((offset>>38) != ((offset+240)>>38)); // This will overflow the small word of the counter

    stream.seek_to(offset).unwrap();

    let mut xs = [0u8; 256];
    stream.xor_read(&mut xs).unwrap();

    assert_eq!(xs.to_vec(), [
        0x15, 0x46, 0xa5, 0x47, 0xff, 0x77, 0xc5, 0xc9,
        0x64, 0xe4, 0x4f, 0xd0, 0x39, 0xe9, 0x13, 0xc6,
        0x39, 0x5c, 0x8f, 0x19, 0xd4, 0x3e, 0xfa, 0xa8,
        0x80, 0x75, 0x0f, 0x66, 0x87, 0xb4, 0xe6, 0xe2,
        0xd8, 0xf4, 0x2f, 0x63, 0x54, 0x6d, 0xa2, 0xd1,
        0x33, 0xb5, 0xaa, 0x2f, 0x1e, 0xf3, 0xf2, 0x18,
        0xb6, 0xc7, 0x29, 0x43, 0x08, 0x9e, 0x40, 0x12,
        0x21, 0x0c, 0x2c, 0xbe, 0xd0, 0xe8, 0xe9, 0x34,
        0x98, 0xa6, 0x82, 0x5f, 0xc8, 0xff, 0x7a, 0x50,
        0x4f, 0x26, 0xdb, 0x33, 0xb6, 0xcb, 0xe3, 0x62,
        0x99, 0x43, 0x62, 0x44, 0xc9, 0xb2, 0xef, 0xf8,
        0x83, 0x02, 0xc5, 0x59, 0x33, 0x91, 0x1b, 0x7d,
        0x5d, 0xea, 0x75, 0xf2, 0xb6, 0xd4, 0x76, 0x1b,
        0xa4, 0x4b, 0xb6, 0xf8, 0x14, 0xc9, 0x87, 0x9d,
        0x2b, 0xa2, 0xac, 0x8b, 0x17, 0x8f, 0xa1, 0x10,
        0x4a, 0x36, 0x86, 0x94, 0x87, 0x23, 0x39, 0x73,
        0x8f, 0xfb, 0x96, 0x0e, 0x33, 0xdb, 0x39, 0xef,
        0xb8, 0xea, 0xef, 0x88, 0x5b, 0x91, 0x0e, 0xea,
        0x07, 0x8e, 0x7a, 0x1f, 0xeb, 0x3f, 0x81, 0x85,
        0xda, 0xfd, 0x14, 0x55, 0xb7, 0x04, 0xd7, 0x6d,
        0xa3, 0xa0, 0xce, 0x47, 0x60, 0x74, 0x18, 0x41,
        0x21, 0x7b, 0xba, 0x1e, 0x4e, 0xce, 0x76, 0x0e,
        0xaf, 0x68, 0x61, 0x71, 0x33, 0x43, 0x1f, 0xeb,
        0x80, 0x6c, 0x06, 0x11, 0x73, 0xaf, 0x6b, 0x8b,
        0x2a, 0x23, 0xbe, 0x90, 0xc5, 0xd1, 0x45, 0xcc,
        0x25, 0x8e, 0x3c, 0x11, 0x9a, 0xab, 0x28, 0x00,
        0xf0, 0xc7, 0xbc, 0x19, 0x59, 0xda, 0xe7, 0x54,
        0x81, 0x71, 0x2c, 0xab, 0x73, 0x1b, 0x7d, 0xfd,
        0x78, 0x3f, 0xa3, 0xa2, 0x28, 0xf9, 0x96, 0x8a,
        0xae, 0xa6, 0x8f, 0x36, 0xa9, 0x2f, 0x43, 0xc9,
        0xb5, 0x23, 0x33, 0x7a, 0x55, 0xb9, 0x7b, 0xca,
        0xf5, 0xf5, 0x77, 0x44, 0x47, 0xbf, 0x41, 0xe8,
    ].to_vec());
}

#[test]
fn seek_off_end() {
    let mut st = ChaCha::new_ietf(&[0xff; 32], &[0; 12]);

    assert_eq!(st.seek_to(0x40_0000_0000), Err(Error::EndReached));
    assert_eq!(st.xor_read(&mut [0u8; 1]), Err(Error::EndReached));

    assert_eq!(st.seek_to(1), Ok(()));
    assert!(st.xor_read(&mut [0u8; 1]).is_ok());
}

#[test]
fn read_last_bytes() {
    let mut st = ChaCha::new_ietf(&[0xff; 32], &[0; 12]);

    st.seek_to(0x40_0000_0000 - 10).expect("should be able to seek to near the end");
    st.xor_read(&mut [0u8; 10]).expect("should be able to read last 10 bytes");
    assert!(st.xor_read(&mut [0u8; 1]).is_err());
    assert!(st.xor_read(&mut [0u8; 10]).is_err());

    st.seek_to(0x40_0000_0000 - 10).unwrap();
    assert!(st.xor_read(&mut [0u8; 11]).is_err());
}

#[test]
fn seek_consistency() {
    let mut st = ChaCha::new_ietf(&[0x50; 32], &[0x44; 12]);

    let mut continuous = [0u8; 1000];
    st.xor_read(&mut continuous).unwrap();

    let mut chunks = [0u8; 1000];

    st.seek_to(128).unwrap();
    st.xor_read(&mut chunks[128..300]).unwrap();

    st.seek_to(0).unwrap();
    st.xor_read(&mut chunks[0..10]).unwrap();

    st.seek_to(300).unwrap();
    st.xor_read(&mut chunks[300..533]).unwrap();

    st.seek_to(533).unwrap();
    st.xor_read(&mut chunks[533..]).unwrap();

    st.seek_to(10).unwrap();
    st.xor_read(&mut chunks[10..128]).unwrap();

    assert_eq!(continuous.to_vec(), chunks.to_vec());

    // Make sure we don't affect a nonce word when we hit the end with the small block counter
    assert!(st.seek_to(0x40_0000_0000).is_err());
    let mut small = [0u8; 100];
    st.seek_to(0).unwrap();
    st.xor_read(&mut small).unwrap();
    assert_eq!(small.to_vec(), continuous[..100].to_vec());
}

} // mod tests


#[cfg(all(test, feature="bench"))]
mod bench {
    use super::{ChaCha, KeyStream};
    use test::Bencher;

    #[bench]
    pub fn chacha20(bh: &mut Bencher) {
        let mut stream = ChaCha::new_chacha20(&[0; 32], &[0; 8]);
        let mut buf = [0u8; 1024];
        bh.bytes = buf.len() as u64;
        bh.iter(|| {
            let _ = stream.xor_read(&mut buf);
        });
    }
}
