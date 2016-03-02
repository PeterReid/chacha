#![cfg_attr(feature="nightly", feature(repr_simd))]

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
}

// Inlining this causes the loop to unroll, which makes the disassembly hard
// to read.
#[inline(always)]
fn permute(mut rounds: u8, xs: &mut [u32; 16], do_add: bool) {
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
            b = Row(b.1, b.2, b.3, b.0);
            c = Row(c.2, c.3, c.0, c.1);
            d = Row(d.3, d.0, d.1, d.2);
        } else {
            // We are coming up on an even round.
            // Undo our rearrangement into diagonals so we can act on
            // columns again.
            b = Row(b.3, b.0, b.1, b.2);
            c = Row(c.2, c.3, c.0, c.1);
            d = Row(d.1, d.2, d.3, d.0);
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

    xs[ 0] = a.0; xs[ 1] = a.1; xs[ 2] = a.2; xs[ 3] = a.3;
    xs[ 4] = b.0; xs[ 5] = b.1; xs[ 6] = b.2; xs[ 7] = b.3;
    xs[ 8] = c.0; xs[ 9] = c.1; xs[10] = c.2; xs[11] = c.3;
    xs[12] = d.0; xs[13] = d.1; xs[14] = d.2; xs[15] = d.3;
}

#[inline(never)]
pub fn permute_only(rounds: u8, xs: &mut [u32; 16]) {
    permute(rounds, xs, false)
}

#[inline(never)]
pub fn permute_and_add(rounds: u8, xs: &mut [u32; 16]) {
    permute(rounds, xs, true)
}

#[test]
fn rfc_7539_permute_20() {
    let mut xs = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    ];

    permute_only(20, &mut xs);

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
