#![feature(repr_simd)]

use std::mem::align_of;

fn quarter_round<E: ChaChaElem>(a: &mut E, b: &mut E, c: &mut E, d: &mut E) {
    a.increase_by(b); d.xor_by(a); d.roll_left_by(16);
    c.increase_by(d); b.xor_by(c); b.roll_left_by(12);
    a.increase_by(b); d.xor_by(a); d.roll_left_by(8);
    c.increase_by(d); b.xor_by(c); b.roll_left_by(7);
}

pub struct QuadState(u32, u32, u32, u32);

impl QuadState {
    fn dup(x: u32) -> QuadState {
        QuadState(x,x,x,x)
    }
}

impl ChaChaElem for QuadState {
    fn increase_by(&mut self, other: &QuadState) {
        self.0 = self.0.wrapping_add(other.0);
        self.1 = self.1.wrapping_add(other.1);
        self.2 = self.2.wrapping_add(other.2);
        self.3 = self.3.wrapping_add(other.3);
    }
    
    fn xor_by(&mut self, other: &QuadState) {
        self.0 ^= other.0;
        self.1 ^= other.1;
        self.2 ^= other.2;
        self.3 ^= other.3;
    }
    
    fn roll_left_by(&mut self, amount: usize) {
        self.0 = roll_left(self.0, amount);
        self.1 = roll_left(self.1, amount);
        self.2 = roll_left(self.2, amount);
        self.3 = roll_left(self.3, amount);
    }
}

impl ChaChaElem for u32 {
    fn increase_by(&mut self, other: &u32) {
        *self = self.wrapping_add(*other);
    }
    
    fn xor_by(&mut self, other: &u32) {
        *self ^= *other;
    }
    
    fn roll_left_by(&mut self, amount: usize) {
        *self = roll_left(*self, amount);
    }
}

fn roll_left(x: u32, bit_distance: usize) -> u32 {
    (x << (bit_distance)) | (x >> (32 - bit_distance))
}

#[test]
fn rfc_7539_quarter_round() {
    let mut a: u32 = 0x11111111;
    let mut b: u32 = 0x01020304;
    let mut c: u32 = 0x9b8d6f43 ;
    let mut d: u32 = 0x01234567;
    quarter_round(&mut a, &mut b, &mut c, &mut d);
    assert_eq!(a, 0xea2a92f4);
    assert_eq!(b, 0xcb1cf8ce);
    assert_eq!(c, 0x4581472e);
    assert_eq!(d, 0x5881c4bb);
}



#[derive(Copy, Clone)]
pub struct ChaChaState<E> {
    row0: (E, E, E, E),
    row1: (E, E, E, E),
    row2: (E, E, E, E),
    row3: (E, E, E, E)
}

fn increase_row<E: ChaChaElem>(x: &mut (E, E, E, E), y: &(E, E, E, E)) {
    x.0.increase_by(&y.0);
    x.1.increase_by(&y.1);
    x.2.increase_by(&y.2);
    x.3.increase_by(&y.3);
}

#[inline]
fn read_u32_le(xs: &[u8]) -> u32 {
    ((xs[0] as u32) << 0) |
    ((xs[1] as u32) << 8) |
    ((xs[2] as u32) << 16) |
    ((xs[3] as u32) << 24)
}

#[inline]
fn write_u32_le(dest: &mut[u8], x: u32) {
    dest[0] = (x >> 0) as u8;
    dest[1] = (x >> 8) as u8;
    dest[2] = (x >> 16) as u8;
    dest[3] = (x >> 24) as u8;
}

impl ChaChaState<u32> {
    fn from_bytes(bs: &[u8; 64]) -> ChaChaState<u32> {
        ChaChaState{
            row0: (
                read_u32_le(&bs[0..4]), 
                read_u32_le(&bs[4..8]),
                read_u32_le(&bs[8..12]),
                read_u32_le(&bs[12..16])
            ),
            row1: (
                read_u32_le(&bs[16..20]), 
                read_u32_le(&bs[20..24]),
                read_u32_le(&bs[24..28]),
                read_u32_le(&bs[28..32])
            ),
            row2: (
                read_u32_le(&bs[32..36]), 
                read_u32_le(&bs[36..40]),
                read_u32_le(&bs[40..44]),
                read_u32_le(&bs[44..48])
            ),
            row3: (
                read_u32_le(&bs[48..52]), 
                read_u32_le(&bs[52..56]),
                read_u32_le(&bs[56..60]),
                read_u32_le(&bs[60..64])
            ),
        }
    }
    
    fn into_bytes(&self, dest: &mut [u8; 64]) {
        write_u32_le(&mut dest[0..4], self.row0.0);
        write_u32_le(&mut dest[4..8], self.row0.1);
        write_u32_le(&mut dest[8..12], self.row0.2);
        write_u32_le(&mut dest[12..16], self.row0.3);
        
        write_u32_le(&mut dest[16..20], self.row1.0);
        write_u32_le(&mut dest[20..24], self.row1.1);
        write_u32_le(&mut dest[24..28], self.row1.2);
        write_u32_le(&mut dest[28..32], self.row1.3);
        
        write_u32_le(&mut dest[32..36], self.row2.0);
        write_u32_le(&mut dest[36..40], self.row2.1);
        write_u32_le(&mut dest[40..44], self.row2.2);
        write_u32_le(&mut dest[44..48], self.row2.3);
        
        write_u32_le(&mut dest[48..52], self.row3.0);
        write_u32_le(&mut dest[52..56], self.row3.1);
        write_u32_le(&mut dest[56..60], self.row3.2);
        write_u32_le(&mut dest[60..64], self.row3.3);
    }
}

impl<E: ChaChaElem> ChaChaState<E> {
    fn double_round(&mut self) {
        quarter_round(&mut self.row0.0, &mut self.row1.0, &mut self.row2.0, &mut self.row3.0);
        quarter_round(&mut self.row0.1, &mut self.row1.1, &mut self.row2.1, &mut self.row3.1);
        quarter_round(&mut self.row0.2, &mut self.row1.2, &mut self.row2.2, &mut self.row3.2);
        quarter_round(&mut self.row0.3, &mut self.row1.3, &mut self.row2.3, &mut self.row3.3);
        
        quarter_round(&mut self.row0.0, &mut self.row1.1, &mut self.row2.2, &mut self.row3.3);
        quarter_round(&mut self.row0.1, &mut self.row1.2, &mut self.row2.3, &mut self.row3.0);
        quarter_round(&mut self.row0.2, &mut self.row1.3, &mut self.row2.0, &mut self.row3.1);
        quarter_round(&mut self.row0.3, &mut self.row1.0, &mut self.row2.1, &mut self.row3.2);
    }
    
    fn increase_by(&mut self, other: &ChaChaState<E>) {
        increase_row(&mut self.row0, &other.row0);
        increase_row(&mut self.row1, &other.row1);
        increase_row(&mut self.row2, &other.row2);
        increase_row(&mut self.row3, &other.row3);
    }
}

impl ChaChaState<QuadState> {
    fn quadify_row(source: &(u32, u32, u32, u32)) -> (QuadState, QuadState, QuadState, QuadState) {
        (QuadState::dup(source.0), QuadState::dup(source.1), QuadState::dup(source.2), QuadState::dup(source.3))
    }

    fn next_four(source: ChaChaState<u32>) -> ChaChaState<QuadState> {
        let mut st = ChaChaState {
            row0: ChaChaState::<QuadState>::quadify_row(&source.row0),
            row1: ChaChaState::<QuadState>::quadify_row(&source.row1),
            row2: ChaChaState::<QuadState>::quadify_row(&source.row2),
            row3: ChaChaState::<QuadState>::quadify_row(&source.row3),
        };
        ChaChaElem::increase_by(&mut (st.row3.0).1, &1);
        ChaChaElem::increase_by(&mut (st.row3.0).2, &2);
        ChaChaElem::increase_by(&mut (st.row3.0).3, &3);
        st
    }
}

trait ChaChaParams {
    fn doubleround_count() -> usize;
}

struct ChaCha20Params;
impl ChaChaParams for ChaCha20Params {
    fn doubleround_count() -> usize {
        10
    }
}

fn permute<P: ChaChaParams, E:ChaChaElem>(s: &mut ChaChaState<E>) {
    for _ in 0..(P::doubleround_count()) {
        s.double_round();
    }
    
    //s.increase_by(&permuted);
}


#[test]
fn it_works() {
}

#[test]
fn rfc_7539_permute_20() {
    let mut st = ChaChaState {
        row0: (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574),
        row1: (0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c),
        row2: (0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c),
        row3: (0x00000001, 0x09000000, 0x4a000000, 0x00000000),
    };
    permute::<ChaCha20Params, u32>(&mut st);
    
    assert_eq!(st.row0, (0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f));
    assert_eq!(st.row1, (0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7));
    assert_eq!(st.row2, (0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd));
    assert_eq!(st.row3, (0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2));
}


pub fn permute_20(bs: &mut [u8; 64]) {
    let mut state = ChaChaState::from_bytes(bs);
    permute::<ChaCha20Params, u32>(&mut state);
    state.into_bytes(bs);
}

#[inline(never)]
pub fn mega_permute_n(bs: &mut [u8; 64], repeat: usize) -> u32 {
    let mut megastate = ChaChaState::<QuadState>::next_four(ChaChaState::from_bytes(bs));
    
    for _ in 0..repeat {
        permute::<ChaCha20Params, QuadState>(&mut megastate);
    }
    
    (megastate.row0.0).0
    
}

#[inline(always)]
fn add4(a: Row, b: Row) -> Row {
    Row(a.0.wrapping_add(b.0), a.1.wrapping_add(b.1), a.2.wrapping_add(b.2), a.3.wrapping_add(b.3))
}

#[inline(always)]
fn xor4(a: Row, b: Row) -> Row {
    Row(a.0^b.0, a.1^b.1, a.2^b.2, a.3^b.3)
}

#[inline(always)]
fn roll4(a: Row, amount: usize) -> Row {
    Row(roll_left(a.0, amount), roll_left(a.1, amount), roll_left(a.2, amount), roll_left(a.3, amount))
}

#[inline(always)]
fn shift4(a: Row, amount: usize) -> Row {
    Row(a.0<<amount, a.1<<amount, a.2<<amount, a.3<<amount)
}

#[inline(always)]
fn right4(a: Row, amount: usize) -> Row {
    Row(a.0>>amount, a.1>>amount, a.2>>amount, a.3>>amount)
}

#[inline(always)]
fn or4(a: Row, b: Row) -> Row {
    Row(a.0|b.0, a.1|b.1, a.2|b.2, a.3|b.3)
}


#[inline(always)]
fn roll_left_4(a: Row, amount: usize) -> Row {
    let al = shift4(a, amount);
    let ar = shift4(a, 32-amount);
    or4(al, ar)
}

#[repr(simd)]
#[derive(Copy, Clone)]
struct Row(u32, u32, u32, u32);

// Inlining this causes the loop to unroll, which makes the disassembly hard 
// to read.
#[inline(always)]
fn sse_permute(mut rounds: u8, xs: &mut [u32; 16], do_add: bool) {
    let mut a = Row(xs[ 0], xs[ 1], xs[ 2], xs[ 3]);
    let mut b = Row(xs[ 4], xs[ 5], xs[ 6], xs[ 7]);
    let mut c = Row(xs[ 8], xs[ 9], xs[10], xs[11]);
    let mut d = Row(xs[12], xs[13], xs[14], xs[15]);
    
    loop {
        rounds = rounds.wrapping_sub(1);
            
        a = add4(a, b); d = xor4(a, d); d = roll_left_4(d, 16);
        c = add4(c, d); b = xor4(b, c); b = roll_left_4(b, 12);
        a = add4(a, b); d = xor4(a, d); d = roll_left_4(d, 8);
        c = add4(c, d); b = xor4(b, c); b = roll_left_4(b, 7);
        
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
        a = add4(a, Row(xs[ 0], xs[ 1], xs[ 2], xs[ 3]));
        b = add4(b, Row(xs[ 4], xs[ 5], xs[ 6], xs[ 7]));
        c = add4(c, Row(xs[ 8], xs[ 9], xs[10], xs[11]));
        d = add4(d, Row(xs[12], xs[13], xs[14], xs[15]));
    }
    
    xs[0] = a.0; xs[1] = a.1; xs[2] = a.2; xs[3] = a.3;
    xs[4] = b.0; xs[5] = b.1; xs[6] = b.2; xs[7] = b.3;
    xs[8] = c.0; xs[9] = c.1; xs[10] = c.2; xs[11] = c.3;
    xs[12] = d.0; xs[13] = d.1; xs[14] = d.2; xs[15] = d.3;
}

#[inline(never)]
pub fn permute_only(rounds: u8, xs: &mut [u32; 16]) {
    sse_permute(rounds, xs, false)
}

#[inline(never)]
pub fn permute_and_add(rounds: u8, xs: &mut [u32; 16]) {
    sse_permute(rounds, xs, true)
}

#[test]
fn test_mega_permute() {
    let mut bs = [1u8; 64];
    
    //assert_eq!(mega_permute_n(&mut bs, 1), 0xade0b876);
}


