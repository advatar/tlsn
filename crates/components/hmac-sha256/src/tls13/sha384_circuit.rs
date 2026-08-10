//! Boolean SHA-512 compression circuit used as the SHA-384 primitive.

use mpz_circuits_core::{Circuit, CircuitBuilder, Feed, Node};

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

trait BitOps {
    type Bit: Copy;

    fn xor(&mut self, a: Self::Bit, b: Self::Bit) -> Self::Bit;
    fn and(&mut self, a: Self::Bit, b: Self::Bit) -> Self::Bit;
    fn inv(&mut self, a: Self::Bit) -> Self::Bit;
    fn zero(&self) -> Self::Bit;
}

impl BitOps for CircuitBuilder {
    type Bit = Node<Feed>;

    fn xor(&mut self, a: Self::Bit, b: Self::Bit) -> Self::Bit {
        self.add_xor_gate(a, b)
    }
    fn and(&mut self, a: Self::Bit, b: Self::Bit) -> Self::Bit {
        self.add_and_gate(a, b)
    }
    fn inv(&mut self, a: Self::Bit) -> Self::Bit {
        self.add_inv_gate(a)
    }
    fn zero(&self) -> Self::Bit {
        self.get_const_zero()
    }
}

#[derive(Default)]
struct BooleanBitOps;

impl BitOps for BooleanBitOps {
    type Bit = bool;

    fn xor(&mut self, a: bool, b: bool) -> bool {
        a ^ b
    }
    fn and(&mut self, a: bool, b: bool) -> bool {
        a & b
    }
    fn inv(&mut self, a: bool) -> bool {
        !a
    }
    fn zero(&self) -> bool {
        false
    }
}

fn xor3_word<O: BitOps>(
    ops: &mut O,
    a: [O::Bit; 64],
    b: [O::Bit; 64],
    c: [O::Bit; 64],
) -> [O::Bit; 64] {
    std::array::from_fn(|i| {
        let ab = ops.xor(a[i], b[i]);
        ops.xor(ab, c[i])
    })
}

fn rotr_word<B: Copy>(x: [B; 64], n: usize) -> [B; 64] {
    std::array::from_fn(|i| x[(i + n) % 64])
}

fn add_word<O: BitOps>(ops: &mut O, a: [O::Bit; 64], b: [O::Bit; 64]) -> [O::Bit; 64] {
    let mut carry = ops.zero();
    std::array::from_fn(|i| {
        let axb = ops.xor(a[i], b[i]);
        let sum = ops.xor(axb, carry);
        let ab = ops.and(a[i], b[i]);
        let carry_axb = ops.and(carry, axb);
        carry = ops.xor(ab, carry_axb);
        sum
    })
}

fn constant(b: &CircuitBuilder, value: u64) -> [Node<Feed>; 64] {
    std::array::from_fn(|i| {
        if (value >> i) & 1 == 1 {
            b.get_const_one()
        } else {
            b.get_const_zero()
        }
    })
}

fn choice_word<O: BitOps>(
    ops: &mut O,
    e: [O::Bit; 64],
    f: [O::Bit; 64],
    g: [O::Bit; 64],
) -> [O::Bit; 64] {
    std::array::from_fn(|i| {
        let ef = ops.and(e[i], f[i]);
        let not_e = ops.inv(e[i]);
        let eg = ops.and(not_e, g[i]);
        ops.xor(ef, eg)
    })
}

fn majority_word<O: BitOps>(
    ops: &mut O,
    a: [O::Bit; 64],
    b: [O::Bit; 64],
    c: [O::Bit; 64],
) -> [O::Bit; 64] {
    std::array::from_fn(|i| {
        let ab = ops.and(a[i], b[i]);
        let ac = ops.and(a[i], c[i]);
        let bc = ops.and(b[i], c[i]);
        let ab_ac = ops.xor(ab, ac);
        ops.xor(ab_ac, bc)
    })
}

fn big0_word<O: BitOps>(ops: &mut O, x: [O::Bit; 64]) -> [O::Bit; 64] {
    xor3_word(ops, rotr_word(x, 28), rotr_word(x, 34), rotr_word(x, 39))
}

fn big1_word<O: BitOps>(ops: &mut O, x: [O::Bit; 64]) -> [O::Bit; 64] {
    xor3_word(ops, rotr_word(x, 14), rotr_word(x, 18), rotr_word(x, 41))
}

fn small0_word<O: BitOps>(ops: &mut O, x: [O::Bit; 64]) -> [O::Bit; 64] {
    let shr7 = std::array::from_fn(|i| if i + 7 < 64 { x[i + 7] } else { ops.zero() });
    xor3_word(ops, rotr_word(x, 1), rotr_word(x, 8), shr7)
}

fn small1_word<O: BitOps>(ops: &mut O, x: [O::Bit; 64]) -> [O::Bit; 64] {
    let shr6 = std::array::from_fn(|i| if i + 6 < 64 { x[i + 6] } else { ops.zero() });
    xor3_word(ops, rotr_word(x, 19), rotr_word(x, 61), shr6)
}

trait Sha512WordOps {
    type Word: Copy;

    fn constant(&mut self, value: u64) -> Self::Word;
    fn add(&mut self, a: Self::Word, b: Self::Word) -> Self::Word;
    fn choice(&mut self, e: Self::Word, f: Self::Word, g: Self::Word) -> Self::Word;
    fn majority(&mut self, a: Self::Word, b: Self::Word, c: Self::Word) -> Self::Word;
    fn big0(&mut self, x: Self::Word) -> Self::Word;
    fn big1(&mut self, x: Self::Word) -> Self::Word;
    fn small0(&mut self, x: Self::Word) -> Self::Word;
    fn small1(&mut self, x: Self::Word) -> Self::Word;
}

struct CircuitWordOps<'a>(&'a mut CircuitBuilder);

impl Sha512WordOps for CircuitWordOps<'_> {
    type Word = [Node<Feed>; 64];

    fn constant(&mut self, value: u64) -> Self::Word {
        constant(self.0, value)
    }

    fn add(&mut self, a: Self::Word, b: Self::Word) -> Self::Word {
        add_word(self.0, a, b)
    }

    fn choice(&mut self, e: Self::Word, f: Self::Word, g: Self::Word) -> Self::Word {
        choice_word(self.0, e, f, g)
    }

    fn majority(&mut self, a: Self::Word, b: Self::Word, c: Self::Word) -> Self::Word {
        majority_word(self.0, a, b, c)
    }

    fn big0(&mut self, x: Self::Word) -> Self::Word {
        big0_word(self.0, x)
    }

    fn big1(&mut self, x: Self::Word) -> Self::Word {
        big1_word(self.0, x)
    }

    fn small0(&mut self, x: Self::Word) -> Self::Word {
        small0_word(self.0, x)
    }

    fn small1(&mut self, x: Self::Word) -> Self::Word {
        small1_word(self.0, x)
    }
}

#[derive(Default)]
struct NativeWordOps;

impl Sha512WordOps for NativeWordOps {
    type Word = u64;

    fn constant(&mut self, value: u64) -> Self::Word {
        value
    }
    fn add(&mut self, a: u64, b: u64) -> u64 {
        a.wrapping_add(b)
    }
    fn choice(&mut self, e: u64, f: u64, g: u64) -> u64 {
        (e & f) ^ ((!e) & g)
    }
    fn majority(&mut self, a: u64, b: u64, c: u64) -> u64 {
        (a & b) ^ (a & c) ^ (b & c)
    }
    fn big0(&mut self, x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }
    fn big1(&mut self, x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }
    fn small0(&mut self, x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }
    fn small1(&mut self, x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }
}

fn sha512_compress_words<O: Sha512WordOps>(
    ops: &mut O,
    state: [O::Word; 8],
    block: [O::Word; 16],
) -> [O::Word; 8] {
    let mut w = Vec::with_capacity(80);
    w.extend(block);
    for t in 16..80 {
        let s1 = ops.small1(w[t - 2]);
        let x = ops.add(s1, w[t - 7]);
        let s0 = ops.small0(w[t - 15]);
        let y = ops.add(s0, w[t - 16]);
        w.push(ops.add(x, y));
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for t in 0..80 {
        let sigma1 = ops.big1(e);
        let mut t1 = ops.add(h, sigma1);
        let choice = ops.choice(e, f, g);
        t1 = ops.add(t1, choice);
        let round_constant = ops.constant(K[t]);
        t1 = ops.add(t1, round_constant);
        t1 = ops.add(t1, w[t]);
        let sigma0 = ops.big0(a);
        let majority = ops.majority(a, b, c);
        let t2 = ops.add(sigma0, majority);
        h = g;
        g = f;
        f = e;
        e = ops.add(d, t1);
        d = c;
        c = b;
        b = a;
        a = ops.add(t1, t2);
    }

    let working = [a, b, c, d, e, f, g, h];
    std::array::from_fn(|i| ops.add(state[i], working[i]))
}

/// Builds SHA-512 compression, suitable for SHA-384's six-word digest.
pub(crate) fn sha384_compress_circuit() -> Circuit {
    let mut b = CircuitBuilder::new();
    let msg: [[Node<Feed>; 8]; 128] =
        std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let state: [[Node<Feed>; 64]; 8] =
        std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let block = std::array::from_fn(|word| {
        let mut bits = Vec::with_capacity(64);
        for byte in (0..8).rev() {
            bits.extend(msg[word * 8 + byte]);
        }
        bits.try_into().unwrap()
    });
    let output = sha512_compress_words(&mut CircuitWordOps(&mut b), state, block);
    for sum in output {
        for bit in sum {
            b.add_output(bit);
        }
    }
    b.build().unwrap()
}

/// Returns the MPZ-compatible SHA-384 compression circuit for build-time
/// serialization into circuit data.
pub fn sha384_compress_circuit_for_generation() -> Circuit {
    sha384_compress_circuit()
}

#[cfg(kani)]
mod verification {
    use super::{
        add_word, big0_word, big1_word, choice_word, majority_word, sha512_compress_words,
        small0_word, small1_word, BooleanBitOps, NativeWordOps,
    };

    fn bits(value: u64) -> [bool; 64] {
        std::array::from_fn(|i| ((value >> i) & 1) != 0)
    }

    #[kani::proof]
    #[kani::unwind(70)]
    fn boolean_addition_refines_wrapping_u64_for_all_inputs() {
        let x: u64 = kani::any();
        let y: u64 = kani::any();
        assert_eq!(
            add_word(&mut BooleanBitOps, bits(x), bits(y)),
            bits(x.wrapping_add(y))
        );
    }

    #[kani::proof]
    #[kani::unwind(70)]
    fn boolean_choice_and_majority_refine_u64_for_all_inputs() {
        let x: u64 = kani::any();
        let y: u64 = kani::any();
        let z: u64 = kani::any();
        assert_eq!(
            choice_word(&mut BooleanBitOps, bits(x), bits(y), bits(z)),
            bits((x & y) ^ ((!x) & z))
        );
        assert_eq!(
            majority_word(&mut BooleanBitOps, bits(x), bits(y), bits(z)),
            bits((x & y) ^ (x & z) ^ (y & z))
        );
    }

    #[kani::proof]
    #[kani::unwind(70)]
    fn boolean_sigma_functions_refine_sha512_for_all_inputs() {
        let x: u64 = kani::any();
        let xb = bits(x);
        assert_eq!(
            big0_word(&mut BooleanBitOps, xb),
            bits(x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39))
        );
        assert_eq!(
            big1_word(&mut BooleanBitOps, xb),
            bits(x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41))
        );
        assert_eq!(
            small0_word(&mut BooleanBitOps, xb),
            bits(x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7))
        );
        assert_eq!(
            small1_word(&mut BooleanBitOps, xb),
            bits(x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6))
        );
    }

    #[kani::proof]
    #[kani::unwind(90)]
    fn shared_round_wiring_refines_sha2_for_all_blocks_and_states() {
        let block: [u64; 16] = kani::any();
        let state: [u64; 8] = kani::any();
        let actual = sha512_compress_words(&mut NativeWordOps, state, block);

        let bytes: [u8; 128] = std::array::from_fn(|i| block[i / 8].to_be_bytes()[i % 8]);
        let mut expected = state;
        sha2::compress512(&mut expected, &[bytes.into()]);
        assert_eq!(actual, expected);
    }
}

#[cfg(test)]
mod tests {
    use super::{sha384_compress_circuit, sha512_compress_words, NativeWordOps};
    use mpz_circuits_core::evaluate;

    const SHA384_IV: [u64; 8] = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];

    #[test]
    fn sha384_compress_matches_reference() {
        let message = std::array::from_fn(|i| i as u8);
        let circuit = sha384_compress_circuit();
        let output: [u64; 8] = evaluate!(circuit, message, SHA384_IV).unwrap();
        let block = std::array::from_fn(|i| {
            u64::from_be_bytes(message[i * 8..i * 8 + 8].try_into().unwrap())
        });
        let shared_output = sha512_compress_words(&mut NativeWordOps, SHA384_IV, block);
        let mut expected = SHA384_IV;
        sha2::compress512(&mut expected, &[message.into()]);
        assert_eq!(shared_output, expected);
        assert_eq!(output, expected);
    }
}
