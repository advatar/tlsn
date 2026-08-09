//! Boolean SHA-512 compression circuit used as the SHA-384 primitive.

use mpz_circuits_core::{ops, Circuit, CircuitBuilder, Feed, Node};

const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

fn xor3(b: &mut CircuitBuilder, a: [Node<Feed>; 64], c: [Node<Feed>; 64], d: [Node<Feed>; 64]) -> [Node<Feed>; 64] {
    std::array::from_fn(|i| {
        let ac = b.add_xor_gate(a[i], c[i]);
        b.add_xor_gate(ac, d[i])
    })
}

fn rotr(x: [Node<Feed>; 64], n: usize) -> [Node<Feed>; 64] {
    std::array::from_fn(|i| x[(i + n) % 64])
}

fn add(b: &mut CircuitBuilder, a: [Node<Feed>; 64], c: [Node<Feed>; 64]) -> [Node<Feed>; 64] {
    ops::wrapping_add(b, &a, &c).try_into().unwrap()
}

fn constant(b: &CircuitBuilder, value: u64) -> [Node<Feed>; 64] {
    std::array::from_fn(|i| if (value >> i) & 1 == 1 { b.get_const_one() } else { b.get_const_zero() })
}

fn ch(b: &mut CircuitBuilder, e: [Node<Feed>; 64], f: [Node<Feed>; 64], g: [Node<Feed>; 64]) -> [Node<Feed>; 64] {
    std::array::from_fn(|i| {
        let ef = b.add_and_gate(e[i], f[i]);
        let not_e = b.add_inv_gate(e[i]);
        let eg = b.add_and_gate(not_e, g[i]);
        b.add_xor_gate(ef, eg)
    })
}

fn maj(b: &mut CircuitBuilder, a: [Node<Feed>; 64], c: [Node<Feed>; 64], d: [Node<Feed>; 64]) -> [Node<Feed>; 64] {
    std::array::from_fn(|i| {
        let ab = b.add_and_gate(a[i], c[i]);
        let ad = b.add_and_gate(a[i], d[i]);
        let cd = b.add_and_gate(c[i], d[i]);
        let ab_ad = b.add_xor_gate(ab, ad);
        b.add_xor_gate(ab_ad, cd)
    })
}

fn big0(b: &mut CircuitBuilder, x: [Node<Feed>; 64]) -> [Node<Feed>; 64] {
    xor3(b, rotr(x, 28), rotr(x, 34), rotr(x, 39))
}

fn big1(b: &mut CircuitBuilder, x: [Node<Feed>; 64]) -> [Node<Feed>; 64] {
    xor3(b, rotr(x, 14), rotr(x, 18), rotr(x, 41))
}

fn small0(b: &mut CircuitBuilder, x: [Node<Feed>; 64]) -> [Node<Feed>; 64] {
    let shr7 = std::array::from_fn(|i| if i + 7 < 64 { x[i + 7] } else { b.get_const_zero() });
    xor3(b, rotr(x, 1), rotr(x, 8), shr7)
}

fn small1(b: &mut CircuitBuilder, x: [Node<Feed>; 64]) -> [Node<Feed>; 64] {
    let shr6 = std::array::from_fn(|i| if i + 6 < 64 { x[i + 6] } else { b.get_const_zero() });
    xor3(b, rotr(x, 19), rotr(x, 61), shr6)
}

/// Builds SHA-512 compression, suitable for SHA-384's six-word digest.
pub(crate) fn sha384_compress_circuit() -> Circuit {
    let mut b = CircuitBuilder::new();
    let msg: [[Node<Feed>; 8]; 128] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let state: [[Node<Feed>; 64]; 8] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let mut w = Vec::with_capacity(80);
    for word in 0..16 {
        let mut bits = Vec::with_capacity(64);
        for byte in (0..8).rev() {
            bits.extend(msg[word * 8 + byte]);
        }
        w.push(bits.try_into().unwrap());
    }
    for t in 16..80 {
        let s1 = small1(&mut b, w[t - 2]);
        let x = add(&mut b, s1, w[t - 7]);
        let s0 = small0(&mut b, w[t - 15]);
        let y = add(&mut b, s0, w[t - 16]);
        w.push(add(&mut b, x, y));
    }
    let mut a = state[0]; let mut bb = state[1]; let mut c = state[2]; let mut d = state[3];
    let mut e = state[4]; let mut f = state[5]; let mut g = state[6]; let mut h = state[7];
    for t in 0..80 {
        let b1 = big1(&mut b, e);
        let mut t1 = add(&mut b, h, b1);
        let choice = ch(&mut b, e, f, g);
        t1 = add(&mut b, t1, choice);
        let k = constant(&b, K[t]);
        t1 = add(&mut b, t1, k);
        t1 = add(&mut b, t1, w[t]);
        let b0 = big0(&mut b, a);
        let majority = maj(&mut b, a, bb, c);
        let t2 = add(&mut b, b0, majority);
        h = g; g = f; f = e; e = add(&mut b, d, t1); d = c; c = bb; bb = a; a = add(&mut b, t1, t2);
    }
    for (old, new) in state.into_iter().zip([a, bb, c, d, e, f, g, h]) {
        let sum = add(&mut b, old, new);
        for bit in sum { b.add_output(bit); }
    }
    b.build().unwrap()
}

/// Returns the MPZ-compatible SHA-384 compression circuit for build-time
/// serialization into circuit data.
pub fn sha384_compress_circuit_for_generation() -> Circuit {
    sha384_compress_circuit()
}

#[cfg(test)]
mod tests {
    use super::sha384_compress_circuit;
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
        let mut expected = SHA384_IV;
        sha2::compress512(&mut expected, &[message.into()]);
        assert_eq!(output, expected);
    }
}
