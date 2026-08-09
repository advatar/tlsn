//! Boolean AES-256 encryption circuit for MPZ.

use std::sync::{Arc, LazyLock};
use mpz_circuits_core::{Circuit, CircuitBuilder, Feed, Node};

/// Serialized MPZ AES-256 encryption circuit used by downstream MPC code.
pub static AES256_ENCRYPT: LazyLock<Arc<Circuit>> = LazyLock::new(|| {
    Arc::new(bincode::deserialize(include_bytes!("../../data/aes256.bin"))
        .expect("embedded AES-256 circuit data must be valid"))
});

const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

type Byte = [Node<Feed>; 8];

fn xor(b: &mut CircuitBuilder, x: Byte, y: Byte) -> Byte {
    std::array::from_fn(|i| b.add_xor_gate(x[i], y[i]))
}

fn sbox(b: &mut CircuitBuilder, x: Byte) -> Byte {
    // Generate the algebraic normal form of each output bit from the table.
    std::array::from_fn(|out| {
        let mut coeff = [false; 256];
        for (i, v) in SBOX.iter().enumerate() { coeff[i] = ((v >> out) & 1) != 0; }
        for bit in 0..8 { for mask in 0..256 { if (mask & (1 << bit)) != 0 { coeff[mask] ^= coeff[mask ^ (1 << bit)]; } } }
        let mut result = b.get_const_zero();
        for mask in 0..256 { if coeff[mask] { let mut term = b.get_const_one(); for bit in 0..8 { if (mask & (1 << bit)) != 0 { term = b.add_and_gate(term, x[bit]); } } result = b.add_xor_gate(result, term); } }
        result
    })
}

fn xtime(b: &mut CircuitBuilder, x: Byte) -> Byte {
    let z = b.get_const_zero();
    let mut out = [z; 8];
    out[0] = z;
    for i in 1..8 { out[i] = x[i - 1]; }
    for i in [0, 1, 3, 4] { out[i] = b.add_xor_gate(out[i], x[7]); }
    out
}

fn mix_column(b: &mut CircuitBuilder, c: [Byte; 4]) -> [Byte; 4] {
    let x2 = c.map(|x| xtime(b, x));
    let x3: [Byte; 4] = std::array::from_fn(|i| xor(b, x2[i], c[i]));
    let a0 = xor(b, x2[0], x3[1]); let b0 = xor(b, c[2], c[3]);
    let a1 = xor(b, c[0], x2[1]); let b1 = xor(b, x3[2], c[3]);
    let a2 = xor(b, c[0], c[1]); let b2 = xor(b, x2[2], x3[3]);
    let a3 = xor(b, x3[0], c[1]); let b3 = xor(b, c[2], x2[3]);
    [xor(b, a0, b0), xor(b, a1, b1), xor(b, a2, b2), xor(b, a3, b3)]
}

/// Builds `fn(key: [u8; 32], iv: [u8; 4], nonce: [u8; 8], counter: [u8; 4], block: [u8; 16]) -> [u8; 16]`.
pub fn aes256_encrypt_circuit() -> Circuit {
    let mut b = CircuitBuilder::new();
    let key: [Byte; 32] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let _iv: [Byte; 4] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let _nonce: [Byte; 8] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let _counter: [Byte; 4] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let input: [Byte; 16] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let mut words: Vec<[Byte; 4]> = (0..8).map(|i| [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]).collect();
    let mut rc = 1u8;
    for i in 8..60 {
        let mut t = words[i-1];
        if i % 8 == 0 { t = [sbox(&mut b, t[1]), sbox(&mut b, t[2]), sbox(&mut b, t[3]), sbox(&mut b, t[0])]; let mut constant = [b.get_const_zero(); 8]; for j in 0..8 { if (rc >> j) & 1 == 1 { constant[j] = b.get_const_one(); } } t[0] = xor(&mut b, t[0], constant); rc = xtime_byte(rc); }
        else if i % 8 == 4 { t = t.map(|x| sbox(&mut b, x)); }
        words.push(std::array::from_fn(|j| xor(&mut b, words[i-8][j], t[j])));
    }
    let mut state = input;
    for i in 0..16 { state[i] = xor(&mut b, state[i], words[i/4][i%4]); }
    for round in 1..14 { state = state.map(|x| sbox(&mut b, x)); state = shift_rows(state); for col in 0..4 { let mixed = mix_column(&mut b, state[4*col..4*col+4].try_into().unwrap()); state[4*col..4*col+4].clone_from_slice(&mixed); } for i in 0..16 { state[i] = xor(&mut b, state[i], words[4*round+i/4][i%4]); } }
    state = state.map(|x| sbox(&mut b, x)); state = shift_rows(state); for i in 0..16 { state[i] = xor(&mut b, state[i], words[56+i/4][i%4]); }
    for byte in state { for bit in byte { b.add_output(bit); } }
    b.build().unwrap()
}

fn shift_rows(mut s: [Byte; 16]) -> [Byte; 16] { for r in 0..4 { let row = [s[r],s[4+r],s[8+r],s[12+r]]; for c in 0..4 { s[4*c+r] = row[(c+r)%4]; } } s }
fn xtime_byte(x: u8) -> u8 { let y=x<<1; if x&0x80 != 0 { y^0x1b } else { y } }

#[cfg(test)]
mod tests {
    use super::{aes256_encrypt_circuit, AES256_ENCRYPT};
    use aes::cipher::{BlockEncrypt, KeyInit};
    use mpz_circuits_core::evaluate;

    #[test]
    fn aes256_circuit_matches_nist_vector() {
        let key = [
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4,
        ];
        let block = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a];
        let iv = [0u8; 4];
        let nonce = [0u8; 8];
        let counter = [0u8, 0, 0, 1];
        let output: [u8; 16] = evaluate!(aes256_encrypt_circuit(), key, iv, nonce, counter, block).unwrap();
        let cipher = aes::Aes256::new_from_slice(&key).unwrap();
        let mut expected = block.into();
        cipher.encrypt_block(&mut expected);
        let expected: [u8; 16] = expected.into();
        assert_eq!(output, expected);

        let embedded: [u8; 16] = evaluate!(AES256_ENCRYPT, key, iv, nonce, counter, block).unwrap();
        assert_eq!(embedded, expected);
    }
}
