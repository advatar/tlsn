//! Boolean AES-256 encryption circuit for MPZ.

use mpz_circuits_core::{Circuit, CircuitBuilder, Feed, Node};
use std::sync::{Arc, LazyLock};

/// Serialized MPZ AES-256 encryption circuit used by downstream MPC code.
pub static AES256_ENCRYPT: LazyLock<Arc<Circuit>> = LazyLock::new(|| {
    Arc::new(
        bincode::deserialize(include_bytes!("../../data/aes256.bin"))
            .expect("embedded AES-256 circuit data must be valid"),
    )
});

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

type Byte = [Node<Feed>; 8];

fn xor(b: &mut CircuitBuilder, x: Byte, y: Byte) -> Byte {
    std::array::from_fn(|i| b.add_xor_gate(x[i], y[i]))
}

fn sbox_boyar(b: &mut CircuitBuilder, x: Byte) -> Byte {
    // Boyar--Peralta AES S-box circuit (113 gates), with the bit order
    // adapted from the bitsliced AES implementation in RustCrypto.
    macro_rules! q {
        ($a:expr, $c:expr) => {
            b.add_xor_gate($a, $c)
        };
    }
    macro_rules! m {
        ($a:expr, $c:expr) => {
            b.add_and_gate($a, $c)
        };
    }
    let (u7, u6, u5, u4, u3, u2, u1, u0) = (x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]);
    let y14 = q!(u3, u5);
    let y13 = q!(u0, u6);
    let y12 = q!(y13, y14);
    let t1 = q!(u4, y12);
    let y15 = q!(t1, u5);
    let t2 = m!(y12, y15);
    let y6 = q!(y15, u7);
    let y20 = q!(t1, u1);
    let y9 = q!(u0, u3);
    let y11 = q!(y20, y9);
    let t12 = m!(y9, y11);
    let y7 = q!(u7, y11);
    let y8 = q!(u0, u5);
    let t0 = q!(u1, u2);
    let y10 = q!(y15, t0);
    let y17 = q!(y10, y11);
    let t13 = m!(y14, y17);
    let t14 = q!(t13, t12);
    let y19 = q!(y10, y8);
    let t15 = m!(y8, y10);
    let t16 = q!(t15, t12);
    let y16 = q!(t0, y11);
    let y21 = q!(y13, y16);
    let t7 = m!(y13, y16);
    let y18 = q!(u0, y16);
    let y1 = q!(t0, u7);
    let y4 = q!(y1, u3);
    let t5 = m!(y4, u7);
    let t6 = q!(t5, t2);
    let t18 = q!(t6, t16);
    let t22 = q!(t18, y19);
    let y2 = q!(y1, u0);
    let t10 = m!(y2, y7);
    let t11 = q!(t10, t7);
    let t20 = q!(t11, t16);
    let t24 = q!(t20, y18);
    let y5 = q!(y1, u6);
    let t8 = m!(y5, y1);
    let t9 = q!(t8, t7);
    let t19 = q!(t9, t14);
    let t23 = q!(t19, y21);
    let y3 = q!(y5, y8);
    let t3 = m!(y3, y6);
    let t4 = q!(t3, t2);
    let t17 = q!(t4, y20);
    let t21 = q!(t17, t14);
    let t26 = m!(t21, t23);
    let t27 = q!(t24, t26);
    let t31 = q!(t22, t26);
    let t25 = q!(t21, t22);
    let t28 = m!(t25, t27);
    let t29 = q!(t28, t22);
    let z14 = m!(t29, y2);
    let z5 = m!(t29, y7);
    let t30 = q!(t23, t24);
    let t32 = m!(t31, t30);
    let t33 = q!(t32, t24);
    let t35 = q!(t27, t33);
    let t36 = m!(t24, t35);
    let t38 = q!(t27, t36);
    let t39 = m!(t29, t38);
    let t40 = q!(t25, t39);
    let t43 = q!(t29, t40);
    let z3 = m!(t43, y16);
    let tc12 = q!(z3, z5);
    let z12 = m!(t43, y13);
    let z13 = m!(t40, y5);
    let z4 = m!(t40, y1);
    let tc6 = q!(z3, z4);
    let t34 = q!(t23, t33);
    let t37 = q!(t36, t34);
    let t41 = q!(t40, t37);
    let z8 = m!(t41, y10);
    let z17 = m!(t41, y8);
    let t44 = q!(t33, t37);
    let z0 = m!(t44, y15);
    let z9 = m!(t44, y12);
    let z10 = m!(t37, y3);
    let z1 = m!(t37, y6);
    let tc5 = q!(z1, z0);
    let tc11 = q!(tc6, tc5);
    let z11 = m!(t33, y4);
    let t42 = q!(t29, t33);
    let t45 = q!(t42, t41);
    let z7 = m!(t45, y17);
    let tc8 = q!(z7, tc6);
    let z16 = m!(t45, y14);
    let z6 = m!(t42, y11);
    let tc16 = q!(z6, tc8);
    let z15 = m!(t42, y9);
    let tc20 = q!(z15, tc16);
    let tc1 = q!(z15, z16);
    let tc2 = q!(z10, tc1);
    let tc21 = q!(tc2, z11);
    let tc3 = q!(z9, tc2);
    let s0 = q!(tc3, tc16);
    let s3 = q!(tc3, tc11);
    let s1 = q!(s3, tc16);
    let tc13 = q!(z13, tc1);
    let z2 = m!(t33, u7);
    let tc4 = q!(z0, z2);
    let tc7 = q!(z12, tc4);
    let tc9 = q!(z8, tc7);
    let tc10 = q!(tc8, tc9);
    let tc17 = q!(z14, tc10);
    let s5 = q!(tc21, tc17);
    let tc26 = q!(tc17, tc20);
    let s2 = q!(tc26, z17);
    let tc14 = q!(tc4, tc12);
    let tc18 = q!(tc13, tc14);
    let s6 = q!(tc10, tc18);
    let s7 = q!(z12, tc18);
    let s4 = q!(tc14, s3);
    let mut out = [s7, s6, s5, s4, s3, s2, s1, s0];
    for i in [0, 1, 5, 6] {
        out[i] = b.add_inv_gate(out[i]);
    }
    out
}

fn gf_mul(b: &mut CircuitBuilder, a: Byte, c: Byte) -> Byte {
    let z = b.get_const_zero();
    let mut result = [z; 8];
    let mut value = a;
    for bit in 0..8 {
        let masked = value.map(|v| b.add_and_gate(v, c[bit]));
        result = result.map(|r| r);
        for i in 0..8 { result[i] = b.add_xor_gate(result[i], masked[i]); }
        value = xtime(b, value);
    }
    result
}

fn sbox(b: &mut CircuitBuilder, x: Byte) -> Byte {
    // Multiplicative inverse in GF(2^8), followed by the AES affine map.
    let one = std::array::from_fn(|i| if i == 0 { b.get_const_one() } else { b.get_const_zero() });
    let mut result = one;
    let mut base = x;
    // x^254, exponent bits are 0b11111110 (LSB first).
    for bit in 0..8 {
        if bit != 0 { result = gf_mul(b, result, base); }
        base = gf_mul(b, base, base);
    }
    let mut out = result;
    for shift in 1..5 {
        let rotated: Byte = std::array::from_fn(|i| result[(i + 8 - shift) % 8]);
        for i in 0..8 { out[i] = b.add_xor_gate(out[i], rotated[i]); }
    }
    for (i, bit) in [1u8,1,0,0,0,1,1,0].into_iter().enumerate() {
        if bit == 1 { out[i] = b.add_xor_gate(out[i], b.get_const_one()); }
    }
    out
}

fn xtime(b: &mut CircuitBuilder, x: Byte) -> Byte {
    let z = b.get_const_zero();
    let mut out = [z; 8];
    out[0] = z;
    for i in 1..8 {
        out[i] = x[i - 1];
    }
    for i in [0, 1, 3, 4] {
        out[i] = b.add_xor_gate(out[i], x[7]);
    }
    out
}

fn mix_column(b: &mut CircuitBuilder, c: [Byte; 4]) -> [Byte; 4] {
    let x2 = c.map(|x| xtime(b, x));
    let x3: [Byte; 4] = std::array::from_fn(|i| xor(b, x2[i], c[i]));
    let a0 = xor(b, x2[0], x3[1]);
    let b0 = xor(b, c[2], c[3]);
    let a1 = xor(b, c[0], x2[1]);
    let b1 = xor(b, x3[2], c[3]);
    let a2 = xor(b, c[0], c[1]);
    let b2 = xor(b, x2[2], x3[3]);
    let a3 = xor(b, x3[0], c[1]);
    let b3 = xor(b, c[2], x2[3]);
    [
        xor(b, a0, b0),
        xor(b, a1, b1),
        xor(b, a2, b2),
        xor(b, a3, b3),
    ]
}

/// Builds `fn(key: [u8; 32], iv: [u8; 4], nonce: [u8; 8], counter: [u8; 4], block: [u8; 16]) -> [u8; 16]`.
pub fn aes256_encrypt_circuit() -> Circuit {
    let mut b = CircuitBuilder::new();
    let key: [Byte; 32] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let _iv: [Byte; 4] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let _nonce: [Byte; 8] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let _counter: [Byte; 4] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let input: [Byte; 16] = std::array::from_fn(|_| std::array::from_fn(|_| b.add_input()));
    let mut words: Vec<[Byte; 4]> = (0..8)
        .map(|i| [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
        .collect();
    let mut rc = 1u8;
    for i in 8..60 {
        let mut t = words[i - 1];
        if i % 8 == 0 {
            t = [
                sbox(&mut b, t[1]),
                sbox(&mut b, t[2]),
                sbox(&mut b, t[3]),
                sbox(&mut b, t[0]),
            ];
            let mut constant = [b.get_const_zero(); 8];
            for j in 0..8 {
                if (rc >> j) & 1 == 1 {
                    constant[j] = b.get_const_one();
                }
            }
            t[0] = xor(&mut b, t[0], constant);
            rc = xtime_byte(rc);
        } else if i % 8 == 4 {
            t = t.map(|x| sbox(&mut b, x));
        }
        words.push(std::array::from_fn(|j| xor(&mut b, words[i - 8][j], t[j])));
    }
    let mut state = input;
    for i in 0..16 {
        state[i] = xor(&mut b, state[i], words[i / 4][i % 4]);
    }
    for round in 1..14 {
        state = state.map(|x| sbox(&mut b, x));
        state = shift_rows(state);
        for col in 0..4 {
            let mixed = mix_column(&mut b, state[4 * col..4 * col + 4].try_into().unwrap());
            state[4 * col..4 * col + 4].clone_from_slice(&mixed);
        }
        for i in 0..16 {
            state[i] = xor(&mut b, state[i], words[4 * round + i / 4][i % 4]);
        }
    }
    state = state.map(|x| sbox(&mut b, x));
    state = shift_rows(state);
    for i in 0..16 {
        state[i] = xor(&mut b, state[i], words[56 + i / 4][i % 4]);
    }
    for byte in state {
        for bit in byte {
            b.add_output(bit);
        }
    }
    b.build().unwrap()
}

fn shift_rows(mut s: [Byte; 16]) -> [Byte; 16] {
    for r in 0..4 {
        let row = [s[r], s[4 + r], s[8 + r], s[12 + r]];
        for c in 0..4 {
            s[4 * c + r] = row[(c + r) % 4];
        }
    }
    s
}
fn xtime_byte(x: u8) -> u8 {
    let y = x << 1;
    if x & 0x80 != 0 {
        y ^ 0x1b
    } else {
        y
    }
}

#[cfg(test)]
mod tests {
    use super::{aes256_encrypt_circuit, sbox, AES256_ENCRYPT, SBOX};
    use aes::cipher::{BlockEncrypt, KeyInit};
    use mpz_circuits_core::evaluate;

    #[test]
    fn aes256_circuit_matches_nist_vector() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let block = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let iv = [0u8; 4];
        let nonce = [0u8; 8];
        let counter = [0u8, 0, 0, 1];
        let output: [u8; 16] =
            evaluate!(aes256_encrypt_circuit(), key, iv, nonce, counter, block).unwrap();
        let cipher = aes::Aes256::new_from_slice(&key).unwrap();
        let mut expected = block.into();
        cipher.encrypt_block(&mut expected);
        let expected: [u8; 16] = expected.into();
        assert_eq!(output, expected);

        let embedded: [u8; 16] = evaluate!(AES256_ENCRYPT, key, iv, nonce, counter, block).unwrap();
        assert_eq!(embedded, expected);
    }

    #[test]
    fn sbox_matches_table() {
        let mut b = mpz_circuits_core::CircuitBuilder::new();
        let x = std::array::from_fn(|_| b.add_input());
        let y = sbox(&mut b, x);
        for bit in y {
            b.add_output(bit);
        }
        let c = b.build().unwrap();
        for value in 0u16..=255 {
            let input = [value as u8];
            let actual: [u8; 1] = evaluate!(&c, input).unwrap();
            assert_eq!(actual[0], SBOX[value as usize], "sbox {:02x}", value);
        }
    }
}
