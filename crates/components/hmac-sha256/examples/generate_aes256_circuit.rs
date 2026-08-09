use std::fs;

fn main() {
    let output = std::env::args().nth(1).expect("output path");
    let circuit = hmac_sha256::aes256_encrypt_circuit();
    fs::write(output, bincode::serialize(&circuit).expect("serialize circuit")).expect("write circuit");
}
