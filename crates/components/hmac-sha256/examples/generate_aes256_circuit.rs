use std::fs;

fn main() {
    let output = std::env::args().nth(1).expect("output path");
    let circuit = hmac_sha256::aes256_encrypt_circuit();
    fs::write(
        &output,
        bincode::serialize(&circuit).expect("serialize circuit"),
    )
    .expect("write circuit");

    let data_dir = std::path::Path::new(&output)
        .parent()
        .expect("output has a parent directory");
    let key_schedule = hmac_sha256::aes256_key_schedule_circuit();
    fs::write(
        data_dir.join("aes256_ks.bin"),
        bincode::serialize(&key_schedule).expect("serialize key schedule"),
    )
    .expect("write key schedule");
    let post_key_schedule = hmac_sha256::aes256_post_key_schedule_circuit();
    fs::write(
        data_dir.join("aes256_post_ks.bin"),
        bincode::serialize(&post_key_schedule).expect("serialize post-key-schedule circuit"),
    )
    .expect("write post-key-schedule circuit");
}
