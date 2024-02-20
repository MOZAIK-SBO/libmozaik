use libmozaik_iot;

use clap::Parser;

#[derive(Parser)]
struct EncryptInputs {
    #[arg(long, value_name = "KEY")]
    key: String,
    #[arg(long, value_name = "NONCE")]
    nonce: String,
    #[arg(long, value_name = "USER-ID")]
    user_id: String,
    #[arg(long, value_name = "MESSAGE")]
    message: String,
}

fn main() {
    let encrypt_inputs = EncryptInputs::parse();
    let key = hex::decode(encrypt_inputs.key).expect("Cannot parse key as hex-encoded bytes.");
    if key.len() != 16 {
        panic!("Expected 16-byte as key");
    }
    let nonce = hex::decode(encrypt_inputs.nonce).expect("Cannot parse nonce as hex-encoded bytes.");
    if nonce.len() != 12 {
        panic!("Expected 12-byte as nonce");
    }
    let message = hex::decode(encrypt_inputs.message).expect("Cannot parse message as hex-encoded bytes.");

    let mut start_nonce = [0u8; 12];
    start_nonce.copy_from_slice(&nonce);
    let mut fresh_key = [0u8; 16];
    fresh_key.copy_from_slice(&key);
    let mut state = libmozaik_iot::DeviceState::new(start_nonce, fresh_key);
    let ciphertext = libmozaik_iot::protect(&encrypt_inputs.user_id, &mut state, libmozaik_iot::ProtectionAlgorithm::AesGcm128, &message).unwrap();

    println!("{}", hex::encode(&ciphertext));
}