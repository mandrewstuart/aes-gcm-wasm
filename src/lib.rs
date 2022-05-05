use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use std::panic;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn encrypt(plaintext: &str, key: &str, nonce: &str) -> Vec<u8> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
    let key = Key::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce.as_bytes());

    return cipher
        .encrypt(nonce, plaintext.as_bytes().as_ref())
        .expect("encryption failure!");
}

#[wasm_bindgen]
pub fn decrypt(ciphertext: &str, key: &str, nonce: &str) -> String {
    let bytes: Vec<u8> = String::from(ciphertext)
        .split(",")
        .map(|c| c.parse::<u8>().unwrap())
        .collect::<Vec<u8>>();
    let key = Key::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce.as_bytes());

    return String::from_utf8(
        cipher
            .decrypt(nonce, bytes.as_ref())
            .expect("decryption failure!"),
    )
    .unwrap();
}
