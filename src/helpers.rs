use crate::common::PrivatePublicKeyPair;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use std::convert::TryInto;
use x25519_dalek::{PublicKey, StaticSecret};

/// Returns an array of zeros if conversion fails.
pub fn vec_to_array32(vec: Vec<u8>) -> [u8; 32] {
    if vec.len() == 32 {
        vec.try_into().unwrap()
    } else {
        [0u8; 32]
    }
}

pub fn generate_private_public_key_pair() -> PrivatePublicKeyPair {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("generate random failed");
    let private_key = StaticSecret::from(buf);
    let public_key = PublicKey::from(&private_key);

    PrivatePublicKeyPair {
        private_key: Some(private_key),
        public_key,
    }
}

pub fn key_derivation(shared_secret: &[u8]) -> Result<[u8; 32], &'static str> {
    let mut encrypt_key = shared_secret.to_vec(); // fixme use a reliable kdf
    encrypt_key.extend(shared_secret.to_vec());
    TryInto::<[u8; 32]>::try_into(encrypt_key).map_err(|_| "Invalid key length")
}

pub(crate) fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<([u8; 12], Vec<u8>), &'static str> {
    let key = Key::<Aes256Gcm>::from_slice(&key[..]);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| "Random generation failed")?;
    let nonce = Nonce::from_slice(&nonce_bytes); // 96-bits; unique per message

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| "Encryption failed")?;

    Ok((nonce_bytes, ciphertext))
}

pub(crate) fn decrypt(
    nonce_bytes: &[u8; 12],
    key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted_data = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed")?;

    Ok(decrypted_data)
}
