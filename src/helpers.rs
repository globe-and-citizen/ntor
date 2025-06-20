use std::convert::TryInto;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use log::error;
use x25519_dalek::{PublicKey, StaticSecret};
use crate::common::PrivatePublicKeyPair;

// wasm incompatible imports
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};


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

pub fn key_derivation(shared_secret: &Vec<u8>) -> Vec<u8> {
    let mut encrypt_key = shared_secret.clone(); // fixme use a reliable kdf
    encrypt_key.extend(shared_secret.clone());
    encrypt_key
}

pub(crate) fn encrypt(key_bytes: Vec<u8>, mut data: Vec<u8>) -> Result<([u8; 12], Vec<u8>), &'static str> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes);

    if let Err(err) = key {
        error!("Error encrypt: {:?}", err);
        return Err("encrypt failed")
    }

    let sealing_key = aead::LessSafeKey::new(key.unwrap());

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).unwrap();
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    return match sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut data) {
        Ok(()) => {
            Ok((nonce_bytes, data))
        }
        Err(err) => {
            error!("encrypt failed {:?}", err);
            Err("encrypt failed")
        }
    }
}

pub(crate) fn decrypt(nonce_bytes: [u8; 12], key_bytes: Vec<u8>, mut data: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap();
    let opening_key = aead::LessSafeKey::new(key);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let decrypted_data = opening_key.open_in_place(nonce, aead::Aad::empty(), &mut data).unwrap();

    // debug!("Decrypted: {:?}", String::from_utf8_lossy(decrypted_data));
    Ok(decrypted_data.to_vec())
}

pub(crate) fn wasm_encrypt(key_bytes: Vec<u8>, data: Vec<u8>) -> Result<([u8; 12], Vec<u8>), &'static str> {
    if key_bytes.len() != 32 {
        return Err("Invalid key length for AES-256");
    }

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| "Random generation failed")?;
    let nonce = Nonce::from_slice(&nonce_bytes); // 96-bits; unique per message

    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|_| "Encryption failed")?;

    Ok((nonce_bytes, ciphertext))
}

pub(crate) fn wasm_decrypt(nonce_bytes: [u8; 12], key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    return match TryInto::<[u8; 32]>::try_into(key) {
        Ok(key_bytes) => {
            let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let decrypted_data = cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|_| "Decryption failed")?;

            Ok(decrypted_data)
        }
        Err(_) => {
            Err("Invalid key")
        }
    }
}

