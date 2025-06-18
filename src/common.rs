use x25519_dalek::{PublicKey, StaticSecret};
use crate::helpers;
use crate::helpers::{key_derivation, vec_to_array32};

#[derive(Clone)]
pub struct PrivatePublicKeyPair {
    // In the future, type StaticSecret should be reserved for the server's static and the EphemeralSecret reserved for the ephemeral private key.
    // However, as a quirk of the nTOR protocol, we also need to use StaticSecret for the client's ephemeral private key hence why it is adopted here.
    pub(crate) private_key: Option<StaticSecret>,
    pub(crate) public_key: PublicKey,
}

impl PrivatePublicKeyPair {
    pub fn get_public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn get_private_key(&self) -> Option<StaticSecret> {
        self.private_key.clone()
    }
}

#[derive(Clone)]
pub struct Certificate {
    pub(crate) public_key: PublicKey,
    pub(crate) server_id: String,
}

// In the paper, the outgoing message is ("ntor", B_id, client_ephemeral_public_key).
pub struct InitSessionMessage {
    pub(crate) client_ephemeral_public_key: PublicKey,
}

impl InitSessionMessage {
    pub fn from(bytes: Vec<u8>) -> Self {
        let u8_array = vec_to_array32(bytes);
        InitSessionMessage {
            client_ephemeral_public_key: PublicKey::from(u8_array),
        }
    }
}

// In the paper, the return message is ("ntor", server_ephemeral_public_key, t_b_hash).
pub struct InitSessionResponse {
    pub(crate) server_ephemeral_public_key: PublicKey,
    pub(crate) t_b_hash: Vec<u8>,
}

pub struct EncryptedMessage {
    pub nonce: [u8; 12],
    pub data: Vec<u8>
}

pub trait NTorParty {
    fn get_shared_secret(&self) -> Option<Vec<u8>>;

    fn encrypt(&self, data: Vec<u8>) -> Result<EncryptedMessage, &'static str> {
        if let Some(key) = self.get_shared_secret() {
            let encrypt_key = key_derivation(&key);
            return match helpers::encrypt(encrypt_key, data) {
                Ok((nonce, encrypted_message)) => {
                    Ok(EncryptedMessage {
                        nonce,
                        data: encrypted_message,
                    })
                }
                Err(err) => Err(err)
            }
        }
        Err("no encryption key found")
    }

    fn decrypt(&self, encrypted_message: EncryptedMessage) -> Result<Vec<u8>, &'static str> {
        if let Some(key) = self.get_shared_secret() {
            let decrypt_key = key_derivation(&key);
            return helpers::decrypt(encrypted_message.nonce, decrypt_key, encrypted_message.data);
        }
        Err("no decryption key found")
    }
}