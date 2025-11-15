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
pub struct NTorCertificate {
    pub(crate) public_key: PublicKey,
    pub(crate) server_id: String,
}

impl NTorCertificate {
    pub fn new(public_key: Vec<u8>, server_id: String) -> Self {
        let pub_key = TryInto::<[u8; 32]>::try_into(public_key).unwrap();
        NTorCertificate {
            public_key: PublicKey::from(pub_key),
            server_id,
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }
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

    pub fn public_key(&self) -> &[u8; 32] {
        self.client_ephemeral_public_key.as_bytes()
    }
}

// In the paper, the return message is ("ntor", server_ephemeral_public_key, t_b_hash).
pub struct InitSessionResponse {
    pub(crate) server_ephemeral_public_key: PublicKey,
    pub(crate) t_b_hash: Vec<u8>,
}

impl InitSessionResponse {
    pub fn new(public_key: Vec<u8>, t_b_hash: Vec<u8>) -> Self {
        let pub_key = TryInto::<[u8; 32]>::try_into(public_key).unwrap();
        InitSessionResponse {
            server_ephemeral_public_key: PublicKey::from(pub_key),
            t_b_hash,
        }
    }

    pub fn public_key(&self) -> &[u8; 32] {
        self.server_ephemeral_public_key.as_bytes()
    }

    pub fn t_b_hash(&self) -> &[u8] {
        &self.t_b_hash
    }
}

#[derive(bincode::Encode, bincode::Decode)]
pub struct EncryptedMessage {
    pub nonce: [u8; 12],
    pub data: Vec<u8>,
}

pub trait NTorParty {
    fn get_shared_secret(&self) -> Option<&[u8]>;

    fn set_shared_secret(&mut self, shared_secret: Vec<u8>);

    fn encrypt(&self, data: &[u8]) -> Result<EncryptedMessage, &'static str> {
        let Some(key) = self.get_shared_secret() else {
            return Err("no encryption key found");
        };

        let encrypt_key = key_derivation(key)?;
        helpers::encrypt(&encrypt_key, data).map(|(nonce, encrypted_message)| EncryptedMessage {
            nonce,
            data: encrypted_message,
        })
    }

    fn decrypt(&self, encrypted_message: EncryptedMessage) -> Result<Vec<u8>, &'static str> {
        let Some(key) = self.get_shared_secret() else {
            return Err("no decryption key found");
        };

        let decrypt_key = key_derivation(key)?;
        helpers::decrypt(
            &encrypted_message.nonce,
            &decrypt_key,
            &encrypted_message.data,
        )
    }

    fn wasm_encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        let Some(key) = self.get_shared_secret() else {
            return Err("no encryption key found");
        };

        let encrypt_key = key_derivation(key)?;
        helpers::encrypt(&encrypt_key, data)
            .map(|(nonce, encrypted_message)| (nonce.to_vec(), encrypted_message))
    }

    fn wasm_decrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let Some(key) = self.get_shared_secret() else {
            return Err("no decryption key found");
        };

        let decrypt_key = key_derivation(key)?;
        helpers::decrypt(nonce, &decrypt_key, data)
    }
}
