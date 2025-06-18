use x25519_dalek::{PublicKey, StaticSecret};
use rand_core::OsRng;

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

pub fn generate_private_public_key_pair() -> PrivatePublicKeyPair {
    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    PrivatePublicKeyPair {
        private_key: Some(private_key),
        public_key,
    }
}

pub struct Certificate {
    pub(crate) public_key: PublicKey,
    pub(crate) server_id: String,
}

// In the paper, the outgoing message is ("ntor", B_id, client_ephemeral_public_key).
pub struct InitSessionMessage {
    pub(crate) client_ephemeral_public_key: PublicKey,
}

// In the paper, the return message is ("ntor", server_ephemeral_public_key, t_b_hash).
pub struct InitSessionResponse {
    pub(crate) server_ephemeral_public_key: PublicKey,
    pub(crate) t_b_hash: Vec<u8>,
}
