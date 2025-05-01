mod test;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

struct PrivatePublicKeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

fn generate_private_public_key_pair() -> PrivatePublicKeyPair {
    let random = SystemRandom::new();

    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref()).unwrap();

    PrivatePublicKeyPair{
        private_key: pkcs8_doc.as_ref().to_vec(),
        public_key: key_pair.public_key().as_ref().to_vec(),
    }
}

fn main() {
    let PrivatePublicKeyPair{ private_key, public_key} =
        generate_private_public_key_pair();

    println!("Private key: {:?}", private_key);
    println!("Public key: {:?}", public_key);
}
