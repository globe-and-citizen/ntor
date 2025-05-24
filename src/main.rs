//Veronica's
//use ring::rand::SystemRandom;
//use ring::signature::{Ed25519KeyPair, KeyPair}; // I'm using ring to generate the keypair

//use std::io::Read;

use sha2::{Sha256, Digest};
//use curve25519_dalek::edwards::{CompressedEdwardsY};
//use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};

// Gemeni's Suggestions
// x25519 is purpose built for Diffie-Hellman key exchange and that's what we're doing so let's go with that.
use x25519_dalek::{PublicKey, StaticSecret};
// use rand::rngs::OsRng;
use rand_core::OsRng;

// House Keeping
type HmacSha256 = Hmac<Sha256>;

/*Ravi's Hack of the nTOR Protocol*/
struct PrivatePublicKeyPair {
    // Oh shit! To make it work, we need to use the StaticSecret type even though it's ephemeral?
    private_key: Option<StaticSecret>,
    public_key: PublicKey,
}

fn generate_private_public_key_pair() -> PrivatePublicKeyPair {
    let private_key = StaticSecret::random_from_rng(&mut OsRng); 
    let public_key = PublicKey::from(&private_key);

    PrivatePublicKeyPair {
        private_key: Some(private_key),
        public_key: public_key,
    }
}

struct Client {
    ephemeral_key_pair: PrivatePublicKeyPair,
    shared_secret: Option<Vec<u8>>,
}

struct Server {
    static_key_pair: PrivatePublicKeyPair,
    ephemeral_key_pair: PrivatePublicKeyPair,
    server_id: String,
    shared_secret: Option<Vec<u8>>,
}

struct Certificate {
    public_key: PublicKey,
    server_id: String, 
}

// In the paper, the outgoing message is ("ntor", B_id, client_ephemeral_public_key).
struct InitSessionMessage {
    client_ephemeral_public_key: PublicKey,
}

// In the paper, the return message is ("ntor", server_ephemeral_public_key, t_b_hash).
struct InitSessionResponse {
    server_ephemeral_public_key: PublicKey,
    t_hash: Vec<u8>
}

impl Client {
    fn new() -> Self {
        let server_ephemeral_key_pair = generate_private_public_key_pair();
        return Self {
            shared_secret: None,
            ephemeral_key_pair: server_ephemeral_key_pair, 
        }
    }

    fn initialise_session(&mut self) -> InitSessionMessage {
        return InitSessionMessage {
            client_ephemeral_public_key: self.ephemeral_key_pair.public_key.clone()  
        }
    }

    // Steps 15 - 20 of the original paper.
    fn handle_response_from_server( 
        &mut self,
        server_certificate: &Certificate,
        msg: &InitSessionResponse,
    ) -> bool {
        // Step 15: Verify that the session state exists
        println!("[Step 15] Client verifies that the session state exists");
    
        // Step 16: Retrieve the server's Certificate, client's ephemeral private key, and client's ephemeral public key. In this case, we are receiving the certificate as an input parameter instead of from state. All we need to do therefore is extract the public key and server ID into local variables. 
        let _server_id = server_certificate.server_id.clone();
        let _server_ephemeral_public_key: PublicKey = server_certificate.public_key.clone();

        // Step 17: Verify that the server's public key is valid. 
        println!("[Step 17] It is unnecessary to verify a public key when using the X25519 curve: all points are valid.");
        
        // Step 18: Compute the shared secret: fuck yeah.
        let mut buffer: Vec<u8> = Vec::new();
        let taken_private_key = self.ephemeral_key_pair.private_key.take().unwrap();
        let mut ecdh_result_1 = taken_private_key.diffie_hellman(&server_certificate.public_key).to_bytes().to_vec();
        let mut ecdh_result_2 = taken_private_key.diffie_hellman(&msg.server_ephemeral_public_key).to_bytes().to_vec();

        let mut hasher = Sha256::new();
        buffer.append(&mut ecdh_result_1);
        buffer.append(&mut ecdh_result_2);
        buffer.append(&mut server_certificate.server_id.as_bytes().to_vec());
        buffer.append(&mut self.ephemeral_key_pair.public_key.as_bytes().to_vec()); 
        buffer.append(&mut msg.server_ephemeral_public_key.as_bytes().to_vec());
        buffer.append(&mut "ntor".as_bytes().to_vec());
        hasher.update(buffer);
        let sha256_hash = hasher.finalize();
        let sha256_hash: &[u8; 32] = match sha256_hash.as_slice().try_into() {
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: sha256_hash was not 32 bytes long: {}", e);
                panic!("Invalid sha256 hash length");
            }
        };

        let secret_key_prime = &sha256_hash[0..16];
        let secret_key = &sha256_hash[16..];

        // Step 19: Compute the HMAC (t_b in the paper) of secret_key_prime, server_id, server_static_public_key, server_ephemeral_public key, "ntor", and "server".
        let mut hmac_data: Vec<u8> = Vec::new();
        hmac_data.append(&mut secret_key_prime.to_vec());
        hmac_data.append(&mut server_certificate.server_id.as_bytes().to_vec());
        hmac_data.append(&mut msg.server_ephemeral_public_key.as_bytes().to_vec());
        hmac_data.append(&mut "ntor".as_bytes().to_vec());
        hmac_data.append(&mut "server".as_bytes().to_vec());
        let hmac_hash = HmacSha256::new_from_slice(&*hmac_data).unwrap(); 
        let computed_t_hash = hmac_hash.finalize().into_bytes().to_vec();

        // assert that computed_t_b_hash equals t_hash generated by server
        if computed_t_hash == msg.t_hash {
            self.shared_secret = Some(secret_key.to_vec());

            println!("R u getting it?! Shared secret:");
            println!("{:?}", secret_key);
            return true;
        } else {
            println!("Failed to verify the shared secret: try again bro.");
            return false;
        }
    }

}

impl Server {
    fn new(server_id: String) -> Self {
        // In the future, this static keypair needs to be handled differently.
        // That is, internally the type for the private key should be x25519_dalek::StaticSecret.
        let static_key_pair = generate_private_public_key_pair();
        return Self{
            static_key_pair,
            server_id,
            shared_secret: None,
            ephemeral_key_pair: generate_private_public_key_pair(),
        }
    }

    fn get_certificate(&self) -> Certificate {
        // Upon implementation and deployment, it's the Service Provider that will create and then upload a certificate to the Layer8 Authentication Server. Likely, Layer8 will also provide the necessary functions to create one for the client. 
        return Certificate{
            public_key: self.static_key_pair.public_key.clone(),
            server_id: self.server_id.clone(),
        }
    }

    fn accept_init_session_request(&mut self, init_msg: &InitSessionMessage) -> InitSessionResponse {
        // Step 9: Normally, it would be necessary to verify that the client's ephemeral public key is valid.
        // However, the X25519 makes it so that all points are valid.
        println!("[Step 9] It is unnecessary to verify the client's public key when using the X25519 curve.");

        // Step 10: Obtain an ephemeral key pair specific to this session and this client. And set the session ID to a hash of the server's ephemeral public key.
        self.ephemeral_key_pair = generate_private_public_key_pair();
        let session_id = HmacSha256::new_from_slice(&self.ephemeral_key_pair.public_key.as_bytes().to_vec()).unwrap();
        let session_id = session_id.finalize().into_bytes().to_vec();
        println!("The Server's Session ID for this connection is: {:?}", session_id);

        // Step 11: Compute the shared secret using 
        // - client_public_ephemeral^server_ephemeral_private (X^y), 
        // - client_public_ephemeral^server_static_private (X^b),
        // - server_id
        // - client_public_ephemeral (X)
        // - server_public_ephemeral (Y)
        // - "ntor"

        let mut hasher = Sha256::new();
        let mut buffer_to_hash: Vec<u8> = Vec::new();
        let taken_private_key = self.ephemeral_key_pair.private_key.take().unwrap();
        let mut ecdh_results_1 = taken_private_key.diffie_hellman(&init_msg.client_ephemeral_public_key).to_bytes().to_vec();
        buffer_to_hash.append(&mut ecdh_results_1);

        let mut ecdh_results_2 = taken_private_key.diffie_hellman(&init_msg.client_ephemeral_public_key).to_bytes().to_vec();
        buffer_to_hash.append(&mut ecdh_results_2);
        buffer_to_hash.append(&mut self.server_id.as_bytes().to_vec());
        buffer_to_hash.append(&mut init_msg.client_ephemeral_public_key.to_bytes().to_vec());
        buffer_to_hash.append(&mut self.ephemeral_key_pair.public_key.to_bytes().to_vec());
        buffer_to_hash.append(&mut "ntor".as_bytes().to_vec());
        hasher.update(buffer_to_hash);
        let sha256_hash = hasher.finalize();
        let sha256_hash: &[u8;32] = match sha256_hash.as_slice().try_into() {
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: sha256_hash was not 32 bytes long: {}", e);
                panic!("Invalid sha256 hash length");
            }
        };

        let secret_key_prime = &sha256_hash[0..16];
        let secret_key = &sha256_hash[16..];

        // Step 12: Compute the HMAC (t_b in the paper) of:
        // -secret_key_prime,
        // -server_id,
        // -server_ephemeral_public_key,
        // -client_ephemeral_public_key
        // -"ntor"
        // -"server"
        
        let mut hasher = Sha256::new();
        let mut buffer_to_hash: Vec<u8> = Vec::new();
        buffer_to_hash.append(&mut secret_key_prime.to_vec());
        buffer_to_hash.append(&mut self.server_id.as_bytes().to_vec());
        buffer_to_hash.append(&mut self.ephemeral_key_pair.public_key.to_bytes().to_vec());
        buffer_to_hash.append(&mut init_msg.client_ephemeral_public_key.to_bytes().to_vec());
        buffer_to_hash.append(&mut "ntor".as_bytes().to_vec());
        buffer_to_hash.append(&mut "server".as_bytes().to_vec());
        hasher.update(buffer_to_hash);
        let sha256_hash = hasher.finalize();
        let sha256_hash: &[u8;32] = match sha256_hash.as_slice().try_into() {
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: sha256_hash was not 32 bytes long: {}", e);
                panic!("Invalid sha256 hash length");
            }
        };
        let output_hash = sha256_hash.to_vec();
        self.shared_secret = Some(secret_key.to_vec());

        println!("Server:");
        println!("Shared secret:");
        println!("{:?}", secret_key);

        InitSessionResponse{
            server_ephemeral_public_key: self.ephemeral_key_pair.public_key.clone(),
            t_hash: output_hash,
        }
    }
}

fn main() {
    // Step 1 is to create a new client.
    let mut client = Client::new();

    // Step 2: Spin up a server
    let server_id = String::from("my server id");
    let mut server   = Server::new(server_id);

    // Step 3: Create a client message to send
    let init_session_msg = client.initialise_session();

    // Step 4: "Send" the message to the server.
    let init_session_response = server.accept_init_session_request(&init_session_msg);

    // Step 5: "Accept" the response from the server.
    client.handle_response_from_server(&server.get_certificate(), &init_session_response);
}


