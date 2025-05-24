use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use x25519_dalek::{PublicKey, StaticSecret};
use rand_core::OsRng;

/*Ravi's Hack of the nTOR Protocol*/
struct PrivatePublicKeyPair {
    // In the future, type StaticSecret should be reserved for the server's static and the EphemeralSecret reserved for the ephemeral private key. 
    // However, as a quirk of the nTOR protocol, we also need to use StaticSecret for the client's ephemeral private key hence why it is adopted here.  
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

    // Steps 15 - 20 of the Goldberg 2012 paper.
    fn handle_response_from_server( 
        &mut self,
        server_certificate: &Certificate,
        msg: &InitSessionResponse,
    ) -> bool {
        // Step 15: Verify that the session state exists
        // Step 16: Retrieve the server's Certificate, client's ephemeral private key, and client's ephemeral public key. In this case, we are receiving the certificate as an input parameter instead of from state. All we need to do therefore is extract the public key and server ID into local variables.

        let server_id = server_certificate.server_id.clone();
        let server_static_public_key: PublicKey = server_certificate.public_key.clone();
        println!("server_id: {}", server_id);
        println!("server_static_public_key: {:?}", server_static_public_key);

        // Step 17: Verify that the server's public key is valid. 

        // Step 18: Compute the shared secret: fuck yeah.
        println!("[Step 18] Compute the shared secret.");
        let mut buffer: Vec<u8> = Vec::new();

        // ECDH Client private ephemeral * server static public key 
        let taken_private_key = self.ephemeral_key_pair.private_key.take().unwrap();
        let mut ecdh_result_1 = taken_private_key.diffie_hellman(&msg.server_ephemeral_public_key).to_bytes().to_vec();
        buffer.append(&mut ecdh_result_1);
        println!("[Debug] ECDH result 1: {:?}", ecdh_result_1);

        // ECDH Client private ephemeral * server ephemeral public Key
        let mut ecdh_result_2 = taken_private_key.diffie_hellman(&server_certificate.public_key).to_bytes().to_vec();
        buffer.append(&mut ecdh_result_2);
        println!("[Debug] ECDH result 2: {:?}", ecdh_result_2);

        // Server ID
        buffer.append(&mut server_certificate.server_id.as_bytes().to_vec());
        
        // Client ephemeral public
        buffer.append(&mut self.ephemeral_key_pair.public_key.as_bytes().to_vec()); 
        
        // Server ephemeral public
        buffer.append(&mut msg.server_ephemeral_public_key.as_bytes().to_vec());

        // "ntor" string identifier
        buffer.append(&mut "ntor".as_bytes().to_vec());
        
        // Instantiate and run hashing function
        let mut hasher = Sha256::new();
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
        println!("[DEBUG] Client secret key prime: {:?}", secret_key_prime);
    
        // Step 19: Compute the HMAC (t_b in the paper) of secret_key_prime, server_id, server_static_public_key, server_ephemeral_public key, "ntor", and "server".
        println!("[Step 19] Compute the transcript t_b for comparison.");

        let mut buffer: Vec<u8> = Vec::new();
        buffer.append(&mut server_certificate.server_id.as_bytes().to_vec());
        buffer.append(&mut msg.server_ephemeral_public_key.as_bytes().to_vec());
        buffer.append(&mut self.ephemeral_key_pair.public_key.as_bytes().to_vec());
        buffer.append(&mut "ntor".as_bytes().to_vec());
        buffer.append(&mut "server".as_bytes().to_vec());

        let mut hmac_hash = Hmac::<Sha256>::new_from_slice(&*buffer).unwrap();
        hmac_hash.update(secret_key_prime);
        let computed_t_hash = hmac_hash.finalize().into_bytes().to_vec();

        // assert that computed_t_b_hash equals t_hash generated by server
        return if computed_t_hash == msg.t_hash {
            self.shared_secret = Some(secret_key.to_vec());

            println!("Client:");
            println!("Shared secret:");
            println!("{:?}", secret_key);
            true
        } else {
            println!("Failed to verify the shared secret: try again bro.");
            false
        }
    }

}

impl Server {
    fn new(server_id: String) -> Self {
        // In the future, implementations of static and ephemeral key pair generation should differ.
        return Self{
            server_id,
            shared_secret: None,
            static_key_pair: generate_private_public_key_pair(),
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
        // Step 9: Normally, it would be necessary to verify that the client's ephemeral public key is valid. However, the X25519 makes it so that all points are valid.
        // Step 10: Obtain an ephemeral key pair specific to this session and this client. And set the session ID to a hash of the server's ephemeral public key.
        // Step 11: Compute the shared secret server side.

        let mut buffer: Vec<u8> = Vec::new();
        // - client_public_ephemeral^server_ephemeral_private (X^y),
        let taken_private_key = self.ephemeral_key_pair.private_key.take().unwrap();
        let mut ecdh_results_1 = taken_private_key.diffie_hellman(&init_msg.client_ephemeral_public_key).to_bytes().to_vec();
        println!("[Debug] ECDH result 1: {:?}", ecdh_results_1);
        buffer.append(&mut ecdh_results_1);

        // - client_public_ephemeral^server_static_private (X^b),
        let taken_private_key = self.static_key_pair.private_key.take().unwrap();
        let mut ecdh_results_2 = taken_private_key.diffie_hellman(&init_msg.client_ephemeral_public_key).to_bytes().to_vec();
        buffer.append(&mut ecdh_results_2);
                println!("[Debug] ECDH result 2: {:?}", ecdh_results_2);
        
        // - server_id
        buffer.append(&mut self.server_id.as_bytes().to_vec());

        // - client_public_ephemeral (X)
        buffer.append(&mut init_msg.client_ephemeral_public_key.to_bytes().to_vec());

        // - server_public_ephemeral (Y)
        buffer.append(&mut self.ephemeral_key_pair.public_key.to_bytes().to_vec());

        // - "ntor"
        buffer.append(&mut "ntor".as_bytes().to_vec());

        // Instantiate hash function and compute
        let mut hasher = Sha256::new();
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
        println!("[DEBUG] Server secret key prime: {:?}", secret_key_prime);

        // Step 12: Compute the HMAC (t_b in the paper) of:
        let mut hmac_key_buffer: Vec<u8> = Vec::new();
        // server_id,
        hmac_key_buffer.append(&mut self.server_id.as_bytes().to_vec());
        // server_ephemeral_public_key,
        hmac_key_buffer.append(&mut self.ephemeral_key_pair.public_key.to_bytes().to_vec());
        // client_ephemeral_public_key
        hmac_key_buffer.append(&mut init_msg.client_ephemeral_public_key.to_bytes().to_vec());
        // "ntor"
        hmac_key_buffer.append(&mut "ntor".as_bytes().to_vec());
        // "server"
        hmac_key_buffer.append(&mut "server".as_bytes().to_vec());

        let mut hmac_hash = Hmac::<Sha256>::new_from_slice(&*hmac_key_buffer).unwrap();
        hmac_hash.update(secret_key_prime);
        let output_hash = hmac_hash.finalize().into_bytes().to_vec();
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
    let success_flag = client.handle_response_from_server(&server.get_certificate(), &init_session_response);

    println!("{success_flag}");
}


