use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair}; // I'm using ring to generate the keypair

use sha2::{Sha256, Digest};
use curve25519_dalek::edwards::{CompressedEdwardsY};
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};

struct PrivatePublicKeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

fn generate_private_public_key_pair() -> PrivatePublicKeyPair {
    let random = SystemRandom::new(); //

    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&random).unwrap(); 
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref()).unwrap();

    PrivatePublicKeyPair {
        private_key: pkcs8_doc.as_ref().to_vec(),
        public_key: key_pair.public_key().as_ref().to_vec(),
    }
}

struct Client {
    ephemeral_key_pair: PrivatePublicKeyPair,

    shared_secret: Vec<u8>
}

struct Server {
    static_key_pair: PrivatePublicKeyPair,
    ephemeral_key_pair: PrivatePublicKeyPair,
    server_id: String,

    shared_secret: Vec<u8>
}

struct Certificate {
    public_key: Vec<u8>,
    server_id: String 
}

struct InitSessionMessage {
    client_ephemeral_public_key: Vec<u8>
}

struct InitSessionResponse {
    server_ephemeral_public_key: Vec<u8>,
    t_hash: Vec<u8>
}

impl Client {
    // Associated function: client constructor
    fn new() -> Self {
        return Self {
            ephemeral_key_pair: PrivatePublicKeyPair {
                private_key: vec![],
                public_key: vec![]
            },
            shared_secret: vec![],
        }
    }

    fn initialise_session(&mut self) -> InitSessionMessage {
        self.ephemeral_key_pair = generate_private_public_key_pair(); // client just needs the ephemeral key pair


        return InitSessionMessage {
            // So, yes, the public part of the key pair is cloned here... but how is it encoded?
            client_ephemeral_public_key: self.ephemeral_key_pair.public_key.clone()  
        }
    }

    fn handle_response_from_server(
        &mut self,
        server_certificate: &Certificate,
        msg: &InitSessionResponse,
    ) -> bool {
        //  Compute (sk0, sk) = H(Y^x, B^x, server_id, X, Y, "ntor");

        let server_ephemeral_public_key: &[u8; 32] = match msg.server_ephemeral_public_key.as_slice().try_into() {
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: server_ephemeral_public_key was not 32 bytes long: {}", e);
                panic!("Invalid server ephemeral public key length");
            }
        };
        let ephemeral_public_key_point = CompressedEdwardsY(*server_ephemeral_public_key).decompress().unwrap();
        
        let server_static_public_key: &[u8; 32] = match server_certificate.public_key.as_slice().try_into() {
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: server_static_public_key was not 32 bytes long: {}", e);
                panic!("Invalid server static public key length");
            }
        };
        let static_public_key_point = CompressedEdwardsY(*server_static_public_key).decompress().unwrap();

        let client_ephemeral_private_key: &[u8; 32] = match self.ephemeral_key_pair.private_key.as_slice().try_into() {
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: client_ephemeral_private_key was not 32 bytes long: {}", e);
                panic!("Invalid client ephemeral private key length");
            }
        };

        let eph_private_key_scalar=
            Scalar::from_bytes_mod_order(*client_ephemeral_private_key);

        let first_hash = &eph_private_key_scalar * &ephemeral_public_key_point;
        let second_hash = &eph_private_key_scalar * &static_public_key_point;

        let mut buffer: Vec<u8> = Vec::new();
        buffer.append(&mut first_hash.compress().as_bytes().to_vec());
        buffer.append(&mut second_hash.compress().as_bytes().to_vec());
        buffer.append(&mut server_certificate.server_id.as_bytes().to_vec());
        buffer.append(&mut self.ephemeral_key_pair.public_key);
        buffer.append(&mut ephemeral_public_key_point.compress().as_bytes().to_vec());
        buffer.append(&mut "ntor".as_bytes().to_vec());

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

        let secret_key_prime = &sha256_hash[0..128];
        let secret_key = &sha256_hash[128..];

        // Compute tB = Hmac(secret_key_prime, server_id, Y, X, "ntor", “server”);

        let mut hmac_key: Vec<u8> = Vec::new();
        hmac_key.append(&mut server_certificate.server_id.as_bytes().to_vec());
        hmac_key.append(&mut msg.server_ephemeral_public_key.to_vec());
        hmac_key.append(&mut self.ephemeral_key_pair.public_key);
        hmac_key.append(&mut "ntor server".as_bytes().to_vec());

        type HmacSha256 = Hmac<Sha256>;
        let mut hmac_hash = HmacSha256::new_from_slice(&*hmac_key).unwrap();
        hmac_hash.update(secret_key_prime);
        let computed_t_hash = hmac_hash.finalize().into_bytes().to_vec();

        println!("Client:");

        // assert that computed_t_b_hash equals t_hash generated by server
        if computed_t_hash == msg.t_hash {
            self.shared_secret = secret_key.to_vec();

            println!("Success! Shared secret:");
            println!("{:?}", secret_key);
            return true;
        } else {
            println!("Failed to verify the shared secret");
            return false;
        }
    }
}

impl Server {
    fn new(server_id: String) -> Self {
        let static_key_pair = generate_private_public_key_pair();
        return Self{
            ephemeral_key_pair: PrivatePublicKeyPair {
                private_key: vec![],
                public_key: vec![],
            },
            static_key_pair, // static key pair being generated from the  
            shared_secret: vec![],
            server_id,
        }
    }

    fn get_certificate(&self) -> Certificate {
        // query the CA here
        return Certificate{
            public_key: self.static_key_pair.public_key.clone(),
            server_id: self.server_id.clone(),
        }
    }

    fn accept_init_session_request(&mut self, init_msg: &InitSessionMessage) -> InitSessionResponse {
        self.ephemeral_key_pair = generate_private_public_key_pair();

        // calculate H(X^y, X^b, server_id, X, Y, "ntor")

        let client_ephemeral_public_key: &[u8; 32] = match init_msg.client_ephemeral_public_key.as_slice().try_into() {
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: client_ephemeral_public_key was not 32 bytes long: {}", e);
                panic!("Invalid client ephemeral public key length");
            }
        };

        let public_key_point = CompressedEdwardsY(*client_ephemeral_public_key).decompress().unwrap();
        
        // RAVI: HERE YOU GET YOUR SERVERS EPHEMERAL PRIVATE KEY
        // HOWEVER, IT'S CODED AS PKS#8
        let ephemeral_key_pair_private_key: &[u8; 48] = match self.ephemeral_key_pair.private_key.as_slice().try_into(){
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: ephemeral_key_pair_private_key was not 32 bytes long: {}", e);
                print!("{:?}", self.ephemeral_key_pair.private_key.as_slice());
                panic!("Invalid ephemeral key pair private key length");
            }
        };
        

        let eph_private_key_scalar=
            Scalar::from_bytes_mod_order(*ephemeral_key_pair_private_key);
        

        let static_key_pair_private_key: &[u8; 32] = match self.static_key_pair.private_key.as_slice().try_into(){
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: static_key_pair_private_key was not 32 bytes long: {}", e);
                panic!("Invalid static key pair private key length");
            }
        };
        
        let static_private_key_scalar =
            Scalar::from_bytes_mod_order(*static_key_pair_private_key);

        // why are these called hashes?
        // Scalar multiplication of two points the ephemeral private key and the client public key
        //                                       scalar       *  edwardspoint
        let first_hash = eph_private_key_scalar * public_key_point;
        let second_hash = static_private_key_scalar * public_key_point;

        let mut buffer: Vec<u8> = Vec::new();
        buffer.append(&mut first_hash.compress().as_bytes().to_vec());
        buffer.append(&mut second_hash.compress().as_bytes().to_vec());
        buffer.append(&mut self.server_id.as_bytes().to_vec());
        buffer.append(&mut public_key_point.compress().as_bytes().to_vec());
        buffer.append(&mut self.ephemeral_key_pair.public_key);
        buffer.append(&mut "ntor".as_bytes().to_vec());

        let mut hasher = Sha256::new();
        hasher.update(buffer);
        let sha256_hash = hasher.finalize();
        let sha256_hash: &[u8;32] = match sha256_hash.as_slice().try_into() {
            Ok(array_ref) => array_ref,
            Err(e) => {
                println!("Error: sha256_hash was not 32 bytes long: {}", e);
                panic!("Invalid sha256 hash length");
            }
        };

        let secret_key_prime = &sha256_hash[0..128];
        let secret_key = &sha256_hash[128..];

        // Compute tB = Hmac(secret_key_prime, server_id, Y, X, "ntor", “server”);

        let mut hmac_key: Vec<u8> = Vec::new();
        hmac_key.append(&mut self.server_id.as_bytes().to_vec());
        hmac_key.append(&mut self.ephemeral_key_pair.public_key);
        hmac_key.append(&mut init_msg.client_ephemeral_public_key.to_vec());
        hmac_key.append(&mut "ntor server".as_bytes().to_vec());

        type HmacSha256 = Hmac<Sha256>;
        let mut hmac_hash = HmacSha256::new_from_slice(&*hmac_key).unwrap();
        hmac_hash.update(secret_key_prime);
        let output_hash = hmac_hash.finalize().into_bytes().to_vec();

        self.shared_secret = secret_key.to_vec();

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


