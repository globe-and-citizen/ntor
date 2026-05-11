use ntor::client::NTorClient;
use ntor::common::{EncryptedMessage, NTorParty};
use ntor::server::NTorServer;

fn main() {
    // Create a new client
    let mut client = NTorClient::new();

    // Spin up a server
    let server_id = String::from("my server id");
    let mut server = NTorServer::new(server_id);

    // Client initializes session with the server
    let init_session_msg = client.initialise_session();

    // Server accepts the connection request and processes it
    let init_session_response = server.accept_init_session_request(&init_session_msg);

    // Client processes response from the server and verifies it authenticity
    let success_flag =
        client.handle_response_from_server(&server.get_certificate(), &init_session_response);

    println!("{success_flag}");

    // Client encrypts a message to send to the server
    let encrypted_message = client.encrypt(b"Hello, server!".to_vec()).unwrap();
    println!("Encrypted message: {:?}", encrypted_message);

    // check bytes conversion
    let encrypted_bytes = encrypted_message.to_bytes();
    println!("Encrypted message bytes: {:?}", encrypted_bytes);

    let decode_msg = EncryptedMessage::from_bytes(&encrypted_bytes).unwrap();
    println!("Decoded encrypted message: {:?}", decode_msg);
    println!("Comparing original and decoded encrypted messages: {}", encrypted_message == *decode_msg);

    // Server decrypts the message
    let decrypted_message = server.decrypt(encrypted_message).unwrap();
    println!("Decrypted message: {}", String::from_utf8(decrypted_message).unwrap());
}
