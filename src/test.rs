#[cfg(test)]
mod tests {
    use crate::client::Client;
    use crate::common::generate_private_public_key_pair;
    use crate::server::Server;

    #[test]
    fn test_generate_private_public_key_pair() {
        let key_pair = generate_private_public_key_pair();
        assert!(
            key_pair.private_key.is_some(),
            "Private key should not be empty"
        );
        assert!(
            !key_pair.public_key.as_bytes().is_empty(),
            "Public key should not be empty"
        );

        println!(
            "Private key: {:?}",
            key_pair.private_key.unwrap().as_bytes()
        );
        println!("Public key: {:?}\n", key_pair.public_key);
    }

    #[test]
    fn test_ntor_handshake_shared_secret_generation() {
        // Create a new client
        let mut client = Client::new();

        // Spin up a server
        let mut server = Server::new(String::from("test_server_id"));

        // Client initializes session with the server
        let init_session_msg = client.initialise_session();

        // Server accepts the connection request and processes it
        let init_session_response = server.accept_init_session_request(&init_session_msg);

        // Client processes response from the server and verifies it authenticity
        let success_flag =
            client.handle_response_from_server(&server.get_certificate(), &init_session_response);

        assert!(success_flag);
        assert_eq!(client.shared_secret, server.shared_secret)
    }
}
