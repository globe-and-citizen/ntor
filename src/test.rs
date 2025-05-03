#[cfg(test)]
mod tests {
    use crate::generate_private_public_key_pair;

    #[test]
    fn test_generate_private_public_key_pair() {
        let key_pair = generate_private_public_key_pair();
        assert!(
            !key_pair.private_key.is_empty(),
            "Private key should not be empty"
        );
        assert!(
            !key_pair.public_key.is_empty(),
            "Public key should not be empty"
        );

        println!("Private key: {:?}", key_pair.private_key);
        println!("Public key: {:?}", key_pair.public_key);
    }
}
