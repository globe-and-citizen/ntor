
// // use curve25519_dalek::edwards::CompressedEdwardsY; // Assuming this is the library

// // // ... inside your function/method ...

// // let server_ephemeral_public_key_vec: Vec<u8> = msg.server_ephemeral_public_key;

// // // Convert Vec<u8> to a slice, then try to convert to a fixed-size array reference
// // let ephemeral_public_key_array_ref: &[u8; 32] = match server_ephemeral_public_key_vec.as_slice().try_into() {
// //     Ok(array_ref) => array_ref,
// //     Err(e) => {
// //         // Handle the error: the vector was not 32 bytes long
// //         eprintln!("Error: server_ephemeral_public_key was not 32 bytes long: {}", e);
// //         // You might want to return an error, panic, or use a default value
// //         // For example, if this is a network message, it's likely a malformed message.
// //         // You might panic or return an Err result for your function.
// //         panic!("Invalid server ephemeral public key length");
// //     }
// // };

// // let ephemeral_public_key_point = CompressedEdwardsY(*ephemeral_public_key_array_ref).decompress().unwrap();

// // Write a function that returns a vector<u8> of len at least 10
// // Write a println statement that displays a view of the it as [u8] using AsRef<T> trait
// // Convert it to a fixed length array [10;u8]

//         let server_ephemeral_public_key: &[u8; 32] = match msg.server_ephemeral_public_key.as_slice().try_into() {
//             Ok(array_ref) => array_ref,
//             Err(e) => {
//                 println!("Error: server_ephemeral_public_key was not 32 bytes long: {}", e);
//                 panic!("Invalid server ephemeral public key length");
//             }
//         };
//         let ephemeral_public_key_point = CompressedEdwardsY(*server_ephemeral_public_key).decompress().unwrap();



// fn main() {
//     let ravis_vector = get_a_vector(10);
//     println!("Hello, world! {:?}", ravis_vector);
//     let ravis_slice_view: &[u8] = ravis_vector.as_ref();
//     println!("Hello, success! {:?}", ravis_slice_view);
    
//     let match_extracated: &[u8; 10] = match ravis_vector.as_slice().try_into() {
//         Ok(array_ref) => array_ref,
//         Err(e) => {
//             println!("Error bro dis long: {} but u still getting it: ", e);
//             panic!("Panic mother fucker!");
//         }
//     };
//     println!("r u getting it! {:?}", match_extracated);
    
// }


// fn get_a_vector(length: u8)-> Vec<u8>{
//     let mut the_vector: Vec<u8> = Vec::new();
//     for idx in 0..length {
//         the_vector.push(idx);
//     }
//     the_vector
// }