extern crate secp256k1;
extern crate tiny_keccak;
extern crate hex;

use secp256k1::{Secp256k1, SecretKey};
use tiny_keccak::{Hasher, Keccak};
use std::str;

fn main() {
    let full_private_key = "YOUR_FULL_64_CHAR_PRIVATE_KEY";
    let known_ethereum_address = "0xYourKnownEthereumAddress";
    let known_ethereum_address = known_ethereum_address.to_lowercase();

    println!("=== Testing full private key ===");
    if let Some(address) = derive_address_from_private_key(full_private_key) {
        println!("Full private key test - Generated address: {}", address);
        if address == known_ethereum_address {
            println!("Full private key matches known Ethereum address!");
        } else {
            println!("Full private key does not match. Check derivation logic.");
        }
    } else {
        println!("Error deriving address from the full private key.");
    }

    let partial_private_key = &full_private_key[..63];  

    println!("=== Starting brute-force for the missing character ===");

    for i in 0..=partial_private_key.len() {
        for ch in "0123456789abcdef".chars() {
            let mut candidate = partial_private_key.to_string();
            candidate.insert(i, ch);

            println!("Testing candidate private key: {}", candidate);

            if let Some(address) = derive_address_from_private_key(&candidate) {
                println!("Generated address: {}", address);
                if address.to_lowercase() == known_ethereum_address {
                    println!("Found matching private key: {}", candidate);
                    return;
                }
            } else {
                println!("Error deriving address for candidate private key.");
            }
        }
    }

    println!("No matching private key found.");
}

fn derive_address_from_private_key(private_key: &str) -> Option<String> {
    let private_key_bytes = hex::decode(private_key).ok()?;
    
    if private_key_bytes.len() != 32 {
        return None;
    }

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key_bytes).ok()?;
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize_uncompressed();

    let mut hasher = Keccak::v256();
    hasher.update(&public_key_bytes[1..]);
    let mut hashed_public_key = [0u8; 32];
    hasher.finalize(&mut hashed_public_key);

    let ethereum_address = &hashed_public_key[12..];
    let ethereum_address_hex = format!("0x{}", hex::encode(ethereum_address));

    Some(ethereum_address_hex)
}

