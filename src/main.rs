use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hkdf::Hkdf;
use sha2::Sha256;

use rand::rngs::OsRng;
use rand::RngCore;

use colored::*;

use std::io::{self, Write};

pub mod adversary;
pub mod oracle;
pub mod ui;

use adversary::Adversary;
use oracle::Oracle;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn main() {
    println!("{}", "--- Padding Oracle Attack ---".bold());

    print!(
        "{}{}{}",
        "Enter key ",
        "(Derived using SHA256-HKDF)".italic(),
        ": "
    );
    io::stdout().flush().unwrap();

    // Reads a key string
    let mut key_str = String::new();
    io::stdin().read_line(&mut key_str).unwrap();

    print!("Enter message: ");
    io::stdout().flush().unwrap();

    // Reads a message string
    let mut msg_str = String::new();
    io::stdin().read_line(&mut msg_str).unwrap();
    if msg_str.ends_with("\n") {
        msg_str.truncate(msg_str.len() - 1);
    }

    // Derives a key using HKDF-SHA256 (weak password key derivation is sufficient for demonstration purposes)
    let hkdf = Hkdf::<Sha256>::new(None, key_str.as_bytes());
    let mut key = [0u8; 16];
    hkdf.expand(&[], &mut key).unwrap();

    // Creates a random IV
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    // Encrypts the message using AES-128 in CBC mode
    let aes_cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
    let cipher = aes_cipher.encrypt_vec(msg_str.as_bytes());

    // Creates a keyed oracle
    let oracle = Oracle::new(&key);

    // Sends the oracle, IV, and ciphertext to the adversary
    let adversary = Adversary::new(oracle, iv.to_vec(), cipher.clone());

    println!();

    // Runs the attack
    adversary.break_ciphertext_fancy();
}
