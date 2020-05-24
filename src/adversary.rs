use crate::oracle::Oracle;
use crate::ui::write_line;

pub struct Adversary {
    oracle: Oracle,
    iv: Vec<u8>,
    cipher: Vec<u8>,
}

impl Adversary {
    pub fn new(oracle: Oracle, iv: Vec<u8>, cipher: Vec<u8>) -> Self {
        Self { oracle, iv, cipher }
    }

    pub fn break_ciphertext_fancy(self) {
        // Creates a vector for storing our final plaintext
        let mut plaintext: Vec<u8> = Vec::new();

        // Creates a group of blocks (IV, c_1, c_2, ..., c_n)
        let first_block = self.iv.as_slice();
        let rest_blocks: Vec<&[u8]> = self.cipher.chunks_exact(16).collect();

        let mut blocks: Vec<&[u8]> = Vec::new();
        blocks.push(first_block);
        blocks.extend(rest_blocks.into_iter());

        // Calculates the number of padding bytes in the final block
        let mut padding = determine_padding(&self.oracle, &blocks).unwrap();

        // Creates a vector for storing a decrypted block
        // Initalizes with the decrypted padding of the final block
        let mut m2 = vec![0u8; 16];
        for pad_i in (16 - padding)..16 {
            m2[pad_i] = padding as u8;
        }

        // Iterates through each block from back-to-front
        // For a ciphertext (IV, c_1, c_2, c_3), we iterate 2->1->0
        let starting_i = blocks.len() - 1;
        for i in (0..starting_i).rev() {
            // Gets references to our two focus blocks
            // c1 will be used as our IV, c2 is used as the ciphertext
            let c1 = blocks[i];
            let c2 = blocks[i + 1];

            // Padding represents the number of trailing bytes cracked thus far
            while padding < 16 {
                // Breaks a byte of the block, storing the updated plaintext block
                m2 = break_block_byte(&self.oracle, c1, c2, &m2, padding).unwrap();
                padding += 1;

                // Updates the UI
                write_line(&plaintext, &m2, padding, blocks.len());
            }

            // Inserts the plaintext block into the decrypted plaintext
            plaintext.splice(0..0, m2.iter().cloned());

            // Resets the plaintext block and padding
            m2 = vec![0u8; 16];
            padding = 0;
        }

        println!();
    }
}

fn determine_padding(oracle: &Oracle, blocks: &[&[u8]]) -> Option<usize> {
    // Gets the last two blocks of the ciphertext
    let (c2, rest) = blocks.split_last().unwrap();
    let (c1, _) = rest.split_last().unwrap();

    let mut c1 = c1.to_vec();
    let c2 = c2.to_vec();

    // Iterates from the first byte of the block to the last
    let mut i = 0;
    loop {
        // Flips the least-significant bit of the of the ith byte in the next-to-last block
        c1[i] ^= 0x1;

        // By flipping a bit in some byte of the next-to-last block
        // (which is used as the IV), we can effectively control the
        // output of the resulting plaintext. We flip a bit in each byte
        // from front-to-back of the block until we modify a byte that is
        // part of the padding. At this point the oracle will return a padding error
        // and we will know how many bytes of padding exist in the final block.
        let test_res = oracle.test(&c1, &c2);
        if test_res.is_err() {
            // Returns the number of padding bytes
            return Some(16 - i);
        }

        // Try the next byte
        i += 1;
        if i >= 16 {
            // We will always return before this point
            // If the last block uses PKCS#7 padding
            return None;
        }
    }
}

fn break_block_byte(
    oracle: &Oracle,
    c1: &[u8],
    c2: &[u8],
    m2: &[u8],
    known_bytes: usize,
) -> Option<Vec<u8>> {
    // Gets the index of the byte that we want to break in c2
    let break_byte_index = 16 - known_bytes - 1;

    // x maintains the value that will be XORd with the break_byte_index byte of the IV
    let mut x = 0;

    // Sets new_padding to the value of the known_bytes + 1
    // This is the value that we want to set the known bytes of the plaintext
    // to manipulate the plaintext into having an extra byte of padding
    let new_padding = (known_bytes + 1) as u8;

    // Iterate for all values of x
    loop {
        // Creates an array of values that will be XORd with c1
        let mut delta = [0u8; 16];
        delta[break_byte_index] = x;
        for pad_i in (break_byte_index + 1)..16 {
            delta[pad_i] = new_padding;
        }

        // XOR the padding bytes of delta with the known bytes of m2
        for (d, m) in delta.iter_mut().zip(m2.iter()) {
            *d = *d ^ m;
        }

        // Generate the IV for the oracle test by XORing delta with c1
        let delta_c1: Vec<u8> = delta.iter().zip(c1.iter()).map(|(d, c)| d ^ c).collect();

        // Query the oracle
        let oracle_res = oracle.test(&delta_c1, c2);
        if oracle_res.is_ok() {
            let mut valid = true;

            // For the final block, it is possible to have two possible valid values for x
            // We modify the next-to-last block to ensure we found the correct value
            if known_bytes == 0 {
                let mut delta_c1_prime = delta_c1.clone();
                delta_c1_prime[break_byte_index - 1] ^= 0x01;
                valid = oracle.test(&delta_c1_prime, c2).is_ok();
            }

            // If we are sure that this is the valid value of x
            // we calculate the plaintext byte and store it
            if valid {
                let plain_byte = x ^ new_padding;
                let mut m2 = m2.to_vec();
                m2[break_byte_index] = plain_byte;
                return Some(m2);
            }
        }

        // If the oracle is used correctly, we should never reach this
        // There should always be a value that yields valid padding
        if x == 0xFF {
            return None;
        }
        x += 1;
    }
}
