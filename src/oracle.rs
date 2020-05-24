use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

#[derive(Debug)]
pub struct OracleError;

#[derive(Debug)]
pub struct Oracle {
    key: Vec<u8>,
}

impl Oracle {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Tests a given iv and ciphertext. Returns whether there was a decryption error.
    pub fn test(&self, iv: &[u8], cipher: &[u8]) -> Result<(), OracleError> {
        let aes_cipher = Aes128Cbc::new_var(&self.key, &iv).unwrap();
        let decrypt_res = aes_cipher.decrypt_vec(cipher);

        if decrypt_res.is_err() {
            Err(OracleError)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use aes::Aes128;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, Cbc};

    type Aes128Cbc = Cbc<Aes128, Pkcs7>;

    use super::Oracle;

    #[test]
    fn oracle_test() {
        let key = b"abcdefghijklmnop";
        let iv = b"abcdefghijklmnop";
        let plain = b"12345678901234567890";
        let aes_cipher = Aes128Cbc::new_var(key, iv).unwrap();
        let cipher = aes_cipher.encrypt_vec(plain);
        assert_eq!(cipher.len(), 32);

        let mut mod_cipher = cipher.clone();
        mod_cipher[15] = 0x00;

        let oracle = Oracle::new(key);
        assert!(oracle.test(iv, &cipher).is_ok());
        assert!(oracle.test(iv, &mod_cipher).is_err());
    }
}
