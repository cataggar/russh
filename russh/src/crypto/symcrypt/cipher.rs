//! Ciphers for the SymCrypt backend.

// TODO(#4): add AES-GCM (`GcmCipher` over `symcrypt::gcm`) and
// `chacha20-poly1305@openssh.com` (`SshChacha20Poly1305Cipher`), move AES-CTR
// to SymCrypt (`SshBlockCipher`), and define this backend's own `ALGORITHMS`
// and `DEFAULT_ORDER` instead of re-exporting the rustcrypto ones (which
// have no AEAD).
pub(crate) use crate::crypto::rustcrypto::cipher::{ALGORITHMS, DEFAULT_ORDER};

#[cfg(test)]
mod tests {
    use crate::cipher::{self, CIPHERS};

    // TODO(#4): replace with the ciphers this backend implements.
    #[test]
    fn offers_aes_ctr_and_no_aead() {
        assert_eq!(
            super::DEFAULT_ORDER,
            [cipher::AES_256_CTR, cipher::AES_192_CTR, cipher::AES_128_CTR]
        );
        assert!(CIPHERS.contains_key(&cipher::AES_128_CTR));
        assert!(!CIPHERS.contains_key(&cipher::AES_256_GCM));
        assert!(!CIPHERS.contains_key(&cipher::CHACHA20_POLY1305));
    }
}
