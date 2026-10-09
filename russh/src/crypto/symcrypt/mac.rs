//! MACs for the SymCrypt backend.

// TODO(#4): implement HMAC-SHA2 (and HMAC-SHA1 if kept) with SymCrypt
// (`symcrypt::hmac`) and define this backend's own `ALGORITHMS` and
// `DEFAULT_ORDER` instead of re-exporting the rustcrypto ones.
pub(crate) use crate::crypto::rustcrypto::mac::{ALGORITHMS, DEFAULT_ORDER};

#[cfg(test)]
mod tests {
    use crate::mac;

    // TODO(#4): replace with the MACs this backend implements.
    #[test]
    fn offers_hmac_sha2() {
        assert_eq!(
            super::DEFAULT_ORDER,
            [
                mac::HMAC_SHA512_ETM,
                mac::HMAC_SHA256_ETM,
                mac::HMAC_SHA512,
                mac::HMAC_SHA256,
            ]
        );
    }
}
