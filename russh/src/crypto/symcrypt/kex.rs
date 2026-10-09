//! Key agreement for the SymCrypt backend.

// TODO(#2): implement X25519, ECDH P-256/P-384 (and P-521 if supported) and
// ML-KEM-768 with SymCrypt (`symcrypt::ecc`, `symcrypt::mlkem`), decide on
// finite-field DH, and define this backend's own `ALGORITHMS` and
// `DEFAULT_ORDER` instead of re-exporting the rustcrypto ones.
pub(crate) use crate::crypto::rustcrypto::kex::{
    ALGORITHMS, DEFAULT_ORDER, Dh, MlKem768, NistP256, NistP384, NistP521, X25519,
};

#[cfg(test)]
mod tests {
    use crate::kex;

    // TODO(#2): replace with the key exchanges this backend implements.
    #[test]
    fn offers_curve25519_and_mlkem() {
        assert_eq!(
            super::DEFAULT_ORDER[..3],
            [
                kex::MLKEM768X25519_SHA256,
                kex::CURVE25519,
                kex::CURVE25519_PRE_RFC_8731,
            ]
        );
    }
}
