//! Key agreement for the SymCrypt backend.

// TODO(#2): implement X25519, ECDH P-256/P-384 (and P-521 if supported) and
// ML-KEM-768 with SymCrypt (`symcrypt::ecc`, `symcrypt::mlkem`), decide on
// finite-field DH, and define this backend's own `ALGORITHMS` and
// `DEFAULT_ORDER` instead of re-exporting the rustcrypto ones.
pub(crate) use crate::crypto::rustcrypto::kex::{
    ALGORITHMS, DEFAULT_ORDER, Dh, MlKem768, NistP256, NistP384, NistP521, X25519,
};
