//! Signatures for the SymCrypt backend.

// TODO(#3): implement ECDSA and RSA PKCS#1 v1.5 signing and verification with
// SymCrypt (`symcrypt::ecc`, `symcrypt::rsa`), restrict
// `Verifier::is_supported` to what this backend can do, and define its own
// `DEFAULT_ORDER` instead of re-exporting the rustcrypto ones.
pub(crate) use crate::crypto::rustcrypto::sign::{DEFAULT_ORDER, Signatures};
