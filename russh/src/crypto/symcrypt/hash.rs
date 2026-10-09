//! Hashes for the SymCrypt backend.

// TODO(#2): implement SHA-1/SHA-256/SHA-384/SHA-512 with SymCrypt
// (`symcrypt::hash`) and drop this re-export.
pub(crate) use crate::crypto::rustcrypto::hash::{Sha1, Sha256, Sha384, Sha512};
