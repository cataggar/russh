//! MACs for the SymCrypt backend.

// TODO(#4): implement HMAC-SHA2 (and HMAC-SHA1 if kept) with SymCrypt
// (`symcrypt::hmac`) and define this backend's own `ALGORITHMS` and
// `DEFAULT_ORDER` instead of re-exporting the rustcrypto ones.
pub(crate) use crate::crypto::rustcrypto::mac::{ALGORITHMS, DEFAULT_ORDER};
