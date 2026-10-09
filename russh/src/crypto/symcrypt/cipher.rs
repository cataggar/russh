//! Ciphers for the SymCrypt backend.

// TODO(#4): add AES-GCM (`GcmCipher` over `symcrypt::gcm`) and
// `chacha20-poly1305@openssh.com` (`SshChacha20Poly1305Cipher`), move AES-CTR
// to SymCrypt (`SshBlockCipher`), and define this backend's own `ALGORITHMS`
// and `DEFAULT_ORDER` instead of re-exporting the rustcrypto ones (which
// have no AEAD).
pub(crate) use crate::crypto::rustcrypto::cipher::{ALGORITHMS, DEFAULT_ORDER};
