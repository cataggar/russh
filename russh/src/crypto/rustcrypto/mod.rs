//! Pure-Rust implementations (RustCrypto, `curve25519-dalek`, `ml-kem`,
//! `num-bigint`, `rsa`, `ssh-key`) of every category except the AEADs.
//!
//! Not a backend of its own: `aws_lc` and `ring` re-export all of it but the
//! AEADs, and `symcrypt` delegates the categories it does not implement yet.

mod cbc;
pub(crate) mod cipher;
pub(crate) mod hash;
pub(crate) mod kex;
pub(crate) mod mac;
pub(crate) mod rng;
pub(crate) mod sign;
