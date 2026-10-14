//! Keys for the tests that need a host, user or CA key of any kind: the
//! integration-test counterpart of `test_keys` in `src/tests.rs`.
//!
//! With the RustCrypto-based backends they are random Ed25519 (and RSA)
//! keys. The SymCrypt backend can't use Ed25519 without its `ed25519-aws-lc`
//! feature, so it gets the committed ECDSA P-256 and RSA keys of
//! `tests/data/test-keys` (made with `ssh-keygen -N "" -C russh-test`), with
//! or without that feature.

use russh::keys::certificate::Builder;
use russh::keys::ssh_key::{Algorithm, Certificate, PrivateKey};

/// The algorithm of the [`key`]s.
#[cfg(not(russh_backend = "symcrypt"))]
pub const ALGORITHM: Algorithm = Algorithm::Ed25519;
/// The algorithm of the [`key`]s.
#[cfg(russh_backend = "symcrypt")]
pub const ALGORITHM: Algorithm = Algorithm::Ecdsa {
    curve: russh::keys::EcdsaCurve::NistP256,
};

/// A private key of [`ALGORITHM`]. Keys with different `n` (0 to 3) differ;
/// with the RustCrypto-based backends, every key does.
#[cfg(not(russh_backend = "symcrypt"))]
pub fn key(_n: usize) -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), ALGORITHM).unwrap()
}

/// A private key of [`ALGORITHM`]. Keys with different `n` (0 to 3) differ;
/// with the RustCrypto-based backends, every key does.
#[cfg(russh_backend = "symcrypt")]
pub fn key(n: usize) -> PrivateKey {
    const KEYS: [&str; 4] = [
        include_str!("../data/test-keys/ecdsa-p256-0"),
        include_str!("../data/test-keys/ecdsa-p256-1"),
        include_str!("../data/test-keys/ecdsa-p256-2"),
        include_str!("../data/test-keys/ecdsa-p256-3"),
    ];
    russh::keys::decode_secret_key(KEYS[n], None).unwrap()
}

/// An RSA private key. Keys with different `n` (0 or 1) differ; with the
/// RustCrypto-based backends, every key does.
#[cfg(not(russh_backend = "symcrypt"))]
pub fn rsa_key(_n: usize) -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Rsa { hash: None }).unwrap()
}

/// An RSA private key. Keys with different `n` (0 or 1) differ; with the
/// RustCrypto-based backends, every key does.
#[cfg(russh_backend = "symcrypt")]
pub fn rsa_key(n: usize) -> PrivateKey {
    const KEYS: [&str; 2] = [
        include_str!("../data/test-keys/rsa-2048-0"),
        include_str!("../data/test-keys/rsa-2048-1"),
    ];
    russh::keys::decode_secret_key(KEYS[n], None).unwrap()
}

/// The certificate `builder` describes, signed by `ca` with the backend
/// (with `rsa-sha2-512` for an RSA `ca`).
pub fn certify(builder: Builder, ca: &PrivateKey) -> Certificate {
    russh::keys::certificate::sign(builder, ca).unwrap()
}
