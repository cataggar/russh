//! Smoke test of the SymCrypt backend, selected when `symcrypt` is the only
//! backend feature: `cargo test -p russh --no-default-features --features
//! symcrypt --test 'symcrypt_*'`.
//!
//! More SymCrypt integration tests go in `russh/tests/symcrypt_*.rs`, which
//! CI (`.github/workflows/symcrypt.yml`) runs with the command above.
#![cfg(all(
    feature = "symcrypt",
    not(feature = "aws-lc-rs"),
    not(feature = "ring")
))]

mod common;

use common::openssh::{self, Case, KeyAlg};
use rand::Rng;
use russh::{Preferred, kex};

#[test]
fn default_preferences_are_not_empty() {
    let extensions = [
        kex::EXTENSION_SUPPORT_AS_CLIENT,
        kex::EXTENSION_SUPPORT_AS_SERVER,
        kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
        kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
    ];
    for pref in [Preferred::default(), Preferred::COMPRESSED] {
        assert!(pref.kex.iter().any(|k| !extensions.contains(k)));
        assert!(!pref.key.is_empty());
        assert!(!pref.cipher.is_empty());
        assert!(!pref.mac.is_empty());
        assert!(!pref.compression.is_empty());
    }
}

#[test]
fn rng_works() {
    let mut rng = russh::keys::key::safe_rng();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut a);
    rng.fill_bytes(&mut b);
    assert_ne!(a, [0; 32]);
    assert_ne!(a, b);
}

/// The client connects to OpenSSH with the default algorithms, for each
/// host key type (RSA needs the `rsa` feature until SymCrypt does RSA).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_with_default_algorithms() {
    let mut host_keys = vec![KeyAlg::ED25519, KeyAlg::ECDSA_P256];
    if cfg!(feature = "rsa") {
        host_keys.extend([KeyAlg::RSA_SHA2_256, KeyAlg::RSA_SHA2_512]);
    }
    openssh::check_host_keys(Case::default(), &host_keys).await;
}
