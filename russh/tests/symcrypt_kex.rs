//! Interop of the SymCrypt backend's key exchanges with OpenSSH, one forced
//! method at a time: `cargo test -p russh --no-default-features --features
//! symcrypt --test symcrypt_kex`. `mlkem768x25519-sha256` is skipped when
//! the local OpenSSH is older than 9.9. The methods SymCrypt lacks are
//! refused.
#![cfg(all(
    feature = "symcrypt",
    not(feature = "aws-lc-rs"),
    not(feature = "ring")
))]

mod common;

use common::openssh::{self, Case, Refused};
use russh::kex;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kex() {
    openssh::check_kex(
        Case::default(),
        &[
            kex::MLKEM768X25519_SHA256,
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::ECDH_SHA2_NISTP256,
            kex::ECDH_SHA2_NISTP384,
        ],
    )
    .await;
}

/// NIST P-521 and finite-field Diffie-Hellman, which OpenSSH implements and
/// the backend doesn't, are neither offered nor accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsupported_kex_is_refused() {
    openssh::check_refused(
        "unsupported kex",
        Refused::Kex,
        [
            kex::ECDH_SHA2_NISTP521,
            kex::DH_G14_SHA256,
            kex::DH_G16_SHA512,
            kex::DH_GEX_SHA256,
        ]
        .map(|kex| Case::default().with_kex(kex)),
    )
    .await;
}
