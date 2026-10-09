//! The ciphers and MACs of the SymCrypt backend against OpenSSH:
//! `cargo test -p russh --no-default-features --features symcrypt --test
//! symcrypt_ciphers_macs`. The cases are skipped when OpenSSH is missing,
//! unless `RUSSH_REQUIRE_SSHD=1`.
#![cfg(all(
    feature = "symcrypt",
    not(feature = "aws-lc-rs"),
    not(feature = "ring")
))]

mod common;

use common::openssh::{self, Case};
use russh::{cipher, mac};

const CTR_CIPHERS: [cipher::Name; 3] = [
    cipher::AES_128_CTR,
    cipher::AES_192_CTR,
    cipher::AES_256_CTR,
];

/// Each cipher (with the default MAC for AES-CTR).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_with_each_cipher() {
    let mut ciphers = vec![
        cipher::AES_128_GCM,
        cipher::AES_256_GCM,
        cipher::CHACHA20_POLY1305,
    ];
    ciphers.extend(CTR_CIPHERS);
    openssh::check_ciphers(Case::default(), &ciphers).await;
}

/// Each MAC with each AES-CTR cipher.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_with_each_mac() {
    let cases = CTR_CIPHERS.into_iter().flat_map(|cipher| {
        [
            mac::HMAC_SHA256,
            mac::HMAC_SHA512,
            mac::HMAC_SHA256_ETM,
            mac::HMAC_SHA512_ETM,
        ]
        .map(|mac| Case::default().with_cipher(cipher).with_mac(mac))
    });
    openssh::check_cases("MACs", cases).await;
}
