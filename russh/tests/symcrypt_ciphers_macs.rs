//! The ciphers and MACs of the SymCrypt backend against OpenSSH:
//! `cargo test -p russh --no-default-features --features symcrypt --test
//! symcrypt_ciphers_macs`. The ciphers and MACs SymCrypt lacks are refused.
//! The cases are skipped when OpenSSH is missing, unless
//! `RUSSH_REQUIRE_SSHD=1`.
#![cfg(all(
    feature = "symcrypt",
    not(feature = "aws-lc-rs"),
    not(feature = "ring")
))]

mod common;

use common::openssh::{self, Case, Query, Refused};
use russh::{Preferred, cipher, mac};

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

/// The CBC modes, which OpenSSH implements and the backend doesn't, are
/// neither offered nor accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsupported_ciphers_are_refused() {
    openssh::check_refused(
        "unsupported ciphers",
        Refused::Cipher,
        [
            cipher::AES_128_CBC,
            cipher::AES_192_CBC,
            cipher::AES_256_CBC,
        ]
        .map(|cipher| Case::default().with_cipher(cipher)),
    )
    .await;
}

/// `3des-cbc` isn't even a cipher name russh knows, with or without the
/// `des` feature, and a server offering only it is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn triple_des_cbc_is_refused() {
    const TRIPLE_DES_CBC: &str = "3des-cbc";
    assert!(cipher::Name::try_from(TRIPLE_DES_CBC).is_err());
    let Some(openssh) = openssh::available() else {
        return;
    };
    if !openssh.supports(Query::Cipher, TRIPLE_DES_CBC) {
        openssh::log_line(&format!(
            "skipped: {} does not support {TRIPLE_DES_CBC}",
            openssh.short_version()
        ));
        return;
    }
    let sshd = Case::default()
        .sshd()
        .ciphers(TRIPLE_DES_CBC)
        .start()
        .await
        .expect("starting sshd");
    let refused =
        openssh::check_no_common(&sshd, Preferred::default(), Refused::Cipher, TRIPLE_DES_CBC);
    if let Err(error) = refused.await {
        panic!("{error:#}\n{}", sshd.diagnostics());
    }
}

/// The SHA-1 MACs, which OpenSSH implements and the backend doesn't, are
/// neither offered nor accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsupported_macs_are_refused() {
    openssh::check_refused(
        "unsupported MACs",
        Refused::Mac,
        [mac::HMAC_SHA1, mac::HMAC_SHA1_ETM].map(|mac| {
            Case::default()
                .with_cipher(cipher::AES_128_CTR)
                .with_mac(mac)
        }),
    )
    .await;
}
