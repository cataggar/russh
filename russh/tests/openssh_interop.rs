//! The russh client against a real OpenSSH server, one forced algorithm at a
//! time. The harness lives in `common/openssh.rs`, which also explains how
//! tests skip when OpenSSH is not installed.
//!
//! This file covers the algorithms of the aws-lc-rs and ring backends. A
//! backend with a different set of algorithms gets its own test file that
//! calls the same runners with its own lists.
#![cfg(any(feature = "aws-lc-rs", feature = "ring"))]

mod common;

use common::openssh::{self, Case, KeyAlg, KeyType, Sshd};
use russh::keys::HashAlg;
use russh::{cipher, kex, mac};

/// Used for both host keys and user keys: every key type, both SHA-2 RSA
/// signature algorithms, and two RSA key sizes.
const KEY_ALGORITHMS: &[KeyAlg] = &[
    KeyAlg::ED25519,
    KeyAlg::ECDSA_P256,
    KeyAlg::ECDSA_P384,
    KeyAlg::ECDSA_P521,
    KeyAlg::RSA_SHA2_256,
    KeyAlg::RSA_SHA2_512,
    KeyAlg::rsa(KeyType::Rsa2048, Some(HashAlg::Sha256)),
    KeyAlg::rsa(KeyType::Rsa2048, Some(HashAlg::Sha512)),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kex() {
    // russh also implements diffie-hellman-group15-sha512 and
    // diffie-hellman-group17-sha512, which OpenSSH lacks.
    openssh::check_kex(
        Case::default(),
        &[
            kex::MLKEM768X25519_SHA256,
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::ECDH_SHA2_NISTP256,
            kex::ECDH_SHA2_NISTP384,
            kex::ECDH_SHA2_NISTP521,
            kex::DH_GEX_SHA256,
            kex::DH_G14_SHA256,
            kex::DH_G16_SHA512,
            kex::DH_G18_SHA512,
        ],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ciphers() {
    openssh::check_ciphers(
        Case::default(),
        &[
            cipher::AES_128_GCM,
            cipher::AES_256_GCM,
            cipher::AES_128_CTR,
            cipher::AES_192_CTR,
            cipher::AES_256_CTR,
            cipher::CHACHA20_POLY1305,
        ],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn macs() {
    // Paired with aes128-ctr: AEAD ciphers don't use a MAC.
    openssh::check_macs(
        Case::default(),
        &[
            mac::HMAC_SHA256,
            mac::HMAC_SHA512,
            mac::HMAC_SHA256_ETM,
            mac::HMAC_SHA512_ETM,
        ],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_keys() {
    openssh::check_host_keys(Case::default(), KEY_ALGORITHMS).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_keys() {
    openssh::check_user_keys(Case::default(), KEY_ALGORITHMS).await;
}

/// Several algorithms forced at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn combinations() {
    openssh::check_cases(
        "combinations",
        [
            Case::default()
                .with_kex(kex::ECDH_SHA2_NISTP256)
                .with_cipher(cipher::AES_256_GCM),
            Case::default()
                .with_kex(kex::ECDH_SHA2_NISTP384)
                .with_cipher(cipher::AES_256_CTR)
                .with_mac(mac::HMAC_SHA512_ETM)
                .with_host_key(KeyAlg::RSA_SHA2_512)
                .with_user_key(KeyAlg::ECDSA_P384),
            Case::default()
                .with_kex(kex::CURVE25519)
                .with_cipher(cipher::CHACHA20_POLY1305)
                .with_host_key(KeyAlg::ED25519)
                .with_user_key(KeyAlg::ED25519),
        ],
    )
    .await;
}

/// Older SHA-1 and CBC algorithms. OpenSSH still implements them, but no
/// longer enables most of them by default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy() {
    let ssh_rsa = KeyAlg::rsa(KeyType::Rsa2048, None);
    #[allow(unused_mut)]
    let mut cases = vec![
        Case::default().with_kex(kex::DH_G1_SHA1),
        Case::default().with_kex(kex::DH_G14_SHA1),
        Case::default().with_kex(kex::DH_GEX_SHA1),
        Case::default().with_cipher(cipher::AES_128_CBC),
        Case::default().with_cipher(cipher::AES_192_CBC),
        Case::default().with_cipher(cipher::AES_256_CBC),
        Case::default()
            .with_cipher(cipher::AES_128_CTR)
            .with_mac(mac::HMAC_SHA1),
        Case::default()
            .with_cipher(cipher::AES_128_CTR)
            .with_mac(mac::HMAC_SHA1_ETM),
        Case::default().with_host_key(ssh_rsa),
        Case::default().with_user_key(ssh_rsa),
    ];
    // Not with an EtM MAC, see `triple_des_etm`.
    #[cfg(feature = "des")]
    cases.push(
        Case::default()
            .with_cipher(cipher::TRIPLE_DES_CBC)
            .with_mac(mac::HMAC_SHA256),
    );
    openssh::check_cases("legacy", cases).await;
}

/// Known russh bug. With an encrypt-then-MAC MAC the packet length is not
/// encrypted, so with 3des-cbc's 8-byte blocks OpenSSH sends packets of
/// only 4 + 8 bytes, such as `SSH_MSG_USERAUTH_SUCCESS`. russh's block
/// cipher `OpeningKey` always reads 16 bytes first and rejects them with
/// `Error::PacketSize(8)`, so authentication appears to fail.
#[cfg(feature = "des")]
#[ignore = "russh bug: 3des-cbc with *-etm@openssh.com MACs rejects 12-byte packets with PacketSize(8)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn triple_des_etm() {
    openssh::check_macs(
        Case::default().with_cipher(cipher::TRIPLE_DES_CBC),
        &[
            mac::HMAC_SHA1_ETM,
            mac::HMAC_SHA256_ETM,
            mac::HMAC_SHA512_ETM,
        ],
    )
    .await;
}

/// Uses the lower-level API: one sshd with several host keys, and a client
/// that selects one of them by its host key algorithm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_key_selection() {
    if openssh::available().is_none() {
        return;
    }
    let sshd = Sshd::builder()
        .host_key(KeyType::Ed25519)
        .host_key(KeyType::EcdsaP384)
        .host_key(KeyType::Rsa2048)
        .start()
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    for host_key in [
        KeyAlg::ED25519,
        KeyAlg::ECDSA_P384,
        KeyAlg::rsa(KeyType::Rsa2048, Some(HashAlg::Sha512)),
    ] {
        let case = Case::default().with_host_key(host_key);
        if let Err(error) = case.run_client(&sshd).await {
            // Dropping `sshd` while panicking prints its diagnostics.
            panic!("{case}: {error:#}");
        }
    }
}

/// Known bug in the ssh-key crate, which parses keys for `russh::keys`. A
/// P-256 private scalar below 2^247 (1 in 512 keys) is an mpint of at most
/// 31 bytes in OpenSSH's key format, and `EcdsaPrivateKey::decode` rejects
/// anything shorter than 32 bytes with `length invalid`. With 4000 keys this
/// test finds such a key with a probability above 99.9%.
#[ignore = "ssh-key bug: 1 in 512 ssh-keygen ECDSA P-256 private keys fail to load with `length invalid`"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdsa_p256_key_loading() {
    openssh::check_key_loading(KeyType::EcdsaP256, 4000).await;
}
