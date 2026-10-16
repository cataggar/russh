//! The algorithm policy, with every crypto backend. Without the
//! `unapproved-algorithms` feature, russh offers and accepts only the
//! approved key exchange methods, ciphers and MACs (`Preferred::APPROVED`),
//! whatever its preferences list, and not `none` either: this is checked
//! against russh and against OpenSSH, which offers each of the others in
//! turn. With the feature, `Preferred::APPROVED` still restricts a connection
//! to them. The OpenSSH checks are skipped when OpenSSH is missing, unless
//! `RUSSH_REQUIRE_SSHD=1`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Context;
#[cfg(not(feature = "unapproved-algorithms"))]
use common::openssh::Refused;
use common::openssh::{self, Case};
use common::test_keys;
#[cfg(not(feature = "unapproved-algorithms"))]
use russh::AlgorithmKind;
use russh::keys::PublicKeyOrCertificate;
use russh::{Disconnect, Names, Preferred, cipher, client, kex, mac, server};
use tokio::sync::oneshot;

/// The key exchange methods russh or OpenSSH implement that are not
/// approved.
#[cfg(not(feature = "unapproved-algorithms"))]
const UNAPPROVED_KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_GEX_SHA256,
    kex::DH_G14_SHA256,
    kex::DH_G16_SHA512,
    kex::DH_G18_SHA512,
    kex::DH_GEX_SHA1,
    kex::DH_G14_SHA1,
    kex::DH_G1_SHA1,
];

/// The ciphers russh or OpenSSH implement that are not approved.
#[cfg(not(feature = "unapproved-algorithms"))]
const UNAPPROVED_CIPHERS: &[cipher::Name] = &[
    cipher::AES_128_GCM,
    cipher::CHACHA20_POLY1305,
    cipher::AES_128_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CBC,
    cipher::AES_192_CBC,
    cipher::AES_256_CBC,
    #[cfg(feature = "des")]
    cipher::TRIPLE_DES_CBC,
];

/// The MACs russh or OpenSSH implement that are not approved.
#[cfg(not(feature = "unapproved-algorithms"))]
const UNAPPROVED_MACS: &[mac::Name] = &[
    mac::HMAC_SHA256,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA1,
    mac::HMAC_SHA1_ETM,
];

#[test]
fn policy_follows_the_feature() {
    let approved = russh::ALGORITHM_POLICY == russh::AlgorithmPolicy::Approved;
    assert_eq!(approved, !cfg!(feature = "unapproved-algorithms"));
    if approved {
        let default = Preferred::default();
        assert_eq!(default.kex, Preferred::APPROVED.kex);
        assert_eq!(default.cipher, Preferred::APPROVED.cipher);
        assert_eq!(default.mac, Preferred::APPROVED.mac);
    }
}

/// `Preferred::APPROVED`, but with `aes256-ctr` only, so that a MAC is used.
fn approved_ctr() -> Preferred {
    Preferred {
        cipher: Cow::Borrowed(&[cipher::AES_256_CTR]),
        ..Preferred::APPROVED
    }
}

/// A russh client and server with the approved preferences negotiate the
/// first approved key exchange method, cipher and MAC.
#[tokio::test]
async fn russh_negotiates_approved_preferences() {
    let names = negotiate(Preferred::APPROVED, Preferred::APPROVED)
        .await
        .unwrap();
    assert_eq!(names.kex, kex::MLKEM1024NISTP384_SHA384);
    assert_eq!(names.cipher, cipher::AES_256_GCM);

    let names = negotiate(approved_ctr(), approved_ctr()).await.unwrap();
    assert_eq!(names.cipher, cipher::AES_256_CTR);
    assert_eq!(names.client_mac, mac::HMAC_SHA512_ETM);
    assert_eq!(names.server_mac, mac::HMAC_SHA512_ETM);
}

/// Without the `unapproved-algorithms` feature, configuring algorithms that
/// are not approved on either side makes the key exchange fail for lack of a
/// common algorithm of that kind: russh neither offers nor accepts them.
#[cfg(not(feature = "unapproved-algorithms"))]
#[tokio::test]
async fn russh_refuses_unapproved_algorithms() {
    let mut cases = Vec::new();
    for &kex in UNAPPROVED_KEX {
        let only = Preferred {
            kex: Cow::Owned(vec![kex]),
            ..Preferred::default()
        };
        cases.push((format!("{kex:?}"), only, AlgorithmKind::Kex));
    }
    for &cipher in UNAPPROVED_CIPHERS {
        let only = Preferred {
            cipher: Cow::Owned(vec![cipher]),
            ..Preferred::default()
        };
        cases.push((format!("{cipher:?}"), only, AlgorithmKind::Cipher));
    }
    for &mac in UNAPPROVED_MACS {
        let only = Preferred {
            mac: Cow::Owned(vec![mac]),
            ..approved_ctr()
        };
        cases.push((format!("{mac:?}"), only, AlgorithmKind::Mac));
    }
    for (name, only, kind) in cases {
        check_refused(&name, only, kind).await;
    }
}

/// Without the `unapproved-algorithms` feature, `none` is refused too: no
/// key exchange, encryption or MAC is not an approved one.
#[cfg(not(feature = "unapproved-algorithms"))]
#[tokio::test]
async fn russh_refuses_none() {
    let none = Preferred {
        kex: Cow::Borrowed(&[kex::NONE]),
        cipher: Cow::Borrowed(&[cipher::NONE]),
        mac: Cow::Borrowed(&[mac::NONE]),
        ..Preferred::default()
    };
    check_refused("none", none.clone(), AlgorithmKind::Kex).await;
    let none_cipher = Preferred {
        kex: Preferred::APPROVED.kex,
        ..none.clone()
    };
    check_refused("cipher none", none_cipher, AlgorithmKind::Cipher).await;
    let none_mac = Preferred {
        mac: Cow::Borrowed(&[mac::NONE]),
        ..approved_ctr()
    };
    check_refused("MAC none", none_mac, AlgorithmKind::Mac).await;
}

/// Checks that a russh client with `only` fails to negotiate with a russh
/// server with the default preferences, and the other way around, for lack
/// of a common algorithm of kind `kind`.
#[cfg(not(feature = "unapproved-algorithms"))]
async fn check_refused(name: &str, only: Preferred, kind: AlgorithmKind) {
    for (server, client) in [
        (Preferred::default(), only.clone()),
        (only, Preferred::default()),
    ] {
        match negotiate(server, client).await {
            Err(russh::Error::NoCommonAlgo { kind: actual, .. })
                if std::mem::discriminant(&actual) == std::mem::discriminant(&kind) => {}
            other => panic!("{name}: expected no common {kind:?} algorithm, got {other:?}"),
        }
    }
}

/// `Preferred::APPROVED` against sshd with its default algorithms: OpenSSH
/// has no ML-KEM hybrid with the NIST curves, so `ecdh-sha2-nistp384`, and
/// `aes256-gcm@openssh.com`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_negotiates_approved_preferences() {
    if openssh::available().is_none() {
        return;
    }
    for (preferred, expected_cipher) in [
        (Preferred::APPROVED, cipher::AES_256_GCM),
        (approved_ctr(), cipher::AES_256_CTR),
    ] {
        let sshd = Case::default()
            .sshd()
            .start()
            .await
            .unwrap_or_else(|error| panic!("{error:#}"));
        let negotiating = async {
            let mut client = sshd.connect(preferred).await?;
            client.authenticate(None).await?;
            client.check_echo().await?;
            let names = client
                .negotiated()
                .context("Handler::kex_done was never called")?;
            client.disconnect().await?;
            anyhow::Ok(names)
        };
        let names = negotiating
            .await
            .unwrap_or_else(|error| panic!("{error:#}\n{}", sshd.diagnostics()));
        assert!(
            Preferred::APPROVED.kex.contains(&names.kex),
            "{:?}",
            names.kex
        );
        assert_eq!(names.cipher, expected_cipher);
        if expected_cipher == cipher::AES_256_CTR {
            assert_eq!(names.client_mac, mac::HMAC_SHA512_ETM);
            assert_eq!(names.server_mac, mac::HMAC_SHA512_ETM);
        }
    }
}

/// Without the `unapproved-algorithms` feature, the key exchange methods
/// that are not approved are neither offered nor accepted.
#[cfg(not(feature = "unapproved-algorithms"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_unapproved_kex_is_refused() {
    openssh::check_refused(
        "unapproved kex",
        Refused::Kex,
        UNAPPROVED_KEX
            .iter()
            .map(|&kex| Case::default().with_kex(kex)),
    )
    .await;
}

/// ... nor are the ciphers that are not approved.
#[cfg(not(feature = "unapproved-algorithms"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_unapproved_ciphers_are_refused() {
    openssh::check_refused(
        "unapproved ciphers",
        Refused::Cipher,
        UNAPPROVED_CIPHERS
            .iter()
            .map(|&cipher| Case::default().with_cipher(cipher)),
    )
    .await;
}

/// ... nor the MACs that are not approved.
#[cfg(not(feature = "unapproved-algorithms"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_unapproved_macs_are_refused() {
    openssh::check_refused(
        "unapproved MACs",
        Refused::Mac,
        UNAPPROVED_MACS.iter().map(|&mac| {
            Case::default()
                .with_cipher(cipher::AES_256_CTR)
                .with_mac(mac)
        }),
    )
    .await;
}

/// The algorithms that a russh client offering `client` negotiates with a
/// russh server offering `server`, or why it couldn't.
async fn negotiate(server: Preferred, client: Preferred) -> Result<Names, russh::Error> {
    let (server_stream, client_stream) = tokio::io::duplex(1 << 16);
    let config = server::Config {
        keys: vec![test_keys::key(0)],
        preferred: server,
        ..Default::default()
    };
    tokio::spawn(server::run_stream(Arc::new(config), server_stream, Server));
    let (sender, names) = oneshot::channel();
    let config = client::Config {
        preferred: client,
        ..Default::default()
    };
    let client =
        client::connect_stream(Arc::new(config), client_stream, Client(Some(sender))).await?;
    let names = names.await.expect("the key exchange failed");
    client
        .disconnect(Disconnect::ByApplication, "", "en")
        .await?;
    Ok(names)
}

/// A russh server handler that only does the key exchange.
struct Server;

impl server::Handler for Server {
    type Error = russh::Error;
}

/// A russh client handler that accepts any host key and sends the
/// algorithms of the first key exchange.
struct Client(Option<oneshot::Sender<Names>>);

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        _: Option<&[u8]>,
        names: &Names,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(names.clone());
        }
        Ok(())
    }
}
