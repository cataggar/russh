//! The algorithm features, with every crypto backend: russh negotiates the
//! key exchange methods, ciphers and MACs whose crate features are enabled,
//! and refuses the others, even if its preferences list them, against russh
//! and against OpenSSH, which offers each of them in turn. `none` is refused
//! too without its feature. The OpenSSH checks are skipped when OpenSSH is
//! missing, unless `RUSSH_REQUIRE_SSHD=1`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Context;
use common::openssh::{self, Case, Refused};
use common::test_keys;
use russh::keys::PublicKeyOrCertificate;
use russh::{AlgorithmKind, Disconnect, Names, Preferred, cipher, client, kex, mac, server};
use tokio::sync::oneshot;

/// The key exchange methods the crypto backend implements (but `none`),
/// enabled or not.
fn implemented_kex() -> Vec<kex::Name> {
    kex::ALL_KEX_ALGORITHMS
        .iter()
        .map(|k| **k)
        .filter(|k| *k != kex::NONE && kex::Name::try_from(k.as_ref()).is_ok())
        .collect()
}

/// The ciphers the crypto backend implements (but `none` and `clear`).
fn implemented_ciphers() -> Vec<cipher::Name> {
    cipher::ALL_CIPHERS
        .iter()
        .map(|c| **c)
        .filter(|c| {
            *c != cipher::NONE && *c != cipher::CLEAR && cipher::Name::try_from(c.as_ref()).is_ok()
        })
        .collect()
}

/// The MACs the crypto backend implements (but `none`).
fn implemented_macs() -> Vec<mac::Name> {
    mac::ALL_MAC_ALGORITHMS
        .iter()
        .map(|m| **m)
        .filter(|m| *m != mac::NONE && mac::Name::try_from(m.as_ref()).is_ok())
        .collect()
}

/// The AES-CTR, CBC and 3DES ciphers, which need a MAC.
const CIPHERS_WITH_A_MAC: &[cipher::Name] = &[
    cipher::AES_256_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CTR,
    cipher::AES_256_CBC,
    cipher::AES_192_CBC,
    cipher::AES_128_CBC,
    #[cfg(feature = "3des-cbc")]
    cipher::TRIPLE_DES_CBC,
];

/// An enabled cipher that needs a MAC, if there is one.
fn enabled_cipher_with_a_mac() -> Option<cipher::Name> {
    let implemented = implemented_ciphers();
    CIPHERS_WITH_A_MAC
        .iter()
        .copied()
        .find(|c| c.is_enabled() && implemented.contains(c))
}

/// The default preferences, but only `cipher`, and `mac` if `cipher` needs
/// one.
fn with_cipher(cipher: cipher::Name, mac: Option<mac::Name>) -> Preferred {
    let mut preferred = Preferred {
        cipher: Cow::Owned(vec![cipher]),
        ..Preferred::default()
    };
    if let Some(mac) = mac {
        preferred.mac = Cow::Owned(vec![mac]);
    }
    preferred
}

/// The default preferences select only enabled algorithms.
#[test]
fn default_preferences_are_enabled() {
    let preferred = Preferred::default();
    assert!(
        preferred
            .kex
            .iter()
            .filter(
                |k| !k.as_ref().starts_with("ext-info-") && !k.as_ref().starts_with("kex-strict-")
            )
            .all(|k| k.is_enabled())
    );
    assert!(preferred.cipher.iter().all(|c| c.is_enabled()));
    assert!(preferred.mac.iter().all(|m| m.is_enabled()));
    assert!(!preferred.kex.contains(&kex::NONE));
    assert!(!preferred.cipher.contains(&cipher::NONE));
}

/// A russh client and server that list only an enabled algorithm negotiate
/// it, for each enabled algorithm the backend implements, including the
/// legacy ones that `Preferred::default()` leaves out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn russh_negotiates_each_enabled_algorithm() {
    for kex_alg in implemented_kex().into_iter().filter(|k| k.is_enabled()) {
        let only = Preferred {
            kex: Cow::Owned(vec![kex_alg]),
            ..Preferred::default()
        };
        let names = negotiate(only.clone(), only)
            .await
            .unwrap_or_else(|error| panic!("{kex_alg:?}: {error}"));
        assert_eq!(names.kex, kex_alg);
    }

    let mac = Preferred::default().mac.first().copied();
    for cipher_alg in implemented_ciphers().into_iter().filter(|c| c.is_enabled()) {
        let needs_mac = CIPHERS_WITH_A_MAC.contains(&cipher_alg);
        if needs_mac && mac.is_none() {
            continue;
        }
        let only = with_cipher(cipher_alg, mac.filter(|_| needs_mac));
        let names = negotiate(only.clone(), only)
            .await
            .unwrap_or_else(|error| panic!("{cipher_alg:?}: {error}"));
        assert_eq!(names.cipher, cipher_alg);
    }

    if let Some(cipher_alg) = enabled_cipher_with_a_mac() {
        for mac_alg in implemented_macs().into_iter().filter(|m| m.is_enabled()) {
            let only = with_cipher(cipher_alg, Some(mac_alg));
            let names = negotiate(only.clone(), only)
                .await
                .unwrap_or_else(|error| panic!("{mac_alg:?}: {error}"));
            assert_eq!(names.client_mac, mac_alg);
            assert_eq!(names.server_mac, mac_alg);
        }
    }

    #[cfg(feature = "ssh-mldsa87-p384")]
    {
        use russh::keys::ssh_key::Algorithm;
        let host_key = russh::keys::generate_secret_key_for(&Algorithm::Mldsa87P384).unwrap();
        let only = Preferred {
            key: Cow::Borrowed(&[Algorithm::Mldsa87P384]),
            ..Preferred::default()
        };
        let names = negotiate_with_keys(vec![host_key], only.clone(), only)
            .await
            .unwrap();
        assert_eq!(names.key, Algorithm::Mldsa87P384);
    }
}

/// Listing algorithms whose features are disabled, on either side, makes the
/// key exchange fail for lack of a common algorithm of that kind: russh
/// neither offers nor accepts them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn russh_refuses_disabled_algorithms() {
    let mut cases = Vec::new();
    for kex_alg in implemented_kex().into_iter().filter(|k| !k.is_enabled()) {
        let only = Preferred {
            kex: Cow::Owned(vec![kex_alg]),
            ..Preferred::default()
        };
        cases.push((format!("{kex_alg:?}"), only, AlgorithmKind::Kex));
    }
    let mac = Preferred::default().mac.first().copied();
    for cipher_alg in implemented_ciphers()
        .into_iter()
        .filter(|c| !c.is_enabled())
    {
        let only = with_cipher(cipher_alg, mac);
        cases.push((format!("{cipher_alg:?}"), only, AlgorithmKind::Cipher));
    }
    if let Some(cipher_alg) = enabled_cipher_with_a_mac() {
        for mac_alg in implemented_macs().into_iter().filter(|m| !m.is_enabled()) {
            let only = with_cipher(cipher_alg, Some(mac_alg));
            cases.push((format!("{mac_alg:?}"), only, AlgorithmKind::Mac));
        }
    }
    #[cfg(not(feature = "ssh-mldsa87-p384"))]
    {
        use russh::keys::ssh_key::Algorithm;
        let only = Preferred {
            key: Cow::Borrowed(&[Algorithm::Mldsa87P384]),
            ..Preferred::default()
        };
        cases.push(("ssh-mldsa87-p384".to_string(), only, AlgorithmKind::Key));
    }
    for (name, only, kind) in cases {
        check_refused(&name, only, kind).await;
    }
}

/// Without the `none` feature, `none` is refused too: no key exchange,
/// encryption or MAC.
#[cfg(not(feature = "none"))]
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
        kex: Preferred::default().kex,
        ..none
    };
    check_refused("cipher none", none_cipher, AlgorithmKind::Cipher).await;
    if let Some(cipher_alg) = enabled_cipher_with_a_mac() {
        let none_mac = with_cipher(cipher_alg, Some(mac::NONE));
        check_refused("MAC none", none_mac, AlgorithmKind::Mac).await;
    }
}

/// Checks that a russh client with `only` fails to negotiate with a russh
/// server with the default preferences, and the other way around, for lack
/// of a common algorithm of kind `kind`.
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

/// Whether OpenSSH is available and supports at least one enabled kex method.
fn openssh_supports_any_enabled_kex() -> bool {
    let Some(openssh) = openssh::available() else {
        return false;
    };
    Preferred::default()
        .kex
        .iter()
        .any(|k| openssh.supports(openssh::Query::Kex, k.as_ref()))
}

/// The default preferences against sshd with its default algorithms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_negotiates_default_preferences() {
    if !openssh_supports_any_enabled_kex() {
        return;
    }
    let sshd = Case::default()
        .sshd()
        .start()
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    let negotiating = async {
        let mut client = sshd.connect(Preferred::default()).await?;
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
    assert!(names.kex.is_enabled(), "{:?}", names.kex);
    assert!(names.cipher.is_enabled(), "{:?}", names.cipher);
}

/// The key exchange methods whose features are disabled are neither offered
/// nor accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_disabled_kex_is_refused() {
    openssh::check_refused(
        "disabled kex",
        Refused::Kex,
        implemented_kex()
            .into_iter()
            .filter(|k| !k.is_enabled())
            .map(|kex| Case::default().with_kex(kex)),
    )
    .await;
}

/// ... nor are the ciphers whose features are disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_disabled_ciphers_are_refused() {
    if !openssh_supports_any_enabled_kex() {
        return;
    }
    let mac = Preferred::default().mac.first().copied();
    openssh::check_refused(
        "disabled ciphers",
        Refused::Cipher,
        implemented_ciphers()
            .into_iter()
            .filter(|c| !c.is_enabled())
            .map(|cipher| {
                let case = Case::default().with_cipher(cipher);
                match mac {
                    Some(mac) if CIPHERS_WITH_A_MAC.contains(&cipher) => case.with_mac(mac),
                    _ => case,
                }
            }),
    )
    .await;
}

/// ... nor the MACs whose features are disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_disabled_macs_are_refused() {
    if !openssh_supports_any_enabled_kex() {
        return;
    }
    let Some(cipher) = enabled_cipher_with_a_mac() else {
        return;
    };
    openssh::check_refused(
        "disabled MACs",
        Refused::Mac,
        implemented_macs()
            .into_iter()
            .filter(|m| !m.is_enabled())
            .map(|mac| Case::default().with_cipher(cipher).with_mac(mac)),
    )
    .await;
}

/// The algorithms that a russh client offering `client` negotiates with a
/// russh server offering `server`, or why it couldn't.
async fn negotiate(server: Preferred, client: Preferred) -> Result<Names, russh::Error> {
    negotiate_with_keys(vec![test_keys::key(0)], server, client).await
}

async fn negotiate_with_keys(
    keys: Vec<russh::keys::PrivateKey>,
    server: Preferred,
    client: Preferred,
) -> Result<Names, russh::Error> {
    let (server_stream, client_stream) = tokio::io::duplex(1 << 16);
    let config = server::Config {
        keys,
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
