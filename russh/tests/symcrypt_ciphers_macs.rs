//! The ciphers and MACs of the SymCrypt backend against OpenSSH:
//! `cargo test -p russh --no-default-features --features
//! symcrypt,secure-algorithms --test symcrypt_ciphers_macs`. The ciphers and
//! MACs SymCrypt lacks are refused. Those whose features are disabled are
//! skipped (`algorithm_features.rs` checks that they are refused). The
//! default preferences pick AES-GCM, and SHA-256-EtM (or the first enabled
//! MAC), also against a russh server. The OpenSSH cases are skipped when
//! OpenSSH is missing, unless `RUSSH_REQUIRE_SSHD=1`.
#![cfg(all(
    feature = "symcrypt",
    not(feature = "aws-lc-rs"),
    not(feature = "ring")
))]

mod common;

use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Context;
use common::openssh::{self, Case, Query, Refused, Sshd};
use common::test_keys;
use russh::keys::PublicKeyOrCertificate;
use russh::{Disconnect, Names, Preferred, cipher, client, mac, server};
use tokio::sync::oneshot;

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
/// `3des-cbc` feature, and a server offering only it is refused.
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
/// neither offered nor accepted, even with their features.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsupported_macs_are_refused() {
    // Without AES-CTR, the cipher would be refused before the MAC.
    if !cipher::AES_256_CTR.is_enabled() {
        return;
    }
    openssh::check_refused(
        "unsupported MACs",
        Refused::Mac,
        [mac::HMAC_SHA1, mac::HMAC_SHA1_ETM].map(|mac| {
            Case::default()
                .with_cipher(cipher::AES_256_CTR)
                .with_mac(mac)
        }),
    )
    .await;
}

/// What the servers of the default-preference tests offer, in their order:
/// `chacha20-poly1305@openssh.com` and `hmac-sha2-512-etm@openssh.com`
/// first, as OpenSSH and russh's other backends prefer.
const SERVER_CIPHERS: [cipher::Name; 3] = [
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_256_CTR,
];
const SERVER_MACS: [mac::Name; 2] = [mac::HMAC_SHA512_ETM, mac::HMAC_SHA256_ETM];

/// The default preferences, but only AES-CTR, so that a MAC is used.
fn ctr_only() -> Preferred {
    Preferred {
        cipher: Cow::Borrowed(&[cipher::AES_256_CTR]),
        ..Preferred::default()
    }
}

/// Whether this build can negotiate what [`check_default_preferences`]
/// expects: AES-256-GCM, AES-256-CTR and one of [`SERVER_MACS`].
fn default_preferences_are_checkable() -> bool {
    cipher::AES_256_GCM.is_enabled()
        && cipher::AES_256_CTR.is_enabled()
        && SERVER_MACS.iter().any(|mac| mac.is_enabled())
}

/// Checks the algorithms a client negotiated with a server offering
/// [`SERVER_CIPHERS`] and [`SERVER_MACS`]: `default` with the default
/// preferences, `ctr` with [`ctr_only`]. The client's order decides, so it
/// gets AES-GCM and SHA-256-EtM, which SymCrypt runs faster
/// (<https://github.com/cataggar/russh/issues/23>), or the first enabled one
/// of the server's MACs.
fn check_default_preferences(default: &Names, ctr: &Names) {
    let mac = Preferred::default()
        .mac
        .iter()
        .copied()
        .find(|mac| SERVER_MACS.contains(mac))
        .expect("no MAC in common with the server");
    assert_eq!(default.cipher, cipher::AES_256_GCM);
    assert_eq!(ctr.cipher, cipher::AES_256_CTR);
    assert_eq!(ctr.client_mac, mac);
    assert_eq!(ctr.server_mac, mac);
}

/// [`check_default_preferences`] against OpenSSH.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_default_preferences() {
    if !default_preferences_are_checkable() {
        return;
    }
    let Some(openssh) = openssh::available() else {
        return;
    };
    let ciphers = SERVER_CIPHERS.map(|cipher| cipher.as_ref().to_owned());
    let macs = SERVER_MACS.map(|mac| mac.as_ref().to_owned());
    let unsupported = ciphers
        .iter()
        .map(|name| (Query::Cipher, name))
        .chain(macs.iter().map(|name| (Query::Mac, name)))
        .find(|(query, name)| !openssh.supports(*query, name));
    if let Some((_, name)) = unsupported {
        openssh::log_line(&format!(
            "skipped: {} does not support {name}",
            openssh.short_version()
        ));
        return;
    }
    let sshd = Case::default()
        .sshd()
        .ciphers(ciphers.join(","))
        .macs(macs.join(","))
        .start()
        .await
        .expect("starting sshd");
    let default = negotiate_with_sshd(&sshd, Preferred::default()).await;
    let ctr = negotiate_with_sshd(&sshd, ctr_only()).await;
    check_default_preferences(&default, &ctr);
}

/// The algorithms a russh client offering `preferred` negotiates with
/// `sshd`.
async fn negotiate_with_sshd(sshd: &Sshd, preferred: Preferred) -> Names {
    let negotiating = async {
        let mut client = sshd.connect(preferred).await?;
        client.authenticate(None).await?;
        let names = client
            .negotiated()
            .context("Handler::kex_done was never called")?;
        client.disconnect().await?;
        anyhow::Ok(names)
    };
    negotiating
        .await
        .unwrap_or_else(|error| panic!("{error:#}"))
}

/// [`check_default_preferences`] against a russh server.
#[tokio::test]
async fn russh_default_preferences() {
    if !default_preferences_are_checkable() {
        return;
    }
    let default = negotiate_with_russh(Preferred::default()).await;
    let ctr = negotiate_with_russh(ctr_only()).await;
    check_default_preferences(&default, &ctr);
}

/// The algorithms a russh client offering `preferred` negotiates with a
/// russh server offering [`SERVER_CIPHERS`] and [`SERVER_MACS`].
async fn negotiate_with_russh(preferred: Preferred) -> Names {
    let (server_stream, client_stream) = tokio::io::duplex(1 << 16);
    let config = server::Config {
        keys: vec![test_keys::key(0)],
        preferred: Preferred {
            cipher: Cow::Borrowed(&SERVER_CIPHERS),
            mac: Cow::Borrowed(&SERVER_MACS),
            ..Preferred::default()
        },
        ..Default::default()
    };
    tokio::spawn(server::run_stream(Arc::new(config), server_stream, Server));
    let (sender, names) = oneshot::channel();
    let config = client::Config {
        preferred,
        ..Default::default()
    };
    let client = client::connect_stream(Arc::new(config), client_stream, Client(Some(sender)))
        .await
        .expect("connecting");
    let names = names.await.expect("the key exchange failed");
    client
        .disconnect(Disconnect::ByApplication, "", "en")
        .await
        .expect("disconnecting");
    names
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
