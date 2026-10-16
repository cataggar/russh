//! Interop of the SymCrypt backend's key exchanges with OpenSSH and russh,
//! one forced method at a time: `cargo test -p russh --no-default-features
//! --features symcrypt,secure-algorithms --test symcrypt_kex`.
//! `mlkem768x25519-sha256` is skipped when the local OpenSSH is older than
//! 9.9, and the ML-KEM hybrids with the NIST curves, which OpenSSH lacks, are
//! tested against russh. The methods SymCrypt lacks are refused. The methods
//! whose features are disabled are skipped (`algorithm_features.rs` checks
//! that they are refused).
#![cfg(all(
    feature = "symcrypt",
    not(feature = "aws-lc-rs"),
    not(feature = "ring")
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use common::openssh::{self, Case, Refused};
use common::test_keys;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kex() {
    openssh::check_kex(
        Case::default(),
        &[
            kex::MLKEM768X25519_SHA256,
            kex::MLKEM1024NISTP384_SHA384,
            kex::MLKEM768NISTP256_SHA256,
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::ECDH_SHA2_NISTP256,
            kex::ECDH_SHA2_NISTP384,
            kex::ECDH_SHA2_NISTP521,
            kex::DH_GEX_SHA256,
            kex::DH_G14_SHA256,
            kex::DH_G15_SHA512,
            kex::DH_G16_SHA512,
            kex::DH_G17_SHA512,
            kex::DH_G18_SHA512,
        ],
    )
    .await;
}

/// Full russh client-to-russh-server SSH handshakes for the ML-KEM hybrids
/// with the NIST curves, which OpenSSH does not implement, and for every
/// supported FFDH algorithm (including `diffie-hellman-group15-sha512` and
/// `diffie-hellman-group17-sha512`, which OpenSSH does not implement either),
/// if their features are enabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn russh_client_server_handshake() {
    let _ = env_logger::try_init();

    let algorithms = [
        kex::MLKEM1024NISTP384_SHA384,
        kex::MLKEM768NISTP256_SHA256,
        kex::DH_G14_SHA256,
        kex::DH_G15_SHA512,
        kex::DH_G16_SHA512,
        kex::DH_G17_SHA512,
        kex::DH_G18_SHA512,
        kex::DH_GEX_SHA256,
    ];
    for kex_alg in algorithms.into_iter().filter(|k| k.is_enabled()) {
        let server_config = Arc::new(server::Config {
            inactivity_timeout: None,
            auth_rejection_time: std::time::Duration::from_secs(3),
            keys: vec![test_keys::key(0)],
            preferred: Preferred {
                kex: Cow::Owned(vec![kex_alg]),
                ..Default::default()
            },
            ..Default::default()
        });

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();
            server::run_stream(server_config, socket, TestServer)
                .await
                .unwrap();
        });

        let client_config = Arc::new(client::Config {
            preferred: Preferred {
                kex: Cow::Owned(vec![kex_alg]),
                ..Default::default()
            },
            ..Default::default()
        });

        let negotiated = Arc::new(Mutex::new(None));
        let mut session = client::connect(
            client_config,
            addr,
            TestClient {
                negotiated: negotiated.clone(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("handshake failed for {}: {e:?}", kex_alg.as_ref()));

        assert_eq!(*negotiated.lock().unwrap(), Some(kex_alg));

        let authenticated = session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(test_keys::key(1)), None),
            )
            .await
            .unwrap()
            .success();
        assert!(authenticated, "auth failed for {}", kex_alg.as_ref());

        let mut channel = session.channel_open_session().await.unwrap();
        let payload = format!("test payload over {}", kex_alg.as_ref());
        channel.data(payload.as_bytes()).await.unwrap();

        match channel.wait().await.unwrap() {
            ChannelMsg::Data { data } => assert_eq!(&*data, payload.as_bytes()),
            msg => panic!(
                "unexpected channel message for {}: {msg:?}",
                kex_alg.as_ref()
            ),
        }

        channel.eof().await.unwrap();
        session
            .disconnect(Disconnect::ByApplication, "", "")
            .await
            .unwrap();
    }
}

/// The SHA-1 Diffie-Hellman key exchanges, which OpenSSH implements and the
/// backend doesn't, are neither offered nor accepted, even with their
/// features.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsupported_kex_is_refused() {
    openssh::check_refused(
        "unsupported kex",
        Refused::Kex,
        [kex::DH_G1_SHA1, kex::DH_G14_SHA1, kex::DH_GEX_SHA1]
            .map(|kex| Case::default().with_kex(kex)),
    )
    .await;
}

struct TestServer;

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

struct TestClient {
    negotiated: Arc<Mutex<Option<kex::Name>>>,
}

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        *self.negotiated.lock().unwrap() = Some(names.kex);
        Ok(())
    }
}
