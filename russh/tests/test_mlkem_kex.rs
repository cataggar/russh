#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for the ML-KEM hybrid key exchanges (RFC 10042):
//! `mlkem1024nistp384-sha384`, `mlkem768nistp256-sha256` and
//! `mlkem768x25519-sha256`, those whose features are enabled.

mod common;

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use common::test_keys;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::*;

/// The hybrid key exchanges this build negotiates.
fn hybrids() -> Vec<kex::Name> {
    [
        kex::MLKEM1024NISTP384_SHA384,
        kex::MLKEM768NISTP256_SHA256,
        kex::MLKEM768X25519_SHA256,
    ]
    .into_iter()
    .filter(|k| k.is_enabled())
    .collect()
}

/// An enabled key exchange method that isn't a hybrid, to fall back to.
fn fallback() -> Option<kex::Name> {
    Preferred::default()
        .kex
        .iter()
        .copied()
        .find(|k| k.is_enabled() && !k.as_ref().starts_with("mlkem"))
}

/// A client offering `client_kex` connected to a server offering
/// `server_kex`, authenticated, and the key exchange method they agreed on.
async fn connect(
    server_kex: &[kex::Name],
    client_kex: &[kex::Name],
) -> (client::Handle<TestClient>, kex::Name) {
    let _ = env_logger::try_init();

    let client_key = test_keys::key(1);

    let server_config = server::Config {
        inactivity_timeout: None,
        auth_rejection_time: std::time::Duration::from_secs(3),
        keys: vec![test_keys::key(0)],
        preferred: Preferred {
            kex: Cow::Owned(server_kex.to_vec()),
            ..Default::default()
        },
        ..Default::default()
    };

    let server_config = Arc::new(server_config);

    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        server::run_stream(server_config, socket, TestServer {})
            .await
            .unwrap();
    });

    let client_config = client::Config {
        preferred: Preferred {
            kex: Cow::Owned(client_kex.to_vec()),
            ..Default::default()
        },
        ..Default::default()
    };
    let client_config = Arc::new(client_config);

    let negotiated = Arc::new(Mutex::new(None));
    let mut session = client::connect(
        client_config,
        addr,
        TestClient {
            negotiated: negotiated.clone(),
        },
    )
    .await
    .unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(
        authenticated,
        "Authentication should succeed with ML-KEM KEX"
    );

    let negotiated = negotiated.lock().unwrap().expect("kex_done was not called");
    (session, negotiated)
}

/// Sends `payload` on `channel` and checks that the server echoes it.
async fn echo(channel: &mut Channel<client::Msg>, payload: &[u8]) {
    channel.data(payload).await.unwrap();
    match channel.wait().await.unwrap() {
        ChannelMsg::Data { data } => assert_eq!(&*data, payload),
        msg => panic!("Unexpected message: {msg:?}"),
    }
}

#[tokio::test]
async fn test_mlkem_handshake() {
    for kex_alg in hybrids() {
        let (session, negotiated) = connect(&[kex_alg], &[kex_alg]).await;
        assert_eq!(negotiated, kex_alg);

        let mut channel = session.channel_open_session().await.unwrap();
        echo(
            &mut channel,
            format!("test data with {kex_alg:?}").as_bytes(),
        )
        .await;

        channel.eof().await.unwrap();
        session
            .disconnect(Disconnect::ByApplication, "", "")
            .await
            .unwrap();
    }
}

/// A client that prefers a hybrid falls back to another method with a server
/// that offers only that one, and the other way around.
#[tokio::test]
async fn test_mlkem_with_fallback() {
    let Some(fallback) = fallback() else {
        return;
    };
    for kex_alg in hybrids() {
        for (server_kex, client_kex) in [
            (&[fallback][..], &[kex_alg, fallback][..]),
            (&[kex_alg, fallback][..], &[fallback][..]),
        ] {
            let (session, negotiated) = connect(server_kex, client_kex).await;
            assert_eq!(negotiated, fallback);

            let mut channel = session.channel_open_session().await.unwrap();
            echo(&mut channel, b"test with fallback").await;

            channel.eof().await.unwrap();
            session
                .disconnect(Disconnect::ByApplication, "", "")
                .await
                .unwrap();
        }
    }
}

/// The client's preference decides between the hybrids both sides offer.
#[tokio::test]
async fn test_mlkem_client_preference() {
    for kex_alg in hybrids() {
        let (session, negotiated) = connect(&hybrids(), &[kex_alg]).await;
        assert_eq!(negotiated, kex_alg);
        session
            .disconnect(Disconnect::ByApplication, "", "")
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_mlkem_rekey() {
    for kex_alg in hybrids() {
        let (session, _) = connect(&[kex_alg], &[kex_alg]).await;

        let mut channel = session.channel_open_session().await.unwrap();
        echo(&mut channel, b"before rekey").await;

        session.rekey_soon().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        echo(&mut channel, b"after rekey").await;

        channel.eof().await.unwrap();
        session
            .disconnect(Disconnect::ByApplication, "", "")
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_mlkem_multiple_channels() {
    for kex_alg in hybrids() {
        let (session, _) = connect(&[kex_alg], &[kex_alg]).await;

        let mut channel1 = session.channel_open_session().await.unwrap();
        let mut channel2 = session.channel_open_session().await.unwrap();

        echo(&mut channel1, b"channel 1 data").await;
        echo(&mut channel2, b"channel 2 data").await;

        channel1.eof().await.unwrap();
        channel2.eof().await.unwrap();
        session
            .disconnect(Disconnect::ByApplication, "", "")
            .await
            .unwrap();
    }
}

#[derive(Clone)]
struct TestServer {}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: server::VerifiedPublicKey<'_>,
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
        let mut negotiated = self.negotiated.lock().unwrap();
        if negotiated.is_none() {
            *negotiated = Some(names.kex);
        }
        Ok(())
    }
}
