//! Regression test for <https://github.com/Eugeny/russh/issues/774>: the russh
//! server answers an `auth-agent-req@openssh.com` channel request the way
//! OpenSSH's sshd does. The reference sshd comes from `common/openssh.rs`, so
//! the test is skipped without OpenSSH (or fails under `RUSSH_REQUIRE_SSHD`).

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::openssh::{self, Sshd};
use common::test_keys;
use russh::keys::ssh_key;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Preferred, client, server};
use tokio::task::JoinHandle;

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Server;

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: russh::ChannelId,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn reply_is_channel_scoped(mut channel: russh::Channel<client::Msg>) -> bool {
    channel.agent_forward(true).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async move {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) | Some(ChannelMsg::Failure) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

impl Server {
    async fn spawn_and_connect() -> (JoinHandle<()>, client::Handle<Client>) {
        let mut config = server::Config::default();
        config.keys.push(test_keys::key(0));
        let config = Arc::new(config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = server::run_stream(config, socket, Server).await;
        });

        let mut handle = client::connect(Arc::new(client::Config::default()), addr, Client)
            .await
            .unwrap();
        let key = test_keys::key(1);
        handle
            .authenticate_publickey("user", PrivateKeyWithHashAlg::new(Arc::new(key), None))
            .await
            .unwrap();

        (server, handle)
    }
}

#[tokio::test]
async fn russh_matches_openssh() {
    if openssh::available().is_none() {
        return;
    }
    // Dropping `sshd` while panicking prints its configuration and logs.
    let sshd = Sshd::builder()
        .config("AllowAgentForwarding yes")
        .start()
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    let (_server, russh) = Server::spawn_and_connect().await;
    let mut openssh = sshd
        .connect(Preferred::default())
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    openssh
        .authenticate(None)
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));

    let russh_channel = russh.channel_open_session().await.unwrap();
    let openssh_channel = openssh.handle().channel_open_session().await.unwrap();

    let (russh_scoped, openssh_scoped) = tokio::join!(
        reply_is_channel_scoped(russh_channel),
        reply_is_channel_scoped(openssh_channel),
    );
    assert!(
        openssh_scoped,
        "reference sshd did not reply on the channel"
    );
    assert_eq!(russh_scoped, openssh_scoped);
}
