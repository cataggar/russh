mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::test_keys;
use rand::Rng;
use russh::Channel;
use russh::client::{self, ChannelOpenHandle, Msg, Session};
use russh::keys::PublicKeyOrCertificate;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Server as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

static DATA_SIZE: usize = 20_000_000;
static THREADS: usize = 16;

#[tokio::test(flavor = "multi_thread")]
async fn test_contention() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Without an AEAD, the debug build's AES-CTR and HMAC are too slow to
    // move the data in time.
    if aead_ciphers().is_empty() {
        return Ok(());
    }

    // The server keeps this listener, so its port can't be taken by anything
    // else before the server listens on it.
    let socket = TcpListener::bind(("127.0.0.1", 0)).await?;
    let ssh_addr = socket.local_addr()?;
    tokio::spawn(Server::run(socket));

    let config = Arc::new(client::Config::default());
    let key = Arc::new(test_keys::key(1));
    let mut data = vec![0u8; DATA_SIZE];
    rand::rng().fill_bytes(&mut data);

    let mut session =
        russh::client::connect(config, ssh_addr, Client(Bytes::from_static(data.leak()))).await?;
    if !session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await?
        .success()
    {
        panic!("Authentication failed")
    };
    // Port 0: the server binds a free port and replies with its number, so
    // there is no window in which the port could be taken by something else.
    let tcp_port = session
        .tcpip_forward("127.0.0.1", 0)
        .await
        .expect("tcpip_forward failed");
    assert_ne!(tcp_port, 0, "the server didn't report the port it bound");
    let tcp_addr = SocketAddr::from(([127, 0, 0, 1], u16::try_from(tcp_port)?));

    timeout(Duration::from_secs(30), async move {
        let mut jh_vec = vec![];
        for i in 1..=THREADS {
            let tcp_stream = TcpStream::connect(tcp_addr).await.unwrap();
            let (mut read_half, mut write_half) = tcp_stream.into_split();
            let jh = tokio::spawn(async move {
                let jh = tokio::spawn(async move {
                    write_half
                        .write_all(&(DATA_SIZE as u32).to_le_bytes()[..])
                        .await
                        .unwrap();
                });
                let mut buf = vec![0u8; DATA_SIZE];
                read_half.read_exact(&mut buf).await.unwrap();
                println!("Join handle #{i} finished");
                jh.abort();
            });
            jh_vec.push(jh);
            tokio::time::sleep(Duration::from_millis(10)).await; // Simulate delay between opening channels
        }
        for jh in jh_vec.into_iter() {
            jh.await.expect("Join handle panicked");
        }
    })
    .await
    .expect("Timeout waiting for test to finish.");

    Ok(())
}

/// The AEAD ciphers whose features are enabled, ChaCha20-Poly1305 first.
fn aead_ciphers() -> Vec<russh::cipher::Name> {
    [
        russh::cipher::CHACHA20_POLY1305,
        russh::cipher::AES_256_GCM,
        russh::cipher::AES_128_GCM,
    ]
    .into_iter()
    .filter(|cipher| cipher.is_enabled())
    .collect()
}

#[derive(Clone)]
struct Server;

impl Server {
    async fn run(socket: TcpListener) {
        let config = Arc::new(server::Config {
            keys: vec![test_keys::key(0)],
            preferred: russh::Preferred {
                cipher: std::borrow::Cow::Owned(aead_ciphers()),
                ..Default::default()
            },
            ..Default::default()
        });
        let mut sh = Server;

        sh.run_on_socket(config, &socket).await.unwrap();
    }
}

impl russh::server::Server for Server {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl russh::server::Handler for Server {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        // Listen before replying: the client connects as soon as the request
        // succeeds. For port 0, the reply carries the port that was bound.
        let listener = TcpListener::bind((address, u16::try_from(*port)?)).await?;
        *port = listener.local_addr()?.port().into();
        let (address, port) = (address.to_owned(), *port);
        let handle = session.handle();
        tokio::spawn(async move {
            while let Ok((mut stream, originator)) = listener.accept().await {
                let handle = handle.clone();
                let address = address.clone();
                tokio::spawn(async move {
                    let channel = handle
                        .channel_open_forwarded_tcpip(
                            address,
                            port,
                            originator.ip().to_string(),
                            originator.port().into(),
                        )
                        .await
                        .unwrap();
                    copy_bidirectional(&mut stream, &mut channel.into_stream())
                        .await
                        .unwrap();
                });
            }
        });
        Ok(true)
    }
}

struct Client(Bytes);

impl russh::client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let bytes = self.0.clone();
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let len = stream.read_u32_le().await.unwrap();
            stream.write_all(&bytes[..len as usize]).await.unwrap();
        });
        reply.accept().await;
        Ok(())
    }
}
