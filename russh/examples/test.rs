use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use log::debug;
use russh::server::{Auth, Msg, Server as _, Session, VerifiedPublicKey};
use russh::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let config = russh::server::Config {
        auth_rejection_time: std::time::Duration::from_secs(3),
        keys: vec![russh::keys::generate_secret_key()?],
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        sh.run_on_address(config, ("0.0.0.0", 2222)),
    )
    .await
    .unwrap_or(Ok(()))?;

    Ok(())
}

type ClientChannels = HashMap<(usize, ChannelId), Channel<Msg>>;

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<ClientChannels>>,
    id: usize,
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        debug!("new client");
        let s = self.clone();
        self.id += 1;
        s
    }
}

impl server::Handler for Server {
    type Error = anyhow::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        {
            debug!("channel open session");
            let mut clients = self.clients.lock().unwrap();
            clients.insert((self.id, channel.id()), channel);
        }
        reply.accept().await;
        Ok(())
    }

    /// The client requests a shell.
    #[allow(unused_variables)]
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.request_success();
        Ok(())
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("data: {data:?}");
        {
            let mut clients = self.clients.lock().unwrap();
            for ((_, _channel_id), ref mut channel) in clients.iter_mut() {
                session.data(channel.id(), data.to_vec())?;
            }
        }
        Ok(())
    }
}
