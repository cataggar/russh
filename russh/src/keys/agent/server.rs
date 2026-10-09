use std::collections::HashMap;
use std::marker::Sync;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use futures::future::Future;
use futures::stream::{Stream, StreamExt};
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::PrivateKey;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::sleep;
use {std, tokio};

use super::{Constraint, msg};
use crate::CryptoVec;
use crate::helpers::{EncodedExt, sign_with_hash_alg};
use crate::keys::Error;
use crate::keys::key::PrivateKeyWithHashAlg;

const MAX_AGENT_FRAME_LEN: usize = 256 * 1024;

#[derive(Clone)]
#[allow(clippy::type_complexity)]
struct KeyStore(Arc<RwLock<HashMap<Vec<u8>, (Arc<PrivateKey>, SystemTime, Vec<Constraint>)>>>);

#[derive(Clone)]
struct Lock(Arc<RwLock<CryptoVec>>);

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ServerError<E> {
    E(E),
    Error(Error),
}

pub enum MessageType {
    RequestKeys,
    AddKeys,
    RemoveKeys,
    RemoveAllKeys,
    Sign,
    Lock,
    Unlock,
}

#[cfg_attr(feature = "async-trait", async_trait::async_trait)]
pub trait Agent: Clone + Send + 'static {
    fn confirm(
        self,
        _pk: Arc<PrivateKey>,
    ) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        Box::new(futures::future::ready((self, true)))
    }

    fn confirm_request(&self, _msg: MessageType) -> impl Future<Output = bool> + Send {
        async { true }
    }
}

pub async fn serve<S, L, A>(mut listener: L, agent: A) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    L: Stream<Item = tokio::io::Result<S>> + Unpin,
    A: Agent + Send + Sync + 'static,
{
    let keys = KeyStore(Arc::new(RwLock::new(HashMap::new())));
    let lock = Lock(Arc::new(RwLock::new(CryptoVec::new())));
    while let Some(Ok(stream)) = listener.next().await {
        russh_util::runtime::spawn(
            (Connection {
                lock: lock.clone(),
                keys: keys.clone(),
                agent: Some(agent.clone()),
                s: stream,
                buf: Vec::new(),
            })
            .run(),
        );
    }
    Ok(())
}

impl Agent for () {
    fn confirm(self, _: Arc<PrivateKey>) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        Box::new(futures::future::ready((self, true)))
    }
}

struct Connection<S: AsyncRead + AsyncWrite + Send + 'static, A: Agent> {
    lock: Lock,
    keys: KeyStore,
    agent: Option<A>,
    s: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static, A: Agent + Send + Sync + 'static>
    Connection<S, A>
{
    async fn read_frame(&mut self) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        self.s.read_exact(&mut self.buf).await?;

        let len = BigEndian::read_u32(&self.buf) as usize;
        if len > MAX_AGENT_FRAME_LEN {
            return Err(Error::AgentProtocolError);
        }

        self.buf.clear();
        self.buf.resize(len, 0);
        self.s.read_exact(&mut self.buf).await?;
        Ok(())
    }

    async fn run(mut self) -> Result<(), Error> {
        let mut writebuf = Vec::new();
        loop {
            self.read_frame().await?;
            // respond
            writebuf.clear();
            self.respond(&mut writebuf).await?;
            self.s.write_all(&writebuf).await?;
            self.s.flush().await?
        }
    }

    async fn respond(&mut self, writebuf: &mut Vec<u8>) -> Result<(), Error> {
        let is_locked = {
            if let Ok(password) = self.lock.0.read() {
                !password.is_empty()
            } else {
                true
            }
        };
        writebuf.extend_from_slice(&[0, 0, 0, 0]);
        let agentref = self.agent.as_ref().ok_or(Error::AgentFailure)?;

        match self.buf.split_first() {
            Some((&11, _))
                if !is_locked && agentref.confirm_request(MessageType::RequestKeys).await =>
            {
                // request identities
                if let Ok(keys) = self.keys.0.read() {
                    msg::IDENTITIES_ANSWER.encode(writebuf)?;
                    (keys.len() as u32).encode(writebuf)?;
                    for (k, _) in keys.iter() {
                        k.encode(writebuf)?;
                        "".encode(writebuf)?;
                    }
                } else {
                    msg::FAILURE.encode(writebuf)?
                }
            }
            Some((&13, mut r))
                if !is_locked && agentref.confirm_request(MessageType::Sign).await =>
            {
                // sign request
                let agent = self.agent.take().ok_or(Error::AgentFailure)?;
                let (agent, signed) = self.try_sign(agent, &mut r, writebuf).await?;
                self.agent = Some(agent);
                if signed {
                    return Ok(());
                } else {
                    writebuf.resize(4, 0);
                    writebuf.push(msg::FAILURE)
                }
            }
            Some((&17, mut r))
                if !is_locked && agentref.confirm_request(MessageType::AddKeys).await =>
            {
                // add identity
                if let Ok(true) = self.add_key(&mut r, false, writebuf).await {
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Some((&18, mut r))
                if !is_locked && agentref.confirm_request(MessageType::RemoveKeys).await =>
            {
                // remove identity
                if let Ok(true) = self.remove_identity(&mut r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Some((&19, _))
                if !is_locked && agentref.confirm_request(MessageType::RemoveAllKeys).await =>
            {
                // remove all identities
                if let Ok(mut keys) = self.keys.0.write() {
                    keys.clear();
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Some((&22, mut r))
                if !is_locked && agentref.confirm_request(MessageType::Lock).await =>
            {
                // lock
                if let Ok(()) = self.lock(&mut r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Some((&23, mut r))
                if is_locked && agentref.confirm_request(MessageType::Unlock).await =>
            {
                // unlock
                if let Ok(true) = self.unlock(&mut r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Some((&25, mut r))
                if !is_locked && agentref.confirm_request(MessageType::AddKeys).await =>
            {
                // add identity constrained
                if let Ok(true) = self.add_key(&mut r, true, writebuf).await {
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            _ => {
                // Message not understood
                writebuf.push(msg::FAILURE)
            }
        }
        let len = writebuf.len() - 4;
        BigEndian::write_u32(&mut writebuf[..], len as u32);
        Ok(())
    }

    fn lock<R: Reader>(&self, r: &mut R) -> Result<(), Error> {
        let password = Bytes::decode(r)?;
        let mut lock = self.lock.0.write().or(Err(Error::AgentFailure))?;
        lock.extend(&password);
        Ok(())
    }

    fn unlock<R: Reader>(&self, r: &mut R) -> Result<bool, Error> {
        let password = Bytes::decode(r)?;
        let mut lock = self.lock.0.write().or(Err(Error::AgentFailure))?;
        if bool::from(lock[..].ct_eq(&password)) {
            lock.clear();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_identity<R: Reader>(&self, r: &mut R) -> Result<bool, Error> {
        if let Ok(mut keys) = self.keys.0.write() {
            if keys.remove(&Bytes::decode(r)?.to_vec()).is_some() {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    async fn add_key<R: Reader>(
        &self,
        r: &mut R,
        constrained: bool,
        writebuf: &mut Vec<u8>,
    ) -> Result<bool, Error> {
        let (blob, key_pair) = {
            #[cfg(not(russh_backend = "symcrypt"))]
            let keypair = ssh_key::private::KeypairData::decode(r)?;
            #[cfg(russh_backend = "symcrypt")]
            let keypair = crate::keys::format::openssh::decode_keypair(r)?;
            let private_key = ssh_key::private::PrivateKey::new(keypair, "")?;
            let _comment = String::decode(r)?;

            (private_key.public_key().key_data().encoded()?, private_key)
        };

        let mut c = Vec::new();
        let mut lifetime = None;
        if constrained {
            while let Ok(t) = u8::decode(r) {
                if t == msg::CONSTRAIN_LIFETIME {
                    if lifetime.is_some() {
                        return Ok(false);
                    }
                    let seconds = u32::decode(r)?;
                    lifetime = Some(seconds);
                    c.push(Constraint::KeyLifetime { seconds });
                } else if t == msg::CONSTRAIN_CONFIRM {
                    c.push(Constraint::Confirm)
                } else {
                    return Ok(false);
                }
            }
        }
        let now = SystemTime::now();
        self.keys
            .0
            .write()
            .or(Err(Error::AgentFailure))?
            .insert(blob.clone(), (Arc::new(key_pair), now, c));
        if let Some(seconds) = lifetime {
            let keys = self.keys.clone();
            russh_util::runtime::spawn(async move {
                sleep(Duration::from_secs(seconds as u64)).await;
                if let Ok(mut keys) = keys.0.write() {
                    let delete = if let Some(&(_, time, _)) = keys.get(&blob) {
                        time == now
                    } else {
                        false
                    };
                    if delete {
                        keys.remove(&blob);
                    }
                }
            });
        }
        writebuf.push(msg::SUCCESS);
        Ok(true)
    }

    async fn try_sign<R: Reader>(
        &self,
        agent: A,
        r: &mut R,
        writebuf: &mut Vec<u8>,
    ) -> Result<(A, bool), Error> {
        let mut needs_confirm = false;
        let key = {
            let blob = Bytes::decode(r)?;
            let k = self.keys.0.read().or(Err(Error::AgentFailure))?;
            if let Some((key, _, constraints)) = k.get(&blob.to_vec()) {
                if constraints.contains(&Constraint::Confirm) {
                    needs_confirm = true;
                }
                key.clone()
            } else {
                return Ok((agent, false));
            }
        };
        let agent = if needs_confirm {
            let (agent, ok) = {
                let _pk = key.clone();
                Box::new(futures::future::ready((agent, true)))
            }
            .await;
            if !ok {
                return Ok((agent, false));
            }
            agent
        } else {
            agent
        };
        writebuf.push(msg::SIGN_RESPONSE);
        let data = Bytes::decode(r)?;

        // SymCrypt has no SHA-1 RSA signatures (`ssh-rsa`): sign RSA with the
        // SHA-2 hash that the flags ask for, as OpenSSH's agent does.
        #[cfg(russh_backend = "symcrypt")]
        let hash_alg = {
            let flags = u32::decode(r).unwrap_or(0);
            if flags & msg::RSA_SHA2_256 != 0 {
                Some(crate::keys::HashAlg::Sha256)
            } else if flags & msg::RSA_SHA2_512 != 0 {
                Some(crate::keys::HashAlg::Sha512)
            } else {
                None
            }
        };
        #[cfg(not(russh_backend = "symcrypt"))]
        let hash_alg = None;

        sign_with_hash_alg(&PrivateKeyWithHashAlg::new(key, hash_alg), &data)?.encode(writebuf)?;

        let len = writebuf.len();
        BigEndian::write_u32(writebuf, (len - 4) as u32);

        Ok((agent, true))
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::AsyncWriteExt;

    use super::{Connection, KeyStore, Lock, MAX_AGENT_FRAME_LEN};
    use crate::keys::Error;

    #[test]
    fn oversized_agent_request_is_rejected_before_allocation() -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        runtime.block_on(async {
            let (server, mut client) = tokio::io::duplex(64);
            let connection = Connection {
                lock: Lock(std::sync::Arc::new(std::sync::RwLock::new(
                    crate::CryptoVec::new(),
                ))),
                keys: KeyStore(std::sync::Arc::new(std::sync::RwLock::new(
                    std::collections::HashMap::new(),
                ))),
                agent: Some(()),
                s: server,
                buf: Vec::new(),
            };
            let server = tokio::spawn(async move { connection.run().await });

            let mut frame = [0u8; 4];
            BigEndian::write_u32(&mut frame, (MAX_AGENT_FRAME_LEN + 1) as u32);
            client.write_all(&frame).await?;
            drop(client);

            let err = server.await.expect("server task").unwrap_err();
            assert!(matches!(err, Error::AgentProtocolError));
            Ok::<(), std::io::Error>(())
        })?;

        Ok(())
    }

    /// With SymCrypt, keys added to the agent are decoded with SymCrypt's
    /// checks (a short ECDSA scalar too), and RSA keys sign with the SHA-2
    /// hash that the request's flags select.
    #[cfg(russh_backend = "symcrypt")]
    #[tokio::test]
    async fn symcrypt_agent_adds_keys_and_signs() -> Result<(), Box<dyn std::error::Error>> {
        use ssh_encoding::Decode;

        use crate::keys::agent::AgentIdentity;
        use crate::keys::agent::client::AgentClient;
        use crate::keys::{HashAlg, decode_secret_key};

        let (server, client) = tokio::io::duplex(1 << 16);
        let connection = Connection {
            lock: Lock(std::sync::Arc::new(std::sync::RwLock::new(
                crate::CryptoVec::new(),
            ))),
            keys: KeyStore(std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            ))),
            agent: Some(()),
            s: server,
            buf: Vec::new(),
        };
        tokio::spawn(async move { connection.run().await });
        let mut client = AgentClient::connect(client);

        for (key, hash_alg) in [
            (include_str!("../../../tests/data/keys/ecdsa-p256"), None),
            (include_str!("../../../tests/data/keys/ecdsa-p256-short"), None),
            (include_str!("../../../tests/data/keys/ecdsa-p384"), None),
            (
                include_str!("../../../tests/data/keys/rsa-2048"),
                Some(HashAlg::Sha256),
            ),
            (
                include_str!("../../../tests/data/keys/rsa-2048"),
                Some(HashAlg::Sha512),
            ),
        ] {
            let key = decode_secret_key(key, None)?;
            client.add_identity(&key, &[]).await?;
            let data = b"signed by the agent".to_vec();
            let identity = AgentIdentity::from(key.public_key().clone());
            let signed = client.sign_request(&identity, hash_alg, data.clone()).await?;
            let mut signature = signed.strip_prefix(&data[..]).ok_or("no data")?;
            u32::decode(&mut signature)?;
            let signature = ssh_key::Signature::decode(&mut signature)?;
            crate::crypto::verify(key.public_key().key_data(), &data, &signature)?;
        }
        Ok(())
    }
}
