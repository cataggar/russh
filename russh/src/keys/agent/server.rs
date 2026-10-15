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
use crate::helpers::sign_with_hash_alg;
use crate::keys::Error;
use crate::keys::key::PrivateKeyWithHashAlg;

const MAX_AGENT_FRAME_LEN: usize = 256 * 1024;

#[derive(Clone)]
#[allow(clippy::type_complexity)]
struct KeyStore(Arc<RwLock<HashMap<Vec<u8>, (Arc<PrivateKey>, SystemTime, Vec<Constraint>)>>>);

#[derive(Default)]
struct LockState {
    passphrase: CryptoVec,
    failed_unlocks: u32,
}

#[derive(Clone, Default)]
struct Lock(Arc<RwLock<LockState>>);

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
    let lock = Lock::default();
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
            if let Ok(lock) = self.lock.0.read() {
                !lock.passphrase.is_empty()
            } else {
                true
            }
        };
        writebuf.extend_from_slice(&[0, 0, 0, 0]);
        let agentref = self.agent.as_ref().ok_or(Error::AgentFailure)?;

        match self.buf.split_first() {
            Some((&11, _)) if agentref.confirm_request(MessageType::RequestKeys).await => {
                // request identities
                if is_locked {
                    msg::IDENTITIES_ANSWER.encode(writebuf)?;
                    0u32.encode(writebuf)?;
                } else if let Ok(keys) = self.keys.0.read() {
                    msg::IDENTITIES_ANSWER.encode(writebuf)?;
                    (keys.len() as u32).encode(writebuf)?;
                    for (k, (key, _, _)) in keys.iter() {
                        k.encode(writebuf)?;
                        key.comment().encode(writebuf)?;
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
                let (agent, signed) = self.try_sign(agent, &mut r, writebuf).await;
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
                    crate::crypto::release_dropped_keys();
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
                crate::crypto::release_dropped_keys();
            }
            Some((&22, mut r))
                if !is_locked && agentref.confirm_request(MessageType::Lock).await =>
            {
                // lock
                if let Ok(true) = self.lock(&mut r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Some((&23, mut r))
                if is_locked && agentref.confirm_request(MessageType::Unlock).await =>
            {
                // unlock
                if let Ok(true) = self.unlock(&mut r).await {
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

    fn lock<R: Reader>(&self, r: &mut R) -> Result<bool, Error> {
        let password = Bytes::decode(r)?;
        if password.is_empty() {
            return Ok(false);
        }
        let mut lock = self.lock.0.write().or(Err(Error::AgentFailure))?;
        lock.passphrase.extend(&password);
        lock.failed_unlocks = 0;
        Ok(true)
    }

    async fn unlock<R: Reader>(&self, r: &mut R) -> Result<bool, Error> {
        let password = Bytes::decode(r)?;
        let delay = {
            let mut lock = self.lock.0.write().or(Err(Error::AgentFailure))?;
            if bool::from(lock.passphrase[..].ct_eq(&password)) {
                lock.passphrase.clear();
                lock.failed_unlocks = 0;
                return Ok(true);
            }
            lock.failed_unlocks = lock.failed_unlocks.saturating_add(1).min(100);
            Duration::from_millis(100 * u64::from(lock.failed_unlocks))
        };
        sleep(delay).await;
        Ok(false)
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
            let (blob, keypair) = crate::keys::format::openssh::decode_agent_key(r)?;
            let comment = String::decode(r)?;
            let private_key = ssh_key::private::PrivateKey::new(keypair, comment)?;
            if !crate::crypto::can_sign_with_key_type(&private_key.algorithm()) {
                return Ok(false);
            }

            (blob, private_key)
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
        let replaced = self
            .keys
            .0
            .write()
            .or(Err(Error::AgentFailure))?
            .insert(blob.clone(), (Arc::new(key_pair), now, c));
        if replaced.is_some() {
            drop(replaced);
            crate::crypto::release_dropped_keys();
        }
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
                crate::crypto::release_dropped_keys();
            });
        }
        writebuf.push(msg::SUCCESS);
        Ok(true)
    }

    async fn try_sign<R: Reader>(&self, agent: A, r: &mut R, writebuf: &mut Vec<u8>) -> (A, bool) {
        let Ok(blob) = Bytes::decode(r) else {
            return (agent, false);
        };
        let mut needs_confirm = false;
        let key = {
            let Ok(k) = self.keys.0.read() else {
                return (agent, false);
            };
            if let Some((key, _, constraints)) = k.get(blob.as_ref()) {
                if constraints.contains(&Constraint::Confirm) {
                    needs_confirm = true;
                }
                key.clone()
            } else {
                return (agent, false);
            }
        };
        let agent = if needs_confirm {
            let (agent, ok) = {
                let _pk = key.clone();
                Box::new(futures::future::ready((agent, true)))
            }
            .await;
            if !ok {
                return (agent, false);
            }
            agent
        } else {
            agent
        };
        let Ok(data) = Bytes::decode(r) else {
            return (agent, false);
        };

        // Sign RSA with the hash that the flags select, as OpenSSH's agent
        // does (`agent_decode_alg` in ssh-agent.c): SHA-256 if
        // SSH_AGENT_RSA_SHA2_256 is set, else SHA-512 if
        // SSH_AGENT_RSA_SHA2_512 is, else SHA-1 (`ssh-rsa`), which the
        // SymCrypt backend cannot make. `PrivateKeyWithHashAlg::new` drops
        // the hash of other keys, so they ignore the flags. A request without
        // flags counts as one with none set.
        let flags = u32::decode(r).unwrap_or(0);
        let hash_alg = if flags & msg::RSA_SHA2_256 != 0 {
            Some(crate::keys::HashAlg::Sha256)
        } else if flags & msg::RSA_SHA2_512 != 0 {
            Some(crate::keys::HashAlg::Sha512)
        } else {
            None
        };

        let Ok(signature) = sign_with_hash_alg(&PrivateKeyWithHashAlg::new(key, hash_alg), &data)
        else {
            return (agent, false);
        };
        writebuf.push(msg::SIGN_RESPONSE);
        if signature.encode(writebuf).is_err() {
            return (agent, false);
        }

        let len = writebuf.len();
        BigEndian::write_u32(writebuf, (len - 4) as u32);

        (agent, true)
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
                lock: Lock::default(),
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

    /// An RSA key signs with the hash that the sign request's flags select,
    /// as in OpenSSH's agent (`agent_decode_alg` in ssh-agent.c): SHA-256 if
    /// `SSH_AGENT_RSA_SHA2_256` is set, else SHA-512 if
    /// `SSH_AGENT_RSA_SHA2_512` is, else SHA-1 (`ssh-rsa`). Other keys
    /// ignore the flags.
    #[cfg(any(feature = "rsa", russh_backend = "symcrypt"))]
    #[tokio::test]
    async fn agent_signs_rsa_with_the_hash_the_flags_select()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::msg::{RSA_SHA2_256, RSA_SHA2_512};
        use crate::keys::agent::client::AgentClient;
        use crate::keys::decode_secret_key;

        let rsa = decode_secret_key(include_str!("../../../tests/data/keys/rsa-2048"), None)?;
        let ecdsa = decode_secret_key(include_str!("../../../tests/data/keys/ecdsa-p256"), None)?;
        let (server, client) = tokio::io::duplex(1 << 16);
        let connection = Connection {
            lock: Lock::default(),
            keys: KeyStore(std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            ))),
            agent: Some(()),
            s: server,
            buf: Vec::new(),
        };
        tokio::spawn(async move { connection.run().await });
        let mut client = AgentClient::connect(client);
        client.add_identity(&rsa, &[]).await?;
        client.add_identity(&ecdsa, &[]).await?;
        let mut stream = client.into_inner();

        let data = b"signed by the agent";
        #[allow(unused_mut)]
        let mut cases = vec![
            (&rsa, RSA_SHA2_256, "rsa-sha2-256"),
            (&rsa, RSA_SHA2_512, "rsa-sha2-512"),
            (&rsa, RSA_SHA2_256 | RSA_SHA2_512, "rsa-sha2-256"),
            (&ecdsa, 0, "ecdsa-sha2-nistp256"),
            (&ecdsa, RSA_SHA2_256 | RSA_SHA2_512, "ecdsa-sha2-nistp256"),
        ];
        #[cfg(not(russh_backend = "symcrypt"))]
        cases.push((&rsa, 0, "ssh-rsa"));
        for (key, flags, name) in cases {
            let signature = sign_request(&mut stream, key.public_key(), data, flags).await?;
            assert_eq!(signature.algorithm().as_str(), name, "flags {flags}");
            crate::crypto::verify(key.public_key().key_data(), data, &signature)?;
        }

        // SymCrypt has no SHA-1 RSA signatures: the request fails with
        // SSH_AGENT_FAILURE, and the connection stays open for later requests.
        #[cfg(russh_backend = "symcrypt")]
        {
            assert!(
                sign_request(&mut stream, rsa.public_key(), data, 0)
                    .await
                    .is_err()
            );
            let signature = sign_request(&mut stream, rsa.public_key(), data, RSA_SHA2_256).await?;
            assert_eq!(signature.algorithm().as_str(), "rsa-sha2-256");
            crate::crypto::verify(rsa.public_key().key_data(), data, &signature)?;
        }
        Ok(())
    }

    /// Sends an `SSH_AGENTC_SIGN_REQUEST` of `data` for `key` with `flags`,
    /// and returns the signature of the `SSH_AGENT_SIGN_RESPONSE`.
    #[cfg(any(feature = "rsa", russh_backend = "symcrypt"))]
    async fn sign_request(
        stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        key: &ssh_key::PublicKey,
        data: &[u8],
        flags: u32,
    ) -> Result<ssh_key::Signature, Box<dyn std::error::Error>> {
        use ssh_encoding::{Decode, Encode};
        use tokio::io::AsyncReadExt;

        use super::msg;
        use crate::helpers::EncodedExt;

        let mut request = vec![0; 4];
        msg::SIGN_REQUEST.encode(&mut request)?;
        key.key_data().encoded()?.encode(&mut request)?;
        data.encode(&mut request)?;
        flags.encode(&mut request)?;
        let len = request.len() - 4;
        BigEndian::write_u32(&mut request, len as u32);
        stream.write_all(&request).await?;

        let mut len = [0; 4];
        stream.read_exact(&mut len).await?;
        let mut response = vec![0; BigEndian::read_u32(&len) as usize];
        stream.read_exact(&mut response).await?;
        let mut response = &response[..];
        if u8::decode(&mut response)? != msg::SIGN_RESPONSE {
            return Err("the agent did not sign".into());
        }
        let signature = Vec::<u8>::decode(&mut response)?;
        Ok(ssh_key::Signature::decode(&mut &signature[..])?)
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
            lock: Lock::default(),
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
            (
                include_str!("../../../tests/data/keys/ecdsa-p256-short"),
                None,
            ),
            (include_str!("../../../tests/data/keys/ecdsa-p384"), None),
            (include_str!("../../../tests/data/keys/ecdsa-p521"), None),
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
            let signed = client
                .sign_request(&identity, hash_alg, data.clone())
                .await?;
            let mut signature = signed.strip_prefix(&data[..]).ok_or("no data")?;
            u32::decode(&mut signature)?;
            let signature = ssh_key::Signature::decode(&mut signature)?;
            crate::crypto::verify(key.public_key().key_data(), &data, &signature)?;
        }
        Ok(())
    }

    /// ECDSA keys whose private scalar is an `mpint` shorter than ssh-key
    /// reads, added as OpenSSH's `ssh-add` adds them (without leading zeros;
    /// russh's client writes them padded), with and without constraints, are
    /// added and sign with every backend (cataggar/russh#31).
    #[tokio::test]
    async fn adds_short_ecdsa_scalars_and_signs() -> Result<(), Box<dyn std::error::Error>> {
        use ssh_encoding::{Decode, Encode};
        use ssh_key::private::KeypairData;
        use tokio::io::AsyncReadExt;

        use super::msg;
        use crate::keys::agent::AgentIdentity;
        use crate::keys::agent::client::AgentClient;
        use crate::keys::decode_secret_key;

        let (server, mut stream) = tokio::io::duplex(1 << 16);
        let connection = Connection {
            lock: Lock::default(),
            keys: KeyStore(std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            ))),
            agent: Some(()),
            s: server,
            buf: Vec::new(),
        };
        tokio::spawn(async move { connection.run().await });

        let mut keys = Vec::new();
        for (key, constraints) in [
            (
                include_str!("../../../tests/data/keys/ecdsa-p256-short"),
                &[][..],
            ),
            (
                include_str!("../../../tests/data/keys/ecdsa-p384-short"),
                &[msg::CONSTRAIN_CONFIRM][..],
            ),
            (
                include_str!("../../../tests/data/keys/ecdsa-p521-short"),
                &[msg::CONSTRAIN_LIFETIME, 0, 0, 0x0e, 0x10][..],
            ),
        ] {
            let key = decode_secret_key(key, None)?;
            let KeypairData::Ecdsa(pair) = key.key_data() else {
                return Err("not ECDSA".into());
            };
            let scalar = pair.private_key_bytes();
            let scalar = scalar
                .get(scalar.iter().take_while(|&&b| b == 0).count()..)
                .ok_or("no scalar")?;
            assert_eq!(scalar.len(), 31, "{:?}", key.algorithm());

            let mut frame = vec![0; 4];
            frame.push(if constraints.is_empty() {
                msg::ADD_IDENTITY
            } else {
                msg::ADD_ID_CONSTRAINED
            });
            key.algorithm().as_str().encode(&mut frame)?;
            pair.curve().as_str().encode(&mut frame)?;
            pair.public_key_bytes().encode(&mut frame)?;
            scalar.encode(&mut frame)?;
            "russh-test".encode(&mut frame)?;
            frame.extend_from_slice(constraints);
            let len = u32::try_from(frame.len() - 4)?;
            BigEndian::write_u32(&mut frame, len);
            stream.write_all(&frame).await?;
            let mut reply = [0; 5];
            stream.read_exact(&mut reply).await?;
            assert_eq!(reply, [0, 0, 0, 1, msg::SUCCESS], "{:?}", key.algorithm());
            keys.push(key);
        }

        let mut client = AgentClient::connect(stream);
        assert_eq!(client.request_identities().await?.len(), keys.len());
        for key in keys {
            let data = b"signed by the agent".to_vec();
            let identity = AgentIdentity::from(key.public_key().clone());
            let signed = client.sign_request(&identity, None, data.clone()).await?;
            let mut signature = signed.strip_prefix(&data[..]).ok_or("no data")?;
            u32::decode(&mut signature)?;
            let signature = ssh_key::Signature::decode(&mut signature)?;
            crate::crypto::verify(key.public_key().key_data(), &data, &signature)?;
        }
        Ok(())
    }

    /// A failed sign request (for an unknown key or a malformed request)
    /// answers `SSH_AGENT_FAILURE` without dropping the connection, and
    /// `add_identity` refuses keys that the backend cannot sign with.
    #[tokio::test]
    async fn failed_sign_and_unsupported_key_do_not_close_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::AsyncReadExt;

        use super::msg;
        use crate::keys::agent::client::AgentClient;
        use crate::keys::generate_secret_key;

        let (server, mut stream) = tokio::io::duplex(1 << 16);
        let connection = Connection {
            lock: Lock::default(),
            keys: KeyStore(std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            ))),
            agent: Some(()),
            s: server,
            buf: Vec::new(),
        };
        tokio::spawn(async move { connection.run().await });

        // Truncated SIGN_REQUEST body answers SSH_AGENT_FAILURE instead of
        // closing the connection.
        stream.write_all(&[0, 0, 0, 1, msg::SIGN_REQUEST]).await?;
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).await?;
        assert_eq!(reply, [0, 0, 0, 1, msg::FAILURE]);

        let mut client = AgentClient::connect(stream);
        let key = generate_secret_key()?;
        // Unknown key answers SSH_AGENT_FAILURE.
        assert!(matches!(
            client
                .sign_request_signature(key.public_key(), None, b"data")
                .await,
            Err(Error::AgentFailure)
        ));

        // Keys that the backend cannot sign with are refused on add.
        #[cfg(not(feature = "dsa"))]
        {
            use ssh_key::Mpint;
            use ssh_key::private::{DsaKeypair, DsaPrivateKey, KeypairData};
            use ssh_key::public::DsaPublicKey;

            let dsa_pub = DsaPublicKey::new(
                Mpint::from_positive_bytes(&[3]),
                Mpint::from_positive_bytes(&[2]),
                Mpint::from_positive_bytes(&[2]),
                Mpint::from_positive_bytes(&[2]),
            )?;
            let dsa_priv = DsaPrivateKey::new(Mpint::from_positive_bytes(&[1]))?;
            let dsa = ssh_key::PrivateKey::new(
                KeypairData::Dsa(DsaKeypair::new(dsa_pub, dsa_priv)?),
                "",
            )?;
            assert!(matches!(
                client.add_identity(&dsa, &[]).await,
                Err(Error::AgentFailure)
            ));
            assert!(client.request_identities().await?.is_empty());
        }
        #[cfg(all(russh_backend = "symcrypt", not(russh_ed25519_aws_lc)))]
        {
            let ed25519 = crate::keys::decode_secret_key(
                include_str!("../../../tests/data/keys/ed25519"),
                None,
            )?;
            assert!(matches!(
                client.add_identity(&ed25519, &[]).await,
                Err(Error::AgentFailure)
            ));
            assert!(client.request_identities().await?.is_empty());
        }
        #[cfg(all(not(russh_backend = "symcrypt"), not(feature = "rsa")))]
        {
            let rsa = crate::keys::decode_secret_key(
                include_str!("../../../tests/data/keys/rsa-2048"),
                None,
            )?;
            assert!(matches!(
                client.add_identity(&rsa, &[]).await,
                Err(Error::AgentFailure)
            ));
            assert!(client.request_identities().await?.is_empty());
        }

        // The connection still works for a supported key.
        client.add_identity(&key, &[]).await?;
        let sig = client
            .sign_request_signature(key.public_key(), None, b"data")
            .await?;
        crate::crypto::verify(key.public_key().key_data(), b"data", &sig)?;
        Ok(())
    }

    /// Failed unlock attempts wait 0.1 s more after each failure, and a
    /// successful unlock resets the counter.
    #[tokio::test]
    async fn failed_unlock_delays_increase_and_reset_on_success()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::{Duration, Instant};

        use crate::keys::agent::client::AgentClient;

        let lock = Lock::default();
        let (server, client) = tokio::io::duplex(1 << 16);
        let connection = Connection {
            lock: lock.clone(),
            keys: KeyStore(std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            ))),
            agent: Some(()),
            s: server,
            buf: Vec::new(),
        };
        tokio::spawn(async move { connection.run().await });
        let mut client = AgentClient::connect(client);

        client.lock(b"secret").await?;
        for attempt in 1..=2u32 {
            let start = Instant::now();
            assert!(matches!(
                client.unlock(b"wrong").await,
                Err(Error::AgentFailure)
            ));
            assert!(
                start.elapsed() >= Duration::from_millis(90 * u64::from(attempt)),
                "attempt {attempt}: {:?}",
                start.elapsed()
            );
            assert_eq!(lock.0.read().unwrap().failed_unlocks, attempt);
        }

        client.unlock(b"secret").await?;
        assert_eq!(lock.0.read().unwrap().failed_unlocks, 0);

        client.lock(b"secret").await?;
        assert!(matches!(
            client.unlock(b"wrong").await,
            Err(Error::AgentFailure)
        ));
        assert_eq!(lock.0.read().unwrap().failed_unlocks, 1);
        Ok(())
    }

    /// Certificates added to the agent (including short ECDSA scalars and RSA
    /// certificates) are listed with their comments and sign requests.
    #[tokio::test]
    async fn holds_and_signs_with_certificates() -> Result<(), Box<dyn std::error::Error>> {
        use ssh_encoding::Decode;
        use ssh_key::certificate::{Builder, CertType};

        use crate::keys::agent::AgentIdentity;
        use crate::keys::agent::client::AgentClient;
        use crate::keys::key::safe_rng;
        use crate::keys::{certificate, decode_secret_key, generate_secret_key};

        let (server, client) = tokio::io::duplex(1 << 16);
        let connection = Connection {
            lock: Lock::default(),
            keys: KeyStore(std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            ))),
            agent: Some(()),
            s: server,
            buf: Vec::new(),
        };
        tokio::spawn(async move { connection.run().await });
        let mut client = AgentClient::connect(client);

        let ca = generate_secret_key()?;
        #[allow(unused_mut)]
        let mut cases = vec![
            (
                decode_secret_key(include_str!("../../../tests/data/keys/ecdsa-p256"), None)?,
                None,
                "ecdsa-cert-comment",
            ),
            (
                decode_secret_key(
                    include_str!("../../../tests/data/keys/ecdsa-p256-short"),
                    None,
                )?,
                None,
                "short-ecdsa-cert-comment",
            ),
        ];
        #[cfg(any(not(russh_backend = "symcrypt"), russh_ed25519_aws_lc))]
        cases.push((
            decode_secret_key(include_str!("../../../tests/data/keys/ed25519"), None)?,
            None,
            "ed25519-cert-comment",
        ));
        #[cfg(any(feature = "rsa", russh_backend = "symcrypt"))]
        cases.push((
            decode_secret_key(include_str!("../../../tests/data/keys/rsa-2048"), None)?,
            Some(crate::keys::HashAlg::Sha512),
            "rsa-cert-comment",
        ));

        for (mut key, hash_alg, comment) in cases {
            key.set_comment(comment);
            let mut builder =
                Builder::new_with_random_nonce(&mut safe_rng(), key.public_key(), 0, u64::MAX - 1)?;
            builder.cert_type(CertType::User)?;
            builder.key_id(comment)?;
            builder.valid_principal("alice")?;
            let cert = certificate::sign(builder, &ca)?;

            // Mismatched key and certificate are rejected.
            assert!(matches!(
                client.add_certificate(&cert, &ca, &[]).await,
                Err(Error::KeyIsCorrupt)
            ));

            client.add_certificate(&cert, &key, &[]).await?;
            let identities = client.request_identities().await?;
            assert_eq!(identities.len(), 1);
            assert_eq!(identities[0].comment(), comment);
            let AgentIdentity::Certificate {
                ref certificate, ..
            } = identities[0]
            else {
                return Err("expected certificate identity".into());
            };
            assert_eq!(certificate.to_bytes()?, cert.to_bytes()?);

            let data = b"signed with certificate".to_vec();
            let signed = client
                .sign_request(&identities[0], hash_alg, data.clone())
                .await?;
            let mut signature = signed.strip_prefix(&data[..]).ok_or("no data")?;
            u32::decode(&mut signature)?;
            let signature = ssh_key::Signature::decode(&mut signature)?;
            crate::crypto::verify(cert.public_key(), &data, &signature)?;

            client.remove_all_identities().await?;
        }
        Ok(())
    }
}
