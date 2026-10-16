use core::str;

use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use log::{debug, error};
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey, Signature};
use tokio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{AgentIdentity, Constraint, msg};
use crate::CryptoVec;
use crate::helpers::EncodedExt;
use crate::keys::{Error, key};

pub trait AgentStream: AsyncRead + AsyncWrite {}

impl<S: AsyncRead + AsyncWrite> AgentStream for S {}

const MAX_AGENT_FRAME_LEN: usize = 256 * 1024;

/// SSH agent client.
pub struct AgentClient<S: AgentStream> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: AgentStream + Send + Unpin> AgentClient<S> {
    /// Wraps the internal stream in a Box<dyn _>, allowing different client
    /// implementations to have the same type
    pub fn dynamic<'a>(self) -> AgentClient<Box<dyn AgentStream + Send + Unpin + 'a>>
    where
        S: 'a,
    {
        AgentClient {
            stream: Box::new(self.stream),
            buf: self.buf,
        }
    }

    pub fn into_inner<'a>(self) -> Box<dyn AgentStream + Send + Unpin + 'a>
    where
        S: 'a,
    {
        Box::new(self.stream)
    }
}

// https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.1
impl<S: AgentStream + Unpin> AgentClient<S> {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub fn connect(stream: S) -> Self {
        AgentClient {
            stream,
            buf: Vec::new(),
        }
    }
}

#[cfg(unix)]
impl AgentClient<tokio::net::UnixStream> {
    /// Connect to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub async fn connect_uds<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        Ok(AgentClient {
            stream,
            buf: Vec::new(),
        })
    }

    /// Connect to an SSH agent specified by the SSH_AUTH_SOCK
    /// environment variable.
    pub async fn connect_env() -> Result<Self, Error> {
        let var = if let Ok(var) = std::env::var("SSH_AUTH_SOCK") {
            var
        } else {
            return Err(Error::EnvVar("SSH_AUTH_SOCK"));
        };
        match Self::connect_uds(var).await {
            Err(Error::IO(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::BadAuthSock)
            }
            owise => owise,
        }
    }
}

#[cfg(windows)]
const ERROR_PIPE_BUSY: u32 = 231u32;

#[cfg(windows)]
impl AgentClient<pageant::PageantStream> {
    /// Connect to a running Pageant instance
    pub async fn connect_pageant() -> Result<Self, Error> {
        Ok(Self::connect(pageant::PageantStream::new().await?))
    }
}

#[cfg(windows)]
impl AgentClient<tokio::net::windows::named_pipe::NamedPipeClient> {
    /// Connect to an SSH agent via a Windows named pipe
    pub async fn connect_named_pipe<P: AsRef<std::ffi::OsStr>>(path: P) -> Result<Self, Error> {
        let stream = loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(path.as_ref()) {
                Ok(client) => break client,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => (),
                Err(e) => return Err(e.into()),
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        };

        Ok(AgentClient {
            stream,
            buf: Vec::new(),
        })
    }
}

impl<S: AgentStream + Unpin> AgentClient<S> {
    async fn read_frame(&mut self) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        self.stream.read_exact(&mut self.buf).await?;

        let len = BigEndian::read_u32(&self.buf) as usize;
        if len > MAX_AGENT_FRAME_LEN {
            return Err(Error::AgentProtocolError);
        }

        self.buf.clear();
        self.buf.resize(len, 0);
        self.stream.read_exact(&mut self.buf).await?;
        Ok(())
    }

    async fn read_response(&mut self) -> Result<(), Error> {
        // Writing the message
        self.stream.write_all(&self.buf).await?;
        self.stream.flush().await?;
        self.read_frame().await
    }

    async fn read_success(&mut self) -> Result<(), Error> {
        self.read_response().await?;
        if self.buf.first() == Some(&msg::SUCCESS) {
            Ok(())
        } else {
            Err(Error::AgentFailure)
        }
    }

    fn encode_constraints(&mut self, constraints: &[Constraint]) -> Result<(), Error> {
        for cons in constraints {
            match *cons {
                Constraint::KeyLifetime { seconds } => {
                    msg::CONSTRAIN_LIFETIME.encode(&mut self.buf)?;
                    seconds.encode(&mut self.buf)?;
                }
                Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                Constraint::Extensions {
                    ref name,
                    ref details,
                } => {
                    msg::CONSTRAIN_EXTENSION.encode(&mut self.buf)?;
                    name.encode(&mut self.buf)?;
                    details.encode(&mut self.buf)?;
                }
            }
        }
        Ok(())
    }

    /// Send a key to the agent, with a (possibly empty) slice of
    /// constraints to apply when using the key to sign.
    pub async fn add_identity(
        &mut self,
        key: &PrivateKey,
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        // See IETF draft-miller-ssh-agent-13, section 3.2 for format.
        // https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
        self.buf.clear();
        self.buf.resize(4, 0);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_IDENTITY)
        } else {
            self.buf.push(msg::ADD_ID_CONSTRAINED)
        }

        key.key_data().encode(&mut self.buf)?;
        key.comment().encode(&mut self.buf)?;
        self.encode_constraints(constraints)?;

        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_success().await?;
        Ok(())
    }

    /// Send a certificate and its matching private key to the agent, with a
    /// (possibly empty) slice of constraints to apply when using the
    /// certificate to sign.
    pub async fn add_certificate(
        &mut self,
        cert: &Certificate,
        key: &PrivateKey,
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        if cert.public_key() != key.public_key().key_data() {
            return Err(Error::KeyIsCorrupt);
        }

        self.buf.clear();
        self.buf.resize(4, 0);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_IDENTITY)
        } else {
            self.buf.push(msg::ADD_ID_CONSTRAINED)
        }

        cert.algorithm()
            .to_certificate_type()
            .encode(&mut self.buf)?;
        cert.to_bytes()?.encode(&mut self.buf)?;

        match key.key_data() {
            ssh_key::private::KeypairData::Dsa(pair) => {
                pair.private().encode(&mut self.buf)?;
            }
            ssh_key::private::KeypairData::Ecdsa(pair) => {
                ssh_key::Mpint::from_positive_bytes(pair.private_key_bytes())
                    .encode(&mut self.buf)?;
            }
            ssh_key::private::KeypairData::Mldsa87P384(pair) => {
                let mut composite_private = zeroize::Zeroizing::new(Vec::with_capacity(
                    32 + 4 + pair.ecdsa_private().as_slice().len() + 1,
                ));
                composite_private.extend_from_slice(pair.mldsa_seed());
                pair.ecdsa_private().encode(&mut *composite_private)?;
                composite_private.as_slice().encode(&mut self.buf)?;
            }
            ssh_key::private::KeypairData::Ed25519(pair) => {
                pair.encode(&mut self.buf)?;
            }
            ssh_key::private::KeypairData::Rsa(pair) => {
                pair.private().encode(&mut self.buf)?;
            }
            _ => {
                return Err(ssh_key::Error::AlgorithmUnsupported {
                    algorithm: key.algorithm(),
                }
                .into());
            }
        }

        let comment = if !key.comment().is_empty() {
            key.comment().as_bytes()
        } else {
            cert.comment().as_bytes()
        };
        comment.encode(&mut self.buf)?;
        self.encode_constraints(constraints)?;

        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_success().await?;
        Ok(())
    }

    /// Add a smart card to the agent, with a (possibly empty) set of
    /// constraints to apply when signing.
    ///
    /// Fails with [`Error::AgentFailure`] if the agent refuses, for example
    /// because it can't load the keys of the token.
    pub async fn add_smartcard_key(
        &mut self,
        id: &str,
        pin: &[u8],
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_SMARTCARD_KEY)
        } else {
            self.buf.push(msg::ADD_SMARTCARD_KEY_CONSTRAINED)
        }
        id.encode(&mut self.buf)?;
        pin.encode(&mut self.buf)?;
        self.encode_constraints(constraints)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await?;
        Ok(())
    }

    /// Lock the agent, making it refuse to sign until unlocked.
    ///
    /// Fails with [`Error::AgentFailure`] if the agent refuses, for example
    /// because it is locked already.
    pub async fn lock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        self.buf.push(msg::LOCK);
        passphrase.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await?;
        Ok(())
    }

    /// Unlock the agent, allowing it to sign again.
    ///
    /// Fails with [`Error::AgentFailure`] if the agent refuses, for example
    /// because the passphrase is wrong or the agent isn't locked.
    pub async fn unlock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::UNLOCK.encode(&mut self.buf)?;
        passphrase.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        #[allow(clippy::indexing_slicing)] // static length
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await?;
        Ok(())
    }

    /// Ask the agent for a list of identities, including certificates.
    ///
    /// Fails with [`Error::AgentFailure`] if the agent refuses.
    pub async fn request_identities(&mut self) -> Result<Vec<AgentIdentity>, Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::REQUEST_IDENTITIES.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_response().await?;
        debug!("identities: {:?}", &self.buf[..]);
        let mut identities = Vec::new();

        #[allow(clippy::indexing_slicing)] // static length
        if let Some((&msg::IDENTITIES_ANSWER, mut r)) = self.buf.split_first() {
            let n = u32::decode(&mut r)?;
            for _ in 0..n {
                let key_blob = Bytes::decode(&mut r)?;
                let comment = String::decode(&mut r)?;

                // Check if blob starts with a certificate algorithm by reading the algorithm string.
                // Certificate algorithms end with "-cert-v01@openssh.com".
                // This avoids parsing the blob twice for regular keys.
                let identity = if Self::is_certificate_blob(&key_blob) {
                    match Certificate::decode(&mut key_blob.as_ref()) {
                        Ok(cert) => AgentIdentity::Certificate {
                            certificate: cert,
                            comment,
                        },
                        Err(_) => {
                            // Fallback to public key if certificate parsing fails
                            let key = key::parse_public_key(&key_blob)?;
                            AgentIdentity::PublicKey { key, comment }
                        }
                    }
                } else {
                    let key = key::parse_public_key(&key_blob)?;
                    AgentIdentity::PublicKey { key, comment }
                };
                identities.push(identity);
            }
        } else if self.buf.first() == Some(&msg::FAILURE) {
            return Err(Error::AgentFailure);
        } else {
            return Err(Error::AgentProtocolError);
        }

        Ok(identities)
    }

    /// Check if a key blob appears to be a certificate by examining the algorithm prefix.
    /// Certificate algorithms end with "-cert-v01@openssh.com".
    fn is_certificate_blob(blob: &[u8]) -> bool {
        // The blob starts with a length-prefixed string containing the algorithm name.
        // Read the length (4 bytes, big-endian) and then the algorithm string.
        let Some(len_bytes) = blob.get(..4) else {
            return false;
        };
        let alg_len = BigEndian::read_u32(len_bytes) as usize;
        let Some(alg_bytes) = blob.get(4..4 + alg_len) else {
            return false;
        };
        if let Ok(alg_str) = str::from_utf8(alg_bytes) {
            alg_str.ends_with("-cert-v01@openssh.com")
        } else {
            false
        }
    }

    /// Ask the agent to sign the supplied piece of data.
    pub async fn sign_request(
        &mut self,
        identity: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        match identity {
            AgentIdentity::PublicKey { key, .. } => self.sign_request_pk(key, hash_alg, data).await,
            AgentIdentity::Certificate { certificate, .. } => {
                self.sign_request_cert(certificate, hash_alg, data).await
            }
        }
    }

    async fn sign_request_pk(
        &mut self,
        public: &PublicKey,
        hash_alg: Option<HashAlg>,
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        debug!("sign_request: {data:?}");
        let hash = self.prepare_sign_request(public, hash_alg, &data)?;

        self.read_response().await?;

        match self.buf.split_first() {
            Some((&msg::SIGN_RESPONSE, mut r)) => {
                self.write_signature(&mut r, hash, &mut data)?;
                Ok(data)
            }
            Some((&msg::FAILURE, _)) => Err(Error::AgentFailure),
            _ => {
                debug!("self.buf = {:?}", &self.buf[..]);
                Err(Error::AgentProtocolError)
            }
        }
    }

    /// Ask the agent to sign data using a certificate identity.
    ///
    /// This sends the certificate blob to the agent (not just the public key),
    /// allowing the agent to match it to the correct private key.
    ///
    /// For RSA certificates, you can specify the hash algorithm to use.
    async fn sign_request_cert(
        &mut self,
        cert: &Certificate,
        hash_alg: Option<HashAlg>,
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        debug!("sign_request_cert: {data:?}");

        self.buf.clear();
        self.buf.resize(4, 0);
        msg::SIGN_REQUEST.encode(&mut self.buf)?;
        cert.to_bytes()?.encode(&mut self.buf)?;
        data.encode(&mut self.buf)?;

        // Calculate hash flag for RSA certificates (same logic as prepare_sign_request)
        let hash = match cert.algorithm() {
            Algorithm::Rsa { .. } => match hash_alg {
                Some(HashAlg::Sha256) => msg::RSA_SHA2_256,
                Some(HashAlg::Sha512) => msg::RSA_SHA2_512,
                _ => 0,
            },
            _ => 0,
        };

        hash.encode(&mut self.buf)?;

        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_response().await?;

        match self.buf.split_first() {
            Some((&msg::SIGN_RESPONSE, mut r)) => {
                self.write_signature(&mut r, hash, &mut data)?;
                Ok(data)
            }
            Some((&msg::FAILURE, _)) => Err(Error::AgentFailure),
            _ => {
                debug!("self.buf = {:?}", &self.buf[..]);
                Err(Error::AgentProtocolError)
            }
        }
    }

    fn prepare_sign_request(
        &mut self,
        public: &ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        data: &[u8],
    ) -> Result<u32, Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::SIGN_REQUEST.encode(&mut self.buf)?;
        public.key_data().encoded()?.encode(&mut self.buf)?;
        data.encode(&mut self.buf)?;
        debug!("public = {public:?}");

        let hash = match public.algorithm() {
            Algorithm::Rsa { .. } => match hash_alg {
                Some(HashAlg::Sha256) => msg::RSA_SHA2_256,
                Some(HashAlg::Sha512) => msg::RSA_SHA2_512,
                _ => 0,
            },
            _ => 0,
        };

        hash.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        Ok(hash)
    }

    fn write_signature<R: Reader>(
        &self,
        r: &mut R,
        hash: u32,
        data: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let mut resp = &Bytes::decode(r)?[..];
        let t = String::decode(&mut resp)?;
        if (hash == msg::RSA_SHA2_256 && t == "rsa-sha2-256")
            || (hash == msg::RSA_SHA2_512 && t == "rsa-sha2-512")
            || hash == 0
        {
            let sig = Bytes::decode(&mut resp)?;
            let is_sk_signature = t.starts_with("sk-");
            (t.len() + sig.len() + 8 + if is_sk_signature { 5 } else { 0 }).encode(data)?;
            t.encode(data)?;
            sig.encode(data)?;
            if is_sk_signature {
                let flags = u8::decode(&mut resp)?;
                let counter = u32::decode(&mut resp)?;
                flags.encode(data)?;
                counter.encode(data)?;
            }
            Ok(())
        } else {
            error!("unexpected agent signature type: {t:?}");
            Err(Error::AgentProtocolError)
        }
    }

    /// Ask the agent to sign the supplied piece of data.
    ///
    /// Fails with [`Error::AgentFailure`] if the agent refuses to sign.
    pub fn sign_request_base64(
        mut self,
        public: &ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        data: &[u8],
    ) -> impl futures::Future<Output = (Self, Result<String, Error>)> {
        debug!("sign_request: {data:?}");
        let r = self.prepare_sign_request(public, hash_alg, data);
        async move {
            if let Err(e) = r {
                return (self, Err(e));
            }

            let resp = self.read_response().await;
            if let Err(e) = resp {
                return (self, Err(e));
            }

            let result = match self.buf.split_first() {
                Some((&msg::SIGN_RESPONSE, signature)) => {
                    Ok(data_encoding::BASE64_NOPAD.encode(signature))
                }
                Some((&msg::FAILURE, _)) => Err(Error::AgentFailure),
                _ => Err(Error::AgentProtocolError),
            };
            (self, result)
        }
    }

    /// Ask the agent to sign the supplied piece of data, and return a `Signature`.
    ///
    /// Fails with [`Error::AgentFailure`] if the agent refuses to sign.
    pub async fn sign_request_signature(
        &mut self,
        public: &ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        data: &[u8],
    ) -> Result<Signature, Error> {
        debug!("sign_request: {data:?}");

        self.prepare_sign_request(public, hash_alg, data)?;
        self.read_response().await?;

        match self.buf.split_first() {
            Some((&msg::SIGN_RESPONSE, mut r)) => {
                let mut resp = &Bytes::decode(&mut r)?[..];
                let sig = Signature::decode(&mut resp)?;
                Ok(sig)
            }
            Some((&msg::FAILURE, _)) => Err(Error::AgentFailure),
            _ => Err(Error::AgentProtocolError),
        }
    }

    /// Ask the agent to remove a key from its memory.
    ///
    /// Fails with [`Error::AgentFailure`] if the agent refuses, for example
    /// because it doesn't hold the key.
    pub async fn remove_identity(&mut self, public: &ssh_key::PublicKey) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        self.buf.push(msg::REMOVE_IDENTITY);
        public.key_data().encoded()?.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await?;
        Ok(())
    }

    /// Ask the agent to remove a smartcard from its memory.
    ///
    /// Fails with [`Error::AgentFailure`] if the agent refuses, for example
    /// because it holds no keys of that token.
    pub async fn remove_smartcard_key(&mut self, id: &str, pin: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::REMOVE_SMARTCARD_KEY.encode(&mut self.buf)?;
        id.encode(&mut self.buf)?;
        pin.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await?;
        Ok(())
    }

    /// Ask the agent to forget all known keys.
    pub async fn remove_all_identities(&mut self) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::REMOVE_ALL_IDENTITIES.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_success().await?;
        Ok(())
    }

    /// Send an `SSH_AGENTC_EXTENSION` request to the agent.
    ///
    /// `typ` is the extension name. `ext` is the extension contents, already
    /// encoded in the format that extension defines; it is sent as is, not
    /// wrapped in a string. For example, OpenSSH's
    /// `session-bind@openssh.com` takes the host key, session identifier
    /// and signature as SSH strings followed by a boolean `is_forwarding`
    /// byte.
    ///
    /// Returns `Ok(())` if the agent answers `SSH_AGENT_SUCCESS` or
    /// `SSH_AGENT_EXTENSION_RESPONSE` (whose extension type matches `typ`).
    /// The contents of either reply are discarded; use
    /// [`Self::extension_response`] to read the reply payload. Fails with
    /// [`Error::AgentFailure`] if the agent answers `SSH_AGENT_FAILURE`,
    /// which usually means it doesn't support the extension, or
    /// `SSH_AGENT_EXTENSION_FAILURE`. Any other reply fails with
    /// [`Error::AgentProtocolError`].
    pub async fn extension(&mut self, typ: &[u8], ext: &[u8]) -> Result<(), Error> {
        self.extension_response(typ, ext).await.map(|_| ())
    }

    /// Send an `SSH_AGENTC_EXTENSION` request to the agent and return the
    /// extension-specific reply bytes.
    ///
    /// `typ` is the extension name. `ext` is the extension contents, already
    /// encoded in the format that extension defines; it is sent as is, not
    /// wrapped in a string.
    ///
    /// Per [RFC 9987 §5.8](https://www.rfc-editor.org/rfc/rfc9987.html#section-5.8):
    /// - If the agent answers `SSH_AGENT_SUCCESS`, returns the remaining
    ///   bytes of the frame (empty for standard `SSH_AGENT_SUCCESS`, or the
    ///   extension reply payload for draft-04 agents such as Pageant).
    /// - If the agent answers `SSH_AGENT_EXTENSION_RESPONSE`, reads the
    ///   leading extension type `string`, checks that it equals `typ`
    ///   (failing with [`Error::AgentProtocolError`] on mismatch), and
    ///   returns the remaining bytes of the frame.
    /// - If the agent answers `SSH_AGENT_FAILURE` or
    ///   `SSH_AGENT_EXTENSION_FAILURE`, fails with [`Error::AgentFailure`].
    /// - Any other reply fails with [`Error::AgentProtocolError`].
    pub async fn extension_response(&mut self, typ: &[u8], ext: &[u8]) -> Result<Vec<u8>, Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::EXTENSION.encode(&mut self.buf)?;
        typ.encode(&mut self.buf)?;
        self.buf.extend_from_slice(ext);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_response().await?;
        match self.buf.split_first() {
            Some((&msg::SUCCESS, r)) => Ok(r.to_vec()),
            Some((&msg::EXTENSION_RESPONSE, mut r)) => {
                let reply_type = Bytes::decode(&mut r)?;
                if reply_type.as_ref() != typ {
                    return Err(Error::AgentProtocolError);
                }
                Ok(r.to_vec())
            }
            Some((&(msg::FAILURE | msg::EXTENSION_FAILURE), _)) => Err(Error::AgentFailure),
            _ => Err(Error::AgentProtocolError),
        }
    }

    /// Query the agent for the names of its supported extensions using the
    /// `"query"` extension ([RFC 9987 §5.8.1](https://www.rfc-editor.org/rfc/rfc9987.html#section-5.8.1)).
    ///
    /// Accepts both `SSH_AGENT_EXTENSION_RESPONSE` with `"query"` followed
    /// by `string[]` (RFC 9987 §5.8.1, used by OpenSSH >= 10.3) and
    /// `SSH_AGENT_SUCCESS` followed by `string[]` (draft-miller-ssh-agent-04
    /// §4.7.1, used by Pageant). Fails with [`Error::AgentFailure`] if the
    /// agent does not support the `"query"` extension.
    pub async fn query_extensions(&mut self) -> Result<Vec<String>, Error> {
        let reply = self.extension_response(b"query", b"").await?;
        let mut r = reply.as_slice();
        let mut exts = Vec::new();
        while !r.is_empty() {
            exts.push(String::decode(&mut r)?);
        }
        Ok(exts)
    }

    /// Ask the agent about a supported extension.
    #[cfg_attr(
        not(test),
        deprecated(
            note = "use `query_extensions` or `extension_response` instead; `query_extension` takes `ext` by value and discards the reply"
        )
    )]
    pub async fn query_extension(&mut self, typ: &[u8], mut ext: CryptoVec) -> Result<bool, Error> {
        self.buf.clear();
        self.buf.resize(4, 0);
        msg::EXTENSION.encode(&mut self.buf)?;
        typ.encode(&mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_response().await?;

        match self.buf.split_first() {
            Some((&msg::SUCCESS, mut r)) => {
                if !r.is_empty() {
                    ext.extend(&Bytes::decode(&mut r)?);
                }
                Ok(true)
            }
            Some((&msg::EXTENSION_RESPONSE, mut r)) => {
                if Bytes::decode(&mut r)?.as_ref() != typ {
                    return Err(Error::AgentProtocolError);
                }
                ext.extend(r);
                Ok(true)
            }
            Some((&(msg::FAILURE | msg::EXTENSION_FAILURE), _)) => Ok(false),
            _ => Err(Error::AgentProtocolError),
        }
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::{AgentClient, MAX_AGENT_FRAME_LEN, msg};
    use crate::CryptoVec;
    use crate::keys::agent::Constraint;
    use crate::keys::{Error, generate_secret_key};

    #[test]
    fn oversized_agent_response_is_rejected_before_allocation() -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        runtime.block_on(async {
            let (mut writer, reader) = tokio::io::duplex(64);
            let server = tokio::spawn(async move {
                let mut frame = [0u8; 4];
                writer.read_exact(&mut frame).await?;
                let len = BigEndian::read_u32(&frame) as usize;
                let mut body = vec![0; len];
                writer.read_exact(&mut body).await?;

                BigEndian::write_u32(&mut frame, (MAX_AGENT_FRAME_LEN + 1) as u32);
                writer.write_all(&frame).await?;
                Ok::<(), std::io::Error>(())
            });

            let mut client = AgentClient::connect(reader);
            let err = client.request_identities().await.unwrap_err();
            assert!(matches!(err, Error::AgentProtocolError));
            server.await.expect("server task")?;
            Ok::<(), std::io::Error>(())
        })?;

        Ok(())
    }

    /// A client of an agent that answers its first request with `reply`, and
    /// the agent's end of the stream.
    async fn agent_answering(
        reply: &[u8],
    ) -> std::io::Result<(AgentClient<DuplexStream>, DuplexStream)> {
        let (client, mut agent) = tokio::io::duplex(1 << 16);
        agent.write_all(reply).await?;
        Ok((AgentClient::connect(client), agent))
    }

    /// Everything that `client` wrote to `agent`.
    async fn written(
        client: AgentClient<DuplexStream>,
        mut agent: DuplexStream,
    ) -> std::io::Result<Vec<u8>> {
        drop(client);
        let mut written = Vec::new();
        agent.read_to_end(&mut written).await?;
        Ok(written)
    }

    /// A request is one frame: a `uint32` length, then a message of that
    /// many bytes, with the contents that draft-ietf-sshm-ssh-agent and
    /// OpenSSH's PROTOCOL.agent give it.
    #[tokio::test]
    async fn requests_are_framed_as_the_agent_protocol_specifies()
    -> Result<(), Box<dyn std::error::Error>> {
        let success = [0, 0, 0, 1, msg::SUCCESS];
        let failure = [0, 0, 0, 1, msg::FAILURE];

        // SSH_AGENTC_REMOVE_ALL_IDENTITIES has no contents.
        let (mut client, agent) = agent_answering(&success).await?;
        client.remove_all_identities().await?;
        assert_eq!(
            written(client, agent).await?,
            [0, 0, 0, 1, msg::REMOVE_ALL_IDENTITIES]
        );

        // SSH_AGENTC_EXTENSION: the extension type, then its contents as
        // they are.
        let (mut client, agent) = agent_answering(&success).await?;
        client.extension(b"ext@example.com", b"data").await?;
        assert_eq!(
            written(client, agent).await?,
            [
                &[0, 0, 0, 24, msg::EXTENSION, 0, 0, 0, 15][..],
                b"ext@example.com",
                b"data",
            ]
            .concat()
        );

        let (mut client, agent) = agent_answering(&failure).await?;
        let supported = client
            .query_extension(b"ext@example.com", CryptoVec::new())
            .await?;
        assert!(!supported);
        assert_eq!(
            written(client, agent).await?,
            [
                &[0, 0, 0, 20, msg::EXTENSION, 0, 0, 0, 15][..],
                b"ext@example.com",
            ]
            .concat()
        );

        // The constraints follow the PIN, without a count.
        let (mut client, agent) = agent_answering(&success).await?;
        let constraints = [Constraint::KeyLifetime { seconds: 60 }, Constraint::Confirm];
        client
            .add_smartcard_key("pkcs11.so", b"1234", &constraints)
            .await?;
        assert_eq!(
            written(client, agent).await?,
            [
                &[0, 0, 0, 28, msg::ADD_SMARTCARD_KEY_CONSTRAINED, 0, 0, 0, 9][..],
                b"pkcs11.so",
                &[0, 0, 0, 4],
                b"1234",
                &[msg::CONSTRAIN_LIFETIME, 0, 0, 0, 60, msg::CONSTRAIN_CONFIRM],
            ]
            .concat()
        );
        Ok(())
    }

    /// A frame holding `message`.
    fn frame(message: &[u8]) -> Vec<u8> {
        [&(message.len() as u32).to_be_bytes()[..], message].concat()
    }

    /// `Ok`, or the error that a request failed with.
    fn outcome<T>(result: &Result<T, Error>) -> String {
        match result {
            Ok(_) => "Ok".into(),
            Err(e) => format!("{e:?}"),
        }
    }

    /// The requests that the agent answers with `SSH_AGENT_SUCCESS` fail
    /// with `AgentFailure` if it answers `SSH_AGENT_FAILURE` instead.
    #[tokio::test]
    async fn requests_fail_when_the_agent_refuses() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_secret_key()?;
        for (reply, expected) in [(msg::SUCCESS, "Ok"), (msg::FAILURE, "AgentFailure")] {
            let (mut client, _agent) = agent_answering(&frame(&[reply]).repeat(6)).await?;
            let outcomes = [
                ("lock", outcome(&client.lock(b"passphrase").await)),
                ("unlock", outcome(&client.unlock(b"passphrase").await)),
                (
                    "remove_identity",
                    outcome(&client.remove_identity(key.public_key()).await),
                ),
                (
                    "add_smartcard_key",
                    outcome(&client.add_smartcard_key("pkcs11.so", b"1234", &[]).await),
                ),
                (
                    "remove_smartcard_key",
                    outcome(&client.remove_smartcard_key("pkcs11.so", b"1234").await),
                ),
                (
                    "extension",
                    outcome(&client.extension(b"ext@example.com", b"").await),
                ),
            ];
            for (method, outcome) in outcomes {
                assert_eq!(outcome, expected, "{method}, answered {reply}");
            }
        }
        Ok(())
    }

    /// `extension` and `extension_response` succeed if the agent answers
    /// `SSH_AGENT_SUCCESS`, with or without contents, or
    /// `SSH_AGENT_EXTENSION_RESPONSE` with the requested extension type.
    /// They fail with `AgentFailure` on `SSH_AGENT_FAILURE` and
    /// `SSH_AGENT_EXTENSION_FAILURE`, and with `AgentProtocolError` if the
    /// response type mismatches or the reply is unexpected.
    #[tokio::test]
    async fn extension_fails_unless_the_agent_answers_success()
    -> Result<(), Box<dyn std::error::Error>> {
        let extension_response = [
            &[msg::EXTENSION_RESPONSE, 0, 0, 0, 15][..],
            b"ext@example.com",
            b"reply",
        ]
        .concat();
        let mismatched_extension_response = [
            &[msg::EXTENSION_RESPONSE, 0, 0, 0, 17][..],
            b"other@example.com",
            b"reply",
        ]
        .concat();
        let success_with_payload = [msg::SUCCESS, 0, 0, 0, 5, b'r', b'e', b'p', b'l', b'y'];
        let replies = [
            (&[msg::SUCCESS][..], "Ok", Some(&b""[..])),
            (
                &success_with_payload,
                "Ok",
                Some(&[0, 0, 0, 5, b'r', b'e', b'p', b'l', b'y']),
            ),
            (&extension_response, "Ok", Some(b"reply")),
            (&mismatched_extension_response, "AgentProtocolError", None),
            (&[msg::FAILURE], "AgentFailure", None),
            (&[msg::EXTENSION_FAILURE], "AgentFailure", None),
            (
                &[msg::IDENTITIES_ANSWER, 0, 0, 0, 0],
                "AgentProtocolError",
                None,
            ),
            (&[], "AgentProtocolError", None),
        ];
        for (reply, expected, expected_payload) in replies {
            let (mut client, _agent) = agent_answering(&frame(reply)).await?;
            let result = client.extension(b"ext@example.com", b"data").await;
            assert_eq!(outcome(&result), expected, "answered {reply:?}");

            let (mut client, _agent) = agent_answering(&frame(reply)).await?;
            let result = client.extension_response(b"ext@example.com", b"data").await;
            assert_eq!(outcome(&result), expected, "answered {reply:?}");
            if let Some(payload) = expected_payload {
                assert_eq!(result?, payload, "answered {reply:?}");
            }
        }
        Ok(())
    }

    /// `query_extensions` decodes the extension list from both RFC 9987
    /// §5.8.1 (`SSH_AGENT_EXTENSION_RESPONSE` + `"query"` + `string[]`, used
    /// by OpenSSH >= 10.3) and draft-miller-ssh-agent-04 §4.7.1
    /// (`SSH_AGENT_SUCCESS` + `string[]`, used by Pageant). `query_extension`
    /// accepts both reply formats too.
    #[tokio::test]
    async fn query_extensions_accepts_rfc9987_and_draft04_replies()
    -> Result<(), Box<dyn std::error::Error>> {
        use ssh_encoding::Encode;

        let mut ext_list = Vec::new();
        "session-bind@openssh.com".encode(&mut ext_list)?;
        "ext@example.com".encode(&mut ext_list)?;

        let mut rfc9987_reply = vec![msg::EXTENSION_RESPONSE];
        "query".encode(&mut rfc9987_reply)?;
        rfc9987_reply.extend_from_slice(&ext_list);

        let mut draft04_reply = vec![msg::SUCCESS];
        draft04_reply.extend_from_slice(&ext_list);

        for reply in [&rfc9987_reply[..], &draft04_reply[..]] {
            let (mut client, agent) = agent_answering(&frame(reply)).await?;
            let exts = client.query_extensions().await?;
            assert_eq!(exts, ["session-bind@openssh.com", "ext@example.com"]);
            assert_eq!(
                written(client, agent).await?,
                [&[0, 0, 0, 10, msg::EXTENSION, 0, 0, 0, 5][..], b"query"].concat()
            );

            let (mut client, _agent) = agent_answering(&frame(reply)).await?;
            assert!(client.query_extension(b"query", CryptoVec::new()).await?);
        }

        // Empty list in either format.
        let mut rfc9987_empty = vec![msg::EXTENSION_RESPONSE];
        "query".encode(&mut rfc9987_empty)?;
        for reply in [&rfc9987_empty[..], &[msg::SUCCESS][..]] {
            let (mut client, _agent) = agent_answering(&frame(reply)).await?;
            assert!(client.query_extensions().await?.is_empty());
            let (mut client, _agent) = agent_answering(&frame(reply)).await?;
            assert!(client.query_extension(b"query", CryptoVec::new()).await?);
        }

        // Unsupported or failed query.
        for reply in [msg::FAILURE, msg::EXTENSION_FAILURE] {
            let (mut client, _agent) = agent_answering(&frame(&[reply])).await?;
            assert_eq!(outcome(&client.query_extensions().await), "AgentFailure");
            let (mut client, _agent) = agent_answering(&frame(&[reply])).await?;
            assert!(!client.query_extension(b"query", CryptoVec::new()).await?);
        }

        // Wrong extension name in SSH_AGENT_EXTENSION_RESPONSE.
        let mut wrong_type = vec![msg::EXTENSION_RESPONSE];
        "other".encode(&mut wrong_type)?;
        let (mut client, _agent) = agent_answering(&frame(&wrong_type)).await?;
        assert_eq!(
            outcome(&client.query_extensions().await),
            "AgentProtocolError"
        );
        let (mut client, _agent) = agent_answering(&frame(&wrong_type)).await?;
        assert_eq!(
            outcome(&client.query_extension(b"query", CryptoVec::new()).await),
            "AgentProtocolError"
        );
        Ok(())
    }

    /// The requests that the agent answers with something other than
    /// `SSH_AGENT_SUCCESS` fail with `AgentFailure` if it answers
    /// `SSH_AGENT_FAILURE`, and with `AgentProtocolError` if it answers
    /// something they don't expect.
    #[tokio::test]
    async fn queries_fail_when_the_agent_refuses() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_secret_key()?;
        let public = key.public_key();
        for (reply, expected) in [
            (msg::FAILURE, "AgentFailure"),
            (msg::SUCCESS, "AgentProtocolError"),
        ] {
            let (mut client, _agent) = agent_answering(&frame(&[reply]).repeat(3)).await?;
            let identities = client.request_identities().await;
            let signature = client.sign_request_signature(public, None, b"data").await;
            let (_client, base64) = client.sign_request_base64(public, None, b"data").await;
            let outcomes = [
                ("request_identities", outcome(&identities)),
                ("sign_request_signature", outcome(&signature)),
                ("sign_request_base64", outcome(&base64)),
            ];
            for (method, outcome) in outcomes {
                assert_eq!(outcome, expected, "{method}, answered {reply}");
            }
        }
        Ok(())
    }

    /// A client of russh's agent, served on a task.
    fn russhs_agent() -> AgentClient<DuplexStream> {
        let (client, agent) = tokio::io::duplex(1 << 16);
        let listener = futures::stream::iter([Ok(agent)]);
        tokio::spawn(crate::keys::agent::server::serve(listener, ()));
        AgentClient::connect(client)
    }

    /// russh's agent refuses to lock when it is locked, to unlock when it
    /// isn't locked or the passphrase is wrong, to sign while locked, and to
    /// remove a key it doesn't hold.
    #[tokio::test]
    async fn russhs_agent_refusals_are_errors() -> Result<(), Box<dyn std::error::Error>> {
        let mut client = russhs_agent();
        let mut key = generate_secret_key()?;
        key.set_comment("test-key-comment");
        let public = key.public_key().clone();
        client.add_identity(&key, &[]).await?;

        let identities = client.request_identities().await?;
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].comment(), "test-key-comment");

        // An empty lock passphrase is refused and leaves the agent unlocked.
        assert_eq!(outcome(&client.lock(b"").await), "AgentFailure");
        assert_eq!(client.request_identities().await?.len(), 1);
        let signature = client
            .sign_request_signature(&public, None, b"data")
            .await?;
        crate::crypto::verify(public.key_data(), b"data", &signature)?;

        assert_eq!(outcome(&client.unlock(b"passphrase").await), "AgentFailure");
        client.lock(b"passphrase").await?;
        assert_eq!(outcome(&client.lock(b"passphrase").await), "AgentFailure");
        // While locked, REQUEST_IDENTITIES returns an empty list rather than
        // SSH_AGENT_FAILURE.
        assert!(client.request_identities().await?.is_empty());
        let signature = client.sign_request_signature(&public, None, b"data").await;
        assert_eq!(outcome(&signature), "AgentFailure");
        let (mut client, base64) = client.sign_request_base64(&public, None, b"data").await;
        assert_eq!(outcome(&base64), "AgentFailure");
        assert_eq!(outcome(&client.unlock(b"wrong").await), "AgentFailure");
        client.unlock(b"passphrase").await?;

        let identities = client.request_identities().await?;
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].comment(), "test-key-comment");
        let signature = client
            .sign_request_signature(&public, None, b"data")
            .await?;
        crate::crypto::verify(public.key_data(), b"data", &signature)?;
        let (mut client, base64) = client.sign_request_base64(&public, None, b"data").await;
        assert!(!base64?.is_empty());

        let other = generate_secret_key()?;
        let removed = client.remove_identity(other.public_key()).await;
        assert_eq!(outcome(&removed), "AgentFailure");
        client.remove_identity(&public).await?;
        assert!(client.request_identities().await?.is_empty());
        Ok(())
    }

    /// `remove_all_identities` removes every key from russh's agent.
    #[tokio::test]
    async fn removes_all_identities_from_russhs_agent() -> Result<(), Box<dyn std::error::Error>> {
        let mut client = russhs_agent();

        // Keys that the backend signs with: Ed25519 (ECDSA with SymCrypt),
        // and RSA.
        #[allow(unused_mut)]
        let mut keys = vec![generate_secret_key()?, generate_secret_key()?];
        #[cfg(any(feature = "rsa", russh_backend = "symcrypt"))]
        keys.push(crate::keys::decode_secret_key(
            include_str!("../../../tests/data/keys/rsa-2048"),
            None,
        )?);
        for key in &keys {
            client.add_identity(key, &[]).await?;
        }
        assert_eq!(client.request_identities().await?.len(), keys.len());

        client.remove_all_identities().await?;
        assert!(client.request_identities().await?.is_empty());
        Ok(())
    }
}
