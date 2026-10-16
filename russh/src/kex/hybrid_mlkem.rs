//! PQ/T hybrid key exchange of ML-KEM with ECDH (RFC 10042):
//! `mlkem768x25519-sha256`, `mlkem768nistp256-sha256` and
//! `mlkem1024nistp384-sha384`.
//!
//! The client sends `C_INIT = C_PK2 || C_PK1`, its ML-KEM encapsulation key
//! and its ECDH public key, in `SSH_MSG_KEX_HYBRID_INIT`. The server answers
//! with `S_REPLY = S_CT2 || S_PK1`, the ML-KEM ciphertext and its own ECDH
//! public key, in `SSH_MSG_KEX_HYBRID_REPLY`. Both sides then hash the ML-KEM
//! shared secret `K_PQ` and the fixed-length ECDH shared secret `K_CL` into
//! `K = HASH(K_PQ || K_CL)`, which the exchange hash and the key derivation
//! encode as a string, not as an mpint.

use std::marker::PhantomData;

use log::debug;
use ssh_encoding::{Encode, Writer};
use zeroize::Zeroizing;

use super::{KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret, compute_keys};
use crate::crypto::provider::hash::{Sha256, Sha384};
use crate::crypto::provider::kex::{MlKem768, MlKem1024, NistP256, NistP384, X25519};
use crate::crypto::{Hash, Kem, KeyAgreement};
use crate::mac;
use crate::session::Exchange;
use crate::{CryptoVec, Error, cipher, msg};

/// The primitives of an RFC 10042 method, and the lengths of what they put on
/// the wire.
pub(crate) trait HybridMethod {
    /// The post-quantum KEM.
    type Kem: Kem;
    /// The traditional key agreement.
    type Ecdh: KeyAgreement;
    /// `HASH`: for `K`, the exchange hash and the key derivation.
    type Hash: Hash;
    /// The length of `C_PK2`, the ML-KEM encapsulation key.
    const ENCAPSULATION_KEY_LEN: usize;
    /// The length of `S_CT2`, the ML-KEM ciphertext.
    const CIPHERTEXT_LEN: usize;
    /// The length of `C_PK1` and `S_PK1`: 32 bytes for X25519, and for the
    /// NIST curves an uncompressed point, the only encoding russh (like
    /// OpenSSH) sends or accepts.
    const ECDH_PUBLIC_KEY_LEN: usize;
    /// Whether an all-zero `K_CL` is refused. X25519 accepts any public key,
    /// and a low-order one gives that secret (RFC 8731 §3). The NIST curves
    /// refuse invalid public keys instead.
    const REFUSE_ZERO_SECRET: bool = false;
}

/// `mlkem768x25519-sha256`.
pub(crate) struct MlKem768X25519;

impl HybridMethod for MlKem768X25519 {
    type Kem = MlKem768;
    type Ecdh = X25519;
    type Hash = Sha256;
    const ENCAPSULATION_KEY_LEN: usize = 1184;
    const CIPHERTEXT_LEN: usize = 1088;
    const ECDH_PUBLIC_KEY_LEN: usize = 32;
    const REFUSE_ZERO_SECRET: bool = true;
}

/// `mlkem768nistp256-sha256`.
pub(crate) struct MlKem768NistP256;

impl HybridMethod for MlKem768NistP256 {
    type Kem = MlKem768;
    type Ecdh = NistP256;
    type Hash = Sha256;
    const ENCAPSULATION_KEY_LEN: usize = 1184;
    const CIPHERTEXT_LEN: usize = 1088;
    const ECDH_PUBLIC_KEY_LEN: usize = 65;
}

/// `mlkem1024nistp384-sha384`.
pub(crate) struct MlKem1024NistP384;

impl HybridMethod for MlKem1024NistP384 {
    type Kem = MlKem1024;
    type Ecdh = NistP384;
    type Hash = Sha384;
    const ENCAPSULATION_KEY_LEN: usize = 1568;
    const CIPHERTEXT_LEN: usize = 1568;
    const ECDH_PUBLIC_KEY_LEN: usize = 97;
}

pub(crate) struct HybridMlKemKexType<M>(PhantomData<fn() -> M>);

impl<M> HybridMlKemKexType<M> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<M: HybridMethod> KexType for HybridMlKemKexType<M>
where
    HybridMlKemKex<M>: Into<KexAlgorithm>,
{
    fn make(&self) -> KexAlgorithm {
        HybridMlKemKex::<M>::new().into()
    }
}

pub(crate) struct HybridMlKemKex<M: HybridMethod> {
    kem_secret: Option<<M::Kem as Kem>::DecapsulationKey>,
    ecdh_secret: Option<<M::Ecdh as KeyAgreement>::PrivateKey>,
    /// `K_PQ`, the ML-KEM shared secret.
    k_pq: Option<Zeroizing<Vec<u8>>>,
    /// `K_CL`, the ECDH shared secret.
    k_cl: Option<Zeroizing<Vec<u8>>>,
}

impl<M: HybridMethod> HybridMlKemKex<M> {
    fn new() -> Self {
        Self {
            kem_secret: None,
            ecdh_secret: None,
            k_pq: None,
            k_cl: None,
        }
    }

    /// `K_CL`, unless [`HybridMethod::REFUSE_ZERO_SECRET`] refuses it.
    fn agree(
        ecdh_secret: <M::Ecdh as KeyAgreement>::PrivateKey,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let k_cl = M::Ecdh::agree(ecdh_secret, peer_public_key).map_err(|_| Error::Kex)?;
        if M::REFUSE_ZERO_SECRET && k_cl.iter().all(|&b| b == 0) {
            debug!("the peer sent a low-order curve25519 public key");
            return Err(Error::Kex);
        }
        Ok(k_cl)
    }

    /// `K = HASH(K_PQ || K_CL)` (RFC 10042 §2.4).
    fn shared_secret(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let k_pq = self.k_pq.as_ref().ok_or(Error::KexInit)?;
        let k_cl = self.k_cl.as_ref().ok_or(Error::KexInit)?;
        let mut secrets = Zeroizing::new(Vec::with_capacity(k_pq.len() + k_cl.len()));
        secrets.extend_from_slice(k_pq);
        secrets.extend_from_slice(k_cl);
        Ok(Zeroizing::new(M::Hash::digest_to_vec(&secrets)))
    }
}

impl<M: HybridMethod> std::fmt::Debug for HybridMlKemKex<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "HybridMlKemKex {{ kem_secret: [hidden], ecdh_secret: [hidden], k_pq: [hidden], k_cl: [hidden] }}",
        )
    }
}

/// The `string` at the start of `bytes`.
fn read_string(bytes: &[u8]) -> Option<&[u8]> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    rest.get(..u32::from_be_bytes(*len) as usize)
}

impl<M: HybridMethod> KexAlgorithmImplementor for HybridMlKemKex<M> {
    fn skip_exchange(&self) -> bool {
        false
    }

    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), Error> {
        debug!("server_dh (hybrid ML-KEM)");

        let c_init = match payload.split_first() {
            Some((&msg::KEX_HYBRID_INIT, rest)) => read_string(rest).ok_or(Error::Inconsistent)?,
            _ => return Err(Error::Inconsistent),
        };

        // RFC 10042 §2.1: the length of C_INIT is checked before
        // encapsulating.
        if c_init.len() != M::ENCAPSULATION_KEY_LEN + M::ECDH_PUBLIC_KEY_LEN {
            return Err(Error::Kex);
        }
        let (c_pk2, c_pk1) = c_init
            .split_at_checked(M::ENCAPSULATION_KEY_LEN)
            .ok_or(Error::Kex)?;

        let (s_ct2, k_pq) = M::Kem::encapsulate(c_pk2).map_err(|_| Error::Kex)?;
        let (ecdh_secret, s_pk1) = M::Ecdh::generate().map_err(|_| Error::Kex)?;
        let k_cl = Self::agree(ecdh_secret, c_pk1)?;

        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend_from_slice(&s_ct2);
        exchange.server_ephemeral.extend_from_slice(&s_pk1);

        self.k_pq = Some(k_pq);
        self.k_cl = Some(k_cl);
        Ok(())
    }

    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        let (kem_secret, c_pk2) = M::Kem::generate().map_err(|_| Error::Kex)?;
        let (ecdh_secret, c_pk1) = M::Ecdh::generate().map_err(|_| Error::Kex)?;

        client_ephemeral.clear();
        client_ephemeral.extend_from_slice(&c_pk2);
        client_ephemeral.extend_from_slice(&c_pk1);

        msg::KEX_HYBRID_INIT.encode(writer)?;
        client_ephemeral.as_slice().encode(writer)?;

        self.kem_secret = Some(kem_secret);
        self.ecdh_secret = Some(ecdh_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), Error> {
        // RFC 10042 §2.1: the length of S_REPLY is checked before
        // decapsulating.
        if remote_pubkey_.len() != M::CIPHERTEXT_LEN + M::ECDH_PUBLIC_KEY_LEN {
            return Err(Error::Kex);
        }
        let (s_ct2, s_pk1) = remote_pubkey_
            .split_at_checked(M::CIPHERTEXT_LEN)
            .ok_or(Error::Kex)?;

        let kem_secret = self.kem_secret.take().ok_or(Error::KexInit)?;
        let k_pq = M::Kem::decapsulate(&kem_secret, s_ct2).map_err(|_| Error::KexInit)?;

        let ecdh_secret = self.ecdh_secret.take().ok_or(Error::KexInit)?;
        let k_cl = Self::agree(ecdh_secret, s_pk1)?;

        self.k_pq = Some(k_pq);
        self.k_cl = Some(k_cl);
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        // `K` is only computed when needed, so this is `K_CL`, the
        // traditional part, as it is for the plain ECDH methods.
        self.k_cl.as_ref().map(|k| k.as_slice())
    }

    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, Error> {
        // RFC 10042 §2.5.
        buffer.clear();
        exchange.client_id.encode(buffer)?;
        exchange.server_id.encode(buffer)?;
        exchange.client_kex_init.encode(buffer)?;
        exchange.server_kex_init.encode(buffer)?;

        buffer.extend(key);

        exchange.client_ephemeral.encode(buffer)?;
        exchange.server_ephemeral.encode(buffer)?;

        self.shared_secret()?.as_slice().encode(buffer)?;

        Ok(M::Hash::digest_to_vec(&buffer[..]))
    }

    fn compute_keys(
        &self,
        session_id: &[u8],
        exchange_hash: &[u8],
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, Error> {
        let shared_secret = SharedSecret::from_string(&self.shared_secret()?)?;

        compute_keys::<M::Hash>(
            Some(&shared_secret),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use ssh_encoding::Encode;

    use super::*;

    /// Runs `check` for each method, with the length of `K_CL` and of the
    /// method's hash.
    macro_rules! for_each_method {
        ($check:ident) => {
            $check::<MlKem768X25519>(32, 32);
            $check::<MlKem768NistP256>(32, 32);
            $check::<MlKem1024NistP384>(48, 48);
        };
    }

    /// A client and a server that have done the key exchange, and the
    /// exchange.
    fn exchange<M: HybridMethod>() -> (HybridMlKemKex<M>, HybridMlKemKex<M>, Exchange) {
        let mut client = HybridMlKemKex::<M>::new();
        let mut server = HybridMlKemKex::<M>::new();
        let mut exchange = Exchange::new(b"SSH-2.0-client", b"SSH-2.0-server");
        let mut init = Vec::new();
        client
            .client_dh(&mut exchange.client_ephemeral, &mut init)
            .unwrap();
        server.server_dh(&mut exchange, &init).unwrap();
        client
            .compute_shared_secret(&exchange.server_ephemeral)
            .unwrap();
        (client, server, exchange)
    }

    #[test]
    fn both_sides_agree() {
        fn check<M: HybridMethod>(k_cl_len: usize, hash_len: usize) {
            let (client, server, exchange) = exchange::<M>();
            assert_eq!(
                exchange.client_ephemeral.len(),
                M::ENCAPSULATION_KEY_LEN + M::ECDH_PUBLIC_KEY_LEN
            );
            assert_eq!(
                exchange.server_ephemeral.len(),
                M::CIPHERTEXT_LEN + M::ECDH_PUBLIC_KEY_LEN
            );
            assert_eq!(client.k_pq.as_ref().unwrap().len(), 32);
            assert_eq!(client.k_pq, server.k_pq, "K_PQ");
            assert_eq!(client.k_cl.as_ref().unwrap().len(), k_cl_len);
            assert_eq!(client.k_cl, server.k_cl, "K_CL");
            assert_eq!(client.shared_secret_bytes(), server.shared_secret_bytes());

            let k = client.shared_secret().unwrap();
            assert_eq!(k.len(), hash_len);
            let mut secrets = client.k_pq.as_ref().unwrap().to_vec();
            secrets.extend_from_slice(client.k_cl.as_ref().unwrap());
            assert_eq!(*k, M::Hash::digest_to_vec(&secrets));

            let host_key = b"\0\0\0\x08host key";
            let mut buffer = CryptoVec::new();
            let client_hash = client
                .compute_exchange_hash(host_key, &exchange, &mut buffer)
                .unwrap();
            let server_hash = server
                .compute_exchange_hash(host_key, &exchange, &mut buffer)
                .unwrap();
            assert_eq!(client_hash, server_hash);
            assert_eq!(client_hash.len(), hash_len);
        }
        for_each_method!(check);
    }

    /// The exchange hash is RFC 10042 §2.5's, with `K` as a string.
    #[test]
    fn exchange_hash_layout() {
        fn check<M: HybridMethod>(_: usize, _: usize) {
            let (client, _, mut exchange) = exchange::<M>();
            exchange.client_kex_init = bytes::Bytes::from_static(b"\x14client kexinit");
            exchange.server_kex_init = bytes::Bytes::from_static(b"\x14server kexinit");
            let host_key = b"\0\0\0\x08host key";
            let mut expected = Vec::new();
            for string in [
                b"SSH-2.0-client".as_slice(),
                b"SSH-2.0-server",
                b"\x14client kexinit",
                b"\x14server kexinit",
            ] {
                string.encode(&mut expected).unwrap();
            }
            expected.extend_from_slice(host_key);
            exchange
                .client_ephemeral
                .as_slice()
                .encode(&mut expected)
                .unwrap();
            exchange
                .server_ephemeral
                .as_slice()
                .encode(&mut expected)
                .unwrap();
            client
                .shared_secret()
                .unwrap()
                .as_slice()
                .encode(&mut expected)
                .unwrap();
            let mut buffer = CryptoVec::new();
            assert_eq!(
                client
                    .compute_exchange_hash(host_key, &exchange, &mut buffer)
                    .unwrap(),
                M::Hash::digest_to_vec(&expected)
            );
        }
        for_each_method!(check);
    }

    #[test]
    fn init_message_format() {
        fn check<M: HybridMethod>(_: usize, _: usize) {
            let mut client = HybridMlKemKex::<M>::new();
            let mut client_ephemeral = Vec::new();
            let mut init = Vec::new();
            client.client_dh(&mut client_ephemeral, &mut init).unwrap();
            let mut expected = vec![msg::KEX_HYBRID_INIT];
            client_ephemeral.as_slice().encode(&mut expected).unwrap();
            assert_eq!(init, expected);
            assert!(client.kem_secret.is_some());
            assert!(client.ecdh_secret.is_some());
        }
        for_each_method!(check);
    }

    /// RFC 10042 §2.1: a C_INIT or S_REPLY of the wrong length is refused.
    #[test]
    fn wrong_lengths_are_refused() {
        fn check<M: HybridMethod>(_: usize, _: usize) {
            let mut client = HybridMlKemKex::<M>::new();
            let mut client_ephemeral = Vec::new();
            let mut init = Vec::new();
            client.client_dh(&mut client_ephemeral, &mut init).unwrap();

            for len in [
                0,
                M::ENCAPSULATION_KEY_LEN,
                client_ephemeral.len() - 1,
                client_ephemeral.len() + 1,
            ] {
                let mut c_init = client_ephemeral.clone();
                c_init.resize(len, 4);
                let mut payload = vec![msg::KEX_HYBRID_INIT];
                c_init.as_slice().encode(&mut payload).unwrap();
                let mut server = HybridMlKemKex::<M>::new();
                let mut exchange = Exchange::default();
                assert!(server.server_dh(&mut exchange, &payload).is_err());
            }

            let mut server = HybridMlKemKex::<M>::new();
            let mut exchange = Exchange::default();
            server.server_dh(&mut exchange, &init).unwrap();
            let s_reply = exchange.server_ephemeral.as_slice();
            let longer = [s_reply, &[0]].concat();
            for s_reply in [&s_reply[1..], &longer[..]] {
                let mut client = HybridMlKemKex::<M>::new();
                client.client_dh(&mut Vec::new(), &mut Vec::new()).unwrap();
                assert!(client.compute_shared_secret(s_reply).is_err());
            }
        }
        for_each_method!(check);
    }

    /// A truncated or mislabeled SSH_MSG_KEX_HYBRID_INIT is refused, without
    /// panicking.
    #[test]
    fn malformed_init_is_refused() {
        fn check<M: HybridMethod>(_: usize, _: usize) {
            let payloads: [&[u8]; 5] = [
                &[],
                &[msg::KEX_HYBRID_INIT],
                &[msg::KEX_HYBRID_INIT, 0, 0],
                &[msg::KEX_HYBRID_INIT, 0, 0, 0, 9, 1],
                &[msg::KEX_HYBRID_INIT + 1, 0, 0, 0, 0],
            ];
            for payload in payloads {
                let mut server = HybridMlKemKex::<M>::new();
                let mut exchange = Exchange::default();
                assert!(server.server_dh(&mut exchange, payload).is_err());
            }
        }
        for_each_method!(check);
    }

    /// An ECDH public key that is not a valid point (all zeroes: for X25519 a
    /// low-order point, for the NIST curves not an uncompressed point) is
    /// refused by both sides.
    #[test]
    fn invalid_ecdh_public_keys_are_refused() {
        fn check<M: HybridMethod>(_: usize, _: usize) {
            let mut client = HybridMlKemKex::<M>::new();
            let mut client_ephemeral = Vec::new();
            client
                .client_dh(&mut client_ephemeral, &mut Vec::new())
                .unwrap();
            client_ephemeral[M::ENCAPSULATION_KEY_LEN..].fill(0);
            let mut payload = vec![msg::KEX_HYBRID_INIT];
            client_ephemeral.as_slice().encode(&mut payload).unwrap();
            let mut server = HybridMlKemKex::<M>::new();
            assert!(
                server
                    .server_dh(&mut Exchange::default(), &payload)
                    .is_err()
            );

            let (_, _, exchange) = exchange::<M>();
            let mut s_reply = exchange.server_ephemeral.clone();
            s_reply[M::CIPHERTEXT_LEN..].fill(0);
            let mut client = HybridMlKemKex::<M>::new();
            client.client_dh(&mut Vec::new(), &mut Vec::new()).unwrap();
            assert!(client.compute_shared_secret(&s_reply).is_err());
        }
        for_each_method!(check);
    }
}
