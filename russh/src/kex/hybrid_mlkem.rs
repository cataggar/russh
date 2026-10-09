use byteorder::{BigEndian, ByteOrder};
use log::debug;
use ssh_encoding::{Encode, Writer};
use zeroize::Zeroizing;

use super::{compute_keys, KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret};
use crate::crypto::provider::hash::Sha256;
use crate::crypto::provider::kex::{MlKem768, X25519};
use crate::crypto::{Hash, Kem, KeyAgreement};
use crate::mac;
use crate::session::Exchange;
use crate::{cipher, msg, CryptoVec, Error};

const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;
const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
const X25519_PUBLIC_KEY_SIZE: usize = 32;

pub struct MlKem768X25519KexType {}

impl KexType for MlKem768X25519KexType {
    fn make(&self) -> KexAlgorithm {
        MlKem768X25519Kex {
            mlkem_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        }
        .into()
    }
}

#[doc(hidden)]
pub struct MlKem768X25519Kex {
    mlkem_secret: Option<<MlKem768 as Kem>::DecapsulationKey>,
    x25519_secret: Option<<X25519 as KeyAgreement>::PrivateKey>,
    k_pq: Option<Zeroizing<Vec<u8>>>,
    k_cl: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for MlKem768X25519Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "MlKem768X25519Kex {{ mlkem_secret: [hidden], x25519_secret: [hidden], k_pq: [hidden], k_cl: [hidden] }}",
        )
    }
}

impl KexAlgorithmImplementor for MlKem768X25519Kex {
    fn skip_exchange(&self) -> bool {
        false
    }

    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), Error> {
        debug!("server_dh (hybrid ML-KEM)");

        if payload.first() != Some(&msg::KEX_HYBRID_INIT) {
            return Err(Error::Inconsistent);
        }

        #[allow(clippy::indexing_slicing)]
        let c_init_len = BigEndian::read_u32(&payload[1..]) as usize;

        if payload.len() < 5 + c_init_len {
            return Err(Error::Inconsistent);
        }

        if c_init_len != MLKEM768_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE {
            return Err(Error::Kex);
        }

        #[allow(clippy::indexing_slicing)]
        let c_init = &payload[5..5 + c_init_len];

        #[allow(clippy::indexing_slicing)]
        let c_pk2_bytes = &c_init[..MLKEM768_PUBLIC_KEY_SIZE];
        #[allow(clippy::indexing_slicing)]
        let c_pk1_bytes = &c_init[MLKEM768_PUBLIC_KEY_SIZE..];

        let (s_ct2, k_pq_shared_secret) =
            MlKem768::encapsulate(c_pk2_bytes).map_err(|_| Error::Kex)?;

        let (s_secret, s_pk1) = X25519::generate().map_err(|_| Error::Kex)?;

        let k_cl = X25519::agree(s_secret, c_pk1_bytes).map_err(|_| Error::Kex)?;
        if k_cl.iter().all(|&b| b == 0) {
            debug!("client sent a low-order curve25519 pubkey");
            return Err(Error::Kex);
        }

        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend_from_slice(&s_ct2);
        exchange.server_ephemeral.extend_from_slice(&s_pk1);

        self.k_pq = Some(k_pq_shared_secret);
        self.k_cl = Some(k_cl);

        Ok(())
    }

    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        let (mlkem_sk, mlkem_pk) = MlKem768::generate().map_err(|_| Error::Kex)?;

        let (x25519_secret, x25519_pk) = X25519::generate().map_err(|_| Error::Kex)?;

        client_ephemeral.clear();
        client_ephemeral.extend(&mlkem_pk);
        client_ephemeral.extend(&x25519_pk);

        msg::KEX_HYBRID_INIT.encode(writer)?;
        let mut c_init = Vec::<u8>::new();
        c_init.extend(&mlkem_pk);
        c_init.extend(&x25519_pk);
        c_init.as_slice().encode(writer)?;

        self.mlkem_secret = Some(mlkem_sk);
        self.x25519_secret = Some(x25519_secret);

        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), Error> {
        if remote_pubkey_.len() != MLKEM768_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE {
            return Err(Error::Kex);
        }

        #[allow(clippy::indexing_slicing)]
        let s_ct2_bytes = &remote_pubkey_[..MLKEM768_CIPHERTEXT_SIZE];
        #[allow(clippy::indexing_slicing)]
        let s_pk1_bytes = &remote_pubkey_[MLKEM768_CIPHERTEXT_SIZE..];

        let mlkem_secret = self.mlkem_secret.take().ok_or(Error::KexInit)?;
        let k_pq_shared_secret =
            MlKem768::decapsulate(&mlkem_secret, s_ct2_bytes).map_err(|_| Error::KexInit)?;

        let x25519_secret = self.x25519_secret.take().ok_or(Error::KexInit)?;
        let k_cl = X25519::agree(x25519_secret, s_pk1_bytes).map_err(|_| Error::Kex)?;
        if k_cl.iter().all(|&b| b == 0) {
            debug!("server sent a low-order curve25519 pubkey");
            return Err(Error::Kex);
        }

        self.k_pq = Some(k_pq_shared_secret);
        self.k_cl = Some(k_cl);

        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        // For hybrid KEX, the shared secret is a combination of ML-KEM and X25519.
        // The actual combined secret is computed during compute_keys.
        // We return the X25519 portion as that's what's directly available.
        // Users needing the full hybrid secret should use compute_keys.
        self.k_cl.as_ref().map(|k| k.as_slice())
    }

    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, Error> {
        buffer.clear();
        exchange.client_id.encode(buffer)?;
        exchange.server_id.encode(buffer)?;
        exchange.client_kex_init.encode(buffer)?;
        exchange.server_kex_init.encode(buffer)?;

        buffer.extend(key);

        exchange.client_ephemeral.encode(buffer)?;
        exchange.server_ephemeral.encode(buffer)?;

        let k_pq = self.k_pq.as_ref().ok_or(Error::KexInit)?;
        let k_cl = self.k_cl.as_ref().ok_or(Error::KexInit)?;

        let k = combined_secret(k_pq, k_cl);
        k.as_slice().encode(buffer)?;

        Ok(Sha256::digest_to_vec(&buffer[..]))
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
        let k_pq = self.k_pq.as_ref().ok_or(Error::KexInit)?;
        let k_cl = self.k_cl.as_ref().ok_or(Error::KexInit)?;

        let k = combined_secret(k_pq, k_cl);
        let shared_secret = SharedSecret::from_string(&k)?;

        compute_keys::<Sha256>(
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

/// `K = SHA-256(K_PQ || K_CL)` (draft-ietf-sshm-mlkem-hybrid-kex).
fn combined_secret(k_pq: &[u8], k_cl: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut combined = Zeroizing::new(Vec::with_capacity(k_pq.len() + k_cl.len()));
    combined.extend_from_slice(k_pq);
    combined.extend_from_slice(k_cl);
    Zeroizing::new(Sha256::digest_to_vec(&combined))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_encoding::Encode;

    #[test]
    fn test_mlkem768x25519_key_exchange() {
        let mut client_kex = MlKem768X25519Kex {
            mlkem_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        };

        let mut server_kex = MlKem768X25519Kex {
            mlkem_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        };

        let mut client_ephemeral = Vec::new();
        let mut client_init_msg = Vec::new();

        client_kex
            .client_dh(&mut client_ephemeral, &mut client_init_msg)
            .unwrap();

        assert_eq!(
            client_ephemeral.len(),
            MLKEM768_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE
        );
        assert!(client_kex.mlkem_secret.is_some());
        assert!(client_kex.x25519_secret.is_some());

        let mut exchange = Exchange::default();
        server_kex
            .server_dh(&mut exchange, &client_init_msg)
            .unwrap();

        assert_eq!(
            exchange.server_ephemeral.len(),
            MLKEM768_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE
        );
        assert!(server_kex.k_pq.is_some());
        assert!(server_kex.k_cl.is_some());

        client_kex
            .compute_shared_secret(&exchange.server_ephemeral)
            .unwrap();

        assert!(client_kex.k_pq.is_some());
        assert!(client_kex.k_cl.is_some());

        let client_k_pq = client_kex.k_pq.unwrap();
        let server_k_pq = server_kex.k_pq.unwrap();
        assert_eq!(
            client_k_pq, server_k_pq,
            "ML-KEM shared secrets should match"
        );

        let client_k_cl = client_kex.k_cl.unwrap();
        let server_k_cl = server_kex.k_cl.unwrap();
        assert_eq!(
            client_k_cl, server_k_cl,
            "X25519 shared secrets should match"
        );
    }

    #[test]
    fn test_mlkem768x25519_exchange_hash() {
        let mut client_kex = MlKem768X25519Kex {
            mlkem_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        };

        let mut server_kex = MlKem768X25519Kex {
            mlkem_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        };

        let mut client_ephemeral = Vec::new();
        let mut client_init_msg = Vec::new();
        client_kex
            .client_dh(&mut client_ephemeral, &mut client_init_msg)
            .unwrap();

        let mut exchange = Exchange {
            client_id: b"SSH-2.0-Test_Client".to_vec(),
            server_id: b"SSH-2.0-Test_Server".to_vec(),
            client_kex_init: bytes::Bytes::from_static(b"client_kex_init"),
            server_kex_init: bytes::Bytes::from_static(b"server_kex_init"),
            client_ephemeral: client_ephemeral.clone(),
            server_ephemeral: Vec::new(),
            gex: None,
        };

        server_kex
            .server_dh(&mut exchange, &client_init_msg)
            .unwrap();
        client_kex
            .compute_shared_secret(&exchange.server_ephemeral)
            .unwrap();

        let key = b"test_host_key";
        let mut buffer = CryptoVec::new();

        let client_hash = client_kex
            .compute_exchange_hash(key, &exchange, &mut buffer)
            .unwrap();

        let server_hash = server_kex
            .compute_exchange_hash(key, &exchange, &mut buffer)
            .unwrap();

        assert_eq!(
            client_hash, server_hash,
            "Exchange hashes should match between client and server"
        );
        assert_eq!(client_hash.len(), 32, "SHA-256 hash should be 32 bytes");
    }

    #[test]
    fn test_mlkem768x25519_invalid_ciphertext_length() {
        let mut client_kex = MlKem768X25519Kex {
            mlkem_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        };

        let mut client_ephemeral = Vec::new();
        let mut client_init_msg = Vec::new();
        client_kex
            .client_dh(&mut client_ephemeral, &mut client_init_msg)
            .unwrap();

        let invalid_reply = vec![0u8; 100];
        let result = client_kex.compute_shared_secret(&invalid_reply);

        assert!(result.is_err(), "Should reject invalid ciphertext length");
    }

    #[test]
    fn test_mlkem768x25519_invalid_init_length() {
        let mut server_kex = MlKem768X25519Kex {
            mlkem_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        };

        let mut invalid_init = Vec::new();
        msg::KEX_HYBRID_INIT.encode(&mut invalid_init).unwrap();
        let invalid_data = vec![0u8; 100];
        invalid_data.encode(&mut invalid_init).unwrap();

        let mut exchange = Exchange::default();
        let result = server_kex.server_dh(&mut exchange, &invalid_init);

        assert!(result.is_err(), "Should reject invalid C_INIT length");
    }

    #[test]
    fn test_mlkem768x25519_message_format() {
        let mut client_kex = MlKem768X25519Kex {
            mlkem_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
        };

        let mut client_ephemeral = Vec::new();
        let mut client_init_msg = Vec::new();
        client_kex
            .client_dh(&mut client_ephemeral, &mut client_init_msg)
            .unwrap();

        assert!(client_init_msg.len() > 5, "Message should include header");

        assert_eq!(
            client_init_msg[0],
            msg::KEX_HYBRID_INIT,
            "First byte should be KEX_HYBRID_INIT"
        );
    }
}
