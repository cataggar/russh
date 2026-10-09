use std::marker::PhantomData;
use std::ops::Deref;

use byteorder::{BigEndian, ByteOrder};
use log::debug;
use ssh_encoding::{Encode, Writer};
use zeroize::Zeroizing;

use super::{KexAlgorithm, SharedSecret as KexSharedSecret, encode_mpint};
use crate::crypto::provider::hash::{Sha256, Sha384, Sha512};
use crate::crypto::provider::kex::{NistP256, NistP384, NistP521};
use crate::crypto::{Hash, KeyAgreement};
use crate::kex::{KexAlgorithmImplementor, KexType, compute_keys};
use crate::mac::{self};
use crate::session::Exchange;
use crate::{CryptoVec, cipher, msg};

pub struct EcdhNistP256KexType {}

impl KexType for EcdhNistP256KexType {
    fn make(&self) -> KexAlgorithm {
        EcdhNistPKex::<NistP256, Sha256>::new().into()
    }
}

pub struct EcdhNistP384KexType {}

impl KexType for EcdhNistP384KexType {
    fn make(&self) -> KexAlgorithm {
        EcdhNistPKex::<NistP384, Sha384>::new().into()
    }
}

pub struct EcdhNistP521KexType {}

impl KexType for EcdhNistP521KexType {
    fn make(&self) -> KexAlgorithm {
        EcdhNistPKex::<NistP521, Sha512>::new().into()
    }
}

/// ECDH key exchange (RFC 5656) over the provider's key agreement `K`
/// and hash `H`.
#[doc(hidden)]
pub struct EcdhNistPKex<K: KeyAgreement, H> {
    local_secret: Option<K::PrivateKey>,
    shared_secret: Option<Zeroizing<Vec<u8>>>,
    _digest: PhantomData<fn() -> H>,
}

impl<K: KeyAgreement, H> EcdhNistPKex<K, H> {
    fn new() -> Self {
        Self {
            local_secret: None,
            shared_secret: None,
            _digest: PhantomData,
        }
    }
}

impl<K: KeyAgreement, H> std::fmt::Debug for EcdhNistPKex<K, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

impl<K: KeyAgreement, H: Hash> KexAlgorithmImplementor for EcdhNistPKex<K, H> {
    fn skip_exchange(&self) -> bool {
        false
    }

    #[doc(hidden)]
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), crate::Error> {
        debug!("server_dh");

        let client_pubkey = {
            if payload.first() != Some(&msg::KEX_ECDH_INIT) {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;

            if payload.len() < 5 + pubkey_len {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            &payload[5..(5 + pubkey_len)]
        };

        let (server_secret, server_pubkey) = K::generate().map_err(|_| crate::Error::Kex)?;
        let shared =
            K::agree(server_secret, client_pubkey).map_err(|_| crate::Error::Inconsistent)?;

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend_from_slice(&server_pubkey);
        self.shared_secret = Some(shared);
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), crate::Error> {
        let (client_secret, client_pubkey) = K::generate().map_err(|_| crate::Error::Kex)?;

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend_from_slice(&client_pubkey);

        msg::KEX_ECDH_INIT.encode(writer)?;
        client_pubkey.as_slice().encode(writer)?;

        self.local_secret = Some(client_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let local_secret = self.local_secret.take().ok_or(crate::Error::KexInit)?;
        let shared = K::agree(local_secret, remote_pubkey_).map_err(|_| crate::Error::KexInit)?;
        self.shared_secret = Some(shared);
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        self.shared_secret.as_ref().map(|s| s.as_slice())
    }

    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        exchange.client_id.deref().encode(buffer)?;
        exchange.server_id.deref().encode(buffer)?;
        exchange.client_kex_init.deref().encode(buffer)?;
        exchange.server_kex_init.deref().encode(buffer)?;

        buffer.extend(key);
        exchange.client_ephemeral.deref().encode(buffer)?;
        exchange.server_ephemeral.deref().encode(buffer)?;

        if let Some(ref shared) = self.shared_secret {
            encode_mpint(shared, buffer)?;
        }

        Ok(H::digest_to_vec(&buffer[..]))
    }

    fn compute_keys(
        &self,
        session_id: &[u8],
        exchange_hash: &[u8],
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<crate::kex::cipher::CipherPair, crate::Error> {
        let shared_secret = self
            .shared_secret
            .as_ref()
            .map(|x| KexSharedSecret::from_mpint(x))
            .transpose()?;

        compute_keys::<H>(
            shared_secret.as_ref(),
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
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret() {
        let (secret1, p1_pubkey) = NistP256::generate().unwrap();
        let mut party1 = EcdhNistPKex::<NistP256, Sha256>::new();
        party1.local_secret = Some(secret1);

        let (secret2, p2_pubkey) = NistP256::generate().unwrap();
        let mut party2 = EcdhNistPKex::<NistP256, Sha256>::new();
        party2.local_secret = Some(secret2);

        party1.compute_shared_secret(&p2_pubkey).unwrap();
        party2.compute_shared_secret(&p1_pubkey).unwrap();

        let p1_shared_secret = party1.shared_secret.unwrap();
        let p2_shared_secret = party2.shared_secret.unwrap();

        assert_eq!(p1_shared_secret, p2_shared_secret)
    }
}
