use std::marker::PhantomData;

use subtle::ConstantTimeEq;

use super::{Mac, MacAlgorithm};
use crate::crypto;

/// The largest `crypto::Mac::OUTPUT_LEN` (HMAC-SHA-512).
const MAX_MAC_LEN: usize = 64;

/// A MAC computed over the sequence number and the packet, with the
/// primitive `M` of the crypto backend.
pub struct CryptoMacAlgorithm<M>(PhantomData<fn() -> M>);

impl<M> CryptoMacAlgorithm<M> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

pub struct CryptoMac<M>(M);

impl<M: crypto::Mac> CryptoMac<M> {
    pub(crate) fn new(key: &[u8]) -> Self {
        // Key exchange derives exactly `key_len()` bytes.
        #[allow(clippy::expect_used)]
        Self(M::new(key).expect("MAC key of key_len() bytes"))
    }
}

impl<M: crypto::Mac> MacAlgorithm for CryptoMacAlgorithm<M> {
    fn key_len(&self) -> usize {
        M::KEY_LEN
    }

    fn make_mac(&self, mac_key: &[u8]) -> Box<dyn Mac + Send> {
        Box::new(CryptoMac::<M>::new(mac_key))
    }
}

impl<M: crypto::Mac> Mac for CryptoMac<M> {
    fn mac_len(&self) -> usize {
        M::OUTPUT_LEN
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        self.0
            .compute(&[&sequence_number.to_be_bytes(), payload], output)
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        let mut buf = [0; MAX_MAC_LEN];
        let Some(expected) = buf.get_mut(..M::OUTPUT_LEN) else {
            return false;
        };
        self.compute(sequence_number, payload, expected);
        expected.ct_eq(mac).into()
    }
}
