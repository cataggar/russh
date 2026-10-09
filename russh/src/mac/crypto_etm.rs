use std::marker::PhantomData;

use super::crypto::CryptoMac;
use super::{Mac, MacAlgorithm};
use crate::crypto;

/// Like [`CryptoMacAlgorithm`](super::crypto::CryptoMacAlgorithm), but
/// encrypt-then-MAC (`*-etm@openssh.com`).
pub struct CryptoEtmMacAlgorithm<M>(PhantomData<fn() -> M>);

impl<M> CryptoEtmMacAlgorithm<M> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<M: crypto::Mac> MacAlgorithm for CryptoEtmMacAlgorithm<M> {
    fn key_len(&self) -> usize {
        M::KEY_LEN
    }

    fn make_mac(&self, mac_key: &[u8]) -> Box<dyn Mac + Send> {
        Box::new(CryptoEtmMac(CryptoMac::<M>::new(mac_key)))
    }
}

pub struct CryptoEtmMac<M>(CryptoMac<M>);

impl<M: crypto::Mac> Mac for CryptoEtmMac<M> {
    fn is_etm(&self) -> bool {
        true
    }

    fn mac_len(&self) -> usize {
        self.0.mac_len()
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        self.0.compute(sequence_number, payload, output)
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        self.0.verify(sequence_number, payload, mac)
    }
}
