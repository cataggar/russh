//! HMAC-SHA1 and HMAC-SHA2 (RustCrypto `hmac`).

use digest::{KeyInit, Mac as _};
use hmac::Hmac;

use crate::crypto::{CryptoError, Mac, Result};
use crate::mac::crypto::CryptoMacAlgorithm;
use crate::mac::crypto_etm::CryptoEtmMacAlgorithm;
use crate::mac::{self, MacAlgorithm};

macro_rules! hmac {
    ($name:ident, $digest:ty, $len:expr) => {
        pub(crate) struct $name(Hmac<$digest>);

        impl Mac for $name {
            const KEY_LEN: usize = $len;
            const OUTPUT_LEN: usize = $len;

            fn new(key: &[u8]) -> Result<Self> {
                if key.len() != Self::KEY_LEN {
                    return Err(CryptoError);
                }
                Ok(Self(
                    <Hmac<$digest> as KeyInit>::new_from_slice(key).map_err(|_| CryptoError)?,
                ))
            }

            fn compute(&self, data: &[&[u8]], output: &mut [u8]) {
                let mut hmac = self.0.clone();
                for data in data {
                    hmac.update(data);
                }
                output.copy_from_slice(&hmac.finalize().into_bytes());
            }
        }
    };
}

hmac!(HmacSha1, sha1::Sha1, 20);
hmac!(HmacSha256, sha2::Sha256, 32);
hmac!(HmacSha512, sha2::Sha512, 64);

/// HMAC-SHA1 with a key of any length (see [`crate::crypto::hmac_sha1`]).
pub(crate) fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; 20]> {
    let mut hmac =
        <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).map_err(|_| CryptoError)?;
    hmac.update(data);
    Ok(hmac.finalize().into_bytes().into())
}

static HMAC_SHA1: CryptoMacAlgorithm<HmacSha1> = CryptoMacAlgorithm::new();
static HMAC_SHA256: CryptoMacAlgorithm<HmacSha256> = CryptoMacAlgorithm::new();
static HMAC_SHA512: CryptoMacAlgorithm<HmacSha512> = CryptoMacAlgorithm::new();
static HMAC_SHA1_ETM: CryptoEtmMacAlgorithm<HmacSha1> = CryptoEtmMacAlgorithm::new();
static HMAC_SHA256_ETM: CryptoEtmMacAlgorithm<HmacSha256> = CryptoEtmMacAlgorithm::new();
static HMAC_SHA512_ETM: CryptoEtmMacAlgorithm<HmacSha512> = CryptoEtmMacAlgorithm::new();

/// Every MAC of this provider (`none` is shared by all providers).
pub(crate) static ALGORITHMS: &[(&mac::Name, &(dyn MacAlgorithm + Send + Sync))] = &[
    (&mac::HMAC_SHA1, &HMAC_SHA1),
    (&mac::HMAC_SHA256, &HMAC_SHA256),
    (&mac::HMAC_SHA512, &HMAC_SHA512),
    (&mac::HMAC_SHA1_ETM, &HMAC_SHA1_ETM),
    (&mac::HMAC_SHA256_ETM, &HMAC_SHA256_ETM),
    (&mac::HMAC_SHA512_ETM, &HMAC_SHA512_ETM),
];

/// Default MAC preference. SHA-1 variants are excluded.
pub(crate) const DEFAULT_ORDER: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_test_case_2() {
        let key = b"Jefe";
        // HMAC accepts any key length, but SSH always derives KEY_LEN bytes.
        assert!(HmacSha256::new(key).is_err());
        let mut key = [0; 32];
        key[..4].copy_from_slice(b"Jefe");
        let mut output = [0; 32];
        HmacSha256::new(&key)
            .unwrap()
            .compute(&[b"what do ya want ", b"for nothing?"], &mut output);
        assert_eq!(
            output,
            hex_literal::hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }
}
