//! MACs for the SymCrypt backend: `hmac-sha2-256` and `hmac-sha2-512`, and
//! their `-etm@openssh.com` forms, with `symcrypt::hmac`. The SHA-1 MACs are
//! not offered; HMAC-SHA1 is only used for hashed `known_hosts` host names
//! ([`hmac_sha1`]).

use std::mem::ManuallyDrop;

use symcrypt::hmac::{HmacSha256State, HmacSha512State, HmacState};

use crate::crypto::{CryptoError, Mac, Result};
use crate::mac::crypto::CryptoMacAlgorithm;
use crate::mac::crypto_etm::CryptoEtmMacAlgorithm;
use crate::mac::{self, MacAlgorithm};

macro_rules! hmac {
    ($name:ident, $state:ty, $len:expr) => {
        /// The keyed state, cloned for each MAC.
        pub(crate) struct $name(ManuallyDrop<$state>);

        impl Mac for $name {
            const KEY_LEN: usize = $len;
            const OUTPUT_LEN: usize = $len;

            fn new(key: &[u8]) -> Result<Self> {
                if key.len() != Self::KEY_LEN {
                    return Err(CryptoError);
                }
                <$state>::new(key)
                    .map(|state| Self(ManuallyDrop::new(state)))
                    .map_err(|_| CryptoError)
            }

            fn compute(&self, data: &[&[u8]], output: &mut [u8]) {
                let mut state = <$state>::clone(&self.0);
                for data in data {
                    state.append(data);
                }
                output.copy_from_slice(&state.result());
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // The state's own `Drop` wipes only its first bytes, but
                // `result` resets it to the unkeyed hash state.
                // SAFETY: `self.0` is not used again.
                let _ = unsafe { ManuallyDrop::take(&mut self.0) }.result();
            }
        }
    };
}

hmac!(SymCryptHmacSha256, HmacSha256State, 32);
hmac!(SymCryptHmacSha512, HmacSha512State, 64);

/// HMAC-SHA1 with a key of any length (see [`crate::crypto::hmac_sha1`]).
pub(crate) fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; 20]> {
    ::symcrypt::hmac::hmac_sha1(key, data).map_err(|_| CryptoError)
}

// SAFETY: `symcrypt` declares the SHA-256 and SHA-384 states `Send` but not
// this one, which has the same layout: an owned allocation whose only
// pointer is to its expanded key, which is immutable and shared through an
// `Arc`.
unsafe impl Send for SymCryptHmacSha512 {}

static HMAC_SHA256: CryptoMacAlgorithm<SymCryptHmacSha256> = CryptoMacAlgorithm::new();
static HMAC_SHA512: CryptoMacAlgorithm<SymCryptHmacSha512> = CryptoMacAlgorithm::new();
static HMAC_SHA256_ETM: CryptoEtmMacAlgorithm<SymCryptHmacSha256> = CryptoEtmMacAlgorithm::new();
static HMAC_SHA512_ETM: CryptoEtmMacAlgorithm<SymCryptHmacSha512> = CryptoEtmMacAlgorithm::new();

/// Every MAC of this backend (`none` is shared by all providers).
pub(crate) static ALGORITHMS: &[(&mac::Name, &(dyn MacAlgorithm + Send + Sync))] = &[
    (&mac::HMAC_SHA256, &HMAC_SHA256),
    (&mac::HMAC_SHA512, &HMAC_SHA512),
    (&mac::HMAC_SHA256_ETM, &HMAC_SHA256_ETM),
    (&mac::HMAC_SHA512_ETM, &HMAC_SHA512_ETM),
];

/// The same preference as the other backends.
pub(crate) const DEFAULT_ORDER: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::mac::MACS;

    #[test]
    fn offers_hmac_sha2() {
        assert_eq!(
            ALGORITHMS.iter().map(|(name, _)| **name).collect::<Vec<_>>(),
            [
                mac::HMAC_SHA256,
                mac::HMAC_SHA512,
                mac::HMAC_SHA256_ETM,
                mac::HMAC_SHA512_ETM,
            ]
        );
        assert_eq!(
            DEFAULT_ORDER,
            [
                mac::HMAC_SHA512_ETM,
                mac::HMAC_SHA256_ETM,
                mac::HMAC_SHA512,
                mac::HMAC_SHA256,
            ]
        );
        assert!(!MACS.contains_key(&mac::HMAC_SHA1));
        assert!(!MACS.contains_key(&mac::HMAC_SHA1_ETM));
    }

    /// Checks `M` against an RFC 4231 test case, with the key zero-padded
    /// to `KEY_LEN` (as HMAC pads it anyway).
    fn check<M: Mac>(key: &[u8], data: &[u8], expected: &[u8]) {
        let mut padded_key = vec![0; M::KEY_LEN];
        padded_key[..key.len()].copy_from_slice(key);
        let mac = M::new(&padded_key).unwrap();

        let mut output = vec![0; M::OUTPUT_LEN];
        mac.compute(&[data], &mut output);
        assert_eq!(output, expected);

        // The keyed state is reused, and `data` may come in pieces.
        let (start, end) = data.split_at(data.len() / 2);
        let mut output = vec![0; M::OUTPUT_LEN];
        mac.compute(&[start, &[], end], &mut output);
        assert_eq!(output, expected);
    }

    /// RFC 4231 test cases 1 to 4.
    #[test]
    fn hmac_sha2_matches_rfc4231() {
        let cases = [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                hex!(
                    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                    "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
                ),
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
                hex!(
                    "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                    "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
                ),
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                hex!("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
                hex!(
                    "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
                    "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
                ),
            ),
            (
                (1..=0x19).collect(),
                vec![0xcd; 50],
                hex!("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
                hex!(
                    "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
                    "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
                ),
            ),
        ];
        for (key, data, sha256, sha512) in cases {
            check::<SymCryptHmacSha256>(&key, &data, &sha256);
            check::<SymCryptHmacSha512>(&key, &data, &sha512);
        }
    }

    #[test]
    fn hmac_rejects_other_key_lengths() {
        for len in [0, 20, 31, 33, 64] {
            assert!(SymCryptHmacSha256::new(&vec![0; len]).is_err(), "{len}");
        }
        for len in [0, 32, 63, 65, 128] {
            assert!(SymCryptHmacSha512::new(&vec![0; len]).is_err(), "{len}");
        }
    }

    /// RFC 2202 test cases 1, 2 and 6 (keys shorter and longer than the
    /// digest and the block), and an empty key.
    #[test]
    fn hmac_sha1_matches_rfc2202() {
        let cases: [(&[u8], &[u8], [u8; 20]); 4] = [
            (
                &[0x0b; 20],
                b"Hi There",
                hex!("b617318655057264e28bc0b6fb378c8ef146be00"),
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                hex!("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
            ),
            (
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                hex!("aa4ae5e15272d00e95705637ce8a3b55ed402112"),
            ),
            (b"", b"", hex!("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")),
        ];
        for (key, data, expected) in cases {
            assert_eq!(hmac_sha1(key, data).unwrap(), expected);
        }
    }
}
