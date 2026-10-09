//! AES-GCM and `chacha20-poly1305@openssh.com` from aws-lc-rs or ring, whose
//! `aead` modules have the same API. The `aws_lc` and `ring` providers take
//! their `cipher` category from here and everything else from `rustcrypto`.

#[cfg(russh_backend = "aws_lc")]
use ::aws_lc_rs as api;
#[cfg(russh_backend = "ring")]
use ::ring as api;
use api::aead::{Aad, LessSafeKey, Nonce, UnboundKey, chacha20_poly1305_openssh};

use crate::crypto::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, Aead, CHACHA20_POLY1305_KEY_LEN, ChaCha20Poly1305, CryptoError,
    Result,
};

macro_rules! aes_gcm {
    ($name:ident, $algorithm:ident, $key_len:expr) => {
        pub(crate) struct $name(LessSafeKey);

        impl Aead for $name {
            const KEY_LEN: usize = $key_len;

            fn new(key: &[u8]) -> Result<Self> {
                let key = UnboundKey::new(&api::aead::$algorithm, key).map_err(|_| CryptoError)?;
                Ok(Self(LessSafeKey::new(key)))
            }

            fn seal_in_place(
                &self,
                nonce: &[u8; AEAD_NONCE_LEN],
                aad: &[u8],
                in_out: &mut [u8],
                tag: &mut [u8; AEAD_TAG_LEN],
            ) -> Result<()> {
                let computed = self
                    .0
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(*nonce),
                        Aad::from(aad),
                        in_out,
                    )
                    .map_err(|_| CryptoError)?;
                tag.copy_from_slice(computed.as_ref());
                Ok(())
            }

            fn open_in_place(
                &self,
                nonce: &[u8; AEAD_NONCE_LEN],
                aad: &[u8],
                ciphertext_and_tag: &mut [u8],
            ) -> Result<()> {
                self.0
                    .open_in_place(
                        Nonce::assume_unique_for_key(*nonce),
                        Aad::from(aad),
                        ciphertext_and_tag,
                    )
                    .map_err(|_| CryptoError)?;
                Ok(())
            }
        }
    };
}

aes_gcm!(Aes128Gcm, AES_128_GCM, 16);
aes_gcm!(Aes256Gcm, AES_256_GCM, 32);

pub(crate) struct ChaCha20Poly1305Openssh {
    opening: chacha20_poly1305_openssh::OpeningKey,
    sealing: chacha20_poly1305_openssh::SealingKey,
}

impl ChaCha20Poly1305 for ChaCha20Poly1305Openssh {
    fn new(key: &[u8; CHACHA20_POLY1305_KEY_LEN]) -> Result<Self> {
        Ok(Self {
            opening: chacha20_poly1305_openssh::OpeningKey::new(key),
            sealing: chacha20_poly1305_openssh::SealingKey::new(key),
        })
    }

    fn decrypt_packet_length(&self, sequence_number: u32, encrypted_length: [u8; 4]) -> [u8; 4] {
        self.opening
            .decrypt_packet_length(sequence_number, encrypted_length)
    }

    fn open_in_place(
        &self,
        sequence_number: u32,
        packet: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<()> {
        self.opening
            .open_in_place(sequence_number, packet, tag)
            .map_err(|_| CryptoError)?;
        Ok(())
    }

    fn seal_in_place(
        &self,
        sequence_number: u32,
        packet: &mut [u8],
        tag: &mut [u8; AEAD_TAG_LEN],
    ) -> Result<()> {
        self.sealing.seal_in_place(sequence_number, packet, tag);
        Ok(())
    }
}

/// The `cipher` category of the `aws_lc` and `ring` providers.
pub(crate) mod cipher {
    use super::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Openssh};
    use crate::cipher::chacha20poly1305::SshChacha20Poly1305Cipher;
    use crate::cipher::gcm::GcmCipher;
    use crate::cipher::{self, Cipher};
    use crate::crypto::rustcrypto::cipher as rustcrypto;

    static AES_128_GCM: GcmCipher<Aes128Gcm> = GcmCipher::new();
    static AES_256_GCM: GcmCipher<Aes256Gcm> = GcmCipher::new();
    static CHACHA20_POLY1305: SshChacha20Poly1305Cipher<ChaCha20Poly1305Openssh> =
        SshChacha20Poly1305Cipher::new();

    /// The AEADs, plus every cipher of `rustcrypto::cipher`.
    pub(crate) static ALGORITHMS: &[(&cipher::Name, &(dyn Cipher + Send + Sync))] = &[
        (&cipher::AES_128_GCM, &AES_128_GCM),
        (&cipher::AES_256_GCM, &AES_256_GCM),
        (&cipher::CHACHA20_POLY1305, &CHACHA20_POLY1305),
        (&cipher::AES_128_CTR, &rustcrypto::AES_128_CTR),
        (&cipher::AES_192_CTR, &rustcrypto::AES_192_CTR),
        (&cipher::AES_256_CTR, &rustcrypto::AES_256_CTR),
        (&cipher::AES_128_CBC, &rustcrypto::AES_128_CBC),
        (&cipher::AES_192_CBC, &rustcrypto::AES_192_CBC),
        (&cipher::AES_256_CBC, &rustcrypto::AES_256_CBC),
        #[cfg(feature = "des")]
        (&cipher::TRIPLE_DES_CBC, &rustcrypto::TRIPLE_DES_CBC),
    ];

    pub(crate) const DEFAULT_ORDER: &[cipher::Name] = &[
        cipher::CHACHA20_POLY1305,
        cipher::AES_256_GCM,
        cipher::AES_256_CTR,
        cipher::AES_192_CTR,
        cipher::AES_128_CTR,
    ];
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use ssh_key::{Algorithm, EcdsaCurve, HashAlg};

    use super::*;
    use crate::crypto::provider;
    use crate::{cipher, kex, mac};

    /// The algorithm lists of the `aws_lc` and `ring` providers are exactly
    /// the ones russh had before the crypto abstraction.
    pub(crate) fn assert_algorithm_lists_are_unchanged() {
        crate::crypto::testing::check_provider_lists();

        let names = |list: &mut dyn Iterator<Item = &str>| {
            let mut list: Vec<String> = list.map(str::to_owned).collect();
            list.sort();
            list
        };
        let all_but_none = |all: &[&str], none: &[&str]| {
            names(&mut all.iter().copied().filter(|n| !none.contains(n)))
        };

        assert_eq!(
            names(&mut provider::kex::ALGORITHMS.iter().map(|(n, _)| n.as_ref())),
            all_but_none(
                &kex::ALL_KEX_ALGORITHMS
                    .iter()
                    .map(|n| n.as_ref())
                    .collect::<Vec<_>>(),
                &["none"]
            )
        );
        assert_eq!(provider::kex::ALGORITHMS.len(), 15);
        assert_eq!(
            provider::kex::DEFAULT_ORDER,
            [
                kex::MLKEM768X25519_SHA256,
                kex::CURVE25519,
                kex::CURVE25519_PRE_RFC_8731,
                kex::DH_GEX_SHA256,
                kex::DH_G18_SHA512,
                kex::DH_G17_SHA512,
                kex::DH_G16_SHA512,
                kex::DH_G15_SHA512,
                kex::DH_G14_SHA256,
            ]
        );

        assert_eq!(
            provider::sign::DEFAULT_ORDER,
            [
                Algorithm::Ed25519,
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256
                },
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP384
                },
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP521
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512)
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256)
                },
                Algorithm::Rsa { hash: None },
            ]
        );

        assert_eq!(
            names(&mut provider::cipher::ALGORITHMS.iter().map(|(n, _)| n.as_ref())),
            all_but_none(
                &cipher::ALL_CIPHERS
                    .iter()
                    .map(|n| n.as_ref())
                    .collect::<Vec<_>>(),
                &["clear", "none"]
            )
        );
        assert_eq!(
            provider::cipher::DEFAULT_ORDER,
            [
                cipher::CHACHA20_POLY1305,
                cipher::AES_256_GCM,
                cipher::AES_256_CTR,
                cipher::AES_192_CTR,
                cipher::AES_128_CTR,
            ]
        );

        assert_eq!(
            names(&mut provider::mac::ALGORITHMS.iter().map(|(n, _)| n.as_ref())),
            all_but_none(
                &mac::ALL_MAC_ALGORITHMS
                    .iter()
                    .map(|n| n.as_ref())
                    .collect::<Vec<_>>(),
                &["none"]
            )
        );
        assert_eq!(
            provider::mac::DEFAULT_ORDER,
            [
                mac::HMAC_SHA512_ETM,
                mac::HMAC_SHA256_ETM,
                mac::HMAC_SHA512,
                mac::HMAC_SHA256,
            ]
        );
    }

    #[test]
    fn aes_gcm_round_trips_and_rejects_tampering() {
        let aead = Aes256Gcm::new(&[7; 32]).unwrap();
        assert!(Aes256Gcm::new(&[7; 16]).is_err());
        let nonce = [1; AEAD_NONCE_LEN];
        let mut data = *b"0123456789abcdef0123456789abcdef";
        let mut tag = [0; AEAD_TAG_LEN];
        aead.seal_in_place(&nonce, b"aad", &mut data[..16], &mut tag)
            .unwrap();
        data[16..].copy_from_slice(&tag);
        let mut tampered = data;
        aead.open_in_place(&nonce, b"aad", &mut data).unwrap();
        assert_eq!(&data[..16], b"0123456789abcdef");
        tampered[0] ^= 1;
        assert!(aead.open_in_place(&nonce, b"aad", &mut tampered).is_err());
    }

    #[test]
    fn chacha20_poly1305_round_trips() {
        let key = [3; CHACHA20_POLY1305_KEY_LEN];
        let cipher = ChaCha20Poly1305Openssh::new(&key).unwrap();
        let mut packet = *b"\0\0\0\x0cpayload-1234";
        let mut tag = [0; AEAD_TAG_LEN];
        cipher.seal_in_place(7, &mut packet, &mut tag).unwrap();
        assert_eq!(
            cipher.decrypt_packet_length(7, packet[..4].try_into().unwrap()),
            [0, 0, 0, 12]
        );
        cipher.open_in_place(7, &mut packet, &tag).unwrap();
        assert_eq!(&packet[4..], b"payload-1234");
        assert!(cipher.open_in_place(8, &mut packet, &tag).is_err());
    }
}
