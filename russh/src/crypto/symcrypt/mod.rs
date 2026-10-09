//! The Microsoft SymCrypt backend (feature `symcrypt`).
//!
//! Selected only when `symcrypt` is the only backend feature enabled
//! (`cargo build -p russh --no-default-features --features symcrypt`; the
//! `russh_backend = "symcrypt"` cfg set by `build.rs`). The native library is
//! linked dynamically by `symcrypt-sys`, which finds it through
//! `SYMCRYPT_LIB_PATH` (and the loader through `LD_LIBRARY_PATH`/`PATH`).
//!
//! # Categories
//!
//! SymCrypt implements every category, each in its own file:
//!
//! | Category | File |
//! |---|---|
//! | `hash`: SHA-1, SHA-2 | `hash.rs` |
//! | `kex`: X25519, ECDH P-256/P-384, ML-KEM-768 hybrid (no P-521, no finite-field DH) | `kex.rs` |
//! | `sign`: ECDSA P-256/P-384, RSA SHA-2 host key, certificate and user signatures (no Ed25519, P-521, SHA-1 RSA) | `sign.rs` |
//! | `cipher`: AES-GCM, ChaCha20-Poly1305, AES-CTR | `cipher.rs` |
//! | `mac`: HMAC-SHA2; HMAC-SHA1 only for hashed `known_hosts` host names | `mac.rs` |
//! | `rng`: all of russh's randomness | `rng.rs` |
//! | Private key loading: SymCrypt checks the keys that format crates parse | `keys.rs` |
//!
//! Nothing comes from the `crypto::rustcrypto` code of the `aws_lc` and
//! `ring` backends, which is not even compiled: its crates and `rand` come
//! with the private `_rustcrypto` feature, which `symcrypt` does not enable.
//! `ci/symcrypt-ban-check.sh` checks that no other crypto implementation is
//! in the dependency graph (`sha2` is, for ssh-key's key fingerprints only).
//!
//! A primitive SymCrypt lacks is `crate::crypto::Unsupported` (`NistP521`
//! and `Dh` in `kex`), and the algorithms that need it are left out of
//! `ALGORITHMS`, so they are neither offered nor accepted.
//!
//! # Changing a category
//!
//! Edit only that category's file (the shared code in `crate::cipher`,
//! `crate::mac`, `crate::kex`, `crate::negotiation` and this `mod.rs` need no
//! change):
//!
//! 1. Implement the category's traits from [`crate::crypto`] with SymCrypt,
//!    keeping the names of the provider contract (see the `crate::crypto`
//!    docs): `hash`: `Sha1`..`Sha512`; `kex`: `X25519`,
//!    `NistP256`/`384`/`521`, `MlKem768`, `Dh` (`Unsupported` if SymCrypt
//!    lacks the primitive); `mac`: also `hmac_sha1`; `sign`: `Signatures`;
//!    `rng`: `SystemRng`.
//! 2. Define the category's `ALGORITHMS` (what the backend implements, with
//!    entries such as `GcmCipher::<SymCryptAes256Gcm>::new()`,
//!    `SshBlockCipher::<SymCryptAes256Ctr>::new()`,
//!    `CryptoEtmMacAlgorithm::<SymCryptHmacSha256>::new()`, or the shared
//!    `crate::kex::_*` key exchanges) and `DEFAULT_ORDER` (what it prefers).
//!    For `sign`, `Signatures::is_supported` decides what is advertised and
//!    accepted, and `DEFAULT_ORDER` the preference.
//! 3. Add unit tests in the same file (known-answer tests, round trips,
//!    and the expected lists). They run with
//!    `cargo test -p russh --no-default-features --features symcrypt --lib -- crypto::symcrypt`;
//!    OpenSSH interoperability tests go in `russh/tests/symcrypt_*.rs` and run
//!    with `cargo test -p russh --no-default-features --features symcrypt --test 'symcrypt_*'`.
//!    CI (`.github/workflows/symcrypt.yml`) runs them.

pub(crate) mod cipher;
pub(crate) mod hash;
pub(crate) mod kex;
pub(crate) mod keys;
pub(crate) mod mac;
pub(crate) mod rng;
pub(crate) mod sign;

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ssh_key::{Algorithm, EcdsaCurve, HashAlg};

    use crate::{Preferred, cipher, compression, kex, mac};

    const P256: Algorithm = Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    };
    const P384: Algorithm = Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    };
    const RSA_SHA512: Algorithm = Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    };
    const RSA_SHA256: Algorithm = Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    };

    #[test]
    fn algorithm_lists_are_consistent() {
        crate::crypto::testing::check_provider_lists();
    }

    /// What russh offers by default with this backend, in order: only
    /// algorithms SymCrypt implements, so `supported()` removes nothing.
    /// The ciphers and MACs are the other backends' defaults:
    /// `aes128-gcm@openssh.com` is implemented, but only offered when
    /// configured.
    #[test]
    fn default_preferences_are_the_symcrypt_algorithms() {
        for pref in [
            Preferred::DEFAULT,
            Preferred::COMPRESSED,
            Preferred::default(),
        ] {
            assert_eq!(
                pref.kex[..],
                [
                    kex::MLKEM768X25519_SHA256,
                    kex::CURVE25519,
                    kex::CURVE25519_PRE_RFC_8731,
                    kex::ECDH_SHA2_NISTP256,
                    kex::ECDH_SHA2_NISTP384,
                    kex::EXTENSION_SUPPORT_AS_CLIENT,
                    kex::EXTENSION_SUPPORT_AS_SERVER,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                ]
            );
            assert_eq!(pref.key[..], [P256, P384, RSA_SHA512, RSA_SHA256]);
            assert!(pref.host_key_certificates.is_empty());
            assert_eq!(
                pref.cipher[..],
                [
                    cipher::CHACHA20_POLY1305,
                    cipher::AES_256_GCM,
                    cipher::AES_256_CTR,
                    cipher::AES_192_CTR,
                    cipher::AES_128_CTR,
                ]
            );
            assert_eq!(
                pref.mac[..],
                [
                    mac::HMAC_SHA512_ETM,
                    mac::HMAC_SHA256_ETM,
                    mac::HMAC_SHA512,
                    mac::HMAC_SHA256,
                ]
            );
            assert_eq!(
                pref.compression[..],
                [
                    compression::NONE,
                    #[cfg(feature = "flate2")]
                    compression::ZLIB,
                    #[cfg(feature = "flate2")]
                    compression::ZLIB_LEGACY,
                ]
            );
            assert!(matches!(pref.supported(), Cow::Borrowed(_)));
        }
    }

    /// Configured algorithms the backend does not implement are neither
    /// offered nor accepted; the others keep their order. Here every
    /// algorithm russh has a name for is configured (3des-cbc only with the
    /// `des` feature), with the signature algorithms SymCrypt lacks.
    #[test]
    fn unsupported_algorithms_are_not_negotiated() {
        let keys = [
            Algorithm::Ed25519,
            P256,
            P384,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            RSA_SHA512,
            RSA_SHA256,
            Algorithm::Rsa { hash: None },
            Algorithm::Dsa,
            Algorithm::SkEd25519,
            Algorithm::SkEcdsaSha2NistP256,
        ];
        let pref = Preferred {
            kex: Cow::Owned(kex::ALL_KEX_ALGORITHMS.iter().map(|k| **k).collect()),
            key: Cow::Owned(keys.to_vec()),
            host_key_certificates: Cow::Owned(keys.to_vec()),
            cipher: Cow::Owned(cipher::ALL_CIPHERS.iter().map(|c| **c).collect()),
            mac: Cow::Owned(mac::ALL_MAC_ALGORITHMS.iter().map(|m| **m).collect()),
            ..Preferred::DEFAULT
        };
        let supported = pref.supported();
        // `none` and `clear` are not cryptography: russh offers them only
        // when they are configured, as here.
        assert_eq!(
            supported.kex[..],
            [
                kex::MLKEM768X25519_SHA256,
                kex::CURVE25519,
                kex::CURVE25519_PRE_RFC_8731,
                kex::ECDH_SHA2_NISTP256,
                kex::ECDH_SHA2_NISTP384,
                kex::NONE,
            ]
        );
        assert_eq!(supported.key[..], [P256, P384, RSA_SHA512, RSA_SHA256]);
        assert_eq!(
            supported.host_key_certificates[..],
            [P256, P384, RSA_SHA512, RSA_SHA256]
        );
        assert_eq!(
            supported.cipher[..],
            [
                cipher::CLEAR,
                cipher::NONE,
                cipher::AES_128_CTR,
                cipher::AES_192_CTR,
                cipher::AES_256_CTR,
                cipher::AES_128_GCM,
                cipher::AES_256_GCM,
                cipher::CHACHA20_POLY1305,
            ]
        );
        assert_eq!(
            supported.mac[..],
            [
                mac::NONE,
                mac::HMAC_SHA256,
                mac::HMAC_SHA512,
                mac::HMAC_SHA256_ETM,
                mac::HMAC_SHA512_ETM,
            ]
        );
    }
}
