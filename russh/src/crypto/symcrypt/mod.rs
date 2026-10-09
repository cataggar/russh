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

    use crate::{cipher, kex, mac};

    #[test]
    fn algorithm_lists_are_consistent() {
        crate::crypto::testing::check_provider_lists();
    }

    /// Configured algorithms the backend does not implement are neither
    /// offered nor accepted; the others keep their order.
    #[test]
    fn unsupported_algorithms_are_not_negotiated() {
        let pref = crate::Preferred {
            kex: Cow::Owned(kex::ALL_KEX_ALGORITHMS.iter().map(|k| **k).collect()),
            cipher: Cow::Owned(cipher::ALL_CIPHERS.iter().map(|c| **c).collect()),
            mac: Cow::Owned(mac::ALL_MAC_ALGORITHMS.iter().map(|m| **m).collect()),
            ..crate::Preferred::DEFAULT
        };
        let supported = pref.supported();
        assert!(supported.kex.iter().copied().eq(kex::ALL_KEX_ALGORITHMS
            .iter()
            .map(|k| **k)
            .filter(|k| kex::KEXES.contains_key(k))));
        assert!(supported.cipher.iter().copied().eq(cipher::ALL_CIPHERS
            .iter()
            .map(|c| **c)
            .filter(|c| cipher::CIPHERS.contains_key(c))));
        assert!(supported.mac.iter().copied().eq(mac::ALL_MAC_ALGORITHMS
            .iter()
            .map(|m| **m)
            .filter(|m| mac::MACS.contains_key(m))));
        assert!(!supported.kex.is_empty());
        assert!(!supported.cipher.is_empty());
        assert!(!supported.mac.is_empty());
    }
}
