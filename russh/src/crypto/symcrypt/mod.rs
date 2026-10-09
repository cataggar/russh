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
//! Each category lives in its own file and is implemented independently:
//!
//! | Category | File | Issue |
//! |---|---|---|
//! | `hash`: SHA-1, SHA-2 | `hash.rs` | #2 |
//! | `kex`: X25519, ECDH, ML-KEM-768 hybrid, DH groups | `kex.rs` | #2 |
//! | `sign`: host key, certificate and user signatures | `sign.rs` | #3 |
//! | `cipher`: AEADs, AES-CTR/CBC | `cipher.rs` | #4 |
//! | `mac`: HMAC-SHA1/SHA2 | `mac.rs` | #4 |
//! | `rng`: protocol randomness | `rng.rs` | done |
//!
//! A file that still re-exports the [`rustcrypto`](super::rustcrypto)
//! implementation (exactly like the `aws_lc` and `ring` backends do for
//! their non-AEAD categories) says so with a `TODO(#issue)` comment. With
//! those re-exports this backend already interoperates with OpenSSH using
//! `aes*-ctr`, `hmac-sha2-*`, `curve25519-sha256`/`mlkem768x25519-sha256`
//! and Ed25519/ECDSA keys (RSA too with the `rsa` feature), but offers no
//! AEAD cipher yet.
//!
//! # Swapping a category
//!
//! Edit only that category's file (the shared code in `crate::cipher`,
//! `crate::mac`, `crate::kex`, `crate::negotiation` and this `mod.rs` need no
//! change):
//!
//! 1. Replace the re-export with types that implement the category's traits
//!    from [`crate::crypto`] with SymCrypt, keeping the names of the provider
//!    contract (see the `crate::crypto` docs): `hash`: `Sha1`..`Sha512`;
//!    `kex`: `X25519`, `NistP256`/`384`/`521`, `MlKem768`, `Dh` (set a
//!    primitive SymCrypt lacks to `crate::crypto::Unsupported`, or keep
//!    re-exporting the rustcrypto one); `sign`: `Signatures`; `rng`:
//!    `SystemRng`.
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
//!    CI (`.github/workflows/symcrypt.yml`) runs both filters.

pub(crate) mod cipher;
pub(crate) mod hash;
pub(crate) mod kex;
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
