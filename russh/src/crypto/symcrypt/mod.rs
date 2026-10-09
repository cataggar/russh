//! The Microsoft SymCrypt backend (feature `symcrypt`).
//!
//! Selected only when `symcrypt` is the only backend feature enabled
//! (`cargo build -p russh --no-default-features --features symcrypt`; the
//! `russh_backend = "symcrypt"` cfg set by `build.rs`). The native library is
//! linked dynamically by `symcrypt-sys`, which finds it through
//! `SYMCRYPT_LIB_PATH` (and the loader through `LD_LIBRARY_PATH`/`PATH`).
//!
//! # Status
//!
//! Each category lives in its own file and is replaced independently. Until
//! then it re-exports the [`rustcrypto`](super::rustcrypto) category, exactly
//! like the `aws_lc` and `ring` backends do for their non-AEAD categories:
//!
//! | Category | File | Implementation today | Issue |
//! |---|---|---|---|
//! | `hash` | `hash.rs` | rustcrypto (`sha1`, `sha2`) | TODO(#2) |
//! | `kex` | `kex.rs` | rustcrypto (`curve25519-dalek`, `p256`/`p384`/`p521`, `ml-kem`, `num-bigint`) | TODO(#2) |
//! | `sign` | `sign.rs` | rustcrypto (`ssh-key`) | TODO(#3) |
//! | `cipher` | `cipher.rs` | rustcrypto AES-CTR/CBC; no AEAD yet | TODO(#4) |
//! | `mac` | `mac.rs` | rustcrypto (`hmac`) | TODO(#4) |
//! | `rng` | `rng.rs` | SymCrypt (`SymCryptRandom`) | done |
//!
//! So this backend already interoperates with OpenSSH using `aes*-ctr`,
//! `hmac-sha2-*`, `curve25519-sha256`/`mlkem768x25519-sha256` and
//! Ed25519/ECDSA/RSA keys.
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
    use crate::{cipher, kex, mac};

    #[test]
    fn algorithm_lists_are_consistent() {
        crate::crypto::testing::check_provider_lists();
    }

    /// What the backend offers until the categories are replaced: no AEAD,
    /// AES-CTR, HMAC-SHA2 and the rustcrypto key exchanges.
    #[test]
    fn algorithm_lists() {
        assert!(cipher::CIPHERS.contains_key(&cipher::AES_256_CTR));
        assert!(!cipher::CIPHERS.contains_key(&cipher::AES_256_GCM));
        assert!(!cipher::CIPHERS.contains_key(&cipher::CHACHA20_POLY1305));
        assert_eq!(
            super::cipher::DEFAULT_ORDER,
            [cipher::AES_256_CTR, cipher::AES_192_CTR, cipher::AES_128_CTR]
        );
        assert!(mac::MACS.contains_key(&mac::HMAC_SHA256_ETM));
        assert!(kex::KEXES.contains_key(&kex::CURVE25519));
        assert!(kex::KEXES.contains_key(&kex::MLKEM768X25519_SHA256));
    }
}
