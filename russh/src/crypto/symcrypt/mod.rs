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
//! | `kex`: X25519, ECDH P-256/P-384/P-521, ML-KEM-768 and ML-KEM-1024 hybrids, finite-field DH Groups 14–18 and DH-GEX SHA-256 (no SHA-1 finite-field DH) | `kex.rs` |
//! | `sign`: ECDSA P-256/P-384/P-521, RSA SHA-2 host key, certificate and user signatures (no SHA-1 RSA; no Ed25519 without `ed25519-aws-lc`) | `sign.rs` |
//! | `cipher`: AES-GCM, ChaCha20-Poly1305, AES-CTR | `cipher.rs` |
//! | `mac`: HMAC-SHA2; HMAC-SHA1 only for hashed `known_hosts` host names | `mac.rs` |
//! | `rng`: all of russh's randomness | `rng.rs` |
//! | Private key loading: SymCrypt checks the keys that format crates parse | `keys.rs` |
//!
//! Nothing comes from the `crypto::rustcrypto` code of the `aws_lc` and
//! `ring` backends, which is not even compiled: its crates and `rand` come
//! with the private `_rustcrypto` feature, which `symcrypt` does not enable.
//! `_rustcrypto` also enables `ssh-key`'s `sha2` feature (README.md lists the
//! `ssh_key` APIs that need it), so `ssh-key` doesn't depend on `sha2` either.
//! `ci/symcrypt-ban-check.sh` checks that no other crypto implementation is
//! in the dependency graph.
//!
//! The one exception is opt-in: SymCrypt has no EdDSA, so the
//! `ed25519-aws-lc` feature takes Ed25519 signatures and keys from
//! `aws-lc-rs`, in `ed25519.rs` and nowhere else (the `russh_ed25519_aws_lc`
//! cfg). The ban check allows `aws-lc-rs` only with
//! `--allow-aws-lc-ed25519`.
//!
//! A primitive SymCrypt lacks is `crate::crypto::Unsupported`, and any
//! algorithms that need it (or use SHA-1, such as the legacy SHA-1
//! finite-field DH methods) are left out of `ALGORITHMS`, so they are neither
//! offered nor accepted.
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
//!    `NistP256`/`384`/`521`, `MlKem768`, `MlKem1024`, `Dh` (`Unsupported`
//!    if SymCrypt lacks the primitive); `mac`: also `hmac_sha1`; `sign`:
//!    `Signatures`; `rng`: `SystemRng`.
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
#[cfg(russh_ed25519_aws_lc)]
pub(crate) mod ed25519;
pub(crate) mod hash;
pub(crate) mod kex;
pub(crate) mod keys;
pub(crate) mod mac;
pub(crate) mod rng;
pub(crate) mod sign;

/// Prints the path of the `symcrypt.dll` that the doctests loaded and, if
/// `RUSSH_EXPECTED_SYMCRYPT_DLL` is set, fails unless that DLL has the same contents as the file it
/// names. rustdoc builds and runs doctests in a temporary directory, where Windows would load
/// `C:\Windows\System32\symcrypt.dll` (an OS copy that some images have) rather than the SymCrypt
/// on `PATH`. CI runs them with `ci/symcrypt-doctest-runner.ps1` as the Cargo runner, which copies
/// the pinned DLL next to each doctest executable, and sets `RUSSH_EXPECTED_SYMCRYPT_DLL` to the
/// pinned DLL.
///
/// ```
/// use std::ffi::{OsString, c_void};
/// use std::os::windows::ffi::OsStringExt;
/// use std::path::Path;
///
/// #[link(name = "kernel32")]
/// unsafe extern "system" {
///     fn GetModuleHandleW(name: *const u16) -> *mut c_void;
///     fn GetModuleFileNameW(module: *mut c_void, path: *mut u16, size: u32) -> u32;
/// }
///
/// // A SymCrypt call makes sure the doctest executable imports symcrypt.dll.
/// let mut bytes = [0u8; 16];
/// symcrypt::symcrypt_random(&mut bytes);
///
/// let name: Vec<u16> = "symcrypt.dll\0".encode_utf16().collect();
/// // SAFETY: `name` is a NUL-terminated UTF-16 string; the handle is not freed.
/// let module = unsafe { GetModuleHandleW(name.as_ptr()) };
/// assert!(!module.is_null(), "symcrypt.dll is not loaded");
/// let mut path = vec![0u16; 32 * 1024];
/// // SAFETY: `path` is writable for `path.len()` UTF-16 units.
/// let len = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) } as usize;
/// assert!(
///     len > 0 && len < path.len(),
///     "cannot get the path of symcrypt.dll"
/// );
/// let loaded = OsString::from_wide(&path[..len]);
/// let loaded = Path::new(&loaded);
/// println!("symcrypt.dll loaded from {}", loaded.display());
///
/// if let Some(expected) =
///     std::env::var_os("RUSSH_EXPECTED_SYMCRYPT_DLL").filter(|p| !p.is_empty())
/// {
///     let expected = Path::new(&expected);
///     let read = |path: &Path| {
///         std::fs::read(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
///     };
///     assert!(
///         read(loaded) == read(expected),
///         "loaded {}, which differs from {}",
///         loaded.display(),
///         expected.display(),
///     );
/// }
/// ```
#[cfg(windows)]
mod windows_doctest_dll {}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ssh_key::{Algorithm, EcdsaCurve, HashAlg};

    use crate::{Preferred, cipher, kex, mac};

    const P256: Algorithm = Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    };
    const P384: Algorithm = Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    };
    const P521: Algorithm = Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
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

    /// What russh offers by default with this backend and every algorithm
    /// that isn't legacy (the `secure-algorithms` feature), in order: only
    /// algorithms SymCrypt implements, so `supported()` removes nothing. The
    /// ciphers and MACs are the other backends' defaults, but with
    /// `aes256-gcm@openssh.com` and the SHA-256 MACs first (see
    /// `cipher::DEFAULT_ORDER` and `mac::DEFAULT_ORDER`).
    #[cfg(feature = "secure-algorithms")]
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
                    kex::MLKEM1024NISTP384_SHA384,
                    kex::MLKEM768NISTP256_SHA256,
                    kex::CURVE25519,
                    kex::CURVE25519_PRE_RFC_8731,
                    kex::ECDH_SHA2_NISTP256,
                    kex::ECDH_SHA2_NISTP384,
                    kex::ECDH_SHA2_NISTP521,
                    kex::DH_GEX_SHA256,
                    kex::DH_G18_SHA512,
                    kex::DH_G17_SHA512,
                    kex::DH_G16_SHA512,
                    kex::DH_G15_SHA512,
                    kex::DH_G14_SHA256,
                    kex::EXTENSION_SUPPORT_AS_CLIENT,
                    kex::EXTENSION_SUPPORT_AS_SERVER,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                ]
            );
            assert_eq!(
                pref.key[..],
                [
                    #[cfg(feature = "ssh-mldsa87-p384")]
                    Algorithm::Mldsa87P384,
                    P256,
                    P384,
                    P521,
                    RSA_SHA512,
                    RSA_SHA256,
                    #[cfg(russh_ed25519_aws_lc)]
                    Algorithm::Ed25519,
                ]
            );
            assert!(pref.host_key_certificates.is_empty());
            assert_eq!(
                pref.cipher[..],
                [
                    cipher::AES_256_GCM,
                    cipher::CHACHA20_POLY1305,
                    cipher::AES_128_GCM,
                    cipher::AES_256_CTR,
                    cipher::AES_192_CTR,
                    cipher::AES_128_CTR,
                ]
            );
            assert_eq!(
                pref.mac[..],
                [
                    mac::HMAC_SHA256_ETM,
                    mac::HMAC_SHA512_ETM,
                    mac::HMAC_SHA256,
                    mac::HMAC_SHA512,
                ]
            );
            assert_eq!(
                pref.compression[..],
                [
                    crate::compression::NONE,
                    #[cfg(feature = "flate2")]
                    crate::compression::ZLIB,
                    #[cfg(feature = "flate2")]
                    crate::compression::ZLIB_LEGACY,
                ]
            );
            assert!(matches!(pref.supported(), Cow::Borrowed(_)));
        }
    }

    /// Configured algorithms the backend does not implement are neither
    /// offered nor accepted, and neither are those whose features are
    /// disabled; the others keep their order. Here every algorithm russh has
    /// a name for is configured (3des-cbc only with its feature), with the
    /// signature algorithms SymCrypt lacks.
    #[test]
    fn unsupported_algorithms_are_not_negotiated() {
        let keys = [
            Algorithm::Mldsa87P384,
            Algorithm::Ed25519,
            P256,
            P384,
            P521,
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
        // when they are configured, as here, and with the `none` feature (and
        // `none` in its own unit tests).
        let kexes: Vec<kex::Name> = [
            kex::MLKEM768X25519_SHA256,
            kex::MLKEM1024NISTP384_SHA384,
            kex::MLKEM768NISTP256_SHA256,
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::DH_GEX_SHA256,
            kex::DH_G14_SHA256,
            kex::DH_G15_SHA512,
            kex::DH_G16_SHA512,
            kex::DH_G17_SHA512,
            kex::DH_G18_SHA512,
            kex::ECDH_SHA2_NISTP256,
            kex::ECDH_SHA2_NISTP384,
            kex::ECDH_SHA2_NISTP521,
            kex::NONE,
        ]
        .into_iter()
        .filter(|k| k.is_enabled() || *k == kex::NONE)
        .collect();
        assert_eq!(supported.kex[..], kexes[..]);
        let signers = [
            #[cfg(feature = "ssh-mldsa87-p384")]
            Algorithm::Mldsa87P384,
            #[cfg(russh_ed25519_aws_lc)]
            Algorithm::Ed25519,
            P256,
            P384,
            P521,
            RSA_SHA512,
            RSA_SHA256,
        ];
        assert_eq!(supported.key[..], signers);
        assert_eq!(supported.host_key_certificates[..], signers);
        let ciphers: Vec<cipher::Name> = [
            cipher::CLEAR,
            cipher::NONE,
            cipher::AES_128_CTR,
            cipher::AES_192_CTR,
            cipher::AES_256_CTR,
            cipher::AES_128_GCM,
            cipher::AES_256_GCM,
            cipher::CHACHA20_POLY1305,
        ]
        .into_iter()
        .filter(|c| c.is_enabled() || *c == cipher::NONE)
        .collect();
        assert_eq!(supported.cipher[..], ciphers[..]);
        let macs: Vec<mac::Name> = [
            mac::NONE,
            mac::HMAC_SHA256,
            mac::HMAC_SHA512,
            mac::HMAC_SHA256_ETM,
            mac::HMAC_SHA512_ETM,
        ]
        .into_iter()
        .filter(|m| m.is_enabled() || *m == mac::NONE)
        .collect();
        assert_eq!(supported.mac[..], macs[..]);
    }
}
