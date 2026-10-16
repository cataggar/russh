//! Signatures for the SymCrypt backend: ECDSA with `symcrypt::ecc` and RSA
//! PKCS#1 v1.5 with `symcrypt::rsa`, over digests from `symcrypt::hash`;
//! with the `ed25519-aws-lc` feature, also Ed25519 from aws-lc-rs.
//!
//! | Algorithm | Digest | Implementation |
//! |---|---|---|
//! | `ecdsa-sha2-nistp256` | SHA-256 | `EcKey::ecdsa_sign`/`ecdsa_verify` on `NistP256` |
//! | `ecdsa-sha2-nistp384` | SHA-384 | `EcKey::ecdsa_sign`/`ecdsa_verify` on `NistP384` |
//! | `ecdsa-sha2-nistp521` | SHA-512 | `EcKey::ecdsa_sign`/`ecdsa_verify` on `NistP521` |
//! | `rsa-sha2-256` | SHA-256 | `RsaKey::pkcs1_sign`/`pkcs1_verify` |
//! | `rsa-sha2-512` | SHA-512 | `RsaKey::pkcs1_sign`/`pkcs1_verify` |
//! | `ssh-ed25519` (feature `ed25519-aws-lc`) | SHA-512, within EdDSA | aws-lc-rs `Ed25519KeyPair::sign`/`ED25519.verify_sig` |
//!
//! These make and check every signature in russh: server host keys,
//! public-key user authentication (client and server side) and the CA
//! signature of OpenSSH certificates (`*-cert-v01@openssh.com`, through
//! `crate::crypto::verify_certificate`). `Signatures::is_supported` limits
//! negotiation to these algorithms and their certificate forms.
//!
//! Keys are imported into SymCrypt from their raw components only (RSA `n`,
//! `e`, `p` and `q`; the ECDSA point and private scalar): `ssh-key`'s
//! RustCrypto signing and verification are never used, so RSA works without
//! the `rsa` feature.
//!
//! Importing a private key costs about as much as a signature, or more for
//! RSA: SymCrypt derives the RSA private exponent and CRT values, checks
//! that the private and public parts match, and, as FIPS 140-3 requires,
//! runs a pairwise consistency test. `Signatures::sign_held`, which russh
//! uses for its own keys (server host keys, client and agent keys), imports
//! a key once and keeps it for as long as its holder lives (see
//! `key_cache`), so these checks run once per key. `Signatures::sign`,
//! which `certificate::sign` uses for CA keys passed by reference, keeps a
//! small LRU cache keyed by the SHA-256 digest of the encoded private key.
//! Importing an RSA public key also computes the Montgomery parameter for
//! the modulus (`SymCryptIntToModulus`), so `Verifier::verify` keeps a
//! bounded LRU cache of imported RSA public keys keyed by the exact `(n, e)`
//! modulus and exponent bytes.
//!
//! Not implemented, so neither offered nor accepted: `ssh-ed25519` (SymCrypt
//! has no EdDSA) unless the `ed25519-aws-lc` feature takes it from aws-lc-rs
//! (see `super::ed25519`), `ssh-rsa` (SHA-1), `ssh-dss` and the security-key
//! (`sk-*`) algorithms. Signing with such a key fails with
//! `ssh_key::Error::AlgorithmUnsupported`, after logging an error that names
//! this backend.
//!
//! With `ed25519-aws-lc`, `ssh-ed25519` is the last of [`DEFAULT_ORDER`], so
//! a peer that implements any of the algorithms above negotiates it instead.

use std::ops::RangeInclusive;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex, PoisonError};

use ::symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use ::symcrypt::errors::SymCryptError;
use ::symcrypt::hash::{HashAlgorithm, sha256, sha384, sha512};
use ::symcrypt::rsa::{RsaKey, RsaKeyUsage};
use hex_literal::hex;
use log::{debug, error};
use ssh_encoding::{Decode, Encode};
#[cfg(feature = "ssh-mldsa87-p384")]
use ssh_key::private::Mldsa87P384Keypair;
use ssh_key::private::{EcdsaKeypair, KeypairData, RsaKeypair};
#[cfg(feature = "ssh-mldsa87-p384")]
use ssh_key::public::Mldsa87P384PublicKey;
use ssh_key::public::{EcdsaPublicKey, KeyData, RsaPublicKey};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, Mpint, PrivateKey, Signature};
use symcrypt_sys::{
    SYMCRYPT_ERROR, SYMCRYPT_ERROR_SYMCRYPT_INVALID_BLOB as SYMCRYPT_INVALID_BLOB,
    SYMCRYPT_ERROR_SYMCRYPT_MEMORY_ALLOCATION_FAILURE as SYMCRYPT_MEMORY_ALLOCATION_FAILURE,
    SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR as SYMCRYPT_NO_ERROR,
};
#[cfg(feature = "ssh-mldsa87-p384")]
use zeroize::Zeroizing;

use self::key_cache::KeyCache;
use crate::crypto::{KeyHolder, Signer, Verifier, held_key};

mod key_cache;

#[cfg(feature = "ssh-mldsa87-p384")]
const COMPOSITE_PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";
#[cfg(feature = "ssh-mldsa87-p384")]
const MLDSA87_P384_LABEL: &[u8; 33] = b"COMPSIG-MLDSA87-ECDSA-P384-SHA512";

pub(crate) const MLDSA87_SEED_LEN: usize = 32;
pub(crate) const MLDSA87_PUBLIC_KEY_LEN: usize = 2592;
#[cfg(feature = "ssh-mldsa87-p384")]
pub(crate) const MLDSA87_SIGNATURE_LEN: usize = 4627;

#[allow(non_camel_case_types)]
mod mldsa_ffi {
    use symcrypt_sys::SYMCRYPT_ERROR;

    #[repr(C)]
    pub(super) struct SYMCRYPT_MLDSAKEY {
        _private: [u8; 0],
    }

    pub(super) const SYMCRYPT_MLDSA_PARAMS_MLDSA87: u32 = 3;
    pub(super) const SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED: u32 = 1;
    pub(super) const SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY: u32 = 3;

    #[link(name = "symcrypt", kind = "dylib")]
    unsafe extern "C" {
        pub(super) fn SymCryptMlDsakeyAllocate(params: u32) -> *mut SYMCRYPT_MLDSAKEY;
        pub(super) fn SymCryptMlDsakeyFree(pk_mldsakey: *mut SYMCRYPT_MLDSAKEY);
        #[cfg(feature = "ssh-mldsa87-p384")]
        pub(super) fn SymCryptMlDsakeyGenerate(
            pk_mldsakey: *mut SYMCRYPT_MLDSAKEY,
            flags: u32,
        ) -> SYMCRYPT_ERROR;
        pub(super) fn SymCryptMlDsakeySetValue(
            pb_src: *const u8,
            cb_src: usize,
            format: u32,
            flags: u32,
            pk_mldsakey: *mut SYMCRYPT_MLDSAKEY,
        ) -> SYMCRYPT_ERROR;
        pub(super) fn SymCryptMlDsakeyGetValue(
            pk_mldsakey: *const SYMCRYPT_MLDSAKEY,
            pb_dst: *mut u8,
            cb_dst: usize,
            format: u32,
            flags: u32,
        ) -> SYMCRYPT_ERROR;
        #[cfg(feature = "ssh-mldsa87-p384")]
        pub(super) fn SymCryptMlDsaSign(
            pk_mldsakey: *const SYMCRYPT_MLDSAKEY,
            pb_input: *const u8,
            cb_input: usize,
            pb_context: *const u8,
            cb_context: usize,
            flags: u32,
            pb_signature: *mut u8,
            cb_signature: usize,
        ) -> SYMCRYPT_ERROR;
        #[cfg(feature = "ssh-mldsa87-p384")]
        pub(super) fn SymCryptMlDsaVerify(
            pk_mldsakey: *const SYMCRYPT_MLDSAKEY,
            pb_input: *const u8,
            cb_input: usize,
            pb_context: *const u8,
            cb_context: usize,
            pb_signature: *const u8,
            cb_signature: usize,
            flags: u32,
        ) -> SYMCRYPT_ERROR;
    }
}

pub(crate) struct MlDsa87Key(NonNull<mldsa_ffi::SYMCRYPT_MLDSAKEY>);

// SAFETY: A `SYMCRYPT_MLDSAKEY` has no thread affinity and after setup is
// only passed as `*const SYMCRYPT_MLDSAKEY` to `SymCryptMlDsaSign`,
// `SymCryptMlDsaVerify` and `SymCryptMlDsakeyGetValue`.
unsafe impl Send for MlDsa87Key {}
unsafe impl Sync for MlDsa87Key {}

impl Drop for MlDsa87Key {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by `SymCryptMlDsakeyAllocate` and is
        // freed once here.
        unsafe { mldsa_ffi::SymCryptMlDsakeyFree(self.0.as_ptr()) }
    }
}

impl MlDsa87Key {
    fn allocate() -> Result<Self, SYMCRYPT_ERROR> {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            // SAFETY: `SymCryptModuleInit` is idempotent and thread-safe; the
            // version constants come from the paired `symcrypt-sys` crate.
            unsafe {
                symcrypt_sys::SymCryptModuleInit(
                    symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
                    symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
                );
            }
        });
        // SAFETY: `SymCryptModuleInit` has run and `SYMCRYPT_MLDSA_PARAMS_MLDSA87`
        // is a valid parameter set.
        let ptr = unsafe {
            mldsa_ffi::SymCryptMlDsakeyAllocate(mldsa_ffi::SYMCRYPT_MLDSA_PARAMS_MLDSA87)
        };
        NonNull::new(ptr)
            .map(Self)
            .ok_or(SYMCRYPT_MEMORY_ALLOCATION_FAILURE)
    }

    #[cfg(feature = "ssh-mldsa87-p384")]
    pub(crate) fn generate_keypair() -> Result<
        (
            Zeroizing<[u8; MLDSA87_SEED_LEN]>,
            [u8; MLDSA87_PUBLIC_KEY_LEN],
        ),
        SYMCRYPT_ERROR,
    > {
        let key = Self::allocate()?;
        // SAFETY: `key.0` is a valid allocated `SYMCRYPT_MLDSAKEY`.
        let err = unsafe { mldsa_ffi::SymCryptMlDsakeyGenerate(key.0.as_ptr(), 0) };
        if err != SYMCRYPT_NO_ERROR {
            return Err(err);
        }
        let mut seed = Zeroizing::new([0u8; MLDSA87_SEED_LEN]);
        // SAFETY: `key.0` holds a generated keypair and `seed` is a writable
        // 32-byte buffer matching `SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED`.
        let err = unsafe {
            mldsa_ffi::SymCryptMlDsakeyGetValue(
                key.0.as_ptr(),
                seed.as_mut_ptr(),
                seed.len(),
                mldsa_ffi::SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
                0,
            )
        };
        if err != SYMCRYPT_NO_ERROR {
            return Err(err);
        }
        let public = key.export_public_key()?;
        Ok((seed, public))
    }

    pub(crate) fn from_private_seed(
        seed: &[u8; MLDSA87_SEED_LEN],
        expected_public: Option<&[u8; MLDSA87_PUBLIC_KEY_LEN]>,
    ) -> Result<(Self, [u8; MLDSA87_PUBLIC_KEY_LEN]), SYMCRYPT_ERROR> {
        let key = Self::allocate()?;
        // SAFETY: `key.0` is a valid allocated `SYMCRYPT_MLDSAKEY` and `seed`
        // is a readable 32-byte buffer matching `SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED`.
        let err = unsafe {
            mldsa_ffi::SymCryptMlDsakeySetValue(
                seed.as_ptr(),
                seed.len(),
                mldsa_ffi::SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
                0,
                key.0.as_ptr(),
            )
        };
        if err != SYMCRYPT_NO_ERROR {
            return Err(err);
        }
        let public = key.export_public_key()?;
        if let Some(expected) = expected_public
            && &public != expected
        {
            return Err(SYMCRYPT_INVALID_BLOB);
        }
        Ok((key, public))
    }

    #[cfg(feature = "ssh-mldsa87-p384")]
    pub(crate) fn from_public_key(
        public: &[u8; MLDSA87_PUBLIC_KEY_LEN],
    ) -> Result<Self, SYMCRYPT_ERROR> {
        let key = Self::allocate()?;
        // SAFETY: `key.0` is a valid allocated `SYMCRYPT_MLDSAKEY` and `public`
        // is a readable 2592-byte buffer matching `SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY`.
        let err = unsafe {
            mldsa_ffi::SymCryptMlDsakeySetValue(
                public.as_ptr(),
                public.len(),
                mldsa_ffi::SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                0,
                key.0.as_ptr(),
            )
        };
        if err != SYMCRYPT_NO_ERROR {
            return Err(err);
        }
        Ok(key)
    }

    pub(crate) fn export_public_key(&self) -> Result<[u8; MLDSA87_PUBLIC_KEY_LEN], SYMCRYPT_ERROR> {
        let mut public = [0u8; MLDSA87_PUBLIC_KEY_LEN];
        // SAFETY: `self.0` holds a key and `public` is a writable 2592-byte
        // buffer matching `SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY`.
        let err = unsafe {
            mldsa_ffi::SymCryptMlDsakeyGetValue(
                self.0.as_ptr(),
                public.as_mut_ptr(),
                public.len(),
                mldsa_ffi::SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                0,
            )
        };
        if err != SYMCRYPT_NO_ERROR {
            return Err(err);
        }
        Ok(public)
    }

    #[cfg(feature = "ssh-mldsa87-p384")]
    pub(crate) fn sign(
        &self,
        input: &[u8],
        context: &[u8],
    ) -> Result<[u8; MLDSA87_SIGNATURE_LEN], SYMCRYPT_ERROR> {
        let mut sig = [0u8; MLDSA87_SIGNATURE_LEN];
        // SAFETY: `self.0` holds a private key, `input` and `context` are
        // valid byte slices, and `sig` is a writable 4627-byte buffer.
        let err = unsafe {
            mldsa_ffi::SymCryptMlDsaSign(
                self.0.as_ptr(),
                input.as_ptr(),
                input.len(),
                context.as_ptr(),
                context.len(),
                0,
                sig.as_mut_ptr(),
                sig.len(),
            )
        };
        if err != SYMCRYPT_NO_ERROR {
            return Err(err);
        }
        Ok(sig)
    }

    #[cfg(feature = "ssh-mldsa87-p384")]
    pub(crate) fn verify(
        &self,
        input: &[u8],
        context: &[u8],
        signature: &[u8; MLDSA87_SIGNATURE_LEN],
    ) -> Result<(), SYMCRYPT_ERROR> {
        // SAFETY: `self.0` holds a public key and `input`, `context` and
        // `signature` are valid byte slices.
        let err = unsafe {
            mldsa_ffi::SymCryptMlDsaVerify(
                self.0.as_ptr(),
                input.as_ptr(),
                input.len(),
                context.as_ptr(),
                context.len(),
                signature.as_ptr(),
                signature.len(),
                0,
            )
        };
        if err != SYMCRYPT_NO_ERROR {
            return Err(err);
        }
        Ok(())
    }
}

#[cfg(feature = "ssh-mldsa87-p384")]
fn mldsa87_p384_message(message: &[u8]) -> Vec<u8> {
    let ph = sha512(message);
    let mut m_prime =
        Vec::with_capacity(COMPOSITE_PREFIX.len() + MLDSA87_P384_LABEL.len() + 1 + ph.len());
    m_prime.extend_from_slice(COMPOSITE_PREFIX);
    m_prime.extend_from_slice(MLDSA87_P384_LABEL);
    m_prime.push(0);
    m_prime.extend_from_slice(&ph);
    m_prime
}

/// How many imported keys `Signatures::sign_held` keeps at most.
const KEY_CACHE_CAPACITY: usize = 32;

/// The keys `Signatures::sign_held` imported.
static SIGNING_KEYS: KeyCache<SigningKey> = KeyCache::new(KEY_CACHE_CAPACITY);

/// How many imported keys `Signatures::sign` keeps at most.
const BY_VALUE_CACHE_CAPACITY: usize = 32;

/// The keys `Signatures::sign` imported, keyed by the SHA-256 digest of their
/// OpenSSH private-key encoding.
static BY_VALUE_KEYS: ByValueCache = ByValueCache::new(BY_VALUE_CACHE_CAPACITY);

/// How many imported RSA public keys `Verifier::verify` keeps at most.
const RSA_VERIFY_CACHE_CAPACITY: usize = 32;

/// The RSA public keys `Verifier::verify` imported, keyed by their exact
/// `(n, e)` modulus and public-exponent bytes.
static RSA_VERIFY_KEYS: RsaVerifyCache = RsaVerifyCache::new(RSA_VERIFY_CACHE_CAPACITY);

pub(crate) struct Signatures;

impl Verifier for Signatures {
    fn is_supported(algorithm: &Algorithm) -> bool {
        matches!(
            algorithm,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256 | EcdsaCurve::NistP384 | EcdsaCurve::NistP521
            } | Algorithm::Rsa {
                hash: Some(HashAlg::Sha256 | HashAlg::Sha512)
            }
        ) || (cfg!(feature = "ssh-mldsa87-p384") && *algorithm == Algorithm::Mldsa87P384)
            || (cfg!(russh_ed25519_aws_lc) && *algorithm == Algorithm::Ed25519)
    }

    fn verify(key: &KeyData, message: &[u8], signature: &Signature) -> signature::Result<()> {
        let algorithm = signature.algorithm();
        if !Self::is_supported(&algorithm) {
            debug!("the symcrypt backend does not verify {algorithm} signatures");
            return Err(ssh_key::Error::AlgorithmUnsupported { algorithm }.into());
        }
        match (key, algorithm) {
            #[cfg(feature = "ssh-mldsa87-p384")]
            (KeyData::Mldsa87P384(key), Algorithm::Mldsa87P384) => {
                verify_mldsa87_p384(key, message, signature.as_bytes())
            }
            (KeyData::Ecdsa(key), Algorithm::Ecdsa { curve }) if key.curve() == curve => {
                verify_ecdsa(Curve::new(curve), key, message, signature.as_bytes())
            }
            (KeyData::Rsa(key), Algorithm::Rsa { hash: Some(hash) }) => {
                verify_rsa(key, hash, message, signature.as_bytes())
            }
            #[cfg(russh_ed25519_aws_lc)]
            (KeyData::Ed25519(key), Algorithm::Ed25519) => {
                super::ed25519::verify(key, message, signature.as_bytes())
            }
            _ => Err(signature::Error::new()),
        }
    }
}

impl Signer for Signatures {
    fn sign(
        key: &PrivateKey,
        hash_alg: Option<HashAlg>,
        message: &[u8],
    ) -> ssh_key::Result<Signature> {
        sign_by_value(&BY_VALUE_KEYS, key, hash_alg, message)
    }

    fn sign_held<H: KeyHolder>(
        holder: &Arc<H>,
        slot: usize,
        hash_alg: Option<HashAlg>,
        message: &[u8],
    ) -> ssh_key::Result<Signature> {
        sign_cached(&SIGNING_KEYS, holder, slot, hash_alg, message)
    }

    fn release_dropped_keys() {
        SIGNING_KEYS.remove_dropped();
    }
}

/// Bounded LRU cache of imported [`SigningKey`]s for [`Signatures::sign`],
/// keyed by the SHA-256 digest of [`PrivateKey::to_bytes`] (which covers both
/// the public and private key components and zeroizes the encoded buffer on
/// drop).
struct ByValueCache {
    capacity: usize,
    /// From the least to the most recently used.
    entries: Mutex<Vec<([u8; 32], Arc<SigningKey>)>>,
}

impl ByValueCache {
    const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(Vec::new()),
        }
    }

    fn get_or_try_insert(&self, key: &PrivateKey) -> ssh_key::Result<Arc<SigningKey>> {
        let digest = sha256(&key.to_bytes()?);
        if let Some(imported) = self.touch(&digest) {
            return Ok(imported);
        }
        // Imported without the lock, so that other keys can be used meanwhile.
        let imported = Arc::new(SigningKey::import(key)?);
        // Declared before locking so an evicted key is freed after the lock is released.
        let mut evicted = None;
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = entries.iter().position(|(d, _)| *d == digest) {
            let entry = entries.remove(index);
            let cached = Arc::clone(&entry.1);
            entries.push(entry);
            return Ok(cached);
        }
        if entries.len() >= self.capacity && !entries.is_empty() {
            evicted = Some(entries.remove(0));
        }
        entries.push((digest, Arc::clone(&imported)));
        drop(entries);
        drop(evicted);
        Ok(imported)
    }

    fn touch(&self, digest: &[u8; 32]) -> Option<Arc<SigningKey>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let index = entries.iter().position(|(d, _)| d == digest)?;
        let entry = entries.remove(index);
        let value = Arc::clone(&entry.1);
        entries.push(entry);
        Some(value)
    }
}

/// Signs with `key`, imported into `cache` unless it already is.
fn sign_by_value(
    cache: &ByValueCache,
    key: &PrivateKey,
    hash_alg: Option<HashAlg>,
    message: &[u8],
) -> ssh_key::Result<Signature> {
    // Checked first, so that no key is imported that cannot sign.
    let algorithm = signature_algorithm(key, hash_alg)?;
    let imported = cache.get_or_try_insert(key)?;
    #[cfg(test)]
    tests::signed_with(&imported);
    imported.sign(algorithm, message)
}

/// Signs with key `slot` of `holder`, imported into `cache` unless it
/// already is.
fn sign_cached<H: KeyHolder>(
    cache: &KeyCache<SigningKey>,
    holder: &Arc<H>,
    slot: usize,
    hash_alg: Option<HashAlg>,
    message: &[u8],
) -> ssh_key::Result<Signature> {
    let key = held_key(holder.as_ref(), slot)?;
    // Checked first, so that no key is imported that cannot sign.
    let algorithm = signature_algorithm(key, hash_alg)?;
    let imported = cache.get_or_try_insert_with(holder, slot, || SigningKey::import(key))?;
    #[cfg(test)]
    tests::signed_with(&imported);
    imported.sign(algorithm, message)
}

/// The algorithm of the signatures `key` makes with `hash_alg` (see
/// [`Signer::sign`]), if this backend implements it.
fn signature_algorithm(key: &PrivateKey, hash_alg: Option<HashAlg>) -> ssh_key::Result<Algorithm> {
    match key.key_data() {
        #[cfg(feature = "ssh-mldsa87-p384")]
        KeypairData::Mldsa87P384(_) => Ok(Algorithm::Mldsa87P384),
        KeypairData::Ecdsa(keypair) => Ok(keypair.algorithm()),
        KeypairData::Rsa(_) => match hash_alg {
            Some(hash @ (HashAlg::Sha256 | HashAlg::Sha512)) => {
                Ok(Algorithm::Rsa { hash: Some(hash) })
            }
            _ => Err(unsupported(Algorithm::Rsa { hash: hash_alg })),
        },
        #[cfg(russh_ed25519_aws_lc)]
        KeypairData::Ed25519(_) => Ok(Algorithm::Ed25519),
        KeypairData::Encrypted(_) => Err(ssh_key::Error::Encrypted),
        _ => Err(unsupported(key.algorithm())),
    }
}

/// A private key imported into SymCrypt (or, for Ed25519, into aws-lc-rs),
/// which checked that its private and public parts match. Dropping it frees
/// and wipes it.
enum SigningKey {
    #[cfg(feature = "ssh-mldsa87-p384")]
    Mldsa87P384 {
        mldsa: MlDsa87Key,
        ecdsa: EcKey,
    },
    Ecdsa(Curve, EcKey),
    Rsa(RsaKey),
    #[cfg(russh_ed25519_aws_lc)]
    Ed25519(super::ed25519::SigningKey),
}

impl SigningKey {
    fn import(key: &PrivateKey) -> ssh_key::Result<Self> {
        #[cfg(test)]
        tests::count_import();
        match key.key_data() {
            #[cfg(feature = "ssh-mldsa87-p384")]
            KeypairData::Mldsa87P384(keypair) => import_mldsa87_p384(keypair),
            KeypairData::Ecdsa(keypair) => import_ecdsa(Curve::new(keypair.curve()), keypair),
            KeypairData::Rsa(keypair) => import_rsa(keypair),
            #[cfg(russh_ed25519_aws_lc)]
            KeypairData::Ed25519(keypair) => {
                super::ed25519::SigningKey::import(keypair).map(SigningKey::Ed25519)
            }
            KeypairData::Encrypted(_) => Err(ssh_key::Error::Encrypted),
            _ => Err(unsupported(key.algorithm())),
        }
    }

    /// Signs `message` as `algorithm`, which [`signature_algorithm`] gave
    /// for the key this was imported from.
    fn sign(&self, algorithm: Algorithm, message: &[u8]) -> ssh_key::Result<Signature> {
        let blob = match (self, &algorithm) {
            #[cfg(feature = "ssh-mldsa87-p384")]
            (SigningKey::Mldsa87P384 { mldsa, ecdsa }, Algorithm::Mldsa87P384) => {
                sign_mldsa87_p384(mldsa, ecdsa, message)?
            }
            (SigningKey::Ecdsa(curve, key), Algorithm::Ecdsa { curve: signing })
                if Curve::new(*signing) == *curve =>
            {
                sign_ecdsa(*curve, key, message)?
            }
            (SigningKey::Rsa(key), Algorithm::Rsa { hash: Some(hash) }) => {
                sign_rsa(key, *hash, message)?
            }
            #[cfg(russh_ed25519_aws_lc)]
            (SigningKey::Ed25519(key), Algorithm::Ed25519) => key.sign(message),
            _ => return Err(ssh_key::Error::Crypto),
        };
        Signature::new(algorithm, blob)
    }
}

/// Default host-key and public-key algorithm preference. With
/// `ed25519-aws-lc`, Ed25519 (from aws-lc-rs) comes last.
pub(crate) const DEFAULT_ORDER: &[Algorithm] = &[
    #[cfg(feature = "ssh-mldsa87-p384")]
    Algorithm::Mldsa87P384,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
    #[cfg(russh_ed25519_aws_lc)]
    Algorithm::Ed25519,
];

/// Logs that this backend cannot sign with `algorithm`, and returns the
/// error.
fn unsupported(algorithm: Algorithm) -> ssh_key::Error {
    let implemented: Vec<&str> = DEFAULT_ORDER.iter().map(Algorithm::as_str).collect();
    error!(
        "cannot sign with {algorithm}: the symcrypt backend implements only {}",
        implemented.join(", ")
    );
    ssh_key::Error::AlgorithmUnsupported { algorithm }
}

/// Logs a SymCrypt failure while signing with a local key.
fn signing_error(action: &str, error: SymCryptError) -> ssh_key::Error {
    error!("SymCrypt failed to {action}: {error}");
    ssh_key::Error::Crypto
}

/// The order `n` of the P-256 base point (SEC 2 version 2, section 2.4.2).
const P256_ORDER: [u8; 32] =
    hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

/// The order `n` of the P-384 base point (SEC 2 version 2, section 2.5.1).
const P384_ORDER: [u8; 48] = hex!(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
    "581a0db248b0a77aecec196accc52973"
);

/// The order `n` of the P-521 base point (SEC 2 version 2, section 2.6.1).
const P521_ORDER: [u8; 66] = hex!(
    "01ff"
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa"
    "51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
);

/// An ECDSA curve: this backend implements all of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Curve {
    NistP256,
    NistP384,
    NistP521,
}

impl Curve {
    fn new(curve: EcdsaCurve) -> Self {
        match curve {
            EcdsaCurve::NistP256 => Curve::NistP256,
            EcdsaCurve::NistP384 => Curve::NistP384,
            EcdsaCurve::NistP521 => Curve::NistP521,
        }
    }

    fn symcrypt(self) -> CurveType {
        match self {
            Curve::NistP256 => CurveType::NistP256,
            Curve::NistP384 => CurveType::NistP384,
            Curve::NistP521 => CurveType::NistP521,
        }
    }

    /// The order `n` of the base point, big-endian.
    fn order(self) -> &'static [u8] {
        match self {
            Curve::NistP256 => &P256_ORDER,
            Curve::NistP384 => &P384_ORDER,
            Curve::NistP521 => &P521_ORDER,
        }
    }

    /// The size in bytes of a coordinate, of the private scalar, and of `r`
    /// and `s`: on these curves, that of the order (66 bytes for P-521,
    /// whose top byte is 0 or 1).
    fn size(self) -> usize {
        self.order().len()
    }

    /// The digest that is signed (RFC 5656, section 6.2.1).
    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Curve::NistP256 => sha256(message).to_vec(),
            Curve::NistP384 => sha384(message).to_vec(),
            Curve::NistP521 => sha512(message).to_vec(),
        }
    }

    /// The `X || Y` coordinates SymCrypt imports, from the SEC1 point SSH
    /// carries (RFC 5656, section 3.1). Like OpenSSH, only uncompressed
    /// points are accepted.
    fn coordinates(self, sec1: &[u8]) -> Option<&[u8]> {
        match sec1 {
            [0x04, xy @ ..] if xy.len() == 2 * self.size() => Some(xy),
            _ => None,
        }
    }

    /// Converts an SSH signature blob (RFC 5656, section 3.1.2: the mpints
    /// `r` and `s`) to SymCrypt's fixed-size big-endian `r || s`. `None`
    /// unless `r` and `s` are both in `1..n` and nothing follows them.
    fn fixed_signature(self, mut blob: &[u8]) -> Option<Vec<u8>> {
        let size = self.size();
        let mut fixed = vec![0; 2 * size];
        for half in fixed.chunks_exact_mut(size) {
            let mpint = Mpint::decode(&mut blob).ok()?;
            // `None` for zero and negative values. `Mpint` rejects
            // non-minimal encodings, so there are no leading zeros either.
            let value = mpint.as_positive_bytes()?;
            let start = size.checked_sub(value.len())?;
            half.get_mut(start..)?.copy_from_slice(value);
            if &*half >= self.order() {
                return None;
            }
        }
        blob.is_empty().then_some(fixed)
    }
}

#[cfg(feature = "ssh-mldsa87-p384")]
fn verify_mldsa87_p384(
    key: &Mldsa87P384PublicKey,
    message: &[u8],
    blob: &[u8],
) -> signature::Result<()> {
    let (mldsa_sig, ecdsa_blob) = blob
        .split_at_checked(MLDSA87_SIGNATURE_LEN)
        .ok_or_else(signature::Error::new)?;
    let mldsa_sig: &[u8; MLDSA87_SIGNATURE_LEN] =
        mldsa_sig.try_into().map_err(|_| signature::Error::new())?;
    let m_prime = mldsa87_p384_message(message);
    let mldsa_key = MlDsa87Key::from_public_key(key.mldsa()).map_err(|error| {
        debug!("SymCrypt rejected an ML-DSA-87 public key: {error}");
        signature::Error::new()
    })?;
    mldsa_key
        .verify(&m_prime, MLDSA87_P384_LABEL, mldsa_sig)
        .map_err(|_| signature::Error::new())?;
    verify_ecdsa_sec1(
        Curve::NistP384,
        key.ecdsa_sec1_bytes(),
        &m_prime,
        ecdsa_blob,
    )
}

#[cfg(feature = "ssh-mldsa87-p384")]
fn import_mldsa87_p384(keypair: &Mldsa87P384Keypair) -> ssh_key::Result<SigningKey> {
    let point = Curve::NistP384
        .coordinates(keypair.public().ecdsa_sec1_bytes())
        .ok_or(ssh_key::Error::PublicKey)?;
    let (mldsa, _) =
        MlDsa87Key::from_private_seed(keypair.mldsa_seed(), Some(keypair.public().mldsa()))
            .map_err(|error| {
                error!("SymCrypt failed to import an ML-DSA-87 key: {error}");
                ssh_key::Error::Crypto
            })?;
    let ecdsa = EcKey::set_key_pair(
        CurveType::NistP384,
        keypair.ecdsa_private().as_slice(),
        Some(point),
        EcKeyUsage::EcDsa,
    )
    .map_err(|error| signing_error("import an ECDSA key", error))?;
    Ok(SigningKey::Mldsa87P384 { mldsa, ecdsa })
}

#[cfg(feature = "ssh-mldsa87-p384")]
fn sign_mldsa87_p384(
    mldsa: &MlDsa87Key,
    ecdsa: &EcKey,
    message: &[u8],
) -> ssh_key::Result<Vec<u8>> {
    let m_prime = mldsa87_p384_message(message);
    let mldsa_sig = mldsa.sign(&m_prime, MLDSA87_P384_LABEL).map_err(|error| {
        error!("SymCrypt failed to sign with an ML-DSA-87 key: {error}");
        ssh_key::Error::Crypto
    })?;
    let ecdsa_blob = sign_ecdsa(Curve::NistP384, ecdsa, &m_prime)?;
    let mut blob = Vec::with_capacity(mldsa_sig.len() + ecdsa_blob.len());
    blob.extend_from_slice(&mldsa_sig);
    blob.extend_from_slice(&ecdsa_blob);
    Ok(blob)
}

fn verify_ecdsa(
    curve: Curve,
    key: &EcdsaPublicKey,
    message: &[u8],
    blob: &[u8],
) -> signature::Result<()> {
    verify_ecdsa_sec1(curve, key.as_sec1_bytes(), message, blob)
}

fn verify_ecdsa_sec1(
    curve: Curve,
    sec1: &[u8],
    message: &[u8],
    blob: &[u8],
) -> signature::Result<()> {
    let point = curve.coordinates(sec1).ok_or_else(signature::Error::new)?;
    let fixed = curve
        .fixed_signature(blob)
        .ok_or_else(signature::Error::new)?;
    let key =
        EcKey::set_public_key(curve.symcrypt(), point, EcKeyUsage::EcDsa).map_err(|error| {
            debug!("SymCrypt rejected an ECDSA public key: {error}");
            signature::Error::new()
        })?;
    key.ecdsa_verify(&fixed, &curve.digest(message))
        .map_err(|_| signature::Error::new())
}

fn import_ecdsa(curve: Curve, keypair: &EcdsaKeypair) -> ssh_key::Result<SigningKey> {
    let point = curve
        .coordinates(keypair.public_key_bytes())
        .ok_or(ssh_key::Error::PublicKey)?;
    let key = EcKey::set_key_pair(
        curve.symcrypt(),
        keypair.private_key_bytes(),
        Some(point),
        EcKeyUsage::EcDsa,
    )
    .map_err(|error| signing_error("import an ECDSA key", error))?;
    Ok(SigningKey::Ecdsa(curve, key))
}

/// The SSH signature blob of `message`.
fn sign_ecdsa(curve: Curve, key: &EcKey, message: &[u8]) -> ssh_key::Result<Vec<u8>> {
    let fixed = key
        .ecdsa_sign(&curve.digest(message))
        .map_err(|error| signing_error("sign with an ECDSA key", error))?;
    let (r, s) = fixed
        .split_at_checked(curve.size())
        .filter(|(_, s)| s.len() == curve.size())
        .ok_or(ssh_key::Error::Crypto)?;
    let mut blob = Vec::new();
    Mpint::from_positive_bytes(r).encode(&mut blob)?;
    Mpint::from_positive_bytes(s).encode(&mut blob)?;
    Ok(blob)
}

/// The RSA modulus sizes accepted, in bits: from OpenSSH's minimum
/// (`SSH_RSA_MINIMUM_MODULUS_SIZE`) to OpenSSL's maximum
/// (`OPENSSL_RSA_MAX_MODULUS_BITS`).
const RSA_MODULUS_BITS: RangeInclusive<usize> = 1024..=16384;

/// Checks that the big-endian, non-zero-padded modulus `n` and public
/// exponent `e` have an odd modulus of an accepted bit length and an odd
/// public exponent of 3 to 64 bits.
fn check_rsa_public_components(n: &[u8], e: &[u8]) -> ssh_key::Result<()> {
    let bits = n.first().map_or(0, |top| {
        n.len()
            .saturating_mul(8)
            .saturating_sub(top.leading_zeros() as usize)
    });
    let odd = |value: &[u8]| value.last().is_some_and(|low| low & 1 == 1);
    if RSA_MODULUS_BITS.contains(&bits) && odd(n) && odd(e) && e != [1] && e.len() <= 8 {
        Ok(())
    } else {
        debug!(
            "rejecting an RSA key of {bits} bits with a {}-byte public exponent",
            e.len()
        );
        Err(ssh_key::Error::PublicKey)
    }
}

/// The modulus and public exponent of `key`, big-endian without leading
/// zeros as SymCrypt imports them, if the modulus is odd and of an accepted
/// size, and the exponent odd, at least 3 and at most 64 bits long.
fn rsa_public_components(key: &RsaPublicKey) -> ssh_key::Result<(&[u8], &[u8])> {
    let (Some(n), Some(e)) = (key.n().as_positive_bytes(), key.e().as_positive_bytes()) else {
        return Err(ssh_key::Error::PublicKey);
    };
    check_rsa_public_components(n, e)?;
    Ok((n, e))
}

/// The digest of `message` that `rsa-sha2-256` or `rsa-sha2-512` signs
/// (RFC 8332, section 3).
fn rsa_digest(hash: HashAlg, message: &[u8]) -> ssh_key::Result<(Vec<u8>, HashAlgorithm)> {
    match hash {
        HashAlg::Sha256 => Ok((sha256(message).to_vec(), HashAlgorithm::Sha256)),
        HashAlg::Sha512 => Ok((sha512(message).to_vec(), HashAlgorithm::Sha512)),
        _ => Err(ssh_key::Error::AlgorithmUnsupported {
            algorithm: Algorithm::Rsa { hash: Some(hash) },
        }),
    }
}

/// Strips leading zero bytes from a big-endian unsigned integer slice.
fn uint_bytes(mut bytes: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
}

type RsaVerifyEntry = (Box<[u8]>, Box<[u8]>, Arc<RsaKey>);

/// Bounded LRU cache of imported [`RsaKey`]s for [`Verifier::verify`], keyed
/// by the exact `(n, e)` modulus and public-exponent bytes (never a hash
/// digest, since public keys come from untrusted peers).
struct RsaVerifyCache {
    capacity: usize,
    /// From the most to the least recently used.
    entries: Mutex<Vec<RsaVerifyEntry>>,
}

impl RsaVerifyCache {
    const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(Vec::new()),
        }
    }

    fn get_or_try_insert(&self, n: &[u8], e: &[u8]) -> signature::Result<Arc<RsaKey>> {
        let (n, e) = (uint_bytes(n), uint_bytes(e));
        check_rsa_public_components(n, e)?;
        if let Some(imported) = self.touch(n, e) {
            return Ok(imported);
        }
        // Imported without the lock, so that other keys can be used meanwhile.
        #[cfg(test)]
        tests::count_rsa_verify_import();
        let key = Arc::new(
            RsaKey::set_public_key(n, e, RsaKeyUsage::Sign).map_err(|error| {
                debug!("SymCrypt rejected an RSA public key: {error}");
                signature::Error::new()
            })?,
        );
        // Declared before locking so an evicted key is freed after the lock is released.
        let mut evicted = None;
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = entries
            .iter()
            .position(|(entry_n, entry_e, _)| (entry_n.as_ref(), entry_e.as_ref()) == (n, e))
        {
            let entry = entries.remove(index);
            let cached = Arc::clone(&entry.2);
            entries.insert(0, entry);
            return Ok(cached);
        }
        if entries.len() >= self.capacity {
            evicted = entries.pop();
        }
        entries.insert(0, (n.into(), e.into(), Arc::clone(&key)));
        drop(entries);
        drop(evicted);
        Ok(key)
    }

    fn touch(&self, n: &[u8], e: &[u8]) -> Option<Arc<RsaKey>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let index = entries
            .iter()
            .position(|(entry_n, entry_e, _)| (entry_n.as_ref(), entry_e.as_ref()) == (n, e))?;
        let entry = entries.remove(index);
        let value = Arc::clone(&entry.2);
        entries.insert(0, entry);
        Some(value)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
fn rsa_verify_key(n: &[u8], e: &[u8]) -> signature::Result<Arc<RsaKey>> {
    RSA_VERIFY_KEYS.get_or_try_insert(n, e)
}

fn verify_rsa(
    key: &RsaPublicKey,
    hash: HashAlg,
    message: &[u8],
    blob: &[u8],
) -> signature::Result<()> {
    verify_rsa_cached(&RSA_VERIFY_KEYS, key, hash, message, blob)
}

fn verify_rsa_cached(
    cache: &RsaVerifyCache,
    key: &RsaPublicKey,
    hash: HashAlg,
    message: &[u8],
    blob: &[u8],
) -> signature::Result<()> {
    let (n, e) = rsa_public_components(key)?;
    // RFC 8332 wants a signature as long as the modulus. Like OpenSSH,
    // accept a shorter one (with its leading zero bytes stripped) and pad it.
    let padding = n
        .len()
        .checked_sub(blob.len())
        .filter(|_| !blob.is_empty())
        .ok_or_else(signature::Error::new)?;
    let mut padded = vec![0; n.len()];
    padded
        .get_mut(padding..)
        .ok_or_else(signature::Error::new)?
        .copy_from_slice(blob);
    let (digest, hash) = rsa_digest(hash, message)?;
    let imported = cache.get_or_try_insert(n, e)?;
    #[cfg(test)]
    tests::verified_rsa_with(&imported);
    imported
        .pkcs1_verify(&digest, &padded, hash)
        .map_err(|_| signature::Error::new())
}

fn import_rsa(keypair: &RsaKeypair) -> ssh_key::Result<SigningKey> {
    let (n, e) = rsa_public_components(keypair.public()).inspect_err(|_| {
        error!(
            "cannot sign with this RSA key: the symcrypt backend takes moduli of 1024 to \
             16384 bits and odd public exponents of 3 to 64 bits"
        )
    })?;
    let private = keypair.private();
    let (Some(p), Some(q)) = (
        private.p().as_positive_bytes(),
        private.q().as_positive_bytes(),
    ) else {
        return Err(ssh_key::Error::Crypto);
    };
    // SymCrypt derives the private exponent and the CRT values from p and q.
    let key = RsaKey::set_key_pair(n, e, p, q, RsaKeyUsage::Sign)
        .map_err(|error| signing_error("import an RSA key", error))?;
    Ok(SigningKey::Rsa(key))
}

/// The SSH signature blob of `message`.
fn sign_rsa(key: &RsaKey, hash: HashAlg, message: &[u8]) -> ssh_key::Result<Vec<u8>> {
    let (digest, hash_algorithm) = rsa_digest(hash, message)?;
    key.pkcs1_sign(&digest, hash_algorithm)
        .map_err(|error| signing_error("sign with an RSA key", error))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Weak};

    use hex_literal::hex;
    use ssh_encoding::{Decode, Encode};
    #[cfg(feature = "ssh-mldsa87-p384")]
    use ssh_key::private::Mldsa87P384Keypair;
    use ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, KeypairData, RsaKeypair, RsaPrivateKey};
    use ssh_key::public::{EcdsaPublicKey, KeyData, RsaPublicKey};
    use ssh_key::{
        Algorithm, Certificate, EcdsaCurve, HashAlg, Mpint, PrivateKey, Signature, SshSig,
    };

    use super::key_cache::KeyCache;
    #[cfg(feature = "ssh-mldsa87-p384")]
    use super::verify_mldsa87_p384;
    use super::{
        BY_VALUE_CACHE_CAPACITY, ByValueCache, Curve, DEFAULT_ORDER, KEY_CACHE_CAPACITY,
        RSA_VERIFY_CACHE_CAPACITY, RsaKey, RsaVerifyCache, SigningKey, rsa_public_components,
        rsa_verify_key, sign_by_value, sign_cached, verify_rsa_cached,
    };
    use crate::crypto::{
        KeyHolder, is_supported_signature_algorithm, sign, sign_held, verify, verify_certificate,
    };
    use crate::keys::PrivateKeyWithHashAlg;

    const P256: Algorithm = Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    };
    const P384: Algorithm = Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    };
    const P521: Algorithm = Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    };
    const RSA_SHA256: Algorithm = Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    };
    const RSA_SHA512: Algorithm = Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    };
    const SSH_RSA: Algorithm = Algorithm::Rsa { hash: None };

    /// A fixture made with `ssh-keygen` (OpenSSH 10.2).
    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("testdata/sign/", $name))
        };
    }

    fn key(openssh: &str) -> PrivateKey {
        PrivateKey::from_openssh(openssh).unwrap()
    }

    fn ecdsa_p256() -> PrivateKey {
        key(fixture!("ecdsa_p256.key"))
    }

    fn ecdsa_p384() -> PrivateKey {
        key(fixture!("ecdsa_p384.key"))
    }

    fn ecdsa_p521() -> PrivateKey {
        key(fixture!("ecdsa_p521.key"))
    }

    fn rsa_1024() -> PrivateKey {
        key(fixture!("rsa_1024.key"))
    }

    fn rsa_2048() -> PrivateKey {
        key(fixture!("rsa_2048.key"))
    }

    /// The SSH encoding of an ECDSA signature: the mpints `r` and `s`.
    fn ecdsa_blob(r: &[u8], s: &[u8]) -> Vec<u8> {
        [mpint(r), mpint(s)].concat()
    }

    /// The SSH encoding of a non-negative integer.
    fn mpint(unsigned: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        Mpint::from_positive_bytes(unsigned)
            .encode(&mut encoded)
            .unwrap();
        encoded
    }

    /// An mpint field holding exactly `body`, valid or not.
    fn raw_mpint(body: &[u8]) -> Vec<u8> {
        [&(body.len() as u32).to_be_bytes()[..], body].concat()
    }

    /// `a - b`, for big-endian integers of the same length with `a >= b`.
    fn sub(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut difference = vec![0; a.len()];
        let mut borrow = 0;
        for i in (0..a.len()).rev() {
            let digit = i16::from(a[i]) - i16::from(b[i]) - borrow;
            borrow = i16::from(digit < 0);
            difference[i] = digit.rem_euclid(256) as u8;
        }
        assert_eq!(borrow, 0);
        difference
    }

    /// RFC 6979, appendix A.2.5 (P-256 with SHA-256), A.2.6 (P-384 with
    /// SHA-384) and A.2.7 (P-521 with SHA-512; the "sample" `r` and `s` are
    /// 65 bytes long, the "test" ones 66).
    struct Rfc6979 {
        curve: EcdsaCurve,
        x: &'static [u8],
        ux: &'static [u8],
        uy: &'static [u8],
        /// `(message, r, s)` for the messages "sample" and "test".
        signatures: [(&'static [u8], &'static [u8], &'static [u8]); 2],
    }

    const RFC6979: [Rfc6979; 3] = [
        Rfc6979 {
            curve: EcdsaCurve::NistP256,
            x: &hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
            ux: &hex!("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"),
            uy: &hex!("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"),
            signatures: [
                (
                    b"sample",
                    &hex!("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"),
                    &hex!("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"),
                ),
                (
                    b"test",
                    &hex!("f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"),
                    &hex!("019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"),
                ),
            ],
        },
        Rfc6979 {
            curve: EcdsaCurve::NistP384,
            x: &hex!(
                "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8"
                "96d5724e4c70a825f872c9ea60d2edf5"
            ),
            ux: &hex!(
                "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64"
                "def8f0ea9055866064a254515480bc13"
            ),
            uy: &hex!(
                "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1"
                "288b231c3ae0d4fe7344fd2533264720"
            ),
            signatures: [
                (
                    b"sample",
                    &hex!(
                        "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c"
                        "81a648152e44acf96e36dd1e80fabe46"
                    ),
                    &hex!(
                        "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f"
                        "a329c145786e679e7b82c71a38628ac8"
                    ),
                ),
                (
                    b"test",
                    &hex!(
                        "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb"
                        "0542a7f0812998da8f1dd3ca3cf023db"
                    ),
                    &hex!(
                        "ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e0"
                        "6a739f040649a667bf3b828246baa5a5"
                    ),
                ),
            ],
        },
        Rfc6979 {
            curve: EcdsaCurve::NistP521,
            x: &hex!(
                "00fa"
                "d06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa8"
                "96eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538"
            ),
            ux: &hex!(
                "0189"
                "4550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd3711"
                "23d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a4"
            ),
            uy: &hex!(
                "0049"
                "3101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0"
                "db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5"
            ),
            signatures: [
                (
                    b"sample",
                    &hex!(
                        "00c3"
                        "28fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e"
                        "25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa"
                    ),
                    &hex!(
                        "0061"
                        "7cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af2826"
                        "23eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a"
                    ),
                ),
                (
                    b"test",
                    &hex!(
                        "013e"
                        "99020abf5cee7525d16b69b229652ab6bdf2affcaef38773b4b7d08725f10cdb"
                        "93482fdcc54edcee91eca4166b2a7c6265ef0ce2bd7051b7cef945babd47ee6d"
                    ),
                    &hex!(
                        "01fb"
                        "d0013c674aa79cb39849527916ce301c66ea7ce8b80682786ad60f98f7e78a19"
                        "ca69eff5c57400e3b3a0ad66ce0978214d13baf4e9ac60752f7b155e2de4dce3"
                    ),
                ),
            ],
        },
    ];

    impl Rfc6979 {
        fn algorithm(&self) -> Algorithm {
            Algorithm::Ecdsa { curve: self.curve }
        }

        fn sec1(&self) -> Vec<u8> {
            [&[0x04], self.ux, self.uy].concat()
        }

        fn public_key(&self) -> KeyData {
            KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&self.sec1()).unwrap())
        }

        fn private_key(&self) -> PrivateKey {
            let keypair = match EcdsaPublicKey::from_sec1_bytes(&self.sec1()).unwrap() {
                EcdsaPublicKey::NistP256(public) => EcdsaKeypair::NistP256 {
                    public,
                    private: EcdsaPrivateKey::from(<[u8; 32]>::try_from(self.x).unwrap()),
                },
                EcdsaPublicKey::NistP384(public) => EcdsaKeypair::NistP384 {
                    public,
                    private: EcdsaPrivateKey::from(<[u8; 48]>::try_from(self.x).unwrap()),
                },
                EcdsaPublicKey::NistP521(public) => EcdsaKeypair::NistP521 {
                    public,
                    private: EcdsaPrivateKey::from(<[u8; 66]>::try_from(self.x).unwrap()),
                },
            };
            PrivateKey::new(KeypairData::Ecdsa(keypair), "").unwrap()
        }
    }

    /// PKCS#1 v1.5 signatures of "sample" by `rsa_2048.key`, made with
    /// OpenSSL (`openssl dgst -<hash> -sign`).
    const RSA_2048_SHA1: [u8; 256] = hex!(
        "388a841b7f6933e32ce6b3ce614d16829bf2cc34f939f5aaf0208e317b35d1a0"
        "4b85eec8f3916d2d9445b85deb680d0c3fef1fc9e3d94e76faa4ea2d30b78744"
        "28d4127b1b88fd6925e52f2a5d5e88e6470094412f6a5400ec7fdb7f2322f771"
        "ec2540e0cb5024b48d50e51a54b1fc14ae08eeaeb1aa7c02d097d4f80dd88b17"
        "e5882986fc85aeba861f573c4affd04812212994b810f3de92daa8b2c9ddc0df"
        "4bb3a2016d2db7f6b7137939dcf6462edbcc1d957cc24ff957dc362394832ced"
        "c3655446ebc9789922da13ef049363a235eb5be4414df8663369b65f6635fb89"
        "48589c2c85b29ee2964413955a7f57c35c1534faba85e91f5c8c9d68cb2f7f0f"
    );
    const RSA_2048_SHA256: [u8; 256] = hex!(
        "1bc8d66d2af879b3f38ca0e9a656dcbce7a3d008e46d23f2b679f234761c851d"
        "b35455f7e4b124a1ab47f17f070a8b307e22c024148383aa85c215b7c6deda0b"
        "6c8c568f661988a2c640fb2cb8b831bcce61482e5f48626188698eab7cc19f53"
        "df3ed8645deb64630eb45e7657ebda14100e6a3282aac9604ffd267cb52f7c0d"
        "54597bdf5a0e18331d2bafb21eb2b353e7a28f019d4080deb4d5b56bca47be83"
        "624fcd1afb705b622c22f86ecf0007cd655affac65a52597fa627876c413e53d"
        "bb491b7bc06497d1f9c07165e5c1fe27d32e6fd38cf89dc84e56c9f85ccc6897"
        "d404e928fa0c5543995256be5a528bc26bd97c2e498afbe7819970f21ecc3f99"
    );
    const RSA_2048_SHA512: [u8; 256] = hex!(
        "72ab38fe8300801561a9e7a2b072d2f5ba6e7aa8efa00c7bfcaf30f56567ebf0"
        "f662f4c2a7f138ea1eafc8fc8e6c4d4f3eca7322ba601726510717cf059fcb16"
        "9812682d83fa42c2d253bc226607c33ceefb5d73cb2b5b2a284fd90f23d48552"
        "2c4b3ed20e5c19fe7b64ccee50127b0ca602a52e42aabc14406928e658e59851"
        "ced36c99dbbf496fe8ecb2ea173bcaffba178b5f2f3a2dc80638cf9b93006286"
        "39233cb271dd0843cf7e5e486f0949a50a434db1ff9cafd0fa417b04b277f45f"
        "50dfac2f9eaa54987371b3cf2e9e111a8c61195ca77ec3d8edad8d8bed7fbaa8"
        "a125e519c3c9c5153705a6996d67272dc0f3a215a2cce967dc9ddf13ffb9cf32"
    );

    #[test]
    fn implements_exactly_ecdsa_and_rsa_sha2() {
        assert_eq!(
            DEFAULT_ORDER,
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
        assert_eq!(crate::Preferred::DEFAULT.key.as_ref(), DEFAULT_ORDER);
        for algorithm in DEFAULT_ORDER {
            assert!(is_supported_signature_algorithm(algorithm), "{algorithm}");
        }
        for algorithm in [
            #[cfg(not(feature = "ssh-mldsa87-p384"))]
            Algorithm::Mldsa87P384,
            #[cfg(not(russh_ed25519_aws_lc))]
            Algorithm::Ed25519,
            SSH_RSA,
            Algorithm::Dsa,
            Algorithm::SkEd25519,
            Algorithm::SkEcdsaSha2NistP256,
            Algorithm::new("unknown@example.com").unwrap(),
        ] {
            assert!(!is_supported_signature_algorithm(&algorithm), "{algorithm}");
        }
    }

    #[test]
    fn ecdsa_rfc6979_signatures_verify() {
        for vector in &RFC6979 {
            let key = vector.public_key();
            let order = Curve::new(vector.curve).order();
            for (message, r, s) in vector.signatures {
                let signature = Signature::new(vector.algorithm(), ecdsa_blob(r, s)).unwrap();
                verify(&key, message, &signature).unwrap();
                assert!(verify(&key, b"tampered", &signature).is_err());
                let swapped = Signature::new(vector.algorithm(), ecdsa_blob(s, r)).unwrap();
                assert!(verify(&key, message, &swapped).is_err());
                // `(r, n - s)` is valid too, so this checks the order
                // constant `fixed_signature` compares with.
                let negated = ecdsa_blob(r, &sub(order, s));
                verify(
                    &key,
                    message,
                    &Signature::new(vector.algorithm(), negated).unwrap(),
                )
                .unwrap();
                let out_of_range = ecdsa_blob(r, order);
                let out_of_range = Signature::new(vector.algorithm(), out_of_range).unwrap();
                assert!(verify(&key, message, &out_of_range).is_err());
            }
        }
    }

    #[test]
    fn ecdsa_sign_verify_round_trip() {
        let keys = [
            ecdsa_p256(),
            ecdsa_p384(),
            ecdsa_p521(),
            RFC6979[0].private_key(),
            RFC6979[1].private_key(),
            RFC6979[2].private_key(),
        ];
        for key in &keys {
            let public = key.public_key().key_data();
            // The hash only matters for RSA.
            for hash_alg in [None, Some(HashAlg::Sha256), Some(HashAlg::Sha512)] {
                let signature = sign(key, hash_alg, b"message").unwrap();
                assert_eq!(signature.algorithm(), key.algorithm());
                verify(public, b"message", &signature).unwrap();
                assert!(verify(public, b"other message", &signature).is_err());
            }
        }
    }

    /// SymCrypt's fixed-size `r` and `s` with leading zero bytes become
    /// shorter mpints, which are padded back when verifying. Each of `r` and
    /// `s` has a leading zero byte with probability 1/256 on P-256; on P-521,
    /// whose 66-byte values start with 0 or 1, with probability 1/2, and two
    /// with probability 1/512.
    #[test]
    fn ecdsa_short_r_and_s_round_trip() {
        for (key, size, max_zeros) in [(ecdsa_p256(), 32, 1), (ecdsa_p521(), 66, 2)] {
            let public = key.public_key().key_data();
            // The numbers of leading zero bytes (up to `max_zeros`) seen in
            // `r` and in `s`.
            let expected: BTreeSet<usize> = (0..=max_zeros).collect();
            let mut seen = [BTreeSet::new(), BTreeSet::new()];
            for i in 0..8192u32 {
                if seen.iter().all(|zeros| *zeros == expected) {
                    break;
                }
                let message = i.to_be_bytes();
                let signature = sign(&key, None, &message).unwrap();
                verify(public, &message, &signature).unwrap();
                let mut blob = signature.as_bytes();
                for zeros in &mut seen {
                    let len = Mpint::decode(&mut blob)
                        .unwrap()
                        .as_positive_bytes()
                        .unwrap()
                        .len();
                    assert!(len <= size);
                    zeros.insert((size - len).min(max_zeros));
                }
            }
            assert_eq!(seen, [expected.clone(), expected], "{}", key.algorithm());
        }
    }

    /// P-521 `r` and `s` are mpints of up to 66 bytes, below `n`, padded to
    /// 66 bytes for SymCrypt.
    #[test]
    fn p521_signature_encoding() {
        let curve = Curve::NistP521;
        let n = curve.order();
        let n_minus_one = sub(n, &[[0; 65].as_slice(), &[1]].concat());
        // 65 bytes with the top bit set, so a 66-byte mpint with a sign byte.
        let high = [[0x80].as_slice(), &[0x5a; 64]].concat();
        assert_eq!(mpint(&high).len(), 4 + 66);
        let short = [0x01; 64];
        let pad = |value: &[u8]| [vec![0; 66 - value.len()], value.to_vec()].concat();
        for (r, s) in [
            (&high[..], &n_minus_one[..]),
            (&short[..], &high[..]),
            (&n_minus_one[..], &short[..]),
        ] {
            assert_eq!(
                curve.fixed_signature(&ecdsa_blob(r, s)),
                Some([pad(r), pad(s)].concat())
            );
        }
        let one = mpint(&[1]);
        let mut two_to_521 = [0; 66];
        two_to_521[0] = 2;
        for (case, blob) in [
            ("r = n", [mpint(n), one.clone()].concat()),
            ("s = n", [one.clone(), mpint(n)].concat()),
            ("s = 2^521", [one.clone(), mpint(&two_to_521)].concat()),
            ("r = 2^528 - 1", [mpint(&[0xff; 66]), one.clone()].concat()),
            ("s of 67 bytes", [one.clone(), mpint(&[1; 67])].concat()),
        ] {
            assert_eq!(curve.fixed_signature(&blob), None, "{case}");
        }
    }

    /// Signatures by OpenSSH 10.2 (with OpenSSL), `ssh-keygen -Y sign -f
    /// ecdsa_p521.key -n russh`, of the messages "russh <n>". Their `r` and
    /// `s` are mpints of 64 to 66 bytes, with and without a sign byte: 0, 1
    /// or 2 bytes shorter than 66 once the sign byte is removed.
    #[test]
    fn verifies_openssh_p521_signatures() {
        // What an SSHSIG signature covers (PROTOCOL.sshsig), hashed by
        // SymCrypt rather than by `sha2`, as `SshSig::signed_data` would.
        fn signed_data(message: &[u8]) -> Vec<u8> {
            let mut data = b"SSHSIG".to_vec();
            let digest = symcrypt::hash::sha512(message);
            for field in [b"russh".as_slice(), b"", b"sha512", &digest] {
                field.encode(&mut data).unwrap();
            }
            data
        }
        let public = ecdsa_p521().public_key().key_data().clone();
        // The body length of the mpints `r` and `s`, and whether it starts
        // with a sign byte.
        let expected = BTreeSet::from([
            (64, false),
            (65, false),
            (65, true),
            (66, false),
            (66, true),
        ]);
        let mut seen = [BTreeSet::new(), BTreeSet::new()];
        let signatures = fixture!("ecdsa_p521.sshsig");
        for signature in signatures.split_inclusive("-----END SSH SIGNATURE-----\n") {
            let (message, pem) = signature.split_once('\n').unwrap();
            let sshsig = SshSig::from_pem(pem).unwrap();
            assert_eq!(sshsig.public_key(), &public);
            assert_eq!(sshsig.namespace(), "russh");
            assert_eq!(sshsig.hash_alg(), HashAlg::Sha512);
            let data = signed_data(message.as_bytes());
            verify(&public, &data, sshsig.signature()).unwrap();
            assert!(verify(&public, &signed_data(b"russh"), sshsig.signature()).is_err());
            let mut blob = sshsig.signature().as_bytes();
            for shapes in &mut seen {
                let mpint = Mpint::decode(&mut blob).unwrap();
                let body = mpint.as_bytes();
                shapes.insert((body.len(), body[0] == 0));
            }
        }
        assert_eq!(seen, [expected.clone(), expected]);
    }

    #[test]
    fn malformed_ecdsa_signatures_are_rejected() {
        let curve = Curve::NistP256;
        let n = curve.order();
        let one = mpint(&[1]);
        let mut fixed_one = vec![0; 32];
        fixed_one[31] = 1;
        assert_eq!(
            curve.fixed_signature(&[one.clone(), one.clone()].concat()),
            Some([fixed_one.clone(), fixed_one].concat())
        );
        let n_minus_one = sub(n, &[[0; 31].as_slice(), &[1]].concat());
        assert!(
            curve
                .fixed_signature(&[mpint(&n_minus_one), mpint(&n_minus_one)].concat())
                .is_some()
        );
        let mut n_plus_one = n.to_vec();
        n_plus_one[31] += 1;
        for (case, blob) in [
            ("empty", vec![]),
            ("no s", one.clone()),
            (
                "truncated s",
                [one.clone(), raw_mpint(&[1, 1])[..5].to_vec()].concat(),
            ),
            (
                "trailing data",
                [one.clone(), one.clone(), vec![0]].concat(),
            ),
            ("r = 0", [raw_mpint(&[]), one.clone()].concat()),
            ("s = 0", [one.clone(), raw_mpint(&[])].concat()),
            ("r = n", [mpint(n), one.clone()].concat()),
            ("s = n", [one.clone(), mpint(n)].concat()),
            ("r = n + 1", [mpint(&n_plus_one), one.clone()].concat()),
            ("s = 2^256 - 1", [one.clone(), mpint(&[0xff; 32])].concat()),
            ("r of 33 bytes", [mpint(&[1; 33]), one.clone()].concat()),
            ("negative r", [raw_mpint(&[0x80]), one.clone()].concat()),
            ("non-minimal r", [raw_mpint(&[0, 1]), one.clone()].concat()),
            ("non-minimal s", [one.clone(), raw_mpint(&[0])].concat()),
        ] {
            assert_eq!(curve.fixed_signature(&blob), None, "{case}");
        }
    }

    #[test]
    fn mismatched_keys_and_algorithms_are_rejected() {
        let (p256, p384, p521, rsa) = (ecdsa_p256(), ecdsa_p384(), ecdsa_p521(), rsa_2048());
        let message = b"message";
        let p256_signature = sign(&p256, None, message).unwrap();
        let p521_signature = sign(&p521, None, message).unwrap();
        let rsa_signature = sign(&rsa, Some(HashAlg::Sha256), message).unwrap();
        assert!(verify(p384.public_key().key_data(), message, &p256_signature).is_err());
        assert!(verify(p521.public_key().key_data(), message, &p256_signature).is_err());
        assert!(verify(p256.public_key().key_data(), message, &p521_signature).is_err());
        assert!(verify(p384.public_key().key_data(), message, &p521_signature).is_err());
        assert!(verify(rsa.public_key().key_data(), message, &p256_signature).is_err());
        assert!(verify(p256.public_key().key_data(), message, &rsa_signature).is_err());
        assert!(verify(&RFC6979[0].public_key(), message, &p256_signature).is_err());
        assert!(verify(&RFC6979[2].public_key(), message, &p521_signature).is_err());
        // Relabelled signatures: P-256 as P-384, and as P-521 (its `r` and
        // `s` are short enough to be padded). ssh-key refuses to label the
        // longer P-521 ones as P-256.
        let relabelled = Signature::new(P384, p256_signature.as_bytes()).unwrap();
        assert!(verify(p256.public_key().key_data(), message, &relabelled).is_err());
        let relabelled = Signature::new(P521, p256_signature.as_bytes()).unwrap();
        assert!(verify(p521.public_key().key_data(), message, &relabelled).is_err());
        assert!(Signature::new(P256, p521_signature.as_bytes()).is_err());
    }

    #[test]
    fn invalid_ecdsa_public_keys_are_rejected() {
        for vector in [&RFC6979[0], &RFC6979[2]] {
            let (message, r, s) = vector.signatures[0];
            let signature = Signature::new(vector.algorithm(), ecdsa_blob(r, s)).unwrap();
            let mut off_curve = vector.sec1();
            *off_curve.last_mut().unwrap() ^= 1;
            // The right point, compressed.
            let y_parity = vector.uy.last().unwrap() & 1;
            let compressed = [&[0x02 | y_parity], vector.ux].concat();
            for sec1 in [off_curve, compressed] {
                let key = KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&sec1).unwrap());
                assert!(verify(&key, message, &signature).is_err());
            }
        }
    }

    #[test]
    fn rsa_pkcs1_v15_known_answers() {
        let key = rsa_2048();
        let public = key.public_key().key_data();
        for (hash, expected) in [
            (HashAlg::Sha256, RSA_2048_SHA256),
            (HashAlg::Sha512, RSA_2048_SHA512),
        ] {
            let algorithm = Algorithm::Rsa { hash: Some(hash) };
            verify(
                public,
                b"sample",
                &Signature::new(algorithm, expected).unwrap(),
            )
            .unwrap();
            // PKCS#1 v1.5 signatures are deterministic.
            let signature = sign(&key, Some(hash), b"sample").unwrap();
            assert_eq!(signature.as_bytes(), expected);
        }
        // A valid `ssh-rsa` (SHA-1) signature is refused...
        let error = verify(
            public,
            b"sample",
            &Signature::new(SSH_RSA, RSA_2048_SHA1).unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            ssh_key::Error::from(error),
            ssh_key::Error::AlgorithmUnsupported { algorithm: SSH_RSA }
        );
        // ...even as `rsa-sha2-256`, and so are signatures with the other
        // SHA-2 hash.
        for (algorithm, signature) in [
            (RSA_SHA256, RSA_2048_SHA1),
            (RSA_SHA512, RSA_2048_SHA256),
            (RSA_SHA256, RSA_2048_SHA512),
        ] {
            let signature = Signature::new(algorithm, signature).unwrap();
            assert!(verify(public, b"sample", &signature).is_err());
        }
    }

    #[test]
    fn rsa_sign_verify_round_trip() {
        for key in [rsa_2048(), rsa_1024()] {
            let public = key.public_key().key_data();
            let KeyData::Rsa(rsa) = public else {
                panic!("not an RSA key");
            };
            let modulus_len = rsa.n().as_positive_bytes().unwrap().len();
            for (hash, other) in [
                (HashAlg::Sha256, HashAlg::Sha512),
                (HashAlg::Sha512, HashAlg::Sha256),
            ] {
                let signature = sign(&key, Some(hash), b"message").unwrap();
                assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(hash) });
                assert_eq!(signature.as_bytes().len(), modulus_len);
                verify(public, b"message", &signature).unwrap();
                assert!(verify(public, b"other message", &signature).is_err());
                let relabelled =
                    Signature::new(Algorithm::Rsa { hash: Some(other) }, signature.as_bytes())
                        .unwrap();
                assert!(verify(public, b"message", &relabelled).is_err());
            }
        }
    }

    #[test]
    fn rsa_signature_length_is_checked() {
        let key = rsa_2048();
        let public = key.public_key().key_data();
        // The signature of this message has a leading zero byte.
        let message = b"leading zero 48";
        let signature = sign(&key, Some(HashAlg::Sha256), message).unwrap();
        let full = signature.as_bytes();
        assert_eq!((full.len(), full[0]), (256, 0));
        // Without it, the signature is padded back, as OpenSSH does.
        verify(
            public,
            message,
            &Signature::new(RSA_SHA256, &full[1..]).unwrap(),
        )
        .unwrap();
        for blob in [
            [&[0], full].concat(),
            [full, &[0]].concat(),
            vec![],
            vec![0; 256],
        ] {
            let signature = Signature::new(RSA_SHA256, blob).unwrap();
            assert!(verify(public, message, &signature).is_err());
        }
    }

    #[test]
    fn rsa_key_policy() {
        let accepts = |n: &[u8], e: &[u8]| {
            let key =
                RsaPublicKey::new(Mpint::from_positive_bytes(e), Mpint::from_positive_bytes(n))
                    .unwrap();
            rsa_public_components(&key).is_ok()
        };
        let modulus = |len: usize, top: u8, bottom: u8| {
            let mut n = vec![0x5a; len];
            n[0] = top;
            n[len - 1] = bottom;
            n
        };
        let f4 = [1, 0, 1];
        assert!(accepts(&modulus(128, 0x80, 1), &f4));
        assert!(!accepts(&modulus(128, 0x7f, 1), &f4));
        assert!(accepts(&modulus(2048, 0xff, 1), &f4));
        assert!(!accepts(&modulus(2049, 0x01, 1), &f4));
        assert!(!accepts(&modulus(256, 0xc5, 2), &f4));
        let n = modulus(256, 0xc5, 1);
        assert!(accepts(&n, &[3]));
        assert!(accepts(&n, &[0xff; 8]));
        assert!(!accepts(&n, &[1]));
        assert!(!accepts(&n, &[1, 0, 0]));
        assert!(!accepts(&n, &[1, 0, 0, 0, 0, 0, 0, 0, 1]));
        for key in [rsa_1024(), rsa_2048()] {
            let KeyData::Rsa(public) = key.public_key().key_data() else {
                panic!("not an RSA key");
            };
            assert!(rsa_public_components(public).is_ok());
        }
    }

    /// SymCrypt checks that the private key matches the public one.
    #[test]
    fn inconsistent_private_keys_cannot_sign() {
        let (rsa_1024, rsa_2048) = (rsa_1024(), rsa_2048());
        let (KeypairData::Rsa(small), KeypairData::Rsa(large)) =
            (rsa_1024.key_data(), rsa_2048.key_data())
        else {
            panic!("not RSA keys");
        };
        let mixed = RsaKeypair::new(large.public().clone(), small.private().clone()).unwrap();
        let mixed = PrivateKey::new(KeypairData::Rsa(mixed), "").unwrap();
        assert_eq!(
            sign(&mixed, Some(HashAlg::Sha256), b"message").unwrap_err(),
            ssh_key::Error::Crypto
        );

        let p256 = ecdsa_p256();
        let KeypairData::Ecdsa(EcdsaKeypair::NistP256 { public, .. }) = p256.key_data() else {
            panic!("not a P-256 key");
        };
        let mixed = EcdsaKeypair::NistP256 {
            public: *public,
            private: EcdsaPrivateKey::from(<[u8; 32]>::try_from(RFC6979[0].x).unwrap()),
        };
        let mixed = PrivateKey::new(KeypairData::Ecdsa(mixed), "").unwrap();
        assert_eq!(
            sign(&mixed, None, b"message").unwrap_err(),
            ssh_key::Error::Crypto
        );

        let p521 = ecdsa_p521();
        let KeypairData::Ecdsa(EcdsaKeypair::NistP521 { public, .. }) = p521.key_data() else {
            panic!("not a P-521 key");
        };
        let mixed = EcdsaKeypair::NistP521 {
            public: *public,
            private: EcdsaPrivateKey::from(<[u8; 66]>::try_from(RFC6979[2].x).unwrap()),
        };
        let mixed = PrivateKey::new(KeypairData::Ecdsa(mixed), "").unwrap();
        assert_eq!(
            sign(&mixed, None, b"message").unwrap_err(),
            ssh_key::Error::Crypto
        );
    }

    // With `ed25519-aws-lc`, `ssh-rsa` is the only unsupported key here.
    #[allow(clippy::single_element_loop)]
    #[test]
    fn unsupported_keys_cannot_sign() {
        for (key, hash_alg, algorithm) in [
            #[cfg(not(russh_ed25519_aws_lc))]
            (key(fixture!("ed25519.key")), None, Algorithm::Ed25519),
            (rsa_2048(), None, SSH_RSA),
        ] {
            assert_eq!(
                sign(&key, hash_alg, b"message").unwrap_err(),
                ssh_key::Error::AlgorithmUnsupported { algorithm }
            );
        }
    }

    /// With `ed25519-aws-lc`, Ed25519 keys sign and verify, both directly
    /// and as held keys, which are imported once.
    #[cfg(russh_ed25519_aws_lc)]
    #[test]
    fn ed25519_sign_verify_round_trip() {
        let key = key(fixture!("ed25519.key"));
        let public_key = key.public_key().key_data().clone();
        let signature = sign(&key, None, MESSAGE).unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
        assert_eq!(signature.as_bytes().len(), 64);
        verify(&public_key, MESSAGE, &signature).unwrap();
        assert!(verify(&public_key, b"tampered", &signature).is_err());
        // Ed25519 is deterministic (RFC 8032), so `sign_held` must agree.
        let holder = Arc::new(key);
        let imports = count_imports(|| {
            for _ in 0..3 {
                let held = sign_held(&holder, 0, None, MESSAGE).unwrap();
                assert_eq!(held, signature);
            }
        });
        assert_eq!(imports, 1);
        // An ECDSA key does not verify an Ed25519 signature.
        assert!(verify(ecdsa_p256().public_key().key_data(), MESSAGE, &signature).is_err());
    }

    /// With `ed25519-aws-lc`, a key whose public half is not the one of its
    /// seed does not sign.
    #[cfg(russh_ed25519_aws_lc)]
    #[test]
    fn inconsistent_ed25519_keys_cannot_sign() {
        use ssh_key::private::Ed25519Keypair;
        use ssh_key::public::Ed25519PublicKey;

        let KeypairData::Ed25519(keypair) = key(fixture!("ed25519.key")).key_data().clone() else {
            panic!("not an Ed25519 key");
        };
        let mut public = keypair.public.0;
        public[0] ^= 1;
        let mixed = Ed25519Keypair {
            public: Ed25519PublicKey(public),
            private: keypair.private,
        };
        let mixed = PrivateKey::new(KeypairData::Ed25519(mixed), "").unwrap();
        assert_eq!(
            sign(&mixed, None, MESSAGE).unwrap_err(),
            ssh_key::Error::Crypto
        );
    }

    /// User certificates for `ecdsa_p256.key`, signed by CA keys of each
    /// type with `ssh-keygen -s`.
    // With `ed25519-aws-lc`, `ssh-rsa` is the only unsupported CA here.
    #[allow(clippy::single_element_loop)]
    #[test]
    fn certificate_ca_signatures() {
        let subject = ecdsa_p256();
        for (openssh, ca_algorithm) in [
            (fixture!("cert_ca_ecdsa_p256.pub"), P256),
            (fixture!("cert_ca_ecdsa_p384.pub"), P384),
            (fixture!("cert_ca_ecdsa_p521.pub"), P521),
            (fixture!("cert_ca_rsa_sha2_256.pub"), RSA_SHA256),
            (fixture!("cert_ca_rsa_sha2_512.pub"), RSA_SHA512),
            #[cfg(russh_ed25519_aws_lc)]
            (fixture!("cert_ca_ed25519.pub"), Algorithm::Ed25519),
        ] {
            let certificate = Certificate::from_openssh(openssh.trim()).unwrap();
            assert_eq!(certificate.public_key(), subject.public_key().key_data());
            assert_eq!(certificate.signature().algorithm(), ca_algorithm);
            verify_certificate(&certificate).unwrap();
            // Changing a signed byte (in the nonce) or the signature breaks it.
            let encoded = certificate.to_bytes().unwrap();
            let nonce = certificate.nonce();
            let nonce_at = encoded
                .windows(nonce.len())
                .position(|window| window == nonce)
                .unwrap();
            for index in [nonce_at, encoded.len() - 1] {
                let mut tampered = encoded.clone();
                tampered[index] ^= 1;
                let tampered = Certificate::from_bytes(&tampered).unwrap();
                assert!(verify_certificate(&tampered).is_err(), "{ca_algorithm}");
            }
        }
        for (openssh, ca_algorithm) in [
            #[cfg(not(russh_ed25519_aws_lc))]
            (fixture!("cert_ca_ed25519.pub"), Algorithm::Ed25519),
            (fixture!("cert_ca_ssh_rsa.pub"), SSH_RSA),
        ] {
            let certificate = Certificate::from_openssh(openssh.trim()).unwrap();
            let error = verify_certificate(&certificate).unwrap_err();
            assert_eq!(
                ssh_key::Error::from(error),
                ssh_key::Error::AlgorithmUnsupported {
                    algorithm: ca_algorithm
                }
            );
        }
    }

    thread_local! {
        /// How many keys this thread imported to sign with.
        static IMPORTS: Cell<usize> = const { Cell::new(0) };
        /// The imported key this thread last signed with.
        static SIGNED_WITH: RefCell<Weak<SigningKey>> = const { RefCell::new(Weak::new()) };
        /// How many RSA public keys this thread imported to verify with.
        static RSA_VERIFY_IMPORTS: Cell<usize> = const { Cell::new(0) };
        /// The imported RSA public key this thread last verified with.
        static VERIFIED_RSA_WITH: RefCell<Weak<RsaKey>> = const { RefCell::new(Weak::new()) };
    }

    pub(super) fn count_import() {
        IMPORTS.set(IMPORTS.get() + 1);
    }

    pub(super) fn signed_with(key: &Arc<SigningKey>) {
        SIGNED_WITH.set(Arc::downgrade(key));
    }

    /// The imported key this thread last signed with, unless it was freed.
    fn last_signed_with() -> Weak<SigningKey> {
        SIGNED_WITH.with_borrow(Weak::clone)
    }

    /// How many keys this thread imports to sign with while running `f`.
    fn count_imports(f: impl FnOnce()) -> usize {
        let before = IMPORTS.get();
        f();
        IMPORTS.get() - before
    }

    pub(super) fn count_rsa_verify_import() {
        RSA_VERIFY_IMPORTS.set(RSA_VERIFY_IMPORTS.get() + 1);
    }

    pub(super) fn verified_rsa_with(key: &Arc<RsaKey>) {
        VERIFIED_RSA_WITH.set(Arc::downgrade(key));
    }

    /// The imported RSA public key this thread last verified with, unless it was freed.
    fn last_verified_rsa_with() -> Weak<RsaKey> {
        VERIFIED_RSA_WITH.with_borrow(Weak::clone)
    }

    /// How many RSA public keys this thread imports to verify with while running `f`.
    fn count_rsa_verify_imports(f: impl FnOnce()) -> usize {
        let before = RSA_VERIFY_IMPORTS.get();
        f();
        RSA_VERIFY_IMPORTS.get() - before
    }

    const MESSAGE: &[u8] = b"message";

    /// Signs [`MESSAGE`] with key `slot` of `holder` through `cache`, and
    /// checks the signature.
    fn sign_checked<H: KeyHolder>(
        cache: &KeyCache<SigningKey>,
        holder: &Arc<H>,
        slot: usize,
        hash_alg: Option<HashAlg>,
    ) {
        let signature = sign_cached(cache, holder, slot, hash_alg, MESSAGE).unwrap();
        let public_key = holder.private_keys()[slot].public_key();
        verify(public_key.key_data(), MESSAGE, &signature).unwrap();
    }

    fn server_config(keys: Vec<PrivateKey>) -> Arc<crate::server::Config> {
        Arc::new(crate::server::Config {
            keys,
            ..Default::default()
        })
    }

    #[test]
    fn held_keys_are_imported_once() {
        let cache = KeyCache::new(KEY_CACHE_CAPACITY);
        let sha2 = [Some(HashAlg::Sha256), Some(HashAlg::Sha512)];
        let cases = [
            (ecdsa_p256(), &[None][..]),
            (ecdsa_p384(), &[None]),
            (ecdsa_p521(), &[None]),
            (rsa_2048(), &sha2),
            #[cfg(feature = "ssh-mldsa87-p384")]
            (
                crate::keys::generate_secret_key_for(&Algorithm::Mldsa87P384).unwrap(),
                &[None],
            ),
        ];
        for (key, hash_algs) in cases {
            let key = Arc::new(key);
            let imports = count_imports(|| {
                for _ in 0..3 {
                    for &hash_alg in hash_algs {
                        sign_checked(&cache, &key, 0, hash_alg);
                    }
                }
            });
            assert_eq!(imports, 1, "{}", key.algorithm());
        }
    }

    /// The host keys of a server configuration are imported once for all
    /// the sessions that share it.
    #[test]
    fn host_keys_are_imported_once_per_config() {
        let cache = KeyCache::new(KEY_CACHE_CAPACITY);
        let keys = vec![ecdsa_p256(), rsa_2048(), ecdsa_p521()];
        let configs = [server_config(keys.clone()), server_config(keys)];
        for config in &configs {
            let imports = count_imports(|| {
                for _ in 0..3 {
                    for (slot, hash_alg) in [(0, None), (1, Some(HashAlg::Sha512)), (2, None)] {
                        sign_checked(&cache, config, slot, hash_alg);
                    }
                }
            });
            assert_eq!(imports, 3);
        }
        assert_eq!(cache.len(), 6);
        assert_eq!(
            sign_cached(&cache, &configs[0], 3, None, MESSAGE).unwrap_err(),
            ssh_key::Error::Crypto
        );
    }

    /// A key is freed once it is evicted, or its holder dropped, and no
    /// signature uses it.
    #[test]
    fn evicted_and_released_keys_are_freed() {
        let cache = KeyCache::new(2);
        let import = |holder: &Arc<PrivateKey>| {
            cache
                .get_or_try_insert_with(holder, 0, || SigningKey::import(holder))
                .unwrap()
        };
        let a = Arc::new(ecdsa_p256());
        let b = Arc::new(ecdsa_p384());
        let c = Arc::new(rsa_1024());
        let imported_a = Arc::downgrade(&import(&a));
        let imported_b = Arc::downgrade(&import(&b));
        // After `a` is used again, `b` is the least recently used key, which
        // makes room for `c`.
        assert_eq!(count_imports(|| drop(import(&a))), 0);
        let imported_c = Arc::downgrade(&import(&c));
        assert!(imported_b.upgrade().is_none());
        assert!(imported_a.upgrade().is_some());
        assert!(imported_c.upgrade().is_some());

        // The key of a dropped holder is freed at the next lookup.
        drop(a);
        assert!(imported_a.upgrade().is_some());
        assert_eq!(cache.len(), 1);
        assert!(imported_a.upgrade().is_none());

        // A key in use is freed when no longer used.
        let in_use = import(&c);
        let imported_b = Arc::downgrade(&import(&b));
        let d = Arc::new(ecdsa_p521());
        let imported_d = Arc::downgrade(&import(&d));
        assert_eq!(cache.len(), 2);
        assert!(imported_c.upgrade().is_some());
        let signature = in_use.sign(RSA_SHA256, MESSAGE).unwrap();
        verify(c.public_key().key_data(), MESSAGE, &signature).unwrap();
        drop(in_use);
        assert!(imported_c.upgrade().is_none());

        // Importing `c` again evicts `b`; dropping the cache frees the rest.
        let before = IMPORTS.get();
        let imported_c = Arc::downgrade(&import(&c));
        assert_eq!(IMPORTS.get() - before, 1);
        assert!(imported_b.upgrade().is_none());
        assert!(imported_d.upgrade().is_some());
        drop(cache);
        assert!(imported_c.upgrade().is_none());
        assert!(imported_d.upgrade().is_none());
    }

    /// `keypair`'s public key with the private scalar `scalar`.
    fn ecdsa_forgery(keypair: &EcdsaKeypair, scalar: &[u8]) -> PrivateKey {
        let forgery = match keypair {
            EcdsaKeypair::NistP256 { public, .. } => EcdsaKeypair::NistP256 {
                public: *public,
                private: EcdsaPrivateKey::from(<[u8; 32]>::try_from(scalar).unwrap()),
            },
            EcdsaKeypair::NistP384 { public, .. } => EcdsaKeypair::NistP384 {
                public: *public,
                private: EcdsaPrivateKey::from(<[u8; 48]>::try_from(scalar).unwrap()),
            },
            EcdsaKeypair::NistP521 { public, .. } => EcdsaKeypair::NistP521 {
                public: *public,
                private: EcdsaPrivateKey::from(<[u8; 66]>::try_from(scalar).unwrap()),
            },
        };
        PrivateKey::new(KeypairData::Ecdsa(forgery), "").unwrap()
    }

    /// Keys, and keys with the same public key but the private part of
    /// another key or an invalid one, with the hash to sign with.
    fn forgeries() -> Vec<(PrivateKey, PrivateKey, Option<HashAlg>)> {
        let mut forgeries = Vec::new();
        let (rsa_1024, rsa_2048) = (rsa_1024(), rsa_2048());
        let (KeypairData::Rsa(other), KeypairData::Rsa(real)) =
            (rsa_1024.key_data(), rsa_2048.key_data())
        else {
            panic!("not RSA keys");
        };
        let junk = Mpint::from_positive_bytes(&[0xff; 128]);
        let one = Mpint::from_positive_bytes(&[1]);
        let junk = RsaPrivateKey::new(one.clone(), one, junk.clone(), junk).unwrap();
        for private in [other.private().clone(), junk] {
            let forgery = RsaKeypair::new(real.public().clone(), private).unwrap();
            let forgery = PrivateKey::new(KeypairData::Rsa(forgery), "").unwrap();
            forgeries.push((rsa_2048.clone(), forgery, Some(HashAlg::Sha512)));
        }
        for (real, rfc6979) in [ecdsa_p256(), ecdsa_p384(), ecdsa_p521()]
            .into_iter()
            .zip(&RFC6979)
        {
            let KeypairData::Ecdsa(keypair) = real.key_data() else {
                panic!("not an ECDSA key");
            };
            for scalar in [rfc6979.x.to_vec(), vec![0; rfc6979.x.len()]] {
                forgeries.push((real.clone(), ecdsa_forgery(keypair, &scalar), None));
            }
        }
        #[cfg(feature = "ssh-mldsa87-p384")]
        {
            let real = crate::keys::generate_secret_key_for(&Algorithm::Mldsa87P384).unwrap();
            let KeypairData::Mldsa87P384(kp) = real.key_data() else {
                panic!("not an Mldsa87P384 key");
            };
            let mut wrong_seed = *kp.mldsa_seed();
            wrong_seed[0] ^= 0x01;
            let forgery_seed = PrivateKey::new(
                KeypairData::Mldsa87P384(
                    Mldsa87P384Keypair::new(
                        kp.public().clone(),
                        wrong_seed,
                        kp.ecdsa_private().clone(),
                    )
                    .unwrap(),
                ),
                "",
            )
            .unwrap();
            let forgery_scalar = PrivateKey::new(
                KeypairData::Mldsa87P384(
                    Mldsa87P384Keypair::new(
                        kp.public().clone(),
                        *kp.mldsa_seed(),
                        EcdsaPrivateKey::from(<[u8; 48]>::try_from(RFC6979[1].x).unwrap()),
                    )
                    .unwrap(),
                ),
                "",
            )
            .unwrap();
            forgeries.push((real.clone(), forgery_seed, None));
            forgeries.push((real, forgery_scalar, None));
        }
        forgeries
    }

    #[cfg(feature = "ssh-mldsa87-p384")]
    #[test]
    fn mldsa87_p384_symcrypt_verify_rejects_malformed_blobs() {
        let key = crate::keys::generate_secret_key_for(&Algorithm::Mldsa87P384).unwrap();
        let sig = sign(&key, None, MESSAGE).unwrap();
        let KeyData::Mldsa87P384(pk) = key.public_key().key_data() else {
            panic!("not Mldsa87P384");
        };
        verify_mldsa87_p384(pk, MESSAGE, sig.as_bytes()).unwrap();
        let mut trailing = sig.as_bytes().to_vec();
        trailing.push(0x00);
        assert!(verify_mldsa87_p384(pk, MESSAGE, &trailing).is_err());
        for len in [0, 4626, 4627] {
            assert!(verify_mldsa87_p384(pk, MESSAGE, &sig.as_bytes()[..len]).is_err());
        }
    }

    /// A key with the public key of another but not its private key cannot
    /// sign with the other key, whether or not that one was imported: it is
    /// imported on its own, which fails. Neither can it in a new holder at
    /// the address of a dropped holder of the other key, as the cache keeps
    /// that address allocated.
    #[test]
    fn forged_keys_never_sign_with_cached_keys() {
        let cache = KeyCache::new(KEY_CACHE_CAPACITY);
        let by_value = ByValueCache::new(BY_VALUE_CACHE_CAPACITY);
        for (real, forgery, hash_alg) in forgeries() {
            assert_eq!(
                real.public_key().key_data(),
                forgery.public_key().key_data()
            );
            let config = server_config(vec![real.clone(), forgery.clone()]);
            let real = Arc::new(real);
            let cannot_sign = |forgery: &Arc<PrivateKey>| {
                for result in [
                    sign_cached(&cache, forgery, 0, hash_alg, MESSAGE),
                    sign_cached(&cache, &config, 1, hash_alg, MESSAGE),
                    sign_held(forgery, 0, hash_alg, MESSAGE),
                    sign_by_value(&by_value, forgery, hash_alg, MESSAGE),
                    sign(forgery, hash_alg, MESSAGE),
                ] {
                    assert_eq!(result.unwrap_err(), ssh_key::Error::Crypto);
                }
            };
            let forgery = Arc::new(forgery);
            cannot_sign(&forgery);
            assert_eq!(cache.len(), 0);
            sign_checked(&cache, &real, 0, hash_alg);
            sign_checked(&cache, &config, 0, hash_alg);
            sign_held(&real, 0, hash_alg, MESSAGE).unwrap();
            sign_by_value(&by_value, &real, hash_alg, MESSAGE).unwrap();
            sign(&real, hash_alg, MESSAGE).unwrap();
            cannot_sign(&forgery);
            assert_eq!(cache.len(), 2);

            let address = Arc::as_ptr(&real);
            drop(real);
            let forgery = Arc::new(PrivateKey::clone(&forgery));
            assert_ne!(Arc::as_ptr(&forgery), address);
            cannot_sign(&forgery);
            assert_eq!(cache.len(), 1);
        }
    }

    /// `Signatures::sign` and `certificate::sign` reuse the cached
    /// `SigningKey` when called repeatedly with the same `&PrivateKey`, and
    /// evict the least recently used entry when full.
    #[test]
    fn sign_and_certificate_sign_reuse_cached_keys() {
        let cache = ByValueCache::new(2);
        let a = ecdsa_p256();
        let b = rsa_2048();
        let c = ecdsa_p384();

        let imports = count_imports(|| {
            for _ in 0..3 {
                let sig = sign_by_value(&cache, &a, None, MESSAGE).unwrap();
                verify(a.public_key().key_data(), MESSAGE, &sig).unwrap();
            }
        });
        assert_eq!(imports, 1);
        let imported_a = last_signed_with();

        let imports = count_imports(|| {
            for hash in [HashAlg::Sha256, HashAlg::Sha512, HashAlg::Sha256] {
                let sig = sign_by_value(&cache, &b, Some(hash), MESSAGE).unwrap();
                verify(b.public_key().key_data(), MESSAGE, &sig).unwrap();
            }
        });
        assert_eq!(imports, 1);
        let imported_b = last_signed_with();

        // Touch `a`, making `b` the least recently used entry, then insert `c`.
        assert_eq!(
            count_imports(|| {
                sign_by_value(&cache, &a, None, MESSAGE).unwrap();
            }),
            0
        );
        assert!(Weak::ptr_eq(&last_signed_with(), &imported_a));
        assert_eq!(
            count_imports(|| {
                sign_by_value(&cache, &c, None, MESSAGE).unwrap();
            }),
            1
        );
        assert!(imported_b.upgrade().is_none());
        assert!(imported_a.upgrade().is_some());

        // `certificate::sign` calls `crate::crypto::sign(&ca, ...)`, which
        // signs via `ByValueCache` and reuses the imported CA key across
        // certificates. Use a dedicated `ByValueCache` to assert zero
        // re-imports deterministically when other unit tests run in parallel.
        let cert_cache = ByValueCache::new(BY_VALUE_CACHE_CAPACITY);
        let subject = ecdsa_p256();
        for (ca, hash) in [(rsa_2048(), Some(HashAlg::Sha512)), (ecdsa_p384(), None)] {
            let mut builder = ssh_key::certificate::Builder::new(
                [1u8; 32],
                subject.public_key().key_data().clone(),
                0,
                u64::MAX,
            )
            .unwrap();
            builder.serial(1).unwrap();
            builder.key_id("test").unwrap();
            builder
                .cert_type(ssh_key::certificate::CertType::User)
                .unwrap();
            builder.valid_principal("user").unwrap();
            let cert = crate::keys::certificate::sign(builder, &ca).unwrap();
            verify_certificate(&cert).unwrap();

            let sig = sign_by_value(&cert_cache, &ca, hash, MESSAGE).unwrap();
            verify(ca.public_key().key_data(), MESSAGE, &sig).unwrap();
            let first_key = last_signed_with();
            assert!(first_key.upgrade().is_some());

            let imports = count_imports(|| {
                for _ in 0..3 {
                    let sig = sign_by_value(&cert_cache, &ca, hash, MESSAGE).unwrap();
                    verify(ca.public_key().key_data(), MESSAGE, &sig).unwrap();
                    assert!(Weak::ptr_eq(&last_signed_with(), &first_key));
                }
            });
            assert_eq!(imports, 0);
        }
    }

    /// `Verifier::verify` reuses the cached `RsaKey` across `rsa-sha2-256`
    /// and `rsa-sha2-512` verifications with the same `(n, e)`, keeps
    /// distinct `(n, e)` entries separate, and evicts the least recently
    /// used entry at capacity.
    #[test]
    fn rsa_verify_reuses_cached_keys_and_evicts_lru() {
        let cache = RsaVerifyCache::new(RSA_VERIFY_CACHE_CAPACITY);
        let key_2048 = rsa_2048();
        let KeyData::Rsa(public_2048) = key_2048.public_key().key_data() else {
            panic!("not an RSA key");
        };
        let (n_2048, e_2048) = rsa_public_components(public_2048).unwrap();

        let imports = count_rsa_verify_imports(|| {
            verify_rsa_cached(
                &cache,
                public_2048,
                HashAlg::Sha256,
                b"sample",
                &RSA_2048_SHA256,
            )
            .unwrap();
        });
        assert_eq!(imports, 1);
        let first_key = last_verified_rsa_with();
        assert!(first_key.upgrade().is_some());

        let imports = count_rsa_verify_imports(|| {
            for (hash, sig) in [
                (HashAlg::Sha512, &RSA_2048_SHA512[..]),
                (HashAlg::Sha256, &RSA_2048_SHA256[..]),
                (HashAlg::Sha512, &RSA_2048_SHA512[..]),
            ] {
                verify_rsa_cached(&cache, public_2048, hash, b"sample", sig).unwrap();
                assert!(Weak::ptr_eq(&last_verified_rsa_with(), &first_key));
            }
        });
        assert_eq!(imports, 0);

        // Leading zero bytes in `n` or `e` are stripped before lookup, so they
        // match the existing cache entry without re-importing.
        let padded_n = [&[0, 0], n_2048].concat();
        let padded_e = [&[0], e_2048].concat();
        let imports = count_rsa_verify_imports(|| {
            let looked_up = cache.get_or_try_insert(&padded_n, &padded_e).unwrap();
            assert!(Arc::ptr_eq(&looked_up, &first_key.upgrade().unwrap()));
        });
        assert_eq!(imports, 0);

        // `Verifier::verify` populates and reuses `RSA_VERIFY_KEYS`.
        verify(
            key_2048.public_key().key_data(),
            b"sample",
            &Signature::new(RSA_SHA256, RSA_2048_SHA256).unwrap(),
        )
        .unwrap();
        let global_first = rsa_verify_key(n_2048, e_2048).unwrap();
        verify(
            key_2048.public_key().key_data(),
            b"sample",
            &Signature::new(RSA_SHA512, RSA_2048_SHA512).unwrap(),
        )
        .unwrap();
        let global_second = rsa_verify_key(n_2048, e_2048).unwrap();
        assert!(Arc::ptr_eq(&global_first, &global_second));

        // Distinct `(n, e)` pairs do not collide, and LRU eviction drops the
        // least recently used entry when full.
        let lru = RsaVerifyCache::new(2);
        let key_1024 = rsa_1024();
        let KeyData::Rsa(public_1024) = key_1024.public_key().key_data() else {
            panic!("not an RSA key");
        };
        let (n_1024, e_1024) = rsa_public_components(public_1024).unwrap();

        let imported_a = lru.get_or_try_insert(n_2048, e_2048).unwrap();
        let imported_b = lru.get_or_try_insert(n_1024, e_1024).unwrap();
        assert!(!Arc::ptr_eq(&imported_a, &imported_b));
        assert_eq!(lru.len(), 2);

        let weak_a = Arc::downgrade(&imported_a);
        let weak_b = Arc::downgrade(&imported_b);
        drop(imported_a);
        drop(imported_b);

        // Touch `a`, making `b` the least recently used entry, then insert `c`
        // (same modulus `n_2048` with a different public exponent `e = 3`).
        assert_eq!(
            count_rsa_verify_imports(|| {
                let touched = lru.get_or_try_insert(n_2048, e_2048).unwrap();
                assert!(Weak::ptr_eq(&Arc::downgrade(&touched), &weak_a));
            }),
            0
        );
        let imported_c = lru.get_or_try_insert(n_2048, &[3]).unwrap();
        let weak_c = Arc::downgrade(&imported_c);
        drop(imported_c);
        assert_eq!(lru.len(), 2);
        assert!(weak_b.upgrade().is_none());
        assert!(weak_a.upgrade().is_some());
        assert!(weak_c.upgrade().is_some());
        assert!(!Weak::ptr_eq(&weak_a, &weak_c));

        // Capacity bound (32 entries): inserting 36 distinct keys keeps the 32
        // most recently used and evicts the first 4.
        let bounded = RsaVerifyCache::new(RSA_VERIFY_CACHE_CAPACITY);
        let mut weaks = Vec::new();
        for i in 0..(RSA_VERIFY_CACHE_CAPACITY + 4) {
            let mut n = n_2048.to_vec();
            n[1] = i as u8;
            let key = bounded.get_or_try_insert(&n, e_2048).unwrap();
            weaks.push(Arc::downgrade(&key));
        }
        assert_eq!(bounded.len(), RSA_VERIFY_CACHE_CAPACITY);
        assert!(weaks[..4].iter().all(|w| w.upgrade().is_none()));
        assert!(weaks[4..].iter().all(|w| w.upgrade().is_some()));
    }

    /// Invalid RSA public keys fail `rsa_public_components` or
    /// `RsaKey::set_public_key` and are never inserted into `RsaVerifyCache`.
    #[test]
    fn invalid_rsa_public_keys_are_not_cached() {
        let cache = RsaVerifyCache::new(RSA_VERIFY_CACHE_CAPACITY);
        let key_2048 = rsa_2048();
        let KeyData::Rsa(public_2048) = key_2048.public_key().key_data() else {
            panic!("not an RSA key");
        };
        let (n_2048, e_2048) = rsa_public_components(public_2048).unwrap();

        let mut even_n = n_2048.to_vec();
        *even_n.last_mut().unwrap() &= !1;
        let small_odd_n = [0x81; 16];
        let mut n_1023_bits = [0xff; 128];
        n_1023_bits[0] = 0x7f;

        // Rejected before or during import in `get_or_try_insert`.
        for (bad_n, bad_e) in [
            (&[][..], e_2048),
            (&[0, 0][..], e_2048),
            (&even_n[..], e_2048),
            (&small_odd_n[..], e_2048),
            (&n_1023_bits[..], e_2048),
            (n_2048, &[][..]),
            (n_2048, &[0, 0][..]),
            (n_2048, &[1][..]),
            (n_2048, &[2][..]),
            (n_2048, &[1, 0, 0][..]),
            (n_2048, &[1; 9][..]),
        ] {
            assert!(
                cache.get_or_try_insert(bad_n, bad_e).is_err(),
                "n len {}, e len {}",
                bad_n.len(),
                bad_e.len()
            );
            assert_eq!(cache.len(), 0);
        }

        // Rejected by `rsa_public_components` in `verify_rsa_cached`.
        for (bad_n, bad_e) in [
            (&even_n[..], e_2048),
            (&small_odd_n[..], e_2048),
            (&n_1023_bits[..], e_2048),
            (n_2048, &[1][..]),
            (n_2048, &[1, 0, 0][..]),
        ] {
            let bad_key = RsaPublicKey::new(
                Mpint::from_positive_bytes(bad_e),
                Mpint::from_positive_bytes(bad_n),
            )
            .unwrap();
            assert!(
                verify_rsa_cached(
                    &cache,
                    &bad_key,
                    HashAlg::Sha256,
                    b"sample",
                    &RSA_2048_SHA256
                )
                .is_err()
            );
            assert_eq!(cache.len(), 0);
        }
    }

    #[test]
    fn keys_sign_from_several_threads() {
        const THREADS: usize = 8;
        let cache = KeyCache::new(KEY_CACHE_CAPACITY);
        let holders = [Arc::new(ecdsa_p256()), Arc::new(rsa_2048())];
        let sign_everywhere = || -> usize {
            std::thread::scope(|scope| {
                let threads: Vec<_> = (0..THREADS)
                    .map(|_| {
                        scope.spawn(|| {
                            count_imports(|| {
                                for _ in 0..8 {
                                    for holder in &holders {
                                        sign_checked(&cache, holder, 0, Some(HashAlg::Sha256));
                                    }
                                }
                            })
                        })
                    })
                    .collect();
                threads
                    .into_iter()
                    .map(|thread| thread.join().unwrap())
                    .sum()
            })
        };
        let imports = sign_everywhere();
        assert!(
            (holders.len()..=holders.len() * THREADS).contains(&imports),
            "{imports} imports"
        );
        assert_eq!(sign_everywhere(), 0);
        assert_eq!(cache.len(), holders.len());
    }

    #[test]
    fn sign_held_imports_once() {
        let key = Arc::new(ecdsa_p384());
        let imports = count_imports(|| {
            for _ in 0..3 {
                let signature = sign_held(&key, 0, None, MESSAGE).unwrap();
                verify(key.public_key().key_data(), MESSAGE, &signature).unwrap();
            }
        });
        assert_eq!(imports, 1);
    }

    /// Sessions that share a server configuration and a user key import
    /// each key once: the host key to sign the exchange hash, and the user
    /// key to sign the authentication request. A user key that only the
    /// session holds is freed once the session signed with it.
    #[tokio::test]
    async fn sessions_import_shared_keys_once() {
        struct Server;

        impl crate::server::Handler for Server {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &ssh_key::PublicKey,
            ) -> Result<crate::server::Auth, Self::Error> {
                Ok(crate::server::Auth::Accept)
            }
        }

        struct Client;

        impl crate::client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _: &crate::cert::PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        /// Authenticates with `key` in a new session with a server of
        /// `config`, and returns the client side.
        async fn authenticate(
            config: &Arc<crate::server::Config>,
            key: PrivateKeyWithHashAlg,
        ) -> crate::client::Handle<Client> {
            let (client_stream, server_stream) = tokio::io::duplex(1 << 16);
            tokio::spawn(crate::server::run_stream(
                Arc::clone(config),
                server_stream,
                Server,
            ));
            let client_config = Arc::new(crate::client::Config::default());
            let mut session = crate::client::connect_stream(client_config, client_stream, Client)
                .await
                .unwrap();
            let result = session.authenticate_publickey("user", key).await.unwrap();
            assert!(result.success());
            session
        }

        let config = server_config(vec![ecdsa_p256()]);
        let user_key = Arc::new(rsa_2048());
        let mut imports = Vec::new();
        for _ in 0..3 {
            let before = IMPORTS.get();
            let key = PrivateKeyWithHashAlg::new(Arc::clone(&user_key), Some(HashAlg::Sha256));
            let session = authenticate(&config, key).await;
            imports.push(IMPORTS.get() - before);
            assert!(last_signed_with().upgrade().is_some());
            session
                .disconnect(crate::Disconnect::ByApplication, "", "")
                .await
                .unwrap();
        }
        assert_eq!(imports, [2, 0, 0]);

        let key = PrivateKeyWithHashAlg::new(Arc::new(ecdsa_p384()), None);
        let session = authenticate(&config, key).await;
        assert!(last_signed_with().upgrade().is_none());
        session
            .disconnect(crate::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
    }

    /// The keys that the agent removes or replaces are freed at once.
    #[tokio::test]
    async fn keys_removed_from_the_agent_are_freed() {
        use crate::keys::agent::AgentIdentity;
        use crate::keys::agent::client::AgentClient;

        let (server, client) = tokio::io::duplex(1 << 16);
        let listener = futures::stream::iter([Ok(server)]);
        tokio::spawn(crate::keys::agent::server::serve(listener, ()));
        let mut client = AgentClient::connect(client);
        let keys = [ecdsa_p256(), ecdsa_p384(), rsa_2048()];
        let mut imported = Vec::new();
        for key in &keys {
            client.add_identity(key, &[]).await.unwrap();
            let identity = AgentIdentity::from(key.public_key().clone());
            client
                .sign_request(&identity, Some(HashAlg::Sha256), MESSAGE.to_vec())
                .await
                .unwrap();
            imported.push(last_signed_with());
        }
        assert!(imported.iter().all(|key| key.upgrade().is_some()));

        client.add_identity(&keys[0], &[]).await.unwrap();
        client.remove_identity(keys[1].public_key()).await.unwrap();
        assert!(imported[0].upgrade().is_none());
        assert!(imported[1].upgrade().is_none());
        assert!(imported[2].upgrade().is_some());

        client.remove_all_identities().await.unwrap();
        assert!(imported[2].upgrade().is_none());
    }
}
