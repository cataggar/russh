//! Crypto backend abstraction: the one seam between the SSH protocol code
//! and the libraries that implement the primitives.
//!
//! # Design
//!
//! The protocol code (`cipher`, `mac`, `kex`, `negotiation`, `client`,
//! `server`, `keys`) never names a crypto library. It calls the small traits
//! of this module through [`provider`], the module of the selected backend:
//!
//! | Category | Trait(s) | Used for |
//! |---|---|---|
//! | `hash` | [`Hash`] | exchange hashes and key derivation |
//! | `kex` | [`KeyAgreement`], [`Kem`], [`FfDh`] | X25519, NIST P-256/384/521 ECDH, ML-KEM-768 (hybrid with X25519), finite-field DH groups |
//! | `sign` | [`Signer`], [`Verifier`] | host-key, certificate and user-auth signatures |
//! | `cipher` | [`Aead`], [`ChaCha20Poly1305`], [`BlockStream`] | AES-GCM, `chacha20-poly1305@openssh.com`, AES-CTR (and CBC/3DES) |
//! | `mac` | [`Mac`] | HMAC-SHA1/SHA2 (plain and encrypt-then-MAC) |
//! | `rng` | [`Rng`] | padding, KEXINIT cookies, ephemeral keys, `safe_rng()` |
//!
//! The SSH framing around each primitive (packet layout, sequence-number
//! nonces, padding, the exchange-hash layout, mpint encoding, error mapping)
//! is written once, generic over these traits, in `cipher/`, `mac/` and
//! `kex/`. A backend only implements raw primitives.
//!
//! # Backend selection
//!
//! `build.rs` turns the backend features into the `russh_backend` cfg. It is
//! the only place that resolves precedence: `aws-lc-rs` > `ring` >
//! `symcrypt`, so `symcrypt` is used only when it is the only backend
//! enabled, and default and `--all-features` builds use aws-lc-rs. Code that
//! depends on the backend checks `russh_backend = "aws_lc" | "ring" |
//! "symcrypt"`, never the features. Exactly one provider module is compiled
//! in and re-exported as [`provider`]:
//!
//! - `aws_lc` and `ring`: AES-GCM and chacha20-poly1305 from that library
//!   (shared code in `ring_aead`), every other category from `rustcrypto`.
//! - `rustcrypto`: pure-Rust implementations of every non-AEAD category. It
//!   is not a backend of its own, but the shared base the others re-export.
//! - `symcrypt`: Microsoft SymCrypt (see its module docs for the status of
//!   each category).
//!
//! # Provider contract
//!
//! A provider module has one submodule per category, each exporting:
//!
//! - `hash`: `Sha1`, `Sha256`, `Sha384`, `Sha512` implementing [`Hash`].
//! - `kex`: `X25519`, `NistP256`, `NistP384`, `NistP521` ([`KeyAgreement`]),
//!   `MlKem768` ([`Kem`]) and `Dh` ([`FfDh`]); a primitive the backend lacks
//!   is set to [`Unsupported`] and left out of `ALGORITHMS`.
//!   `ALGORITHMS: &[(&kex::Name, &(dyn KexType + Send + Sync))]` lists the
//!   implemented kex methods (the values are the shared `crate::kex::_*`
//!   constants), and `DEFAULT_ORDER: &[kex::Name]` the default preference
//!   order, without the `ext-info-*`/`kex-strict-*` pseudo-algorithms that
//!   negotiation appends.
//! - `sign`: a `Signatures` type implementing [`Signer`] and [`Verifier`],
//!   and `DEFAULT_ORDER: &[ssh_key::Algorithm]`.
//! - `cipher`: `ALGORITHMS: &[(&cipher::Name, &(dyn Cipher + Send + Sync))]`
//!   and `DEFAULT_ORDER: &[cipher::Name]`. Entries instantiate the generic
//!   SSH glue with the provider's primitives, e.g.
//!   `GcmCipher::<MyAes256Gcm>::new()` or
//!   `SshBlockCipher::<MyAes256Ctr>::new()`.
//! - `mac`: `ALGORITHMS: &[(&mac::Name, &(dyn MacAlgorithm + Send + Sync))]`
//!   (`CryptoMacAlgorithm::<MyHmacSha256>::new()` and
//!   `CryptoEtmMacAlgorithm::<MyHmacSha256>::new()`) and
//!   `DEFAULT_ORDER: &[mac::Name]`.
//! - `rng`: a `SystemRng` type implementing [`Rng`].
//!
//! The `ALGORITHMS` lists fill the registries (`kex::KEXES`,
//! `cipher::CIPHERS` and `mac::MACS`, which add the shared `none`/`clear`
//! entries), and the `DEFAULT_ORDER` lists make up `Preferred::DEFAULT` and
//! `Preferred::COMPRESSED`. Negotiation drops whatever the backend does not
//! implement from the preferences (`Preferred::supported`), so a backend
//! never advertises or accepts an algorithm it cannot run. The public
//! algorithm-name constants (`kex::*`, `cipher::*`, `mac::*`) exist for
//! every backend.
//!
//! # Swapping a category
//!
//! To move a backend's category to another implementation, edit only that
//! category's file of the provider (for SymCrypt,
//! `crypto/symcrypt/<category>.rs`): implement the trait(s) above for new
//! types, export them under the names of the contract, and update that
//! file's `ALGORITHMS`/`DEFAULT_ORDER`. The registries, negotiation,
//! `Preferred::DEFAULT` and all call sites follow. Put unit tests in the
//! same file; for SymCrypt they run with
//! `cargo test -p russh --no-default-features --features symcrypt --lib -- crypto::symcrypt`.

use std::convert::Infallible;

use ssh_encoding::Encode;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, Signature};
use zeroize::Zeroizing;

use crate::kex::dh::groups::DhGroup;

#[cfg(russh_backend = "aws_lc")]
pub(crate) mod aws_lc;
#[cfg(russh_backend = "aws_lc")]
pub(crate) use self::aws_lc as provider;

#[cfg(russh_backend = "ring")]
pub(crate) mod ring;
#[cfg(russh_backend = "ring")]
pub(crate) use self::ring as provider;

#[cfg(russh_backend = "symcrypt")]
pub(crate) mod symcrypt;
#[cfg(russh_backend = "symcrypt")]
pub(crate) use self::symcrypt as provider;

#[cfg(any(russh_backend = "aws_lc", russh_backend = "ring"))]
pub(crate) mod ring_aead;

// Parts of it go unused once a backend replaces a category.
#[cfg_attr(russh_backend = "symcrypt", allow(dead_code, unused_imports))]
pub(crate) mod rustcrypto;

/// Error from a crypto primitive. Deliberately opaque: the protocol code maps
/// it to the [`crate::Error`] that fits the context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CryptoError;

pub(crate) type Result<T> = std::result::Result<T, CryptoError>;

/// AEAD nonce length (AES-GCM, RFC 5647).
pub(crate) const AEAD_NONCE_LEN: usize = 12;
/// AEAD tag length (AES-GCM and chacha20-poly1305).
pub(crate) const AEAD_TAG_LEN: usize = 16;
/// Key length of `chacha20-poly1305@openssh.com` (two ChaCha20 keys).
pub(crate) const CHACHA20_POLY1305_KEY_LEN: usize = 64;

/// A hash function, used one-shot for exchange hashes and key derivation.
pub(crate) trait Hash {
    type Output: AsRef<[u8]>;
    fn digest(data: &[u8]) -> Self::Output;

    fn digest_to_vec(data: &[u8]) -> Vec<u8> {
        Self::digest(data).as_ref().to_vec()
    }
}

/// Ephemeral elliptic-curve Diffie-Hellman.
///
/// Public keys use the SSH wire format: 32 raw bytes for X25519 (RFC 8731),
/// uncompressed SEC1 points for the NIST curves (RFC 5656).
pub(crate) trait KeyAgreement {
    type PrivateKey: Send;
    /// Generate an ephemeral key pair, returning the private key and the
    /// encoded public key.
    fn generate() -> Result<(Self::PrivateKey, Vec<u8>)>;
    /// Compute the raw shared secret (the X25519 output, or the x-coordinate
    /// for the NIST curves). Fails if `peer_public_key` is malformed or not
    /// a valid point.
    fn agree(private_key: Self::PrivateKey, peer_public_key: &[u8])
    -> Result<Zeroizing<Vec<u8>>>;
}

/// Key encapsulation (ML-KEM-768, FIPS 203), with keys and ciphertexts in
/// their standard encodings.
pub(crate) trait Kem {
    type DecapsulationKey: Send;
    /// Returns the decapsulation key and the encoded encapsulation key.
    fn generate() -> Result<(Self::DecapsulationKey, Vec<u8>)>;
    /// Returns the ciphertext and the shared secret. Fails if
    /// `encapsulation_key` is malformed.
    fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)>;
    /// Fails if `ciphertext` is malformed.
    fn decapsulate(
        decapsulation_key: &Self::DecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;
}

/// Finite-field Diffie-Hellman over an SSH group (RFC 4253, RFC 4419,
/// RFC 8268). Integers are unsigned big-endian bytes.
pub(crate) trait FfDh: Sized + Send {
    /// Generate a key pair in `group` (the private exponent's lower bound
    /// differs between client and server), returning our public key. Fails
    /// if the public key is out of range.
    fn generate(group: &DhGroup, is_server: bool) -> Result<(Self, Vec<u8>)>;
    /// Compute the shared secret. Fails unless both the peer's public key and
    /// the result are in `(1, p - 1)`.
    fn agree(&self, peer_public_key: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

/// An AEAD with a 96-bit nonce and a 128-bit tag (AES-GCM, RFC 5647). The
/// SSH glue (`cipher::gcm`) manages the nonce counter and packet layout.
pub(crate) trait Aead: Sized + Send + 'static {
    const KEY_LEN: usize;
    fn new(key: &[u8]) -> Result<Self>;
    fn seal_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; AEAD_TAG_LEN],
    ) -> Result<()>;
    /// Verify and decrypt `ciphertext_and_tag` (the tag is its last
    /// [`AEAD_TAG_LEN`] bytes), leaving the plaintext in front of the tag.
    fn open_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<()>;
}

/// `chacha20-poly1305@openssh.com` (OpenSSH `PROTOCOL.chacha20poly1305`):
/// the packet length is encrypted with a separate key, and the tag covers
/// the whole packet. `packet` always starts with the 4-byte packet length.
pub(crate) trait ChaCha20Poly1305: Sized + Send + 'static {
    fn new(key: &[u8; CHACHA20_POLY1305_KEY_LEN]) -> Result<Self>;
    fn decrypt_packet_length(&self, sequence_number: u32, encrypted_length: [u8; 4]) -> [u8; 4];
    /// Verify the tag over `packet`, then decrypt `packet[4..]` in place.
    fn open_in_place(
        &self,
        sequence_number: u32,
        packet: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<()>;
    fn seal_in_place(
        &self,
        sequence_number: u32,
        packet: &mut [u8],
        tag: &mut [u8; AEAD_TAG_LEN],
    ) -> Result<()>;
}

/// A stateful cipher used with a separate MAC: AES-CTR (RFC 4344) and the
/// legacy CBC modes. Callers only pass whole blocks.
pub(crate) trait BlockStream: Sized + Send + 'static {
    const KEY_LEN: usize;
    const IV_LEN: usize;
    fn new(key: &[u8], iv: &[u8]) -> Result<Self>;
    fn encrypt(&mut self, data: &mut [u8]);
    fn decrypt(&mut self, data: &mut [u8]);
    /// Decrypt the first 16 bytes of the next packet without advancing the
    /// cipher state, to learn the packet length.
    fn peek_decrypt(&self, first_block: &mut [u8; 16]);
}

/// A keyed MAC (HMAC-SHA1/SHA2).
pub(crate) trait Mac: Sized + Send + 'static {
    const KEY_LEN: usize;
    const OUTPUT_LEN: usize;
    fn new(key: &[u8]) -> Result<Self>;
    /// MAC the concatenation of `data` into `output` (`OUTPUT_LEN` bytes).
    fn compute(&self, data: &[&[u8]], output: &mut [u8]);
}

/// Signature verification for host keys, certificates and user auth.
pub(crate) trait Verifier {
    /// Whether this backend can verify (and sign with) `algorithm`. Others
    /// are not offered during negotiation.
    fn is_supported(algorithm: &Algorithm) -> bool;
    fn verify(key: &KeyData, message: &[u8], signature: &Signature) -> signature::Result<()>;
}

/// Signing with a private key (server host keys, client auth, agent).
pub(crate) trait Signer {
    /// `hash_alg` selects the RSA hash (`None` is SHA-1, i.e. `ssh-rsa`);
    /// it is ignored for other keys.
    fn sign(
        key: &PrivateKey,
        hash_alg: Option<HashAlg>,
        message: &[u8],
    ) -> ssh_key::Result<Signature>;
}

/// A cryptographically secure random number generator.
pub(crate) trait Rng {
    fn fill_bytes(dest: &mut [u8]);
}

/// Placeholder a provider uses for a kex primitive it does not implement
/// (and leaves out of its `kex::ALGORITHMS`). It cannot be instantiated:
/// generating a key always fails.
#[allow(dead_code)]
pub(crate) enum Unsupported {}

impl KeyAgreement for Unsupported {
    type PrivateKey = Unsupported;

    fn generate() -> Result<(Self::PrivateKey, Vec<u8>)> {
        Err(CryptoError)
    }

    fn agree(private_key: Self::PrivateKey, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match private_key {}
    }
}

impl Kem for Unsupported {
    type DecapsulationKey = Unsupported;

    fn generate() -> Result<(Self::DecapsulationKey, Vec<u8>)> {
        Err(CryptoError)
    }

    fn encapsulate(_: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        Err(CryptoError)
    }

    fn decapsulate(
        decapsulation_key: &Self::DecapsulationKey,
        _: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        match *decapsulation_key {}
    }
}

impl FfDh for Unsupported {
    fn generate(_: &DhGroup, _: bool) -> Result<(Self, Vec<u8>)> {
        Err(CryptoError)
    }

    fn agree(&self, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match *self {}
    }
}

/// Fill `dest` with random bytes from the provider's RNG.
pub(crate) fn fill_random(dest: &mut [u8]) {
    <provider::rng::SystemRng as Rng>::fill_bytes(dest)
}

/// The provider's RNG as a [`rand_core`] RNG, for APIs that take one.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ProviderRng;

impl rand_core::TryRng for ProviderRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Infallible> {
        let mut bytes = [0; 4];
        fill_random(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Infallible> {
        let mut bytes = [0; 8];
        fill_random(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), Infallible> {
        fill_random(dest);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for ProviderRng {}

/// Whether the backend can verify and sign with `algorithm`.
pub(crate) fn is_supported_signature_algorithm(algorithm: &Algorithm) -> bool {
    <provider::sign::Signatures as Verifier>::is_supported(algorithm)
}

/// Verify `signature` over `message` with `key`.
pub(crate) fn verify(key: &KeyData, message: &[u8], signature: &Signature) -> signature::Result<()> {
    <provider::sign::Signatures as Verifier>::verify(key, message, signature)
}

/// Verify the CA signature of an OpenSSH certificate (not its validity
/// period, principals or CA trust).
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(crate) fn verify_certificate(certificate: &Certificate) -> signature::Result<()> {
    // The signed data is the certificate encoding up to, and including, the
    // signature key: everything but the trailing signature field.
    let encoded = certificate
        .encode_vec()
        .map_err(|_| signature::Error::new())?;
    let signature_len = certificate
        .signature()
        .encoded_len_prefixed()
        .map_err(|_| signature::Error::new())?;
    let signed = encoded
        .len()
        .checked_sub(signature_len)
        .and_then(|len| encoded.get(..len))
        .ok_or_else(signature::Error::new)?;
    verify(certificate.signature_key(), signed, certificate.signature())
}

/// Sign `message` with `key` (see [`Signer::sign`] for `hash_alg`).
pub(crate) fn sign(
    key: &PrivateKey,
    hash_alg: Option<HashAlg>,
    message: &[u8],
) -> ssh_key::Result<Signature> {
    <provider::sign::Signatures as Signer>::sign(key, hash_alg, message)
}

/// The body of the SSH mpint encoding (RFC 4251) of an unsigned big-endian
/// integer: no leading zero bytes, but a zero byte prepended when the high
/// bit is set. Zero gives a single zero byte, as russh always encoded it.
pub(crate) fn mpint_body(unsigned_be: &[u8]) -> Vec<u8> {
    let start = unsigned_be
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(unsigned_be.len());
    let digits = unsigned_be.get(start..).unwrap_or_default();
    let mut mpint = Vec::with_capacity(digits.len() + 1);
    match digits.first() {
        None => mpint.push(0),
        Some(&b) if b & 0x80 != 0 => mpint.push(0),
        Some(_) => {}
    }
    mpint.extend_from_slice(digits);
    mpint
}

/// Checks every provider's algorithm lists must pass.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashSet;

    use super::{provider, is_supported_signature_algorithm};
    use crate::{cipher, kex, mac};

    fn check<N: AsRef<str>>(category: &str, all: &[&N], algorithms: &[&N], default: &[N]) {
        let all: HashSet<&str> = all.iter().map(|n| n.as_ref()).collect();
        let implemented: HashSet<&str> = algorithms.iter().map(|n| n.as_ref()).collect();
        assert_eq!(
            implemented.len(),
            algorithms.len(),
            "duplicate {category} in ALGORITHMS"
        );
        assert!(!implemented.is_empty(), "no {category} implemented");
        assert!(
            implemented.is_subset(&all),
            "{category} ALGORITHMS has unknown names"
        );
        assert!(!default.is_empty(), "empty {category} DEFAULT_ORDER");
        for name in default {
            assert!(
                implemented.contains(name.as_ref()),
                "{category} {} is preferred but not implemented",
                name.as_ref()
            );
        }
        let unique: HashSet<&str> = default.iter().map(|n| n.as_ref()).collect();
        assert_eq!(unique.len(), default.len(), "duplicate in {category} DEFAULT_ORDER");
    }

    /// The selected provider's lists are consistent: no duplicates, only
    /// known names, and every default is implemented.
    pub(crate) fn check_provider_lists() {
        let kex: Vec<&kex::Name> = provider::kex::ALGORITHMS.iter().map(|(n, _)| *n).collect();
        check(
            "kex",
            kex::ALL_KEX_ALGORITHMS,
            &kex,
            provider::kex::DEFAULT_ORDER,
        );
        let ciphers: Vec<&cipher::Name> =
            provider::cipher::ALGORITHMS.iter().map(|(n, _)| *n).collect();
        check(
            "cipher",
            cipher::ALL_CIPHERS,
            &ciphers,
            provider::cipher::DEFAULT_ORDER,
        );
        let macs: Vec<&mac::Name> = provider::mac::ALGORITHMS.iter().map(|(n, _)| *n).collect();
        check(
            "mac",
            mac::ALL_MAC_ALGORITHMS,
            &macs,
            provider::mac::DEFAULT_ORDER,
        );
        assert!(!provider::sign::DEFAULT_ORDER.is_empty());
        for (i, algorithm) in provider::sign::DEFAULT_ORDER.iter().enumerate() {
            assert!(is_supported_signature_algorithm(algorithm));
            assert!(!provider::sign::DEFAULT_ORDER[..i].contains(algorithm));
        }
    }

    #[test]
    fn provider_lists_are_consistent() {
        check_provider_lists();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_body_matches_rfc4251() {
        assert_eq!(mpint_body(&[]), [0]);
        assert_eq!(mpint_body(&[0, 0]), [0]);
        assert_eq!(mpint_body(&[0, 0x12, 0x34]), [0x12, 0x34]);
        assert_eq!(mpint_body(&[0x80]), [0, 0x80]);
        assert_eq!(mpint_body(&[0, 0, 0xff, 1]), [0, 0xff, 1]);
    }

    /// `verify_certificate` accepts exactly what `ssh-key` accepts.
    // The symcrypt backend has no Ed25519; its certificate tests are in
    // symcrypt/sign.rs.
    #[test]
    #[cfg(not(russh_backend = "symcrypt"))]
    #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
    fn verify_certificate_matches_ssh_key() {
        use ssh_key::certificate::{Builder, CertType};

        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let subject = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mut builder =
            Builder::new_with_random_nonce(&mut rand::rng(), subject.public_key(), 0, u64::MAX)
                .unwrap();
        builder.key_id("test").unwrap();
        builder.cert_type(CertType::User).unwrap();
        builder.valid_principal("user").unwrap();
        let cert = builder.sign(&ca).unwrap();
        assert!(cert.verify_signature().is_ok());
        assert!(verify_certificate(&cert).is_ok());

        let encoded = cert.encode_vec().unwrap();
        // A byte of the nonce (after the type string and the nonce length),
        // and the last byte of the signature.
        let nonce = 4 + cert.algorithm().to_certificate_type().len() + 4;
        for offset in [nonce, encoded.len() - 1] {
            let mut tampered = encoded.clone();
            tampered[offset] ^= 1;
            let tampered = Certificate::from_bytes(&tampered).unwrap();
            assert!(tampered.verify_signature().is_err());
            assert!(verify_certificate(&tampered).is_err());
        }
    }

    #[test]
    fn provider_rng_fills_bytes() {
        use rand_core::Rng as _;

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        ProviderRng.fill_bytes(&mut a);
        fill_random(&mut b);
        assert_ne!(a, [0; 32]);
        assert_ne!(a, b);
    }
}
