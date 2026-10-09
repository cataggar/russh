//! Keys for the tests that need a host, user or CA key of any kind: the
//! integration-test counterpart of `test_keys` in `src/tests.rs`.
//!
//! With the RustCrypto-based backends they are random Ed25519 (and RSA)
//! keys. The SymCrypt backend can neither generate keys nor use Ed25519, so
//! it gets the committed ECDSA P-256 and RSA keys of `tests/data/test-keys`
//! (made with `ssh-keygen -N "" -C russh-test`). ssh-key signs and checks
//! certificates with RustCrypto only, so with SymCrypt, [`certify`] and
//! [`validate`] do that with SymCrypt itself.

use russh::keys::ssh_key::certificate::Builder;
use russh::keys::ssh_key::{self, Algorithm, Certificate, Fingerprint, PrivateKey};

/// The algorithm of the [`key`]s.
#[cfg(not(russh_backend = "symcrypt"))]
pub const ALGORITHM: Algorithm = Algorithm::Ed25519;
/// The algorithm of the [`key`]s.
#[cfg(russh_backend = "symcrypt")]
pub const ALGORITHM: Algorithm = Algorithm::Ecdsa {
    curve: russh::keys::EcdsaCurve::NistP256,
};

/// A private key of [`ALGORITHM`]. Keys with different `n` (0 to 3) differ;
/// with the RustCrypto-based backends, every key does.
#[cfg(not(russh_backend = "symcrypt"))]
pub fn key(_n: usize) -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), ALGORITHM).unwrap()
}

/// A private key of [`ALGORITHM`]. Keys with different `n` (0 to 3) differ;
/// with the RustCrypto-based backends, every key does.
#[cfg(russh_backend = "symcrypt")]
pub fn key(n: usize) -> PrivateKey {
    const KEYS: [&str; 4] = [
        include_str!("../data/test-keys/ecdsa-p256-0"),
        include_str!("../data/test-keys/ecdsa-p256-1"),
        include_str!("../data/test-keys/ecdsa-p256-2"),
        include_str!("../data/test-keys/ecdsa-p256-3"),
    ];
    russh::keys::decode_secret_key(KEYS[n], None).unwrap()
}

/// An RSA private key. Keys with different `n` (0 or 1) differ; with the
/// RustCrypto-based backends, every key does.
#[cfg(not(russh_backend = "symcrypt"))]
pub fn rsa_key(_n: usize) -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Rsa { hash: None }).unwrap()
}

/// An RSA private key. Keys with different `n` (0 or 1) differ; with the
/// RustCrypto-based backends, every key does.
#[cfg(russh_backend = "symcrypt")]
pub fn rsa_key(n: usize) -> PrivateKey {
    const KEYS: [&str; 2] = [
        include_str!("../data/test-keys/rsa-2048-0"),
        include_str!("../data/test-keys/rsa-2048-1"),
    ];
    russh::keys::decode_secret_key(KEYS[n], None).unwrap()
}

/// The certificate `builder` describes, signed by `ca` (with `rsa-sha2-512`
/// for an RSA `ca`).
#[cfg(not(russh_backend = "symcrypt"))]
pub fn certify(builder: Builder, ca: &PrivateKey) -> Certificate {
    builder.sign(ca).unwrap()
}

/// The certificate `builder` describes, signed by `ca` (with `rsa-sha2-512`
/// for an RSA `ca`).
///
/// ssh-key signs, and checks its signature in debug builds, with RustCrypto
/// only: this signs with SymCrypt instead, then assembles the certificate
/// from the signed data and the signature.
#[cfg(russh_backend = "symcrypt")]
pub fn certify(builder: Builder, ca: &PrivateKey) -> Certificate {
    use std::cell::RefCell;

    use russh::keys::signature;
    use russh::keys::ssh_encoding::Encode;
    use ssh_key::{Signature, public};

    struct SymCryptSigner<'a> {
        key: &'a PrivateKey,
        signed: RefCell<Option<(Vec<u8>, Signature)>>,
    }

    impl signature::Signer<Signature> for SymCryptSigner<'_> {
        fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
            let signature = backend::sign(self.key, message);
            *self.signed.borrow_mut() = Some((message.to_vec(), signature.clone()));
            Ok(signature)
        }
    }

    impl From<&SymCryptSigner<'_>> for public::KeyData {
        fn from(signer: &SymCryptSigner<'_>) -> Self {
            signer.key.public_key().key_data().clone()
        }
    }

    let signer = SymCryptSigner {
        key: ca,
        signed: RefCell::new(None),
    };
    // Fails in debug builds if ssh-key cannot verify the signature.
    let _ = builder.sign(&signer);
    let (mut encoded, signature) = signer.signed.into_inner().expect("incomplete certificate");
    signature.encode_prefixed(&mut encoded).unwrap();
    Certificate::from_bytes(&encoded).unwrap()
}

/// Like [`Certificate::validate`]: whether `cert` is valid now and signed by
/// the CA with fingerprint `ca`.
#[cfg(not(russh_backend = "symcrypt"))]
pub fn validate(cert: &Certificate, ca: &Fingerprint) -> ssh_key::Result<()> {
    cert.validate([ca])
}

/// Like [`Certificate::validate`]: whether `cert` is valid now and signed by
/// the CA with fingerprint `ca`. The CA signature is checked with SymCrypt.
#[cfg(russh_backend = "symcrypt")]
pub fn validate(cert: &Certificate, ca: &Fingerprint) -> ssh_key::Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    use russh::keys::ssh_encoding::Encode;

    let encoded = cert.to_bytes()?;
    // The signed data is everything but the trailing signature field.
    let signed = &encoded[..encoded.len() - cert.signature().encoded_len_prefixed()?];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if backend::verify(cert.signature_key(), signed, cert.signature())
        && cert.signature_key().fingerprint(ca.algorithm()) == *ca
        && cert.valid_after() <= now
        && now < cert.valid_before()
    {
        Ok(())
    } else {
        Err(ssh_key::Error::CertificateValidation)
    }
}

/// `ecdsa-sha2-nistp256` and `rsa-sha2-512` signing and verification with
/// SymCrypt, for [`certify`] and [`validate`].
#[cfg(russh_backend = "symcrypt")]
mod backend {
    use russh::keys::ssh_encoding::{Decode, Encode};
    use russh::keys::ssh_key::private::KeypairData;
    use russh::keys::ssh_key::public::KeyData;
    use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg, Mpint, PrivateKey, Signature};
    use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
    use symcrypt::hash::{HashAlgorithm, sha256, sha512};
    use symcrypt::rsa::{RsaKey, RsaKeyUsage};

    /// The size in bytes of a P-256 scalar and coordinate.
    const P256_SIZE: usize = 32;

    pub(super) fn sign(key: &PrivateKey, message: &[u8]) -> Signature {
        match key.key_data() {
            KeypairData::Ecdsa(keypair) if keypair.curve() == EcdsaCurve::NistP256 => {
                // SymCrypt takes the `X || Y` of the uncompressed SEC1 point.
                let point = &keypair.public_key_bytes()[1..];
                let key = EcKey::set_key_pair(
                    CurveType::NistP256,
                    keypair.private_key_bytes(),
                    Some(point),
                    EcKeyUsage::EcDsa,
                )
                .unwrap();
                let fixed = key.ecdsa_sign(&sha256(message)).unwrap();
                let (r, s) = fixed.split_at(P256_SIZE);
                let mut blob = Vec::new();
                Mpint::from_positive_bytes(r).encode(&mut blob).unwrap();
                Mpint::from_positive_bytes(s).encode(&mut blob).unwrap();
                Signature::new(keypair.algorithm(), blob).unwrap()
            }
            KeypairData::Rsa(keypair) => {
                let (public, private) = (keypair.public(), keypair.private());
                let key = RsaKey::set_key_pair(
                    positive(public.n()),
                    positive(public.e()),
                    positive(private.p()),
                    positive(private.q()),
                    RsaKeyUsage::Sign,
                )
                .unwrap();
                let blob = key
                    .pkcs1_sign(&sha512(message), HashAlgorithm::Sha512)
                    .unwrap();
                let algorithm = Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                };
                Signature::new(algorithm, blob).unwrap()
            }
            _ => panic!("no SymCrypt signing with a {} key here", key.algorithm()),
        }
    }

    pub(super) fn verify(key: &KeyData, message: &[u8], signature: &Signature) -> bool {
        match (key, signature.algorithm()) {
            (
                KeyData::Ecdsa(key),
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                },
            ) if key.curve() == EcdsaCurve::NistP256 => {
                // SymCrypt takes `r || s`, each of them `P256_SIZE` bytes.
                let mut blob = signature.as_bytes();
                let mut fixed = Vec::new();
                for _ in 0..2 {
                    let Some(value) = Mpint::decode(&mut blob)
                        .ok()
                        .and_then(|mpint| mpint.as_positive_bytes().map(<[u8]>::to_vec))
                        .filter(|value| value.len() <= P256_SIZE)
                    else {
                        return false;
                    };
                    fixed.resize(fixed.len() + P256_SIZE - value.len(), 0);
                    fixed.extend_from_slice(&value);
                }
                let point = &key.as_sec1_bytes()[1..];
                blob.is_empty()
                    && EcKey::set_public_key(CurveType::NistP256, point, EcKeyUsage::EcDsa)
                        .is_ok_and(|key| key.ecdsa_verify(&fixed, &sha256(message)).is_ok())
            }
            (KeyData::Rsa(key), Algorithm::Rsa { hash: Some(hash) }) => {
                let (digest, hash) = match hash {
                    HashAlg::Sha256 => (sha256(message).to_vec(), HashAlgorithm::Sha256),
                    HashAlg::Sha512 => (sha512(message).to_vec(), HashAlgorithm::Sha512),
                    _ => return false,
                };
                RsaKey::set_public_key(positive(key.n()), positive(key.e()), RsaKeyUsage::Sign)
                    .is_ok_and(|key| {
                        key.pkcs1_verify(&digest, signature.as_bytes(), hash)
                            .is_ok()
                    })
            }
            _ => false,
        }
    }

    /// The big-endian bytes of a positive `mpint`, without leading zeros.
    fn positive(mpint: &Mpint) -> &[u8] {
        mpint.as_positive_bytes().unwrap()
    }
}
