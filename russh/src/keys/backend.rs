//! What the crypto backend russh was built with can do with keys.

use ssh_key::{Algorithm, PrivateKey};

use super::Error;

/// Whether the crypto backend russh was built with can sign with
/// `algorithm`.
///
/// `algorithm` is a signature algorithm, so for RSA the hash matters:
/// `Algorithm::Rsa { hash: None }` is `ssh-rsa`, with SHA-1. That is also what
/// [`PrivateKey::algorithm`] returns for every RSA key, so ask with the
/// algorithm you'll sign with, such as
/// [`PrivateKeyWithHashAlg::algorithm`](super::PrivateKeyWithHashAlg::algorithm).
///
/// | Backend | Signs with |
/// |---|---|
/// | `aws-lc-rs`, `ring` | `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`; with the `rsa` feature, `rsa-sha2-512`, `rsa-sha2-256` and `ssh-rsa`; with the `dsa` feature, `ssh-dss` |
/// | `symcrypt` | `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `rsa-sha2-512`, `rsa-sha2-256`; with the `ed25519-aws-lc` feature, `ssh-ed25519` (from aws-lc-rs) |
///
/// No backend signs with security keys (`sk-*`): their private key stays on
/// the token.
///
/// russh checks keys with this before it uses them:
/// [`Handle::authenticate_publickey`](crate::client::Handle::authenticate_publickey)
/// fails with [`ssh_key::Error::AlgorithmUnsupported`] before it sends
/// anything, and a server fails to start with
/// [`Error::InvalidConfig`](crate::Error::InvalidConfig) if it can't sign with
/// any of its host keys.
///
/// # Example
///
/// ```
/// use russh::keys::{Algorithm, EcdsaCurve, supports_signing};
///
/// // Every backend signs with ECDSA on P-256, and none with security keys.
/// assert!(supports_signing(&Algorithm::Ecdsa {
///     curve: EcdsaCurve::NistP256
/// }));
/// assert!(!supports_signing(&Algorithm::SkEd25519));
/// ```
pub fn supports_signing(algorithm: &Algorithm) -> bool {
    crate::crypto::can_sign(algorithm)
}

/// Whether the crypto backend russh was built with can verify signatures
/// with `algorithm`: a server's host key signatures, a client's publickey
/// authentication, and the CA signatures of certificates.
///
/// That is every algorithm [`supports_signing`] accepts, and, with
/// `aws-lc-rs` and `ring`, the security-key algorithms
/// (`sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`).
/// As with [`supports_signing`], for RSA the hash matters.
pub fn supports_verifying(algorithm: &Algorithm) -> bool {
    crate::crypto::can_verify(algorithm)
}

/// Generates a private key of the default type of the crypto backend: the
/// first algorithm of [`Preferred::DEFAULT`](crate::Preferred::DEFAULT)'s
/// `key` list.
///
/// | Backend | Key |
/// |---|---|
/// | `aws-lc-rs`, `ring` | Ed25519, from `ssh-key` |
/// | `symcrypt` | ECDSA on NIST P-256, from SymCrypt |
///
/// Use it where any key type will do, such as a test server's host key.
/// `ssh_key::PrivateKey::random` works only with `aws-lc-rs` and `ring`, and
/// `symcrypt` can't sign with Ed25519 keys unless the `ed25519-aws-lc`
/// feature is enabled. The key has an empty comment.
///
/// # Example
///
/// A server with a new host key:
///
/// ```
/// # fn main() -> Result<(), russh::keys::Error> {
/// let config = russh::server::Config {
///     keys: vec![russh::keys::generate_secret_key()?],
///     ..Default::default()
/// };
/// # assert!(russh::keys::supports_signing(&config.keys[0].algorithm()));
/// # Ok(())
/// # }
/// ```
pub fn generate_secret_key() -> Result<PrivateKey, Error> {
    let algorithm = crate::crypto::provider::sign::DEFAULT_ORDER
        .first()
        .ok_or(ssh_key::Error::AlgorithmUnknown)?;
    generate_secret_key_for(algorithm)
}

/// Generates a private key for `algorithm`, if the crypto backend can sign
/// with keys of that type (see [`supports_signing`]).
///
/// For RSA, the hash of `algorithm` doesn't matter: the key is 4096 bits,
/// and can sign with every RSA algorithm the backend supports. With
/// `aws-lc-rs` and `ring`, keys come from `ssh_key::PrivateKey::random`;
/// with `symcrypt`, SymCrypt generates them (for Ed25519, with the
/// `ed25519-aws-lc` feature, SymCrypt makes the seed and aws-lc-rs computes
/// the public key). The key has an empty comment.
///
/// # Errors
///
/// [`Error::SshKey`] with [`ssh_key::Error::AlgorithmUnsupported`] if the
/// backend can't sign with keys of this type, for example Ed25519 with
/// `symcrypt` without `ed25519-aws-lc`.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), russh::keys::Error> {
/// use russh::keys::{Algorithm, EcdsaCurve, generate_secret_key_for};
///
/// let p384 = Algorithm::Ecdsa {
///     curve: EcdsaCurve::NistP384,
/// };
/// let key = generate_secret_key_for(&p384)?;
/// assert_eq!(key.algorithm(), p384);
/// # Ok(())
/// # }
/// ```
pub fn generate_secret_key_for(algorithm: &Algorithm) -> Result<PrivateKey, Error> {
    if !crate::crypto::can_sign_with_key_type(algorithm) {
        return Err(ssh_key::Error::AlgorithmUnsupported {
            algorithm: algorithm.clone(),
        }
        .into());
    }
    #[cfg(not(russh_backend = "symcrypt"))]
    return Ok(PrivateKey::random(
        &mut super::key::safe_rng(),
        algorithm.clone(),
    )?);
    #[cfg(russh_backend = "symcrypt")]
    return crate::crypto::symcrypt::keys::generate(algorithm);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use ssh_key::{EcdsaCurve, HashAlg, LineEnding};

    use super::*;
    use crate::Preferred;
    use crate::keys::key::ALL_KEY_TYPES;

    const CURVES: [EcdsaCurve; 3] = [
        EcdsaCurve::NistP256,
        EcdsaCurve::NistP384,
        EcdsaCurve::NistP521,
    ];

    /// Every algorithm a backend knows of, and one none does.
    fn candidates() -> Vec<Algorithm> {
        let mut candidates = vec![
            Algorithm::Dsa,
            Algorithm::Ed25519,
            Algorithm::SkEd25519,
            Algorithm::SkEcdsaSha2NistP256,
            Algorithm::new("unknown@example.com").unwrap(),
        ];
        candidates.extend(CURVES.map(|curve| Algorithm::Ecdsa { curve }));
        candidates.extend(
            [None, Some(HashAlg::Sha256), Some(HashAlg::Sha512)]
                .map(|hash| Algorithm::Rsa { hash }),
        );
        candidates.extend(ALL_KEY_TYPES.iter().cloned());
        candidates.extend(Preferred::DEFAULT.key.iter().cloned());
        candidates.sort();
        candidates.dedup();
        candidates
    }

    #[test]
    fn capabilities_match_the_algorithm_lists() {
        for algorithm in candidates() {
            // `ALL_KEY_TYPES` of `aws-lc-rs` and `ring` has DSA without the
            // `dsa` feature too.
            let verifies = ALL_KEY_TYPES.contains(&algorithm)
                && (algorithm != Algorithm::Dsa || cfg!(feature = "dsa"));
            let security_key = matches!(
                algorithm,
                Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256
            );
            assert_eq!(supports_verifying(&algorithm), verifies, "{algorithm}");
            assert_eq!(
                supports_signing(&algorithm),
                verifies && !security_key,
                "{algorithm}"
            );
        }
        for algorithm in Preferred::DEFAULT.key.iter() {
            // `aws-lc-rs` and `ring` prefer RSA without the `rsa` feature
            // too, and fail when they use it.
            let supported = !matches!(algorithm, Algorithm::Rsa { .. })
                || cfg!(any(feature = "rsa", russh_backend = "symcrypt"));
            assert_eq!(supports_signing(algorithm), supported, "{algorithm}");
            assert_eq!(supports_verifying(algorithm), supported, "{algorithm}");
        }
    }

    /// Signs and verifies with `key`, and decodes it from the OpenSSH format.
    fn round_trip(key: &PrivateKey, hash_alg: Option<HashAlg>) {
        let message = b"message";
        let signature = crate::crypto::sign(key, hash_alg, message).unwrap();
        let public = key.public_key().key_data();
        crate::crypto::verify(public, message, &signature).unwrap();
        assert!(crate::crypto::verify(public, b"other message", &signature).is_err());
        let openssh = key.to_openssh(LineEnding::LF).unwrap();
        assert_eq!(
            &super::super::decode_secret_key(&openssh, None).unwrap(),
            key
        );
    }

    #[test]
    fn generates_the_default_key_type() {
        let key = generate_secret_key().unwrap();
        let expected = if cfg!(russh_backend = "symcrypt") {
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            }
        } else {
            Algorithm::Ed25519
        };
        assert_eq!(key.algorithm(), expected);
        assert_eq!(Preferred::DEFAULT.key.first(), Some(&expected));
        round_trip(&key, None);
        assert_ne!(generate_secret_key().unwrap(), key);
    }

    #[test]
    fn generates_every_key_type_it_signs_with() {
        let mut algorithms = CURVES.map(|curve| Algorithm::Ecdsa { curve }).to_vec();
        if cfg!(russh_backend = "symcrypt") {
            // RSA from `ssh-key` takes too long in debug builds.
            algorithms.push(Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            });
        }
        if cfg!(any(not(russh_backend = "symcrypt"), russh_ed25519_aws_lc)) {
            algorithms.push(Algorithm::Ed25519);
        }
        for algorithm in algorithms {
            let key = generate_secret_key_for(&algorithm).unwrap();
            if let Algorithm::Rsa { .. } = algorithm {
                assert_eq!(key.algorithm(), Algorithm::Rsa { hash: None });
                round_trip(&key, Some(HashAlg::Sha512));
                round_trip(&key, Some(HashAlg::Sha256));
            } else {
                assert_eq!(key.algorithm(), algorithm);
                round_trip(&key, None);
            }
        }
    }

    #[test]
    fn does_not_generate_keys_it_cannot_sign_with() {
        for algorithm in candidates() {
            let signs = match algorithm {
                Algorithm::Rsa { .. } => [Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]
                    .into_iter()
                    .any(|hash| supports_signing(&Algorithm::Rsa { hash })),
                ref algorithm => supports_signing(algorithm),
            };
            if signs {
                continue;
            }
            match generate_secret_key_for(&algorithm) {
                Err(Error::SshKey(ssh_key::Error::AlgorithmUnsupported { algorithm: refused })) => {
                    assert_eq!(refused, algorithm)
                }
                other => panic!(
                    "{algorithm}: {:?}",
                    other.map(|key| key.algorithm().to_string())
                ),
            }
        }
    }
}
