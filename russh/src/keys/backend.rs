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
/// | `aws-lc-rs`, `ring` | `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`; with the `ssh-mldsa87-p384` feature (in `secure-algorithms`), `ssh-mldsa87-p384`; with the `rsa` feature, `rsa-sha2-512`, `rsa-sha2-256` and `ssh-rsa`; with the `dsa` feature, `ssh-dss` |
/// | `symcrypt` | `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `rsa-sha2-512`, `rsa-sha2-256`; with the `ssh-mldsa87-p384` feature (in `secure-algorithms`), `ssh-mldsa87-p384`; with the `ed25519-aws-lc` feature, `ssh-ed25519` (from aws-lc-rs) |
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

/// Generates a private key of the default type of the crypto backend:
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
    #[cfg(not(russh_backend = "symcrypt"))]
    const DEFAULT: Algorithm = Algorithm::Ed25519;
    #[cfg(russh_backend = "symcrypt")]
    const DEFAULT: Algorithm = Algorithm::Ecdsa {
        curve: ssh_key::EcdsaCurve::NistP256,
    };
    generate_secret_key_for(&DEFAULT)
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
            Algorithm::Mldsa87P384,
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
        if cfg!(feature = "ssh-mldsa87-p384") {
            assert_eq!(
                Preferred::DEFAULT.key.first(),
                Some(&Algorithm::Mldsa87P384)
            );
            assert_eq!(Preferred::DEFAULT.key.get(1), Some(&expected));
        } else {
            assert_eq!(Preferred::DEFAULT.key.first(), Some(&expected));
        }
        round_trip(&key, None);
        assert_ne!(generate_secret_key().unwrap(), key);
    }

    #[test]
    fn generates_every_key_type_it_signs_with() {
        let mut algorithms = CURVES.map(|curve| Algorithm::Ecdsa { curve }).to_vec();
        if cfg!(feature = "ssh-mldsa87-p384") {
            algorithms.push(Algorithm::Mldsa87P384);
        }
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
    fn crypto_backend_matches_cfg() {
        let (expected, expected_str) = if cfg!(russh_backend = "aws_lc") {
            (crate::CryptoBackend::AwsLcRs, "aws-lc-rs")
        } else if cfg!(russh_backend = "ring") {
            (crate::CryptoBackend::Ring, "ring")
        } else if cfg!(russh_backend = "symcrypt") {
            (crate::CryptoBackend::SymCrypt, "symcrypt")
        } else {
            panic!("unknown russh_backend cfg");
        };
        assert_eq!(crate::CRYPTO_BACKEND, expected);
        assert_eq!(crate::CRYPTO_BACKEND.as_str(), expected_str);
        assert_eq!(crate::CRYPTO_BACKEND.to_string(), expected_str);
        assert_eq!(crate::CryptoBackend::AwsLcRs.as_str(), "aws-lc-rs");
        assert_eq!(crate::CryptoBackend::Ring.as_str(), "ring");
        assert_eq!(crate::CryptoBackend::SymCrypt.as_str(), "symcrypt");
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

    #[cfg(feature = "ssh-mldsa87-p384")]
    #[tokio::test]
    async fn mldsa87_p384_end_to_end_and_negative_cases() {
        use std::path::Path;

        use ssh_encoding::{Decode, Encode};
        use ssh_key::Signature;
        use ssh_key::certificate::{Builder, CertType};
        use ssh_key::private::{KeypairData, Mldsa87P384Keypair};
        use ssh_key::public::Mldsa87P384PublicKey;

        use crate::keys::agent::AgentIdentity;
        use crate::keys::agent::client::AgentClient;
        use crate::keys::certificate;
        use crate::keys::decode_secret_key;
        use crate::keys::format::openssh::decode_agent_key;

        let key = generate_secret_key_for(&Algorithm::Mldsa87P384).unwrap();
        let other = generate_secret_key_for(&Algorithm::Mldsa87P384).unwrap();
        assert_eq!(key.algorithm(), Algorithm::Mldsa87P384);
        assert_eq!(key.public_key().algorithm(), Algorithm::Mldsa87P384);

        // 1. Sign and verify round-trip + negative tampered signature tests.
        let message = b"composite signature test message";
        let sig = crate::crypto::sign(&key, None, message).unwrap();
        assert_eq!(sig.algorithm(), Algorithm::Mldsa87P384);
        assert!(sig.as_bytes().len() > 4627);
        let pub_data = key.public_key().key_data();
        crate::crypto::verify(pub_data, message, &sig).unwrap();
        assert!(crate::crypto::verify(other.public_key().key_data(), message, &sig).is_err());

        // Corrupting a byte in the 4627-byte ML-DSA-87 signature fails even when P-384 is valid.
        for offset in [0, 2300, 4626] {
            let mut tampered = sig.as_bytes().to_vec();
            tampered[offset] ^= 0x01;
            let tampered = Signature::new(Algorithm::Mldsa87P384, tampered).unwrap();
            assert!(
                crate::crypto::verify(pub_data, message, &tampered).is_err(),
                "ML-DSA byte {offset}"
            );
        }

        // Corrupting a byte in the P-384 r or s fails even when ML-DSA-87 is valid.
        for offset in [4627 + 5, sig.as_bytes().len() - 1] {
            let mut tampered = sig.as_bytes().to_vec();
            tampered[offset] ^= 0x01;
            let tampered = Signature::new(Algorithm::Mldsa87P384, tampered).unwrap();
            assert!(
                crate::crypto::verify(pub_data, message, &tampered).is_err(),
                "ECDSA byte {offset}"
            );
        }

        // Trailing bytes after mpint s or truncated signatures are rejected.
        let mut trailing = sig.as_bytes().to_vec();
        trailing.push(0x00);
        assert!(Signature::new(Algorithm::Mldsa87P384, trailing).is_err());
        for len in [0, 4626, 4627] {
            assert!(
                Signature::new(Algorithm::Mldsa87P384, sig.as_bytes()[..len].to_vec()).is_err()
            );
        }

        // 2. OpenSSH public and private key round-trip.
        let pub_openssh = key.public_key().to_openssh().unwrap();
        assert!(pub_openssh.starts_with("ssh-mldsa87-p384 "));
        assert_eq!(
            &ssh_key::PublicKey::from_openssh(&pub_openssh).unwrap(),
            key.public_key()
        );
        let priv_openssh = key.to_openssh(LineEnding::LF).unwrap();
        assert_eq!(&decode_secret_key(&priv_openssh, None).unwrap(), &key);

        // 3. Mismatched public key in private key / agent key decoding fails.
        let (KeypairData::Mldsa87P384(kp), KeypairData::Mldsa87P384(other_kp)) =
            (key.key_data(), other.key_data())
        else {
            panic!("expected Mldsa87P384");
        };
        let valid_agent_blob = key.key_data().encode_vec().unwrap();
        let (_, decoded_kp) = decode_agent_key(&mut valid_agent_blob.as_slice()).unwrap();
        assert_eq!(&decoded_kp, key.key_data());

        // Helper to build an agent keypair blob with custom public key and private components.
        let make_agent_blob = |pub_key: &Mldsa87P384PublicKey, seed: &[u8; 32], scalar: &[u8]| {
            let mut comp_priv = Vec::new();
            comp_priv.extend_from_slice(seed);
            scalar.encode(&mut comp_priv).unwrap();
            let mut blob = Vec::new();
            "ssh-mldsa87-p384".encode(&mut blob).unwrap();
            pub_key.encode(&mut blob).unwrap();
            comp_priv.encode(&mut blob).unwrap();
            blob
        };

        let mut bad_mldsa = *kp.public().mldsa();
        bad_mldsa[0] ^= 0x01;
        let bad_mldsa_pub = Mldsa87P384PublicKey::new(bad_mldsa, *kp.public().ecdsa()).unwrap();
        let bad_ecdsa_pub =
            Mldsa87P384PublicKey::new(*kp.public().mldsa(), *other_kp.public().ecdsa()).unwrap();
        for bad_pub in [&bad_mldsa_pub, &bad_ecdsa_pub] {
            let bad_blob = make_agent_blob(bad_pub, kp.mldsa_seed(), kp.ecdsa_private().as_slice());
            assert!(decode_agent_key(&mut bad_blob.as_slice()).is_err());

            // Also test inside an unencrypted OpenSSH private key PEM.
            let valid_bytes = key.to_bytes().unwrap();
            let mut orig_pub_encoded = Vec::new();
            kp.public().encode(&mut orig_pub_encoded).unwrap();
            let mut bad_pub_encoded = Vec::new();
            bad_pub.encode(&mut bad_pub_encoded).unwrap();
            // Replace the second occurrence of `orig_pub_encoded` (in the private section).
            let pos = valid_bytes
                .windows(orig_pub_encoded.len())
                .rposition(|w| w == orig_pub_encoded.as_slice())
                .unwrap();
            let mut tampered_bytes = valid_bytes;
            tampered_bytes[pos..pos + bad_pub_encoded.len()].copy_from_slice(&bad_pub_encoded);
            let pem = format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
                data_encoding::BASE64.encode(&tampered_bytes)
            );
            assert!(decode_secret_key(&pem, None).is_err());
        }

        // 4. Short P-384 scalar (31 bytes) inside composite_private_key is padded and decoded.
        let p384_short_fixture = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/keys/ecdsa-p384-short"),
        )
        .unwrap();
        let p384_short = decode_secret_key(&p384_short_fixture, None).unwrap();
        let KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP384 {
            public: short_point,
            private: short_priv,
        }) = p384_short.key_data()
        else {
            panic!("expected NistP384");
        };
        let short_scalar = &short_priv.as_slice()[short_priv
            .as_slice()
            .iter()
            .take_while(|&&b| b == 0)
            .count()..];
        assert_eq!(short_scalar.len(), 31);
        let short_pub = Mldsa87P384PublicKey::new(*kp.public().mldsa(), *short_point).unwrap();
        let short_agent_blob = make_agent_blob(&short_pub, kp.mldsa_seed(), short_scalar);
        let (_, decoded_short_kp) = decode_agent_key(&mut short_agent_blob.as_slice()).unwrap();
        let short_private_key = PrivateKey::new(decoded_short_kp, "").unwrap();
        round_trip(&short_private_key, None);
        assert_eq!(
            Mldsa87P384Keypair::MLDSA_SEED_SIZE + Mldsa87P384Keypair::ECDSA_SCALAR_SIZE,
            80
        );

        // 5. Certificate sign/verify round-trip + Agent add_identity / add_certificate / sign round-trip.
        let mut builder =
            Builder::new([7u8; 32], key.public_key().key_data().clone(), 0, u64::MAX).unwrap();
        builder.serial(1).unwrap();
        builder.key_id("mldsa87-p384-cert").unwrap();
        builder.cert_type(CertType::User).unwrap();
        builder.valid_principal("alice").unwrap();
        let cert = certificate::sign(builder, &other).unwrap();
        assert_eq!(cert.algorithm(), Algorithm::Mldsa87P384);
        assert_eq!(cert.signature().algorithm(), Algorithm::Mldsa87P384);
        certificate::validate_at(&cert, 100, [other.public_key()]).unwrap();

        let (server, client) = tokio::io::duplex(1 << 16);
        let listener = futures::stream::iter([Ok(server)]);
        tokio::spawn(crate::keys::agent::server::serve(listener, ()));
        let mut agent = AgentClient::connect(client);

        agent.add_identity(&key, &[]).await.unwrap();
        let agent_sig = agent
            .sign_request_signature(key.public_key(), None, message)
            .await
            .unwrap();
        crate::crypto::verify(pub_data, message, &agent_sig).unwrap();

        agent.add_certificate(&cert, &key, &[]).await.unwrap();
        let cert_identity = AgentIdentity::from(cert);
        let cert_signed = agent
            .sign_request(&cert_identity, None, message.to_vec())
            .await
            .unwrap();
        let mut sig_slice = &cert_signed[message.len()..];
        let cert_sig_blob = Vec::<u8>::decode(&mut sig_slice).unwrap();
        let cert_agent_sig = Signature::decode(&mut cert_sig_blob.as_slice()).unwrap();
        crate::crypto::verify(pub_data, message, &cert_agent_sig).unwrap();
    }
}
