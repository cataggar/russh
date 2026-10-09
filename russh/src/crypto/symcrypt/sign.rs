//! Signatures for the SymCrypt backend.

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, Signature};

use crate::crypto::rustcrypto::sign as rustcrypto;
use crate::crypto::{Signer, Verifier};

// TODO(#3): implement ECDSA and RSA PKCS#1 v1.5 signing and verification with
// SymCrypt (`symcrypt::ecc`, `symcrypt::rsa`), decide what to do with
// Ed25519, and define `is_supported` and `DEFAULT_ORDER` from that, instead
// of delegating to the rustcrypto implementation.

/// Delegates to `ssh-key`, which does RSA only with the `rsa` feature.
pub(crate) struct Signatures;

impl Verifier for Signatures {
    fn is_supported(algorithm: &Algorithm) -> bool {
        cfg!(feature = "rsa") || !matches!(algorithm, Algorithm::Rsa { .. })
    }

    fn verify(key: &KeyData, message: &[u8], signature: &Signature) -> signature::Result<()> {
        rustcrypto::Signatures::verify(key, message, signature)
    }
}

impl Signer for Signatures {
    fn sign(
        key: &PrivateKey,
        hash_alg: Option<HashAlg>,
        message: &[u8],
    ) -> ssh_key::Result<Signature> {
        rustcrypto::Signatures::sign(key, hash_alg, message)
    }
}

/// Default host-key and public-key algorithm preference.
pub(crate) const DEFAULT_ORDER: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    #[cfg(feature = "rsa")]
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    #[cfg(feature = "rsa")]
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
    #[cfg(feature = "rsa")]
    Algorithm::Rsa { hash: None },
];

#[cfg(test)]
mod tests {
    use ssh_key::{Algorithm, EcdsaCurve, HashAlg};

    use crate::crypto::is_supported_signature_algorithm;

    // TODO(#3): replace with the signature algorithms this backend implements.
    #[test]
    fn offers_ed25519_ecdsa_and_rsa_with_the_rsa_feature() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        ] {
            assert!(super::DEFAULT_ORDER.contains(&algorithm));
            assert!(is_supported_signature_algorithm(&algorithm));
        }
        let rsa = Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        };
        assert_eq!(super::DEFAULT_ORDER.contains(&rsa), cfg!(feature = "rsa"));
        assert_eq!(is_supported_signature_algorithm(&rsa), cfg!(feature = "rsa"));
    }
}
