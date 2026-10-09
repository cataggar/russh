//! Signatures through `ssh-key` (RustCrypto `ed25519-dalek`, `p256`/`p384`/
//! `p521`, `rsa`, and `dsa` with the `dsa` feature).

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, Signature};

use crate::crypto::{Signer, Verifier};

pub(crate) struct Signatures;

impl Verifier for Signatures {
    fn is_supported(_: &Algorithm) -> bool {
        // Whatever `ssh-key` was built with. Without the `rsa` feature, RSA
        // stays advertised: verification then fails at use, as before.
        true
    }

    fn verify(key: &KeyData, message: &[u8], signature: &Signature) -> signature::Result<()> {
        signature::Verifier::verify(key, message, signature)
    }
}

impl Signer for Signatures {
    fn sign(
        key: &PrivateKey,
        hash_alg: Option<HashAlg>,
        message: &[u8],
    ) -> ssh_key::Result<Signature> {
        match key.key_data() {
            #[cfg(feature = "rsa")]
            ssh_key::private::KeypairData::Rsa(rsa_keypair) => Ok(signature::Signer::try_sign(
                &(rsa_keypair, hash_alg),
                message,
            )?),
            // With the `rsa` feature off, `ssh-key` cannot honour the
            // negotiated hash and would fail with `Rsa { hash: None }` only
            // after the peer has accepted the key (USERAUTH_PK_OK): a
            // confusing error that points at the credential, not the build.
            // Fail here instead, naming the missing feature and the algorithm
            // that was actually negotiated.
            // See https://github.com/Eugeny/russh/issues/758.
            #[cfg(not(feature = "rsa"))]
            ssh_key::private::KeypairData::Rsa(_) => {
                log::error!(
                    "cannot sign with an RSA key: russh was built without the `rsa` \
                     feature (enable it, e.g. `features = [\"rsa\"]`)"
                );
                Err(ssh_key::Error::AlgorithmUnsupported {
                    algorithm: Algorithm::Rsa { hash: hash_alg },
                })
            }
            keypair => Ok(signature::Signer::try_sign(keypair, message)?),
        }
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
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
    Algorithm::Rsa { hash: None },
];
