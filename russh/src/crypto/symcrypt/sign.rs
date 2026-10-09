//! Signatures for the SymCrypt backend: ECDSA with `symcrypt::ecc` and RSA
//! PKCS#1 v1.5 with `symcrypt::rsa`, over digests from `symcrypt::hash`.
//!
//! | Algorithm | Digest | SymCrypt |
//! |---|---|---|
//! | `ecdsa-sha2-nistp256` | SHA-256 | `EcKey::ecdsa_sign`/`ecdsa_verify` on `NistP256` |
//! | `ecdsa-sha2-nistp384` | SHA-384 | `EcKey::ecdsa_sign`/`ecdsa_verify` on `NistP384` |
//! | `rsa-sha2-256` | SHA-256 | `RsaKey::pkcs1_sign`/`pkcs1_verify` |
//! | `rsa-sha2-512` | SHA-512 | `RsaKey::pkcs1_sign`/`pkcs1_verify` |
//!
//! These make and check every signature in russh: server host keys,
//! public-key user authentication (client and server side) and the CA
//! signature of OpenSSH certificates (`*-cert-v01@openssh.com`, through
//! `crate::crypto::verify_certificate`). `Signatures::is_supported` limits
//! negotiation to these four algorithms and their certificate forms.
//!
//! Keys are imported into SymCrypt from their raw components only (RSA `n`,
//! `e`, `p` and `q`; the ECDSA point and private scalar): `ssh-key`'s
//! RustCrypto signing and verification are never used, so RSA works without
//! the `rsa` feature.
//!
//! Not implemented, so neither offered nor accepted: `ssh-ed25519` (SymCrypt
//! has no EdDSA), `ecdsa-sha2-nistp521`, `ssh-rsa` (SHA-1), `ssh-dss` and
//! the security-key (`sk-*`) algorithms. Signing with such a key fails with
//! `ssh_key::Error::AlgorithmUnsupported`, after logging an error that names
//! this backend.

use std::ops::RangeInclusive;

use ::symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use ::symcrypt::errors::SymCryptError;
use ::symcrypt::hash::{HashAlgorithm, sha256, sha384, sha512};
use ::symcrypt::rsa::{RsaKey, RsaKeyUsage};
use hex_literal::hex;
use log::{debug, error};
use ssh_encoding::{Decode, Encode};
use ssh_key::private::{EcdsaKeypair, KeypairData, RsaKeypair};
use ssh_key::public::{EcdsaPublicKey, KeyData, RsaPublicKey};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, Mpint, PrivateKey, Signature};

use crate::crypto::{Signer, Verifier};

pub(crate) struct Signatures;

impl Verifier for Signatures {
    fn is_supported(algorithm: &Algorithm) -> bool {
        matches!(
            algorithm,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256 | EcdsaCurve::NistP384
            } | Algorithm::Rsa {
                hash: Some(HashAlg::Sha256 | HashAlg::Sha512)
            }
        )
    }

    fn verify(key: &KeyData, message: &[u8], signature: &Signature) -> signature::Result<()> {
        let algorithm = signature.algorithm();
        if !Self::is_supported(&algorithm) {
            debug!("the symcrypt backend does not verify {algorithm} signatures");
            return Err(ssh_key::Error::AlgorithmUnsupported { algorithm }.into());
        }
        match (key, algorithm) {
            (KeyData::Ecdsa(key), Algorithm::Ecdsa { curve }) if key.curve() == curve => {
                let curve = Curve::new(curve).ok_or_else(signature::Error::new)?;
                verify_ecdsa(curve, key, message, signature.as_bytes())
            }
            (KeyData::Rsa(key), Algorithm::Rsa { hash: Some(hash) }) => {
                verify_rsa(key, hash, message, signature.as_bytes())
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
        match key.key_data() {
            KeypairData::Ecdsa(keypair) => match Curve::new(keypair.curve()) {
                Some(curve) => sign_ecdsa(curve, keypair, message),
                None => Err(unsupported(keypair.algorithm())),
            },
            KeypairData::Rsa(keypair) => match hash_alg {
                Some(hash @ (HashAlg::Sha256 | HashAlg::Sha512)) => {
                    sign_rsa(keypair, hash, message)
                }
                _ => Err(unsupported(Algorithm::Rsa { hash: hash_alg })),
            },
            KeypairData::Encrypted(_) => Err(ssh_key::Error::Encrypted),
            _ => Err(unsupported(key.algorithm())),
        }
    }
}

/// Default host-key and public-key algorithm preference.
pub(crate) const DEFAULT_ORDER: &[Algorithm] = &[
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
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

/// An ECDSA curve this backend implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Curve {
    NistP256,
    NistP384,
}

impl Curve {
    fn new(curve: EcdsaCurve) -> Option<Self> {
        match curve {
            EcdsaCurve::NistP256 => Some(Curve::NistP256),
            EcdsaCurve::NistP384 => Some(Curve::NistP384),
            EcdsaCurve::NistP521 => None,
        }
    }

    fn symcrypt(self) -> CurveType {
        match self {
            Curve::NistP256 => CurveType::NistP256,
            Curve::NistP384 => CurveType::NistP384,
        }
    }

    /// The order `n` of the base point, big-endian.
    fn order(self) -> &'static [u8] {
        match self {
            Curve::NistP256 => &P256_ORDER,
            Curve::NistP384 => &P384_ORDER,
        }
    }

    /// The size in bytes of a coordinate, of the private scalar, and of `r`
    /// and `s`: on these curves, that of the order.
    fn size(self) -> usize {
        self.order().len()
    }

    /// The digest that is signed (RFC 5656, section 6.2.1).
    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Curve::NistP256 => sha256(message).to_vec(),
            Curve::NistP384 => sha384(message).to_vec(),
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

fn verify_ecdsa(
    curve: Curve,
    key: &EcdsaPublicKey,
    message: &[u8],
    blob: &[u8],
) -> signature::Result<()> {
    let point = curve
        .coordinates(key.as_sec1_bytes())
        .ok_or_else(signature::Error::new)?;
    let fixed = curve
        .fixed_signature(blob)
        .ok_or_else(signature::Error::new)?;
    let key = EcKey::set_public_key(curve.symcrypt(), point, EcKeyUsage::EcDsa).map_err(|error| {
        debug!("SymCrypt rejected an ECDSA public key: {error}");
        signature::Error::new()
    })?;
    key.ecdsa_verify(&fixed, &curve.digest(message))
        .map_err(|_| signature::Error::new())
}

fn sign_ecdsa(curve: Curve, keypair: &EcdsaKeypair, message: &[u8]) -> ssh_key::Result<Signature> {
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
    Signature::new(keypair.algorithm(), blob)
}

/// The RSA modulus sizes accepted, in bits: from OpenSSH's minimum
/// (`SSH_RSA_MINIMUM_MODULUS_SIZE`) to OpenSSL's maximum
/// (`OPENSSL_RSA_MAX_MODULUS_BITS`).
const RSA_MODULUS_BITS: RangeInclusive<usize> = 1024..=16384;

/// The modulus and public exponent of `key`, big-endian without leading
/// zeros as SymCrypt imports them, if the modulus is odd and of an accepted
/// size, and the exponent odd, at least 3 and at most 64 bits long.
fn rsa_public_components(key: &RsaPublicKey) -> ssh_key::Result<(&[u8], &[u8])> {
    let (Some(n), Some(e)) = (key.n().as_positive_bytes(), key.e().as_positive_bytes()) else {
        return Err(ssh_key::Error::PublicKey);
    };
    let bits = n.first().map_or(0, |top| {
        n.len()
            .saturating_mul(8)
            .saturating_sub(top.leading_zeros() as usize)
    });
    let odd = |value: &[u8]| value.last().is_some_and(|low| low & 1 == 1);
    if RSA_MODULUS_BITS.contains(&bits) && odd(n) && odd(e) && e != [1] && e.len() <= 8 {
        Ok((n, e))
    } else {
        debug!(
            "rejecting an RSA key of {bits} bits with a {}-byte public exponent",
            e.len()
        );
        Err(ssh_key::Error::PublicKey)
    }
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

fn verify_rsa(
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
    let key = RsaKey::set_public_key(n, e, RsaKeyUsage::Sign).map_err(|error| {
        debug!("SymCrypt rejected an RSA public key: {error}");
        signature::Error::new()
    })?;
    key.pkcs1_verify(&digest, &padded, hash)
        .map_err(|_| signature::Error::new())
}

fn sign_rsa(keypair: &RsaKeypair, hash: HashAlg, message: &[u8]) -> ssh_key::Result<Signature> {
    let (n, e) = rsa_public_components(keypair.public()).inspect_err(|_| {
        error!(
            "cannot sign with this RSA key: the symcrypt backend takes moduli of 1024 to \
             16384 bits and odd public exponents of 3 to 64 bits"
        )
    })?;
    let private = keypair.private();
    let (Some(p), Some(q)) = (private.p().as_positive_bytes(), private.q().as_positive_bytes())
    else {
        return Err(ssh_key::Error::Crypto);
    };
    let (digest, hash_algorithm) = rsa_digest(hash, message)?;
    // SymCrypt derives the private exponent and the CRT values from p and q.
    let key = RsaKey::set_key_pair(n, e, p, q, RsaKeyUsage::Sign)
        .map_err(|error| signing_error("import an RSA key", error))?;
    let blob = key
        .pkcs1_sign(&digest, hash_algorithm)
        .map_err(|error| signing_error("sign with an RSA key", error))?;
    Signature::new(Algorithm::Rsa { hash: Some(hash) }, blob)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use hex_literal::hex;
    use ssh_encoding::{Decode, Encode};
    use ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, KeypairData, RsaKeypair};
    use ssh_key::public::{EcdsaPublicKey, KeyData, RsaPublicKey};
    use ssh_key::{Algorithm, Certificate, EcdsaCurve, HashAlg, Mpint, PrivateKey, Signature};

    use super::{Curve, DEFAULT_ORDER, rsa_public_components};
    use crate::crypto::{is_supported_signature_algorithm, sign, verify, verify_certificate};

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

    /// RFC 6979, appendix A.2.5 (P-256 with SHA-256) and A.2.6 (P-384 with
    /// SHA-384).
    struct Rfc6979 {
        curve: EcdsaCurve,
        x: &'static [u8],
        ux: &'static [u8],
        uy: &'static [u8],
        /// `(message, r, s)` for the messages "sample" and "test".
        signatures: [(&'static [u8], &'static [u8], &'static [u8]); 2],
    }

    const RFC6979: [Rfc6979; 2] = [
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
                other => panic!("unexpected key {other:?}"),
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
    fn implements_exactly_ecdsa_p256_p384_and_rsa_sha2() {
        assert_eq!(DEFAULT_ORDER, [P256, P384, RSA_SHA512, RSA_SHA256]);
        assert_eq!(crate::Preferred::DEFAULT.key.as_ref(), DEFAULT_ORDER);
        for algorithm in DEFAULT_ORDER {
            assert!(is_supported_signature_algorithm(algorithm), "{algorithm}");
        }
        for algorithm in [
            Algorithm::Ed25519,
            P521,
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
            let order = Curve::new(vector.curve).unwrap().order();
            for (message, r, s) in vector.signatures {
                let signature = Signature::new(vector.algorithm(), ecdsa_blob(r, s)).unwrap();
                verify(&key, message, &signature).unwrap();
                assert!(verify(&key, b"tampered", &signature).is_err());
                let swapped = Signature::new(vector.algorithm(), ecdsa_blob(s, r)).unwrap();
                assert!(verify(&key, message, &swapped).is_err());
                // `(r, n - s)` is valid too, so this checks the order
                // constant `fixed_signature` compares with.
                let negated = ecdsa_blob(r, &sub(order, s));
                verify(&key, message, &Signature::new(vector.algorithm(), negated).unwrap())
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
            RFC6979[0].private_key(),
            RFC6979[1].private_key(),
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
    /// shorter mpints, which are padded back when verifying.
    #[test]
    fn ecdsa_short_r_and_s_round_trip() {
        let key = ecdsa_p256();
        let public = key.public_key().key_data();
        let (mut short_r, mut short_s) = (false, false);
        // Each of `r` and `s` is short with probability 1/256.
        for i in 0..4096u32 {
            let message = i.to_be_bytes();
            let signature = sign(&key, None, &message).unwrap();
            verify(public, &message, &signature).unwrap();
            let mut blob = signature.as_bytes();
            let r = Mpint::decode(&mut blob).unwrap();
            let s = Mpint::decode(&mut blob).unwrap();
            short_r |= r.as_positive_bytes().unwrap().len() < 32;
            short_s |= s.as_positive_bytes().unwrap().len() < 32;
            if short_r && short_s {
                return;
            }
        }
        panic!("no short r and s in 4096 signatures");
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
        assert!(curve
            .fixed_signature(&[mpint(&n_minus_one), mpint(&n_minus_one)].concat())
            .is_some());
        let mut n_plus_one = n.to_vec();
        n_plus_one[31] += 1;
        for (case, blob) in [
            ("empty", vec![]),
            ("no s", one.clone()),
            ("truncated s", [one.clone(), raw_mpint(&[1, 1])[..5].to_vec()].concat()),
            ("trailing data", [one.clone(), one.clone(), vec![0]].concat()),
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
        let (p256, p384, rsa) = (ecdsa_p256(), ecdsa_p384(), rsa_2048());
        let message = b"message";
        let p256_signature = sign(&p256, None, message).unwrap();
        let rsa_signature = sign(&rsa, Some(HashAlg::Sha256), message).unwrap();
        assert!(verify(p384.public_key().key_data(), message, &p256_signature).is_err());
        assert!(verify(rsa.public_key().key_data(), message, &p256_signature).is_err());
        assert!(verify(p256.public_key().key_data(), message, &rsa_signature).is_err());
        assert!(verify(&RFC6979[0].public_key(), message, &p256_signature).is_err());
        // The P-256 signature, labelled as P-384.
        let relabelled = Signature::new(P384, p256_signature.as_bytes()).unwrap();
        assert!(verify(p256.public_key().key_data(), message, &relabelled).is_err());
    }

    #[test]
    fn invalid_ecdsa_public_keys_are_rejected() {
        let vector = &RFC6979[0];
        let (message, r, s) = vector.signatures[0];
        let signature = Signature::new(P256, ecdsa_blob(r, s)).unwrap();
        let mut off_curve = vector.sec1();
        *off_curve.last_mut().unwrap() ^= 1;
        // The right point, compressed (its Y is odd).
        let compressed = [&[0x03], vector.ux].concat();
        for sec1 in [off_curve, compressed] {
            let key = KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&sec1).unwrap());
            assert!(verify(&key, message, &signature).is_err());
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
            verify(public, b"sample", &Signature::new(algorithm, expected).unwrap()).unwrap();
            // PKCS#1 v1.5 signatures are deterministic.
            let signature = sign(&key, Some(hash), b"sample").unwrap();
            assert_eq!(signature.as_bytes(), expected);
        }
        // A valid `ssh-rsa` (SHA-1) signature is refused...
        let error = verify(public, b"sample", &Signature::new(SSH_RSA, RSA_2048_SHA1).unwrap())
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
        verify(public, message, &Signature::new(RSA_SHA256, &full[1..]).unwrap()).unwrap();
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
    }

    #[test]
    fn unsupported_keys_cannot_sign() {
        for (key, hash_alg, algorithm) in [
            (key(fixture!("ed25519.key")), None, Algorithm::Ed25519),
            (key(fixture!("ecdsa_p521.key")), None, P521),
            (rsa_2048(), None, SSH_RSA),
        ] {
            assert_eq!(
                sign(&key, hash_alg, b"message").unwrap_err(),
                ssh_key::Error::AlgorithmUnsupported { algorithm }
            );
        }
    }

    /// User certificates for `ecdsa_p256.key`, signed by CA keys of each
    /// type with `ssh-keygen -s`.
    #[test]
    fn certificate_ca_signatures() {
        let subject = ecdsa_p256();
        for (openssh, ca_algorithm) in [
            (fixture!("cert_ca_ecdsa_p256.pub"), P256),
            (fixture!("cert_ca_ecdsa_p384.pub"), P384),
            (fixture!("cert_ca_rsa_sha2_256.pub"), RSA_SHA256),
            (fixture!("cert_ca_rsa_sha2_512.pub"), RSA_SHA512),
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
            (fixture!("cert_ca_ed25519.pub"), Algorithm::Ed25519),
            (fixture!("cert_ca_ecdsa_p521.pub"), P521),
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
}
