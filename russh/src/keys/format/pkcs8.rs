use std::convert::TryInto;

#[cfg(not(russh_backend = "symcrypt"))]
use p256::NistP256;
#[cfg(not(russh_backend = "symcrypt"))]
use p384::NistP384;
#[cfg(not(russh_backend = "symcrypt"))]
use p521::NistP521;
use pkcs8::PrivateKeyInfoRef;
#[cfg(not(russh_backend = "symcrypt"))]
use pkcs8::{AssociatedOid, EncodePrivateKey, SecretDocument};
use spki::ObjectIdentifier;
use ssh_key::PrivateKey;
#[cfg(not(russh_backend = "symcrypt"))]
use ssh_key::private::Ed25519PrivateKey;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData};

use crate::keys::Error;
#[cfg(not(russh_backend = "symcrypt"))]
use crate::keys::key::safe_rng;

const NIST_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const NIST_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const NIST_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
#[cfg(russh_backend = "symcrypt")]
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Decode a PKCS#8-encoded private key (ASN.1 or X9.62)
#[cfg(not(russh_backend = "symcrypt"))]
pub fn decode_pkcs8(
    ciphertext: &[u8],
    password: Option<&[u8]>,
) -> Result<ssh_key::PrivateKey, Error> {
    let doc = SecretDocument::try_from(ciphertext)?;
    let doc = if let Some(password) = password {
        doc.decode_msg::<pkcs8::EncryptedPrivateKeyInfoRef<'_>>()?
            .decrypt(password)?
    } else {
        doc
    };

    if let Ok(key) = doc.decode_msg::<sec1::EcPrivateKey>() {
        // X9.62 EC private key
        let Some(curve) = key.parameters.and_then(|x| x.named_curve()) else {
            return Err(Error::CouldNotReadKey);
        };
        let kp = ec_key_data_into_keypair(curve, key)?;
        return Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?);
    }

    // SEC1 key with full domain parameters (not a named curve OID)
    if let Ok(kp) = explicit_curve_params::decode_sec1_with_full_domain_params(ciphertext) {
        return Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?);
    }

    // ASN.1 key (PKCS#8)
    Ok(pkcs8_pki_into_keypair_data(doc.decode_msg::<PrivateKeyInfoRef<'_>>()?)?.try_into()?)
}

/// Decode a PKCS#8-encoded private key (ASN.1 or X9.62)
///
/// The symcrypt backend does not decrypt keys: an encrypted key
/// (`EncryptedPrivateKeyInfo`) fails with [`Error::UnsupportedKeyType`], and
/// `password` is ignored.
#[cfg(russh_backend = "symcrypt")]
pub fn decode_pkcs8(
    ciphertext: &[u8],
    _password: Option<&[u8]>,
) -> Result<ssh_key::PrivateKey, Error> {
    use der::Decode;

    if is_encrypted_private_key_info(ciphertext) {
        return Err(super::encrypted("PKCS#8"));
    }

    if let Ok(key) = sec1::EcPrivateKey::from_der(ciphertext) {
        // X9.62 EC private key
        let Some(curve) = key.parameters.and_then(|x| x.named_curve()) else {
            return Err(Error::CouldNotReadKey);
        };
        let kp = sec1_into_keypair(ecdsa_curve(curve)?, &key)?;
        return Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?);
    }

    // SEC1 key with full domain parameters (not a named curve OID)
    if let Ok(kp) = explicit_curve_params::decode_sec1_with_full_domain_params(ciphertext) {
        return Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?);
    }

    // ASN.1 key (PKCS#8)
    let pki = PrivateKeyInfoRef::from_der(ciphertext)?;
    let key_data = match pki.algorithm.oid {
        pkcs1::ALGORITHM_OID => {
            KeypairData::Rsa(super::decode_rsa_pkcs1_der(pki.private_key.as_bytes())?)
        }
        ED25519 => KeypairData::Ed25519(ed25519_into_keypair(&pki)?),
        sec1::ALGORITHM_OID => {
            let curve = ecdsa_curve(pki.algorithm.parameters_oid()?)?;
            let key = sec1::EcPrivateKey::from_der(pki.private_key.as_bytes())?;
            KeypairData::Ecdsa(sec1_into_keypair(curve, &key)?)
        }
        oid => return Err(Error::UnknownAlgorithm(oid)),
    };
    Ok(key_data.try_into()?)
}

/// Whether `der` is an `EncryptedPrivateKeyInfo` (RFC 5208): the encryption
/// algorithm and the encrypted key.
#[cfg(russh_backend = "symcrypt")]
fn is_encrypted_private_key_info(der: &[u8]) -> bool {
    use der::asn1::OctetStringRef;
    use der::{Decode, Reader, SliceReader};
    use spki::AlgorithmIdentifierRef;

    let Ok(mut reader) = SliceReader::new(der) else {
        return false;
    };
    reader
        .sequence(|seq| {
            AlgorithmIdentifierRef::decode(seq)?;
            <&OctetStringRef>::decode(seq)?;
            Ok::<_, der::Error>(())
        })
        .and_then(|()| reader.finish())
        .is_ok()
}

#[cfg(russh_backend = "symcrypt")]
fn ecdsa_curve(oid: ObjectIdentifier) -> Result<ssh_key::EcdsaCurve, Error> {
    use ssh_key::EcdsaCurve;

    match oid {
        NIST_P256 => Ok(EcdsaCurve::NistP256),
        NIST_P384 => Ok(EcdsaCurve::NistP384),
        NIST_P521 => Ok(EcdsaCurve::NistP521),
        oid => Err(Error::UnknownAlgorithm(oid)),
    }
}

/// Like the other backends: the curve of `key`, if any, must be `curve`, and
/// the public key, if any, must be the one of the private key.
#[cfg(russh_backend = "symcrypt")]
fn sec1_into_keypair(
    curve: ssh_key::EcdsaCurve,
    key: &sec1::EcPrivateKey<'_>,
) -> Result<EcdsaKeypair, Error> {
    if let Some(oid) = key.parameters.and_then(|x| x.named_curve())
        && ecdsa_curve(oid).ok() != Some(curve)
    {
        return Err(der::Error::from(der::Tag::ObjectIdentifier.value_error()).into());
    }
    crate::crypto::symcrypt::keys::ecdsa_keypair(curve, key.private_key, key.public_key)
}

/// An RFC 8410 Ed25519 key. Unlike the other backends, the symcrypt backend
/// needs the public key (PKCS#8 v2): computing it from the seed needs
/// Ed25519 arithmetic, which SymCrypt does not expose.
#[cfg(russh_backend = "symcrypt")]
fn ed25519_into_keypair(pki: &PrivateKeyInfoRef<'_>) -> Result<Ed25519Keypair, Error> {
    use pkcs8::KeyError;
    use zeroize::Zeroizing;

    if pki.algorithm.parameters.is_some() {
        return Err(pkcs8::Error::ParametersMalformed.into());
    }
    // An OCTET STRING of 32 bytes in the OCTET STRING.
    let seed: &[u8; 32] = match pki.private_key.as_bytes() {
        [0x04, 0x20, rest @ ..] => rest.try_into().map_err(|_| KeyError::Invalid),
        _ => Err(KeyError::Invalid),
    }
    .map_err(pkcs8::Error::from)?;
    let Some(public) = pki.public_key.and_then(|x| x.as_bytes()) else {
        return Err(super::unsupported(
            "Ed25519 PKCS#8 private key without its public key: the symcrypt crypto \
             backend cannot compute it (convert the key with `ssh-keygen -p`, or to PKCS#8 v2)",
        ));
    };
    let public: &[u8; 32] = public
        .try_into()
        .map_err(|_| pkcs8::Error::from(KeyError::Invalid))?;
    let mut bytes = Zeroizing::new([0; Ed25519Keypair::BYTE_SIZE]);
    let (private_bytes, public_bytes) = bytes.split_at_mut(seed.len());
    private_bytes.copy_from_slice(seed);
    public_bytes.copy_from_slice(public);
    // Checks the public key while ssh-key's `ed25519` feature is enabled.
    Ed25519Keypair::from_bytes(&bytes).map_err(|_| Error::KeyIsCorrupt)
}

#[cfg(not(russh_backend = "symcrypt"))]
fn pkcs8_pki_into_keypair_data(pki: PrivateKeyInfoRef<'_>) -> Result<KeypairData, Error> {
    // Temporary if {} due to multiple const_oid crate versions
    #[cfg(feature = "rsa")]
    if pki.algorithm.oid.as_bytes() == pkcs1::ALGORITHM_OID.as_bytes() {
        let sk = &pkcs1::RsaPrivateKey::try_from(pki.private_key)?;
        let pk = rsa::RsaPrivateKey::from_components(
            rsa::BoxedUint::from_be_slice_vartime(sk.modulus.as_bytes()),
            rsa::BoxedUint::from_be_slice_vartime(sk.public_exponent.as_bytes()),
            rsa::BoxedUint::from_be_slice_vartime(sk.private_exponent.as_bytes()),
            vec![
                rsa::BoxedUint::from_be_slice_vartime(sk.prime1.as_bytes()),
                rsa::BoxedUint::from_be_slice_vartime(sk.prime2.as_bytes()),
            ],
        )?;
        return Ok(KeypairData::Rsa(pk.try_into()?));
    }
    match pki.algorithm.oid {
        ed25519_dalek::pkcs8::ALGORITHM_OID => {
            let kpb = ed25519_dalek::pkcs8::KeypairBytes::try_from(pki)?;
            let pk = Ed25519PrivateKey::from_bytes(&kpb.secret_key);
            Ok(KeypairData::Ed25519(Ed25519Keypair {
                public: pk.clone().into(),
                private: pk,
            }))
        }
        sec1::ALGORITHM_OID => Ok(KeypairData::Ecdsa(ec_key_data_into_keypair(
            pki.algorithm.parameters_oid()?,
            pki,
        )?)),
        oid => Err(Error::UnknownAlgorithm(oid)),
    }
}

#[cfg(not(russh_backend = "symcrypt"))]
fn ec_key_data_into_keypair<K, E>(
    curve_oid: ObjectIdentifier,
    private_key: K,
) -> Result<EcdsaKeypair, Error>
where
    p256::SecretKey: TryFrom<K, Error = E>,
    p384::SecretKey: TryFrom<K, Error = E>,
    p521::SecretKey: TryFrom<K, Error = E>,
    crate::keys::Error: From<E>,
{
    Ok(match curve_oid {
        NistP256::OID => {
            let sk = p256::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP256 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        NistP384::OID => {
            let sk = p384::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP384 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        NistP521::OID => {
            let sk = p521::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP521 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        oid => return Err(Error::UnknownAlgorithm(oid)),
    })
}

mod explicit_curve_params {
    use super::*;

    use der::{
        Reader, SliceReader, Tag, TagNumber, Tagged,
        asn1::{AnyRef, ContextSpecific, UintRef},
    };

    /// Try to parse an SEC1 EC key with full domain parameters.
    ///
    /// Some key generators (e.g. OpenSSL with certain options) produce SEC1 keys
    /// where the `[0]` parameters field contains full EC domain parameters instead
    /// of a named curve OID. The `sec1` crate does not support this format.
    pub fn decode_sec1_with_full_domain_params(der_bytes: &[u8]) -> Result<EcdsaKeypair, Error> {
        let mut reader = SliceReader::new(der_bytes)?;
        reader.sequence(|seq| {
            let version: u8 = seq.decode()?;
            if version < 1 {
                return Err(Error::CouldNotReadKey);
            }

            let priv_key: AnyRef = seq.decode()?;
            priv_key.tag().assert_eq(Tag::OctetString)?;

            let params = ContextSpecific::<AnyRef>::decode_explicit(seq, TagNumber(0))?
                .ok_or(Error::CouldNotReadKey)?;

            let curve_oid = extract_curve_from_domain_params(params.value)?;

            let keypair = build_ec_keypair_from_bytes(curve_oid, priv_key.value())?;

            // Drain any remaining optional fields (e.g. [1] publicKey) so finish() succeeds
            seq.drain(seq.remaining_len())?;
            Ok(keypair)
        })
    }

    /// Extract the named curve OID from full EC domain parameters.
    /// Handles two formats:
    /// 1. Standard ECParameters: SEQUENCE { FieldID, Curve, base, order, cofactor }
    /// 2. Wrapped ECParameters: SEQUENCE { INTEGER version, SEQUENCE { FieldID, ... } }
    fn extract_curve_from_domain_params(params: AnyRef<'_>) -> Result<ObjectIdentifier, Error> {
        params.tag().assert_eq(Tag::Sequence)?;

        // Use a standalone SliceReader so we aren't required to consume all of ECParams
        // (Curve, base, order, cofactor follow FieldID but are irrelevant here).
        let mut seq = SliceReader::new(params.value())?;

        // Skip optional ECParameters version INTEGER
        if Tag::peek(&seq)? == Tag::Integer {
            seq.decode::<u8>()?;
        }

        // FieldID ::= SEQUENCE { fieldType OID, parameters ANY }
        seq.sequence(|field_id| {
            let _field_oid: ObjectIdentifier = field_id.decode()?;
            // prime INTEGER — as_bytes() strips DER sign-extension leading zero
            let prime: UintRef = field_id.decode()?;
            Ok(match prime.as_bytes().len() {
                32 => NIST_P256,
                48 => NIST_P384,
                66 => NIST_P521,
                _ => return Err(Error::CouldNotReadKey),
            })
        })
    }

    /// Build an EcdsaKeypair from raw private key bytes and a curve OID.
    #[cfg(not(russh_backend = "symcrypt"))]
    fn build_ec_keypair_from_bytes(
        curve_oid: ObjectIdentifier,
        private_key_bytes: &[u8],
    ) -> Result<EcdsaKeypair, Error> {
        if curve_oid == NistP256::OID {
            let sk = p256::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| Error::CouldNotReadKey)?;
            Ok(EcdsaKeypair::NistP256 {
                public: sk.public_key().into(),
                private: sk.into(),
            })
        } else if curve_oid == NistP384::OID {
            let sk = p384::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| Error::CouldNotReadKey)?;
            Ok(EcdsaKeypair::NistP384 {
                public: sk.public_key().into(),
                private: sk.into(),
            })
        } else if curve_oid == NistP521::OID {
            let sk = p521::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| Error::CouldNotReadKey)?;
            Ok(EcdsaKeypair::NistP521 {
                public: sk.public_key().into(),
                private: sk.into(),
            })
        } else {
            Err(Error::UnknownAlgorithm(curve_oid))
        }
    }

    /// Build an EcdsaKeypair from raw private key bytes and a curve OID.
    #[cfg(russh_backend = "symcrypt")]
    fn build_ec_keypair_from_bytes(
        curve_oid: ObjectIdentifier,
        private_key_bytes: &[u8],
    ) -> Result<EcdsaKeypair, Error> {
        crate::crypto::symcrypt::keys::ecdsa_keypair(
            ecdsa_curve(curve_oid)?,
            private_key_bytes,
            None,
        )
    }
}

/// Encode into a password-protected PKCS#8-encoded private key.
#[cfg(not(russh_backend = "symcrypt"))]
pub fn encode_pkcs8_encrypted(
    pass: &[u8],
    rounds: u32,
    key: &PrivateKey,
) -> Result<Vec<u8>, Error> {
    let pvi_bytes = encode_pkcs8(key)?;
    let pvi = PrivateKeyInfoRef::try_from(pvi_bytes.as_slice())?;

    use rand_core::Rng;
    let mut rng = safe_rng();
    let mut salt = [0; 32];
    rng.fill_bytes(&mut salt);
    let mut iv = [0; 16];
    rng.fill_bytes(&mut iv);

    let doc = pvi.encrypt_with_params(
        pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(rounds, &salt, iv)
            .map_err(|_| Error::InvalidParameters)?,
        pass,
    )?;
    Ok(doc.as_bytes().to_vec())
}

/// Encode into a password-protected PKCS#8-encoded private key.
///
/// The symcrypt backend does not encrypt keys: this fails with
/// [`Error::UnsupportedKeyType`].
#[cfg(russh_backend = "symcrypt")]
pub fn encode_pkcs8_encrypted(
    _pass: &[u8],
    _rounds: u32,
    _key: &PrivateKey,
) -> Result<Vec<u8>, Error> {
    Err(super::unsupported(
        "encrypted PKCS#8 private key: the symcrypt crypto backend does not encrypt private keys",
    ))
}

/// Encode into a PKCS#8-encoded private key.
#[cfg(not(russh_backend = "symcrypt"))]
pub fn encode_pkcs8(key: &ssh_key::PrivateKey) -> Result<Vec<u8>, Error> {
    let v = match key.key_data() {
        ssh_key::private::KeypairData::Ed25519(pair) => {
            let sk: ed25519_dalek::SigningKey = pair.try_into()?;
            sk.to_pkcs8_der()?.as_bytes().to_vec()
        }
        #[cfg(feature = "rsa")]
        ssh_key::private::KeypairData::Rsa(pair) => {
            use rsa::pkcs8::EncodePrivateKey;
            let sk: rsa::RsaPrivateKey = pair.try_into()?;
            sk.to_pkcs8_der()?.as_bytes().to_vec()
        }
        ssh_key::private::KeypairData::Ecdsa(pair) => match pair {
            EcdsaKeypair::NistP256 { private, .. } => {
                let sk = p256::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP384 { private, .. } => {
                let sk = p384::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP521 { private, .. } => {
                let sk = p521::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
        },
        _ => {
            let algo = key.algorithm();
            let kt = algo.as_str();
            return Err(Error::UnsupportedKeyType {
                key_type_string: kt.into(),
                key_type_raw: kt.as_bytes().into(),
            });
        }
    };
    Ok(v)
}

/// Encode into a PKCS#8-encoded private key.
///
/// Writes what the other backends write: PKCS#8 v1 for ECDSA (with the
/// public key in the SEC1 key) and RSA, and v2 (with the public key) for
/// Ed25519.
#[cfg(russh_backend = "symcrypt")]
pub fn encode_pkcs8(key: &ssh_key::PrivateKey) -> Result<Vec<u8>, Error> {
    use der::Encode;
    use der::asn1::{AnyRef, BitStringRef, OctetStringRef, UintRef};
    use spki::AlgorithmIdentifierRef;
    use ssh_key::EcdsaCurve;
    use zeroize::Zeroizing;

    use crate::crypto::symcrypt::keys;

    let v = match key.key_data() {
        KeypairData::Ed25519(pair) => {
            let seed: &[u8; 32] = pair.private.as_ref();
            let mut private_key = Zeroizing::new([0; 34]);
            let (header, private_seed) = private_key.split_at_mut(2);
            header.copy_from_slice(&[0x04, 0x20]);
            private_seed.copy_from_slice(seed);
            let mut pki = PrivateKeyInfoRef::new(
                AlgorithmIdentifierRef {
                    oid: ED25519,
                    parameters: None,
                },
                OctetStringRef::new(private_key.as_slice())?,
            );
            pki.public_key = Some(BitStringRef::from_bytes(&pair.public.0)?);
            pki.to_der()?
        }
        KeypairData::Rsa(pair) => {
            fn positive(x: &ssh_key::Mpint) -> Result<&[u8], Error> {
                x.as_positive_bytes().ok_or(Error::KeyIsCorrupt)
            }
            let n = positive(pair.public().n())?;
            let e = positive(pair.public().e())?;
            let p = positive(pair.private().p())?;
            let q = positive(pair.private().q())?;
            let crt = keys::rsa_crt(n, e, p, q)?;
            let rsa = pkcs1::RsaPrivateKey {
                modulus: UintRef::new(n)?,
                public_exponent: UintRef::new(e)?,
                private_exponent: UintRef::new(positive(pair.private().d())?)?,
                prime1: UintRef::new(p)?,
                prime2: UintRef::new(q)?,
                exponent1: UintRef::new(&crt.exponent1)?,
                exponent2: UintRef::new(&crt.exponent2)?,
                coefficient: UintRef::new(&crt.coefficient)?,
                other_prime_infos: None,
            };
            let private_key = Zeroizing::new(rsa.to_der()?);
            PrivateKeyInfoRef::new(pkcs1::ALGORITHM_ID, OctetStringRef::new(&private_key)?)
                .to_der()?
        }
        KeypairData::Ecdsa(pair) => {
            let curve = pair.curve();
            // Like the other backends, writes the public key of the private
            // key, not the stored one.
            let pair = keys::ecdsa_keypair(curve, pair.private_key_bytes(), None)?;
            let private_key = Zeroizing::new(
                sec1::EcPrivateKey {
                    private_key: pair.private_key_bytes(),
                    parameters: None,
                    public_key: Some(pair.public_key_bytes()),
                }
                .to_der()?,
            );
            let curve = match curve {
                EcdsaCurve::NistP256 => NIST_P256,
                EcdsaCurve::NistP384 => NIST_P384,
                EcdsaCurve::NistP521 => NIST_P521,
            };
            PrivateKeyInfoRef::new(
                AlgorithmIdentifierRef {
                    oid: sec1::ALGORITHM_OID,
                    parameters: Some(AnyRef::from(&curve)),
                },
                OctetStringRef::new(&private_key)?,
            )
            .to_der()?
        }
        _ => {
            let algo = key.algorithm();
            let kt = algo.as_str();
            return Err(Error::UnsupportedKeyType {
                key_type_string: kt.into(),
                key_type_raw: kt.as_bytes().into(),
            });
        }
    };
    Ok(v)
}
