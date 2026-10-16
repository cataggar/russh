use ssh_key::PrivateKey;

use crate::keys::Error;

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
#[cfg(not(russh_backend = "symcrypt"))]
pub fn decode_openssh(secret: &[u8], password: Option<&str>) -> Result<PrivateKey, Error> {
    let pk = raw::from_bytes(secret)?;
    if pk.is_encrypted() {
        if let Some(password) = password {
            return raw::decrypt(&pk, password);
        } else {
            return Err(Error::KeyIsEncrypted);
        }
    }
    Ok(pk)
}

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
///
/// The symcrypt backend does not decrypt keys: an encrypted key fails with
/// [`Error::UnsupportedKeyType`], and `password` is ignored.
#[cfg(russh_backend = "symcrypt")]
pub fn decode_openssh(secret: &[u8], _password: Option<&str>) -> Result<PrivateKey, Error> {
    let mut fields = raw::Fields(secret);
    if fields.take(raw::MAGIC.len()) == Some(raw::MAGIC) {
        match fields.string() {
            Some(b"none") | None => {}
            Some(cipher) => {
                return Err(super::encrypted(&match raw::cipher_name(cipher) {
                    Some(name) => format!("OpenSSH ({name})"),
                    None => "OpenSSH".to_owned(),
                }));
            }
        }
    }
    let key = raw::from_bytes(secret)?;
    if key.is_encrypted() {
        return Err(super::encrypted("OpenSSH"));
    }
    if let ssh_key::private::KeypairData::Mldsa87P384(kp) = key.key_data() {
        crate::crypto::symcrypt::keys::mldsa87_p384_keypair(
            kp.mldsa_seed(),
            kp.ecdsa_private().as_slice(),
            Some(kp.public().mldsa()),
            Some(kp.public().ecdsa_sec1_bytes()),
        )?;
    }
    Ok(key)
}

/// Decodes a plain key pair or a certificate with its private key as OpenSSH
/// encodes it in the agent protocol (`SSH_AGENTC_ADD_IDENTITY` and
/// `SSH_AGENTC_ADD_ID_CONSTRAINED`), returning the identity blob (the
/// encoded public key or the raw certificate bytes) and the [`KeypairData`].
pub(crate) fn decode_agent_key(
    reader: &mut impl ssh_encoding::Reader,
) -> Result<(Vec<u8>, ssh_key::private::KeypairData), Error> {
    use ssh_encoding::Decode;
    use ssh_key::{Algorithm, Certificate};

    use crate::helpers::{AlgorithmExt, EncodedExt};

    let algorithm_name = String::decode(reader)?;
    if algorithm_name.ends_with("-cert-v01@openssh.com") {
        let cert_alg = Algorithm::new_certificate_ext(&algorithm_name)?;
        let cert_blob = Vec::<u8>::decode(reader)?;
        let cert = Certificate::from_bytes(&cert_blob)?;
        if cert.public_key().algorithm().with_hash_alg(None) != cert_alg.with_hash_alg(None) {
            return Err(Error::KeyIsCorrupt);
        }
        let keypair = decode_cert_keypair(cert.public_key(), reader)?;
        Ok((cert_blob, keypair))
    } else {
        let algorithm = Algorithm::new(&algorithm_name)?;
        let keypair = decode_keypair_as(reader, algorithm)?;
        let public = ssh_key::public::KeyData::try_from(&keypair)?.encoded()?;
        Ok((public, keypair))
    }
}

/// Decodes a key pair as OpenSSH encodes it in a private key and in the
/// agent protocol (`SSH_AGENTC_ADD_IDENTITY`): the algorithm name, then the
/// key's fields.
///
/// ssh-key reads the key, once an ECDSA private scalar shorter than it reads
/// is padded (see [`raw`]).
#[allow(dead_code)]
pub(crate) fn decode_keypair(
    reader: &mut impl ssh_encoding::Reader,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Decode;
    use ssh_key::Algorithm;

    let algorithm = Algorithm::decode(reader)?;
    decode_keypair_as(reader, algorithm)
}

#[cfg(not(russh_backend = "symcrypt"))]
fn decode_keypair_as(
    reader: &mut impl ssh_encoding::Reader,
    algorithm: ssh_key::Algorithm,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Decode;
    use ssh_key::Algorithm;
    use ssh_key::private::KeypairData;
    use zeroize::Zeroizing;

    match algorithm {
        Algorithm::Ecdsa { curve } => {
            // The curve, the public point and the private scalar, which ssh-key
            // reads again, with the scalar padded if it is short.
            let curve_name = Vec::<u8>::decode(reader)?;
            let point = Vec::<u8>::decode(reader)?;
            let scalar = Zeroizing::new(Vec::<u8>::decode(reader)?);
            decode_ecdsa_keypair(curve, &curve_name, &point, scalar)
        }
        Algorithm::Mldsa87P384 => {
            let public = ssh_key::public::Mldsa87P384PublicKey::decode(reader)?;
            let composite_private = Zeroizing::new(Vec::<u8>::decode(reader)?);
            decode_mldsa87_p384_keypair(&public, composite_private)
        }
        algorithm => Ok(KeypairData::decode_as(reader, algorithm)?),
    }
}

#[cfg(not(russh_backend = "symcrypt"))]
fn decode_mldsa87_p384_keypair(
    public: &ssh_key::public::Mldsa87P384PublicKey,
    mut composite_private: zeroize::Zeroizing<Vec<u8>>,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Encode;
    use ssh_key::Algorithm;
    use ssh_key::private::KeypairData;
    use zeroize::Zeroizing;

    let mut priv_fields = raw::Fields(&composite_private);
    if let (Some(seed), Some(scalar)) = (priv_fields.take(32), priv_fields.string())
        && priv_fields.0.is_empty()
        && raw::is_short_scalar(scalar)
    {
        let padded_scalar = raw::padded_scalar(
            ssh_key::EcdsaCurve::NistP384,
            scalar,
            public.ecdsa_sec1_bytes(),
        )?;
        let mut new_priv = Zeroizing::new(Vec::with_capacity(32 + 4 + padded_scalar.len()));
        new_priv.extend_from_slice(seed);
        padded_scalar.as_slice().encode(&mut *new_priv)?;
        composite_private = new_priv;
    }
    let mut fields = Zeroizing::new(Vec::with_capacity(
        public.encoded_len()? + 4 + composite_private.len(),
    ));
    public.encode(&mut *fields)?;
    composite_private.as_slice().encode(&mut *fields)?;
    Ok(KeypairData::decode_as(
        &mut fields.as_slice(),
        Algorithm::Mldsa87P384,
    )?)
}

#[cfg(not(russh_backend = "symcrypt"))]
fn decode_ecdsa_keypair(
    curve: ssh_key::EcdsaCurve,
    curve_name: &[u8],
    point: &[u8],
    mut scalar: zeroize::Zeroizing<Vec<u8>>,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Encode;
    use ssh_key::Algorithm;
    use ssh_key::private::KeypairData;
    use zeroize::Zeroizing;

    if raw::is_short_scalar(&scalar) {
        scalar = raw::padded_scalar(curve, &scalar, point)?;
    }
    let mut fields = Zeroizing::new(Vec::with_capacity(
        12 + curve_name.len() + point.len() + scalar.len(),
    ));
    curve_name.encode(&mut *fields)?;
    point.encode(&mut *fields)?;
    scalar.as_slice().encode(&mut *fields)?;
    Ok(KeypairData::decode_as(
        &mut fields.as_slice(),
        Algorithm::Ecdsa { curve },
    )?)
}

#[cfg(not(russh_backend = "symcrypt"))]
fn decode_cert_keypair(
    public: &ssh_key::public::KeyData,
    reader: &mut impl ssh_encoding::Reader,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Decode;
    use ssh_key::private::{
        DsaKeypair, DsaPrivateKey, Ed25519Keypair, KeypairData, RsaKeypair, RsaPrivateKey,
    };
    use ssh_key::public::KeyData;
    use zeroize::Zeroizing;

    match public {
        KeyData::Dsa(pk) => {
            let private = DsaPrivateKey::decode(reader)?;
            Ok(KeypairData::Dsa(DsaKeypair::new(pk.clone(), private)?))
        }
        KeyData::Ecdsa(pk) => {
            let scalar = Zeroizing::new(Vec::<u8>::decode(reader)?);
            decode_ecdsa_keypair(
                pk.curve(),
                pk.curve().as_str().as_bytes(),
                pk.as_sec1_bytes(),
                scalar,
            )
        }
        KeyData::Mldsa87P384(pk) => {
            let composite_private = Zeroizing::new(Vec::<u8>::decode(reader)?);
            decode_mldsa87_p384_keypair(pk, composite_private)
        }
        KeyData::Ed25519(pk) => {
            let keypair = Ed25519Keypair::decode(reader)?;
            if keypair.public != *pk {
                return Err(Error::KeyIsCorrupt);
            }
            Ok(KeypairData::Ed25519(keypair))
        }
        KeyData::Rsa(pk) => {
            let private = RsaPrivateKey::decode(reader)?;
            Ok(KeypairData::Rsa(RsaKeypair::new(pk.clone(), private)?))
        }
        _ => Err(ssh_key::Error::AlgorithmUnsupported {
            algorithm: public.algorithm(),
        }
        .into()),
    }
}

/// Decodes a key pair as OpenSSH encodes it in a private key and in the
/// agent protocol (`SSH_AGENTC_ADD_IDENTITY`): the algorithm name, then the
/// key's fields.
///
/// SymCrypt checks ECDSA and RSA keys (see [`crate::crypto::symcrypt::keys`]):
/// the private scalar must be the one of the public point, and it may be
/// shorter than ssh-key reads (see [`raw`]) or have leading zeros, as ssh-key
/// writes it; `iqmp` is recomputed. ssh-key reads the other key types.
#[cfg(russh_backend = "symcrypt")]
fn decode_keypair_as(
    reader: &mut impl ssh_encoding::Reader,
    algorithm: ssh_key::Algorithm,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Decode;
    use ssh_key::private::KeypairData;
    use ssh_key::{Algorithm, EcdsaCurve, Mpint};
    use zeroize::Zeroizing;

    use crate::crypto::symcrypt::keys;

    match algorithm {
        Algorithm::Ecdsa { curve } => {
            if EcdsaCurve::decode(reader)? != curve {
                return Err(ssh_key::Error::AlgorithmUnknown.into());
            }
            let point = Vec::<u8>::decode(reader)?;
            // An `mpint`, read as an unsigned integer like ssh-key reads it:
            // ssh-key writes the curve's size, so leading zeros are kept.
            let scalar = Zeroizing::new(Vec::<u8>::decode(reader)?);
            // Uncompressed, as OpenSSH requires: the key is stored with the
            // point that SymCrypt derives, which is uncompressed.
            if point.first() != Some(&0x04) {
                return Err(Error::KeyIsCorrupt);
            }
            let keypair = keys::ecdsa_keypair(curve, &scalar, Some(&point))?;
            Ok(KeypairData::Ecdsa(keypair))
        }
        Algorithm::Rsa { .. } => {
            let n = Mpint::decode(reader)?;
            let e = Mpint::decode(reader)?;
            decode_symcrypt_rsa_private(&n, &e, reader)
        }
        Algorithm::Mldsa87P384 => {
            let public = ssh_key::public::Mldsa87P384PublicKey::decode(reader)?;
            decode_symcrypt_mldsa87_p384_private(&public, reader)
        }
        algorithm => Ok(KeypairData::decode_as(reader, algorithm)?),
    }
}

#[cfg(russh_backend = "symcrypt")]
fn decode_symcrypt_mldsa87_p384_private(
    public: &ssh_key::public::Mldsa87P384PublicKey,
    reader: &mut impl ssh_encoding::Reader,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Decode;
    use ssh_key::private::KeypairData;
    use zeroize::Zeroizing;

    use crate::crypto::symcrypt::keys;

    let composite_private = Zeroizing::new(Vec::<u8>::decode(reader)?);
    let mut fields = raw::Fields(&composite_private);
    let (Some(seed), Some(scalar)) = (fields.take(32), fields.string()) else {
        return Err(Error::KeyIsCorrupt);
    };
    if !fields.0.is_empty() || scalar.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(Error::KeyIsCorrupt);
    }
    let seed: &[u8; 32] = seed.try_into().map_err(|_| Error::KeyIsCorrupt)?;
    let keypair = keys::mldsa87_p384_keypair(
        seed,
        scalar,
        Some(public.mldsa()),
        Some(public.ecdsa_sec1_bytes()),
    )?;
    Ok(KeypairData::Mldsa87P384(keypair))
}

#[cfg(russh_backend = "symcrypt")]
fn decode_symcrypt_rsa_private(
    n: &ssh_key::Mpint,
    e: &ssh_key::Mpint,
    reader: &mut impl ssh_encoding::Reader,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Decode;
    use ssh_key::Mpint;
    use ssh_key::private::KeypairData;
    use zeroize::Zeroizing;

    use crate::crypto::symcrypt::keys;

    fn positive(mpint: &Mpint) -> Result<&[u8], Error> {
        mpint.as_positive_bytes().ok_or(Error::KeyIsCorrupt)
    }

    let d = Zeroizing::new(Mpint::decode(reader)?);
    let _iqmp = Zeroizing::new(Mpint::decode(reader)?);
    let p = Zeroizing::new(Mpint::decode(reader)?);
    let q = Zeroizing::new(Mpint::decode(reader)?);
    let keypair = keys::rsa_keypair(
        positive(n)?,
        positive(e)?,
        positive(&d)?,
        positive(&p)?,
        positive(&q)?,
    )?;
    Ok(KeypairData::Rsa(keypair))
}

#[cfg(russh_backend = "symcrypt")]
fn decode_cert_keypair(
    public: &ssh_key::public::KeyData,
    reader: &mut impl ssh_encoding::Reader,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Decode;
    use ssh_key::private::{DsaKeypair, DsaPrivateKey, Ed25519Keypair, KeypairData};
    use ssh_key::public::KeyData;
    use zeroize::Zeroizing;

    use crate::crypto::symcrypt::keys;

    match public {
        KeyData::Dsa(pk) => {
            let private = DsaPrivateKey::decode(reader)?;
            Ok(KeypairData::Dsa(DsaKeypair::new(pk.clone(), private)?))
        }
        KeyData::Ecdsa(pk) => {
            let scalar = Zeroizing::new(Vec::<u8>::decode(reader)?);
            let point = pk.as_sec1_bytes();
            if point.first() != Some(&0x04) {
                return Err(Error::KeyIsCorrupt);
            }
            let keypair = keys::ecdsa_keypair(pk.curve(), &scalar, Some(point))?;
            Ok(KeypairData::Ecdsa(keypair))
        }
        KeyData::Ed25519(pk) => {
            let keypair = Ed25519Keypair::decode(reader)?;
            if keypair.public != *pk {
                return Err(Error::KeyIsCorrupt);
            }
            Ok(KeypairData::Ed25519(keypair))
        }
        KeyData::Mldsa87P384(pk) => decode_symcrypt_mldsa87_p384_private(pk, reader),
        KeyData::Rsa(pk) => decode_symcrypt_rsa_private(pk.n(), pk.e(), reader),
        _ => Err(ssh_key::Error::AlgorithmUnsupported {
            algorithm: public.algorithm(),
        }
        .into()),
    }
}

/// The binary OpenSSH private key format (`PROTOCOL.key` in OpenSSH), and a
/// workaround for an ssh-key bug: `EcdsaPrivateKey::decode` rejects private
/// scalars shorter than 32 bytes, but the scalar is an `mpint`, which has
/// no leading zeros, so 1 in 512 P-256 keys from `ssh-keygen` have one.
/// Such a key is decoded again with the scalar padded to the size of the
/// curve, which ssh-key reads.
mod raw {
    use ssh_key::PrivateKey;
    use zeroize::Zeroizing;

    use crate::keys::{EcdsaCurve, Error};

    pub(super) const MAGIC: &[u8] = b"openssh-key-v1\0";

    /// What follows [`MAGIC`] in an unencrypted key: cipher `none`, KDF
    /// `none`, empty KDF options, and one key.
    const UNENCRYPTED: &[u8] = b"\0\0\0\x04none\0\0\0\x04none\0\0\0\0\0\0\0\x01";

    /// Reads `uint32` and `string` fields.
    pub(super) struct Fields<'a>(pub(super) &'a [u8]);

    impl<'a> Fields<'a> {
        pub(super) fn take(&mut self, len: usize) -> Option<&'a [u8]> {
            let (field, rest) = self.0.split_at_checked(len)?;
            self.0 = rest;
            Some(field)
        }

        fn u32(&mut self) -> Option<u32> {
            Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
        }

        pub(super) fn string(&mut self) -> Option<&'a [u8]> {
            let len = usize::try_from(self.u32()?).ok()?;
            self.take(len)
        }
    }

    /// The cipher's name, if it looks like one.
    #[cfg(russh_backend = "symcrypt")]
    pub(super) fn cipher_name(cipher: &[u8]) -> Option<&str> {
        std::str::from_utf8(cipher)
            .ok()
            .filter(|name| name.len() <= 64 && name.bytes().all(|b| b.is_ascii_graphic()))
    }

    /// The shortest private scalar that ssh-key reads.
    const SSH_KEY_MIN_SCALAR_LEN: usize = 32;

    /// Whether ssh-key rejects `scalar`, an ECDSA private scalar written as
    /// an `mpint`, only because it is too short: it is not negative.
    pub(super) fn is_short_scalar(scalar: &[u8]) -> bool {
        scalar.len() < SSH_KEY_MIN_SCALAR_LEN && scalar.first().is_none_or(|b| b & 0x80 == 0)
    }

    /// `scalar` padded to the size of the curve, once SymCrypt has checked
    /// that it is the private key of the public `point`.
    #[cfg(russh_backend = "symcrypt")]
    pub(super) fn padded_scalar(
        curve: EcdsaCurve,
        scalar: &[u8],
        point: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let keypair = crate::crypto::symcrypt::keys::ecdsa_keypair(curve, scalar, Some(point))?;
        Ok(Zeroizing::new(keypair.private_key_bytes().to_vec()))
    }

    /// `scalar` padded with zeros to the size of the curve, as ssh-key pads
    /// a scalar of 32 bytes or more. Like ssh-key, this does not check it
    /// against the public point.
    #[cfg(not(russh_backend = "symcrypt"))]
    pub(super) fn padded_scalar(
        curve: EcdsaCurve,
        scalar: &[u8],
        _point: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let size: usize = match curve {
            EcdsaCurve::NistP256 => 32,
            EcdsaCurve::NistP384 => 48,
            EcdsaCurve::NistP521 => 66,
        };
        let zeros = size
            .checked_sub(scalar.len())
            .ok_or(Error::CouldNotReadKey)?;
        let mut padded = Zeroizing::new(Vec::with_capacity(size));
        padded.resize(zeros, 0);
        padded.extend_from_slice(scalar);
        Ok(padded)
    }

    /// [`PrivateKey::from_bytes`], which also reads an unencrypted ECDSA key
    /// with a short scalar (see [`pad_short_ecdsa_scalar`]).
    pub(super) fn from_bytes(secret: &[u8]) -> Result<PrivateKey, Error> {
        match PrivateKey::from_bytes(secret) {
            Ok(key) => Ok(key),
            Err(error) => match pad_short_ecdsa_scalar(secret)? {
                Some(padded) => Ok(PrivateKey::from_bytes(&padded)?),
                None => Err(error.into()),
            },
        }
    }

    /// [`PrivateKey::decrypt`], which also reads an ECDSA key with a short
    /// scalar.
    ///
    /// ssh-key rejects the decrypted key with the error of a short scalar,
    /// after the check integers matched (a wrong password fails there). The
    /// key is then decrypted again, and decoded as an unencrypted key with
    /// the scalar padded (see [`pad_section`]), as `decrypt` returns it.
    #[cfg(not(russh_backend = "symcrypt"))]
    pub(super) fn decrypt(key: &PrivateKey, password: &str) -> Result<PrivateKey, Error> {
        use ssh_encoding::Encode;

        let error = match key.decrypt(password) {
            Err(error @ ssh_key::Error::Encoding(ssh_encoding::Error::Length)) => error,
            result => return Ok(result?),
        };
        let cipher = key.cipher();
        let ciphertext = key
            .key_data()
            .encrypted()
            .ok_or(ssh_key::Error::Decrypted)?;
        // The authentication tag, if any, ends the encoded key.
        let tag = if cipher.has_tag() {
            let encoded = key.to_bytes()?;
            let tag = encoded.last_chunk::<16>().ok_or(Error::CouldNotReadKey)?;
            Some(ssh_key::cipher::Tag::from(*tag))
        } else {
            None
        };
        let (cipher_key, iv) = key.kdf().derive_key_and_iv(cipher, password)?;
        let mut section = Zeroizing::new(ciphertext.to_vec());
        cipher
            .decrypt(&cipher_key, &iv, &mut section, tag)
            .map_err(ssh_key::Error::from)?;
        let public_key = key.public_key().key_data().encode_vec()?;
        // ssh-key accepts less padding with a cipher than without.
        let max_padding = cipher.block_size() - 1;
        match pad_section(&public_key, &section, max_padding)? {
            Some(padded) => Ok(PrivateKey::from_bytes(&padded)?),
            None => Err(error.into()),
        }
    }

    /// If `secret` is an unencrypted ECDSA key with a scalar that ssh-key
    /// rejects because it is short, returns it with the scalar padded (see
    /// [`pad_section`]). Returns `None` for other keys, and for keys that
    /// ssh-key rejects for another reason.
    pub(super) fn pad_short_ecdsa_scalar(
        secret: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        // Magic, cipher, KDF, KDF options and number of keys, then the
        // public key and the private section.
        let Some(rest) = secret
            .strip_prefix(MAGIC)
            .and_then(|rest| rest.strip_prefix(UNENCRYPTED))
        else {
            return Ok(None);
        };
        let mut fields = Fields(rest);
        let (Some(public_key), Some(section)) = (fields.string(), fields.string()) else {
            return Ok(None);
        };
        if !fields.0.is_empty() || !section.len().is_multiple_of(8) {
            return Ok(None);
        }
        // ssh-key accepts up to 16 bytes of padding without a cipher.
        pad_section(public_key, section, 16)
    }

    /// If `section`, a decrypted private section with at most `max_padding`
    /// bytes of padding, has an ECDSA key with a short scalar (see
    /// [`is_short_scalar`]), returns the unencrypted key with `public_key`
    /// and `section`, with the scalar padded to the size of the curve (see
    /// [`padded_scalar`]). Returns `None` otherwise.
    fn pad_section(
        public_key: &[u8],
        section: &[u8],
        max_padding: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        // Check integers, key type, curve/composite public key, private
        // scalar/composite private key, comment and padding.
        let mut fields = Fields(section);
        let (_, Some(key_type)) = (fields.take(8), fields.string()) else {
            return Ok(None);
        };
        let (curve, point, replace_start, seed_prefix, scalar) = match key_type {
            b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521" => {
                let curve = match key_type {
                    b"ecdsa-sha2-nistp256" => EcdsaCurve::NistP256,
                    b"ecdsa-sha2-nistp384" => EcdsaCurve::NistP384,
                    _ => EcdsaCurve::NistP521,
                };
                let (Some(_), Some(point)) = (fields.string(), fields.string()) else {
                    return Ok(None);
                };
                let scalar_start = section.len() - fields.0.len();
                let Some(scalar) = fields.string() else {
                    return Ok(None);
                };
                (curve, point, scalar_start, None, scalar)
            }
            b"ssh-mldsa87-p384" => {
                let Some(composite_public) = fields.string() else {
                    return Ok(None);
                };
                let mut pub_fields = Fields(composite_public);
                let (Some(_mldsa_pub), Some(point)) = (pub_fields.take(2592), pub_fields.string())
                else {
                    return Ok(None);
                };
                if !pub_fields.0.is_empty() {
                    return Ok(None);
                }
                let priv_start = section.len() - fields.0.len();
                let Some(composite_private) = fields.string() else {
                    return Ok(None);
                };
                let mut priv_fields = Fields(composite_private);
                let (Some(seed), Some(scalar)) = (priv_fields.take(32), priv_fields.string())
                else {
                    return Ok(None);
                };
                if !priv_fields.0.is_empty() {
                    return Ok(None);
                }
                (EcdsaCurve::NistP384, point, priv_start, Some(seed), scalar)
            }
            _ => return Ok(None),
        };
        if !is_short_scalar(scalar) {
            return Ok(None);
        }
        let comment_start = section.len() - fields.0.len();
        if fields.string().is_none() {
            return Ok(None);
        }
        let padding = fields.0;
        if padding.len() > max_padding || padding.iter().zip(1..).any(|(&byte, i)| byte != i) {
            return Ok(None);
        }
        let comment = section
            .get(comment_start..section.len() - padding.len())
            .ok_or(Error::CouldNotReadKey)?;

        let scalar = padded_scalar(curve, scalar, point)?;
        let scalar_len = u32::try_from(scalar.len()).map_err(|_| Error::CouldNotReadKey)?;
        let replacement = match seed_prefix {
            Some(seed) => {
                let mut comp_priv = Zeroizing::new(Vec::with_capacity(32 + 4 + scalar.len()));
                comp_priv.extend_from_slice(seed);
                comp_priv.extend_from_slice(&scalar_len.to_be_bytes());
                comp_priv.extend_from_slice(&scalar);
                comp_priv
            }
            None => scalar,
        };
        let replacement_len =
            u32::try_from(replacement.len()).map_err(|_| Error::CouldNotReadKey)?;
        let public_key_len = u32::try_from(public_key.len()).map_err(|_| Error::CouldNotReadKey)?;

        let unpadded_len = replace_start + 4 + replacement.len() + comment.len();
        let padding_len = (8 - unpadded_len % 8) % 8;
        let section_len =
            u32::try_from(unpadded_len + padding_len).map_err(|_| Error::CouldNotReadKey)?;
        // Sized for what follows, so that the scalar is never copied by a
        // reallocation, which would not wipe it.
        let mut padded = Zeroizing::new(Vec::with_capacity(
            MAGIC.len() + UNENCRYPTED.len() + 4 + public_key.len() + 4 + unpadded_len + padding_len,
        ));
        padded.extend_from_slice(MAGIC);
        padded.extend_from_slice(UNENCRYPTED);
        padded.extend_from_slice(&public_key_len.to_be_bytes());
        padded.extend_from_slice(public_key);
        padded.extend_from_slice(&section_len.to_be_bytes());
        padded.extend_from_slice(section.get(..replace_start).ok_or(Error::CouldNotReadKey)?);
        padded.extend_from_slice(&replacement_len.to_be_bytes());
        padded.extend_from_slice(&replacement);
        padded.extend_from_slice(comment);
        padded.extend((1..).take(padding_len));
        Ok(Some(padded))
    }
}

#[cfg(test)]
mod tests {
    //! ECDSA keys whose private scalar is an `mpint` shorter than ssh-key
    //! reads (cataggar/russh#31). The fixtures in `russh/tests/data/keys`
    //! (comment `russh-test`, password `password`) have a 31-byte scalar, and
    //! were made with OpenSSH 10.2 and OpenSSL 3.5:
    //! - `ecdsa-p256-short`: `ssh-keygen -t ecdsa -b 256`, run until the
    //!   scalar was short (1 key in 512), and its SEC1 and PKCS#8 forms (see
    //!   `crypto::symcrypt::keys::tests`).
    //! - `ecdsa-p384-short`: the scalar is the first 31 bytes of
    //!   SHA-512(`russh-test ecdsa-p384-short`), with the top bit cleared and
    //!   the next one set. It was written as SEC1 DER by a script, checked
    //!   with `openssl ec`, converted by `ssh-keygen -p -N ""`, and given its
    //!   comment by `ssh-keygen -c`; `.pub` is `ssh-keygen -y`.
    //! - `ecdsa-p521-short`: the same scalar, from
    //!   SHA-512(`russh-test ecdsa-p521-short`), and the OpenSSH key written
    //!   by the script, as OpenSSH rejects P-521 scalars of 260 bits or
    //!   fewer ("invalid elliptic curve value"). The check integer is the
    //!   first 4 bytes of SHA-256(`checkint p521`); `.pub` is `ssh-keygen -i
    //!   -m PKCS8` of `openssl ec -pubout`, with the comment appended.
    //! - `ecdsa-p256-short-encrypted` and `ecdsa-p384-short-encrypted`:
    //!   `ssh-keygen -p -a 1 -N password` (one KDF round, to keep the tests
    //!   fast), with `-Z chacha20-poly1305@openssh.com` for P-384 (aes256-ctr
    //!   for P-256).
    //! - `ecdsa-p256-short.ppk`: PPK v3 without encryption, written from
    //!   `ecdsa-p256-short` by a script, with the `Private-MAC` that PuTTY
    //!   computes (HMAC-SHA-256 with an empty key).
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use std::path::Path;

    use ssh_encoding::{Decode, Encode};
    use ssh_key::private::KeypairData;
    use ssh_key::{LineEnding, PrivateKey, PublicKey};

    use crate::keys::decode_secret_key;

    /// One key with a short scalar per curve.
    const SHORT: [&str; 3] = ["ecdsa-p256-short", "ecdsa-p384-short", "ecdsa-p521-short"];

    fn fixture(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
    }

    fn load(name: &str) -> PrivateKey {
        decode_secret_key(&fixture(name), None).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    /// The key pair as OpenSSH writes it, in a private key and to an agent:
    /// the scalar is an `mpint`, so it has no leading zeros.
    fn openssh_keypair(key: &PrivateKey) -> Vec<u8> {
        let KeypairData::Ecdsa(pair) = key.key_data() else {
            panic!("not ECDSA");
        };
        let scalar = pair.private_key_bytes();
        let scalar = &scalar[scalar.iter().take_while(|&&b| b == 0).count()..];
        assert!(
            scalar.len() == 31 && scalar[0] < 0x80,
            "{:?}",
            key.algorithm()
        );
        let mut encoded = Vec::new();
        key.algorithm().as_str().encode(&mut encoded).unwrap();
        pair.curve().as_str().encode(&mut encoded).unwrap();
        pair.public_key_bytes().encode(&mut encoded).unwrap();
        scalar.encode(&mut encoded).unwrap();
        encoded
    }

    fn is_short_scalar_error<T>(result: Result<T, ssh_key::Error>) -> bool {
        matches!(
            result,
            Err(ssh_key::Error::Encoding(ssh_encoding::Error::Length))
        )
    }

    /// ssh-key still rejects short scalars, so russh pads them (see
    /// [`super::raw`]). Once this fails because ssh-key reads them, the
    /// workaround can go: `raw`, `decode_keypair` and this test.
    #[test]
    fn ssh_key_still_rejects_short_ecdsa_scalars() {
        const CHANGED: &str = "ssh-key no longer rejects short ECDSA scalars with \
            `Encoding(Length)`. If it reads them now, remove the workaround in \
            `russh/src/keys/format/openssh.rs` (cataggar/russh#31); if it fails \
            differently, update the error that `raw::decrypt` matches";
        for name in SHORT {
            assert!(
                is_short_scalar_error(PrivateKey::from_openssh(fixture(name))),
                "{name}: {CHANGED}"
            );
            let keypair = openssh_keypair(&load(name));
            assert!(
                is_short_scalar_error(KeypairData::decode(&mut keypair.as_slice())),
                "{name} (agent): {CHANGED}"
            );
        }
        // The symcrypt backend does not decrypt keys.
        #[cfg(not(russh_backend = "symcrypt"))]
        for name in ["ecdsa-p256-short-encrypted", "ecdsa-p384-short-encrypted"] {
            let key = PrivateKey::from_openssh(fixture(name)).unwrap();
            assert!(
                is_short_scalar_error(key.decrypt("password")),
                "{name}: {CHANGED}"
            );
        }
    }

    /// Signs with `key`, and verifies the signature with its public key.
    fn check_signs(name: &str, key: &PrivateKey) {
        let message = b"signed with a short scalar";
        let signature =
            crate::crypto::sign(key, None, message).unwrap_or_else(|e| panic!("{name}: {e}"));
        crate::crypto::verify(key.public_key().key_data(), message, &signature)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }

    /// Every backend loads the keys, which are the keys of the `.pub` files,
    /// and signs with them.
    #[test]
    fn loads_short_ecdsa_scalars() {
        for name in SHORT {
            let key = load(name);
            let public = PublicKey::from_openssh(fixture(&format!("{name}.pub")).trim()).unwrap();
            assert_eq!(key.public_key().key_data(), public.key_data(), "{name}");
            assert_eq!(key.comment().as_bytes(), b"russh-test", "{name}");
            // The scalar is the fixture's: `openssh_keypair` checks its size.
            openssh_keypair(&key);
            // ssh-key writes the scalar with leading zeros, which it reads.
            let written = key.to_openssh(LineEnding::LF).unwrap();
            assert!(PrivateKey::from_openssh(&written).unwrap() == key, "{name}");
            check_signs(name, &key);
        }
    }

    /// The other formats do not have the bug. PKCS#8 and SEC1 store the
    /// scalar with the size of the curve, and the shorter SEC1 scalars that
    /// OpenSSL wrote before 1.1.0 are read from 24 bytes (from 1 byte with
    /// SymCrypt), as PPK `mpint`s are (the symcrypt backend does not read
    /// PPK).
    #[test]
    fn loads_short_ecdsa_scalars_in_other_formats() {
        let openssh = load("ecdsa-p256-short");
        for file in [
            "ecdsa-p256-short.pem",
            "ecdsa-p256-short.pk8.pem",
            "ecdsa-p256-short-unpadded.pem",
        ] {
            assert!(load(file).key_data() == openssh.key_data(), "{file}");
        }
        // The symcrypt backend does not load PPK keys.
        #[cfg(not(russh_backend = "symcrypt"))]
        assert!(load("ecdsa-p256-short.ppk") == openssh, "PPK");
    }

    /// The other backends decrypt the keys too, and still reject a wrong
    /// password.
    #[cfg(not(russh_backend = "symcrypt"))]
    #[test]
    fn decrypts_short_ecdsa_scalars() {
        use crate::keys::Error;

        for (name, unencrypted) in [
            ("ecdsa-p256-short-encrypted", "ecdsa-p256-short"),
            ("ecdsa-p384-short-encrypted", "ecdsa-p384-short"),
        ] {
            let text = fixture(name);
            let key = decode_secret_key(&text, Some("password"))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(key == load(unencrypted), "{name}");
            check_signs(name, &key);
            for (password, expected) in [(Some("wrong"), "Crypto"), (None, "KeyIsEncrypted")] {
                let result = decode_secret_key(&text, password);
                assert!(
                    matches!(
                        (&result, expected),
                        (Err(Error::SshKey(ssh_key::Error::Crypto)), "Crypto")
                            | (Err(Error::KeyIsEncrypted), "KeyIsEncrypted")
                    ),
                    "{name} ({password:?}): {:?}",
                    result.map(|key| key.algorithm())
                );
            }
        }
    }
}
