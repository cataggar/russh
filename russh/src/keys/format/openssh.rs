use ssh_key::PrivateKey;

use crate::keys::Error;

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
#[cfg(not(russh_backend = "symcrypt"))]
pub fn decode_openssh(secret: &[u8], password: Option<&str>) -> Result<PrivateKey, Error> {
    let pk = PrivateKey::from_bytes(secret)?;
    if pk.is_encrypted() {
        if let Some(password) = password {
            return Ok(pk.decrypt(password)?);
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
    let key = match PrivateKey::from_bytes(secret) {
        Ok(key) => key,
        Err(error) => match raw::pad_short_ecdsa_scalar(secret)? {
            Some(padded) => PrivateKey::from_bytes(&padded)?,
            None => return Err(error.into()),
        },
    };
    if key.is_encrypted() {
        return Err(super::encrypted("OpenSSH"));
    }
    Ok(key)
}

/// Decodes a key pair as OpenSSH encodes it in a private key and in the
/// agent protocol (`SSH_AGENTC_ADD_IDENTITY`): the algorithm name, then the
/// key's fields.
///
/// SymCrypt checks ECDSA and RSA keys (see [`crate::crypto::symcrypt::keys`]):
/// the private scalar must be the one of the public point, and it may be
/// shorter than ssh-key reads (see [`raw::pad_short_ecdsa_scalar`]) or have
/// leading zeros, as ssh-key writes it; `iqmp` is recomputed. ssh-key reads
/// the other key types.
#[cfg(russh_backend = "symcrypt")]
pub(crate) fn decode_keypair(
    reader: &mut impl ssh_encoding::Reader,
) -> Result<ssh_key::private::KeypairData, Error> {
    use ssh_encoding::Decode;
    use ssh_key::private::KeypairData;
    use ssh_key::{Algorithm, EcdsaCurve, Mpint};
    use zeroize::Zeroizing;

    use crate::crypto::symcrypt::keys;

    fn positive(mpint: &Mpint) -> Result<&[u8], Error> {
        mpint.as_positive_bytes().ok_or(Error::KeyIsCorrupt)
    }

    match Algorithm::decode(reader)? {
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
            let d = Zeroizing::new(Mpint::decode(reader)?);
            let _iqmp = Zeroizing::new(Mpint::decode(reader)?);
            let p = Zeroizing::new(Mpint::decode(reader)?);
            let q = Zeroizing::new(Mpint::decode(reader)?);
            let keypair = keys::rsa_keypair(
                positive(&n)?,
                positive(&e)?,
                positive(&d)?,
                positive(&p)?,
                positive(&q)?,
            )?;
            Ok(KeypairData::Rsa(keypair))
        }
        algorithm => Ok(KeypairData::decode_as(reader, algorithm)?),
    }
}

/// The binary OpenSSH private key format (`PROTOCOL.key` in OpenSSH).
#[cfg(russh_backend = "symcrypt")]
mod raw {
    use zeroize::Zeroizing;

    use crate::keys::{EcdsaCurve, Error};

    pub(super) const MAGIC: &[u8] = b"openssh-key-v1\0";

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
    pub(super) fn cipher_name(cipher: &[u8]) -> Option<&str> {
        std::str::from_utf8(cipher)
            .ok()
            .filter(|name| name.len() <= 64 && name.bytes().all(|b| b.is_ascii_graphic()))
    }

    /// The shortest private scalar that ssh-key reads.
    const SSH_KEY_MIN_SCALAR_LEN: usize = 32;

    /// Works around an ssh-key bug: `EcdsaPrivateKey::decode` rejects private
    /// scalars shorter than 32 bytes, but the scalar is an `mpint`, which has
    /// no leading zeros, so 1 in 512 P-256 keys from `ssh-keygen` have one.
    ///
    /// If `secret` is an unencrypted ECDSA key with such a scalar, returns it
    /// with the scalar padded to the size of the curve, which ssh-key reads,
    /// once SymCrypt has checked that the scalar is the private key of the
    /// public key. Returns `None` for other keys, and for keys that ssh-key
    /// rejects for another reason.
    pub(super) fn pad_short_ecdsa_scalar(
        secret: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        // Magic, cipher, KDF, KDF options, number of keys and public key,
        // then the private section.
        let mut fields = Fields(secret);
        if fields.take(MAGIC.len()) != Some(MAGIC)
            || !matches!(fields.string(), Some(b"none"))
            || !matches!(fields.string(), Some(b"none"))
            || !matches!(fields.string(), Some(b""))
            || fields.u32() != Some(1)
            || fields.string().is_none()
        {
            return Ok(None);
        }
        let header_len = secret.len() - fields.0.len();
        let Some(section) = fields.string() else {
            return Ok(None);
        };
        if !fields.0.is_empty() || !section.len().is_multiple_of(8) {
            return Ok(None);
        }

        // Check integers, key type, curve, public point, private scalar,
        // comment and padding.
        let mut fields = Fields(section);
        let curve = match (fields.take(8), fields.string()) {
            (Some(_), Some(b"ecdsa-sha2-nistp256")) => EcdsaCurve::NistP256,
            (Some(_), Some(b"ecdsa-sha2-nistp384")) => EcdsaCurve::NistP384,
            (Some(_), Some(b"ecdsa-sha2-nistp521")) => EcdsaCurve::NistP521,
            _ => return Ok(None),
        };
        let (Some(_), Some(point)) = (fields.string(), fields.string()) else {
            return Ok(None);
        };
        let scalar_start = section.len() - fields.0.len();
        let Some(scalar) = fields.string() else {
            return Ok(None);
        };
        // ssh-key reads longer scalars, and the `mpint` must not be negative.
        if scalar.len() >= SSH_KEY_MIN_SCALAR_LEN || scalar.first().is_some_and(|b| b & 0x80 != 0)
        {
            return Ok(None);
        }
        let comment_start = section.len() - fields.0.len();
        if fields.string().is_none() {
            return Ok(None);
        }
        let padding = fields.0;
        if padding.len() > 16 || padding.iter().zip(1..).any(|(&byte, i)| byte != i) {
            return Ok(None);
        }
        let comment = section
            .get(comment_start..section.len() - padding.len())
            .ok_or(Error::CouldNotReadKey)?;

        let keypair = crate::crypto::symcrypt::keys::ecdsa_keypair(curve, scalar, Some(point))?;
        let scalar = keypair.private_key_bytes();
        let scalar_len = u32::try_from(scalar.len()).map_err(|_| Error::CouldNotReadKey)?;

        let unpadded_len = scalar_start + 4 + scalar.len() + comment.len();
        let padding_len = (8 - unpadded_len % 8) % 8;
        let section_len =
            u32::try_from(unpadded_len + padding_len).map_err(|_| Error::CouldNotReadKey)?;
        let mut padded =
            Zeroizing::new(Vec::with_capacity(header_len + 4 + unpadded_len + padding_len));
        padded.extend_from_slice(secret.get(..header_len).ok_or(Error::CouldNotReadKey)?);
        padded.extend_from_slice(&section_len.to_be_bytes());
        padded.extend_from_slice(section.get(..scalar_start).ok_or(Error::CouldNotReadKey)?);
        padded.extend_from_slice(&scalar_len.to_be_bytes());
        padded.extend_from_slice(scalar);
        padded.extend_from_slice(comment);
        padded.extend((1..).take(padding_len));
        Ok(Some(padded))
    }
}
