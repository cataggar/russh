//! Private key loading and generation for the SymCrypt backend.
//!
//! [`decode_secret_key`](crate::keys::decode_secret_key),
//! [`load_secret_key`](crate::keys::load_secret_key) and
//! [`pkcs8::decode_pkcs8`](crate::keys::pkcs8::decode_pkcs8) parse keys
//! with format-only crates: `ssh-key`'s OpenSSH format parser, and `der`,
//! `pkcs8`, `pkcs1`, `sec1` and `spki`. SymCrypt does the arithmetic, in
//! this file: it derives and checks ECDSA public points, and it checks RSA
//! keys and computes their CRT values. The RustCrypto algorithm crates
//! (`p256`, `p384`, `p521`, `rsa`, `ed25519-dalek`) are not used. The
//! result is the same [`ssh_key::PrivateKey`] as with the other backends:
//! `KeypairData::Ecdsa` with the uncompressed public point, and
//! `KeypairData::Rsa` with `n`, `e`, `d`, `iqmp`, `p` and `q`.
//!
//! | Format | ECDSA P-256/P-384/P-521 | RSA | Ed25519 |
//! |---|---|---|---|
//! | OpenSSH (`BEGIN OPENSSH PRIVATE KEY`) | yes | yes | yes (1) |
//! | PKCS#8 (`BEGIN PRIVATE KEY`, or DER) | yes | yes | with public key (2) |
//! | SEC1 (`BEGIN EC PRIVATE KEY`), named or explicit curve | yes | | |
//! | PKCS#1 (`BEGIN RSA PRIVATE KEY`) | | yes | |
//!
//! 1. Loaded, but whether it can sign depends on the backend's signatures.
//! 2. PKCS#8 v2 (RFC 8410 `OneAsymmetricKey`). A v1 key has only the seed,
//!    and computing the public key needs Ed25519 arithmetic, which SymCrypt
//!    does not expose.
//!
//! Not supported, with an error that names the symcrypt backend:
//! - Encrypted keys, with or without a password: OpenSSH keys with a cipher
//!   (bcrypt-pbkdf), PKCS#8 `EncryptedPrivateKeyInfo` (PBES2) and PEM with
//!   `Proc-Type: 4,ENCRYPTED`. They are never decrypted;
//!   `pkcs8::encode_pkcs8_encrypted` fails too.
//! - PuTTY (PPK) keys.
//! - Multi-prime RSA keys.
//!
//! Differences from the other backends:
//! - A password is ignored for unencrypted keys. The other backends reject
//!   an unencrypted PKCS#8 key when they are given a password.
//! - ssh-key rejects OpenSSH ECDSA keys whose private scalar is an mpint
//!   shorter than 32 bytes (1 in 512 P-256 keys from `ssh-keygen`). Every
//!   backend pads the scalar and parses the key again; here the scalar is
//!   also checked against the public point with SymCrypt first.
//! - A SEC1 private key may have 1 to N bytes, where N is the curve's size
//!   in bytes; leading zeros are ignored. The other backends need at least
//!   24 bytes and at most N.
//! - RSA keys from PKCS#1 and PKCS#8 are checked by SymCrypt (`n = p·q`, `e`
//!   invertible), and `iqmp` is computed. Their `d` is kept as stored.
//! - The public key of an Ed25519 PKCS#8 v2 key is checked against the seed
//!   only while ssh-key's `ed25519` feature is enabled.
//!
//! As with the other backends, OpenSSH keys are checked by ssh-key only
//! (checkints, padding, matching public key), and a SEC1 or PKCS#8 EC key's
//! public point is derived from the scalar, then compared with the embedded
//! one, if any.
//!
//! [`generate`] makes new ECDSA and RSA keys with SymCrypt for
//! [`generate_secret_key`](crate::keys::generate_secret_key): `ssh-key`'s
//! `PrivateKey::random` needs the RustCrypto algorithm crates.

use ssh_key::private::{EcdsaKeypair, KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::public::RsaPublicKey;
use ssh_key::{Algorithm, EcdsaCurve, Mpint, PrivateKey};
use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use symcrypt::errors::SymCryptError;
use symcrypt::rsa::{RsaKey, RsaKeyPairExportBlob, RsaKeyUsage};
use zeroize::{Zeroize, Zeroizing};

use crate::keys::Error;

/// The size of the RSA keys [`generate`] makes, as `ssh-key` does.
const RSA_GENERATED_BITS: u32 = 4096;

/// Generates a key pair with SymCrypt, with an empty comment: ECDSA on any
/// curve, or a 4096-bit RSA key with `e = 65537` (the hash of `algorithm`
/// doesn't matter).
///
/// Fails with `ssh_key::Error::AlgorithmUnsupported` for other algorithms,
/// and with `ssh_key::Error::Crypto` if SymCrypt fails.
pub(crate) fn generate(algorithm: &Algorithm) -> Result<PrivateKey, Error> {
    let keypair = match algorithm {
        Algorithm::Ecdsa { curve } => {
            let curve_type = match curve {
                EcdsaCurve::NistP256 => CurveType::NistP256,
                EcdsaCurve::NistP384 => CurveType::NistP384,
                EcdsaCurve::NistP521 => CurveType::NistP521,
            };
            let key = EcKey::generate_key_pair(curve_type, EcKeyUsage::EcDsa)
                .map_err(generation_error)?;
            // SymCrypt does not wipe what it exports.
            let scalar = Zeroizing::new(key.export_private_key().map_err(generation_error)?);
            KeypairData::Ecdsa(ecdsa_keypair(*curve, &scalar, None)?)
        }
        Algorithm::Rsa { .. } => {
            let key = RsaKey::generate_key_pair(RSA_GENERATED_BITS, None, RsaKeyUsage::Sign)
                .map_err(generation_error)?;
            let RsaKeyPairExportBlob {
                modulus,
                pub_exp,
                p,
                q,
                d_p,
                d_q,
                crt_coefficient,
                private_exp,
            } = key.export_key_pair_blob().map_err(generation_error)?;
            // SymCrypt does not wipe what it exports. `rsa_keypair` checks
            // the key and computes `iqmp` again.
            let [p, q, d, _d_p, _d_q, _iqmp] =
                [p, q, private_exp, d_p, d_q, crt_coefficient].map(Zeroizing::new);
            KeypairData::Rsa(rsa_keypair(&modulus, &pub_exp, &d, &p, &q)?)
        }
        _ => {
            return Err(ssh_key::Error::AlgorithmUnsupported {
                algorithm: algorithm.clone(),
            }
            .into());
        }
    };
    Ok(PrivateKey::new(keypair, "")?)
}

fn generation_error(error: SymCryptError) -> Error {
    log::error!("SymCrypt failed to generate a key: {error}");
    ssh_key::Error::Crypto.into()
}

/// Builds an ECDSA key pair from a big-endian private `scalar` (leading
/// zeros allowed) with the public point derived by SymCrypt. If `public` (a
/// SEC1 point, compressed or not) is given, it must be that point.
///
/// Fails with [`Error::KeyIsCorrupt`] if the scalar is 0 or not below the
/// group order, or if `public` does not match.
pub(crate) fn ecdsa_keypair(
    curve: EcdsaCurve,
    scalar: &[u8],
    public: Option<&[u8]>,
) -> Result<EcdsaKeypair, Error> {
    Ok(match curve {
        EcdsaCurve::NistP256 => {
            let (private, point) = ec_derive::<32>(CurveType::NistP256, scalar, public)?;
            EcdsaKeypair::NistP256 {
                public: point.as_slice().try_into()?,
                private: (*private).into(),
            }
        }
        EcdsaCurve::NistP384 => {
            let (private, point) = ec_derive::<48>(CurveType::NistP384, scalar, public)?;
            EcdsaKeypair::NistP384 {
                public: point.as_slice().try_into()?,
                private: (*private).into(),
            }
        }
        EcdsaCurve::NistP521 => {
            let (private, point) = ec_derive::<66>(CurveType::NistP521, scalar, public)?;
            EcdsaKeypair::NistP521 {
                public: point.as_slice().try_into()?,
                private: (*private).into(),
            }
        }
    })
}

/// Returns the scalar padded to `SIZE` bytes and the uncompressed public
/// point (`0x04 || x || y`).
fn ec_derive<const SIZE: usize>(
    curve: CurveType,
    scalar: &[u8],
    public: Option<&[u8]>,
) -> Result<(Zeroizing<[u8; SIZE]>, Vec<u8>), Error> {
    let digits = trim_leading_zeros(scalar);
    if digits.is_empty() || digits.len() > SIZE {
        return Err(Error::KeyIsCorrupt);
    }
    let mut padded = Zeroizing::new([0; SIZE]);
    padded
        .get_mut(SIZE - digits.len()..)
        .ok_or(Error::KeyIsCorrupt)?
        .copy_from_slice(digits);
    // SymCrypt rejects 0 and scalars not below the group order.
    let key = EcKey::set_key_pair(curve, padded.as_slice(), None, EcKeyUsage::EcDsa)
        .map_err(|_| Error::KeyIsCorrupt)?;
    let xy = key.export_public_key().map_err(|_| Error::KeyIsCorrupt)?;
    let mut point = Vec::with_capacity(1 + xy.len());
    point.push(0x04);
    point.extend_from_slice(&xy);
    if let Some(public) = public
        && !same_point(&point, public)
    {
        return Err(Error::KeyIsCorrupt);
    }
    Ok((padded, point))
}

/// Whether the SEC1 point `other` (uncompressed, or compressed: `x` and the
/// parity of `y`) is `uncompressed`.
fn same_point(uncompressed: &[u8], other: &[u8]) -> bool {
    let Some((x, y)) = uncompressed
        .split_first()
        .and_then(|(_, xy)| xy.split_at_checked(xy.len() / 2))
    else {
        return false;
    };
    match other.split_first() {
        Some((0x04, _)) => other == uncompressed,
        Some((&tag @ (0x02 | 0x03), other_x)) => {
            other_x == x && y.last().map(|last| last & 1) == Some(tag & 1)
        }
        _ => false,
    }
}

/// Builds an RSA key pair from PKCS#1 values (big-endian, leading zeros
/// allowed), after SymCrypt checks the key. `iqmp` is computed by SymCrypt;
/// `d` is kept as given.
///
/// Fails with [`Error::KeyIsCorrupt`] if SymCrypt rejects the key: `n` is not
/// `p·q`, `e` is not invertible, `e` is wider than 64 bits, or the modulus
/// size is not supported by SymCrypt.
pub(crate) fn rsa_keypair(
    n: &[u8],
    e: &[u8],
    d: &[u8],
    p: &[u8],
    q: &[u8],
) -> Result<RsaKeypair, Error> {
    if trim_leading_zeros(d).is_empty() {
        return Err(Error::KeyIsCorrupt);
    }
    let crt = rsa_crt(n, e, p, q)?;
    let public = RsaPublicKey::new(Mpint::from_positive_bytes(e), Mpint::from_positive_bytes(n))?;
    let private = RsaPrivateKey::new(
        Mpint::from_positive_bytes(d),
        Mpint::from_positive_bytes(&crt.coefficient),
        Mpint::from_positive_bytes(p),
        Mpint::from_positive_bytes(q),
    )?;
    Ok(RsaKeypair::new(public, private)?)
}

/// The CRT values of an RSA key, big-endian, possibly with leading zeros.
pub(crate) struct RsaCrt {
    /// `d mod (p - 1)`.
    pub(crate) exponent1: Zeroizing<Vec<u8>>,
    /// `d mod (q - 1)`.
    pub(crate) exponent2: Zeroizing<Vec<u8>>,
    /// `q^-1 mod p`, OpenSSH's `iqmp`.
    pub(crate) coefficient: Zeroizing<Vec<u8>>,
}

/// Imports the key into SymCrypt, which checks it (see [`rsa_keypair`]),
/// and returns its CRT values.
pub(crate) fn rsa_crt(n: &[u8], e: &[u8], p: &[u8], q: &[u8]) -> Result<RsaCrt, Error> {
    // SymCrypt takes the modulus size from the length of `n`.
    let n = trim_leading_zeros(n);
    let key =
        RsaKey::set_key_pair(n, e, p, q, RsaKeyUsage::Sign).map_err(|_| Error::KeyIsCorrupt)?;
    let RsaKeyPairExportBlob {
        modulus: _,
        pub_exp: _,
        p,
        q,
        d_p,
        d_q,
        crt_coefficient,
        private_exp,
    } = key
        .export_key_pair_blob()
        .map_err(|_| Error::KeyIsCorrupt)?;
    let crt = RsaCrt {
        exponent1: Zeroizing::new(d_p),
        exponent2: Zeroizing::new(d_q),
        coefficient: Zeroizing::new(crt_coefficient),
    };
    // SymCrypt does not wipe what it exports.
    for mut secret in [p, q, private_exp] {
        secret.zeroize();
    }
    Ok(crt)
}

fn trim_leading_zeros(mut bytes: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
}

#[cfg(test)]
mod tests {
    //! The fixtures in `russh/tests/data/keys` (comment `russh-test`,
    //! password `password` for the encrypted ones) were made with OpenSSH
    //! 10.2 and OpenSSL 3.5:
    //! - `<name>` and `<name>.pub`: `ssh-keygen -t <type> -b <bits>`.
    //!   `ecdsa-p256-short` is one whose private scalar is 31 bytes.
    //! - `<name>.pk8.pem` and `<name>.pem`: `ssh-keygen -p -m PKCS8` and
    //!   `-m PEM`; `<name>.pk8.der`: `openssl pkcs8 -topk8 -nocrypt -outform DER`.
    //! - `ecdsa-p256-nopub.pem`, `ecdsa-p256-explicit.pem`,
    //!   `ecdsa-p384-compressed.pem`: `openssl ec` with `-no_public`,
    //!   `-param_enc explicit` and `-conv_form compressed`.
    //! - `ecdsa-p256-short-unpadded.pem`: SEC1 with the 31-byte scalar, as
    //!   OpenSSL before 1.1.0 wrote it; `ed25519-v1.pk8.pem` and
    //!   `ed25519-v2.pk8.pem`: RFC 8410 without and with the public key.
    //! - `rsa-3prime.pem`: `openssl genpkey -algorithm RSA -pkeyopt
    //!   rsa_keygen_primes:3`, then `openssl pkey -traditional`.
    //! - Encrypted: `ssh-keygen -p -N password` (`-Z
    //!   chacha20-poly1305@openssh.com` for `ed25519-encrypted`, `-m PEM`
    //!   for `*-encrypted.pem`), `openssl ec -aes256`, and `openssl pkcs8
    //!   -topk8` with `-v2 aes-256-cbc` or `-scrypt`.
    //! - The other keys with a short ECDSA scalar (`*-short*`): see
    //!   `keys::format::openssh::tests`.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::path::Path;

    use der::{Decode, Encode};
    use hex_literal::hex;
    use ssh_key::private::{EcdsaKeypair, KeypairData};
    use ssh_key::{PrivateKey, PublicKey};

    use crate::keys::pkcs8::{decode_pkcs8, encode_pkcs8, encode_pkcs8_encrypted};
    use crate::keys::{Error, decode_pkcs5, decode_secret_key, encode_pkcs8_pem};

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
    }

    fn fixture(name: &str) -> String {
        String::from_utf8(fixture_bytes(name)).unwrap()
    }

    fn pem_der(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----") && !l.contains(':') && !l.is_empty())
            .collect();
        data_encoding::BASE64.decode(body.as_bytes()).unwrap()
    }

    fn load(name: &str) -> PrivateKey {
        decode_secret_key(&fixture(name), None).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn public(name: &str) -> PublicKey {
        PublicKey::from_openssh(fixture(&format!("{name}.pub")).trim()).unwrap()
    }

    fn error(result: Result<PrivateKey, Error>) -> Error {
        match result {
            Ok(key) => panic!("loaded {:?}", key.algorithm()),
            Err(error) => error,
        }
    }

    /// Every unencrypted key loads, with or without a password, and is the
    /// key `ssh-keygen` generated: same private and public parts as the
    /// OpenSSH file, and the public key of the `.pub` file.
    #[test]
    fn loads_unencrypted_keys() {
        let cases = [
            ("ecdsa-p256", "ecdsa-p256"),
            ("ecdsa-p384", "ecdsa-p384"),
            ("ecdsa-p521", "ecdsa-p521"),
            ("rsa-2048", "rsa-2048"),
            ("ed25519", "ed25519"),
            ("ecdsa-p256-short", "ecdsa-p256-short"),
            ("ecdsa-p256.pk8.pem", "ecdsa-p256"),
            ("ecdsa-p384.pk8.pem", "ecdsa-p384"),
            ("ecdsa-p521.pk8.pem", "ecdsa-p521"),
            ("rsa-2048.pk8.pem", "rsa-2048"),
            ("ecdsa-p256-short.pk8.pem", "ecdsa-p256-short"),
            ("ed25519-v2.pk8.pem", "ed25519"),
            ("ecdsa-p256.pem", "ecdsa-p256"),
            ("ecdsa-p384.pem", "ecdsa-p384"),
            ("ecdsa-p521.pem", "ecdsa-p521"),
            ("rsa-2048.pem", "rsa-2048"),
            ("ecdsa-p256-short.pem", "ecdsa-p256-short"),
            ("ecdsa-p256-nopub.pem", "ecdsa-p256"),
            ("ecdsa-p256-explicit.pem", "ecdsa-p256"),
            ("ecdsa-p384-compressed.pem", "ecdsa-p384"),
            ("ecdsa-p256-short-unpadded.pem", "ecdsa-p256-short"),
        ];
        for (file, name) in cases {
            let openssh = load(name);
            for password in [None, Some("password")] {
                let key = decode_secret_key(&fixture(file), password)
                    .unwrap_or_else(|e| panic!("{file} ({password:?}): {e}"));
                assert_eq!(
                    key.public_key().key_data(),
                    public(name).key_data(),
                    "{file}"
                );
                assert!(key.key_data() == openssh.key_data(), "{file}");
            }
        }
    }

    #[test]
    fn loads_pkcs8_der() {
        for name in ["ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "rsa-2048"] {
            let der = fixture_bytes(&format!("{name}.pk8.der"));
            let key = decode_pkcs8(&der, None).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(key.key_data() == load(name).key_data(), "{name}");
        }
    }

    /// `encode_pkcs8` writes what OpenSSL writes, and what the other
    /// backends write.
    #[test]
    fn encodes_pkcs8() {
        for name in ["ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "rsa-2048"] {
            let der = encode_pkcs8(&load(name)).unwrap();
            assert_eq!(der, fixture_bytes(&format!("{name}.pk8.der")), "{name}");
        }
        let ed25519 = load("ed25519");
        let der = encode_pkcs8(&ed25519).unwrap();
        assert_eq!(der, pem_der(&fixture("ed25519-v2.pk8.pem")));

        for name in ["ecdsa-p256", "rsa-2048", "ed25519"] {
            let key = load(name);
            let mut pem = Vec::new();
            encode_pkcs8_pem(&key, &mut pem).unwrap();
            let decoded = decode_secret_key(std::str::from_utf8(&pem).unwrap(), None).unwrap();
            assert!(decoded.key_data() == key.key_data(), "{name}");
        }
    }

    /// The P-521 private scalars `0x0102…1f` (31 bytes) and `0x0102…40` (64
    /// bytes), and their public points.
    const P521_SHORT_SCALARS: [(&[u8], [u8; 133]); 2] = [
        (
            &hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            hex!(
                "04"
                "00df"
                "3ec97448b70a1e6c7e14d18fe2e265888f0ae704e922961520b610a7248c709b"
                "a3410eca5a2d62946151b360f47f0a1dfc98632ce27f8c1d9ce1c04d47c38de3"
                "00a1"
                "d1cf55787695c49950e441f48eadf76c6948b9b7c35c5d80fceaa046ef286370"
                "404602bfee96bcfa16984c8dc0e8f67584e3b957b529c73914ce6142ea8018d7"
            ),
        ),
        (
            &hex!(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
            ),
            hex!(
                "04"
                "017f"
                "30635fc463be581744b72e0c4fa6f267b05540a38643fb4fb7bdccb3ef1ef2f2"
                "74d433ecf6e75c35e42a674aa075a4746709c75cb275dd526a2c168065aa08ed"
                "0126"
                "74797f74196eb13190bc1e7e6c93b356dd903e709b6801d62ee222ef37d3d270"
                "35ad79eceebc44289b18f45ecffe0da32dd9c0d008c5abd9354cb6b784309762"
            ),
        ),
    ];

    /// An unencrypted OpenSSH P-521 key, with `scalar` as its `mpint`.
    fn openssh_p521(scalar: &[u8], point: &[u8]) -> String {
        fn string(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
            out.extend_from_slice(bytes);
        }
        let mut public = Vec::new();
        string(&mut public, b"ecdsa-sha2-nistp521");
        string(&mut public, b"nistp521");
        string(&mut public, point);
        let mut private = [0x5a; 8].to_vec();
        private.extend_from_slice(&public);
        string(&mut private, scalar);
        string(&mut private, b"russh-test");
        let padding = (8 - private.len() % 8) % 8;
        private.extend((1..).take(padding));
        let mut key = b"openssh-key-v1\0".to_vec();
        for field in [&b"none"[..], b"none", b""] {
            string(&mut key, field);
        }
        key.extend_from_slice(&1u32.to_be_bytes());
        string(&mut key, &public);
        string(&mut key, &private);
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            data_encoding::BASE64.encode(&key)
        )
    }

    /// P-521 scalars below 2^512 are short `mpint`s (1 in 512 keys from
    /// `ssh-keygen`): ssh-key pads those of 32 bytes or more, and
    /// `pad_short_ecdsa_scalar` in `keys::format::openssh` shorter ones.
    /// Both are padded to 66 bytes, from OpenSSH and SEC1 keys, and sign.
    #[test]
    fn loads_short_p521_scalars() {
        let parameters = pem_der(&fixture("ecdsa-p521.pem"));
        let parameters = sec1::EcPrivateKey::from_der(&parameters)
            .unwrap()
            .parameters;
        for (scalar, point) in P521_SHORT_SCALARS {
            let sec1 = sec1::EcPrivateKey {
                private_key: scalar,
                parameters,
                public_key: None,
            };
            let keys = [
                decode_secret_key(&openssh_p521(scalar, &point), None).unwrap(),
                decode_pkcs8(&sec1_der(&sec1), None).unwrap(),
            ];
            for key in keys {
                let KeypairData::Ecdsa(pair @ EcdsaKeypair::NistP521 { .. }) = key.key_data()
                else {
                    panic!("not P-521");
                };
                let (zeros, digits) = pair.private_key_bytes().split_at(66 - scalar.len());
                assert!(zeros.iter().all(|&b| b == 0) && digits == scalar);
                assert_eq!(pair.public_key_bytes(), point);
                let signature = crate::crypto::sign(&key, None, b"message").unwrap();
                crate::crypto::verify(key.public_key().key_data(), b"message", &signature).unwrap();
            }
        }
    }

    #[test]
    fn rejects_encrypted_keys() {
        let cases = [
            ("ecdsa-p256-encrypted", "OpenSSH (aes256-ctr)"),
            (
                "ed25519-encrypted",
                "OpenSSH (chacha20-poly1305@openssh.com)",
            ),
            ("ecdsa-p256-short-encrypted", "OpenSSH (aes256-ctr)"),
            (
                "ecdsa-p384-short-encrypted",
                "OpenSSH (chacha20-poly1305@openssh.com)",
            ),
            ("ecdsa-p256-encrypted.pem", "PEM"),
            ("rsa-2048-encrypted.pem", "PEM"),
            ("ecdsa-p384-aes256.pem", "PEM"),
            ("ecdsa-p256-encrypted.pk8.pem", "PKCS#8"),
            ("ecdsa-p521-scrypt.pk8.pem", "PKCS#8"),
        ];
        for (file, format) in cases {
            for password in [None, Some("password")] {
                let message = error(decode_secret_key(&fixture(file), password)).to_string();
                assert!(
                    message.contains(&format!("encrypted {format} private key"))
                        && message.contains("symcrypt"),
                    "{file}: {message}"
                );
            }
        }
        let der = fixture_bytes("rsa-2048-encrypted.pk8.der");
        for password in [None, Some(&b"password"[..])] {
            let message = error(decode_pkcs8(&der, password)).to_string();
            assert!(message.contains("encrypted PKCS#8"), "{message}");
        }
        let message = error(decode_pkcs5(
            &pem_der(&fixture("rsa-2048-encrypted.pem")),
            Some("password"),
            crate::keys::Encryption::Aes128Cbc([0; 16]),
        ))
        .to_string();
        assert!(message.contains("symcrypt"), "{message}");
        let message = encode_pkcs8_encrypted(b"password", 10, &load("ecdsa-p256"))
            .unwrap_err()
            .to_string();
        assert!(message.contains("symcrypt"), "{message}");
    }

    #[test]
    fn rejects_unsupported_keys() {
        let message = error(decode_secret_key(&fixture("ed25519-v1.pk8.pem"), None)).to_string();
        assert!(
            message.contains("Ed25519") && message.contains("symcrypt"),
            "{message}"
        );
        let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n";
        let message = error(decode_secret_key(ppk, None)).to_string();
        assert!(
            message.contains("PPK") && message.contains("symcrypt"),
            "{message}"
        );
        let message = error(decode_secret_key(&fixture("rsa-3prime.pem"), None)).to_string();
        assert!(
            message.contains("multi-prime") && message.contains("symcrypt"),
            "{message}"
        );
    }

    fn sec1_der(key: &sec1::EcPrivateKey<'_>) -> Vec<u8> {
        key.to_der().unwrap()
    }

    #[test]
    fn rejects_corrupt_ec_keys() {
        let p256 = pem_der(&fixture("ecdsa-p256.pem"));
        let p256 = sec1::EcPrivateKey::from_der(&p256).unwrap();
        let other = pem_der(&fixture("ecdsa-p256-short.pem"));
        let other = sec1::EcPrivateKey::from_der(&other).unwrap();
        let p384 = pem_der(&fixture("ecdsa-p384-compressed.pem"));
        let p384 = sec1::EcPrivateKey::from_der(&p384).unwrap();
        let flipped = p384
            .public_key
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, &b)| if i == 0 { b ^ 1 } else { b })
            .collect::<Vec<u8>>();
        let corrupt = [
            sec1::EcPrivateKey {
                public_key: other.public_key,
                ..p256.clone()
            },
            sec1::EcPrivateKey {
                private_key: &[0; 32],
                ..p256.clone()
            },
            sec1::EcPrivateKey {
                private_key: &[0xff; 32],
                public_key: None,
                ..p256.clone()
            },
            sec1::EcPrivateKey {
                public_key: Some(&flipped),
                ..p384.clone()
            },
        ];
        for (i, key) in corrupt.iter().enumerate() {
            let error = error(decode_pkcs8(&sec1_der(key), None));
            assert!(matches!(error, Error::KeyIsCorrupt), "{i}: {error}");
        }
        // The point of P-256's generator is not on P-384.
        let wrong_curve = sec1::EcPrivateKey {
            parameters: p384.parameters,
            ..p256.clone()
        };
        assert!(decode_pkcs8(&sec1_der(&wrong_curve), None).is_err());
    }

    #[test]
    fn rejects_corrupt_rsa_keys() {
        let der = pem_der(&fixture("rsa-2048.pem"));
        let key = pkcs1::RsaPrivateKey::from_der(&der).unwrap();
        let swapped = pkcs1::RsaPrivateKey {
            prime2: key.prime1,
            ..key.clone()
        };
        let mut n = key.modulus.as_bytes().to_vec();
        if let Some(last) = n.last_mut() {
            *last ^= 2;
        }
        let wrong_n = pkcs1::RsaPrivateKey {
            modulus: der::asn1::UintRef::new(&n).unwrap(),
            ..key.clone()
        };
        for (i, key) in [swapped, wrong_n].iter().enumerate() {
            let pem = format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
                data_encoding::BASE64.encode(&key.to_der().unwrap())
            );
            let error = error(decode_secret_key(&pem, None));
            assert!(matches!(error, Error::KeyIsCorrupt), "{i}: {error}");
        }
    }
}
