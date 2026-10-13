//! Signing and validating OpenSSH certificates with russh's crypto backend.
//!
//! `ssh-key` signs certificates ([`Builder::sign`]) and validates them
//! ([`Certificate::validate`]) with its own RustCrypto code. That bypasses
//! the crypto backend russh was built with, and with the `symcrypt` backend
//! it doesn't work at all. These functions do the same work through the
//! backend:
//!
//! - [`sign`] signs the certificate a [`Builder`] describes with a CA key.
//! - [`validate`] and [`validate_at`] check that a certificate is signed by a
//!   trusted CA and within its validity period.
//! - [`check_principal`] checks the type of a certificate, and that a user or
//!   host name is one of its principals.
//! - [`validate_host`] does all of that for the host certificate a server
//!   presents to a client.
//!
//! The CA key can be of any type the backend signs with (see the algorithm
//! tables of the README). With `aws-lc-rs` and `ring`, RSA needs the `rsa`
//! feature.
//!
//! # Errors
//!
//! The functions return [`ssh_key::Error`]s. A certificate that fails a check
//! gives [`ssh_key::Error::CertificateFieldInvalid`] with the [`Field`] at
//! fault:
//!
//! | Field | The certificate |
//! |---|---|
//! | [`SignatureKey`](Field::SignatureKey) | is signed by a CA that isn't trusted. |
//! | [`Signature`](Field::Signature) | has an invalid CA signature: it was changed after signing. |
//! | [`ValidAfter`](Field::ValidAfter) | isn't valid yet. |
//! | [`ValidBefore`](Field::ValidBefore) | has expired. |
//! | [`Type`](Field::Type) | is a user certificate where a host certificate is expected, or the reverse. |
//! | [`ValidPrincipals`](Field::ValidPrincipals) | isn't valid for the user or host name. |
//! | [`CriticalOptions`](Field::CriticalOptions) | is a host certificate with critical options. |
//!
//! [`ssh_key::Error::AlgorithmUnsupported`] means that the backend can't sign
//! or verify with the CA's algorithm, or that the CA signature uses SHA-1
//! (`ssh-rsa` or `ssh-dss`), which OpenSSH refuses too.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! use russh::keys::certificate::{self, Builder, CertType};
//! use russh::keys::key::safe_rng;
//! use russh::keys::load_secret_key;
//!
//! let ca = load_secret_key("tests/data/keys/ecdsa-p256", None)?;
//! let user_key = load_secret_key("tests/data/keys/ecdsa-p384", None)?;
//!
//! // A user certificate for `alice`, valid for an hour.
//! let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
//! let mut builder =
//!     Builder::new_with_random_nonce(&mut safe_rng(), user_key.public_key(), now, now + 3600)?;
//! builder.cert_type(CertType::User)?;
//! builder.key_id("alice@example.com")?;
//! builder.valid_principal("alice")?;
//! let cert = certificate::sign(builder, &ca)?;
//!
//! // What a server that trusts `ca` checks when `alice` logs in with it.
//! certificate::validate(&cert, [ca.public_key()])?;
//! certificate::check_principal(&cert, CertType::User, "alice")?;
//! assert!(certificate::check_principal(&cert, CertType::User, "bob").is_err());
//! # Ok(())
//! # }
//! ```

use std::cell::RefCell;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use ssh_encoding::Encode;
pub use ssh_key::certificate::{Builder, CertType, Field};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey, Signature};

/// Signs the certificate that `builder` describes with the private key of
/// the CA, through the crypto backend.
///
/// RSA CA keys sign with `rsa-sha2-512`, like `ssh-keygen`. The builder's
/// comment is not kept: set it with [`Certificate::set_comment`].
///
/// # Errors
///
/// - The errors of [`Builder::sign`] for invalid fields, e.g.
///   [`Field::ValidPrincipals`] when no principal is set.
/// - [`ssh_key::Error::AlgorithmUnsupported`] if the backend can't sign with
///   the CA key, or for a DSA CA key: [`validate`] and OpenSSH refuse its
///   SHA-1 signatures.
/// - [`ssh_key::Error::Encrypted`] if the CA key is encrypted.
pub fn sign(builder: Builder, ca: &PrivateKey) -> ssh_key::Result<Certificate> {
    let algorithm = ca.algorithm();
    let hash_alg = match algorithm {
        Algorithm::Dsa => return Err(ssh_key::Error::AlgorithmUnsupported { algorithm }),
        Algorithm::Rsa { .. } => Some(HashAlg::Sha512),
        _ => None,
    };
    let mut encoded = signed_data(builder, ca.public_key().key_data())?;
    let signature = crate::crypto::sign(ca, hash_alg, &encoded)?;
    signature.encode_prefixed(&mut encoded)?;
    let certificate = Certificate::from_bytes(&encoded)?;
    // A faulty signature can leak the private key (e.g. an RSA-CRT fault):
    // never hand one out.
    crate::crypto::verify_certificate(&certificate).map_err(|_| ssh_key::Error::Crypto)?;
    Ok(certificate)
}

/// Checks that `certificate` is signed by one of the `trusted_cas` and valid
/// now. See [`validate_at`].
///
/// # Errors
///
/// Those of [`validate_at`], or [`ssh_key::Error::Time`] if the system clock
/// is set before 1970.
pub fn validate<'a, I>(certificate: &Certificate, trusted_cas: I) -> ssh_key::Result<()>
where
    I: IntoIterator<Item = &'a PublicKey>,
{
    validate_at(certificate, now()?, trusted_cas)
}

/// Checks that `certificate` is signed by one of the `trusted_cas` and valid
/// at `unix_timestamp`.
///
/// These are the checks of [`Certificate::validate_at`], with three
/// differences: the CA key is compared with the trusted keys themselves
/// rather than their fingerprints, the crypto backend verifies the
/// signature, and SHA-1 CA signatures (`ssh-rsa` and `ssh-dss`) are refused,
/// as by OpenSSH's default `CASignatureAlgorithms`.
///
/// <div class="warning">
///
/// That's not enough to trust a certificate. Also check its type and
/// principal with [`check_principal`], and that its critical options are
/// ones you implement: OpenSSH defines `force-command`, `source-address` and
/// `verify-required` for user certificates. [`validate_host`] does all of
/// that for host certificates.
///
/// </div>
///
/// # Errors
///
/// The first check that fails, in this order (see the
/// [module documentation](self#errors)): [`Field::SignatureKey`],
/// [`Field::Signature`] or [`ssh_key::Error::AlgorithmUnsupported`], then
/// [`Field::ValidAfter`] or [`Field::ValidBefore`].
pub fn validate_at<'a, I>(
    certificate: &Certificate,
    unix_timestamp: u64,
    trusted_cas: I,
) -> ssh_key::Result<()>
where
    I: IntoIterator<Item = &'a PublicKey>,
{
    let ca = certificate.signature_key();
    if !trusted_cas
        .into_iter()
        .any(|trusted| trusted.key_data() == ca)
    {
        return Err(Field::SignatureKey.invalid_error());
    }
    verify_signature(certificate)?;
    // PROTOCOL.certkeys: valid after <= current time < valid before.
    if unix_timestamp < certificate.valid_after() {
        return Err(Field::ValidAfter.invalid_error());
    }
    if unix_timestamp >= certificate.valid_before() {
        return Err(Field::ValidBefore.invalid_error());
    }
    Ok(())
}

/// Checks that `certificate` is of type `cert_type` and valid for
/// `principal`: a user name for a user certificate, a host name for a host
/// certificate.
///
/// The rules are those of current OpenSSH. A user name must be one of the
/// principals. The principals of a host certificate are patterns in which
/// `*` matches any sequence of bytes and `?` any single byte. Matching is
/// case-sensitive. A certificate without principals is valid for no one
/// (older OpenSSH versions accepted it for anyone).
///
/// This checks neither the signature nor the validity period: see
/// [`validate`].
///
/// # Errors
///
/// [`Field::Type`] for a certificate of the other type, or
/// [`Field::ValidPrincipals`] if `principal` doesn't match.
pub fn check_principal(
    certificate: &Certificate,
    cert_type: CertType,
    principal: &str,
) -> ssh_key::Result<()> {
    if certificate.cert_type() != cert_type {
        return Err(Field::Type.invalid_error());
    }
    let mut principals = certificate.valid_principals().iter();
    let matches = match cert_type {
        CertType::User => principals.any(|valid| valid == principal),
        CertType::Host => {
            principals.any(|valid| matches_pattern(valid.as_bytes(), principal.as_bytes()))
        }
    };
    if matches {
        Ok(())
    } else {
        Err(Field::ValidPrincipals.invalid_error())
    }
}

/// Checks a host certificate the way `ssh` does: [`validate`] it, then check
/// that it's a host certificate for `host` ([`check_principal`]), without
/// critical options.
///
/// `host` is the name or IP address the client connects to, without port or
/// brackets. Like `ssh`, this compares names in lowercase, and IP addresses
/// in their canonical form.
///
/// A client gets host certificates only if it asks for them with
/// [`Preferred::host_key_certificates`](crate::Preferred::host_key_certificates).
/// It can then check them in
/// [`check_server_key`](crate::client::Handler::check_server_key):
///
/// ```
/// use russh::client;
/// use russh::keys::certificate::{self, Field};
/// use russh::keys::{PublicKey, PublicKeyOrCertificate, check_known_hosts, ssh_key};
///
/// struct Client {
///     host: String,
///     port: u16,
///     /// The CAs trusted to sign host certificates.
///     host_cas: Vec<PublicKey>,
/// }
///
/// impl client::Handler for Client {
///     type Error = russh::Error;
///
///     async fn check_server_key(
///         &mut self,
///         server_key: &PublicKeyOrCertificate,
///     ) -> Result<bool, Self::Error> {
///         if let Some(cert) = server_key.certificate() {
///             match certificate::validate_host(cert, &self.host, &self.host_cas) {
///                 Ok(()) => return Ok(true),
///                 // Like `ssh`, fall back to known_hosts when the CA isn't
///                 // trusted.
///                 Err(ssh_key::Error::CertificateFieldInvalid(Field::SignatureKey)) => {}
///                 Err(e) => {
///                     eprintln!("invalid host certificate for {}: {e}", self.host);
///                     return Ok(false);
///                 }
///             }
///         }
///         Ok(check_known_hosts(&self.host, self.port, &server_key.public_key())?)
///     }
/// }
/// ```
///
/// # Errors
///
/// Those of [`validate`], then those of [`check_principal`], then
/// [`Field::CriticalOptions`] (see the [module documentation](self#errors)).
pub fn validate_host<'a, I>(
    certificate: &Certificate,
    host: &str,
    trusted_cas: I,
) -> ssh_key::Result<()>
where
    I: IntoIterator<Item = &'a PublicKey>,
{
    validate_host_at(certificate, host, now()?, trusted_cas)
}

fn validate_host_at<'a, I>(
    certificate: &Certificate,
    host: &str,
    unix_timestamp: u64,
    trusted_cas: I,
) -> ssh_key::Result<()>
where
    I: IntoIterator<Item = &'a PublicKey>,
{
    validate_at(certificate, unix_timestamp, trusted_cas)?;
    check_principal(certificate, CertType::Host, &canonical_host(host))?;
    if !certificate.critical_options().is_empty() {
        return Err(Field::CriticalOptions.invalid_error());
    }
    Ok(())
}

fn now() -> ssh_key::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| ssh_key::Error::Time)
}

/// Verifies the CA signature of `certificate` with the crypto backend.
fn verify_signature(certificate: &Certificate) -> ssh_key::Result<()> {
    let algorithm = certificate.signature().algorithm();
    // Otherwise some backends would report an unsupported algorithm.
    let consistent = match (&algorithm, certificate.signature_key().algorithm()) {
        (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
        (signature, key) => *signature == key,
    };
    if !consistent {
        return Err(Field::Signature.invalid_error());
    }
    if matches!(algorithm, Algorithm::Rsa { hash: None } | Algorithm::Dsa) {
        return Err(ssh_key::Error::AlgorithmUnsupported { algorithm });
    }
    crate::crypto::verify_certificate(certificate).map_err(|error| {
        match ssh_key::Error::from(error) {
            ssh_key::Error::AlgorithmUnsupported { .. } => {
                ssh_key::Error::AlgorithmUnsupported { algorithm }
            }
            _ => Field::Signature.invalid_error(),
        }
    })
}

/// Records the data that [`Builder::sign`] asks it to sign, then fails, so
/// that the builder doesn't go on to check the signature with RustCrypto.
struct Capture<'a> {
    ca: &'a KeyData,
    data: RefCell<Option<Vec<u8>>>,
}

impl signature::Signer<Signature> for Capture<'_> {
    fn try_sign(&self, data: &[u8]) -> signature::Result<Signature> {
        self.data.replace(Some(data.to_vec()));
        Err(signature::Error::new())
    }
}

impl From<&Capture<'_>> for KeyData {
    fn from(capture: &Capture<'_>) -> Self {
        capture.ca.clone()
    }
}

/// The data that `ca` signs for the certificate `builder` describes: its
/// encoding up to the signature.
fn signed_data(builder: Builder, ca: &KeyData) -> ssh_key::Result<Vec<u8>> {
    let capture = Capture {
        ca,
        data: RefCell::new(None),
    };
    let error = builder.sign(&capture).err();
    capture
        .data
        .into_inner()
        .ok_or_else(|| error.unwrap_or(ssh_key::Error::Signature))
}

/// `host` the way `ssh` matches it with principals: an IP address in its
/// canonical form, a name in lowercase.
fn canonical_host(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(address) => address.to_string(),
        Err(_) => host.to_ascii_lowercase(),
    }
}

/// Whether `name` matches `pattern`, in which `*` matches any sequence of
/// bytes and `?` any single byte: OpenSSH's `match_pattern`.
fn matches_pattern(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    // After a `*`: the pattern position after it, and the name position it
    // has matched up to.
    let mut star = None;
    loop {
        match (pattern.get(p), name.get(n)) {
            (None, None) => return true,
            (Some(b'*'), _) => {
                p += 1;
                star = Some((p, n));
            }
            (Some(&expected), Some(&byte)) if expected == b'?' || expected == byte => {
                p += 1;
                n += 1;
            }
            // Let the last `*` match one more byte, if there is one.
            _ => match star {
                Some((after_star, matched)) if matched < name.len() => {
                    p = after_star;
                    n = matched + 1;
                    star = Some((p, n));
                }
                _ => return false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    /// The time of the tests: certificates are valid from `NOW - 60` to
    /// `NOW + 3600` (excluded).
    const NOW: u64 = 1_700_000_000;

    macro_rules! key {
        ($name:literal) => {
            crate::keys::decode_secret_key(
                include_str!(concat!("../../tests/data/keys/", $name)),
                None,
            )
            .unwrap()
        };
    }

    fn subject() -> PublicKey {
        PublicKey::from_openssh(include_str!("../../tests/data/keys/ecdsa-p384.pub")).unwrap()
    }

    fn builder(cert_type: CertType, principals: &[&str]) -> Builder {
        let mut builder = Builder::new(vec![7; 32], subject(), NOW - 60, NOW + 3600).unwrap();
        builder.cert_type(cert_type).unwrap();
        builder.key_id("test").unwrap();
        for principal in principals {
            builder.valid_principal(*principal).unwrap();
        }
        builder
    }

    fn signature_algorithm(ca: &PrivateKey) -> Algorithm {
        match ca.algorithm() {
            Algorithm::Rsa { .. } => Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            algorithm => algorithm,
        }
    }

    fn can_sign(ca: &PrivateKey) -> bool {
        let algorithm = signature_algorithm(ca);
        crate::crypto::is_supported_signature_algorithm(&algorithm)
            && (!algorithm.is_rsa() || cfg!(any(feature = "rsa", russh_backend = "symcrypt")))
    }

    /// The certificate `builder` describes, with `signature` as the
    /// signature of `ca`.
    fn with_signature(builder: Builder, ca: &PublicKey, signature: Signature) -> Certificate {
        let mut encoded = signed_data(builder, ca.key_data()).unwrap();
        signature.encode_prefixed(&mut encoded).unwrap();
        Certificate::from_bytes(&encoded).unwrap()
    }

    #[test]
    fn sign_and_validate() {
        let cas = [
            key!("ed25519"),
            key!("ecdsa-p256"),
            key!("ecdsa-p384"),
            key!("ecdsa-p521"),
            key!("rsa-2048"),
        ];
        for ca in &cas {
            let algorithm = signature_algorithm(ca);
            let signed = sign(builder(CertType::User, &["alice"]), ca);
            if !can_sign(ca) {
                assert_eq!(
                    signed,
                    Err(ssh_key::Error::AlgorithmUnsupported { algorithm })
                );
                continue;
            }
            let cert = signed.unwrap();
            assert_eq!(cert.signature().algorithm(), algorithm);
            assert_eq!(cert.signature_key(), ca.public_key().key_data());
            assert_eq!(cert.public_key(), subject().key_data());
            assert_eq!(cert.valid_principals(), ["alice"]);
            assert_eq!(validate_at(&cert, NOW, [ca.public_key()]), Ok(()));
            assert_eq!(check_principal(&cert, CertType::User, "alice"), Ok(()));
            assert_eq!(
                Certificate::from_openssh(&cert.to_openssh().unwrap()).unwrap(),
                cert
            );
            // ssh-key agrees, where it can verify signatures.
            #[cfg(not(russh_backend = "symcrypt"))]
            cert.validate_at(NOW, [&ca.public_key().fingerprint(HashAlg::Sha256)])
                .unwrap();
        }
    }

    #[test]
    fn sign_errors() {
        let ca = key!("ecdsa-p256");
        let no_principals = Builder::new(vec![7; 32], subject(), NOW, NOW + 60).unwrap();
        assert_eq!(
            sign(no_principals, &ca),
            Err(Field::ValidPrincipals.invalid_error())
        );

        let encrypted =
            PrivateKey::from_openssh(include_str!("../../tests/data/keys/ed25519-encrypted"))
                .unwrap();
        assert!(encrypted.is_encrypted());
        assert_eq!(
            sign(builder(CertType::User, &["alice"]), &encrypted),
            Err(ssh_key::Error::Encrypted)
        );
    }

    #[test]
    fn validity_period() {
        let ca = key!("ecdsa-p256");
        let trusted = [ca.public_key()];
        let cert = sign(builder(CertType::User, &["alice"]), &ca).unwrap();
        assert_eq!(validate_at(&cert, NOW - 60, trusted), Ok(()));
        assert_eq!(validate_at(&cert, NOW + 3599, trusted), Ok(()));
        let not_yet = Err(Field::ValidAfter.invalid_error());
        assert_eq!(validate_at(&cert, NOW - 61, trusted), not_yet);
        assert_eq!(validate_at(&cert, 0, trusted), not_yet);
        let expired = Err(Field::ValidBefore.invalid_error());
        assert_eq!(validate_at(&cert, NOW + 3600, trusted), expired);
        assert_eq!(validate_at(&cert, u64::MAX, trusted), expired);
        assert_eq!(validate(&cert, trusted), expired);

        // OpenSSH's "forever".
        let mut builder = Builder::new(vec![7; 32], subject(), 0, u64::MAX).unwrap();
        builder.valid_principal("alice").unwrap();
        let forever = sign(builder, &ca).unwrap();
        assert_eq!(validate(&forever, trusted), Ok(()));
        assert_eq!(validate_at(&forever, 0, trusted), Ok(()));
    }

    #[test]
    fn untrusted_ca() {
        let ca = key!("ecdsa-p256");
        let other = crate::keys::decode_secret_key(
            include_str!("../../tests/data/test-keys/ecdsa-p256-1"),
            None,
        )
        .unwrap();
        let cert = sign(builder(CertType::User, &["alice"]), &ca).unwrap();
        let untrusted = Err(Field::SignatureKey.invalid_error());
        assert_eq!(validate_at(&cert, NOW, [other.public_key()]), untrusted);
        assert_eq!(
            validate_at(&cert, NOW, std::iter::empty::<&PublicKey>()),
            untrusted
        );
        assert_eq!(
            validate_at(&cert, NOW, [other.public_key(), ca.public_key()]),
            Ok(())
        );
        // Comments don't matter.
        let mut renamed = ca.public_key().clone();
        renamed.set_comment("renamed");
        assert_eq!(validate_at(&cert, NOW, [&renamed]), Ok(()));
    }

    #[test]
    fn tampered_certificate() {
        let ca = key!("ecdsa-p256");
        let encoded = sign(builder(CertType::User, &["alice"]), &ca)
            .unwrap()
            .to_bytes()
            .unwrap();
        let find = |needle: &[u8]| {
            encoded
                .windows(needle.len())
                .position(|window| window == needle)
                .unwrap()
        };
        let principal = find(b"alice");
        let valid_before = find(&(NOW + 3600).to_be_bytes()) + 7;
        let signature = encoded.len() - 1;
        for offset in [principal, valid_before, signature] {
            let mut tampered = encoded.clone();
            tampered[offset] ^= 1;
            let tampered = Certificate::from_bytes(&tampered).unwrap();
            assert_eq!(
                validate_at(&tampered, NOW, [ca.public_key()]),
                Err(Field::Signature.invalid_error()),
                "byte {offset} changed"
            );
        }
    }

    #[test]
    fn forged_signatures() {
        let validate_with = |ca: &PrivateKey, signature: Signature| {
            let cert = with_signature(
                builder(CertType::User, &["alice"]),
                ca.public_key(),
                signature,
            );
            validate_at(&cert, NOW, [ca.public_key()])
        };

        let zeros = Signature::new(Algorithm::Ed25519, vec![0; 64]).unwrap();
        let expected = if crate::crypto::is_supported_signature_algorithm(&Algorithm::Ed25519) {
            Field::Signature.invalid_error()
        } else {
            ssh_key::Error::AlgorithmUnsupported {
                algorithm: Algorithm::Ed25519,
            }
        };
        assert_eq!(
            validate_with(&key!("ed25519"), zeros.clone()),
            Err(expected)
        );

        // A signature of another algorithm than the CA key's.
        assert_eq!(
            validate_with(&key!("ecdsa-p256"), zeros),
            Err(Field::Signature.invalid_error())
        );

        // SHA-1 is refused before the signature is verified.
        let ssh_rsa = Algorithm::Rsa { hash: None };
        let signature = Signature::new(ssh_rsa.clone(), vec![1; 256]).unwrap();
        assert_eq!(
            validate_with(&key!("rsa-2048"), signature),
            Err(ssh_key::Error::AlgorithmUnsupported { algorithm: ssh_rsa })
        );
    }

    #[test]
    fn user_principals() {
        let ca = key!("ecdsa-p256");
        let cert = sign(builder(CertType::User, &["alice", "bob"]), &ca).unwrap();
        assert_eq!(check_principal(&cert, CertType::User, "alice"), Ok(()));
        assert_eq!(check_principal(&cert, CertType::User, "bob"), Ok(()));
        let mismatch = Err(Field::ValidPrincipals.invalid_error());
        for name in ["carol", "Alice", "alice ", ""] {
            assert_eq!(check_principal(&cert, CertType::User, name), mismatch);
        }
        assert_eq!(
            check_principal(&cert, CertType::Host, "alice"),
            Err(Field::Type.invalid_error())
        );

        // No patterns in user certificates.
        let star = sign(builder(CertType::User, &["*"]), &ca).unwrap();
        assert_eq!(check_principal(&star, CertType::User, "alice"), mismatch);
        assert_eq!(check_principal(&star, CertType::User, "*"), Ok(()));
    }

    #[test]
    fn no_principals_match_no_one() {
        let ca = key!("ecdsa-p256");
        for cert_type in [CertType::User, CertType::Host] {
            let mut builder = builder(cert_type, &[]);
            builder.all_principals_valid().unwrap();
            let cert = sign(builder, &ca).unwrap();
            assert!(cert.valid_principals().is_empty());
            for name in ["alice", "localhost", "*", ""] {
                assert_eq!(
                    check_principal(&cert, cert_type, name),
                    Err(Field::ValidPrincipals.invalid_error())
                );
            }
        }
    }

    #[test]
    fn host_principal_patterns() {
        let ca = key!("ecdsa-p256");
        let principals = ["server.example.com", "*.example.org", "host?.example.net"];
        let cert = sign(builder(CertType::Host, &principals), &ca).unwrap();
        for name in [
            "server.example.com",
            "www.example.org",
            "a.b.example.org",
            ".example.org",
            "host1.example.net",
        ] {
            assert_eq!(
                check_principal(&cert, CertType::Host, name),
                Ok(()),
                "{name}"
            );
        }
        for name in [
            "SERVER.example.com",
            "other.example.com",
            "example.org",
            "host.example.net",
            "host12.example.net",
        ] {
            assert_eq!(
                check_principal(&cert, CertType::Host, name),
                Err(Field::ValidPrincipals.invalid_error()),
                "{name}"
            );
        }
        assert_eq!(
            check_principal(&cert, CertType::User, "server.example.com"),
            Err(Field::Type.invalid_error())
        );
    }

    #[test]
    fn patterns() {
        for (pattern, name, expected) in [
            ("", "", true),
            ("", "a", false),
            ("abc", "abc", true),
            ("abc", "abd", false),
            ("abc", "ab", false),
            ("a?c", "abc", true),
            ("?", "", false),
            ("*", "", true),
            ("*", "abc", true),
            ("**", "abc", true),
            ("a*", "", false),
            ("*?", "", false),
            ("*a", "aaa", true),
            ("a*b*c", "aXbYc", true),
            ("a*b*c", "aXbYcZ", false),
            ("a*b*c", "abcbc", true),
            ("*.example.org", "example.org", false),
        ] {
            assert_eq!(
                matches_pattern(pattern.as_bytes(), name.as_bytes()),
                expected,
                "{pattern:?} with {name:?}"
            );
        }
    }

    #[test]
    fn host_certificates() {
        let ca = key!("ecdsa-p256");
        let trusted = [ca.public_key()];
        let principals = [
            "server.example.com",
            "*.example.org",
            "192.0.2.1",
            "2001:db8::1",
        ];
        let cert = sign(builder(CertType::Host, &principals), &ca).unwrap();
        for host in [
            "server.example.com",
            "SERVER.Example.COM",
            "www.example.org",
            "192.0.2.1",
            "2001:DB8:0::1",
        ] {
            assert_eq!(
                validate_host_at(&cert, host, NOW, trusted),
                Ok(()),
                "{host}"
            );
        }
        for host in [
            "other.example.com",
            "example.org",
            "192.0.2.10",
            "2001:db8::2",
            "[2001:db8::1]",
            "server.example.com:22",
        ] {
            assert_eq!(
                validate_host_at(&cert, host, NOW, trusted),
                Err(Field::ValidPrincipals.invalid_error()),
                "{host}"
            );
        }

        let host = "server.example.com";
        assert_eq!(
            validate_host_at(&cert, host, NOW, std::iter::empty::<&PublicKey>()),
            Err(Field::SignatureKey.invalid_error())
        );
        let expired = Err(Field::ValidBefore.invalid_error());
        assert_eq!(validate_host_at(&cert, host, NOW + 3600, trusted), expired);
        assert_eq!(validate_host(&cert, host, trusted), expired);

        let user_cert = sign(builder(CertType::User, &[host]), &ca).unwrap();
        assert_eq!(
            validate_host_at(&user_cert, host, NOW, trusted),
            Err(Field::Type.invalid_error())
        );

        let mut builder = builder(CertType::Host, &[host]);
        builder.critical_option("force-command", "true").unwrap();
        let with_option = sign(builder, &ca).unwrap();
        assert_eq!(validate_at(&with_option, NOW, trusted), Ok(()));
        assert_eq!(
            validate_host_at(&with_option, host, NOW, trusted),
            Err(Field::CriticalOptions.invalid_error())
        );
    }
}
