//! OpenSSH interop of `russh::keys::certificate`, with CA keys of every type
//! the backend signs with:
//!
//! * `sshd` accepts user certificates made by `certificate::sign`
//!   (`TrustedUserCAKeys`), and refuses one from a CA it doesn't trust.
//! * A russh client checks the host certificate `sshd` presents, made by
//!   `certificate::sign`, with `certificate::validate_host`.
//! * Certificates made by `ssh-keygen -s` pass `certificate::validate`,
//!   `check_principal` and `validate_host`.
//!
//! Like the harness, the tests skip when OpenSSH is unavailable, and fail
//! instead under `RUSSH_REQUIRE_SSHD=1`.
#![cfg(unix)]

mod common;

use std::borrow::Cow;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use common::openssh::{self, OpenSsh, STEP_TIMEOUT, Sshd};
use russh::keys::certificate::{self, Builder, CertType, Field, UserOptions};
use russh::keys::key::safe_rng;
use russh::keys::{
    Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey, PublicKey, PublicKeyOrCertificate,
    known_host_ca_keys_path, ssh_key,
};
use russh::{Disconnect, Preferred, client};
use tokio::time::timeout;

/// A CA key from `tests/data/keys`.
struct Ca {
    name: &'static str,
    /// The OpenSSH private key file.
    file: &'static str,
    key: PrivateKey,
}

impl Ca {
    fn new(name: &'static str, file: &'static str) -> Ca {
        let key = russh::keys::decode_secret_key(file, None).unwrap();
        Ca { name, file, key }
    }

    fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    /// The algorithm of the signatures this CA makes with
    /// `certificate::sign` and, by default, `ssh-keygen -s`.
    fn signature_algorithm(&self) -> Algorithm {
        match self.key.algorithm() {
            Algorithm::Rsa { .. } => Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            algorithm => algorithm,
        }
    }
}

/// CA keys of every type.
fn cas() -> [Ca; 5] {
    [
        Ca::new("ed25519", include_str!("data/keys/ed25519")),
        Ca::new("ecdsa-p256", include_str!("data/keys/ecdsa-p256")),
        Ca::new("ecdsa-p384", include_str!("data/keys/ecdsa-p384")),
        Ca::new("ecdsa-p521", include_str!("data/keys/ecdsa-p521")),
        Ca::new("rsa-2048", include_str!("data/keys/rsa-2048")),
    ]
}

/// A CA key that no test trusts.
fn untrusted_ca() -> Ca {
    Ca::new("untrusted", include_str!("data/test-keys/ecdsa-p256-1"))
}

/// Whether the backend signs and verifies `algorithm`. RSA needs the `rsa`
/// feature, except with SymCrypt.
fn supported(algorithm: &Algorithm) -> bool {
    Preferred::DEFAULT.key.contains(algorithm)
        && (!matches!(algorithm, Algorithm::Rsa { .. })
            || cfg!(any(feature = "rsa", russh_backend = "symcrypt")))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A temporary directory with an absolute path, as `sshd` needs.
fn temp_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("russh-certificates-")
        .tempdir()
        .unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

/// Writes a private key file with the mode OpenSSH requires: 0600.
fn write_private_key(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// A certificate for `key`, valid from a minute ago for ten minutes.
fn new_certificate(
    key: &PublicKey,
    cert_type: CertType,
    key_id: &str,
    principals: &[&str],
) -> Builder {
    let now = now();
    let mut builder =
        Builder::new_with_random_nonce(&mut safe_rng(), key, now - 60, now + 600).unwrap();
    builder.cert_type(cert_type).unwrap();
    builder.key_id(key_id).unwrap();
    for principal in principals {
        builder.valid_principal(*principal).unwrap();
    }
    builder
}

/// Logs in to `sshd` with `certificate` for its user key, then runs a
/// command.
async fn certificate_login(
    sshd: &Sshd,
    user_key: &PrivateKey,
    certificate: Certificate,
) -> anyhow::Result<()> {
    let mut client = sshd.connect(Preferred::default()).await?;
    let authenticating = client.handle_mut().authenticate_openssh_cert(
        sshd.user(),
        Arc::new(user_key.clone()),
        certificate,
    );
    match timeout(STEP_TIMEOUT, authenticating).await {
        Ok(Ok(result)) if result.success() => {}
        result => anyhow::bail!(
            "authentication failed: {result:?} (the connection ended: {:?})",
            client.disconnect_reason()
        ),
    }
    client.check_echo().await?;
    client.disconnect().await
}

/// `sshd` accepts the user certificates of `certificate::sign`, and refuses
/// one from a CA it doesn't trust.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sshd_accepts_user_certificates() {
    let Some(_) = openssh::available() else {
        return;
    };
    let (cas, unsupported): (Vec<Ca>, Vec<Ca>) = cas()
        .into_iter()
        .partition(|ca| supported(&ca.signature_algorithm()));
    for ca in &unsupported {
        openssh::log_line(&format!("no {} CA with this backend", ca.name));
    }
    let (_dir, root) = temp_dir();
    let trusted = root.join("trusted_user_ca_keys");
    let lines: Vec<String> = cas
        .iter()
        .map(|ca| ca.public_key().to_openssh().unwrap())
        .collect();
    fs::write(&trusted, lines.join("\n") + "\n").unwrap();
    // Only certificates: the user key in `authorized_keys` doesn't log in.
    let sshd = Sshd::builder()
        .config(format!("TrustedUserCAKeys {}", trusted.display()))
        .pubkey_accepted_algorithms("ecdsa-sha2-nistp256-cert-v01@openssh.com")
        .start()
        .await
        .unwrap();
    let user_key = russh::keys::load_secret_key(sshd.user_key().1, None).unwrap();

    let mut failures = Vec::new();
    for ca in &cas {
        let builder = new_certificate(
            user_key.public_key(),
            CertType::User,
            &format!("{} user", ca.name),
            &[sshd.user()],
        );
        let certificate = certificate::sign(builder, &ca.key).unwrap();
        if let Err(error) = certificate_login(&sshd, &user_key, certificate).await {
            failures.push(format!("{} CA: {error:#}", ca.name));
        }
    }
    let untrusted = untrusted_ca();
    let builder = new_certificate(
        user_key.public_key(),
        CertType::User,
        "untrusted user",
        &[sshd.user()],
    );
    let certificate = certificate::sign(builder, &untrusted.key).unwrap();
    if certificate_login(&sshd, &user_key, certificate)
        .await
        .is_ok()
    {
        failures.push("logged in with a certificate from an untrusted CA".into());
    }
    assert!(
        failures.is_empty(),
        "{}\n{}",
        failures.join("\n"),
        sshd.diagnostics()
    );
}

/// Checks the host certificate of the server with
/// `certificate::validate_host`, and records the result.
struct HostCertificateClient {
    host: &'static str,
    trusted_cas: Vec<PublicKey>,
    result: Arc<Mutex<Option<ssh_key::Result<()>>>>,
}

impl client::Handler for HostCertificateClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let result = match server_key.certificate() {
            Some(cert) => certificate::validate_host(cert, self.host, &self.trusted_cas),
            None => Err(ssh_key::Error::CertificateValidation),
        };
        let accepted = result.is_ok();
        *self.result.lock().unwrap() = Some(result);
        Ok(accepted)
    }
}

/// Connects to `sshd` as `host`, asking for an ECDSA P-384 host
/// certificate, and returns what `validate_host` said about it.
async fn check_host_certificate(
    sshd: &Sshd,
    host: &'static str,
    trusted_cas: &[&PublicKey],
) -> ssh_key::Result<()> {
    let mut config = client::Config::default();
    config.preferred.host_key_certificates = Cow::Owned(vec![Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    }]);
    let result = Arc::new(Mutex::new(None));
    let handler = HostCertificateClient {
        host,
        trusted_cas: trusted_cas.iter().map(|&ca| ca.clone()).collect(),
        result: result.clone(),
    };
    let connecting = client::connect(Arc::new(config), sshd.addr(), handler);
    let connected = timeout(STEP_TIMEOUT, connecting)
        .await
        .expect("connecting timed out");
    let checked = result.lock().unwrap().take();
    match (connected, checked) {
        (Ok(handle), Some(Ok(()))) => {
            handle
                .disconnect(Disconnect::ByApplication, "", "")
                .await
                .unwrap();
            Ok(())
        }
        (Err(_), Some(Err(error))) => Err(error),
        (Ok(_), checked) => panic!("connected, but the host key check said {checked:?}"),
        (Err(error), checked) => {
            panic!("connecting failed ({error}), but the host key check said {checked:?}")
        }
    }
}

/// A russh client checks the host certificate `sshd` presents, made by
/// `certificate::sign`, with `certificate::validate_host`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_validates_host_certificate() {
    let Some(_) = openssh::available() else {
        return;
    };
    let ca = Ca::new("ecdsa-p256", include_str!("data/keys/ecdsa-p256"));
    let host_key =
        russh::keys::decode_secret_key(include_str!("data/keys/ecdsa-p384"), None).unwrap();
    let builder = new_certificate(
        host_key.public_key(),
        CertType::Host,
        "sshd",
        &["localhost", "127.0.0.1"],
    );
    let host_certificate = certificate::sign(builder, &ca.key).unwrap();
    let (_dir, root) = temp_dir();
    let host_key_path = root.join("host_ecdsa-p384");
    write_private_key(&host_key_path, include_str!("data/keys/ecdsa-p384"));
    let host_certificate_path = root.join("host_ecdsa-p384-cert.pub");
    fs::write(
        &host_certificate_path,
        host_certificate.to_openssh().unwrap() + "\n",
    )
    .unwrap();
    // The configuration of the harness adds an ECDSA P-256 host key, which
    // sshd won't use: it presents only the certificate.
    let sshd = Sshd::builder()
        .config(format!("HostKey {}", host_key_path.display()))
        .config(format!(
            "HostCertificate {}",
            host_certificate_path.display()
        ))
        .host_key_algorithms("ecdsa-sha2-nistp384-cert-v01@openssh.com")
        .start()
        .await
        .unwrap();

    let trusted = [ca.public_key()];
    let untrusted = untrusted_ca();
    let known_hosts = root.join("known_hosts");
    fs::write(
        &known_hosts,
        format!(
            "@cert-authority [localhost]:{},127.0.0.1 {}\n",
            sshd.addr().port(),
            ca.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    let ca_from_known_hosts: Vec<PublicKey> =
        known_host_ca_keys_path("localhost", sshd.addr().port(), &known_hosts)
            .unwrap()
            .into_iter()
            .map(|(_, k)| k)
            .collect();
    assert_eq!(ca_from_known_hosts.len(), 1);
    assert_eq!(
        ca_from_known_hosts[0].key_data(),
        ca.public_key().key_data()
    );
    let ca_refs: Vec<&PublicKey> = ca_from_known_hosts.iter().collect();

    for (host, trusted_cas, expected) in [
        ("localhost", &ca_refs[..], Ok(())),
        ("127.0.0.1", &trusted[..], Ok(())),
        (
            "other.example.com",
            &trusted[..],
            Err(Field::ValidPrincipals.invalid_error()),
        ),
        (
            "localhost",
            &[untrusted.public_key()][..],
            Err(Field::SignatureKey.invalid_error()),
        ),
    ] {
        let result = check_host_certificate(&sshd, host, trusted_cas).await;
        assert_eq!(result, expected, "{host}\n{}", sshd.diagnostics());
    }
}

/// Runs `ssh-keygen` and fails unless it succeeds.
fn ssh_keygen(openssh: &OpenSsh, args: &[&str]) {
    let output = Command::new(&openssh.ssh_keygen)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ssh-keygen {args:?} failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

/// The certificate `ssh-keygen -s` makes with `ca` for the public key in
/// `subject`, a file under `root` named after `name`. `options` go to
/// `ssh-keygen`.
fn ssh_keygen_certificate(
    openssh: &OpenSsh,
    root: &Path,
    ca: &Ca,
    subject: &str,
    name: &str,
    options: &[&str],
) -> Certificate {
    let ca_path = root.join(ca.name);
    if !ca_path.exists() {
        write_private_key(&ca_path, ca.file);
    }
    let public_path = root.join(format!("{name}.pub"));
    fs::write(&public_path, subject).unwrap();
    let mut args = vec!["-q", "-s", ca_path.to_str().unwrap(), "-I", name];
    args.extend(["-V", "-5m:+1h"]);
    args.extend(options);
    args.push(public_path.to_str().unwrap());
    ssh_keygen(openssh, &args);
    russh::keys::load_openssh_certificate(root.join(format!("{name}-cert.pub"))).unwrap()
}

/// Certificates made by `ssh-keygen -s` pass `certificate::validate`,
/// `check_principal` and `validate_host` if the backend implements the
/// signature algorithm of the CA, and fail with `AlgorithmUnsupported`
/// otherwise.
#[test]
fn ssh_keygen_certificates_validate() {
    let Some(openssh) = openssh::available() else {
        return;
    };
    let (_dir, root) = temp_dir();
    let subject = include_str!("data/keys/ecdsa-p384.pub");
    let untrusted = untrusted_ca();
    let mut checked = Vec::new();
    for ca in &cas() {
        let mut signature_algorithms = vec![(ca.signature_algorithm(), None)];
        if matches!(ca.key.algorithm(), Algorithm::Rsa { .. }) {
            signature_algorithms.extend([
                (
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    Some("rsa-sha2-256"),
                ),
                (Algorithm::Rsa { hash: None }, Some("ssh-rsa")),
            ]);
        }
        for (algorithm, option) in signature_algorithms {
            let name = format!("{}-{}", ca.name, algorithm.as_str());
            let mut user_options = vec!["-n", "alice,bob"];
            let mut host_options = vec!["-h", "-n", "host.example.com,*.example.org"];
            if let Some(option) = option {
                user_options.extend(["-t", option]);
                host_options.extend(["-t", option]);
            }
            let user = ssh_keygen_certificate(
                openssh,
                &root,
                ca,
                subject,
                &format!("{name}-user"),
                &user_options,
            );
            let host = ssh_keygen_certificate(
                openssh,
                &root,
                ca,
                subject,
                &format!("{name}-host"),
                &host_options,
            );
            assert_eq!(user.signature().algorithm(), algorithm);
            assert_eq!(host.signature().algorithm(), algorithm);
            let trusted = [ca.public_key()];

            // SHA-1 is refused, like OpenSSH's `CASignatureAlgorithms` does.
            if !supported(&algorithm) || algorithm == (Algorithm::Rsa { hash: None }) {
                let unsupported = Err(ssh_key::Error::AlgorithmUnsupported { algorithm });
                assert_eq!(certificate::validate(&user, trusted), unsupported, "{name}");
                assert_eq!(
                    certificate::validate_host(&host, "host.example.com", trusted),
                    unsupported,
                    "{name}"
                );
                continue;
            }

            assert_eq!(certificate::validate(&user, trusted), Ok(()), "{name}");
            let now = now();
            assert_eq!(
                certificate::validate_at(&user, now - 3600, trusted),
                Err(Field::ValidAfter.invalid_error()),
                "{name}"
            );
            assert_eq!(
                certificate::validate_at(&user, now + 7200, trusted),
                Err(Field::ValidBefore.invalid_error()),
                "{name}"
            );
            assert_eq!(
                certificate::validate(&user, [untrusted.public_key()]),
                Err(Field::SignatureKey.invalid_error()),
                "{name}"
            );
            for principal in ["alice", "bob"] {
                assert_eq!(
                    certificate::check_principal(&user, CertType::User, principal),
                    Ok(()),
                    "{name}"
                );
                assert_eq!(
                    certificate::validate_user(&user, principal, None, trusted),
                    Ok(UserOptions {
                        force_command: None,
                        source_address: None,
                        verify_required: false,
                        permit_x11_forwarding: true,
                        permit_agent_forwarding: true,
                        permit_port_forwarding: true,
                        permit_pty: true,
                        permit_user_rc: true,
                        no_touch_required: false,
                    }),
                    "{name}"
                );
            }
            assert_eq!(
                certificate::check_principal(&user, CertType::User, "carol"),
                Err(Field::ValidPrincipals.invalid_error()),
                "{name}"
            );
            assert_eq!(
                certificate::check_principal(&user, CertType::Host, "alice"),
                Err(Field::Type.invalid_error()),
                "{name}"
            );

            for host_name in ["host.example.com", "HOST.example.com", "www.example.org"] {
                assert_eq!(
                    certificate::validate_host(&host, host_name, trusted),
                    Ok(()),
                    "{name}: {host_name}"
                );
            }
            for host_name in ["example.org", "other.example.com"] {
                assert_eq!(
                    certificate::validate_host(&host, host_name, trusted),
                    Err(Field::ValidPrincipals.invalid_error()),
                    "{name}: {host_name}"
                );
            }
            assert_eq!(
                certificate::validate_host(&user, "alice", trusted),
                Err(Field::Type.invalid_error()),
                "{name}"
            );
            checked.push(name);
        }
    }
    openssh::log_line(&format!(
        "certificates from {} validated: {}",
        openssh.short_version(),
        checked.join(", ")
    ));
}
