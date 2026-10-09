//! OpenSSH interop of the SymCrypt backend's signatures: ECDSA P-256 and
//! P-384, and RSA with `rsa-sha2-256` and `rsa-sha2-512`, for host keys,
//! user keys and certificates. Both directions are covered:
//!
//! * The russh **client** against `sshd`, through `common::openssh`. It
//!   verifies host key signatures, signs publickey authentication with plain
//!   keys (loaded from OpenSSH, PKCS#8 and PEM files) and with user
//!   certificates, and fails clearly with the algorithms the backend lacks
//!   (Ed25519, ECDSA P-521 and `ssh-rsa`).
//! * The OpenSSH `ssh` client against an in-process russh **server**. The
//!   server signs with host keys and host certificates, verifies user key
//!   signatures, and verifies the CA signature of user certificates. Its
//!   handler accepts the user key or CA of the case, so a refusal can only
//!   come from the backend.
//!
//! All keys come from `ssh-keygen`. Like the harness, the tests skip when
//! OpenSSH is unavailable, and fail instead under `RUSSH_REQUIRE_SSHD=1`.
//! The server tests also need `ssh` next to `ssh-keygen`.
#![cfg(all(
    feature = "symcrypt",
    not(feature = "aws-lc-rs"),
    not(feature = "ring")
))]

mod common;

use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};
use common::openssh::{self, Case, KeyAlg, KeyFormat, KeyType, OpenSsh, Query, Refused, Sshd};
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Certificate, HashAlg, PrivateKey, PublicKey};
use russh::{ChannelId, Preferred, server};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// The signature algorithms the backend implements, with 2048- and 3072-bit
/// RSA keys.
const ALGORITHMS: [KeyAlg; 6] = [
    KeyAlg::ECDSA_P256,
    KeyAlg::ECDSA_P384,
    KeyAlg::rsa(KeyType::Rsa2048, Some(HashAlg::Sha256)),
    KeyAlg::rsa(KeyType::Rsa2048, Some(HashAlg::Sha512)),
    KeyAlg::RSA_SHA2_256,
    KeyAlg::RSA_SHA2_512,
];

/// Key types OpenSSH has and the backend lacks.
const UNSUPPORTED: [KeyType; 2] = [KeyType::Ed25519, KeyType::EcdsaP521];

/// Time limit for each `ssh` run and each russh client step.
const TIMEOUT: Duration = Duration::from_secs(120);

/// The user `ssh` logs in to the russh server as.
const USER: &str = "russh";

// ---------------------------------------------------------------------------
// The russh client against sshd
// ---------------------------------------------------------------------------

/// The client verifies sshd's host key signature with each algorithm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_verifies_host_keys() {
    openssh::check_host_keys(Case::default().with_round_trip(0), &ALGORITHMS).await;
}

/// The client signs publickey authentication to sshd with each algorithm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_signs_user_keys() {
    openssh::check_user_keys(Case::default().with_round_trip(0), &ALGORITHMS).await;
}

/// Each ECDSA or RSA host key with each ECDSA or RSA user key. The 12 cases
/// cycle through the user key file formats, so that each user key algorithm
/// is loaded from an OpenSSH, a PKCS#8 and a PEM file once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_with_each_host_and_user_key() {
    const HOST_KEYS: [KeyAlg; 3] = [KeyAlg::ECDSA_P256, KeyAlg::ECDSA_P384, KeyAlg::RSA_SHA2_512];
    const USER_KEYS: [KeyAlg; 4] = [
        KeyAlg::ECDSA_P256,
        KeyAlg::ECDSA_P384,
        KeyAlg::RSA_SHA2_256,
        KeyAlg::RSA_SHA2_512,
    ];
    const FORMATS: [KeyFormat; 3] = [KeyFormat::OpenSsh, KeyFormat::Pkcs8, KeyFormat::Pem];
    let cases = HOST_KEYS
        .into_iter()
        .flat_map(|host_key| USER_KEYS.map(|user_key| (host_key, user_key)))
        .zip(FORMATS.into_iter().cycle())
        .map(|((host_key, user_key), format)| {
            Case::default()
                .with_round_trip(0)
                .with_host_key(host_key)
                .with_user_key(user_key)
                .with_user_key_format(format)
        });
    openssh::check_cases("host and user keys", cases).await;
}

/// The client authenticates to sshd with ECDSA user certificates. RSA user
/// certificates are left out: the client names them
/// `ssh-rsa-cert-v01@openssh.com` whatever the signature, and OpenSSH no
/// longer accepts that by default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_signs_with_certificates() {
    let Some(openssh) = openssh::available() else {
        return;
    };
    let _ = env_logger::try_init();
    let mut failures = Vec::new();
    for key_type in [KeyType::EcdsaP256, KeyType::EcdsaP384] {
        if let Err(error) = certificate_login(openssh, key_type).await {
            failures.push(format!(
                "===== FAILED: {key_type} certificate =====\n{error:#}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

async fn certificate_login(openssh: &'static OpenSsh, key_type: KeyType) -> anyhow::Result<()> {
    let keys = KeyDir::new(openssh)?;
    let (ca, user) = tokio::try_join!(
        keys.generate("ca", KeyType::EcdsaP256),
        keys.generate("user", key_type),
    )?;
    let algorithm = format!("{}-cert-v01@openssh.com", key_type.openssh_name());
    let sshd = Sshd::builder()
        .config(format!(
            "TrustedUserCAKeys {}",
            public_path(&ca.path).display()
        ))
        .pubkey_accepted_algorithms(&algorithm)
        .start()
        .await?;
    let (_, certificate) = keys
        .certify("user_cert", &ca, &user, sshd.user(), &[])
        .await?;
    let mut client = sshd.connect(Preferred::default()).await?;
    let authenticating = client.handle_mut().authenticate_openssh_cert(
        sshd.user(),
        Arc::new(user.private.clone()),
        certificate,
    );
    match timeout(TIMEOUT, authenticating).await {
        Ok(Ok(result)) if result.success() => {}
        result => bail!(
            "authentication with {algorithm} failed: {result:?} (the connection ended: {:?})\n{}",
            client.disconnect_reason(),
            sshd.diagnostics()
        ),
    }
    client.check_echo().await?;
    client.disconnect().await
}

/// With Ed25519, ECDSA P-521 and `ssh-rsa` (SHA-1) user keys,
/// authentication fails with an error naming the algorithm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_refuses_unsupported_keys() {
    let Some(openssh) = openssh::available() else {
        return;
    };
    let _ = env_logger::try_init();
    let mut user_keys: Vec<KeyAlg> = supported_by(openssh, &UNSUPPORTED)
        .into_iter()
        .map(KeyAlg::new)
        .collect();
    let ssh_rsa = KeyAlg::rsa(KeyType::Rsa3072, None);
    if openssh.supports(Query::Sig, &ssh_rsa.name()) {
        user_keys.push(ssh_rsa);
    } else {
        note(&format!(
            "skipped: {} does not support {}",
            openssh.short_version(),
            ssh_rsa.name()
        ));
    }
    let mut failures = Vec::new();
    for user_key in user_keys {
        if let Err(error) = refused_user_key(user_key).await {
            failures.push(format!(
                "===== FAILED: {user_key} user key =====\n{error:#}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// sshd with only a host key algorithm the backend lacks (Ed25519, ECDSA
/// P-521, or `ssh-rsa` with SHA-1) has none in common with the client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_refuses_unsupported_host_keys() {
    openssh::check_refused(
        "unsupported host keys",
        Refused::Key,
        [
            KeyAlg::ED25519,
            KeyAlg::ECDSA_P521,
            KeyAlg::rsa(KeyType::Rsa3072, None),
        ]
        .map(|host_key| Case::default().with_host_key(host_key)),
    )
    .await;
}

/// Authenticates with `user_key` to sshd, which accepts its algorithm, so
/// that the client gets to sign.
async fn refused_user_key(user_key: KeyAlg) -> anyhow::Result<()> {
    let sshd = Sshd::builder()
        .user_key(user_key.key)
        .pubkey_accepted_algorithms(user_key.name())
        .start()
        .await?;
    let mut client = sshd.connect(Preferred::default()).await?;
    let error = match client.authenticate(user_key.rsa_hash).await {
        Ok(()) => bail!("authentication succeeded\n{}", sshd.diagnostics()),
        Err(error) => error,
    };
    // The handler records the session error, maybe after `authenticate`
    // returns.
    let started = Instant::now();
    let reason = loop {
        match client.disconnect_reason() {
            Some(reason) => break reason,
            None if started.elapsed() < Duration::from_secs(5) => {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            None => bail!(
                "authentication failed ({error:#}), but the session did not end with an error\n{}",
                sshd.diagnostics()
            ),
        }
    };
    let expected = format!("unsupported algorithm: {}", user_key.name());
    ensure!(
        reason.contains(&expected),
        "the session ended with {reason:?}, which does not contain {expected:?}\n{}",
        sshd.diagnostics()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenSSH's ssh against the russh server
// ---------------------------------------------------------------------------

/// The server signs the key exchange with each host key algorithm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_signs_host_keys() {
    let Some(setup) = Setup::new() else {
        return;
    };
    let host_types = [
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::Rsa2048,
        KeyType::Rsa3072,
    ];
    let (hosts, user) = tokio::try_join!(
        setup.keys.generate_all("host", &host_types),
        setup.keys.generate("user", KeyType::EcdsaP256),
    )
    .expect("generating keys");
    let logins = ALGORITHMS
        .iter()
        .map(|algorithm| Login {
            host_key_algorithm: algorithm.name(),
            ..Login::new(
                format!("host key {algorithm}"),
                find(&hosts, algorithm.key),
                &user,
            )
        })
        .collect();
    setup.check("server host keys", logins).await;
}

/// The server presents host certificates, and signs the key exchange with
/// the certified key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_signs_with_host_certificates() {
    let Some(setup) = Setup::new() else {
        return;
    };
    let host_types = [KeyType::EcdsaP256, KeyType::EcdsaP384, KeyType::Rsa2048];
    let (hosts, ca, user) = tokio::try_join!(
        setup.keys.generate_all("host", &host_types),
        setup.keys.generate("ca", KeyType::EcdsaP256),
        setup.keys.generate("user", KeyType::EcdsaP256),
    )
    .expect("generating keys");
    let mut certified = Vec::new();
    for host in &hosts {
        let name = format!("{}_cert", host.name);
        let (_, certificate) = setup
            .keys
            .certify(&name, &ca, host, "127.0.0.1", &["-h"])
            .await
            .expect("certifying a host key");
        certified.push((host, certificate));
    }
    let algorithms = [
        KeyAlg::ECDSA_P256,
        KeyAlg::ECDSA_P384,
        KeyAlg::rsa(KeyType::Rsa2048, Some(HashAlg::Sha256)),
        KeyAlg::rsa(KeyType::Rsa2048, Some(HashAlg::Sha512)),
    ];
    let logins = algorithms
        .iter()
        .map(|algorithm| {
            let (host, certificate) = certified
                .iter()
                .find(|(host, _)| host.key_type == algorithm.key)
                .expect("a certified host key");
            Login {
                config: server_config(&host.private, Some(certificate.clone())),
                known_host: format!("@cert-authority * {}", ca.public_line),
                host_key_algorithm: format!("{}-cert-v01@openssh.com", algorithm.name()),
                ..Login::new(format!("host certificate {algorithm}"), host, &user)
            }
        })
        .collect();
    setup.check("server host certificates", logins).await;
}

/// The server verifies user key signatures with each algorithm, and refuses
/// the key types the backend lacks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_verifies_user_keys() {
    let Some(setup) = Setup::new() else {
        return;
    };
    let unsupported = supported_by(setup.openssh, &UNSUPPORTED);
    let mut user_types = vec![
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::Rsa2048,
        KeyType::Rsa3072,
    ];
    user_types.extend(&unsupported);
    let (host, users) = tokio::try_join!(
        setup.keys.generate("host", KeyType::EcdsaP256),
        setup.keys.generate_all("user", &user_types),
    )
    .expect("generating keys");
    let accepted = ALGORITHMS.iter().map(|algorithm| Login {
        user_key_algorithm: algorithm.name(),
        ..Login::new(
            format!("user key {algorithm}"),
            &host,
            find(&users, algorithm.key),
        )
    });
    let refused = unsupported.iter().map(|&key_type| Login {
        expect: Expect::Denied,
        ..Login::new(
            format!("user key {} (refused)", key_type.openssh_name()),
            &host,
            find(&users, key_type),
        )
    });
    setup
        .check("server user keys", accepted.chain(refused).collect())
        .await;
}

/// The server verifies the CA signature of user certificates with each
/// algorithm, and refuses certificates signed with an algorithm the backend
/// lacks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_verifies_certificate_cas() {
    let Some(setup) = Setup::new() else {
        return;
    };
    let unsupported = supported_by(setup.openssh, &UNSUPPORTED);
    // The CA and its signature algorithm, the `ssh-keygen -s` options that
    // select it, and whether the server accepts it.
    let mut cases: Vec<(KeyAlg, &[&str], Expect)> = vec![
        (KeyAlg::ECDSA_P256, &[][..], Expect::Success),
        (KeyAlg::ECDSA_P384, &[][..], Expect::Success),
        (
            KeyAlg::RSA_SHA2_256,
            &["-t", "rsa-sha2-256"][..],
            Expect::Success,
        ),
        (
            KeyAlg::RSA_SHA2_512,
            &["-t", "rsa-sha2-512"][..],
            Expect::Success,
        ),
        (
            KeyAlg::rsa(KeyType::Rsa3072, None),
            &["-t", "ssh-rsa"][..],
            Expect::Denied,
        ),
    ];
    cases.extend(
        unsupported
            .iter()
            .map(|&key_type| (KeyAlg::new(key_type), &[][..], Expect::Denied)),
    );
    let mut ca_types = vec![KeyType::EcdsaP256, KeyType::EcdsaP384, KeyType::Rsa3072];
    ca_types.extend(&unsupported);
    let (host, user, cas) = tokio::try_join!(
        setup.keys.generate("host", KeyType::EcdsaP256),
        setup.keys.generate("user", KeyType::EcdsaP256),
        setup.keys.generate_all("ca", &ca_types),
    )
    .expect("generating keys");
    let mut logins = Vec::new();
    for (algorithm, options, expect) in cases {
        let ca = find(&cas, algorithm.key);
        let name = format!("user_cert_{}", algorithm.name());
        let (identity, _) = setup
            .keys
            .certify(&name, ca, &user, USER, options)
            .await
            .expect("certifying the user key");
        let refused = if expect == Expect::Denied {
            " (refused)"
        } else {
            ""
        };
        logins.push(Login {
            handler: Server {
                user_key: None,
                ca: Some(ca.private.public_key().key_data().clone()),
            },
            identity,
            user_key_algorithm: "ecdsa-sha2-nistp256-cert-v01@openssh.com".into(),
            expect,
            ..Login::new(format!("CA {algorithm}{refused}"), &host, &user)
        });
    }
    setup.check("server certificate CAs", logins).await;
}

/// What a login of `ssh` to the russh server must lead to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// Authentication succeeds and the command runs.
    Success,
    /// The server refuses the offered key: "Permission denied".
    Denied,
}

/// One login of OpenSSH's `ssh` to an in-process russh server, with the
/// host key and user key algorithms forced on the `ssh` side.
struct Login {
    label: String,
    config: Arc<server::Config>,
    handler: Server,
    /// The `known_hosts` line that `ssh` checks the host key with.
    known_host: String,
    host_key_algorithm: String,
    /// The private user key. `ssh` also offers `<identity>-cert.pub`.
    identity: PathBuf,
    user_key_algorithm: String,
    expect: Expect,
}

impl Login {
    /// `ssh` logs in with the plain key `user` to a server with the plain
    /// host key `host`, with the algorithm named after each key's type.
    fn new(label: String, host: &Key, user: &Key) -> Login {
        Login {
            label,
            config: server_config(&host.private, None),
            handler: Server {
                user_key: Some(user.private.public_key().key_data().clone()),
                ca: None,
            },
            known_host: format!("* {}", host.public_line),
            host_key_algorithm: KeyAlg::new(host.key_type).name(),
            identity: user.path.clone(),
            user_key_algorithm: KeyAlg::new(user.key_type).name(),
            expect: Expect::Success,
        }
    }

    /// Serves one connection on a new port and runs `ssh -v` against it,
    /// with a command that the server echoes. Then checks the result
    /// against [`Self::expect`] and that the forced host key algorithm was
    /// negotiated.
    async fn run(self, ssh: &Path, dir: &Path) -> anyhow::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("binding a port")?;
        let port = listener.local_addr()?.port();
        let (config, handler) = (self.config.clone(), self.handler.clone());
        let mut server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.context("accepting")?;
            let session = server::run_stream(config, socket, handler)
                .await
                .context("starting the session")?;
            session.await.context("the session failed")
        });

        let known_hosts = dir.join(format!("known_hosts_{port}"));
        fs::write(&known_hosts, format!("{}\n", self.known_host)).context("writing known_hosts")?;
        let options = [
            "BatchMode=yes".to_owned(),
            "StrictHostKeyChecking=yes".into(),
            format!("UserKnownHostsFile=\"{}\"", known_hosts.display()),
            "GlobalKnownHostsFile=/dev/null".into(),
            "UpdateHostKeys=no".into(),
            "CheckHostIP=no".into(),
            format!("HostKeyAlgorithms={}", self.host_key_algorithm),
            format!("PubkeyAcceptedAlgorithms={}", self.user_key_algorithm),
            "IdentitiesOnly=yes".into(),
            "IdentityAgent=none".into(),
            format!("IdentityFile=\"{}\"", self.identity.display()),
            "PreferredAuthentications=publickey".into(),
            "PasswordAuthentication=no".into(),
            "KbdInteractiveAuthentication=no".into(),
            "ConnectTimeout=30".into(),
        ];
        let command = format!("russh-symcrypt-{port}");
        let mut ssh_command = Command::new(ssh);
        ssh_command
            .args(["-F", "none", "-v", "-n", "-T", "-p"])
            .arg(port.to_string());
        for option in &options {
            ssh_command.arg("-o").arg(option);
        }
        ssh_command
            .arg(format!("{USER}@127.0.0.1"))
            .arg(&command)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = timeout(TIMEOUT, ssh_command.output()).await;

        let server_result = match timeout(Duration::from_secs(10), &mut server).await {
            Ok(Ok(Ok(()))) => "ended normally".to_owned(),
            Ok(Ok(Err(error))) => format!("ended with an error: {error:#}"),
            Ok(Err(error)) => format!("task failed: {error}"),
            Err(_) => {
                server.abort();
                "was still running".to_owned()
            }
        };
        let output = match output {
            Ok(output) => output.with_context(|| format!("running {}", ssh.display()))?,
            Err(_) => bail!("ssh timed out after {TIMEOUT:?}; the server {server_result}"),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let kex = format!("kex: host key algorithm: {}", self.host_key_algorithm);
        let (passed, expected) = match self.expect {
            Expect::Success => (
                output.status.success()
                    && stdout == format!("{command}\n")
                    && stderr.contains(&kex),
                "the command to run",
            ),
            Expect::Denied => (
                !output.status.success()
                    && stdout.is_empty()
                    && stderr.contains(&kex)
                    && stderr.contains("Offering public key")
                    && stderr.contains("Permission denied"),
                "the server to refuse the key",
            ),
        };
        ensure!(
            passed,
            "expected {expected} after a key exchange with {}, but ssh exited with {}, stdout \
             {stdout:?}; the server {server_result}\n----- ssh -v -----\n{stderr}----- end of \
             ssh -v -----",
            self.host_key_algorithm,
            output.status,
        );
        Ok(())
    }
}

fn server_config(host_key: &PrivateKey, certificate: Option<Certificate>) -> Arc<server::Config> {
    Arc::new(server::Config {
        keys: vec![host_key.clone()],
        certificates: certificate.into_iter().collect(),
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(TIMEOUT),
        ..Default::default()
    })
}

/// A russh server handler that accepts one user key, or the certificates of
/// one CA, and answers `exec` requests by echoing the command.
#[derive(Clone)]
struct Server {
    user_key: Option<KeyData>,
    ca: Option<KeyData>,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(accept_if(self.user_key.as_ref() == Some(key.key_data())))
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        certificate: &Certificate,
    ) -> Result<server::Auth, Self::Error> {
        Ok(accept_if(
            self.ca.as_ref() == Some(certificate.signature_key()),
        ))
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let mut output = data.to_vec();
        output.push(b'\n');
        session.channel_success(channel)?;
        session.data(channel, output)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)
    }
}

fn accept_if(accept: bool) -> server::Auth {
    if accept {
        server::Auth::Accept
    } else {
        server::Auth::reject()
    }
}

/// What the server tests need: OpenSSH with its `ssh` client, and a
/// directory for keys.
struct Setup {
    openssh: &'static OpenSsh,
    ssh: PathBuf,
    keys: KeyDir,
}

impl Setup {
    /// `None`, after reporting a skip, if OpenSSH or its `ssh` is missing.
    fn new() -> Option<Setup> {
        let openssh = openssh::available()?;
        let ssh = openssh.ssh_keygen.with_file_name("ssh");
        if !ssh.is_file() {
            openssh::skip(&format!("{} not found", ssh.display()));
            return None;
        }
        let _ = env_logger::try_init();
        let keys = KeyDir::new(openssh).expect("creating a directory for keys");
        Some(Setup { openssh, ssh, keys })
    }

    /// Runs the logins, a few at a time. Then prints a summary and panics
    /// with the details of each failed login.
    async fn check(&self, name: &str, logins: Vec<Login>) {
        let jobs = Arc::new(Semaphore::new(4));
        let tasks: Vec<_> = logins
            .into_iter()
            .map(|login| {
                let label = login.label.clone();
                let (jobs, ssh, dir) = (jobs.clone(), self.ssh.clone(), self.keys.root.clone());
                let task = tokio::spawn(async move {
                    let _permit = jobs.acquire_owned().await;
                    let started = Instant::now();
                    login.run(&ssh, &dir).await.map(|()| started.elapsed())
                });
                (label, task)
            })
            .collect();
        let total = tasks.len();
        let mut summary = String::new();
        let mut failures = Vec::new();
        for (label, task) in tasks {
            let error = match task.await {
                Ok(Ok(elapsed)) => {
                    let _ = writeln!(
                        summary,
                        "  ok       {label} ({:.2}s)",
                        elapsed.as_secs_f64()
                    );
                    continue;
                }
                Ok(Err(error)) => format!("{error:#}"),
                Err(error) => format!("the login task failed: {error}"),
            };
            let _ = writeln!(summary, "  FAILED   {label}");
            failures.push(format!("===== FAILED: {label} =====\n{error}"));
        }
        note(&format!(
            "symcrypt_signatures: {name} against {}: {} passed, {} failed\n{summary}",
            self.openssh.short_version(),
            total - failures.len(),
            failures.len()
        ));
        assert!(
            failures.is_empty(),
            "{name}: {} of {total} login(s) failed:\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A key pair generated by `ssh-keygen`, and loaded by russh.
struct Key {
    name: String,
    key_type: KeyType,
    /// The private key file. The public key is next to it, in `.pub`.
    path: PathBuf,
    /// The line of the `.pub` file.
    public_line: String,
    private: PrivateKey,
}

fn find(keys: &[Key], key_type: KeyType) -> &Key {
    keys.iter()
        .find(|key| key.key_type == key_type)
        .unwrap_or_else(|| panic!("no {key_type} key was generated"))
}

/// The key types in `key_types` that OpenSSH implements. Reports the
/// others, which are skipped even under `RUSSH_REQUIRE_SSHD`, as the harness
/// does with algorithms.
fn supported_by(openssh: &OpenSsh, key_types: &[KeyType]) -> Vec<KeyType> {
    let (supported, missing): (Vec<KeyType>, Vec<KeyType>) = key_types
        .iter()
        .copied()
        .partition(|key_type| openssh.supports(Query::Key, key_type.openssh_name()));
    for key_type in missing {
        note(&format!(
            "skipped: {} does not support {}",
            openssh.short_version(),
            key_type.openssh_name()
        ));
    }
    supported
}

/// A temporary directory for keys, certificates and `known_hosts` files.
struct KeyDir {
    _dir: tempfile::TempDir,
    root: PathBuf,
    ssh_keygen: PathBuf,
}

impl KeyDir {
    fn new(openssh: &OpenSsh) -> anyhow::Result<KeyDir> {
        let dir = tempfile::Builder::new()
            .prefix("russh-signatures-")
            .tempdir()
            .context("creating a temporary directory for keys")?;
        let root = dir.path().canonicalize()?;
        Ok(KeyDir {
            _dir: dir,
            root,
            ssh_keygen: openssh.ssh_keygen.clone(),
        })
    }

    fn ssh_keygen(&self) -> Command {
        let mut command = Command::new(&self.ssh_keygen);
        command.stdin(Stdio::null()).kill_on_drop(true);
        command
    }

    /// Generates a key pair with `ssh-keygen` and loads it with russh.
    async fn generate(&self, name: impl Into<String>, key_type: KeyType) -> anyhow::Result<Key> {
        let name = name.into();
        let path = self.root.join(&name);
        let mut attempt = 1;
        loop {
            let mut command = self.ssh_keygen();
            command
                .args(["-q", "-N", "", "-C", &name])
                .args(key_type.keygen_args())
                .arg("-f")
                .arg(&path);
            run(command).await?;
            match russh::keys::load_secret_key(&path, None) {
                Ok(private) => {
                    let public_line = fs::read_to_string(public_path(&path))?.trim().to_owned();
                    return Ok(Key {
                        name,
                        key_type,
                        path,
                        public_line,
                        private,
                    });
                }
                // The ssh-key bug with short ECDSA P-256 scalars, see
                // common/openssh.rs: 1 in 512 keys.
                Err(_) if attempt < 5 => {
                    attempt += 1;
                    fs::remove_file(&path)?;
                    fs::remove_file(public_path(&path))?;
                }
                Err(error) => bail!("russh cannot load {}: {error}", path.display()),
            }
        }
    }

    /// Generates a key of each type, concurrently, named `{prefix}_{type}`.
    async fn generate_all(&self, prefix: &str, key_types: &[KeyType]) -> anyhow::Result<Vec<Key>> {
        futures::future::try_join_all(
            key_types
                .iter()
                .map(|&key_type| self.generate(format!("{prefix}_{key_type}"), key_type)),
        )
        .await
    }

    /// Copies `key` to `name` and signs the copy of its public key with
    /// `ca` (`ssh-keygen -s`) for `principal`, which writes
    /// `name-cert.pub`. Returns the path of the copied private key and the
    /// certificate. `options` go to `ssh-keygen`, e.g. `-h` for a host
    /// certificate or `-t rsa-sha2-256` for the signature algorithm of an
    /// RSA CA.
    ///
    /// `ssh -o IdentityFile=name` offers the certificate and signs with the
    /// private key next to it, even when `PubkeyAcceptedAlgorithms` allows
    /// only the certificate algorithm. With `CertificateFile` it would need
    /// the plain key, which that filter drops.
    async fn certify(
        &self,
        name: &str,
        ca: &Key,
        key: &Key,
        principal: &str,
        options: &[&str],
    ) -> anyhow::Result<(PathBuf, Certificate)> {
        let identity = self.root.join(name);
        ensure!(identity != key.path, "{name} would overwrite the key");
        // `fs::copy` keeps the mode, which `ssh` checks: 0600.
        fs::copy(&key.path, &identity).context("copying a private key")?;
        let public = public_path(&identity);
        fs::copy(public_path(&key.path), &public).context("copying a public key")?;
        let mut command = self.ssh_keygen();
        command
            .arg("-q")
            .arg("-s")
            .arg(&ca.path)
            .args(options)
            .args(["-I", name, "-n", principal])
            .arg(&public);
        run(command).await?;
        let path = self.root.join(format!("{name}-cert.pub"));
        let certificate = russh::keys::load_openssh_certificate(&path)
            .with_context(|| format!("loading {}", path.display()))?;
        Ok((identity, certificate))
    }
}

/// Runs `command` and fails unless it succeeds.
async fn run(mut command: Command) -> anyhow::Result<()> {
    let output = command
        .output()
        .await
        .with_context(|| format!("running {:?}", command.as_std()))?;
    ensure!(
        output.status.success(),
        "{:?} failed with {}: {}{}",
        command.as_std(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim(),
        String::from_utf8_lossy(&output.stdout).trim(),
    );
    Ok(())
}

fn public_path(private_key: &Path) -> PathBuf {
    let mut path = private_key.as_os_str().to_owned();
    path.push(".pub");
    path.into()
}

/// Writes straight to stderr, bypassing libtest's capture, like the
/// harness's summaries.
fn note(message: &str) {
    let _ = writeln!(std::io::stderr().lock(), "[openssh-interop] {message}");
}
