//! OpenSSH's `ssh` logs into a real sshd with an RSA key that the russh agent
//! server ([`russh::keys::agent::server::serve`]) holds.
//!
//! `ssh` asks the agent for an `rsa-sha2-256` or `rsa-sha2-512` signature
//! through the flags of `SSH_AGENTC_SIGN_REQUEST`, and rejects a signature of
//! another type (<https://github.com/cataggar/russh/issues/29>). sshd and
//! `ssh` both allow only the algorithm under test, and `ssh` has no key but
//! the agent's.
#![cfg(all(unix, any(feature = "rsa", russh_backend = "symcrypt")))]

mod common;

use std::process::Stdio;

use anyhow::{Context as _, ensure};
use common::openssh::{self, KeyType, Sshd};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::server;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::time::timeout;
use tokio_stream::wrappers::UnixListenerStream;

#[tokio::test]
async fn ssh_signs_with_rsa_sha2_256_through_the_russh_agent() {
    check_login("rsa-sha2-256").await;
}

#[tokio::test]
async fn ssh_signs_with_rsa_sha2_512_through_the_russh_agent() {
    check_login("rsa-sha2-512").await;
}

async fn check_login(algorithm: &str) {
    let Some(openssh) = openssh::available() else {
        return;
    };
    let ssh = openssh.ssh_keygen.with_file_name("ssh");
    if !ssh.is_file() {
        openssh::skip(&format!("{} not found", ssh.display()));
        return;
    }
    if let Err(error) = log_in(&ssh, algorithm).await {
        panic!("{algorithm}: {error:#}");
    }
}

async fn log_in(ssh: &std::path::Path, algorithm: &str) -> anyhow::Result<()> {
    let sshd = Sshd::builder()
        .user_key(KeyType::Rsa3072)
        .pubkey_accepted_algorithms(algorithm)
        .start()
        .await?;
    let socket = sshd.dir().join("agent.sock");
    let listener = UnixListener::bind(&socket).context("binding the agent socket")?;
    let agent = tokio::spawn(server::serve(UnixListenerStream::new(listener), ()));
    let key = sshd.load_user_key(None)?;
    AgentClient::connect_uds(&socket)
        .await?
        .add_identity(&key, &[])
        .await
        .context("adding the user key to the agent")?;

    let output = Command::new(ssh)
        .env("SSH_AUTH_SOCK", &socket)
        .args(["-F", "/dev/null", "-v", "-T"])
        .args(["-o", "BatchMode=yes"])
        .args(["-o", "IdentityFile=none"])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "GlobalKnownHostsFile=/dev/null"])
        .args(["-o", "PreferredAuthentications=publickey"])
        .arg("-o")
        .arg(format!("PubkeyAcceptedAlgorithms={algorithm}"))
        .arg("-p")
        .arg(sshd.addr().port().to_string())
        .args(["-l", sshd.user()])
        .arg(sshd.addr().ip().to_string())
        .arg("echo agent-ok")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let output = timeout(openssh::STEP_TIMEOUT, output)
        .await
        .context("ssh timed out")?
        .with_context(|| format!("running {}", ssh.display()))?;
    agent.abort();
    ensure!(
        output.status.success() && output.stdout == b"agent-ok\n",
        "ssh exited with {}\n----- ssh stdout -----\n{}\n----- ssh stderr -----\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        sshd.diagnostics(),
    );
    Ok(())
}

/// `ssh-add` loads both a private key and its `-cert.pub` certificate into
/// russh's agent server ( preserving comments in `ssh-add -L`), and `ssh`
/// logs into an `sshd` that trusts only the user CA using the certificate
/// held by russh's agent.
#[tokio::test]
async fn ssh_adds_certificates_and_logs_in_through_the_russh_agent() {
    let Some(openssh) = openssh::available() else {
        return;
    };
    let ssh = openssh.ssh_keygen.with_file_name("ssh");
    let ssh_add = openssh.ssh_keygen.with_file_name("ssh-add");
    for bin in [&ssh, &ssh_add] {
        if !bin.is_file() {
            openssh::skip(&format!("{} not found", bin.display()));
            return;
        }
    }
    for key_type in [KeyType::EcdsaP256, KeyType::Rsa3072] {
        if let Err(error) = check_cert_login(&ssh, &ssh_add, key_type).await {
            panic!("{key_type}: {error:#}");
        }
    }
}

async fn check_cert_login(
    ssh: &std::path::Path,
    ssh_add: &std::path::Path,
    key_type: KeyType,
) -> anyhow::Result<()> {
    let sshd = Sshd::builder()
        .user_key(key_type)
        .user_ca(KeyType::EcdsaP256)
        .config("AuthorizedKeysFile none")
        .start()
        .await?;
    let socket = sshd.dir().join("agent.sock");
    let listener = UnixListener::bind(&socket).context("binding the agent socket")?;
    let agent = tokio::spawn(server::serve(UnixListenerStream::new(listener), ()));

    let (_, key_path) = sshd.user_key();
    let add_out = timeout(
        openssh::STEP_TIMEOUT,
        Command::new(ssh_add)
            .env("SSH_AUTH_SOCK", &socket)
            .arg(key_path)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("ssh-add timed out")?
    .context("running ssh-add")?;
    ensure!(
        add_out.status.success(),
        "ssh-add failed with {}: {}",
        add_out.status,
        String::from_utf8_lossy(&add_out.stderr)
    );

    let list_out = timeout(
        openssh::STEP_TIMEOUT,
        Command::new(ssh_add)
            .env("SSH_AUTH_SOCK", &socket)
            .arg("-L")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("ssh-add -L timed out")?
    .context("running ssh-add -L")?;
    let listed = String::from_utf8_lossy(&list_out.stdout);
    ensure!(
        list_out.status.success() && listed.contains("-cert-v01@openssh.com"),
        "ssh-add -L did not list certificate:\nstdout: {listed}\nstderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );

    let output = timeout(
        openssh::STEP_TIMEOUT,
        Command::new(ssh)
            .env("SSH_AUTH_SOCK", &socket)
            .args(["-F", "/dev/null", "-v", "-T"])
            .args(["-o", "BatchMode=yes"])
            .args(["-o", "IdentityFile=none"])
            .args(["-o", "StrictHostKeyChecking=no"])
            .args(["-o", "UserKnownHostsFile=/dev/null"])
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .args(["-o", "PreferredAuthentications=publickey"])
            .arg("-p")
            .arg(sshd.addr().port().to_string())
            .args(["-l", sshd.user()])
            .arg(sshd.addr().ip().to_string())
            .arg("echo agent-cert-ok")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("ssh timed out")?
    .context("running ssh")?;
    agent.abort();
    ensure!(
        output.status.success() && output.stdout == b"agent-cert-ok\n",
        "ssh exited with {}\n----- ssh stdout -----\n{}\n----- ssh stderr -----\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        sshd.diagnostics(),
    );
    Ok(())
}

/// Against russh's agent, `ssh-add -l` prints key comments when unlocked and
/// `"The agent has no identities."` (exit status 1) when locked, and
/// `AgentClient::add_certificate` / `query_extensions` interoperate with
/// OpenSSH's `ssh-agent`.
#[tokio::test]
async fn openssh_tools_interoperate_with_agent_lock_comments_and_certificates() {
    let Some(openssh) = openssh::available() else {
        return;
    };
    let ssh_add = openssh.ssh_keygen.with_file_name("ssh-add");
    let ssh_agent = openssh.ssh_keygen.with_file_name("ssh-agent");
    for bin in [&ssh_add, &ssh_agent] {
        if !bin.is_file() {
            openssh::skip(&format!("{} not found", bin.display()));
            return;
        }
    }
    if let Err(error) = check_lock_comments_and_openssh_agent(openssh, &ssh_add, &ssh_agent).await {
        panic!("{error:#}");
    }
}

async fn check_lock_comments_and_openssh_agent(
    openssh: &openssh::OpenSsh,
    ssh_add: &std::path::Path,
    ssh_agent: &std::path::Path,
) -> anyhow::Result<()> {
    use russh::keys::agent::AgentIdentity;
    use russh::keys::certificate::{self, Builder, CertType};
    use russh::keys::key::safe_rng;
    use russh::keys::{Error, generate_secret_key};

    let dir = tempfile::Builder::new()
        .prefix("russh-agent-")
        .tempdir()
        .context("creating temporary directory")?;
    let socket = dir.path().join("russh-agent.sock");
    let listener = UnixListener::bind(&socket).context("binding russh agent socket")?;
    let russh_agent = tokio::spawn(server::serve(UnixListenerStream::new(listener), ()));

    let mut client = AgentClient::connect_uds(&socket).await?;
    let mut key = generate_secret_key()?;
    key.set_comment("comment-visible-in-ssh-add");
    client.add_identity(&key, &[]).await?;

    let list_unlocked = Command::new(ssh_add)
        .env("SSH_AUTH_SOCK", &socket)
        .arg("-l")
        .stdin(Stdio::null())
        .output()
        .await?;
    let unlocked_stdout = String::from_utf8_lossy(&list_unlocked.stdout);
    ensure!(
        list_unlocked.status.success() && unlocked_stdout.contains("comment-visible-in-ssh-add"),
        "expected key comment in ssh-add -l output, got: {unlocked_stdout}"
    );

    // Empty passphrase is refused and leaves the agent unlocked.
    ensure!(matches!(client.lock(b"").await, Err(Error::AgentFailure)));
    client.lock(b"passphrase").await?;

    // While locked, `ssh-add -l` receives an empty identity list (exit code 1),
    // not SSH_AGENT_FAILURE (exit code 2).
    let list_locked = Command::new(ssh_add)
        .env("SSH_AUTH_SOCK", &socket)
        .arg("-l")
        .stdin(Stdio::null())
        .output()
        .await?;
    let locked_out = format!(
        "{}{}",
        String::from_utf8_lossy(&list_locked.stdout),
        String::from_utf8_lossy(&list_locked.stderr)
    );
    ensure!(
        list_locked.status.code() == Some(1) && locked_out.contains("The agent has no identities."),
        "expected empty identities when locked, got {:?}: {locked_out}",
        list_locked.status.code()
    );

    client.unlock(b"passphrase").await?;
    russh_agent.abort();

    // Test AgentClient::add_certificate and query_extensions against real OpenSSH ssh-agent.
    let openssh_sock = dir.path().join("openssh-agent.sock");
    let mut child = Command::new(ssh_agent)
        .arg("-D")
        .arg("-a")
        .arg(&openssh_sock)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("spawning ssh-agent")?;

    let mut client = loop {
        if let Ok(c) = AgentClient::connect_uds(&openssh_sock).await {
            break c;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };

    if openssh.version_at_least(10, 3) {
        let exts = client.query_extensions().await?;
        ensure!(
            exts.iter().any(|e| e == "session-bind@openssh.com"),
            "expected session-bind@openssh.com in {exts:?}"
        );
    }
    ensure!(matches!(
        client.extension_response(b"unknown@example.com", b"").await,
        Err(Error::AgentFailure)
    ));

    let ca = generate_secret_key()?;
    let mut builder =
        Builder::new_with_random_nonce(&mut safe_rng(), key.public_key(), 0, u64::MAX - 1)?;
    builder.cert_type(CertType::User)?;
    builder.key_id("cert-id")?;
    builder.valid_principal("alice")?;
    let cert = certificate::sign(builder, &ca)?;

    client.add_certificate(&cert, &key, &[]).await?;
    let identities = client.request_identities().await?;
    ensure!(
        identities.len() == 1
            && identities[0].comment() == "comment-visible-in-ssh-add"
            && matches!(identities[0], AgentIdentity::Certificate { .. }),
        "unexpected identities from OpenSSH ssh-agent: {identities:?}"
    );
    let signed = client
        .sign_request(&identities[0], None, b"test-data".to_vec())
        .await?;
    ensure!(signed.len() > b"test-data".len());

    let _ = child.kill().await;
    let _ = child.wait().await;
    Ok(())
}
