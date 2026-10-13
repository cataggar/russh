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
