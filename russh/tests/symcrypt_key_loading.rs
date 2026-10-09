//! Private keys from `ssh-keygen`, loaded by the SymCrypt backend: `cargo
//! test -p russh --no-default-features --features symcrypt --test
//! symcrypt_key_loading`.
//!
//! Each user key is converted to the other formats `ssh-keygen` writes
//! (PKCS#8 and legacy PEM; Ed25519 keys only exist in the OpenSSH format),
//! must load as the same key from every file, and then authenticates to
//! OpenSSH if russh can sign with its algorithm in this build.
#![cfg(all(
    feature = "symcrypt",
    not(feature = "aws-lc-rs"),
    not(feature = "ring")
))]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use anyhow::{Context, ensure};
use common::openssh::{self, KeyAlg, KeyType, OpenSsh, Sshd};
use russh::Preferred;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, load_secret_key};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdsa_p256() {
    check(KeyType::EcdsaP256).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdsa_p384() {
    check(KeyType::EcdsaP384).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdsa_p521() {
    check(KeyType::EcdsaP521).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ed25519() {
    check(KeyType::Ed25519).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rsa_2048() {
    check(KeyType::Rsa2048).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rsa_3072() {
    check(KeyType::Rsa3072).await;
}

/// About 1 in 512 `ssh-keygen` ECDSA P-256 keys has a private scalar
/// below 2^248, which OpenSSH writes in fewer than 32 bytes and ssh-key
/// alone rejects. 2048 keys include one with a probability of 98%.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdsa_p256_short_scalars() {
    openssh::check_key_loading(KeyType::EcdsaP256, 2048).await;
}

/// Starts sshd with a new user key of `key_type`, loads it from every file
/// format, and authenticates with each loaded key.
async fn check(key_type: KeyType) {
    let Some(openssh) = openssh::available() else {
        return;
    };
    let sshd = Sshd::builder()
        .user_key(key_type)
        .start()
        .await
        .unwrap_or_else(|error| panic!("starting sshd: {error:#}"));
    let keys = load_all_formats(openssh, &sshd, key_type)
        .unwrap_or_else(|error| panic!("{key_type}: {error:#}\n{}", sshd.diagnostics()));

    let rsa_hash =
        matches!(key_type, KeyType::Rsa2048 | KeyType::Rsa3072).then_some(HashAlg::Sha256);
    let algorithm = KeyAlg::rsa(key_type, rsa_hash).algorithm();
    if !Preferred::default().key.contains(&algorithm) {
        eprintln!(
            "not authenticating with {key_type}: {} is not enabled in this build",
            algorithm.as_str()
        );
        return;
    }
    for (format, key) in keys {
        let key = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
        let result = async {
            let mut client = sshd.connect(Preferred::default()).await?;
            client.authenticate_with(key).await?;
            client.check_echo().await?;
            client.disconnect().await
        };
        if let Err(error) = result.await {
            panic!("{key_type} ({format}): {error:#}");
        }
    }
}

/// Loads the sshd user key from its OpenSSH file and from the copies
/// `ssh-keygen` converts to the other formats, which must all be the same
/// key.
fn load_all_formats(
    openssh: &OpenSsh,
    sshd: &Sshd,
    key_type: KeyType,
) -> anyhow::Result<Vec<(&'static str, PrivateKey)>> {
    let (_, path) = sshd.user_key();
    let original = load(path)?;
    let formats: &[(&str, &str)] = match key_type {
        KeyType::Ed25519 => &[],
        KeyType::Rsa2048 | KeyType::Rsa3072 => &[
            ("PKCS8", "-----BEGIN PRIVATE KEY-----"),
            ("PEM", "-----BEGIN RSA PRIVATE KEY-----"),
        ],
        _ => &[
            ("PKCS8", "-----BEGIN PRIVATE KEY-----"),
            ("PEM", "-----BEGIN EC PRIVATE KEY-----"),
        ],
    };
    let mut keys = vec![("OpenSSH", original.clone())];
    for &(format, header) in formats {
        let copy = convert(
            openssh,
            path,
            &sshd.dir().join(format!("{key_type}.{format}")),
            format,
        )?;
        let text = std::fs::read_to_string(&copy)?;
        ensure!(
            text.starts_with(header),
            "ssh-keygen -m {format} wrote {}",
            text.lines().next().unwrap_or_default()
        );
        let key = load(&copy)?;
        ensure!(
            key.key_data() == original.key_data(),
            "the {format} file is not the OpenSSH key"
        );
        keys.push((format, key));
    }
    Ok(keys)
}

fn load(path: &Path) -> anyhow::Result<PrivateKey> {
    load_secret_key(path, None).with_context(|| format!("loading {}", path.display()))
}

/// Copies the private key `from` to `to` and rewrites the copy in `format`
/// with `ssh-keygen -p -m <format>`.
fn convert(openssh: &OpenSsh, from: &Path, to: &Path, format: &str) -> anyhow::Result<PathBuf> {
    std::fs::copy(from, to).with_context(|| format!("copying {}", from.display()))?;
    let output = Command::new(&openssh.ssh_keygen)
        .args(["-q", "-p", "-P", "", "-N", "", "-m", format, "-f"])
        .arg(to)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {}", openssh.ssh_keygen.display()))?;
    ensure!(
        output.status.success(),
        "ssh-keygen -p -m {format} failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(to.to_owned())
}
