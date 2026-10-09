//! Interop harness: the russh **client** against a real, unprivileged
//! OpenSSH **server**, with forced algorithms.
//!
//! A check starts a throw-away `sshd` (run as the current user, listening on
//! `127.0.0.1:<free port>`) that allows exactly one algorithm of the kind
//! under test. It then connects a russh client that offers only that same
//! algorithm, verifies the host key, authenticates with a user key, runs
//! `echo <nonce>`, pipes a payload through `cat`, and asserts that the
//! negotiated algorithms are the forced ones. Neither side can fall back to
//! anything else, so a passing check proves that russh interoperates with
//! OpenSSH using that algorithm.
//!
//! All keys come from `ssh-keygen`, never from russh, so the harness works
//! under every russh crypto backend, including one without key generation or
//! without Ed25519.
//!
//! # Usage
//!
//! ```ignore
//! mod common;
//!
//! use common::openssh::{self, Case, KeyAlg};
//! use russh::{cipher, kex, mac};
//!
//! // One check per listed algorithm. The checks run concurrently, then the
//! // test panics with a per-algorithm report if any of them failed.
//! #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
//! async fn kex() {
//!     openssh::check_kex(
//!         Case::default(),
//!         &[kex::ECDH_SHA2_NISTP256, kex::ECDH_SHA2_NISTP384],
//!     )
//!     .await;
//! }
//!
//! // Pinning several algorithms at once.
//! #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
//! async fn custom() {
//!     let case = Case::default()
//!         .with_kex(kex::ECDH_SHA2_NISTP384)
//!         .with_cipher(cipher::AES_256_CTR)
//!         .with_mac(mac::HMAC_SHA512_ETM)
//!         .with_host_key(KeyAlg::RSA_SHA2_512)
//!         .with_user_key(KeyAlg::ECDSA_P384);
//!     openssh::check_cases("custom", [case]).await;
//! }
//! ```
//!
//! ## API overview
//!
//! * Family runners [`check_kex`], [`check_ciphers`], [`check_macs`],
//!   [`check_host_keys`] and [`check_user_keys`]. Each takes a *base* [`Case`]
//!   (the algorithms that stay fixed) and a list of algorithms to try one at
//!   a time. A backend with fewer algorithms passes its own lists, and its
//!   own base case if the defaults are unsupported.
//! * [`check_cases`] runs any list of cases and panics on failure, after
//!   printing a summary. [`run_cases`] and [`run_case`] return [`Outcome`]s
//!   instead, and [`report`] prints and checks them.
//! * [`Case`] is one combination of host key, user key, and (optionally)
//!   kex, cipher and MAC. [`Case::sshd`] returns the matching server
//!   configuration and [`Case::preferred`] the matching client [`Preferred`].
//! * [`Sshd::builder`] → [`SshdBuilder::start`] → [`Sshd`] is a running
//!   sshd for custom scenarios. [`Sshd::connect`] returns a [`Client`] with
//!   [`Client::authenticate`], [`Client::negotiated`], [`Client::exec`],
//!   [`Client::check_echo`], [`Client::check_round_trip`] and
//!   [`Client::disconnect_reason`], plus the raw russh handle. Errors from
//!   these steps include why the connection ended, if it did.
//! * [`available`] returns the detected OpenSSH installation (paths,
//!   version, and the algorithms `ssh -Q` lists), or `None` to skip.
//! * [`check_key_loading`] generates many keys of one type with `ssh-keygen`
//!   and checks that `russh::keys::load_secret_key` loads them all.
//!
//! # Forcing algorithms
//!
//! Every algorithm a [`Case`] sets is the only one either side allows:
//!
//! | `Case` field | sshd_config                       | russh client                                     |
//! |--------------|-----------------------------------|--------------------------------------------------|
//! | `kex`        | `KexAlgorithms`                   | `Preferred::kex = [kex, ext-info-c, kex-strict-c-v00@openssh.com]` |
//! | `cipher`     | `Ciphers`                         | `Preferred::cipher`                              |
//! | `mac`        | `MACs`                            | `Preferred::mac`                                 |
//! | `host_key`   | `HostKey` + `HostKeyAlgorithms`   | `Preferred::key`                                 |
//! | `user_key`   | `AuthorizedKeysFile` + `PubkeyAcceptedAlgorithms` | key + RSA hash given to `authenticate_publickey` |
//!
//! A `kex`, `cipher` or `mac` of `None` leaves both sides at their defaults.
//! Host and user keys are always forced. Their default, ECDSA P-256, is
//! supported by every russh backend.
//!
//! After authentication the algorithms passed to `Handler::kex_done` are
//! compared with the forced ones. A MAC is only used with a non-AEAD
//! cipher. So [`check_macs`] forces `aes128-ctr` unless the base case sets a
//! cipher, and a case that forces a MAC but negotiates an AEAD cipher fails.
//!
//! # Skips and environment variables
//!
//! * If OpenSSH is unavailable, every check prints a `skipped` line and
//!   returns without failing. That happens when not on Unix, when there is
//!   no sshd at `$RUSSH_SSHD` (default `/usr/sbin/sshd`), or when
//!   `ssh-keygen` is not on `PATH`. Tests using [`Sshd`] directly should
//!   start with `let Some(_) = openssh::available() else { return };`.
//! * `RUSSH_REQUIRE_SSHD=1` turns that skip into a failure, e.g. for CI.
//! * Algorithms the local OpenSSH lacks are always skipped and listed in the
//!   summary, even with `RUSSH_REQUIRE_SSHD`. For example,
//!   `mlkem768x25519-sha256` needs OpenSSH 9.9. Support is checked with
//!   `ssh -Q kex|cipher|mac|key|sig`. If `ssh` is missing, everything counts
//!   as supported.
//! * `RUSSH_SSHD=/abs/path/sshd` selects another sshd. The path must be
//!   absolute because sshd re-executes itself.
//! * `RUSSH_INTEROP_JOBS=<n>` caps how many cases a runner runs at once.
//!   The default is the CPU count, clamped to 2..=8.
//! * `RUST_LOG=russh=debug` enables russh's logging through `env_logger`.
//!
//! The summary and skip lines go straight to stderr (bypassing libtest's
//! capture), so they show up even when tests pass. A failure's panic
//! message has, for each failed case, the error, the generated
//! `sshd_config`, and the sshd log. The log is at `LogLevel DEBUG1`, so it
//! names the algorithms sshd negotiated.
//!
//! # Limitations
//!
//! * Only the russh *client* is exercised. Interop of the russh *server* is
//!   not covered.
//! * The unprivileged sshd can only log in the current user.
//! * Lines added with [`SshdBuilder::config`] go *before* the generated
//!   settings, because sshd keeps the first value it reads for most
//!   keywords. `Match` blocks are not supported.
//! * russh cannot load 1 in 512 ECDSA P-256 private keys from `ssh-keygen`
//!   (a bug in the ssh-key crate with scalars below 2^247). The
//!   harness generates a new P-256 user key when that happens, and logs a
//!   line. The ignored `ecdsa_p256_key_loading` test in `openssh_interop.rs`
//!   reproduces the bug.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::{self, Write as _};
use std::fs;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow, bail, ensure};
use russh::keys::{
    Algorithm, EcdsaCurve, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate,
};
use russh::{ChannelMsg, Disconnect, Names, Preferred, cipher, client, kex, mac};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Set to anything but empty, `0`, `false` or `no` to turn "OpenSSH is not
/// available" skips into failures.
pub const REQUIRE_ENV: &str = "RUSSH_REQUIRE_SSHD";
/// Absolute path of the `sshd` to test against (default: [`DEFAULT_SSHD`]).
pub const SSHD_ENV: &str = "RUSSH_SSHD";
/// Maximum number of cases a runner runs concurrently.
pub const JOBS_ENV: &str = "RUSSH_INTEROP_JOBS";
pub const DEFAULT_SSHD: &str = "/usr/sbin/sshd";

/// Time limit for each client step: connecting (including key exchange),
/// authenticating, and each command. It is generous because 8192-bit
/// Diffie-Hellman (group18, group exchange) takes tens of seconds in debug
/// builds.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(120);
/// Time limit for the client side of one [`Case`].
pub const CASE_TIMEOUT: Duration = Duration::from_secs(300);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_START_ATTEMPTS: u32 = 5;

// ---------------------------------------------------------------------------
// OpenSSH detection and skips
// ---------------------------------------------------------------------------

/// The local OpenSSH installation, as detected by [`available`].
#[derive(Debug)]
pub struct OpenSsh {
    /// Absolute path of `sshd`.
    pub sshd: PathBuf,
    /// Path of `ssh-keygen`.
    pub ssh_keygen: PathBuf,
    /// Version banner, e.g. `OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13 30 Jan 2024`.
    pub version: String,
    /// The current user: the only one an unprivileged sshd can log in.
    pub user: String,
    kex: Option<HashSet<String>>,
    ciphers: Option<HashSet<String>>,
    macs: Option<HashSet<String>>,
    key_types: Option<HashSet<String>>,
    signatures: Option<HashSet<String>>,
}

/// An `ssh -Q` query, see [`OpenSsh::supports`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Query {
    Kex,
    Cipher,
    Mac,
    /// Key types, e.g. `ssh-rsa`.
    Key,
    /// Signature algorithms, e.g. `rsa-sha2-256`.
    Sig,
}

impl OpenSsh {
    /// Whether OpenSSH implements `name` according to `ssh -Q`; `true` if
    /// that list is unknown.
    pub fn supports(&self, query: Query, name: &str) -> bool {
        let list = match query {
            Query::Kex => &self.kex,
            Query::Cipher => &self.ciphers,
            Query::Mac => &self.macs,
            Query::Key => &self.key_types,
            Query::Sig => &self.signatures,
        };
        list.as_ref().is_none_or(|list| list.contains(name))
    }

    /// The first word of [`Self::version`], e.g. `OpenSSH_9.6p1`.
    pub fn short_version(&self) -> &str {
        self.version
            .split([' ', ','])
            .next()
            .unwrap_or(&self.version)
    }

    /// Whether this is at least OpenSSH `major.minor`; `false` if unknown.
    pub fn version_at_least(&self, major: u32, minor: u32) -> bool {
        let parse = || -> Option<(u32, u32)> {
            let rest = self.version.split_once("OpenSSH_")?.1;
            let (major, rest) = rest.split_once('.')?;
            let minor: String = rest.chars().take_while(char::is_ascii_digit).collect();
            Some((major.parse().ok()?, minor.parse().ok()?))
        };
        parse().is_some_and(|version| version >= (major, minor))
    }
}

/// The local OpenSSH installation, detected once per test binary. If it is
/// unavailable, this reports a skip through [`skip`] (which panics under
/// [`REQUIRE_ENV`]) and returns `None`.
pub fn available() -> Option<&'static OpenSsh> {
    match detected() {
        Ok(openssh) => Some(openssh),
        Err(reason) => {
            skip(&format!("OpenSSH is not available: {reason}"));
            None
        }
    }
}

/// Whether [`REQUIRE_ENV`] is set.
pub fn required() -> bool {
    std::env::var(REQUIRE_ENV).is_ok_and(|value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no"
        )
    })
}

/// Reports a skipped check on stderr, or panics if [`REQUIRE_ENV`] is set.
#[track_caller]
pub fn skip(reason: &str) {
    if required() {
        panic!("{reason} (failing because {REQUIRE_ENV} is set)");
    }
    log_line(&format!("skipped: {reason}"));
}

/// Writes straight to the process's stderr, bypassing libtest's capture.
fn log_line(message: &str) {
    let _ = writeln!(std::io::stderr().lock(), "[openssh-interop] {message}");
}

fn detected() -> Result<&'static OpenSsh, &'static str> {
    static OPENSSH: OnceLock<Result<OpenSsh, String>> = OnceLock::new();
    OPENSSH.get_or_init(detect).as_ref().map_err(String::as_str)
}

fn detect() -> Result<OpenSsh, String> {
    if !cfg!(unix) {
        return Err("the OpenSSH interop harness only supports Unix".into());
    }
    let sshd = std::env::var_os(SSHD_ENV)
        .filter(|value| !value.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_SSHD), PathBuf::from);
    if !sshd.is_absolute() {
        return Err(format!(
            "{SSHD_ENV}={} is not an absolute path",
            sshd.display()
        ));
    }
    if !sshd.is_file() {
        return Err(format!("{} not found", sshd.display()));
    }
    let ssh_keygen = find_program("ssh-keygen").ok_or("ssh-keygen not found on PATH")?;
    let user = current_user().ok_or("cannot determine the current user name")?;
    let ssh = find_program("ssh");
    let query = |what: &str| ssh.as_deref().and_then(|ssh| ssh_query(ssh, what));
    Ok(OpenSsh {
        version: sshd_version(&sshd),
        kex: query("kex"),
        ciphers: query("cipher"),
        macs: query("mac"),
        key_types: query("key"),
        signatures: query("sig"),
        sshd,
        ssh_keygen,
        user,
    })
}

fn find_program(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(["/usr/bin", "/usr/local/bin"].map(PathBuf::from))
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn sshd_version(sshd: &Path) -> String {
    // Recent versions print the version for `-V`; older ones reject the
    // option and print it as part of the usage message.
    Command::new(sshd)
        .arg("-V")
        .stdin(Stdio::null())
        .output()
        .ok()
        .and_then(|output| {
            let text = String::from_utf8_lossy(&output.stderr).into_owned()
                + &String::from_utf8_lossy(&output.stdout);
            let line = text.lines().find(|line| line.contains("OpenSSH"))?;
            Some(line.trim().to_owned())
        })
        .unwrap_or_else(|| "OpenSSH (unknown version)".into())
}

fn current_user() -> Option<String> {
    let non_empty = |name: String| {
        let name = name.trim().to_owned();
        (!name.is_empty()).then_some(name)
    };
    Command::new("id")
        .arg("-un")
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(non_empty)
        .or_else(|| std::env::var("USER").ok().and_then(non_empty))
        .or_else(|| std::env::var("LOGNAME").ok().and_then(non_empty))
}

fn ssh_query(ssh: &Path, what: &str) -> Option<HashSet<String>> {
    let output = Command::new(ssh)
        .args(["-Q", what])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let names: HashSet<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(String::from)
        .collect();
    (!names.is_empty()).then_some(names)
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A key type `ssh-keygen` can generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Rsa2048,
    Rsa3072,
}

impl KeyType {
    pub const ALL: [KeyType; 6] = [
        KeyType::Ed25519,
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::EcdsaP521,
        KeyType::Rsa2048,
        KeyType::Rsa3072,
    ];

    /// The key type's name in OpenSSH (`ssh -Q key`, `.pub` files).
    pub fn openssh_name(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ssh-ed25519",
            KeyType::EcdsaP256 => "ecdsa-sha2-nistp256",
            KeyType::EcdsaP384 => "ecdsa-sha2-nistp384",
            KeyType::EcdsaP521 => "ecdsa-sha2-nistp521",
            KeyType::Rsa2048 | KeyType::Rsa3072 => "ssh-rsa",
        }
    }

    fn keygen_args(self) -> [&'static str; 4] {
        match self {
            KeyType::Ed25519 => ["-t", "ed25519", "-b", "256"],
            KeyType::EcdsaP256 => ["-t", "ecdsa", "-b", "256"],
            KeyType::EcdsaP384 => ["-t", "ecdsa", "-b", "384"],
            KeyType::EcdsaP521 => ["-t", "ecdsa", "-b", "521"],
            KeyType::Rsa2048 => ["-t", "rsa", "-b", "2048"],
            KeyType::Rsa3072 => ["-t", "rsa", "-b", "3072"],
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::EcdsaP384 => "ecdsa-p384",
            KeyType::EcdsaP521 => "ecdsa-p521",
            KeyType::Rsa2048 => "rsa-2048",
            KeyType::Rsa3072 => "rsa-3072",
        })
    }
}

/// A public key signature algorithm and the key it is used with: a
/// [`KeyType`] plus, for RSA, the signature hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyAlg {
    pub key: KeyType,
    /// RSA only: `Some(Sha256)` is `rsa-sha2-256`, `Some(Sha512)` is
    /// `rsa-sha2-512` and `None` is the legacy SHA-1 `ssh-rsa`. Ignored for
    /// other key types.
    pub rsa_hash: Option<HashAlg>,
}

impl KeyAlg {
    pub const ED25519: KeyAlg = KeyAlg::new(KeyType::Ed25519);
    pub const ECDSA_P256: KeyAlg = KeyAlg::new(KeyType::EcdsaP256);
    pub const ECDSA_P384: KeyAlg = KeyAlg::new(KeyType::EcdsaP384);
    pub const ECDSA_P521: KeyAlg = KeyAlg::new(KeyType::EcdsaP521);
    /// `rsa-sha2-256` with a 3072-bit key.
    pub const RSA_SHA2_256: KeyAlg = KeyAlg::rsa(KeyType::Rsa3072, Some(HashAlg::Sha256));
    /// `rsa-sha2-512` with a 3072-bit key.
    pub const RSA_SHA2_512: KeyAlg = KeyAlg::rsa(KeyType::Rsa3072, Some(HashAlg::Sha512));

    /// A non-RSA key type, or RSA with the legacy SHA-1 `ssh-rsa` algorithm.
    pub const fn new(key: KeyType) -> KeyAlg {
        KeyAlg {
            key,
            rsa_hash: None,
        }
    }

    /// An RSA key of the given size, signing with `hash` (`None` is `ssh-rsa`).
    pub const fn rsa(key: KeyType, hash: Option<HashAlg>) -> KeyAlg {
        KeyAlg {
            key,
            rsa_hash: hash,
        }
    }

    fn is_rsa(&self) -> bool {
        matches!(self.key, KeyType::Rsa2048 | KeyType::Rsa3072)
    }

    /// The russh/ssh-key algorithm, e.g. `Algorithm::Rsa { hash: Some(HashAlg::Sha256) }`.
    pub fn algorithm(&self) -> Algorithm {
        match self.key {
            KeyType::Ed25519 => Algorithm::Ed25519,
            KeyType::EcdsaP256 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            KeyType::EcdsaP384 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            KeyType::EcdsaP521 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            KeyType::Rsa2048 | KeyType::Rsa3072 => Algorithm::Rsa {
                hash: self.rsa_hash,
            },
        }
    }

    /// The SSH signature algorithm name, e.g. `rsa-sha2-256`.
    pub fn name(&self) -> String {
        self.algorithm().as_str().to_owned()
    }
}

impl fmt::Display for KeyAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_rsa() {
            write!(f, "{}/{}", self.name(), self.key)
        } else {
            f.write_str(&self.name())
        }
    }
}

fn generate_keys(ssh_keygen: &Path, keys: &[(KeyType, &Path)]) -> anyhow::Result<()> {
    // Run all ssh-keygen processes at once: RSA 3072 takes a while.
    let mut children = Vec::with_capacity(keys.len());
    for &(key_type, path) in keys {
        let child = Command::new(ssh_keygen)
            .args(["-q", "-N", "", "-C", "russh-interop-test"])
            .args(key_type.keygen_args())
            .arg("-f")
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning {}", ssh_keygen.display()))?;
        children.push((key_type, child));
    }
    for (key_type, child) in children {
        let output = child.wait_with_output()?;
        ensure!(
            output.status.success(),
            "ssh-keygen ({key_type}) failed with {}: {}{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
            String::from_utf8_lossy(&output.stdout).trim(),
        );
    }
    Ok(())
}

fn public_key_path(private_key: &Path) -> PathBuf {
    let mut path = private_key.as_os_str().to_owned();
    path.push(".pub");
    path.into()
}

/// Known bug: the ssh-key crate, which parses keys for `russh::keys`,
/// rejects an ECDSA P-256 private key whose scalar is below 2^247. OpenSSH
/// writes such a scalar as an mpint of at most 31 bytes, and
/// `EcdsaPrivateKey::decode` wants at least 32. That is 1 in 512 keys from
/// `ssh-keygen -t ecdsa -b 256`. So random cases don't fail, the harness
/// generates a new user key in that case. `check_key_loading` reproduces
/// the bug.
fn replace_unloadable_user_key(ssh_keygen: &Path, path: &Path) -> anyhow::Result<()> {
    // Each new key fails with probability 1/512, so a few new keys are plenty.
    for _ in 0..4 {
        let Err(error) = russh::keys::load_secret_key(path, None) else {
            return Ok(());
        };
        log_line(&format!(
            "generating a new user key because russh cannot load {} ({error}), probably \
             because of the known ssh-key bug with short ECDSA P-256 scalars",
            path.display()
        ));
        fs::remove_file(path)?;
        fs::remove_file(public_key_path(path))?;
        generate_keys(ssh_keygen, &[(KeyType::EcdsaP256, path)])?;
    }
    // If the last key can't be loaded either, authentication reports why.
    Ok(())
}

/// Generates `count` keys of `key_type` with `ssh-keygen` and checks that
/// `russh::keys::load_secret_key` loads every one. It takes many keys to hit
/// rare encodings, such as ECDSA scalars with leading zero bytes. Panics
/// with the number of failures and the first error.
pub async fn check_key_loading(key_type: KeyType, count: usize) {
    let Some(openssh) = available() else { return };
    let started = Instant::now();
    let failures =
        tokio::task::spawn_blocking(move || key_loading_failures(openssh, key_type, count))
            .await
            .expect("the key loading task panicked")
            .unwrap_or_else(|error| panic!("{error:#}"));
    log_line(&format!(
        "russh loaded {} of {count} {key_type} keys from ssh-keygen ({:.2}s)",
        count - failures.len(),
        started.elapsed().as_secs_f64()
    ));
    if let Some(first) = failures.first() {
        panic!(
            "russh::keys::load_secret_key failed for {} of {count} {key_type} keys generated by \
             {}, first: {first}",
            failures.len(),
            openssh.short_version()
        );
    }
}

fn key_loading_failures(
    openssh: &OpenSsh,
    key_type: KeyType,
    count: usize,
) -> anyhow::Result<Vec<String>> {
    const BATCH: usize = 32;
    let dir = tempfile::Builder::new()
        .prefix("russh-keys-")
        .tempdir()
        .context("creating a temporary directory for keys")?;
    let mut failures = Vec::new();
    for start in (0..count).step_by(BATCH) {
        let paths: Vec<PathBuf> = (start..count.min(start + BATCH))
            .map(|i| dir.path().join(format!("key{i}")))
            .collect();
        let keys: Vec<(KeyType, &Path)> = paths
            .iter()
            .map(|path| (key_type, path.as_path()))
            .collect();
        generate_keys(&openssh.ssh_keygen, &keys)?;
        for path in &paths {
            if let Err(error) = russh::keys::load_secret_key(path, None) {
                failures.push(error.to_string());
            }
            fs::remove_file(path)?;
            fs::remove_file(public_key_path(path))?;
        }
    }
    Ok(failures)
}

fn read_public_key(path: &Path) -> anyhow::Result<PublicKey> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    PublicKey::from_openssh(text.trim()).with_context(|| format!("parsing {}", path.display()))
}

fn describe_key(key: &PublicKey) -> String {
    format!(
        "{} {}",
        key.algorithm().as_str(),
        key.fingerprint(HashAlg::Sha256)
    )
}

// ---------------------------------------------------------------------------
// sshd
// ---------------------------------------------------------------------------

/// Configuration of an [`Sshd`]; see [`Sshd::builder`].
#[derive(Clone, Debug)]
pub struct SshdBuilder {
    host_keys: Vec<KeyType>,
    user_key: KeyType,
    kex_algorithms: Option<String>,
    ciphers: Option<String>,
    macs: Option<String>,
    host_key_algorithms: Option<String>,
    pubkey_accepted_algorithms: Option<String>,
    extra_config: Vec<String>,
}

impl Default for SshdBuilder {
    fn default() -> Self {
        SshdBuilder {
            host_keys: Vec::new(),
            user_key: KeyType::EcdsaP256,
            kex_algorithms: None,
            ciphers: None,
            macs: None,
            host_key_algorithms: None,
            pubkey_accepted_algorithms: None,
            extra_config: Vec::new(),
        }
    }
}

impl SshdBuilder {
    /// Adds a host key of this type. Without any, sshd gets one ECDSA P-256
    /// host key.
    pub fn host_key(mut self, key_type: KeyType) -> Self {
        if !self.host_keys.contains(&key_type) {
            self.host_keys.push(key_type);
        }
        self
    }

    /// Type of the user key put into `authorized_keys` (default: ECDSA P-256).
    pub fn user_key(mut self, key_type: KeyType) -> Self {
        self.user_key = key_type;
        self
    }

    /// `KexAlgorithms`: a comma-separated list. OpenSSH's `+`, `-` and `^`
    /// prefixes work too.
    pub fn kex_algorithms(mut self, list: impl Into<String>) -> Self {
        self.kex_algorithms = Some(list.into());
        self
    }

    /// `Ciphers`, a comma-separated list.
    pub fn ciphers(mut self, list: impl Into<String>) -> Self {
        self.ciphers = Some(list.into());
        self
    }

    /// `MACs`, a comma-separated list.
    pub fn macs(mut self, list: impl Into<String>) -> Self {
        self.macs = Some(list.into());
        self
    }

    /// `HostKeyAlgorithms`, a comma-separated list.
    pub fn host_key_algorithms(mut self, list: impl Into<String>) -> Self {
        self.host_key_algorithms = Some(list.into());
        self
    }

    /// `PubkeyAcceptedAlgorithms`, a comma-separated list.
    pub fn pubkey_accepted_algorithms(mut self, list: impl Into<String>) -> Self {
        self.pubkey_accepted_algorithms = Some(list.into());
        self
    }

    /// Adds a raw `sshd_config` line such as `"LogLevel DEBUG3"`. It goes
    /// before the generated settings, so it wins for keywords where sshd
    /// keeps the first value.
    pub fn config(mut self, line: impl Into<String>) -> Self {
        self.extra_config.push(line.into());
        self
    }

    /// Generates the keys and the configuration, then starts sshd and waits
    /// until it listens. Fails if OpenSSH is not [`available`].
    pub async fn start(self) -> anyhow::Result<Sshd> {
        let openssh = available().context("OpenSSH is not available")?;
        tokio::task::spawn_blocking(move || self.start_blocking(openssh))
            .await
            .context("sshd startup task failed")?
    }

    fn start_blocking(self, openssh: &'static OpenSsh) -> anyhow::Result<Sshd> {
        let dir = tempfile::Builder::new()
            .prefix("russh-sshd-")
            .tempdir()
            .context("creating a temporary directory for sshd")?;
        // sshd needs absolute paths.
        let root = dir.path().canonicalize()?;

        let mut host_key_types = self.host_keys.clone();
        if host_key_types.is_empty() {
            host_key_types.push(KeyType::EcdsaP256);
        }
        let host_key_paths: Vec<PathBuf> = host_key_types
            .iter()
            .map(|key_type| root.join(format!("host_{key_type}")))
            .collect();
        let user_key_path = root.join(format!("user_{}", self.user_key));
        let mut keys: Vec<(KeyType, &Path)> = host_key_types
            .iter()
            .copied()
            .zip(host_key_paths.iter().map(PathBuf::as_path))
            .collect();
        keys.push((self.user_key, &user_key_path));
        generate_keys(&openssh.ssh_keygen, &keys)?;
        if self.user_key == KeyType::EcdsaP256 {
            replace_unloadable_user_key(&openssh.ssh_keygen, &user_key_path)?;
        }

        let host_keys = host_key_types
            .iter()
            .zip(&host_key_paths)
            .map(|(&key_type, path)| Ok((key_type, read_public_key(&public_key_path(path))?)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let authorized_keys = root.join("authorized_keys");
        fs::copy(public_key_path(&user_key_path), &authorized_keys)
            .context("writing authorized_keys")?;

        let config_path = root.join("sshd_config");
        let log_path = root.join("sshd.log");
        let output_path = root.join("sshd.out");
        let mut attempt = 1;
        loop {
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()?));
            let config =
                self.render_config(openssh, &root, addr, &host_key_paths, &authorized_keys);
            fs::write(&config_path, &config).context("writing sshd_config")?;
            let _ = fs::remove_file(&log_path);
            let output = fs::File::create(&output_path)?;
            let mut child = Command::new(&openssh.sshd)
                .arg("-D")
                .arg("-E")
                .arg(&log_path)
                .arg("-f")
                .arg(&config_path)
                .stdin(Stdio::null())
                .stdout(output.try_clone()?)
                .stderr(output)
                .spawn()
                .with_context(|| format!("spawning {}", openssh.sshd.display()))?;
            match wait_until_listening(&mut child, &log_path, addr) {
                Ok(()) => {
                    return Ok(Sshd {
                        child,
                        _dir: dir,
                        root,
                        addr,
                        openssh,
                        host_keys,
                        user_key: self.user_key,
                        user_key_path,
                        config,
                    });
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let log = read_lossy(&log_path);
                    // Another process may have taken the port in the meantime.
                    if attempt < MAX_START_ATTEMPTS
                        && (log.contains("Address already in use")
                            || log.contains("Cannot bind any address"))
                    {
                        attempt += 1;
                        continue;
                    }
                    bail!(
                        "{error:#}\n{}",
                        diagnostics(openssh, addr, &config, &log, &read_lossy(&output_path))
                    );
                }
            }
        }
    }

    fn render_config(
        &self,
        openssh: &OpenSsh,
        root: &Path,
        addr: SocketAddr,
        host_keys: &[PathBuf],
        authorized_keys: &Path,
    ) -> String {
        let mut lines = vec![
            "# Generated by russh/tests/common/openssh.rs. For most keywords sshd keeps the first value."
                .to_owned(),
        ];
        lines.extend(self.extra_config.iter().cloned());
        for (keyword, value) in [
            ("KexAlgorithms", &self.kex_algorithms),
            ("Ciphers", &self.ciphers),
            ("MACs", &self.macs),
            ("HostKeyAlgorithms", &self.host_key_algorithms),
            ("PubkeyAcceptedAlgorithms", &self.pubkey_accepted_algorithms),
        ] {
            if let Some(value) = value {
                lines.push(format!("{keyword} {value}"));
            }
        }
        lines.push(format!("ListenAddress {}", addr.ip()));
        lines.push(format!("Port {}", addr.port()));
        for key in host_keys {
            lines.push(format!("HostKey {}", key.display()));
        }
        lines.push(format!("PidFile {}", root.join("sshd.pid").display()));
        lines.push(format!("AuthorizedKeysFile {}", authorized_keys.display()));
        lines.extend(
            [
                "UsePAM no",
                "StrictModes no",
                "PubkeyAuthentication yes",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "PermitUserRC no",
                "PrintMotd no",
                "PrintLastLog no",
                "AllowAgentForwarding no",
                "AllowTcpForwarding no",
                "X11Forwarding no",
                "UseDNS no",
                "LogLevel DEBUG1",
            ]
            .map(String::from),
        );
        if openssh.version_at_least(9, 8) {
            // Don't let failed connections in one test throttle later ones.
            lines.push("PerSourcePenalties no".into());
        }
        lines.join("\n") + "\n"
    }
}

fn free_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("finding a free port")?;
    Ok(listener.local_addr()?.port())
}

fn wait_until_listening(
    child: &mut Child,
    log_path: &Path,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let listening = format!("Server listening on {} port {}.", addr.ip(), addr.port());
    let started = Instant::now();
    loop {
        if fs::read_to_string(log_path).is_ok_and(|log| log.contains(&listening)) {
            return Ok(());
        }
        if let Some(status) = child.try_wait().context("checking on sshd")? {
            bail!("sshd exited during startup ({status})");
        }
        // Fallback for when the log line is missing, e.g. with a custom
        // `LogLevel QUIET`. The probe shows up in the log as an aborted connection.
        if started.elapsed() > Duration::from_secs(2)
            && TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
        {
            return Ok(());
        }
        if started.elapsed() > STARTUP_TIMEOUT {
            bail!("sshd did not start listening on {addr} within {STARTUP_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn read_lossy(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) => format!("<cannot read {}: {error}>", path.display()),
    }
}

fn diagnostics(
    openssh: &OpenSsh,
    addr: SocketAddr,
    config: &str,
    log: &str,
    output: &str,
) -> String {
    let mut text = format!(
        "----- {} at {addr} -----\n----- sshd_config -----\n{config}----- sshd log -----\n{log}",
        openssh.version
    );
    if !output.trim().is_empty() {
        let _ = write!(text, "----- sshd stdout/stderr -----\n{output}");
    }
    text.push_str("----- end of sshd diagnostics -----");
    text
}

/// A running, unprivileged OpenSSH server with keys generated by
/// `ssh-keygen`. It is killed and its directory deleted on drop; if that
/// happens during a panic, its [diagnostics](Sshd::diagnostics) are printed.
pub struct Sshd {
    child: Child,
    _dir: tempfile::TempDir,
    root: PathBuf,
    addr: SocketAddr,
    openssh: &'static OpenSsh,
    host_keys: Vec<(KeyType, PublicKey)>,
    user_key: KeyType,
    user_key_path: PathBuf,
    config: String,
}

impl Sshd {
    /// Starts configuring an sshd: one ECDSA P-256 host key, an ECDSA P-256
    /// user key, and OpenSSH's default algorithms.
    ///
    /// ```ignore
    /// let sshd = Sshd::builder()
    ///     .host_key(KeyType::Rsa3072)
    ///     .host_key_algorithms("rsa-sha2-512")
    ///     .kex_algorithms(kex::ECDH_SHA2_NISTP384.as_ref())
    ///     .start()
    ///     .await?;
    /// ```
    pub fn builder() -> SshdBuilder {
        SshdBuilder::default()
    }

    /// The address sshd listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The user to log in as.
    pub fn user(&self) -> &str {
        &self.openssh.user
    }

    pub fn openssh(&self) -> &'static OpenSsh {
        self.openssh
    }

    /// The temporary directory with the keys, configuration and log.
    pub fn dir(&self) -> &Path {
        &self.root
    }

    /// The host keys sshd was given, with their public halves.
    pub fn host_keys(&self) -> &[(KeyType, PublicKey)] {
        &self.host_keys
    }

    /// Type and private key file of the authorized user key.
    pub fn user_key(&self) -> (KeyType, &Path) {
        (self.user_key, &self.user_key_path)
    }

    /// Loads the user key with `russh::keys::load_secret_key`. See
    /// [`KeyAlg::rsa_hash`] for `rsa_hash`.
    pub fn load_user_key(
        &self,
        rsa_hash: Option<HashAlg>,
    ) -> anyhow::Result<PrivateKeyWithHashAlg> {
        load_user_key(&self.user_key_path, rsa_hash)
    }

    /// The generated `sshd_config`.
    pub fn config(&self) -> &str {
        &self.config
    }

    /// The sshd log so far.
    pub fn log(&self) -> String {
        read_lossy(&self.root.join("sshd.log"))
    }

    /// Version, address, configuration and log, for failure messages.
    pub fn diagnostics(&self) -> String {
        diagnostics(
            self.openssh,
            self.addr,
            &self.config,
            &self.log(),
            &read_lossy(&self.root.join("sshd.out")),
        )
    }

    /// Connects a russh client that offers `preferred` and accepts exactly
    /// this sshd's host keys.
    pub async fn connect(&self, preferred: Preferred) -> anyhow::Result<Client> {
        self.connect_with(client::Config {
            preferred,
            nodelay: true,
            ..Default::default()
        })
        .await
    }

    /// Like [`Sshd::connect`], with a complete client configuration.
    pub async fn connect_with(&self, config: client::Config) -> anyhow::Result<Client> {
        let state = Arc::new(Mutex::new(ClientState::default()));
        let handler = ClientHandler {
            expected: self.host_keys.iter().map(|(_, key)| key.clone()).collect(),
            state: state.clone(),
        };
        let connecting = client::connect(Arc::new(config), self.addr, handler);
        let handle = match timeout(STEP_TIMEOUT, connecting).await {
            Ok(Ok(handle)) => handle,
            Ok(Err(error)) => match lock(&state).rejected_key.take() {
                Some(key) => bail!(
                    "connection failed ({error}): the server presented host key {key}, which is \
                     not one of the generated host keys"
                ),
                None => bail!("connection or key exchange failed: {error}"),
            },
            Err(_) => bail!("connection or key exchange timed out after {STEP_TIMEOUT:?}"),
        };
        Ok(Client {
            handle,
            state,
            user: self.openssh.user.clone(),
            user_key_path: self.user_key_path.clone(),
        })
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            log_line(&self.diagnostics());
        }
    }
}

fn load_user_key(path: &Path, rsa_hash: Option<HashAlg>) -> anyhow::Result<PrivateKeyWithHashAlg> {
    let key = russh::keys::load_secret_key(path, None)
        .map_err(|error| anyhow!("loading {}: {error}", path.display()))?;
    Ok(PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ClientState {
    names: Option<Names>,
    rejected_key: Option<String>,
    disconnected: Option<String>,
}

/// The [`client::Handler`] of a [`Client`]. It accepts exactly the host keys
/// generated for the [`Sshd`] and records the negotiated algorithms and why
/// the connection ended.
pub struct ClientHandler {
    expected: Vec<PublicKey>,
    state: Arc<Mutex<ClientState>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let (accepted, description) = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => (
                self.expected
                    .iter()
                    .any(|expected| expected.key_data() == key.key_data()),
                describe_key(key),
            ),
            PublicKeyOrCertificate::Certificate(certificate) => (
                false,
                format!("certificate of type {}", certificate.algorithm().as_str()),
            ),
        };
        if !accepted {
            lock(&self.state).rejected_key = Some(description);
        }
        Ok(accepted)
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        lock(&self.state).names = Some(names.clone());
        Ok(())
    }

    /// Same result as the default implementation. After the key exchange,
    /// this is the only place russh reports why a session failed: a pending
    /// `authenticate_publickey` just returns `AuthResult::Failure`.
    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        let (description, result) = match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => (
                format!(
                    "the server disconnected ({:?}): {}",
                    info.reason_code, info.message
                ),
                Ok(()),
            ),
            client::DisconnectReason::Error(error) => (
                format!("the russh session failed: {error} ({error:?})"),
                Err(error),
            ),
        };
        lock(&self.state).disconnected = Some(description);
        result
    }
}

/// Output of [`Client::exec`].
#[derive(Debug, Default)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
}

/// A russh client connected to an [`Sshd`]; see [`Sshd::connect`].
pub struct Client {
    handle: client::Handle<ClientHandler>,
    state: Arc<Mutex<ClientState>>,
    user: String,
    user_key_path: PathBuf,
}

impl Client {
    /// The underlying russh handle.
    pub fn handle(&self) -> &client::Handle<ClientHandler> {
        &self.handle
    }

    pub fn handle_mut(&mut self) -> &mut client::Handle<ClientHandler> {
        &mut self.handle
    }

    /// The algorithms negotiated by the latest key exchange.
    pub fn negotiated(&self) -> Option<Names> {
        lock(&self.state).names.clone()
    }

    /// Why the connection ended, if it has: a russh session error or a
    /// disconnect message from the server.
    pub fn disconnect_reason(&self) -> Option<String> {
        lock(&self.state).disconnected.clone()
    }

    /// Adds [`Self::disconnect_reason`], if any, to a failed step's error.
    fn explain(&self, error: anyhow::Error) -> anyhow::Error {
        match self.disconnect_reason() {
            Some(reason) => anyhow!("{error:#} (the connection has ended: {reason})"),
            None => error,
        }
    }

    /// Authenticates with the sshd's user key, loaded with
    /// `russh::keys::load_secret_key`. For RSA keys, `rsa_hash` selects
    /// `rsa-sha2-256`, `rsa-sha2-512` or (`None`) `ssh-rsa`.
    pub async fn authenticate(&mut self, rsa_hash: Option<HashAlg>) -> anyhow::Result<()> {
        let key = load_user_key(&self.user_key_path, rsa_hash)?;
        self.authenticate_with(key).await
    }

    /// Authenticates as the sshd's user with any key.
    pub async fn authenticate_with(&mut self, key: PrivateKeyWithHashAlg) -> anyhow::Result<()> {
        let algorithm = key.algorithm();
        let algorithm = algorithm.as_str();
        let authenticating = self.handle.authenticate_publickey(self.user.clone(), key);
        let error = match timeout(STEP_TIMEOUT, authenticating).await {
            Ok(Ok(result)) if result.success() => return Ok(()),
            Ok(Ok(result)) => {
                anyhow!("publickey authentication with {algorithm} failed: {result:?}")
            }
            Ok(Err(error)) => anyhow!("publickey authentication with {algorithm} failed: {error}"),
            Err(_) => anyhow!("publickey authentication with {algorithm} timed out"),
        };
        Err(self.explain(error))
    }

    /// Runs `command` in a new session channel, sends `stdin` followed by
    /// EOF, and collects the output until the channel closes.
    pub async fn exec(&self, command: &str, stdin: &[u8]) -> anyhow::Result<ExecOutput> {
        match timeout(STEP_TIMEOUT, self.exec_inner(command, stdin)).await {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(error)) => Err(self.explain(error)),
            Err(_) => Err(self.explain(anyhow!("`{command}` timed out after {STEP_TIMEOUT:?}"))),
        }
    }

    async fn exec_inner(&self, command: &str, stdin: &[u8]) -> anyhow::Result<ExecOutput> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|error| anyhow!("opening a session channel failed: {error}"))?;
        channel
            .exec(true, command)
            .await
            .map_err(|error| anyhow!("sending the exec request failed: {error}"))?;
        let (mut reader, writer) = channel.split();
        let write = async {
            if !stdin.is_empty() {
                writer.data(stdin).await?;
            }
            writer.eof().await
        };
        let read = async {
            let mut output = ExecOutput::default();
            while let Some(message) = reader.wait().await {
                match message {
                    ChannelMsg::Data { data } => output.stdout.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, ext: 1 } => {
                        output.stderr.extend_from_slice(&data)
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        output.exit_status = Some(exit_status)
                    }
                    ChannelMsg::Failure => bail!("the server refused to run `{command}`"),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            Ok(output)
        };
        let (written, output) = tokio::join!(write, read);
        let output = output?;
        if let Err(error) = written {
            ensure!(
                output.exit_status == Some(0),
                "sending stdin to `{command}` failed: {error}"
            );
        }
        Ok(output)
    }

    /// Runs `echo <nonce>` and checks that the nonce comes back with exit
    /// status 0.
    pub async fn check_echo(&self) -> anyhow::Result<()> {
        let nonce = nonce();
        let output = self.exec(&format!("echo {nonce}"), &[]).await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Tolerate extra lines from the user's shell startup files.
        if output.exit_status == Some(0) && stdout.lines().any(|line| line.trim_end() == nonce) {
            return Ok(());
        }
        Err(self.explain(anyhow!(
            "`echo {nonce}` returned exit status {:?}, stdout {stdout:?}, stderr {:?}",
            output.exit_status,
            String::from_utf8_lossy(&output.stderr),
        )))
    }

    /// Pipes `len` bytes through `cat` and checks that they come back
    /// unchanged. This spans many packets and both directions.
    pub async fn check_round_trip(&self, len: usize) -> anyhow::Result<()> {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let output = self.exec("cat", &payload).await?;
        // Tolerate a prefix from the user's shell startup files.
        if output.exit_status == Some(0) && output.stdout.ends_with(&payload) {
            return Ok(());
        }
        let same = output
            .stdout
            .iter()
            .zip(&payload)
            .take_while(|(a, b)| a == b)
            .count();
        Err(self.explain(anyhow!(
            "`cat` returned exit status {:?} and {} bytes instead of the {len} bytes sent \
             (identical prefix: {same} bytes), stderr {:?}",
            output.exit_status,
            output.stdout.len(),
            String::from_utf8_lossy(&output.stderr),
        )))
    }

    /// Sends `SSH_MSG_DISCONNECT`.
    pub async fn disconnect(self) -> anyhow::Result<()> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
            .map_err(|error| self.explain(anyhow!("disconnecting failed: {error}")))
    }
}

/// A string that is unique within this test run, without using an RNG.
fn nonce() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.subsec_nanos());
    format!(
        "russh-nonce-{}-{}-{nanos}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn is_aead(cipher: cipher::Name) -> bool {
    let name = cipher.as_ref();
    name.ends_with("-gcm@openssh.com") || name.starts_with("chacha20-poly1305")
}

// ---------------------------------------------------------------------------
// Cases and runners
// ---------------------------------------------------------------------------

/// One interop check: which algorithms to force, see the
/// [module documentation](self#forcing-algorithms).
#[derive(Clone, Debug)]
pub struct Case {
    /// Host key and host key algorithm.
    pub host_key: KeyAlg,
    /// User key and the algorithm it signs with.
    pub user_key: KeyAlg,
    pub kex: Option<kex::Name>,
    pub cipher: Option<cipher::Name>,
    pub mac: Option<mac::Name>,
    /// Bytes piped through `cat` after the `echo` check (0 to skip).
    pub round_trip: usize,
}

impl Default for Case {
    /// ECDSA P-256 host and user keys, default kex, cipher and MAC.
    fn default() -> Self {
        Case {
            host_key: KeyAlg::ECDSA_P256,
            user_key: KeyAlg::ECDSA_P256,
            kex: None,
            cipher: None,
            mac: None,
            round_trip: 100_003,
        }
    }
}

impl Case {
    pub fn with_host_key(mut self, host_key: KeyAlg) -> Self {
        self.host_key = host_key;
        self
    }

    pub fn with_user_key(mut self, user_key: KeyAlg) -> Self {
        self.user_key = user_key;
        self
    }

    pub fn with_kex(mut self, kex: kex::Name) -> Self {
        self.kex = Some(kex);
        self
    }

    pub fn with_cipher(mut self, cipher: cipher::Name) -> Self {
        self.cipher = Some(cipher);
        self
    }

    pub fn with_mac(mut self, mac: mac::Name) -> Self {
        self.mac = Some(mac);
        self
    }

    pub fn with_round_trip(mut self, len: usize) -> Self {
        self.round_trip = len;
        self
    }

    /// The client side: `Preferred::default()` restricted to this case's
    /// algorithms.
    pub fn preferred(&self) -> Preferred {
        let mut preferred = Preferred::default();
        if let Some(kex) = self.kex {
            preferred.kex = Cow::Owned(vec![
                kex,
                kex::EXTENSION_SUPPORT_AS_CLIENT,
                kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
            ]);
        }
        preferred.key = Cow::Owned(vec![self.host_key.algorithm()]);
        if let Some(cipher) = self.cipher {
            preferred.cipher = Cow::Owned(vec![cipher]);
        }
        if let Some(mac) = self.mac {
            preferred.mac = Cow::Owned(vec![mac]);
        }
        preferred
    }

    /// The server side: an sshd restricted to this case's algorithms.
    pub fn sshd(&self) -> SshdBuilder {
        let mut sshd = Sshd::builder()
            .host_key(self.host_key.key)
            .host_key_algorithms(self.host_key.name())
            .user_key(self.user_key.key)
            .pubkey_accepted_algorithms(self.user_key.name());
        if let Some(kex) = self.kex {
            sshd = sshd.kex_algorithms(kex.as_ref());
        }
        if let Some(cipher) = self.cipher {
            sshd = sshd.ciphers(cipher.as_ref());
        }
        if let Some(mac) = self.mac {
            sshd = sshd.macs(mac.as_ref());
        }
        sshd
    }

    /// Why `openssh` can't run this case, if it can't.
    pub fn unsupported_by(&self, openssh: &OpenSsh) -> Option<String> {
        let mut missing = Vec::new();
        let mut check = |query, kind: &str, name: &str| {
            let entry = format!("{kind} {name}");
            if !openssh.supports(query, name) && !missing.contains(&entry) {
                missing.push(entry);
            }
        };
        if let Some(kex) = self.kex {
            check(Query::Kex, "kex", kex.as_ref());
        }
        if let Some(cipher) = self.cipher {
            check(Query::Cipher, "cipher", cipher.as_ref());
        }
        if let Some(mac) = self.mac {
            check(Query::Mac, "MAC", mac.as_ref());
        }
        for key in [self.host_key, self.user_key] {
            check(Query::Key, "key type", key.key.openssh_name());
            check(Query::Sig, "signature algorithm", &key.name());
        }
        (!missing.is_empty()).then(|| {
            format!(
                "{} does not support {}",
                openssh.short_version(),
                missing.join(", ")
            )
        })
    }

    /// Checks the algorithms passed to `Handler::kex_done` against the
    /// forced ones.
    pub fn check_negotiated(&self, names: Option<&Names>) -> anyhow::Result<()> {
        let names = names.context("Handler::kex_done was never called")?;
        if let Some(kex) = self.kex {
            ensure!(
                names.kex == kex,
                "negotiated kex {} instead of {}",
                names.kex.as_ref(),
                kex.as_ref()
            );
        }
        let host_key = self.host_key.algorithm();
        ensure!(
            names.key == host_key,
            "negotiated host key algorithm {} instead of {}",
            names.key.as_str(),
            host_key.as_str()
        );
        if let Some(cipher) = self.cipher {
            ensure!(
                names.cipher == cipher,
                "negotiated cipher {} instead of {}",
                names.cipher.as_ref(),
                cipher.as_ref()
            );
        }
        if let Some(mac) = self.mac {
            ensure!(
                !is_aead(names.cipher),
                "MAC {} was forced but not used, because the negotiated cipher {} is an AEAD; \
                 force a non-AEAD cipher too",
                mac.as_ref(),
                names.cipher.as_ref()
            );
            ensure!(
                names.client_mac == mac && names.server_mac == mac,
                "negotiated MACs {} (client to server) and {} (server to client) instead of {}",
                names.client_mac.as_ref(),
                names.server_mac.as_ref(),
                mac.as_ref()
            );
        }
        Ok(())
    }

    /// The client side of [`run_case`].
    pub async fn run_client(&self, sshd: &Sshd) -> anyhow::Result<()> {
        let mut client = sshd.connect(self.preferred()).await?;
        client.authenticate(self.user_key.rsa_hash).await?;
        self.check_negotiated(client.negotiated().as_ref())?;
        client.check_echo().await?;
        if self.round_trip > 0 {
            client.check_round_trip(self.round_trip).await?;
        }
        client.disconnect().await
    }
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(kex) = self.kex {
            write!(f, "kex={} ", kex.as_ref())?;
        }
        if let Some(cipher) = self.cipher {
            write!(f, "cipher={} ", cipher.as_ref())?;
        }
        if let Some(mac) = self.mac {
            write!(f, "mac={} ", mac.as_ref())?;
        }
        write!(f, "host-key={} user-key={}", self.host_key, self.user_key)
    }
}

/// The result of one [`Case`].
#[derive(Debug)]
pub enum Outcome {
    Passed(Duration),
    /// Skipped, with the reason.
    Skipped(String),
    /// Failed, with the error and the sshd diagnostics.
    Failed(String),
}

/// Runs one case: starts an sshd restricted to the case's algorithms,
/// connects with a matching client, authenticates, checks the negotiated
/// algorithms, runs `echo <nonce>` and the `cat` round trip, and
/// disconnects. Never panics, except through [`available`] when OpenSSH is
/// missing and [`REQUIRE_ENV`] is set.
pub async fn run_case(case: &Case) -> Outcome {
    let _ = env_logger::try_init();
    let Some(openssh) = available() else {
        return Outcome::Skipped("OpenSSH is not available".into());
    };
    if let Some(reason) = case.unsupported_by(openssh) {
        return Outcome::Skipped(reason);
    }
    let started = Instant::now();
    let sshd = match case.sshd().start().await {
        Ok(sshd) => sshd,
        Err(error) => return Outcome::Failed(format!("starting sshd failed: {error:#}")),
    };
    match timeout(CASE_TIMEOUT, case.run_client(&sshd)).await {
        Ok(Ok(())) => Outcome::Passed(started.elapsed()),
        Ok(Err(error)) => Outcome::Failed(format!("{error:#}\n{}", sshd.diagnostics())),
        Err(_) => Outcome::Failed(format!(
            "timed out after {CASE_TIMEOUT:?}\n{}",
            sshd.diagnostics()
        )),
    }
}

/// Runs cases concurrently (see [`JOBS_ENV`]) and returns their outcomes
/// in order. If OpenSSH is not [`available`], all of them are skipped.
pub async fn run_cases(cases: impl IntoIterator<Item = Case>) -> Vec<(Case, Outcome)> {
    let cases: Vec<Case> = cases.into_iter().collect();
    if available().is_none() {
        let reason = || Outcome::Skipped("OpenSSH is not available".into());
        return cases.into_iter().map(|case| (case, reason())).collect();
    }
    let jobs = Arc::new(Semaphore::new(jobs()));
    let tasks: Vec<_> = cases
        .iter()
        .cloned()
        .map(|case| {
            let jobs = jobs.clone();
            tokio::spawn(async move {
                let _permit = jobs.acquire_owned().await;
                run_case(&case).await
            })
        })
        .collect();
    let mut results = Vec::with_capacity(cases.len());
    for (case, task) in cases.into_iter().zip(tasks) {
        let outcome = task.await.unwrap_or_else(|error| {
            let message = if error.is_panic() {
                panic_message(&*error.into_panic())
            } else {
                error.to_string()
            };
            Outcome::Failed(format!("the case panicked: {message}"))
        });
        results.push((case, outcome));
    }
    results
}

fn jobs() -> usize {
    std::env::var(JOBS_ENV)
        .ok()
        .and_then(|jobs| jobs.trim().parse().ok())
        .filter(|&jobs| jobs > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(4, |n| n.get())
                .clamp(2, 8)
        })
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "<non-string panic payload>".into()
    }
}

/// Prints a summary of `results` to stderr, then panics with the details of
/// every failed case, if any.
#[track_caller]
pub fn report(name: &str, results: &[(Case, Outcome)]) {
    let name = format!("{}: {name}", env!("CARGO_CRATE_NAME"));
    let version = detected().map_or("OpenSSH (not available)", OpenSsh::short_version);
    let (mut passed, mut skipped) = (0, 0);
    let mut lines = String::new();
    let mut failures = Vec::new();
    for (case, outcome) in results {
        let _ = match outcome {
            Outcome::Passed(elapsed) => {
                passed += 1;
                writeln!(lines, "  ok       {case} ({:.2}s)", elapsed.as_secs_f64())
            }
            Outcome::Skipped(reason) => {
                skipped += 1;
                writeln!(lines, "  skipped  {case}: {reason}")
            }
            Outcome::Failed(error) => {
                failures.push(format!("===== FAILED: {case} =====\n{error}"));
                writeln!(lines, "  FAILED   {case}")
            }
        };
    }
    log_line(&format!(
        "{name} against {version}: {passed} passed, {skipped} skipped, {} failed\n{lines}",
        failures.len()
    ));
    if !failures.is_empty() {
        panic!(
            "{name}: {} of {} OpenSSH interop case(s) failed:\n\n{}",
            failures.len(),
            results.len(),
            failures.join("\n\n")
        );
    }
}

/// Runs the cases (see [`run_cases`]) and [`report`]s the results under
/// `name`.
pub async fn check_cases(name: &str, cases: impl IntoIterator<Item = Case>) {
    let results = run_cases(cases).await;
    report(name, &results);
}

/// Checks each key exchange algorithm on top of `base`.
pub async fn check_kex(base: Case, algorithms: &[kex::Name]) {
    let cases = algorithms.iter().map(|&kex| base.clone().with_kex(kex));
    check_cases("kex", cases).await;
}

/// Checks each cipher on top of `base`.
pub async fn check_ciphers(base: Case, algorithms: &[cipher::Name]) {
    let cases = algorithms
        .iter()
        .map(|&cipher| base.clone().with_cipher(cipher));
    check_cases("ciphers", cases).await;
}

/// Checks each MAC on top of `base`, with `aes128-ctr` unless `base` sets a
/// (non-AEAD) cipher.
pub async fn check_macs(base: Case, algorithms: &[mac::Name]) {
    let base = match base.cipher {
        Some(_) => base,
        None => base.with_cipher(cipher::AES_128_CTR),
    };
    let cases = algorithms.iter().map(|&mac| base.clone().with_mac(mac));
    check_cases("MACs", cases).await;
}

/// Checks each host key algorithm on top of `base`.
pub async fn check_host_keys(base: Case, algorithms: &[KeyAlg]) {
    let cases = algorithms
        .iter()
        .map(|&host_key| base.clone().with_host_key(host_key));
    check_cases("host keys", cases).await;
}

/// Checks publickey authentication with each user key algorithm on top of
/// `base`.
pub async fn check_user_keys(base: Case, algorithms: &[KeyAlg]) {
    let cases = algorithms
        .iter()
        .map(|&user_key| base.clone().with_user_key(user_key));
    check_cases("user keys", cases).await;
}
