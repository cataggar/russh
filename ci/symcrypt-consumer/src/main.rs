//! A downstream crate that depends on russh with only the `symcrypt` feature
//! (`default-features = false, features = ["symcrypt"]`). It is its own workspace, so no other
//! package can add russh features through feature unification. `.github/workflows/symcrypt.yml`
//! builds it, checks its dependency graph with `ci/symcrypt-ban-check.sh` and runs it.
//!
//! - `symcrypt-consumer` prints the algorithms `Preferred::default()` offers, and fails if a list
//!   other than `host_key_certificates` is empty.
//! - `symcrypt-consumer <host> <port> <user> <private key> <host public key> <command>...` connects
//!   to an SSH server that must present the given host key, authenticates with the private key,
//!   runs the command, copies its output and exits with its exit status. The negotiated algorithms
//!   are printed to stderr.

use std::error::Error;
use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{
    load_public_key, load_secret_key, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate,
};
use russh::{client, ChannelMsg, Disconnect, Names, Preferred};

const USAGE: &str =
    "usage: symcrypt-consumer [<host> <port> <user> <private key> <host public key> <command>...]";

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.is_empty() {
        print_algorithms()
    } else {
        run_command(&args).await
    };
    result.unwrap_or_else(|error| {
        eprintln!("symcrypt-consumer: {error}");
        ExitCode::FAILURE
    })
}

fn print_algorithms() -> Result<ExitCode, Box<dyn Error>> {
    let preferred = Preferred::default();
    let lists: [(&str, Vec<&str>); 6] = [
        ("kex", preferred.kex.iter().map(AsRef::as_ref).collect()),
        ("key", preferred.key.iter().map(|a| a.as_str()).collect()),
        (
            "host_key_certificates",
            preferred
                .host_key_certificates
                .iter()
                .map(|a| a.as_str())
                .collect(),
        ),
        (
            "cipher",
            preferred.cipher.iter().map(AsRef::as_ref).collect(),
        ),
        ("mac", preferred.mac.iter().map(AsRef::as_ref).collect()),
        (
            "compression",
            preferred.compression.iter().map(AsRef::as_ref).collect(),
        ),
    ];
    for (name, list) in &lists {
        println!("{name}: {}", list.join(","));
    }
    for (name, list) in &lists {
        if list.is_empty() && *name != "host_key_certificates" {
            return Err(format!("Preferred::default().{name} is empty").into());
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_command(args: &[String]) -> Result<ExitCode, Box<dyn Error>> {
    let [host, port, user, private_key, host_key, command @ ..] = args else {
        return Err(USAGE.into());
    };
    if command.is_empty() {
        return Err(USAGE.into());
    }
    let port: u16 = port.parse()?;
    let private_key = load_secret_key(private_key, None)?;
    let host_key = load_public_key(host_key)?;

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let mut session = client::connect(config, (host.as_str(), port), Client { host_key }).await?;
    let rsa_hash = session.best_supported_rsa_hash().await?.flatten();
    let auth = session
        .authenticate_publickey(
            user,
            PrivateKeyWithHashAlg::new(Arc::new(private_key), rsa_hash),
        )
        .await?;
    if !auth.success() {
        return Err(format!("the server did not accept the key for {user}: {auth:?}").into());
    }

    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command.join(" ")).await?;
    let mut exit_status = None;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => std::io::stdout().write_all(&data)?,
            ChannelMsg::ExtendedData { data, .. } => std::io::stderr().write_all(&data)?,
            ChannelMsg::ExitStatus {
                exit_status: status,
            } => exit_status = Some(status),
            _ => {}
        }
    }
    session
        .disconnect(Disconnect::ByApplication, "", "en")
        .await?;

    let exit_status = exit_status.ok_or("the server did not send the command's exit status")?;
    Ok(ExitCode::from(u8::try_from(exit_status).unwrap_or(u8::MAX)))
}

struct Client {
    host_key: PublicKey,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                key.key_data() == self.host_key.key_data()
            }
            PublicKeyOrCertificate::Certificate(_) => false,
        })
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        eprintln!(
            "symcrypt-consumer: negotiated kex {}, host key {}, cipher {}",
            names.kex.as_ref(),
            names.key.as_str(),
            names.cipher.as_ref(),
        );
        Ok(())
    }
}
