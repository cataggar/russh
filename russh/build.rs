//! Selects the crypto backend: the one place that turns the backend features
//! into the `russh_backend` cfg used by `src/crypto` (see its module docs).
//!
//! Precedence when several backends are enabled is `aws-lc-rs` > `ring` >
//! `symcrypt`, so default and `--all-features` builds keep using aws-lc-rs.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!(
        "cargo::rustc-check-cfg=cfg(russh_backend, values(\"aws_lc\", \"ring\", \"symcrypt\"))"
    );
    // Set when the symcrypt backend takes Ed25519 from aws-lc-rs (feature
    // `ed25519-aws-lc`).
    println!("cargo::rustc-check-cfg=cfg(russh_ed25519_aws_lc)");

    let enabled = |feature: &str| std::env::var_os(format!("CARGO_FEATURE_{feature}")).is_some();
    let backend = if enabled("AWS_LC_RS") {
        Some("aws_lc")
    } else if enabled("RING") {
        Some("ring")
    } else if enabled("SYMCRYPT") {
        Some("symcrypt")
    } else {
        // lib.rs reports the missing backend with a `compile_error!`.
        None
    };
    if let Some(backend) = backend {
        println!("cargo::rustc-cfg=russh_backend=\"{backend}\"");
    }
    if backend == Some("symcrypt") && enabled("ED25519_AWS_LC") {
        println!("cargo::rustc-cfg=russh_ed25519_aws_lc");
    }
}
