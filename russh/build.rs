//! Selects the crypto backend: the one place that turns the backend features
//! into the `russh_backend` cfg used by `src/crypto` (see its module docs).
//!
//! Precedence when several backends are enabled is `aws-lc-rs` > `ring` >
//! `symcrypt`, so default and `--all-features` builds keep using aws-lc-rs.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=RUSSH_REQUIRE_BACKEND");
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

    if let Ok(raw) = std::env::var("RUSSH_REQUIRE_BACKEND") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let (required, required_name) = match trimmed {
                "aws-lc-rs" | "aws_lc" => ("aws_lc", "aws-lc-rs"),
                "ring" => ("ring", "ring"),
                "symcrypt" => ("symcrypt", "symcrypt"),
                _ => {
                    println!(
                        "cargo::error=RUSSH_REQUIRE_BACKEND={raw:?} is not a known russh crypto backend (expected `aws-lc-rs`, `ring`, or `symcrypt`)"
                    );
                    return;
                }
            };
            if backend != Some(required) {
                let selected_name = match backend {
                    Some("aws_lc") => "aws-lc-rs",
                    Some(other) => other,
                    None => "none",
                };
                let enabled_features: Vec<&str> = [
                    ("AWS_LC_RS", "aws-lc-rs"),
                    ("RING", "ring"),
                    ("SYMCRYPT", "symcrypt"),
                ]
                .into_iter()
                .filter_map(|(env, name)| enabled(env).then_some(name))
                .collect();
                let enabled = if enabled_features.is_empty() {
                    "none".to_string()
                } else {
                    enabled_features.join(", ")
                };
                println!(
                    "cargo::error=RUSSH_REQUIRE_BACKEND requires the `{required_name}` backend, but russh selected `{selected_name}` (enabled backend features: {enabled}); run `cargo tree -e features -i russh` to see which dependency enabled `{selected_name}`"
                );
            }
        }
    }
}
