//! Signatures with the SymCrypt backend, for each key imported once or for
//! each signature:
//! `cargo bench -p russh --no-default-features --features symcrypt,_bench --bench symcrypt_sign`

#[cfg(russh_backend = "symcrypt")]
criterion::criterion_group!(benches, russh::keys::benchmark::bench);
#[cfg(russh_backend = "symcrypt")]
criterion::criterion_main!(benches);

// Another backend takes precedence over SymCrypt.
#[cfg(not(russh_backend = "symcrypt"))]
fn main() {}
