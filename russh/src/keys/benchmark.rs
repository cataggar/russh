//! Signature benchmarks of the SymCrypt backend, which imports each private
//! key into SymCrypt to sign with it (`benches/symcrypt_sign.rs`).
#![allow(clippy::unwrap_used)]

use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use criterion::Criterion;
use ssh_key::{HashAlg, PrivateKey};

/// The keys, from the backend's test fixtures, with the hash RSA signs with.
const KEYS: [(&str, &str, Option<HashAlg>); 4] = [
    (
        "ecdsa-sha2-nistp256",
        include_str!("../crypto/symcrypt/testdata/sign/ecdsa_p256.key"),
        None,
    ),
    (
        "ecdsa-sha2-nistp384",
        include_str!("../crypto/symcrypt/testdata/sign/ecdsa_p384.key"),
        None,
    ),
    (
        "ecdsa-sha2-nistp521",
        include_str!("../crypto/symcrypt/testdata/sign/ecdsa_p521.key"),
        None,
    ),
    (
        "rsa-sha2-256 (2048 bits)",
        include_str!("../crypto/symcrypt/testdata/sign/rsa_2048.key"),
        Some(HashAlg::Sha256),
    ),
];

/// What a host key signs: an exchange hash.
const MESSAGE: [u8; 32] = [0x5a; 32];

/// How many threads sign at once in the contended benchmark.
const THREADS: usize = 4;

pub fn bench(c: &mut Criterion) {
    for (name, openssh, hash_alg) in KEYS {
        let key = Arc::new(PrivateKey::from_openssh(openssh).unwrap());
        let mut group = c.benchmark_group(format!("Sign: {name}"));
        // As russh signs with host and user keys: imported once.
        group.bench_function("held key", |b| {
            b.iter(|| crate::crypto::sign_held(&key, 0, hash_alg, black_box(&MESSAGE)).unwrap())
        });
        // The time per signature of each thread.
        group.bench_function(format!("held key, {THREADS} threads"), |b| {
            b.iter_custom(|iterations| sign_concurrently(&key, hash_alg, iterations))
        });
        // As certificates are signed: imported for each signature.
        group.bench_function("key imported per signature", |b| {
            b.iter(|| crate::crypto::sign(&key, hash_alg, black_box(&MESSAGE)).unwrap())
        });
        group.finish();
    }
}

/// The time [`THREADS`] threads take to sign `iterations` times each with
/// `key`, all at once.
fn sign_concurrently(
    key: &Arc<PrivateKey>,
    hash_alg: Option<HashAlg>,
    iterations: u64,
) -> Duration {
    let barrier = Barrier::new(THREADS + 1);
    std::thread::scope(|scope| {
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    for _ in 0..iterations {
                        crate::crypto::sign_held(key, 0, hash_alg, black_box(&MESSAGE)).unwrap();
                    }
                })
            })
            .collect();
        barrier.wait();
        let start = Instant::now();
        for thread in threads {
            thread.join().unwrap();
        }
        start.elapsed()
    })
}
