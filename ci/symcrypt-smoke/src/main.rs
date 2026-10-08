//! CI smoke test for the native SymCrypt library.
//!
//! Built against the same `symcrypt` revision as russh, so a successful run shows that the library
//! provisioned by `.github/actions/setup-symcrypt` links, loads at runtime, and computes the
//! primitives russh relies on. The process exits non-zero if any check fails.

use std::process::ExitCode;

use symcrypt::cipher::BlockCipherType;
use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use symcrypt::errors::SymCryptError;
use symcrypt::gcm::GcmExpandedKey;
use symcrypt::hash::sha256;
use symcrypt::hmac::hmac_sha256;
use symcrypt::mlkem::{MlKemKey, MlKemParams};
use symcrypt::symcrypt_random;

type CheckResult = Result<(), String>;
type Check = (&'static str, fn() -> CheckResult);

const CHECKS: &[Check] = &[
    ("symcrypt_random", random),
    ("SHA-256 known answers (FIPS 180-2)", sha256_kat),
    ("HMAC-SHA256 known answer (RFC 4231)", hmac_sha256_kat),
    (
        "AES-GCM known answer, round trip, tamper rejection",
        aes_gcm,
    ),
    ("ECDH P-256 round trip", ecdh_p256),
    ("X25519 known answer (RFC 7748) and round trip", x25519),
    ("ML-KEM-768 encapsulate/decapsulate", mlkem768),
];

fn main() -> ExitCode {
    let mut failures = 0;
    for (name, check) in CHECKS {
        match check() {
            Ok(()) => println!("ok   {name}"),
            Err(err) => {
                failures += 1;
                println!("FAIL {name}: {err}");
            }
        }
    }

    if failures == 0 {
        println!("all {} SymCrypt checks passed", CHECKS.len());
        ExitCode::SUCCESS
    } else {
        eprintln!("{failures} of {} SymCrypt checks failed", CHECKS.len());
        ExitCode::FAILURE
    }
}

fn random() -> CheckResult {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    symcrypt_random(&mut a);
    symcrypt_random(&mut b);
    if a == [0u8; 32] || b == [0u8; 32] {
        return Err("returned an all-zero buffer".into());
    }
    if a == b {
        return Err("two calls returned the same bytes".into());
    }
    Ok(())
}

fn sha256_kat() -> CheckResult {
    expect_eq(
        "SHA-256(\"abc\")",
        &sha256(b"abc"),
        &unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    )?;
    expect_eq(
        "SHA-256(\"\")",
        &sha256(b""),
        &unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    )
}

fn hmac_sha256_kat() -> CheckResult {
    // RFC 4231, test case 2.
    let mac =
        hmac_sha256(b"Jefe", b"what do ya want for nothing?").map_err(failed("hmac_sha256"))?;
    expect_eq(
        "HMAC-SHA256",
        &mac,
        &unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    )
}

fn aes_gcm() -> CheckResult {
    // AES-128 test case 4 from the GCM specification (McGrew and Viega).
    let key = unhex("feffe9928665731c6d6a8f9467308308");
    let nonce = nonce(&unhex("cafebabefacedbaddecaf888"));
    let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let plaintext = unhex(concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    ));
    let ciphertext = unhex(concat!(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
    ));
    let tag = unhex("5bc94fbc3221a5db94fae95ae7121a47");

    let gcm = GcmExpandedKey::new(&key, BlockCipherType::AesBlock)
        .map_err(failed("GcmExpandedKey::new (AES-128)"))?;
    let mut buf = plaintext.clone();
    let mut computed_tag = [0u8; 16];
    gcm.encrypt_in_place(&nonce, &aad, &mut buf, &mut computed_tag);
    expect_eq("AES-128-GCM ciphertext", &buf, &ciphertext)?;
    expect_eq("AES-128-GCM tag", &computed_tag, &tag)?;
    gcm.decrypt_in_place(&nonce, &aad, &mut buf, &tag)
        .map_err(failed("AES-128-GCM decrypt"))?;
    expect_eq("AES-128-GCM decrypted plaintext", &buf, &plaintext)?;

    // AES-256 with a random key and nonce; a modified tag must be rejected.
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    symcrypt_random(&mut key);
    symcrypt_random(&mut nonce);
    let gcm = GcmExpandedKey::new(&key, BlockCipherType::AesBlock)
        .map_err(failed("GcmExpandedKey::new (AES-256)"))?;
    let message = b"russh symcrypt smoke test: aes256-gcm@openssh.com";
    let aad = 4u32.to_be_bytes();
    let mut buf = message.to_vec();
    let mut tag = [0u8; 16];
    gcm.encrypt_in_place(&nonce, &aad, &mut buf, &mut tag);
    if buf == message {
        return Err("AES-256-GCM encryption left the plaintext unchanged".into());
    }

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    let mut copy = buf.clone();
    match gcm.decrypt_in_place(&nonce, &aad, &mut copy, &bad_tag) {
        Err(SymCryptError::AuthenticationFailure) => {}
        other => {
            return Err(format!(
                "AES-256-GCM with a modified tag returned {other:?}"
            ))
        }
    }

    gcm.decrypt_in_place(&nonce, &aad, &mut buf, &tag)
        .map_err(failed("AES-256-GCM decrypt"))?;
    expect_eq("AES-256-GCM round trip", &buf, message)
}

fn ecdh_p256() -> CheckResult {
    ecdh_round_trip(CurveType::NistP256)
}

fn x25519() -> CheckResult {
    // RFC 7748, section 6.1.
    let mut alice_private =
        unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_public = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    // SymCrypt only imports clamped scalars. X25519 clamps the scalar itself (decodeScalar25519),
    // so clamping up front leaves the expected public key and shared secret unchanged.
    alice_private[0] &= 248;
    alice_private[31] &= 127;
    alice_private[31] |= 64;

    let alice = EcKey::set_key_pair(
        CurveType::Curve25519,
        &alice_private,
        None,
        EcKeyUsage::EcDh,
    )
    .map_err(failed("set_key_pair (X25519)"))?;
    let derived_public = alice
        .export_public_key()
        .map_err(failed("export_public_key (X25519)"))?;
    expect_eq("X25519 public key", &derived_public, &alice_public)?;
    let bob = EcKey::set_public_key(CurveType::Curve25519, &bob_public, EcKeyUsage::EcDh)
        .map_err(failed("set_public_key (X25519)"))?;
    let secret = alice
        .ecdh_secret_agreement(bob)
        .map_err(failed("ecdh_secret_agreement (X25519)"))?;
    expect_eq("X25519 shared secret", &secret, &shared)?;

    ecdh_round_trip(CurveType::Curve25519)
}

fn ecdh_round_trip(curve: CurveType) -> CheckResult {
    let alice =
        EcKey::generate_key_pair(curve, EcKeyUsage::EcDh).map_err(failed("generate_key_pair"))?;
    let bob =
        EcKey::generate_key_pair(curve, EcKeyUsage::EcDh).map_err(failed("generate_key_pair"))?;
    let alice_public = alice
        .export_public_key()
        .map_err(failed("export_public_key"))?;
    let bob_public = bob
        .export_public_key()
        .map_err(failed("export_public_key"))?;
    let alice_public = EcKey::set_public_key(curve, &alice_public, EcKeyUsage::EcDh)
        .map_err(failed("set_public_key"))?;
    let bob_public = EcKey::set_public_key(curve, &bob_public, EcKeyUsage::EcDh)
        .map_err(failed("set_public_key"))?;

    let alice_secret = alice
        .ecdh_secret_agreement(bob_public)
        .map_err(failed("ecdh_secret_agreement"))?;
    let bob_secret = bob
        .ecdh_secret_agreement(alice_public)
        .map_err(failed("ecdh_secret_agreement"))?;
    expect_eq(
        &format!("{curve:?} shared secrets"),
        &alice_secret,
        &bob_secret,
    )?;
    if alice_secret.len() != curve.get_size() as usize || alice_secret.iter().all(|&b| b == 0) {
        return Err(format!(
            "{curve:?} shared secret {} is malformed",
            hex(&alice_secret)
        ));
    }
    Ok(())
}

fn mlkem768() -> CheckResult {
    let params = MlKemParams::MlKem768;
    let receiver = MlKemKey::generate_key_pair(params).map_err(failed("generate_key_pair"))?;
    let encapsulation_key = receiver
        .export_encapsulation_key()
        .map_err(failed("export_encapsulation_key"))?;
    if encapsulation_key.len() != 1184 {
        return Err(format!(
            "encapsulation key is {} bytes, expected 1184",
            encapsulation_key.len()
        ));
    }

    let sender = MlKemKey::from_encapsulation_key(params, &encapsulation_key)
        .map_err(failed("from_encapsulation_key"))?;
    let encapsulation = sender.encapsulate().map_err(failed("encapsulate"))?;
    if encapsulation.ciphertext.len() != 1088 {
        return Err(format!(
            "ciphertext is {} bytes, expected 1088",
            encapsulation.ciphertext.len()
        ));
    }

    let secret = receiver
        .decapsulate(&encapsulation.ciphertext)
        .map_err(failed("decapsulate"))?;
    expect_eq(
        "ML-KEM-768 shared secret",
        secret.as_bytes(),
        encapsulation.shared_secret.as_bytes(),
    )?;

    // Implicit rejection: a modified ciphertext decapsulates to an unrelated secret.
    let mut ciphertext = encapsulation.ciphertext.clone();
    ciphertext[0] ^= 1;
    let rejected = receiver
        .decapsulate(&ciphertext)
        .map_err(failed("decapsulate (modified ciphertext)"))?;
    if rejected.as_bytes() == encapsulation.shared_secret.as_bytes() {
        return Err("a modified ciphertext decapsulated to the original secret".into());
    }
    Ok(())
}

fn failed(operation: &'static str) -> impl FnOnce(SymCryptError) -> String {
    move |err| format!("{operation} failed: {err:?}")
}

fn expect_eq(what: &str, actual: &[u8], expected: &[u8]) -> CheckResult {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{what} mismatch: got {}, expected {}",
            hex(actual),
            hex(expected)
        ))
    }
}

fn nonce(bytes: &[u8]) -> [u8; 12] {
    bytes
        .try_into()
        .expect("GCM nonce literal must be 12 bytes")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex literal");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex literal"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
