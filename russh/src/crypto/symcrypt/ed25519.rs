//! Ed25519 (`ssh-ed25519`) for the SymCrypt backend, from `aws-lc-rs`
//! (feature `ed25519-aws-lc`): SymCrypt has no EdDSA
//! (<https://github.com/microsoft/SymCrypt/issues/43>).
//!
//! This is the only code of the symcrypt backend that uses `aws-lc-rs`, and
//! only for Ed25519:
//! - signing with Ed25519 private keys and verifying `ssh-ed25519`
//!   signatures, for host keys, user authentication and certificate CAs
//!   (`sign.rs`);
//! - computing the public key of a seed, to generate keys (`keys.rs`) and to
//!   load and check Ed25519 PKCS#8 keys (`crate::keys::format::pkcs8`).
//!
//! The seeds of new keys come from SymCrypt's RNG, and every other algorithm
//! stays in SymCrypt.
//!
//! TODO(<https://github.com/cataggar/russh/issues/62>): use SymCrypt once it
//! implements EdDSA.

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, VerificationAlgorithm};
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey};
use ssh_key::public::Ed25519PublicKey;
use zeroize::Zeroizing;

/// An Ed25519 private key imported into aws-lc-rs, which checked that its
/// public key is the one of its seed. Dropping it frees it.
pub(crate) struct SigningKey(Ed25519KeyPair);

impl SigningKey {
    /// Fails with `ssh_key::Error::Crypto` if the public key of `keypair` is
    /// not the one of its seed.
    pub(crate) fn import(keypair: &Ed25519Keypair) -> ssh_key::Result<Self> {
        Ed25519KeyPair::from_seed_and_public_key(keypair.private.as_ref(), keypair.public.as_ref())
            .map(Self)
            .map_err(|error| {
                log::error!("aws-lc-rs rejected an Ed25519 private key: {error}");
                ssh_key::Error::Crypto
            })
    }

    /// The 64-byte signature of `message` (RFC 8032, section 5.1.6).
    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).as_ref().to_vec()
    }
}

/// Verifies a 64-byte Ed25519 `signature` of `message` (RFC 8032, section
/// 5.1.7).
pub(crate) fn verify(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &[u8],
) -> signature::Result<()> {
    ED25519
        .verify_sig(public_key.as_ref(), message, signature)
        .map_err(|_| signature::Error::new())
}

/// The key pair of `seed`, with its public key computed by aws-lc-rs.
pub(crate) fn keypair(
    seed: &[u8; Ed25519PrivateKey::BYTE_SIZE],
) -> ssh_key::Result<Ed25519Keypair> {
    let derived = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|error| {
        log::error!("aws-lc-rs rejected an Ed25519 seed: {error}");
        ssh_key::Error::Crypto
    })?;
    Ok(Ed25519Keypair {
        public: Ed25519PublicKey::try_from(derived.public_key().as_ref())?,
        private: Ed25519PrivateKey::from_bytes(seed),
    })
}

/// A new key pair, from a seed that SymCrypt's RNG makes.
pub(crate) fn generate() -> ssh_key::Result<Ed25519Keypair> {
    let mut seed = Zeroizing::new([0; Ed25519PrivateKey::BYTE_SIZE]);
    ::symcrypt::symcrypt_random(&mut *seed);
    keypair(&seed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use hex_literal::hex;

    use super::*;

    /// An RFC 8032 test vector.
    struct Vector {
        seed: &'static [u8; 32],
        public: [u8; 32],
        message: &'static [u8],
        signature: [u8; 64],
    }

    /// RFC 8032, section 7.1: TEST 1 (empty message), TEST 2 (one byte) and
    /// TEST 3 (two bytes).
    const RFC8032: [Vector; 3] = [
        Vector {
            seed: &hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
            public: hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            message: b"",
            signature: hex!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
        },
        Vector {
            seed: &hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
            public: hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            message: &hex!("72"),
            signature: hex!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
        },
        Vector {
            seed: &hex!("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
            public: hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
            message: &hex!("af82"),
            signature: hex!(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            ),
        },
    ];

    #[test]
    fn rfc8032_known_answers() {
        for Vector {
            seed,
            public,
            message,
            signature,
        } in RFC8032
        {
            let keypair = keypair(seed).unwrap();
            assert_eq!(keypair.public.0, public);
            assert_eq!(
                SigningKey::import(&keypair).unwrap().sign(message),
                signature
            );
            verify(&keypair.public, message, &signature).unwrap();

            let mut tampered = signature;
            tampered[0] ^= 1;
            assert!(verify(&keypair.public, message, &tampered).is_err());
            assert!(verify(&keypair.public, b"tampered", &signature).is_err());
            assert!(verify(&keypair.public, message, &signature[..63]).is_err());
        }
    }

    #[test]
    fn mismatched_keys_are_rejected() {
        let mut keypair = keypair(RFC8032[0].seed).unwrap();
        keypair.public = Ed25519PublicKey(RFC8032[1].public);
        assert!(matches!(
            SigningKey::import(&keypair),
            Err(ssh_key::Error::Crypto)
        ));
    }

    #[test]
    fn generated_keys_sign() {
        let first = generate().unwrap();
        let second = generate().unwrap();
        assert_ne!(first.private.to_bytes(), second.private.to_bytes());
        let signature = SigningKey::import(&first).unwrap().sign(b"message");
        verify(&first.public, b"message", &signature).unwrap();
        assert!(verify(&second.public, b"message", &signature).is_err());
    }
}
