//! Key agreement: X25519 (`curve25519-dalek`), ECDH on the NIST curves
//! (`p256`, `p384`, `p521`), ML-KEM-768 (`ml-kem`) and finite-field
//! Diffie-Hellman (`num-bigint`).

use std::marker::PhantomData;

use curve25519_dalek::montgomery::MontgomeryPoint;
use elliptic_curve::ecdh::EphemeralSecret;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, Generate};
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{KeyExport, TryKeyInit};
use num_bigint::{BigRng010, BigUint};
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, FfDh, Kem, KeyAgreement, ProviderRng, Result, fill_random};
use crate::kex::dh::groups::DhGroup;
use crate::kex::{self, KexType};

pub(crate) struct X25519;

impl KeyAgreement for X25519 {
    type PrivateKey = Zeroizing<[u8; 32]>;

    fn generate() -> Result<(Self::PrivateKey, Vec<u8>)> {
        let mut private_key = Zeroizing::new([0; 32]);
        fill_random(&mut private_key[..]);
        let public_key = MontgomeryPoint::mul_base_clamped(*private_key);
        Ok((private_key, public_key.0.to_vec()))
    }

    fn agree(
        private_key: Self::PrivateKey,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let peer_public_key = MontgomeryPoint(peer_public_key.try_into().map_err(|_| CryptoError)?);
        let shared = peer_public_key.mul_clamped(*private_key);
        Ok(Zeroizing::new(shared.0.to_vec()))
    }
}

/// ECDH with ephemeral keys on curve `C`; public keys are uncompressed SEC1
/// points and the shared secret is the x-coordinate.
pub(crate) struct Ecdh<C>(PhantomData<C>);

pub(crate) type NistP256 = Ecdh<p256::NistP256>;
pub(crate) type NistP384 = Ecdh<p384::NistP384>;
pub(crate) type NistP521 = Ecdh<p521::NistP521>;

impl<C> KeyAgreement for Ecdh<C>
where
    C: CurveArithmetic + PointCompression,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    EphemeralSecret<C>: Send,
{
    type PrivateKey = EphemeralSecret<C>;

    fn generate() -> Result<(Self::PrivateKey, Vec<u8>)> {
        let private_key = EphemeralSecret::<C>::generate_from_rng(&mut ProviderRng);
        let public_key = private_key.public_key().to_sec1_bytes().into_vec();
        Ok((private_key, public_key))
    }

    fn agree(
        private_key: Self::PrivateKey,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let peer_public_key = elliptic_curve::PublicKey::<C>::from_sec1_bytes(peer_public_key)
            .map_err(|_| CryptoError)?;
        let shared = private_key.diffie_hellman(&peer_public_key);
        Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
    }
}

pub(crate) struct MlKem768;

impl Kem for MlKem768 {
    type DecapsulationKey = Box<DecapsulationKey<ml_kem::MlKem768>>;

    fn generate() -> Result<(Self::DecapsulationKey, Vec<u8>)> {
        let (decapsulation_key, encapsulation_key) =
            <ml_kem::MlKem768 as ml_kem::Kem>::generate_keypair_from_rng(&mut ProviderRng);
        Ok((
            Box::new(decapsulation_key),
            encapsulation_key.to_bytes().to_vec(),
        ))
    }

    fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let encapsulation_key =
            EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(encapsulation_key)
                .map_err(|_| CryptoError)?;
        let (ciphertext, shared) = encapsulation_key.encapsulate_with_rng(&mut ProviderRng);
        Ok((ciphertext.to_vec(), Zeroizing::new(shared.to_vec())))
    }

    fn decapsulate(
        decapsulation_key: &Self::DecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let ciphertext =
            ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(ciphertext).map_err(|_| CryptoError)?;
        Ok(Zeroizing::new(
            decapsulation_key.decapsulate(&ciphertext).to_vec(),
        ))
    }
}

/// Finite-field Diffie-Hellman in a safe-prime group.
pub(crate) struct Dh {
    prime: BigUint,
    private_key: BigUint,
}

impl FfDh for Dh {
    fn generate(group: &DhGroup, is_server: bool) -> Result<(Self, Vec<u8>)> {
        let prime = BigUint::from_bytes_be(&group.prime);
        let generator = BigUint::from_bytes_be(&group.generator);
        let one = BigUint::from(1u8);
        if prime <= one {
            return Err(CryptoError);
        }
        // The private exponent is drawn from [1, q) (server) or [2, q)
        // (client), with q = (p - 1) / 2.
        let q = (&prime - &one) / BigUint::from(2u8);
        let low = if is_server { one } else { BigUint::from(2u8) };
        if low >= q {
            return Err(CryptoError);
        }
        let private_key = ProviderRng.random_biguint_range(&low, &q);
        let public_key = generator.modpow(&private_key, &prime);
        if !in_range(&public_key, &prime) {
            return Err(CryptoError);
        }
        Ok((Self { prime, private_key }, public_key.to_bytes_be()))
    }

    fn agree(&self, peer_public_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let peer_public_key = BigUint::from_bytes_be(peer_public_key);
        if !in_range(&peer_public_key, &self.prime) {
            return Err(CryptoError);
        }
        let shared = peer_public_key.modpow(&self.private_key, &self.prime);
        if !in_range(&shared, &self.prime) {
            return Err(CryptoError);
        }
        Ok(Zeroizing::new(shared.to_bytes_be()))
    }
}

/// Whether `1 < x < p - 1`.
fn in_range(x: &BigUint, prime: &BigUint) -> bool {
    let one = BigUint::from(1u8);
    x > &one && *x < prime - &one
}

/// Every key exchange of this provider (`none` is shared by all providers).
pub(crate) static ALGORITHMS: &[(&kex::Name, &(dyn KexType + Send + Sync))] = &[
    (&kex::MLKEM768X25519_SHA256, &kex::_MLKEM768X25519_SHA256),
    (&kex::CURVE25519, &kex::_CURVE25519),
    (&kex::CURVE25519_PRE_RFC_8731, &kex::_CURVE25519),
    (&kex::DH_GEX_SHA1, &kex::_DH_GEX_SHA1),
    (&kex::DH_GEX_SHA256, &kex::_DH_GEX_SHA256),
    (&kex::DH_G1_SHA1, &kex::_DH_G1_SHA1),
    (&kex::DH_G14_SHA1, &kex::_DH_G14_SHA1),
    (&kex::DH_G14_SHA256, &kex::_DH_G14_SHA256),
    (&kex::DH_G15_SHA512, &kex::_DH_G15_SHA512),
    (&kex::DH_G16_SHA512, &kex::_DH_G16_SHA512),
    (&kex::DH_G17_SHA512, &kex::_DH_G17_SHA512),
    (&kex::DH_G18_SHA512, &kex::_DH_G18_SHA512),
    (&kex::ECDH_SHA2_NISTP256, &kex::_ECDH_SHA2_NISTP256),
    (&kex::ECDH_SHA2_NISTP384, &kex::_ECDH_SHA2_NISTP384),
    (&kex::ECDH_SHA2_NISTP521, &kex::_ECDH_SHA2_NISTP521),
];

/// Default key exchange preference (the RFC 8308 / strict-kex extension
/// pseudo-algorithms are appended by `Preferred`).
pub(crate) const DEFAULT_ORDER: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_GEX_SHA256,
    kex::DH_G18_SHA512,
    kex::DH_G17_SHA512,
    kex::DH_G16_SHA512,
    kex::DH_G15_SHA512,
    kex::DH_G14_SHA256,
];

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::kex::dh::groups::DH_GROUP14;

    fn agree<K: KeyAgreement>() {
        let (a, a_public) = K::generate().unwrap();
        let (b, b_public) = K::generate().unwrap();
        let a_shared = K::agree(a, &b_public).unwrap();
        let b_shared = K::agree(b, &a_public).unwrap();
        assert_eq!(a_shared, b_shared);
        assert!(K::agree(K::generate().unwrap().0, &[1, 2, 3]).is_err());
    }

    #[test]
    fn key_agreements_agree() {
        agree::<X25519>();
        agree::<NistP256>();
        agree::<NistP384>();
        agree::<NistP521>();
    }

    #[test]
    fn ecdh_public_keys_are_uncompressed() {
        assert_eq!(NistP256::generate().unwrap().1.first(), Some(&4));
        assert_eq!(NistP256::generate().unwrap().1.len(), 65);
    }

    #[test]
    fn ml_kem_round_trips() {
        let (dk, ek) = MlKem768::generate().unwrap();
        assert_eq!(ek.len(), 1184);
        let (ciphertext, shared) = MlKem768::encapsulate(&ek).unwrap();
        assert_eq!(ciphertext.len(), 1088);
        assert_eq!(MlKem768::decapsulate(&dk, &ciphertext).unwrap(), shared);
        assert!(MlKem768::encapsulate(&ek[1..]).is_err());
    }

    #[test]
    fn dh_agrees_and_validates_peer_keys() {
        let (client, client_public) = Dh::generate(&DH_GROUP14, false).unwrap();
        let (server, server_public) = Dh::generate(&DH_GROUP14, true).unwrap();
        assert_eq!(
            client.agree(&server_public).unwrap(),
            server.agree(&client_public).unwrap()
        );
        assert!(client.agree(&[1]).is_err());
        assert!(client.agree(&[]).is_err());
    }
}
