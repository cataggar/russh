//! Key agreement for the SymCrypt backend: X25519 and ECDH on NIST P-256
//! and P-384 (`symcrypt::ecc`), and ML-KEM-768 (`symcrypt::mlkem`), which
//! run `curve25519-sha256` (and `@libssh.org`), `ecdh-sha2-nistp256`,
//! `ecdh-sha2-nistp384` and `mlkem768x25519-sha256`.
//!
//! ECDH on P-521 and finite-field Diffie-Hellman are not offered: `NistP521`
//! and `Dh` are [`Unsupported`], and `ecdh-sha2-nistp521`,
//! `diffie-hellman-group*` and `diffie-hellman-group-exchange-*` are not in
//! [`ALGORITHMS`].
//!
//! SymCrypt validates peer keys when importing them:
//! - NIST points must be uncompressed (`0x04 || x || y`, as OpenSSH sends
//!   and requires them), with coordinates below the field prime, on the
//!   curve and not the identity.
//! - X25519 keys are decoded as RFC 7748 §5 says (top bit masked,
//!   non-canonical values reduced), then must be in the prime-order
//!   subgroup: low-order points and points on the twist are rejected (RFC
//!   7748 §7 allows it; honest peers' keys are always in the subgroup).
//! - ML-KEM encapsulation keys get the FIPS 203 §7.2 checks; a malformed
//!   ciphertext of the right length is implicitly rejected (FIPS 203 §6.3).
//!
//! Private keys are wiped by SymCrypt when they are dropped (`EcKey`,
//! `MlKemKey`), and shared secrets are returned in [`Zeroizing`] buffers.

use std::marker::PhantomData;

use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use symcrypt::mlkem::{MlKemKey, MlKemParams};
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, Kem, KeyAgreement, Result, Unsupported};
use crate::kex::{self, KexType};

/// Not offered by this backend.
pub(crate) type NistP521 = Unsupported;
/// Not offered by this backend.
pub(crate) type Dh = Unsupported;

pub(crate) struct X25519;

impl KeyAgreement for X25519 {
    type PrivateKey = EcKey;

    fn generate() -> Result<(Self::PrivateKey, Vec<u8>)> {
        let private_key = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDh)
            .map_err(|_| CryptoError)?;
        let public_key = private_key.export_public_key().map_err(|_| CryptoError)?;
        Ok((private_key, public_key))
    }

    fn agree(
        private_key: Self::PrivateKey,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let peer_public_key = decode_u_coordinate(peer_public_key)?;
        let peer_public_key =
            EcKey::set_public_key(CurveType::Curve25519, &peer_public_key, EcKeyUsage::EcDh)
                .map_err(|_| CryptoError)?;
        private_key
            .ecdh_secret_agreement(peer_public_key)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError)
    }
}

/// Decodes an X25519 public key as RFC 7748 §5 says: the top bit is masked
/// and a non-canonical value (`p <= u < 2^255`) is reduced modulo
/// `p = 2^255 - 19`, since SymCrypt only imports canonical field elements.
fn decode_u_coordinate(public_key: &[u8]) -> Result<[u8; 32]> {
    let mut u: [u8; 32] = public_key.try_into().map_err(|_| CryptoError)?;
    let [low, middle @ .., high] = &mut u;
    *high &= 0x7f;
    // Little-endian, `p` is `ed ff .. ff 7f`: the values from `p` up differ
    // from it in the lowest byte only.
    if *high == 0x7f && middle.iter().all(|&b| b == 0xff) && *low >= 0xed {
        *low -= 0xed;
        middle.fill(0);
        *high = 0;
    }
    Ok(u)
}

/// A NIST curve to run ECDH on.
pub(crate) trait NistCurve {
    const CURVE: CurveType;
}

pub(crate) struct P256;

impl NistCurve for P256 {
    const CURVE: CurveType = CurveType::NistP256;
}

pub(crate) struct P384;

impl NistCurve for P384 {
    const CURVE: CurveType = CurveType::NistP384;
}

/// ECDH with ephemeral keys on curve `C`; public keys are uncompressed SEC1
/// points and the shared secret is the x-coordinate.
pub(crate) struct Ecdh<C>(PhantomData<C>);

pub(crate) type NistP256 = Ecdh<P256>;
pub(crate) type NistP384 = Ecdh<P384>;

/// SEC1 tag of an uncompressed point.
const UNCOMPRESSED: u8 = 0x04;

/// The SEC1 uncompressed encoding of `key`'s public key (SymCrypt exports
/// `x || y`).
fn sec1_public_key(key: &EcKey) -> Result<Vec<u8>> {
    let xy = key.export_public_key().map_err(|_| CryptoError)?;
    let mut public_key = Vec::with_capacity(1 + xy.len());
    public_key.push(UNCOMPRESSED);
    public_key.extend_from_slice(&xy);
    Ok(public_key)
}

impl<C: NistCurve> KeyAgreement for Ecdh<C> {
    type PrivateKey = EcKey;

    fn generate() -> Result<(Self::PrivateKey, Vec<u8>)> {
        let private_key =
            EcKey::generate_key_pair(C::CURVE, EcKeyUsage::EcDh).map_err(|_| CryptoError)?;
        let public_key = sec1_public_key(&private_key)?;
        Ok((private_key, public_key))
    }

    fn agree(
        private_key: Self::PrivateKey,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let xy = match peer_public_key.split_first() {
            Some((&UNCOMPRESSED, xy)) if xy.len() == 2 * C::CURVE.get_size() as usize => xy,
            _ => return Err(CryptoError),
        };
        let peer_public_key =
            EcKey::set_public_key(C::CURVE, xy, EcKeyUsage::EcDh).map_err(|_| CryptoError)?;
        private_key
            .ecdh_secret_agreement(peer_public_key)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError)
    }
}

pub(crate) struct MlKem768;

impl Kem for MlKem768 {
    type DecapsulationKey = MlKemKey;

    fn generate() -> Result<(Self::DecapsulationKey, Vec<u8>)> {
        let decapsulation_key =
            MlKemKey::generate_key_pair(MlKemParams::MlKem768).map_err(|_| CryptoError)?;
        let encapsulation_key = decapsulation_key
            .export_encapsulation_key()
            .map_err(|_| CryptoError)?;
        Ok((decapsulation_key, encapsulation_key))
    }

    fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let encapsulation_key =
            MlKemKey::from_encapsulation_key(MlKemParams::MlKem768, encapsulation_key)
                .map_err(|_| CryptoError)?;
        let encapsulation = encapsulation_key.encapsulate().map_err(|_| CryptoError)?;
        let shared_secret = Zeroizing::new(encapsulation.shared_secret.as_bytes().to_vec());
        Ok((encapsulation.ciphertext, shared_secret))
    }

    fn decapsulate(
        decapsulation_key: &Self::DecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let shared_secret = decapsulation_key
            .decapsulate(ciphertext)
            .map_err(|_| CryptoError)?;
        Ok(Zeroizing::new(shared_secret.as_bytes().to_vec()))
    }
}

/// Every key exchange of this backend (`none` is shared by all backends).
pub(crate) static ALGORITHMS: &[(&kex::Name, &(dyn KexType + Send + Sync))] = &[
    (&kex::MLKEM768X25519_SHA256, &kex::_MLKEM768X25519_SHA256),
    (&kex::CURVE25519, &kex::_CURVE25519),
    (&kex::CURVE25519_PRE_RFC_8731, &kex::_CURVE25519),
    (&kex::ECDH_SHA2_NISTP256, &kex::_ECDH_SHA2_NISTP256),
    (&kex::ECDH_SHA2_NISTP384, &kex::_ECDH_SHA2_NISTP384),
];

/// Default key exchange preference: all of them, in the order of
/// `kex::ALL_KEX_ALGORITHMS` (the RFC 8308 / strict-kex extension
/// pseudo-algorithms are appended by `Preferred`).
pub(crate) const DEFAULT_ORDER: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use hex_literal::hex;
    use ssh_encoding::Encode;

    use super::*;
    use crate::cipher::{self, SealingKey};
    use crate::crypto::symcrypt::hash::{Sha256, Sha384};
    use crate::crypto::{FfDh, Hash};
    use crate::kex::dh::groups::DH_GROUP14;
    use crate::kex::{
        KexAlgorithm, KexAlgorithmImplementor, SharedSecret, compute_keys, encode_mpint,
    };
    use crate::session::Exchange;
    use crate::{CryptoVec, mac};

    // RFC 7748 §6.1.
    const ALICE_PRIVATE: [u8; 32] =
        hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const ALICE_PUBLIC: [u8; 32] =
        hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const BOB_PRIVATE: [u8; 32] =
        hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const BOB_PUBLIC: [u8; 32] =
        hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const X25519_SHARED: [u8; 32] =
        hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    /// Imports an RFC 7748 scalar (SymCrypt only takes clamped ones).
    fn x25519_private_key(scalar: &[u8; 32]) -> EcKey {
        let mut scalar = *scalar;
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        EcKey::set_key_pair(CurveType::Curve25519, &scalar, None, EcKeyUsage::EcDh).unwrap()
    }

    fn x25519(scalar: &[u8; 32], u: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        X25519::agree(x25519_private_key(scalar), u)
    }

    #[test]
    fn x25519_rfc7748_diffie_hellman() {
        let alice = x25519_private_key(&ALICE_PRIVATE);
        assert_eq!(alice.export_public_key().unwrap(), ALICE_PUBLIC);
        assert_eq!(*X25519::agree(alice, &BOB_PUBLIC).unwrap(), X25519_SHARED);
        let bob = x25519_private_key(&BOB_PRIVATE);
        assert_eq!(bob.export_public_key().unwrap(), BOB_PUBLIC);
        assert_eq!(*X25519::agree(bob, &ALICE_PUBLIC).unwrap(), X25519_SHARED);
    }

    /// RFC 7748 §5.2: starting from `k = u = 9`, `k, u = X25519(k, u), k`.
    #[test]
    fn x25519_rfc7748_iterations() {
        let mut k = [0; 32];
        k[0] = 9;
        let mut u = k;
        for i in 1..=1000 {
            let next = x25519(&k, &u).unwrap();
            u = k;
            k = next.as_slice().try_into().unwrap();
            if i == 1 {
                assert_eq!(
                    k,
                    hex!("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        assert_eq!(
            k,
            hex!("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    /// RFC 7748 §5: the top bit is ignored, and `u` is taken modulo `p`.
    #[test]
    fn x25519_decodes_public_keys_like_rfc7748() {
        let mut bob = BOB_PUBLIC;
        bob[31] |= 0x80;
        assert_eq!(*x25519(&ALICE_PRIVATE, &bob).unwrap(), X25519_SHARED);

        // p + 9 = 9, the base point, with and without the top bit.
        let mut nine = hex!("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert_eq!(*x25519(&ALICE_PRIVATE, &nine).unwrap(), ALICE_PUBLIC);
        nine[31] |= 0x80;
        assert_eq!(*x25519(&ALICE_PRIVATE, &nine).unwrap(), ALICE_PUBLIC);
    }

    #[test]
    fn x25519_rejects_invalid_public_keys() {
        let u = |byte0: u8| {
            let mut u = [0; 32];
            u[0] = byte0;
            u
        };
        for public_key in [
            // Low order: 0, 1, two points of order 8, and p and p + 1
            // (0 and 1 again).
            u(0),
            u(1),
            hex!("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex!("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            // On the twist.
            u(2),
            // On the curve, outside the prime-order subgroup.
            u(4),
        ] {
            assert!(
                x25519(&ALICE_PRIVATE, &public_key).is_err(),
                "accepted {public_key:02x?}"
            );
        }
        for len in [0, 31, 33] {
            assert!(x25519(&ALICE_PRIVATE, &vec![9; len]).is_err());
        }
    }

    // RFC 5903 §8.1 and §8.2: private keys, public keys and shared secrets
    // of the initiator (`i`) and the responder (`r`).
    const P256_I: [u8; 32] =
        hex!("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    const P256_GI: [u8; 65] = hex!(
        "04"
        "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180"
        "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3"
    );
    const P256_R: [u8; 32] =
        hex!("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
    const P256_GR: [u8; 65] = hex!(
        "04"
        "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63"
        "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB"
    );
    const P256_GIRX: [u8; 32] =
        hex!("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

    const P384_I: [u8; 48] = hex!(
        "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655"
        "E35B538041E649EE3FAEF896783AB194"
    );
    const P384_GI: [u8; 97] = hex!(
        "04"
        "667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6"
        "DE3AC808ACB4BDB4C88732AEE95F41AA"
        "9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38E"
        "EB9FCFF3C2C947DAE69B4C634573A81C"
    );
    const P384_R: [u8; 48] = hex!(
        "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942"
        "E0308312916B8ED2960E4BD55A7448FC"
    );
    const P384_GR: [u8; 97] = hex!(
        "04"
        "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D"
        "0D1AC43A0336DEF96FDA41D0774A3571"
        "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FF"
        "F83FA40142209DFF5EAAD96DB9E6386C"
    );
    const P384_GIRX: [u8; 48] = hex!(
        "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4"
        "D603135569B9E9D09CF5D4A270F59746"
    );

    fn ecdh_private_key<C: NistCurve>(scalar: &[u8]) -> EcKey {
        EcKey::set_key_pair(C::CURVE, scalar, None, EcKeyUsage::EcDh).unwrap()
    }

    fn check_rfc5903<C: NistCurve>(i: &[u8], gi: &[u8], r: &[u8], gr: &[u8], girx: &[u8]) {
        let initiator = ecdh_private_key::<C>(i);
        assert_eq!(sec1_public_key(&initiator).unwrap(), gi);
        assert_eq!(*Ecdh::<C>::agree(initiator, gr).unwrap(), girx);
        let responder = ecdh_private_key::<C>(r);
        assert_eq!(sec1_public_key(&responder).unwrap(), gr);
        assert_eq!(*Ecdh::<C>::agree(responder, gi).unwrap(), girx);
    }

    #[test]
    fn ecdh_rfc5903_vectors() {
        check_rfc5903::<P256>(&P256_I, &P256_GI, &P256_R, &P256_GR, &P256_GIRX);
        check_rfc5903::<P384>(&P384_I, &P384_GI, &P384_R, &P384_GR, &P384_GIRX);
    }

    fn check_rejects_invalid_points<C: NistCurve>(i: &[u8], gr: &[u8], prime: &[u8]) {
        let size = C::CURVE.get_size() as usize;
        let (x, y) = gr[1..].split_at(size);
        let point = |tag: &[u8], x: &[u8], y: &[u8]| [tag, x, y].concat();
        let mut y_plus_one = y.to_vec();
        *y_plus_one.last_mut().unwrap() ^= 1;
        for public_key in [
            // Compressed (the parity of `y` is irrelevant: SymCrypt has no
            // decompression), hybrid and infinity encodings.
            point(&[0x02], x, &[]),
            point(&[0x03], x, &[]),
            point(&[0x06], x, y),
            point(&[0x07], x, y),
            vec![0x00],
            // Truncated, too long, untagged.
            gr[..gr.len() - 1].to_vec(),
            point(&[UNCOMPRESSED], x, &[y, &[0]].concat()),
            gr[1..].to_vec(),
            // Off the curve, the origin, a coordinate not reduced modulo p.
            point(&[UNCOMPRESSED], x, &y_plus_one),
            point(&[UNCOMPRESSED], &vec![0; size], &vec![0; size]),
            point(&[UNCOMPRESSED], prime, y),
            vec![],
        ] {
            assert!(
                Ecdh::<C>::agree(ecdh_private_key::<C>(i), &public_key).is_err(),
                "accepted {public_key:02x?}"
            );
        }
        assert!(Ecdh::<C>::agree(ecdh_private_key::<C>(i), gr).is_ok());
    }

    #[test]
    fn ecdh_rejects_invalid_public_keys() {
        check_rejects_invalid_points::<P256>(
            &P256_I,
            &P256_GR,
            &hex!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
        );
        check_rejects_invalid_points::<P384>(
            &P384_I,
            &P384_GR,
            &hex!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                "fffffffeffffffff0000000000000000ffffffff"
            ),
        );
        // A P-256 key on P-384 and the reverse.
        assert!(NistP384::agree(ecdh_private_key::<P384>(&P384_I), &P256_GR).is_err());
        assert!(NistP256::agree(ecdh_private_key::<P256>(&P256_I), &P384_GR).is_err());
    }

    #[test]
    fn key_agreements_agree() {
        fn agree<K: KeyAgreement>(public_key_len: usize) {
            let (a, a_public) = K::generate().unwrap();
            let (b, b_public) = K::generate().unwrap();
            assert_eq!(a_public.len(), public_key_len);
            assert_ne!(a_public, b_public);
            let a_shared = K::agree(a, &b_public).unwrap();
            let b_shared = K::agree(b, &a_public).unwrap();
            assert_eq!(a_shared, b_shared);
        }
        agree::<X25519>(32);
        agree::<NistP256>(65);
        agree::<NistP384>(97);
    }

    // An ML-KEM-768 key from the FIPS 203 key generation KAT used by
    // SymCrypt (`d || z`, kat_kem.dat), and a ciphertext for it with its
    // shared secret, from RustCrypto `ml-kem`'s deterministic encapsulation
    // (m = 00 01 .. 1f).
    const MLKEM_SEED: [u8; 64] = hex!(
        "e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dc"
        "a85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd"
    );
    /// SHA-256 of the KAT's encapsulation key.
    const MLKEM_EK_SHA256: [u8; 32] =
        hex!("7799c9d8eef172aa78c073514f2f039c240de8c5cb61bca82ba0bc46041ce279");
    const MLKEM_SHARED: [u8; 32] =
        hex!("3e90d7d7aa86b4428c227966abbf5ed6a3d82f3dd0b8b35e0fa799ce83d97590");
    /// The implicit rejection secret for the ciphertext with its last bit
    /// flipped.
    const MLKEM_REJECTED: [u8; 32] =
        hex!("11237fa938b7fff14713c96dae6e7a9a106301ac41e25dce0fe207721c221a92");

    #[test]
    fn ml_kem_768_known_answers() {
        let key = MlKemKey::from_private_seed(MlKemParams::MlKem768, &MLKEM_SEED).unwrap();
        let encapsulation_key = key.export_encapsulation_key().unwrap();
        assert_eq!(Sha256::digest(&encapsulation_key), MLKEM_EK_SHA256);
        assert_eq!(
            *MlKem768::decapsulate(&key, &MLKEM_CIPHERTEXT).unwrap(),
            MLKEM_SHARED
        );
        let mut ciphertext = MLKEM_CIPHERTEXT;
        ciphertext[1087] ^= 1;
        assert_eq!(
            *MlKem768::decapsulate(&key, &ciphertext).unwrap(),
            MLKEM_REJECTED
        );

        let (ciphertext, shared) = MlKem768::encapsulate(&encapsulation_key).unwrap();
        assert_eq!(MlKem768::decapsulate(&key, &ciphertext).unwrap(), shared);
    }

    #[test]
    fn ml_kem_768_round_trips_and_validates() {
        let (key, encapsulation_key) = MlKem768::generate().unwrap();
        assert_eq!(encapsulation_key.len(), 1184);
        let (ciphertext, shared) = MlKem768::encapsulate(&encapsulation_key).unwrap();
        assert_eq!(ciphertext.len(), 1088);
        assert_eq!(shared.len(), 32);
        assert_eq!(MlKem768::decapsulate(&key, &ciphertext).unwrap(), shared);

        assert!(MlKem768::encapsulate(&encapsulation_key[1..]).is_err());
        assert!(MlKem768::encapsulate(&[encapsulation_key.as_slice(), &[0]].concat()).is_err());
        assert!(MlKem768::decapsulate(&key, &ciphertext[1..]).is_err());
        assert!(MlKem768::decapsulate(&key, &[ciphertext.as_slice(), &[0]].concat()).is_err());
        // FIPS 203 §7.2 modulus check: a coefficient (12 bits) of 4095 >= q.
        let mut encapsulation_key = encapsulation_key;
        encapsulation_key[0] = 0xff;
        encapsulation_key[1] |= 0x0f;
        assert!(MlKem768::encapsulate(&encapsulation_key).is_err());
    }

    #[test]
    fn nistp521_and_dh_are_unsupported() {
        assert!(<NistP521 as KeyAgreement>::generate().is_err());
        assert!(<Dh as FfDh>::generate(&DH_GROUP14, false).is_err());
    }

    #[test]
    fn offers_exactly_the_supported_key_exchanges() {
        let expected = [
            kex::MLKEM768X25519_SHA256,
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::ECDH_SHA2_NISTP256,
            kex::ECDH_SHA2_NISTP384,
        ];
        assert_eq!(DEFAULT_ORDER, expected);
        assert!(ALGORITHMS.iter().map(|(name, _)| **name).eq(expected));
        for pref in [
            crate::Preferred::DEFAULT,
            crate::Preferred::COMPRESSED,
            crate::Preferred::default(),
        ] {
            assert_eq!(
                pref.kex[..],
                [
                    &expected[..],
                    &[
                        kex::EXTENSION_SUPPORT_AS_CLIENT,
                        kex::EXTENSION_SUPPORT_AS_SERVER,
                        kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                        kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                    ],
                ]
                .concat()
            );
        }
        let mut registered: Vec<_> = kex::KEXES.keys().map(|name| name.as_ref()).collect();
        registered.sort_unstable();
        let mut expected: Vec<_> = expected
            .iter()
            .chain([&kex::NONE])
            .map(|name| name.as_ref())
            .collect();
        expected.sort_unstable();
        assert_eq!(registered, expected);
    }

    /// The exchange hash framing of RFC 8731 §3.1 and RFC 5656 §4 (as in
    /// `compute_exchange_hash`), with fixed identification strings, KEXINIT
    /// payloads and host key.
    fn exchange_hash<H: Hash>(client_ephemeral: &[u8], server_ephemeral: &[u8], k: &[u8]) -> Vec<u8> {
        let mut host_key = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        host_key.extend(0..32);
        let mut buffer = CryptoVec::new();
        for string in [
            b"SSH-2.0-OpenSSH_9.6".as_slice(),
            b"SSH-2.0-russh",
            b"\x14client kexinit",
            b"\x14server kexinit",
            &host_key,
            client_ephemeral,
            server_ephemeral,
        ] {
            string.encode(&mut buffer).unwrap();
        }
        encode_mpint(k, &mut buffer).unwrap();
        H::digest_to_vec(&buffer)
    }

    /// The exchange hash of `curve25519-sha256` for the RFC 7748 §6.1 key
    /// pairs, which is also the session ID in [`key_derivation_known_answer`].
    const CURVE25519_H: [u8; 32] =
        hex!("5d2ce809f8117fb6a6642235e338396b38532f5d0bf0f95d79e56deb781a697a");

    /// Exchange hashes for the RFC 7748 and RFC 5903 key pairs, matching the
    /// RustCrypto backend's `compute_exchange_hash` and Python's `hashlib`.
    #[test]
    fn exchange_hash_known_answers() {
        let k = x25519(&ALICE_PRIVATE, &BOB_PUBLIC).unwrap();
        assert_eq!(
            exchange_hash::<Sha256>(&ALICE_PUBLIC, &BOB_PUBLIC, &k),
            CURVE25519_H
        );
        let k = NistP384::agree(ecdh_private_key::<P384>(&P384_I), &P384_GR).unwrap();
        assert_eq!(
            exchange_hash::<Sha384>(&P384_GI, &P384_GR, &k),
            hex!(
                "0109d565549f411f1bdfdf6568e42a21aab0c07fb3774ecb34e95e084ca7ca05"
                "e6ba6ac4d4bc02e834938947a6ad2c1d"
            )
        );
    }

    /// The first 64 bytes (two SHA-256 blocks) of the RFC 4253 §7.2 keys A
    /// to F for `K` = [`X25519_SHARED`] and `H` = `session_id` =
    /// [`CURVE25519_H`], from Python's `hashlib`.
    const DERIVED_KEYS: [[u8; 64]; 6] = [
        hex!(
            "c84a06d3b0ffc170b2f4b74949b45ea9d0863c0c3726e4dc4bba3e23585f8066"
            "14aa70957420960e97630a3936e90bdfaee118b2793c6d2bfc07ce227d55d5ef"
        ),
        hex!(
            "6a936ab1a0a51dccb637f6e035a07a151e00a822fd0d0bc5a6331d3693a8e62d"
            "33e198ceeadfad77335729880f8e3967a3dbf8af7e16773bf77083db9cbf8b53"
        ),
        hex!(
            "51a6516caad6452442a0fe0d51127cbc512555762b4ab2aede38bf0e0ca3a9c2"
            "b732f5f33411d42e09e61009d7b07c7bb10b4f37f130d1d5c0428fb8758e6907"
        ),
        hex!(
            "337f92b83e69361b71357893f1de425ec23f843216082ab0902f5dcce6ed9d0b"
            "de163b5e5eefb9131e353890977cd2b407b991eea1d5082568fafbce728d76f0"
        ),
        hex!(
            "3cf40a38f79bb413c1f8a584e83452d3269ae4ee00cc1c472dbf3a85b51997bf"
            "2ad67ac018dc6a9855a5651542f2da0ab85cee22cf915956bab2cf2717ddaf04"
        ),
        hex!(
            "cdaf5104ef10b642ea30438eb19dfc167166cfccb079f5a2e34a64a384d136a5"
            "6e7dc4630fb83267ed0727a707074293a5d525c3285d9328beac0c7e5f95a750"
        ),
    ];

    const PAYLOAD: &[u8] = b"\x05\0\0\0\x0cssh-userauth";

    /// Seals [`PAYLOAD`] in a packet like `SealingKey::write` does, but
    /// with zero padding.
    fn seal(key: &mut dyn SealingKey) -> Vec<u8> {
        let padding_length = key.padding_length(PAYLOAD);
        let mut packet = ((1 + PAYLOAD.len() + padding_length) as u32)
            .to_be_bytes()
            .to_vec();
        packet.push(padding_length as u8);
        packet.extend_from_slice(PAYLOAD);
        packet.resize(packet.len() + padding_length, 0);
        let mut tag = vec![0; key.tag_len()];
        key.seal(3, &mut packet, &mut tag);
        packet.extend(tag);
        packet
    }

    /// RFC 4253 §7.2 key derivation (`kex::compute_keys`) with this
    /// backend's SHA-256, for every cipher and MAC: the derived sealing keys
    /// seal like ones made from [`DERIVED_KEYS`].
    #[test]
    fn key_derivation_known_answer() {
        let [a, b, c, d, e, f] = &DERIVED_KEYS;
        let shared_secret = SharedSecret::from_mpint(&X25519_SHARED).unwrap();
        let mut longest_key = 0;
        for (&&cipher_name, &cipher) in cipher::CIPHERS.iter() {
            if cipher.key_len() == 0 {
                continue;
            }
            let macs: Vec<mac::Name> = if cipher.needs_mac() {
                mac::MACS.keys().map(|&&name| name).collect()
            } else {
                vec![mac::NONE]
            };
            for mac_name in macs {
                let mac = *mac::MACS.get(&mac_name).unwrap();
                for (is_server, key, nonce, mac_key) in [(false, c, a, e), (true, d, b, f)] {
                    let mut derived = compute_keys::<Sha256>(
                        Some(&shared_secret),
                        &CURVE25519_H,
                        &CURVE25519_H,
                        cipher_name,
                        mac_name,
                        mac_name,
                        is_server,
                    )
                    .unwrap()
                    .local_to_remote;
                    let mut expected = cipher.make_sealing_key(
                        &key[..cipher.key_len()],
                        &nonce[..cipher.nonce_len()],
                        &mac_key[..mac.key_len()],
                        mac,
                    );
                    assert_eq!(
                        seal(&mut *derived),
                        seal(&mut *expected),
                        "{cipher_name:?} {mac_name:?} server: {is_server}"
                    );
                }
                longest_key = longest_key.max(cipher.key_len().max(mac.key_len()));
            }
        }
        // At least one key needed a second hash block.
        assert!(longest_key > 32, "{longest_key}");
    }

    /// Both sides of every key exchange through the shared protocol code:
    /// they compute the same exchange hash, and the keys they derive from it
    /// interoperate.
    #[test]
    fn key_exchanges_agree() {
        let cipher_name = crate::Preferred::DEFAULT.cipher[0];
        let mac_name = crate::Preferred::DEFAULT.mac[0];
        for name in DEFAULT_ORDER {
            let kex_type = kex::KEXES.get(name).unwrap();
            let (mut client, mut server) = (kex_type.make(), kex_type.make());
            let mut exchange = Exchange::new(b"SSH-2.0-client", b"SSH-2.0-server");
            let mut init = Vec::new();
            client
                .client_dh(&mut exchange.client_ephemeral, &mut init)
                .unwrap();
            server.server_dh(&mut exchange, &init).unwrap();
            client
                .compute_shared_secret(&exchange.server_ephemeral)
                .unwrap();

            let host_key = b"\0\0\0\x08host key";
            let mut buffer = CryptoVec::new();
            let hash = client
                .compute_exchange_hash(host_key, &exchange, &mut buffer)
                .unwrap();
            assert_eq!(
                hash,
                server
                    .compute_exchange_hash(host_key, &exchange, &mut buffer)
                    .unwrap(),
                "{name:?}"
            );

            let keys = |kex: &KexAlgorithm, is_server| {
                kex.compute_keys(&hash, &hash, cipher_name, mac_name, mac_name, is_server)
                    .unwrap()
            };
            let mut client_keys = keys(&client, false);
            let mut server_keys = keys(&server, true);
            for (sealing, opening) in [
                (&mut client_keys.local_to_remote, &mut server_keys.remote_to_local),
                (&mut server_keys.local_to_remote, &mut client_keys.remote_to_local),
            ] {
                let mut packet = seal(&mut **sealing);
                let plaintext = opening.open(3, &mut packet).unwrap();
                assert_eq!(&plaintext[1..][..PAYLOAD.len()], PAYLOAD, "{name:?}");
            }
        }
    }

    const MLKEM_CIPHERTEXT: [u8; 1088] = hex!(
        "c608bfebb9a2349a594964aa0a136c392bb08f0cf86772bbc2d88ccb6979c47b"
        "3198c50acc7d7d8d6be54cc5218d463121c50e1c95792af899b4204c40ca46f6"
        "bf9faf88d99bd194f1817fc43b80614f59dd67499f6c400726fe56b60315d5fb"
        "9d551f42b0cc4c634dab9cb8b229f0b5beda9adfe779b45ec2405855454fe8b7"
        "303b9d4e6010ba8747ab693265c85080ae09268ea59be3a019ff0df602bc196f"
        "5474544ebf6d4e24e7f5fb7a0e5968275ffa72baebdc0cd7cf31acd2f849a149"
        "544ae486e99e79624d7f808e75e683540e1fb9d59ef86ba77dd9fda2bcf521d7"
        "c425d254763db0d1171167196068ceb5ac968324b42acd01786df85826ea5e3f"
        "855ae72b63d7729f9863558e7af3cbf102c2ec676b66dbb56d7bc8b1fe1cc990"
        "f65542e0c7453e0f78d1267ad10016ea03baae20e937e4f192f17ba71e2bc1af"
        "58abef7fe3a81be04e4690d827be4eb839e0e42c47b89c9b6d36b750102b3c72"
        "d7a57f1fd3a245e2bb55a4f20499d1da420c58e5d2df2cb2430c5c7591c326da"
        "af48fd4cb738dd156e44088a0695ca348b1c1c04a5fa9c414490f73c1bd78338"
        "4f672938a33c55fd3aee39a833c1311e5a515dc520fcf2bd0c2a9d4cbe6081b9"
        "5814ba634e1b9066b5fce190076c9dfaf44bc9e82db87438afd92e6af787a425"
        "2b28b8640b5e2c4e34376418e0bb8ff9ef40313cf00aa52cca42c6b7cf4e00bd"
        "769eea9125c6e467c91e6d98994fd7a33371ba6b64b21e24d5e2a80875cf5c3d"
        "69df9f261a916629ee6ada2a0f0c045051281e12dd849245e36381968f5a50cc"
        "a4915696d94804524365bccca536fdeb31a03afbc7ed177ed48d811f9578f0e3"
        "429031bda6c8e97b5268ce988cbbf1aa10202750b61e3bb5a432094c0a3bc103"
        "701e4462f0e4ea43ec99e766546ca217c8668b9103d5aa0ab6b55b1035ba5fdf"
        "dd437cae0e6fc074408d008fc04fa7240c603ab617803c257de343cb745bbe78"
        "01b873b9f6a4d868bd7353aae949614531c80b5fde400f53ed8e7a0d08cf2734"
        "9d2d8eeb77f55b1d911527252794de7fee2c6bd0e4a2a2610e0a62c23350713b"
        "dfa90ba6da73280b3e4d07a72c15823a970df207f18ea505af9d7ab70fa36ed7"
        "5030c5e2b20454ec4627d16295b3a8afe4bf79015289c711c165a521eea56f8e"
        "6df062b1dc24e43c1773fc876375e54a47bb7d334e97426ca18108e07c2e3a40"
        "3cd99d2730bbfccc969389a9df2441a07deea4af29a9073d12a81b00353aff4b"
        "d297c98bbf850b067e94f709dfbc9baa5d60fce7a2c73eee364f8665cdc7166b"
        "f9a355be3f4215bd90f5d4cb1ea8cfc4ae7718b22754b05b17ea567f388532f7"
        "80ec77cb60e048202fac66bae0f80fd1cdfe26668b9026a079f081487f79de4a"
        "8d8d61bf4a6ebffcf04ecaa0bf844a139edea62e6e1b2286b0478cf4adbabc62"
        "9940dbd1e3200789c0f328df63eb6f30199e3e746c96d7d3cea7a007cd3bf4ec"
        "cb1503aed50223914f88b07b3966fa4f9b8cd9c8664a6d7697287c89f79bf1a3"
    );
}
