//! Key agreement for the SymCrypt backend:
//!
//! - X25519 and ECDH on NIST P-256, P-384 and P-521 (`symcrypt::ecc`), for
//!   `curve25519-sha256` (and `@libssh.org`), `ecdh-sha2-nistp256`,
//!   `ecdh-sha2-nistp384` and `ecdh-sha2-nistp521`;
//! - ML-KEM-768 and ML-KEM-1024 (`symcrypt::mlkem`), for the hybrids with
//!   ECDH `mlkem768x25519-sha256`, `mlkem768nistp256-sha256` and
//!   `mlkem1024nistp384-sha384`;
//! - finite-field Diffie-Hellman over RFC 3526 Groups 14–18 and custom DH-GEX
//!   groups (SymCrypt's `SymCryptDlgroup*` / `SymCryptDlkey*` /
//!   `SymCryptDhSecretAgreement` C API), for
//!   `diffie-hellman-group-exchange-sha256`, `diffie-hellman-group14-sha256`
//!   and `diffie-hellman-group{15,16,17,18}-sha512`.
//!
//! The SHA-1 finite-field Diffie-Hellman methods (`diffie-hellman-group1-sha1`,
//! `diffie-hellman-group14-sha1` and `diffie-hellman-group-exchange-sha1`) are
//! not offered.
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
//! - Finite-field DH peer public keys must lie in `(1, p - 1)` and, on the
//!   named RFC 3526 safe-prime groups, in the prime-order subgroup of order
//!   `q = (p - 1) / 2` (`y^q == 1 mod p`, SP 800-56A §5.6.2.3.1).
//!
//! Private keys are wiped by SymCrypt when they are dropped (`EcKey`,
//! `MlKemKey`, `SymCryptDlkeyFree`), and shared secrets are returned in
//! [`Zeroizing`] buffers.

use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::{self, NonNull};
use std::sync::{LazyLock, Once};

use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use symcrypt::mlkem::{MlKemKey, MlKemParams};
use symcrypt_sys::{
    _SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_MSB_FIRST as SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
    SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR, SYMCRYPT_ERROR,
    SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR as SYMCRYPT_NO_ERROR, SYMCRYPT_NUMBER_FORMAT,
    SymCryptModuleInit,
};
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, FfDh, Kem, KeyAgreement, Result};
use crate::kex::dh::groups::{DH_GROUP14, DH_GROUP15, DH_GROUP16, DH_GROUP17, DH_GROUP18, DhGroup};
use crate::kex::{self, KexType};

// `symcrypt-sys` does not run bindgen over SymCrypt's DLGROUP / DLKEY / DH
// declarations. Mirror the C signatures from `symcrypt.h` and link against
// the same shared library that `symcrypt-sys`'s `build.rs` configures.
#[allow(non_camel_case_types)]
mod ffi {
    use super::{SYMCRYPT_ERROR, SYMCRYPT_NUMBER_FORMAT, c_void};

    #[repr(C)]
    pub(super) struct SYMCRYPT_DLGROUP {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub(super) struct SYMCRYPT_DLKEY {
        _private: [u8; 0],
    }

    pub(super) const SYMCRYPT_DLGROUP_FIPS_NONE: u32 = 0;
    pub(super) const SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526: u32 = 1;
    pub(super) const SYMCRYPT_FLAG_DLKEY_DH: u32 = 0x2000;
    pub(super) const SYMCRYPT_FLAG_KEY_NO_FIPS: u32 = 0x100;

    #[link(name = "symcrypt", kind = "dylib")]
    unsafe extern "C" {
        pub(super) fn SymCryptDlgroupAllocate(
            n_bits_of_p: u32,
            n_bits_of_q: u32,
        ) -> *mut SYMCRYPT_DLGROUP;
        pub(super) fn SymCryptDlgroupFree(p_dlgroup: *mut SYMCRYPT_DLGROUP);
        pub(super) fn SymCryptDlgroupSetValue(
            pb_prime_p: *const u8,
            cb_prime_p: usize,
            pb_prime_q: *const u8,
            cb_prime_q: usize,
            pb_gen_g: *const u8,
            cb_gen_g: usize,
            num_format: SYMCRYPT_NUMBER_FORMAT,
            p_hash_algorithm: *const c_void,
            pb_seed: *const u8,
            cb_seed: usize,
            gen_counter: u32,
            fips_standard: u32,
            p_dlgroup: *mut SYMCRYPT_DLGROUP,
        ) -> SYMCRYPT_ERROR;
        pub(super) fn SymCryptDlgroupSetValueSafePrime(
            dh_safe_prime_type: u32,
            p_dlgroup: *mut SYMCRYPT_DLGROUP,
        ) -> SYMCRYPT_ERROR;

        pub(super) fn SymCryptDlkeyAllocate(
            p_dlgroup: *const SYMCRYPT_DLGROUP,
        ) -> *mut SYMCRYPT_DLKEY;
        pub(super) fn SymCryptDlkeyFree(pk_obj: *mut SYMCRYPT_DLKEY);
        pub(super) fn SymCryptDlkeySizeofPublicKey(pk_dlkey: *const SYMCRYPT_DLKEY) -> u32;
        pub(super) fn SymCryptDlkeyGenerate(
            flags: u32,
            pk_dlkey: *mut SYMCRYPT_DLKEY,
        ) -> SYMCRYPT_ERROR;
        pub(super) fn SymCryptDlkeySetValue(
            pb_private_key: *const u8,
            cb_private_key: usize,
            pb_public_key: *const u8,
            cb_public_key: usize,
            num_format: SYMCRYPT_NUMBER_FORMAT,
            flags: u32,
            pk_dlkey: *mut SYMCRYPT_DLKEY,
        ) -> SYMCRYPT_ERROR;
        pub(super) fn SymCryptDlkeyGetValue(
            pk_dlkey: *const SYMCRYPT_DLKEY,
            pb_private_key: *mut u8,
            cb_private_key: usize,
            pb_public_key: *mut u8,
            cb_public_key: usize,
            num_format: SYMCRYPT_NUMBER_FORMAT,
            flags: u32,
        ) -> SYMCRYPT_ERROR;
        pub(super) fn SymCryptDhSecretAgreement(
            pk_private: *const SYMCRYPT_DLKEY,
            pk_public: *const SYMCRYPT_DLKEY,
            num_format: SYMCRYPT_NUMBER_FORMAT,
            flags: u32,
            pb_agreed_secret: *mut u8,
            cb_agreed_secret: usize,
        ) -> SYMCRYPT_ERROR;
    }
}

fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: `SymCryptModuleInit` is idempotent and thread-safe; the
        // version constants come from the paired `symcrypt-sys` crate.
        unsafe {
            SymCryptModuleInit(SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR);
        }
    });
}

struct DlGroup(NonNull<ffi::SYMCRYPT_DLGROUP>);

// SAFETY: Once initialized by `SymCryptDlgroupSetValue*`, a `SYMCRYPT_DLGROUP`
// is immutable and safe to share or move across threads.
unsafe impl Send for DlGroup {}
unsafe impl Sync for DlGroup {}

impl Drop for DlGroup {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by `SymCryptDlgroupAllocate` and is
        // uniquely owned by `self`.
        unsafe {
            ffi::SymCryptDlgroupFree(self.0.as_ptr());
        }
    }
}

impl DlGroup {
    fn new_safe_prime(bits: u32) -> Option<Self> {
        init();
        // SAFETY: `SymCryptModuleInit` has been called; `SymCryptDlgroupAllocate`
        // returns either a valid pointer or null on allocation failure.
        let ptr = unsafe { ffi::SymCryptDlgroupAllocate(bits, 0) };
        let group = Self(NonNull::new(ptr)?);
        // SAFETY: `group.0` was allocated with `bits` matching one of the
        // RFC 3526 safe-prime bit lengths supported by SymCrypt.
        let err = unsafe {
            ffi::SymCryptDlgroupSetValueSafePrime(
                ffi::SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526,
                group.0.as_ptr(),
            )
        };
        (err == SYMCRYPT_NO_ERROR).then_some(group)
    }

    fn new_custom(prime: &[u8], generator: &[u8]) -> Result<Self> {
        if !(128..=1024).contains(&prime.len())
            || prime.last().is_none_or(|b| b & 1 != 1)
            || !in_range(generator, prime)
        {
            return Err(CryptoError);
        }
        let bits = u32::try_from(prime.len())
            .ok()
            .and_then(|n| n.checked_mul(8))
            .ok_or(CryptoError)?;
        init();
        // SAFETY: `SymCryptModuleInit` has been called; `bits` is in
        // `1024..=8192`.
        let ptr = unsafe { ffi::SymCryptDlgroupAllocate(bits, 0) };
        let group = Self(NonNull::new(ptr).ok_or(CryptoError)?);
        // SAFETY: `prime` and `generator` are valid slices within the allocated
        // group's modulus capacity (`bits`), and `group.0` is a valid group
        // object.
        let err = unsafe {
            ffi::SymCryptDlgroupSetValue(
                prime.as_ptr(),
                prime.len(),
                ptr::null(),
                0,
                generator.as_ptr(),
                generator.len(),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                ptr::null(),
                ptr::null(),
                0,
                0,
                ffi::SYMCRYPT_DLGROUP_FIPS_NONE,
                group.0.as_ptr(),
            )
        };
        if err != SYMCRYPT_NO_ERROR {
            return Err(CryptoError);
        }
        Ok(group)
    }
}

static GROUP14: LazyLock<Option<DlGroup>> = LazyLock::new(|| DlGroup::new_safe_prime(2048));
static GROUP15: LazyLock<Option<DlGroup>> = LazyLock::new(|| DlGroup::new_safe_prime(3072));
static GROUP16: LazyLock<Option<DlGroup>> = LazyLock::new(|| DlGroup::new_safe_prime(4096));
static GROUP17: LazyLock<Option<DlGroup>> = LazyLock::new(|| DlGroup::new_safe_prime(6144));
static GROUP18: LazyLock<Option<DlGroup>> = LazyLock::new(|| DlGroup::new_safe_prime(8192));

enum GroupRef {
    Static(&'static DlGroup),
    Owned(DlGroup),
}

impl GroupRef {
    fn as_ptr(&self) -> *const ffi::SYMCRYPT_DLGROUP {
        match self {
            Self::Static(group) => group.0.as_ptr(),
            Self::Owned(group) => group.0.as_ptr(),
        }
    }
}

struct DlKey(NonNull<ffi::SYMCRYPT_DLKEY>);

// SAFETY: A `SYMCRYPT_DLKEY` is uniquely owned by `DlKey` and is not mutated
// concurrently across threads.
unsafe impl Send for DlKey {}
unsafe impl Sync for DlKey {}

impl Drop for DlKey {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by `SymCryptDlkeyAllocate`, is
        // uniquely owned by `self`, and its backing `SYMCRYPT_DLGROUP` is still
        // alive when `DlKey` is dropped.
        unsafe {
            ffi::SymCryptDlkeyFree(self.0.as_ptr());
        }
    }
}

impl DlKey {
    fn allocate(group: *const ffi::SYMCRYPT_DLGROUP) -> Result<Self> {
        // SAFETY: `group` is an initialized `SYMCRYPT_DLGROUP` that outlives
        // the returned `DlKey`.
        let ptr = unsafe { ffi::SymCryptDlkeyAllocate(group) };
        Ok(Self(NonNull::new(ptr).ok_or(CryptoError)?))
    }
}

fn strip_leading_zeros(mut bytes: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
}

/// Checks `1 < x < p - 1` for big-endian unsigned integers `x` and `prime`,
/// where `prime` has no leading zero bytes, is at least 128 bytes long, and is
/// odd.
fn in_range(x: &[u8], prime: &[u8]) -> bool {
    let x = strip_leading_zeros(x);
    let ([x_prefix @ .., x_last], [p_prefix @ .., p_last]) = (x, prime) else {
        return false;
    };
    if x_prefix.is_empty() && *x_last <= 1 {
        return false;
    }
    if x.len() != prime.len() {
        return x.len() < prime.len();
    }
    // `prime` is odd, so `p - 1` has the same prefix bytes and last byte
    // `p_last - 1`.
    (x_prefix, *x_last) < (p_prefix, p_last.saturating_sub(1))
}

fn resolve_group(prime: &[u8], generator: &[u8]) -> Result<(GroupRef, u32)> {
    if generator == [2] {
        let named = if prime == &*DH_GROUP14.prime {
            Some(&*GROUP14)
        } else if prime == &*DH_GROUP15.prime {
            Some(&*GROUP15)
        } else if prime == &*DH_GROUP16.prime {
            Some(&*GROUP16)
        } else if prime == &*DH_GROUP17.prime {
            Some(&*GROUP17)
        } else if prime == &*DH_GROUP18.prime {
            Some(&*GROUP18)
        } else {
            None
        };
        if let Some(group) = named {
            let group = group.as_ref().ok_or(CryptoError)?;
            return Ok((GroupRef::Static(group), ffi::SYMCRYPT_FLAG_DLKEY_DH));
        }
    }
    let group = DlGroup::new_custom(prime, generator)?;
    Ok((
        GroupRef::Owned(group),
        ffi::SYMCRYPT_FLAG_DLKEY_DH | ffi::SYMCRYPT_FLAG_KEY_NO_FIPS,
    ))
}

/// Ephemeral finite-field Diffie-Hellman key pair backed by SymCrypt's
/// `SYMCRYPT_DLGROUP` / `SYMCRYPT_DLKEY` C API.
pub(crate) struct Dh {
    /// Must be declared before `group` so `SymCryptDlkeyFree` runs before
    /// `SymCryptDlgroupFree` (`SymCryptDlkeyFree` reads group sizes through
    /// `pkObj->pDlgroup`).
    private_key: DlKey,
    group: GroupRef,
    prime: Vec<u8>,
    flags: u32,
}

impl FfDh for Dh {
    fn generate(group: &DhGroup, _is_server: bool) -> Result<(Self, Vec<u8>)> {
        let prime = strip_leading_zeros(&group.prime);
        let generator = strip_leading_zeros(&group.generator);
        let (group_ref, flags) = resolve_group(prime, generator)?;
        let private_key = DlKey::allocate(group_ref.as_ptr())?;
        // SAFETY: `private_key` is a freshly allocated `SYMCRYPT_DLKEY` bound
        // to `group_ref`.
        let err = unsafe { ffi::SymCryptDlkeyGenerate(flags, private_key.0.as_ptr()) };
        if err != SYMCRYPT_NO_ERROR {
            return Err(CryptoError);
        }
        // SAFETY: `private_key` is a valid key object.
        let pub_len =
            usize::try_from(unsafe { ffi::SymCryptDlkeySizeofPublicKey(private_key.0.as_ptr()) })
                .map_err(|_| CryptoError)?;
        let mut public_key = vec![0u8; pub_len];
        // SAFETY: `public_key` has `pub_len` writable bytes; a null private-key
        // pointer with length 0 exports only the public key.
        let err = unsafe {
            ffi::SymCryptDlkeyGetValue(
                private_key.0.as_ptr(),
                ptr::null_mut(),
                0,
                public_key.as_mut_ptr(),
                public_key.len(),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
            )
        };
        if err != SYMCRYPT_NO_ERROR || !in_range(&public_key, prime) {
            return Err(CryptoError);
        }
        Ok((
            Self {
                private_key,
                group: group_ref,
                prime: prime.to_vec(),
                flags,
            },
            public_key,
        ))
    }

    fn agree(&self, peer_public_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let peer = strip_leading_zeros(peer_public_key);
        if !in_range(peer, &self.prime) {
            return Err(CryptoError);
        }
        let peer_key = DlKey::allocate(self.group.as_ptr())?;
        // SAFETY: `peer` is non-empty and at most `self.prime.len()` bytes
        // (`cbPrimeP`), and `peer_key` is allocated on the same `SYMCRYPT_DLGROUP`.
        let err = unsafe {
            ffi::SymCryptDlkeySetValue(
                ptr::null(),
                0,
                peer.as_ptr(),
                peer.len(),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                self.flags,
                peer_key.0.as_ptr(),
            )
        };
        if err != SYMCRYPT_NO_ERROR {
            return Err(CryptoError);
        }
        // SAFETY: `self.private_key` is a valid key object.
        let secret_len = usize::try_from(unsafe {
            ffi::SymCryptDlkeySizeofPublicKey(self.private_key.0.as_ptr())
        })
        .map_err(|_| CryptoError)?;
        let mut shared = Zeroizing::new(vec![0u8; secret_len]);
        // SAFETY: `self.private_key` and `peer_key` belong to the same
        // `SYMCRYPT_DLGROUP`, and `shared` has `secret_len` (`cbPrimeP`)
        // writable bytes.
        let err = unsafe {
            ffi::SymCryptDhSecretAgreement(
                self.private_key.0.as_ptr(),
                peer_key.0.as_ptr(),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                shared.as_mut_ptr(),
                shared.len(),
            )
        };
        if err != SYMCRYPT_NO_ERROR || !in_range(&shared, &self.prime) {
            return Err(CryptoError);
        }
        Ok(shared)
    }
}

pub(crate) struct X25519;

impl KeyAgreement for X25519 {
    type PrivateKey = EcKey;

    fn generate() -> Result<(Self::PrivateKey, Vec<u8>)> {
        let private_key = EcKey::generate_key_pair(CurveType::Curve25519, EcKeyUsage::EcDh)
            .map_err(|_| CryptoError)?;
        let public_key = private_key.export_public_key().map_err(|_| CryptoError)?;
        Ok((private_key, public_key))
    }

    fn agree(private_key: Self::PrivateKey, peer_public_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
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

pub(crate) struct P521;

impl NistCurve for P521 {
    const CURVE: CurveType = CurveType::NistP521;
}

/// ECDH with ephemeral keys on curve `C`; public keys are uncompressed SEC1
/// points and the shared secret is the x-coordinate, as many bytes as a
/// field element (66 for P-521, whose top byte is 0 or 1).
pub(crate) struct Ecdh<C>(PhantomData<C>);

pub(crate) type NistP256 = Ecdh<P256>;
pub(crate) type NistP384 = Ecdh<P384>;
pub(crate) type NistP521 = Ecdh<P521>;

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

    fn agree(private_key: Self::PrivateKey, peer_public_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
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

/// An ML-KEM parameter set.
pub(crate) trait MlKemParamSet {
    const PARAMS: MlKemParams;
}

pub(crate) struct MlKem768Params;

impl MlKemParamSet for MlKem768Params {
    const PARAMS: MlKemParams = MlKemParams::MlKem768;
}

pub(crate) struct MlKem1024Params;

impl MlKemParamSet for MlKem1024Params {
    const PARAMS: MlKemParams = MlKemParams::MlKem1024;
}

/// ML-KEM with parameter set `P`.
pub(crate) struct MlKem<P>(PhantomData<P>);

pub(crate) type MlKem768 = MlKem<MlKem768Params>;
pub(crate) type MlKem1024 = MlKem<MlKem1024Params>;

impl<P: MlKemParamSet> Kem for MlKem<P> {
    type DecapsulationKey = MlKemKey;

    fn generate() -> Result<(Self::DecapsulationKey, Vec<u8>)> {
        let decapsulation_key = MlKemKey::generate_key_pair(P::PARAMS).map_err(|_| CryptoError)?;
        let encapsulation_key = decapsulation_key
            .export_encapsulation_key()
            .map_err(|_| CryptoError)?;
        Ok((decapsulation_key, encapsulation_key))
    }

    fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let encapsulation_key = MlKemKey::from_encapsulation_key(P::PARAMS, encapsulation_key)
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
    (
        &kex::MLKEM1024NISTP384_SHA384,
        &kex::_MLKEM1024NISTP384_SHA384,
    ),
    (
        &kex::MLKEM768NISTP256_SHA256,
        &kex::_MLKEM768NISTP256_SHA256,
    ),
    (&kex::CURVE25519, &kex::_CURVE25519),
    (&kex::CURVE25519_PRE_RFC_8731, &kex::_CURVE25519),
    (&kex::ECDH_SHA2_NISTP256, &kex::_ECDH_SHA2_NISTP256),
    (&kex::ECDH_SHA2_NISTP384, &kex::_ECDH_SHA2_NISTP384),
    (&kex::ECDH_SHA2_NISTP521, &kex::_ECDH_SHA2_NISTP521),
    (&kex::DH_GEX_SHA256, &kex::_DH_GEX_SHA256),
    (&kex::DH_G18_SHA512, &kex::_DH_G18_SHA512),
    (&kex::DH_G17_SHA512, &kex::_DH_G17_SHA512),
    (&kex::DH_G16_SHA512, &kex::_DH_G16_SHA512),
    (&kex::DH_G15_SHA512, &kex::_DH_G15_SHA512),
    (&kex::DH_G14_SHA256, &kex::_DH_G14_SHA256),
];

/// Default key exchange preference: all of them, in the order of
/// [`ALGORITHMS`] (the RFC 8308 / strict-kex extension pseudo-algorithms are
/// appended by `Preferred`).
pub(crate) const DEFAULT_ORDER: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::MLKEM1024NISTP384_SHA384,
    kex::MLKEM768NISTP256_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_GEX_SHA256,
    kex::DH_G18_SHA512,
    kex::DH_G17_SHA512,
    kex::DH_G16_SHA512,
    kex::DH_G15_SHA512,
    kex::DH_G14_SHA256,
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use hex_literal::hex;
    use ssh_encoding::Encode;

    use super::*;
    use crate::cipher::{self, SealingKey};
    use crate::client::GexParams;
    use crate::crypto::symcrypt::hash::{Sha256, Sha384, Sha512};
    use crate::crypto::{FfDh, Hash};
    use crate::kex::dh::groups::{DH_GROUP1, DH_GROUP14, DhGroupUInt};
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

    // Known-answer test vector for RFC 3526 2048-bit MODP Group 14 (`DH_GROUP14`)
    // using `ALICE_PRIVATE` and `BOB_PRIVATE` as big-endian exponents.
    const DH14_ALICE_PUBLIC: [u8; 256] = hex!(
        "5784573243556b2a5943d9f7c7cbe8f0b0348e937e579f2964ef6a484dd5b9dd"
        "38b17df216a5f8dc55e7e8ef7c9b9256d152b33879fec77aaa95186a3f28b39d"
        "bd66262cb005915ff257ee9a7b299ca17599187d1fbf866a75155232b91886f7"
        "f5dc3a2ca99014f441854a69204ff30d55cbf9a0972405398f2acf7f80de2a75"
        "689436bc0c84a8b2e7e9f4791203ea7ac6eebc09a3d58dd6d16a1a0d64874474"
        "9e929785cdf84b73c5c519c83db85c624262970fe3f48604ad0a5e1da21c0e70"
        "17b4e7863981adae25c05cc10c34fe30557366f3e1a3c581367180ee7d7fe1e7"
        "414711e6e26f2a651b29ed1d464fe1a90f822d64115c66da285552c1f5e0fe67"
    );
    const DH14_BOB_PUBLIC: [u8; 256] = hex!(
        "dce454917767021012065aa3208969c8abc123b7ea7327e33d6dbea29baa5158"
        "e5c8f9fa2e0b8413c85861d75d1c6bb182926db13ecec2fdead9d977f65ca04b"
        "58876a2e6aeffe9f41a51c933661ed6d7c8bd3e189b77fae46b19f4b57f4f7b6"
        "071c41285f623156a881e12b2e41272ead74110910b03448c05cd63247d72ca8"
        "58c434e0539169c0786414a76b4197a22e3938535a827f9341170d5169e0d1c8"
        "b1586a6357de612d2d3e75c4ff48352c046236a8ff831b34e0541817bb101a7b"
        "7fc97500293750e8cba39001de2a54b3288b1b22c937f83affcc91f1b51c5aca"
        "af14cc5f9930ed883cb1ceae9bd7b44cfaf851928f1ef959d7f3810975f685fe"
    );
    const DH14_SHARED: [u8; 256] = hex!(
        "37d4642afc2829669eeeeccdafc7d9ed8762412b9c8b6b8d7c67e704a1388ba3"
        "18d23eedbd2c1809cb06aa91973978d0c1eb82da33beae9f9d04031f28cc106c"
        "de4fe3e40dd89cca6632224287992c827e3400228ca4ae9f81705d69949d61ba"
        "cecbb4262885c98d2ad20b30788a7dfcf6428014bbe4f2584088620757ce3744"
        "e51212094ef2aed7b739c2546554290d0ee93c75471cb00c9e202a1638a9fdc7"
        "56da0f6cc41f1adec7fd725ebae438b55ab56ff1436ae528640fb535214432eb"
        "4c64f012354569868f59fd74e6f7d224805047b32c7cbbfffeddc05ffb1aaaea"
        "2de1cc9b360afe1cbac4fd0a476c45b9e509294f126022321d4922b1ac58a285"
    );

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

    // RFC 5903 §8.1 to §8.3: private keys, public keys and shared secrets
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

    const P521_I: [u8; 66] = hex!(
        "0037"
        "ADE9319A89F4DABDB3EF411AACCCA5123C61ACAB57B5393DCE47608172A095AA"
        "85A30FE1C2952C6771D937BA9777F5957B2639BAB072462F68C27A57382D4A52"
    );
    const P521_GI: [u8; 133] = hex!(
        "04"
        "0015"
        "417E84DBF28C0AD3C278713349DC7DF153C897A1891BD98BAB4357C9ECBEE1E3"
        "BF42E00B8E380AEAE57C2D107564941885942AF5A7F4601723C4195D176CED3E"
        "017C"
        "AE20B6641D2EEB695786D8C946146239D099E18E1D5A514C739D7CB4A10AD8A7"
        "88015AC405D7799DC75E7B7D5B6CF2261A6A7F1507438BF01BEB6CA3926F9582"
    );
    const P521_R: [u8; 66] = hex!(
        "0145"
        "BA99A847AF43793FDD0E872E7CDFA16BE30FDC780F97BCCC3F078380201E9C67"
        "7D600B343757A3BDBF2A3163E4C2F869CCA7458AA4A4EFFC311F5CB151685EB9"
    );
    const P521_GR: [u8; 133] = hex!(
        "04"
        "00D0"
        "B3975AC4B799F5BEA16D5E13E9AF971D5E9B984C9F39728B5E5739735A219B97"
        "C356436ADC6E95BB0352F6BE64A6C2912D4EF2D0433CED2B6171640012D9460F"
        "015C"
        "68226383956E3BD066E797B623C27CE0EAC2F551A10C2C724D9852077B87220B"
        "6536C5C408A1D2AEBB8E86D678AE49CB57091F4732296579AB44FCD17F0FC56A"
    );
    const P521_GIRX: [u8; 66] = hex!(
        "0114"
        "4C7D79AE6956BC8EDB8E7C787C4521CB086FA64407F97894E5E6B2D79B04D142"
        "7E73CA4BAA240A34786859810C06B3C715A3A8CC3151F2BEE417996D19F3DDEA"
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
        check_rfc5903::<P521>(&P521_I, &P521_GI, &P521_R, &P521_GR, &P521_GIRX);
    }

    /// The SEC1 encoding of P-521's generator.
    fn p521_generator() -> Vec<u8> {
        let mut one = [0; 66];
        one[65] = 1;
        sec1_public_key(&ecdh_private_key::<P521>(&one)).unwrap()
    }

    /// P-521 shared secrets are 66 bytes even when their top bytes are zero:
    /// `x(i·G)` and `x(r·G)` are the x-coordinates of the RFC 5903 public
    /// keys, which start with `00 15` and `00 d0`.
    #[test]
    fn ecdh_p521_keeps_leading_zeros() {
        let generator = p521_generator();
        for (scalar, public_key) in [(&P521_I, &P521_GI), (&P521_R, &P521_GR)] {
            let shared = NistP521::agree(ecdh_private_key::<P521>(scalar), &generator).unwrap();
            assert_eq!(shared.len(), 66);
            assert_eq!(shared[0], 0);
            assert_eq!(*shared, public_key[1..67]);
        }
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
        check_rejects_invalid_points::<P521>(
            &P521_I,
            &P521_GR,
            // 2^521 - 1.
            &[[0x01].as_slice(), &[0xff; 65]].concat(),
        );
        // Keys of other curves.
        assert!(NistP384::agree(ecdh_private_key::<P384>(&P384_I), &P256_GR).is_err());
        assert!(NistP256::agree(ecdh_private_key::<P256>(&P256_I), &P384_GR).is_err());
        assert!(NistP521::agree(ecdh_private_key::<P521>(&P521_I), &P384_GR).is_err());
        assert!(NistP384::agree(ecdh_private_key::<P384>(&P384_I), &P521_GR).is_err());
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
        agree::<NistP521>(133);
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
        ml_kem_round_trips_and_validates::<MlKem768>(1184, 1088);
    }

    /// SHA-256 of the ML-KEM-1024 encapsulation key for [`MLKEM_SEED`], and
    /// the shared secret of [`MLKEM1024_CIPHERTEXT`] for it, from RustCrypto
    /// `ml-kem`, like the ML-KEM-768 values above.
    const MLKEM1024_EK_SHA256: [u8; 32] =
        hex!("07dbd290591709e2bb7f47b3d9bc66e26a0c2f6de1df03453f9cfa589d16e416");
    const MLKEM1024_SHARED: [u8; 32] =
        hex!("4a74fc0839c5156ac6b69e2fc3a9aa55c9878d37241c0c75d187b8b24c50546a");
    /// The implicit rejection secret for the ciphertext with its last bit
    /// flipped.
    const MLKEM1024_REJECTED: [u8; 32] =
        hex!("c6f06ce4f8ec77aadb53a3b5e9ed56c816d30ba83ad521ebc76687fac305a1fe");

    #[test]
    fn ml_kem_1024_known_answers() {
        let key = MlKemKey::from_private_seed(MlKemParams::MlKem1024, &MLKEM_SEED).unwrap();
        let encapsulation_key = key.export_encapsulation_key().unwrap();
        assert_eq!(Sha256::digest(&encapsulation_key), MLKEM1024_EK_SHA256);
        assert_eq!(
            *MlKem1024::decapsulate(&key, &MLKEM1024_CIPHERTEXT).unwrap(),
            MLKEM1024_SHARED
        );
        let mut ciphertext = MLKEM1024_CIPHERTEXT;
        ciphertext[1567] ^= 1;
        assert_eq!(
            *MlKem1024::decapsulate(&key, &ciphertext).unwrap(),
            MLKEM1024_REJECTED
        );
        // An ML-KEM-768 ciphertext is not one for this key.
        assert!(MlKem1024::decapsulate(&key, &MLKEM_CIPHERTEXT).is_err());

        let (ciphertext, shared) = MlKem1024::encapsulate(&encapsulation_key).unwrap();
        assert_eq!(MlKem1024::decapsulate(&key, &ciphertext).unwrap(), shared);
    }

    #[test]
    fn ml_kem_1024_round_trips_and_validates() {
        ml_kem_round_trips_and_validates::<MlKem1024>(1568, 1568);
    }

    fn ml_kem_round_trips_and_validates<K: Kem<DecapsulationKey = MlKemKey>>(
        encapsulation_key_len: usize,
        ciphertext_len: usize,
    ) {
        let (key, encapsulation_key) = K::generate().unwrap();
        assert_eq!(encapsulation_key.len(), encapsulation_key_len);
        let (ciphertext, shared) = K::encapsulate(&encapsulation_key).unwrap();
        assert_eq!(ciphertext.len(), ciphertext_len);
        assert_eq!(shared.len(), 32);
        assert_eq!(K::decapsulate(&key, &ciphertext).unwrap(), shared);

        assert!(K::encapsulate(&encapsulation_key[1..]).is_err());
        assert!(K::encapsulate(&[encapsulation_key.as_slice(), &[0]].concat()).is_err());
        assert!(K::decapsulate(&key, &ciphertext[1..]).is_err());
        assert!(K::decapsulate(&key, &[ciphertext.as_slice(), &[0]].concat()).is_err());
        // FIPS 203 §7.2 modulus check: a coefficient (12 bits) of 4095 >= q.
        let mut encapsulation_key = encapsulation_key;
        encapsulation_key[0] = 0xff;
        encapsulation_key[1] |= 0x0f;
        assert!(K::encapsulate(&encapsulation_key).is_err());
    }

    fn dh_from_private(group: &DhGroup, private_bytes: &[u8]) -> (Dh, Vec<u8>) {
        let prime = strip_leading_zeros(&group.prime);
        let generator = strip_leading_zeros(&group.generator);
        let (group_ref, flags) = resolve_group(prime, generator).unwrap();
        let private_key = DlKey::allocate(group_ref.as_ptr()).unwrap();
        let err = unsafe {
            ffi::SymCryptDlkeySetValue(
                private_bytes.as_ptr(),
                private_bytes.len(),
                ptr::null(),
                0,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                flags,
                private_key.0.as_ptr(),
            )
        };
        assert_eq!(err, SYMCRYPT_NO_ERROR);
        let pub_len =
            usize::try_from(unsafe { ffi::SymCryptDlkeySizeofPublicKey(private_key.0.as_ptr()) })
                .unwrap();
        let mut public_key = vec![0u8; pub_len];
        let err = unsafe {
            ffi::SymCryptDlkeyGetValue(
                private_key.0.as_ptr(),
                ptr::null_mut(),
                0,
                public_key.as_mut_ptr(),
                public_key.len(),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
            )
        };
        assert_eq!(err, SYMCRYPT_NO_ERROR);
        (
            Dh {
                private_key,
                group: group_ref,
                prime: prime.to_vec(),
                flags,
            },
            public_key,
        )
    }

    #[test]
    fn dh_known_answer_and_leading_zero_mpint() {
        let (alice, alice_pub) = dh_from_private(&DH_GROUP14, &ALICE_PRIVATE);
        let (bob, bob_pub) = dh_from_private(&DH_GROUP14, &BOB_PRIVATE);
        assert_eq!(alice_pub.as_slice(), &DH14_ALICE_PUBLIC);
        assert_eq!(bob_pub.as_slice(), &DH14_BOB_PUBLIC);

        // `DH14_BOB_PUBLIC[0]` is `0xdc` (MSB bit 7 set), so SSH `mpint`
        // encoding prepends a `0x00` sign byte (`cbPrimeP + 1` = 257 bytes).
        assert!(bob_pub[0] & 0x80 != 0);
        let mut bob_mpint = Vec::with_capacity(bob_pub.len() + 1);
        bob_mpint.push(0x00);
        bob_mpint.extend_from_slice(&bob_pub);

        let alice_shared = alice.agree(&bob_mpint).unwrap();
        let bob_shared = bob.agree(&alice_pub).unwrap();
        assert_eq!(alice_shared.as_slice(), &DH14_SHARED);
        assert_eq!(bob_shared.as_slice(), &DH14_SHARED);
    }

    #[test]
    fn dh_round_trip_named_and_custom_groups() {
        // Custom 2048-bit group with generator 4 (quadratic residue subgroup of
        // Group 14), plus RFC 2409 1024-bit `DH_GROUP1` (with and without
        // leading zero padding), exercising `SymCryptDlgroupSetValue` with
        // `SYMCRYPT_FLAG_KEY_NO_FIPS`.
        let custom_g4 = DhGroup {
            prime: DH_GROUP14.prime.clone(),
            generator: DhGroupUInt::new(&[4]),
        };
        let mut padded_prime = vec![0x00, 0x00];
        padded_prime.extend_from_slice(&DH_GROUP1.prime);
        let custom_padded = DhGroup {
            prime: DhGroupUInt::from(padded_prime),
            generator: DhGroupUInt::new(&[0x00, 2]),
        };

        for group in [
            &DH_GROUP14,
            &DH_GROUP15,
            &DH_GROUP16,
            &DH_GROUP17,
            &DH_GROUP18,
            &DH_GROUP1,
            &custom_g4,
            &custom_padded,
        ] {
            let (alice, alice_pub) = Dh::generate(group, false).unwrap();
            let (bob, bob_pub) = Dh::generate(group, true).unwrap();
            let expected_len = strip_leading_zeros(&group.prime).len();
            assert_eq!(alice_pub.len(), expected_len);
            assert_eq!(bob_pub.len(), expected_len);

            let mut bob_mpint = vec![0x00];
            bob_mpint.extend_from_slice(&bob_pub);
            let s1 = alice.agree(&bob_mpint).unwrap();
            let s2 = bob.agree(&alice_pub).unwrap();
            assert_eq!(s1.as_slice(), s2.as_slice());
        }
    }

    #[test]
    fn dh_rejects_invalid_groups_and_peer_public_keys() {
        // Invalid custom groups: prime too short (< 128 bytes), too long
        // (> 1024 bytes), even prime, or out-of-range generator.
        let mut even_prime = DH_GROUP14.prime.to_vec();
        *even_prime.last_mut().unwrap() &= !1;

        for bad_group in [
            DhGroup {
                prime: DhGroupUInt::from(vec![0xff; 127]),
                generator: DhGroupUInt::new(&[2]),
            },
            DhGroup {
                prime: DhGroupUInt::from(vec![0xff; 1025]),
                generator: DhGroupUInt::new(&[2]),
            },
            DhGroup {
                prime: DhGroupUInt::from(even_prime),
                generator: DhGroupUInt::new(&[2]),
            },
            DhGroup {
                prime: DH_GROUP14.prime.clone(),
                generator: DhGroupUInt::new(&[0]),
            },
            DhGroup {
                prime: DH_GROUP14.prime.clone(),
                generator: DhGroupUInt::new(&[1]),
            },
            DhGroup {
                prime: DH_GROUP14.prime.clone(),
                generator: DH_GROUP14.prime.clone(),
            },
        ] {
            assert!(Dh::generate(&bad_group, false).is_err());
        }

        let p = DH_GROUP14.prime.to_vec();
        let mut p_minus_1 = p.clone();
        *p_minus_1.last_mut().unwrap() -= 1;
        let mut p_minus_2 = p.clone();
        *p_minus_2.last_mut().unwrap() -= 2;
        let mut p_plus_1 = vec![0x01];
        p_plus_1.resize(p.len() + 1, 0x00);
        *p_plus_1.last_mut().unwrap() = 1;

        // `p - 2` satisfies `1 < p - 2 < p - 1`, so it passes `in_range`, but
        // since `p == 7 (mod 8)` for RFC 3526 Group 14, `((-2)/p) = -1` and
        // `(p - 2)^q == p - 1 != 1 (mod p)`. SymCrypt's SP 800-56A full
        // public-key validation on named safe-prime groups must reject it.
        let (alice, _) = Dh::generate(&DH_GROUP14, false).unwrap();
        for bad_peer in [
            &[][..],
            &[0][..],
            &[0, 0, 0][..],
            &[1][..],
            &[0, 1][..],
            &p_minus_1,
            &p,
            &p_plus_1,
            &p_minus_2,
        ] {
            assert!(
                alice.agree(bad_peer).is_err(),
                "accepted invalid peer key of len {}",
                bad_peer.len()
            );
        }
    }

    #[test]
    fn offers_exactly_the_supported_key_exchanges() {
        let expected = [
            kex::MLKEM768X25519_SHA256,
            kex::MLKEM1024NISTP384_SHA384,
            kex::MLKEM768NISTP256_SHA256,
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::ECDH_SHA2_NISTP256,
            kex::ECDH_SHA2_NISTP384,
            kex::ECDH_SHA2_NISTP521,
            kex::DH_GEX_SHA256,
            kex::DH_G18_SHA512,
            kex::DH_G17_SHA512,
            kex::DH_G16_SHA512,
            kex::DH_G15_SHA512,
            kex::DH_G14_SHA256,
        ];
        assert_eq!(DEFAULT_ORDER, expected);
        assert!(ALGORITHMS.iter().map(|(name, _)| **name).eq(expected));
        // With every algorithm that isn't legacy, `Preferred::DEFAULT` offers
        // all of them (see `negotiation::tests` for other features).
        #[cfg(feature = "secure-algorithms")]
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
    fn exchange_hash<H: Hash>(
        client_ephemeral: &[u8],
        server_ephemeral: &[u8],
        k: &[u8],
    ) -> Vec<u8> {
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

    /// Exchange hashes for the RFC 7748 and RFC 5903 key pairs, matching
    /// Python's `hashlib` (and, for X25519 and P-384, the RustCrypto
    /// backend's `compute_exchange_hash`). The P-521 secrets `K` start with
    /// `01`, `00 15` and `00 d0`: their mpints are 66 bytes, 65 bytes, and
    /// 66 bytes with a zero byte prepended.
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
        let generator = p521_generator();
        for (scalar, client_ephemeral, server_ephemeral, h) in [
            (
                &P521_I,
                &P521_GI[..],
                &P521_GR[..],
                hex!(
                    "211c4222110a7a1c579fa1cacd1b28efd458fe414edcc2b82eea9147e2883326"
                    "c1e3cc3bd41aa6729aeddc6160800d6029aefc62a142f90237b7ce580513d41f"
                ),
            ),
            (
                &P521_I,
                &P521_GI[..],
                &generator[..],
                hex!(
                    "3e7809af181f56766392aefc6d343e65d2f0ddeecd85c6756d3eb0aec5f0407f"
                    "b9d2d664fe79838cfa2ffbf21abb13c8faa57461fe3e12291dc93b2beaaf2813"
                ),
            ),
            (
                &P521_R,
                &P521_GR[..],
                &generator[..],
                hex!(
                    "fda84f71938b872f48b41c9e740e7183e83de41d8cfda4e20456df539d5052ff"
                    "e6a6aff1df82bd439a4c8f4af27cf1c6adbc1a6545ec1169ae05577320d62cf9"
                ),
            ),
        ] {
            let k = NistP521::agree(ecdh_private_key::<P521>(scalar), server_ephemeral).unwrap();
            assert_eq!(
                exchange_hash::<Sha512>(client_ephemeral, server_ephemeral, &k),
                h
            );
        }
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
        let cipher_name = cipher::AES_256_GCM;
        let mac_name = mac::NONE;
        for name in DEFAULT_ORDER {
            let kex_type = kex::KEXES.get(name).unwrap();
            let (mut client, mut server) = (kex_type.make(), kex_type.make());
            let mut exchange = Exchange::new(b"SSH-2.0-client", b"SSH-2.0-server");
            if client.is_dh_gex() {
                let params = GexParams::new(2048, 2048, 8192).unwrap();
                client.dh_gex_set_group(DH_GROUP14.clone()).unwrap();
                server.dh_gex_set_group(DH_GROUP14.clone()).unwrap();
                exchange.gex = Some((params, DH_GROUP14.clone()));
            }
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
                (
                    &mut client_keys.local_to_remote,
                    &mut server_keys.remote_to_local,
                ),
                (
                    &mut server_keys.local_to_remote,
                    &mut client_keys.remote_to_local,
                ),
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

    /// An ML-KEM-1024 ciphertext for the key from [`MLKEM_SEED`], from
    /// RustCrypto `ml-kem`'s deterministic encapsulation (m = 00 01 .. 1f).
    const MLKEM1024_CIPHERTEXT: [u8; 1568] = hex!(
        "e0d19458d67922e3b6b3944c649cb60a1a08a28e551b603d5b3556ab09e018ed"
        "ce34e6129b0e43d24b969bc1d521b32d97c8f916b47c9e84f75a173166810821"
        "940eb16dcd8edb075f8af0091c2c618a6c263a5bd71c4bf8ad34600dc61d7699"
        "5514808dc220477a16293d499f309280da1a30095219b147772dd23f43eae4a9"
        "b79dfd233a54d5e1a668c0b9aa5edfe59c6918e7da33ae8fb83c64b10ec03ab6"
        "6c1b24d6706501b732b29d2ba0320fc0d9fe300ee181cc1f1e966df5284250f1"
        "75d782028d2485026810ea39605a782e9e2cef2347db5a3bd7c61b8a35c44e2e"
        "be82323b3352ac9a4e608e8b790bbf92be33d017eeb0ee9205f4240256e304ee"
        "014058f1a9174ab7b5c48dbc319eec52b2a493c147533b565b72a1d506938a9e"
        "71a2e3d29ab0628f43e2c05dcf97a8cbdc0be6e3dc378395a9928ed7acb892d7"
        "d71e491a02b6155703d1c57bfce0d82ccb921204489f61cbc6fd7faefbc9cc12"
        "37f178ef74642f6876e75ab8897e2b714779b4692b0fcb9e7fcf6e072d179cc1"
        "bbc667eb547438be308781c1b821116189210ac921d4c779296d008e6d827703"
        "92cb1e67769d1057cefe3ccfed107466ee87fc40d84462e4fe689610f4b46ad8"
        "8cecd90d38c728ab105e0f7771a6baa22792e2d56816ec2ee772ce06d49c1d24"
        "693afb122d5b2d6d1f42e95fd8d9b34ce9915ba94b1d0d66964f487beecab587"
        "1d761bb07822adb89b8f87e07e3e1dc96f9a71b467dd76074c0a9a0b3b565ad5"
        "e66a56f25641924214d72e7ba5acb8b96665607a71ab136dd4d7ea20594d2686"
        "4be1982aca78f0f6be7e04dc4a5caccc4cef766486a90a874736b5a78e53846e"
        "40439cf9a84700e92d03a4a1f7f8cf13e8590a21804883d21a15fbfc5eb9be7e"
        "1141dc3715e9f5f7b3f0521fa574a0ac5c4230612def9a4b39236260f7ef315f"
        "875a0ac49bf2dbff59a8dc7b24af5b3bb2a6da5983832edab175ee408ff25757"
        "9219eeb4e4d42214983e67511f59fc279773736ddbebe0ec08894c0ac006e27c"
        "6a81c4e2b8d7758056952a50ef0d67b66fb59f9e1a9358bbc6c2b8ffb04b07a7"
        "ae30f528b6d21c4e63094f5bee27a79226e62877571063b03442fe8f1f231270"
        "6d3fb03e1d221e21c464177ea788b904354d8eddc95aba71c2419f95f12a0630"
        "7474a39cb0ba994e5abf3c00e069ef9b25228fe1f2ec80d488fd137546184bd5"
        "47ba963f0f73fd5a2bd337ccac80d2a481b4b6215b73ccbdf92a4eb3fdebc22f"
        "1b784e10b786292631e1b585cc65f134b2b5a9eab0dd9f7bf561776e7a0cbe11"
        "f049a395658ca07095496355d3584f09c57236f52c33272642b51de156111a98"
        "1d3fb674d05a7e858d6df5da11580f3f2a459ad10e5f474b744bb8b246d04519"
        "72245640d11a05fb2609b19c2fdf8e190817f59b0ebf6a4a0c29807394a71f86"
        "0ec12b03aaf471862fb94bf9d491ba8ee61863a7a68c25598cf1891f3421c55b"
        "d0c55d2a9a35e7c1c573710520841c6d487ee90ed82b836b78246bd7f6efa2a7"
        "82ee9720b56250a7b0aafe2f8d4432272155acb6457a7f2740ffbb64f84639cf"
        "8b3cff338aee47faa5ff2bf37b956ae2693c5aa2ecdb9a2bde1d327624f40dfc"
        "2de11fa0ab0fb6813b6fa9e0707e9f57821b96b54c7e56738756ad06f5d14fd2"
        "5fab8d311b749be1ed4b6409d67ae04036fbc7ffd71b99604bf08bf655bafd90"
        "a9bb1a8b377a2f9ff3099e764d1efcc7860ed601213ac981402b7b55ac9607c5"
        "f46b82d8454a729a3d74d002277c6d6d5014341e8348a3bd871223cdaba0b556"
        "9daa47556d59c4dfe3a201e78db42854435480513fa16b2567f40803a8eb535d"
        "64b1b1e40718bc6a601d8b00e45f7280adaa4d1b3b7a3c7a56d6d56b71a35515"
        "0cdc90348aad39ffd9b62703611bed6e134dcdc7b421cdbd6b23302d39f05dd0"
        "14060dd0376de53fab16d94429feca91d901b0a4713e700bafa64b36f70676b5"
        "598599e22809c4bdd02a59934fe544ec129b9b2a001678688f5b9c4e97d2f577"
        "c513d27baa1ec3d4702da8a1d190714cc8ee46689116db0d099bf1ba167ca0d3"
        "30c495610ecfb5ee9a747971b38920123c14bbf88874ee9a64ea240abc710e44"
        "afcfeb50b7fc4477bc3cf8a121e6e4b67b197a638721dbf238f6bf1bb277637a"
        "78fd6c7e9de7eb5721c57f32bd7707252cd6d5be8147408bdba187b669c40d9f"
    );
}
