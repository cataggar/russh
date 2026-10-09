//! Ciphers for the SymCrypt backend:
//!
//! - `aes128-gcm@openssh.com` and `aes256-gcm@openssh.com` (RFC 5647), with
//!   `symcrypt::gcm`;
//! - `chacha20-poly1305@openssh.com` (OpenSSH `PROTOCOL.chacha20poly1305`),
//!   with SymCrypt's ChaCha20 and Poly1305;
//! - `aes128-ctr`, `aes192-ctr` and `aes256-ctr` (RFC 4344), with SymCrypt's
//!   AES in CTR mode.
//!
//! The CBC modes and 3DES are not offered.
//!
//! The `symcrypt` crate has no CTR mode, raw ChaCha20 or Poly1305, and
//! `symcrypt-sys` does not bind them, so the `ffi` module declares those
//! SymCrypt functions. The SymCrypt builds russh is tested with export them
//! (Linux and Windows, x86_64 and arm64).

use std::ptr;
use std::sync::Once;

use subtle::ConstantTimeEq;
use symcrypt::cipher::BlockCipherType;
use symcrypt::gcm::GcmExpandedKey;
use symcrypt_sys::{SIZE_T, SYMCRYPT_AES_EXPANDED_KEY, SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR};
use zeroize::{Zeroize, Zeroizing};

use crate::cipher::block::SshBlockCipher;
use crate::cipher::chacha20poly1305::SshChacha20Poly1305Cipher;
use crate::cipher::gcm::GcmCipher;
use crate::cipher::{self, Cipher, PACKET_LENGTH_LEN};
use crate::crypto::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, Aead, BlockStream, CHACHA20_POLY1305_KEY_LEN, ChaCha20Poly1305,
    CryptoError, Result,
};

/// SymCrypt functions and types that `symcrypt-sys` does not bind, declared
/// as in `symcrypt.h`.
mod ffi {
    use symcrypt_sys::{
        PBYTE, PCBYTE, PCSYMCRYPT_BLOCKCIPHER, PCVOID, SIZE_T, SYMCRYPT_ERROR, UINT64,
    };

    /// `SYMCRYPT_CHACHA20_STATE` (`symcrypt_internal.h`). It has no pointers,
    /// so it may move.
    #[allow(dead_code)] // Only SymCrypt reads the fields.
    #[repr(C, align(16))]
    pub(super) struct ChaCha20State {
        key: [u32; 8],
        nonce: [u32; 3],
        offset: u64,
        keystream_buffer_valid: u8,
        keystream: [u8; 64],
    }

    const _: () = assert!(size_of::<ChaCha20State>() == 128);

    impl ChaCha20State {
        pub(super) const ZERO: Self = Self {
            key: [0; 8],
            nonce: [0; 3],
            offset: 0,
            keystream_buffer_valid: 0,
            keystream: [0; 64],
        };
    }

    // `kind = "dylib"` makes them `dllimport`s on Windows, like the statics
    // of `symcrypt-sys`.
    #[link(name = "symcrypt", kind = "dylib")]
    unsafe extern "C" {
        /// CTR mode over whole blocks. Increments only the last 8 bytes of
        /// `chaining_value` (big-endian, wrapping).
        pub(super) fn SymCryptCtrMsb64(
            block_cipher: PCSYMCRYPT_BLOCKCIPHER,
            expanded_key: PCVOID,
            chaining_value: PBYTE,
            src: PCBYTE,
            dst: PBYTE,
            len: SIZE_T,
        );

        /// Fails only if the key is not 32 bytes or the nonce not 12 bytes.
        pub(super) fn SymCryptChaCha20Init(
            state: *mut ChaCha20State,
            key: PCBYTE,
            key_len: SIZE_T,
            nonce: PCBYTE,
            nonce_len: SIZE_T,
            offset: UINT64,
        ) -> SYMCRYPT_ERROR;

        pub(super) fn SymCryptChaCha20SetOffset(state: *mut ChaCha20State, offset: UINT64);

        pub(super) fn SymCryptChaCha20Crypt(
            state: *mut ChaCha20State,
            src: PCBYTE,
            dst: PBYTE,
            len: SIZE_T,
        );

        /// One-shot Poly1305 with a 32-byte key and a 16-byte result.
        pub(super) fn SymCryptPoly1305(key: PCBYTE, data: PCBYTE, len: SIZE_T, result: PBYTE);
    }
}

/// Calls `SymCryptModuleInit` once, as SymCrypt requires before its other
/// functions. (The `symcrypt` crate does it too, but only in its own
/// functions.)
fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: no preconditions; it checks that the library is compatible
        // with the headers `symcrypt-sys` was generated from.
        unsafe {
            symcrypt_sys::SymCryptModuleInit(
                symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
                symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
            )
        }
    });
}

/// AES-GCM with a `KEY_SIZE`-byte key.
pub(crate) struct SymCryptAesGcm<const KEY_SIZE: usize>(GcmExpandedKey);

pub(crate) type SymCryptAes128Gcm = SymCryptAesGcm<16>;
pub(crate) type SymCryptAes256Gcm = SymCryptAesGcm<32>;

impl<const KEY_SIZE: usize> Aead for SymCryptAesGcm<KEY_SIZE> {
    const KEY_LEN: usize = KEY_SIZE;

    fn new(key: &[u8]) -> Result<Self> {
        // `GcmExpandedKey` accepts every AES key size.
        if key.len() != KEY_SIZE {
            return Err(CryptoError);
        }
        GcmExpandedKey::new(key, BlockCipherType::AesBlock)
            .map(Self)
            .map_err(|_| CryptoError)
    }

    fn seal_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; AEAD_TAG_LEN],
    ) -> Result<()> {
        self.0.encrypt_in_place(nonce, aad, in_out, tag);
        Ok(())
    }

    fn open_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<()> {
        let ciphertext_len = ciphertext_and_tag
            .len()
            .checked_sub(AEAD_TAG_LEN)
            .ok_or(CryptoError)?;
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);
        self.0
            .decrypt_in_place(nonce, aad, ciphertext, tag)
            .map_err(|_| CryptoError)
    }
}

/// AES-CTR with a `KEY_SIZE`-byte key and the 128-bit big-endian counter of
/// RFC 4344, which persists across packets.
pub(crate) struct SymCryptAesCtr<const KEY_SIZE: usize> {
    // Boxed so that it never moves: SymCrypt's expanded key points into
    // itself.
    key: Box<SYMCRYPT_AES_EXPANDED_KEY>,
    /// The counter of the next block.
    counter: [u8; 16],
}

pub(crate) type SymCryptAes128Ctr = SymCryptAesCtr<16>;
pub(crate) type SymCryptAes192Ctr = SymCryptAesCtr<24>;
pub(crate) type SymCryptAes256Ctr = SymCryptAesCtr<32>;

// SAFETY: the pointers in the expanded key only point into its own
// allocation, which this value owns; SymCrypt keeps no reference to it.
unsafe impl<const KEY_SIZE: usize> Send for SymCryptAesCtr<KEY_SIZE> {}

impl<const KEY_SIZE: usize> SymCryptAesCtr<KEY_SIZE> {
    /// XORs `blocks` (whole blocks) with the key stream from `counter`,
    /// which SymCrypt advances in its low 64 bits only.
    fn ctr_msb64(&self, counter: &mut [u8; 16], blocks: &mut [u8]) {
        let data = blocks.as_mut_ptr();
        // SAFETY: `self.key` is an expanded AES key, as the block cipher
        // requires; `counter` is one block; `data` is valid for
        // `blocks.len()` bytes, and SymCrypt allows the same source and
        // destination.
        unsafe {
            ffi::SymCryptCtrMsb64(
                symcrypt_sys::SymCryptAesBlockCipher,
                ptr::from_ref(&*self.key).cast(),
                counter.as_mut_ptr(),
                data,
                data,
                blocks.len() as SIZE_T,
            );
        }
    }

    fn apply_key_stream(&mut self, data: &mut [u8]) {
        let (mut blocks, tail) = data.split_at_mut(data.len() - data.len() % 16);
        while !blocks.is_empty() {
            let start = u128::from_be_bytes(self.counter);
            // SymCrypt does not carry into the high 64 bits of the counter:
            // stop where the low 64 bits wrap, and carry here.
            let before_wrap = (1u128 << 64) - u128::from(start as u64);
            let count = (blocks.len() / 16).min(usize::try_from(before_wrap).unwrap_or(usize::MAX));
            let (chunk, rest) = std::mem::take(&mut blocks).split_at_mut(count * 16);
            let mut counter = self.counter;
            self.ctr_msb64(&mut counter, chunk);
            self.counter = start.wrapping_add(count as u128).to_be_bytes();
            blocks = rest;
        }
        if !tail.is_empty() {
            // Only a peer that breaks the protocol makes us decrypt a partial
            // block: use the key stream of a whole one.
            let mut key_stream = Zeroizing::new([0; 16]);
            self.apply_key_stream(&mut *key_stream);
            for (byte, key) in tail.iter_mut().zip(key_stream.iter()) {
                *byte ^= key;
            }
        }
    }
}

impl<const KEY_SIZE: usize> BlockStream for SymCryptAesCtr<KEY_SIZE> {
    const KEY_LEN: usize = KEY_SIZE;
    const IV_LEN: usize = 16;

    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(CryptoError);
        }
        let counter = iv.try_into().map_err(|_| CryptoError)?;
        init();
        let mut ctr = Self {
            key: Box::default(),
            counter,
        };
        // SAFETY: `ctr.key` is a writable expanded key that does not move
        // afterwards, and `key` is valid for `key.len()` bytes.
        let error = unsafe {
            symcrypt_sys::SymCryptAesExpandKey(&mut *ctr.key, key.as_ptr(), key.len() as SIZE_T)
        };
        if error != SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR {
            return Err(CryptoError);
        }
        Ok(ctr)
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        self.apply_key_stream(data);
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        self.apply_key_stream(data);
    }

    fn peek_decrypt(&self, first_block: &mut [u8; 16]) {
        let mut counter = self.counter;
        self.ctr_msb64(&mut counter, first_block);
    }
}

impl<const KEY_SIZE: usize> Drop for SymCryptAesCtr<KEY_SIZE> {
    fn drop(&mut self) {
        // SAFETY: wipes exactly the expanded key.
        unsafe {
            symcrypt_sys::SymCryptWipe(
                ptr::from_mut(&mut *self.key).cast(),
                size_of::<SYMCRYPT_AES_EXPANDED_KEY>() as SIZE_T,
            );
        }
        self.counter.zeroize();
    }
}

/// `chacha20-poly1305@openssh.com`: two ChaCha20 keys, each used with the
/// packet sequence number as nonce.
pub(crate) struct SymCryptChaCha20Poly1305 {
    /// K_2 (the first half of the key): the payload, from block 1, and the
    /// Poly1305 key, from block 0.
    main_key: Zeroizing<[u8; 32]>,
    /// K_1 (the second half): the packet length.
    header_key: Zeroizing<[u8; 32]>,
}

impl ChaCha20Poly1305 for SymCryptChaCha20Poly1305 {
    fn new(key: &[u8; CHACHA20_POLY1305_KEY_LEN]) -> Result<Self> {
        let mut main_key = Zeroizing::new([0; 32]);
        let mut header_key = Zeroizing::new([0; 32]);
        let (main, header) = key.split_at(32);
        main_key.copy_from_slice(main);
        header_key.copy_from_slice(header);
        Ok(Self {
            main_key,
            header_key,
        })
    }

    fn decrypt_packet_length(
        &self,
        sequence_number: u32,
        mut encrypted_length: [u8; 4],
    ) -> [u8; 4] {
        ChaCha20::new(&self.header_key, sequence_number).apply(&mut encrypted_length);
        encrypted_length
    }

    fn open_in_place(
        &self,
        sequence_number: u32,
        packet: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<()> {
        if packet.len() < PACKET_LENGTH_LEN {
            return Err(CryptoError);
        }
        let mut main = ChaCha20::new(&self.main_key, sequence_number);
        let mut expected = [0; AEAD_TAG_LEN];
        poly1305(&main.poly1305_key(), packet, &mut expected);
        if !bool::from(expected.as_slice().ct_eq(tag.as_slice())) {
            return Err(CryptoError);
        }
        let payload = packet.get_mut(PACKET_LENGTH_LEN..).ok_or(CryptoError)?;
        main.seek_block(1);
        main.apply(payload);
        Ok(())
    }

    fn seal_in_place(
        &self,
        sequence_number: u32,
        packet: &mut [u8],
        tag: &mut [u8; AEAD_TAG_LEN],
    ) -> Result<()> {
        let (length, payload) = packet
            .split_at_mut_checked(PACKET_LENGTH_LEN)
            .ok_or(CryptoError)?;
        ChaCha20::new(&self.header_key, sequence_number).apply(length);
        let mut main = ChaCha20::new(&self.main_key, sequence_number);
        let poly1305_key = main.poly1305_key();
        main.seek_block(1);
        main.apply(payload);
        poly1305(&poly1305_key, packet, tag);
        Ok(())
    }
}

/// The ChaCha20 key stream of a packet, wiped on drop.
struct ChaCha20(ffi::ChaCha20State);

impl ChaCha20 {
    /// Starts at block 0. OpenSSH uses the original ChaCha20, whose 64-bit
    /// nonce is the big-endian sequence number; in the RFC 8439 layout
    /// SymCrypt implements, that is a 96-bit nonce of 8 zero bytes and the
    /// sequence number (the block counter of a packet never exceeds 32 bits).
    fn new(key: &[u8; 32], sequence_number: u32) -> Self {
        init();
        let [s0, s1, s2, s3] = sequence_number.to_be_bytes();
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0, s0, s1, s2, s3];
        let mut chacha = Self(ffi::ChaCha20State::ZERO);
        // SAFETY: the state is writable, and the key and nonce have the 32
        // and 12 bytes SymCrypt reads.
        let error = unsafe {
            ffi::SymCryptChaCha20Init(
                &mut chacha.0,
                key.as_ptr(),
                key.len() as SIZE_T,
                nonce.as_ptr(),
                nonce.len() as SIZE_T,
                0,
            )
        };
        // It only checks the key and nonce lengths.
        debug_assert_eq!(error, SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR);
        chacha
    }

    fn seek_block(&mut self, block: u64) {
        // SAFETY: the state was initialized by `new`.
        unsafe { ffi::SymCryptChaCha20SetOffset(&mut self.0, block * 64) }
    }

    fn apply(&mut self, data: &mut [u8]) {
        let data_ptr = data.as_mut_ptr();
        // SAFETY: the state was initialized by `new`; `data_ptr` is valid for
        // `data.len()` bytes, and SymCrypt allows the same source and
        // destination.
        unsafe {
            ffi::SymCryptChaCha20Crypt(&mut self.0, data_ptr, data_ptr, data.len() as SIZE_T)
        }
    }

    /// The first 32 bytes of the key stream.
    fn poly1305_key(&mut self) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0; 32]);
        self.apply(&mut *key);
        key
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        // SAFETY: wipes exactly the state.
        unsafe {
            symcrypt_sys::SymCryptWipe(
                ptr::from_mut(&mut self.0).cast(),
                size_of::<ffi::ChaCha20State>() as SIZE_T,
            );
        }
    }
}

fn poly1305(key: &[u8; 32], data: &[u8], tag: &mut [u8; AEAD_TAG_LEN]) {
    // SAFETY: the key and tag have the 32 and 16 bytes SymCrypt reads and
    // writes, and `data` is valid for `data.len()` bytes.
    unsafe {
        ffi::SymCryptPoly1305(
            key.as_ptr(),
            data.as_ptr(),
            data.len() as SIZE_T,
            tag.as_mut_ptr(),
        );
    }
}

static AES_128_GCM: GcmCipher<SymCryptAes128Gcm> = GcmCipher::new();
static AES_256_GCM: GcmCipher<SymCryptAes256Gcm> = GcmCipher::new();
static CHACHA20_POLY1305: SshChacha20Poly1305Cipher<SymCryptChaCha20Poly1305> =
    SshChacha20Poly1305Cipher::new();
static AES_128_CTR: SshBlockCipher<SymCryptAes128Ctr> = SshBlockCipher::new();
static AES_192_CTR: SshBlockCipher<SymCryptAes192Ctr> = SshBlockCipher::new();
static AES_256_CTR: SshBlockCipher<SymCryptAes256Ctr> = SshBlockCipher::new();

/// Every cipher of this backend (`clear`/`none` are shared by all providers).
pub(crate) static ALGORITHMS: &[(&cipher::Name, &(dyn Cipher + Send + Sync))] = &[
    (&cipher::AES_128_GCM, &AES_128_GCM),
    (&cipher::AES_256_GCM, &AES_256_GCM),
    (&cipher::CHACHA20_POLY1305, &CHACHA20_POLY1305),
    (&cipher::AES_128_CTR, &AES_128_CTR),
    (&cipher::AES_192_CTR, &AES_192_CTR),
    (&cipher::AES_256_CTR, &AES_256_CTR),
];

/// The same preference as the `aws_lc` and `ring` backends.
pub(crate) const DEFAULT_ORDER: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_256_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CTR,
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::cipher::CIPHERS;
    use crate::mac::{self, MacAlgorithm};
    use crate::sshbuffer::SSHBuffer;

    #[test]
    fn offers_aeads_and_aes_ctr() {
        assert_eq!(
            ALGORITHMS.iter().map(|(name, _)| **name).collect::<Vec<_>>(),
            [
                cipher::AES_128_GCM,
                cipher::AES_256_GCM,
                cipher::CHACHA20_POLY1305,
                cipher::AES_128_CTR,
                cipher::AES_192_CTR,
                cipher::AES_256_CTR,
            ]
        );
        assert_eq!(
            DEFAULT_ORDER,
            [
                cipher::CHACHA20_POLY1305,
                cipher::AES_256_GCM,
                cipher::AES_256_CTR,
                cipher::AES_192_CTR,
                cipher::AES_128_CTR,
            ]
        );
        for name in [
            cipher::AES_128_CBC,
            cipher::AES_192_CBC,
            cipher::AES_256_CBC,
            #[cfg(feature = "des")]
            cipher::TRIPLE_DES_CBC,
        ] {
            assert!(!CIPHERS.contains_key(&name), "{name:?}");
        }
    }

    fn check_gcm<A: Aead>(
        key: &[u8],
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &[u8],
        tag: [u8; 16],
    ) {
        let aead = A::new(key).unwrap();
        let mut in_out = plaintext.to_vec();
        let mut actual_tag = [0; 16];
        aead.seal_in_place(&nonce, aad, &mut in_out, &mut actual_tag)
            .unwrap();
        assert_eq!(in_out, ciphertext);
        assert_eq!(actual_tag, tag);

        let sealed = [ciphertext, &tag].concat();
        let mut opened = sealed.clone();
        aead.open_in_place(&nonce, aad, &mut opened).unwrap();
        assert_eq!(&opened[..plaintext.len()], plaintext);

        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert!(aead.open_in_place(&nonce, aad, &mut tampered).is_err());
        }
        let mut other_nonce = nonce;
        other_nonce[11] ^= 1;
        assert!(
            aead.open_in_place(&other_nonce, aad, &mut sealed.clone())
                .is_err()
        );
        assert!(
            aead.open_in_place(&nonce, b"other", &mut sealed.clone())
                .is_err()
        );
        assert!(
            aead.open_in_place(&nonce, aad, &mut sealed[..15].to_vec())
                .is_err()
        );
    }

    /// Test cases 2, 4 and 16 of the GCM specification (McGrew and Viega).
    #[test]
    fn aes_gcm_matches_known_answers() {
        check_gcm::<SymCryptAes128Gcm>(
            &[0; 16],
            [0; 12],
            &[],
            &[0; 16],
            &hex!("0388dace60b6a392f328c2b971b2fe78"),
            hex!("ab6e47d42cec13bdf53a67b21257bddf"),
        );

        let nonce = hex!("cafebabefacedbaddecaf888");
        let aad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        );
        check_gcm::<SymCryptAes128Gcm>(
            &hex!("feffe9928665731c6d6a8f9467308308"),
            nonce,
            &aad,
            &plaintext,
            &hex!(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
            ),
            hex!("5bc94fbc3221a5db94fae95ae7121a47"),
        );
        check_gcm::<SymCryptAes256Gcm>(
            &hex!(
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
            ),
            nonce,
            &aad,
            &plaintext,
            &hex!(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
            ),
            hex!("76fc6ece0f4e1768cddf8853bb2d551b"),
        );
    }

    #[test]
    fn aes_gcm_rejects_other_key_lengths() {
        for len in [0, 15, 24, 32] {
            assert!(SymCryptAes128Gcm::new(&vec![0; len]).is_err(), "{len}");
        }
        for len in [0, 16, 24, 31] {
            assert!(SymCryptAes256Gcm::new(&vec![0; len]).is_err(), "{len}");
        }
    }

    const CTR_PLAINTEXT: [u8; 64] = hex!(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    );
    const CTR_IV: [u8; 16] = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const AES_128_KEY: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    const AES_128_CTR_CIPHERTEXT: [u8; 64] = hex!(
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
    );

    /// Encrypts and decrypts `CTR_PLAINTEXT` in two calls, split at every
    /// block boundary: the counter carries over from one call to the next.
    fn check_ctr<B: BlockStream>(key: &[u8], iv: [u8; 16], ciphertext: [u8; 64]) {
        for split in (0..=64).step_by(16) {
            let mut encryptor = B::new(key, &iv).unwrap();
            let mut data = CTR_PLAINTEXT;
            let (first, second) = data.split_at_mut(split);
            encryptor.encrypt(first);
            encryptor.encrypt(second);
            assert_eq!(data, ciphertext, "split at {split}");

            let mut decryptor = B::new(key, &iv).unwrap();
            let (first, second) = data.split_at_mut(split);
            decryptor.decrypt(first);
            if let Some(next_block) = second.first_chunk::<16>() {
                // Without advancing the counter.
                let mut next_block = *next_block;
                decryptor.peek_decrypt(&mut next_block);
                assert_eq!(next_block, CTR_PLAINTEXT[split..split + 16]);
            }
            decryptor.decrypt(second);
            assert_eq!(data, CTR_PLAINTEXT, "split at {split}");
        }
    }

    /// The CTR examples of NIST SP 800-38A (F.5.1, F.5.3 and F.5.5), and a
    /// counter that carries into its high 64 bits and one that wraps (the
    /// expected values are OpenSSL's).
    #[test]
    fn aes_ctr_matches_known_answers() {
        check_ctr::<SymCryptAes128Ctr>(&AES_128_KEY, CTR_IV, AES_128_CTR_CIPHERTEXT);
        check_ctr::<SymCryptAes192Ctr>(
            &hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
            CTR_IV,
            hex!(
                "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94"
                "1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050"
            ),
        );
        check_ctr::<SymCryptAes256Ctr>(
            &hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            CTR_IV,
            hex!(
                "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
                "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"
            ),
        );
        check_ctr::<SymCryptAes128Ctr>(
            &AES_128_KEY,
            hex!("0001020304050607fffffffffffffffe"),
            hex!(
                "80d9f9cddc6c8d50d1f8ccf65bbe1a0a93a52cdaaef04f5af0c8b76df464f72b"
                "1a408d949ac87ffbdb5f37d86574fbb8fc4d52fc7b8090024498e98e9d968b59"
            ),
        );
        check_ctr::<SymCryptAes128Ctr>(
            &AES_128_KEY,
            [0xff; 16],
            hex!(
                "e13338e36cb71962e00d020b4cedbd86d3dae15b04bb352fa0f59febfcb4da3e"
                "67da610697ed5aae4b0fa7a0dd783d2961a00ab697367915d23c754bd99e2899"
            ),
        );
    }

    #[test]
    fn aes_ctr_partial_block_uses_a_whole_block_of_key_stream() {
        let mut ctr = SymCryptAes128Ctr::new(&AES_128_KEY, &CTR_IV).unwrap();
        let mut data = CTR_PLAINTEXT;
        ctr.encrypt(&mut data[..40]);
        ctr.encrypt(&mut data[48..]);
        assert_eq!(data[..40], AES_128_CTR_CIPHERTEXT[..40]);
        assert_eq!(data[48..], AES_128_CTR_CIPHERTEXT[48..]);
    }

    #[test]
    fn aes_ctr_rejects_other_key_and_iv_lengths() {
        assert!(SymCryptAes128Ctr::new(&[0; 24], &[0; 16]).is_err());
        assert!(SymCryptAes192Ctr::new(&[0; 16], &[0; 16]).is_err());
        assert!(SymCryptAes256Ctr::new(&[0; 24], &[0; 16]).is_err());
        assert!(SymCryptAes256Ctr::new(&[0; 32], &[0; 12]).is_err());
        assert!(SymCryptAes256Ctr::new(&[0; 32], &[0; 17]).is_err());
    }

    /// Computed with OpenSSL's ChaCha20 and Poly1305 following OpenSSH's
    /// `PROTOCOL.chacha20poly1305`, and checked against aws-lc's
    /// `chacha20_poly1305_openssh`.
    #[test]
    fn chacha20_poly1305_matches_known_answers() {
        let key: [u8; 64] = std::array::from_fn(|i| i as u8);
        let cipher = SymCryptChaCha20Poly1305::new(&key).unwrap();

        let mut long_packet = 100u32.to_be_bytes().to_vec();
        long_packet.extend((0..100).map(|i: u8| i.wrapping_mul(7)));
        let cases = [
            (
                7,
                &hex!("0000000c7061796c6f61642d31323334")[..],
                &hex!("a39afca658276c2f21e24e735d5f88c4")[..],
                hex!("6623f62289ddbe50653a873f80a5e0ca"),
            ),
            (
                0x89ab_cdef,
                &long_packet[..],
                &hex!(
                    "52a7502b3da24e30d9bd70f24943dc5bda2e9b757d27c810b0cc5796158260a6"
                    "980c72b327e4031864956d815ed5d42e17f14f8a1d77a507fda97ee235d77238"
                    "ea88fe2a2ca8a7d430647b0c7a180e0292d75d48f754d8b211d0458e2ffbdf50"
                    "5e01b23a99f2db92"
                )[..],
                hex!("df27c80db3e34111ddfba18769822823"),
            ),
        ];
        for (sequence_number, packet, sealed, tag) in cases {
            let mut data = packet.to_vec();
            let mut actual_tag = [0; 16];
            cipher
                .seal_in_place(sequence_number, &mut data, &mut actual_tag)
                .unwrap();
            assert_eq!(data, sealed);
            assert_eq!(actual_tag, tag);

            assert_eq!(
                cipher.decrypt_packet_length(sequence_number, sealed[..4].try_into().unwrap()),
                packet[..4]
            );

            // The packet length stays encrypted.
            let mut data = sealed.to_vec();
            cipher
                .open_in_place(sequence_number, &mut data, &tag)
                .unwrap();
            assert_eq!(data[..4], sealed[..4]);
            assert_eq!(data[4..], packet[4..]);

            assert!(
                cipher
                    .open_in_place(sequence_number.wrapping_add(1), &mut sealed.to_vec(), &tag)
                    .is_err()
            );
            // Nothing is decrypted unless the tag is valid.
            for i in 0..sealed.len() {
                let mut tampered = sealed.to_vec();
                tampered[i] ^= 1;
                let before = tampered.clone();
                assert!(
                    cipher
                        .open_in_place(sequence_number, &mut tampered, &tag)
                        .is_err()
                );
                assert_eq!(tampered, before);
            }
            for i in 0..tag.len() {
                let mut bad_tag = tag;
                bad_tag[i] ^= 1;
                assert!(
                    cipher
                        .open_in_place(sequence_number, &mut sealed.to_vec(), &bad_tag)
                        .is_err()
                );
            }
        }

        assert!(cipher.seal_in_place(0, &mut [0; 3], &mut [0; 16]).is_err());
        assert!(cipher.open_in_place(0, &mut [0; 3], &[0; 16]).is_err());
    }

    fn fixture(len: usize, seed: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + seed) as u8).collect()
    }

    /// Every cipher, with every MAC if it needs one, through the packet
    /// layer (`SealingKey::write` and `cipher::read`).
    #[tokio::test]
    async fn packets_round_trip() {
        for &(name, cipher) in ALGORITHMS {
            let macs: Vec<(&mac::Name, &(dyn MacAlgorithm + Send + Sync))> = if cipher.needs_mac()
            {
                super::super::mac::ALGORITHMS.to_vec()
            } else {
                vec![(&mac::NONE, &mac::_NONE)]
            };
            for (mac_name, mac) in macs {
                let key = fixture(cipher.key_len(), 1);
                let nonce = fixture(cipher.nonce_len(), 2);
                let mac_key = fixture(mac.key_len(), 3);
                let mut sealing = cipher.make_sealing_key(&key, &nonce, &mac_key, mac);
                let mut opening = cipher.make_opening_key(&key, &nonce, &mac_key, mac);
                let mut written = SSHBuffer::new();
                let mut read = SSHBuffer::new();
                for len in [0, 1, 15, 16, 17, 100, 1000, 35000] {
                    let payload = fixture(len, 4);
                    written.buffer.clear();
                    sealing.write(&payload, &mut written);
                    let mut stream = written.buffer.as_slice();
                    let n = cipher::read(&mut stream, &mut read, &mut *opening)
                        .await
                        .unwrap();
                    assert_eq!(
                        &read.buffer[5..n],
                        &payload[..],
                        "{name:?} with {mac_name:?}, {len} bytes"
                    );
                    assert!(stream.is_empty());
                }

                written.buffer.clear();
                sealing.write(b"payload", &mut written);
                written.buffer[10] ^= 1;
                let mut stream = written.buffer.as_slice();
                assert!(
                    cipher::read(&mut stream, &mut read, &mut *opening)
                        .await
                        .is_err(),
                    "{name:?} with {mac_name:?}"
                );
            }
        }
    }
}
