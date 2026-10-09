//! AES-CTR, AES-CBC and 3DES-CBC (RustCrypto `aes`, `ctr`, `cbc`, `des`).
//! No AEADs: those come from aws-lc-rs or ring.

use aes::cipher::typenum::Unsigned as _;
use aes::cipher::{
    InOutBuf, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser, StreamCipher, StreamCipherError,
    StreamCipherSeek,
};
use aes::{Aes128, Aes192, Aes256};
use ctr::Ctr128BE;

use super::cbc::CbcWrapper;
use crate::cipher::block::SshBlockCipher;
use crate::crypto::{BlockStream, CryptoError, Result};

/// Cloneable wrapper for `Ctr128BE<>`
pub(crate) struct CtrWrapper<C>
where
    C: KeyIvInit,
{
    key: Key<C>,
    initial_iv: Iv<C>,
    pos: u64,
}

impl<C: KeyIvInit> Clone for CtrWrapper<C> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            initial_iv: self.initial_iv.clone(),
            pos: self.pos,
        }
    }
}

impl<C: KeyIvInit> KeySizeUser for CtrWrapper<C> {
    type KeySize = <C as KeySizeUser>::KeySize;
}

impl<C: KeyIvInit> IvSizeUser for CtrWrapper<C> {
    type IvSize = <C as IvSizeUser>::IvSize;
}

impl<C: KeyIvInit> KeyIvInit for CtrWrapper<C> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            key: key.clone(),
            initial_iv: iv.clone(),
            pos: 0,
        }
    }
}

impl<C: KeyIvInit + StreamCipher + StreamCipherSeek> StreamCipher for CtrWrapper<C> {
    fn check_remaining(&self, _data_len: usize) -> std::result::Result<(), StreamCipherError> {
        Ok(())
    }

    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        let mut cipher = C::new(&self.key, &self.initial_iv);
        cipher.seek(self.pos);
        cipher.unchecked_apply_keystream_inout(buf);
        self.pos = cipher.current_pos();
    }

    fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
        let mut cipher = C::new(&self.key, &self.initial_iv);
        cipher.seek(self.pos);
        cipher.unchecked_write_keystream(buf);
        self.pos = cipher.current_pos();
    }
}

impl<C> BlockStream for CtrWrapper<C>
where
    C: KeyIvInit + StreamCipher + StreamCipherSeek + 'static,
{
    const KEY_LEN: usize = <Self as KeySizeUser>::KeySize::USIZE;
    const IV_LEN: usize = <Self as IvSizeUser>::IvSize::USIZE;

    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        <Self as KeyIvInit>::new_from_slices(key, iv).map_err(|_| CryptoError)
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    fn peek_decrypt(&self, first_block: &mut [u8; 16]) {
        self.clone().apply_keystream(first_block);
    }
}

pub(crate) static AES_128_CTR: SshBlockCipher<CtrWrapper<Ctr128BE<Aes128>>> =
    SshBlockCipher::new();
pub(crate) static AES_192_CTR: SshBlockCipher<CtrWrapper<Ctr128BE<Aes192>>> =
    SshBlockCipher::new();
pub(crate) static AES_256_CTR: SshBlockCipher<CtrWrapper<Ctr128BE<Aes256>>> =
    SshBlockCipher::new();
pub(crate) static AES_128_CBC: SshBlockCipher<CbcWrapper<Aes128>> = SshBlockCipher::new();
pub(crate) static AES_192_CBC: SshBlockCipher<CbcWrapper<Aes192>> = SshBlockCipher::new();
pub(crate) static AES_256_CBC: SshBlockCipher<CbcWrapper<Aes256>> = SshBlockCipher::new();
#[cfg(feature = "des")]
pub(crate) static TRIPLE_DES_CBC: SshBlockCipher<CbcWrapper<des::TdesEde3>> =
    SshBlockCipher::new();

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn stream_cipher_probe_does_not_advance_cipher_state() {
        let plaintext = *b"0123456789ABCDEF";
        let key = fixture_bytes::<16>(7);
        let iv = fixture_bytes::<16>(3);

        let mut encryptor = <CtrWrapper<Ctr128BE<Aes128>> as BlockStream>::new(&key, &iv).unwrap();
        let mut ciphertext = plaintext;
        encryptor.encrypt(&mut ciphertext);

        let cipher = <CtrWrapper<Ctr128BE<Aes128>> as BlockStream>::new(&key, &iv).unwrap();
        let mut probed_block = ciphertext;
        cipher.peek_decrypt(&mut probed_block);
        assert_eq!(probed_block, plaintext);

        let mut decrypted = ciphertext;
        let mut cipher_after_probe = cipher;
        cipher_after_probe.decrypt(&mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_ctr_matches_nist_sp800_38a() {
        // NIST SP 800-38A F.5.1 (CTR-AES128.Encrypt), first block.
        let key = hex_literal::hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut block = hex_literal::hex!("6bc1bee22e409f96e93d7e117393172a");
        let mut cipher = <CtrWrapper<Ctr128BE<Aes128>> as BlockStream>::new(&key, &iv).unwrap();
        cipher.encrypt(&mut block);
        assert_eq!(block, hex_literal::hex!("874d6191b620e3261bef6864990db6ce"));
        assert!(<CtrWrapper<Ctr128BE<Aes128>> as BlockStream>::new(&key[1..], &iv).is_err());
    }

    fn fixture_bytes<const N: usize>(seed: u8) -> [u8; N] {
        let mut bytes = [0; N];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        bytes
    }
}
