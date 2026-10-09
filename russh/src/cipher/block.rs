// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use std::convert::TryInto;
use std::marker::PhantomData;

use super::super::Error;
use super::PACKET_LENGTH_LEN;
use crate::crypto::{self, BlockStream};
use crate::mac::{Mac, MacAlgorithm};

/// A stateful cipher with a separate MAC (AES-CTR and CBC modes), generic
/// over the backend's [`BlockStream`].
pub struct SshBlockCipher<B>(PhantomData<fn() -> B>);

impl<B> SshBlockCipher<B> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

fn new_block_stream<B: BlockStream>(k: &[u8], n: &[u8]) -> B {
    #[allow(clippy::expect_used)]
    B::new(k, n).expect("key and iv lengths match")
}

impl<B: BlockStream> super::Cipher for SshBlockCipher<B> {
    fn key_len(&self) -> usize {
        B::KEY_LEN
    }

    fn nonce_len(&self) -> usize {
        B::IV_LEN
    }

    fn needs_mac(&self) -> bool {
        true
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        Box::new(OpeningKey {
            cipher: new_block_stream::<B>(k, n),
            mac: mac.make_mac(m),
        })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        Box::new(SealingKey {
            cipher: new_block_stream::<B>(k, n),
            mac: mac.make_mac(m),
        })
    }
}

pub struct OpeningKey<B> {
    pub(crate) cipher: B,
    pub(crate) mac: Box<dyn Mac + Send>,
}

pub struct SealingKey<B> {
    pub(crate) cipher: B,
    pub(crate) mac: Box<dyn Mac + Send>,
}

impl<B: BlockStream> super::OpeningKey for OpeningKey<B> {
    fn packet_length_to_read_for_block_length(&self) -> usize {
        16
    }

    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        let mut first_block = [0u8; 16];
        // Fine because of self.packet_length_to_read_for_block_length()
        #[allow(clippy::indexing_slicing)]
        first_block.copy_from_slice(&encrypted_packet_length[..16]);

        if self.mac.is_etm() {
            // Fine because of self.packet_length_to_read_for_block_length()
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            encrypted_packet_length[..4].try_into().unwrap()
        } else {
            self.cipher.peek_decrypt(&mut first_block);

            // Fine because of self.packet_length_to_read_for_block_length()
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            first_block[..4].try_into().unwrap()
        }
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let ciphertext_len = ciphertext_and_tag.len() - self.tag_len();
        let (ciphertext_in_plaintext_out, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);
        if self.mac.is_etm() {
            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
            #[allow(clippy::indexing_slicing)]
            self.cipher
                .decrypt(&mut ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..]);
        } else {
            self.cipher.decrypt(ciphertext_in_plaintext_out);

            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
        }

        #[allow(clippy::indexing_slicing)]
        Ok(&ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..])
    }
}

impl<B: BlockStream> super::SealingKey for SealingKey<B> {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;

        let pll = if self.mac.is_etm() {
            0
        } else {
            PACKET_LENGTH_LEN
        };

        let extra_len = PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + self.mac.mac_len();

        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN - pll
        } else {
            block_size - ((pll + super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        crypto::fill_random(padding_out);
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        if self.mac.is_etm() {
            #[allow(clippy::indexing_slicing)]
            self.cipher
                .encrypt(&mut plaintext_in_ciphertext_out[PACKET_LENGTH_LEN..]);
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
        } else {
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
            self.cipher.encrypt(plaintext_in_ciphertext_out);
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::OpeningKey;
    use crate::crypto::{self, BlockStream};
    use crate::mac::MacAlgorithm;
    use crate::sshbuffer::SSHBuffer;

    #[test]
    fn decrypt_packet_length_uses_independent_cipher_state() -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut opening = OpeningKey {
            cipher: OwnedStateCipher {
                packet_length: Box::new([0, 0, 0, 13]),
            },
            mac: crate::mac::_NONE.make_mac(&[]),
        };
        let mut buffer = SSHBuffer::new();
        let bytes_read = runtime
            .block_on(async {
                let (mut writer, mut reader) = tokio::io::duplex(64);
                writer.write_all(&[0; 17]).await?;
                drop(writer);
                crate::cipher::read(&mut reader, &mut buffer, &mut opening).await
            })
            .map_err(std::io::Error::other)?;

        assert_eq!(bytes_read, 16);
        Ok(())
    }

    /// Decrypts every packet length to 13, but peeks 12: the probe must not
    /// share state with the cipher that decrypts the packet.
    struct OwnedStateCipher {
        packet_length: Box<[u8; 4]>,
    }

    impl BlockStream for OwnedStateCipher {
        const KEY_LEN: usize = 16;
        const IV_LEN: usize = 16;

        fn new(_: &[u8], _: &[u8]) -> crypto::Result<Self> {
            Err(crypto::CryptoError)
        }

        fn encrypt(&mut self, _data: &mut [u8]) {}

        fn decrypt(&mut self, data: &mut [u8]) {
            if let Some(prefix) = data.get_mut(..4) {
                prefix.copy_from_slice(&self.packet_length[..]);
            }
        }

        fn peek_decrypt(&self, first_block: &mut [u8; 16]) {
            if let Some(prefix) = first_block.get_mut(..4) {
                prefix.copy_from_slice(&[0, 0, 0, 12]);
            }
        }
    }
}
