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
        if self.mac.is_etm() {
            // Sent in the clear.
            PACKET_LENGTH_LEN
        } else {
            B::BLOCK_SIZE
        }
    }

    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        if self.mac.is_etm() {
            // Fine because of self.packet_length_to_read_for_block_length()
            #[allow(clippy::unwrap_used)]
            encrypted_packet_length.try_into().unwrap()
        } else {
            let mut first_block = [0u8; 16];
            // Fine because BLOCK_SIZE is at most 16
            #[allow(clippy::indexing_slicing)]
            let first_block = &mut first_block[..B::BLOCK_SIZE];
            // Fine because of self.packet_length_to_read_for_block_length()
            first_block.copy_from_slice(encrypted_packet_length);
            self.cipher.peek_decrypt(first_block);

            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            first_block[..PACKET_LENGTH_LEN].try_into().unwrap()
        }
    }

    fn is_valid_packet_length(&self, packet_length: usize) -> bool {
        if self.mac.is_etm() {
            // Only what follows the clear packet length is encrypted, so only
            // that is padded to whole blocks: with 3DES, a packet can be as
            // short as 4 + 8 bytes.
            packet_length != 0 && packet_length.is_multiple_of(B::BLOCK_SIZE)
        } else {
            // RFC 4253, section 6.
            PACKET_LENGTH_LEN + packet_length >= super::MINIMUM_PACKET_LEN
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
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::OpeningKey;
    use crate::Error;
    use crate::cipher::{self, CIPHERS, PACKET_LENGTH_LEN};
    use crate::crypto::{self, BlockStream};
    use crate::mac::{self, MACS, MacAlgorithm};
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
        const BLOCK_SIZE: usize = 16;

        fn new(_: &[u8], _: &[u8]) -> crypto::Result<Self> {
            Err(crypto::CryptoError)
        }

        fn encrypt(&mut self, _data: &mut [u8]) {}

        fn decrypt(&mut self, data: &mut [u8]) {
            if let Some(prefix) = data.get_mut(..4) {
                prefix.copy_from_slice(&self.packet_length[..]);
            }
        }

        fn peek_decrypt(&self, first_block: &mut [u8]) {
            if let Some(prefix) = first_block.get_mut(..4) {
                prefix.copy_from_slice(&[0, 0, 0, 12]);
            }
        }
    }

    /// Keys for both directions, and whether the MAC is EtM.
    fn keys(
        cipher_name: cipher::Name,
        mac_name: mac::Name,
    ) -> (
        Box<dyn cipher::SealingKey + Send>,
        Box<dyn cipher::OpeningKey + Send>,
        bool,
    ) {
        let cipher = CIPHERS.get(&cipher_name).unwrap();
        let mac = *MACS.get(&mac_name).unwrap();
        let key = vec![1; cipher.key_len()];
        let nonce = vec![2; cipher.nonce_len()];
        let mac_key = vec![3; mac.key_len()];
        (
            cipher.make_sealing_key(&key, &nonce, &mac_key, mac),
            cipher.make_opening_key(&key, &nonce, &mac_key, mac),
            mac.make_mac(&mac_key).is_etm(),
        )
    }

    /// Seals a packet padded the way OpenSSH pads it
    /// (`ssh_packet_send2_wrapped`): what gets encrypted ends on a whole
    /// `block_size` block, after at least 4 bytes of padding.
    fn openssh_packet(
        sealing: &mut (dyn cipher::SealingKey + Send),
        etm: bool,
        block_size: usize,
        seqn: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let clear_len = if etm { PACKET_LENGTH_LEN } else { 0 };
        let unpadded_len = PACKET_LENGTH_LEN + 1 + payload.len() - clear_len;
        let mut padding_length = block_size - unpadded_len % block_size;
        if padding_length < 4 {
            padding_length += block_size;
        }
        let packet_length = 1 + payload.len() + padding_length;

        let mut packet = (packet_length as u32).to_be_bytes().to_vec();
        packet.push(padding_length as u8);
        packet.extend_from_slice(payload);
        packet.resize(PACKET_LENGTH_LEN + packet_length, 0);
        let mut tag = vec![0; sealing.tag_len()];
        sealing.seal(seqn, &mut packet, &mut tag);
        packet.extend_from_slice(&tag);
        packet
    }

    /// Reads two packets with `payload`, padded the way OpenSSH pads them,
    /// and returns how long each is on the wire, without its MAC.
    async fn read_openssh_packets(
        cipher_name: cipher::Name,
        mac_name: mac::Name,
        block_size: usize,
        payload: &[u8],
    ) -> usize {
        let (mut sealing, mut opening, etm) = keys(cipher_name, mac_name);
        let mut wire = Vec::new();
        for seqn in 0..2 {
            let packet = openssh_packet(&mut *sealing, etm, block_size, seqn, payload);
            wire.extend(packet);
        }

        let mut stream = wire.as_slice();
        let mut buffer = SSHBuffer::new();
        for _ in 0..2 {
            let n = cipher::read(&mut stream, &mut buffer, &mut *opening)
                .await
                .unwrap();
            assert_eq!(&buffer.buffer[5..n], payload);
        }
        assert!(stream.is_empty());
        wire.len() / 2 - sealing.tag_len()
    }

    /// Reads a packet from `wire`, which holds no more than what `read`
    /// needs to learn the packet length.
    async fn read_packet_length(
        cipher_name: cipher::Name,
        mac_name: mac::Name,
        wire: &[u8],
    ) -> Result<usize, Error> {
        let (_, mut opening, _) = keys(cipher_name, mac_name);
        let mut stream = wire;
        cipher::read(&mut stream, &mut SSHBuffer::new(), &mut *opening).await
    }

    /// With an EtM MAC, only what follows the clear packet length is padded
    /// to whole blocks: OpenSSH sends SSH_MSG_USERAUTH_SUCCESS with
    /// 3des-cbc in 4 + 8 bytes.
    #[cfg(all(feature = "des", not(russh_backend = "symcrypt")))]
    #[tokio::test]
    async fn reads_short_3des_cbc_etm_packets() {
        let payload = [crate::msg::USERAUTH_SUCCESS];
        let len =
            read_openssh_packets(cipher::TRIPLE_DES_CBC, mac::HMAC_SHA256_ETM, 8, &payload).await;
        assert_eq!(len, 4 + 8);
    }

    #[cfg(all(feature = "des", not(russh_backend = "symcrypt")))]
    #[tokio::test]
    async fn reads_short_3des_cbc_packets() {
        let payload = [crate::msg::USERAUTH_SUCCESS];
        let len = read_openssh_packets(cipher::TRIPLE_DES_CBC, mac::HMAC_SHA256, 8, &payload).await;
        assert_eq!(len, 16);
    }

    #[tokio::test]
    async fn reads_short_aes_ctr_packets() {
        let payload = [crate::msg::USERAUTH_SUCCESS];
        let len = read_openssh_packets(cipher::AES_128_CTR, mac::HMAC_SHA256, 16, &payload).await;
        assert_eq!(len, 16);
        let len =
            read_openssh_packets(cipher::AES_128_CTR, mac::HMAC_SHA256_ETM, 16, &payload).await;
        assert_eq!(len, 4 + 16);
    }

    /// With an EtM MAC, the encrypted part of a packet must be a non-zero
    /// number of whole blocks, as in OpenSSH's packet.c: `read` rejects
    /// other lengths before reading past the clear packet length.
    #[tokio::test]
    async fn rejects_aes_ctr_etm_packets_of_partial_blocks() {
        for packet_length in [0, 8, 20] {
            let wire = (packet_length as u32).to_be_bytes();
            let err = read_packet_length(cipher::AES_128_CTR, mac::HMAC_SHA256_ETM, &wire)
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::PacketSize(n) if n == packet_length),
                "{packet_length}: {err:?}"
            );
        }
    }

    #[cfg(all(feature = "des", not(russh_backend = "symcrypt")))]
    #[tokio::test]
    async fn rejects_3des_cbc_etm_packets_of_partial_blocks() {
        for packet_length in [0, 4, 12] {
            let wire = (packet_length as u32).to_be_bytes();
            let err = read_packet_length(cipher::TRIPLE_DES_CBC, mac::HMAC_SHA256_ETM, &wire)
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::PacketSize(n) if n == packet_length),
                "{packet_length}: {err:?}"
            );
        }
    }

    /// Without EtM, 3des-cbc reads one 8-byte block to learn the packet
    /// length, but packets are still at least 16 bytes long (RFC 4253,
    /// section 6).
    #[cfg(all(feature = "des", not(russh_backend = "symcrypt")))]
    #[tokio::test]
    async fn rejects_3des_cbc_packets_shorter_than_16_bytes() {
        let (mut sealing, _, _) = keys(cipher::TRIPLE_DES_CBC, mac::HMAC_SHA256);
        // packet_length 4: padding_length 3, no payload, 3 bytes of padding.
        let mut packet = [0, 0, 0, 4, 3, 0, 0, 0];
        let mut tag = vec![0; sealing.tag_len()];
        sealing.seal(0, &mut packet, &mut tag);

        let err = read_packet_length(cipher::TRIPLE_DES_CBC, mac::HMAC_SHA256, &packet)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::PacketSize(4)), "{err:?}");
    }
}
