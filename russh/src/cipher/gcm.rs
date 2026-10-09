// Copyright 2016 Pierre-Étienne Meunier
//
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

// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use std::convert::TryInto;
use std::marker::PhantomData;

use super::super::Error;
use crate::crypto::{self, AEAD_NONCE_LEN, AEAD_TAG_LEN, Aead};
use crate::mac::MacAlgorithm;

/// `aes*-gcm@openssh.com` (RFC 5647), generic over the backend's [`Aead`].
pub struct GcmCipher<A>(PhantomData<fn() -> A>);

impl<A> GcmCipher<A> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<A: Aead> super::Cipher for GcmCipher<A> {
    fn key_len(&self) -> usize {
        A::KEY_LEN
    }

    fn nonce_len(&self) -> usize {
        AEAD_NONCE_LEN
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        Box::new(OpeningKey(GcmKey::<A>::new(k, n)))
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        Box::new(SealingKey(GcmKey::<A>::new(k, n)))
    }
}

pub struct OpeningKey<A>(GcmKey<A>);

pub struct SealingKey<A>(GcmKey<A>);

struct GcmKey<A> {
    aead: A,
    nonce: [u8; AEAD_NONCE_LEN],
}

impl<A: Aead> GcmKey<A> {
    fn new(k: &[u8], n: &[u8]) -> Self {
        #[allow(clippy::expect_used)]
        Self {
            aead: A::new(k).expect("key length matches"),
            nonce: n.try_into().expect("nonce length matches"),
        }
    }

    /// Returns the nonce for the next packet and increments the invocation
    /// counter.
    fn advance(&mut self) -> [u8; AEAD_NONCE_LEN] {
        let nonce = self.nonce;
        let mut carry = 1;
        for byte in self.nonce.iter_mut().rev() {
            let n = *byte as u16 + carry;
            *byte = n as u8;
            carry = n >> 8;
        }
        nonce
    }
}

impl<A: Aead> super::OpeningKey for OpeningKey<A> {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        // Fine because of self.packet_length_to_read_for_block_length()
        #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
        encrypted_packet_length.try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn open<'a>(
        &mut self,
        _sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = self.0.advance();
        // Packet length is sent unencrypted
        let (packet_length, ciphertext_and_tag) = ciphertext_and_tag
            .split_at_mut_checked(super::PACKET_LENGTH_LEN)
            .ok_or(Error::DecryptionError)?;
        self.0
            .aead
            .open_in_place(&nonce, packet_length, ciphertext_and_tag)
            .map_err(|_| Error::DecryptionError)?;
        let plaintext: &'a [u8] = ciphertext_and_tag;
        plaintext
            .len()
            .checked_sub(AEAD_TAG_LEN)
            .and_then(|len| plaintext.get(..len))
            .ok_or(Error::DecryptionError)
    }
}

impl<A: Aead> super::SealingKey for SealingKey<A> {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        crypto::fill_random(padding_out);
    }

    fn tag_len(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn seal(
        &mut self,
        _sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag: &mut [u8],
    ) {
        let nonce = self.0.advance();
        // Packet length is sent unencrypted
        let (packet_length, plaintext_in_ciphertext_out) =
            plaintext_in_ciphertext_out.split_at_mut(super::PACKET_LENGTH_LEN);
        #[allow(clippy::expect_used)]
        self.0
            .aead
            .seal_in_place(
                &nonce,
                packet_length,
                plaintext_in_ciphertext_out,
                tag.try_into().expect("tag length matches"),
            )
            .expect("AEAD sealing succeeds");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::CryptoError;

    /// Records nonces; "encrypts" by XOR with the first nonce byte.
    struct FakeAead;

    impl Aead for FakeAead {
        const KEY_LEN: usize = 16;

        fn new(_: &[u8]) -> crypto::Result<Self> {
            Ok(Self)
        }

        fn seal_in_place(
            &self,
            nonce: &[u8; AEAD_NONCE_LEN],
            aad: &[u8],
            in_out: &mut [u8],
            tag: &mut [u8; AEAD_TAG_LEN],
        ) -> crypto::Result<()> {
            tag.fill(0);
            tag[..AEAD_NONCE_LEN].copy_from_slice(nonce);
            tag[AEAD_NONCE_LEN..].copy_from_slice(aad);
            in_out.iter_mut().for_each(|b| *b ^= 0x55);
            Ok(())
        }

        fn open_in_place(
            &self,
            nonce: &[u8; AEAD_NONCE_LEN],
            aad: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> crypto::Result<()> {
            let (ciphertext, tag) = ciphertext_and_tag
                .split_at_mut_checked(ciphertext_and_tag.len().checked_sub(AEAD_TAG_LEN).ok_or(CryptoError)?)
                .ok_or(CryptoError)?;
            if tag[..AEAD_NONCE_LEN] != nonce[..] || tag[AEAD_NONCE_LEN..] != *aad {
                return Err(CryptoError);
            }
            ciphertext.iter_mut().for_each(|b| *b ^= 0x55);
            Ok(())
        }
    }

    #[test]
    fn gcm_glue_uses_length_as_aad_and_counts_nonces() {
        use super::super::Cipher;

        let cipher = GcmCipher::<FakeAead>::new();
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce[AEAD_NONCE_LEN - 1] = 0xff;
        let mut sealing = cipher.make_sealing_key(&[0; 16], &nonce, &[], &crate::mac::_NONE);
        let mut opening = cipher.make_opening_key(&[0; 16], &nonce, &[], &crate::mac::_NONE);
        for _ in 0..2 {
            let mut packet = *b"\0\0\0\x08payload!";
            let mut tag = [0; AEAD_TAG_LEN];
            sealing.seal(0, &mut packet, &mut tag);
            assert_eq!(&packet[..4], b"\0\0\0\x08");
            assert_ne!(&packet[4..], b"payload!");
            let mut ciphertext_and_tag = packet.to_vec();
            ciphertext_and_tag.extend_from_slice(&tag);
            assert_eq!(opening.open(0, &mut ciphertext_and_tag).unwrap(), b"payload!");
        }
        // The counter carries into the next byte.
        let mut tag = [0; AEAD_TAG_LEN];
        sealing.seal(0, &mut [0; 8], &mut tag);
        assert_eq!(tag[AEAD_NONCE_LEN - 2..AEAD_NONCE_LEN], [1, 1]);

        let mut truncated = [0u8; 8];
        assert!(opening.open(0, &mut truncated).is_err());
    }
}
