//! The ring backend (feature `ring`, used when `aws-lc-rs` is off): AES-GCM
//! and `chacha20-poly1305@openssh.com` from ring, every other category from
//! [`rustcrypto`](super::rustcrypto).

pub(crate) use super::ring_aead::cipher;
pub(crate) use super::rustcrypto::{hash, kex, mac, rng, sign};

#[cfg(test)]
mod tests {
    #[test]
    fn algorithm_lists_are_unchanged() {
        super::super::ring_aead::tests::assert_algorithm_lists_are_unchanged();
    }
}
