//! Randomness from SymCrypt's RNG (`SymCryptRandom`, seeded from the OS).

use crate::crypto::Rng;

pub(crate) struct SystemRng;

impl Rng for SystemRng {
    fn fill_bytes(dest: &mut [u8]) {
        ::symcrypt::symcrypt_random(dest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_with_fresh_random_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        SystemRng::fill_bytes(&mut a);
        SystemRng::fill_bytes(&mut b);
        assert_ne!(a, [0; 32]);
        assert_ne!(a, b);
        SystemRng::fill_bytes(&mut []);
    }
}
