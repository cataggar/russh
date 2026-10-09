//! The `rand` thread-local CSPRNG (seeded from the OS).

use rand_core::Rng as _;

use crate::crypto::Rng;

pub(crate) struct SystemRng;

impl Rng for SystemRng {
    fn fill_bytes(dest: &mut [u8]) {
        rand::rng().fill_bytes(dest)
    }
}
