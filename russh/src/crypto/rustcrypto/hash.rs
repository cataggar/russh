//! SHA-1 and SHA-2 (RustCrypto `sha1`, `sha2`).

use crate::crypto::Hash;

macro_rules! hash {
    ($name:ident, $digest:ty) => {
        pub(crate) struct $name;

        impl Hash for $name {
            type Output = digest::Output<$digest>;

            fn digest(data: &[u8]) -> Self::Output {
                <$digest as digest::Digest>::digest(data)
            }
        }
    };
}

hash!(Sha1, sha1::Sha1);
hash!(Sha256, sha2::Sha256);
hash!(Sha384, sha2::Sha384);
hash!(Sha512, sha2::Sha512);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_match_known_answers() {
        assert_eq!(
            Sha1::digest_to_vec(b"abc"),
            hex_literal::hex!("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            Sha256::digest_to_vec(b"abc"),
            hex_literal::hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            Sha384::digest_to_vec(b"abc"),
            hex_literal::hex!(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                "8086072ba1e7cc2358baeca134c825a7"
            )
        );
        assert_eq!(
            Sha512::digest_to_vec(b"abc"),
            hex_literal::hex!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }
}
